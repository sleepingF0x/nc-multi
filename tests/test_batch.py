"""Batch execution through real Bash/TCP peers and split completion frames."""

import os
from pathlib import Path
import select
import shlex
import shutil
import subprocess
import tempfile
import unittest

from nc_multi import BatchResult, SEND_LIMIT
from test_nc_multi import RunningConsole


class BatchFrameTests(unittest.TestCase):
    def test_every_frame_boundary_preserves_output_and_exit_status(self):
        prefix = b"\x1eNCMB_test:"
        data = b"before" + prefix + b"start\x1fresult" + prefix + b"end:7\x1fafter"
        for split in range(len(data) + 1):
            with self.subTest(split=split):
                result = BatchResult(1, 1, "127.0.0.1:1", prefix)
                output = result.feed(data[:split])
                output += result.feed(data[split:]) if result.state in ("queued", "sent", "running") else data[split:]
                self.assertEqual(output, b"beforeresultafter")
                self.assertEqual(result.state, "failed")
                self.assertEqual(result.exit_code, 7)

    def test_malformed_frames_are_output_and_pending_memory_is_bounded(self):
        prefix = b"\x1eNCMB_test:"
        result = BatchResult(1, 1, "127.0.0.1:1", prefix)
        bad = prefix + b"end:0\x1f" + prefix + b"invalid" * 10000
        output = b"".join(result.feed(bad[i:i + 37]) for i in range(0, len(bad), 37))
        self.assertEqual(output + result.pending, bad)
        self.assertLessEqual(len(result.pending), len(prefix) + 16)
        self.assertEqual(result.state, "queued")
        self.assertIsNone(result.exit_code)


@unittest.skipUnless(shutil.which("bash"), "Bash not installed")
class BatchIntegrationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="batch scripts ")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.console = RunningConsole()
        self.addCleanup(self.console.close)

    def script(self, text):
        path = self.directory / "script with spaces.sh"
        path.write_text(text, encoding="utf-8")
        return path

    def bash_client(self, node="client"):
        client = self.console.connect()
        child = subprocess.Popen(
            [shutil.which("bash"), "--noprofile", "--norc", "-i"],
            stdin=client, stdout=client, stderr=client,
            env={**os.environ, "NODE": node, "PS1": "BATCH-TEST> "}, start_new_session=True,
        )

        def finish():
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)
        self.addCleanup(finish)
        return client, child

    def run_batch(self, path):
        self.console.command("batch " + shlex.quote(str(path)))
        return self.console.read_until(b"Use jobs ")

    def test_two_bash_clients_report_independent_results_and_keep_shells(self):
        self.bash_client("first")
        self.bash_client("second")
        self.console.read_until(b"Session 2 connected")
        path = self.script("printf 'hello-%s 中文\\n' \"$NODE\"\nif [ \"$NODE\" = first ]; then exit 7; fi\n")
        self.run_batch(path)
        self.console.read_until(b"Session 1: failed, exit 7.")
        self.console.read_until(b"Session 2: ok, exit 0.")
        self.console.command("jobs 1")
        output = self.console.read_until(b"nc-multi> ")
        self.assertRegex(output, rb"1\s+127\.0\.0\.1:\d+\s+failed\s+7")
        self.assertRegex(output, rb"2\s+127\.0\.0\.1:\d+\s+ok\s+0")
        self.console.command("i 1")
        output = self.console.read_until(b"hello-first")
        self.assertNotIn(b"hello-second", output)
        self.assertNotIn(b"\x1eNCMB_", output)
        self.console.type(b"printf 'PARENT-STILL-ALIVE\\n'\r")
        self.console.read_until(b"PARENT-STILL-ALIVE")

    def test_script_quotes_stdin_and_redirections_do_not_break_completion(self):
        self.bash_client()
        self.console.read_until(b"Session 1 connected")
        path = self.script("if read -r value; then exit 19; fi\nprintf '%s\\n' \"a'b\"\nexec >/dev/null\nexit 4\n")
        self.run_batch(path)
        self.console.read_until(b"Session 1: failed, exit 4.")
        self.console.command("i 1")
        self.console.read_until(b"a'b")

    def test_unresponsive_peer_does_not_block_others_and_new_peers_are_excluded(self):
        slow = self.console.connect()
        self.bash_client()
        self.console.read_until(b"Session 2 connected")
        path = self.script("printf 'FAST-PEER\\n'\n")
        self.run_batch(path)
        self.console.read_until(b"Session 2: ok, exit 0.")
        late = self.console.connect()
        self.console.read_until(b"Session 3 connected")
        self.assertFalse(select.select([late], [], [], 0.1)[0])
        self.console.command("jobs")
        output = self.console.read_until(b"nc-multi> ")
        self.assertRegex(output, rb"1\s+127\.0\.0\.1:\d+\s+sent\s+-")
        self.assertNotRegex(output, rb"\n3\s+127")
        slow.close()
        self.console.read_until(b"Session 1 disconnected")
        self.console.command("jobs 1")
        output = self.console.read_until(b"nc-multi> ")
        self.assertRegex(output, rb"1\s+127\.0\.0\.1:\d+\s+disconnected\s+-")

    def test_running_job_rejects_manual_input_and_duplicate_dispatch(self):
        client = self.console.connect()
        self.console.read_until(b"Session 1 connected")
        path = self.script("echo placeholder")
        self.run_batch(path)
        packet = bytearray()
        while not packet.endswith(b"\n"):
            packet.extend(client.recv(65536))
        self.console.attach(1)
        self.console.type(b"must-not-interleave\r")
        self.console.read_until(b"Batch in progress; input was not queued")
        self.assertFalse(select.select([client], [], [], 0.1)[0])
        self.console.detach()
        output = self.run_batch(path)
        self.assertIn(b"0 queued, 1 skipped", output)
        self.assertFalse(select.select([client], [], [], 0.1)[0])

    def test_idle_timeout_leaves_exit_unknown_and_listener_accepts_again(self):
        console = RunningConsole("-t", "1")
        self.addCleanup(console.close)
        client = console.connect()
        console.read_until(b"Session 1 connected")
        path = self.script("echo placeholder")
        console.command("batch " + shlex.quote(str(path)))
        console.read_until(b"Use jobs 1")
        while client.recv(65536):
            pass
        console.read_until(b"Session 1 idle timeout")
        console.command("jobs 1")
        output = console.read_until(b"nc-multi> ")
        self.assertRegex(output, rb"1\s+127\.0\.0\.1:\d+\s+idle-timeout\s+-")
        console.connect()
        console.read_until(b"Session 2 connected")

    def test_invalid_files_never_send_partial_script(self):
        client = self.console.connect()
        self.console.read_until(b"Session 1 connected")
        path = self.directory / "bad.sh"
        for content in (b"", b"\xff", b"nul\x00", b"x" * (SEND_LIMIT + 1), b"'" * 20000):
            with self.subTest(content=content[:10]):
                path.write_bytes(content)
                self.console.command("batch " + shlex.quote(str(path)))
                self.console.read_until(b"Batch not started:")
                self.assertFalse(select.select([client], [], [], 0.05)[0])
        fifo = self.directory / "pipe"
        os.mkfifo(fifo)
        self.console.command("batch " + shlex.quote(str(fifo)))
        self.console.read_until(b"script must be a regular file")
        self.assertIsNone(self.console.process.poll())
        self.console.command("jobs")
        self.console.read_until(b"(no matching jobs)")

    def test_unknown_home_user_does_not_close_listener_or_connections(self):
        client = self.console.connect()
        self.console.read_until(b"Session 1 connected")
        self.console.command("batch ~__nc_multi_nonexistent_user_123__/script.sh")
        self.console.read_until(b"Batch not started:")
        client.sendall(b"STILL-CONNECTED")
        self.console.command("i 1")
        self.console.read_until(b"STILL-CONNECTED")
        self.assertIsNone(self.console.process.poll())


if __name__ == "__main__":
    unittest.main()

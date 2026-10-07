"""Batch execution through real Bash/TCP peers and split completion frames."""

import base64
import os
from pathlib import Path
import re
import select
import shlex
import shutil
import subprocess
import tempfile
import unittest

from nc_multi import BATCH_DECODER, BatchResult, SEND_LIMIT
from test_nc_multi import RunningConsole


BASH = shutil.which("bash")


@unittest.skipUnless(BASH, "Bash not installed")
class BatchDecoderTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="batch-decode-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.capture = self.directory / "decoded"
        # Observe the exact argument passed to the final Bash, without executing test bytes.
        executable = self.directory / "bash"
        executable.write_text(
            f"#!{BASH}\n"
            '[[ $# == 3 && $1 == -c && $3 == nc-multi-batch ]] || exit 81\n'
            'printf "%s" "$2" > "$CAPTURE_PATH"\nexit 7\n'
        )
        executable.chmod(0o700)

    def decode(self, encoded):
        return subprocess.run(
            [BASH, "-c", BATCH_DECODER, "nc-multi-decode", encoded],
            env={**os.environ, "PATH": str(self.directory), "CAPTURE_PATH": str(self.capture)},
            capture_output=True, timeout=5,
        )

    def test_all_padding_lengths_preserve_utf8_controls_and_trailing_newlines(self):
        source = bytes(range(1, 128)) + "中文🙂 'quoted' $() `ticks` \\\n\n".encode()
        for tail in (b"", b"\n", b"\n\n"):
            with self.subTest(padding=len(source + tail) % 3):
                result = self.decode(base64.b64encode(source + tail).decode())
                self.assertEqual(result.returncode, 7, result.stderr)
                self.assertEqual(self.capture.read_bytes(), source + tail)

    def test_invalid_encoding_and_nul_never_reach_execution(self):
        for encoded in ("", "A", "AAA", "A===", "====", "AA==junk", "AA A", "AA\nA", "!!!!", "AA=="):
            with self.subTest(encoded=encoded):
                result = self.decode(encoded)
                self.assertEqual(result.returncode, 125, result.stderr)
                self.assertIn(b"Invalid Base64 script", result.stderr)
                self.assertFalse(self.capture.exists())


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

    def run_batch(self, path, *arguments):
        self.console.command(" ".join(shlex.quote(str(part)) for part in ("batch", path, *arguments)))
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

    def test_short_option_selects_one_session_without_sending_to_other_peers(self):
        excluded = self.console.connect()
        self.bash_client()
        self.console.read_until(b"Session 2 connected")
        output = self.run_batch(self.script("printf 'SELECTED-ONLY\\n'\n"), "-s", "2")
        self.assertIn(b"1 queued, 0 skipped", output)
        self.console.read_until(b"Session 2: ok, exit 0.")
        self.assertFalse(select.select([excluded], [], [], 0.1)[0], "script reached an unselected session")
        self.console.command("jobs 1")
        listing = self.console.read_until(b"nc-multi> ")
        self.assertRegex(listing, rb"\n2\s+127\.0\.0\.1:\d+\s+ok\s+0")
        self.assertNotRegex(listing, rb"\n1\s+127\.0\.0\.1:")

    def test_invalid_session_selection_rejects_the_whole_batch(self):
        connected = self.console.connect()
        disconnected = self.console.connect()
        self.console.read_until(b"Session 2 connected")
        disconnected.close()
        self.console.read_until(b"Session 2 disconnected")
        path = self.script("printf 'MUST-NOT-RUN\\n'\n")
        invalid_arguments = (
            "--sessions", '--sessions ""', "--sessions 1,", "--sessions ,1", "--sessions 1,,2",
            "--sessions 0", "--sessions -1", "--sessions 1,abc", "--sessions 1,１",
            "--sessions 1,1-3", "--sessions 1," + "9" * 21, "--sessions 1,999", "--sessions 1,2",
            "--sessions 1, 2", "--sessions all", "--session 1", "--sessions 1 --sessions 1",
            '-s ""', "-s 1,999",
        )
        for arguments in invalid_arguments:
            with self.subTest(arguments=arguments):
                self.console.command("batch " + shlex.quote(str(path)) + " " + arguments)
                output = self.console.read_until(b"nc-multi> ")
                self.assertIn(b"Batch not started:", output)
                self.assertFalse(select.select([connected], [], [], 0.05)[0], "an invalid selection sent a script")
        self.console.command("jobs")
        self.console.read_until(b"(no matching jobs)")
        self.console.command("history")
        self.console.read_until(b"Execution history: 0 records;")
        output = self.run_batch(path, "--sessions", "1")
        self.assertIn(b"[Job 1] 1 queued, 0 skipped", output)

    def test_selected_busy_session_is_skipped_without_expanding_targets(self):
        busy = self.console.connect()
        excluded = self.console.connect()
        self.bash_client()
        self.console.read_until(b"Session 3 connected")
        path = self.script("printf 'SELECTED-FREE-PEER\\n'\n")
        self.run_batch(path, "--sessions", "1")
        packet = bytearray()
        while not packet.endswith(b"\n"):
            data = busy.recv(65536)
            self.assertTrue(data, "connection closed before the first batch was sent")
            packet.extend(data)
        output = self.run_batch(path, "--sessions", "1,3")
        self.assertIn(b"1 queued, 1 skipped", output)
        self.console.read_until(b"Session 3: ok, exit 0.")
        self.assertFalse(select.select([busy, excluded], [], [], 0.1)[0])
        self.console.command("jobs 2")
        listing = self.console.read_until(b"nc-multi> ")
        self.assertRegex(listing, rb"\n1\s+127\.0\.0\.1:\d+\s+skipped-busy\s+-")
        self.assertRegex(listing, rb"\n3\s+127\.0\.0\.1:\d+\s+ok\s+0")
        self.assertNotRegex(listing, rb"\n2\s+127\.0\.0\.1:")

    def test_script_quotes_stdin_and_redirections_do_not_break_completion(self):
        self.bash_client()
        self.console.read_until(b"Session 1 connected")
        path = self.script("if read -r value; then exit 19; fi\nprintf '%s\\n' \"a'b\"\nexec >/dev/null\nexit 4\n")
        self.run_batch(path)
        self.console.read_until(b"Session 1: failed, exit 4.")
        self.console.command("i 1")
        self.console.read_until(b"a'b")

    def test_base64_packet_is_one_ascii_line_and_executes_without_external_decoder(self):
        client = self.console.connect()
        self.console.read_until(b"Session 1 connected")
        source = (
            "if read -r input; then exit 19; fi\n"
            "IFS= read -r -d '' text <<'END'\n"
            "TRANSPORT_ONLY 中文 'quotes' \"double\" $() `literal`\n"
            "END\n"
            "printf '%s' \"$text\"\n"
            "printf '%s\\n' \"$data:$payload:$script:$LC_ALL\"\n"
            "exit 7\n\n"
        )
        path = self.directory / "encoded.sh"
        path.write_bytes(b"\xef\xbb\xbf" + source.replace("\n", "\r\n").encode())
        self.run_batch(path)
        packet = bytearray()
        while not packet.endswith(b"\n"):
            chunk = client.recv(65536)
            self.assertTrue(chunk)
            packet.extend(chunk)
        self.assertTrue(packet.isascii())
        self.assertEqual(packet.count(b"\n"), 1)
        self.assertIn(base64.b64encode(source.encode()), packet)
        self.assertNotIn(b"TRANSPORT_ONLY", packet)
        executable_dir = self.directory / "bin"
        executable_dir.mkdir()
        (executable_dir / "bash").symlink_to(BASH)
        result = subprocess.run(
            [BASH], input=bytes(packet), cwd=self.directory,
            env={**os.environ, "PATH": str(executable_dir), "data": "one", "payload": "two", "script": "three", "LC_ALL": "POSIX"},
            capture_output=True, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertIn("TRANSPORT_ONLY 中文 'quotes' \"double\" $() `literal`\n".encode(), result.stdout)
        self.assertIn(b"one:two:three:POSIX\n", result.stdout)
        client.sendall(result.stdout)
        self.console.read_until(b"Session 1: failed, exit 7.")

    def test_quote_heavy_script_fits_after_base64_encoding(self):
        self.bash_client()
        self.console.read_until(b"Session 1 connected")
        path = self.script("#" + "'" * 20000 + "\nprintf 'QUOTE-HEAVY-OK\\n'\n")
        self.run_batch(path)
        self.console.read_until(b"Session 1: ok, exit 0.")
        self.console.command("i 1")
        self.console.read_until(b"QUOTE-HEAVY-OK")

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

    def test_close_all_marks_unfinished_jobs_disconnected(self):
        clients = [self.console.connect() for _ in range(2)]
        self.console.read_until(b"Session 2 connected")
        self.run_batch(self.script("echo placeholder"))
        tokens = []
        for client in clients:
            packet = bytearray()
            while not packet.endswith(b"\n"):
                data = client.recv(65536)
                self.assertTrue(data, "connection closed before the batch was sent")
                packet.extend(data)
            tokens.append(re.search(rb"NCMB_[0-9a-f]{32}", packet)[0])
        clients[0].sendall(b"\x1e" + tokens[0] + b":start\x1fRUNNING-OUTPUT")
        self.console.command("i 1")
        self.console.read_until(b"RUNNING-OUTPUT")
        self.console.detach()
        self.console.command("jobs 1")
        output = self.console.read_until(b"nc-multi> ")
        self.assertRegex(output, rb"1\s+127\.0\.0\.1:\d+\s+running\s+-")
        self.assertRegex(output, rb"2\s+127\.0\.0\.1:\d+\s+sent\s+-")
        self.console.command("close all")
        self.console.read_until(b"Closed all sessions (2 removed). Listener remains active.")
        for client in clients:
            self.assertEqual(client.recv(1), b"")
        self.console.command("jobs 1")
        output = self.console.read_until(b"nc-multi> ")
        for sid in (1, 2):
            self.assertRegex(output, str(sid).encode() + rb"\s+127\.0\.0\.1:\d+\s+disconnected\s+-")
        self.console.command("ls")
        self.console.read_until(b"(no sessions)")

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
        for content in (b"", b"\xff", b"nul\x00", b"x" * (SEND_LIMIT + 1), b"x" * (SEND_LIMIT * 3 // 4)):
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

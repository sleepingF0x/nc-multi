"""Black-box tests using real TCP sockets and a real local pseudo-terminal."""

import fcntl
import os
import pathlib
import pty
import re
import select
import shutil
import signal
import socket
import subprocess
import sys
import termios
import tempfile
import threading
import time
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "nc_multi.py"


class RunningConsole:
    def __init__(self, *arguments, config_home=None):
        self.config_directory = tempfile.TemporaryDirectory(prefix="nc-multi-test-")
        self.config_home = pathlib.Path(config_home or self.config_directory.name)
        self.master, self.slave = pty.openpty()
        self.attributes = termios.tcgetattr(self.slave)
        self.flags = fcntl.fcntl(self.slave, fcntl.F_GETFL)
        self.process = subprocess.Popen(
            [sys.executable, str(SCRIPT), "--host", "127.0.0.1", "-l", "0", *arguments],
            stdin=self.slave, stdout=self.slave, stderr=self.slave, close_fds=True,
            env={**os.environ, "XDG_CONFIG_HOME": str(self.config_home)},
        )
        self.output = bytearray()
        self.clients = []
        self.read_until(b"nc-multi> ")
        self.port = int(re.search(rb"Listening on 127\.0\.0\.1:(\d+)", self.output)[1])

    def read_until(self, marker, timeout=5):
        deadline = time.monotonic() + timeout
        while marker not in self.output:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f"Missing {marker!r}; received {bytes(self.output[-3000:])!r}")
            readable, _, _ = select.select([self.master], [], [], min(remaining, 0.1))
            if readable:
                data = os.read(self.master, 65536)
                self.output.extend(data)
            elif self.process.poll() is not None:
                raise AssertionError(f"Console exited {self.process.returncode}: {bytes(self.output)!r}")
        return bytes(self.output)

    def drain(self, duration=0.1):
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            readable, _, _ = select.select([self.master], [], [], 0.01)
            if readable:
                self.output.extend(os.read(self.master, 65536))
        result = bytes(self.output)
        self.output.clear()
        return result

    def type(self, data):
        offset = 0
        while offset < len(data):
            offset += os.write(self.master, data[offset:])

    def command(self, text):
        self.drain()
        self.type(text.encode() + b"\r")

    def connect(self, receive_buffer=None):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(3)
        if receive_buffer is not None:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, receive_buffer)
        client.connect(("127.0.0.1", self.port))
        self.clients.append(client)
        return client

    def attach(self, sid, raw=False):
        self.command(f"interact {sid}" + (" raw" if raw else ""))
        self.read_until(f"[Session {sid} ".encode())
        self.drain()

    def detach(self):
        self.drain()
        self.type(b"\x1d")
        self.read_until(b"nc-multi> ")
        self.drain()

    def stop(self, signum=signal.SIGTERM):
        if self.process.poll() is None:
            self.process.send_signal(signum)
            self.process.wait(timeout=5)

    def close(self):
        self.stop()
        for client in self.clients:
            client.close()
        os.close(self.master)
        os.close(self.slave)
        self.config_directory.cleanup()


def receive(client, count):
    result = bytearray()
    while len(result) < count:
        data = client.recv(count - len(result))
        if not data:
            raise AssertionError(f"Connection ended after {bytes(result)!r}")
        result.extend(data)
    return bytes(result)


class SessionIntegrationTests(unittest.TestCase):
    def start(self, *args):
        console = RunningConsole(*args)
        self.addCleanup(console.close)
        return console

    def test_three_clients_input_isolation_and_background_replay(self):
        console = self.start()
        first, second, third = [console.connect() for _ in range(3)]
        console.read_until(b"Session 3 connected")
        console.attach(1)
        console.type(b"first-only\r")
        self.assertEqual(receive(first, 11), b"first-only\n")
        for client in (second, third):
            self.assertFalse(select.select([client], [], [], 0.1)[0], "input was broadcast")
        second.sendall(b"SECOND-BACKGROUND\n")
        third.sendall(b"THIRD-BACKGROUND\n")
        first.sendall(b"FIRST-FOREGROUND\n")
        output = console.read_until(b"FIRST-FOREGROUND")
        self.assertNotIn(b"SECOND-BACKGROUND", output)
        self.assertNotIn(b"THIRD-BACKGROUND", output)
        console.detach()
        console.command("interact 2")
        output = console.read_until(b"SECOND-BACKGROUND")
        self.assertNotIn(b"THIRD-BACKGROUND", output)
        console.type(b"second-only\r")
        self.assertEqual(receive(second, 12), b"second-only\n")
        console.detach()
        console.attach(1)
        console.type(b"still-alive\r")
        self.assertEqual(receive(first, 12), b"still-alive\n")

    def test_accepting_new_client_while_attached_does_not_steal_focus(self):
        console = self.start()
        first = console.connect()
        console.read_until(b"Session 1 connected")
        console.attach(1)
        second = console.connect()
        second.sendall(b"NEW-CLIENT-OUTPUT\n")
        console.type(b"original\r")
        self.assertEqual(receive(first, 9), b"original\n")
        self.assertNotIn(b"NEW-CLIENT-OUTPUT", console.drain())
        console.detach()
        console.command("interact 2")
        console.read_until(b"NEW-CLIENT-OUTPUT")

    def test_buffer_overflow_is_bounded_and_reported(self):
        console = self.start("--buffer-kib", "1")
        client = console.connect()
        console.read_until(b"Session 1 connected")
        client.sendall(b"x" * 4096 + b"TAIL")
        deadline = time.monotonic() + 4
        while True:
            console.command("sessions")
            output = console.read_until(b"nc-multi> ")
            if re.search(rb"connected\s+1024\s+3076", output):
                break
            self.assertLess(time.monotonic(), deadline)
        console.command("interact 1")
        output = console.read_until(b"TAIL")
        self.assertIn(b"3076 oldest bytes dropped", output)
        self.assertIn(b"x" * 1020 + b"TAIL", output)

    def test_disconnected_output_can_be_read_and_other_client_survives(self):
        console = self.start()
        first, second = console.connect(), console.connect()
        console.read_until(b"Session 2 connected")
        first.sendall(b"FINAL-OUTPUT\n")
        first.close()
        console.read_until(b"Session 1 disconnected")
        console.command("interact 1")
        console.read_until(b"FINAL-OUTPUT")
        console.read_until(b"Session 1 disconnected.")
        console.attach(2)
        console.type(b"healthy\r")
        self.assertEqual(receive(second, 8), b"healthy\n")

    def test_raw_bytes_and_escape_do_not_close_connection(self):
        console = self.start()
        client = console.connect()
        console.read_until(b"Session 1 connected")
        console.attach(1, raw=True)
        payload = b"a\x03\x04\x00\x1b[A\xff\r"
        console.type(payload)
        self.assertEqual(receive(client, len(payload)), payload)
        self.assertNotIn(payload, console.drain())
        console.detach()
        self.assertFalse(select.select([client], [], [], 0.1)[0])
        console.attach(1)
        console.type(b"abc\x7fd\r")
        self.assertEqual(receive(client, 4), b"abd\n")

    def test_limit_rejects_connections_and_reclaims_closed_records(self):
        console = self.start("--max-sessions", "2")
        first, second = console.connect(), console.connect()
        console.read_until(b"Session 2 connected")
        rejected = console.connect()
        self.assertEqual(rejected.recv(1), b"")
        first.close()
        console.read_until(b"Session 1 disconnected")
        third = console.connect()
        console.read_until(b"Session 3 connected")
        console.command("sessions")
        output = console.read_until(b"nc-multi> ")
        self.assertNotRegex(output, rb"\n1\s+")
        self.assertRegex(output, rb"\n3\s+")
        console.attach(3)
        console.type(b"new\r")
        self.assertEqual(receive(third, 4), b"new\n")
        self.assertFalse(select.select([second], [], [], 0.1)[0])

    def test_busy_background_client_does_not_block_other_sessions(self):
        console = self.start("--buffer-kib", "4")
        busy, other = console.connect(), console.connect()
        console.read_until(b"Session 2 connected")
        errors = []

        def flood():
            try:
                busy.sendall(b"z" * (4 * 1024 * 1024))
            except OSError as error:
                errors.append(error)

        worker = threading.Thread(target=flood, daemon=True)
        worker.start()
        console.attach(2)
        console.type(b"responsive\r")
        self.assertEqual(receive(other, 11), b"responsive\n")
        worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertFalse(errors)
        self.assertNotIn(b"zzzz", console.drain())

    def test_blocked_terminal_output_does_not_block_session_switch(self):
        console = self.start("--buffer-kib", "64")
        busy, other = console.connect(), console.connect()
        console.read_until(b"Session 2 connected")
        console.attach(1, raw=True)
        busy.sendall(b"BUSY-OUTPUT\n" * 100000)
        # Deliberately do not drain the PTY output before switching and sending.
        console.type(b"\x1dinteract 2 raw\rSELECTED\n")
        self.assertEqual(receive(other, 9), b"SELECTED\n")
        console.read_until(b"[Session 2 ")
        output = console.drain()
        self.assertNotIn(b"BUSY-OUTPUT", output.split(b"[Session 2 ", 1)[1])

    def test_slow_client_pauses_input_without_blocking_other_sessions(self):
        console = self.start()
        slow, other = console.connect(receive_buffer=1024), console.connect()
        console.read_until(b"Session 2 connected")
        console.attach(1, raw=True)
        errors = []

        def flood_input():
            try:
                console.type(b"x" * (8 * 1024 * 1024))
            except OSError as error:
                errors.append(error)

        worker = threading.Thread(target=flood_input, daemon=True)
        worker.start()
        console.read_until(b"Send queue full; input paused", timeout=10)
        worker.join(timeout=10)
        self.assertFalse(worker.is_alive())
        self.assertFalse(errors)
        console.type(b"quit\r")
        console.drain()
        self.assertIsNone(console.process.poll(), "unsent remote input became a local command")
        console.detach()
        console.attach(2)
        console.type(b"other-still-works\r")
        self.assertEqual(receive(other, 18), b"other-still-works\n")

    def test_overlong_input_is_rejected_instead_of_executing_a_prefix(self):
        console = self.start()
        client = console.connect()
        console.read_until(b"Session 1 connected")
        console.attach(1)
        console.type(b"x" * 8200 + b"\r")
        console.read_until(b"entire line discarded")
        self.assertFalse(select.select([client], [], [], 0.1)[0])
        console.type(b"normal\r")
        self.assertEqual(receive(client, 7), b"normal\n")

    @unittest.skipUnless(shutil.which("bash"), "Bash not installed")
    def test_real_bash_process_keeps_state_across_detach(self):
        console = self.start()
        client = console.connect()
        child = subprocess.Popen(
            [shutil.which("bash"), "--noprofile", "--norc", "-i"],
            stdin=client, stdout=client, stderr=client, env={**os.environ, "PS1": "BASH-TEST> "},
            start_new_session=True,
        )

        def finish_bash():
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)

        self.addCleanup(finish_bash)
        console.read_until(b"Session 1 connected")
        console.attach(1)
        console.type(b"SESSION_VALUE=retained; cd /; printf '%s\\n' READY-$SESSION_VALUE\r")
        console.read_until(b"READY-retained")
        console.detach()
        console.attach(1)
        console.type(b"printf '%s:%s\\n' STATE-$SESSION_VALUE $PWD\r")
        console.read_until(b"STATE-retained:/")
        console.type(b"exit\r")
        # The parent socket must be closed too for the server to observe EOF.
        child.wait(timeout=3)
        client.close()
        console.read_until(b"Session 1 disconnected.")

    def test_terminal_restored_after_signal_while_attached(self):
        console = self.start()
        client = console.connect()
        console.read_until(b"Session 1 connected")
        console.attach(1, raw=True)
        console.stop()
        self.assertEqual(console.process.returncode, 0)
        # Compare the blocking setting we change. macOS also adds an internal
        # F_GETFL bit after any write, independently of terminal configuration.
        self.assertEqual(os.get_blocking(console.slave), not bool(console.flags & os.O_NONBLOCK))
        # BSD kernels set transient PENDIN when canonical mode is restored;
        # one nonblocking read clears it, as the next shell read normally would.
        os.set_blocking(console.slave, False)
        try:
            with self.assertRaises(BlockingIOError):
                os.read(console.slave, 1)
        finally:
            fcntl.fcntl(console.slave, fcntl.F_SETFL, console.flags)
        self.assertEqual(termios.tcgetattr(console.slave), console.attributes)
        self.assertEqual(client.recv(1), b"")

    def test_quit_closes_all_connections(self):
        console = self.start()
        clients = [console.connect() for _ in range(3)]
        console.read_until(b"Session 3 connected")
        console.command("quit")
        console.process.wait(timeout=3)
        self.assertEqual(console.process.returncode, 0)
        for client in clients:
            self.assertEqual(client.recv(1), b"")

    def test_invalid_commands_do_not_exit_and_close_affects_only_one_client(self):
        console = self.start()
        first, second = console.connect(), console.connect()
        console.read_until(b"Session 2 connected")
        for invalid in ("interact", "interact -1", "interact " + "9" * 5000, "close 1 raw"):
            console.command(invalid)
            console.read_until(b"Usage:")
            self.assertIsNone(console.process.poll())
        console.command("close 1")
        console.read_until(b"Closed session 1")
        self.assertEqual(first.recv(1), b"")
        console.attach(2)
        console.type(b"alive\r")
        self.assertEqual(receive(second, 6), b"alive\n")


if __name__ == "__main__":
    unittest.main()

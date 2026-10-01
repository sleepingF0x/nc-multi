"""Idle policy checks with a controlled clock and real socket/PTY integration."""

import select
import socket
import subprocess
import sys
import time
import unittest
from unittest import mock

from nc_multi import Console
from test_nc_multi import RunningConsole, SCRIPT, receive


class IdleDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.setblocking(False)
        # No terminal is accessed by these clock-controlled network checks.
        self.console = Console(self.listener, None, 1024, 10)
        self.client = socket.create_connection(self.listener.getsockname(), timeout=2)
        self.assertTrue(select.select([self.listener], [], [], 2)[0])
        self.console.accept()
        self.session = self.console.sessions[1]
        self.origin = self.session.last_input

    def tearDown(self):
        for session in self.console.sessions.values():
            self.console.disconnect(session, notify=False)
        self.console.selector.close()
        self.console.history.close()
        self.client.close()
        self.listener.close()

    def expire_at(self, seconds):
        with mock.patch("nc_multi.time.monotonic", return_value=self.origin + seconds):
            self.console.expire_idle_sessions()

    def remote_output(self, data):
        self.client.sendall(data)
        # sendall does not guarantee recv is ready on a nonblocking peer yet.
        self.assertTrue(select.select([self.session.sock], [], [], 2)[0])
        self.console.read_session(self.session)

    def test_default_closes_at_fifteen_minutes_and_retains_output(self):
        self.remote_output(b"saved-output")
        self.expire_at(899.999)
        self.assertFalse(select.select([self.client], [], [], 0)[0])
        self.expire_at(900)
        self.assertEqual(self.client.recv(1), b"")
        self.assertEqual(self.session.close_reason, "idle-timeout")
        self.assertEqual(self.session.output.head(), b"saved-output")

    def test_submitted_input_moves_deadline_but_viewing_does_not(self):
        with mock.patch("nc_multi.time.monotonic", return_value=self.origin + 800):
            self.console.command("interact 1")
            self.console.send(b"echo hello\n")
            self.console.write_session(self.session)
        self.assertEqual(receive(self.client, 11), b"echo hello\n")
        self.console.detach()
        self.expire_at(1699.999)
        self.assertFalse(select.select([self.client], [], [], 0)[0])
        # Merely opening or listing a session must not keep it alive forever.
        with mock.patch("nc_multi.time.monotonic", return_value=self.origin + 1699.999):
            self.console.command("sessions")
            self.console.command("interact 1")
        self.expire_at(1700)
        self.assertEqual(self.client.recv(1), b"")
        self.assertIsNone(self.console.active)

    def test_remote_output_does_not_reset_deadline(self):
        with mock.patch("nc_multi.time.monotonic", return_value=self.origin + 899):
            self.remote_output(b"still-producing-output")
        self.expire_at(900)
        self.assertEqual(self.client.recv(1), b"")

    def test_zero_disables_expiration(self):
        self.console.idle_timeout = 0
        self.expire_at(86400)
        self.assertFalse(select.select([self.client], [], [], 0)[0])
        self.console.command("interact 1")
        self.console.send(b"alive\n")
        self.console.write_session(self.session)
        self.assertEqual(receive(self.client, 6), b"alive\n")


class IdleIntegrationTests(unittest.TestCase):
    def start(self, *args):
        console = RunningConsole(*args)
        self.addCleanup(console.close)
        return console

    def test_listener_without_clients_survives_multiple_idle_periods(self):
        console = self.start("-t", "1")
        # Leave the real event loop idle past more than one session deadline.
        time.sleep(2.3)
        self.assertIsNone(console.process.poll(), "listener exited with no clients")
        client = console.connect()
        console.read_until(b"Session 1 connected")
        console.attach(1)
        console.type(b"still-listening\r")
        self.assertEqual(receive(client, 16), b"still-listening\n")
        client.sendall(b"CLIENT-REPLY")
        console.read_until(b"CLIENT-REPLY")

    def test_unused_session_expires_and_listener_accepts_another(self):
        console = self.start("--idle-timeout", "1")
        self.assertIn(b"Idle timeout: 1s", console.output)
        client = console.connect()
        console.read_until(b"Session 1 connected")
        self.assertEqual(client.recv(1), b"")
        console.read_until(b"Session 1 idle timeout")
        console.command("sessions")
        console.read_until(b"idle-timeout")
        # Expiring the final client must not start a listener-wide idle timer.
        time.sleep(2.3)
        self.assertIsNone(console.process.poll(), "listener exited after the final session expired")
        second = console.connect()
        console.read_until(b"Session 2 connected")
        second.sendall(b"AFTER-TIMEOUT")
        console.command("interact 2")
        console.read_until(b"AFTER-TIMEOUT")
        console.type(b"still-listening\r")
        self.assertEqual(receive(second, 16), b"still-listening\n")
        self.assertIsNone(console.process.poll())

    def test_active_session_expires_with_unsent_line_and_returns_to_menu(self):
        console = self.start("--idle-timeout", "1")
        client = console.connect()
        console.read_until(b"Session 1 connected")
        console.attach(1)
        console.type(b"unsent-local-input")
        self.assertEqual(client.recv(1), b"")
        console.read_until(b"Session 1 idle timeout")
        console.read_until(b"nc-multi> ")
        console.command("sessions")
        console.read_until(b"idle-timeout")

    def test_activity_keeps_only_the_selected_session_alive(self):
        console = self.start("--idle-timeout", "2")
        active, inactive = console.connect(), console.connect()
        console.read_until(b"Session 2 connected")
        console.attach(1)
        deadline = time.monotonic() + 5
        while not select.select([inactive], [], [], 0.2)[0]:
            self.assertLess(time.monotonic(), deadline, "inactive session did not expire")
            console.type(b"keepalive\r")
            self.assertEqual(receive(active, 10), b"keepalive\n")
        self.assertEqual(inactive.recv(1), b"")
        console.type(b"only-first-alive\r")
        self.assertEqual(receive(active, 17), b"only-first-alive\n")
        self.assertNotIn(b"Session 2 idle timeout", console.drain(), "background notice interrupted the active shell")

    def test_raw_input_resets_timer_then_session_expires(self):
        console = self.start("--idle-timeout", "1")
        client = console.connect()
        console.read_until(b"Session 1 connected")
        console.attach(1, raw=True)
        for _ in range(5):
            self.assertFalse(select.select([client], [], [], 0.3)[0])
            console.type(b"a")
            self.assertEqual(receive(client, 1), b"a")
        self.assertEqual(client.recv(1), b"")
        console.read_until(b"Session 1 idle timeout")

    def test_timeout_option_accepts_zero_and_rejects_invalid_values(self):
        console = self.start("--idle-timeout", "0")
        self.assertIn(b"Idle timeout: disabled", console.output)
        for value in ("-1", "nan", "1.5"):
            with self.subTest(value=value):
                result = subprocess.run(
                    [sys.executable, str(SCRIPT), "--idle-timeout", value],
                    capture_output=True, timeout=3,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn(b"--idle-timeout", result.stderr)


if __name__ == "__main__":
    unittest.main()

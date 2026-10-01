"""Pure-Bash download tests against loopback HTTP fixtures; never run the payload."""

import contextlib
import os
from pathlib import Path
import shutil
import shlex
import socket
import subprocess
import tempfile
import threading
import time
import unittest

from test_nc_multi import RunningConsole


SCRIPT = Path(__file__).resolve().parents[1] / "examples" / "download_pv3.sh"
BASH = shutil.which("bash")
CHMOD = shutil.which("chmod")


class HTTPFixture:
    def __init__(self, response, hold_open=False):
        self.response = response
        self.hold_open = hold_open
        self.request = b""
        self.stop = threading.Event()
        self.peer_closed = threading.Event()
        self.errors = []
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen()
        self.listener.settimeout(0.1)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        try:
            while not self.stop.is_set():
                try:
                    peer, _ = self.listener.accept()
                    break
                except socket.timeout:
                    continue
            else:
                return
            with peer:
                peer.settimeout(0.1)
                while b"\r\n\r\n" not in self.request and not self.stop.is_set():
                    try:
                        data = peer.recv(4096)
                    except socket.timeout:
                        continue
                    if not data:
                        return
                    self.request += data
                peer.sendall(self.response)
                while self.hold_open and not self.stop.is_set():
                    try:
                        if not peer.recv(4096):
                            self.peer_closed.set()
                            return
                    except socket.timeout:
                        continue
        except (BrokenPipeError, ConnectionResetError):
            self.peer_closed.set()
        except OSError as error:
            if not self.stop.is_set():
                self.errors.append(error)

    def close(self):
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=2)


@unittest.skipUnless(BASH and CHMOD, "Bash and chmod are required")
class BashDownloadTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="bash-download-test-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.output = self.directory / "download.bin"
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        (self.bin / "chmod").symlink_to(CHMOD)

    @contextlib.contextmanager
    def server(self, response, hold_open=False):
        fixture = HTTPFixture(response, hold_open)
        try:
            yield fixture
        finally:
            fixture.close()
            self.assertFalse(fixture.thread.is_alive(), "HTTP fixture did not stop")
            self.assertEqual(fixture.errors, [])

    def environment(self, port, **changes):
        return {
            **os.environ,
            "PATH": str(self.bin),  # Only chmod is available as an external command.
            "PV_HOST": "127.0.0.1", "PV_PORT": str(port),
            "PV_PATH": "/fixture/download", "PV_KEY": "testkey123",
            "PV_OUTPUT": str(self.output), "PV_TIMEOUT": "5",
            **changes,
        }

    def run_download(self, port, **changes):
        return subprocess.run(
            [BASH, str(SCRIPT)], cwd=self.directory,
            env=self.environment(port, **changes), capture_output=True, timeout=8,
        )

    def assert_failed(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn(b"[ready]", result.stdout)
        if self.output.is_file():
            self.assertEqual(self.output.stat().st_mode & 0o111, 0)

    @staticmethod
    def response(body):
        return b"HTTP/1.0 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body

    def test_binary_bytes_and_nuls_at_chunk_boundaries_are_preserved(self):
        body = b"a" * 16383 + b"\0" + b"b" * 16384 + b"\0\0" + bytes(range(256)) * 4 + b"\0last\xff"
        with self.server(self.response(body)) as server:
            result = self.run_download(server.port)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(b"GET /fixture/download HTTP/1.0\r\n", server.request)
            self.assertIn(b"X-PV: testkey123\r\n", server.request)
            self.assertIn(b"Accept-Encoding: identity\r\n", server.request)
        self.assertEqual(self.output.read_bytes(), body)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertNotIn(b"testkey123", result.stdout + result.stderr)
        self.assertIn(b"not started", result.stdout)

    def test_complete_body_does_not_wait_for_connection_close(self):
        with self.server(self.response(b"complete"), hold_open=True) as server:
            result = self.run_download(server.port, PV_TIMEOUT="1")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(server.peer_closed.wait(1))
        self.assertEqual(self.output.read_bytes(), b"complete")

    def test_truncated_body_is_not_reported_successful_or_made_executable(self):
        with self.server(b"HTTP/1.0 200 OK\r\nContent-Length: 100\r\n\r\nabc") as server:
            result = self.run_download(server.port)
        self.assert_failed(result)
        self.assertIn(b"received 3 of 100", result.stderr)

    def test_incomplete_headers_do_not_create_output(self):
        with self.server(b"HTTP/1.0 200 OK\r\nContent-Length: 100\r\n") as server:
            result = self.run_download(server.port)
        self.assert_failed(result)
        self.assertFalse(self.output.exists())

    def test_non_200_responses_are_rejected_without_following_redirects(self):
        for status in (302, 403, 500):
            with self.subTest(status=status), self.server(
                f"HTTP/1.0 {status} Refused\r\nContent-Length: 3\r\nLocation: /elsewhere\r\n\r\nabc".encode()
            ) as server:
                result = self.run_download(server.port)
                self.assert_failed(result)
                self.assertIn(f"HTTP {status}".encode(), result.stderr)
                self.assertFalse(self.output.exists())

    def test_unsupported_or_invalid_http_framing_is_rejected(self):
        cases = [
            b"", b"Content-Length: 0\r\n", b"Content-Length: -3\r\n",
            b"Content-Length: 1 0\r\n", b"Content-Length: 99999999999999999999\r\n",
            b"Content-Length: 3\r\nContent-Length: 3\r\n",
            b"Content-Length: 3\r\nContent-Length: 4\r\n",
            b"Content-Length: 3\r\nTransfer-Encoding: chunked\r\n",
            b"Content-Length: 3\r\nContent-Encoding: gzip\r\n",
            b"Content-Length: 3\r\ninvalid header\r\n",
            b"Content-Length: 3\r\nX-Padding: " + b"a" * 8192 + b"\r\n",
            b"Content-Length: 3\r\n" + (b"X-Padding: " + b"a" * 2000 + b"\r\n") * 33,
        ]
        for headers in cases:
            with self.subTest(headers=headers[:80]), self.server(b"HTTP/1.1 200 OK\r\n" + headers + b"\r\nabc") as server:
                result = self.run_download(server.port)
                self.assert_failed(result)
                self.assertFalse(self.output.exists())

    def test_mixed_case_headers_and_decimal_length_are_supported(self):
        with self.server(b"HTTP/1.1 200 OK\r\ncOnTeNt-LeNgTh:\t0008 \t\r\nContent-Encoding: Identity\r\n\r\n12345678") as server:
            result = self.run_download(server.port)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.output.read_bytes(), b"12345678")

    def test_deadline_stops_stalled_headers_and_body_without_orphan_connections(self):
        for response in (b"", b"HTTP/1.0 200 OK\r\nContent-Length: 100\r\n\r\npartial"):
            with self.subTest(response=response), self.server(response, hold_open=True) as server:
                started = time.monotonic()
                result = self.run_download(server.port, PV_TIMEOUT="1")
                self.assertEqual(result.returncode, 124, result.stdout + result.stderr)
                self.assertLess(time.monotonic() - started, 4)
                self.assertTrue(server.peer_closed.wait(1), "download child left its TCP connection open")
                self.assert_failed(result)

    def test_existing_file_and_symlink_are_not_overwritten(self):
        self.output.write_bytes(b"keep original")
        target = self.directory / "target"
        target.write_bytes(b"keep target")
        for symlink in (False, True):
            if symlink:
                self.output.unlink()
                self.output.symlink_to(target)
            with self.subTest(symlink=symlink), self.server(self.response(b"new")) as server:
                result = self.run_download(server.port)
                self.assert_failed(result)
                self.assertIn(b"Refusing to overwrite", result.stderr)
                self.assertEqual(server.request, b"")
            self.assertEqual(self.output.read_bytes(), b"keep target" if symlink else b"keep original")

    def test_invalid_configuration_does_not_send_a_request_or_expose_the_key(self):
        for setting in (
            {"PV_KEY": ""}, {"PV_KEY": "secret\r\nInjected: header"},
            {"PV_HOST": ""}, {"PV_HOST": "localhost/invalid"}, {"PV_PORT": "0"},
            {"PV_PORT": "65536"}, {"PV_PORT": "x"},
            {"PV_PATH": "/x\r\nInjected: header"},
            {"PV_TIMEOUT": "0"}, {"PV_TIMEOUT": "x"},
        ):
            with self.subTest(setting=setting), self.server(self.response(b"x")) as server:
                result = self.run_download(server.port, **setting)
                self.assert_failed(result)
                self.assertEqual(server.request, b"")
                self.assertNotIn(b"secret", result.stdout + result.stderr)

    def test_connection_failure_does_not_create_output(self):
        with socket.socket() as unavailable:
            unavailable.bind(("127.0.0.1", 0))
            result = self.run_download(unavailable.getsockname()[1])
        self.assert_failed(result)
        self.assertFalse(self.output.exists())

    def test_chmod_failure_is_reported_without_running_the_download(self):
        (self.bin / "chmod").unlink()
        (self.bin / "chmod").write_text(f"#!{BASH}\nexit 9\n")
        (self.bin / "chmod").chmod(0o700)
        with self.server(self.response(b"arbitrary binary data\0")) as server:
            result = self.run_download(server.port)
        self.assert_failed(result)
        self.assertIn(b"chmod failed", result.stderr)
        self.assertEqual(self.output.read_bytes(), b"arbitrary binary data\0")

    def test_batch_download_returns_status_without_executing_the_payload(self):
        console = RunningConsole()
        self.addCleanup(console.close)
        client = console.connect()
        console.read_until(b"Session 1 connected")
        # This is test data only; executing it would create a marker and fail the test.
        marker = self.directory / "payload-was-run"
        body = ("#!/bin/sh\nprintf executed > " + shlex.quote(str(marker)) + "\n").encode()
        (self.bin / "bash").symlink_to(BASH)
        with self.server(self.response(body)) as server:
            child = subprocess.Popen(
                [BASH, "--noprofile", "--norc", "-i"],
                stdin=client, stdout=client, stderr=client,
                env=self.environment(server.port), start_new_session=True,
            )
            try:
                console.command("batch " + shlex.quote(str(SCRIPT)))
                console.read_until(b"Session 1: ok, exit 0.")
                console.command("i 1")
                output = console.read_until(b"not started.")
                self.assertIn(b"[ready]", output)
                self.assertEqual(self.output.read_bytes(), body)
                self.assertFalse(marker.exists())
            finally:
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=3)


if __name__ == "__main__":
    unittest.main()

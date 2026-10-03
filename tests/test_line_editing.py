"""Line editing through the real console PTY and TCP connection."""

import unittest

from nc_multi import LINE_LIMIT
from test_nc_multi import RunningConsole, receive


class LineEditingIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.console = RunningConsole()
        self.addCleanup(self.console.close)
        self.client = self.console.connect()
        self.console.read_until(b"Session 1 connected")

    def test_menu_left_arrow_inserts_at_cursor(self):
        self.console.drain()
        self.console.type(b"i1\x1b[D \r")
        self.console.read_until(b"[Session 1 ", timeout=1)
        self.console.type(b"ready\r")
        self.assertEqual(receive(self.client, 6), b"ready\n")

    def test_line_left_and_right_arrows_insert_at_cursor(self):
        self.console.attach(1)
        self.console.type(b"ac\x1b[Db\x1b[Cd\r")
        self.assertEqual(receive(self.client, 5), b"abcd\n")

    def test_backspace_and_delete_erase_at_cursor(self):
        self.console.attach(1)
        self.console.type(b"abXcd\x1b[2D\x7f\x1b[3~Z\r")
        self.assertEqual(receive(self.client, 5), b"abZd\n")

    def test_home_end_variants_and_arrow_boundaries(self):
        self.console.attach(1)
        for home, end in ((b"\x1b[H", b"\x1b[F"), (b"\x1bOH", b"\x1bOF"),
                          (b"\x1b[1~", b"\x1b[4~"), (b"\x1b[7~", b"\x1b[8~")):
            with self.subTest(home=home, end=end):
                self.console.type(b"b" + home + b"\x1b[99D\x7fa" + end + b"\x1b[99C\x1b[3~c\r")
                self.assertEqual(receive(self.client, 4), b"abc\n")

    def test_split_escape_sequences_and_application_cursor_keys(self):
        self.console.attach(1)
        self.console.type(b"ac\x1b")
        self.console.drain()
        self.console.type(b"O")
        self.console.drain()
        self.console.type(b"Db\x1b[")
        self.console.drain()
        self.console.type(b"1")
        self.console.drain()
        self.console.type(b"Cd\r")
        self.assertEqual(receive(self.client, 5), b"abcd\n")

    def test_utf8_insert_and_delete_use_character_boundaries_and_columns(self):
        self.console.attach(1)
        self.console.type("甲🙂乙".encode() + b"\x1b[D")
        output = self.console.drain()
        self.assertTrue(output.endswith(b"\x1b[2D"), output)
        character = "中".encode()
        self.console.type(character[:1])
        self.assertEqual(self.console.drain(), b"")
        self.console.type(character[1:])
        output = self.console.drain()
        self.assertEqual(output, "中乙".encode() + b"\x1b[2D")
        self.console.type(b"\x1b[D\x7f\x1b[3~\r")
        self.assertEqual(receive(self.client, len("甲乙\n".encode())), "甲乙\n".encode())

    def test_connection_notice_restores_draft_and_cursor(self):
        self.console.drain()
        self.console.type(b"i1\x1b[D")
        self.console.drain()
        self.console.connect()
        self.console.read_until(b"Session 2 connected")
        output = self.console.drain()
        self.assertIn(b"nc-multi> i1\x1b[1D", output)
        self.console.type(b" \r")
        self.console.read_until(b"[Session 1 ")
        self.console.type(b"ready\r")
        self.assertEqual(receive(self.client, 6), b"ready\n")

    def test_clear_and_detach_reset_cursor_and_incomplete_escape(self):
        self.console.attach(1)
        self.console.type(b"discard\x1b[3D\x15kept\r")
        self.assertEqual(receive(self.client, 5), b"kept\n")
        self.console.type(b"discard\x1b[D\x1b[\x03fresh\r")
        self.assertEqual(receive(self.client, 6), b"fresh\n")
        self.console.type(b"discard\x1b[H\x1b[")
        self.console.detach()
        self.console.attach(1)
        self.console.type(b"new\r")
        self.assertEqual(receive(self.client, 4), b"new\n")

    def test_unknown_escape_sequences_do_not_leak_into_commands(self):
        self.console.attach(1)
        self.console.type(b"a\x1b[A\x1b[B\x1b[200~b\x1b[201~\x1b[" + b"9" * 40 + b"Dc\r")
        self.assertEqual(receive(self.client, 4), b"abc\n")
        self.console.type(b"ok\x1b[\r")
        self.assertEqual(receive(self.client, 3), b"ok\n")

    def test_midline_utf8_overflow_discards_entire_command(self):
        self.console.attach(1)
        self.console.type(b"x" * (LINE_LIMIT - 1) + b"\x1b[H" + "中".encode() + b"\r")
        self.console.read_until(b"entire line discarded")
        self.console.type(b"next\r")
        self.assertEqual(receive(self.client, 5), b"next\n")

    def test_raw_mode_forwards_editing_keys_unchanged(self):
        self.console.attach(1, raw=True)
        payload = b"a\x1b[D\x1bOC\x1b[H\x1b[3~\x7f\x15\r"
        self.console.type(payload)
        self.assertEqual(receive(self.client, len(payload)), payload)
        self.assertEqual(self.console.drain(), b"")


if __name__ == "__main__":
    unittest.main()

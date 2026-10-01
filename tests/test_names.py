"""Persistent IP names and remarks exercised through SQLite and a real console."""

import json
from pathlib import Path
import re
import select
import sqlite3
import tempfile
import unittest

from nc_multi import IPNames
from test_nc_multi import RunningConsole, receive


def read_names(path):
    import contextlib
    with contextlib.closing(sqlite3.connect(path)) as db:
        return dict(db.execute("SELECT ip, name FROM hosts WHERE name != ''"))


class NameDatabaseTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "nc-multi" / "names.db"

    def test_failed_transaction_preserves_existing_record_and_cache(self):
        names = IPNames(self.path)
        names.set("192.0.2.10", "original")
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TRIGGER refuse_update BEFORE INSERT ON hosts "
                       "BEGIN SELECT RAISE(ABORT, 'write refused'); END")
        db.close()
        with self.assertRaises(sqlite3.IntegrityError):
            names.set("192.0.2.10", "replacement")
        self.assertEqual(names.values, {"192.0.2.10": "original"})
        self.assertEqual(read_names(self.path), names.values)

    def test_corruption_after_startup_is_not_overwritten(self):
        names = IPNames(self.path)
        names.set("192.0.2.10", "original")
        self.path.write_bytes(b"broken database")
        with self.assertRaises(sqlite3.DatabaseError):
            names.set("192.0.2.11", "replacement")
        self.assertEqual(self.path.read_bytes(), b"broken database")
        self.assertEqual(names.values, {"192.0.2.10": "original"})

    def test_deleted_database_is_not_recreated_by_read_or_write(self):
        names = IPNames(self.path)
        names.set("192.0.2.10", "original")
        self.path.unlink()
        for operation in (names.refresh, lambda: names.set("192.0.2.11", "new")):
            with self.assertRaises(sqlite3.OperationalError):
                operation()
            self.assertFalse(self.path.exists())
        restored = IPNames(self.path)
        restored.set("192.0.2.11", "new")
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_busy_database_does_not_change_names(self):
        names = IPNames(self.path)
        names.set("192.0.2.10", "original")
        db = sqlite3.connect(self.path)
        try:
            db.execute("BEGIN EXCLUSIVE")
            with self.assertRaisesRegex(sqlite3.OperationalError, "locked"):
                names.set("192.0.2.10", "replacement")
        finally:
            db.rollback()
            db.close()
        self.assertEqual(names.values, {"192.0.2.10": "original"})
        self.assertEqual(read_names(self.path), names.values)
        names.set("192.0.2.10", "replacement")
        self.assertEqual(IPNames(self.path).values, {"192.0.2.10": "replacement"})

    def test_startup_lock_recovers_on_later_read_or_write(self):
        original = IPNames(self.path)
        original.set("192.0.2.10", "original")
        db = sqlite3.connect(self.path)
        try:
            db.execute("BEGIN IMMEDIATE")
            reader, writer = IPNames(self.path), IPNames(self.path)
            self.assertTrue(reader.error)
            self.assertTrue(writer.error)
        finally:
            db.rollback()
            db.close()
        reader.refresh()
        self.assertEqual(reader.values, {"192.0.2.10": "original"})
        writer.set("192.0.2.11", "recovered")
        self.assertEqual(IPNames(self.path).values,
                         {"192.0.2.10": "original", "192.0.2.11": "recovered"})

    def test_invalid_legacy_file_is_not_partially_imported(self):
        self.path.parent.mkdir()
        legacy = self.path.with_name("names.json")
        for data in ("{broken", "[]", '{"bad-ip":"host"}',
                     '{"192.0.2.10":123}',
                     '{"192.0.2.10":"valid", "192.0.2.11":"\\u001b[2J"}'):
            with self.subTest(data=data):
                legacy.write_text(data, encoding="utf-8")
                names = IPNames(self.path)
                self.assertTrue(names.error)
                self.assertEqual(names.values, {})
                with self.assertRaises(ValueError):
                    names.set("192.0.2.10", "replacement")
                self.assertEqual(legacy.read_text(encoding="utf-8"), data)
        legacy.write_text('{"192.0.2.12":"recovered"}')
        self.assertEqual(IPNames(self.path).values, {"192.0.2.12": "recovered"})

    def test_legacy_import_runs_once_and_preserves_original_file(self):
        self.path.parent.mkdir()
        legacy = self.path.with_name("names.json")
        original = json.dumps({"192.0.2.10": "测试机"}, ensure_ascii=False)
        legacy.write_text(original, encoding="utf-8")
        names = IPNames(self.path)
        self.assertEqual(names.values, {"192.0.2.10": "测试机"})
        names.set("192.0.2.10")
        self.assertEqual(IPNames(self.path).values, {})
        self.assertEqual(legacy.read_text(encoding="utf-8"), original)

    def test_name_and_note_updates_preserve_other_fields_and_ips(self):
        first = IPNames(self.path)
        second = IPNames(self.path)
        first.set("192.0.2.10", "测试机")
        second.set("192.0.2.10", "用于接口测试", "note")
        first.set("192.0.2.11", "database")
        restored = IPNames(self.path)
        self.assertEqual(restored.records["192.0.2.10"], ("测试机", "用于接口测试"))
        self.assertEqual(restored.values, {"192.0.2.10": "测试机", "192.0.2.11": "database"})
        restored.set("192.0.2.10")
        self.assertEqual(IPNames(self.path).records["192.0.2.10"], ("", "用于接口测试"))
        restored.set("192.0.2.10", None, "note")
        self.assertNotIn("192.0.2.10", IPNames(self.path).records)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_invalid_values_do_not_change_database(self):
        names = IPNames(self.path)
        for field, limit in (("name", 64), ("note", 512)):
            for value in ("", " ", "x" * (limit + 1), "bad\nname", "\x1b[2J", "\ud800"):
                with self.subTest(field=field, value=repr(value)):
                    with self.assertRaises(ValueError):
                        names.set("192.0.2.10", value, field)
        self.assertEqual(names.records, {})
        self.assertEqual(IPNames(self.path).records, {})

    def test_sql_fragments_are_stored_as_literal_text(self):
        names = IPNames(self.path)
        text = "x'); DROP TABLE hosts;--"
        names.set("192.0.2.10", text)
        names.set("192.0.2.10", text, "note")
        self.assertEqual(IPNames(self.path).records, {"192.0.2.10": (text, text)})


class NameIntegrationTests(unittest.TestCase):
    def start(self, **kwargs):
        console = RunningConsole(**kwargs)
        self.addCleanup(console.close)
        return console

    def test_shared_names_reconnect_and_id_routing(self):
        console = self.start()
        first, second = console.connect(), console.connect()
        console.read_until(b"Session 2 connected")
        console.command("name 1 测试机")
        console.read_until("Name saved for 127.0.0.1: 测试机".encode())
        console.command("ls")
        output = console.read_until(b"nc-multi> ")
        rows = [row for row in output.splitlines() if re.match(rb"[12]\s+127\.0\.0\.1:", row)]
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row.endswith("测试机".encode()) for row in rows))
        console.command("i 2")
        output = console.read_until(b"[Session 2 ")
        self.assertIn("(测试机); line".encode(), output)
        console.type(b"second-only\r")
        self.assertEqual(receive(second, 12), b"second-only\n")
        self.assertFalse(select.select([first], [], [], 0.1)[0])
        console.detach()
        console.command("close 1")
        console.read_until(b"Closed session 1")
        self.assertEqual(first.recv(1), b"")
        console.connect()
        output = console.read_until(b"Session 3 connected")
        self.assertRegex(output, rb"Session 3 connected from 127\.0\.0\.1:\d+ \(" + "测试机".encode() + rb"\)")

    def test_ip_name_and_removal_survive_restarts(self):
        with tempfile.TemporaryDirectory() as directory:
            first = self.start(config_home=directory)
            first.command("name 127.0.0.1 测试 server")
            first.read_until("Name saved for 127.0.0.1: 测试 server".encode())
            first.stop()
            second = self.start(config_home=directory)
            second.connect()
            output = second.read_until(b"Session 1 connected")
            self.assertIn("(测试 server)".encode(), output)
            second.command("unname 1")
            second.read_until(b"Name removed for 127.0.0.1")
            self.assertEqual(read_names(Path(directory) / "nc-multi/names.db"), {})
            second.stop()
            third = self.start(config_home=directory)
            third.connect()
            output = third.read_until(b"Session 1 connected")
            self.assertNotIn("测试 server".encode(), output)

    def test_two_listeners_preserve_each_others_saved_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            first = self.start(config_home=directory)
            second = self.start(config_home=directory)
            first.command("name 192.0.2.10 first-host")
            first.read_until(b"Name saved for 192.0.2.10")
            second.command("name 192.0.2.11 second-host")
            second.read_until(b"Name saved for 192.0.2.11")
            path = Path(directory) / "nc-multi/names.db"
            self.assertEqual(read_names(path),
                             {"192.0.2.10": "first-host", "192.0.2.11": "second-host"})
            second.command("note 192.0.2.10 shared remark")
            second.read_until(b"Note saved for 192.0.2.10")
            first.command("names 192.0.2.10")
            output = first.read_until(b"nc-multi> ")
            self.assertIn(b"first-host", output)
            self.assertIn(b"shared remark", output)
            second.command("unname 192.0.2.10")
            second.read_until(b"Name removed for 192.0.2.10")
            first.command("name 192.0.2.12 third-host")
            first.read_until(b"Name saved for 192.0.2.12")
            self.assertEqual(read_names(path),
                             {"192.0.2.11": "second-host", "192.0.2.12": "third-host"})

    def test_notes_are_queryable_offline_and_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            first = self.start(config_home=directory)
            client = first.connect()
            first.read_until(b"Session 1 connected")
            first.command("name 1 测试机")
            first.read_until(b"Name saved for 127.0.0.1")
            first.command("note 1 张三维护，用于接口测试")
            first.read_until(b"Note saved for 127.0.0.1")
            first.command("close 1")
            first.read_until(b"Closed session 1")
            self.assertEqual(client.recv(1), b"")
            first.command("names 127.0.0.1")
            output = first.read_until(b"nc-multi> ")
            self.assertIn("测试机".encode(), output)
            self.assertIn("张三维护，用于接口测试".encode(), output)
            first.stop()
            second = self.start(config_home=directory)
            second.command("names")
            output = second.read_until(b"nc-multi> ")
            self.assertIn("张三维护，用于接口测试".encode(), output)
            second.command("unnote 127.0.0.1")
            second.read_until(b"Note removed for 127.0.0.1")
            second.command("names 127.0.0.1")
            output = second.read_until(b"nc-multi> ")
            self.assertIn("测试机".encode(), output)
            self.assertIn(b"Note: -", output)
            second.command("unname 127.0.0.1")
            second.read_until(b"Name removed for 127.0.0.1")
            second.command("names")
            second.read_until(b"(no saved names or notes)")

    def test_invalid_commands_and_failed_save_leave_listener_usable(self):
        console = self.start()
        console.connect()
        console.read_until(b"Session 1 connected")
        for command, marker in (("name", b"Usage:"), ("unname 1 extra", b"Usage:"),
                                ("name 99 missing", b"No such session"),
                                ("name invalid nope", b"Name unchanged:"),
                                ("name 1 " + "x" * 65, b"Name unchanged:")):
            console.command(command)
            console.read_until(marker)
        db = sqlite3.connect(console.config_home / "nc-multi/names.db")
        try:
            db.execute("BEGIN EXCLUSIVE")
            console.command("name 1 cannot-save")
            console.read_until(b"Name unchanged:")
            console.connect()
            console.read_until(b"Session 2 connected")
        finally:
            db.rollback()
            db.close()
        console.command("ls")
        output = console.read_until(b"nc-multi> ")
        self.assertNotIn(b"cannot-save", output)
        self.assertIsNone(console.process.poll())

    def test_corrupt_file_warns_without_stopping_listener(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nc-multi/names.json"
            path.parent.mkdir()
            path.write_text("{broken")
            console = self.start(config_home=directory)
            self.assertIn(b"Cannot load names", console.output)
            console.connect()
            console.read_until(b"Session 1 connected")
            console.command("name 1 replacement")
            console.read_until(b"Name unchanged:")
            self.assertEqual(path.read_text(), "{broken")
            self.assertIsNone(console.process.poll())


if __name__ == "__main__":
    unittest.main()

"""Persistent execution history tested with loopback peers and harmless scripts."""

import base64
import hashlib
import os
from pathlib import Path
import re
import select
import shlex
import shutil
import signal
import sqlite3
import subprocess
import tempfile
import time
import unittest
from types import SimpleNamespace

from history_store import HistoryStore, OUTPUT_LIMIT, PAGE_SIZE
from nc_multi import BatchResult
from test_nc_multi import RunningConsole


class HistoryStoreTests(unittest.TestCase):
    def test_missing_execution_record_rejects_the_whole_update(self):
        with tempfile.TemporaryDirectory() as directory:
            store = HistoryStore(Path(directory) / 'history.db')
            session = SimpleNamespace(id=1, ip='192.0.2.10', peer='192.0.2.10:1234', connected_at=1000.)
            results = [BatchResult(0, 1, session.peer, b'\x1eTEST:') for _ in range(2)]
            store.create_batch(Path('/private/check.sh'), 'test-digest', [(session, r) for r in results])
            with store.connection() as db, db:
                db.execute('DELETE FROM script_runs WHERE id=?', (results[1].record_id,))
            for result in results:
                result.feed(b'\x1eTEST:start\x1f\x1eTEST:script\x1fhello\x1eTEST:end:0\x1f')
            with self.assertRaisesRegex(sqlite3.DatabaseError, 'missing'):
                store.update(results)
            self.assertEqual(store.get(results[0].record_id)['state'], 'queued')

    def test_more_than_twenty_runs_persist_with_version_and_filters(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'history.db'
            store = HistoryStore(path)
            session = SimpleNamespace(id=1, ip='192.0.2.10', peer='192.0.2.10:1234', connected_at=1000.)
            for index in range(25):
                result = BatchResult(0, 1, session.peer, b'\x1eTEST:')
                store.create_batch(Path('/private/check.sh'), str(index), [(session, result)])
                result.feed(b'\x1eTEST:start\x1f\x1eTEST:script\x1fhello\x1eTEST:end:0\x1f')
                store.update([result])
            rows, count, started = store.query(script='check.sh')
            self.assertEqual((len(rows), count, started), (PAGE_SIZE, 25, {1}))
            self.assertEqual(rows[0]['sha256'], '24')
            self.assertEqual(len(store.query(ip='192.0.2.10', page=2)[0]), 5)
            other = HistoryStore(path)
            self.assertEqual(other.query(session=1)[1], 0)
            self.assertEqual(other.query(ip='192.0.2.10')[1], 25)
            self.assertEqual(other.get(1)['output'], b'hello')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_frame_boundaries_preserve_only_batch_output_and_script_start(self):
        prefix = b'\x1eTEST:'
        wire = b'PROMPT' + prefix + b'start\x1fdecode\n' + prefix + b'script\x1fresult\n' + prefix + b'end:7\x1fNEXT-PROMPT'
        for split in range(len(wire) + 1):
            result = BatchResult(1, 1, '127.0.0.1:1', prefix)
            result.feed(wire[:split])
            if result.state in ('queued', 'sent', 'running'):
                result.feed(wire[split:])
            self.assertEqual(b''.join(result.log.parts), b'decode\nresult\n')
            self.assertEqual((result.state, result.exit_code), ('failed', 7))
            self.assertIsNotNone(result.received_at)
            self.assertIsNotNone(result.started_at)
            self.assertIsNotNone(result.finished_at)

    def test_decoder_failure_does_not_claim_script_started(self):
        result = BatchResult(1, 1, '127.0.0.1:1', b'\x1eTEST:')
        result.feed(b'\x1eTEST:start\x1fdecode failed\x1eTEST:end:125\x1f')
        self.assertEqual(result.exit_code, 125)
        self.assertIsNone(result.started_at)
        self.assertEqual(b''.join(result.log.parts), b'decode failed')


class HistoryIntegrationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='nc-history-test-')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.path = self.root / 'check script.sh'
        self.source = "# SOURCE_ONLY_SECRET_d802b3\nprintf 'RESULT-%s\\n' \"$NODE\"\nif [[ $NODE == first ]]; then exit 7; fi\n"
        self.path.write_text(self.source)
        self.console = self.start()

    def start(self, *args):
        console = RunningConsole(*args, config_home=self.root)
        self.addCleanup(console.close)
        return console

    def db(self):
        db = sqlite3.connect(self.root / 'nc-multi' / 'history.db')
        db.row_factory = sqlite3.Row
        self.addCleanup(db.close)
        return db

    def bash_client(self, node, trace=False, **environment):
        if not shutil.which('bash'):
            self.skipTest('Bash is required')
        client = self.console.connect()
        child = subprocess.Popen([shutil.which('bash'), '--noprofile', '--norc', '-i'] + (['-x'] if trace else []),
                                 stdin=client, stdout=client, stderr=client,
                                 env={**os.environ, 'NODE': node, 'PS1': 'TEST> ', **environment}, start_new_session=True)
        def close():
            if child.poll() is None:
                child.terminate()
                try: child.wait(timeout=3)
                except subprocess.TimeoutExpired: child.kill(); child.wait(timeout=3)
        self.addCleanup(close)
        return client

    def command(self, text):
        self.console.command(text)
        return self.console.read_until(b'nc-multi> ')

    def dispatch(self):
        self.console.command('batch ' + shlex.quote(str(self.path)))
        return self.console.read_until(b'Use jobs ')

    @staticmethod
    def token(client):
        data = bytearray()
        while not data.endswith(b'\n'):
            part = client.recv(65536)
            if not part: raise AssertionError('batch was not delivered')
            data.extend(part)
        return b'\x1e' + re.search(rb'NCMB_[0-9a-f]{32}', data)[0] + b':'

    def test_two_real_clients_logs_versions_and_late_connection(self):
        self.bash_client('first')
        self.bash_client('second')
        self.console.read_until(b'Session 2 connected')
        self.dispatch()
        self.console.read_until(b'Session 1: failed, exit 7.')
        self.console.read_until(b'Session 2: ok, exit 0.')
        self.console.connect()
        self.console.read_until(b'Session 3 connected')
        listing = self.command('history "check script.sh"')
        self.assertIn(b'2 records', listing)
        self.assertIn(b'confirmation for this filter: 3.', listing)
        rows = self.db().execute('SELECT * FROM script_runs ORDER BY id').fetchall()
        self.assertEqual([r['exit_code'] for r in rows], [7, 0])
        self.assertTrue(all(r['started_at'] and r['received_at'] and r['finished_at'] for r in rows))
        self.assertIn(b'RESULT-first', rows[0]['output'])
        self.assertNotIn(b'RESULT-second', rows[0]['output'])
        self.assertNotIn(b'SOURCE_ONLY_SECRET', b''.join(r['output'] for r in rows))
        result = self.command('result 1')
        self.assertIn(b'exit: 7', result)
        self.assertIn(b'RESULT-first', result)
        self.assertIn(hashlib.sha256(self.source.encode()).hexdigest().encode(), result)
        self.command('close all')
        self.assertIn(b'2 records', self.command('history'))
        self.assertIn(b'RESULT-second', self.command('result 2'))

    def test_traced_client_does_not_archive_transport_source_or_lose_trace_setting(self):
        self.bash_client('second', trace=True)
        self.console.read_until(b'Session 1 connected')
        self.dispatch()
        self.console.read_until(b'Session 1: ok, exit 0.')
        result = self.command('result 1')
        self.assertIn(b'RESULT-second', result)
        row = self.db().execute('SELECT output FROM script_runs').fetchone()
        self.assertNotIn(base64.b64encode(self.source.encode()), row['output'])
        self.assertNotIn(b'SOURCE_ONLY_SECRET', row['output'])
        self.console.command('i 1')
        self.console.read_until(b'[Session 1 ')
        self.console.drain()
        self.console.type(b'printf "TRACE=%s\\n" "${-//[^x]/}"\r')
        self.console.read_until(b'TRACE=x\r\n')

    def test_exported_verbose_mode_does_not_archive_source_or_change_parent_flags(self):
        self.bash_client('second', SHELLOPTS='verbose')
        self.console.read_until(b'Session 1 connected')
        self.dispatch()
        self.console.read_until(b'Session 1: ok, exit 0.')
        self.assertIn(b'RESULT-second', self.command('result 1'))
        row = self.db().execute('SELECT output FROM script_runs').fetchone()
        self.assertNotIn(b'SOURCE_ONLY_SECRET', row['output'])
        self.assertNotIn(base64.b64encode(self.source.encode()), row['output'])
        self.console.command('i 1')
        self.console.read_until(b'[Session 1 ')
        self.console.drain()
        self.console.type(b'printf "VERBOSE=%s\\n" "${-//[^v]/}"\r')
        self.console.read_until(b'VERBOSE=v\r\n')

    def test_restart_preserves_history_without_reusing_session_identity(self):
        self.bash_client('second')
        self.console.read_until(b'Session 1 connected')
        self.dispatch()
        self.console.read_until(b'Session 1: ok, exit 0.')
        self.console.stop()
        self.console = self.start()
        self.console.connect()
        self.console.read_until(b'Session 1 connected')
        self.assertIn(b'0 records', self.command('history 1'))
        listing = self.command('history 127.0.0.1')
        self.assertIn(b'1 records', listing)
        self.assertIn(b'old:1', listing)
        self.assertIn(b'confirmation for this filter: 1.', listing)
        self.assertIn(b'RESULT-second', self.command('result 1'))

    def test_crashed_console_reports_unfinished_run_as_unknown_without_redispatch(self):
        client = self.console.connect()
        self.console.read_until(b'Session 1 connected')
        self.dispatch()
        token = self.token(client)
        client.sendall(token+b'start\x1f'+token+b'script\x1fIN-PROGRESS')
        self.assertIn(b'running', self.command('history'))
        self.console.stop(signal.SIGKILL)
        self.console = self.start()
        new = self.console.connect()
        self.console.read_until(b'Session 1 connected')
        listing = self.command('history')
        self.assertIn(b'unknown', listing)
        self.assertFalse(select.select([new], [], [], .1)[0], 'a historical task was replayed')
        result = self.command('result 1')
        self.assertIn(b'exit: unknown', result)
        self.assertIn(b'IN-PROGRESS', result)

    def test_busy_skip_and_disconnect_are_not_success(self):
        client = self.console.connect()
        self.console.read_until(b'Session 1 connected')
        self.dispatch()
        token = self.token(client)
        self.dispatch()
        self.assertIn(b'skipped-busy', self.command('history'))
        client.sendall(token+b'start\x1f'+token+b'script\x1fpartial'+token[:5])
        client.close()
        self.console.read_until(b'Session 1 disconnected')
        self.assertIn(b'disconnected', self.command('history'))
        rows = self.db().execute('SELECT * FROM script_runs ORDER BY id').fetchall()
        self.assertEqual([r['state'] for r in rows], ['disconnected', 'skipped-busy'])
        self.assertTrue(all(r['exit_code'] is None for r in rows))
        self.assertEqual(rows[0]['output'], b'partial'+token[:5])
        self.assertIsNone(rows[1]['started_at'])

    def test_long_output_is_bounded_paginated_and_terminal_controls_are_escaped(self):
        client = self.console.connect()
        self.console.read_until(b'Session 1 connected')
        self.dispatch()
        token = self.token(client)
        output = b'A' * (OUTPUT_LIMIT + 20) + b'\x1b[2JFINAL-TAIL\n'
        client.sendall(b'BEFORE'+token+b'start\x1f'+token+b'script\x1f'+output+token+b'end:0\x1fAFTER')
        self.console.read_until(b'Session 1: ok, exit 0.')
        result = self.command('result 1')
        self.assertIn(b'page 16/16', result)
        self.assertIn(b'FINAL-TAIL', result)
        self.assertIn(b'\\u001b[2J', result)
        self.assertNotIn(b'\x1b[2J', result)
        row = self.db().execute('SELECT * FROM script_runs').fetchone()
        self.assertEqual(row['output'], output[-OUTPUT_LIMIT:])
        self.assertEqual(row['dropped'], len(output)-OUTPUT_LIMIT)
        self.assertIn(b'page 1/16', self.command('result 1 1'))

    def test_locked_database_prevents_dispatch_then_recovers(self):
        client = self.console.connect()
        self.console.read_until(b'Session 1 connected')
        db = self.db()
        db.execute('BEGIN IMMEDIATE')
        self.assertIn(b'Batch not started', self.command('batch '+shlex.quote(str(self.path))))
        self.assertFalse(select.select([client], [], [], .1)[0])
        db.rollback()
        self.dispatch()
        self.assertTrue(self.token(client))
        self.assertEqual(db.execute('SELECT COUNT(*) FROM batch_jobs').fetchone()[0], 1)

    def test_partial_history_insert_failure_does_not_dispatch_any_client(self):
        clients = [self.console.connect() for _ in range(2)]
        self.console.read_until(b'Session 2 connected')
        db = self.db()
        db.execute("CREATE TRIGGER reject_second BEFORE INSERT ON script_runs WHEN NEW.session_id=2 BEGIN SELECT RAISE(ABORT, 'reject second'); END")
        db.commit()
        self.assertIn(b'Batch not started', self.command('batch '+shlex.quote(str(self.path))))
        self.assertFalse(select.select(clients, [], [], .1)[0])
        self.assertEqual(db.execute('SELECT COUNT(*) FROM script_runs').fetchone()[0], 0)
        self.assertEqual(db.execute('SELECT COUNT(*) FROM batch_jobs').fetchone()[0], 0)

    def test_result_write_failure_is_retried_and_blocks_new_batches(self):
        client = self.console.connect()
        self.console.read_until(b'Session 1 connected')
        self.dispatch()
        token = self.token(client)
        db = self.db()
        db.execute('BEGIN EXCLUSIVE')
        client.sendall(token+b'start\x1f'+token+b'script\x1fSAVED-LATER'+token+b'end:7\x1f')
        self.console.read_until(b'Execution history could not be saved')
        self.assertIn(b'Batch not started', self.command('batch '+shlex.quote(str(self.path))))
        self.assertFalse(select.select([client], [], [], .1)[0])
        db.rollback()
        self.console.read_until(b'Pending execution history saved')
        result = self.command('result 1')
        self.assertIn(b'exit: 7', result)
        self.assertIn(b'SAVED-LATER', result)

    def test_idle_timeout_preserves_unknown_result(self):
        self.console.stop()
        self.console = self.start('-t', '1')
        client = self.console.connect()
        self.console.read_until(b'Session 1 connected')
        self.dispatch()
        token = self.token(client)
        client.sendall(token+b'start\x1f'+token+b'script\x1fBEFORE-TIMEOUT')
        self.console.read_until(b'Session 1 idle timeout', timeout=4)
        result = self.command('result 1')
        self.assertIn(b'idle-timeout', result)
        self.assertIn(b'exit: unknown', result)
        self.assertIn(b'BEFORE-TIMEOUT', result)


if __name__ == '__main__':
    unittest.main()

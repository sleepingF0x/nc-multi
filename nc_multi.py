#!/usr/bin/env python3
"""A standard-library-only TCP session console for Linux and macOS."""

from __future__ import annotations

import argparse
import collections
import dataclasses
from contextlib import closing
import ipaddress
import json
import os
from pathlib import Path
import selectors
import secrets
import shlex
import signal
import socket
import sqlite3
import stat
import sys
import termios
import time
import tty
import unicodedata


READ_SIZE = 65536
SEND_LIMIT = 65536
LINE_LIMIT = 8192
CONTROL_LIMIT = 65536
DEFAULT_IDLE_TIMEOUT = 900
JOB_LIMIT = 20
PENDING_JOB_STATES = {"queued", "sent", "running"}
PROMPT = b"nc-multi> "
HELP = """Commands:
  sessions / ls          List sessions, including retained disconnected sessions
  interact ID / use ID   Attach with local echo and line editing (plain Bash/TCP)
  interact ID raw        Attach without local echo (for a remote PTY)
  close ID               Close the connection and discard its saved output
  name ID|IP NAME         Save a shared name for this IPv4 address
  unname ID|IP            Remove the saved name for this IPv4 address
  note ID|IP TEXT         Save a separate remark for this IPv4 address
  unnote ID|IP            Remove the remark, keeping the name
  names [ID|IP]           Show saved names and remarks, including offline hosts
  batch PATH             Run a local Bash script on currently connected sessions
  jobs [ID]              Show batch delivery states and remote exit codes
  help                   Show this help
  quit / exit            Stop the listener and close every connection

While attached: Ctrl+] returns to this menu without closing the connection.
Line mode: Enter sends a line; Backspace/Ctrl+U edit; Ctrl+C clears local input.
Raw mode: every byte except Ctrl+] is forwarded, including Ctrl+C and Ctrl+D.
Session management does not create a remote PTY or recover a broken TCP stream.
Idle timeout counts time without submitted input; remote output does not reset it.
"""


class Buffer:
    """A bounded byte FIFO; overflow drops oldest bytes, never splits routing."""

    def __init__(self, limit: int):
        self.limit = limit
        self.parts = collections.deque()
        self.size = 0
        self.dropped = 0

    def append(self, data: bytes) -> None:
        if not data:
            return
        if self.parts and len(self.parts[-1]) + len(data) <= 8192:
            self.parts[-1] += data
        else:
            self.parts.append(data)
        self.size += len(data)
        overflow = max(0, self.size - self.limit)
        self.dropped += overflow
        self.consume(overflow)

    def consume(self, count: int) -> None:
        while count:
            part = self.parts[0]
            taken = min(count, len(part))
            if taken == len(part):
                self.parts.popleft()
            else:
                self.parts[0] = part[taken:]
            count -= taken
            self.size -= taken

    def head(self) -> bytes:
        return self.parts[0][:READ_SIZE] if self.parts else b""


@dataclasses.dataclass
class BatchResult:
    job_id: int
    session_id: int
    peer: str
    marker: bytes
    state: str = "queued"
    exit_code: int = None
    pending: bytes = b""

    def feed(self, data: bytes) -> bytes:
        """Remove only this run's control frames, retaining split frame prefixes."""
        data = self.pending + data
        self.pending = b""
        output = bytearray()
        while data:
            position = data.find(self.marker)
            if position < 0:
                keep = next((n for n in range(min(len(data), len(self.marker) - 1), 0, -1)
                             if data.endswith(self.marker[:n])), 0)
                output.extend(data[:-keep] if keep else data)
                self.pending = data[-keep:] if keep else b""
                break
            output.extend(data[:position])
            data = data[position:]
            end = data.find(b"\x1f", len(self.marker))
            if end < 0 and len(data) <= len(self.marker) + 16:
                self.pending = data
                break
            body = data[len(self.marker):end] if end >= 0 else b""
            if body == b"start":
                self.state = "running"
            elif (self.state == "running" and body.startswith(b"end:") and
                  1 <= len(body[4:]) <= 3 and body[4:].isdigit() and int(body[4:]) <= 255):
                self.exit_code = int(body[4:])
                self.state = "ok" if self.exit_code == 0 else "failed"
                output.extend(data[end + 1:])
                break
            else:
                # An invalid frame is ordinary output. Never retain an unbounded tail.
                output.extend(data[:1])
                data = data[1:]
                continue
            data = data[end + 1:]
        return bytes(output)


@dataclasses.dataclass
class Session:
    id: int
    sock: socket.socket
    peer: str
    output: Buffer
    created: float = dataclasses.field(default_factory=time.monotonic)
    last_input: float = dataclasses.field(default_factory=time.monotonic)
    connected: bool = True
    close_reason: str = ""
    outgoing: bytearray = dataclasses.field(default_factory=bytearray)
    batch: BatchResult = None

    @property
    def ip(self) -> str:
        return self.peer.rsplit(":", 1)[0]


class IPNames:
    """Persistent per-IP labels, updated transactionally in SQLite."""

    def __init__(self, path=None):
        self.path = path
        self.records = {}
        self.error = ""
        self.retry_initialization = False
        if path is not None:
            try:
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                try:
                    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
                except FileExistsError:
                    pass
                else:
                    os.close(fd)
                with closing(self._connect()) as db, db:
                    db.execute("BEGIN IMMEDIATE")
                    db.execute("CREATE TABLE IF NOT EXISTS hosts "
                               "(ip TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', "
                               "note TEXT NOT NULL DEFAULT '')")
                    db.execute("CREATE TABLE IF NOT EXISTS metadata "
                               "(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                    if not db.execute("SELECT 1 FROM metadata WHERE key = 'names_json_imported'").fetchone():
                        legacy = path.with_name("names.json")
                        try:
                            values = json.loads(legacy.read_text(encoding="utf-8"))
                        except FileNotFoundError:
                            values = {}
                        if not isinstance(values, dict):
                            raise ValueError("names.json must map IPv4 addresses to names")
                        for ip, name in values.items():
                            self.validate(ip, name, "name")
                            db.execute("INSERT INTO hosts (ip, name) VALUES (?, ?) "
                                       "ON CONFLICT(ip) DO NOTHING", (ip, name))
                        db.execute("INSERT INTO metadata VALUES ('names_json_imported', '1')")
                    records = self._read(db)
                self.records = records
            except (OSError, ValueError, sqlite3.Error) as error:
                self.retry_initialization = isinstance(error, sqlite3.OperationalError) and str(error).startswith(
                    ("database is locked", "database table is locked", "database schema is locked"))
                action = "Retry a name/note/names command shortly." if self.retry_initialization else "Fix the file and restart."
                self.error = f"Cannot load names database {path}: {error}. {action}"

    def _connect(self):
        # Creation goes through __init__ with mode 0600, never a later read/write.
        return sqlite3.connect(self.path.absolute().as_uri() + "?mode=rw", uri=True, timeout=0)

    def _ensure_ready(self) -> None:
        if self.retry_initialization:
            recovered = IPNames(self.path)
            self.records = recovered.records
            self.error = recovered.error
            self.retry_initialization = recovered.retry_initialization
        if self.error:
            raise ValueError(self.error)

    @property
    def values(self) -> dict:
        return {ip: row[0] for ip, row in self.records.items() if row[0]}

    @staticmethod
    def validate(ip: str, value: str, field: str, allow_empty=False) -> None:
        try:
            ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            raise ValueError("expected a valid IPv4 address") from None
        limit = 64 if field == "name" else 512
        if allow_empty and value == "":
            return
        if not isinstance(value, str) or not 1 <= len(value) <= limit or not value.strip() or not value.isprintable():
            raise ValueError(f"{field} must contain 1-{limit} printable characters")

    def _read(self, db) -> dict:
        records = {}
        for ip, name, note in db.execute("SELECT ip, name, note FROM hosts ORDER BY ip"):
            self.validate(ip, name, "name", allow_empty=True)
            self.validate(ip, note, "note", allow_empty=True)
            records[ip] = (name, note)
        return records

    def refresh(self) -> None:
        self._ensure_ready()
        if self.path is not None:
            with closing(self._connect()) as db:
                self.records = self._read(db)

    def set(self, ip: str, value=None, field="name") -> None:
        self._ensure_ready()
        if field not in ("name", "note"):
            raise ValueError("unknown field")
        self.validate(ip, value if value is not None else "", field, allow_empty=value is None)
        value = value or ""
        if self.path is None:
            row = list(self.records.get(ip, ("", "")))
            row[0 if field == "name" else 1] = value
            if any(row):
                self.records[ip] = tuple(row)
            else:
                self.records.pop(ip, None)
            return
        # Each statement changes only the selected field, preserving other writers.
        sql = {"name": "INSERT INTO hosts (ip, name) VALUES (?, ?) ON CONFLICT(ip) DO UPDATE SET name=excluded.name",
               "note": "INSERT INTO hosts (ip, note) VALUES (?, ?) ON CONFLICT(ip) DO UPDATE SET note=excluded.note"}[field]
        with closing(self._connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(sql, (ip, value))
            db.execute("DELETE FROM hosts WHERE ip=? AND name='' AND note=''", (ip,))
            records = self._read(db)
        self.records = records


class Terminal:
    def __init__(self):
        self.input_fd = sys.stdin.fileno()
        self.output_fd = sys.stdout.fileno()
        self.attributes = None
        self.blocking = {}

    def __enter__(self):
        if not os.isatty(self.input_fd) or not os.isatty(self.output_fd):
            raise ValueError("run nc-multi in an interactive terminal (stdin and stdout must be TTYs)")
        self.attributes = termios.tcgetattr(self.input_fd)
        try:
            tty.setraw(self.input_fd, termios.TCSANOW)
            # Keep newline rendering for ordinary shells that emit LF, not CRLF.
            attributes = termios.tcgetattr(self.input_fd)
            attributes[1] = self.attributes[1]
            termios.tcsetattr(self.input_fd, termios.TCSANOW, attributes)
            # stdin/stdout can share one open file description (for example a PTY).
            self.blocking = {fd: os.get_blocking(fd) for fd in (self.input_fd, self.output_fd)}
            for fd in self.blocking:
                os.set_blocking(fd, False)
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, *_):
        try:
            if self.attributes is not None:
                termios.tcsetattr(self.input_fd, termios.TCSANOW, self.attributes)
        finally:
            for fd, blocking in self.blocking.items():
                os.set_blocking(fd, blocking)


class Console:
    def __init__(self, listener: socket.socket, terminal: Terminal, buffer_limit: int,
                 max_sessions: int, idle_timeout: int = DEFAULT_IDLE_TIMEOUT, names=None):
        self.listener = listener
        self.terminal = terminal
        self.buffer_limit = buffer_limit
        self.max_sessions = max_sessions
        self.idle_timeout = idle_timeout
        self.names = names if names is not None else IPNames()
        self.selector = selectors.DefaultSelector()
        self.sessions = {}
        self.next_id = 1
        self.active = None
        self.raw = False
        self.input_paused = False
        self.line = bytearray()
        self.line_overflow = False
        self.escape_state = 0
        self.control = Buffer(CONTROL_LIMIT)
        self.output_registered = False
        self.running = True
        self.jobs = {}
        self.next_job_id = 1

    def emit(self, text: str) -> None:
        self.control.append(text.encode("utf-8"))

    def prompt(self) -> None:
        self.control.append(PROMPT)

    def name_suffix(self, session: Session) -> str:
        name = self.names.records.get(session.ip, ("", ""))[0]
        return f" ({name})" if name else ""

    def notice(self, text: str) -> None:
        # Remote bytes are never rendered in the menu or in a different session.
        if self.active is None:
            self.control.append(b"\r\x1b[2K")
            self.emit(text + "\n")
            self.prompt()
            self.control.append(bytes(self.line))

    def run(self) -> None:
        self.selector.register(self.listener, selectors.EVENT_READ, "listener")
        self.selector.register(self.terminal.input_fd, selectors.EVENT_READ, "input")
        host, port = self.listener.getsockname()[:2]
        self.emit(f"Listening on {host}:{port}\nType help for commands. Ctrl+] detaches a session.\n")
        timeout_label = f"{self.idle_timeout}s without submitted input" if self.idle_timeout else "disabled"
        self.emit(f"Idle timeout: {timeout_label}.\n")
        if self.names.error:
            self.emit(f"[!] {self.names.error}\n")
        self.prompt()
        try:
            while self.running:
                self.update_output_interest()
                for key, mask in self.selector.select(timeout=0.2):
                    if not self.running:
                        break
                    if key.data == "listener":
                        self.accept()
                    elif key.data == "input":
                        self.read_input()
                    elif key.data == "output":
                        self.write_output()
                    else:
                        session = key.data
                        if session.connected and mask & selectors.EVENT_READ:
                            self.read_session(session)
                        if session.connected and mask & selectors.EVENT_WRITE:
                            self.write_session(session)
                # Handle ready input first, then expire sessions even when other
                # connections or the terminal are continuously generating events.
                self.expire_idle_sessions()
        finally:
            for session in list(self.sessions.values()):
                self.disconnect(session, notify=False)
            self.selector.close()

    def accept(self) -> None:
        # Bound work per turn so an accept flood cannot starve existing sessions.
        for _ in range(16):
            try:
                sock, address = self.listener.accept()
            except BlockingIOError:
                return
            if len(self.sessions) >= self.max_sessions:
                stale = next((sid for sid, s in self.sessions.items()
                              if not s.connected and sid != self.active), None)
                if stale is not None:
                    del self.sessions[stale]
                else:
                    sock.close()
                    self.notice("[!] Session limit reached; new connection rejected.")
                    continue
            sock.setblocking(False)
            session = Session(self.next_id, sock, f"{address[0]}:{address[1]}", Buffer(self.buffer_limit))
            self.next_id += 1
            self.sessions[session.id] = session
            self.selector.register(sock, selectors.EVENT_READ, session)
            self.notice(f"[+] Session {session.id} connected from {session.peer}{self.name_suffix(session)}")

    def read_session(self, session: Session) -> None:
        try:
            data = session.sock.recv(READ_SIZE)
        except BlockingIOError:
            return
        except OSError:
            self.disconnect(session)
            return
        if data:
            if session.batch is not None:
                result = session.batch
                data = result.feed(data)
                if result.state not in PENDING_JOB_STATES:
                    session.batch = None
                    self.notice(f"[Job {result.job_id}] Session {session.id}: {result.state}, exit {result.exit_code}.")
            session.output.append(data)
        else:
            self.disconnect(session)

    def disconnect(self, session: Session, notify: bool = True, reason: str = "disconnected") -> None:
        if not session.connected:
            return
        self.selector.unregister(session.sock)
        session.sock.close()
        session.connected = False
        session.close_reason = reason
        session.outgoing.clear()
        if session.batch is not None:
            session.batch.state = reason
            session.output.append(session.batch.pending)
            session.batch.pending = b""
            session.batch = None
        if notify:
            self.notice(f"[-] Session {session.id} disconnected; saved output is available via interact {session.id}.")

    def expire_idle_sessions(self) -> None:
        if not self.idle_timeout:
            return
        now = time.monotonic()
        for session in self.sessions.values():
            if not session.connected or now - session.last_input < self.idle_timeout:
                continue
            self.disconnect(session, notify=False, reason="idle-timeout")
            message = (f"Session {session.id} idle timeout after {self.idle_timeout}s without submitted input; "
                       f"saved output is available via interact {session.id}.")
            if self.active == session.id:
                # Do not wait for a blocked terminal to drain before leaving a
                # timed-out session; unread bytes stay in that session's buffer.
                self.detach(message)
            else:
                self.notice("[-] " + message)

    def send(self, data: bytes) -> bool:
        session = self.sessions[self.active]
        if not session.connected:
            return False
        if session.batch is not None:
            self.emit("\n[Batch in progress; input was not queued. Use Ctrl+] then jobs to check progress.]\n")
            return False
        if len(session.outgoing) + len(data) > SEND_LIMIT:
            self.input_paused = True
            self.emit("\n[Send queue full; input paused. This input was not queued. "
                      "Ctrl+] returns to menu; check remote state before retrying.]\n")
            return False
        session.outgoing.extend(data)
        if data:
            session.last_input = time.monotonic()
        self.selector.modify(session.sock, selectors.EVENT_READ | selectors.EVENT_WRITE, session)
        return True

    def write_session(self, session: Session) -> None:
        try:
            sent = session.sock.send(session.outgoing)
        except BlockingIOError:
            return
        except OSError:
            self.disconnect(session)
            return
        if sent == 0:
            self.disconnect(session)
            return
        del session.outgoing[:sent]
        if not session.outgoing:
            if session.batch is not None and session.batch.state == "queued":
                session.batch.state = "sent"
            self.selector.modify(session.sock, selectors.EVENT_READ, session)

    def update_output_interest(self) -> None:
        session = self.sessions.get(self.active)
        if session is not None and not session.connected and not session.output.size:
            self.detach(f"Session {session.id} disconnected.")
            session = None
        ready = bool(self.control.size or (session is not None and session.output.size))
        if ready and not self.output_registered:
            self.selector.register(self.terminal.output_fd, selectors.EVENT_WRITE, "output")
            self.output_registered = True
        elif not ready and self.output_registered:
            self.selector.unregister(self.terminal.output_fd)
            self.output_registered = False

    def write_output(self) -> None:
        buffer = self.control
        if not buffer.size:
            session = self.sessions.get(self.active)
            if session is None:
                return
            buffer = session.output
        if not buffer.size:
            return
        try:
            written = os.write(self.terminal.output_fd, buffer.head())
        except BlockingIOError:
            return
        buffer.consume(written)

    def read_input(self) -> None:
        try:
            data = os.read(self.terminal.input_fd, 4096)
        except BlockingIOError:
            return
        if not data:
            self.running = False
            return
        cursor = 0
        while cursor < len(data):
            if not self.running:
                return
            if self.active is not None and self.input_paused:
                if data[cursor] == 0x1D:
                    self.detach()
                cursor += 1
                continue
            if self.active is not None and self.raw:
                boundary = data.find(b"\x1d", cursor)
                end = len(data) if boundary < 0 else boundary
                if end > cursor and not self.send(data[cursor:end]):
                    return
                if boundary < 0:
                    return
                self.detach()
                cursor = boundary + 1
                continue
            byte = data[cursor]
            cursor += 1
            if self.active is not None and byte == 0x1D:
                self.detach()
            else:
                self.edit_line(byte)

    def edit_line(self, byte: int) -> None:
        if self.escape_state:
            if self.escape_state == 1:
                self.escape_state = 2 if byte in (ord("["), ord("O")) else 0
            elif 0x40 <= byte <= 0x7E:
                self.escape_state = 0
            return
        if byte == 0x1B:
            self.escape_state = 1
        elif byte in (10, 13):
            line = bytes(self.line)
            self.line.clear()
            self.control.append(b"\n")
            if self.line_overflow:
                self.line_overflow = False
                self.emit(f"[Input exceeded {LINE_LIMIT} bytes; entire line discarded.]\n")
                if self.active is None:
                    self.prompt()
                return
            if self.active is None:
                self.command(line.decode("utf-8", errors="replace"))
            else:
                self.send(line + b"\n")
        elif byte in (8, 127):
            self.erase_character()
        elif byte == 0x15:
            while self.line:
                self.erase_character()
            self.line_overflow = False
        elif byte == 0x03:
            self.line.clear()
            self.line_overflow = False
            self.control.append(b"^C\n")
            if self.active is None:
                self.prompt()
            else:
                self.emit("[Local input cleared; no remote signal sent. Ctrl+] returns to menu.]\n")
        elif byte == 0x04:
            if self.active is not None:
                self.detach()
            elif not self.line:
                self.running = False
        elif byte >= 32 and len(self.line) < LINE_LIMIT:
            self.line.append(byte)
            self.control.append(bytes((byte,)))
        elif byte >= 32:
            self.line_overflow = True
            self.control.append(b"\a")

    def erase_character(self) -> None:
        if not self.line:
            return
        start = len(self.line) - 1
        while start and self.line[start] & 0xC0 == 0x80:
            start -= 1
        character = bytes(self.line[start:]).decode("utf-8", errors="replace")
        del self.line[start:]
        width = sum(0 if unicodedata.combining(c) else
                    2 if unicodedata.east_asian_width(c) in ("W", "F") else 1 for c in character)
        self.control.append(b"\b \b" * width)

    def detach(self, reason: str = "") -> None:
        sid = self.active
        self.active = None
        self.raw = False
        self.input_paused = False
        self.line.clear()
        self.line_overflow = False
        self.escape_state = 0
        self.emit(f"\n[Detached session {sid}; unsent local input cleared.]\n")
        if reason:
            self.emit(reason + "\n")
        self.prompt()

    def command(self, line: str) -> None:
        words = line.split()
        if not words:
            self.prompt()
            return
        name = words[0]
        if name in ("help", "?") and len(words) == 1:
            self.emit(HELP)
        elif name in ("name", "unname", "note", "unnote"):
            self.name_command(line)
        elif name == "names":
            self.show_names(words)
        elif name == "batch":
            self.batch_command(line)
        elif name == "jobs":
            self.show_jobs(words)
        elif name in ("sessions", "ls") and len(words) == 1:
            try:
                self.names.refresh()
            except (OSError, ValueError, sqlite3.Error) as error:
                self.emit(f"[!] Cannot refresh names: {error}\n")
            self.emit("ID    PEER                     STATE          BUFFERED   DROPPED    AGE       IDLE       NAME\n")
            now = time.monotonic()
            for session in self.sessions.values():
                state = "connected" if session.connected else session.close_reason
                age = int(now - session.created)
                idle = f"{int(now - session.last_input)}s" if session.connected else "-"
                self.emit(f"{session.id:<5} {session.peer:<24} {state:<14} "
                          f"{session.output.size:<10} {session.output.dropped:<10} {str(age) + 's':<9} "
                          f"{idle:<10} {self.names.records.get(session.ip, ('', ''))[0] or '-'}\n")
            if not self.sessions:
                self.emit("(no sessions)\n")
        elif name in ("quit", "exit") and len(words) == 1:
            self.running = False
        elif name in ("interact", "use", "i", "close"):
            valid = len(words) == 2 or (len(words) == 3 and name != "close" and words[2] == "raw")
            if not valid or len(words[1]) > 20 or not words[1].isascii() or not words[1].isdigit():
                self.emit("Usage: interact ID [raw] | close ID\n")
            else:
                session = self.sessions.get(int(words[1]))
                if session is None:
                    self.emit("No such session. Use sessions to list IDs.\n")
                elif name == "close":
                    self.disconnect(session, notify=False)
                    del self.sessions[session.id]
                    self.emit(f"Closed session {session.id}.\n")
                else:
                    self.active = session.id
                    self.raw = len(words) == 3
                    self.input_paused = False
                    mode = "raw (no local echo)" if self.raw else "line (local echo)"
                    self.emit(f"[Session {session.id} {session.peer}{self.name_suffix(session)}; {mode}; Ctrl+] detaches]\n")
                    if session.output.dropped:
                        self.emit(f"[Buffer overflow: {session.output.dropped} oldest bytes dropped in total.]\n")
                    return
        else:
            self.emit("Unknown command. Type help.\n")
        if self.running:
            self.prompt()

    def batch_command(self, line: str) -> None:
        try:
            parts = shlex.split(line)
            if len(parts) != 2:
                raise ValueError("Usage: batch PATH (quote paths containing spaces)")
            targets = [s for s in self.sessions.values() if s.connected]
            if not targets:
                raise ValueError("No connected sessions.")
            try:
                path = Path(parts[1]).expanduser()
            except RuntimeError as error:
                raise ValueError("cannot expand the script path; check the user or use an absolute path") from error
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as file:
                if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
                    raise ValueError("script must be a regular file")
                source = file.read(SEND_LIMIT + 1)
            if len(source) > SEND_LIMIT:
                raise ValueError("script exceeds the 64 KiB send limit")
            script = source.decode("utf-8-sig").replace("\r\n", "\n")
            if not script.strip() or "\x00" in script:
                raise ValueError("script must be nonempty UTF-8 text without NUL bytes")
            packets = []
            for session in targets:
                token = "NCMB_" + secrets.token_hex(16)
                start = "\\036" + token + ":start\\037"
                end = "\\036" + token + ":end:%s\\037"
                # A child Bash contains exit/cd/redirections. Its stdin is closed to interaction.
                command = (f"printf {shlex.quote(start)}; if bash -c {shlex.quote(script)} nc-multi-batch </dev/null; "
                           f"then printf {shlex.quote(end)} 0; else printf {shlex.quote(end)} \"$?\"; fi\n")
                packet = command.encode("utf-8")
                if len(packet) > SEND_LIMIT:
                    raise ValueError("quoted script exceeds the 64 KiB send limit; split it into smaller scripts")
                packets.append((session, packet, b"\x1e" + token.encode("ascii") + b":"))
            if len(self.jobs) >= JOB_LIMIT:
                stale = next((jid for jid, (_, results) in self.jobs.items()
                              if all(r.state not in PENDING_JOB_STATES for r in results)), None)
                if stale is None:
                    raise ValueError("too many unfinished jobs; wait for completion or close stalled sessions")
                del self.jobs[stale]
        except (OSError, ValueError) as error:
            self.emit(f"[!] Batch not started: {error}\n")
            return
        job_id = self.next_job_id
        self.next_job_id += 1
        results = []
        for session, packet, marker in packets:
            result = BatchResult(job_id, session.id, session.peer, marker)
            results.append(result)
            if session.batch is not None or session.outgoing:
                result.state = "skipped-busy"
                continue
            session.batch = result
            session.outgoing.extend(packet)
            session.last_input = time.monotonic()
            self.selector.modify(session.sock, selectors.EVENT_READ | selectors.EVENT_WRITE, session)
        self.jobs[job_id] = (str(path), results)
        self.emit(f"[Job {job_id}] {sum(r.state == 'queued' for r in results)} queued, "
                  f"{sum(r.state == 'skipped-busy' for r in results)} skipped. Use jobs {job_id} for results.\n")

    def show_jobs(self, words) -> None:
        if len(words) > 2 or (len(words) == 2 and
                             (not words[1].isascii() or not words[1].isdigit() or len(words[1]) > 20)):
            self.emit("Usage: jobs [ID]\n")
            return
        selected = int(words[1]) if len(words) == 2 else None
        found = False
        for job_id, (path, results) in self.jobs.items():
            if selected is not None and selected != job_id:
                continue
            found = True
            self.emit(f"Job {job_id}: {path!r}\nSESSION  PEER                     STATE          EXIT\n")
            for result in results:
                code = str(result.exit_code) if result.exit_code is not None else "-"
                self.emit(f"{result.session_id:<9}{result.peer:<25}{result.state:<15}{code}\n")
        if not found:
            self.emit("(no matching jobs)\n")

    def resolve_ip(self, target: str) -> str:
        if target.isascii() and target.isdigit() and len(target) <= 20:
            session = self.sessions.get(int(target))
            if session is None:
                raise ValueError("No such session. Use sessions to list IDs, or specify an IP.")
            target = session.ip
        IPNames.validate(target, "", "name", allow_empty=True)
        return target

    def show_names(self, words) -> None:
        if len(words) > 2:
            self.emit("Usage: names [ID|IP]\n")
            return
        try:
            target = self.resolve_ip(words[1]) if len(words) == 2 else None
            self.names.refresh()
            rows = [(ip, row) for ip, row in sorted(self.names.records.items()) if target is None or ip == target]
        except (OSError, ValueError, sqlite3.Error) as error:
            self.emit(f"[!] Cannot read names: {error}\n")
            return
        self.emit("IP                NAME\n")
        for ip, (name, note) in rows:
            self.emit(f"{ip:<17} {name or '-'}\n  Note: {note or '-'}\n")
        if not rows:
            self.emit("(no saved names or notes)\n")

    def name_command(self, line: str) -> None:
        parts = line.split(maxsplit=2)
        setting = parts[0] in ("name", "note")
        if len(parts) != (3 if setting else 2):
            self.emit("Usage: name ID|IP NAME | note ID|IP TEXT | unname ID|IP | unnote ID|IP\n")
            return
        field = "note" if parts[0] in ("note", "unnote") else "name"
        value = parts[2].strip() if setting else None
        try:
            target = self.resolve_ip(parts[1])
            self.names.set(target, value, field)
        except (OSError, ValueError, sqlite3.Error) as error:
            self.emit(f"[!] {field.title()} unchanged: {error}\n")
            return
        if value is None:
            self.emit(f"{field.title()} removed for {target}.\n")
        else:
            self.emit(f"{field.title()} saved for {target}: {value}\n")


def positive(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def nonnegative(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return number


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-l", "--listen", type=int, default=9000, metavar="PORT", help="TCP listening port; 0 chooses a free port")
    parser.add_argument("-H", "--host", default="0.0.0.0", help="IPv4 address to listen on")
    parser.add_argument("-b", "--buffer-kib", type=positive, default=1024, help="maximum unread output per session in KiB")
    parser.add_argument("-m", "--max-sessions", type=positive, default=100, help="maximum retained sessions; oldest inactive closed record is evicted first")
    parser.add_argument("-t", "--idle-timeout", type=nonnegative, default=DEFAULT_IDLE_TIMEOUT, metavar="SECONDS",
                        help="disconnect each session after this many seconds without submitted input; 0 disables")
    args = parser.parse_args()
    if not 0 <= args.listen <= 65535:
        parser.error("port must be between 0 and 65535")
    handlers = {}
    try:
        config_home = os.environ.get("XDG_CONFIG_HOME")
        config_root = Path(config_home) if config_home and Path(config_home).is_absolute() else Path.home() / ".config"
        names = IPNames(config_root / "nc-multi" / "names.db")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((args.host, args.listen))
            listener.listen(128)
            listener.setblocking(False)
            with Terminal() as terminal:
                console = Console(listener, terminal, args.buffer_kib * 1024, args.max_sessions, args.idle_timeout, names)

                def stop(_signum, _frame):
                    console.running = False

                for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
                    handlers[signum] = signal.signal(signum, stop)
                console.run()
    except (OSError, ValueError, termios.error) as error:
        print(f"nc-multi: {error}", file=sys.stderr)
        return 1
    finally:
        for signum, handler in handlers.items():
            signal.signal(signum, handler)
    print("\nListener stopped; all connections closed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""A standard-library-only TCP session console for Linux and macOS."""

from __future__ import annotations

import argparse
import collections
import dataclasses
import os
import selectors
import signal
import socket
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
PROMPT = b"nc-multi> "
HELP = """Commands:
  sessions / ls          List sessions, including retained disconnected sessions
  interact ID / use ID   Attach with local echo and line editing (plain Bash/TCP)
  interact ID raw        Attach without local echo (for a remote PTY)
  close ID               Close the connection and discard its saved output
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
                 max_sessions: int, idle_timeout: int = DEFAULT_IDLE_TIMEOUT):
        self.listener = listener
        self.terminal = terminal
        self.buffer_limit = buffer_limit
        self.max_sessions = max_sessions
        self.idle_timeout = idle_timeout
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

    def emit(self, text: str) -> None:
        self.control.append(text.encode("utf-8"))

    def prompt(self) -> None:
        self.control.append(PROMPT)

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
            self.notice(f"[+] Session {session.id} connected from {session.peer}")

    def read_session(self, session: Session) -> None:
        try:
            data = session.sock.recv(READ_SIZE)
        except BlockingIOError:
            return
        except OSError:
            self.disconnect(session)
            return
        if data:
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
        elif name in ("sessions", "ls") and len(words) == 1:
            self.emit("ID    PEER                     STATE          BUFFERED   DROPPED    AGE       IDLE\n")
            now = time.monotonic()
            for session in self.sessions.values():
                state = "connected" if session.connected else session.close_reason
                age = int(now - session.created)
                idle = f"{int(now - session.last_input)}s" if session.connected else "-"
                self.emit(f"{session.id:<5} {session.peer:<24} {state:<14} "
                          f"{session.output.size:<10} {session.output.dropped:<10} {str(age) + 's':<9} {idle}\n")
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
                    self.emit(f"[Session {session.id} {session.peer}; {mode}; Ctrl+] detaches]\n")
                    if session.output.dropped:
                        self.emit(f"[Buffer overflow: {session.output.dropped} oldest bytes dropped in total.]\n")
                    return
        else:
            self.emit("Unknown command. Type help.\n")
        if self.running:
            self.prompt()


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
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((args.host, args.listen))
            listener.listen(128)
            listener.setblocking(False)
            with Terminal() as terminal:
                console = Console(listener, terminal, args.buffer_kib * 1024, args.max_sessions, args.idle_timeout)

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

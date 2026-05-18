import hashlib
import os
import re
import socket
import struct
from pathlib import Path

HOST = "127.0.0.1"
PORT = 4444
TIMEOUT = 5
PROMPT = b">"
STEP = 4
VERIFY_READS = 2
MAX_RETRIES = 3
PROGRESS_INTERVAL = 0x400
FLUSH_INTERVAL = 0x1000

HEX_RE = re.compile(r"0x[0-9a-fA-F]+")


def read_until(sock, prompt=PROMPT):
    data = b""
    while prompt not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Socket closed while waiting for prompt")
        data += chunk
    return data


def tncmd(sock, cmd):
    sock.sendall((cmd + "\n").encode("ascii"))
    return read_until(sock).decode("ascii", errors="strict")


def reconnect(reset=False):
    sock = socket.create_connection((HOST, PORT), timeout=TIMEOUT)
    sock.settimeout(TIMEOUT)
    read_until(sock)
    tncmd(sock, "reset halt" if reset else "halt")
    return sock


def read_word(sock, addr):
    tncmd(sock, "reg pc 0x6d4")
    tncmd(sock, f"reg r4 {hex(addr)}")
    tncmd(sock, "step")
    resp = tncmd(sock, "reg r4")
    matches = HEX_RE.findall(resp)
    if len(matches) != 1:
        raise RuntimeError(
            f"Expected exactly one hex value, got {matches} from {resp!r}"
        )
    return int(matches[0], 16)


def read_block(sock, start, length, output_path=None, label=None):
    """Read a contiguous block of memory word by word.

    Yields (addr, value) pairs. If output_path is given, writes raw LE words
    to that file with resume support. Handles retries and reconnection.
    Returns (sock, hasher) — sock may differ from input if reconnects occurred.
    """
    end = start + length
    hasher = hashlib.sha256()
    current_sock = sock
    display = label or f"{start:#010x}"

    resume_addr = start
    if output_path is not None:
        p = Path(output_path)
        if p.exists():
            existing = p.stat().st_size
            if existing % STEP:
                raise RuntimeError(f"Existing file not word-aligned: {existing} bytes")
            resume_addr = start + existing
            if resume_addr > end:
                raise RuntimeError("Existing file larger than requested region")
            if resume_addr > start:
                print(f"[{display}] Resuming at {resume_addr:#010x}")
            with p.open("rb") as f:
                while chunk := f.read(4096):
                    hasher.update(chunk)

    file_handle = None
    try:
        if output_path is not None:
            file_handle = open(output_path, "ab")

        for addr in range(resume_addr, end, STEP):
            verified_value = None

            for attempt in range(1, MAX_RETRIES + 1):
                try:
                    reads = [read_word(current_sock, addr) for _ in range(VERIFY_READS)]
                    if len(set(reads)) != 1:
                        raise RuntimeError(f"Read mismatch at {addr:#010x}: {reads}")
                    verified_value = reads[0]
                    break
                except (TimeoutError, ConnectionError, OSError, RuntimeError) as exc:
                    print(f"[{display}] Retry {attempt}/{MAX_RETRIES} at {addr:#010x}: {exc}")
                    try:
                        current_sock.close()
                    except Exception:
                        pass
                    if attempt >= MAX_RETRIES:
                        raise
                    current_sock = reconnect()

            packed = struct.pack("<I", verified_value)

            if file_handle is not None:
                file_handle.write(packed)
                hasher.update(packed)

                if (addr % FLUSH_INTERVAL) == 0:
                    file_handle.flush()
                    os.fsync(file_handle.fileno())

            if (addr % PROGRESS_INTERVAL) == 0:
                done = addr - start
                pct = (done / length) * 100
                print(f"[{display}] {addr:#010x} ({pct:5.1f}%)")

            yield addr, verified_value

    finally:
        if file_handle is not None:
            file_handle.close()

    return current_sock, hasher

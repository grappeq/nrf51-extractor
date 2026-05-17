import hashlib
import os
import re
import socket
import struct
from pathlib import Path

# Based on:
# https://www.pentestpartners.com/security-blog/nrf51822-code-readout-protection-bypass-a-how-to/

HOST = "127.0.0.1"
PORT = 4444
TIMEOUT = 5
PROMPT = b">"
DUMP_SIZE = 0x40000
STEP = 4
PROGRESS_INTERVAL = 0x400
FLUSH_INTERVAL = 0x1000
MAX_RETRIES = 3
VERIFY_READS = 2

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


def reconnect():
    sock = socket.create_connection((HOST, PORT), timeout=TIMEOUT)
    sock.settimeout(TIMEOUT)

    # Consume initial prompt
    read_until(sock)

    tncmd(sock, "reset halt")

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


try:
    sock = reconnect()

    dump_path = Path("dump.bin")

    start_addr = 0
    hasher = hashlib.sha256()

    if dump_path.exists():
        existing_size = dump_path.stat().st_size

        if (existing_size % STEP) != 0:
            raise RuntimeError(
                f"Existing dump size is not aligned: {existing_size} bytes"
            )

        start_addr = existing_size

        print(f"Resuming existing dump at {start_addr:#08x}")

        with dump_path.open("rb") as existing:
            while chunk := existing.read(4096):
                hasher.update(chunk)

    with sock:
        # Note - the following pc and r4 instructions will need to change based on what
        # you learn by running the commands in gdb.config on your particular device that
        # you are reverse engineering.

        with dump_path.open("ab") as outfile:
            for addr in range(start_addr, DUMP_SIZE, STEP):
                verified_value = None

                for attempt in range(1, MAX_RETRIES + 1):
                    try:
                        reads = []

                        for _ in range(VERIFY_READS):
                            reads.append(read_word(sock, addr))

                        if len(set(reads)) != 1:
                            raise RuntimeError(
                                f"Read mismatch at {addr:#08x}: {reads}"
                            )

                        verified_value = reads[0]
                        break

                    except (
                            TimeoutError,
                            ConnectionError,
                            OSError,
                            RuntimeError,
                    ) as exc:
                        print(
                            f"Retry {attempt}/{MAX_RETRIES} at {addr:#08x}: {exc}"
                        )

                        try:
                            sock.close()
                        except Exception:
                            pass

                        if attempt >= MAX_RETRIES:
                            raise

                        sock = reconnect()

                packed = struct.pack("<I", verified_value)

                outfile.write(packed)
                hasher.update(packed)

                if (addr % FLUSH_INTERVAL) == 0:
                    outfile.flush()
                    os.fsync(outfile.fileno())

                if (addr % PROGRESS_INTERVAL) == 0:
                    percent = (addr / DUMP_SIZE) * 100
                    print(f"{addr:#08x} ({percent:5.1f}%)")

    print(f"SHA256: {hasher.hexdigest()}")

except KeyboardInterrupt:
    print("Interrupted by user")

import argparse
import hashlib
from pathlib import Path

# Based on:
# https://www.pentestpartners.com/security-blog/nrf51822-code-readout-protection-bypass-a-how-to/

import swd

DEFAULT_START = 0x0
DEFAULT_END = 0x40000
DEFAULT_OUTPUT = "dump.bin"


def main():
    parser = argparse.ArgumentParser(description="Dump nRF51 memory region via OpenOCD")
    parser.add_argument("--start", type=lambda x: int(x, 0), default=DEFAULT_START,
                        help=f"Start address (default: {DEFAULT_START:#x})")
    parser.add_argument("--end", type=lambda x: int(x, 0), default=DEFAULT_END,
                        help=f"End address exclusive (default: {DEFAULT_END:#x})")
    parser.add_argument("--output", default=DEFAULT_OUTPUT,
                        help=f"Output file path (default: {DEFAULT_OUTPUT})")
    args = parser.parse_args()

    length = args.end - args.start
    if length <= 0:
        parser.error("--end must be greater than --start")

    sock = swd.reconnect()
    hasher = hashlib.sha256()

    try:
        for _addr, value in swd.read_block(
            sock,
            start=args.start,
            length=length,
            output_path=args.output,
            label=Path(args.output).name,
        ):
            pass
    except KeyboardInterrupt:
        print("Interrupted by user")
        return

    # Re-hash the completed file for the final digest
    hasher = hashlib.sha256()
    with open(args.output, "rb") as f:
        while chunk := f.read(4096):
            hasher.update(chunk)

    print(f"SHA256: {hasher.hexdigest()}")


if __name__ == "__main__":
    main()

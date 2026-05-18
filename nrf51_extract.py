"""nRF51822 structured memory extractor.

Dumps FICR, UICR, RAM, and peripheral registers via OpenOCD SWD.
Produces raw .bin files and decoded .json files per region.
"""

import argparse
import json
import struct
import sys
from pathlib import Path

import swd

# ---------------------------------------------------------------------------
# Region definitions
# ---------------------------------------------------------------------------

REGIONS = {
    "ficr": (0x10000000, 0x100),
    "uicr": (0x10001000, 0x100),
    "ram":  (0x20000000, 0x4000),
}

# ---------------------------------------------------------------------------
# FICR / UICR decoders
# ---------------------------------------------------------------------------

def _mac(words, off):
    lo = words[off]
    hi = words[off + 1] & 0xFFFF
    raw = lo | (hi << 32)
    return ":".join(f"{(raw >> (8 * i)) & 0xFF:02X}" for i in range(5, -1, -1))


def _key128(words, off):
    return "".join(f"{words[off + i]:08X}" for i in range(4))


def decode_ficr(words):
    def w(offset_bytes):
        return words[offset_bytes // 4]

    addr_type_raw = w(0xA0)
    addr_type = "random" if (addr_type_raw & 0x1) else "public"

    return {
        "CODEPAGESIZE":   w(0x10),
        "CODESIZE":       w(0x14),
        "CLENR0":         w(0x28),
        "PPFC":           w(0x2C),
        "NUMRAMBLOCK":    w(0x34),
        "SIZERAMBLOCK":   w(0x38),
        "CONFIGID":       f"{w(0x5C):#010x}",
        "DEVICEID": (
            f"{w(0x60):08X}{w(0x64):08X}"
        ),
        "ER":             _key128(words, 0x80 // 4),
        "IR":             _key128(words, 0x90 // 4),
        "DEVICEADDRTYPE": addr_type,
        "DEVICEADDR":     _mac(words, 0xA4 // 4),
    }


def decode_uicr(words):
    def w(offset_bytes):
        return words[offset_bytes // 4]

    rbpconf = w(0x04)
    pall = (rbpconf >> 8) & 0xFF
    pr0  = rbpconf & 0xFF

    customer = [f"{words[0x80 // 4 + i]:#010x}" for i in range(32)]

    return {
        "CLENR0":         f"{w(0x00):#010x}",
        "RBPCONF": {
            "raw":  f"{rbpconf:#010x}",
            "PALL": "protected" if pall == 0x00 else "open",
            "PR0":  "protected" if pr0  == 0x00 else "open",
        },
        "XTALFREQ":       f"{w(0x08):#010x}",
        "FWID":           f"{w(0x10):#010x}",
        "BOOTLOADERADDR": f"{w(0x14):#010x}",
        "NRFFW":          [f"{words[0x14 // 4 + i]:#010x}" for i in range(15)],
        "NRFHW":          [f"{words[0x50 // 4 + i]:#010x}" for i in range(12)],
        "CUSTOMER":       customer,
    }


BLOCK_DECODERS = {
    "ficr": decode_ficr,
    "uicr": decode_uicr,
    "ram":  None,
}

# ---------------------------------------------------------------------------
# Peripheral register map
# ---------------------------------------------------------------------------
# Each entry: (name, address, decoder_fn | None)
# decoder_fn(value) -> dict of field_name -> decoded_value

def _bits(value, hi, lo):
    mask = (1 << (hi - lo + 1)) - 1
    return (value >> lo) & mask


def dec_nvmc_config(v):
    mode = {0: "read-only", 1: "write-enabled", 2: "erase-enabled"}.get(v & 0x3, "unknown")
    return {"raw": f"{v:#010x}", "WEN": mode}


def dec_resetreas(v):
    return {
        "raw":     f"{v:#010x}",
        "RESETPIN": bool(v & (1 << 0)),
        "DOG":      bool(v & (1 << 1)),
        "SREQ":     bool(v & (1 << 2)),
        "LOCKUP":   bool(v & (1 << 3)),
        "OFF":      bool(v & (1 << 16)),
        "LPCOMP":   bool(v & (1 << 17)),
        "DIF":      bool(v & (1 << 18)),
    }


def dec_ramon(v):
    return {
        "raw":    f"{v:#010x}",
        "ONRAM0": bool(v & (1 << 0)),
        "ONRAM1": bool(v & (1 << 1)),
    }


def dec_radio_crccnf(v):
    return {
        "raw":    f"{v:#010x}",
        "LEN":    _bits(v, 1, 0),
        "SKIP_ADDR": bool(v & (1 << 8)),
    }


def dec_uart_config(v):
    parity = "included" if _bits(v, 3, 1) == 0b111 else "excluded"
    return {
        "raw":    f"{v:#010x}",
        "HWFC":   bool(v & 1),
        "PARITY": parity,
    }


def dec_uart_baud(v):
    known = {
        0x0004F000: 1200,   0x0009D000: 2400,   0x0013B000: 4800,
        0x00275000: 9600,   0x003B0000: 14400,  0x004EA000: 19200,
        0x0075F000: 38400,  0x00800000: 31250,  0x009D5000: 57600,
        0x00E50000: 115200, 0x01000000: 250000, 0x02000000: 1000000,
        0x04000000: 250000,  # nRF51 encoding for 250kbps (also power-on default)
    }
    return {"raw": f"{v:#010x}", "bps": known.get(v, "unknown")}


def dec_pin_cnf(v):
    dir_   = "output" if (v & 1) else "input"
    input_ = "disconnect" if _bits(v, 1, 1) else "connect"
    pull   = {0: "disabled", 1: "pulldown", 3: "pullup"}.get(_bits(v, 3, 2), "reserved")
    drive  = _bits(v, 10, 8)
    sense  = {0: "disabled", 2: "high", 3: "low"}.get(_bits(v, 17, 16), "reserved")
    return {
        "raw":   f"{v:#010x}",
        "DIR":   dir_,
        "INPUT": input_,
        "PULL":  pull,
        "DRIVE": drive,
        "SENSE": sense,
    }


def dec_ppi_ch(v):
    return {"EEP": f"{v:#010x}"}


def dec_wdt_config(v):
    behaviour = {0: "run-sleep", 8: "run-sleep-halt"}.get(v & 0x9, "other")
    return {"raw": f"{v:#010x}", "BEHAVIOUR": behaviour}


def dec_gpiote_config(v):
    mode = {0: "disabled", 1: "event", 3: "task"}.get(_bits(v, 1, 0), "reserved")
    psel = _bits(v, 12, 8)
    polarity = {1: "LoToHi", 2: "HiToLo", 3: "Toggle"}.get(_bits(v, 17, 16), "none")
    return {"raw": f"{v:#010x}", "MODE": mode, "PSEL": psel, "POLARITY": polarity}


def _psel(v):
    if v == 0xFFFFFFFF:
        return "disconnected"
    return f"P0.{v & 0x1F}"


def dec_psel(v):
    return {"raw": f"{v:#010x}", "pin": _psel(v)}


PERIPHERAL_MAP = [
    # NVMC
    ("NVMC.CONFIG",          0x40018504, dec_nvmc_config),

    # POWER
    ("POWER.RESETREAS",      0x40000400, dec_resetreas),
    ("POWER.RAMON",          0x40000524, dec_ramon),

    # RADIO
    ("RADIO.BASE0",          0x4000151C, None),
    ("RADIO.BASE1",          0x40001520, None),
    ("RADIO.PREFIX0",        0x40001524, None),
    ("RADIO.PREFIX1",        0x40001528, None),
    ("RADIO.TXPOWER",        0x40001504, None),
    ("RADIO.DATAWHITEIV",    0x40001554, None),
    ("RADIO.CRCCNF",         0x40001534, dec_radio_crccnf),
    ("RADIO.CRCPOLY",        0x40001538, None),
    ("RADIO.CRCINIT",        0x4000153C, None),

    # UART0
    ("UART0.PSELTXD",        0x4000250C, dec_psel),
    ("UART0.PSELRXD",        0x40002514, dec_psel),
    ("UART0.PSELCTS",        0x40002510, dec_psel),
    ("UART0.PSELRTS",        0x40002508, dec_psel),
    ("UART0.BAUDRATE",       0x40002524, dec_uart_baud),
    ("UART0.CONFIG",         0x4000256C, dec_uart_config),

    # SPI0 / TWI0
    ("SPI0.PSELSCK",         0x40003508, dec_psel),
    ("SPI0.PSELMOSI",        0x4000350C, dec_psel),
    ("SPI0.PSELMISO",        0x40003510, dec_psel),
    ("SPI0.FREQUENCY",       0x40003524, None),
    ("TWI0.PSELSCL",         0x40003508, dec_psel),
    ("TWI0.PSELSDA",         0x4000350C, dec_psel),
    ("TWI0.ADDRESS",         0x40003588, None),

    # SPI1 / TWI1
    ("SPI1.PSELSCK",         0x40004508, dec_psel),
    ("SPI1.PSELMOSI",        0x4000450C, dec_psel),
    ("SPI1.PSELMISO",        0x40004510, dec_psel),
    ("SPI1.FREQUENCY",       0x40004524, None),
    ("TWI1.PSELSCL",         0x40004508, dec_psel),
    ("TWI1.PSELSDA",         0x4000450C, dec_psel),
    ("TWI1.ADDRESS",         0x40004588, None),

    # GPIOTE
    ("GPIOTE.CONFIG[0]",     0x40006510, dec_gpiote_config),
    ("GPIOTE.CONFIG[1]",     0x40006514, dec_gpiote_config),
    ("GPIOTE.CONFIG[2]",     0x40006518, dec_gpiote_config),
    ("GPIOTE.CONFIG[3]",     0x4000651C, dec_gpiote_config),

    # GPIO P0
    ("GPIO.OUT",             0x50000504, None),
    ("GPIO.IN",              0x50000510, None),
    ("GPIO.DIR",             0x50000514, None),
    *[(f"GPIO.PIN_CNF[{i}]", 0x50000700 + i * 4, dec_pin_cnf) for i in range(32)],

    # PPI channels
    *[(f"PPI.CH[{i}].EEP",   0x4001E510 + i * 8, None) for i in range(16)],
    *[(f"PPI.CH[{i}].TEP",   0x4001E514 + i * 8, None) for i in range(16)],

    # WDT
    ("WDT.CONFIG",           0x40010504, dec_wdt_config),

    # AAR / CCM / ECB — pointer registers only, not chased
    ("AAR.IRKPTR",           0x4000F018, None),
    ("AAR.ADDRPTR",          0x4000F020, None),
    ("CCM.CNFPTR",           0x4000F518, None),
    ("ECB.ECBDATAPTR",       0x4000E504, None),
]

# ---------------------------------------------------------------------------
# Block dump
# ---------------------------------------------------------------------------

def dump_block(sock, name, start, length, out_dir):
    bin_path = out_dir / f"{name}.bin"
    json_path = out_dir / f"{name}.json"

    print(f"\n=== {name.upper()} ({start:#010x}, {length} bytes) ===")

    words = []
    for _addr, value in swd.read_block(sock, start, length,
                                        output_path=str(bin_path), label=name):
        words.append(value)

    print(f"[{name}] Saved {bin_path}")

    decoder = BLOCK_DECODERS.get(name)
    if decoder is not None:
        try:
            decoded = decoder(words)
            with json_path.open("w") as f:
                json.dump(decoded, f, indent=2)
            print(f"[{name}] Saved {json_path}")
            _print_decoded(name, decoded)
        except Exception as exc:
            print(f"[{name}] Decode failed: {exc}")


def _print_decoded(name, decoded, indent=0):
    prefix = "  " * indent
    for k, v in decoded.items():
        if isinstance(v, dict):
            print(f"{prefix}  {k}:")
            _print_decoded(name, v, indent + 2)
        elif isinstance(v, list):
            print(f"{prefix}  {k}: [{', '.join(str(x) for x in v[:4])}{'...' if len(v) > 4 else ''}]")
        else:
            print(f"{prefix}  {k}: {v}")

# ---------------------------------------------------------------------------
# Peripheral snapshot
# ---------------------------------------------------------------------------

def dump_peripherals(sock, out_dir):
    print("\n=== PERIPHERAL SNAPSHOT ===")

    results = {}
    rows = []

    for entry in PERIPHERAL_MAP:
        name, addr, decoder = entry
        try:
            value = swd.read_word(sock, addr)
        except Exception as exc:
            print(f"  ERROR reading {name} @ {addr:#010x}: {exc}")
            results[name] = {"error": str(exc)}
            rows.append((name, addr, None, None))
            continue

        if decoder is not None:
            try:
                decoded = decoder(value)
            except Exception as exc:
                decoded = {"raw": f"{value:#010x}", "decode_error": str(exc)}
        else:
            decoded = f"{value:#010x}"

        results[name] = decoded
        rows.append((name, addr, value, decoded))

    # Print table
    col_name = max(len(r[0]) for r in rows)
    print(f"\n  {'Register':<{col_name}}  {'Address':<12}  {'Raw':<12}  Decoded")
    print(f"  {'-'*col_name}  {'-'*10}  {'-'*10}  {'-'*30}")
    for name, addr, value, decoded in rows:
        raw_str = f"{value:#010x}" if value is not None else "ERROR"
        if isinstance(decoded, dict):
            dec_str = ", ".join(f"{k}={v}" for k, v in decoded.items() if k != "raw")
        elif decoded is not None:
            dec_str = str(decoded)
        else:
            dec_str = ""
        print(f"  {name:<{col_name}}  {addr:#010x}  {raw_str:<12}  {dec_str}")

    json_path = out_dir / "peripherals.json"
    with json_path.open("w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[peripherals] Saved {json_path}")

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

VALID_REGIONS = {"ficr", "uicr", "ram", "peripherals"}
DEFAULT_REGIONS = {"ficr", "uicr", "peripherals"}


def main():
    parser = argparse.ArgumentParser(description="nRF51822 structured data extractor")
    parser.add_argument(
        "--regions",
        default=",".join(sorted(DEFAULT_REGIONS)),
        help=(
            f"Comma-separated list of regions to extract. "
            f"Valid: {', '.join(sorted(VALID_REGIONS))}. "
            f"Default: {', '.join(sorted(DEFAULT_REGIONS))} (RAM excluded by default due to size)"
        ),
    )
    parser.add_argument(
        "--out-dir", default="dumps",
        help="Directory for output files (default: dumps/)",
    )
    parser.add_argument(
        "--reset", action="store_true", default=False,
        help="Issue 'reset halt' on connect instead of plain 'halt' (destroys runtime state)",
    )
    args = parser.parse_args()

    requested = {r.strip().lower() for r in args.regions.split(",")}
    unknown = requested - VALID_REGIONS
    if unknown:
        parser.error(f"Unknown region(s): {', '.join(sorted(unknown))}")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Connecting to OpenOCD ({'reset halt' if args.reset else 'halt, preserving runtime state'})...")
    try:
        sock = swd.reconnect(reset=args.reset)
    except Exception as exc:
        print(f"Failed to connect: {exc}")
        sys.exit(1)

    try:
        for region in ("ficr", "uicr", "ram"):
            if region not in requested:
                continue
            start, length = REGIONS[region]
            dump_block(sock, region, start, length, out_dir)

        if "peripherals" in requested:
            dump_peripherals(sock, out_dir)

    except KeyboardInterrupt:
        print("\nInterrupted by user")
    finally:
        try:
            sock.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()

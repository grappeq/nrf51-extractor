# nrf51-extractor

Tools for bypassing code readout protection (CRP) on Nordic Semiconductor NRF51822 chips and extracting the protected flash contents.

This is a fork of [geeksville/nrf51-extractor](https://github.com/geeksville/nrf51-extractor) with the following improvements over the original:

- **Python 3 compatibility** — the original script used Python 2 idioms; this fork updates it to run under Python 3.6+.
- **Retry logic** — transient connection drops or timeouts are caught and the script reconnects and retries up to 3 times per word before giving up, instead of crashing.
- **Read verification** — each 32-bit word is read twice and the two values are compared; a mismatch triggers a retry, reducing silent bit errors in the output.
- **Resume support** — if the script is interrupted, re-running it detects the existing `dump.bin` and picks up from the last written byte rather than starting over.
- **Periodic fsync** — the output file is flushed and synced to disk every 4 KB so a crash loses at most one page of data.
- **SHA-256 checksum** — a hash of the complete dump is printed on completion so you can verify integrity or compare two runs.
- **Structured extractor** — `nrf51_extract.py` decodes FICR, UICR, RAM, and peripheral registers into JSON files for easy analysis.

Based on the Pen Test Partners article: [NRF51822 code readout protection bypass: a how-to](https://www.pentestpartners.com/security-blog/nrf51822-code-readout-protection-bypass-a-how-to/)

## How it works

The NRF51822 has a hardware bug: even when code readout protection is enabled, you can find a load instruction already present in unprotected flash and use it to leak one word at a time by setting the PC and source register before each single-step. `readout.py` automates this over the OpenOCD telnet interface, dumping the full 256 KB of flash to `dump.bin`. Reads are verified twice per word and the script resumes from where it left off if interrupted.

## Files

| File | Purpose |
|---|---|
| `swd.py` | Shared transport layer (OpenOCD telnet, read_word, read_block) |
| `readout.py` | Dump an arbitrary memory range to a raw binary file |
| `nrf51_extract.py` | Structured extractor: FICR, UICR, RAM, and peripheral registers |

## Prerequisites

- [OpenOCD](https://openocd.org/) with ST-Link support
- `arm-none-eabi-gdb` with Python support (`arm-none-eabi-gdb-py`)
- Python 3.6+
- An ST-Link v2 programmer connected to the target device

## Step 1 — Find the load instruction address

This step is manual and device-specific. You only need to do it once per firmware version.

**Start OpenOCD:**
```sh
openocd -f interface/stlink.cfg -f target/nrf51.cfg -c "init; reset init;"
```

**Start GDB:**
```sh
./rungdb
```

Inside the GDB shell, run these helper commands (defined in `gdb.config`):

| Command | What it does |
|---|---|
| `uicrtofile` | Dumps UICR registers (0x10001000–0x10001400) to `uicr.bin` |
| `dumpuicr` | Prints UICR registers to the console |
| `dumpficr` | Prints FICR registers (factory info — readable even on protected devices) |
| `regset <addr>` | Sets r0–r12 all to `<addr>` |
| `regset2 <addr>` | Sets r0–r12 to `<addr>`, `<addr+4>`, … (sequential offsets) |
| `rdhack <addr>` | Sets PC to 0x6d4 and r4 to `<addr>`, steps once, prints r4 |

**Find a usable load instruction:**

1. Run `monitor reset halt` to put the PC at the reset vector.
2. Run `regset 0x10000000` (fills all registers with a known FICR address).
3. Run `si` then `i r` — if any register now holds the value at `0x10000000`, you found your instruction.
4. Repeat `regset` / `si` / `i r` until a register changes. Note the **PC value** (the instruction address) and **which register** received the loaded value.
5. Run `regset2 0x10000000` followed by `si` / `i r` to confirm which register holds the source address (they will have sequential offsets).

## Step 2 — Configure readout.py

Edit `readout.py` to match what you found above. Look for this block near the top of the `read_word` function:

```python
def read_word(sock, addr):
    tncmd(sock, "reg pc 0x6d4")   # <-- instruction address you found
    tncmd(sock, f"reg r4 {hex(addr)}")  # <-- source-address register (r4 in this example)
    tncmd(sock, "step")
    resp = tncmd(sock, "reg r4")  # <-- destination register (r4 in this example)
```

Update the PC value and the two register names to match your device.

## Step 3 — Dump firmware (256 KB flash)

With OpenOCD still running:

```bash
python readout.py
```

- Progress is printed every 1 KB.
- The dump is flushed to disk every 4 KB.
- If interrupted, re-running resumes from the last written byte automatically.
- On completion, the SHA-256 of `dump.bin` is printed.

The full 256 KB dump takes roughly 30 minutes.

Optional arguments:
```
--start   Start address (default: 0x0)
--end     End address exclusive (default: 0x40000)
--output  Output file (default: dump.bin)
```

Example — dump FICR manually:
```bash
python readout.py --start 0x10000000 --end 0x10000100 --output ficr_raw.bin
```

## Step 4 — Extract device identity and configuration

`nrf51_extract.py` dumps and decodes the regions most useful for device analysis.

```bash
python nrf51_extract.py
```

Default run extracts **FICR**, **UICR**, and a **peripheral register snapshot** (RAM excluded by default due to size). Output files are written to the current directory.

### Options

```
--regions   Comma-separated list: ficr, uicr, ram, peripherals (default: ficr,uicr,peripherals)
--out-dir   Output directory (default: current directory)
```

Examples:
```bash
# Everything including RAM
python nrf51_extract.py --regions ficr,uicr,ram,peripherals

# FICR and UICR only, write to a dedicated folder
python nrf51_extract.py --regions ficr,uicr --out-dir device_dump/

# Peripheral snapshot only
python nrf51_extract.py --regions peripherals
```

### What FICR/UICR JSON contains

**ficr.json** — `DEVICEID`, `DEVICEADDR` (BLE MAC), `DEVICEADDRTYPE`, `ER` (Encryption Root, 128-bit), `IR` (Identity Root, 128-bit), `CODEPAGESIZE`, `CODESIZE`, `CONFIGID`

**uicr.json** — `RBPCONF` (readback protection state), `BOOTLOADERADDR`, `CUSTOMER[0..31]` (32 words of user storage, often holds serial numbers or provisioning tokens), `NRFFW`, `NRFHW`

### What the peripheral snapshot covers

NVMC (flash write protection), POWER (reset reason, RAM blocks), RADIO (base addresses, CRC config — reveals BLE vs proprietary RF), UART0/SPI0/SPI1/TWI0/TWI1 (all PSEL pin assignments and baud/frequency), GPIOTE (event/task config), GPIO (all 32 PIN_CNF registers — full hardware pin mapping), PPI channels, WDT, and AAR/CCM/ECB data pointer registers (point to live key material in RAM).

## Step 5 — Write the image to a new device

Connect to the OpenOCD telnet port and run:

```
telnet localhost 4444
```

```
reset halt
nrf51 mass_erase
flash write_image dump.bin 0
flash write_image uicr.bin 0x10001000
reset run
```

> **Note:** `uicr.bin` is device-specific (it contains things like the bootloader start address and device keys). Only copy it if you are cloning an identical device.

## Output files

| File | Contents |
|---|---|
| `dump.bin` | Full 256 KB flash image (address 0x00000000–0x0003FFFF) |
| `uicr.bin` | 1 KB UICR region (address 0x10001000–0x10001400) |
| `ficr.bin` | Raw FICR region (256 bytes) |
| `ficr.json` | Decoded: device ID, BLE MAC, ER/IR keys, flash geometry |
| `uicr.json` | Decoded: readback protection, bootloader address, CUSTOMER[] words |
| `ram.bin` | Raw SRAM dump (16 KB, only if requested) |
| `peripherals.json` | Decoded peripheral register snapshot |

## Reference

- [Pen Test Partners article](https://www.pentestpartners.com/security-blog/nrf51822-code-readout-protection-bypass-a-how-to/) (also included as a PDF in this repo)
- [OpenOCD GDB integration docs](http://openocd.org/doc/html/GDB-and-OpenOCD.html)

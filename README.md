# Tools for reverse engineering NRF51 firmware

This is based on the great article at: https://www.pentestpartners.com/security-blog/nrf51822-code-readout-protection-bypass-a-how-to/

I'm mostly just making this for my own use but if useful for others then great.

## Files

| File | Purpose |
|---|---|
| `swd.py` | Shared transport layer (OpenOCD telnet, read_word, read_block) |
| `readout.py` | Dump an arbitrary memory range to a raw binary file |
| `nrf51_extract.py` | Structured extractor: FICR, UICR, RAM, and peripheral registers |

---

# How to read from a protected NRF51

* (first read the article above)
* start OPENOCD with `/usr/local/share/openocd/bin/openocd -f .../interface/stlink.cfg -f .../target/nrf51.cfg -c "init; reset init;"`
* run `rungdb`
* inside the GDB shell run `uicrtofile` to save all the uicr registers to a bin file.  If you are cloning a device you'll want to use these later.
* run `dumpficr` to get a handy set of known memory values (when a device is protected most flash is not readable, but this is)

Using the values from dumpficr do the following sequence:
* `monitor reset halt` (to put the PC at the start addr)
* `regset 0x10000000` (or some other address with recognizable data in the FICR region) — fills all registers with that address
* `si` to step one instruction
* `i r` to dump all registers to see if the value you wanted was read into any register; if not, repeat `regset`/`si`/`i r` until you see it (should happen within 10 instructions)
* Now you know the PC address of a load instruction and which register it loads into
* Set PC to that address again, run `regset2 0x10000000` (reads the first 52 bytes into r0–r12), then `si` + `i r` to identify which register holds the source address

Based on the instruction address you found and the registers involved, edit the `read_word()` function in `swd.py` (the `reg pc` and `reg r4` lines).

---

# Dumping firmware (256 KB flash)

```bash
python readout.py
```

Takes ~30 minutes. Writes `dumps/dump.bin`. The `dumps/` directory is created automatically and is gitignored. Supports resume if interrupted.

Optional arguments:
```
--start   Start address (default: 0x0)
--end     End address exclusive (default: 0x40000)
--output  Output file (default: dumps/dump.bin)
```

Example — dump FICR manually:
```bash
python readout.py --start 0x10000000 --end 0x10000100 --output dumps/ficr_raw.bin
```

---

# Extracting device identity and configuration

`nrf51_extract.py` dumps and decodes the regions most useful for device analysis.

```bash
python nrf51_extract.py
```

Default run extracts **FICR**, **UICR**, and a **peripheral register snapshot** (RAM excluded by default due to size). Output files are written to `dumps/` by default. The directory is created automatically and is gitignored.

### Output files

| File | Contents |
|---|---|
| `ficr.bin` | Raw FICR region (256 bytes) |
| `ficr.json` | Decoded: device ID, BLE MAC, ER/IR keys, flash geometry |
| `uicr.bin` | Raw UICR region (256 bytes) |
| `uicr.json` | Decoded: readback protection, bootloader address, CUSTOMER[] words |
| `ram.bin` | Raw SRAM dump (16 KB, only if requested) |
| `peripherals.json` | Decoded peripheral register snapshot |

### Options

```
--regions   Comma-separated list: ficr, uicr, ram, peripherals (default: ficr,uicr,peripherals)
--out-dir   Output directory (default: dumps/)
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

---

# How to write an image to a new device

```
telnet localhost 4444
reset halt
nrf51 mass_erase
flash write_image dump.bin 0
flash write_image uicr.bin 0x10001000
```

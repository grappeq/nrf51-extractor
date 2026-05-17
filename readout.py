import socket
import re
import struct

HOST = "127.0.0.1"
PORT = 4444

sock = socket.create_connection((HOST, PORT))

def read_until(prompt=b">"):
    data = b""
    while prompt not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Socket closed")
        data += chunk
    return data

read_until()

def tncmd(cmd):
    sock.sendall((cmd + "\n").encode("ascii"))
    return read_until().decode("ascii")

tncmd("reset halt")

with open("dump.bin", "wb") as outfile:
    for addr in range(0, 0x40000, 4):
        tncmd("reg pc 0x6d4")
        tncmd(f"reg r4 {hex(addr)}")
        tncmd("step")

        resp = tncmd("reg r4")
        t = re.findall(r"0x[0-9a-fA-F]+", resp)

        if t:
            outfile.write(struct.pack("I", int(t[0], 16)))

        if (addr % 0x400) == 0:
            print(hex(addr))

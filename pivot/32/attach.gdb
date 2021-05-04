set target-async on
set pagination off
set follow-fork-mode child
set disassembly-flavor intel
attach 3876

alias -a di = disassemble
# after first read
b * 0x080487be
# b *0x080487b9
# b *0x080487be

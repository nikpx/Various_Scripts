#Insipired by https://github.com/StuckinVim-Forever/Dridex-INT3
#Unfortunately, it was not working in my target sample so I had to modify it a bit
#To do: fix the stack after patching
from idaapi import *
import idautils


ea = idc.get_inf_attr(INF_MIN_EA)

for seg in idautils.Segments():
    start = idc.get_segm_start(ea)
    end = idc.get_segm_end(ea)


def fixDridex(start, end):
    for address in range(start, end + 1):
        new_address = next_addr(address)
        if get_byte(new_address) == 0xCC and get_byte(new_address+1) == 0xC3:
            patch_byte(new_address, 0xFF)
            patch_byte(new_address+1, 0xD0)
            print ("Patching INT 3 at " + hex(new_address))

fixDridex(start, end)

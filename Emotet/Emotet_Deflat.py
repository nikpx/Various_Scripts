'''
Experimental script to patch/unflatten the control flow of Emotet. There are many implementations/solutions already to solve this issue (or part of it) by using the miasm framework.
The idea was to attempt to solve this issue with emulation (Unicorn engine) and IDAPython. The script was written on a Saturday night and 
contains a lot of bugs and some features are missing (e.g. not detecting the state register, not storing the identified addresses in a proper structure). 
In addition, it is not able to handle every single "obfuscated" function (Emotet appears to use two different types for obfuscating its flow). 

The idea is simple. We create a list of relevant blocks (blocks without a 'cmp state_register' instruction). As soon as a compare instruction with a state register is reached,
we start checking if there is an address that is also included in the list of relevant blocks. If it is then we mark it for patching.

To link a block with another one, we check if there are any 'jmp' instructions in it. If there is then we simply patch with the destination address we have collectied.
In case it is not, we check the next block node for a 'jmp' instruction and patch with the destination address.

The script was tested against one Emotet sample only, SHA-1: e186e0869276d3af6465d7c754b22527c7ac2ced

Any patches are applied to IDA (idb) only and not to the actual file.
'''

from unicorn import *
from unicorn.x86_const import *
import pefile


collected_addresses = []
relavant_block = []
flag = 0
full_block_info = {}



def hook_block(uc, address, size, user_data):
    global flag
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))
    disasmed = generate_disasm_line(address,0)

    if flag:
        for i in relavant_block:
            if address == i:
                collected_addresses.append(i)
                flag = 0
    #Skip calls            
    if 'call' in disasmed:
        uc.reg_write(UC_X86_REG_EIP, address+5  )
    if 'cmp' in print_insn_mnem(address) and 'ecx' in print_operand(address,0):
        flag = 1



def check_if_rel_block(start_address,end_address):
    start_addr = start_address
    end_address = end_address
    while start_addr < end_address:
        disasmed = generate_disasm_line(start_addr,0)
        if 'cmp     ecx' in disasmed:
            return 0
        start_addr = next_head(start_addr)
    return 1

def find_relevant_blocks(func_address):
    function = idaapi.get_func(func_address)
    flowchart = idaapi.FlowChart(function)
    global relavant_block
    global full_block_info
    for bb in flowchart:
        start_addr = bb.start_ea
        end_address = bb.end_ea
        if check_if_rel_block(start_addr,end_address):
            full_block_info[bb.start_ea] = prev_head(bb.end_ea)
            relavant_block.append(bb.start_ea)
    return relavant_block

def patch_jump(address,destination):
    ret, buf  = Assemble(address, "jmp {0:x}h".format(destination) )
    print ("{0:x} => {1:x}".format( address,destination))
    ida_bytes.patch_bytes(address, buf)

def patch_jmps(full_node_info,dests_array):
    patched = []
    for i in range(len(dests_array)):
        start = dests_array[i]
        end = full_node_info[dests_array[i]]
        while start<=end:
            disasmed = generate_disasm_line(start,0)
            try:
                if 'jmp' in disasmed and dests_array[i+1]:
                    patch_jump(start,dests_array[i+1])
                    patched.append(dests_array[i])
                    break
            except IndexError:
                print ("[-] No next element in the addresses list")
            start = next_head(start)
        
    #No jump found in the same block. search the next block for switch register in it and  jump instructon. if there are then patch 
    for p in range(len(dests_array)):
        end = full_node_info[dests_array[p]]
        if dests_array[p] in patched:
            continue
        for i in range(2): #We want only the next 2 instructions
            end = next_head(end)
            disasmed = generate_disasm_line(end,0)
            if 'jmp' in disasmed:
                patch_jump(end, dests_array[p+1]) #a check needs to be added here to validate that there is a follow up element in the list



found_blocks = find_relevant_blocks(0x03412654) #Change to a different address
if len(found_blocks) == 0:
    print ("[-] No relavant blocks were found")
    exit()
STACK_LIMIT = 0x117d000
STACK_BASE = 0x1180000
HOOK_BASE = 0x2000000



with open("ipzyqmelqzh_dump.dll", 'rb') as f:
    PE_IMAGE = f.read()


pe = pefile.PE(data=PE_IMAGE)

IMAGE_BASE = pe.OPTIONAL_HEADER.ImageBase
SIZE_OF_IMAGE = pe.OPTIONAL_HEADER.SizeOfImage
ENTRY_POINT = pe.OPTIONAL_HEADER.AddressOfEntryPoint

try:
    mapped_image = pe.get_memory_mapped_image(ImageBase=IMAGE_BASE)
except AttributeError:
    mapped_image = PE_IMAGE


mapped_size = (len(mapped_image) + 0x1000) & ~0xFFF
uc = Uc(UC_ARCH_X86, UC_MODE_32)
uc.mem_map(IMAGE_BASE, mapped_size)
uc.mem_write(IMAGE_BASE, mapped_image)

uc.mem_map(STACK_LIMIT, STACK_BASE-STACK_LIMIT)
uc.mem_write(STACK_LIMIT, b'\xdd' * (STACK_BASE-STACK_LIMIT))

uc.reg_write(UC_X86_REG_ESP, STACK_BASE-0x800)
uc.reg_write(UC_X86_REG_EBP, STACK_BASE-0x400)
uc.hook_add(UC_HOOK_CODE , hook_block)

uc.emu_start(0x03412654, 0x3412984) #Change to a different address

    
patch_jmps(full_block_info,collected_addresses)

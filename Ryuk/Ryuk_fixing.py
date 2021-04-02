def fix_jump(eai):
    if print_insn_mnem(eai) == "jnz" or print_insn_mnem(eai) == "jmp" or print_insn_mnem(eai) == "jz":
        if GetDisasm(eai)[-2:-1] == "+" and GetDisasm(eai)[-1:].isdigit() and "$" not in GetDisasm(eai):
            print ("Broken Instruction: {0:x}".format(eai), GetDisasm(eai) )
            
            code_addr = get_operand_value(eai, 0) -  int( GetDisasm(eai)[-1:] )
            fix_addr = get_operand_value(eai, 0) +  int( GetDisasm(eai)[-1:])
            del_items(code_addr,int( GetDisasm(eai)[-1:]) )
            create_insn( get_operand_value(eai, 0) )
            
def fix_stack_jump():

    ea = ida_ida.cvar.inf.min_ea
    end = 0x35014200
    while True:
        ea = ida_search.find_binary(ea, end, "80 04 24 ?? c3", 16, SEARCH_NEXT|SEARCH_DOWN)
        if ea == idaapi.BADADDR:
            break
        print ( "Found at: {0:x}".format(ea) )
        print ( "Defining code at: {0:x}".format(next_head(ea)+1) ) #ret is one byte so we just add it and get the next address that we want to convert to code
        create_insn( next_head(ea)+1 )
        fix_jump2(prev_head(ea))

def fix_jump2(ea):
    original_ea = ea
    end = ea+0x50  #search next few instructions
    while ea<end:
        if print_insn_mnem(ea) == "jnz" or print_insn_mnem(ea) == "jmp" or print_insn_mnem(ea) == "jz":
            if GetDisasm(ea)[-2:-1] == "+" and GetDisasm(ea)[-1:].isdigit() and "$" not in GetDisasm(ea):
                print ("Broken Instruction: {0:x}".format(ea), GetDisasm(ea) )
                print ( "Jump source: {0:x}".format(original_ea) )
                print ( "Jump destination: {0:x}".format(next_head(ea)) )
                ret, buf = Assemble(original_ea, "jmp {0:x}h".format(next_head(ea)+1) )
                ida_bytes.patch_bytes(original_ea, buf)
                break
        ea = next_head(ea)
        
def find_stack_to_fix():
    ea = ida_ida.cvar.inf.min_ea
    end = 0x35014200
    while ea<end:
        fix_jump(ea)
        ea = next_head(ea)
        
find_stack_to_fix()

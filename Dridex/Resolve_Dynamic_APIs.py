#Resolve Dridex APIs by using the 'Appcall' instruction of IDA
function_name = "Resolve_API"
definition = "int  __stdcall {:s}(int hash1, int hash2);".format(function_name)
decrypt_function = Appcall.definition(function_name, definition)
for xrefs in XrefsTo(get_name_ea_simple(function_name)):
    hash1 = prev_head(xrefs.frm)
    if print_insn_mnem( hash1 ) == "push":
        hash1_value = get_operand_value( hash1, 0)
        hash2 = prev_head( hash1 )
        if print_insn_mnem( hash2 ) == "push":
            hash2_value = get_operand_value( hash2, 0)
            res = decrypt_function(hash1_value,hash2_value)
            if res != 0:
                function_name = get_function_name(res)
                if len(function_name) == 0:
                    print (function_name)
                    print ( "Address: {}".format ( hex(xrefs.frm) ))
                else:
                    RVA = xrefs.frm - 0x75680000 #0x75680000 base address
                    API_address = RVA + 0x0400000 #0x0400000 base address without debugging
                    print( str(hex(API_address)) )
                    print( hex( res ) )
                    print(function_name)
                    print("\n")
            else:
                print ("failed: {}".format ( hex(xrefs.frm)) )

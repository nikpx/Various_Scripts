def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def Read_Encrypted_Bytes(address):
    result = b''
    while True:
        read_bytes = idaapi.get_bytes(address,4)
        if read_bytes == b'\x00\x00\x00\x00':
            break
        result += read_bytes
        address += 4
    return result

def decrypt_string(address):
    encrypted_string_address = Read_Encrypted_Bytes(address)

    encrypted_string = encrypted_string_address[8:]

    encrypted_string_size = encrypted_string_address[4:8]

    string_size = byte_xor(encrypted_string_address[:4], encrypted_string_size)

    string_size = int.from_bytes(string_size,'little')
    
    xor_key = encrypted_string_address[:4]
    output = b''
    
    for i in range(0,string_size,4):
        output += byte_xor(xor_key,encrypted_string[i:i+4])
    
    return output[:string_size].decode('utf8')

for xref in XrefsTo(0x10004BB4):
    address = prev_head(xref.frm)
    decrypted_flag = 0 
    for i in range(10):
        if 'ecx' in print_operand(address,0):
            encrypted_address = get_operand_value(address,1)
            decrypted_string = decrypt_string(encrypted_address)
            print ("Decrypted string: {0} at {1:x}".format(decrypted_string,address))
            set_cmt(xref.frm,decrypted_string,0)
            decrypted_flag =1
            break
        address = prev_head(address)
    if decrypted_flag == 0:
        print ("Failed to decrypt at {0:x}".format(xref.frm))

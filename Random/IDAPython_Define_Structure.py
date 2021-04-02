#Create a structure with a specified size. Found it a tedious task
#to manually create big structures (with unknown members).
structure_name = idaapi.ask_str("Structure_Name",0, "Structure name")
structure_name = idc.add_struc(-1, structure_name, 0)
num_members = idaapi.ask_long(1, "Number of members")
Binary_Architecture = idaapi.get_inf_structure()

if Binary_Architecture.is_64bit():
    nbytes = 8
    flag = idc.FF_QWORD
elif Binary_Architecture.is_32bit():
    nbytes = 4
    flag = idc.FF_DWORD

for i in range(num_members):
    idc.add_struc_member(structure_name, "Unknown_member{0}".format(i), -1, flag, -1, nbytes)
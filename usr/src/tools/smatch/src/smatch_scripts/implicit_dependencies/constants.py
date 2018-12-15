from collections import defaultdict

# location of kernel.implicit_dependencies
IMPL_DEP_FILE_STR = "../../smatch_data/kernel.implicit_dependencies"
OUTPUT_FILE_STR = "implicit_dependencies"

# struct fields to ignore, because they are too common
GLOBAL_BLACKLIST = [
    ('fd', 'file'),
]

# here we can manually add struct fields that smatch missed
hardcode_syscall_write_fields = {}

# here we can manually add struct fields that smatch missed
hardcode_syscall_read_fields = {
    "msync": [("vm_area_struct", "vm_flags"), ("vm_area_struct", "vm_file")]
}

SYSCALL_PREFIXES = [
    "SYSC_",
    "C_SYSC_",
    "sys_",
]

class ListType(object):
    READ = "read_list"
    WRITE = "write_list"

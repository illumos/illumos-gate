#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"

@ _START_

# Message file for elfedit 'ehdr' module

@ MSG_ID_ELFEDIT_EHDR


# Debug messages
@ MSG_DEBUG_E_S_OK	"ehdr.%s: value unchanged: %s\n"
@ MSG_DEBUG_E_S_CHG	"ehdr.%s: change from %s to %s\n"
@ MSG_DEBUG_E_D_OK	"ehdr.%s: value unchanged: %d\n"
@ MSG_DEBUG_E_D_CHG	"ehdr.%s: change from %d to %d\n"
@ MSG_DEBUG_E_LLX_OK	"ehdr.%s: value unchanged: %#llx\n"
@ MSG_DEBUG_E_LLX_CHG	"ehdr.%s: change from %#llx to %#llx\n"
@ MSG_DEBUG_EI_S_S_OK	"ehdr.e_ident[%s]: value unchanged: %s\n";
@ MSG_DEBUG_EI_S_S_CHG	"ehdr.e_ident[%s]: change from %s to %s\n"
@ MSG_DEBUG_EI_S_X_OK	"ehdr.e_ident[%s]: value unchanged: %#x\n";
@ MSG_DEBUG_EI_S_X_CHG	"ehdr.e_ident[%s]: change from %#x to %#x\n"
@ MSG_DEBUG_EI_D_X_OK	"ehdr.e_ident[%d]: value unchanged: %#x\n"
@ MSG_DEBUG_EI_D_X_CHG	"ehdr.e_ident[%d]: change from %#x to %#x\n"
@ MSG_DEBUG_SHDR0_D_OK	"shdr[0].%s: value unchanged: %d\n"
@ MSG_DEBUG_SHDR0_D_CHG	"shdr[0].%s: change from %d to %d\n"
@ MSG_DEBUG_NOTSTRTAB	"ehdr.%s: ELF warning: section is not a \
			 string table: %d\n"


# Module description

@ MSG_MOD_DESC		"ELF Header"


# 1-line description strings

@ MSG_DESC_DUMP			"Dump ELF Header"
@ MSG_DESC_E_IDENT		"ELF Identification"
@ MSG_DESC_E_TYPE		"Object File Type"
@ MSG_DESC_E_MACHINE		"Machine Architecture"
@ MSG_DESC_E_VERSION		"Object File Version"
@ MSG_DESC_E_ENTRY		"Starting Virtual Address"
@ MSG_DESC_E_PHOFF		"Program Header Table File Offset"
@ MSG_DESC_E_SHOFF		"Section Header Table File Offset"
@ MSG_DESC_E_FLAGS		"Processor-Specific Flags"
@ MSG_DESC_E_EHSIZE		"ELF Header's Size"
@ MSG_DESC_E_PHENTSIZE		"Program Header Table Entry Size"
@ MSG_DESC_E_PHNUM		"Number Program Header Entries"
@ MSG_DESC_E_SHENTSIZE		"Section Header Table Entry Size"
@ MSG_DESC_E_SHNUM		"Number Section Header Entries"
@ MSG_DESC_E_SHSTRNDX		"Section Name String Table Index"

@ MSG_DESC_EI_MAG0		"File Identification Byte #1"
@ MSG_DESC_EI_MAG1		"File Identification Byte #2"
@ MSG_DESC_EI_MAG2		"File Identification Byte #3"
@ MSG_DESC_EI_MAG3		"File Identification Byte #4"
@ MSG_DESC_EI_CLASS		"File Class (System Word Size)"
@ MSG_DESC_EI_DATA		"Data Encoding (Byte Order)"
@ MSG_DESC_EI_VERSION		"File Version"
@ MSG_DESC_EI_OSABI		"Operating System / ABI Identification"
@ MSG_DESC_EI_ABIVERSION	"ABI version"

# Command option description strings

@ MSG_OPTDESC_SHNDX	"\
   Interpret the sec argument as a section index rather than\n\
   as a section name. section can be one of the well known SHN_\n\
   symbolic constants, or any integer.\n"

@ MSG_OPTDESC_SHTYP	"\
   Interpret the sec argument as a section type rather than\n\
   as a section name. section can be one of the well known SHT_\n\
   symbolic constants, or any integer.\n"

# Command argument description strings

@ MSG_ARGDESC_E_IDENT_NDX	"\
   Index of element of e_ident[] array. This can be\n\
   an integer value, or any of the EI_ symbolic constants\n\
   defined in /usr/include/sys/elf.h.\n"

@ MSG_ARGDESC_E_IDENT_VALUE	"\
   New value for element of e_ident[] array. This can be\n\
   an integer value, or any symbolic constants defined in\n\
   /usr/include/sys/elf.h that apply to the selected item.\n"

@ MSG_ARGDESC_E_TYPE_VALUE	"\
   New value for type of the ELF object. This can be\n\
   an integer value, or any of the ET_ symbolic constants\n\
   defined in /usr/include/sys/elf.h.\n"

@ MSG_ARGDESC_E_MACHINE_VALUE	"\
   New value for architecture of the ELF object. This can be\n\
   an integer value, or any of the EM_ symbolic constants\n\
   defined in /usr/include/sys/elf.h.\n"

@ MSG_ARGDESC_E_VERSION_VALUE	"\
   New value for version of the ELF object. This can be\n\
   an integer value, or any of the EV_ symbolic constants\n\
   defined in /usr/include/sys/elf.h.\n"

@ MSG_ARGDESC_E_ENTRY_VALUE	"\
   New value for virtual address to which the system first transfers control.\n"

@ MSG_ARGDESC_E_PHOFF_VALUE	"\
   New value for program header table's file offset.\n"

@ MSG_ARGDESC_E_SHOFF_VALUE	"\
   New value for section header table's file offset.\n"

@ MSG_ARGDESC_E_FLAGS_VALUE	"\
   New value for processor-specific flags. This can be an integer\n\
   value, or any of the EF_ symbolic constants defined in the\n\
   system header files\n"

@ MSG_ARGDESC_E_EHSIZE_VALUE	"\
   New value for size of ELF header, in bytes.\n"

@ MSG_ARGDESC_E_PHENTSIZE_VALUE	"\
   New value for size of one entry in the file's program header table,\n\
   in bytes.\n"

@ MSG_ARGDESC_E_PHNUM_VALUE	"\
   New value for number of entries in the program header table.\n"

@ MSG_ARGDESC_E_SHENTSIZE_VALUE	"\
   New value for size of one entry in the file's section header table,\n\
   in bytes.\n"

@ MSG_ARGDESC_E_SHNUM_VALUE	"\
   New value for number of entries in the section header table.\n"

@ MSG_ARGDESC_E_SHSTRNDX_SEC	"\
   String table section containing section name strings.\n\
   By default, this argument is interpreted as the name\n\
   of the desired section. The section index of the first\n\
   section with the specified name is used.\n\
   \n\
   If -shndx is set, then sec is a section index, and is\n\
   interpreted as an integer, or one of the well known SHN_\n\
   symbolic constant names.\n\
   \n\
   If -shtyp is set, then sec is a section type, and is\n\
   interpreted as an integer, or one of the well known SHT_\n\
   symbolic constant names. The section index of the first\n\
   section with the specified type is used.\n"

@ MSG_ARGDESC_EI_MAG0_VALUE	"\
   New value for first byte of file magic number.\n"

@ MSG_ARGDESC_EI_MAG1_VALUE	"\
   New value for second byte of file magic number.\n"

@ MSG_ARGDESC_EI_MAG2_VALUE	"\
   New value for third byte of file magic number.\n"

@ MSG_ARGDESC_EI_MAG3_VALUE	"\
   New value for fourth byte of file magic number.\n"

@ MSG_ARGDESC_EI_CLASS_VALUE	"\
   New value for file's class. This can be an integer value, or any of\n\
   the ELFCLASS symbolic constants defined in /usr/include/sys/elf.h.\n"

@ MSG_ARGDESC_EI_DATA_VALUE	"\
   New value for file's data encoding. This can be an integer\n\
   value, or any ELFDATA symbolic constants defined in\n\
   /usr/include/sys/elf.h.\n"

# Note: EI_VERSION uses the same string as E_VERSION, above

@ MSG_ARGDESC_EI_OSABI_VALUE	"\
   New value for ABI identification of the ELF object. This can be\n\
   an integer value, or any of the ELFOSABI_ symbolic constants\n\
   defined in /usr/include/sys/elf.h.\n"

@ MSG_ARGDESC_EI_ABIVERSION_VALUE	"\
   New value for version of the ABI to which the object is targeted.\n"


# Help strings

@ MSG_HELP_DUMP	"   \
   The ehdr:dump command is used to display the contents of\n\
   the ELF header using the same style used by the elfdump program.\n"

@ MSG_HELP_E_IDENT	"   \
   Examine or modify ELF Identification information for the\n\
   object. This information is found in the e_ident array in\n\
   the ELF header.\n\
   \n\
   If ehdr:e_ident is called without any argument, all values\n\
   the value in e_ident are shown. If called with the index\n\
   argument, the selected element of e_ident is shown. If also\n\
   called with the value argument, the selected e_ident element\n\
   is updated with the new value.\n"


@ MSG_HELP_E_TYPE	"   \
   Examine or modify the object file type. This information is\n\
   found in the e_type field of the ELF header.\n\
   \n\
   If ehdr:e_type is called without an argument, the value of\n\
   e_type is shown. If called with the value argument, the\n\
   e_type field is updated with the new value.\n\
   \n\
   Note: Changing the type code of an object does not change the\n\
   other contents of the file, and is unlikely to produce a usable\n\
   ELF object.\n"


@ MSG_HELP_E_MACHINE	"   \
   Examine or modify the required architecture of the object.\n\
   This information is found in the e_machine field of the\n\
   ELF header.\n\
   \n\
   If ehdr:e_machine is called without an argument, the value of\n\
   e_machine is shown. If called with the value argument, the\n\
   e_machine field is updated with the new value.\n\
   \n\
   Note: Changing the architecture code of an object does not change the\n\
   other contents of the file, and is unlikely to produce a usable\n\
   ELF object.\n"


@ MSG_HELP_E_VERSION	"   \
   Examine or modify the object file version. This information\n\
   is found in the e_version field of the ELF header.\n\
   \n\
   If ehdr:e_version is called without an argument, the value of\n\
   e_version is shown. If called with the value argument, the\n\
   e_version field is updated with the new value.\n\
   \n\
   Note: The e_ident[EI_VERSION] element of the ELF header\n\
   identification array also contains a version value. These\n\
   two fields should be set to the same value. Use the\n\
   ehdr:ei_version command to change that element.\n"


@ MSG_HELP_E_ENTRY	"   \
   Examine or modify the virtual address to which the system\n\
   first transfers control, thus starting the process. This\n\
   information is found in the e_entry field of the ELF header.\n\
   If the file has no associated entry point, this member\n\
   holds zero.\n\
   \n\
   If ehdr:e_entry is called without an argument, the value of\n\
   e_entry is shown. If called with the value argument, the\n\
   e_entry field is updated with the new value.\n\
   \n\
   Note: The entry point of an object is highly system\n\
   dependent. Changing it is likely to produce an object that\n\
   does not run properly.\n"


@ MSG_HELP_E_PHOFF	"   \
   Examine or modify the program header table's file offset.\n\
   This information is found in the e_phoff field of the\n\
   ELF header. If the file has no program header table, this\n\
   member holds zero.\n\
   \n\
   If ehdr:e_phoff is called without an argument, the value of\n\
   e_phoff is shown. If called with the value argument, the\n\
   e_phoff field is updated with the new value.\n\
   \n\
   Note: Changing the e_phoff field of an object does not change\n\
   the actual layout of the file or move the program header table.\n\
   As such, changing this value is likely to produce an unusable\n\
   ELF object.\n"


@ MSG_HELP_E_SHOFF	"   \
   Examine or modify the section header table's file offset.\n\
   This information is found in the e_shoff field of the\n\
   ELF header. If the file has no section header table, this\n\
   member holds zero.\n\
   \n\
   If ehdr:e_shoff is called without an argument, the value of\n\
   e_shoff is shown. If called with the value argument, the\n\
   e_shoff field is updated with the new value.\n\
   \n\
   Note: Changing the e_shoff field of an object does not change\n\
   the actual layout of the file or move the section header table.\n\
   As such, changing this value is likely to produce an unusable\n\
   ELF object.\n"


@ MSG_HELP_E_FLAGS	"   \
   Examine or modify the processor specific flags associated\n\
   with the file. This information is found in the e_flags\n\
   field of the ELF header.\n\
   \n\
   If ehdr:e_flags is called without an argument, the value of\n\
   e_flags is shown. If called with one or more flag_value\n\
   arguments, the the following steps are taken:\n\
   \n   \
   o\tAll the flag_value arguments are OR'd together.\n\
   \n   \
   o\tIf the -cmp option has been specified, the new value\n\
   \tis complemented.\n\
   \n   \
   o\tThe e_flags field of the ELF header is updated with\n\
   \tthe new value. If -and is specified, the new value is\n\
   \tAND'd against the existing value. If -or is specified,\n\
   \tthe new value is OR'd against the existing value. If\n\
   \tneither -and or -or are specified, the new value replaces\n\
   \tthe existing value.\n\
   \n\
   Note: Changing the e_flags field of an object does not change\n\
   the code contained in the file. Setting a flag that implies\n\
   an ability the existing code cannot support will produce an\n\
   unusable ELF object.\n"


@ MSG_HELP_E_EHSIZE	"   \
   Examine or modify the size of the ELF header. This information\n\
   is found in the e_ehsize field of the ELF header.\n\
   \n\
   If ehdr:e_ehsize is called without an argument, the value of\n\
   e_ehsize is shown. If called with the value argument, the\n\
   e_ehsize field is updated with the new value.\n\
   \n\
   Note: Changing the e_ehsize field of the ELF header does not\n\
   change the size of the actual ELF header data structure. Setting\n\
   it to a different value is likely to produce an unusable ELF object.\n"


@ MSG_HELP_E_PHENTSIZE	"   \
   Examine or modify the size of one entry in the file's program\n\
   header table. This information is found in the e_phentsize\n\
   field of the ELF header.\n\
   \n\
   If ehdr:e_phentsize is called without an argument, the value of\n\
   e_phentsize is shown. If called with the value argument, the\n\
   e_phentsize field is updated with the new value.\n\
   \n\
   Note: Changing the e_phentsize field of the ELF header does\n\
   not change the size of the actual program header array elements.\n\
   Setting it to a different value is likely to produce an unusable\n\
   ELF object.\n"


@ MSG_HELP_E_PHNUM	"   \
   Examine or modify the number of entries in the program header\n\
   table. This information is found in the e_phnum field of the\n\
   ELF header, or in the sh_link field of the first section header\n\
   in the case of extended program indexes.\n\
   \n\
   If the number of program headers is greater than or equal\n\
   to PN_XNUM (0xffff), e_phnum has the value PN_XNUM, and the\n\
   actual number of program header table entries is contained\n\
   in the sh_info field of the section header at index 0.\n\
   \n\
   If ehdr:e_phnum is called without an argument, the number\n\
   of program headers is shown. If called with the value argument,\n\
   the number is updated with the new value.\n\
   \n\
   Note: Changing e_phnum and/or the sh_link field of the first\n\
   section header  does not change the size of the actual program\n\
   header array in the file.\n"


@ MSG_HELP_E_SHENTSIZE	"   \
   Examine or modify the size of one entry in the file's section\n\
   header table. This information is found in the e_shentsize\n\
   field of the ELF header.\n\
   \n\
   If ehdr:e_shentsize is called without an argument, the value of\n\
   e_shentsize is shown. If called with the value argument, the\n\
   e_shentsize field is updated with the new value.\n\
   \n\
   Note: Changing the e_shentsize field of the ELF header does\n\
   not change the size of the actual section header array elements.\n\
   Setting it to a different value is likely to produce an unusable\n\
   ELF object.\n"


@ MSG_HELP_E_SHNUM	"   \
   Examine or modify the number of entries in the section header\n\
   table. This information is found in the e_shnum field of the\n\
   ELF header, or in the sh_size field of the first section header\n\
   in the case of extended section indexes.\n\
   \n\
   If the number of sections is greater than or equal to\n\
   SHN_LORESERVE (0xff00), e_shnum has the value zero, and\n\
   the actual number of section header table entries is\n\
   contained in the sh_size field of the section header\n\
   at index 0.\n\
   \n\
   If ehdr:e_shnum is called without an argument, the number of\n\
   sections is shown. If called with the value argument, the\n\
   number of sections is updated with the new value.\n\
   \n\
   Note: Changing e_shnum and/or the sh_size field of the first\n\
   section header does not change the size of the actual section\n\
   header array in the file.\n"


@ MSG_HELP_E_SHSTRNDX	"   \
   Examine or modify the section table index of the entry that is\n\
   associated with the section name string table. This information\n\
   is found in the e_shstrndx field of the ELF header, or in the\n\
   sh_link field of the first section header in the case of\n\
   extended section indexes. If the file has no section name\n\
   string table, this member holds the value SHN_UNDEF.\n\
   \n\
   If the section name string table section index is greater\n\
   than or equal to SHN_LORESERVE (0xff00), e_shstrndx has the\n\
   value SHN_XINDEX (0xffff) and   the actual index of the section\n\
   name string table section is contained in the sh_link field of\n\
   the section header at index 0.\n\
   \n\
   If ehdr:e_shstrndx is called without an argument, the index of\n\
   the section name string table is shown. If called with the value\n\
   argument, the ELF header is updated with the new value.\n\
   \n\
   Note: The e_shstrndx field of the ELF header must reference\n\
   a string table section. Otherwise, diagnostic tools will be\n\
   confused by the resulting object.\n"


@ MSG_HELP_EI_MAG0	"   \
   Examine or modify the first byte of the object's \"magic number\".\n\
   The magic number is the first 4 bytes of the object file, and is\n\
   used to identify it as being an ELF object. This information\n\
   is found in the e_ident[EI_MAG0] field of the ELF header.\n\
   \n\
   If ehdr:ei_mag0 is called without an argument, the value of\n\
   e_ident[EI_MAG0] is shown. If called with the value argument,\n\
   the e_ident[EI_MAG0] field is updated with the new value.\n\
   \n\
   Note: Changing the e_ident[EI_MAG0] field of the ELF header\n\
   to a value other than 0x7f will cause the system to fail to\n\
   identify it as an ELF object.\n"


@ MSG_HELP_EI_MAG1	"   \
   Examine or modify the second byte of the object's \"magic number\".\n\
   The magic number is the first 4 bytes of the object file, and is\n\
   used to identify it as being an ELF object. This information\n\
   is found in the e_ident[EI_MAG1] field of the ELF header.\n\
   \n\
   If ehdr:ei_mag1 is called without an argument, the value of\n\
   e_ident[EI_MAG1] is shown. If called with the value argument,\n\
   the e_ident[EI_MAG1] field is updated with the new value.\n\
   \n\
   Note: Changing the e_ident[EI_MAG1] field of the ELF header\n\
   to a value other than 0x45 ('E') will cause the system to\n\
   fail to identify it as an ELF object.\n"


@ MSG_HELP_EI_MAG2	"   \
   Examine or modify the third byte of the object's \"magic number\".\n\
   The magic number is the first 4 bytes of the object file, and is\n\
   used to identify it as being an ELF object. This information\n\
   is found in the e_ident[EI_MAG2] field of the ELF header.\n\
   \n\
   If ehdr:ei_mag2 is called without an argument, the value of\n\
   e_ident[EI_MAG2] is shown. If called with the value argument,\n\
   the e_ident[EI_MAG2] field is updated with the new value.\n\
   \n\
   Note: Changing the e_ident[EI_MAG2] field of the ELF header\n\
   to a value other than 0x4c ('L') will cause the system to\n\
   fail to identify it as an ELF object.\n"


@ MSG_HELP_EI_MAG3	"   \
   Examine or modify the fourth byte of the object's \"magic number\".\n\
   The magic number is the first 4 bytes of the object file, and is\n\
   used to identify it as being an ELF object. This information\n\
   is found in the e_ident[EI_MAG3] field of the ELF header.\n\
   \n\
   If ehdr:ei_mag3 is called without an argument, the value of\n\
   e_ident[EI_MAG3] is shown. If called with the value argument,\n\
   e_ident[EI_MAG3] field is updated with the new value.\n\
   \n\
   Note: Changing the e_ident[EI_MAG3] field of the ELF header\n\
   to a value other than 0x46 ('F') will cause the system to\n\
   fail to identify it as an ELF object.\n"


@ MSG_HELP_EI_CLASS	"   \
   Examine or modify the file's class (system word size). This\n\
   information is found in the e_ident[EI_CLASS] field of the\n\
   ELF header.\n\
   \n\
   If ehdr:ei_class is called without an argument, the value of\n\
   e_ident[EI_CLASS] is shown. If called with the value argument,\n\
   the e_ident[EI_CLASS] field is updated with the new value.\n\
   \n\
   Note: Changing the e_ident[EI_CLASS] field of the ELF header\n\
   does not alter the contents of the file, and is therefore\n\
   likely to render the file unusable.\n"

@ MSG_HELP_EI_DATA	"   \
   Examine or modify the file's data encoding (byte order). This\n\
   information is found in the e_ident[EI_DATA] field of the\n\
   ELF header.\n\
   \n\
   If ehdr:ei_data is called without an argument, the value of\n\
   e_ident[EI_DATA] is shown. If called with the value argument,\n\
   the e_ident[EI_DATA] field is updated with the new value.\n\
   \n\
   Note: Changing the e_ident[EI_DATA] field of the ELF header\n\
   does not alter the contents of the file or the byte order\n\
   of the data, and is therefore likely to render the file unusable.\n"


@ MSG_HELP_EI_VERSION	"   \
   Examine or modify the object file version. This information\n\
   is found in the e_ident[EI_VERSION] field of the ELF header.\n\
   \n\
   If ehdr:ei_version is called without an argument, the value\n\
   of e_ident[EI_VERSION]  is shown. If called with the value\n\
   argument, the e_ident[EI_VERSION] field is updated with the\n\
   new value.\n\
   \n\
   Note: The e_version element of the ELF header also contains\n\
   a version value. These two fields should be set to the same\n\
   value. Use the ehdr:e_version command to change that element.\n"


@ MSG_HELP_EI_OSABI	"   \
   Examine or modify the operating system / ABI identification for\n\
   the object. This information is kept in the e_ident[EI_OSABI]\n\
   field of the ELF header.\n\
   \n\
   If ehdr:ei_osabi is called without arguments, current value of\n\
   e_ident[EI_OSABI] is shown. If called with the value argument,\n\
   the e_ident[EI_OSABI] field is updated with the new value.\n\
   \n\
   Note: Changing the e_ident[EI_OSABI] field of the ELF header\n\
   does not alter the contents of the file, or cause the actual\n\
   ABI to be altered. Setting an incompatible ABI value is likely\n\
   to cause the object to become unusable.\n"


@ MSG_HELP_EI_ABIVERSION	"   \
   Examine or modify the ABI version for the object. This\n\
   information is kept in the e_ident[EI_ABIVERSION] field of\n\
   the ELF header.\n\
   \n\
   If ehdr:ei_abiversion is called without arguments, the current\n\
   value of e_ident[EI_ABIVERSION] is shown. If called with the\n\
   value argument, the e_ident[EI_ABIVERSION] field is updated with\n\
   the new value.\n\
   \n\
   Note: The meaning of the e_ident[EI_ABIVERSION] field of\n\
   the ELF header depends on the value of e_ident[EI_OSABI]\n\
   (See ehdr:ei_osabi).\n"


@ _END_



# Strings

@ MSG_STR_EMPTY		""
@ MSG_STR_NL		"\n"
@ MSG_STR_VALUE		"value"
@ MSG_STR_EIDENT_HDR	"e_ident:\n"
@ MSG_STR_INDEX		"index"
@ MSG_STR_SEC		"sec"
@ MSG_STR_TYPE		"type"
@ MSG_STR_VERSION	"version"
@ MSG_STR_OFFSET	"offset"
@ MSG_STR_FLAGVALUE	"flag_value"
@ MSG_STR_MINUS_SHNDX	"-shndx"
@ MSG_STR_MINUS_SHTYP	"-shtyp"
@ MSG_STR_SH_INFO	"sh_info"
@ MSG_STR_SH_LINK	"sh_link"
@ MSG_STR_SH_SIZE	"sh_size"


# Format strings
@ MSG_FMT_BKTSTR	"[%s]"
@ MSG_FMT_BKTINT	"[%d]"
@ MSG_FMT_STRNL		"%s\n"
@ MSG_FMT_WORDVAL	"%u"
@ MSG_FMT_DECNUMNL	"%d\n"
@ MSG_FMT_HEXNUM	"%#x"
@ MSG_FMT_HEXNUMNL	"%#x\n"
@ MSG_FMT_HEXNUM_QCHR	"%#x ('%c')"
@ MSG_FMT_EI_ELT	"    %-18s%s\n"




# The following strings represent reserved words, files, pathnames and symbols.
# Reference to this strings is via the MSG_ORIG() macro, and thus no message
# translation is required.


# Module name

@ MSG_MOD_NAME		"ehdr"


# Command names

@ MSG_CMD_DUMP		"dump"

@ MSG_CMD_E_IDENT	"e_ident"
@ MSG_CMD_E_TYPE	"e_type"
@ MSG_CMD_E_MACHINE	"e_machine"
@ MSG_CMD_E_VERSION	"e_version"
@ MSG_CMD_E_ENTRY	"e_entry"
@ MSG_CMD_E_PHOFF	"e_phoff"
@ MSG_CMD_E_SHOFF	"e_shoff"
@ MSG_CMD_E_FLAGS	"e_flags"
@ MSG_CMD_E_EHSIZE	"e_ehsize"
@ MSG_CMD_E_PHENTSIZE	"e_phentsize"
@ MSG_CMD_E_PHNUM	"e_phnum"
@ MSG_CMD_E_SHENTSIZE	"e_shentsize"
@ MSG_CMD_E_SHNUM	"e_shnum"
@ MSG_CMD_E_SHSTRNDX	"e_shstrndx"

@ MSG_CMD_EI_MAG0	"ei_mag0"
@ MSG_CMD_EI_MAG1	"ei_mag1"
@ MSG_CMD_EI_MAG2	"ei_mag2"
@ MSG_CMD_EI_MAG3	"ei_mag3"
@ MSG_CMD_EI_CLASS	"ei_class"
@ MSG_CMD_EI_DATA	"ei_data"
@ MSG_CMD_EI_VERSION	"ei_version"
@ MSG_CMD_EI_OSABI	"ei_osabi"
@ MSG_CMD_EI_ABIVERSION	"ei_abiversion"

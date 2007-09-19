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

# Message file for elfedit 'shdr' module

@ MSG_ID_ELFEDIT_SHDR


# Section header format
@ MSG_ELF_SHDR		"Section Header[%d]:  sh_name: %s\n"

# Debug messages

@ MSG_DEBUG_S_OK	"shdr[%d: %s].%s: value unchanged: %s\n"
@ MSG_DEBUG_S_CHG	"shdr[%d: %s].%s: change from %s to %s\n"
@ MSG_DEBUG_LLX_OK	"shdr[%d: %s].%s: value unchanged: %#llx\n"
@ MSG_DEBUG_LLX_CHG	"shdr[%d: %s].%s: change from %#llx to %#llx\n"
@ MSG_DEBUG_D_OK	"shdr[%d: %s].%s: value unchanged: %d\n"
@ MSG_DEBUG_D_CHG	"shdr[%d: %s].%s: change from %d to %d\n"
@ MSG_DEBUG_CHGSHDR0	"ELF warning: Unexpected direct change to \
			 section header [0]: Header [0] is used for \
			 extended section and program headers by the ehdr \
			 module, and should otherwise be completely zero\n"
@ MSG_DEBUG_ADDRALIGN	"ELF warning: sh_addralign value is expected to \
			 be 0, 1, or a power of 2: %s\n"


# Module description

@ MSG_MOD_DESC		"Section Header Array"


# 1-line description strings

@ MSG_DESC_DUMP		"Dump Section Headers"

@ MSG_DESC_SH_ADDR	"Section memory address"
@ MSG_DESC_SH_ADDRALIGN	"Section address alignment"
@ MSG_DESC_SH_ENTSIZE	"Section per-item size"
@ MSG_DESC_SH_FLAGS	"Section flags"
@ MSG_DESC_SH_INFO	"Section info"
@ MSG_DESC_SH_LINK	"Section link"
@ MSG_DESC_SH_NAME	"Section name"
@ MSG_DESC_SH_OFFSET	"Section file offset"
@ MSG_DESC_SH_SIZE	"Section size (bytes)"
@ MSG_DESC_SH_TYPE	"Section type"


# Command option description strings

@ MSG_OPTDESC_SHNDX	"\
   Interpret the sec argument as a section index rather than\n\
   as a section name. section can be one of the well known SHN_\n\
   symbolic constants, or any integer.\n"

@ MSG_OPTDESC_SHTYP	"\
   Interpret the sec argument as a section type rather than\n\
   as a section name. section can be one of the well known SHT_\n\
   symbolic constants, or any integer.\n"

@ MSG_OPTDESC_NAME_OFFSET	"\
   Interpret the name argument as a string table offset rather\n\
   than as a string.\n"


# Command argument descriptions

@ MSG_A1_SEC	"\
   Section to examine or modify. By default, this argument is\n\
   interpreted as the name of the desired section. The section\n\
   index of the first section with the specified name is used.\n\
   \n\
   If -shndx is set, then sec is a section index, and is\n\
   interpreted as an integer, or one of the well known SHN_\n\
   symbolic constant names.\n\
   \n\
   If -shtyp is set, then sec is a section type, and is\n\
   interpreted as an integer, or one of the well known SHT_\n\
   symbolic constant names. The section index of the first\n\
   section with the specified type is used.\n"

@ MSG_A2_DESC_SH_ADDR	"Integer value to set for section address.\n"

@ MSG_A2_DESC_SH_ADDRALIGN "\
   Integer value to set for section alignment.\n"

@ MSG_A2_DESC_SH_ENTSIZE "\
   Integer value to set for size of an individual element in\n\
   a section of fixed-size entries.\n"

@ MSG_A2_DESC_SH_FLAGS "\
   Section flags. SHF_ flag constants are accepted, as is\n\
   any integer.\n"

@ MSG_A2_DESC_SH_INFO	"\
   Integer value to set for symbol sh_info field. The meaning\n\
   of this value depends on the type of the section.\n"

@ MSG_A2_DESC_SH_LINK	"\
   Integer value to set for symbol sh_link field. The meaning\n\
   of this value depends on the type of the section.\n"

@ MSG_A2_DESC_SH_NAME	"\
   Name to set for section. If the -name_offset option is\n\
   used, this is an integer offset into the section header\n\
   string table. Otherwise, it is a string, which will be\n\
   looked up in the symbol table in order to obtain the needed\n\
    offset value.\n"

@ MSG_A2_DESC_SH_OFFSET	"\
   Integer value to set for symbol sh_offset field. The value\n\
   of sh_offset gives the byte offset from the beginning of\n\
   the file to the first byte in the section. For SHT_NOBITS\n\
   sections, this member indicates the conceptual offset in the\n\
   file, as the section occupies no space in the file.\n"

@ MSG_A2_DESC_SH_SIZE	"\
   Integer value to set for size of section, in bytes. Unless the\n\
   section type is SHT_NOBITS, the section occupies sh_size bytes\n\
   in the file. A section of type SHT_NOBITS can have a nonzero\n\
   size, but the section occupies no space in the file.\n"

@ MSG_A2_DESC_SH_TYPE	"\
   Value to set for section type. The value can be an integer,\n\
   or one of the well known SHT_ symbolic constant names.\n"



# Help strings

@ MSG_HELP_DUMP	"   \
   The shdr:dump command is used to display section header\n\
    information using the same style used by the elfdump program.\n\
   \n\
   If shdr:dump is called without arguments, information for every\n\
   section header in the object is shown. If called with the shndx\n\
   argument, the section header at that index is displayed.\n"

@ MSG_HELP_SH_ADDR	"   \
   The shdr:sh_addr command is used to display or alter the\n\
   starting virtual memory address of the section.\n\
   \n\
   If the section appears in the memory image of a process,\n\
   this member gives the address at which the sections's\n\
   first byte should reside. Otherwise, the member is expected\n\
   to contain the value zero.\n\
   \n\
   If shdr:sh_addr is called without arguments, the value of\n\
   sh_addr for every section in the section header array is\n\
   shown. If called with the shndx argument, the value of the\n\
   section at that index is displayed. If both arguments are\n\
   present, the sh_addr field of the section at the specified\n\
   index is set to the given value.\n"

@ MSG_HELP_SH_ADDRALIGN	"   \
   The shdr:sh_addralign command is used to display or alter the\n\
   alignment constraint for the section.\n\
   \n\
   Some sections have address alignment constraints. For example,\n\
   if a section holds a double-word, the system must ensure\n\
   double-word alignment for the entire section. In this case,\n\
   the value of sh_addr must be congruent to 0, modulo the value\n\
   of sh_addralign. Currently, only 0 and positive integral\n\
   powers of 2 are used in Solaris ELF files. Values 0 and 1\n\
   mean the section has no alignment constraints.\n\
   \n\
   If shdr:sh_addralign is called without arguments, the value\n\
   of sh_addralign for every section in the section header array\n\
   is shown. If called with the shndx argument, the value of the\n\
   section at that index is displayed. If both arguments are\n\
   present, the sh_addralign field of the section at the specified\n\
   index is set to the given value.\n"

@ MSG_HELP_SH_ENTSIZE	"   \
   The shdr:sh_entsize command is used to display or alter the\n\
   per-item entry size for the section.\n\
   \n\
   Some sections hold a table of fixed-size entries, such as a\n\
   symbol table. For such a section, this member gives the size\n\
   in bytes of each entry. By convention, the member is set to\n\
   the value zero if the section does not hold a table of\n\
   fixed-size entries.\n\
   \n\
   If shdr:sh_entsize is called without arguments, the value\n\
   of sh_entsize for every section in the section header array\n\
   is shown. If called with the shndx argument, the value of the\n\
   section at that index is displayed. If both arguments are\n\
   present, the sh_entsize field of the section at the specified\n\
   index is set to the given value.\n"

@ MSG_HELP_SH_FLAGS	"   \
   The shdr:sh_flags command is used to display or alter the\n\
   flags that are associated with the section.\n\
   \n\
   \n\
   If shdr:sh_flags is called without arguments, the value\n\
   of sh_flags for every section in the section header array\n\
   is shown. If called with the shndx argument, the value of\n\
   the section at that index is displayed. If one or more\n\
   value arguments are present, the following steps are taken:\n\
   \n   \
   o\tAll the value arguments are OR'd together.\n\
   \n   \
   o\tIf the -cmp option has been specified, the new value\n\
   \tis complemented.\n\
   \n   \
   o\tThe sh_flags field of the section header is updated with\n\
   \tthe new value. If -and is specified, the new value is\n\
   \tAND'd against the existing value. If -or is specified,\n\
   \tthe new value is OR'd against the existing value. If\n\
   \tneither -and or -or are specified, the new value replaces\n\
   \tthe existing value.\n"

@ MSG_HELP_SH_INFO	"   \
   The shdr:sh_info command is used to display or alter the\n\
   sh_info field of the specified section.\n\
   \n\
   sh_info contains extra information, the interpretation\n\
   of which depends on the section type.\n\
   \n\
   If shdr:sh_info is called without arguments, the value\n\
   of sh_info for every section in the section header array\n\
   is shown. If called with the shndx argument, the value of the\n\
   section at that index is displayed. If both arguments are\n\
   present, the sh_info field of the section at the specified\n\
   index is set to the given value.\n"

@ MSG_HELP_SH_LINK	"   \
   The shdr:sh_link command is used to display or alter the\n\
   sh_link field of the specified section.\n\
   \n\
   sh_link contains extra information, the interpretation\n\
   of which depends on the section type.\n\
   \n\
   If shdr:sh_link is called without arguments, the value\n\
   of sh_link for every section in the section header array\n\
   is shown. If called with the shndx argument, the value of the\n\
   section at that index is displayed. If both arguments are\n\
   present, the sh_link field of the section at the specified\n\
   index is set to the given value.\n"

@ MSG_HELP_SH_NAME	"   \
   The shdr:sh_name command is used to display or alter the\n\
   name associated with a specified section.\n\
   \n\
   The sh_name field of a section header is an index into\n\
   the section header string table section giving the location\n\
   of a null terminated string.\n\
   \n\
   If shdr:sh_name is called without arguments, the name of\n\
   every section in the section header array is shown. If called\n\
   with the shndx argument, the name of the section at that\n\
   index is displayed. If both arguments are present, the\n\
   sh_name field of the section at the specified index is set\n\
   to the given value.\n\
   \n\
   When changing the name of a section, you should be aware\n\
   that the name selected must exist within the section header\n\
   string table, as it is not possible to add new strings to\n\
   this string table.\n"

@ MSG_HELP_SH_OFFSET	"   \
   The shdr:sh_offset command is used to display or alter the\n\
   sh_offset field of the specified section.\n\
   \n\
   sh_offset provides the byte offset from the beginning of\n\
   the file to the first byte in the section. For a SHT_NOBITS\n\
   section, this member indicates the conceptual offset in\n\
   the file, as the section occupies no space in the file.\n\
   \n\
   If shdr:sh_offset is called without arguments, the value\n\
   of sh_offset for every section in the section header array\n\
   is shown. If called with the shndx argument, the value of the\n\
   section at that index is displayed. If both arguments are\n\
   present, the sh_offset field of the section at the specified\n\
   index is set to the given value.\n"

@ MSG_HELP_SH_SIZE	"   \
   The shdr:sh_size command is used to display or alter the\n\
   sh_size field of the specified section.\n\
   \n\
   sh_size provides the section's size in bytes. Unless the\n\
   section type is SHT_NOBITS, the section occupies sh_size\n\
   bytes in the file. A section of type SHT_NOBITS can have\n\
   a non-zero size, but the section occupies no space in the file.\n\
   \n\
   If shdr:sh_size is called without arguments, the value\n\
   of sh_size for every section in the section header array\n\
   is shown. If called with the shndx argument, the value of the\n\
   section at that index is displayed. If both arguments are\n\
   present, the sh_size field of the section at the specified\n\
   index is set to the given value.\n"

@ MSG_HELP_SH_TYPE	"   \
   The shdr:sh_type command is used to display or alter the\n\
   sh_type field of the specified section.\n\
   \n\
   The type of a section categorizes the section's contents\n\
   and semantics.\n\
   \n\
   If shdr:sh_type is called without arguments, the value\n\
   of sh_type for every section in the section header array\n\
   is shown. If called with the shndx argument, the value of the\n\
   section at that index is displayed. If both arguments are\n\
   present, the sh_type field of the section at the specified\n\
   index is set to the given value.\n"



@ _END_


# The following strings represent reserved words, files, pathnames and symbols.
# Reference to this strings is via the MSG_ORIG() macro, and thus no message
# translation is required.


# Miscellaneous clutter
@ MSG_STR_EMPTY			""
@ MSG_STR_NL			"\n"
@ MSG_STR_MINUS_SHNDX		"-shndx"
@ MSG_STR_MINUS_SHTYP		"-shtyp"
@ MSG_STR_MINUS_NAME_OFFSET	"-name_offset"
@ MSG_STR_NAME			"name"
@ MSG_STR_SEC			"sec"
@ MSG_STR_VALUE			"value"


# Format strings

@ MSG_FMT_WORDVALNL		"%u\n"
@ MSG_FMT_WORDHEXNL		"%#x\n"
@ MSG_FMT_XWORDHEXNL		"%#llx\n"
@ MSG_FMT_STRNL			"%s\n"


# Module name

@ MSG_MOD_NAME		"shdr"


# Command names

@ MSG_CMD_DUMP		"dump"

@ MSG_CMD_SH_ADDR	"sh_addr"
@ MSG_CMD_SH_ADDRALIGN	"sh_addralign"
@ MSG_CMD_SH_ENTSIZE	"sh_entsize"
@ MSG_CMD_SH_FLAGS	"sh_flags"
@ MSG_CMD_SH_INFO	"sh_info"
@ MSG_CMD_SH_LINK	"sh_link"
@ MSG_CMD_SH_NAME	"sh_name"
@ MSG_CMD_SH_OFFSET	"sh_offset"
@ MSG_CMD_SH_SIZE	"sh_size"
@ MSG_CMD_SH_TYPE	"sh_type"

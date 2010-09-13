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

# Message file for elfedit 'phdr' module

@ MSG_ID_ELFEDIT_PHDR


# Program header format
@ MSG_ELF_PHDR		"Program header [%d]:\n"

# Debug messages
@ MSG_DEBUG_PHDR	"phdr[%d]: Program header: %s\n"
@ MSG_DEBUG_OLDINTERPOK	"[%d: %s][%d]: value unchanged: %s\n"
@ MSG_DEBUG_SETPHINTERP	"phdr[%d]: update PT_INTERP program header: \
			 p_offset=%#llx,  p_size=%#llx\n"
@ MSG_DEBUG_NEWISTR 	"[%d: %s][%d]: Write new value in .interp \
			 section: %s\n"
@ MSG_DEBUG_LNGISTR	"[%d: %s][%d]: New value too long (%d bytes) for \
			 .interp section (%d bytes): %s\n"
@ MSG_DEBUG_S_OK	"phdr[%d].%s: value unchanged: %s\n"
@ MSG_DEBUG_S_CHG	"phdr[%d].%s: change from %s to %s\n"
@ MSG_DEBUG_LLX_OK	"phdr[%d].%s: value unchanged: %#llx\n"
@ MSG_DEBUG_LLX_CHG	"phdr[%d].%s: change from %#llx to %#llx\n"

# Format strings

@ MSG_FMT_ELF_INTERP	"Interpreter Section:  %s\n\t%s\n"



# Errors

@ MSG_ERR_NOINTERPPHDR	"ELF object does not have an interpreter \
			 program header\n"
@ MSG_ERR_NOINTERPSEC	"Unable to locate section corresponding to PT_INTERP \
			 program header\n"
@ MSG_ERR_NOPHDR	"No program header with specified type available: %s\n"


# Module description

@ MSG_MOD_DESC		"Program Header"


# 1-line description strings

@ MSG_DESC_DUMP		"Dump Program Header Contents"
@ MSG_DESC_P_TYPE	"Segment type"
@ MSG_DESC_P_OFFSET	"Offset from start of file"
@ MSG_DESC_P_VADDR	"Virtual address of 1st byte in memory"
@ MSG_DESC_P_PADDR	"Segment's physical address"
@ MSG_DESC_P_FILESZ	"# of bytes in file image of segment"
@ MSG_DESC_P_MEMSZ	"# bytes in memory image of segment"
@ MSG_DESC_P_FLAGS	"Segment flags"
@ MSG_DESC_P_ALIGN	"Segment alignmnent"
@ MSG_DESC_INTERP	"Dynamic object interpreter (PT_INTERP)"
@ MSG_DESC_DELETE	"Delete program headers"
@ MSG_DESC_MOVE		"Move program headers"


# Command option description strings

@ MSG_OPTDESC_PHNDX	"\
   Interpret the element argument as a program header index\n\
   rather than as a program header type.\n"

# Command argument description strings

@ MSG_A1_ELEMENT	"\
   Type of program header. The first program header with the\n\
   specified type will be used. If the -phndx option is used,\n\
   then element is instead an integer giving the index of the\n\
   specified program header element.\n"

@ MSG_A1_INTERP_NEWPATH	"\
   Path of new interpreter for ELF PT_INTERP program header.\n"

@ MSG_A2_P_TYPE_TYPE	"\
   Value to set for segment type. The value can be an integer,\n\
   or one of hte well known PT_ symbolic constant names.\n"

@ MSG_A2_P_OFFSET_VALUE	"\
   Integer value to set for program header p_offset field.\n\
   The value of p_offset gives the offset from the beginning\n\
   of the file at which the first byte of the segment resides.\n"

@ MSG_A2_P_VADDR_ADDR	"\
   Integer value to set for virtual address at which the first\n\
   byte of the segment resides in memory.\n"

@ MSG_A2_P_PADDR_ADDR	"\
   Integer value to set for physical address at which the first\n\
   byte of the segment resides in memory.\n"

@ MSG_A2_P_FILESZ_SIZE	"\
   Integer value to set for number of bytes in the file image\n\
   of the segment, which can be zero.\n"

@ MSG_A2_P_MEMSZ_SIZE	"\
   Integer value to set for number of bytes in the memory image\n\
   of the segment, which can be zero.\n"

@ MSG_A2_P_FLAGS_VALUE "\
   Segment flags. PF_ flag constants are accepted, as is\n\
   any integer.\n"

@ MSG_A2_P_ALIGN_ALIGN "\
   Value to which the segment is aligned in memory, and in\n\
   the file.\n"

@ MSG_A2_DELETE_COUNT	"\
   Number of program header elements to delete, starting\n\
   at the specified position. This value cannot exceed the number\n\
   of slots remaining in the header table below the specified.\n\
   position If count is not supplied, a single element is deleted.\n"

@ MSG_A2_MOVE_DST_INDEX	"\
   Numeric index within program header to which the element(s)\n\
   should be moved.\n"

@ MSG_A3_MOVE_COUNT	"\
   Number of program header elements to move. This value\n\
   cannot exceed the number of slots remaining in the program\n\
   header table below the specified position. If count is not\n\
   supplied, a single header element is moved.\n"


# Help strings

@ MSG_HELP_DUMP	"   \
   The phdr:dump command is used to display program headers\n\
   using the same style used by the elfdump program.\n\
   \n\
   If phdr:dump is called without an argument, information for\n\
   every program header is shown. If called with the element\n\
   argument, the information for the program header symbol at\n\
   that index is displayed.\n"

@ MSG_HELP_P_TYPE	"   \
   The phdr:p_type command is used to display or alter the\n\
   segment type program header. This information is maintained\n\
   in the p_type field of an ELF program header element.\n\
   \n\
   If phdr:p_type is called without arguments, the value of\n\
   p_type for every element of the program header array is\n\
   shown. If called with the element argument, the value of the\n\
   program header specified is displayed. If both arguments are\n\
   present, the p_type field of the program header at the\n\
   specified position is set to the given value.\n"

@ MSG_HELP_P_OFFSET	"   \
   The phdr:p_offset command is used to display or alter the\n\
   p_offset field of the specified program header.\n\
   \n\
   p_offset provides the offset from the beginning of the\n\
   at which the first byte of the segment resides.\n\
   \n\
   If phdr:p_offset is called without arguments, the value\n\
   of p_offset for every element in the program header array\n\
   is shown. If called with the element argument, the value\n\
   of the element specified is displayed. If both arguments are\n\
   present, the p_offset field of the element at the\n\
   specifiedindex is set to the given value.\n"

@ MSG_HELP_P_VADDR	"   \
   The phdr:p_vaddr command is used to display or alter the\n\
   p_vaddr field of the specified program header.\n\
   \n\
   p_vaddr provides the virtual address at which the first byte\n\
   of the segment resides in memory\n\
   \n\
   If phdr:p_vaddr is called without arguments, the value\n\
   of p_vaddr for every element in the program header array\n\
   is shown. If called with the element argument, the value\n\
   of the element specified is displayed. If both arguments are\n\
   present, the p_vaddr field of the element at the specified\n\
   index is set to the given value.\n"

@ MSG_HELP_P_PADDR	"   \
   The phdr:p_paddr command is used to display or alter the\n\
   p_paddr field of the specified program header.\n\
   \n\
   p_paddr provides the physical address at which the first\n\
   byte of the segment resides in memory, for systems in which\n\
   physical addressing is relevant. Because the system ignores\n\
   physical addressing for application programs, this member\n\
   has unspecified contents for executable files and shared\n\
   objects.\n\
   \n\
   If phdr:p_paddr is called without arguments, the value\n\
   of p_paddr for every element in the program header array\n\
   is shown. If called with the element argument, the value\n\
   of the element specified is displayed. If both arguments are\n\
   present, the p_paddr field of the element at the specified\n\
   index is set to the given value.\n"

@ MSG_HELP_P_FILESZ	"   \
   The phdr:p_filesz command is used to display or alter the\n\
   p_filesz field of the specified program header.\n\
   \n\
   p_filesz contains the number of bytes in the file image\n\
   of the segment. This value can be zero.\n\
   \n\
   If phdr:p_filesz is called without arguments, the value\n\
   of p_filesz for every element in the program header array\n\
   is shown. If called with the element argument, the value\n\
   of the element specified is displayed. If both arguments are\n\
   present, the p_filesz field of the element at the specified\n\
   index is set to the given value.\n"

@ MSG_HELP_P_MEMSZ	"   \
   The phdr:p_memsz command is used to display or alter the\n\
   p_memsz field of the specified program header.\n\
   \n\
   p_memsz contains the number of bytes in the memory image\n\
   of the segment. This value can be zero.\n\
   \n\
   If phdr:p_memsz is called without arguments, the value\n\
   of p_memsz for every element in the program header array\n\
   is shown. If called with the element argument, the value\n\
   of the element specified is displayed. If both arguments are\n\
   present, the p_memsz field of the element at the specified\n\
   index is set to the given value.\n"

@ MSG_HELP_P_FLAGS	"   \
   The phdr:p_flags command is used to display or alter the\n\
   flags that are associated with the segment described by\n\
   the program header.\n\
   \n\
   If phdr:p_flags is called without arguments, the value\n\
   of p_flags for every element in the program header array\n\
   is shown. If called with the element argument, the value of\n\
   the program header at that index is displayed. If one or\n\
   more value arguments are present, the following steps are\n\
   taken:\n\
   \n\
   o\tAll the value arguments are OR'd together.\n\
   \n\
   o\tIf the -cmp option has been specified, the new value\n\
   \tis complemented.\n\
   \n\
   o\tThe p_flags field of the section header is updated with\n\
   \tthe new value. If -and is specified, the new value is\n\
   \tAND'd against the existing value. If -or is specified,\n\
   \tthe new value is OR'd against the existing value. If\n\
   \tneither -and or -or are specified, the new value replaces\n\
   \tthe existing value.\n"

@ MSG_HELP_P_ALIGN	"   \
   The phdr:p_align command is used to display or alter the\n\
   p_align field of the specified program header.\n\
   \n\
   p_align is the value to which the segment is aligned in\n\
   memory, and in the file. Values 0 and 1 mean no alignment\n\
   is required. Otherwise, p_align should be a positive\n\
   integral power of 2, and p_vaddr should equal p_offset,\n\
   modulo p_align.\n\
   \n\
   If phdr:p_align is called without arguments, the value\n\
   of p_align for every element in the program header array\n\
   is shown. If called with the element argument, the value\n\
   of the element specified is displayed. If both arguments are\n\
   present, the p_align field of the element at the specified\n\
   index is set to the given value.\n"

@ MSG_HELP_INTERP	"   \
   The phdr:interp command is used to display or alter the\n\
   interpreter of the ELF object.\n\
   \n\
   If phdr:interp is called without arguments, the existing\n\
   interpreter is shown. If called with the newpath argument,\n\
   the interpreter is set to the given string, if possible.\n\
   \n\
   An ELF PT_INTERP program header usually references its own\n\
   special section instead of some other string table. The ELF\n\
   ABI says that this section must be named \".interp\". .interp\n\
   is typically sized to just fit the original string, including\n\
   its NULL termination. You can treat it as a string table with\n\
   one string. If the new interpreter path is short enough to fit\n\
   in this .interp section, phdr:interp simply replaces the old\n\
   path with the new one.\n\
   \n\
   In the case where the new path is too long to fit in the .interp\n\
   section, phdr:interp will attempt to use the dynamic string table\n\
   instead. This is not always possible: The desired string must\n\
   already exist in the dynamic string table, or there must be\n\
   enough room in the reserved section at the end (DT_SUNW_STRPAD)\n\
   for the new string to be added.\n"

@ MSG_HELP_DELETE	"   \
   The phdr:delete command is used to delete one or more elements\n\
   in the program header. The elements following the deleted items\n\
   move up, and the vacated elements at the end are zero filled.\n"

@ MSG_HELP_MOVE	"   \
   The phdr:move command is used to move the position of one\n\
   or more elements in the program header array. The specified\n\
   number of elements are moved from elt to dst_index.\n"


@ _END_


# Strings

@ MSG_STR_EMPTY		""
@ MSG_STR_NL		"\n"
@ MSG_STR_ALIGN		"align"
@ MSG_STR_ADDR		"addr"
@ MSG_STR_COUNT		"count"
@ MSG_STR_DST_INDEX	"dst_index"
@ MSG_STR_ELEMENT	"element"
@ MSG_STR_NEWPATH	"newpath"
@ MSG_STR_SIZE		"size"
@ MSG_STR_TYPE		"type"
@ MSG_STR_VALUE		"value"
@ MSG_STR_MINUS_PHNDX	"-phndx"

# Format strings

@ MSG_FMT_U_NL			"%u\n"
@ MSG_FMT_X_NL			"%#x\n"
@ MSG_FMT_LLX_NL		"%#llx\n"
@ MSG_FMT_STRNL			"%s\n"



# The following strings represent reserved words, files, pathnames and symbols.
# Reference to this strings is via the MSG_ORIG() macro, and thus no message
# translation is required.

# ELF section names
@ MSG_SEC_INTERP	".interp"


# Module name

@ MSG_MOD_NAME		"phdr"


# Command names

@ MSG_CMD_DUMP		"dump"
@ MSG_CMD_P_TYPE	"p_type"
@ MSG_CMD_P_OFFSET	"p_offset"
@ MSG_CMD_P_VADDR	"p_vaddr"
@ MSG_CMD_P_PADDR	"p_paddr"
@ MSG_CMD_P_FILESZ	"p_filesz"
@ MSG_CMD_P_MEMSZ	"p_memsz"
@ MSG_CMD_P_FLAGS	"p_flags"
@ MSG_CMD_P_ALIGN	"p_align"
@ MSG_CMD_INTERP	"interp"
@ MSG_CMD_DELETE	"delete"
@ MSG_CMD_MOVE		"move"

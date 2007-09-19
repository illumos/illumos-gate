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

# Message file for elfedit 'sym' module

@ MSG_ID_ELFEDIT_SYM


# Command argument strings
@ MSG_ARG_SECNDX	"symbol section index"
@ MSG_ARG_SYM		"Name of desired symbol within symbol table(s)"
@ MSG_ARG_SYMVIS	"symbol visibility"
@ MSG_ARG_SYMBIND	"symbol binding"

# Names of things we allocate dynamically

@ MSG_ALLOC_ARGSTATE		"symbol table state"

# Format strings
@ MSG_FMT_SYMTAB		"Symbol Table Section:  %s\n"

# Debug messages

@ MSG_DEBUG_S_OK	"[%d: %s][%d].%s: value unchanged: %s\n"
@ MSG_DEBUG_S_CHG	"[%d: %s][%d].%s: change from %s to %s\n"
@ MSG_DEBUG_EXT_S_OK	"[%d: %s][%d]: value unchanged: %s\n"
@ MSG_DEBUG_EXT_S_CHG	"[%d: %s][%d]: change from %s to %s\n"
@ MSG_DEBUG_D_OK	"[%d: %s][%d].%s: value unchanged: %d\n"
@ MSG_DEBUG_D_CHG	"[%d: %s][%d].%s: change from %d to %d\n"
@ MSG_DEBUG_LLX_OK	"[%d: %s][%d].%s: value unchanged: %#llx\n"
@ MSG_DEBUG_LLX_CHG	"[%d: %s][%d].%s: change from %#llx to %#llx\n"
@ MSG_DEBUG_SHNDX_UNDEF0 "ELF warning: symbol [0] is expected to reference \
			 SHN_UNDEF\n"
@ MSG_DEBUG_SHNDX_XINDEX	"ELF warning: SHN_XINDEX is not supposed to \
			 be set directly\n"
@ MSG_DEBUG_SHNDX_EFORCE "[%d: %s][%d]: ELF warning: Section index does not \
			 normally go in extended index section: %d\n"
@ MSG_DEBUG_LBINDGSYM	"[%d: %s][%d]: ELF warning: local binding set for \
			 symbol in global part of symbol table \
			 (shdr[%d].sh_info == %d)\n"
@ MSG_DEBUG_GBINDLSYM	"[%d: %s][%d]: ELF warning: global binding set for \
			 symbol in local part of symbol table \
			 (shdr[%d].sh_info == %d)\n"
@ MSG_DEBUG_DYNSYMNAMCHG	"[%d: %s][%d]: ELF warning: changing the name \
			 of a symbol in the dynamic symbol table will confuse \
			 the hash section and likely render the object \
			 unusable\n"
@ MSG_DEBUG_CHGSYMELT0	"[%d: %s][%d]: ELF warning: Symbol [0] is expected \
			 to be NULL\n"

# Errors

@ MSG_ERR_NOSYMTAB	"Object does not have any symbol tables\n";
@ MSG_ERR_NEEDEXPSYMTAB	"The -symndx option requires a symbol table to be \
			 explicitly specified (-shnam, -shndx, or \
			 -shtyp options)\n"



# Module description

@ MSG_MOD_DESC		"Symbol Section"


# 1-line description strings

@ MSG_DESC_DUMP		"Dump Symbol Table"
@ MSG_DESC_ST_BIND	"Symbol binding"
@ MSG_DESC_ST_INFO	"st_info (binding and type)"
@ MSG_DESC_ST_NAME	"Symbol name"
@ MSG_DESC_ST_OTHER	"st_other (visibility)"
@ MSG_DESC_ST_SHNDX	"Symbol section index"
@ MSG_DESC_ST_SIZE	"Symbol size"
@ MSG_DESC_ST_TYPE	"Symbol type"
@ MSG_DESC_ST_VALUE	"Symbol value"
@ MSG_DESC_ST_VISIBILITY "Symbol visibility"


# Command option description strings

@ MSG_OPTDESC_E		"\
   Force the use of the extended index section to hold the\n\
   specified section index, even if it is small enough to fit\n\
   into the symbol st_shndx field. Note that this will produce\n\
   a non-standard ELF file.\n"
@ MSG_OPTDESC_SHNDX	"\
   Use the symbol table found in the ELF section with the\n\
   specified index.\n"
@ MSG_OPTDESC_SHNAM	"\
   Use the symbol table found in the ELF section with the\n\
   specified name.\n"
@ MSG_OPTDESC_SHTYP	"\
   Use the first symbol table found in the ELF section with\n\
    the specified section type.\n"
@ MSG_OPTDESC_SECSHNDX	"\
   Interpret the sec argument as a section index rather than\n\
   as a section name. section can be one of the well known SHN_\n\
   symbolic constants, or any integer.\n"
@ MSG_OPTDESC_SECSHTYP	"\
   Interpret the sec argument as a section type rather than\n\
   as a section name. section can be one of the well known SHT_\n\
   symbolic constants, or any integer.\n"
@ MSG_OPTDESC_NAME_OFFSET	"\
   Interpret the name argument as a string table offset rather\n\
   than as a string.\n"

@ MSG_OPTDESC_SYMNDX		"\
   The sym argument supplies a numeric index into the symbol\n\
   section instead of the name of the symbol. The symbol table\n\
   to use must be explicitly specified (-shnam, -shndx, or\n\
   -shtyp option) when -symndx is used.\n".

# Command argument descriptions

@ MSG_A1_SYM		"Name of desired symbol within symbol table.\n"

@ MSG_A2_DESC_ST_BIND	"Symbol binding. STB_ symbol constants are\n\
   accepted, as is any integer in the range 0 - 15.\n"

@ MSG_A2_DESC_ST_INFO	"Integer value to set for symbol st_info field.\n\
   Note that the fact that the value of st_info affects both\n\
   the symbol binding and type values.\n"

@ MSG_A2_DESC_ST_NAME	"\
   Name to set for symbol. If the -name_offset option is used,\n\
    this is an integer offset into the string table section\n\
   associated with the symbol table. Otherwise, it is a string,\n\
   which will be looked up in the symbol table (and inserted if\n\
   necessary, and if possible) in order to obtain the needed\n\
   offset value.\n"

@ MSG_A2_DESC_ST_OTHER	"\
   Integer value to set for symbol st_other field. Note\n\
   that the fact that the value of st_other affects the\n\
   symbol visibility value.\n"

@ MSG_A2_DESC_ST_SEC	"\
   Section to set for symbol section index. By default, this\n\
   argument is interpreted as the name of the desired section.\n\
   The section index of the first section with the specified\n\
   name is used.\n\
   \n\
   If -secshndx is set, then sec is a section index,\n\
   and is interpreted as an integer, or one of the well known\n\
   SHN_ symbolic constant names.\n\
   \n\
   If -secshtyp is set, then sec is a section type,\n\
   and is interpreted as an integer, or one of the well known\n\
   SHT_ symbolic constant names. The section index of the first\n\
   section with the specified type is used.\n"


@ MSG_A2_DESC_ST_SIZE	"Integer value to set for symbol size.\n"

@ MSG_A2_DESC_ST_TYPE	"\
   Symbol type. STT_ symbol constants are accepted, as is any\n\
   integer in the range 0 - 15.\n"

@ MSG_A2_DESC_ST_VALUE	"Integer value to set for symbol value.\n"

@ MSG_A2_DESC_ST_VISIBILITY "\
   Symbol visibility. STV_ symbol constants are accepted, as\n\
   are integer values.\n"



# Help strings

@ MSG_HELP_DUMP	"   \
   The sym:dump command is used to display symbol information\n\
   using the same style used by the elfdump program.\n\
   \n\
   By default, symbols are taken from all available symbol tables.\n\
   The symbol table to use can be changed using the -shnam, -shndx,\n\
   or -shtyp options. Only one of these options can be used at a time.\n\
   \n\
   If sym:dump is called without arguments, information for every\n\
   symbol in the symbol table is shown. If called with the symndx\n\
   argument, the information forthe symbol at that index is\n\
   displayed.\n"

@ MSG_HELP_ST_BIND	"   \
   The sym:st_bind command is used to display or alter symbol\n\
   binding. Symbol binding is found in the st_bind portion of the\n\
   st_info field of an ELF symbol.\n\
   \n\
   By default, symbols are taken from all available symbol tables.\n\
   The symbol table to use can be changed using the -shnam, -shndx,\n\
   or -shtyp options. Only one of these options can be used at a time.\n\
   \n\
   If sym:st_bind is called without arguments, the value of\n\
   st_bind for every symbol in the symbol table is shown. If\n\
   called with the symndx argument, the value of the symbol at that\n\
   index is displayed. If both arguments are present, the st_bind\n\
   field of the symbol at the specified index is set to the given\n\
   value.\n"

@ MSG_HELP_ST_INFO	"   \
   The sym:st_info command is used to display or alter the\n\
   st_info field of the specified symbol. It provides raw access\n\
   to the entire st_info value. Normally, the sym:st_bind or sym:st_type\n\
   commands are used in preference to sym:st_info.\n\
   \n\
   By default, symbols are taken from all available symbol tables.\n\
   The symbol table to use can be changed using the -shnam, -shndx,\n\
   or -shtyp options. Only one of these options can be used at a time.\n\
   If sym:st_info is called without arguments, the value of st_info\n\
   for every symbol in the symbol table is shown. If called with the\n\
   symndx argument, the value of the symbol at that index is displayed.\n\
   If both arguments are present, the st_info field of the symbol at\n\
   the specified index is set to the given value.\n"

@ MSG_HELP_ST_NAME	"   \
   The sym:st_name command is used to display or alter the\n\
   name associated with a specified symbol.\n\
   \n\
   By default, symbols are taken from all available symbol tables.\n\
   The symbol table to use can be changed using the -shnam, -shndx,\n\
   or -shtyp options. Only one of these options can be used at a time.\n\
   \n\
   If sym:st_name is called without arguments, the value of st_name\n\
   for every symbol in the symbol table is shown. If called with the\n\
   symndx argument, the name of the symbol at that index is displayed.\n\
   If both arguments are present, the name field of the symbol at\n\
   the specified index is set to the given value.\n\
   \n\
   When changing the name of a symbol, you should be aware of the\n\
   following limitations:\n\
   \n   \
   o\tIt is only possible to change the name of a symbol in a\n\
   \tnon-dynamic symbol table to one of the names already found\n\
   \tin the associated string table.\n\
   \n   \
   o\tChanging the name of a symbol in the dynamic symbol table\n\
   \twill lead to the hash table having inaccurate information\n\
   \tabout the symbol table, and is likely render the object\n\
   \tunusable.\n"

@ MSG_HELP_ST_OTHER	"   \
   The sym:st_other command is used to display or alter the\n\
   st_other field of the specified symbol. It provides raw access\n\
   to the entire st_other value. Normally, the sym:st_visibility\n\
   command is used in preference to sym:st_other.\n\
   \n\
   By default, symbols are taken from all available symbol tables.\n\
   The symbol table to use can be changed using the -shnam, -shndx,\n\
   or -shtyp options. Only one of these options can be used at a time.\n\
   \n\
   If sym:st_other is called without arguments, the value of st_other\n\
   for every symbol in the symbol table is shown. If called with the\n\
   symndx argument, the value of the symbol at that index is displayed.\n\
   If both arguments are present, the st_other field of the symbol at\n\
   the specified index is set to the given value.\n"

@ MSG_HELP_ST_SHNDX	"   \
   Every symbol table entry is defined in relation to some section.\n\
   This information is maintained in the st_shndx field of an ELF\n\
   symbol. The sym:st_shndx command is used to display or alter the\n\
   st_shndx field of the specified symbol.\n\
   \n\
   By default, symbols are taken from all available symbol tables.\n\
   The symbol table to use can be changed using the -shnam, -shndx,\n\
   or -shtyp options. Only one of these options can be used at a time.\n\
   \n\
   If sym:st_shndx is called without arguments, the value of st_shndx\n\
   for every symbol in the symbol table is shown. If called with the\n\
   symndx argument, the value of the symbol at that index is displayed.\n\
   If both arguments are present, the st_shndx field of the symbol at\n\
   the specified index is set to the given value.\n\
   \n\
   sym:st_shndx is aware of extended section indexes, and will\n\
   access/modify the extended index sections associated with a given\n\
   symbol table as necessary.\n"

@ MSG_HELP_ST_SIZE	"   \
   The sym:st_size command is used to display or alter the\n\
   size of the specified symbol (st_size field).\n\
   \n\
   By default, symbols are taken from all available symbol tables.\n\
   The symbol table to use can be changed using the -shnam, -shndx,\n\
   or -shtyp options. Only one of these options can be used at a time.\n\
   \n\
   If sym:st_size is called without arguments, the value of st_size\n\
   for every symbol in the symbol table is shown. If called with\n\
   the symndx argument, the size of the symbol at that index is\n\
   displayed. If both arguments are present, the st_size field of\n\
   the symbol at the specified index is set to the given value.\n"

@ MSG_HELP_ST_TYPE	"   \
   The sym:st_type command is used to display or alter the\n\
   st_type portion of the st_info field of the specified\n\
   symbol.\n\
   \n\
   By default, symbols are taken from all available symbol tables.\n\
   The symbol table to use can be changed using the -shnam, -shndx,\n\
   or -shtyp options. Only one of these options can be used at a time.\n\
   \n\
   If sym:st_type is called without arguments, the value of\n\
   st_type for every symbol in the symbol table is shown. If\n\
   called with the symndx argument, the value of the symbol at that\n\
   index is displayed. If both arguments are present, the st_type\n\
   field of the symbol at the specified index is set to the given value.\n"

@ MSG_HELP_ST_VALUE	"   \
   The sym:st_value command is used to display or alter the\n\
   value of the specified symbol (st_value field).\n\
   \n\
   By default, symbols are taken from all available symbol tables.\n\
   The symbol table to use can be changed using the -shnam, -shndx,\n\
   or -shtyp options. Only one of these options can be used at a time.\n\
   \n\
   If sym:st_value is called without arguments, the value of\n\
   st_value for every symbol in the symbol table is shown. If\n\
   called with the symndx argument, the value of the symbol at that\n\
   index is displayed. If both arguments are present, the st_value\n\
   field of the symbol at the specified index is set to the given value.\n"

@ MSG_HELP_ST_VISIBILITY	"   \
   The sym:st_visibility command is used to display or alter the\n\
   st_visibility portion of the st_other field of the specified\n\
   symbol.\n\
   \n\
   By default, symbols are taken from all available symbol tables.\n\
   The symbol table to use can be changed using the -shnam, -shndx,\n\
   or -shtyp options. Only one of these options can be used at a time.\n\
   \n\
   If sym:st_visibility is called without arguments, the value of\n\
   st_visibility for every symbol in the symbol table is shown. If\n\
   called with the symndx argument, the value of the symbol at that\n\
   index is displayed. If both arguments are present, the st_visibility\n\
   field of the symbol at the specified index is set to the given value.\n"


@ _END_


# The following strings represent reserved words, files, pathnames and symbols.
# Reference to this strings is via the MSG_ORIG() macro, and thus no message
# translation is required.


# Miscellaneous clutter
@ MSG_STR_EMPTY			""
@ MSG_STR_NL			"\n"
@ MSG_STR_MINUS_E		"-e"
@ MSG_STR_MINUS_SHNAM		"-shnam"
@ MSG_STR_MINUS_SHNDX		"-shndx"
@ MSG_STR_MINUS_SHTYP		"-shtyp"
@ MSG_STR_MINUS_SYMNDX		"-symndx"
@ MSG_STR_MINUS_NAME_OFFSET	"-name_offset"
@ MSG_STR_MINUS_SECSHNDX	"-secshndx"
@ MSG_STR_MINUS_SECSHTYP	"-secshtyp"
@ MSG_STR_INDEX			"index"
@ MSG_STR_NAME			"name"
@ MSG_STR_SEC			"sec"
@ MSG_STR_SYM			"sym"
@ MSG_STR_TYPE			"type"
@ MSG_STR_VALUE			"value"


# Format strings

@ MSG_FMT_WORDVAL		"%u"
@ MSG_FMT_WORDVALNL		"%u\n"
@ MSG_FMT_XWORDVALNL_32		"0x%8.8x\n"
@ MSG_FMT_XWORDVALNL_64		"0x%16.16llx\n"
@ MSG_FMT_STRNL			"%s\n"
@ MSG_FMT_INDEX			" [%lld]"


# Module name

@ MSG_MOD_NAME		"sym"


# Command names

@ MSG_CMD_DUMP		"dump"
@ MSG_CMD_ST_BIND	"st_bind"
@ MSG_CMD_ST_INFO	"st_info"
@ MSG_CMD_ST_NAME	"st_name"
@ MSG_CMD_ST_OTHER	"st_other"
@ MSG_CMD_ST_SHNDX	"st_shndx"
@ MSG_CMD_ST_SIZE	"st_size"
@ MSG_CMD_ST_TYPE	"st_type"
@ MSG_CMD_ST_VALUE	"st_value"
@ MSG_CMD_ST_VISIBILITY	"st_visibility"

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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"

@ _START_

# Message file for elfedit 'str' module

@ MSG_ID_ELFEDIT_STR


# Format strings
@ MSG_FMT_STRTAB	"String Table Section:  %s\n"
@ MSG_FMT_DYNSTRPAD	"Dynamic String Table Padding \
			 Region: [%d-%d] (%d bytes)\n"
@ MSG_FMT_DUMPTITLE	"          index    value\n"

# Debug messages

@ MSG_DEBUG_S_OK	"[%d: %s][%d]: value unchanged: %s\n"
@ MSG_DEBUG_S_CHG	"[%d: %s][%d]: change from %.*s to %s\n"
@ MSG_DEBUG_Z_OK	"[%d: %s][%d]: value unchanged\n"
@ MSG_DEBUG_Z_CHG	"[%d: %s][%d]: inserted %d NULL bytes\n"
@ MSG_DEBUG_CHGSTR0	"[%d: %s][%d]: ELF warning: element [0] is expected \
			 to contain a NULL (0) byte, and should not be \
			 altered: %s\n"
@ MSG_DEBUG_BADSTRPAD	"[%d: %s]: DT_SUNW_STRPAD value (%#llx) is larger \
			 than string table section (%#llx), and will be \
			 ignored\n"
@ MSG_DEBUG_ADDDYNSTR	"[%d: %s][%d]: Using %d/%d bytes from reserved area \
			 to add string: %s\n"
@ MSG_DEBUG_LONGSTR	"[%d: %s][%d]: ELF warning: new string is longer \
			 than previous value (%d > %d), and will overwrite \
			 the beginning of the following item\n"

# Errors

@ MSG_ERR_STRNOTFND	"[%d: %s]: String table does not contain string: %s\n"
@ MSG_ERR_NOFIT		"[%d: %s][%d]: New value would extend past end \
			 of string table: %s\n"
@ MSG_ERR_FINALNULL	"[%d: %s][%d]: New value would set final byte of \
			 string table to non-NULL value: %s\n"



# Module description

@ MSG_MOD_DESC		"String Table Section"


# 1-line description strings

@ MSG_DESC_DUMP		"Dump String Table Section"
@ MSG_DESC_SET		"Alter Existing String Table Contents"
@ MSG_DESC_ADD		"Add New String to String Table"
@ MSG_DESC_ZERO		"Zero String Table Region"


# Command option description strings

@ MSG_OPTDESC_ANY		"\
   Normally, only string table sections (section type SHT_STRTAB)\n\
   or sections with the SHF_STRINGS section flag set are allowed.\n\
   If -any is set, then the specified section is used without\n\
   checking its section type, and will be treated as if it is a\n\
   string table. This can be used to examine sections that are\n\
   known to be in string table format even though they are not\n\
   properly marked as such (i.e. SHT_PROGBITS).\n"

@ MSG_OPTDESC_END		"\
   Zero to the end of the string table. The count argument\n\
   cannot be used in conjunction with -end.\n".

@ MSG_OPTDESC_NOTERM		"\
   Do not write the null termination for the new string into\n\
   the string table. This option cannot be used with the final\n\
   position in the string table. Attempts to do so will result\n\
   in an error.\n".

@ MSG_OPTDESC_SHNAM		"\
   Use the string table found in the ELF section with the\n\
   specified name. If this is a string table section, it\n\
   is used directly. If it is a section that has an associated\n\
   symbol table or string table via its sh_link field, then the\n\
   associated string table is used.\n"

@ MSG_OPTDESC_SHNDX		"\
   Use the string table found in the ELF section with the\n\
   specified index. If this is a string table section, it\n\
   is used directly. If it is a section that has an associated\n\
   symbol table or string table via its sh_link field, then the\n\
   associated string table is used.\n"

@ MSG_OPTDESC_SHTYP		"\
   Locate the first section in the ELF object with the\n\
   given section type, and use the string table associated\n\
   with it. If this is a string table section, it is used\n\
   directly. If it is a section that has an associated\n\
   symbol table or string table via its sh_link field, then the\n\
   associated string table is used.\n"

@ MSG_OPTDESC_STRNDX		"\
   The string argument supplies a numeric index into the\n\
   string table instead of the string value.\n".


# Command argument descriptions

@ MSG_A1_STRING		"String to locate in string table section.\n"

@ MSG_A1_NEWSTRING	"\
   New string to insert in string table section\n\
   if not already present.\n"

@ MSG_A2_NEWSTRING	"\
   New string to overwrite previous value.\n"

@ MSG_A2_COUNT	"\
   Number of null bytes to write at specified offset.\n"



# Help strings

@ MSG_HELP_DUMP	"   \
   The str:dump command is used to display information\n\
   from a string table section.\n\
   \n\
   By default, the string table referenced by the e_shstrndx field\n\
   of the ELF header is used. The -shnam, -shndx, or -shndx options\n\
   can be used to select a different string table.\n\
   \n\
   If str:dump is called without arguments, every string in the\n\
   string table is shown. If called with the string argument,\n\
   the information for that string is displayed.\n\
   \n\
   The strings are displayed within double quotes. These quotes are\n\
   not part of the actual string, and serve to visually delimit the\n\
   actual string. Printable characters are shown as themselves, while\n\
   non-printable characters are shown using the same notation used\n\
   by the C programming language for literal string constants:\n\
   \n\
   \t\\a\talert (bell)\n\
   \t\\b\tbackspace\n\
   \t\\f\tform feed\n\
   \t\\n\tnewline\n\
   \t\\r\treturn\n\
   \t\\t\thorizontal tab\n\
   \t\\v\tvertical tab\n\
   \t\\\\\tbackslash\n\
   \t\\'\tsingle quote\n\
   \t\\\"\tdouble quote\n\
   \t\\ooo\tAn octal constant, where ooo is one to three\n\
   \t\t\toctal digits (0..7)\n"

@ MSG_HELP_SET	"   \
   The str:set command is used to display or alter the existing\n\
   contents of the string table section.\n\
   \n\
   By default, the string table referenced by the e_shstrndx field\n\
   of the ELF header is used. The -shnam, -shndx, or -shndx options\n\
   can be used to select a different string table.\n\
   \n\
   The string table offset is normally determined by looking\n\
   for the specified string in the table and using its offset.\n\
   Alternatively, the -strndx option can be used to specify an\n\
   offset directly.\n\
   \n\
   If the new-string argument is not present, the current string\n\
   at the given offset is shown. If new-string is present, it\n\
   is used to overwrite the contents of the string table at\n\
   the specified offset. The new string can have any length, as\n\
   long as it will fit in the existing size of the string table.\n\
   A terminating null character is always included in the string,\n\
   unless the -noterm option is specified. However, -noterm cannot\n\
   be used for the final byte of the string table, which must\n\
   always be NULL.\n\
   \n\
   Note:\n\
   \n\
   o\tIf new-string is longer than the existing string at\n\
   \tthe specified offset, it will overwrite the start of\n\
   \tthe following string in the string table. Any reference to\n\
   \tthat following string in the ELF file will then refer to\n\
   \tthe tail of the new-string.\n\
   \n\
   o\tELF files may have other dependencies upon the existing\n\
   \tname of an item. Changing the string for such a name to\n\
   \ta different value can create problems for the object and\n\
   \teven render it unusable.\n\
   \n\
   o\tThe dynamic string table (.dynstr) may have an unused area\n\
   \tat the end, reserved for adding new strings to the table.\n\
   \tIn this case, the dynamic section will contain a DT_SUNW_STRPAD\n\
   \tvalue giving the size of the unused space. If str:set is used\n\
   \tto modify the contents of the unused space, it will adjust\n\
   \tthe existing value of DT_SUNW_STRPAD to reflect the space used.\n"

@ MSG_HELP_ADD	"   \
   The str:add command examines the specified string table to\n\
   determine if it contains the given string. If the string\n\
   does not exist, str:add will add it to the end, if possible.\n\
   \n\
   By default, the string table referenced by the e_shstrndx field\n\
   of the ELF header is used. The -shnam, -shndx, or -shndx options\n\
   can be used to select a different string table.\n\
   \n\
   It is only possible to add a new string to a string table\n\
   if the string table in question is the dynamic string table\n\
   (.dynstr), and if that string table has reserved space at\n\
   the end, indicated by a DT_SUNW_STRPAD entry in the dynamic\n\
   section.\n"

@ MSG_HELP_ZERO	"   \
   The str:zero command is used to set a portion of the specified\n\
   string table to NULL (0) byte values.\n\
   \n\
   By default, the string table referenced by the e_shstrndx field\n\
   of the ELF header is used. The -shnam, -shndx, or -shndx options\n\
   can be used to select a different string table.\n\
   \n\
   The string table offset is normally determined by looking\n\
   for the specified string in the table and using its offset.\n\
   Alternatively, the -strndx option can be used to specify an\n\
   offset directly.\n\
   \n\
   The number of bytes to zero are determined as follows:\n\
   \n\
   o\tIf the -end option is specified, all bytes between the\n\
   \tstarting offset and the end of the string table are zeroed.\n\
   \n\
   o\tIf the count argument is present, the number of bytes\n\
   \tspecified are zeroed.\n\
   \n\
   o\tIf neither -end nor count are present, all bytes of the\n\
   \texisting string at the given offset are zeroed, up to the\n\
   \texisting null termination.\n\
   \n\
   The count argument and -end option are mutually exclusive. Only\n\
   one of these can be used in a given call to str:zero.\n\
   \n\
   Note:\n\
   \n\
   o\tELF files may have other dependencies upon the existing\n\
   \tname of an item. Changing the string for such a name to\n\
   \ta different value can create problems for the object and\n\
   \teven render it unusable.\n\
   \n\
   o\tThe dynamic string table (.dynstr) may have an unused area\n\
   \tat the end, reserved for adding new strings to the table.\n\
   \tIn this case, the dynamic section will contain a\n\
   \tDT_SUNW_STRPAD value giving the size of the unused space.\n\
   \tstr:zero does not alter DT_SUNW_STRPAD, or otherwise attempt\n\
   \tto \"reclaim\" space zeroed at the end of the string table.\n"



@ _END_


# The following strings represent reserved words, files, pathnames and symbols.
# Reference to this strings is via the MSG_ORIG() macro, and thus no message
# translation is required.


# Miscellaneous clutter
@ MSG_STR_EMPTY			""
@ MSG_STR_MINUS_ANY		"-any"
@ MSG_STR_MINUS_END		"-end"
@ MSG_STR_MINUS_NOTERM		"-noterm"
@ MSG_STR_MINUS_SHNAM		"-shnam"
@ MSG_STR_MINUS_SHNDX		"-shndx"
@ MSG_STR_MINUS_SHTYP		"-shtyp"
@ MSG_STR_MINUS_STRNDX		"-strndx"
@ MSG_STR_COUNT			"count"
@ MSG_STR_INDEX			"index"
@ MSG_STR_NAME			"name"
@ MSG_STR_NEWSTRING		"new-string"
@ MSG_STR_STRING		"string"
@ MSG_STR_TYPE			"type"
@ MSG_STR_DQUOTE		"\""
@ MSG_STR_DQUOTENL		"\"\n"


# Format strings

@ MSG_FMT_STRNL			"%s\n"
@ MSG_FMT_INDEX			"[%lld]"
@ MSG_FMT_INDEXRANGE		"[%lld-%lld]"
@ MSG_FMT_DUMPENTRY		"%15s  "


# Module name

@ MSG_MOD_NAME		"str"


# Command names

@ MSG_CMD_DUMP		"dump"
@ MSG_CMD_SET		"set"
@ MSG_CMD_ADD		"add"
@ MSG_CMD_ZERO		"zero"

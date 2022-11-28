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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2022 Oxide Computer Company
#

@ _START_

# Message file for elfedit 'cap' module

@ MSG_ID_ELFEDIT_CAP


# Debug messages

@ MSG_DEBUG_S_OK	"[%d: %s][%d]: value unchanged: %s\n"
@ MSG_DEBUG_S_CHG	"[%d: %s][%d]: change from %s to %s\n"
@ MSG_DEBUG_BSB_OK	"[%d: %s][%d]: value unchanged: [%s]\n"
@ MSG_DEBUG_BSB_CHG	"[%d: %s][%d]: change from [%s] to [%s]\n"
@ MSG_DEBUG_X_OK	"[%d: %s][%d]: value unchanged: %#llx\n"
@ MSG_DEBUG_X_CHG	"[%d: %s][%d]: change from %#llx to %#llx\n"
@ MSG_DEBUG_CA2NDX	"[%d: %s][%d]: capability entry for tag: %s\n"
@ MSG_DEBUG_CAPGRP	"[%d: %s][%u-%u: %s]: capability group\n"
@ MSG_DEBUG_CONVNULL	"[%d: %s][%d]: no existing %s to modify, converting \
			 extra CA_SUNW_NULL\n"

# Errors

@ MSG_ERR_NOCAELT	"[%d: %s][%u-%u: %s]: capabilities group does not \
			 contain tag: %s\n"
@ MSG_ERR_NOSTRTAB	"[%d: %s]: capabilities section does not have an \
			 associated string table\n"
@ MSG_ERR_BADCAPID	"[%d: %s]: capabilities section does not contain \
			 specified id: %s\n"
@ MSG_ERR_GRPARRBNDS	"%s[%u-%u: %s]: attempt to access elements outside \
			 of capabilities group\n"

# Module description

@ MSG_MOD_DESC		"Capabilities Section"

# Strings
@ MSG_STR_OBJECT	"<object>"
@ MSG_STR_NONAME	"<noname>"

# Format strings
@ MSG_FMT_CAPGRP	"   Group[%u-%u]: %s\n"

# 1-line description strings

@ MSG_DESC_DUMP		"Dump Capabilities Section"
@ MSG_DESC_TAG		"Change element tag"
@ MSG_DESC_VALUE	"Change element value"
@ MSG_DESC_DELETE	"Delete elements"
@ MSG_DESC_MOVE		"Move elements"
@ MSG_DESC_HW1		"Hardware capabilities (CA_SUNW_HW_1) bit values"
@ MSG_DESC_SF1		"Software capabilities (CA_SUNW_SF_1) bit values"
@ MSG_DESC_HW2		"Hardware capabilities (CA_SUNW_HW_2) bit values"
@ MSG_DESC_HW3		"Hardware capabilities (CA_SUNW_HW_3) bit values"


# Command option description strings

@ MSG_OPTDESC_CAPNDX		"\
   Interpret the elt argument as a direct index into the\n\
   capabilities section, rather than as a CA_ tag value.\n"

@ MSG_OPTDESC_CAPID		"\
   Restrict the elt argument to the capability elements belonging\n\
   to the capabilities group with a CA_SUNW_ID entry matching the\n\
   specified id name.\n"

@ MSG_OPTDESC_S		"\
   Interpret the value argument as a string rather than an\n\
   integer. If the specified string already exists in the\n\
   string table, the offset of that string is stored in the\n\
   capability entry. If the string does not exist in the string\n\
   table, but there is room to add it, the new string is added\n\
   and then the offset is placed in the capability entry.\n"


# Command argument description strings

@ MSG_A1_TAG_ELT	"\
   Capabilities element to be examined or changed. By default,\n\
   this is a CA_ tag value. The index of the first element\n\
   in the capabilities section that has the specified tag value\n\
   will be used. The value specified can be one of the well known\n\
   CA_ constants, or any integer.\n\
   \n\
   If the -capndx option is specified, elt is instead interpreted\n\
   as a simple integer index into the capabilities section.\n"

@ MSG_A2_TAG_VALUE	"\
   Value to be set for c_tag field of specified capabilities\n\
   element. Tag values can be specified using the well known\n\
   CA_ symbolic constants from /usr/include/sys/elf.h, or\n\
   as integers.\n"

@ MSG_ARGDESC_ELT	"\
   Element within capabilities section. By default, this is a\n\
   tag value. In this case, the index of the first capabilities\n\
   element with the specified tag value will be used. Tag values\n\
   can be specified using the well known CA_ symbolic constants\n\
   from /usr/include/sys/elf.h, or as integers. If the -capndx\n\
   option is specified, then elt is instead interpreted as a\n\
   direct numeric index into the capabilities section. If the\n\
   -capid option is specified, the search is limited to elements\n\
   within the named capabilities group.\n"

@ MSG_A2_VALUE_VALUE	"\
   Value to set for specified capabilities section element.\n\
   This is a numeric value which is used directly.\n"

@ MSG_A2_DELETE_COUNT	"\
   Number of capabilities elements to delete, starting at the\n\
   specified position. This value cannot exceed the number\n\
   of slots remaining in the capabilities group below the specified\n\
   position. If count is not supplied, a single element is deleted.\n"

@ MSG_A2_MOVE_DST_INDEX	"\
   Numeric index within capabilities section to which the element(s)\n\
   should be moved. The destination index must lie within the same\n\
   capabilities group as elt.\n"

@ MSG_A3_MOVE_COUNT	"\
   Number of capabilities elements to move. This value cannot\n\
   exceed the number of slots remaining in the capabilities group\n\
   below the specified position. If count is not supplied, a\n\
   single element is moved.\n"

@ MSG_A1_HW1_VALUE	"\
   Hardware capability (CA_SUNW_HW_1) values. This can be an integer\n\
   value, any of the AV_386_ symbolic constants defined in\n\
   /usr/include/sys/auxv_386.h, or the AV_SPARC symbolic\n\
   constants defined in /usr/include/sys/auxv_SPARC.h.\n"

@ MSG_A1_SF1_VALUE	"\
   Software capability (CA_SUNW_SF_1) values. This can be an integer\n\
   value, any of the SF1_SUNW_ symbolic constants defined in\n\
   /usr/include/sys/elf.h.\n"

@ MSG_A1_HW2_VALUE	"\
   Hardware capability (CA_SUNW_HW_2) values. This can be an integer\n\
   value, any of the AV_386_2_ symbolic constants defined in\n\
   /usr/include/sys/auxv_386.h.\n"

@ MSG_A1_HW3_VALUE	"\
   Hardware capability (CA_SUNW_HW_3) values. This can be an integer\n\
   value, any of the AV_386_3_ symbolic constants defined in\n\
   /usr/include/sys/auxv_386.h.\n"

# Help strings

@ MSG_HELP_DUMP	"   \
   The cap:dump command is used to display the contents of the\n\
   capabilities section using the same style used by the elfdump\n\
   program.\n"

@ MSG_HELP_TAG	"   \
   The cap:tag command is used to display or alter the\n\
   type of an element in the capabilities section. This information\n\
   is found in the c_tag field of a capabilities element.\n\
   \n\
   If cap:tag is called without arguments, the value of c_tag\n\
   for every element in the capabilities section is shown. If called\n\
   with the elt argument, the specified elements are displayed.\n\
   If both arguments are present, the c_tag field of the specified\n\
   capabilities element is set to the given value.\n"

@ MSG_HELP_VALUE	"   \
   The cap:value command is used to display or alter the\n\
   value of an element in the capabilities section. The value\n\
   of a capabilities element is found in the c_un union of the\n\
   element.\n\
   \n\
   If cap:value is called without arguments, the value of every\n\
   element in the capabilities section is shown. If called with the\n\
   elt argument, the value of the specified elements are displayed.\n\
   If both arguments are present, the value of the specified\n\
   capabilities element is set to the given value.\n"

@ MSG_HELP_DELETE	"   \
   The cap:delete command is used to delete one or more elements\n\
   from a capabilities group within the capabilities section. The\n\
   elements following the deleted items move up, and new CA_NULL\n\
   elements are inserted at the end of the capabilities group to\n\
   fill the vacated space.\n"

@ MSG_HELP_MOVE	"   \
   The cap:move command is used to move the position of one\n\
   or more elements in a capabilities group within in the\n\
   capabilities section. The specified number of elements are\n\
   moved from elt to dst_index.\n"

@ MSG_HELP_HW1	"   \
   The cap:hw1 command is used to display or alter the\n\
   value of the hardware capabilities element (CA_SUNW_HW_1).\n\
   \n\
   If cap:hw1 is called without arguments, the current\n\
   value is shown. If one or more value arguments are present,\n\
   the following steps are taken:\n\
   \n   \
   o\tAll the value arguments are OR'd together.\n\
   \n   \
   o\tIf the -cmp option has been specified, the new value\n\
   \tis complemented.\n\
   \n   \
   o\tThe CA_SUNW_HW_1 element of the capabilities section is\n\
   \tupdated with the new value. If -and is specified, the new\n\
   \tvalue is AND'd against the existing value. If -or is\n\
   \tspecified, the new value is OR'd against the existing\n\
   \tvalue. If neither -and or -or are specified, the new value\n\
   \treplaces the existing value.\n"

@ MSG_HELP_SF1	"   \
   The cap:sf1 command is used to display or alter the\n\
   value of the software capabilities element (CA_SUNW_SF_1).\n\
   \n\
   If cap:sf1 is called without arguments, the current\n\
   value is shown. If one or more value arguments are present,\n\
   the following steps are taken:\n\
   \n   \
   o\tAll the value arguments are OR'd together.\n\
   \n   \
   o\tIf the -cmp option has been specified, the new value\n\
   \tis complemented.\n\
   \n   \
   o\tThe CA_SUNW_SF_1 element of the capabilities section is\n\
   \tupdated with the new value. If -and is specified, the new\n\
   \tvalue is AND'd against the existing value. If -or is\n\
   \tspecified, the new value is OR'd against the existing\n\
   \tvalue. If neither -and or -or are specified, the new value\n\
   replaces the existing value.\n"

@ MSG_HELP_HW2	"   \
   The cap:hw2 command is used to display or alter the\n\
   value of the hardware capabilities element (CA_SUNW_HW_2).\n\
   \n\
   If cap:hw2 is called without arguments, the current\n\
   value is shown. If one or more value arguments are present,\n\
   the following steps are taken:\n\
   \n   \
   o\tAll the value arguments are OR'd together.\n\
   \n   \
   o\tIf the -cmp option has been specified, the new value\n\
   \tis complemented.\n\
   \n   \
   o\tThe CA_SUNW_HW_2 element of the capabilities section is\n\
   \tupdated with the new value. If -and is specified, the new\n\
   \tvalue is AND'd against the existing value. If -or is\n\
   \tspecified, the new value is OR'd against the existing\n\
   \tvalue. If neither -and or -or are specified, the new value\n\
   \treplaces the existing value.\n"

@ MSG_HELP_HW3	"   \
   The cap:hw3 command is used to display or alter the\n\
   value of the hardware capabilities element (CA_SUNW_HW_3).\n\
   \n\
   If cap:hw3 is called without arguments, the current\n\
   value is shown. If one or more value arguments are present,\n\
   the following steps are taken:\n\
   \n   \
   o\tAll the value arguments are OR'd together.\n\
   \n   \
   o\tIf the -cmp option has been specified, the new value\n\
   \tis complemented.\n\
   \n   \
   o\tThe CA_SUNW_HW_3 element of the capabilities section is\n\
   \tupdated with the new value. If -and is specified, the new\n\
   \tvalue is AND'd against the existing value. If -or is\n\
   \tspecified, the new value is OR'd against the existing\n\
   \tvalue. If neither -and or -or are specified, the new value\n\
   \treplaces the existing value.\n"
@ _END_


# The following strings represent reserved words, files, pathnames and symbols.
# Reference to this strings is via the MSG_ORIG() macro, and thus no message
# translation is required.


# Strings
@ MSG_STR_EMPTY		""
@ MSG_STR_COUNT		"count"
@ MSG_STR_ELT		"elt"
@ MSG_STR_DST_INDEX	"dst_index"
@ MSG_STR_MINUS_CAPID	"-capid"
@ MSG_STR_MINUS_CAPNDX	"-capndx"
@ MSG_STR_MINUS_S	"-s"
@ MSG_STR_VALUE		"value"
@ MSG_STR_IDNAME	"id_name"

# Format strings
@ MSG_FMT_STRNL		"%s\n"
@ MSG_FMT_HEXXWORDNL	"%#llx\n"
@ MSG_FMT_WORDVALNL	"%u\n"


# Module name

@ MSG_MOD_NAME		"cap"


# Command names

@ MSG_CMD_DUMP		"dump"
@ MSG_CMD_TAG		"tag"
@ MSG_CMD_VALUE		"value"
@ MSG_CMD_DELETE	"delete"
@ MSG_CMD_MOVE		"move"
@ MSG_CMD_HW1		"hw1"
@ MSG_CMD_SF1		"sf1"
@ MSG_CMD_HW2		"hw2"
@ MSG_CMD_HW3		"hw3"

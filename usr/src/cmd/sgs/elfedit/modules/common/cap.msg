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

# Message file for elfedit 'cap' module

@ MSG_ID_ELFEDIT_CAP


# Debug messages

@ MSG_DEBUG_S_OK	"[%d: %s][%d]: value unchanged: %s\n"
@ MSG_DEBUG_S_CHG	"[%d: %s][%d]: change from %s to %s\n"
@ MSG_DEBUG_BSB_OK	"[%d: %s][%d]: value unchanged: [%s]\n"
@ MSG_DEBUG_BSB_CHG	"[%d: %s][%d]: change from [%s] to [%s]\n"
@ MSG_DEBUG_X_OK	"[%d: %s][%d]: value unchanged: %#llx\n"
@ MSG_DEBUG_X_CHG	"[%d: %s][%d]: change from %#llx to %#llx\n"
@ MSG_DEBUG_CA2NDX	"[%d: %s][%d]: Capability entry for tag: %s\n"


# Errors

@ MSG_ERR_NOCAELT	"[%d: %s]: Capabilities section does not contain \
			 tag: %s\n"


# Module description

@ MSG_MOD_DESC		"Capabilities Section"



# 1-line description strings

@ MSG_DESC_DUMP		"Dump Capabilities Section"
@ MSG_DESC_TAG		"Change element tag"
@ MSG_DESC_VALUE	"Change element value"
@ MSG_DESC_DELETE	"Delete elements"
@ MSG_DESC_MOVE		"Move elements"
@ MSG_DESC_HW1		"Hardware capabilities bit values"
@ MSG_DESC_SF1		"Software capabilities bit values"


# Commmand option description strings

@ MSG_OPTDESC_CAPNDX		"\
   Interpret the elt argument as a direct index into the\n\
   capabilities section, rather than as a CA_ tag value.\n"


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
   direct numeric index into the capabilities section.\n"

@ MSG_A2_VALUE_VALUE	"\
   Value to set for specified capabilities section element.\n\
   This is a numeric value which is used directly.\n"

@ MSG_A2_DELETE_COUNT	"\
   Number of capabilities elements to delete, starting at the\n\
   specified position. This value cannot exceed the number\n\
   of slots remaining in the table below the specified position.\n\
   If count is not supplied, a single element is deleted.\n"

@ MSG_A2_MOVE_DST_INDEX	"\
   Numeric index within capabilities section to which the element(s)\n\
   should be moved.\n"

@ MSG_A3_MOVE_COUNT	"\
   Number of capabilities elements to move. This value cannot\n\
   exceed the number of slots remaining in the table below\n\
   the specified position. If count is not supplied, a\n\
   single element is moved.\n"

@ MSG_A1_HW1_VALUE	"\
   Hardware capability values. This can be an integer value,\n\
   any of the AV_386_ symbolic constants defined in\n\
   /usr/include/sys/auxv_386.h, or the AV_SPARC symbolic\n\
   constants defined in /usr/include/sys/auxv_SPARC.h\n"

@ MSG_A1_SF1_VALUE	"\
   Software capability values. This can be an integer value,\n\
   any of the SF1_SUNW_ symbolic constants defined in\n\
   /usr/include/sys/elf.h\n"



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
   in the capabilities section. The elements following the deleted\n\
   items move up, and new CA_NULL elements are inserted at the\n\
   end of the capabilities section to fill the vacated space.\n"

@ MSG_HELP_MOVE	"   \
   The cap:move command is used to move the position of one\n\
   or more elements in the capabilities section. The specified\n\
   number of elements are moved from elt to dst_index.\n"

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

@ _END_


# The following strings represent reserved words, files, pathnames and symbols.
# Reference to this strings is via the MSG_ORIG() macro, and thus no message
# translation is required.


# Strings
@ MSG_STR_EMPTY		""
@ MSG_STR_COUNT		"count"
@ MSG_STR_ELT		"elt"
@ MSG_STR_DST_INDEX	"dst_index"
@ MSG_STR_MINUS_CAPNDX	"-capndx"
@ MSG_STR_VALUE		"value"

# Format strings
@ MSG_FMT_STRNL		"%s\n"
@ MSG_FMT_HEXXWORDNL	"%#llx\n"


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

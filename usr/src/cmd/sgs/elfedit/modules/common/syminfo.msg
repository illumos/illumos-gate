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

# Message file for elfedit 'syminfo' module

@ MSG_ID_ELFEDIT_SYMINFO


# Debug messages

@ MSG_DEBUG_S_OK	"[%d: %s][%d].%s: value unchanged: %s\n"
@ MSG_DEBUG_S_CHG	"[%d: %s][%d].%s: change from %s to %s\n"
@ MSG_DEBUG_X_OK	"[%d: %s][%d].%s: value unchanged: %#x\n"
@ MSG_DEBUG_X_CHG	"[%d: %s][%d].%s: change from %#x to %#x\n"
@ MSG_DEBUG_FNDNEEDED	"[%d: %s][%d]: DT_NEEDED element for si_boundto: %s\n"
@ MSG_DEBUG_CONVNULL	"[%d: %s][%d]: No existing %s to modify. Converting \
			 extra DT_NULL\n"
@ MSG_DEBUG_CHGSYMINFO0	"[%d: %s][%d]: ELF warning: element [0] is expected to \
			 contain SYMINFO_VERSION, and should not be altered\n"

# Errors

@ MSG_ERR_NOEXTRANULL	"[%d: %s]: Dynamic section does not have room to add \
			 a new element\n"



# Module description

@ MSG_MOD_DESC		"Syminfo Section"


# 1-line description strings

@ MSG_DESC_DUMP		"Dump Syminfo Section"
@ MSG_DESC_SI_BOUNDTO	"Symbol to Object Binding"
@ MSG_DESC_SI_FLAGS	"Binding Flags"


# Command option description strings

@ MSG_OPTDESC_NEEDED		"\
   The value argument is a string giving the name of an ELF\n\
   object. The si_boundto field will be set to the index of the\n\
   corresponding DT_NEEDED entry of the dynamic section. If no\n\
   such DT_NEEDED entry exists in the dynamic section and there\n\
   is sufficient room, it will be added in order to satisfy this\n\
   request\n"

@ MSG_OPTDESC_SYMNDX		"\
   The sym argument supplies a numeric index into the syminfo\n\
   section instead of the name of the symbol.\n".


# Command argument descriptions

@ MSG_A1_SYM		"Name of desired symbol within symbol table.\n"

@ MSG_A2_DESC_SI_BOUNDTO	"\
   An integer value that describes the object this symbol is\n\
   bound to. SYMINFO_BT_ symbolic constants are accepted to\n\
   represent special values (self, parent, none), or the value\n\
   can be the index of a dynamic section element.\n"

@ MSG_A2_DESC_SI_FLAGS	"\
   New value for symbol binding flags. SYMINFO_FLG_ symbolic\n\
   constants are accepted, as is any integer.\n"



# Help strings

@ MSG_HELP_DUMP	"   \
   The syminfo:dump command is used to display information\n\
   from the syminfo section using the same style used by the\n\
   elfdump program.\n\
   \n\
   The syminfo section augments the information found in the\n\
   dynamic symbol table.\n\
   \n\
   If sym:dump is called without arguments, syminfo information\n\
   for every symbol in the symbol table is shown. If called with\n\
   the sym argument, the information for that symbol is\n\
   displayed.\n"

@ MSG_HELP_SI_BOUNDTO	"   \
   The syminfo:si_boundto command is used to display or alter\n\
   the external object the symbol is bound to. This information\n\
   is found in the si_boundto field of a syminfo structure. It is\n\
   an integer that contains one of the special SYMINFO_BT_ values,\n\
   or alternaltively, an index into the dynamic section of the\n\
   ELF object.\n\
   \n\
   If syminfo:si_boundto is called without arguments, the value of\n\
   si_boundto for every symbol in the symbol table is shown. If\n\
   called with the sym argument, the si_boundto information for\n\
   that is displayed. If both arguments are present, the second\n\
   argument supplies a new value for si_boundto.\n\
   \n\
   By default, value is an integer, which will have one of the\n\
   special SYMINFO_BT_ values, or which will be the index of an\n\
   element in the dynamic section. Alternatively, the -needed\n\
   option can be used to specify a string with the name of an\n\
   object. If -needed is is used, si_boundto will be set to the\n\
   index of the DT_NEEDED entry in the dynamic section that\n\
   corresponds to the given name. If no such DT_NEEDED element\n\
   exists, and room is available to add it, it will be added in\n\
   order to faciliate this operation.\n"

@ MSG_HELP_SI_FLAGS	"   \
   Examine or modify the syminfo binding flags associated\n\
   with a given symbol. This information is found in the\n\
   si_flags field of the syminfo structure.\n\
   \n\
   If syminfo:si_flags is called without arguments, the value\n\
   of si_flags for every symbol in the symbol table is shown.\n\
   If called with the sym argument, the si_flags information\n\
   for that symbol is displayed. If one or more value arguments\n\
   are present, the the following steps are taken:\n\
   \n   \
   o\tAll the value arguments are OR'd together.\n\
   \n   \
   o\tIf the -cmp option has been specified, the new value\n\
   \tis complemented.\n\
   \n   \
   o\tThe si_flags field of the syminfo structure is updated\n\
   \twith the new value. If -and is specified, the new value is\n\
   \tAND'd against the existing value. If -or is specified,\n\
   \tthe new value is OR'd against the existing value. If\n\
   \tneither -and or -or are specified, the new value replaces\n\
   \tthe existing value.\n"


@ _END_


# The following strings represent reserved words, files, pathnames and symbols.
# Reference to this strings is via the MSG_ORIG() macro, and thus no message
# translation is required.


# Miscellaneous clutter
@ MSG_STR_EMPTY			""
@ MSG_STR_MINUS_NEEDED		"-needed"
@ MSG_STR_MINUS_SYMNDX		"-symndx"
@ MSG_STR_SYM			"sym"
@ MSG_STR_VALUE			"value"


# Format strings

@ MSG_FMT_WORDVALNL		"%u\n"
@ MSG_FMT_HEXNUMNL		"%#x\n"
@ MSG_FMT_STRNL			"%s\n"


# Module name

@ MSG_MOD_NAME		"syminfo"


# Command names

@ MSG_CMD_DUMP		"dump"
@ MSG_CMD_SI_BOUNDTO	"si_boundto"
@ MSG_CMD_SI_FLAGS	"si_flags"

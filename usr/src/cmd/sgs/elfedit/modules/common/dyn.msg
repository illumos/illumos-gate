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

# Message file for elfedit 'dyn' module

@ MSG_ID_ELFEDIT_DYN


# Strings
@ MSG_STR_DEPRECATED	"(deprecated value)"

# Debug messages

@ MSG_DEBUG_S_OK	"[%d: %s][%d]: value unchanged: %s\n"
@ MSG_DEBUG_S_CHG	"[%d: %s][%d]: change from %s to %s\n"
@ MSG_DEBUG_X_OK	"[%d: %s][%d]: value unchanged: %#llx\n"
@ MSG_DEBUG_X_CHG	"[%d: %s][%d]: change from %#llx to %#llx\n"
@ MSG_DEBUG_PREVRPATH	"[%d: %s][%d]: Reusing existing %s entry: %s\n"
@ MSG_DEBUG_OLDRPATHOK	"[%d: %s][%d]: Existing %s already has desired \
			 value\n"
@ MSG_DEBUG_CONVNULL	"[%d: %s][%d]: No existing %s to modify. Converting \
			 extra DT_NULL\n"
@ MSG_DEBUG_DT2NDX	"[%d: %s][%d]: Dynamic entry for tag: %s\n"
@ MSG_DEBUG_NULCLIP	"[%d: %s][%d]: ELF warning: null element will cause \
			 the runtime linker to ignore the non-null \
			 elements that follow: %s\n"
@ MSG_DEBUG_NULHIDE	"[%d: %s][%d]: ELF warning: this non-null element \
			 follows the first DT_NULL element, and will be \
			 ignored by the runtime linker: %s\n"
@ MSG_DEBUG_NULLTERM	"[%d: %s][%d]: ELF warning: dynamic section is \
			 must be terminated by a DT_NULL. The runtime linker \
			 will be unable to use this object: %s\n"
@ MSG_DEBUG_DTNULLVALUE	"[%d: %s][%d]: ELF warning: DT_NULL element value \
			 is expected to be 0: %#llx\n"


# Errors

@ MSG_ERR_NODTELT	"[%d: %s]: Dynamic section does not contain tag: %s\n"
@ MSG_ERR_NOEXTRANULL	"[%d: %s]: Dynamic section does not have room to add \
			 a new element\n"
@ MSG_ERR_NORUNPATH	"[%d: %s]: no runpath (DT_RPATH or DT_RUNPATH) found\n"
@ MSG_ERR_NODYNELT	"[%d: %s]: no elements of type %s found\n"
@ MSG_ERR_STRPADSTRVAL	"[%d: %s]: -s option cannot be used with \
			 DT_SUNW_STRPAD dynamic element\n"
@ MSG_ERR_WRONGTAG	"[%d: %s][%d]: expected %s dynamic element: %s\n"
@ MSG_ERR_NEEDEDNOMATCH	"[%d: %s]: matching DT_NEEDED element not found: %s\n";


# Module description

@ MSG_MOD_DESC		"Dynamic Section"



# 1-line description strings

@ MSG_DESC_DUMP		"Dump Dynamic Section"
@ MSG_DESC_TAG		"Change element tag"
@ MSG_DESC_VALUE	"Change element value"
@ MSG_DESC_DELETE	"Delete elements"
@ MSG_DESC_MOVE		"Move elements"
@ MSG_DESC_RUNPATH	"Set runpath"
@ MSG_DESC_POSFLAG1	"DT_POSFLAG_1 bit values"
@ MSG_DESC_FLAGS	"DT_FLAGS bit values"
@ MSG_DESC_FLAGS1	"DT_FLAGS_1 bit values"
@ MSG_DESC_FEATURE1	"DT_FEATURE_1 bit values"
@ MSG_DESC_CHECKSUM	"Recompute DT_CHECKSUM"
@ MSG_DESC_SUNW_LDMACH	"Linker machine type"


# Commmand option description strings

@ MSG_OPTDESC_ADD	"\
   By default, dyn:value modifies the first element of the\n\
   dynamic section that has the specified tag type, creating\n\
   a new element only if no element of the specified type\n\
   exists, and if room exists in the file. If -add is specified,\n\
   dyn:value will always create a new element for the new value,\n\
   leaving any existing elements with the same tag untouched.\n"

@ MSG_OPTDESC_S		"\
   Interpret the value argument as a string rather than an\n\
   integer. If the specified string already exists in the dynamic\n\
   string table, the offset of that string is stored in the\n\
   dynamic entry. If the string does not exist in the string table,\n\
   but there is room to add it, the new string is added and then\n\
   the offset is placed in the dynamic entry.\n"

@ MSG_OPTDESC_DYNNDX_ELT	"\
   Interpret the elt argument as a direct index into the dynamic\n\
   section, rather than as a DT_ tag value.\n"

@ MSG_OPTDESC_DYNNDX_VAL	"\
   Use the dynamic element with the specified index.\n"

@ MSG_OPTDESC_NEEDED	"\
   Select the first DT_POSFLAG_1 dynamic element that corresponds\n\
   to the DT_NEEDED element with a value that starts with the\n\
   string given by prefix. If present, the DT_POSFLAG_1 element\n\
   will be in the dynamic element directly in front of the\n\
   DT_NEEDED element.\n"


# Command argument description strings

@ MSG_A1_TAG_ELT	"\
   Dynamic element to be examined or changed. By default, this\n\
   is a DT_ tag value. The index of the first element in the\n\
   dynamic section that has the specified tag value will be used.\n\
   The value specified can be one of the well known DT_ constants,\n\
   or any integer.\n\
   \n\
   If the -dynndx option is specified, elt is instead interpreted\n\
   as a simple integer index into the dynamic section.\n"

@ MSG_A2_TAG_VALUE	"\
   Value to be set for d_tag field of specified dynamic\n\
   element. Tag values can be specified using the well known\n\
   DT_ symbolic constants from /usr/include/sys/link.h, or\n\
   as integers.\n"

@ MSG_ARGDESC_ELT	"\
   Element within dynamic section. By default, this is a tag\n\
   value. In this case, the index of the first dynamic element\n\
   with the specified tag value will be used. Tag values can\n\
   be specified using the well known DT_ symbolic constants from\n\
   /usr/include/sys/link.h, or as integers. If the -dynndx\n\
   option is specified, then elt is instead interpreted as a\n\
   direct numeric index into the dynamic section.\n"

@ MSG_A2_VALUE_VALUE	"\
   Value to set for specified dynamic section element. By\n\
   default, this is a numeric value which is used directly.\n\
   If the -s option is used, this is a string value, and the\n\
   dynamic element will receive the numeric offset of the\n\
   specified string from within the associated dynamic string\n\
   table.\n"

@ MSG_A2_DELETE_COUNT	"\
   Number of dynamic elements to delete, starting at the\n\
   specified position. This value cannot exceed the number\n\
   of slots remaining in the table below the specified position.\n\
   If count is not supplied, a single element is deleted.\n"

@ MSG_A2_MOVE_DST_INDEX	"\
   Numeric index within dynamic section to which the element(s)\n\
   should be moved.\n"

@ MSG_A3_MOVE_COUNT	"\
   Number of dynamic elements to move. This value cannot\n\
   exceed the number of slots remaining in the table below\n\
   the specified position. If count is not supplied, a\n\
   single element is moved.\n"

@ MSG_A1_RUNPATH_NEWPATH	"\
   New runpath string for the ELF object.\n"

@ MSG_A1_POSFLAG1_VALUE "\
   Position dependent state flags which are applied to the\n\
   element immediately following. This can be an integer\n\
   value, or any of the DF_P1_ symbolic constants defined\n\
   in /usr/include/sys/link.h\n"

@ MSG_A1_FLAGS_VALUE	"\
   Flag values. This can be an integer value, or any of the\n\
   DF_ symbolic constants defined in /usr/include/sys/link.h\n"

@ MSG_A1_FLAGS1_VALUE	"\
   Flag values. This can be an integer value, or any of the\n\
   DF_1_ symbolic constants defined in /usr/include/sys/link.h\n"

@ MSG_A1_FEATURE1_VALUE	"\
   Feature values. This can be an integer value, or any of\n\
   the DTF_1_ symbolic constants defined in\n\
   /usr/include/sys/link.h\n"

@ MSG_A1_SUNW_LDMACH_VALUE	"\
   Machine type of link-editor that built the object being edited.\n\
   This can be an integer value, or any of the EM_ symbolic\n\
   constants defined in /usr/include/elf.h\n"


# Help strings

@ MSG_HELP_DUMP	"   \
   The dyn:dump command is used to display the contents of the\n\
   dynamic section using the same style used by the elfdump program.\n"

@ MSG_HELP_TAG	"   \
   The dyn:tag command is used to display or alter the\n\
   type of an element in the dynamic section. This information\n\
   is found in the d_tag field of a dynamic element.\n\
   \n\
   If dyn:tag is called without arguments, the value of d_tag\n\
   for every element in the dynamic section is shown. If called\n\
   with the elt argument, the specified elements are displayed.\n\
   If both arguments are present, the d_tag field of the specified\n\
   dynamic element is set to the given value.\n"

@ MSG_HELP_VALUE	"   \
   The dyn:value command is used to display or alter the\n\
   value of an element in the dynamic section, or to add\n\
   a new element of a desired type. The value of a dynamic\n\
   element is found in the d_un union of the element.\n\
   \n\
   If dyn:value is called without arguments, the value of every\n\
   element in the dynamic section is shown. If called with the\n\
   elt argument, the value of the specified elements are displayed.\n\
   If both arguments are present, the value of the specified\n\
   dynamic element is set to the given value.\n"

@ MSG_HELP_DELETE	"   \
   The dyn:delete command is used to delete one or more elements\n\
   in the dynamic section. The elements following the deleted\n\
   items move up, and new DT_NULL elements are inserted at the\n\
   end of the dynamic section to fill the vacated space.\n\
   \n\
   Other parts of the ELF object may have dependencies on the\n\
   position and values of existing dynamic elements. Moving or\n\
   deleting dynamic elements can therefore break the object,\n\
   and should be done with caution. Among the potential issues:\n\
   \n\
   o\tDT_POSFLAG_1 has a positional dependency on the item that\n\
   \tfollows it. If that item is removed, the DT_POSFLAG_1 will\n\
   \tapply to the new item that moves below it.\n\
   \n\
   o\tSyminfo sections reference DT_NEEDED elements in the dynamic\n\
   \tsection by index. Moving or deleting such elements will break\n\
   \tthis dependency.\n"

@ MSG_HELP_MOVE	"   \
   The dyn:move command is used to move the position of one\n\
   or more elements in the dynamic section. The specified\n\
   number of elements are moved from elt to dst_index.\n\
   \n\
   Other parts of the ELF object may have dependencies on the\n\
   position and values of existing dynamic elements. Moving or\n\
   deleting dynamic elements can therefore break the object,\n\
   and should be done with caution. Among the potential issues:\n\
   \n\
   o\tDT_POSFLAG_1 has a positional dependency on the item that\n\
   \tfollows it. If that item is removed, the DT_POSFLAG_1 will\n\
   \tapply to the new item that moves below it.\n\
   \n\
   o\tSyminfo sections reference DT_NEEDED elements in the dynamic\n\
   \tsection by index. Moving or deleting such elements will break\n\
   \tthis dependency.\n"

@ MSG_HELP_RUNPATH	"   \
   The dyn:runpath command is used to display or alter the\n\
   runpath of the ELF object.\n\
   \n\
   If dyn:runpath is called without arguments, the existing runpath\n\
   is shown. If called with the newpath argument, the runpath is set\n\
   to the given string, if possible.\n\
   \n\
   Not all files can be modified to have a new runpath:\n\
   \n\
   o\tThe desired string must already exist in the dynamic string\n\
   \ttable, or there must be enough room in the reserved section\n\
   \tsection at the end (DT_SUNW_STRPAD) for the new string to be\n\
   \tadded.\n\
   \n\
   o\tThe dynamic section must already have a DT_RPATH or DT_RUNPATH\n\
   \telement, or there must be an extra DT_NULL slot at the end\n\
   \twhere a DT_RUNPATH can be inserted.\n\
   \n\
   If the file has both DT_RPATH and DT_RUNPATH elements in\n\
   the dynamic section, both are set to the new value. If no\n\
   runpath entry exists, a new DT_RUNPATH is inserted if the room\n\
   for it exists.\n"

@ MSG_HELP_POSFLAG1	"   \
   The dyn:posflag1 command is used to display or alter\n\
   DT_POSFLAG_1 flags values. DT_POSFLAG_1 is a positional\n\
   dynamic element that affects the interpretation of the item\n\
   that follows it. Therefore, when displaying DT_POSFLAG_1 elements\n\
   using the default output style, dyn:posflag1 also displays the\n\
   dynamic element that follows it.\n\
   \n\
   If dyn:posflag1 is called without arguments, the current\n\
   value of all DT_POSFLAG_1 elements are shown. It is possible\n\
   to display the value of a single specific DT_POSFLAG_1 element\n\
   by using the -dynndx or -needed option to specify it.\n\
   \n\
   If one or more value arguments are present, the default is to\n\
   modify the first DT_POSFLAG_1 element. The -dynndx or -needed\n\
   option can be used to specify a specific DT_POSFLAG_1_element\n\
   instead. The following steps are taken to compute the new value:\n\
   \n   \
   o\tAll the value arguments are OR'd together.\n\
   \n   \
   o\tIf the -cmp option has been specified, the new value\n\
   \tis complemented.\n\
   \n   \
   o\tThe DT_POSFLAG_1 element is updated with the new value.\n\
   \tIf -and is specified, the new value is AND'd against the\n\
   \texisting value. If -or is specified, the new value is OR'd\n\
   \tagainst the existing value. If neither -and or -or are\n\
   \tspecified, the new value replaces the existing value.\n\
   \n\
   A new DT_POSFLAG_1 element is inserted in the dynamic section\n\
   when all of the following are true:\n\
   \n   \
   o\tOne or more value arguments are present.\n\
   \n   \
   o\tThe -dynndx and -needed options are not used.\n\
   \n   \
   o\tThe current dynamic section does not have a current\n\
   \tDT_POSFLAG_1 element.\n\
   \n   \
   o\tThere is available space at the end of the dynamic section.\n"

@ MSG_HELP_FLAGS	"   \
   The dyn:flags command is used to display or alter the\n\
   value of the DT_FLAGS dynamic element.\n\
   \n\
   If dyn:flags is called without arguments, the current\n\
   value is shown. If one or more value arguments are present,\n\
   the following steps are taken:\n\
   \n   \
   o\tAll the value arguments are OR'd together.\n\
   \n   \
   o\tIf the -cmp option has been specified, the new value\n\
   \tis complemented.\n\
   \n   \
   o\tThe DT_FLAGS element of the dynamic section is updated\n\
   \twith the new value. If -and is specified, the new value is\n\
   \tAND'd against the existing value. If -or is specified,\n\
   \tthe new value is OR'd against the existing value. If\n\
   \tneither -and or -or are specified, the new value replaces\n\
   \tthe existing value.\n\
   \n\
   If the current dynamic section does not have a current\n\
   DT_FLAGS element, and room for it exists at the end\n\
   of the section, a new one is inserted.\n"

@ MSG_HELP_FLAGS1	"   \
   The dyn:flags1 command is used to display or alter the\n\
   value of the DT_FLAGS_1 dynamic element.\n\
   \n\
   If dyn:flags1 is called without arguments, the current\n\
   value is shown. If one or more value arguments are present,\n\
   the following steps are taken:\n\
   \n   \
   o\tAll the value arguments are OR'd together.\n\
   \n   \
   o\tIf the -cmp option has been specified, the new value\n\
   \tis complemented.\n\
   \n   \
   o\tThe DT_FLAGS_1 element of the dynamic section is updated\n\
   \twith the new value. If -and is specified, the new value is\n\
   \tAND'd against the existing value. If -or is specified,\n\
   \tthe new value is OR'd against the existing value. If\n\
   \tneither -and or -or are specified, the new value replaces\n\
   \tthe existing value.\n\
   \n\
   If the current dynamic section does not have a current\n\
   DT_FLAGS_1 element, and room for it exists at the end\n\
   of the section, a new one is inserted.\n"

@ MSG_HELP_FEATURE1	"   \
   The dyn:feature1 command is used to display or alter the\n\
   value of the DT_FEATURE_1 dynamic element.\n\
   \n\
   If dyn:feature1 is called without arguments, the current\n\
   value is shown. If one or more value arguments are present,\n\
   the following steps are taken:\n\
   \n   \
   o\tAll the value arguments are OR'd together.\n\
   \n   \
   o\tIf the -cmp option has been specified, the new value\n\
   \tis complemented.\n\
   \n   \
   o\tThe DT_FEATURE_1 element of the dynamic section is updated\n\
   \twith the new value. If -and is specified, the new value is\n\
   \tAND'd against the existing value. If -or is specified,\n\
   \tthe new value is OR'd against the existing value. If\n\
   \tneither -and or -or are specified, the new value replaces\n\
   \tthe existing value.\n\
   \n\
   If the current dynamic section does not have a current\n\
   DT_FEATURE_1 element, and room for it exists at the end\n\
   of the section, a new one is inserted.\n"

@ MSG_HELP_CHECKSUM	"   \
   The dyn:checksum command recomputes the value of the DT_CHECKSUM\n\
   dynamic element. It calls the elf32_checksum() for 32-bit objects,\n\
   or elf64_checksum() for 64-bit objects, and then sets the value of\n\
   the DT_CHECKSUM element to the resulting value.\n\
   \n\
   If the current dynamic section does not have a current\n\
   DT_CHECKSUM element, and room for it exists at the end\n\
   of the section, a new one is inserted.\n"

@ MSG_HELP_SUNW_LDMACH	"   \
   The dyn:sunw_ldmach command is used to display or alter the\n\
   DT_SUNW_LDMACH dynamic element of the ELF object. This dynamic\n\
   element records the ELF machine type of the link-editor that produced\n\
   the object. This is of special interest if the object was built\n\
   by a cross link-editor instead of being linked on a machine of the\n\
   same type as the object.\n\
   \n\
   If dyn:sunw_ldmach is called without arguments, the current\n\
   value is shown. If called with the value argument, the\n\
   DT_SUNW_LDMACH dynamic element is set to the specified machine type.\n\
   \n\
   If the current dynamic section does not have a current\n\
   DT_SUNW_LDMACH element, and room for it exists at the end\n\
   of the section, a new one is inserted.\n"

@ _END_


# The following strings represent reserved words, files, pathnames and symbols.
# Reference to this strings is via the MSG_ORIG() macro, and thus no message
# translation is required.


# Strings
@ MSG_STR_EMPTY		""
@ MSG_STR_COUNT		"count"
@ MSG_STR_ELT		"elt"
@ MSG_STR_DST_INDEX	"dst_index"
@ MSG_STR_INDEX		"index"
@ MSG_STR_MINUS_ADD	"-add"
@ MSG_STR_MINUS_DYNNDX	"-dynndx"
@ MSG_STR_MINUS_NEEDED	"-needed"
@ MSG_STR_MINUS_S	"-s"
@ MSG_STR_NEWPATH	"newpath"
@ MSG_STR_PREFIX	"prefix"
@ MSG_STR_VALUE		"value"

# Format strings
@ MSG_FMT_STRNL		"%s\n"
@ MSG_FMT_HEXXWORDNL	"%#llx\n"


# Module name

@ MSG_MOD_NAME		"dyn"


# Command names

@ MSG_CMD_DUMP		"dump"
@ MSG_CMD_TAG		"tag"
@ MSG_CMD_VALUE		"value"
@ MSG_CMD_DELETE	"delete"
@ MSG_CMD_MOVE		"move"
@ MSG_CMD_RUNPATH	"runpath"
@ MSG_CMD_RUNPATH_A1	"rpath"
@ MSG_CMD_POSFLAG1	"posflag1"
@ MSG_CMD_FLAGS		"flags"
@ MSG_CMD_FLAGS1	"flags1"
@ MSG_CMD_FEATURE1	"feature1"
@ MSG_CMD_CHECKSUM	"checksum"
@ MSG_CMD_SUNW_LDMACH	"sunw_ldmach"

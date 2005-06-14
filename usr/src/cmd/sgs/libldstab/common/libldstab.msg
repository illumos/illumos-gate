#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# ident	"%Z%%M%	%I%	%E% SMI"


@ _START_

# Message file for cmd/sgs/libldstab.

@ MSG_ID_LIBLDSTAB


# Stab processing errors.

@ MSG_STAB_MISTBL	"libldstab: file %s: .stab[.index|.sbfocus] found \
			 with no matching string table\n"
@ MSG_STAB_BADTBL	"libldstab: file %s: .stab[.index|.sbfocus] error \
			 when reading string table\n"
@ MSG_STAB_NOSBROW	"SourceBrowser data will be lost"

# System errors

@ MSG_SYS_EXEC		"libldstab: file %s: %s exec failed: %s: %s\n"
@ MSG_SYS_FORK		"libldstab: file %s: fork failed: %s: %s\n"
@ MSG_SYS_GETCWD	"libldstab: file %s: getcwd failed: %s\n"

@ MSG_ELF_GETDATA	"libldstab: file %s: elf_getdata: %s\n"
@ MSG_ELF_GETSCN	"libldstab: file %s: elf_getscn: %s\n"

@ _END_

# The following strings represent reserved names.  Reference to these strings
# is via the MSG_ORIG() macro, and thus translations are not required.

# Elf processing messages.

@ MSG_STR_DASHR		"-r"
@ MSG_STR_DASHX		"-x"
@ MSG_STR_W		"w"

@ MSG_STR_SBFOCUS	"sbfocus"

@ MSG_SUNW_OST_SGS	"SUNW_OST_SGS"

# Section strings

@ MSG_SCN_STAB		".stab"
@ MSG_SCN_STABSTR	".stabstr"
@ MSG_SCN_STABINDEX	".stab.index"
@ MSG_SCN_STABINDEXSTR	".stab.indexstr"
@ MSG_SCN_STABSBFOCUS	".stab.sbfocus"
@ MSG_SCN_STABSBFOCUSTR	".stab.sbfocusstr"

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

@ _START_

# Messages for cmd/sgs/librtld

@ MSG_ID_LIBRTLD


# System call messages

@ MSG_SYS_PROC		"%s: /proc error: %s"
@ MSG_SYS_OPEN		"%s: open failed: %s"


# Image processing messages

@ MSG_IMG_ELF		"%s: is not a dynamic ELF object"
@ MSG_IMG_DATASEG	"%s: data segment not found"
@ MSG_IMG_DATASEC	"%s: final data section not found"


# ELF processing messages

@ MSG_DT_UNKNOWN	"%s: unknown dynamic entry: ignored: %lld"


# Basic strings

@ MSG_STR_UNKNOWN       "<unknown>"


@ _END_


# The following strings represent reserved section and symbol names.  Reference
# to these strings is via the MSG_ORIG() macro, and thus no translations are
# required.

@ MSG_FMT_PROC		"/proc/%d"

@ MSG_ELF_BEGIN		"%s: elf_begin"
@ MSG_ELF_GETDATA	"%s: elf_getdata"
@ MSG_ELF_GETEHDR	"%s: elf_getehdr"
@ MSG_ELF_GETPHDR	"%s: elf_getphdr"
@ MSG_ELF_GETSCN	"%s: elf_getscn"
@ MSG_ELF_GETSHDR	"%s: elf_getshdr"
@ MSG_ELF_GETSHDRNUM	"%s: elf_getshdrnum"
@ MSG_ELF_GETSHDRSTRNDX	"%s: elf_getshdrstrndx"
@ MSG_ELF_NEWDATA	"%s: elf_newdata"
@ MSG_ELF_NEWEHDR	"%s: elf_newehdr"
@ MSG_ELF_NEWPHDR	"%s: elf_newphdr"
@ MSG_ELF_NEWSCN	"%s: elf_newscn"
@ MSG_ELF_NEWSHDR	"%s: elf_newshdr"
@ MSG_ELF_UPDATE	"%s: elf_update"

@ MSG_SCN_HEAP		".SUNW_heap"
@ MSG_SCN_RELOC		".SUNW_reloc"
@ MSG_SCN_SHSTR		".shstrtab"

@ MSG_SYM_END		"_end"
@ MSG_SYM_EDATA		"_edata"

@ MSG_SUNW_OST_SGS	"SUNW_OST_SGS"

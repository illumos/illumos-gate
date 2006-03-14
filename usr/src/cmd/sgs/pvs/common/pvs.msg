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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"

@ _START_

# Message file for cmd/sgs/pvs.

@ MSG_ID_PVS


# Argument usage messages.

@ MSG_USAGE_BRIEF	"usage: %s [-Cdlnorsv] [-N Name] file(s)\n"
@ MSG_USAGE_DETAIL	"\t[-C]\t\tdemangle C++ symbol names\n\
			 \t[-d]\t\tprint version definition information\n\
			 \t[-l]\t\tprint reduced symbols\n\
			 \t[-N name]\tqualify version with `name'\n\
			 \t[-n]\t\tnormalize version definition information\n\
			 \t[-o]\t\tone-line version definition output\n\
			 \t[-r]\t\tprint version dependency (requirements) \
			  information\n\
			 \t[-s]\t\tprint version definition symbols\n\
			 \t[-v]\t\tprint verbose information\n"


# Versioning messages.

@ MSG_VER_HIGHREV	"%s: warning: %s: version revision %d is \
			 higher than expected %d\n"
@ MSG_VER_UNREDSYMS	"%s: warning: %s: unable to deduce reduced symbols:\n"
@ MSG_VER_NOTSTTFILE	"\tmalformed symbol table[1]=%s: does not equal \
			 STT_FILE\n"
@ MSG_VER_NOSYMTAB	"\tno symbol table (SHT_SYMTAB) found\n"


# ELF messages
@ MSG_ELF_NOTELF	"%s: %s: is not ELF\n"

# System error messages

@ MSG_SYS_OPEN		"%s: %s: cannot open file: %s\n"
@ MSG_SYS_MALLOC	"%s: %s: malloc failed: %s\n"

@ _END_

# The following strings represent reserved words, files, pathnames and symbols.
# Reference to this strings is via the MSG_ORIG() macro, and thus no message
# translation is required.

@ MSG_ELF_BEGIN		"%s: %s: elf_begin: %s\n"
@ MSG_ELF_GETEHDR	"%s: %s: elf_getehdr: %s\n"
@ MSG_ELF_GETSCN	"%s: %s: elf_getscn: %s\n"
@ MSG_ELF_GETSHDR	"%s: %s: elf_getshdr: %s\n"
@ MSG_ELF_GETDATA	"%s: %s: elf_getdata: %s\n"

@ MSG_STR_EMPTY		""

@ MSG_SUNW_OST_SGS	"SUNW_OST_SGS"

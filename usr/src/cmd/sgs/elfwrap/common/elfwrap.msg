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
#

@ _START_

# Message file for cmd/sgs/elfwrap.

@ MSG_ID_ELFWRAP

# Usage Messages

@ MSG_USAGE_BRIEF	"usage: %s [-64] [-o file] [-z target=platform] \
			 data, ...\n"

@ MSG_ARG_BADTARG	"%s: unknown target platform: %s\n"
@ MSG_ARG_ILLEGAL	"%s: option %s has illegal argument `%s'\n"

@ MSG_ERR_LIBELF	"%s: libelf: version not supported: %d\n"

@ MSG_ERR_ALLOC		"%s: %s: can't allocate memory: %s\n"
@ MSG_ERR_FSTAT		"%s: %s: can't fstat: %s\n"
@ MSG_ERR_MMAP		"%s: %s: can't mmap: %s\n"
@ MSG_ERR_OPEN		"%s: %s: can't open: %s\n"

@ MSG_WARN_ZERO		"%s: %s: has zero length - ignoring\n"

@ MSG_ELF_BEGIN		"%s: elf_begin failed: %s\n"
@ MSG_ELF_GETEHDR	"%s: elf_getehdr failed: %s\n"
@ MSG_ELF_NEWEHDR	"%s: elf_newehdr failed: %s\n"
@ MSG_ELF_SWAP_WRIMAGE	"%s: elf_swap_wrimage failed: %s\n"
@ MSG_ELF_UPDATE	"%s: elf_update failed: %s\n"

@ MSG_ELF_GETDATA	"%s: %s: elf_getdata failed: %s\n"
@ MSG_ELF_GETSCN	"%s: %s: elf_getscn failed: %s\n"
@ MSG_ELF_GETSHDR	"%s: %s: elf_getshdr failed: %s\n"
@ MSG_ELF_NEWDATA	"%s: %s: elf_newdata failed: %s\n"
@ MSG_ELF_NEWSCN	"%s: %s: elf_newscn failed: %s\n"

@ _END_

# The following strings represent reserved words, files, path names and symbols.
# Reference to this strings is via the MSG_ORIG() macro, and thus no message
# translation is required.

@ MSG_SUNW_OST_SGS	"SUNW_OST_SGS"

@ MSG_ARG_6		"-6"
@ MSG_ARG_OPTIONS	"6:o:z:"
@ MSG_ARG_TARGET	"target="
@ MSG_ARG_Z		"-z"

@ MSG_TARG_SPARC	"sparc"
@ MSG_TARG_X86		"x86"

@ MSG_STR_AWRAPO	"a.wrap.o"
@ MSG_STR_EMPTY		""
@ MSG_STR_START		"_start"
@ MSG_STR_END		"_end"
@ MSG_STR_DOT		"."

@ MSG_SCN_SYMTAB	".symtab"
@ MSG_SCN_STRTAB	".strtab"
@ MSG_SCN_SHSTRTAB	".shstrtab"

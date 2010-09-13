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
# Copyright (c) 1996, 2010, Oracle and/or its affiliates. All rights reserved.
#

@ _START_

# Message file for cmd/sgs/ld.

@ MSG_ID_LD

# System error messages

@ MSG_SYS_OPEN		"file %s: open failed: %s"
@ MSG_SYS_EXEC		"file %s: exec failed: %s"

@ MSG_SYS_ALLOC		"alloc failed: %s"
@ MSG_SYS_64		"unable to execute 64-bit version of ld"

@ MSG_ERR_BADTARG	"unknown target platform: %s"

# Generic error diagnostic labels

@ MSG_ERR_WARNING	"warning: "
@ MSG_ERR_GUIDANCE	"guidance: "
@ MSG_ERR_FATAL		"fatal: "
@ MSG_ERR_ELF		"elf error: "

@ _END_


# The following strings represent reserved words, files, pathnames and symbols.
# Reference to these strings is via the MSG_ORIG() macro, and thus no message
# translation is required.

@ MSG_STR_EMPTY		""
@ MSG_STR_NL		"\n"
@ MSG_STR_LDDIAG	"ld: "
@ MSG_STR_ELFDIAG	": %s"

@ MSG_ARG_TWO		"2"
@ MSG_ARG_FOUR		"4"
@ MSG_ARG_ALTEXEC64	"altexec64"
@ MSG_ARG_TARGET	"target="

@ MSG_LD_OPTIONS	"LD_OPTIONS"
@ MSG_LD_ALTEXEC	"LD_ALTEXEC="

@ MSG_SUNW_OST_SGS	"SUNW_OST_SGS"

@ MSG_TARG_SPARC	"sparc"
@ MSG_TARG_X86		"x86"

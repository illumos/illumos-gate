#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

@ _START_

# Message file for cmd/sgs/rtld (ld.so.1) - sparc specific.

@ MSG_REL_UNIMPL	"relocation error: file %s: symbol %s: \
			 unimplemented relocation type: %d"
@ MSG_REL_NONALIGN	"relocation error: %s: file %s: symbol %s: \
			 offset 0x%llx is non-aligned"
@ MSG_REL_UNNOBITS	"relocation error: %s: file %s: symbol %s: \
			 unsupported number of bits: %d"
@ MSG_REL_LOSEBITS	"relocation error: %s: file %s: symbol %s: \
			 value 0x%llx loses %d bits at offset 0x%llx"
@ MSG_REL_NOFIT		"relocation error: %s: file %s: symbol %s: \
			 value 0x%llx does not fit"
@ MSG_REL_NOSWAP	"relocation error: %s: file %s: symbol %s: \
			 linker does not support byte swapping relocated data"
@ MSG_REL_BADREG	"relocation error: file %s: REGISTER relocation \
			 against bad register offset: 0x%llx"

@ MSG_REG_SYMCONF	"register symbol conflict: %s: \
			 file %s symbol %s; file %s symbol %s"

@ MSG_LDD_REG_SYMCONF	"\tregister symbol conflict: %s\n\
			 \t\t(file %s symbol %s; file %s symbol %s)\n"

@ _END_

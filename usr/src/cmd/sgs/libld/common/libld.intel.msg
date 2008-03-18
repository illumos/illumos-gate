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

# Message file for cmd/sgs/libld - intel specific.

@ MSG_REL_BADTLSINS	"relocation error: %s: file %s: symbol %s: section %s: \
			 offset 0x%llx, relocation against unknown TLS \
			 instruction sequence"

@ MSG_PLT_PLT0FAIL	"creation of PLT entry plt0 failed"
@ MSG_PLT_PLTNFAIL	"creation of PLT[%d] for symbol `%s' failed"

@ MSG_UNW_BADCIEVERS	"unwind table: file %s: section %s: \
			 bad cie version %d: offset 0x%llx\n"

@ _END_

@ MSG_SYM_PLTENT	"<pltentry>"

@ MSG_SPECFIL_PLTENT    "<output_file>"

@ MSG_SCN_UNWINDHDR	".eh_frame_hdr"

@ MSG_PTH_RTLD_AMD64	"/usr/lib/amd64/ld.so.1"

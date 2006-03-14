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
#

@ _START_

# Messages to satisfy chkmsg target.  Numerous messages within common code
# (reloc.h) aren't required for each target, but chkmsg has no way of dealing
# with ifdefs, thus this file exists to satisfy common code messages.

@ MSG_REL_UNIMPL	"relocation error: file %s:  symbol %s: \
			 unimplemented relocation type: %d"
@ MSG_REL_UNNOBITS	"relocation error: %s: file %s: symbol %s: \
			 unsupported number of bits: %d"
@ MSG_REL_LOSEBITS	"relocation error: %s: file %s: symbol %s: \
			 value 0x%llx loses %d bits at offset 0x%llx"

@ _END_

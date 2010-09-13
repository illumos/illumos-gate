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

# Message file for cmd/sgs/ldprof

@ MSG_ID_LIBPROF


# System call messages.

@ MSG_SYS_OPEN		"%s: open failed: %s: profiling disabled\n"
@ MSG_SYS_MMAP		"%s: mmap failed: %s: profiling disabled\n"
@ MSG_SYS_FTRUNC	"%s: ftruncate failed: %s: profiling disabled\n"

# General error diagnostics
@ MSG_GEN_PROFSZCHG	"ldprof.so: %s: profile target has changed size; \
			 recreate profile buffer: profiling disabled\n"
@ MSG_GEN_AUDITVERSION	"ldprof.so: audit version mismatch: expected %d, \
			 found %d: profiling disabled\n"
@ MSG_GEN_PROFNOTSET	"ldprof.so: profile target must be specified with \
			 LD_PROFILE: profiling disabled\n"


@ _END_

# The following strings represent reserved words, files, pathnames and symbols.
# Reference to this strings is via the MSG_ORIG() macro, and thus no message
# translation is required.

@ MSG_SUNW_OST_SGS	"SUNW_OST_SGS"

@ MSG_FMT_PROFILE	"%s/%s%s"
@ MSG_FMT_PROCSELF	"/proc/self/status"
@ MSG_SUF_PROFILE	".profile"
@ MSG_SUF_PROFILE_64	".profilex"

@ MSG_PTH_VARTMP	"/var/tmp"

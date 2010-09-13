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

# Messages for cmd/sgs/libcrle

@ MSG_ID_LIBCRLE

# System error messages

@ MSG_SYS_OPEN		"%s: %s: open failed: %s\n"
@ MSG_SYS_READ		"%s: %s: read failed: %s\n"
@ MSG_SYS_MMAP		"%s: %s: mmap failed: %s\n"
@ MSG_SYS_ALLOC		"%s: memory allocation failed: %s\n"

# Runtime linker error messages

@ MSG_DL_OPEN		"%s: dlopen failed: %s\n"
@ MSG_DL_DUMP		"%s: dldump failed: %s\n"
@ MSG_DL_INFO		"%s: dlinfo failed: %s\n"

@ _END_


# The following strings represent reserved section and symbol names.  Reference
# to these strings is via the MSG_ORIG() macro, and thus no translations are
# required.

@ MSG_AUD_DEPEND	"__CRLE_DEP__:depend:%s\n"
@ MSG_AUD_FILTER	"__CRLE_DEP__:filter:%s:(%s):%s\n"
@ MSG_AUD_RESBGN	"__CRLE_DEP__:resbgn:%llu\n"
@ MSG_AUD_RESEND	"__CRLE_DEP__:resend:%llu\n"

@ MSG_ENV_AUD_FD	"CRLE_FD"
@ MSG_ENV_AUD_FLAGS	"CRLE_FLAGS"

@ MSG_FIL_LIBCRLE	"libcrle"

@ MSG_PTH_PROCRMAP	"/proc/self/rmap"
@ MSG_PTH_PROCSTATUS	"/proc/self/status"
@ MSG_PTH_DEVNULL	"/dev/null"

@ MSG_SUNW_OST_SGS	"SUNW_OST_SGS"

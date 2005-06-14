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
#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libaio/common/Makefile

LINTSRC32= lintsrc32
LINTOUT32= lint32.out
LINTLIB32= $(LIBNAME)32
$(LINTSRC32):= LINTFLAGS +=

LINTSRC64= lintsrc64
LINTOUT64= lint64.out
LINTLIB64= $(LIBNAME)64
$(LINTSRC64):= LINTFLAGS64 += -fd -Xtransition=yes

lints	:	$(LINTSRC32) $(LINTSRC64)

$(LINTSRC32):	$$(SRCS)
	$(LINT.c) -o  $(LINTLIB32) $(SRCS) > $(LINTOUT32) 2>&1

$(LINTSRC64):	$$(SRCS)
	$(LINT64.c) -o  $(LINTLIB64) $(SRCS) > $(LINTOUT64) 2>&1

include ../Makefile.com


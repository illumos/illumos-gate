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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#

MODULE = software-diagnosis
CLASS = common

include ../Makefile.com

#
# Sources for the primary software-diagnosis module
#
SWDE_SRCS = swde_main.c swde_case.c

#
# Sources for subsidiary diagnosis "modules" that we host.  These should
# be listed in ../Makefile.com
#
SUBDE_SRCS = $(SMF_DE_SRCS) $(PANIC_DE_SRCS)

#
# All sources for softtware-diagnosis
#
SRCS = $(SWDE_SRCS) $(CMN_SRCS:%=../%) $(SUBDE_SRCS:%=../%)

include ../../../Makefile.plugin

CFLAGS += $(INCS)
LINTFLAGS += $(INCS)
LDLIBS += -L$(ROOTLIB)/fm -ltopo -luutil -luuid -lkstat
LDFLAGS += -R/usr/lib/fm
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += $(CNOWARN_UNINIT)

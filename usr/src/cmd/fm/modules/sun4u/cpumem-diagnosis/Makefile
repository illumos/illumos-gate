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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"

MODULE = cpumem-diagnosis
CLASS = arch
ARCH = sun4u
SRCS = \
	cmd_bank.c \
	cmd_cpu.c \
	cmd_cpuerr.c \
	cmd_dimm.c \
	cmd_ecache.c \
	cmd_fmri.c \
	cmd_list.c \
	cmd_main.c \
	cmd_mem.c \
	cmd_memerr.c \
	cmd_page.c \
	cmd_pageerr.c \
	cmd_state.c \
	cmd_util.c

include ../../Makefile.plugin

CMD_VERSION = "1.4"

INCDIRS = \
	. \
	$(SRC)/uts/sun4 \
	$(SRC)/uts/sun4u \
	$(SRC)/uts/sparc/v9

CPPFLAGS += $(INCDIRS:%=-I%) -DCMD_VERSION='$(CMD_VERSION)'

LDFLAGS += -lkstat

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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

PROG = powertop

COMMON_OBJS = $(PROG).o \
	display.o \
	battery.o \
	cpufreq.o \
	cpuidle.o \
	events.o \
	util.o \
	suggestions.o \
	turbo.o

SRCS		= $(COMMON_OBJS:%.o=../common/%.c)

include ../../Makefile.cmd
.KEEP_STATE:

CFLAGS		+= $(CCVERBOSE)
CFLAGS64	+= $(CCVERBOSE)
CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-uninitialized

SMOFF += free

LDLIBS		+= -lcurses -ldtrace -lkstat

FILEMODE	= 0555

CLEANFILES	+= $(COMMON_OBJS)

all:	$(PROG)

clean:
	$(RM) $(CLEANFILES)

lint:	lint_SRCS

include ../../Makefile.targ

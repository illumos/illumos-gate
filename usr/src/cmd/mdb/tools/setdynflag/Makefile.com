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

.KEEP_STATE:

PROG = setdynflag

SRCS = \
	die.c \
	findscn.c \
	setdynflag.c
OBJS = $(SRCS:%.c=%.o)

include ../../../../Makefile.cmd
include ../../common/Makefile.util

#
# We're going to run this as part of the build, so we want it to use the
# running kernel's includes and libraries.
#
CPPFLAGS = -I../../common
CFLAGS += $(CCVERBOSE)
CERRWARN += $(CNOWARN_UNINIT)
LDFLAGS =
LDLIBS	= -lelf

LINTFILES = $(SRCS:%.c=%.ln)

install all: $(PROG)

clobber clean:
	$(RM) $(OBJS) $(LINTFILES) $(PROG)

lint: $(LINTFILES)
	$(LINT) $(LINTFLAGS) $(LINTFILES) $(LDLIBS)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

%.o: ../common/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

%.ln: ../common/%.c
	$(LINT.c) -c $<

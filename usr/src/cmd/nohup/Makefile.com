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
# cmd/nohup/Makefile.com
# 

XPG4PROG = nohup
PROG = nohup

OBJS = nohup.o
XPG4OBJS = $(OBJS:%.o=xpg4_%.o)
SRCS = $(OBJS:%.o=../%.c)
LNTS = $(OBJS:%.o=%.ln)
CLEANFILES = $(OBJS) $(XPG4OBJS) $(LNTS)

include ../../Makefile.cmd

CFLAGS += $(CCVERBOSE)
CFLAGS64 += $(CCVERBOSE)

$(XPG4) := CPPFLAGS += -DXPG4

# not needed for xpg4/nohup
EXTRALIBS = -lproc

TARGETS = $(PROG) $(XPG4)

.KEEP_STATE:

.PARALLEL: $(OBJS) $(XPG4OBJS) $(LNTS)

all: $(PROG) $(XPG4)

lint:
	$(LINT.c) $(SRCS) $(LDLIBS) $(EXTRALIBS)

clean:
	$(RM) $(CLEANFILES)

include ../../Makefile.targ

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS) $(EXTRALIBS)
	$(POST_PROCESS)

$(XPG4): $(XPG4OBJS)
	$(LINK.c) -o $@ $(XPG4OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o: ../%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

xpg4_%.o: ../%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

PROG =		cpustat
OBJS =		$(PROG).o caps.o time.o setgrp.o strtoset.o
SRCS =		$(OBJS:%.o=../common/%.c)

include ../../Makefile.cmd

STATCOMMONDIR = $(SRC)/cmd/stat/common

STAT_COMMON_OBJS = timestamp.o
STAT_COMMON_SRCS = $(STAT_COMMON_OBJS:%.o=$(STATCOMMONDIR)/%.c)
SRCS += $(STAT_COMMON_SRCS)

CFLAGS		+= $(CCVERBOSE) $(CTF_FLAGS)
CERRWARN	+= $(CNOWARN_UNINIT)
CPPFLAGS	+= -D_REENTRANT -I$(SRC)/lib/libcpc/common -I$(STATCOMMONDIR)
LDLIBS +=	-lcpc -lkstat

# not linted
SMATCH=off

.KEEP_STATE:

all:	$(PROG)

$(PROG): $(OBJS) $(STAT_COMMON_OBJS)
	$(LINK.c) $(OBJS) $(STAT_COMMON_OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)
	$(CTFMERGE) -L VERSION -o $@ $(OBJS) $(STAT_COMMON_OBJS)

install: all $(ROOTUSRSBINPROG)

clean:
	$(RM) $(OBJS) $(STAT_COMMON_OBJS)

lint:	lint_SRCS

strip: all
	$(STRIP) $(PROG)

%.o:	../common/%.c
	$(COMPILE.c) $<
	$(CTFCONVERT_O)

%.o:	$(STATCOMMONDIR)/%.c
	$(COMPILE.c) $<
	$(CTFCONVERT_O)

POFILES =	../common/$(PROG).po ../common/caps.po
POFILE =	$(PROG)_cmd.po

$(POFILE): $(POFILES)
	$(RM) $@
	cat $(POFILES) > $@

include ../../Makefile.targ

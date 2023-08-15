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
# cmd/pools/poolstat/Makefile

PROG =		poolstat
OBJS =		poolstat.o poolstat_utils.o sa_libpool.o sa_kstat.o
SRCS =		$(OBJS:%.o=%.c) $(COMMON_SRCS)
POFILES = 	$(OBJS:.o=.po)

include ../../Makefile.cmd
include ../Makefile.pools

STATCOMMONDIR = $(SRC)/cmd/stat/common

STAT_COMMON_OBJS = timestamp.o
STAT_COMMON_SRCS = $(STAT_COMMON_OBJS:%.o=$(STATCOMMONDIR)/%.c)
SRCS += $(STAT_COMMON_SRCS)

CFLAGS +=	-I$(POOLSCOMMONDIR) -I$(STATCOMMONDIR) $(EXTRA_CFLAGS)
sparc_COPTFLAG=
LDLIBS +=	-lpool -lkstat
XGETFLAGS =	-a
CLOBBERFILES += $(POFILES)

lint := LINTFLAGS += -I$(POOLSCOMMONDIR) -I$(STATCOMMONDIR)

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS) $(COMMON_OBJS) $(STAT_COMMON_OBJS)
	$(LINK.c) -o $@ $(OBJS) $(COMMON_OBJS) $(STAT_COMMON_OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o : $(POOLSCOMMONDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.o : $(STATCOMMONDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

install: all $(ROOTPROG)

clean:
	$(RM) $(OBJS) $(COMMON_OBJS) $(STAT_COMMON_OBJS) $(POFILES)

lint: lint_SRCS

include ../../Makefile.targ

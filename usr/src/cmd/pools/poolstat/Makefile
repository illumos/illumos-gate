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
# Copyright 2025 Hans Rosenfeld
#
# cmd/pools/poolstat/Makefile

PROG =		poolstat
OBJS =		poolstat.o poolstat_utils.o sa_libpool.o sa_kstat.o
SRCS =		$(OBJS:%.o=%.c) $(COMMON_SRCS)
POFILES =	$(OBJS:.o=.po)

CLEANFILES =	$(OBJS)

include ../../Makefile.cmd
include $(SRC)/cmd/stat/Makefile.stat
include ../Makefile.pools

OBJS += $(COMMON_OBJS)

CFLAGS +=	-I$(POOLSCOMMONDIR) $(EXTRA_CFLAGS)
LDLIBS +=	-lpool -lkstat
XGETFLAGS =	-a
CLOBBERFILES += $(POFILES)

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o : $(POOLSCOMMONDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

install: all $(ROOTPROG)

clean:
	$(RM) $(CLEANFILES)

include ../../Makefile.targ

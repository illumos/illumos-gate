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

PROG= ctstat
OBJS = ctstat.o
SRCS = $(OBJS:%.o=%.c)

include ../Makefile.cmd

STATCOMMONDIR = $(SRC)/cmd/stat/common

STAT_COMMON_OBJS = timestamp.o
STAT_COMMON_SRCS = $(STAT_COMMON_OBJS:%.o=$(STATCOMMONDIR)/%.c)
SRCS += $(STAT_COMMON_SRCS)

CPPFLAGS += -I$(STATCOMMONDIR)
CFLAGS += $(CCVERBOSE)
CERRWARN += -_gcc=-Wno-parentheses
LDLIBS += -lcontract -luutil

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS) $(STAT_COMMON_OBJS)
	$(LINK.c) -o $(PROG) $(OBJS) $(STAT_COMMON_OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o : $(STATCOMMONDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

install: all $(ROOTPROG)

clean:
	$(RM) $(OBJS) $(STAT_COMMON_OBJS)

lint:	lint_SRCS

include ../Makefile.targ

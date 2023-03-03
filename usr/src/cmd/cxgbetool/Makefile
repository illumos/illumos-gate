#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright (c) 2019 by Chelsio Communications, Inc.
#
# Copyright (c) 2018, Joyent, Inc.

PROG =  cxgbetool
OBJS =	cxgbetool.o cudbg.o cudbg_view.o fastlz_api.o fastlz.o cudbg_common.o
SRCS =	$(OBJS:%.o=%.c)
VPATH = $(SRC)/uts/common/io/cxgbe/t4nex/

include ../Makefile.cmd

CFLAGS += $(CCVERBOSE) -I$(SRC)/uts/common/io/cxgbe/t4nex -I$(SRC)/uts/common/io/cxgbe/firmware \
	  -I$(SRC)/uts/common/io/cxgbe/common

LDLIBS += -ldevinfo
SMOFF += all_func_returns

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG)

clean:

lint: lint_PROG

include ../Makefile.targ

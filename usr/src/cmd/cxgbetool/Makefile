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
# Copyright (c) 2018 by Chelsio Communications, Inc.
#
PROG =  cxgbetool

include ../Makefile.cmd

CFLAGS += $(CCVERBOSE) -I$(SRC)/uts/common/io/cxgbe/t4nex -I$(SRC)/uts/common/io/cxgbe/firmware

all: $(PROG)

install: all $(ROOTUSRSBINPROG)

clean:

lint: lint_PROG

include ../Makefile.targ

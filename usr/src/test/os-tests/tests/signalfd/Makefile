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
# Copyright 2022 Oxide Computer Company
# Copyright 2023 MNX Cloud, Inc.
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

PROGS = basic_args basic_read multipoll
COMMON_OBJS = common.o

poll_test := LDLIBS += -lsocket
poll_test.ln := LDLIBS += -lsocket
CSTD = $(CSTD_GNU99)

ROOTOPTDIR = $(ROOT)/opt/os-tests/tests
ROOTOPTSIGFD = $(ROOTOPTDIR)/signalfd

CMDS = $(PROGS:%=$(ROOTOPTSIGFD)/%)
$(CMDS) := FILEMODE = 0555

all: $(PROGS)

install: all $(CMDS)

clobber: clean
	-$(RM) $(PROGS)

clean:
	-$(RM) $(COMMON_OBJS)

$(CMDS): $(ROOTOPTSIGFD) $(PROGS)

$(PROGS): $(COMMON_OBJS)

$(ROOTOPTSIGFD):
	$(INS.dir)

$(ROOTOPTSIGFD)/%: %
	$(INS.file)

%.o: %.c
	$(COMPILE.c) -o $@ -c $<
	$(POST_PROCESS_O)

%: %.o
	$(LINK.c) -o $@ $< $(COMMON_OBJS) $(LDLIBS)
	$(POST_PROCESS)

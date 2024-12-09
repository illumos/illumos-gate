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
# Copyright 2019, Joyent, Inc.
# Copyright 2024 Oxide Computer Company
#

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/os-tests
TESTDIR = $(ROOTOPTPKG)/tests/uccid

PROGS =		\
	atrparse	\
	excl-basic	\
	excl-badread	\
	excl-close	\
	excl-loop	\
	excl-nonblock	\
	excl-reset	\
	modify		\
	notxn-poll	\
	status		\
	pollin		\
	pollout		\
	txn-pollerr	\
	yk		\
	yk-poll		\
	yk-readonly

COMMON_OBJS = \
	atr.o		\
	hexdump.o	\
	ilstr.o

atrparse := EXTRA_OBJS = $(COMMON_OBJS)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

CMDS = $(PROGS:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

CPPFLAGS += -D_REENTRANT -I$(SRC)/common/ccid/

hexdump.o := CSTD = $(CSTD_GNU99)

all: $(PROGS)

install: all $(CMDS)

clobber: clean
	-$(RM) $(PROGS)

clean:
	-$(RM) *.o

$(PROGS): $(COMMON_OBJS)

$(CMDS): $(TESTDIR) $(PROGS)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

%.o: $(SRC)/common/ccid/%.c
	$(COMPILE.c) -o $@ -c $<
	$(POST_PROCESS_O)

%.o: $(SRC)/common/ilstr/%.c
	$(COMPILE.c) -o $@ -c $<
	$(POST_PROCESS_O)

%.o: $(SRC)/common/hexdump/%.c
	$(COMPILE.c) -o $@ -c $<
	$(POST_PROCESS_O)

%.o: %.c
	$(COMPILE.c) -o $@ -c $<
	$(POST_PROCESS_O)

%: %.o
	$(LINK.c) -o $@ $< $(EXTRA_OBJS) $(LDLIBS)
	$(POST_PROCESS)

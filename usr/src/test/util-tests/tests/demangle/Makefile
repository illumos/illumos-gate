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
# Copyright 2018 Jason King.
# Copyright 2019 Joyent, Inc.
#

include $(SRC)/Makefile.master
include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

ROOTBINDIR = $(ROOTOPTPKG)/bin

PROG = gcc-libstdc++ llvm-stdcxxabi afl-fast rust

ROOTOPTPKG = $(ROOT)/opt/util-tests
TESTDIR = $(ROOTOPTPKG)/tests/demangle

CMDS = $(PROG:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

OBJS = $(PROG:%=%.o)
SRCS = $(OBJS:%.o=%.c)

CSTD = $(CSTD_GNU99)

LDLIBS += -ldemangle-sys
rust := LDLIBS += -lumem

all: $(PROG)

gcc-libstdc++: gcc-libstdc++.o
	$(LINK.c) -o $@ gcc-libstdc++.o $(LDLIBS)
	$(POST_PROCESS)

llvm-stdcxxabi: llvm-stdcxxabi.o
	$(LINK.c) -o $@ llvm-stdcxxabi.o $(LDLIBS)
	$(POST_PROCESS)

afl-fast: afl-fast.o
	$(LINK.c) -o $@ afl-fast.o $(LDLIBS)
	$(POST_PROCESS)

rust: rust.o
	$(LINK.c) -o $@ rust.o $(LDLIBS)
	$(POST_PROCESS)

install: all $(CMDS)

lint:

clobber: clean
	-$(RM) $(PROG)

clean:
	-$(RM) $(OBJS)

$(CMDS): $(TESTDIR) $(PROG)

$(ROOTBINDIR):
	$(INS.dir)

$(ROOTBINDIR)/%: %
	$(INS.file)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

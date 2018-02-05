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
# Copyright (c) 2016 by Delphix. All rights reserved.
#

include $(SRC)/cmd/Makefile.cmd

ROOTOPTPKG = $(ROOT)/opt/zfs-tests
TESTDIR = $(ROOTOPTPKG)/tests/functional/channel_program/lua_core

KSHFILES :sh= ls *.ksh
KSHPROGS = $(KSHFILES:%.ksh=%)
SRCS :sh= ls *.c
CPROGS = $(SRCS:%.c=%.exe)
PROGS = $(KSHPROGS) $(CPROGS)
FILES :sh= ls *.zcp *.out *.err
LDLIBS =	$(LDLIBS.cmd)
LDLIBS += -lzfs_core -lnvpair
CSTD = $(CSTD_GNU99)

INSTPROGS = $(PROGS:%=$(TESTDIR)/%)
INSTFILES = $(FILES:%=$(TESTDIR)/%)

OBJS = $(SRCS:%.c=%.o)

$(INSTPROGS) := FILEMODE = 0555
$(INSTFILES) := FILEMODE = 0444

all lint: $(CPROGS)
	echo SRCS: $(SRCS)
	echo PROGS: $(PROGS)

install: $(INSTPROGS) $(INSTFILES)

$(INSTPROGS): $(TESTDIR)
$(INSTFILES): $(TESTDIR)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %.ksh
	$(INS.rename)

$(TESTDIR)/%: %
	$(INS.file)

%.o: ../%.c
	$(COMPILE.c) $<

%.exe: %.o
	$(LINK.c) $< -o $@ $(LDLIBS)
	$(POST_PROCESS)

clobber: clean
	-$(RM) $(PROGS)

clean:
	-$(RM) $(OBJS)

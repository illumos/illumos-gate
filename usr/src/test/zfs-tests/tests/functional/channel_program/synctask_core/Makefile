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
# Copyright 2020 Joyent, Inc.
#

include $(SRC)/Makefile.master
include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.ctf

ROOTOPTPKG = $(ROOT)/opt/zfs-tests
TESTDIR = $(ROOTOPTPKG)/tests/functional/channel_program/synctask_core

KSHFILES :sh= ls *.ksh
KSHPROGS = $(KSHFILES:.ksh=)

SRCS :sh= ls *.c
CPROGS = $(SRCS:%.c=%.exe)
LDLIBS = $(LDLIBS.cmd)
LDLIBS += -lzfs_core -lnvpair
CSTD = $(CSTD_GNU99)
OBJS = $(SRCS:%.c=%.o)

PROGS = $(KSHPROGS) $(CPROGS)
FILES :sh= ls *.zcp *.out *.err 2>/dev/null; true

INSTPROGS = $(PROGS:%=$(TESTDIR)/%)
INSTFILES = $(FILES:%=$(TESTDIR)/%)

$(INSTPROGS) := FILEMODE = 0555
$(INSTFILES) := FILEMODE = 0444

all: $(CPROGS)

clean clobber:

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

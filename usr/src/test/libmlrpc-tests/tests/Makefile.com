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
# Copyright (c) 2012 by Delphix. All rights reserved.
# Copyright 2014 Garrett D'Amore <garrett@damore.org>
# Copyright 2020 Tintri by DDN, Inc. All rights reserved.
#

include $(SRC)/Makefile.master
include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

#
# Note: NDR currently is only supported in 32-bit programs.
#
OBJS = $(PROG).o util_common.o
SRCS = $(PROG).c $(TESTCOMMONDIR)/util_common.c

CSTD = $(CSTD_GNU99)
CPPFLAGS += -I$(TESTCOMMONDIR)

ROOTOPTPKG = $(ROOT)/opt/libmlrpc-tests
TESTDIR = $(ROOTOPTPKG)/tests/$(TESTSUBDIR)

CMDS = $(PROG:%=$(TESTDIR)/%) $(KSHPROG:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

BINS = $(BINFILES:%=$(TESTDIR)/%)
$(BINS) := FILEMODE = 0444

all: $(PROG) $(KSHPROG) $(SUBDIRS)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(KSHPROG): $(KSHPROG).ksh
	$(RM) $@
	$(CP) $(KSHPROG).ksh $(@)
	$(CHMOD) +x $@

%.o: %.c
	$(COMPILE.c) -o $@ $(CFLAGS_$(MACH)) $<

%.o: $(TESTCOMMONDIR)/%.c
	$(COMPILE.c) -o $@ $(CFLAGS_$(MACH)) $<

install: $(SUBDIRS) $(CMDS) $(BINS)

lint: lint_SRCS

clobber: clean
	-$(RM) $(PROG) $(KSHPROG)

clean:
	-$(RM) $(OBJS)

$(CMDS): $(TESTDIR) $(PROG) $(KSHPROG)

$(BINS): $(TESTDIR)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

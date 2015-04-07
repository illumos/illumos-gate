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
#

include $(SRC)/Makefile.master
include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

$(OBJS_OVERRIDE)OBJS = $(PROG).o test_common.o
OBJS32 = $(OBJS:%.o=%.$(MACH).o)
PROG32 = $(PROG).$(MACH)

$(BUILD64) OBJS64 = $(OBJS:%.o=%.$(MACH64).o)
$(BUILD64) PROG64= $(PROG).$(MACH64)

$(OBJS_OVERRIDE)SRCS = $(PROG).c ../common/test_common.c

C99MODE = -xc99=%all
LINTFLAGS += -I../common -DARCH=\"ARCH\" -DLINT
CPPFLAGS += -I$(ROOT)/usr/include -I../common

ROOTOPTPKG = $(ROOT)/opt/libc-tests
TESTDIR = $(ROOTOPTPKG)/tests/$(TESTSUBDIR)

CMDS = $(PROG32:%=$(TESTDIR)/%) $(PROG64:%=$(TESTDIR)/%) \
	$(KSHPROG:%=$(TESTDIR)/%) $(ARCHPROG:%=$(TESTDIR)/%) \
	$(EXTRAPROG:%=$(TESTDIR)/%)

$(CMDS) := FILEMODE = 0555

all: $(PROG32) $(PROG64) $(KSHPROG) $(ARCHPROG) $(SUBDIRS)

$(PROG32): $(OBJS32)
	$(LINK.c) $(OBJS32) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(PROG64): $(OBJS64)
	$(LINK64.c) $(OBJS64) -o $@ $(LDLIBS64)
	$(POST_PROCESS)

$(KSHPROG): $(KSHPROG).ksh
	$(RM) $@
	$(CP) $(KSHPROG).ksh $(@)
	$(CHMOD) +x $@

$(ARCHPROG): ../common/run_arch_tests.ksh
	$(RM) $@
	$(CP) ../common/run_arch_tests.ksh $(@)
	$(CHMOD) +x $@

%.$(MACH).o: %.c
	$(COMPILE.c) -o $@ $(CFLAGS_$(MACH)) -DARCH=\"$(MACH)\" $<

%.$(MACH).o: ../common/%.c
	$(COMPILE.c) -o $@ $(CFLAGS_$(MACH)) -DARCH=\"$(MACH)\" $<

%.$(MACH64).o: %.c
	$(COMPILE64.c) -o $@ $(CFLAGS_$(MACH64)) -DARCH=\"$(MACH64)\" $<

%.$(MACH64).o: ../common/%.c
	$(COMPILE64.c) -o $@ $(CFLAGS_$(MACH64)) -DARCH=\"$(MACH64)\" $<

install: $(SUBDIRS) $(CMDS)

lint: lint_SRCS

clobber: clean
	-$(RM) $(PROG32) $(PROG64) $(KSHPROG) $(ARCHPROG)

clean:
	-$(RM) $(OBJS32) $(OBJS64)

$(CMDS): $(TESTDIR) $(PROG32) $(PROG64) $(KSHPROG) $(ARCHPROG)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

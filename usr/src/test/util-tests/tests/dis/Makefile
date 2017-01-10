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
# Copyright 2016 Joyent, Inc.
#

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/util-tests
TESTDIR = $(ROOTOPTPKG)/tests/dis
ARCHS = i386 sparc

PROG = distest

SPARC_TESTS = \
	tst.regs

I386_TESTS =		\
	32.adx 		\
	32.aes 		\
	32.bmi1 	\
	32.bmi2 	\
	32.fma-pd 	\
	32.fma-ps 	\
	32.fma-sd 	\
	32.fma-ss 	\
	32.lzcnt 	\
	32.popcnt 	\
	32.sse-4.2 	\
	32.ssse3 	\
	32.xsave 	\
	64.adx 		\
	64.aes 		\
	64.bmi1 	\
	64.bmi2 	\
	64.ept 		\
	64.fma-pd 	\
	64.fma-ps 	\
	64.fma-sd 	\
	64.fma-ss 	\
	64.lzcnt 	\
	64.popcnt 	\
	64.random 	\
	64.sse-4.2 	\
	64.ssse3 	\
	64.vmx 		\
	64.xsave 	\
	tst.mwait 	\
	tst.random	\
	tst.smap	\
	tst.vmx

I386_FILES = $(I386_TESTS:%=%.s) $(I386_TESTS:%=%.out)
ROOTI386 = $(I386_FILES:%=$(TESTDIR)/i386/%)

SPARC_FILES = $(SPARC_TESTS:%=%.s) $(SPARC_TESTS:%=%.out)
ROOTSPARC = $(SPARC_FILES:%=$(TESTDIR)/sparc/%)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

ARCHDIRS = $(ARCHS:%=$(TESTDIR)/%)
CMDS = $(PROG:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

install: $(CMDS) $(ROOTI386) $(ROOTSPARC)

lint:

clobber: clean

clean:

$(CMDS) $(ROOTI386) $(ROOTSPARC): $(TESTDIR) $(ARCHDIRS)

$(TESTDIR) $(ARCHDIRS):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

$(TESTDIR)/%: %.ksh
	$(INS.rename)

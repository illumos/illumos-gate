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
# Copyright 2018 Joyent, Inc.
#

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/util-tests
TESTDIR = $(ROOTOPTPKG)/tests/dis
ARCHS = i386 risc-v risc-v-c sparc

PROG = distest

I386_FILES :sh= (cd i386; print *)
RISCV_FILES :sh= (cd risc-v; print *)
RISCV_C_FILES :sh= (cd risc-v-c; print *)
SPARC_FILES :sh= (cd sparc; print *)

ROOTFILES = \
	$(I386_FILES:%=$(TESTDIR)/i386/%)		\
	$(RISCV_FILES:%=$(TESTDIR)/risc-v/%)		\
	$(RISCV_C_FILES:%=$(TESTDIR)/risc-v-c/%)	\
	$(SPARC_FILES:%=$(TESTDIR)/sparc/%)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

ARCHDIRS = $(ARCHS:%=$(TESTDIR)/%)
CMDS = $(PROG:%=$(TESTDIR)/%)
FILEMODE=0444
$(CMDS) := FILEMODE = 0555

install: $(CMDS) $(ROOTFILES)

lint:

clobber: clean

clean:

$(CMDS) $(ROOTFILES): $(TESTDIR) $(ARCHDIRS)

$(TESTDIR) $(ARCHDIRS):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

$(TESTDIR)/%: %.ksh
	$(INS.rename)

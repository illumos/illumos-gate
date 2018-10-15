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

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

DATA_FILES =		\
	test.countries	\
	test.data

BUGS_AWK :sh= (cd bugs-fixed; print *.awk)
BUGS_FILES = $(BUGS_AWK) $(BUGS_AWK:%.awk=%.ok)

EXAMPLES_FILES :sh= (cd examples/awk; print p.* t.*)

TESTS_FILES :sh= (cd tests; print T.* chem.awk latin1 lilly.progs lsd1.p penicil.p res.p)

GNU_AWK :sh= (cd gnu; print *.awk)
GNU_KSH :sh= (cd gnu; print *.sh)
GNU_IN :sh= (cd gnu; print *.in)

#
# For the imported gnu/ tests, we have three different styles:
#
#   - AWK scripts with input
#   - AWK scripts with no input
#   - Shell scripts that run AWK scripts themselves
#
# All of these have a corresponding *.ok file, and we generate a *.awk
# dependency from each *.in file to check for bad test setups.
#
GNU_FILES =	\
	$(GNU_AWK) $(GNU_AWK:%.awk=%.ok) \
	$(GNU_KSH) $(GNU_KSH:%.sh=%.ok) \
	$(GNU_IN) $(GNU_KSH:%.in=%.awk) \
	arynocls.data out1.ok out2.ok out3.ok # arynocls.awk & messages.sh data

SYN_FILES :sh= (cd syn; print *.awk)

ROOTFILES =					\
	$(BUGS_FILES:%=$(TESTDIR)/bugs-fixed/%)	\
	$(DATA_FILES:%=$(TESTDIR)/data/%)	\
	$(EXAMPLES_FILES:%=$(TESTDIR)/examples/awk/%) \
	$(EXAMPLES_FILES:%=$(TESTDIR)/examples/out/%) \
	$(TESTS_FILES:%=$(TESTDIR)/tests/%)	\
	$(GNU_FILES:%=$(TESTDIR)/gnu/%)	\
	$(SYN_FILES:%=$(TESTDIR)/syn/%) \
	$(SYN_FILES:%.awk=$(TESTDIR)/syn/%.ok) \
	$(TESTDIR)/runtests.sh

SUBDIRS = bugs-fixed data examples/awk examples/out gnu syn tests

ROOTOPTPKG = $(ROOT)/opt/util-tests
TESTDIR = $(ROOTOPTPKG)/tests/awk
TESTSUBDIRS = $(SUBDIRS:%=$(TESTDIR)/%)

all lint clean clobber:

install: all $(ROOTFILES)

$(TESTDIR):
	$(INS.dir)

$(TESTSUBDIRS): $(TESTDIR)
	$(INS.dir)

$(TESTDIR)/%: % $(TESTSUBDIRS)
	$(INS.file)

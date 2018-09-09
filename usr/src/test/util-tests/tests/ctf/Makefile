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
# Copyright (c) 2019, Joyent, Inc.
#

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/util-tests
TESTDIR = $(ROOTOPTPKG)/tests/ctf

SCRIPTS =	ctftest.ksh

TESTS =		test-float.c \
		test-reference.c \
		test-int.c \
		test-array.c \
		test-enum.c \
		test-forward.c \
		test-sou.c \
		test-function.c \
		test-merge-static/Makefile.ctftest \
		test-merge-static/test-a.c \
		test-merge-static/test-b.c \
		test-merge-static/test-c.c \
		test-merge-static/test-d.c \
		test-merge-static/test-main.c \
		test-merge-forward/Makefile.ctftest \
		test-merge-forward/test-impl.c \
		test-merge-forward/test-merge.c \
		test-merge-dedup/Makefile.ctftest \
		test-merge-dedup/test-merge-1.c \
		test-merge-dedup/test-merge-2.c \
		test-merge-dedup/test-merge-3.c \
		test-merge-dedup/test-merge-dedup.c \
		test-merge-reduction/Makefile.ctftest \
		test-merge-reduction/mapfile-vers \
		test-merge-reduction/test-global.c \
		test-merge-reduction/test-scoped.c \
		test-merge-weak/Makefile.ctftest \
		test-merge-weak/test-merge-weak.c \
		test-weak.c \
		Makefile.ctftest.com

MAKEDIRS =	test-merge-static \
		test-merge-forward \
		test-merge-dedup \
		test-merge-reduction \
		test-merge-weak

CHECKS =	check-float-32 \
		check-float-64 \
		check-int-32 \
		check-int-64 \
		check-reference \
		check-array \
		check-enum \
		check-sou-32 \
		check-sou-64 \
		check-forward-32 \
		check-forward-64 \
		check-function \
		check-merge-static \
		check-merge-forward-32 \
		check-merge-forward-64 \
		check-merge-dedup \
		check-merge-reduction \
		check-merge-weak \
		check-weak

COMMON_OBJS =	check-common.o
ALL_OBJS =	$(CHECKS:%=%.o) $(CHECKS:%-32=%.32.o) $(CHECKS:%-64=%.64.o) $(COMMON_OBJS)

ROOTTESTS =	$(TESTS:%=$(TESTDIR)/%)
ROOTMAKEDIRS =	$(MAKEDIRS:%=$(TESTDIR)/%)
ROOTCHECKS =	$(CHECKS:%=$(TESTDIR)/%)
ROOTSCRIPTS =	$(SCRIPTS:%.ksh=$(TESTDIR)/%)

ROOTTESTS	:= FILEMODE =	0444
ROOTCHECKS	:= FILEMODE =	0555
ROOTSCRIPTS	:= FILEMODE =	0555

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

LDLIBS +=	-lctf

check-merge-static :=	LDLIBS += -lelf

all: $(CHECKS)

install: all $(ROOTTESTS) $(ROOTCHECKS) $(ROOTSCRIPTS)

$(CHECKS): $(COMMON_OBJS)

clean:
	$(RM) $(ALL_OBJS)

clobber: clean
	$(RM) $(CHECKS)

$(ROOTTESTS): $(TESTDIR) $(ROOTMAKEDIRS) $(TESTS)
$(ROOTCHECKS): $(TESTDIR) $(CHECKS)
$(ROOTSCRIPTS): $(TESTDIR) $(SCRIPTS)

$(TESTDIR):
	$(INS.dir)

$(ROOTMAKEDIRS):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

$(TESTDIR)/%: %.ksh
	$(INS.rename)

%.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.32.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.64.o: %.c
	$(COMPILE.c) -DTARGET_LP64 -o $@ $<
	$(POST_PROCESS_O)

%-32: %.32.o
	$(LINK.c) -o $@ $< $(COMMON_OBJS) $(LDLIBS)
	$(POST_PROCESS)

%-64: %.64.o
	$(LINK.c) -o $@ $< $(COMMON_OBJS) $(LDLIBS)
	$(POST_PROCESS)

%: %.o
	$(LINK.c) -o $@ $< $(COMMON_OBJS) $(LDLIBS)
	$(POST_PROCESS)

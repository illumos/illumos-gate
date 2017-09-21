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
# Copyright (c) 2017, Joyent, Inc.
#

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/util-tests
TESTDIR = $(ROOTOPTPKG)/tests/libsff

DIFF_PROGS = \
	libsff_8472 \
	libsff_8636_diag \
	libsff_8636_extspec \
	libsff_8636_tech \
	libsff_8636_temp \
	libsff_br \
	libsff_conn \
	libsff_compliance \
	libsff_enc \
	libsff_ident \
	libsff_lengths \
	libsff_opts \
	libsff_wave

ERR_PROGS = \
	libsff_efault \
	libsff_einval

PROGS = $(DIFF_PROGS) \
	$(ERR_PROGS) \
	libsff_strings

SCRIPTS = libsff

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

CMDS = $(PROGS:%=$(TESTDIR)/%) $(SCRIPTS:%=$(TESTDIR)/%)
OUTFILES = $(DIFF_PROGS:%=$(TESTDIR)/%.out)
$(CMDS) := FILEMODE = 0555
$(OUTFILES) := FILEMODE = 0444

CPPFLAGS += -I$(SRC)/lib/libsff/common

#
# Different tests require different sets of libraries. If we try and use
# the same set, we'll get guidance errors from ld.
#
$(ERR_PROGS)	:= LDLIBS += -lsff
$(DIFF_PROGS)	:= LDLIBS += -lsff -lnvpair
libsff_strings	:= LDLIBS += -lsff -lnvpair

all: $(PROGS)

install: all $(CMDS) $(OUTFILES)

lint: lint_SRCS

clobber: clean
	-$(RM) $(PROGS)

clean:

$(CMDS): $(TESTDIR) $(PROG)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

$(TESTDIR)/%: %.ksh
	$(INS.rename)

%: %.c
	$(LINK.c) -o $@ $< $(LDLIBS)
	$(POST_PROCESS)

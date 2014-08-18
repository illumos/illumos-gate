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
# Copyright (c) 2014 Joyent, Inc. All rights reserved.
#

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/util-tests
TESTDIR = $(ROOTOPTPKG)/tests/libnvpair_json
ROOTBINDIR = $(ROOTOPTPKG)/bin

PROG = print_json

SCRIPTS = \
	json_00_blank \
	json_01_boolean \
	json_02_numbers \
	json_03_empty_arrays \
	json_04_number_arrays \
	json_05_strings \
	json_06_nested \
	json_07_nested_arrays \
	json_common

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

OBJS = $(PROG:%=%.o)
SRCS = $(OBJS:%.o=%.c)

CMDS = $(PROG:%=$(ROOTBINDIR)/%) $(SCRIPTS:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

LDLIBS += -lnvpair

LINTFLAGS += -erroff=E_FUNC_ARG_UNUSED

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: all $(CMDS)

lint: lint_SRCS

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

$(TESTDIR)/%: %.ksh
	$(INS.rename)

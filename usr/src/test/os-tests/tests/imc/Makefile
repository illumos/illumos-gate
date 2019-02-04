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
# Copyright 2019 Joyent, Inc.
#

ROOTOPTPKG = $(ROOT)/opt/os-tests
TESTDIR = $(ROOTOPTPKG)/tests

#
# Test objects
#
OBJS =	imc_test.o \
	imc_test_basic.o \
	imc_test_badaddr.o \
	imc_test_fail.o \
	imc_test_rir.o \
	imc_test_sad.o \
	imc_test_skx_loop.o \
	imc_test_tad.o

#
# Common objects that we need.
#
OBJS += imc_decode.o

PROG = imc_test

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com
include $(SRC)/cmd/Makefile.ctf

CPPFLAGS += -I$(SRC)/uts/i86pc/io/imc

CMDS = $(PROG:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

all: $(PROG)

install: all $(CMDS)

clobber: clean
	-$(RM) $(PROG)

clean:
	-$(RM) *.o

$(CMDS): $(TESTDIR) $(PROG)

$(TESTDIR)/%: %
	$(INS.file)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o: %.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

%.o: $(SRC)/common/mc/imc/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

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
# Copyright 2023 Oxide Computer Company
#

ROOTOPTPKG = $(ROOT)/opt/os-tests
TESTDIR = $(ROOTOPTPKG)/tests

#
# Test objects
#
OBJS =	zen_umc_test.o \
	zen_umc_fabric_ids.o \
	zen_umc_test_basic.o \
	zen_umc_test_chans.o \
	zen_umc_test_cod.o \
	zen_umc_test_errors.o \
	zen_umc_test_hole.o \
	zen_umc_test_ilv.o \
	zen_umc_test_multi.o \
	zen_umc_test_nps.o \
	zen_umc_test_remap.o

#
# Common objects that we need.
#
OBJS += zen_fabric_utils.o zen_umc_decode.o bitext.o

PROG = zen_umc_test

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com
include $(SRC)/cmd/Makefile.ctf

CSTD = $(CSTD_GNU99)
#
# Ensure we always build with asserts. The first -I gives us access to
# the zen_umc.h pieces while the second gives us the registers that are
# required (dependency of the zen_umc.h header).
#
CPPFLAGS += -DDEBUG
CPPFLAGS += -I$(SRC)/uts/intel/io/amdzen
CPPFLAGS += -I$(SRC)/uts/intel/

CMDS = $(PROG:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

all: $(PROG)

install: all $(CMDS)

clobber: clean
	-$(RM) $(PROG)

clean:
	-$(RM) *.o

$(CMDS): $(TESTDIR) $(PROG)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o: %.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

%.o: $(SRC)/common/bitext/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

%.o: $(SRC)/common/mc/zen_umc/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

%.o: $(SRC)/common/amdzen/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

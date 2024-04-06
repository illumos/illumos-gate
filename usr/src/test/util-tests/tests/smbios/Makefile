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
# Copyright (c) 2018, Joyent, Inc.
# Copyright 2024 Oxide Computer Company
#

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/util-tests
TESTDIR = $(ROOTOPTPKG)/tests/

OBJS =	smbios.o \
	smbios_test_addinfo.o \
	smbios_test_chassis.o \
	smbios_test_errors.o \
	smbios_test_extmemdevice.o \
	smbios_test_fwinfo.o \
	smbios_test_memdevice.o \
	smbios_test_proc.o \
	smbios_test_pinfo.o \
	smbios_test_slot.o \
	smbios_test_strings.o \
	smbios_test_strprop.o
PROGS = smbios

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

CMDS = $(PROGS:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555
CSTD = $(GNU_C99)

#
# Since this program uses quite a number of variables declared on the
# stack that are then written to by libsmbios, we opt to pay the cost
# of always have the stack protector on every function as an additional
# means of checking ourselves.
#
STACKPROTECT = all

LDLIBS += -lsmbios -lumem
CFLAGS += -_gcc=-Wall -_gcc=-Wextra -_gcc=-Wno-unknown-pragmas

all: $(PROGS)

install: all $(CMDS)

clobber: clean
	-$(RM) $(PROGS)

clean:
	-$(RM) $(OBJS)

$(CMDS): $(TESTDIR) $(PROGS)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

$(PROGS): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

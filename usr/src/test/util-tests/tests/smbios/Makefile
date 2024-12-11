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
# Copyright 2025 Oxide Computer Company
#

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/util-tests
TESTDIR = $(ROOTOPTPKG)/tests/

SRCS =	smbios.c \
	smbios_test_addinfo.c \
	smbios_test_chassis.c \
	smbios_test_errors.c \
	smbios_test_extmemdevice.c \
	smbios_test_fwinfo.c \
	smbios_test_memdevice.c \
	smbios_test_mgmtdev.c \
	smbios_test_proc.c \
	smbios_test_pinfo.c \
	smbios_test_slot.c \
	smbios_test_strings.c \
	smbios_test_strprop.c \
	smbios_test_tpm.c
PROGS = smbios

PROGS32 = $(PROGS:%=%.32)
PROGS64 = $(PROGS:%=%.64)

OBJS32 = $(SRCS:%.c=%.32.o)
OBJS64 = $(SRCS:%.c=%.64.o)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.ctf
include $(SRC)/test/Makefile.com

CMDS = $(PROGS32:%=$(TESTDIR)/%) $(PROGS64:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555
CSTD = $(CSTD_GNU17)
CTF_MODE = link

#
# Since this program uses quite a number of variables declared on the
# stack that are then written to by libsmbios, we opt to pay the cost
# of always have the stack protector on every function as an additional
# means of checking ourselves.
#
STACKPROTECT = all

LDLIBS += -lsmbios -lumem
LDLIBS64 += -lsmbios -lumem
CFLAGS += -_gcc=-Wall -_gcc=-Wextra
CFLAGS64 += -_gcc=-Wall -_gcc=-Wextra

all: $(PROGS32) $(PROGS64)

install: all $(CMDS)

clobber: clean
	-$(RM) $(PROGS32) $(PROGS64)

clean:
	-$(RM) $(OBJS32) $(OBJS64)

$(CMDS): $(TESTDIR) $(PROGS32) $(PROGS64)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

%.32.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.64.o: %.c
	$(COMPILE64.c) -o $@ $<
	$(POST_PROCESS_O)


$(PROGS32): $(OBJS32)
	$(LINK.c) -o $@ $(OBJS32) $(LDLIBS)
	$(POST_PROCESS)

$(PROGS64): $(OBJS64)
	$(LINK64.c) -o $@ $(OBJS64) $(LDLIBS64)
	$(POST_PROCESS)

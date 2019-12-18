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
#

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/util-tests
TESTDIR = $(ROOTOPTPKG)/tests/

OBJS =	smbios.o \
	smbios_test_errors.o \
	smbios_test_memdevice.o \
	smbios_test_pinfo.o \
	smbios_test_slot.o
PROGS = smbios

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

CMDS = $(PROGS:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

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

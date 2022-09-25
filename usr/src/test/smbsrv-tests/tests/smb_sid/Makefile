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
# Copyright (c) 2012, 2016 by Delphix. All rights reserved.
# Copyright 2022 Tintri by DDN, Inc. All rights reserved.
#
include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

PROG = large_sids_lib large_sids_kern
KERN_OBJS = smb_sid.o

large_sids_lib := LDLIBS += -L$(ROOT)/usr/lib/smbsrv -lsmb
large_sids_lib := LDFLAGS += -R/usr/lib/smbsrv
large_sids_kern := LDLIBS64 += -lfakekernel

smb_sid.o := CPPFLAGS.first += -I $(SRC)/lib/libfakekernel/common -D_FAKE_KERNEL

ROOTOPTPKG = $(ROOT)/opt/smbsrv-tests
TESTDIR = $(ROOTOPTPKG)/tests/smb_sid

CMDS = $(PROG:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

CSTD = $(CSTD_GNU99)

all: $(PROG)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

%_lib: %.c
	$(LINK.c) -o $@ $< $(LDLIBS)
	$(POST_PROCESS)

%_kern: %.c $(KERN_OBJS)
	$(LINK64.c) -o $@ $^ $(LDLIBS64)
	$(POST_PROCESS)

smb_sid.c: $(SRC)/common/smbsrv/smb_sid.c
	$(CP) $^ $@

%.o: %.c
	$(COMPILE64.c) $<

install: all $(CMDS)

clobber: clean
	-$(RM) $(PROG)

clean:
	-$(RM) $(KERN_OBJS)

$(CMDS): $(TESTDIR) $(PROG)

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

# Copyright 2024 RackTop Systems, Inc.

PROGS = \
	acl_fromtext \
	acl_totext

SCRIPTS = \
	libsectest.ksh

ROOTOPTDIR = $(ROOT)/opt/libsec-tests/bin
ROOTOPTPROGS = $(PROGS:%=$(ROOTOPTDIR)/%) \
		$(SCRIPTS:%.ksh=$(ROOTOPTDIR)/%) \

include $(SRC)/cmd/Makefile.cmd

LDFLAGS += '-R$$ORIGIN/../../../lib'
LDLIBS = -L$(ROOT)/usr/lib -lsec

.KEEP_STATE:

install: $(ROOTOPTPROGS)

all: $(PROGS)

$(ROOTOPTPROGS): $(PROGS) $(ROOTOPTDIR)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTDIR)/%: %
	$(INS.file)

$(ROOTOPTDIR)/%: %.ksh
	$(INS.rename)

OBJS1 = acl_from_text.o acl_canned.o lib_stubs.o
acl_fromtext : $(OBJS1)
	$(LINK.c) -Wl,-zinterpose -o $@ $(OBJS1) $(LDLIBS)
	$(POST_PROCESS)

OBJS2 = acl_to_text.o acl_canned.o lib_stubs.o
acl_totext : $(OBJS2)
	$(LINK.c) -Wl,-zinterpose -o $@ $(OBJS2) $(LDLIBS)
	$(POST_PROCESS)

clobber: clean
	$(RM) $(PROGS)

clean:

FRC:

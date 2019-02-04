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
# Copyright 2019 Joyent, Inc.
#

SUBDIRS_i386 = i386 imc

SUBDIRS =       \
		ddi_ufm \
		file-locking \
		pf_key \
		poll \
		sdevfs \
		secflags \
		sigqueue \
		sockfs \
		spoof-ras \
		stress \
		timer \
		tmpfs \
		$(SUBDIRS_$(MACH))

PROGS = \
	OS-6097

PROGS32 = $(PROGS:%=%.32)
PROGS64 = $(PROGS:%=%.64)

OS-6097.32 :=	LDLIBS += -ldlpi
OS-6097.64 :=	LDLIBS64 += -ldlpi

ROOTOPTDIR = $(ROOT)/opt/os-tests/tests
ROOTOPTPROGS = $(PROGS32:%=$(ROOTOPTDIR)/%) \
	$(PROGS64:%=$(ROOTOPTDIR)/%) \
	$(SCRIPTS:%=$(ROOTOPTDIR)/%)

include $(SRC)/cmd/Makefile.cmd

all     :=      TARGET = all
install :=      TARGET = install
clean   :=      TARGET = clean
clobber :=      TARGET = clobber
lint    :=      TARGET = lint

.KEEP_STATE:

install: $(SUBDIRS) $(ROOTOPTPROGS)

all: $(SUBDIRS) $(PROGS32) $(PROGS64)

clean lint: $(SUBDIRS)

$(ROOTOPTPROGS): $(PROGS32) $(PROGS64) $(ROOTOPTDIR)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTDIR)/%: %
	$(INS.file)

$(ROOTOPTDIR)/%: %.ksh
	$(INS.rename)

%.64: %.c
	$(LINK64.c) -o $@ $< $(LDLIBS64)
	$(POST_PROCESS)

%.32: %.c
	$(LINK.c) -o $@ $< $(LDLIBS)
	$(POST_PROCESS)

clobber: $(SUBDIRS)
	$(RM) $(PROGS32) $(PROGS64)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

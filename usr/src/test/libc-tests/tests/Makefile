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
# Copyright (c) 2012 by Delphix. All rights reserved.
# Copyright 2015 Garrett D'Amore <garrett@damore.org>
# Copyright 2016 Joyent, Inc.
#

SUBDIRS = \
	catopen \
	fpround \
	newlocale \
	nl_langinfo \
	priv_gettext \
	random \
	regex \
	select \
	strerror \
	symbols \
	threads \
	wcsrtombs \
	wctype

PROGS = \
	aligned_alloc \
	c11_threads \
	c11_tss \
	call_once \
	endian \
	env-7076 \
	psignal-5097 \
	quick_exit_order \
	quick_exit_status \
	strcoll-strxfrm-6907 \
	timespec_get \
	wcsncasecmp \
	wcsncasecmp-7344 \
	wcsncasecmp-7350

SCRIPTS = \
	quick_exit \
	psignal

CPPFLAGS += -D_REENTRANT

PROGS32 = $(PROGS:%=%.32)
PROGS64 = \
	$(PROGS:%=%.64) \
	printf-6961.64

aligned_alloc.32 :=	LDLIBS += -lproc
aligned_alloc.64 :=	LDLIBS64 += -lproc

ROOTOPTDIR = $(ROOT)/opt/libc-tests/tests
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

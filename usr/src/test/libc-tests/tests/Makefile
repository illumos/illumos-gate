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
# Copyright 2019 Joyent, Inc.
# Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
# Copyright 2023 Bill Sommerfeld <sommerfeld@alum.mit.edu>
# Copyright 2025 Oxide Computer Company
#

SUBDIRS = \
	catopen \
	clocklock \
	err \
	fexecve \
	fpround \
	i18n \
	newlocale \
	nl_langinfo \
	printf-intmax \
	priv_gettext \
	qsort \
	posix_spawn \
	random \
	regex \
	select \
	stdio \
	symbols \
	threads \
	wcsrtombs \
	wctype

PROGS = \
	aligned_alloc \
	ascftime \
	asprintf-14933 \
	c11_threads \
	c11_tss \
	call_once \
	closefrom \
	dprintf \
	endian \
	env-7076 \
	fnmatch \
	getlocname \
	isatty \
	memchr \
	memset_s \
	mutex_attr \
	mutex-16200 \
	posix_memalign \
	printf-15294 \
	printf-9511 \
	psignal-5097 \
	ptsname \
	quick_exit_order \
	quick_exit_status \
	set_constraint_handler_s \
	strcoll-strxfrm-6907 \
	stdbit \
	strerror \
	strtonum \
	timespec_get \
	timespec_getres \
	wcslcat \
	wcslcpy \
	wcsncasecmp \
	wcsncasecmp-7344 \
	wcsncasecmp-7350 \
	uchar \
	utimes

SCRIPTS = \
	aligned_alloc \
	quick_exit \
	psignal

CPPFLAGS += -D_REENTRANT

PROGS32 = $(PROGS:%=%.32)
PROGS64 = \
	$(PROGS:%=%.64) \
	printf-6961.64

aligned_alloc.32 :=	CSTD=$(CSTD_GNU17)
aligned_alloc.64 :=	CSTD=$(CSTD_GNU17)
aligned_alloc.32 :=	LDLIBS += -lproc
aligned_alloc.64 :=	LDLIBS64 += -lproc
posix_memalign.32 :=	LDLIBS += -lproc
posix_memalign.64 :=	LDLIBS64 += -lproc

asprintf-14933.32 :=	CSTD=$(CSTD_GNU17)
asprintf-14933.64 :=	CSTD=$(CSTD_GNU17)

dprintf.32 :=	CSTD=$(CSTD_GNU17)
dprintf.64 :=	CSTD=$(CSTD_GNU17)
dprintf.32 :=	CPPFLAGS += -D_XOPEN_SOURCE=700 -D__EXTENSIONS__
dprintf.64 :=	CPPFLAGS += -D_XOPEN_SOURCE=700 -D__EXTENSIONS__

memset_s.32 :=	CPPFLAGS += -D__STDC_WANT_LIB_EXT1__=1
memset_s.64 :=	CPPFLAGS += -D__STDC_WANT_LIB_EXT1__=1
set_constraint_handler_s.32 := CPPFLAGS += -D__STDC_WANT_LIB_EXT1__=1
set_constraint_handler_s.64 := CPPFLAGS += -D__STDC_WANT_LIB_EXT1__=1

getlocname.32 := CSTD=$(CSTD_GNU17)
getlocname.64 := CSTD=$(CSTD_GNU17)

isatty.32 :=	CSTD=$(CSTD_GNU17)
isatty.64 :=	CSTD=$(CSTD_GNU17)

mutex-16200.32 :=	LDLIBS += -lproc
mutex-16200.64 :=	LDLIBS64 += -lproc
mutex-16200.32 :=	CSTD=$(CSTD_GNU17)
mutex-16200.64 :=	CSTD=$(CSTD_GNU17)
mutex_attr.32 :=	CSTD=$(CSTD_GNU17)
mutex_attr.64 :=	CSTD=$(CSTD_GNU17)

ptsname.32 :=		LDLIBS += -lsocket
ptsname.64 :=		LDLIBS64 += -lsocket

stdbit.32 :=	CSTD=$(CSTD_GNU17)
stdbit.64 :=	CSTD=$(CSTD_GNU17)

strtonum.32 :=		CSTD=$(CSTD_GNU17)
strtonum.64 :=		CSTD=$(CSTD_GNU17)

timespec_get.32 :=	CSTD=$(CSTD_GNU17)
timespec_get.64 :=	CSTD=$(CSTD_GNU17)
timespec_getres.32 :=	CSTD=$(CSTD_GNU17)
timespec_getres.64 :=	CSTD=$(CSTD_GNU17)

wcslcat.32 :=		CSTD=$(CSTD_GNU17)
wcslcat.64 :=		CSTD=$(CSTD_GNU17)
wcslcpy.32 :=		CSTD=$(CSTD_GNU17)
wcslcpy.64 :=		CSTD=$(CSTD_GNU17)

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

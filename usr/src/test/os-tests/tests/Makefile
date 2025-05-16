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
# Copyright 2020 Joyent, Inc.
# Copyright 2021 Tintri by DDN, Inc. All rights reserved.
# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
# Copyright 2025 Oxide Computer Company
#

SUBDIRS_i386 =		\
	i386		\
	imc		\
	saveargs	\
	xsave		\
	zen_umc

SUBDIRS =       \
		cores \
		ddi_ufm \
		definit \
		execvpe \
		file-locking \
		hexdump \
		idmap \
		ilstr \
		ksensor \
		ksid \
		ktest \
		libtopo \
		mac \
		minttl \
		oclo \
		pf_key \
		poll \
		portfs \
		regression \
		sdevfs \
		secflags \
		secure_getenv \
		signalfd \
		sigqueue \
		sockfs \
		spoof-ras \
		stackalign \
		stress \
		syscall \
		tcpsig \
		timer \
		tmpfs \
		uccid \
		vfs \
		$(SUBDIRS_$(MACH))

PROGS = \
	clock_gettime \
	eventfd \
	fifo-tvnsec \
	odirectory \
	OS-6097 \
	ucontext \
	getcontext_extd \
	writev

CPPFLAGS += -D_REENTRANT
PROGS32 = $(PROGS:%=%.32)
PROGS64 = $(PROGS:%=%.64)

ROOTOPTDIR = $(ROOT)/opt/os-tests/tests
ROOTOPTPROGS = $(PROGS32:%=$(ROOTOPTDIR)/%) \
	$(PROGS64:%=$(ROOTOPTDIR)/%) \
	$(SCRIPTS:%=$(ROOTOPTDIR)/%)

odirectory.32 :=	LDLIBS += -lsocket
odirectory.64 :=	LDLIBS64 += -lsocket

OS-6097.32 :=	LDLIBS += -ldlpi
OS-6097.64 :=	LDLIBS64 += -ldlpi

clock_gettime.32 :=	LDLIBS += -lproc
clock_gettime.32 :=	CSTD = $(CSTD_GNU99)
clock_gettime.64 :=	LDLIBS64 += -lproc
clock_gettime.64 :=	CSTD = $(CSTD_GNU99)

fifo-tvnsec.32 :=	CSTD = $(CSTD_GNU99)
fifo-tvnsec.64 :=	CSTD = $(CSTD_GNU99)

ucontext.32 :=		SMOFF += unreachable
ucontext.64 :=		SMOFF += unreachable

writev.32 :=		CPPFLAGS += -D_FILE_OFFSET_BITS=64
writev.32 :=		CSTD = $(CSTD_GNU99)
writev.64 :=		CSTD = $(CSTD_GNU99)

include $(SRC)/cmd/Makefile.cmd

all     :=      TARGET = all
install :=      TARGET = install
clean   :=      TARGET = clean
clobber :=      TARGET = clobber

.KEEP_STATE:

install: $(SUBDIRS) $(ROOTOPTPROGS)

all: $(SUBDIRS) $(PROGS32) $(PROGS64)

clean: $(SUBDIRS)

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

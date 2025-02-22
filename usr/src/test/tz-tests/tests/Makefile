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
# Copyright 2025 Oxide Computer Company
#

PROGS = \
	tzload		\
	zoneinfo_dump

SCRIPTS = \
	basic_tzs \
	tz_dump

PROGS32 = $(PROGS:%=%.32)
PROGS64 = $(PROGS:%=%.64) \
	tzparams.64 \
	tzlist.64

ROOTOPTDIR = $(ROOT)/opt/tz-tests
ROOTOPTTESTS = $(ROOTOPTDIR)/tests
ROOTOPTPROGS = $(PROGS32:%=$(ROOTOPTTESTS)/%) \
	$(PROGS64:%=$(ROOTOPTTESTS)/%) \
	$(SCRIPTS:%=$(ROOTOPTTESTS)/%)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.ctf

CSTD = $(CSTD_GNU17)
CTF_MODE = link
CPPFLAGS += -D_REENTRANT

zoneinfo_dump.32 := LDLIBS += -lzoneinfo
zoneinfo_dump.64 := LDLIBS64 += -lzoneinfo
tzlist.64 := LDLIBS64 += -lzoneinfo

.KEEP_STATE:

all: $(PROGS32) $(PROGS64)

install: $(ROOTOPTTESTS) .WAIT $(ROOTOPTPROGS)

$(ROOTOPTPROGS): $(PROGS32) $(PROGS64) $(ROOTOPTDIR)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTTESTS): $(ROOTOPTDIR)
	$(INS.dir)

$(ROOTOPTTESTS)/%: %
	$(INS.file)

$(ROOTOPTTESTS)/%: %.ksh
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

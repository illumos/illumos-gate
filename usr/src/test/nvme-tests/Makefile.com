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

#
# Common Makefile rules and patterns for building the various NVMe
# tests.
#

PROGS32 += $(PROGS:%=%.32)
PROGS64 += $(PROGS:%=%.64)

EXTRA_OBJS32 = $(COMMON_SRCS:%.c=%.o.32)
EXTRA_OBJS64 = $(COMMON_SRCS:%.c=%.o.64)

ROOTOPTDIR = $(ROOT)/opt/nvme-tests
ROOTOPTTESTS = $(ROOTOPTDIR)/tests
ROOTOPTTARG = $(ROOTOPTTESTS)/$(TESTDIR)
ROOTOPTPROGS = $(PROGS32:%=$(ROOTOPTTARG)/%) $(PROGS64:%=$(ROOTOPTTARG)/%)
ROOTOPTPROGS += $(SCRIPTS:%=$(ROOTOPTTARG)/%)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.ctf

CPPFLAGS += -D_REENTRANT
CSTD = $(CSTD_GNU17)
CTF_MODE = link

.KEEP_STATE:

all: $(PROGS32) $(PROGS64)

clobber: clean
	-$(RM) $(PROGS32) $(PROGS64)

clean:
	-$(RM) *.o.32 *.o.64

install: $(ROOTOPTTARG) .WAIT $(ROOTOPTPROGS)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTTESTS): $(ROOTOPTDIR)
	$(INS.dir)

$(ROOTOPTTARG): $(ROOTOPTTESTS)
	$(INS.dir)

$(ROOTOPTTARG)/%: %
	$(INS.file)

$(ROOTOPTTARG)/%: %.ksh
	$(INS.rename)

%.o.32: %.c
	$(COMPILE.c) -o $@ -c $<
	$(POST_PROCESS_O)

%.o.64: %.c
	$(COMPILE64.c) -o $@ -c $<
	$(POST_PROCESS_O)

%.o.32: $(SRC)/common/nvme/%.c
	$(COMPILE.c) -o $@ -c $<
	$(POST_PROCESS_O)

%.o.64: $(SRC)/common/nvme/%.c
	$(COMPILE64.c) -o $@ -c $<
	$(POST_PROCESS_O)

%.64: %.o.64 $(EXTRA_OBJS64)
	$(LINK64.c) -o $@ $< $(EXTRA_OBJS64) $(LDLIBS64)
	$(POST_PROCESS)

%.32: %.o.32 $(EXTRA_OBJS32)
	$(LINK.c) -o $@ $< $(EXTRA_OBJS32) $(LDLIBS)
	$(POST_PROCESS)

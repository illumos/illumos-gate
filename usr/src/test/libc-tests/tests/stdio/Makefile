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
# Copyright 2020 Robert Mustacchi
#

PROGS = \
	fdclose \
	fileno \
	fmemopentest \
	ftell_ungetc \
	memstream \
	memstream_reopen \
	open_memstreamtest \
	orientation_test \
	test_mbrtowc

LFSPROGS = \
	ftello_12768

PROGS32 = $(PROGS:%=%.32)
PROGSLFS = $(LFSPROGS:%=%.lfs)
PROGS64 = $(PROGS:%=%.64) $(LFSPROGS:%=%.64)

ROOTOPTDIR = $(ROOT)/opt/libc-tests/tests
ROOTOPTSTDIO = $(ROOTOPTDIR)/stdio
ROOTOPTPROGS = $(PROGS32:%=$(ROOTOPTSTDIO)/%) \
	$(PROGS64:%=$(ROOTOPTSTDIO)/%) \
	$(PROGSLFS:%=$(ROOTOPTSTDIO)/%)

include $(SRC)/cmd/Makefile.cmd

CPPFLAGS += -D_REENTRANT -D__EXTENSIONS__
LFSCPPFLAGS = -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64

#
# libumem is used to interpose on all of these tests to modify the
# behavior of libc's malloc for additional debugging. Each of the tests
# enables umem debugging in their program text.
#
LDLIBS += -lumem
LDLIBS64 += -lumem

#
# This test requires C99/xpg6 behavior. Therefore we build it explicitly
# with c99 and XPG7 so it has access to the required functions.
#
memstream_reopen.32 := CPPFLAGS += -D_XOPEN_SOURCE=700
memstream_reopen.64 := CPPFLAGS += -D_XOPEN_SOURCE=700
memstream_reopen.32 := CSTD = $(CSTD_GNU99)
memstream_reopen.64 := CSTD = $(CSTD_GNU99)

# Third-party code
orientation_test.32 := SMOFF += all_func_returns
orientation_test.64 := SMOFF += all_func_returns

.KEEP_STATE:

all: $(PROGS32) $(PROGS64)

install: $(ROOTOPTPROGS)

clean:

$(ROOTOPTPROGS): $(PROGS32) $(PROGS64) $(ROOTOPTSTDIO)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTSTDIO): $(ROOTOPTDIR)
	$(INS.dir)

$(ROOTOPTSTDIO)/%: %
	$(INS.file)

%.64: %.c
	$(LINK64.c) -o $@ $< $(LDLIBS64)
	$(POST_PROCESS)

%.lfs: %.c
	$(LINK.c) $(LFSCPPFLAGS) -o $@ $< $(LDLIBS)
	$(POST_PROCESS)

%.32: %.c
	$(LINK.c) -o $@ $< $(LDLIBS)
	$(POST_PROCESS)

clobber:
	$(RM) $(PROGS32) $(PROGS64)

FRC:

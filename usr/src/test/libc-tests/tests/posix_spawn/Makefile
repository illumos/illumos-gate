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
# Copyright 2026 Oxide Computer Company
#

PROGS = posix_spawn_chdir posix_spawn_fileactions posix_spawn_attr \
	posix_spawn_defpath posix_spawn_path posix_spawn_pipe_np \
	posix_spawn_priv posix_spawn_wait

HELPERS32 = posix_spawn_child.32
HELPERS64 = posix_spawn_child.64

DATA = posix_spawn_noshebang

COMMON_OBJS32 = posix_spawn_common.32.o
COMMON_OBJS64 = posix_spawn_common.64.o

PROGS32 = $(PROGS:%=%.32) $(HELPERS32)
PROGS64 = $(PROGS:%=%.64) $(HELPERS64)
OBJS32 = $(PROGS32:%=%.o) $(COMMON_OBJS32)
OBJS64 = $(PROGS64:%=%.o) $(COMMON_OBJS64)

ROOTOPTDIR = $(ROOT)/opt/libc-tests/tests
ROOTOPTSPAWN = $(ROOTOPTDIR)/posix_spawn
ROOTOPTPROGS =	$(PROGS32:%=$(ROOTOPTSPAWN)/%) \
		$(PROGS64:%=$(ROOTOPTSPAWN)/%)
ROOTOPTDATA = $(DATA:%=$(ROOTOPTSPAWN)/%)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.ctf

CSTD = $(CSTD_GNU17)
CPPFLAGS += -D_REENTRANT
CTF_MODE = link

posix_spawn_priv.32 := LDLIBS += -lproc
posix_spawn_priv.64 := LDLIBS64 += -lproc
posix_spawn_wait.32 := LDLIBS += -lproc
posix_spawn_wait.64 := LDLIBS64 += -lproc

.KEEP_STATE:

all: $(PROGS32) $(PROGS64)

$(ROOTOPTSPAWN)/posix_spawn_noshebang := FILEMODE = 0555

install: $(ROOTOPTPROGS) $(ROOTOPTDATA)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTSPAWN): $(ROOTOPTDIR)
	$(INS.dir)

$(ROOTOPTPROGS): $(PROGS32) $(PROGS64) $(ROOTOPTSPAWN)
$(ROOTOPTDATA): $(ROOTOPTSPAWN)

$(ROOTOPTSPAWN)/%: %
	$(INS.file)

%.32.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.32: %.32.o $(COMMON_OBJS32)
	$(LINK.c) -o $@ $< $(COMMON_OBJS32) $(LDLIBS)
	$(POST_PROCESS)

%.64.o: %.c
	$(COMPILE64.c) -o $@ $<
	$(POST_PROCESS_O)

%.64: %.64.o $(COMMON_OBJS64)
	$(LINK64.c) -o $@ $< $(COMMON_OBJS64) $(LDLIBS64)
	$(POST_PROCESS)

clean:
	$(RM) $(OBJS32) $(OBJS64)

clobber: clean
	$(RM) $(PROGS32) $(PROGS64)

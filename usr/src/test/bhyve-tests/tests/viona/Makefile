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

# Copyright 2024 Oxide Computer Company

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.cmd.64
include $(SRC)/test/Makefile.com

PROGS =	interface_version create_delete link_params

SCRIPTS =	setup cleanup

COMMON_OBJS =	in_guest.o common.o viona_suite.o null_payload.o

CLEAN_OBJS =	$(PROGS:%=%.o) $(COMMON_OBJS)

ROOTOPTPKG = $(ROOT)/opt/bhyve-tests
TESTDIR = $(ROOTOPTPKG)/tests/viona

CMDS = \
	$(PROGS:%=$(TESTDIR)/%) \
	$(SCRIPTS:%=$(TESTDIR)/%)

$(CMDS) := FILEMODE = 0555

CSTD=		$(CSTD_GNU99)
CPPFLAGS =	-I$(COMPAT)/bhyve -I$(CONTRIB)/bhyve \
		-I$(COMPAT)/bhyve/amd64 -I$(CONTRIB)/bhyve/amd64 \
		$(CPPFLAGS.master) \
		-I$(SRC)/uts/intel/io/vmm \
		-I$(SRC)/uts/intel \
		-I../common

$(PROGS) :=	LDLIBS += -lvmmapi -ldladm
link_params :=	LDLIBS += -lnvpair

all: $(PROGS)

install: all $(CMDS)

clean:
	-$(RM) $(CLEAN_OBJS)
clobber: clean
	-$(RM) $(PROGS)

$(CMDS): $(TESTDIR)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

$(TESTDIR)/%: %.ksh
	$(INS.rename)

%.o: ../common/%.c
	$(COMPILE.c) -o $@ $^
	$(POST_PROCESS)

%: %.o $(COMMON_OBJS)
	$(LINK.c) -o $@ $^ $(LDLIBS)
	$(POST_PROCESS)

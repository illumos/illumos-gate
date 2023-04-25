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

# Copyright 2023 Oxide Computer Company

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.cmd.64
include $(SRC)/test/Makefile.com

PROG =	vpmtmr_freq \
	vhpet_freq \
	vlapic_freq \
	vlapic_freq_periodic \
	vlapic_mmio_access \
	vlapic_msr_access \
	vatpit_freq

# These should probably go in the `vmm` tests, but since they depend on
# in-guest payloads, it is easier to build them here.
PROG += guest_tsc_adjust \
	tsc_freq_ctrl \
	wrmsr_tsc \
	rdmsr_tsc

PAYLOADS = $(PROG)
include ../Makefile.in_guest

COMMON_OBJS =	in_guest.o common.o

CLEANFILES =	$(COMMON_OBJS) $(PAYLOAD_CLEANFILES) payload_utils.o
CLOBBERFILES =	$(PROG)

ROOTOPTPKG = $(ROOT)/opt/bhyve-tests
TESTDIR = $(ROOTOPTPKG)/tests/kdev

CMDS = $(PROG:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

CSTD=		$(CSTD_GNU99)
CPPFLAGS =	-I$(COMPAT)/bhyve -I$(CONTRIB)/bhyve \
		-I$(COMPAT)/bhyve/amd64 -I$(CONTRIB)/bhyve/amd64 \
		$(CPPFLAGS.master) \
		-I$(SRC)/uts/intel/io/vmm \
		-I$(SRC)/uts/intel \
		-I../common

ASFLAGS +=	-D_ASM
ASFLAGS64 +=	-D_ASM


CFLAGS = -m64
$(PROG) :=	LDLIBS += -lvmmapi

all: $(PROG)

install: all $(CMDS)

clean:
	-$(RM) $(CLEANFILES)
clobber: clean
	-$(RM) $(CLOBBERFILES)

$(CMDS): $(TESTDIR) $(PROG)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

%: %.c pobj_%.o $(COMMON_OBJS)
	$(LINK.c) -o $@ $^ $(LDLIBS)
	$(POST_PROCESS)

%: %.o
	$(LINK.c) -o $@ $^ $(LDLIBS)
	$(POST_PROCESS)

$(PAYLOADS:%=payload_%): payload_utils.o

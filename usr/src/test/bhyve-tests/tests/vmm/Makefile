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
# Copyright 2022 MNX Cloud, Inc.
# Copyright 2023 Oxide Computer Company
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.cmd.64
include $(SRC)/test/Makefile.com

PROG =	mem_partial \
	mem_seg_map \
	mem_devmem \
	fpu_getset \
	interface_version \
	check_iommu \
	auto_destruct \
	legacy_destruct \
	self_destruct \
	drv_hold \
	cpuid_ioctl \
	default_capabs \
	datarw_constraints \
	datarw_msrs \
	datarw_vcpu \
	pause_resume \
	import_vlapic \
	time_data \
	maxcpu \
	npt_ops

SCRIPT = vmm_drv_test_fini vmm_drv_test_init

COMMON_OBJS =	common.o
CLEAN_OBJS =	$(PROG:%=%.o)

ROOTOPTPKG = $(ROOT)/opt/bhyve-tests
TESTDIR = $(ROOTOPTPKG)/tests/vmm

CMDS = $(PROG:%=$(TESTDIR)/%)
CMDS += $(SCRIPT:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

CSTD=		$(CSTD_GNU99)
CPPFLAGS =	-I$(COMPAT)/bhyve -I$(CONTRIB)/bhyve \
		-I$(COMPAT)/bhyve/amd64 -I$(CONTRIB)/bhyve/amd64 \
		$(CPPFLAGS.master) \
		-I$(SRC)/uts/intel/io/vmm \
		-I$(SRC)/uts/intel \
		-I../common
$(PROG) :=	LDLIBS += -lvmmapi

all: $(PROG)

install: all $(CMDS)

clean:
	-$(RM) $(CLEAN_OBJS) $(COMMON_OBJS)
clobber: clean
	-$(RM) $(PROG)

$(PROG): $(COMMON_OBJS)

$(CMDS): $(TESTDIR) $(PROG)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

%.o: ../common/%.c
	$(COMPILE.c) -o $@ $^
	$(POST_PROCESS)

%: %.o
	$(LINK.c) -o $@ $< $(COMMON_OBJS) $(LDLIBS)
	$(POST_PROCESS)

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

LIBRARY =	libnvme.a
VERS =		.1
OBJECTS =	libnvme.o \
		libnvme_ctrl_info.o \
		libnvme_error.o \
		libnvme_feature.o \
		libnvme_format.o \
		libnvme_fw.o \
		libnvme_identify.o \
		libnvme_kioxia.o \
		libnvme_log.o \
		libnvme_micron.o \
		libnvme_ns_info.o \
		libnvme_ns_mgmt.o \
		libnvme_ocp.o \
		libnvme_phison.o \
		libnvme_samsung.o \
		libnvme_solidigm.o \
		libnvme_vendor.o \
		libnvme_vuc.o \
		libnvme_wdc.o \
		nvme_feature.o \
		nvme_field.o \
		nvme_firmware.o \
		nvme_format.o \
		nvme_identify.o \
		nvme_log.o \
		nvme_nsmgmt.o \
		nvme_version.o \
		nvme_vuc.o

include ../../Makefile.lib

SRCDIR =	../common
LIBS =		$(DYNLIB)
CSTD =		$(CSTD_GNU99)
CPPFLAGS +=	-I$(SRC)/common/nvme
LDLIBS +=	-lc -ldevinfo -lnvpair

objs/%.o pics/%.o: $(SRC)/common/nvme/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

.KEEP_STATE:

all: $(LIBS)

include ../../Makefile.targ

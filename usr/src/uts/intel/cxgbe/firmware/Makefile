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
# Copyright 2023 Oxide Computer Company
#

UTSBASE = ../../..

#
# Firmware location and files
#
#
FW_VERSION_T4=	1.27.1.0
FW_VERSION_T5=	1.27.4.0
FW_VERSION_T6=	1.27.4.0

FWDIR	= $(UTSBASE)/common/io/cxgbe/firmware
FWFILES	= \
	t4fw-$(FW_VERSION_T4).bin \
	t5fw-$(FW_VERSION_T5).bin \
	t6fw-$(FW_VERSION_T6).bin
FWLINKS = t4fw.bin t5fw.bin t6fw.bin
CFGFILES = t4fw_cfg.txt t5fw_cfg.txt t6fw_cfg.txt

MODULE		= cxgbe
ROOTFIRMWARE	= \
	$(FWFILES:%=$(ROOT_FIRMWARE_DIR)/$(MODULE)/%) \
	$(FWLINKS:%=$(ROOT_FIRMWARE_DIR)/$(MODULE)/%) \
	$(CFGFILES:%=$(ROOT_FIRMWARE_DIR)/$(MODULE)/%)

include $(UTSBASE)/intel/Makefile.intel

.KEEP_STATE:

all def clean clobber:

install: $(ROOTFIRMWARE)

$(ROOT_FIRMWARE_DIR)/$(MODULE)/t4fw.bin := \
	INSLINKTARGET= t4fw-$(FW_VERSION_T4).bin
$(ROOT_FIRMWARE_DIR)/$(MODULE)/t5fw.bin := \
	INSLINKTARGET= t5fw-$(FW_VERSION_T5).bin
$(ROOT_FIRMWARE_DIR)/$(MODULE)/t6fw.bin := \
	INSLINKTARGET= t6fw-$(FW_VERSION_T6).bin

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ

# Force this symlink to be always re-created in order that the link in proto
# does not become stale if the target is changed between incremental builds.
$(ROOT_FIRMWARE_DIR)/$(MODULE)/%: FRC
	$(INS.symlink)

FRC:

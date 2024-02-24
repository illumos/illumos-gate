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
# Copyright 2024 Oxide Computer Company
#

PROGS = \
	feature \
	firmware \
	format \
	identify \
	logs \
	version \
	vuc

COMMON_SRCS = \
	controllers.c \
	nvme_feature.c \
	nvme_field.c \
	nvme_firmware.c \
	nvme_format.c \
	nvme_identify.c \
	nvme_log.c \
	nvme_version.c \
	nvme_vuc.c

TESTDIR = unit

include $(SRC)/test/nvme-tests/Makefile.com

CPPFLAGS += -I$(SRC)/common/nvme

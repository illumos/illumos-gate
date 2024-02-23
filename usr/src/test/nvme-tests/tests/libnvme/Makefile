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
	bad-req \
	ctrl-disc \
	info-roundtrip \
	missing-field \
	ns-disc \
	ns-info \
	sctostr

COMMON_SRCS = libnvme_test_common.c
TESTDIR = libnvme

include $(SRC)/test/nvme-tests/Makefile.com

LDLIBS += -lnvme
LDLIBS64 += -lnvme

bad-req.32 := LDLIBS += -lumem
bad-req.64 := LDLIBS64 += -lumem

ctrl-disc.32 := LDLIBS += -ldevinfo -lumem
ctrl-disc.64 := LDLIBS64 += -ldevinfo -lumem

ns-disc.32 := LDLIBS += -lumem
ns-disc.64 := LDLIBS64 += -lumem

ns-info.32 := LDLIBS += -lumem
ns-info.64 := LDLIBS64 += -lumem

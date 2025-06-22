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

PROGS = \
	bad-req \
	bad-req-nsmgmt \
	ctrl-disc \
	format \
	info-roundtrip \
	missing-field \
	missing-field-destruct \
	need-write-lock \
	ns-cap \
	ns-disc \
	ns-info \
	ns-lifecycle \
	ns-max \
	pev \
	sctostr

#
# These are programs that are only used as part of pre-checks for the
# destructive tests.
#
PROGS64 = \
	check-destruct.64 \
	device-empty.64 \
	device-reset.64

COMMON_SRCS = libnvme_test_common.c
TESTDIR = libnvme

include $(SRC)/test/nvme-tests/Makefile.com

LDLIBS += -lnvme
LDLIBS64 += -lnvme

bad-req.32 := LDLIBS += -lumem
bad-req.64 := LDLIBS64 += -lumem
bad-req-nsmgmt.32 := LDLIBS += -lumem
bad-req-nsmgmt.64 := LDLIBS64 += -lumem

ctrl-disc.32 := LDLIBS += -ldevinfo -lumem
ctrl-disc.64 := LDLIBS64 += -ldevinfo -lumem

format.32 := LDLIBS += -ldevinfo
format.64 := LDLIBS64 += -ldevinfo

ns-disc.32 := LDLIBS += -lumem
ns-disc.64 := LDLIBS64 += -lumem

ns-info.32 := LDLIBS += -lumem
ns-info.64 := LDLIBS64 += -lumem

check-destruct.64 := LDLIBS64 += -lpcidb

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
	addresses \
	ioc-errnos \
	invalid-io

COMMON_SRCS = i2c_ioctl_util.c

TESTDIR = ioctl

include $(SRC)/test/i2c-tests/tests/Makefile.com

LDLIBS += -ldevinfo
LDLIBS64 += -ldevinfo

addresses.32 := LDLIBS += -lnvpair
addresses.64 := LDLIBS64 += -lnvpair

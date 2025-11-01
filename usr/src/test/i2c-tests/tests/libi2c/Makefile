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
	addr-util \
	claimed-addrs \
	discovery \
	missing-field

COMMON_SRCS = libi2c_test_util.c

TESTDIR = libi2c

include $(SRC)/test/i2c-tests/tests/Makefile.com

LDLIBS += -li2c
LDLIBS64 += -li2c

addresses.32 := LDLIBS += -lnvpair
addresses.64 := LDLIBS64 += -lnvpair

discovery.32 := LDLIBS += -ldevinfo
discovery.64 := LDLIBS64 += -ldevinfo

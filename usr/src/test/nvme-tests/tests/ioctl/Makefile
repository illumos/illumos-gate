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
	bad-lock \
	basic-get-feature \
	basic-get-log \
	basic-identify \
	basic-lock \
	ctrl-block-lock \
	lock-order \
	lock-signal \
	multi-lock-err \
	multi-reader-lock

COMMON_SRCS = nvme_ioctl_util.c
TESTDIR = ioctl

include $(SRC)/test/nvme-tests/Makefile.com

LDLIBS += -ldevinfo -lproc
LDLIBS64 += -ldevinfo -lproc

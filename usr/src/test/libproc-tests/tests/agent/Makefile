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
# Copyright 2026 Oxide Computer Company
#

PROGS = \
	agent_destroy \
	agent_target

SCRIPTS = \
	agent_destroy

TESTDIR = agent

include $(SRC)/test/libproc-tests/Makefile.com

agent_destroy.32 := LDLIBS += -lproc
agent_destroy.64 := LDLIBS64 += -lproc

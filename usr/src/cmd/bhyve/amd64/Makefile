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
# Copyright 2024 OmniOS Community Edition (OmniOSce) Association.
#

BHYVE_OBJS = $(COMMON_OBJS)	\
	atkbdc.o		\
	bhyverun_machdep.o	\
	e820.o			\
	inout.o			\
	ioapic.o		\
	fwctl.o			\
	mptbl.o			\
	pci_fbuf.o		\
	pci_lpc.o		\
	pci_passthru.o		\
	pctestdev.o		\
	post.o			\
	pm.o			\
	ps2kbd.o		\
	ps2mouse.o		\
	rfb.o			\
	rtc.o			\
	spinup_ap.o		\
	task_switch.o		\
	vga.o			\
	vmexit.o		\
	xmsr.o

include ../Makefile.com

CPPFLAGS += -I.

install: all $(ROOTUSRSBINPROG)

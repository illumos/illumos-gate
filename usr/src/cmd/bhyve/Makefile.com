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
# Copyright 2015 Pluribus Networks Inc.
#

PROG= bhyve

SRCS =	atkbdc.c		\
	bhyvegc.c		\
	bhyverun.c		\
	block_if.c		\
	console.c		\
	consport.c		\
	inout.c			\
	ioapic.c		\
	mem.c			\
	mptbl.c			\
	pci_ahci.c		\
	pci_emul.c		\
	pci_hostbridge.c	\
	pci_irq.c		\
	pci_lpc.c		\
	pci_virtio_block.c	\
	pci_virtio_net.c	\
	pci_virtio_viona.c	\
	pm.c			\
	pmtmr.c			\
	post.c			\
	ps2kbd.c		\
	ps2mouse.c		\
	rfb.c			\
	rtc.c			\
	smbiostbl.c		\
	uart_emul.c		\
	vga.c			\
	virtio.c		\
	vmm_instruction_emul.c	\
	xmsr.c			\
	spinup_ap.c		\
	bhyve_sol_glue.c

OBJS = $(SRCS:.c=.o)

include ../../Makefile.cmd

.KEEP_STATE:

CFLAGS +=	$(CCVERBOSE) -_gcc=-Wimplicit-function-declaration
CFLAGS64 +=	$(CCVERBOSE) -_gcc=-Wimplicit-function-declaration
CPPFLAGS =	-I$(COMPAT)/freebsd -I$(CONTRIB)/freebsd $(CPPFLAGS.master) \
		-I$(ROOT)/usr/platform/i86pc/include \
		-I$(SRC)/uts/i86pc/io/vmm \
		-I$(SRC)/uts/common \
		-I$(SRC)/uts/i86pc \
		-I$(SRC)/lib/libdladm/common
LDLIBS +=	-lsocket -lnsl -ldlpi -ldladm -lkstat -lmd -luuid -lvmmapi

POST_PROCESS += ; $(GENSETDEFS) $@

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

include ../../Makefile.targ

%.o: ../%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

%.o: $(SRC)/uts/i86pc/io/vmm/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

%.o: ../%.s
	$(COMPILE.s) $<

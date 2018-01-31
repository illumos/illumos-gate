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
# Copyright 2018 Joyent, Inc.
#

PROG= bhyve

SRCS =	acpi.c			\
	atkbdc.c		\
	bhyvegc.c		\
	bhyverun.c		\
	block_if.c		\
	bootrom.c		\
	console.c		\
	consport.c		\
	dbgport.c		\
	fwctl.c			\
	inout.c			\
	ioapic.c		\
	mem.c			\
	mptbl.c			\
	pci_ahci.c		\
	pci_e82545.c		\
	pci_emul.c		\
	pci_fbuf.c		\
	pci_hostbridge.c	\
	pci_irq.c		\
	pci_lpc.c		\
	pci_passthru.c		\
	pci_uart.c		\
	pci_virtio_block.c	\
	pci_virtio_net.c	\
	pci_virtio_rnd.c	\
	pci_virtio_viona.c	\
	pci_xhci.c		\
	pm.c			\
	post.c			\
	ps2kbd.c		\
	ps2mouse.c		\
	rfb.c			\
	rtc.c			\
	smbiostbl.c		\
	sockstream.c		\
	task_switch.c		\
	uart_emul.c		\
	usb_emul.c		\
	usb_mouse.c		\
	vga.c			\
	virtio.c		\
	vmm_instruction_emul.c	\
	xmsr.c			\
	spinup_ap.c		\
	bhyve_sol_glue.c	\
	zhyve.c

OBJS = $(SRCS:.c=.o)

include ../../Makefile.cmd
include ../../Makefile.ctf

.KEEP_STATE:

CFLAGS +=	$(CCVERBOSE) -_gcc=-Wimplicit-function-declaration -_gcc=-Wno-parentheses
CFLAGS64 +=	$(CCVERBOSE) -_gcc=-Wimplicit-function-declaration -_gcc=-Wno-parentheses
CPPFLAGS =	-I$(COMPAT)/freebsd -I$(CONTRIB)/freebsd \
		-I$(CONTRIB)/freebsd/dev/usb/controller \
		-I$(CONTRIB)/freebsd/dev/mii \
		-I$(SRC)/uts/common/io/e1000api \
		$(CPPFLAGS.master) \
		-I$(ROOT)/usr/platform/i86pc/include \
		-I$(SRC)/uts/i86pc/io/vmm \
		-I$(SRC)/uts/common \
		-I$(SRC)/uts/i86pc \
		-I$(SRC)/lib/libdladm/common \
		-DWITHOUT_CAPSICUM
LDLIBS +=	-lsocket -lnsl -ldlpi -ldladm -lmd -luuid -lvmmapi -lz -lnvpair

POST_PROCESS += ; $(GENSETDEFS) $@

# Real main is in zhyve.c
bhyverun.o :=	CPPFLAGS += -Dmain=bhyve_main

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

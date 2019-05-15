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
# Copyright 2014 Pluribus Networks Inc.
# Copyright 2019 Joyent, Inc.
#

PROG =		bhyve

include ../Makefile.cmd
include ../Makefile.cmd.64
include ../Makefile.ctf

SUBDIRS = test

all	:=	TARGET = all
install	:=	TARGET = install
clean	:=	TARGET = clean
clobber	:=	TARGET = clobber
lint	:=	TARGET = lint

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
	gdb.c			\
	inout.c			\
	ioapic.c		\
	mem.c			\
	mevent.c		\
	mptbl.c			\
	pci_ahci.c		\
	pci_e82545.c		\
	pci_emul.c		\
	pci_fbuf.c		\
	pci_hostbridge.c	\
	pci_irq.c		\
	pci_lpc.c		\
	pci_nvme.c		\
	pci_passthru.c		\
	pci_uart.c		\
	pci_virtio_block.c	\
	pci_virtio_console.c	\
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
	iov.c			\
	bhyve_sol_glue.c

# The virtio-scsi driver appears to include  a slew of materials from FreeBSD's
# native SCSI implementation.  We will omit that complexity for now.
	#ctl_util.c		\
	#ctl_scsi_all.c		\
	#pci_virtio_scsi.c	\


OBJS = $(SRCS:.c=.o)

CLOBBERFILES =	$(ROOTUSRSBINPROG) $(ZHYVE)

ZHYVE_DIR =	$(ROOT)/usr/lib/brand/bhyve
ZHYVE_PROG =	zhyve
ZHYVE =		$(ZHYVE_DIR)/$(ZHYVE_PROG)

MEVENT_TEST_PROG = mevent_test
MEVENT_TEST_SRCS = mevent.c mevent_test.c
MEVENT_TEST_OBJS = $(MEVENT_TEST_SRCS:.c=.o)

CLEANFILES =	$(PROG) $(ZHYVE_PROG) $(MEVENT_TEST_PROG) $(MEVENT_TEST_OBJS)

CFLAGS +=	$(CCVERBOSE) -_gcc=-Wimplicit-function-declaration -_gcc=-Wno-parentheses
CPPFLAGS =	-I$(COMPAT)/freebsd -I$(CONTRIB)/freebsd \
		-I$(COMPAT)/freebsd/amd64 -I$(CONTRIB)/freebsd/amd64 \
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

# Disable the crypto code until it is wired up
CPPFLAGS +=	-DNO_OPENSSL

pci_nvme.o := CERRWARN += -_gcc=-Wno-pointer-sign

SMOFF += all_func_returns,leaks,no_if_block

# Force c99 for everything
CSTD=		$(CSTD_GNU99)
C99MODE=	-xc99=%all
C99LMODE=	-Xc99=%all

$(PROG) := LDLIBS += -lsocket -lnsl -ldlpi -ldladm -lmd -luuid -lvmmapi -lz
$(ZHYVE_PROG) := LDLIBS += -lnvpair
$(MEVENT_TEST_PROG) := LDLIBS += -lsocket

POST_PROCESS += ; $(GENSETDEFS) $@

.KEEP_STATE:

all: $(PROG) $(MEVENT_TEST_PROG) $(ZHYVE_PROG) $(SUBDIRS)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

$(MEVENT_TEST_PROG): $(MEVENT_TEST_OBJS)
	$(LINK.c) -o $@ $(MEVENT_TEST_OBJS) $(LDFLAGS) $(LDLIBS)

install: all $(ZHYVE) $(ROOTUSRSBINPROG) $(SUBDIRS)

clean: $(SUBDIRS)
	$(RM) $(OBJS) $(CLEANFILES)

clobber: clean $(SUBDIRS)
	$(RM) $(CLOBBERFILES)

lint:	lint_SRCS $(SUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include ../Makefile.targ

$(ZHYVE_DIR)/%: %
	$(INS.file)

%.o: $(SRC)/uts/i86pc/io/vmm/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

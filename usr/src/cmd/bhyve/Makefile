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
# Copyright 2020 Joyent, Inc.
# Copyright 2020 Oxide Computer Company
# Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
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

SRCS =	acpi.c			\
	acpi_device.c		\
	atkbdc.c		\
	basl.c			\
	bhyvegc.c		\
	bhyverun.c		\
	block_if.c		\
	bootrom.c		\
	config.c		\
	console.c		\
	crc16.c			\
	e820.c			\
	fwctl.c			\
	gdb.c			\
	hexdump.c		\
	inout.c			\
	ioapic.c		\
	iov.c			\
	mem.c			\
	mevent.c		\
	mptbl.c			\
	net_backends.c		\
	net_utils.c		\
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
	pci_virtio_9p.c		\
	pci_virtio_block.c	\
	pci_virtio_console.c	\
	pci_virtio_net.c	\
	pci_virtio_rnd.c	\
	pci_virtio_viona.c	\
	pci_xhci.c		\
	pctestdev.c		\
	pm.c			\
	post.c			\
	privileges.c		\
	ps2kbd.c		\
	ps2mouse.c		\
	qemu_fwcfg.c		\
	qemu_loader.c		\
	rfb.c			\
	rtc.c			\
	smbiostbl.c		\
	sockstream.c		\
	spinup_ap.c		\
	task_switch.c		\
	tpm_device.c		\
	tpm_emul_passthru.c	\
	tpm_intf_crb.c		\
	tpm_ppi_qemu.c		\
	uart_emul.c		\
	usb_emul.c		\
	usb_mouse.c		\
	vga.c			\
	virtio.c		\
	vmgenc.c		\
	xmsr.c			\
	bhyve_sol_glue.c

# We are not yet performing instruction emulation in userspace, so going to the
# trouble of fixing the header tangle for this is not worth the complexity.
	#kernemu_dev.c		\

# The virtio-scsi driver appears to include a slew of materials from FreeBSD's
# native SCSI implementation.  We will omit that complexity for now.
	#ctl_util.c		\
	#ctl_scsi_all.c		\
	#pci_virtio_scsi.c	\

# The audio backend in FreeBSD is different than the one found in audio_oss.h
	#audio.c		\
	#hda_codec.c		\
	#pci_hda.c		\

# The virtio input device expects to link to a FreeBSD /dev/input/eventX device
	#pci_virtio_input.c	\

OBJS = $(SRCS:.c=.o)

ZHYVE_DIR =	$(ROOT)/usr/lib/brand/bhyve
ZHYVE_PROG =	zhyve
ZHYVE =		$(ZHYVE_DIR)/$(ZHYVE_PROG)

MEVENT_TEST_PROG = mevent_test
MEVENT_TEST_SRCS = mevent.c mevent_test.c
MEVENT_TEST_OBJS = $(MEVENT_TEST_SRCS:.c=.o)

CLEANFILES =	$(OBJS) $(MEVENT_TEST_OBJS)
CLOBBERFILES =	$(PROG) $(MEVENT_TEST_PROG) $(ZHYVE_PROG)

CFLAGS +=	$(CCVERBOSE)
CFLAGS +=	-_gcc=-Wimplicit-function-declaration
CPPFLAGS =	-I$(COMPAT)/bhyve -I$(CONTRIB)/bhyve \
		-I$(COMPAT)/bhyve/amd64 -I$(CONTRIB)/bhyve/amd64 \
		-I$(CONTRIB)/bhyve/dev/usb/controller \
		-I$(CONTRIB)/bhyve/dev/mii \
		-I$(SRC)/lib/lib9p/common \
		-I$(SRC)/uts/common/io/e1000api \
		$(CPPFLAGS.master) \
		-I$(SRC)/uts/intel/io/vmm \
		-I$(SRC)/uts/common \
		-I$(SRC)/uts/intel \
		-I$(SRC)/lib/libdladm/common \
		-DWITHOUT_CAPSICUM \
		-DOPENSSL_API_COMPAT=0x10100000L

SMOFF += all_func_returns
rfb.o := SMOFF=

# Force c99 for everything
CSTD=		$(CSTD_GNU99)

$(PROG) := LDLIBS += \
	-l9p \
	-lcmdutils \
	-ldladm \
	-ldlpi \
	-lidspace \
	-lmd \
	-lnsl \
	-lnvpair \
	-lsocket \
	-lsunw_crypto \
	-lumem \
	-luuid \
	-lvmmapi \
	-lz
NATIVE_LIBS += libz.so libsunw_crypto.so
$(ZHYVE_PROG) := LDLIBS += -lnvpair
$(MEVENT_TEST_PROG) := LDLIBS += -lsocket
$(PROG) := LDFLAGS += $(ZASLR)

.KEEP_STATE:

all: $(PROG) $(MEVENT_TEST_PROG) $(ZHYVE_PROG) $(SUBDIRS)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

$(MEVENT_TEST_PROG): $(MEVENT_TEST_OBJS)
	$(LINK.c) -o $@ $(MEVENT_TEST_OBJS) $(LDFLAGS) $(LDLIBS)

install: all $(ZHYVE) $(ROOTUSRSBINPROG) $(SUBDIRS)

clean: $(SUBDIRS)
	$(RM) $(CLEANFILES)

clobber: clean $(SUBDIRS)
	$(RM) $(CLOBBERFILES)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include ../Makefile.targ

$(ZHYVE_DIR)/%: %
	$(INS.file)

%.o: $(SRC)/uts/intel/io/vmm/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

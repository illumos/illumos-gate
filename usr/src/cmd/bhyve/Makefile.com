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
# Copyright 2024 OmniOS Community Edition (OmniOSce) Association.
# Copyright 2026 Hans Rosenfeld
#

PROG =		bhyve

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.cmd.64
include $(SRC)/cmd/Makefile.ctf

COMMON_OBJS = \
	acpi.o			\
	acpi_device.o		\
	basl.o			\
	bhyvegc.o		\
	bhyverun.o		\
	block_if.o		\
	bootrom.o		\
	config.o		\
	console.o		\
	crc16.o			\
	gdb.o			\
	hexdump.o		\
	ilstr.o			\
	iov.o			\
	mem.o			\
	mevent.o		\
	net_backend_dlpi.o	\
	net_backends.o		\
	net_utils.o		\
	pci_ahci.o		\
	pci_e82545.o		\
	pci_emul.o		\
	pci_hostbridge.o	\
	pci_irq.o		\
	pci_nvme.o		\
	pci_uart.o		\
	pci_virtio_9p.o		\
	pci_virtio_block.o	\
	pci_virtio_console.o	\
	pci_virtio_net.o	\
	pci_virtio_rnd.o	\
	pci_virtio_scsi.o	\
	pci_virtio_scsi_uscsi.o	\
	pci_virtio_viona.o	\
	pci_xhci.o		\
	privileges.o		\
	qemu_fwcfg.o		\
	qemu_loader.o		\
	smbiostbl.o		\
	sockstream.o		\
	tpm_device.o		\
	tpm_emul_passthru.o	\
	tpm_emul_swtpm.o	\
	tpm_intf_crb.o		\
	tpm_ppi_qemu.o		\
	uart_backend.o		\
	uart_emul.o		\
	usb_emul.o		\
	usb_mouse.o		\
	virtio.o		\
	vmgenc.o		\
	bhyve_sol_glue.o

CFLAGS64 +=	$(CCVERBOSE)
CFLAGS64 +=	-_gcc=-Wimplicit-function-declaration

CPPFLAGS =	-I../common \
		-I$(COMPAT)/bhyve -I$(CONTRIB)/bhyve \
		-I$(COMPAT)/bhyve/amd64 -I$(CONTRIB)/bhyve/amd64 \
		-I$(CONTRIB)/bhyve/dev/usb/controller \
		-I$(CONTRIB)/bhyve/dev/mii \
		-I$(SRC)/lib/lib9p/common \
		-I$(SRC)/uts/common/io/e1000api \
		$(CPPFLAGS.master) \
		-I$(SRC)/uts/intel/io/vmm \
		-I$(SRC)/uts/common \
		-I$(SRC)/uts/intel \
		-DWITHOUT_CAPSICUM \
		-DOPENSSL_API_COMPAT=10101

SMOFF += all_func_returns
pics/rfb.o := SMOFF=
pics/pci_virtio_scsi_uscsi.o := SMOFF=
pics/pci_virtio_scsi_uscsi.o := CFLAGS64 += -_gcc=-Wswitch-default

CSTD=		$(CSTD_GNU99)

$(PROG) := LDLIBS += \
	-l9p \
	-lcmdutils \
	-lcrypto \
	-ldladm \
	-ldlpi \
	-lidspace \
	-lmd \
	-lnsl \
	-lnvpair \
	-lscsi \
	-lsocket \
	-lumem \
	-luuid \
	-lvmmapi \
	-lz
NATIVE_LIBS += libz.so libcrypto.so
$(PROG) := LDFLAGS += $(ZASLR)
$(PROG) := LDFLAGS += -Wl,-L$(ROOT)/usr/lib/scsi/$(MACH64)
$(PROG) := LDFLAGS += -Wl,-R/usr/lib/scsi/$(MACH64)

OBJS =		$(BHYVE_OBJS:%=pics/%)

CLEANFILES =	$(OBJS)
CLOBBERFILES =	$(PROG)

all: pics $(PROG)

clean:
	$(RM) $(CLEANFILES)

clobber: clean
	$(RM) $(CLOBBERFILES)

pics: FRC
	$(MKDIR) -p $@

pics/%.o: ../common/%.c
	$(COMPILE.c) $< -o $@
	$(POST_PROCESS_O)

pics/%.o: %.c
	$(COMPILE.c) $< -o $@
	$(POST_PROCESS_O)

pics/%.o: $(SRC)/common/hexdump/%.c
	$(COMPILE.c) $< -o $@
	$(POST_PROCESS_O)

pics/%.o: $(SRC)/common/ilstr/%.c
	$(COMPILE.c) $< -o $@
	$(POST_PROCESS_O)

$(PROG): pics $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

FRC:

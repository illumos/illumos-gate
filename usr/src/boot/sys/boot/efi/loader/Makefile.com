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
# Copyright 2016 Toomas Soome <tsoome@me.com>
#

include $(SRC)/Makefile.master
include $(SRC)/boot/Makefile.version
include $(SRC)/boot/sys/boot/Makefile.inc

CC=		$(GNUC_ROOT)/bin/gcc
LD=		$(GNU_ROOT)/bin/gld
OBJCOPY=	$(GNU_ROOT)/bin/gobjcopy
OBJDUMP=	$(GNU_ROOT)/bin/gobjdump

PROG=		loader.sym

PNGLITE=	$(SRC)/common/pnglite

# architecture-specific loader code
SRCS=	\
	acpi.c \
	autoload.c \
	bootinfo.c \
	conf.c \
	copy.c \
	efi_main.c \
	font.c \
	$(FONT).c \
	framebuffer.c \
	list.c \
	main.c \
	memmap.c \
	multiboot.S \
	multiboot2.c \
	self_reloc.c \
	smbios.c \
	tem.c \
	vers.c

OBJS=	\
	acpi.o \
	autoload.o \
	bootinfo.o \
	conf.o \
	copy.o \
	efi_main.o \
	font.o \
	$(FONT).o \
	framebuffer.o \
	list.o \
	main.o \
	memmap.o \
	multiboot.o \
	multiboot2.o \
	self_reloc.o \
	smbios.o \
	tem.o \
	vers.o

CFLAGS=	-Os
CPPFLAGS= -nostdinc -I../../../../../include -I../../..../
CPPFLAGS += -I../../../../../lib/libstand
CPPFLAGS += -I../../../../../lib/libz

include ../../Makefile.inc

include ../arch/$(MACHINE)/Makefile.inc

CPPFLAGS +=	-I. -I..
CPPFLAGS +=	-I../../include
CPPFLAGS +=	-I../../include/$(MACHINE)
CPPFLAGS +=	-I../../../..
CPPFLAGS +=	-I../../../i386/libi386
CPPFLAGS +=	-I../../../zfs
CPPFLAGS +=	-I../../../../cddl/boot/zfs
CPPFLAGS +=	-I$(SRC)/uts/intel/sys/acpi
CPPFLAGS +=	-I$(PNGLITE)
CPPFLAGS +=	-DNO_PCI -DEFI

# Export serial numbers, UUID, and asset tag from loader.
smbios.o := CPPFLAGS += -DSMBIOS_SERIAL_NUMBERS
# Use little-endian UUID format as defined in SMBIOS 2.6.
smbios.o := CPPFLAGS += -DSMBIOS_LITTLE_ENDIAN_UUID
# Use network-endian UUID format for backward compatibility.
#CPPFLAGS += -DSMBIOS_NETWORK_ENDIAN_UUID

LIBSTAND=	../../../libstand/$(MACHINE)/libstand.a

BOOT_FORTH=	yes
CPPFLAGS +=	-DBOOT_FORTH -D_STANDALONE
CPPFLAGS +=	-I$(SRC)/common/ficl
CPPFLAGS +=	-I../../../libficl
LIBFICL=	../../../libficl/$(MACHINE)/libficl.a

CPPFLAGS +=	-I../../../zfs
LIBZFSBOOT=	../../../zfs/$(MACHINE)/libzfsboot.a

# Always add MI sources
include	../Makefile.common
CPPFLAGS +=	-I../../../common

# For multiboot2.h, must be last, to avoid conflicts
CPPFLAGS +=	-I$(SRC)/uts/common

FILES=		$(EFIPROG)
FILEMODE=	0555
ROOT_BOOT=	$(ROOT)/boot
ROOTBOOTFILES=$(FILES:%=$(ROOT_BOOT)/%)

LDSCRIPT=	../arch/$(MACHINE)/ldscript.$(MACHINE)
LDFLAGS =	-nostdlib --eh-frame-hdr
LDFLAGS +=	-shared --hash-style=both --enable-new-dtags
LDFLAGS +=	-T$(LDSCRIPT) -Bsymbolic

CLEANFILES=	loader.sym loader.bin
CLEANFILES +=	$(FONT).c vers.c

NEWVERSWHAT=	"EFI loader" $(MACHINE)

install: all $(ROOTBOOTFILES)

vers.c:	../../../common/newvers.sh $(SRC)/boot/Makefile.version
	$(SH) ../../../common/newvers.sh $(LOADER_VERSION) $(NEWVERSWHAT)

$(EFIPROG): loader.bin
	$(BTXLD) -V $(BOOT_VERSION) -o $@ loader.bin

loader.bin: loader.sym
	if [ `$(OBJDUMP) -t loader.sym | fgrep '*UND*' | wc -l` != 0 ]; then \
		$(OBJDUMP) -t loader.sym | fgrep '*UND*'; \
		exit 1; \
	fi
	$(OBJCOPY) --readonly-text -j .peheader -j .text -j .sdata -j .data \
		-j .dynamic -j .dynsym -j .rel.dyn \
		-j .rela.dyn -j .reloc -j .eh_frame -j set_Xcommand_set \
		-j set_Xficl_compile_set \
		--output-target=$(EFI_TARGET) --subsystem efi-app loader.sym $@

LIBEFI=		../../libefi/$(MACHINE)/libefi.a
LIBCRYPTO=	../../../libcrypto/$(MACHINE)/libcrypto.a

DPADD=		$(LIBFICL) $(LIBZFSBOOT) $(LIBEFI) $(LIBCRYPTO) $(LIBSTAND) \
		$(LDSCRIPT)
LDADD=		$(LIBFICL) $(LIBZFSBOOT) $(LIBEFI) $(LIBCRYPTO) $(LIBSTAND)


loader.sym:	$(OBJS) $(DPADD)
	$(LD) $(LDFLAGS) -o $@ $(OBJS) $(LDADD)

machine:
	$(RM) machine
	$(SYMLINK) ../../../../$(MACHINE)/include machine

x86:
	$(RM) x86
	$(SYMLINK) ../../../../x86/include x86

clean clobber:
	$(RM) $(CLEANFILES) $(OBJS)

%.o:	../%.c
	$(COMPILE.c) $<

%.o:	../arch/$(MACHINE)/%.c
	$(COMPILE.c) $<

#
# using -W to silence gas here, as for 32bit build, it will generate warning
# for start.S because hand crafted .reloc section does not have group name
#
%.o:	../arch/$(MACHINE)/%.S
	$(COMPILE.S) -Wa,-W $<

%.o:	../../../common/%.S
	$(COMPILE.S) $<

%.o:	../../../common/%.c
	$(COMPILE.c) $<

%.o:	../../../common/linenoise/%.c
	$(COMPILE.c) $<

%.o: ../../../i386/libi386/%.c
	$(COMPILE.c) $<

%.o: $(SRC)/common/list/%.c
	$(COMPILE.c) -DNDEBUG $<

%.o: $(SRC)/common/font/%.c
	$(COMPILE.c) $<

$(FONT).c: $(FONT_DIR)/$(FONT_SRC)
	$(VTFONTCVT) -f compressed-source -o $@ $(FONT_DIR)/$(FONT_SRC)

$(ROOT_BOOT)/%: %
	$(INS.file)

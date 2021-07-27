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
# Copyright 2015 Toomas Soome <tsoome@me.com>
# Copyright 2016 RackTop Systems.
#

include $(SRC)/Makefile.master
include $(SRC)/boot/sys/boot/Makefile.inc

CPPFLAGS += -I../../../../include -I../../..
CPPFLAGS += -I$(ZFSSRC)

all install: libi386.a

clean: clobber
clobber:
	$(RM) machine x86 $(OBJS) libi386.a

SRCS=	\
	amd64_tramp.S \
	bio.c \
	biosacpi.c \
	biosdisk.c \
	biosmem.c \
	biospci.c \
	biospnp.c \
	biossmap.c \
	bootinfo.c \
	bootinfo32.c \
	bootinfo64.c \
	comconsole.c \
	cpuid.c \
	devicename.c \
	elf32_freebsd.c \
	elf64_freebsd.c \
	i386_copy.c \
	i386_module.c \
	linux.c \
	multiboot.c \
	multiboot_tramp.S \
	nullconsole.c \
	pxe.c \
	pxetramp.s \
	relocater_tramp.S \
	smbios.c \
	spinconsole.c \
	time.c \
	vbe.c \
	vgasubr.c \
	vidconsole.c

OBJS=	\
	amd64_tramp.o \
	bio.o \
	biosacpi.o \
	biosdisk.o \
	biosmem.o \
	biospci.o \
	biospnp.o \
	biossmap.o \
	bootinfo.o \
	bootinfo32.o \
	bootinfo64.o \
	comconsole.o \
	cpuid.o \
	devicename.o \
	elf32_freebsd.o \
	elf64_freebsd.o \
	i386_copy.o \
	i386_module.o \
	linux.o \
	multiboot.o \
	multiboot_tramp.o \
	nullconsole.o \
	pxe.o \
	pxetramp.o \
	relocater_tramp.o \
	smbios.o \
	spinconsole.o \
	time.o \
	vbe.o \
	vgasubr.o \
	vidconsole.o

COMMON=  ../../common
VGASUBR=$(SRC)/common/vga
CPPFLAGS += -I$(PNGLITE)
SRCS +=	$(COMMON)/gfx_fb.c $(PNGLITE)/pnglite.c
OBJS +=	gfx_fb.o pnglite.o

gfx_fb.o := CPPFLAGS += $(DEFAULT_CONSOLE_COLOR) -I$(LZ4)
pnglite.o := CPPFLAGS += -I$(ZLIB)

SRCS +=	$(ZFSSRC)/devicename_stubs.c
OBJS +=	devicename_stubs.o

BOOT_COMCONSOLE_PORT= 0x3f8
CPPFLAGS +=	-DCOMPORT=${BOOT_COMCONSOLE_PORT}

BOOT_COMCONSOLE_SPEED= 9600
CPPFLAGS +=	-DCOMSPEED=${BOOT_COMCONSOLE_SPEED}

# Make the disk code more talkative
# CPPFLAGS+= -DDISK_DEBUG

# Export serial numbers, UUID, and asset tag from loader.
smbios.o := CPPFLAGS += -DSMBIOS_SERIAL_NUMBERS
# Use little-endian UUID format as defined in SMBIOS 2.6.
smbios.o := CPPFLAGS += -DSMBIOS_LITTLE_ENDIAN_UUID
# Use network-endian UUID format for backward compatibility.
#CPPFLAGS += -DSMBIOS_NETWORK_ENDIAN_UUID

# XXX: make alloca() useable
CPPFLAGS += -Dalloca=__builtin_alloca

CPPFLAGS +=	-I$(SRC)/common/ficl -I../../libficl \
		-I../../common -I../common \
		-I../btx/lib \
		-I$(SRC)/uts/intel/sys/acpi \
		-I../../.. -I.
# the location of libstand
CPPFLAGS +=	-I../../../../lib/libstand/

multiboot.o := CPPFLAGS += -I../../../cddl/boot/zfs
multiboot2.o := CPPFLAGS += -I../../../cddl/boot/zfs
devicename.o := CPPFLAGS += -I../../../cddl/boot/zfs
devicename_stubs.o := CPPFLAGS += -I../../../cddl/boot/zfs

CLEANFILES +=	machine x86

include ../Makefile.inc

# For multiboot2.h, must be last, to avoid conflicts
CPPFLAGS +=	-I$(SRC)/uts/common

machine:
	$(RM) machine
	$(SYMLINK) ../../../i386/include machine

x86:
	$(RM) x86
	$(SYMLINK) ../../../x86/include x86

$(OBJS): machine x86

libi386.a: $(OBJS)
	$(AR) $(ARFLAGS) $@ $(OBJS)

%.o:	$(ZFSSRC)/%.c
	$(COMPILE.c) -o $@ $<

%.o:	$(COMMON)/%.c
	$(COMPILE.c) -o $@ $<

%.o:	$(PNGLITE)/%.c
	$(COMPILE.c) -o $@ $<

%.o:	$(VGASUBR)/%.c
	$(COMPILE.c) -o $@ $<

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
include $(SRC)/boot/Makefile.inc

install:

OBJS +=	\
	acpi.o \
	delay.o \
	devicename.o \
	devpath.o \
	efi_console.o \
	efi_driver_utils.o \
	efichar.o \
	efienv.o \
	efinet.o \
	efipart.o \
	efiserialio.o \
	efiisaio.o \
	efizfs.o \
	env.o \
	errno.o \
	gfx_fb.o \
	handles.o \
	libefi.o \
	pnglite.o \
	wchar.o

CPPFLAGS += -DEFI
CPPFLAGS += -I. -I../../../include -I../../../sys
CPPFLAGS += -I$(SRC)/common/ficl -I../../../libficl
CPPFLAGS += -I../../include
CPPFLAGS += -I../../include/$(MACHINE)
CPPFLAGS += -I../../../libsa
CPPFLAGS += -I$(ZFSSRC)
CPPFLAGS += -I../../../sys/cddl/boot/zfs

acpi.o := CPPFLAGS += -I$(SRC)/uts/intel/sys/acpi
gfx_fb.o := CPPFLAGS += $(DEFAULT_CONSOLE_COLOR) -I$(LZ4)
pnglite.o := CPPFLAGS += -I$(ZLIB)
gfx_fb.o pnglite.o efi_console.o := CPPFLAGS += -I$(PNGLITE)

# Pick up the bootstrap header for some interface items
CPPFLAGS += -I../../../common

include ../../Makefile.inc

# For multiboot2.h, must be last, to avoid conflicts
CPPFLAGS +=	-I$(SRC)/uts/common

libefi.a: $(OBJS)
	$(AR) $(ARFLAGS) $@ $(OBJS)

clean: clobber
clobber:
	$(RM) $(CLEANFILES) $(OBJS) libefi.a

machine:
	$(RM) machine
	$(SYMLINK) ../../../sys/$(MACHINE)/include machine

x86:
	$(RM) x86
	$(SYMLINK) ../../../sys/x86/include x86

%.o:	../%.c
	$(COMPILE.c) $<

%.o:	../../../common/%.c
	$(COMPILE.c) $<

%.o:	$(PNGLITE)/%.c
	$(COMPILE.c) $<

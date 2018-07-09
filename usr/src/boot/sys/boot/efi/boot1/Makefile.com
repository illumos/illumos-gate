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

CC=	$(GNUC_ROOT)/bin/gcc
LD=	$(GNU_ROOT)/bin/gld
OBJCOPY= $(GNU_ROOT)/bin/gobjcopy
OBJDUMP= $(GNU_ROOT)/bin/gobjdump

PROG=		boot1.sym

# architecture-specific loader code
SRCS=	multiboot.S boot1.c self_reloc.c start.S ufs_module.c zfs_module.c \
	devopen.c
OBJS=	multiboot.o boot1.o self_reloc.o start.o ufs_module.o zfs_module.o \
	devopen.o

CFLAGS= -O2
CPPFLAGS=	-nostdinc -D_STANDALONE

zfs_module.o := CFLAGS += -Wno-unused-function

CPPFLAGS +=	-I.
CPPFLAGS +=	-I../../include
CPPFLAGS +=	-I../../include/$(MACHINE)
CPPFLAGS +=	-I../../../../../include
CPPFLAGS +=	-I../../../../sys
CPPFLAGS +=	-I../../../..
CPPFLAGS +=	-I../../../../../lib/libstand
CPPFLAGS +=	-DUFS1_ONLY
# CPPFLAGS +=	-DEFI_DEBUG

CPPFLAGS +=	-I../../../zfs/
CPPFLAGS +=	-I../../../../cddl/boot/zfs/

# Always add MI sources and REGULAR efi loader bits
CPPFLAGS +=	-I../../../common

# For sys/skein.h
CPPFLAGS +=	-I$(SRC)/uts/common

include ../../Makefile.inc

FILES=  $(EFIPROG)
FILEMODE=	0555
ROOT_BOOT=	$(ROOT)/boot
ROOTBOOTFILES=$(FILES:%=$(ROOT_BOOT)/%)

LDSCRIPT=	../../loader/arch/$(MACHINE)/ldscript.$(MACHINE)
LDFLAGS=	-nostdlib --eh-frame-hdr
LDFLAGS +=	-shared --hash-style=both --enable-new-dtags
LDFLAGS +=	-T$(LDSCRIPT) -Bsymbolic

install: all $(ROOTBOOTFILES)

LIBEFI=		../../libefi/$(MACHINE)/libefi.a
#
# Add libstand for the runtime functions used by the compiler - for example
# __aeabi_* (arm) or __divdi3 (i386).
# as well as required string and memory functions for all platforms.
#
LIBSTAND=	../../../libstand/$(MACHINE)/libstand.a
LIBZFSBOOT=	../../../zfs/$(MACHINE)/libzfsboot.a
DPADD=		$(LIBEFI) $(LIBZFSBOOT) $(LIBSTAND)
LDADD=		-L../../libefi/$(MACHINE) -lefi
LDADD +=	-L../../../zfs/$(MACHINE) -lzfsboot
LDADD +=	-L../../../libstand/$(MACHINE) -lstand

DPADD +=	$(LDSCRIPT)

$(EFIPROG): $(PROG)
	if [ `$(OBJDUMP) -t $(PROG) | fgrep '*UND*' | wc -l` != 0 ]; then \
		$(OBJDUMP) -t $(PROG) | fgrep '*UND*'; \
		exit 1; \
	fi
	$(OBJCOPY) --readonly-text -j .peheader -j .text -j .sdata -j .data \
		-j .dynamic -j .dynsym -j .rel.dyn \
		-j .rela.dyn -j .reloc -j .eh_frame \
		--output-target=$(EFI_TARGET) --subsystem efi-app $(PROG) $@
	$(BTXLD) -V $(BOOT_VERSION) -o $@ $@

boot1.o: ../../../common/ufsread.c

CLEANFILES= $(EFIPROG) $(PROG)

$(PROG):	$(OBJS) $(DPADD)
	$(LD) $(LDFLAGS) -o $@ $(OBJS) $(LDADD)

machine:
	$(RM) machine
	$(SYMLINK) ../../../../$(MACHINE)/include machine

x86:
	$(RM) x86
	$(SYMLINK) ../../../../x86/include x86

clean clobber:
	$(RM) $(CLEANFILES) $(OBJS)

%.o:	../../../common/%.S
	$(COMPILE.S) $<

%.o:	../%.c
	$(COMPILE.c) $<

#
# using -W to silence gas here, as for 32bit build, it will generate warning
# for start.S because hand crafted .reloc section does not have group name
#
%.o:	../../loader/arch/$(MACHINE)/%.S
	$(COMPILE.S) -Wa,-W $<

%.o:	../../loader/%.c
	$(COMPILE.c) $<

%.o:	../../../common/%.c
	$(COMPILE.c) $<

$(ROOT_BOOT)/%: %
	$(INS.file)

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
# Copyright 2016 RackTop Systems.
#

include $(SRC)/Makefile.master
include $(SRC)/boot/Makefile.version

CC=	$(GNUC_ROOT)/bin/gcc
LD=	$(GNU_ROOT)/bin/gld
OBJCOPY= $(GNU_ROOT)/bin/gobjcopy
OBJDUMP= $(GNU_ROOT)/bin/gobjdump

PROG=		boot1.sym
MACHINE=$(MACH64)

# architecture-specific loader code
SRCS=	multiboot.S boot1.c self_reloc.c start.S ufs_module.c zfs_module.c \
	devopen.c
OBJS=	multiboot.o boot1.o self_reloc.o start.o ufs_module.o zfs_module.o \
	devopen.o

ASFLAGS=-m64 -fPIC
CFLAGS= -O2
CPPFLAGS=	-nostdinc -D_STANDALONE
CPPFLAGS +=	-I.
CPPFLAGS +=	-I./../include
CPPFLAGS +=	-I./../include/${MACHINE}
CPPFLAGS +=	-I$(SRC)/uts/intel/sys/acpi
CPPFLAGS +=	-I./../../../../include
CPPFLAGS +=	-I./../../../sys
CPPFLAGS +=	-I./../../..
CPPFLAGS +=	-I../../../../lib/libstand
CPPFLAGS +=	-DUFS1_ONLY
# CPPFLAGS +=	-DEFI_DEBUG

CPPFLAGS +=	-I./../../zfs/
CPPFLAGS +=	-I./../../../cddl/boot/zfs/

# Always add MI sources and REGULAR efi loader bits
CPPFLAGS +=	-I./../../common

# For sys/skein.h
CPPFLAGS +=	-I$(SRC)/uts/common

include ../Makefile.inc

FILES=  boot1.efi
FILEMODE=	0555
ROOT_BOOT=	$(ROOT)/boot
ROOTBOOTFILES=$(FILES:%=$(ROOT_BOOT)/%)

LDSCRIPT=	./../loader/arch/${MACHINE}/ldscript.${MACHINE}
LDFLAGS=	-nostdlib --eh-frame-hdr -znocombreloc
LDFLAGS +=	-shared --hash-style=both --enable-new-dtags
LDFLAGS +=	-T${LDSCRIPT} -Bsymbolic

all: boot1.efi

install: all $(ROOTBOOTFILES)

LIBEFI=		../libefi/libefi.a
#
# Add libstand for the runtime functions used by the compiler - for example
# __aeabi_* (arm) or __divdi3 (i386).
# as well as required string and memory functions for all platforms.
#
LIBSTAND=	../../libstand/$(MACH64)/libstand.a
LIBZFSBOOT=	../../zfs/$(MACH64)/libzfsboot.a
DPADD=		$(LIBEFI) $(LIBZFSBOOT) $(LIBSTAND)
LDADD=		-L../libefi -lefi
LDADD +=	-L../../zfs/$(MACH64) -lzfsboot
LDADD +=	-L../../libstand/$(MACH64) -lstand

DPADD +=	${LDSCRIPT}

EFI_TARGET=	pei-x86-64

boot1.efi: ${PROG}
	if [ `${OBJDUMP} -t ${PROG} | fgrep '*UND*' | wc -l` != 0 ]; then \
		${OBJDUMP} -t ${PROG} | fgrep '*UND*'; \
		exit 1; \
	fi
	${OBJCOPY} --readonly-text -j .peheader -j .text -j .sdata -j .data \
		-j .dynamic -j .dynsym -j .rel.dyn \
		-j .rela.dyn -j .reloc -j .eh_frame \
		--output-target=${EFI_TARGET} --subsystem efi-app ${PROG} $@
	$(BTXLD) -V ${BOOT_VERSION} -o $@ $@

boot1.o: ./../../common/ufsread.c

CLEANFILES= boot1.efi ${PROG}

${PROG}:	$(OBJS) $(DPADD)
	$(LD) $(LDFLAGS) -o $@ $(OBJS) $(LDADD)

CLEANFILES +=   machine x86

machine:
	$(RM) machine
	$(SYMLINK) ./../../../${MACHINE}/include machine

x86:
	$(RM) x86
	$(SYMLINK) ./../../../x86/include x86

$(OBJS): machine x86

clean clobber:
	$(RM) $(CLEANFILES) $(OBJS)

%.o:	../loader/arch/${MACHINE}/%.S
	$(COMPILE.S) $<

%.o:	../loader/%.c
	$(COMPILE.c) $<

%.o:	../../common/%.S
	$(COMPILE.S) $<

%.o:	../../common/%.c
	$(COMPILE.c) $<

$(ROOT_BOOT)/%: %
	$(INS.file)

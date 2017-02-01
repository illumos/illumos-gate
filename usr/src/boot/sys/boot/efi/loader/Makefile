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

CC=		$(GCC_ROOT)/bin/gcc
LD=		$(GNU_ROOT)/bin/gld
OBJCOPY=	$(GNU_ROOT)/bin/gobjcopy
OBJDUMP=	$(GNU_ROOT)/bin/gobjdump

PROG=		loader.sym
MACHINE=	$(MACH64)

# architecture-specific loader code
SRCS=	autoload.c bootinfo.c conf.c copy.c devicename.c main.c self_reloc.c \
	smbios.c acpi.c vers.c
OBJS= autoload.o bootinfo.o conf.o copy.o devicename.o main.o self_reloc.o \
	smbios.o acpi.o vers.o

ASFLAGS=-m64 -fPIC
CFLAGS=	-O2
CPPFLAGS= -nostdinc -I../../../../include -I../../..
CPPFLAGS += -I../../../../lib/libstand

include ../Makefile.inc

include arch/${MACHINE}/Makefile.inc

CPPFLAGS +=	-I.
CPPFLAGS +=	-I./arch/${MACHINE}
CPPFLAGS +=	-I./../include
CPPFLAGS +=	-I./../include/${MACHINE}
CPPFLAGS +=	-I$(SRC)/uts/intel/sys/acpi
CPPFLAGS +=	-I./../../..
CPPFLAGS +=	-I./../../i386/libi386
CPPFLAGS +=	-I./../../zfs
CPPFLAGS +=	-I./../../../cddl/boot/zfs
CPPFLAGS +=	-DEFI_ZFS_BOOT
CPPFLAGS +=	-DNO_PCI -DEFI -DTERM_EMU

LIBSTAND=	../../libstand/${MACHINE}/libstand.a

BOOT_FORTH=	yes
CPPFLAGS +=	-DBOOT_FORTH -DSTAND
CPPFLAGS +=	-I$(SRC)/common/ficl
CPPFLAGS +=	-I../../ficl
LIBFICL=	../../ficl/${MACHINE}/libficl.a

CPPFLAGS +=	-I../../zfs
LIBZFSBOOT=	../../zfs/${MACHINE}/libzfsboot.a

#LOADER_FDT_SUPPORT?=	no
#.if ${MK_FDT} != "no" && ${LOADER_FDT_SUPPORT} != "no"
#CFLAGS+=	-I${.CURDIR}/../../fdt
#CFLAGS+=	-I${.OBJDIR}/../../fdt
#CFLAGS+=	-DLOADER_FDT_SUPPORT
#LIBEFI_FDT=	${.OBJDIR}/../../efi/fdt/libefi_fdt.a
#LIBFDT=		${.OBJDIR}/../../fdt/libfdt.a
#.endif

# Always add MI sources
include	./Makefile.common
CPPFLAGS +=	-I../../common

FILES=	loader.efi
FILEMODE=	0555
ROOT_BOOT=	$(ROOT)/boot
ROOTBOOTFILES=$(FILES:%=$(ROOT_BOOT)/%)

LDSCRIPT=	./arch/${MACHINE}/ldscript.${MACHINE}
LDFLAGS =	-nostdlib --eh-frame-hdr -znocombreloc
LDFLAGS +=	-shared --hash-style=both --enable-new-dtags
LDFLAGS +=	-T${LDSCRIPT} -Bsymbolic

CLEANFILES=	vers.c loader.efi

NEWVERSWHAT=	"EFI loader" ${MACHINE}

all: loader.efi

install: all $(ROOTBOOTFILES)

vers.c:	../../common/newvers.sh ../../efi/loader/version
	$(SH) ../../common/newvers.sh version ${NEWVERSWHAT}

EFI_TARGET=	pei-x86-64

loader.efi: loader.sym
	if [ `${OBJDUMP} -t loader.sym | fgrep '*UND*' | wc -l` != 0 ]; then \
		${OBJDUMP} -t loader.sym | fgrep '*UND*'; \
		exit 1; \
	fi
	${OBJCOPY} --readonly-text -j .peheader -j .text -j .sdata -j .data \
		-j .dynamic -j .dynsym -j .rel.dyn \
		-j .rela.dyn -j .reloc -j .eh_frame -j set_Xcommand_set \
		--output-target=${EFI_TARGET} --subsystem efi-app loader.sym $@

LIBEFI=		../libefi/libefi.a

DPADD=		${LIBFICL} ${LIBZFSBOOT} ${LIBEFI} ${LIBFDT} ${LIBEFI_FDT} \
		${LIBSTAND} ${LDSCRIPT}
LDADD=		${LIBFICL} ${LIBZFSBOOT} ${LIBEFI} ${LIBFDT} ${LIBEFI_FDT} \
		${LIBSTAND}


loader.sym:	$(OBJS) $(DPADD)
	$(LD) $(LDFLAGS) -o $@ $(OBJS) $(LDADD)

CLEANFILES +=   machine x86

machine:
	$(RM) machine
	$(SYMLINK) ../../../${MACHINE}/include machine

x86:
	$(RM) x86
	$(SYMLINK) ../../../x86/include x86

$(OBJS): machine x86

clean clobber:
	$(RM) $(CLEANFILES) $(OBJS) loader.sym loader.efi

%.o:	%.c
	$(COMPILE.c) $<

%.o:	./arch/${MACHINE}/%.c
	$(COMPILE.c) $<

%.o:	./arch/${MACHINE}/%.S
	$(COMPILE.S) $<

%.o:	../../common/%.c
	$(COMPILE.c) $<

%.o:	../../common/linenoise/%.c
	$(COMPILE.c) $<

%.o: ../../i386/libi386/%.c
	$(COMPILE.c) $<

$(ROOT_BOOT)/%: %
	$(INS.file)

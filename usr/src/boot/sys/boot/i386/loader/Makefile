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

CFLAGS= -O2
CPPFLAGS= -DSTAND -nostdinc -I../../../../include -I../../..
LOADER=		zfsloader
NEWVERSWHAT=	"ZFS enabled bootstrap loader" x86
MAN=

# Set by zfsloader Makefile
CPPFLAGS +=	-DLOADER_ZFS_SUPPORT -I../../zfs
CPPFLAGS +=	-I../libi386
LIBZFSBOOT=	../../zfs/i386/libzfsboot.a
LIBI386=        ../libi386/libi386.a

# loader.help build needs better awk
AWK=		/usr/xpg4/bin/awk
LD=		$(GNU_ROOT)/bin/gld
CC=		$(GCC_ROOT)/bin/gcc
OBJCOPY=	$(GNU_ROOT)/bin/gobjcopy
GSTRIP=		$(GNU_ROOT)/bin/gstrip
ROOT_BOOT=	$(ROOT)/boot
ROOT_BOOT_DEFAULTS=	$(ROOT)/boot/defaults
ROOT_BOOT_FORTH=	$(ROOT)/boot/forth
ROOT_BOOT_CONF=		$(ROOT)/boot/conf.d
ROOTBOOTFILES=$(FILES:%=$(ROOT_BOOT)/%)
ROOTBOOTFORTH=$(FORTH:%=$(ROOT_BOOT_FORTH)/%)
ROOTBOOTDEFAULTS=$(DEFFILES:%=$(ROOT_BOOT_DEFAULTS)/%)
FILEMODE=0444

all: ${LOADER} loader.help

install: all $(ROOTBOOTLOADER)

PROG=		${LOADER}.sym
INTERNALPROG=

# architecture-specific loader code
SRCS=		main.c conf.c vers.c chain.c

CPPFLAGS +=	-DLOADER_TFTP_SUPPORT -DLOADER_GZIP_SUPPORT

# Enable BootForth
CPPFLAGS +=	-DBOOT_FORTH -I$(SRC)/common/ficl -I../../ficl
LIBFICL=	../../ficl/i386/libficl.a

# Always add MI sources
SRCS +=	boot.c commands.c console.c devopen.c interp.c
SRCS +=	interp_backslash.c interp_parse.c ls.c misc.c
SRCS +=	module.c panic.c linenoise.c

SRCS +=	load_elf32.c load_elf32_obj.c reloc_elf32.c
SRCS +=	load_elf64.c load_elf64_obj.c reloc_elf64.c

SRCS +=	dev_net.c

SRCS +=	disk.c part.c
CPPFLAGS += -DLOADER_DISK_SUPPORT
SRCS +=	crc32.c
CPPFLAGS += -DLOADER_GPT_SUPPORT
CPPFLAGS += -DLOADER_MBR_SUPPORT

SRCS +=  bcache.c

SRCS +=	isapnp.c
SRCS +=	pnp.c

# Forth interpreter
SRCS +=	interp_forth.c

MAN +=	loader.8
MAN +=	zfsloader.8
CPPFLAGS +=	-I../../common
CPPFLAGS +=	-I.

CLEANFILES=	vers.c ${LOADER} ${LOADER}.sym ${LOADER}.bin loader.help

CFLAGS +=	-Wall
LDFLAGS=	-static -Ttext 0x0

# i386 standalone support library
CPPFLAGS +=	-I.. -I../../../../lib/libstand
LIBSTAND=	../../libstand/i386/libstand.a

# BTX components
CPPFLAGS +=	-I../btx/lib

# Debug me!
#CFLAGS+=	-g
#LDFLAGS+=	-g

include ../Makefile.inc

vers.c:	../../common/newvers.sh version
	$(SH) ../../common/newvers.sh version ${NEWVERSWHAT}

${LOADER}: ${LOADER}.bin ${BTXLDR} ${BTXKERN}
	$(BTXLD) -f aout -e ${LOADER_ADDRESS} -o $@ -l ${BTXLDR} \
		-b ${BTXKERN} ${LOADER}.bin

${LOADER}.bin: ${LOADER}.sym
	$(CP) $^ $@
	$(GSTRIP) -R .comment -R .note $@

loader.help: ../../common/help.common help.i386
	$(CAT) $^ | $(AWK) -f ../../common/merge_help.awk > $@

FILES=	${LOADER} loader.help

include	../../forth/Makefile.inc
FORTH +=	pcibios.4th

FILES +=	loader.rc
FORTH +=	menu.rc

# XXX crt0.o needs to be first for pxeboot(8) to work

DPADD=	${LIBFICL} ${LIBZFSBOOT} ${LIBI386} ${LIBSTAND}
LDADD=	${LIBFICL} ${LIBZFSBOOT} ${LIBI386} ${LIBSTAND}

CLEANFILES +=	machine x86
CFLAGS +=	-DLOADER_PREFER_AMD64

machine:
	$(RM) machine
	$(SYMLINK) ../../../i386/include machine

x86:
	$(RM) x86
	$(SYMLINK) ../../../x86/include x86

OBJS=		$(SRCS:%.c=%.o)

${OBJS}: machine x86

${PROG}: ${OBJS} $(LDADD)
	$(LD) $(LDFLAGS) -o $@ $(BTXCRT) $(OBJS) $(LDADD)

clean: clobber
clobber:
	$(RM) $(CLEANFILES) $(OBJS)

install: all $(ROOT_BOOT_DEFAULTS) $(ROOT_BOOT_FORTH) \
	$(ROOTBOOTFILES) $(ROOTBOOTDEFAULTS) $(ROOT_BOOT_CONF) $(ROOTBOOTFORTH)

%.o:	../../common/%.c
	$(COMPILE.c) -o $@ $<

%.o:	../../common/linenoise/%.c
	$(COMPILE.c) -o $@ $<

$(ROOT_BOOT)/%: ../../forth/%
	$(INS.file)

$(ROOT_BOOT_DEFAULTS)/%: ../../forth/%
	$(INS.file)

$(ROOT_BOOT_FORTH)/%: ../../forth/%
	$(INS.file)

$(ROOT_BOOT_DEFAULTS) $(ROOT_BOOT_CONF) $(ROOT_BOOT_FORTH):
	$(INS.dir)

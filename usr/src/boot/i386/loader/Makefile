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
# Copyright 2024 MNX Cloud, Inc.
#

include $(SRC)/Makefile.master
include $(SRC)/boot/Makefile.version
include $(SRC)/boot/Makefile.inc

CPPFLAGS +=	-I../../include -I../../sys
CPPFLAGS +=	-I$(SRC)/uts/intel/sys/acpi
CPPFLAGS +=	-I$(ZLIB)
LOADER=		loader
NEWVERSWHAT=	"ZFS enabled bootstrap loader" x86

# Set by loader Makefile
CPPFLAGS +=	-I$(ZFSSRC)
CPPFLAGS +=	-I../libi386
DPLIBI386=	../libi386/libi386.a
LIBI386=	-L../libi386 -li386

ROOT_BOOT=	$(ROOT)/boot
ROOTBOOTFILES=$(FILES:%=$(ROOT_BOOT)/%)
FILEMODE=0444

all: $(LOADER) loader.help

install: all $(ROOTBOOTLOADER)

PROG=		$(LOADER).sym

# architecture-specific loader code
SRCS=		main.c conf.c vers.c chain.c

# Enable BootForth
CPPFLAGS +=	-DBOOT_FORTH -I$(SRC)/common/ficl -I../../libficl
DPLIBFICL=	../../libficl/$(MACH)/libficl.a
LIBFICL=	-L../../libficl/$(MACH) -lficl

# Always add MI sources
SRCS +=	boot.c commands.c console.c devopen.c interp.c
SRCS +=	interp_backslash.c interp_parse.c ls.c misc.c
SRCS +=	module.c linenoise.c multiboot2.c nvstore.c
SRCS +=	zfs_cmd.c
SRCS +=	font.c $(FONT).c tem.c

module.o := CPPFLAGS += -I$(CRYPTOSRC)
tem.o := CPPFLAGS += $(DEFAULT_CONSOLE_COLOR)

SRCS +=	load_elf32.c load_elf32_obj.c reloc_elf32.c
SRCS +=	load_elf64.c load_elf64_obj.c reloc_elf64.c

SRCS +=	dev_net.c

SRCS +=	disk.c part.c vdisk.c
CPPFLAGS += -DLOADER_DISK_SUPPORT
CPPFLAGS += -DLOADER_GPT_SUPPORT
CPPFLAGS += -DLOADER_MBR_SUPPORT

SRCS +=  bcache.c

SRCS +=	isapnp.c
SRCS +=	pnp.c

# Forth interpreter
SRCS +=	interp_forth.c

CPPFLAGS +=	-I../../common
CPPFLAGS +=	-I.

CLEANFILES=	vers.c $(LOADER) $(LOADER).sym $(LOADER).bin loader.help
CLEANFILES +=	$(FONT).c

LDSCRIPT=	ldscript.i386
LDFLAGS=	-static -T $(LDSCRIPT) -N --gc-sections

# i386 standalone support library
CPPFLAGS +=	-I.. -I../../libsa
DPLIBSA=	../../libsa/$(MACH)/libsa.a
LIBSA=	-L../../libsa/$(MACH) -lsa

# BTX components
CPPFLAGS +=	-I../btx/lib

# Debug me!
#CFLAGS+=	-g
#LDFLAGS+=	-g

include ../Makefile.inc

conf.o := CPPFLAGS += -I../../sys/cddl/boot/zfs
multiboot2.o := CPPFLAGS += -I../../sys/cddl/boot/zfs
main.o := CPPFLAGS += -I../../sys/cddl/boot/zfs -I$(SRC)/uts/common/fs/zfs
zfs_cmd.o := CPPFLAGS += -I../../sys/cddl/boot/zfs

# For multiboot2.h, must be last, to avoid conflicts
CPPFLAGS +=	-I$(SRC)/uts/common

vers.c:	../../common/newvers.sh $(SRC)/boot/Makefile.version
	$(SH) ../../common/newvers.sh $(LOADER_VERSION) $(NEWVERSWHAT)

$(LOADER): $(LOADER).bin $(BTXLDR) $(BTXKERN)
	$(BTXLD) -f aout -e $(LOADER_ADDRESS) -o $@ -l $(BTXLDR) \
		-b $(BTXKERN) $(LOADER).bin

$(LOADER).bin: $(LOADER).sym
	$(CP) $^ $@
	$(GSTRIP) -R .comment -R .note $@

loader.help: ../../common/help.common help.i386
	$(CAT) $^ | $(AWK) -f ../../common/merge_help.awk > $@

FILES=	$(LOADER) loader.help

# XXX crt0.o needs to be first for pxeboot(8) to work

DPADD=	$(DPLIBFICL) $(DPLIBI386) $(DPLIBSA)
LDADD=	$(LIBFICL) $(LIBI386) $(LIBSA)

CLEANFILES +=	machine x86

machine:
	$(RM) machine
	$(SYMLINK) ../../sys/i386/include machine

x86:
	$(RM) x86
	$(SYMLINK) ../../sys/x86/include x86

OBJS=		$(SRCS:%.c=%.o)

$(OBJS): machine x86

$(PROG): $(OBJS) $(DPADD)
	$(GLD) $(LDFLAGS) -o $@ $(BTXCRT) $(OBJS) $(LDADD)

clean: clobber
clobber:
	$(RM) $(CLEANFILES) $(OBJS)

install: all $(ROOTBOOTFILES)

%.o:	../../common/%.c
	$(COMPILE.c) -o $@ $<

%.o:	../../common/linenoise/%.c
	$(COMPILE.c) -o $@ $<

%.o: $(SRC)/common/font/%.c
	$(COMPILE.c) $<

$(FONT).c: $(FONT_DIR)/$(FONT_SRC)
	$(VTFONTCVT) -f compressed-source -o $@ $(FONT_DIR)/$(FONT_SRC)

$(ROOT_BOOT)/%: ../../forth/% $(ROOT_BOOT)
	$(INS.file)

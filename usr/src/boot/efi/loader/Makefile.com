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
# Copyright 2022 Joyent, Inc.
#

include $(SRC)/boot/Makefile.version
include $(SRC)/boot/Makefile.inc

PROG=		loader.sym

# architecture-specific loader code
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
	main.o \
	memmap.o \
	mb_header.o \
	multiboot2.o \
	nvstore.o \
	self_reloc.o \
	tem.o \
	vers.o

module.o := CPPFLAGS += -I$(CRYPTOSRC)
tem.o := CPPFLAGS += $(DEFAULT_CONSOLE_COLOR)
main.o := CPPFLAGS += -I$(SRC)/uts/common/fs/zfs

CPPFLAGS += -I../../../include -I../../../sys
CPPFLAGS += -I../../../libsa

include ../../Makefile.inc

include ../arch/$(MACHINE)/Makefile.inc

CPPFLAGS +=	-I. -I..
CPPFLAGS +=	-I../../include
CPPFLAGS +=	-I../../include/$(MACHINE)
CPPFLAGS +=	-I$(ZFSSRC)
CPPFLAGS +=	-I../../../sys/cddl/boot/zfs
CPPFLAGS +=	-I$(SRC)/uts/intel/sys/acpi
CPPFLAGS +=	-I$(PNGLITE)
CPPFLAGS +=	-DNO_PCI -DEFI

#
# Using SNP from loader causes issues when chain-loading iPXE, as described in
# TRITON-1191.  While the exact problem is not known, we have no use for SNP, so
# we'll just disable it.
#
CPPFLAGS +=	-DLOADER_DISABLE_SNP


DPLIBSA=	../../../libsa/$(MACHINE)/libsa_pics.a
LIBSA=	-L../../../libsa/$(MACHINE) -lsa_pics

BOOT_FORTH=	yes
CPPFLAGS +=	-DBOOT_FORTH
CPPFLAGS +=	-I$(SRC)/common/ficl
CPPFLAGS +=	-I../../../libficl
DPLIBFICL=	../../../libficl/$(MACHINE)/libficl_pics.a
LIBFICL=	-L../../../libficl/$(MACHINE) -lficl_pics

# Always add MI sources
#
OBJS += boot.o commands.o console.o devopen.o interp.o \
	interp_backslash.o interp_parse.o ls.o misc.o \
	module.o linenoise.o zfs_cmd.o

OBJS += load_elf32.o load_elf32_obj.o reloc_elf32.o \
	load_elf64.o load_elf64_obj.o reloc_elf64.o

OBJS += disk.o part.o dev_net.o vdisk.o
CPPFLAGS += -DLOADER_DISK_SUPPORT
CPPFLAGS += -DLOADER_GPT_SUPPORT
CPPFLAGS += -DLOADER_MBR_SUPPORT

part.o := CPPFLAGS += -I$(ZLIB)

OBJS +=  bcache.o

# Forth interpreter
OBJS +=	interp_forth.o
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

CLEANFILES=	$(EFIPROG) loader.sym loader.bin
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

DPLIBEFI=	../../libefi/$(MACHINE)/libefi.a
LIBEFI=		-L../../libefi/$(MACHINE) -lefi

DPADD=		$(DPLIBFICL) $(DPLIBEFI) $(DPLIBSA) $(LDSCRIPT)
LDADD=		$(LIBFICL) $(LIBEFI) $(LIBSA)

loader.sym:	$(OBJS) $(DPADD)
	$(GLD) $(LDFLAGS) -o $@ $(OBJS) $(LDADD)

machine:
	$(RM) machine
	$(SYMLINK) ../../../sys/$(MACHINE)/include machine

x86:
	$(RM) x86
	$(SYMLINK) ../../../sys/x86/include x86

clean clobber:
	$(RM) $(CLEANFILES) $(OBJS) machine x86

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

%.o: $(SRC)/common/font/%.c
	$(COMPILE.c) $<

$(FONT).c: $(FONT_DIR)/$(FONT_SRC)
	$(VTFONTCVT) -f compressed-source -o $@ $(FONT_DIR)/$(FONT_SRC)

$(ROOT_BOOT)/%: %
	$(INS.file)

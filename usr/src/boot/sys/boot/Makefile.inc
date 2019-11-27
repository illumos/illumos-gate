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
# Copyright 2017 Toomas Soome <tsoome@me.com>
# Copyright 2019 Joyent, Inc.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

# loader.help build needs better awk
AWK=		/usr/xpg4/bin/awk
LD=		$(GNU_ROOT)/bin/gld
OBJCOPY=	$(GNU_ROOT)/bin/gobjcopy
OBJDUMP=	$(GNU_ROOT)/bin/gobjdump
GSTRIP=		$(GNU_ROOT)/bin/gstrip

GLDTARGET=	-melf_i386_sol2
LDFLAGS	+=	$(GLDTARGET)

# Default Console font setup.
# We want it to be the same as kernel.
# We build compressed, stripped down version of the default font, so we have
# bare minimum for case we can not load font from the OS root.

FONT=		8x16
FONT_SRC=	ter-u16n.bdf
FONT_DIR=	$(SRC)/data/consfonts

PNGLITE=	$(SRC)/common/pnglite

BOOTSRC=	$(SRC)/boot/sys/boot
LIBSRC=		$(SRC)/boot/lib
SASRC=		$(LIBSRC)/libstand
ZFSSRC=		$(SASRC)/zfs
ZLIB=		$(SRC)/contrib/zlib
LZ4=		$(SRC)/common/lz4

# set standard values
AS_CPPFLAGS=
CPPFLAGS=	-D_STANDALONE -_gcc=-nostdinc
CFLAGS64=	-_gcc=-mno-red-zone

CFLAGS=		-_gcc=-Os -_gcc=-fPIC -_gcc=-ffreestanding -_gcc=-fno-builtin
CFLAGS +=	-_gcc=-ffunction-sections -_gcc=-fdata-sections
CFLAGS +=	-_gcc=-mno-mmx -_gcc=-mno-3dnow -_gcc=-mno-sse -_gcc=-mno-sse2
CFLAGS +=	-_gcc=-mno-sse3 -_gcc=-msoft-float
CFLAGS +=	-_gcc=-mno-avx -_gcc=-mno-aes
CFLAGS +=	-_gcc=-Wall
CFLAGS +=	$(CCNOAUTOINLINE) $(CCNOREORDER) $(CSTD_GNU99)
CCASFLAGS=	-fPIC -Wa,--divide
ASFLAGS=	--divide

SMATCH_ =
SMATCH_on =
SMATCH_off = -_smatch=off

# smatch does not define __amd64 and __amd64__
SMATCH_amd64=	-_smatch=-D__amd64 -_smatch=-D__amd64__

# SMATCH_ARGS will bring in set of -Wno-* options.
#CFLAGS +=	$(SMATCH_ARGS:%=-_smatch=%)
CFLAGS +=	$(SMOFF:%=-_smatch=--disable=%)
CFLAGS +=	$(SMATCH_$(MACHINE))
CFLAGS +=	$(SMATCH_$(SMATCH))
CFLAGS +=	-_smatch=--timeout=0

COMPILE.S=	$(CC) $(SMATCH_off) $(CCASFLAGS) $(CPPFLAGS) -c

ROOT_BOOT=	$(ROOT)/boot
ROOTBOOTPROG=$(PROG:%=$(ROOT_BOOT)/%)

$(ROOT_BOOT)/%: %
	$(INS.file)

#.if ${MACHINE_CPUARCH} == "arm"
# Do not generate movt/movw, because the relocation fixup for them does not
# translate to the -Bsymbolic -pie format required by self_reloc() in loader(8).
# Also, the fpu is not available in a standalone environment.
#CFLAGS.clang+=  -mllvm -arm-use-movt=0
#CFLAGS.clang+=  -mfpu=none
#.endif

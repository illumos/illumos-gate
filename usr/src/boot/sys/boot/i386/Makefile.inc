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
#

# Common defines for all of /sys/boot/i386/

ROOT_BOOT=	$(ROOT)/boot
ROOTBOOTPROG=$(PROG:%=$(ROOT_BOOT)/%)

LOADER_ADDRESS=0x200000
CFLAGS +=	-march=i386 -ffreestanding
CFLAGS +=	-mpreferred-stack-boundary=2
CFLAGS +=	-mno-mmx -mno-3dnow -mno-sse -mno-sse2 -mno-sse3 -msoft-float
CFLAGS +=	-std=gnu99 -fno-reorder-functions
LDFLAGS +=	-nostdlib

CFLAGS +=	-m32
ACFLAGS +=	-m32
AFLAGS +=	--32

# BTX components
BTXDIR=		$(SRC)/boot/sys/boot/i386/btx
BTXLDR=		${BTXDIR}/btxldr/btxldr
BTXKERN=	${BTXDIR}/btx/btx
BTXCRT=		${BTXDIR}/lib/crt0.o

$(ROOT_BOOT)/%: %
	$(INS.file)

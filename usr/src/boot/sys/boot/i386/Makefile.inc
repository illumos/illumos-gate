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

LOADER_ADDRESS=0x200000
CFLAGS +=	-m32
CCASFLAGS +=	-m32
ASFLAGS +=	--32

# BTX components
BTXDIR=		$(SRC)/boot/sys/boot/i386/btx
BTXLDR=		${BTXDIR}/btxldr/btxldr
BTXKERN=	${BTXDIR}/btx/btx
BTXCRT=		${BTXDIR}/lib/crt0.o

.PARALLEL:

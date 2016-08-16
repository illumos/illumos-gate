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

MACHINE=	$(MACH64)
ASFLAGS=	-m64
EFIPROG=	bootx64.efi

all:		$(EFIPROG)

include ../Makefile.com

EFI_TARGET=	pei-x86-64
LDFLAGS +=	-znocombreloc

CPPFLAGS +=	-DLOADER_EFI=\"loader64.efi\"
CFLAGS +=	-m64 -mno-red-zone

CLEANFILES +=	machine x86

$(OBJS): machine x86

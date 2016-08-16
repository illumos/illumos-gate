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

MACHINE=	$(MACH)
ASFLAGS=	-m32
EFIPROG=	loader32.efi

all:		$(EFIPROG)

include ../Makefile.com

EFI_TARGET=	pei-i386
LDFLAGS +=	-znocombreloc

efi_main.o := CPPFLAGS += -DLOADER_EFI=L\"loader32.efi\"
CFLAGS +=	-m32

CLEANFILES +=	machine x86 $(EFIPROG)

$(OBJS):	machine x86

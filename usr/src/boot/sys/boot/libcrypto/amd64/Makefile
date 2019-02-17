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

COMDIR=		$(SRC)/common/crypto
MACHINE=	$(MACH64)
AS=		$(AS_amd64_64)

all:		libcrypto.a

SRCS = sha1-x86_64.s
OBJS = sha1-x86_64.o

include ../Makefile.com
ASFLAGS =	$(amd64_AS_XARCH) -I$(SRC)/uts/common -D_ASM

CFLAGS +=	-m64 $(CFLAGS64)
CLEANFILES +=	machine x86 sha1-x86_64.s

$(OBJS): machine x86

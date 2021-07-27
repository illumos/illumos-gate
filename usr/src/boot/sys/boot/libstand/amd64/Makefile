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

MACHINE=	$(MACH64)
DYNLIB=		libstand_pics.a

all install:    $(DYNLIB)

include ../Makefile.com

ASFLAGS =	$(amd64_AS_XARCH) -I$(SRC)/uts/common -D_ASM
CFLAGS +=	-m64 $(CFLAGS64)
CCASFLAGS +=	-m64

# _setjmp/_longjmp
SRCS += $(SASRC)/amd64/_setjmp.S
OBJECTS += _setjmp.o
SRCS += sha1-x86_64.s
OBJECTS += sha1-x86_64.o

CLEANFILES += sha1-x86_64.s

pics/%.o: $(SASRC)/amd64/%.S
	$(COMPILE.S) -o $@ $<

include $(SRC)/boot/sys/boot/Makefile.lib

FRC:

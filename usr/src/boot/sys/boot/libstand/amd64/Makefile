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
LIBRARY=	libstand.a

all install:    $(LIBRARY)

include ../Makefile.com

CFLAGS +=	-m64 -mno-red-zone
ASFLAGS +=	-m64

CLEANFILES += x86

# _setjmp/_longjmp
SRCS += $(LIBSTAND_SRC)/amd64/_setjmp.S
OBJS += _setjmp.o

$(LIBRARY): $(SRCS) $(OBJS)

$(OBJS): machine x86

%.o: $(LIBSTAND_SRC)/amd64/%.S
	$(COMPILE.S) $<

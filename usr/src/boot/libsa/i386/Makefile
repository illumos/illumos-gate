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

MACHINE=	$(MACH)
LIBRARY=	libsa.a
DYNLIB=		libsa_pics.a

all install:	$(LIBRARY) $(DYNLIB)

include ../Makefile.com

CFLAGS +=	-m32
CCASFLAGS +=	-m32

# _setjmp/_longjmp
SRCS += $(SASRC)/i386/_setjmp.S
OBJECTS += _setjmp.o

SRCS += $(SASRC)/x86/hypervisor.c
OBJECTS += hypervisor.o

pics/%.o objs/%.o: $(SASRC)/i386/%.S
	$(COMPILE.S) -o $@ $<

pics/%.o objs/%.o: $(SASRC)/x86/%.c
	$(COMPILE.c) -o $@ $<

include $(BOOTSRC)/Makefile.lib

FRC:

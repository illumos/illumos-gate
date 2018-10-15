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


CC=		$(GNUC_ROOT)/bin/gcc
FICLDIR=	$(SRC)/common/ficl

CPPFLAGS= -nostdinc -D_STANDALONE -I. -I.. -I../../../../include
CPPFLAGS += -I../../../../lib/libstand
CPPFLAGS += -I../../..  -I$(FICLDIR) -I../../common

CFLAGS=		-O2 -fPIC -Wall -ffreestanding -mno-mmx -mno-3dnow -mno-sse
CFLAGS +=	-mno-sse2 -mno-sse3 -msoft-float -std=gnu99

OBJECTS= dictionary.o system.o fileaccess.o float.o double.o prefix.o search.o
OBJECTS += softcore.o stack.o tools.o vm.o primitives.o unix.o utility.o
OBJECTS += hash.o callback.o word.o loader.o
HEADERS= $(FICLDIR)/ficl.h $(FICLDIR)/ficlplatform/unix.h ../ficllocal.h
#

MAJOR = 4
MINOR = 1.0

lib: libficl.a

# static library build
libficl.a: $(OBJECTS)
	$(AR) $(ARFLAGS) libficl.a $(OBJECTS)

machine:
	$(RM) machine
	$(SYMLINK) ../../../$(MACHINE)/include machine

x86:
	$(RM) x86
	$(SYMLINK) ../../../x86/include x86

%.o:	../softcore/%.c $(HEADERS)
	$(COMPILE.c) $<

%.o:	$(FICLDIR)/%.c $(HEADERS)
	$(COMPILE.c) $<

%.o:	$(FICLDIR)/ficlplatform/%.c $(HEADERS)
	$(COMPILE.c) $<

#
#       generic cleanup code
#
clobber clean:	FRC
	$(RM) *.o *.a libficl.* ficl machine x86

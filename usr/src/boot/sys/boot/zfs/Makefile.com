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

LIB=		zfsboot

all: libzfsboot.a

clean: clobber

clobber:
	$(RM) machine x86 $(OBJS) libzfsboot.a

CC=     $(GCC_ROOT)/bin/gcc
CPPFLAGS=

SRCS +=		../zfs.c ../gzip.c
SRCS +=		$(SRC)/common/crypto/edonr/edonr.c
SRCS +=		$(SRC)/common/crypto/skein/skein.c
SRCS +=		$(SRC)/common/crypto/skein/skein_iv.c
SRCS +=		$(SRC)/common/crypto/skein/skein_block.c
OBJS +=		zfs.o gzip.o edonr.o skein.o skein_iv.o skein_block.o

CFLAGS= -O2 -D_STANDALONE -nostdinc -I../../../../include -I../../..
CFLAGS +=	-I../../common -I../../.. -I.. -I.
CFLAGS +=	-I../../../../lib/libstand
CFLAGS +=	-I../../../../lib/libz
CFLAGS +=	-I../../../cddl/boot/zfs
CFLAGS +=	-I$(SRC)/uts/common

# Do not unroll skein loops, reduce code size
CFLAGS +=	-DSKEIN_LOOP=111

CFLAGS +=	-ffreestanding
CFLAGS +=	-mno-mmx -mno-3dnow -mno-sse -mno-sse2 -mno-sse3 -msoft-float
CFLAGS +=	-Wformat -Wall -std=gnu99

CLEANFILES +=    machine x86

machine:
	$(RM) machine
	$(SYMLINK) ../../../$(MACHINE)/include machine

x86:
	$(RM) x86
	$(SYMLINK) ../../../x86/include x86

$(OBJS): machine x86

libzfsboot.a: $(OBJS)
	$(AR) $(ARFLAGS) $@ $(OBJS)

%.o:	../%.c
	$(COMPILE.c) -o $@ $<

%.o:	$(SRC)/common/crypto/edonr/%.c
	$(COMPILE.c) -o $@ $<

%.o:	$(SRC)/common/crypto/skein/%.c
	$(COMPILE.c) -o $@ $<

zfs.o: ../zfsimpl.c

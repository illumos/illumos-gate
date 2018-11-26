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

include $(SRC)/Makefile.master

LIB=		zfsboot

clean: clobber

clobber:
	$(RM) machine x86 $(OBJS) libzfsboot.a

CC=     $(GNUC_ROOT)/bin/gcc

CFLAGS=		-Os
CFLAGS +=       -fPIC -ffreestanding -msoft-float
CFLAGS +=       -mno-mmx -mno-3dnow -mno-sse2 -mno-sse3 -mno-sse
CFLAGS +=       -mno-avx -mno-aes -std=gnu99

SRCS +=		$(SRC)/boot/sys/boot/zfs/zfs.c $(SRC)/boot/sys/boot/zfs/gzip.c
SRCS +=		$(SRC)/common/crypto/edonr/edonr.c
SRCS +=		$(SRC)/common/crypto/skein/skein.c
SRCS +=		$(SRC)/common/crypto/skein/skein_iv.c
SRCS +=		$(SRC)/common/crypto/skein/skein_block.c
OBJS +=		zfs.o gzip.o edonr.o skein.o skein_iv.o skein_block.o

CPPFLAGS=	-D_STANDALONE -nostdinc -I../../../../include -I../..
CPPFLAGS +=	-I../../common -I../../.. -I.. -I.
CPPFLAGS +=	-I../../../../lib/libstand
CPPFLAGS +=	-I../../../../lib/libz
CPPFLAGS +=	-I../../../cddl/boot/zfs
CPPFLAGS +=	-I$(SRC)/uts/common

# Do not unroll skein loops, reduce code size
CPPFLAGS +=	-DSKEIN_LOOP=111

#include ../../Makefile.inc

CLEANFILES +=    machine

machine:
	$(RM) machine
	$(SYMLINK) ../../../$(MACHINE)/include machine

x86:
	$(RM) x86
	$(SYMLINK) ../../../x86/include x86

libzfsboot.a: $(OBJS)
	$(AR) $(ARFLAGS) $@ $(OBJS)

%.o:	$(SRC)/boot/sys/boot/zfs/%.c
	$(COMPILE.c) -o $@ $<

%.o:	$(SRC)/common/crypto/edonr/%.c
	$(COMPILE.c) -o $@ $<

%.o:	$(SRC)/common/crypto/skein/%.c
	$(COMPILE.c) -o $@ $<

zfs.o: $(SRC)/boot/sys/boot/zfs/zfsimpl.c

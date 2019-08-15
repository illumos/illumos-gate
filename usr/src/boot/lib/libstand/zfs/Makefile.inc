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

SRCS +=		$(ZFSSRC)/zfs.c
SRCS +=		$(ZFSSRC)/gzip.c
SRCS +=		$(SRC)/common/crypto/edonr/edonr.c
SRCS +=		$(SRC)/common/crypto/skein/skein.c
SRCS +=		$(SRC)/common/crypto/skein/skein_iv.c
SRCS +=		$(SRC)/common/crypto/skein/skein_block.c
SRCS +=		$(SRC)/common/list/list.c
OBJS +=		zfs.o
OBJS +=		gzip.o
OBJS +=		edonr.o
OBJS +=		skein.o
OBJS +=		skein_iv.o
OBJS +=		skein_block.o
OBJS +=		list.o

zfs.o := CPPFLAGS +=	-I../../common
zfs.o := CPPFLAGS +=	-I../../../cddl/boot/zfs

# Do not unroll skein loops, reduce code size
skein_block.o := CPPFLAGS +=	-DSKEIN_LOOP=111

%.o:	$(ZFSSRC)/%.c
	$(COMPILE.c) -o $@ $<

%.o:	$(SRC)/common/crypto/edonr/%.c
	$(COMPILE.c) -o $@ $<

%.o:	$(SRC)/common/crypto/skein/%.c
	$(COMPILE.c) -o $@ $<

%.o:	$(SRC)/common/list/%.c
	$(COMPILE.c) -DNDEBUG $<

zfs.o: $(ZFSSRC)/zfsimpl.c

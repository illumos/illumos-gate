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
# Copyright 2015 Toomas Soome <tsoome@me.com>
#

include $(SRC)/Makefile.master

AS=	$(GNU_ROOT)/bin/gas
LD=	$(GNU_ROOT)/bin/gld
CC=	$(GNUC_ROOT)/bin/gcc

CPPFLAGS= -I./../../common
CFLAGS=	-O2 -march=i386 -ffreestanding -mno-mmx -mno-3dnow -mno-sse -mno-sse2
CFLAGS += -mno-sse3 -msoft-float -m32 -std=gnu99
AS_CPPFLAGS=
ASFLAGS=--32

PROG=	crt0.o
SRCS=	btxcsu.S btxsys.s btxv86.s
OBJS=	btxcsu.o btxsys.o btxv86.o

LDFLAGS=-Wl,-r -nostdlib

all install: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS)

.S.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clobber: clean

clean:
	$(RM) $(PROG) $(OBJS)

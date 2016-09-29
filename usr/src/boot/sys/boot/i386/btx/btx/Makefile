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

PROG=	btx
SRCS=	btx.S
OBJS=	btx.o

AS=	$(GNU_ROOT)/bin/gas
LD=	$(GNU_ROOT)/bin/gld
CC=	$(GCC_ROOT)/bin/gcc

#.if defined(BOOT_BTX_NOHANG)
#BOOT_BTX_FLAGS=0x1
#.else
BOOT_BTX_FLAGS=0x0
#.endif

CFLAGS = -DBTX_FLAGS=${BOOT_BTX_FLAGS}
CFLAGS += -I./../../common
CFLAGS += -march=i386 -ffreestanding -mno-mmx -mno-3dnow -mno-sse -mno-sse2
CFLAGS += -mno-sse3 -msoft-float -m32 -std=gnu99
CFLAGS += -Wa,--divide

#.if defined(BTX_SERIAL)
#BOOT_COMCONSOLE_PORT?= 0x3f8
#BOOT_COMCONSOLE_SPEED?= 9600
#B2SIOFMT?=	0x3
#
#CFLAGS+=-DBTX_SERIAL -DSIOPRT=${BOOT_COMCONSOLE_PORT} \
#	-DSIOFMT=${B2SIOFMT} -DSIOSPD=${BOOT_COMCONSOLE_SPEED}
#.endif

ORG=	0x9000

LDFLAGS=-e start -Ttext ${ORG} -N -S --oformat binary

all:	$(PROG)

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $(OBJS)

.S.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clobber: clean

clean:
	$(RM) $(PROG) $(OBJS)

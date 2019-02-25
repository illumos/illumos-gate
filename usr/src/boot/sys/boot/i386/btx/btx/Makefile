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
include $(SRC)/boot/sys/boot/Makefile.inc
include ../../Makefile.inc

PROG=	btx
SRCS=	btx.S
OBJS=	btx.o

#.if defined(BOOT_BTX_NOHANG)
#BOOT_BTX_FLAGS=0x1
#.else
BOOT_BTX_FLAGS=0x0
#.endif

CPPFLAGS += -DBTX_FLAGS=${BOOT_BTX_FLAGS}
CPPFLAGS += -I./../../common

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

all install:	$(PROG)

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $(OBJS)

clobber: clean

clean:
	$(RM) $(PROG) $(OBJS)

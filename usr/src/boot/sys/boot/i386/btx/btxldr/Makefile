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

PROG=	btxldr
SRCS=	btxldr.S
OBJS=	btxldr.o

AS=	$(GNU_ROOT)/bin/gas
LD=	$(GNU_ROOT)/bin/gld
CC=	$(GNUC_ROOT)/bin/gcc

LOADER_ADDRESS=0x200000
CPPFLAGS=
CFLAGS = -m32 -DLOADER_ADDRESS=${LOADER_ADDRESS}
CFLAGS += -I./../../common
CFLAGS += -Wa,--divide
CFLAGS += -DBTXLDR_VERBOSE

LDFLAGS=-e start -Ttext ${LOADER_ADDRESS} -N -S --oformat binary

all install:	$(PROG)

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $(OBJS)

.S.o:
	$(COMPILE.S) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clobber: clean

clean:
	$(RM) $(PROG) $(OBJS)

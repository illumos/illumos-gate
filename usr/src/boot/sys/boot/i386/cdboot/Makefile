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

ROOT_BOOT = $(ROOT)/boot

LD=	$(GNU_ROOT)/bin/gld
CC=	$(GNUC_ROOT)/bin/gcc

CFLAGS =	-O2 -I../common -march=i386 -ffreestanding -mno-mmx -mno-3dnow
CFLAGS +=	-mno-sse -mno-sse2 -mno-sse3 -msoft-float -std=gnu99 -m32
CPPFLAGS=
CCASFLAGS=	-Wa,--divide

PROG=	cdboot
STRIP=
FILEMODE=0444
MAN=
SRCS=	${PROG}.S
OBJS=	$(SRCS:%.S=%.o)


ORG=	0x7c00

LDFLAGS=-e start -Ttext ${ORG} -N -S --oformat binary

all:	${PROG}

install: $(PROG:%=$(ROOT_BOOT)/%)

${PROG}: ${OBJS}
	${LD} ${LDFLAGS} -o $@ $^

clobber: clean
clean:
	$(RM) $(PROG) $(OBJS)

.S.o:
	$(CC) $(CFLAGS) $(CCASFLAGS) -c -o $@ $<

$(ROOT_BOOT)/%: %
	$(INS.file)

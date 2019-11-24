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
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

#
# x86 EFI pmbr build rules
#
include $(SRC)/Makefile.master
include $(SRC)/boot/sys/boot/Makefile.inc
include ../Makefile.inc

PROG=	pmbr

FILEMODE=0444
OBJS=	pmbr.o
SRCS=	$(OBJS:%.o=%.s)

ORG=	0x600

LDFLAGS=-e start -Ttext ${ORG} -N -S --oformat binary $(GLDTARGET)

all: $(PROG)

install: $(PROG:%=$(ROOT_BOOT)/%)

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) -o $(PROG) $(OBJS)

clobber: clean

clean:
	$(RM) $(PROG) $(OBJS)

$(ROOT_BOOT)/%: %
	$(INS.file)

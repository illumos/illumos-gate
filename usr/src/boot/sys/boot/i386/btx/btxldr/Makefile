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

include $(SRC)/Makefile.master
include $(SRC)/boot/sys/boot/Makefile.inc
include ../../Makefile.inc

PROG=	btxldr
SRCS=	btxldr.S
OBJS=	btxldr.o

CPPFLAGS += -DLOADER_ADDRESS=${LOADER_ADDRESS}
CPPFLAGS += -DBTXLDR_VERBOSE
CPPFLAGS += -I./../../common

LDFLAGS=-e start -Ttext ${LOADER_ADDRESS} -N -S --oformat binary $(GLDTARGET)

all install:	$(PROG)

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $(OBJS)

clobber: clean

clean:
	$(RM) $(PROG) $(OBJS)

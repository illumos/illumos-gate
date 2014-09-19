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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright 2014 Joyent, Inc.  All rights reserved.
#
#
# lib/brand/lx/amd64/Makefile

ISASRCDIR=.

ASFLAGS	+= -P -D_ASM

include ../Makefile.com
include $(SRC)/lib/Makefile.lib.64

DYNFLAGS +=	-Wl,-I/native/lib/64/ld.so.1
CPPFLAGS +=	-D_SYSCALL32

POFILE=		lx_brand.po
MSGFILES=	$(CSRCS)

ASSYMDEP_OBJS = lx_handler.o

$(ASSYMDEP_OBJS:%=pics/%): assym.h

OFFSETS = ../$(MACH64)/offsets.in

assym.h: $(OFFSETS)
	$(OFFSETS_CREATE) $(CTF_FLAGS) < $(OFFSETS) > $@

CLOBBERFILES += assym.h

install: all $(ROOTLIBS64)

$(POFILE): $(MSGFILES)
	$(BUILDPO.msgfiles)

_msg: $(MSGDOMAINPOFILE)

include $(SRC)/Makefile.msg.targ

#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright 2014 Joyent, Inc.  All rights reserved.
#
# lib/brand/lx/i386/Makefile

ISASRCDIR=.

ASFLAGS	+= -P -D_ASM

include ../Makefile.com

DYNFLAGS +=	-Wl,-I/native/lib/ld.so.1

POFILE=		lx_brand.po
MSGFILES=	$(CSRCS)

ASSYMDEP_OBJS = lx_handler.o

$(ASSYMDEP_OBJS:%=pics/%): assym.h

OFFSETS = ../$(MACH)/offsets.in

assym.h: $(OFFSETS)
	$(OFFSETS_CREATE) $(CTF_FLAGS) < $(OFFSETS) > $@

CLOBBERFILES += assym.h

install: all $(ROOTLIBS)

$(POFILE): $(MSGFILES)
	$(BUILDPO.msgfiles)

_msg: $(MSGDOMAINPOFILE)

include $(SRC)/Makefile.msg.targ

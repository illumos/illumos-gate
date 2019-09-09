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
# Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright (c) 2019, Joyent, Inc.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

PROG=		nm
XPG4PROG=	nm

ARFORMAT=	PORTAR

include		../../../Makefile.cmd
include		../../Makefile.com

COMOBJS=	nm.o

OBJS=		$(COMOBJS)
XPG4OBJS=	objs.xpg4/nm.o

SRCS=		$(COMOBJS:%.o=../common/%.c)

LLDFLAGS =	'-R$$ORIGIN/../../lib'
INCLIST=	-I../../include -I../../include/i386 \
		-I$(SRC)/uts/$(ARCH)/sys
DEFLIST=	-DTARGET=I386 -DI386=1 -D$(ARFORMAT) -DELF
CPPFLAGS=	$(INCLIST) $(DEFLIST) $(CPPFLAGS.master) -I$(ELFCAP)

LDLIBS +=	$(CONVLIBDIR) -lconv $(ELFLIBDIR) -lelf
objs.xpg4/%.o := CPPFLAGS += -DXPG4

$(DEMOBJS):=	DEFLIST = -DELF_OBJ

objs.xpg4/%.o:	../common/%.c
		$(COMPILE.c) -o $@ $<

%.o:		../common/%.c
		$(COMPILE.c) $<

.KEEP_STATE:

all:		$(PROG) $(XPG4)

$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LLDFLAGS) $(LDLIBS)
		$(POST_PROCESS)

$(XPG4):	$(XPG4OBJS)
		$(LINK.c) $(XPG4OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

$(XPG4OBJS):	objs.xpg4

objs.xpg4:
	-@mkdir -p $@

package \
install:	all $(VAR_SGSBINPROG) $(ROOTXPG4PROG) $(VAR_SGSCCSLINK)

clean:
		$(RM) $(OBJS) $(XPG4OBJS) $(CLEANFILES)

include		../../../Makefile.targ
include		../../Makefile.targ

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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

PROG=		nm

ARFORMAT=	PORTAR

include 	../../../Makefile.cmd
include 	../../Makefile.com

COMOBJS=	nm.o

OBJS=		$(COMOBJS)

SRCS=		$(COMOBJS:%.o=../common/%.c)

LDFLAGS +=	'-R$$ORIGIN/../../../lib/$(MACH64)'
INCLIST=	-I../../include -I../../include/i386 \
		-I$(SRCBASE)/uts/$(ARCH)/sys
CPPFLAGS=	$(INCLIST) $(DEFLIST) $(CPPFLAGS.master) -I$(ELFCAP)

CERRWARN +=	-_gcc=-Wno-uninitialized

SMOFF += precedence,indenting

LDLIBS +=	$(CONVLIBDIR64) $(CONV_LIB) $(ELFLIBDIR) -lelf
LINTFLAGS64 +=	-x $(LDLIBS) -m64
LINTSRCS=	$(SRCS)
CLEANFILES +=	$(LINTOUTS)


%.o:		../common/%.c
		$(COMPILE.c) $<

$(ROOTCCSBIN64)/%: %
	$(INS.file)

.KEEP_STATE:

all:		$(PROG)

$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

package \
install:	all $(VAR_SGSBINPROG64) $(VAR_SGSCCSLINK64)

clean:
		$(RM) $(OBJS) $(CLEANFILES)

lint:		$(LINTOUT64) $(SGSLINTOUT)


include		../../Makefile.targ
include		../../../Makefile.targ
include		../../Makefile.sub.64

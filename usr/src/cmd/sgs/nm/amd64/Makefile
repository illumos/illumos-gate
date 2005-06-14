#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

PROG=		nm

ARFORMAT=	PORTAR

include 	../../../Makefile.cmd
include 	../../Makefile.com

COMOBJS=	nm.o

OBJS=		$(COMOBJS)

SRCS=		$(COMOBJS:%.o=../common/%.c)

LDFLAGS +=	'-R$$ORIGIN/../../../lib/$(MACH64)'
INCLIST=	-I../../include -I../../include/sparc \
		-I$(SRCBASE)/uts/$(ARCH)/sys
CPPFLAGS=	$(INCLIST) $(DEFLIST) $(CPPFLAGS.master)
LDLIBS +=	-L ../../sgsdemangler/amd64 -ldemangle \
		-L ../../libconv/amd64 -lconv -lelf
LINTFLAGS64=	-mx $(LDLIBS) -Xarch=amd64
CLEANFILES +=	$(LINTOUT)


%.o:		../common/%.c
		$(COMPILE.c) $<

$(ROOTCCSBIN64)/%: %
	$(INS.file)

.KEEP_STATE:

all:		$(PROG)

$(PROG):	$(OBJS) ../../sgsdemangler/amd64/libdemangle.a
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

package \
install:	all $(ROOTCCSBINPROG64)

clean:
		$(RM) $(OBJS) $(CLEANFILES)

lint:		$(LINTOUT)

$(LINTOUT):	$(SRCS)
		$(LINT.c) $(SRCS) > $(LINTOUT) 2>&1

include		../../../Makefile.targ
include		../../Makefile.sub.64

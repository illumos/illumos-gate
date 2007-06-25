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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/sgs/m4/sparc/Makefile
#

PROG=		m4
XPG4PROG=	m4

include 	../../../Makefile.cmd
include		../../../sgs/Makefile.var

COBJS=		m4.o  m4ext.o  m4macs.o

YOBJS=		m4objs/m4y.o
XPG4YOBJS=	m4objs.xpg4/m4y_xpg4.o

OBJS=		$(COBJS:%=m4objs/%) $(YOBJS)
XPG4OBJS=	$(COBJS:%=m4objs.xpg4/%) $(XPG4YOBJS)
ALLOBJS=	$(OBJS) $(XPG4OBJS)

BLTSRCS=	../common/m4y.c ../common/m4y_xpg4.c

SRCS=		$(COBJS:%.o=../common/%.c) $(BLTSRCS)

INCLIST=	-I../common
DEFLIST=	-DELF
CPPFLAGS=	$(INCLIST) $(DEFLIST) $(CPPFLAGS.master)
CFLAGS +=	$(CCVERBOSE)
C99MODE=	$(C99_ENABLE)

CLEANFILES +=	$(LINTOUT) $(BLTSRCS)

m4objs.xpg4/%.o := CPPFLAGS += -DXPG4

m4objs/%.o m4objs.xpg4/%.o: ../common/%.c
		$(COMPILE.c) -o $@ $<

.KEEP_STATE:

all:		$(PROG) $(XPG4)

$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

$(XPG4):	$(XPG4OBJS)
		$(LINK.c) $(XPG4OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

$(OBJS):	m4objs

$(XPG4OBJS):	m4objs.xpg4

m4objs m4objs.xpg4:
		-@mkdir -p $@

install:	all $(VAR_SGSBINPROG) $(ROOTXPG4PROG) $(VAR_SGSCCSLINK)
clean:
		$(RM) $(ALLOBJS) $(CLEANFILES)

lint:		$(LINTOUT)

$(LINTOUT):	$(SRCS)
		$(LINT.c) $(SRCS) > $(LINTOUT) 2>&1

include		../../../Makefile.targ

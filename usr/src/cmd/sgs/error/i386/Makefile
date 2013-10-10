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
# Copyright (c) 2013 Gary Mills
#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG=		error

include 	../../../Makefile.cmd

OBJS=		errormain.o errorinput.o errorpi.o errorsubr.o \
		errorfilter.o errortouch.o

SRCS=		$(OBJS:%.o=../common/%.c)

INCLIST=	-I../common
DEFLIST=	-DELF
CPPFLAGS=	$(INCLIST) $(DEFLIST) $(CPPFLAGS.master)
CFLAGS +=	$(CCVERBOSE)
C99MODE=	$(C99_ENABLE)

CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-parentheses

CLEANFILES +=	$(LINTOUT)

%.o:		../common/%.c
		$(COMPILE.c) $<

.KEEP_STATE:

all:		$(PROG)

$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

install:	all $(ROOTPROG) $(ROOTCCSBINLINK)

clean:
		$(RM) $(OBJS) $(CLEANFILES)

lint:		$(LINTOUT)

$(LINTOUT):	$(SRCS)
		perl ../../tools/lint_hdr.pl $(PROG)	> $(LINTOUT)
		$(LINT.c) $(SRCS) $(LDLIBS)		2>&1 | tee -a $(LINTOUT)

include		../../../Makefile.targ

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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG=		tsort

include 	../../../Makefile.cmd

OBJS=		Err.o erraction.o errafter.o errbefore.o errexit.o \
		errprefix.o errsource.o errstrtok.o errtag.o errtext.o \
		errtofix.o errusage.o tsort.o zfopen.o zmalloc.o

SRCS=		$(OBJS:%.o=../common/%.c)

DEFLIST=	-DELF
CPPFLAGS=	$(INCLIST) $(DEFLIST) $(CPPFLAGS.master)
CFLAGS +=	$(CCVERBOSE)
CSTD=	$(CSTD_GNU99)

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
		perl ../../tools/lint_hdr.pl $(PROG)	 > $(LINTOUT)
		$(LINT.c) $(SRCS)			2>&1 | tee -a $(LINTOUT)

include		../../../Makefile.targ

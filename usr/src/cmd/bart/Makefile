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
#
# Copyright (c) 2018, Joyent, Inc.

PROG=	bart
SRCS=	rules.c create.c compare.c main.c lutbl.c
OBJS=	rules.o create.o compare.o main.o lutbl.o
BART=	bart

include ../Makefile.cmd

LDLIBS +=	-lsec -lmd
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	$(CNOWARN_UNINIT)

SMOFF +=	indenting

#
# for messaging catalog
#

POFILE=	bart.po
DCFILE=	bart.dc

ROOTBINBART=	$(BART:%=$(ROOTBIN)/%)
ROOTLIBDIFFH=	$(DIFFH:%=$(ROOTLIB)/%)

.KEEP_STATE:

all:	$(PROG)

$(PROG):	$(OBJS)
	$(CC) -o $(PROG) $(OBJS) $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

clean:
	$(RM) $(OBJS)


#
# Use private rule
#
$(POFILE):
	$(RM) $@
	$(COMPILE.cpp)   $(SRCS) > bart.po.i
	$(XGETTEXT) $(XGETFLAGS) bart.po.i
	sed "/^domain/d"        messages.po     > $@
	$(RM)  bart.po.i messages.po

$(DCFILE):
	$(RM) $@
	$(COMPILE.cpp)   $(SRCS) > bart.dc.i
	$(XGETTEXT) -c TRANSLATION_NOTE_FOR_DC -t bart.dc.i
	sed "/^domain/d"        messages.po     > $@
	$(RM)  bart.dc.i messages.po

install:	all $(ROOTBINBART) $(ROOTLIBDIFFH)

clean:

lint:	lint_SRCS

include ../Makefile.targ

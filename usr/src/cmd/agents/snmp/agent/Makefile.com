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
# ident	"%Z%%M%	%I%	%E% SMI"
#

LIBRARY =	libssagent.a
VERS =		.1
SRCOBJS =	node.o access.o agent.o snmpd.o pagent.o subtree.o reg_subtree.o
OBJECTS =	$(SRCOBJS) personal.o

include $(SRC)/lib/Makefile.lib

LIBS =		$(DYNLIB) $(LINTLIB)
SRCS = 		$(SRCOBJS:%.o=$(SRCDIR)/%.c) personal.c

$(LINTLIB):=	SRCS = $(SRCDIR)/$(LINTSRC)
LDLIBS +=	-lssasnmp -lc -lsocket -lnsl

CLEANFILES +=	personal.c personal.lex.c

MAPFILES =	../agent-mapfile-vers 

CPPFLAGS =	-I. -I.. -I../../snmplib $(CPPFLAGS.master)
LINTFLAGS64 +=	-errchk=longptr64
#
# This library has references to hooks that are defined by the programs
# that link with it; need to turn off -zdefs.
#
ZDEFS =

.KEEP_STATE:

all: $(LIBS)

personal.c: ../personal.y
	$(YACC.y) ../personal.y
	$(MV) y.tab.c personal.c

personal.lex.c: ../personal.l
	$(LEX.l) ../personal.l > personal.lex.c

pics/personal.o: personal.c personal.lex.c
	$(COMPILE.c) -o pics/personal.o personal.c
	$(POST_PROCESS_O)

lint: lintcheck

include $(SRC)/lib/Makefile.targ

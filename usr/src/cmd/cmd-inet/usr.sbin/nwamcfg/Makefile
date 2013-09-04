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
# cmd/cmd-inet/usr.sbin/nwamcfg/Makefile

PROG=	nwamcfg
OBJS=	nwamcfg.o nwamcfg_lex.o nwamcfg_grammar.tab.o

include ../../../Makefile.cmd

XGETFLAGS +=	-a -x $(PROG).xcl
LFLAGS =	-t
LDLIBS +=	-ll -ltecla -lnwam -lumem
YFLAGS +=	-d -b nwamcfg_grammar
CLEANFILES +=	nwamcfg_lex.c nwamcfg_grammar.tab.c nwamcfg_grammar.tab.h
CLEANFILES +=	$(PROG).ln

CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-unused-label
CERRWARN +=	-_gcc=-Wno-implicit-function-declaration

.KEEP_STATE:

all: $(PROG) 

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG)

nwamcfg_lex.c:	nwamcfg_lex.l nwamcfg_grammar.tab.h nwamcfg.h
	$(LEX) $(LFLAGS) nwamcfg_lex.l > $@

nwamcfg_grammar.tab.h nwamcfg_grammar.tab.c:	nwamcfg_grammar.y nwamcfg.h
	$(YACC) $(YFLAGS) nwamcfg_grammar.y

nwamcfg_lex.o nwamcfg_grammar.tab.o := CCVERBOSE =

check:  $(PROG).c $(PROG).h
	$(CSTYLE) -pP $(PROG).c $(PROG).h
	$(HDRCHK) $(PROG).h

clean:
	$(RM) $(OBJS) $(CLEANFILES)

#
# We don't do lint of lex- and yacc- generated source files
#
lint:
	$(LINT.c) -c $(PROG).c $(LDLIBS)

include ../../../Makefile.targ

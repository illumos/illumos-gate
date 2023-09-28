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

include ../Makefile.cmd

PROG=		genmsg
PSRC_Y=		genmsg.y
C_OBJS=         main.o util.o

LEXARGS=
LEXSRCS=	genmsg.l
LEXINTSRCS=	lex.yy.c
LEXOBJS=	lex.yy.o

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-unused-variable

# because of labels from yacc
genmsg.o := CERRWARN +=	-_gcc=-Wno-unused-label
genmsg.o := SMATCH=off

LDLIBS += -ll
YFLAGS = -d
CPPFLAGS = -I../head $(CPPFLAGS.master)

# genmsg has a name clash with main() and libl.so.1.  However, genmsg must
# still export a number of "yy*" (libl) interfaces.  Reduce all other symbols
# to local scope.
MAPFILES +=	$(MAPFILE.LEX) $(MAPFILE.NGB)
MAPOPTS =	$(MAPFILES:%=-Wl,-M%)

LDFLAGS +=	$(MAPOPTS)

OBJS =          $(C_OBJS) $(PSRC_Y:%.y=%.o) $(LEXOBJS)
PSRC_C =        $(PSRC_Y:%.y=%.c)
SRCS =          $(C_OBJS:%.o=%.c) $(PSRC_C) $(LEXINTSRCS)

.KEEP_STATE:

all:    $(PROG)

install: all $(ROOTPROG)

$(PROG): $(OBJS) $(MAPFILES)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

$(LEXINTSRCS): $(LEXSRCS)
	$(LEX) $(LEXARGS) $(LEXSRCS)

$(PSRC_C) + y.tab.h:    $(PSRC_Y)
	$(YACC) $(YFLAGS) $(PSRC_Y)
	$(MV) y.tab.c $(PSRC_C)

$(OBJS): y.tab.h lex.yy.c

catalog:        $(POFILE)

$(POFILE):      $(SRCS)
	$(RM) $@
	$(COMPILE.cpp) $(SRCS)  > $(POFILE).i
	$(XGETTEXT) $(XGETFLAGS)        $(POFILE).i
	$(SED) "/^domain/d" messages.po > $@
	$(RM) $(POFILE).i messages.po

clean:
	$(RM) $(OBJS) $(PSRC_C) $(LEXINTSRCS) y.tab.h *.po

include ../Makefile.targ

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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/genmsg/Makefile

include ../Makefile.cmd

PROG=		genmsg
PSRC_Y=		genmsg.y
C_OBJS=         main.o util.o lex.yy.o

LEXARGS=
LEXSRCS=	genmsg.l
LEXINTSRCS=	lex.yy.c
LEXOBJS=	lex.yy.o

LDLIBS += -ll
YFLAGS = -d
CPPFLAGS = -I../head $(CPPFLAGS.master)

OBJS =          $(C_OBJS) $(PSRC_Y:%.y=%.o)
PSRC_C =        $(PSRC_Y:%.y=%.c)
SRCS =          $(C_OBJS:%.o=%.c) $(PSRC_C)

.KEEP_STATE:

all:    $(PROG)

install: all $(ROOTPROG)

$(PROG): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)
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

lint: $(SRCS) .WAIT lint_SRCS

clean:
	$(RM) $(OBJS) $(PSRC_C) y.tab.h lex.yy.c $(PSRC_C) *.po

include ../Makefile.targ

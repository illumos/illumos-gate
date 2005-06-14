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
# Copyright (c) 2001 by Sun Microsystems, Inc.
# All rights reserved.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/pools/poolbind/Makefile

PROG =		poolcfg
OBJS =		poolcfg_lex.o poolcfg_grammar.o
SRCS =		$(OBJS:%.o=%.c) $(COMMON_SRCS)
POFILES = 	$(OBJS:.o=.po)
POFILE =	poolcfg.po

include ../../Makefile.cmd
include ../Makefile.pools

LFLAGS =	-t
YFLAGS =	-d
CFLAGS +=	-I$(POOLSCOMMONDIR)
LDLIBS +=	-lpool -ll
XGETFLAGS =	-a
CLOBBERFILES +=	poolcfg_lex.c poolcfg_grammar.c poolcfg_grammar.h

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS) $(COMMON_OBJS)
	$(LINK.c) -o $@ $(OBJS) $(COMMON_OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o : $(POOLSCOMMONDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

install: all $(ROOTUSRSBINPROG)

poolcfg_lex.c: poolcfg.l poolcfg_grammar.h
	$(LEX) $(LFLAGS) poolcfg.l > $@

poolcfg_grammar.h poolcfg_grammar.c: poolcfg.y
	$(YACC) $(YFLAGS) poolcfg.y
	@$(MV) y.tab.h poolcfg_grammar.h
	@$(MV) y.tab.c poolcfg_grammar.c

poolcfg_lex.o poolcfg_grammar.o := CCVERBOSE =

clean:
	$(RM) $(OBJS) $(COMMON_OBJS) $(POFILES)

$(POFILE):	$(POFILES)
	$(RM) $@; cat $(POFILES) > $@

#
# We don't do lint of lex- and yacc- generated source files
#
lint:

include ../../Makefile.targ

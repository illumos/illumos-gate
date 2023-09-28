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
# Copyright (c) 2018, Joyent, Inc.

PROG =		poolcfg
OBJS =		poolcfg_lex.o poolcfg_grammar.o
SRCS =		$(OBJS:%.o=%.c) $(COMMON_SRCS)
POFILES =	$(OBJS:.o=.po)
POFILE =	poolcfg.po

include ../../Makefile.cmd
include ../Makefile.pools

# poolcf has a name clash with main() and libl.so.1.  However, poolcfg must
# still export a number of "yy*" (libl) interfaces.  Reduce all other symbols
# to local scope.
MAPFILES +=	$(MAPFILE.LEX) $(MAPFILE.NGB)
MAPOPTS =	$(MAPFILES:%=-Wl,-M%)

LFLAGS =	-t
YFLAGS =	-d
CFLAGS +=	-I$(POOLSCOMMONDIR)
LDFLAGS +=	$(MAPOPTS)
LDLIBS +=	-lpool -ll
XGETFLAGS =	-a
CLOBBERFILES +=	poolcfg_lex.c poolcfg_grammar.c poolcfg_grammar.h

# not linted
SMATCH=off

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS) $(COMMON_OBJS) $(MAPFILES)
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
# because of labels from yacc
poolcfg_lex.o poolcfg_grammar.o := CERRWARN += -_gcc=-Wno-unused-label

clean:
	$(RM) $(OBJS) $(COMMON_OBJS) $(POFILES)

$(POFILE):	$(POFILES)
	$(RM) $@; cat $(POFILES) > $@

include ../../Makefile.targ

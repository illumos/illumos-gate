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
# Copyright 1989,2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

PROG=		prex

OBJS.c=		source.o	\
		main.o		\
		util.o		\
		expr.o		\
		spec.o		\
		set.o		\
		queue.o		\
		cmd.o		\
		new.o		\
		list.o		\
		fcn.o		\
		prbk.o		\
		help.o

OBJS.yl=	prexgram.o	\
		prexlex.o

OBJS=		 $(OBJS.yl) $(OBJS.c)

SRCS= $(OBJS.c:%.o=../%.c) $(OBJS.yl:%.o=%.c)

SRCS.yl = $(OBJS.yl:%.o=%.c)
CLEANFILES = $(SRCS.yl)  y.tab.h

include	../../../Makefile.cmd

POFILE= prex.po
POFILES= $(OBJS.c:%.o=%.po)

#YFLAGS=	-d -t -v
YFLAGS=		-d
LFLAGS=		-v
# FOR normal makefile, uncomment the next line
LDLIBS +=	-lgen -ltnfctl -lelf -lc

CFLAGS +=	$(CCVERBOSE)
CERRWARN +=	-_gcc=-Wno-unused-label
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-uninitialized

# not linted
SMATCH=off

.KEEP_STATE:

.PARALLEL: $(OBJS)

all: $(PROG)

#OBJS can be built in parallel after all .c (and y.tab.h) are properly built
$(PROG): $(SRCS.yl) .WAIT $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

#This also builds y.tab.h
prexgram.c: ../prexgram.y
	$(YACC.y) ../prexgram.y
	mv y.tab.c $@

prexlex.c: ../prexlex.l
	$(RM) $@
	$(LEX.l) ../prexlex.l > $@

#Use %.c in priority to ../%.c for prexgram.c and prexlec.c
%.o:	%.c
	$(COMPILE.c) $<

%.o:	../%.c
	$(COMPILE.c) $<


$(ROOTBIN):
	$(INS.dir)

$(POFILE):      $(POFILES)
	$(RM)	$@
	cat     $(POFILES)      > $@

clean:
	$(RM) $(OBJS) $(CLEANFILES)

lint: $(OBJS)
	$(LINT.c) $(SRCS)

include	../../../Makefile.targ

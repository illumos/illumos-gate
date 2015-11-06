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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG= cscope-fast

OBJS= 	main.o dir.o crossref.o scanner.o lookup.o command.o display.o \
	find.o edit.o exec.o help.o history.o input.o menu.o alloc.o \
	cgrep.o compath.o invlib.o logdir.o \
	mouse.o mygetenv.o mygetwd.o mypopen.o \
	vpaccess.o vpfopen.o vpinit.o vpopen.o vpstat.o
SRCS=	$(OBJS:%.o=%.c)
CLEANFILES += $(OBJS) scanner.c
TMPDIR= /tmp

include ../Makefile.tools

# these three are because we cannot seem to redefine the size of YYLMAX,
# and thus yytext, in the code because yytext is defined before our code
# is seen. YYLMAX is supposed to be STMTMAX+PATLEN+1.
PATLEN=		250
STMTMAX=	10000
YYLMAX=		10251
CFLAGS +=	-DPATLEN=$(PATLEN) -DSTMTMAX=$(STMTMAX) -DYYLMAX=$(YYLMAX)
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-implicit-function-declaration
CERRWARN +=	-_gcc=-Wno-unused
CERRWARN +=	-_gcc=-Wno-uninitialized

CFLAGS +=	$(CCVERBOSE)
LDLIBS +=	-lcurses -ll

.KEEP_STATE:

.PARALLEL: $(OBJS)

all:	$(PROG)

# because of goto's in the scanner
scanner.o := CCVERBOSE=

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all .WAIT  $(ROOTONBLDMACHPROG)

clean:
	$(RM) $(CLEANFILES)

lint: lint_SRCS

include ../Makefile.targ

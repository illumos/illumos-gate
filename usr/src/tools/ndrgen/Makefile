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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG=	ndrgen ndrgen1

MAN1ONBLDFILES=	ndrgen.1onbld

OBJS=	ndr_main.o ndr_lex.o ndr_anal.o \
	ndr_gen.o ndr_parse.o ndr_print.o
SRCS=	$(OBJS:%.o=%.c)

include ../Makefile.tools

CFLAGS += $(CCVERBOSE)
CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-unused

CLEANFILES += $(OBJS) y.tab.c y.tab.h

$(ROOTONBLDMAN1ONBLDFILES) := FILEMODE=      644

.KEEP_STATE:

.PARALLEL: $(OBJS)

all:	$(PROG) $(MAN1ONBLDFILES)

install: all .WAIT $(ROOTONBLDMACHPROG) $(ROOTONBLDMAN1ONBLDFILES)

lint:	lint_SRCS

clean:
	$(RM) $(CLEANFILES)

$(OBJS): y.tab.h

y.tab.c y.tab.h: ndr_parse.y
	$(YACC.y) -d ndr_parse.y

ndr_parse.o : y.tab.c
	$(COMPILE.c) -o $@ y.tab.c
	$(POST_PROCESS_O)

ndrgen1: $(OBJS)
	$(LINK.c) -o $@ $(OBJS)
	$(POST_PROCESS)

include ../Makefile.targ

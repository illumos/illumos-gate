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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2020 Joyent, Inc.

include		../Makefile.cmd

PROG =		oawk

SRCS =		b.c lib.c main.c parse.c run.c tran.c

#TXTS =		README EXPLAIN

OBJS =		awk.g.o awk.lx.o proctab.o tmptoken.o		\
		$(SRCS:%.c=%.o)

#
# for message catalogue
#
POFILES=        $(OBJS:%.o=%.po)
POFILE=         oawk.po
XGETFLAGS +=    -a -x oawk.xcl

NATIVEDIR =	native
MAKEPRCTAB =	$(NATIVEDIR)/makeprctab

NATIVEOBJS =	$(NATIVEDIR)/makeprctab.o $(NATIVEDIR)/tmptoken.o
$(MAKEPRCTAB) :=	CC = $(NATIVECC)
$(MAKEPRCTAB) :=	POST_PROCESS=
$(MAKEPRCTAB) :=	POST_PROCESS_O=
$(MAKEPRCTAB) :=	NATIVE_LIBS += libm.so libc.so

CLEANFILES =	proctab.c y.tab.h y.tab.c awk.h awk.g.c		\
		tmptoken.c awk.lx.c $(NATIVEOBJS) $(MAKEPRCTAB)	\
		temp

YFLAGS =	-d
LDLIBS += -lm
CPPFLAGS =      -I. $(CPPFLAGS.master)
CPPFLAGS +=	-D_FILE_OFFSET_BITS=64

CERRWARN +=	-_gcc=-Wno-implicit-function-declaration
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-extra
CERRWARN +=	-_gcc=-Wno-parentheses

# because of labels from yacc
awk.lx.o awk.g.o := CERRWARN +=	-_gcc=-Wno-unused-label

# missing type declarations
SMATCH =	off

.KEEP_STATE :

all :		$(PROG) $(TXTS)

$(PROG) :	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

$(POFILE):      $(POFILES)
		$(RM)	$@
		$(CAT)	$(POFILES) > $@

awk.g.c + awk.h :	awk.g.y
		$(RM) awk.g.c awk.h
		$(YACC.y) awk.g.y
		$(MV) y.tab.c awk.g.c
		$(MV) y.tab.h awk.h

awk.lx.c:	awk.lx.l
		$(LEX.l) -w awk.lx.l > awk.lx.c

tmptoken.c :	tokenscript token.c
		$(RM) $@
		ed - < tokenscript

proctab.c :	$(MAKEPRCTAB)
		$(RM) $@
		$(MAKEPRCTAB) > $@

$(MAKEPRCTAB) :	$(NATIVEDIR) $(NATIVEOBJS)
		$(LINK.c) $(NATIVEOBJS) -o $@ $(XLDLIBS5CC)

install :	all $(ROOTPROG)

$(NATIVEDIR) :
		-@mkdir -p $(NATIVEDIR)

$(NATIVEDIR)/%.o :	%.c
		$(COMPILE.c) -o $@ $<

clean:
		$(RM) $(OBJS) $(CLEANFILES)

lint :		lint_SRCS

strip:
		$(STRIP) $(PROG)

include		../Makefile.targ

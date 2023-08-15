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
# Copyright (c) 1989 by Sun Microsystems, Inc.
#
# Copyright (c) 2018, Joyent, Inc.

include		../Makefile.cmd

PROG =		tbl

SRCS =		t0.c t1.c t2.c t3.c t4.c t5.c t6.c t7.c	\
		t8.c t9.c tb.c tc.c te.c tf.c tg.c ti.c	\
		tm.c ts.c tt.c tu.c tv.c

OBJS =		$(SRCS:%.c=%.o)

POFILES=        $(OBJS:%.o=%.po)
POFILE=         tbl.po

CERRWARN	+= -_gcc=-Wno-implicit-function-declaration
CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= $(CNOWARN_UNINIT)
CERRWARN	+= -_gcc=-Wno-char-subscripts

# not linted
SMATCH=off

.KEEP_STATE :

all :		$(PROG)

$(PROG):	$(OBJS)
		$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
		$(POST_PROCESS)

$(POFILE):      $(POFILES)
	$(RM)	$@
	cat     $(POFILES)      > $@

install :	all $(ROOTPROG)

clean :
		$(RM) $(OBJS)

lint:		lint_SRCS

strip :
		$(STRIP) $(PROG)

include		../Makefile.targ

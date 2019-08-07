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

PROG=	amt
OBJS=	amt.o
SRCS=	$(OBJS:%.o=../%.c)

include ../../Makefile.cmd

LDLIBS +=	-lelf

LINTFLAGS +=	-erroff=E_NAME_USED_NOT_DEF2
LINTFLAGS64 +=	-erroff=E_NAME_USED_NOT_DEF2

CERRWARN +=	$(CNOWARN_UNINIT)

CLEANFILES	+= $(PROG) $(OBJS)

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

lint:	lint_SRCS

%.o:	../%.c
	$(COMPILE.c) $<

clean:
	$(RM) $(CLEANFILES)

include ../../Makefile.targ

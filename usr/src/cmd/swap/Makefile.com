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
# cmd/swap/Makefile.com

PROG=	swap
OBJS=	$(PROG).o
SRCS=	$(OBJS:%.o=../%.c)

include ../../Makefile.cmd

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D_LARGEFILE64_SOURCE
CFLAGS64 +=	$(CCVERBOSE)
CERRWARN +=	-_gcc=-Wno-uninitialized

FILEMODE=02555

CLEANFILES += $(OBJS)

.KEEP_STATE:

all: $(PROG)

LDLIBS	+=	-ldiskmgt -lcmdutils
$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

lint:	lint_SRCS

%.o:	../%.c
	$(COMPILE.c) $<

clean:
	$(RM) $(CLEANFILES)

include ../../Makefile.targ

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

include	../../../Makefile.cmd

PROG =		cputrack
OBJS =		$(PROG).o caps.o time.o setgrp.o strtoset.o
SRCS =		$(OBJS:%.o=../../common/%.c)
LDLIBS +=	-lcpc -lpctx

CFLAGS +=	$(CCVERBOSE) $(CTF_FLAGS)
CFLAGS64 +=	$(CCVERBOSE) $(CTF_FLAGS)
CPPFLAGS +=	-I$(SRC)/lib/libcpc/common

# not linted
SMATCH=off

LINTFLAGS +=	-u
LINTFLAGS64 +=	-u

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)
	$(CTFMERGE) -L VERSION -o $@ $(OBJS)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

strip:
	$(STRIP) $(PROG)

%.o:	../../common/%.c
	$(COMPILE.c) $<
	$(CTFCONVERT_O)

include	../../../Makefile.targ

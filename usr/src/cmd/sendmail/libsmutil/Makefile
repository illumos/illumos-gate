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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/sendmail/libsmutil/Makefile
#

include		../../Makefile.cmd
include		../Makefile.cmd

INCPATH=	-I. -I../src -I../include
CPPFLAGS=	$(INCPATH) $(CPPFLAGS.sm)

ARFLAGS=	cq

OBJS=   cf.o debug.o err.o lockfile.o safefile.o snprintf.o

SRCS=	$(OBJS:%.o=%.c)

libsmutil=	libsmutil.a

.KEEP_STATE:
all: $(libsmutil)

.PARALLEL:	$(OBJS)

$(libsmutil): $(OBJS)
	$(RM) $@
	$(AR) $(ARFLAGS) $@ $(OBJS)

clean:
	$(RM) $(OBJS) $(libsmutil)

lint:	lint_SRCS

depend obj:

install: all

include		../../Makefile.targ

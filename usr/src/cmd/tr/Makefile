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
#
# Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
# Use is subject to license terms.
#


PROG=		tr
XPG4PROG=	$(PROG)
XPG6PROG=	$(PROG)

OBJS=		tr.o str.o cset.o cmap.o
SRCS=	 	$(OBJS:%.o=%.c)

include ../Makefile.cmd

CLOBBERFILES=	$(PROG)


C99MODE=	-xc99=%all
C99LMODE=	-Xc99=%all
CPPFLAGS +=	-D_ILLUMOS_PRIVATE -I.
LINTFLAGS +=	-D_ILLUMOS_PRIVATE -I.

# install rules
$(ROOTINC)/% : %
	$(INS.file)

.KEEP_STATE:

.PARALLEL: $(OBJS)

all:		$(PROG) 

$(PROG):	$(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: all .WAIT $(ROOTPROG) $(ROOTXPG4PROG) $(ROOTXPG6PROG)

$(ROOTXPG4PROG) $(ROOTXPG6PROG):
	-$(RM) $@
	-$(LN) -s ../../bin/$(PROG) $@

lint: 	lint_SRCS

clean:
	$(RM) $(OBJS)

include ../Makefile.targ

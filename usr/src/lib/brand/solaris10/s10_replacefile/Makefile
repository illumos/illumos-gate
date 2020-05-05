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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#

PROG =		s10_replacefile
PROGS =		$(PROG)
OBJS =		s10_replacefile

all:		$(PROG)

include ../Makefile.s10
include $(SRC)/cmd/Makefile.cmd

# override the install directory
ROOTBIN =	$(ROOTBRANDDIR)
CLOBBERFILES =	$(OBJS) $(ROOTPROGS)

UTSBASE =	$(SRC)/uts

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D_REENTRANT

.KEEP_STATE:

install:	all $(ROOTPROGS)

clean:
		$(RM) $(PROG) $(OBJS)


include $(SRC)/cmd/Makefile.targ

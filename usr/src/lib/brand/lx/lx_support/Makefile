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
# Copyright 2019 Joyent, Inc.

PROG =		lx_support
PROGS =		$(PROG)
OBJS =		lx_support

all:		$(PROG)

include ../Makefile.lx
include $(SRC)/cmd/Makefile.cmd

# override the install directory
ROOTBIN =	$(ROOTBRANDDIR)
CLOBBERFILES =	$(OBJS) $(ROOTPROGS)

UTSBASE =	$(SRC)/uts

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D_REENTRANT -I$(UTSBASE)/common/brand/lx
LDLIBS +=	-lzonecfg

SMOFF += signed

.KEEP_STATE:

install:	all $(ROOTPROGS)

clean:
		$(RM) $(PROG) $(OBJS)

lint:		lint_PROG

include $(SRC)/cmd/Makefile.targ

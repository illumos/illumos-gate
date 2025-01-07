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
# Copyright (c) 2019, Joyent, Inc.
# Copyright 2024 Oxide Computer Company

PROG=		ipcs
XPG4PROG=	$(PROG)
OBJS=		ipcs.o $(HEXDUMP_OBJS)

include ../Makefile.cmd
include $(SRC)/common/hexdump/Makefile.com

CFLAGS +=	$(CCVERBOSE)
LDLIBS +=	-lproject

# main() too hairy
SMATCH =	off

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTXPG4PROG)

clean:
	$(RM) $(OBJS)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

$(ROOTXPG4PROG):	$(ROOTPROG)
	-$(RM) $(ROOTXPG4PROG)
	-$(LN) -s ../../bin/$(PROG) $(ROOTXPG4PROG)

clean:

include $(SRC)/common/hexdump/Makefile.targ
include ../Makefile.targ

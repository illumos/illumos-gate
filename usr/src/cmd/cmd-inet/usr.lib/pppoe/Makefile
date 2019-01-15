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
# Copyright 2000-2002 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

include		../../../Makefile.cmd

PROG=		pppoec pppoed
CLIENT_OBJS=	pppoec.o common.o logging.o
DAEMON_OBJS=	pppoed.o options.o logging.o common.o

CPPFLAGS +=	-I$(SRC)/uts/common

# not linted
SMATCH=off

.KEEP_STATE:

all:		$(PROG)

OBJS=		$(CLIENT_OBJS) $(DAEMON_OBJS)

LDLIBS +=	-lsocket -lnsl

.PARALLEL:	$(OBJS)

pppoec:	$(CLIENT_OBJS)
	$(LINK.c) $(CLIENT_OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

pppoed:	$(DAEMON_OBJS)
	$(LINK.c) $(DAEMON_OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

include		../Makefile.lib

install:	all .WAIT $(PROG) $(ROOTLIBINETPROG)

clean:
	$(RM) $(OBJS)

lint:
	$(LINT.c) $(CLIENT_OBJS:%.o=%.c) $(LDLIBS)
	$(LINT.c) $(DAEMON_OBJS:%.o=%.c) $(LDLIBS)

include		../../../Makefile.targ

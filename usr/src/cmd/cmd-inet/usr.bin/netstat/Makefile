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
# Copyright (c) 1990 Mentat Inc.
#
# Copyright (c) 2018, Joyent, Inc.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
# Copyright 2025 Hans Rosenfeld

PROG=		netstat

LOCALOBJS=	netstat.o
COMMONOBJS=	compat.o

include ../../../Makefile.cmd
# netstat uses libproc to grab processes and extract information about their
# sockets. In order to be able to grab 64-bit processes, netstat itself must
# be built 64-bit.
$(BUILD64) include ../../../Makefile.cmd.64

include ../../Makefile.cmd-inet

LOCALSRCS=	$(LOCALOBJS:%.o=%.c)
COMMONSRCS=	$(CMDINETCOMMONDIR)/$(COMMONOBJS:%.o=%.c)

OBJS=		$(LOCALOBJS) $(COMMONOBJS)
SRCS=		$(LOCALSRCS) $(COMMONSRCS)

CLEANFILES =	$(OBJS)

include $(SRC)/cmd/stat/Makefile.stat

CPPFLAGS += -DNDEBUG -I$(CMDINETCOMMONDIR)
LDLIBS += -ldhcpagent -lsocket -lnsl -lkstat -ltsnet -ltsol -lproc

CSTD=		$(CSTD_GNU99)

.KEEP_STATE:

all: $(PROG)

ROOTPROG=   $(PROG:%=$(ROOTBIN)/%)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTPROG)

clean:
	$(RM) $(CLEANFILES)

include ../../../Makefile.targ


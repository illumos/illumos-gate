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
# cmd/cmd-inet/usr.lib/in.dhcpd/tests/Makefile
#

COMMON_NET =	$(SRC)/common/net/dhcp

PROG = test_client
OBJS = test_client.o
SRCS = $(OBJS:%.o=%.c)

DPROG = test_dstore
DOBJS = test_dstore.o
DSRCS = $(OBJS:%.o=%.c)

MPROG = mkdstore
MOBJS = mkdstore.o
MSRCS = $(OBJS:%.o=%.c)

include ../../../../Makefile.cmd

DLIBS = -linetutil -ldhcpsvc -lsocket -lnsl -lmtmalloc
LDLIBS += $(DLIBS)
CPPFLAGS += -g -DNDEBUG -D_REENTRANT -I$(COMMON_NET)
LINTFLAGS += -Xt

.KEEP_STATE:

all: $(PROG) $(DPROG) $(MPROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(DPROG): $(DOBJS)
	$(LINK.c) $(DOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(MPROG): $(MOBJS)
	$(LINK.c) $(MOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

%.o:	$(COMMON_NET)/%.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POST_PROCESS_O)

clean:
	$(RM) $(OBJS) $(DOBJS) $(MOBJS)

install:
	$(ECHO) "Nothing to Install" >&2


lint: 
	$(LINT.c) $(PROG).c $(ENVLDLIBS1) $(DLIBS)
	$(LINT.c) $(DPROG).c $(ENVLDLIBS1) $(DLIBS)
	$(LINT.c) $(MPROG).c $(ENVLDLIBS1) $(DLIBS)

include ../../../../Makefile.targ

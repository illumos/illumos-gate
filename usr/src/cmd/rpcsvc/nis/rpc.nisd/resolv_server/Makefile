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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# Makefile for the nis+ dns fwd daemon
#

SRVOBJS= main.o \
	ypresolv_proc.o \
	rpc_as.o \
	svc_run_as.o \
	ngethostbyname.o \
	nget_answer.o \
	nres_search.o \
	nres_rcv.o \
	nres_send.o

COMMONOBJS= resolv_common.o

OBJS= $(SRVOBJS) $(COMMONOBJS)
SRCS= $(OBJS:.o=.c)

include $(SRC)/cmd/Makefile.cmd

PROG= rpc.nisd_resolv

CFLAGS += $(CCVERBOSE)

# We don't use -lsocket for 4.x build
LDLIBS += -lnsl -lresolv -lsocket 

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTUSRSBINPROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

resolv_common.o: ../resolv_common.c
	$(COMPILE.c) ../resolv_common.c

lint:
	$(LINT.c) $(SRVOBJS:.o=.c) ../resolv_common.c $(LDLIBS)

clobber:  clean
	$(RM) $(PROG)

clean:
	$(RM) $(OBJS)

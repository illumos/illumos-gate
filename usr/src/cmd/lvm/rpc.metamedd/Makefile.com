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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Architecture independent makefile for rpc.metamedd
#
# cmd/lvm/rpc.metamedd/Makefile.com

PROG = rpc.metamedd 

RPC_DIR = $(SRC)/uts/common/sys/lvm

RPC_OBJS = \
	meta_basic.x \
	metamed.x \
	meta_arr.x

DERIVED_OBJS = \
	metamed_svc.o \
	metamed_xdr.o \
	meta_basic_xdr.o

LOCAL_OBJS= \
	med_db.o \
	med_error.o \
	med_freeresult.o \
	med_hash.o \
	med_init.o \
	med_mem.o \
	med_synch.o \
	med_svc_subr.o

LOCAL_SRCS   = $(LOCAL_OBJS:%.o=../%.c)
DERIVED_SRCS = $(DERIVED_OBJS:%.o=%.c)

include ../../../Makefile.cmd
include ../../Makefile.lvm

LDLIBS += -lmeta -lsocket -lnsl
LDFLAGS += $(ZINTERPOSE)

CPPFLAGS += $(DEFINES)

lint := LINTFLAGS += -m

metamed_svc.c := RPCGENFLAGS += -K -1

.KEEP_STATE:

%.o:    ../%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

all:	$(PROG)

$(PROG): $(LOCAL_OBJS) $(DERIVED_OBJS)
	$(LINK.c) -o $@ $(LOCAL_OBJS) $(DERIVED_OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG)

cstyle:
	$(CSTYLE) $(LOCAL_SRCS)

lint:
	$(LINT.c) $(LINTFLAGS) $(LOCAL_SRCS)

clean:
	$(RM) $(DERIVED_SRCS) $(DERIVED_OBJS) $(LOCAL_OBJS) $(RPC_OBJS)

clobber: clean
	$(RM) $(PROG)

$(RPC_OBJS): $$(@:%=$(RPC_DIR)/%)
	$(RM) $@
	$(CP) $(RPC_DIR)/$@ .

meta_basic_xdr.c: meta_basic.x
	$(RPCGEN) $(RPCGENFLAGS) -c meta_basic.x > $@

metamed_xdr.c: metamed.x meta_arr.x
	$(RPCGEN) $(RPCGENFLAGS) -c metamed.x > $@

metamed_svc.c: metamed.x meta_arr.x
	$(RPCGEN) $(RPCGENFLAGS_SERVER) metamed.x > $@

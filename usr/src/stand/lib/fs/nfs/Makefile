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
# ident	"%Z%%M%	%I%	%E% SMI"
#

LIBRARY = libnfs.a
LOCOBJS = auth_none.o auth_unix.o bootparams.o getdents.o \
	  getdents3.o getdents4.o lookup.o mount.o \
	  nfsops.o nfs2ops.o nfs3ops.o nfs4ops.o pathname.o pmap.o rpc.o \
	  clnt_budp.o clnt_btcp.o nfs_xdr.o nfs3_xdr.o nfs4_xdr.o xdr_rec.o

RPC_CMNOBJS = rpc_prot.o
CMNOBJS = bootparam_xdr.o
OBJECTS = $(LOCOBJS) $(RPC_CMNOBJS) $(CMNOBJS)

include ../Makefile.com

RPC_CMNDIR = $(TOPDIR)/uts/common/rpc
CMNDIR = $(TOPDIR)/uts/common/fs/nfs
SRCS	= $(LOCOBJS:%.o=$(SRCDIR)/%.c) $(RPC_CMNOBJS:%.o=$(RPC_CMNDIR)/%.c) \
		$(CMNOBJS:%.o=$(CMNDIR)/%.c)

LDLIBS += -linet -lsock -lxdr
CPPFLAGS += $(SOCKCPPFLAGS) $(DHCPCPPFLAGS) -I../../inet
CPPFLAGS += -I$(STANDDIR)/lib/sa -I$(TOPDIR)/head

#
# This is really wrong, but we have no choice since <rpc/*.h> needs to
# resolve types that are in <sys/stream.h>.  Thankfully, we don't use
# anything from libsock.a that relies on the definition of an mblk_t.
#
CPPFLAGS += -U_SYS_STREAM_H

objs/%.o: $(RPC_CMNDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../../Makefile.targ

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

LIBRARY =	libmlrpc.a
VERS =		.1

OBJS_COMMON = 			\
	mlndo.o			\
	mlndr.o			\
	mlrpc_client.o		\
	mlrpc_encdec.o		\
	mlrpc_heap.o		\
	mlrpc_server.o		\
	mlrpc_svc.o

NDLLIST = rpcpdu

OBJECTS=	$(OBJS_COMMON) $(OBJS_SHARED) $(NDLLIST:%=%_ndr.o)

include ../../../Makefile.lib
include ../../Makefile.lib

INCS += -I$(SRC)/common/smbsrv

LDLIBS +=	-lsmb -lc

CPPFLAGS += $(INCS) -D_REENTRANT

SRCS=   $(OBJS_COMMON:%.o=$(SRCDIR)/%.c)		\
	$(OBJS_SHARED:%.o=$(SRC)/common/smbsrv/%.c)

include ../../Makefile.targ
include ../../../Makefile.targ

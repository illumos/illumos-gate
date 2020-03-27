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
# Copyright 2015 Gary Mills
# Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
#
#

LIBRARY =	libidmap.a
VERS =		.1
OBJECTS =			\
	directory_client.o	\
	directory_error.o	\
	directory_helper.o	\
	directory_rpc_clnt.o	\
	idmap_xdr.o		\
	sidutil.o		\
	sized_array.o		\
	idmap_api.o		\
	idmap_cache.o		\
	utils.o

include ../../Makefile.lib
CSTD = $(CSTD_GNU99)

LIBS =		$(DYNLIB)
LDLIBS +=	-lc -lavl -lnsl -lnvpair -luutil

SRCDIR =	../common

# Relative path to ensure path to idmap_prot.h is also relative
IDMAP_PROT_X =		../../../uts/common/rpcsvc/idmap_prot.x

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D_REENTRANT -I$(SRCDIR)

CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-switch

CLOBBERFILES +=	idmap_xdr.c

.KEEP_STATE:

all: $(LIBS)

idmap_xdr.c:	$(IDMAP_PROT_X)
	$(RM) $@; $(RPCGEN) -CMNc -o $@ $(IDMAP_PROT_X)


include ../../Makefile.targ

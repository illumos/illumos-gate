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
# lib/librpcsvc/Makefile
#

LIBRARY= librpcsvc.a
VERS = .1

OBJECTS= rstat_simple.o rstat_xdr.o rusers_simple.o rusersxdr.o rusers_xdr.o \
	 rwallxdr.o spray_xdr.o nlm_prot.o sm_inter_xdr.o nsm_addr_xdr.o \
	 bootparam_prot_xdr.o mount_xdr.o mountlist_xdr.o rpc_sztypes.o \
	 bindresvport.o

# include library definitions
include ../../Makefile.lib

# install this library in the root filesystem
include ../../Makefile.rootfs

# Don't mess with this. DAAMAPFILE gets correctly overridden
# for 64bit.
MAPFILE=	$(MAPDIR)/mapfile

CLOBBERFILES +=	$(MAPFILE)

SRCS=		$(OBJECTS:%.o=../common/%.c)

pics/%.o: ../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

LIBS = $(DYNLIB)


CPPFLAGS += -DYP
LDLIBS += -lnsl -lc
DYNFLAGS += -M $(MAPFILE)

.KEEP_STATE:


$(DYNLIB): $(MAPFILE)
$(MAPFILE):
	@cd $(MAPDIR); $(MAKE) mapfile

lint:	lintcheck

# include library targets
include ../../Makefile.targ

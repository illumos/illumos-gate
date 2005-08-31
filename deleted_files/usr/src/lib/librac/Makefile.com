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

LIBRARY= librac.a
VERS = .1

OBJECTS=  \
clnt_generic.o clnt_dg.o rac.o clnt_vc.o  rpcb_clnt.o xdr_rec_subr.o xdr_rec.o

# include library definitions
include ../../Makefile.lib

SRCS=	$(OBJECTS:%.o=../rpc/%.c)

MAPFILE=	$(MAPDIR)/mapfile

LIBS = $(DYNLIB) $(LINTLIB)

$(LINTLIB):= SRCS = ../rpc/llib-lrac

LINTSRC=	$(LINTLIB:%.ln=%)

LDLIBS += -lnsl -lc
DYNFLAGS += -M $(MAPFILE)

CPPFLAGS += -DPORTMAP -DNIS
CFLAGS += $(CCVERBOSE)

.KEEP_STATE:

$(DYNLIB):	$(MAPFILE)

$(MAPFILE):
	@cd $(MAPDIR); $(MAKE) mapfile

lint:		lintcheck

include ../../Makefile.targ

pics/%.o: ../rpc/%.c
	$(COMPILE.c) -o $@  $<
	$(POST_PROCESS_O)

# install rule for lint library target
$(ROOTLINTDIR)/%:	../rpc/%
	$(INS.file)

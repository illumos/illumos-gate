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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libsec/Makefile.com
#

LIBRARY= libsec.a
VERS= .1

OBJS_SHARED= acl_common.o
OBJS_COMMON= aclcheck.o aclmode.o aclsort.o acltext.o aclutils.o
OBJECTS= $(OBJS_COMMON) $(OBJS_SHARED)

# include library definitions
include ../../Makefile.lib

LIBS =		$(DYNLIB) $(LINTLIB)

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I$(SRCDIR) -I../../../common/acl
LDLIBS += -lc 

# install this library in the root filesystem
include ../../Makefile.rootfs

SRCS=		$(OBJS_COMMON:%.o=$(SRCDIR)/%.c) \
		 $(OBJS_SHARED:%.o=$(SRC)/common/acl/%.c)

$(LINTLIB):= SRCS=	$(SRCDIR)/$(LINTSRC)

SRCDIR=		../common
MAPDIR=		../spec/$(TRANSMACH)
SPECMAPFILE=	$(MAPDIR)/mapfile

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

pics/%.o: ../../../common/acl/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../../Makefile.targ

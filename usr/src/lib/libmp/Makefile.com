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
# lib/libmp/Makefile.com
#
# (libmp.so.1 is built from selected platform-specific makefiles)
#

LIBRARY=	libmp.a
VERS=		.2

OBJECTS= gcd.o madd.o mdiv.o mout.o msqrt.o mult.o pow.o util.o

# include library definitions
include ../../Makefile.lib

# install this library in the root filesystem
include ../../Makefile.rootfs

MAPFILE=	$(MAPDIR)/mapfile
OMAPFILE=	$(MAPDIR)/mapfile_1
SRCS=		$(OBJECTS:%.o=../common/%.c)

LIBS =		$(DYNLIB)

CFLAGS	+=	$(CCVERBOSE)
DYNFLAGS +=	-M $(MAPFILE)
LDLIBS +=	-lc

.KEEP_STATE:

lint: lintcheck

$(DYNLIB): 	$(MAPFILE)

$(MAPFILE):
	@cd $(MAPDIR); $(MAKE) mapfile

$(OMAPFILE):
	@cd $(MAPDIR); $(MAKE) mapfile_1

#
# Include library targets
#
include ../../Makefile.targ

pics/%.o: ../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

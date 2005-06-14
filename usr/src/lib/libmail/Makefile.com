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
# lib/libmail/Makefile.com
#

LIBRARY= libmail.a
VERS= .1

OBJECTS= 	abspath.o  casncmp.o   copystream.o delempty.o \
		getdomain.o maillock.o notifyu.o    popenvp.o \
		s_string.o  setup_exec.o strmove.o  skipspace.o \
		substr.o   systemvp.o  trimnl.o     xgetenv.o

# include library definitions
include ../../Makefile.lib

MAPFILE=	$(MAPDIR)/mapfile
SRCS=		$(OBJECTS:%.o=../common/%.c)

LIBS =		$(DYNLIB) $(LINTLIB)

$(LINTLIB):= SRCS = ../common/llib-lmail

LINTSRC=	$(LINTLIB:%.ln=%)

CPPFLAGS =	-I../inc $(CPPFLAGS.master)
CFLAGS +=	$(CCVERBOSE)
DYNFLAGS +=	-M $(MAPFILE)
LDLIBS +=	-lc

.KEEP_STATE:

lint: lintcheck

$(DYNLIB) $(DYNLIB64):	$(MAPFILE)

$(MAPFILE):
	@cd $(MAPDIR); $(MAKE) mapfile

# include library targets
include ../../Makefile.targ

pics/%.o: ../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../inc/%.h

# install rule for lint library target
$(ROOTLINTDIR)/%: ../common/%
	$(INS.file)

# install rule for 64 bit lint library target
$(ROOTLINTDIR64)/%: ../common/%
	$(INS.file)

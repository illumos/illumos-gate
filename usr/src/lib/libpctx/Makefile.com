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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2019 Joyent, Inc.
#

LIBRARY = libpctx.a
VERS = .1

OBJECTS = libpctx.o

# include library definitions
include ../../Makefile.lib

LIBS = $(DYNLIB) $(LINTLIB)
$(LINTLIB) :=	SRCS = ../common/llib-lpctx
LDLIBS +=	-lproc -lc

SRCDIR =	../common

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D_REENTRANT -I$(SRCDIR)

# false positive: pctx_run() error: dereferencing freed memory 'pctx'
SMOFF += free

.KEEP_STATE:

all: $(LIBS)

# x86 and sparc have different alignment complaints (all LINTED).
# Make lint shut up about suppression directive not used.
lint := LINTFLAGS += -erroff=E_SUPPRESSION_DIRECTIVE_UNUSED
lint := LINTFLAGS64 += -erroff=E_SUPPRESSION_DIRECTIVE_UNUSED

lint: lintcheck

# include library targets
include ../../Makefile.targ

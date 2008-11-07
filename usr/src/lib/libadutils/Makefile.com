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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

LIBRARY =	libadutils.a
VERS =		.1
OBJECTS =	adutils.o
LINT_OBJECTS =	adutils.o

include ../../Makefile.lib

LIBS =		$(DYNLIB) $(LINTLIB)
LDLIBS +=	-lc -lldap -lidmap
SRCDIR =	../common
$(LINTLIB):=	SRCS = $(SRCDIR)/$(LINTSRC)
IDMAP_PROT_DIR =	$(SRC)/head/rpcsvc
CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D_REENTRANT -I$(SRCDIR) -I$(SRC)/lib/libidmap/common \
		-I$(IDMAP_PROT_DIR)

lint := OBJECTS = $(LINT_OBJECTS)

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

include ../../Makefile.targ

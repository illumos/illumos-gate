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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2015 Joyent, Inc.
#

LIBRARY=	libzonecfg.a
VERS=		.1
LIB_OBJS=	libzonecfg.o getzoneent.o scratchops.o
XML_OBJS=	os_dtd.o
OBJECTS=	$(LIB_OBJS) $(XML_OBJS)

include ../../Makefile.lib

LIBS =		$(DYNLIB) $(LINTLIB)
LDLIBS +=	-lc -lsocket -luuid -lnvpair -lsysevent -lsec -lbrand \
		-lpool -lscf -lproc -luutil -lbsm -lsecdb
# DYNLIB libraries do not have lint libs and are not linted
$(DYNLIB) :=	LDLIBS += -lxml2

SRCDIR =	../common

XMLDIR =	$(SRC)/lib/xml
SRCS = \
		$(LIB_OBJS:%.o=$(SRCDIR)/%.c) \
		$(XML_OBJS:%.o=$(XMLDIR)/%.c) \

CPPFLAGS +=	-I$(ADJUNCT_PROTO)/usr/include/libxml2 -I$(SRCDIR) -D_REENTRANT
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-parentheses
$(LINTLIB) := SRCS=	$(SRCDIR)/$(LINTSRC)

CPPFLAGS +=	-I$(XMLDIR)

.KEEP_STATE:

all:	$(LIBS)

lint:	lintcheck

pics/%.o: $(XMLDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../../Makefile.targ

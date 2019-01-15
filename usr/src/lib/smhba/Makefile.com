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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.


LIBRARY =	libSMHBAAPI.a
VERS =		.1
OBJECTS	=	SMHBAAPILIB.o
CONFIGFILE=	smhba.conf
ROOTETC=	$(ROOT)/etc

include ../../Makefile.lib

HETCFILES=	$(CONFIGFILE:%=$(ROOTETC)/%)

LIBS =		$(DYNLIB) $(LINTLIB)
SRCDIR=		../common

INCS +=		-I$(SRCDIR)
INCS +=		-I$(SRC)/lib/hbaapi/common
CFLAGS +=	-DSOLARIS
CFLAGS +=	-DVERSION='"Version 1"'
CFLAGS +=	-DUSESYSLOG
CPPFLAGS +=	$(INCS)
CPPFLAGS +=	-DPOSIX_THREADS

CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-unused-function

SMOFF += indenting,all_func_returns

LDLIBS +=	-lc

$(LINTLIB) := SRCS=	$(SRCDIR)/$(LINTSRC)

$(ROOTETC)/%:	../common/%
	$(INS.file)

.KEEP_STATE:

all:	$(LIBS) $(HETCFILES)

lint: lintcheck

include ../../Makefile.targ

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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright 2018, Joyent, Inc.
#

LIBRARY =	libipsecutil.a
VERS =		.1
OBJECTS =	ipsec_util.o algs.o

include ../../Makefile.lib

LIBS +=		$(DYNLIB) $(LINTLIB)

SRCDIR =	../common

BERDIR = $(SRC)/lib/libkmf/ber_der/inc

$(LINTLIB):=	SRCS = $(SRCDIR)/$(LINTSRC)
LDLIBS +=	-ltecla -lsocket -lnsl -lc -lkmf -lkmfberder
LAZYLIBS = $(ZLAZYLOAD) -ltsol $(ZNOLAZYLOAD)
lint := LAZYLIBS = -ltsol
LDLIBS += $(LAZYLIBS)

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I$(SRCDIR) -I$(BERDIR)

CERRWARN +=	-_gcc=-Wno-unused-function
CERRWARN +=	-_gcc=-Wno-uninitialized

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

include ../../Makefile.targ

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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

LIBRARY= libvscan.a
VERS= .1

OBJS_SHARED=
OBJS_COMMON= libvscan.o

OBJECTS= $(OBJS_COMMON) $(OBJS_SHARED)

include ../../Makefile.lib

LIBS=	$(DYNLIB) $(LINTLIB)

SRCDIR =	../common
SRCS=	$(OBJS_COMMON:%.o=$(SRCDIR)/%.c)	\
	$(OBJS_SHARED:%.o=$(SRC)/common/vscan/%.c)
$(LINTLIB) := SRCS=	$(SRCDIR)/$(LINTSRC)

# Reset the Makefile.lib macro ROOTLIBDIR to refer to usr/lib/vscan
ROOTLIBDIR = $(ROOT)/usr/lib/vscan
ROOTHDRDIR = $(ROOT)/usr/include
ROOTHDRS = $(HDRS:%=$(ROOTHDRDIR)/%)

$(ROOTLIBDIR):
	$(INS.dir)

LDLIBS +=	-lc -lscf -lsecdb -lnsl -lm
CFLAGS +=   $(CCVERBOSE)
CPPFLAGS += -I$(SRCDIR)
DYNFLAGS +=	-R/usr/lib/vscan
LDLIBS32 +=	-L$(ROOT)/usr/lib/vscan

#C99MODE=	-xc99=%all
#C99LMODE=	-Xc99=%all

.KEEP_STATE:

install: all $(ROOTLIBDIR) install_h

install_h: $(ROOTHDRDIR) $(ROOTHDRS)

all: $(LIBS)

lint: lintcheck

include ../../Makefile.targ


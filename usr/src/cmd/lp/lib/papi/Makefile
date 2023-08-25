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
# ident	"%Z%%M%	%I%	%E% SMI"
#

LIBRARY =	psm-lpsched.a
VERS=.1

LPSCHED_OBJS =	lpsched-msgs.o lpsched-service.o lpsched-printers.o \
		lpsched-jobs.o lpsched-misc.o
OBJECTS =	$(LPSCHED_OBJS) service.o printer.o job.o ppd.o library.o


include		../../../../lib/Makefile.lib
include         ../../Makefile.lp

ROOTLIBDIR=	$(ROOT)/usr/lib/print

CPPFLAGS =	-I.
CPPFLAGS +=	-I$(LPINC)
CPPFLAGS +=	-I$(SRC)/lib/print/libpapi-common/common
CPPFLAGS +=	-D_REENTRANT
CPPFLAGS +=	$(ENVCPPFLAGS1)
CPPFLAGS +=	$(ENVCPPFLAGS2)
LDLIBS +=	-lcurses -lc
LDLIBS +=	-L$(SRC)/cmd/lp/lib/msgs -llpmsg
LDLIBS +=	-L$(SRC)/cmd/lp/lib/printers -llpprt
LDLIBS +=	-L$(SRC)/cmd/lp/lib/class -llpcls
LDLIBS +=	-L$(SRC)/cmd/lp/lib/requests -llpreq
LDLIBS +=	-L$(SRC)/cmd/lp/lib/secure -llpsec
LDLIBS +=	-L$(SRC)/cmd/lp/lib/forms -llpfrm
LDLIBS +=	-L$(SRC)/cmd/lp/lib/access -llpacc
LDLIBS +=	-L$(SRC)/cmd/lp/lib/lp -llp

MAPFILES =	mapfile

LIBS = $(DYNLIB)
SRCS= $(OBJECTS:%.o=%.c)

#${ROOTLIBDIR}:
#	$(INS.dir)

POFILE =	lp_lib_papi_psm.po

.KEEP_STATE:

all:		$(LIBS)

_msg:	$(POFILE)

install:	$(ROOTLIBDIR) $(ROOTLIBS) $(ROOTLINKS)

cstyle:
		$(CSTYLE) $(SRCS)

lint:	lintcheck

include		../../../../lib/Makefile.targ
include		../Makefile.msg

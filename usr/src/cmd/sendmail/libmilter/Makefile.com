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

LIBRARY=	libmilter.a
VERS=		.1
LOCOBJS=	main.o engine.o listener.o handler.o comm.o smfi.o signal.o \
	sm_gethost.o worker.o monitor.o
REMOBJS=	errstring.o strl.o
OBJECTS=	$(LOCOBJS) $(REMOBJS)
SENDMAIL=	$(SRC)/cmd/sendmail

include         $(SENDMAIL)/Makefile.cmd
include		$(SRC)/lib/Makefile.lib

REMDIR=		$(SENDMAIL)/libsm
SRCDIR=		$(SENDMAIL)/libmilter

# There should be a mapfile here
MAPFILES =

SRCS=		$(LOCOBJS:%.o=$(SRCDIR)/%.c) $(REMOBJS:%.o=$(REMDIR)/%.c)

INCPATH=        -I$(SENDMAIL)/src -I$(SENDMAIL)/include
ENVDEF=		-DMILTER -DNETINET6 -DNOT_SENDMAIL -D_REENTRANT \
	-Dsm_snprintf=snprintf
CPPFLAGS=	$(INCPATH) $(ENVDEF) $(CPPFLAGS.sm)

CERRWARN +=	-_gcc=-Wno-type-limits

LIBS=		$(DYNLIB)
LDLIBS +=	-lc -lsocket -lnsl

.KEEP_STATE:

all:		$(LIBS)

install:	all .WAIT $(ROOTLIBS) $(ROOTLINKS)

lint:

include $(SRC)/lib/Makefile.targ

pics/%.o:	$(REMDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

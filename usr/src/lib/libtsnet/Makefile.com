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

LIBRARY	=	libtsnet.a
VERS =		.1

OBJECTS = \
	misc.o \
	tnrh.o tnrhtp.o tnmlp.o \
	tsol_getrhent.o tsol_gettpent.o \
	tsol_sgetrhent.o tsol_sgettpent.o tsol_sgetzcent.o

include ../../Makefile.lib

# install this library in the root filesystem
include ../../Makefile.rootfs

LIBS =		$(DYNLIB)

SRCDIR =	../common

LDLIBS +=	-lsocket -lnsl -lc -lsecdb -ltsol

LIBTSOLINC =	$(SRC)/lib/libtsol/common

CPPFLAGS +=	-D_REENTRANT -I$(LIBTSOLINC)
CERRWARN +=	$(CNOWARN_UNINIT)

.KEEP_STATE:

all: $(LIBS)


include ../../Makefile.targ

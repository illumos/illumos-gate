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
#

LIBRARY =	libmmsadm.a
VERS =		.1

OBJECTS = 	mgmt_lib.o mgmt_media.o mgmt_dsk.o \
		mgmt_mmp.o mgmt_mmsdb.o mgmt_probe.o \
		mgmt_util.o mgmt_acsls.o mgmt_mm.o

include $(SRC)/lib/Makefile.lib
include ../Makefile.defs

LIBS =		$(DYNLIB) $(LINTLIB)

SRCDIR =	../common

SRCS =	$(OBJECTS:%.o=$(SRCDIR)/%.c)

MAPFILES =

ROOTLIBDIR = 	$(ROOTMMSLIBDIR)

LDLIBS +=	-lsocket -lc
LDLIBS +=	-lscf -lgen -lnvpair -lsecdb
LDLIBS +=	-L$(SRC)/lib/mms/mms/$(MACH) -lmms

CFLAGS +=	$(CTF_FLAGS) $(CCVERBOSE)
CFLAGS +=	$(C_BIGPICFLAGS)

DEBUGFORMAT =

CPPFLAGS +=	-DMMS_OPENSSL
CPPFLAGS +=	-I$(SRCDIR) -I$(SRC)/common/mms/mms
CPPFLAGS +=	-I$(SRC)/lib/mms/mms/common
CPPFLAGS +=	-I$(SRC)/uts/common/io/mms/dda
CPPFLAGS +=	-I$(ACSLSH)
CPPFLAGS += 	-D_POSIX_PTHREAD_SEMANTICS

C99MODE = $(C99_ENABLE)

.KEEP_STATE:

all: $(LIBS) $(LIBLINKS)

lint: $(LINTLIB) lintcheck

$(LIBLINKS):    FRC
	$(RM) $@; $(SYMLINK) $(DYNLIB) $@

FRC: 

include $(SRC)/lib/Makefile.targ
include ../Makefile.rootdirs


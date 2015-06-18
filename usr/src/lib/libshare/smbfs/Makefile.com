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

LIBRARY =	libshare_smbfs.a
VERS =		.1

LIBOBJS =	libshare_smbfs.o
SMBBASE_OBJ =	smbfs_scfutil.o
OBJECTS =	$(LIBOBJS) $(SMBBASE_OBJ)

include ../../../Makefile.lib

ROOTLIBDIR =	$(ROOT)/usr/lib/fs/smbfs
ROOTLIBDIR64 =	$(ROOT)/usr/lib/fs/smbfs/$(MACH64)

LIBSRCS = $(LIBOBJS:%.o=$(SRCDIR)/%.c)

LIBS =		$(DYNLIB)
LDLIBS +=	-lshare -lscf -lumem -luuid -lc -lxml2 -lsmbfs

CFLAGS +=	$(CCVERBOSE)
CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	-_gcc=-Wno-uninitialized
CPPFLAGS +=	-D_REENTRANT -I$(ADJUNCT_PROTO)/usr/include/libxml2 \
		-I$(SRCDIR)/../common -I$(SRC)/lib/libsmbfs -I$(SRC)/uts/common

.KEEP_STATE:

all: $(LIBS)

install: $(ROOTLIBDIR) $(ROOTLIBDIR64) all

lint: lintcheck

$(ROOTLIBDIR):
	$(INS.dir)

$(ROOTLIBDIR64):
	$(INS.dir)

include ../../../Makefile.targ

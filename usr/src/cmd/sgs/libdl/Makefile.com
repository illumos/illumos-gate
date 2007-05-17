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

LIBRARY=	libdl.a
VERS=		.1

include 	$(SRC)/lib/Makefile.lib
include 	$(SRC)/cmd/sgs/Makefile.com

SRCDIR =	../common

MAPFILES +=	mapfile-vers $(MAPFILE.FLT)

# Redefine shared object build rule to use $(LD) directly (this avoids .init
# and .fini sections being added).  Also, since there are no OBJECTS, turn
# off CTF.

BUILD.SO=	$(LD) -o $@ -G $(DYNFLAGS)
CTFMERGE_LIB=	:

DYNFLAGS +=	$(ZNODUMP) $(VERSREF) $(CONVLIBDIR) -lconv

LINTFLAGS +=	-u
LINTFLAGS64 +=	-u 
SRCS=		../common/llib-ldl

CLEANFILES +=
CLOBBERFILES +=	$(DYNLIB) $(LINTLIB) $(LINTOUTS) $(LIBLINKS)


ROOTFS_DYNLIB64=	$(DYNLIB:%=$(ROOTFS_LIBDIR64)/%)
ROOTFS_LINTLIB64=	$(LINTLIB:%=$(ROOTFS_LIBDIR64)/%)

#
# In the libc/libthread unified environment:
# This library needs to be placed in /lib to allow
# dlopen() functionality while in single-user mode.
ROOTFS_DYNLIB=		$(DYNLIB:%=$(ROOTFS_LIBDIR)/%)
ROOTFS_LINTLIB=		$(LINTLIB:%=$(ROOTFS_LIBDIR)/%)

$(ROOTFS_DYNLIB) :=	FILEMODE= 755
$(ROOTFS_DYNLIB64) :=	FILEMODE= 755

#
# In the libc/libthread un-unified environment:
# A version of this library needs to be placed in /etc/lib to allow
# dlopen() functionality while in single-user mode.
ETCLIBDIR=	$(ROOT)/etc/lib
ETCDYNLIB=	$(DYNLIB:%=$(ETCLIBDIR)/%)

$(ETCDYNLIB) :=	FILEMODE= 755

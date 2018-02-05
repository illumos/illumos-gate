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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
#

LIBRARY =	ioctl.a
VERS =
OBJECTS =	ioctl.o

PYSRCS=		__init__.py util.py dataset.py \
	allow.py unallow.py \
	userspace.py groupspace.py holds.py table.py


include ../../Makefile.lib

LIBLINKS = 
SRCDIR =	../common
ROOTLIBDIR=	$(ROOT)/usr/lib/python$(PYTHON_VERSION)/vendor-packages/zfs
PYOBJS=		$(PYSRCS:%.py=$(SRCDIR)/%.pyc)
PYFILES=	$(PYSRCS) $(PYSRCS:%.py=%.pyc)
ROOTPYZFSFILES= $(PYFILES:%=$(ROOTLIBDIR)/%)

CSTD=        $(CSTD_GNU99)
C99LMODE=       -Xc99=%all

LIBS =		$(DYNLIB)
LDLIBS +=	-lc -lnvpair -lpython$(PYTHON_VERSION) -lzfs
CFLAGS +=	$(CCVERBOSE)
CERRWARN +=	-_gcc=-Wno-unused-variable
CPPFLAGS +=	-I$(ADJUNCT_PROTO)/usr/include/python$(PYTHON_VERSION)
CPPFLAGS +=	-I../../../uts/common/fs/zfs
CPPFLAGS +=	-I../../../common/zfs

.KEEP_STATE:

all: $(PYOBJS) $(LIBS)

install: all $(ROOTPYZFSFILES)

$(ROOTLIBDIR)/%: %
	$(INS.pyfile)

$(ROOTLIBDIR)/%: ../common/%
	$(INS.pyfile)

lint: lintcheck

include ../../Makefile.targ

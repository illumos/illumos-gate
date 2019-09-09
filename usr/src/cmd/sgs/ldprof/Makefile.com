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
# Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright (c) 2018, Joyent, Inc.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

LIBRARY=	ldprof.a
VERS=		.1
COMOBJS=	profile.o
BLTOBJ=		msg.o
OBJECTS=	$(COMOBJS) $(BLTOBJ)

include		../../../../lib/Makefile.lib
include		../../Makefile.com

ROOTLIBDIR=	$(ROOT)/usr/lib/link_audit

MAPFILES =	../common/mapfile-vers

CPPFLAGS=	-I. -I../common -I../../include \
		-I../../rtld/common \
		-I../../include/$(MACH) \
		-I$(SRC)/lib/libc/inc \
		-I$(SRC)/uts/common/krtld \
		-I$(SRC)/common/sgsrtcid \
		-I$(SRC)/uts/$(ARCH)/sys \
		$(CPPFLAGS.master) -I$(ELFCAP)
CFLAGS +=	$(C_PICFLAGS)

SMOFF += indenting

LDLIBS +=	$(ZRECORD) -lmapmalloc -lc $(DLLIB)

BLTDEFS=	msg.h
BLTDATA=	msg.c
BLTMESG=	$(SGSMSGDIR)/ldprof

BLTFILES=	$(BLTDEFS) $(BLTDATA) $(BLTMESG)

SGSMSGCOM=	../common/ldprof.msg
SGSMSGTARG=	$(SGSMSGCOM)
SGSMSGALL=	$(SGSMSGCOM)
SGSMSGFLAGS +=	-h $(BLTDEFS) -d $(BLTDATA) -m $(BLTMESG) -n ldprof_msg

SRCS=		$(COMOBJS:%.o=../common/%.c) $(BLTDATA)

CLEANFILES +=	$(BLTFILES)
CLOBBERFILES +=	$(DYNLIB)

ROOTDYNLIB=	$(DYNLIB:%=$(ROOTLIBDIR)/%)

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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#
include		$(SRC)/Makefile.master

FSTYPE=		reparse
TYPEPROG=	reparsed

include		../Makefile.fstype

OBJS=		$(TYPEPROG).o
SRCS=		$(TYPEPROG).c
POFILE=		$(TYPEPROG).po

CLOBBERFILES += $(TYPEPROG)

CFLAGS +=	$(CCVERBOSE)
CERRWARN +=	-_gcc=-Wno-unused-variable
CSTD=	$(CSTD_GNU99)

LDLIBS +=	-lreparse -lnsl

CPPFLAGS +=	-I$(SRC)/uts/common

all:		$(TYPEPROG)

catalog:	$(POFILE)

lint:		lint_SRCS

clean:
		$(RM) $(OBJS) $(POFILE)

MANIFEST=	reparsed.xml
ROOTMANIFESTDIR=	$(ROOTSVCNETWORKSHARES)
$(ROOTMANIFEST) := FILEMODE = 0444
install:	$(ROOTMANIFEST)

.KEEP_STATE:

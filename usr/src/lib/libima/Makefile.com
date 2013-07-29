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

LIBRARY=	libima.a
VERS=		.1
OBJECTS=	ima-lib.o sunima-lib.o
CONFIGFILE=	ima.conf
ROOTETC=	$(ROOT)/etc

include ../../Makefile.lib

IETCFILES=	$(CONFIGFILE:%=$(ROOTETC)/%)
IETCFILES:=	FILEMODE= 644

LIBS =		$(DYNLIB) $(LINTLIB)
LDLIBS +=	-lc

CFLAGS +=	-mt
CFLAGS +=	$(CCVERBOSE)
CFLAGS +=	-xCC
CFLAGS +=	-erroff=E_IMPLICIT_DECL_FUNC_RETURN_INT
CFLAGS +=	-DSOLARIS

CFLAGS64 +=       -mt
CFLAGS64 +=       $(CCVERBOSE)
CFLAGS64 +=       -xCC
CFLAGS64 +=       -erroff=E_IMPLICIT_DECL_FUNC_RETURN_INT
CFLAGS64 +=       -DSOLARIS

CERRWARN +=	-_gcc=-Wno-unused-variable

LINTFLAGS += -DSOLARIS
LINTFLAGS64 += -DSOLARIS

SRCDIR =	../common
$(LINTLIB) := SRCS=	$(SRCDIR)/$(LINTSRC)

$(ROOTETC)/%:	../common/%
	$(INS.file)

.KEEP_STATE:

all:	$(LIBS) $(IETCFILES)

lint:
	@echo "This section is not required to be lint clean"

include ../../Makefile.targ

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

LIBRARY	=	rfc2136.a
VERS =		.1
OBJECTS	=	rfc2136.o

include $(SRC)/lib/Makefile.lib

LIBS =		$(DYNLIB)
LDLIBS +=	-lnvpair -lresolv -lnsl -lc

ROOTLIBDIR =	$(ROOT)/usr/lib/inet/dhcp/nsu
SRCDIR =	../common

#
# Since lint is not smart enough to grok `do { } while (0)' in macros,
# we're forced to turn off constant-in-conditional checks.
#
LINTFLAGS +=	-erroff=E_CONSTANT_CONDITION
CPPFLAGS += 	-D_REENTRANT -I../../libresolv2/include

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-uninitialized

MAPFILES =	../common/mapfile

.KEEP_STATE:

all:	$(LIBS)

lint:	lintcheck

include $(SRC)/lib/Makefile.targ

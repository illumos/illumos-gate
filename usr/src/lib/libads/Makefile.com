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
# Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
#

LIBRARY =	libads.a
VERS =		.1
OBJECTS =	dsgetdc.o poke.o adspriv_xdr.o

include ../../Makefile.lib

CSTD=	$(CSTD_GNU99)

LIBS =		$(DYNLIB)
LDLIBS +=	-lnsl -lc
SRCDIR =	../common

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D_REENTRANT -I$(SRCDIR) -I..
# CPPFLAGS +=	-I$(SRC)/lib/libldap5/include/ldap

CERRWARN +=	-_gcc=-Wno-type-limits
CERRWARN +=	$(CNOWARN_UNINIT)
CERRWARN +=	-_gcc=-Wno-unused-variable

.KEEP_STATE:

all: $(LIBS)


include ../../Makefile.targ

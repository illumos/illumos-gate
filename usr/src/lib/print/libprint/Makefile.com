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
# Copyright (c) 2018, Joyent, Inc.

LIBRARY =		libprint.a
VERS =			.2
OBJECTS = \
	list.o ns.o ns_bsd_addr.o ns_cmn_kvp.o \
	ns_cmn_printer.o nss_convert.o nss_ldap.o nss_printer.o nss_write.o

include ../../../Makefile.lib

SRCDIR =	../common

LIBS =			$(DYNLIB)


CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I$(SRCDIR)
CPPFLAGS +=	-I../../head -D_REENTRANT

# not linted
SMATCH=off

LDLIBS +=	-lnsl -lsocket -lc -lldap


.KEEP_STATE:

all:	$(LIBS)


include ../../../Makefile.targ

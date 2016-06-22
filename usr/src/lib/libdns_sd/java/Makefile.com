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

LIBRARY=	libjdns_sd.a
VERS=		.1

OBJECTS=	JNISupport.o

include		$(SRC)/lib/Makefile.lib

LIBS =		$(DYNLIB)

SRCDIR =	../common

C99MODE =       $(C99_ENABLE)
CPPFLAGS +=	-I$(JAVA_ROOT)/include -I$(JAVA_ROOT)/include/solaris
CPPFLAGS +=	-I../com/apple/dnssd
CPPFLAGS +=	-D_REENTRANT
CPPFLAGS +=	-DMDNS_VERSIONSTR_NODTS

LDLIBS +=	-lc -lsocket -ldns_sd

CLEANFILES=	$(LINTOUT) $(LINTLIB)

LINTLIB =	

.KEEP_STATE:

lint:		lintcheck

include		$(SRC)/lib/Makefile.targ

pics/%.o: ../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

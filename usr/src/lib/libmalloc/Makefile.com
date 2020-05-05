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

LIBRARY=	libmalloc.a
VERS=		.1

OBJECTS=	malloc.o

# include library definitions
include ../../Makefile.lib

SRCDIR =	../common

LIBS =		$(DYNLIB)


CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I../../common/inc -D_REENTRANT
DYNFLAGS +=	$(ZINTERPOSE)
LDLIBS +=	-lc

COMPATLINKS=	usr/ccs/lib/libmalloc.so
COMPATLINKS64=	usr/ccs/lib/$(MACH64)/libmalloc.so

$(ROOT)/usr/ccs/lib/libmalloc.so := COMPATLINKTARGET=../../lib/libmalloc.so.1
$(ROOT)/usr/ccs/lib/$(MACH64)/libmalloc.so:= \
	COMPATLINKTARGET=../../../lib/$(MACH64)/libmalloc.so.1

.KEEP_STATE:


# include library targets
include ../../Makefile.targ

pics/%.o: ../common/%.c
		$(COMPILE.c) -o $@ $<
		$(POST_PROCESS_O)

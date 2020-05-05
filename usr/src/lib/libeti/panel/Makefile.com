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

LIBRARY=	libpanel.a
VERS=		.1

OBJECTS=  \
	bottom.o \
	move.o \
	replace.o \
	update.o \
	delete.o \
	misc.o \
	new.o \
	top.o

# include library definitions
include ../../../Makefile.lib

LIBS =          $(DYNLIB)

SRCDIR=		../common

CPPFLAGS +=	-I../inc
CFLAGS +=       $(CCVERBOSE)
LDLIBS +=       -lcurses -lc

CERRWARN +=	-_gcc=-Wno-parentheses

COMPATLINKS=	usr/ccs/lib/libpanel.so
COMPATLINKS64=	usr/ccs/lib/$(MACH64)/libpanel.so

$(ROOT)/usr/ccs/lib/libpanel.so:=	COMPATLINKTARGET=../../lib/libpanel.so.1
$(ROOT)/usr/ccs/lib/$(MACH64)/libpanel.so:= \
	COMPATLINKTARGET=../../../lib/$(MACH64)/libpanel.so.1

.KEEP_STATE:

all: $(LIBS)


# include library targets
include ../../../Makefile.targ

pics/%.o:	../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

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

LIBRARY=	libmenu.a
VERS=		.1

OBJECTS=  \
	affect.o \
	chk.o \
	connect.o \
	curitem.o \
	driver.o \
	global.o \
	itemcount.o \
	itemopts.o \
	itemusrptr.o \
	itemvalue.o \
	link.o \
	menuback.o \
	menucursor.o \
	menufore.o \
	menuformat.o \
	menugrey.o \
	menuitems.o \
	menumark.o \
	menuopts.o \
	menupad.o \
	menuserptr.o \
	menusub.o \
	menuwin.o \
	newitem.o \
	newmenu.o \
	pattern.o \
	post.o \
	scale.o \
	show.o \
	terminit.o \
	topitem.o \
	visible.o

# include library definitions
include ../../../Makefile.lib

LIBS =          $(DYNLIB)

SRCDIR=		../common

CPPFLAGS +=	-I../inc
CFLAGS +=       $(CCVERBOSE)
LDLIBS +=       -lcurses -lc

CERRWARN +=	-_gcc=-Wno-parentheses

COMPATLINKS=	usr/ccs/lib/libmenu.so
COMPATLINKS64=	usr/ccs/lib/$(MACH64)/libmenu.so

$(ROOT)/usr/ccs/lib/libmenu.so := COMPATLINKTARGET= ../../lib/libmenu.so.1
$(ROOT)/usr/ccs/lib/$(MACH64)/libmenu.so:= \
	COMPATLINKTARGET=../../../lib/$(MACH64)/libmenu.so.1

.KEEP_STATE:

all: $(LIBS)


# include library targets
include ../../../Makefile.targ

pics/%.o:	../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

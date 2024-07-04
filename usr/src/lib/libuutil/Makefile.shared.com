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
# Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright (c) 2018, Joyent, Inc.

LIBRARY =	libuutil.a
VERS =		.1

OBJECTS =		\
	avl.o		\
	uu_alloc.o	\
	uu_avl.o	\
	uu_dprintf.o	\
	uu_ident.o	\
	uu_list.o	\
	uu_misc.o	\
	uu_open.o	\
	uu_pname.o	\
	uu_string.o	\
	uu_strtoint.o

include $(SRC)/lib/Makefile.lib

LIBS =		$(DYNLIB)

LDLIBS +=	-lc

CPPFLAGS +=	-I$(SRCDIR)

SMOFF += signed

$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG

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
# Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2013 Saso Kiselkov. All rights reserved.
#

LIBS =		$(DYNLIB) $(LINTLIB)
SRCS =		$(COMDIR)/edonr/edonr.c \
		$(COMDIR)/md4/md4.c \
		$(COMDIR)/md5/md5.c \
		$(COMDIR)/sha1/sha1.c \
		$(COMDIR)/sha2/sha2.c \
		$(COMDIR)/skein/skein.c \
		$(COMDIR)/skein/skein_block.c \
		$(COMDIR)/skein/skein_iv.c

COMDIR =	$(SRC)/common/crypto
SRCDIR =	../common
MAPFILEDIR =	$(SRCDIR)

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I$(SRCDIR)
LDLIBS +=	-lc

$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)

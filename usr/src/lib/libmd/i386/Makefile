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

LIBRARY =	libmd.a
VERS =		.1

OBJECTS =	edonr.o md4.o md5.o sha1.o sha2.o \
		skein.o skein_block.o skein_iv.o

include		$(SRC)/lib/Makefile.lib
include		$(SRC)/lib/Makefile.rootfs
include		../Makefile.com

.KEEP_STATE:

all:		$(LIBS)

install:	all $(ROOTLIBS) $(ROOTLINKS) $(ROOTLINT)

lint:		lintcheck

include		../Makefile.targ

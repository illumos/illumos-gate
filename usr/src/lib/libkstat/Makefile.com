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

LIBRARY= libkstat.a
VERS= .1

OBJECTS= kstat.o

# include library definitions
include ../../Makefile.lib

# install this library in the root filesystem
include ../../Makefile.rootfs

SRCDIR =	../common

LIBS =		$(DYNLIB)

CPPFLAGS +=	-I..
CFLAGS +=	$(CCVERBOSE)
LDLIBS +=	-lc

.KEEP_STATE:


# include library targets
include ../../Makefile.targ

pics/%.o: ../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/kstat.o: ../kstat.h

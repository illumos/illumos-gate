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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

#
#	Create default so empty rules don't
#	confuse make
#
CLASS		= 32

include $(SRCDIR)/../Makefile.cmd

PROG		= eeprom

FILEMODE	= 02555
DIRMODE		= 755

OBJS		= error.o

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-implicit-function-declaration

# not linted
SMATCH=off

LINT_OBJS = $(OBJS:%.o=%.ln)
SOURCES = $(OBJS:%.o=%.c)

.PARALLEL: $(OBJS)

%.o:	$(SRCDIR)/common/%.c
	$(COMPILE.c) -o $@ $<

%.ln:	../common/%.c
	$(LINT.c) -c $@ $<

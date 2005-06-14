#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Makefile for PCFS ident function.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#


IDENT_VERS=1
FSTYPE=		pcfs
LIBPROG=	ident_pcfs.so.${IDENT_VERS} 

include ../../../../lib/Makefile.lib
include ../../Makefile.fstype

DYNLIB=		$(LIBPROG)
#
# Override PMAP dependency
#
PMAP=

CFLAGS += $(C_PICFLAGS)
#
# Rules for making shared objects out of .c files.  Works well if
# we have a one-to-one mapping.  Applies in all cases so far.
#
.SUFFIXES: .so.${IDENT_VERS} ${SUFFIXES}

.c.so.${IDENT_VERS}:
	${CC} ${CPPFLAGS} $(DYNFLAGS) ${CFLAGS} $(GSHARED) -o $@ $< -lc
	$(POST_PROCESS_SO)

SRCS=	${LIBPROG:%.so.$(IDENT_VERS)=%.c}

CPPFLAGS += 	-DIDENT_VERS=${IDENT_VERS}

LINTFLAGS=	-avx

.KEEP_STATE:

all: ${LIBPROG}

lint:
	$(LINT.c) ${CPPLAGS} ${SRCS}

cstyle:
	${CSTYLE} ${SRCS}

clean:     
	${RM} ${IDENTS} core a.out

clobber: clean

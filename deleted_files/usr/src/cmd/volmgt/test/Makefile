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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Makefile for volume management test programs
#
# cmd/volmgt/test/Makefile
#

include ../../Makefile.cmd
include ../Makefile.volmgt

OBJS=		vttest.o voltestdrv.o
SRCS=		$(OBJS:%.o=%.c)

KSRC=		${SRC}/uts

RAM_ARCH:sh=	uname -m
MACH:sh=	uname -p

KERNEL_CDEFS =	-D_KERNEL -DDEBUG -DSYSACCT -DC2_AUDIT -DQUOTA \
		-DSOLARIS2=$(RELEASE:5.%=%)

sparc_KERNEL_CINC =	-I${KSRC}/sparc
i386_KERNEL_CINC =	-I${KSRC}/i86pc -I${KSRC}/intel
KERNEL_CINC =	$($(MACH)_KERNEL_CINC) -I${KSRC}/sun -Y I,${KSRC}/common

sparc_CFLAGS =	-xcg92
i386_CFLAGS=
COPTFLAG=-O
CFLAGS= $($(MACH)_CFLAGS)

lint := CPPFLAGS += $(KERNEL_CDEFS) \
	$($(MACH)_KERNEL_CINC) -I${KSRC}/sun

PROGS= 	vttest voltestdrv

.KEEP_STATE:


all: ${PROGS}

vttest:	vttest.o
	${CC} ${CFLAGS} -o $@ vttest.o

voltestdrv: voltestdrv.c voltestdrv.h
	${COMPILE.c} $(COPTFLAG) ${KERNEL_CDEFS} ${KERNEL_CINC} $@.c
	${LD} -r -o $@ $@.o

install: all

cstyle:
	${CSTYLE} ${SRCS}

lint:
	${LINT.c} voltestdrv.c

depend:

clean:
	${RM} *.o a.out core

clobber: clean
	${RM} ${PROGS}


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
# Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

COMOBJS64 =	rd_elf64.o
PLTOBJS =	plt32_resolution.o plt64_resolution.o
PLTSRCS =	../i386/plt32_resolution.c plt64_resolution.c

include		../Makefile.com

SGSMSGTARG +=	$(SGSMSGINTEL)

CPPFLAGS +=	-D_SYSCALL32
CONVLIBDIR =	$(CONVLIBDIR64)

.KEEP_STATE:

all:		$(DYNLIB)

install:	all $(ROOTLIBS64) $(ROOTLINKS64) $(ROOTCOMPATLINKS64)

pics/plt32_resolution.o: ../i386/plt32_resolution.c
		$(COMPILE.c) -D_ELF32 $(PICFLAGS) -o $@ \
		    ../i386/plt32_resolution.c
		$(POST_PROCESS_O)

include		../Makefile.targ
include		../../Makefile.sub.64

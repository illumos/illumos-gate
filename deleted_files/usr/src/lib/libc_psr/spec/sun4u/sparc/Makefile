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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libc_psr/spec/sun4u/sparc/Makefile

.KEEP_STATE:

LIBRARY	=	libc_psr.a
VERS	=	.1

PLATFORM=	sun4u
CLASS	=	32

OBJECTS	=	c_psr-sparc.o

SPECVERS =	-sparc

include	$(SRC)/lib/Makefile.lib
include $(SRC)/lib/libc_psr/spec/$(PLATFORM)/Makefile.links

# Uncomment the following if the linker complains
#sparc_C_PICFLAGS  = -K PIC

include	$(SRC)/lib/Makefile.spec
include	$(SRC)/lib/Makefile.spec.psm

install:

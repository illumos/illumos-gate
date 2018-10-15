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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#

TRG_PLATFORM =	sun4u-us3
GEN_PLATFORM =	sun4u

include		../../Makefile.com

OBJECTS =	memcpy.o memset.o memcmp.o

include		$(SRC)/lib/Makefile.lib

IFLAGS =	-I$(SRC)/uts/$(GEN_PLATFORM) \
		-I$(ROOT)/usr/platform/$(GEN_PLATFORM)/include

MAPFILE-CAP +=	../../$(TRG_PLATFORM)/common/mapfile-cap

AS_CPPFLAGS +=	-D__STDC__ -D_ASM -DPIC -D_REENTRANT -D$(MACH) $(IFLAGS) \
		-DBSTORE_SIZE=256
ASFLAGS =	-P $(AS_PICFLAGS)

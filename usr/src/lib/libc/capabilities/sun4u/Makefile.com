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

TRG_PLATFORM =	sun4u
GEN_PLATFORM =	sun4u

include		../../Makefile.com

OBJECTS =	memcpy.o memset.o memcmp.o

include		$(SRC)/lib/Makefile.lib

IFLAGS =	-I$(SRC)/uts/$(GEN_PLATFORM) \
		-I$(ROOT)/usr/platform/$(GEN_PLATFORM)/include

AS_CPPFLAGS +=	-D__STDC__ -D_ASM -DPIC -D_REENTRANT -D$(MACH) $(IFLAGS)
ASFLAGS =	-P $(AS_PICFLAGS)

# memcpy.s provides __align_cpy_1 as an alias for memcpy.  However, this isn't
# a WEAK symbol, and hence ld(1)'s ability to cull duplicate local symbols with
# the same address is compromised.  The result is .SUNW_dynsymsort: duplicate
# symbol errors from check_rtime.  Use elfedit to assign a weak binding.

POST_PROCESS_OBJCAP_O =	elfedit -e "sym:st_bind __align_cpy_1 STB_WEAK" $@

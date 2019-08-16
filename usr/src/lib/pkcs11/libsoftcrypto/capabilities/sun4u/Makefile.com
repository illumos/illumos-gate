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

PLATFORM =	sun4u

AES_PSM_OBJS =		aes_crypt_asm.o
ARCFOUR_PSM_OBJS =	arcfour_crypt_asm.o
DES_PSM_OBJS =		des_crypt_asm.o
BIGNUM_PSM_OBJS =	mont_mulf_asm.o

include		../../Makefile.com

# Redefine the objects required for this capabilities group.
OBJECTS =	$(AES_OBJS) $(ARCFOUR_OBJS) $(DES_OBJS) $(BIGNUM_OBJS) \
		$(MODES_OBJS)

include		$(SRC)/lib/Makefile.lib

AS_CPPFLAGS +=	-D__STDC__ -D_ASM -DPIC -D_REENTRANT -D$(MACH)
ASFLAGS +=	$(AS_PICFLAGS) -P
CFLAGS +=	$(CCVERBOSE)
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	$(CNOWARN_UNINIT)
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-unused-function
CPPFLAGS +=	-D$(PLATFORM) -I$(CRYPTODIR) -I$(UTSDIR) \
		-D_POSIX_PTHREAD_SEMANTICS
BIGNUM_FLAGS +=	-DUSE_FLOATING_POINT -DNO_BIG_ONE -DNO_BIG_TWO

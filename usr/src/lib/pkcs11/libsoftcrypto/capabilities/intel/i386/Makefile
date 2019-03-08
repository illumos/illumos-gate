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
# Copyright (c) 2019, Joyent, Inc.
#

BIGNUM_PSM_OBJS =	bignum_i386.o bignum_i386_asm.o

include		../../Makefile.com

# Redefine the objects required for this capabilities group.
OBJECTS =	$(BIGNUM_OBJS)

include		$(SRC)/lib/Makefile.lib

AS_CPPFLAGS +=	-D__STDC__ -D_ASM -DPIC -D_REENTRANT -D$(MACH)
ASFLAGS +=	$(AS_PICFLAGS) -P
CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I$(CRYPTODIR) -I$(UTSDIR) -D_POSIX_PTHREAD_SEMANTICS
BIGNUM_FLAGS +=	-DMMX_MANAGE -DHWCAP -DPSR_MUL -DNO_BIG_ONE -DNO_BIG_TWO

CERRWARN +=	 -_gcc=-Wno-unused-variable

.KEEP_STATE:

all install:	$(SYMCAP)

include		../../Makefile.targ

pics/bignum_i386.o: $(BIGNUM_DIR)/i386/bignum_i386.c
		$(COMPILE.c) $(BIGNUM_FLAGS) -o $@ \
		    $(BIGNUM_DIR)/i386/bignum_i386.c
		$(POST_PROCESS_O)

pics/bignum_i386_asm.o: $(BIGNUM_DIR)/i386/bignum_i386_asm.s
		$(COMPILE.s) -o $@ $(BIGNUM_DIR)/i386/bignum_i386_asm.s
		$(POST_PROCESS_S_O)

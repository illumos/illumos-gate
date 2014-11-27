#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
#

LIBMDIR		= $(SRC)/lib/libm

LIBMSRC		= $(LIBMDIR)/common

CPP_CMD		= $(CC) -E -Xs

ASSUFFIX_sparc	= S
ASSUFFIX_i386	= s
ASSUFFIX	= $(ASSUFFIX_$(MACH))

# C99MODE of neither enabled nor disabled is "no_lib", whereby we expect
# C99-the-language, but don't modify the behaviour of library routines.  This
# is VERY IMPORTANT, as -xc99=%all, for instance, would link us with
# values-xpg6, which would introduce an __xpg6 to our object with the C99
# flags set, causing us to default C99 libm behaviour on, breaking
# compatibility.
C99MODE		=

M4FLAGS		= -D__STDC__ -DPIC

LDBLDIR_sparc	= Q
LDBLDIR_i386	= LD
LDBLDIR		= $(LDBLDIR_$(MACH))

LM_IL		= $(LIBMDIR)/$(TARGET_ARCH)/src/locallibm.il

CFLAGS		+= $(C_PICFLAGS) $(XSTRCONST) $(LM_IL)
CFLAGS64	+= $(C_PICFLAGS) $(XSTRCONST) $(LM_IL)
sparc_CFLAGS	+= -Wa,-xarch=v8plus

CPPFLAGS	+= -I$(LIBMSRC)/C \
		-I$(LIBMSRC)/$(LDBLDIR) -I$(LIBMDIR)/$(TARGET_ARCH)/src

# GCC needs __C99FEATURES__ such that the implementations of isunordered,
# isgreaterequal, islessequal, etc, exist.  This is basically equivalent to
# providing no -xc99 to Studio, in that it gets us the C99 language features,
# but not values-xpg6, the reason for which is outline with C99MODE.
CFLAGS		+= -_gcc=-D__C99FEATURES__
CFLAGS64	+= -_gcc=-D__C99FEATURES__

# libm depends on integer overflow characteristics
CFLAGS		+= -_gcc=-fno-strict-overflow
CFLAGS64	+= -_gcc=-fno-strict-overflow

$(DYNLIB) 	:= LDLIBS += -lc

$(LINTLIB) 	:= SRCS = $(LIBMSRC)/$(LINTSRC)

CLEANFILES 	+= pics/*.s pics/*.S

FPDEF_amd64	= -DARCH_amd64
FPDEF_sparc	= -DCG89 -DARCH_v8plus -DFPADD_TRAPS_INCOMPLETE_ON_NAN
FPDEF_sparcv9	= -DARCH_v9 -DFPADD_TRAPS_INCOMPLETE_ON_NAN
FPDEF		= $(FPDEF_$(TARGET_ARCH))

ASFLAGS		= -P -D_ASM $(FPDEF)

XARCH_sparc	= v8plus
XARCH_sparcv9	= v9
XARCH_i386	= f80387
XARCH_amd64	= amd64
XARCH		= $(XARCH_$(TARGET_ARCH))

ASOPT_sparc	= -xarch=$(XARCH) $(AS_PICFLAGS)
ASOPT_sparcv9	= -xarch=$(XARCH) $(AS_PICFLAGS)
ASOPT_i386	= 
ASOPT_amd64	= -xarch=$(XARCH) $(AS_PICFLAGS)
ASOPT		= $(ASOPT_$(TARGET_ARCH))

ASFLAGS		+= $(ASOPT)

CPPFLAGS_sparc = -DFPADD_TRAPS_INCOMPLETE_ON_NAN \
	-DFDTOS_TRAPS_INCOMPLETE_IN_FNS_MODE

CPPFLAGS	+= $(CPPFLAGS_$(MACH))
ASFLAGS		+= $(CPPFLAGS)

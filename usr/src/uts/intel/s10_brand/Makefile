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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
#
#	This makefile drives the production of the kernel component of
#	the Solaris 10 brand
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE =	../..
S10_BASE =	$(UTSBASE)/common/brand/solaris10

#
#	Define the module and object file sets.
#
MODULE =	s10_brand
OBJECTS =	$(S10_BRAND_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE =	$(USR_BRAND_DIR)/$(MODULE)

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
#	Define targets
#
ALL_TARGET =		$(BINARY)
INSTALL_TARGET =	$(BINARY) $(ROOTMODULE)


#
#	Update compiler variables.
#
INC_PATH +=	-I$(S10_BASE) -I$(OBJS_DIR)
AS_INC_PATH	+= -I$(UTSBASE)/i86pc/genassym/$(OBJS_DIR)
LDFLAGS +=	-dy -Nexec/elfexec

#
# Ugh, this is a gross hack.  s10_brand_asm.s uses lots of defines
# to simplify variable access.  All these defines work fine for amd64
# compiles because when compiling for amd64 we use the GNU assembler,
# gas.  For 32-bit code we use the Sun assembler, as.  Unfortunatly
# as does not handle certian constructs that gas does.  So rather than
# make our code less readable, we'll just use gas to compile our 32-bit
# code as well.
#
i386_AS		= $(amd64_AS)

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS)

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ

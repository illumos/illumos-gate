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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright (c) 2019, Joyent, Inc.
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..
BIGNUMDIR = $(COMMONBASE)/bignum
CRYPTODIR = $(COMMONBASE)/crypto

#
#	Define the module and object file sets.
#
MODULE		= bignum
OBJECTS		= $(BIGNUM_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(BIGNUM_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_MISC_DIR)/$(MODULE)

BIGNUM_PSR_OBJS = bignum_amd64.o bignum_amd64_asm.o

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

#
# Linkage dependencies
#
LDFLAGS += -dy -Nmisc/kcf

CPPFLAGS	+= -I$(BIGNUMDIR) -I$(CRYPTODIR)

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS)

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS)

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ

# Bignum configuration (BIGNUM_CFG):
#   PSR_MUL:
#       There is a processor-specific implementation bignum multiply functions
#   HWCAP:
#       There are multiple implementations of bignum functions, and the
#	appropriate one must be chosen at run time, based on testing
#	hardware capabilites.
#
# -DPSR_MUL:
# For AMD64, there is a processor-specific implementation of
# the bignum multiply functions, which takes advantage of the
# 64x64->128 bit multiply instruction.
#
# -UHWCAP:
# There is only one implementation, because the 128 bit multiply using
# general-purpose registers is faster than any MMX or SSE2 implementation.

BIGNUM_CFG = -DPSR_MUL
CFLAGS	+= -xO4 -xcrossfile
$(OBJS_DIR)/bignumimpl.o $(LINTS_DIR)/bignumimpl.ln := \
	CPPFLAGS += $(BIGNUM_CFG)
$(OBJS_DIR)/bignum_amd64.o $(LINTS_DIR)/bignum_amd64.ln := \
	CPPFLAGS += $(BIGNUM_CFG)

$(OBJS_DIR)/bignum_amd64.o: $(BIGNUMDIR)/amd64/bignum_amd64.c
	$(COMPILE.c) -o $@ $(BIGNUM_CFG) $(BIGNUMDIR)/amd64/bignum_amd64.c
	$(CTFCONVERT_O)

$(OBJS_DIR)/bignum_amd64_asm.o: $(BIGNUMDIR)/amd64/bignum_amd64_asm.s
	$(COMPILE.s) -P -o $@ $(BIGNUM_CFG) \
		$(BIGNUMDIR)/amd64/bignum_amd64_asm.s

$(LINTS_DIR)/bignum_amd64.ln: $(BIGNUMDIR)/amd64/bignum_amd64.c
	@($(LHEAD) $(LINT.c) $(BIGNUMDIR)/amd64/bignum_amd64.c $(LTAIL))

$(LINTS_DIR)/bignum_amd64_asm.ln: $(BIGNUMDIR)/amd64/bignum_amd64_asm.s
	@($(LHEAD) $(LINT.s) $(BIGNUMDIR)/amd64/bignum_amd64_asm.s $(LTAIL))

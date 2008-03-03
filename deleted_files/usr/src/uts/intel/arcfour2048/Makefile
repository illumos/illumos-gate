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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
#	This makefile drives the production of the ARCFOUR KEF provider.
#
#	intel implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..
COM_DIR = $(COMMONBASE)/crypto/arcfour

#
#	Define the module and object file sets.
#
MODULE		= arcfour2048
LINTS		= $(ARCFOURPROV_OBJS:%.o=$(LINTS_DIR)/%.ln)
ARCFOURPROV_OBJS_32 =
ARCFOURPROV_OBJS_64 = arcfour_crypt_amd64.o
ARCFOURPROV_OBJS += $(ARCFOURPROV_OBJS_$(CLASS))
OBJECTS		= $(ARCFOURPROV_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_CRYPTO_DIR)/$(MODULE)

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#	set signing mode
ELFSIGN_MOD	= $(ELFSIGN_CRYPTO)

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

#
# Overrides
#
CPPFLAGS	+= -I$(COM_DIR) -DCRYPTO_UNLIMITED

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

$(OBJS_DIR)/arcfour_crypt_amd64.o: $(COM_DIR)/amd64/arcfour_crypt_amd64.s
	$(COMPILE.s) -o $@ $(COM_DIR)/amd64/arcfour_crypt_amd64.s
	$(POST_PROCESS_O)

$(OBJS_DIR)/arcfour_crypt_amd64.ln: $(COM_DIR)/amd64/arcfour_crypt_amd64.s
	@($(LHEAD) $(LINT.s) $(COM_DIR)/amd64/arcfour_crypt_amd64.s $(LTAIL))

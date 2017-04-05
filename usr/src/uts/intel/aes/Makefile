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
# Copyright 2014 Garrett D'Amore <garrett@damore.org>
#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#	This makefile drives the production of the AES KEF provider.
#
#	Intel implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..
COM_DIR = $(COMMONBASE)/crypto/aes

#
#	Define the module and object file sets.
#
MODULE		= aes
LINTS		= $(AESPROV_OBJS:%.o=$(LINTS_DIR)/%.ln)
AESPROV_OBJS_32	=
AESPROV_OBJS_64	= aes_amd64.o aes_intel.o aeskey.o
AESPROV_OBJS	+= $(AESPROV_OBJS_$(CLASS))
OBJECTS		= $(AESPROV_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_CRYPTO_DIR)/$(MODULE)

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
#	Linkage dependencies
#
LDFLAGS += -dy -Nmisc/kcf

CPPFLAGS	+= -I$(COM_DIR) -I$(COM_DIR)/..
CPPFLAGS	+= -DCRYPTO_PROVIDER_NAME=\"$(MODULE)\"
AS_CPPFLAGS	+= -I../../$(PLATFORM)

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

$(OBJS_DIR)/%.ln: $(COM_DIR)/amd64/%.c
	@($(LHEAD) $(LINT.c) $(COM_DIR)/amd64/${@F:.ln=.c} $(LTAIL))

$(OBJS_DIR)/%.o:  $(COM_DIR)/amd64/%.c
	$(COMPILE.c) -o $@ $(COM_DIR)/amd64/${@F:.o=.c}
	$(POST_PROCESS_O)

$(OBJS_DIR)/%.o: $(COM_DIR)/amd64/%.s
	$(COMPILE.s) -o $@ $(COM_DIR)/amd64/${@F:.o=.s}
	$(POST_PROCESS_O)

$(OBJS_DIR)/%.ln: $(COM_DIR)/amd64/%.s
	@($(LHEAD) $(LINT.s) $(COM_DIR)/amd64/${@F:.ln=.s} $(LTAIL))

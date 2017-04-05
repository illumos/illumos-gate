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
# Copyright 2014 Garrett D'Amore <garrett@damore.org>
#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
#	This makefile drives the production of the dummy KEF provider.
#
#	intel implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..
COM_DIR = $(SRC)/common/crypto

#
#	Define the module and object file sets.
#
MODULE		= dprov
OBJECTS		= $(DPROV_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(DPROV_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
ROOTLINK	= $(ROOT_CRYPTO_DIR)/$(MODULE)
TARGET_32	= ../../kernel/drv/$(MODULE)
TARGET_64	= ../../../kernel/drv/$(SUBDIR64)/$(MODULE)
LINK_TARGET	= $(TARGET_$(CLASS))
CONF_SRCDIR	= $(UTSBASE)/common/crypto/io

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(SRC_CONFFILE)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOTLINK) $(ROOT_CONFFILE)

#
# Linkage dependencies
#
# Note that regular providers do not need to have an explicit dependency
# on KCF. This is a special case since the test pseudo driver dprov
# uses private KCF functions.
#
LDFLAGS += -dy -Nmisc/kcf

CFLAGS		+= $(CCVERBOSE) -I$(COM_DIR)
LINTFLAGS	+= -I$(COM_DIR)

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
# Please do not carry these forward to new Makefiles.
#
LINTTAGS	+= -erroff=E_SUSPICIOUS_COMPARISON
LINTTAGS	+= -erroff=E_ASSIGN_NARROW_CONV
LINTTAGS	+= -erroff=E_SUPPRESSION_DIRECTIVE_UNUSED

CERRWARN	+= -_gcc=-Wno-switch
CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-unused-label

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

$(ROOTLINK):	$(ROOT_CRYPTO_DIR) $(ROOTMODULE)
	-$(RM) $@; ln -s $(LINK_TARGET) $@

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ

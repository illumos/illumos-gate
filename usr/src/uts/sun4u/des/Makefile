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
# uts/sun4u/des/Makefile
#
# Copyright 2014 Garrett D'Amore <garrett@damore.org>
#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
#	This makefile drives the production of the des kernel module.
#
#	sun4u implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..
COM_DIR = $(COMMONBASE)/crypto

#
#	Define the module and object file sets.
#
MODULE		= des
OBJECTS		= $(DES_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_PSM_CRYPTO_DIR)/$(MODULE)
ROOTLINK	= $(ROOT_PSM_MISC_DIR)/$(MODULE)
TARGET_32	= ../../kernel/crypto/$(MODULE)
TARGET_64	= ../../../kernel/crypto/$(SUBDIR64)/$(MODULE)
LINK_TARGET	= $(TARGET_$(CLASS))

#
#	Include common rules.
#
include $(UTSBASE)/sun4u/Makefile.sun4u

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOTLINK)

#
# Linkage dependencies
#
LDFLAGS += -Nmisc/kcf

CFLAGS		+= -I$(COM_DIR)

#
# For now, disable these warnings; maintainers should endeavor
# to investigate and remove these for maximum coverage.
# Please do not carry these forward to new Makefiles.
#
CFLAGS		+= $(CCVERBOSE)
CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= $(CNOWARN_UNINIT)

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS)

$(ROOTLINK):	$(ROOT_PSM_MISC_DIR) $(ROOTMODULE)
	-$(RM) $@; ln -s $(LINK_TARGET) $@

#
#	Include common targets.
#
include $(UTSBASE)/sun4u/Makefile.targ


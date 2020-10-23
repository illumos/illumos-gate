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
# uts/sun4u/aes/Makefile
#
# Copyright 2014 Garrett D'Amore <garrett@damore.org>
#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
#	This makefile drives the production of the aes kernel module.
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
MODULE		= aes
OBJECTS		= $(AES_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_US3_CRYPTO_DIR)/$(MODULE)

#
#	Include common rules.
#
include $(UTSBASE)/sun4u/Makefile.sun4u

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

#
# Linkage dependencies
#
LDFLAGS += -dy -Nmisc/kcf

CFLAGS		+= $(CCVERBOSE) -I$(COM_DIR)
CPPFLAGS	+= -DCRYPTO_PROVIDER_NAME=\"$(MODULE)\"

#
# Turn on doubleword alignment for 64 bit registers
#
CFLAGS += -dalign

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
include $(UTSBASE)/sun4u/Makefile.targ

$(ROOT_US3_DIR): $(ROOT_PLAT_DIR)
	-$(INS.dir)

$(ROOT_US3_MOD_DIR): $(ROOT_US3_DIR)
	-$(INS.dir)

$(ROOT_US3_CRYPTO_DIR): $(ROOT_US3_MOD_DIR)
	-$(INS.dir)

$(ROOT_US3_CRYPTO_DIR)/%: $(OBJS_DIR)/% $(ROOT_US3_CRYPTO_DIR)
	-$(INS.file)


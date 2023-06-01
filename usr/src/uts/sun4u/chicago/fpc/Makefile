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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
#	uts/sun4u/chicago/fpc/Makefile
#
#	This makefile drives the production of the sun4u
#	fire performance counter kernel module
#
#	sun4u implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../../..

#
#	Define the module and object file sets.
#
MODULE		= fpc
OBJECTS		= $(FPC_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_CHICAGO_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/sun4/io/fpc

ROOT_BOSTON_DIR		= $(ROOT_PLAT_DIR)/SUNW,Sun-Fire-V445
ROOT_BOSTON_MOD_DIR	= $(ROOT_BOSTON_DIR)/kernel
ROOT_BOSTON_DRV_DIR_32	= $(ROOT_BOSTON_MOD_DIR)/drv
ROOT_BOSTON_DRV_DIR_64	= $(ROOT_BOSTON_DRV_DIR_32)/$(SUBDIR64)

ROOT_SEATTLE_DIR	= $(ROOT_PLAT_DIR)/SUNW,Sun-Fire-V215
ROOT_SEATTLE_MOD_DIR	= $(ROOT_SEATTLE_DIR)/kernel
ROOT_SEATTLE_DRV_DIR_32	= $(ROOT_SEATTLE_MOD_DIR)/drv
ROOT_SEATTLE_DRV_DIR_64	= $(ROOT_SEATTLE_DRV_DIR_32)/$(SUBDIR64)

ROOTMODULE_SOFTLINK	= $(ROOT_BOSTON_DRV_DIR_64:$(ROOT_BOSTON_DIR)%=../../../../SUNW,A70%/$(MODULE))

CONFFILE_SOFTLINK	= $(ROOT_BOSTON_DRV_DIR_32:$(ROOT_BOSTON_DIR)%=../../../SUNW,A70%/$(CONFFILE))

BOSTON_ROOTMODULE	= $(ROOT_BOSTON_DRV_DIR_64)/$(MODULE)
BOSTON_CONFFILE		= $(ROOT_BOSTON_DRV_DIR_32)/$(CONFFILE)

SEATTLE_ROOTMODULE	= $(ROOT_SEATTLE_DRV_DIR_64)/$(MODULE)
SEATTLE_CONFFILE	= $(ROOT_SEATTLE_DRV_DIR_32)/$(CONFFILE)

#
#	Include common rules.
#
include $(UTSBASE)/sun4u/chicago/Makefile.chicago

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(SRC_CONFFILE)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE) \
			$(BOSTON_ROOTMODULE) $(BOSTON_CONFFILE) \
			$(SEATTLE_ROOTMODULE) $(SEATTLE_CONFFILE)

#
#	Include SUN4 and SUN4U specific headers files
#
INC_PATH	+= -I$(UTSBASE)/sun4/io/fpc

#
# For now, disable these warnings; maintainers should endeavor
# to investigate and remove these for maximum coverage.
# Please do not carry these forward to new Makefiles.
#
CFLAGS		+= $(CCVERBOSE)
CERRWARN	+= -_gcc=-Wno-unused-variable

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS)

$(ROOT_BOSTON_DIR): $(ROOT_PLAT_DIR)
	-$(INS.dir)

$(ROOT_BOSTON_MOD_DIR): $(ROOT_BOSTON_DIR)
	-$(INS.dir)

$(ROOT_BOSTON_DRV_DIR_32): $(ROOT_BOSTON_MOD_DIR)
	-$(INS.dir)

$(ROOT_BOSTON_DRV_DIR_64): $(ROOT_BOSTON_DRV_DIR_32)
	-$(INS.dir)

$(ROOT_SEATTLE_DIR): $(ROOT_PLAT_DIR)
	-$(INS.dir)

$(ROOT_SEATTLE_MOD_DIR): $(ROOT_SEATTLE_DIR)
	-$(INS.dir)

$(ROOT_SEATTLE_DRV_DIR_32): $(ROOT_SEATTLE_MOD_DIR)
	-$(INS.dir)

$(ROOT_SEATTLE_DRV_DIR_64): $(ROOT_SEATTLE_DRV_DIR_32)
	-$(INS.dir)

$(BOSTON_ROOTMODULE): $(ROOTMODULE) $(ROOT_BOSTON_DRV_DIR_64)
	$(RM) $@; $(SYMLINK) $(ROOTMODULE_SOFTLINK) $@

$(BOSTON_CONFFILE): $(ROOT_CONFFILE) $(ROOT_BOSTON_DRV_DIR_32)
	$(RM) $@; $(SYMLINK) $(CONFFILE_SOFTLINK) $@

$(SEATTLE_ROOTMODULE): $(ROOTMODULE) $(ROOT_SEATTLE_DRV_DIR_64)
	$(RM) $@; $(SYMLINK) $(ROOTMODULE_SOFTLINK) $@

$(SEATTLE_CONFFILE): $(ROOT_CONFFILE) $(ROOT_SEATTLE_DRV_DIR_32)
	$(RM) $@; $(SYMLINK) $(CONFFILE_SOFTLINK) $@


#
#	Include common targets.
#
include $(UTSBASE)/sun4u/chicago/Makefile.targ

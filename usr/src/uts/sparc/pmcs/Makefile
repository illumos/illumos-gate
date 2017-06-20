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
#
#	This makefile drives the production of the pmcs driver kernel module.
#
#	SPARC architecture dependent
#

#
#	Paths to the base of the uts directory trees
#
UTSBASE   = ../../../../src/uts

#
#	Define the module and object file sets.
#
MODULE		= pmcs
OBJECTS		= $(PMCS_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(PMCS_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/common/io/scsi/adapters/pmcs

#
#	Kernel Module Dependencies
#
LDFLAGS += -dy -Nmisc/scsi

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(CONFMOD)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

#
#	Include common rules.
#
include $(UTSBASE)/sparc/Makefile.sparc
include $(CONF_SRCDIR)/pmcs8001fw.version

#
# Add additional flags
#
PMCS_DRV_FLGS	= -DMODNAME=\"${MODULE}\" -DDISABLE_MSIX
CPPFLAGS	+= $(PMCS_DRV_FLGS) \
	-DPMCS_FIRMWARE_VERSION=${PMCS_FW_VERSION} \
	-DPMCS_FIRMWARE_VERSION_STRING=\"${PMCS_FW_VERSION_STRING}\"

CERRWARN	+= -_gcc=-Wno-switch
CERRWARN	+= -_gcc=-Wno-uninitialized
CERRWARN	+= -_gcc=-Wno-unused-value
CERRWARN	+= -_gcc=-Wno-unused-label
CERRWARN	+= -_gcc=-Wno-parentheses


#
#	Default build targets.
#
.KEEP_STATE:

all:		$(ALL_DEPS)

def:		$(DEF_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS)

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS)

#
#	Include common targets.
#
include $(UTSBASE)/sparc/Makefile.targ

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
# This makefile drives the production of pmcs8001fw firmware kernel module.
#
# SPARC architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE   = ../../../../src/uts

#
#	Define the module and object file sets.
#
MODULE		= pmcs8001fw
OBJECTS		= $(PMCS8001FW_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_PMCS_FW_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/common/io/scsi/adapters/pmcs

#
#	Include common rules.
#
include $(UTSBASE)/sparc/Makefile.sparc
include $(CONF_SRCDIR)/pmcs8001fw.version

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(CONFMOD) $(ITUMOD)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

LDFLAGS		+= -dy

#
#	Extra flags
#
CPPFLAGS	+=	-DPMCS_FIRMWARE_VERSION=${PMCS_FW_VERSION} \
	-DPMCS_FIRMWARE_VERSION_STRING=\"${PMCS_FW_VERSION_STRING}\"


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
include $(UTSBASE)/sparc/Makefile.targ


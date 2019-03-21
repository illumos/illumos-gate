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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2016 Joyent, Inc.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

#	This makefile drives the production of the tzmon
#	ThermalZone Monitor driver kernel module.
#
#	i86pc architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= tzmon
OBJECTS		= $(TZMON_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/i86pc/io/tzmon

#
#	Include common rules.
#
include $(UTSBASE)/i86pc/Makefile.i86pc

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(CONFMOD)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

DEBUG_FLGS      =
$(NOT_RELEASE_BUILD)DEBUG_DEFS	+= $(DEBUG_FLGS)

CPPFLAGS	+= -DSUNDDI
CERRWARN	+= -_gcc=-Wno-unused-function

LDFLAGS		+= -dy -N misc/acpica

#
# For now, disable these checks; maintainers should endeavor
# to investigate and remove these for maximum coverage.
# Please do not carry these forward to new Makefiles.
#
CERRWARN	+= -_gcc=-Wno-uninitialized

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
include $(UTSBASE)/i86pc/Makefile.targ

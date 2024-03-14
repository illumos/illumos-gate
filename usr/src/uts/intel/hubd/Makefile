#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
#	This makefile drives the production of the hubd driver kernel module.
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..


#
#	Define the module and object file sets.
#
SRCDIR		= $(UTSBASE)/common/io/usb/hubd
CONFIGFILES	= config_map.conf
ROOTETCUSB	= $(ROOT)/etc/usb

SRCFILES	= $(CONFIGFILES:%=$(SRCDIR)/%)
ROOTCONFIGFILES	= $(CONFIGFILES:%=$(ROOTETCUSB)/%)

$(ROOTCONFIGFILES):=	FILEMODE = $(CFILEMODE)

#
#	Define the module and object file sets.
#
MODULE		= hubd
OBJECTS		= $(HUBD_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

#
# depends on misc/usba
#
LDFLAGS         += -Nmisc/usba

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS) $(ROOTCONFIGFILES)

$(ROOTETCUSB)/%: $(ROOTETCUSB) $(SRCDIR)/%
	$(INS.file)

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ


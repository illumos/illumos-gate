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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
#	This makefile drives the production of the platform power
#	management driver in the sun4u Chicago system.
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../../..

#
#	Define the module and object file sets.
#
MODULE		= ppm
ROOTMODULE	= $(ROOT_CHICAGO_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/sun4u/chicago/io

#
#	Include common rules.
#
include $(UTSBASE)/sun4u/chicago/Makefile.chicago


#
# Define targets
#
ALL_TARGET	= $(SRC_CONFILE)
INSTALL_TARGET	= $(ROOT_CONFFILE)

#
#	Overrides
#
NO_BUILDS	=
ALL_BUILDS	= $(ALL_BUILDSONLY64)
DEF_BUILDS	= $(DEF_BUILDSONLY64)

#
# The only thing we do from here is install the .conf file
#
CONF_INSTALL_DEPS	= $(DEF_BUILDS:%=conf_install.%)
CONF_INSTALL_TARGS	= conf_install
CONF_INSTALL_OBJ64	= $(CONF_INSTALL_TARGS:%=%.obj64)
CONF_INSTALL_DBG64	= $(CONF_INSTALL_TARGS:%=%.debug64)

$(CONF_INSTALL_OBJ64):	FRC
	@BUILD_TYPE=OBJ64 $(MAKE) $(INSTALL_TARGET)

$(CONF_INSTALL_DBG64):	FRC
	@BUILD_TYPE=DBG64 $(MAKE) $(INSTALL_TARGET)

#
#	Default build targets.
#
.KEEP_STATE:

def all clean clobber:

install:	$(CONF_INSTALL_DEPS)

#
#	Include common targets.
#
include $(UTSBASE)/sun4u/chicago/Makefile.targ

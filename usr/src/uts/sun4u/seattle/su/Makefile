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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# uts/sun4u/seattle/su/Makefile
#
#	This makefile drives the install of the platform su.conf
#	driver configuration file in the sun4u Seattle system.
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../../..

#
#	Define the module and file sets.
#
MODULE		= su
ROOTMODULE	= $(ROOT_SEATTLE_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/sun4u/seattle/io

#
#	Include common rules.
#
include $(UTSBASE)/sun4u/seattle/Makefile.seattle


#
# Define targets
#
ALL_TARGET	= $(SRC_CONFILE)
INSTALL_TARGET	= $(ROOT_CONFFILE)

#
# The only thing we do from here is install the .conf file
#
CONF_INSTALL_TARGS	= conf_install
CONF_INSTALL_OBJ	= $(CONF_INSTALL_TARGS)

$(CONF_INSTALL_OBJ):	FRC
	$(MAKE) $(INSTALL_TARGET)

#
#	Default build targets.
#
.KEEP_STATE:

def all clean clobber lint modlintlib clean.lint:

install:	$(INSTALL_TARGET)

#
#	Include common targets.
#
include $(UTSBASE)/sun4u/seattle/Makefile.targ

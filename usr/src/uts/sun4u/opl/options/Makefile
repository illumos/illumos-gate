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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# uts/sun4u/opl/options/Makefile
#
#	This makefile drives the production of the opl options conf file
#
#	sparc architecture dependent
#
#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../../..

#
#	Define the module and object file sets.
#
MODULE		= options
ROOTMODULE      = $(ROOT_OPL_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/sun4u/opl/io

#
#	Include common rules.
#
include $(UTSBASE)/sun4u/opl/Makefile.opl

#
#	Define targets
#
ALL_TARGET	= $(SRC_CONFILE)
LINT_TARGET	= 
INSTALL_TARGET	= $(ROOT_OPL_DRV_DIR) $(ROOT_CONFFILE)

#
#	Overrides.
#
CFLAGS		+= $(CCVERBOSE)

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

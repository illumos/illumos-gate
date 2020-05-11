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
#	This makefile drives the production of the sun4u sunfire platform
#	module.
#
#	sun4u implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	  = ../..

#
#	Include common rules.
#
include $(UTSBASE)/sun4u/sunfire/Makefile.sunfire

def		:=	TARGET= def
all		:=	TARGET= all
install		:=	TARGET= install
install_h	:=	TARGET= install_h
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber
modlist		:=	TARGET= modlist
modlist		:=	NO_STATE= -K $$MODSTATE$$$$
check		:=	TARGET= check

#
#	Default build targets.
#
.KEEP_STATE:

def all clean clobber modlist: \
	$(SUNFIRE_KMODS) $(CLOSED_SUNFIRE_KMODS)

IMPLEMENTED_PLATFORM	= SUNW,Ultra-Enterprise

install:	$(ROOT_SUNFIRE_DIR) $(USR_SUNFIRE_DIR) \
		$(USR_SUNFIRE_INC_DIR) \
		$(USR_SUNFIRE_SBIN_DIR) \
		$(USR_SUNFIRE_LIB_DIR) \
		.WAIT $(SUNFIRE_KMODS) $(CLOSED_SUNFIRE_KMODS)

install_h check:	FRC
	@cd sys; pwd; $(MAKE) $(TARGET)

$(SUNFIRE_KMODS): FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

$(CLOSED_SUNFIRE_KMODS): FRC
	@cd $(CLOSED)/uts/sun4u/sunfire/$@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

#
#	Include common targets.
#
include $(UTSBASE)/sun4u/sunfire/Makefile.targ

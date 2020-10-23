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
# uts/sun4v/ontario/Makefile
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#	This makefile drives the production of the sun4v ontario platform
#	modules.
#
#	sun4v ontario implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Include common rules.
#
include $(UTSBASE)/sun4v/ontario/Makefile.ontario

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

def all clean clobber modlist:	$(ONTARIO_KMODS)

IMPLEMENTED_PLATFORM	= SUNW,Sun-Fire-T200
LINKED_PLATFORMS	= SUNW,Sun-Fire-T1000
LINKED_PLATFORMS	+= SUNW,SPARC-Enterprise-T1000
LINKED_PLATFORMS	+= SUNW,Netra-T2000
LINKED_PLATFORMS	+= SUNW,SPARC-Enterprise-T2000
PPLINKED_PLATFORMS	= SUNW,Netra-T2000
PPLINKED_PLATFORMS	+= SUNW,SPARC-Enterprise-T2000

install:	$(ROOT_ONTARIO_DIR) $(USR_ONTARIO_DIR) \
		$(USR_ONTARIO_SBIN_DIR) \
		$(USR_ONTARIO_LIB_DIR) \
		$(ROOT_ONTARIO_LIB_DIR) \
		$(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%) \
		$(PPLINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%) \
		.WAIT $(ONTARIO_KMODS)

$(ONTARIO_KMODS):	FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

install_h check:	FRC

#
#	Include common targets.
#
include $(UTSBASE)/$(PLATFORM)/ontario/Makefile.targ

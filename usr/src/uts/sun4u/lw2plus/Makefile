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
#	This makefile drives the production of the sun4u lw2plus platform
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
include $(UTSBASE)/sun4u/lw2plus/Makefile.lw2plus

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

def all clean clobber modlist: $(LW2PLUS_KMODS)

IMPLEMENTED_PLATFORM	= SUNW,Netra-T4
LINKS2DESTDIR	= ../../../../SUNW,Sun-Fire-280R/kernel/misc/sparcv9
LW2PLUS_LINKS_2	= SUNW,Netra-T4/kernel/misc/sparcv9/platmod
LW2PLUS_PLAT_LINKS_2  = $(LW2PLUS_LINKS_2:%=$(ROOT_PLAT_DIR)/%)

install:	$(ROOT_LW2PLUS_DIR) $(USR_LW2PLUS_DIR) \
		$(ROOT_LW2PLUS_MISC_DIR_64) \
		$(USR_LW2PLUS_INC_DIR) \
		$(USR_LW2PLUS_SBIN_DIR) \
		$(USR_LW2PLUS_LIB_DIR) \
		.WAIT $(LW2PLUS_KMODS) \
		$(LW2PLUS_PLAT_LINKS_2) \
		$(LW2PLUS_CRYPTO_LINKS)

install_h check:

$(LW2PLUS_KMODS): FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

$(LW2PLUS_PLAT_LINKS_2):
	$(RM) $@; $(SYMLINK) $(LINKS2DESTDIR)/$(@F) $@

$(LW2PLUS_CRYPTO_LINKS): $(ROOT_LW2PLUS_CRYPTO_DIR_64)
	-$(RM) $(ROOT_LW2PLUS_CRYPTO_DIR_64)/$@;
	$(SYMLINK) $(ROOT_US3_CRYPTO_LINK)/$@ $(ROOT_LW2PLUS_CRYPTO_DIR_64)/$@

#
#
#	Include common targets.
#
include $(UTSBASE)/sun4u/lw2plus/Makefile.targ

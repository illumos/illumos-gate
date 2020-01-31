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
# Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
#
# uts/sun4u/seattle/Makefile
#
#	This makefile drives the production of the sun4u seattle platform
#	module.
#
#	sun4u implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Include common rules.
#
include $(UTSBASE)/sun4u/seattle/Makefile.seattle

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

def all clean clobber modlist: $(SEATTLE_KMODS)

LINKED_PLATFORMS	= SUNW,Sun-Fire-V245

install:	$(ROOT_SEATTLE_DIR) \
		$(USR_SEATTLE_DIR) \
		$(USR_SEATTLE_INC_DIR) \
		$(USR_SEATTLE_SBIN_PRTDIAG) \
		$(USR_SEATTLE_SBIN_FRUADM) \
		$(USR_SEATTLE_LIB_DIR) \
		$(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%) \
		$(LINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%) \
		$(SEATTLE_CRYPTO_LINKS) \
		.WAIT $(SEATTLE_KMODS)

check install_h:

$(SEATTLE_KMODS): FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

$(SEATTLE_CRYPTO_LINKS): $(ROOT_SEATTLE_CRYPTO_DIR_64)
	-$(RM) $(ROOT_SEATTLE_CRYPTO_DIR_64)/$@;
	$(SYMLINK) $(ROOT_US3_CRYPTO_LINK)/$@ $(ROOT_SEATTLE_CRYPTO_DIR_64)/$@


#
#	Include common targets.
#
include $(UTSBASE)/sun4u/seattle/Makefile.targ

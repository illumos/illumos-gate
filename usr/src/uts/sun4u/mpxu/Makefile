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
# Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
#

#
#	This makefile drives the production of the sun4u mpxu platform
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
include $(UTSBASE)/sun4u/mpxu/Makefile.mpxu

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

def all clean clobber modlist: $(MPXU_KMODS) $(CLOSED_MPXU_KMODS)

IMPLEMENTED_PLATFORM	= SUNW,Sun-Fire-V240

LINKED_PLATFORMS	= SUNW,Sun-Fire-V210
LINKED_PLATFORMS	+= SUNW,Netra-240
LINKED_PLATFORMS	+= SUNW,Netra-210


install:	$(ROOT_MPXU_DIR) $(USR_MPXU_DIR) \
		$(USR_MPXU_INC_DIR) \
		$(USR_MPXU_SBIN_PRTDIAG) \
		$(USR_MPXU_SBIN_FRUADM) \
		$(USR_MPXU_LIB_DIR) \
		$(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%) \
		$(LINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%) \
		$(MPXU_CRYPTO_LINKS) \
		$(CLOSED_MPXU_KMODS) \
		.WAIT $(MPXU_KMODS)

$(MPXU_KMODS): FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

$(CLOSED_MPXU_KMODS): FRC
	cd $(CLOSED)/uts/sun4u/mpxu/$@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

$(MPXU_CRYPTO_LINKS): $(ROOT_MPXU_CRYPTO_DIR_64)
	-$(RM) $(ROOT_MPXU_CRYPTO_DIR_64)/$@;
	$(SYMLINK) $(ROOT_US3_CRYPTO_LINK)/$@ $(ROOT_MPXU_CRYPTO_DIR_64)/$@

install_h check:	FRC
	@cd sys; pwd; $(MAKE) $(TARGET)

#
#
#	Include common targets.
#
include $(UTSBASE)/sun4u/mpxu/Makefile.targ

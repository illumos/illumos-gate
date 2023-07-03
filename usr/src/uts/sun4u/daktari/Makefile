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
# uts/sun4u/daktari/Makefile
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#	This makefile drives the production of all Daktari system
#	dependent modules for the sun4u architecture.
#


#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE = ../..

#
#	Include common rules.
#
include $(UTSBASE)/sun4u/daktari/Makefile.daktari

def		:=	TARGET= def
all		:=	TARGET= all
install		:=	TARGET= install
install_h	:=	TARGET= install_h
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber
check		:=	TARGET= check

#
#	Default build targets.
#
.KEEP_STATE:

def all clean clobber: $(DAKTARI_KMODS)

IMPLEMENTED_PLATFORM	= SUNW,Sun-Fire-880

LINKED_PLATFORMS	= SUNW,Sun-Fire-V890

install:	$(ROOT_DAKTARI_DIR) $(USR_DAKTARI_DIR) \
		$(USR_DAKTARI_INC_DIR) \
		$(USR_DAKTARI_SBIN_DIR) \
		$(USR_DAKTARI_LIB_DIR) \
		$(LINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%) \
		$(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib) \
		$(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/include) \
		$(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/sbin) \
		$(DAKTARI_CRYPTO_LINKS) \
		.WAIT $(DAKTARI_KMODS)

$(DAKTARI_CRYPTO_LINKS): $(ROOT_DAKTARI_CRYPTO_DIR_64)
	-$(RM) $(ROOT_DAKTARI_CRYPTO_DIR_64)/$@;
	$(SYMLINK) $(ROOT_US3_CRYPTO_LINK)/$@ $(ROOT_DAKTARI_CRYPTO_DIR_64)/$@

install_h check:	FRC
	@cd sys; pwd; $(MAKE) $(TARGET)

$(DAKTARI_KMODS):	FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

#
#
#	Include common targets.
#
include $(UTSBASE)/sun4u/daktari/Makefile.targ

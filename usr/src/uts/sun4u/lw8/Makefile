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
#	This makefile drives the production of the sun4u lw8 platform
#	module.
#
#	sun4u implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE = ../..

#
#	Include common rules.
#
include $(UTSBASE)/sun4u/lw8/Makefile.lw8

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

def all clean clobber: $(LW8_KMODS)

IMPLEMENTED_PLATFORM	= SUNW,Netra-T12
LINKS2DESTDIR	= ../../SUNW,Sun-Fire/kernel
LINKS3DESTDIR	= ../../../../SUNW,Sun-Fire/kernel/drv/sparcv9
LINKS4DESTDIR	= ../../../../SUNW,Sun-Fire/kernel/misc/sparcv9
LW8_LINKS_2     = SUNW,Netra-T12/kernel/cpu
LW8_LINKS_2	+= SUNW,Netra-T12/kernel/sparcv9
LW8_LINKS_3	= SUNW,Netra-T12/kernel/drv/sparcv9/sgcn
LW8_LINKS_3	+= SUNW,Netra-T12/kernel/drv/sparcv9/sgsbbc
LW8_LINKS_3	+= SUNW,Netra-T12/kernel/drv/sparcv9/ssm
LW8_LINKS_4	= SUNW,Netra-T12/kernel/misc/sparcv9/sbdp
LW8_PLAT_LINKS_2  = $(LW8_LINKS_2:%=$(ROOT_PLAT_DIR)/%)
LW8_PLAT_LINKS_3  = $(LW8_LINKS_3:%=$(ROOT_PLAT_DIR)/%)
LW8_PLAT_LINKS_4  = $(LW8_LINKS_4:%=$(ROOT_PLAT_DIR)/%)

install:	$(ROOT_LW8_DIR) $(USR_LW8_DIR) \
		$(USR_LW8_INC_DIR) \
		$(USR_LW8_SBIN_DIR) \
		$(USR_LW8_LIB_DIR) \
		.WAIT $(LW8_KMODS) \
		$(LW8_PLAT_LINKS_2) \
		$(LW8_PLAT_LINKS_3) \
		$(LW8_PLAT_LINKS_4) \
		$(LW8_CRYPTO_LINKS)

$(LW8_KMODS): FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

install_h check:	FRC
	@cd sys; pwd; $(MAKE) $(TARGET)

$(LW8_PLAT_LINKS_2): $(ROOT_LW8_MOD_DIR)
	$(RM) $@; $(SYMLINK) $(LINKS2DESTDIR)/$(@F) $@

$(LW8_PLAT_LINKS_3): $(ROOT_LW8_DRV_DIR_64)
	$(RM) $@; $(SYMLINK) $(LINKS3DESTDIR)/$(@F) $@

$(LW8_PLAT_LINKS_4): $(ROOT_LW8_DRV_DIR_64)
	$(RM) $@; $(SYMLINK) $(LINKS4DESTDIR)/$(@F) $@

$(LW8_CRYPTO_LINKS): $(ROOT_LW8_CRYPTO_DIR_64)
	-$(RM) $(ROOT_LW8_CRYPTO_DIR_64)/$@;
	$(SYMLINK) $(ROOT_US3_CRYPTO_LINK)/$@ $(ROOT_LW8_CRYPTO_DIR_64)/$@

#
#
#	Include common targets.
#
include $(UTSBASE)/sun4u/lw8/Makefile.targ

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
# uts/sun4u/boston/Makefile
#
#	This makefile drives the production of the sun4u boston platform
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
include $(UTSBASE)/sun4u/boston/Makefile.boston

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

def all clean clobber modlist: $(BOSTON_KMODS)

install:	$(ROOT_BOSTON_DIR) \
		$(USR_BOSTON_DIR) \
		$(USR_BOSTON_INC_DIR) \
		$(USR_BOSTON_SBIN_PRTDIAG) \
		$(USR_BOSTON_SBIN_FRUADM) \
		$(USR_BOSTON_LIB_DIR) \
		$(BOSTON_CRYPTO_LINKS) \
		.WAIT $(BOSTON_KMODS)

check install_h:

$(BOSTON_KMODS): FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

$(BOSTON_CRYPTO_LINKS): $(ROOT_BOSTON_CRYPTO_DIR_64)
	-$(RM) $(ROOT_BOSTON_CRYPTO_DIR_64)/$@;
	$(SYMLINK) $(ROOT_US3_CRYPTO_LINK)/$@ $(ROOT_BOSTON_CRYPTO_DIR_64)/$@

#
#
#	Include common targets.
#
include $(UTSBASE)/sun4u/boston/Makefile.targ

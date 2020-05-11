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
# uts/sun4u/littleneck/Makefile
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#	This makefile drives the production of all Littleneck system
#	dependent modules for the sun4u architecture.
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE = ../..

#
#	Include common rules.
#
include $(UTSBASE)/sun4u/littleneck/Makefile.littleneck

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

def all clean clobber modlist: $(LITTLENECK_KMODS)

install:	$(ROOT_LITTLENECK_DIR) $(USR_LITTLENECK_DIR) \
		$(USR_LITTLENECK_INC_DIR) \
		$(USR_LITTLENECK_SBIN_DIR) \
		$(USR_LITTLENECK_LIB_DIR) \
		$(LITTLENECK_CRYPTO_LINKS) \
		.WAIT $(LITTLENECK_KMODS)

install_h check:

$(LITTLENECK_KMODS):	FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

$(LITTLENECK_CRYPTO_LINKS): $(ROOT_LITTLENECK_CRYPTO_DIR_64)
	-$(RM) $(ROOT_LITTLENECK_CRYPTO_DIR_64)/$@;
	$(SYMLINK) $(ROOT_US3_CRYPTO_LINK)/$@ \
	    $(ROOT_LITTLENECK_CRYPTO_DIR_64)/$@

#
#
#	Include common targets.
#
include $(UTSBASE)/sun4u/littleneck/Makefile.targ

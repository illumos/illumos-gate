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
# Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
#
#	This makefile drives the production of the sun4u opl platform
#	module.
#
#	sun4u opl implementation architecture dependent
#
# uts/sun4u/opl/Makefile

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#       Include common rules.
#
include $(UTSBASE)/sun4u/opl/Makefile.opl

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

def all clean clobber: genassym unix .WAIT \
		$(OPL_CPU_KMODS) $(OPL_KMODS)

IMPLEMENTED_PLATFORM	= SUNW,SPARC-Enterprise

install: $(ROOT_OPL_DIR) $(USR_OPL_DIR) \
	$(USR_OPL_INC_DIR) \
	$(USR_OPL_SBIN_DIR) \
	$(USR_OPL_SBIN_PRTDIAG) \
	$(USR_OPL_SBIN_FRUADM) \
	$(USR_OPL_LIB_DIR) \
	$(OPL_CRYPTO_LINKS) \
	genassym unix .WAIT $(OPL_CPU_KMODS) $(OPL_KMODS) \
	$(OPLMSU_OPTION)

genassym unix $(OPL_KMODS) $(OPL_CPU_KMODS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

$(OPL_CRYPTO_LINKS): $(ROOT_OPL_CRYPTO_DIR_64)
	-$(RM) $(ROOT_OPL_CRYPTO_DIR_64)/$@
	$(SYMLINK) $(ROOT_US3_CRYPTO_LINK)/$@ $(ROOT_OPL_CRYPTO_DIR_64)/$@

$(OPLMSU_OPTION):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

install_h check:	FRC
	@cd sys; pwd; $(MAKE) $(TARGET)

#
#
#	Include common targets.
#
include $(UTSBASE)/sun4u/opl/Makefile.targ

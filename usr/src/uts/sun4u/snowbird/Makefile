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
# Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2018 Gary mills
#
#	This makefile drives the production of the sun4u snowbird platform
#	module.
#
#	sun4u snowbird implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

include $(UTSBASE)/sun4u/snowbird/Makefile.snowbird

#
#
#

def		:=	TARGET= def
all		:=	TARGET= all
install		:=	TARGET= install
install_h	:=	TARGET= install_h
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber
lint		:=	TARGET= lint
lintlib		:=	TARGET= lintlib
modlintlib	:=	TARGET= modlintlib
modlist		:=	TARGET= modlist
modlist		:=	NO_STATE= -K $$MODSTATE$$$$
clean.lint	:=	TARGET= clean.lint
check		:=	TARGET= check

IMPLEMENTED_PLATFORM	= SUNW,Netra-CP2300

#
#	Default build targets.
#
.KEEP_STATE:

.PARALLEL:	$(SNOWBIRD_KMODS)

def all clean clobber clean.lint modlist:	$(SNOWBIRD_KMODS)

install:	$(ROOT_SNOWBIRD_DIR) $(USR_SNOWBIRD_DIR) \
		$(USR_SNOWBIRD_INC_DIR) \
		$(USR_SNOWBIRD_SBIN_DIR) \
		$(USR_SNOWBIRD_SBIN_PRTDIAG) \
		$(USR_SNOWBIRD_SBIN_FRUADM) \
		$(USR_SNOWBIRD_LIB_DIR) \
		.WAIT $(SNOWBIRD_KMODS) \
		ttymux_dacf ttymux.conf

modlintlib:	$(SNOWBIRD_KMODS)

$(SNOWBIRD_KMODS):	FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

ttymux_dacf:	$(ROOT_SNOWBIRD_DACF_DIR_64)
		-@$(RM) $(ROOT_SNOWBIRD_DACF_DIR_64)/$@
		$(SYMLINK) $(ROOT_SNOWBIRD_DACF_LINK_64)/$@ \
		$(ROOT_SNOWBIRD_DACF_DIR_64)/$@


ttymux.conf:	$(ROOT_SNOWBIRD_DRV_DIR_32)
		-@$(RM) $(ROOT_SNOWBIRD_DRV_DIR_32)/$@
		$(SYMLINK) $(ROOT_SNOWBIRD_DRV_LINK_32)/$@ \
		$(ROOT_SNOWBIRD_DRV_DIR_32)/$@

install_h check:	FRC
	@cd sys; pwd; $(MAKE) $(TARGET)

lint:	modlintlib

LINT_LIBS	= $(LINT_LIB) \
			-L$(SNOWBIRD_LINT_LIB_DIR) \
			-L$(LINT_LIB_DIR) $(LINT_KMODS:%=-l%) \
			    $(CLOSED_LINT_KMODS:%=-l%) \
			-L$(SPARC_LIB_DIR) $(SPARC_LINTS:%=-l%)

lint.platmod:   modlintlib
	@-$(ECHO) "\nSnowbird Platform-dependent module: global crosschecks:"
	@-$(LINT) $(LINTFLAGS) $(LINT_LIBS) 2>&1 | $(LGREP.2)

#
#	Include common targets.
#
include $(UTSBASE)/sun4u/snowbird/Makefile.targ

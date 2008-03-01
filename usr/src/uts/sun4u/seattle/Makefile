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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
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
lint		:=	TARGET= lint
lintlib		:=	TARGET= lintlib
modlintlib	:=	TARGET= modlintlib
modlist		:=	TARGET= modlist
modlist		:=	NO_STATE= -K $$MODSTATE$$$$
clean.lint	:=	TARGET= clean.lint
check		:=	TARGET= check

#
#	Default build targets.
#
.KEEP_STATE:

def all clean clean.lint clobber modlist: $(SEATTLE_KMODS)

modlintlib:	$(SEATTLE_KMODS)

LINKED_PLATFORMS	= SUNW,Sun-Fire-V245

install:	$(ROOT_SEATTLE_DIR) \
		$(USR_SEATTLE_DIR) \
		$(USR_SEATTLE_INC_DIR) \
		$(USR_SEATTLE_SBIN_PRTDIAG) \
		$(USR_SEATTLE_SBIN_TRAPSTAT) \
		$(USR_SEATTLE_SBIN_FRUADM) \
		$(USR_SEATTLE_LIB_DIR) \
		$(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%) \
		$(LINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%) \
		$(SEATTLE_CRYPTO_LINKS) \
		.WAIT $(SEATTLE_KMODS)

check install_h:

lint:		modlintlib

#
# The 'lint.platmod' target lints the seattle platform module against the sun4u
# kernel.  This ends up doing all the kernel cross-checks, so it takes a couple
# of minutes.  Due to the low ROI, it's not run by default, but it's a good
# idea to run this if you change os/seattle.c.
#
LINT_LIBS	 = $(LINT_LIB) \
		   -L$(SEATTLE_LINT_LIB_DIR) \
		   -L$(LINT_LIB_DIR) $(LINT_KMODS:%=-l%) \
			$(CLOSED_LINT_KMODS:%=-l%) \
		   -L$(SPARC_LIB_DIR) $(SPARC_LINTS:%=-l%)

lint.platmod:	modlintlib
	@-$(ECHO) "\nSeattle Platform-dependent module: global crosschecks:"
	@-$(LINT) $(LINTFLAGS) $(LINT_LIBS) 2>&1 | $(LGREP.2)

$(SEATTLE_KMODS): FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

$(SEATTLE_CRYPTO_LINKS): $(ROOT_SEATTLE_CRYPTO_DIR_64)
	-$(RM) $(ROOT_SEATTLE_CRYPTO_DIR_64)/$@;
	$(SYMLINK) $(ROOT_US3_CRYPTO_LINK)/$@ $(ROOT_SEATTLE_CRYPTO_DIR_64)/$@


#
#	Include common targets.
#
include $(UTSBASE)/sun4u/seattle/Makefile.targ

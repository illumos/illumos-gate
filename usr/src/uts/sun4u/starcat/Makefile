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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
#
#	This makefile drives the production of the sun4u starcat platform
#	module.
#
#	sun4u starcat implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#       Include common rules.
#
include $(UTSBASE)/sun4u/starcat/Makefile.starcat

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

def all clean clobber clean.lint: genassym unix .WAIT \
		$(STARCAT_CPU_KMODS) $(STARCAT_KMODS)

modlist:	unix \
		$(STARCAT_CPU_KMODS) $(STARCAT_KMODS)

lintlib:	unix

modlintlib:	$(STARCAT_KMODS)

IMPLEMENTED_PLATFORM	= SUNW,Sun-Fire-15000

install: $(ROOT_STARCAT_DIR) $(USR_STARCAT_DIR) \
	$(USR_STARCAT_INC_DIR) \
	$(USR_STARCAT_SBIN_DIR) \
	$(USR_STARCAT_LIB_DIR) \
	$(STARCAT_CRYPTO_LINKS) \
	genassym unix .WAIT $(STARCAT_CPU_KMODS) \
	$(STARCAT_KMODS)

genassym unix $(STARCAT_KMODS) $(STARCAT_CPU_KMODS): FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

$(STARCAT_CRYPTO_LINKS): $(ROOT_STARCAT_CRYPTO_DIR_64)
	-$(RM) $(ROOT_STARCAT_CRYPTO_DIR_64)/$@;
	$(SYMLINK) $(ROOT_US3_CRYPTO_LINK)/$@ $(ROOT_STARCAT_CRYPTO_DIR_64)/$@

install_h check:	FRC
	@cd sys; pwd; $(MAKE) $(TARGET)

lint:	modlintlib


#
# The 'lint.platmod' target lints the starcat platform module against
# the sun4u kernel.  This ends up doing all the kernel cross-checks,
# so it takes a couple of minutes.
# Due to the low ROI, it's not run by default, but it's a good
# idea to run this if you change os/starcat.c.
#

LINT_LIBS	= $(LINT_LIB) \
		  -L$(STARCAT_LINT_LIB_DIR) \
		  -L$(LINT_LIB_DIR) $(LINT_KMODS:%=-l%) \
		      $(CLOSED_LINT_KMODS:%=-l%) \
		  -L$(SPARC_LIB_DIR) $(SPARC_LINTS:%=-l%)

lint.platmod:   modlintlib
	@-$(ECHO) "\nStarcat Platform-dependent module: global crosschecks:"
	@-$(LINT) $(LINTFLAGS) $(LINT_LIBS) 2>&1 | $(LGREP.2)


#
#	Include common targets.
#
include $(UTSBASE)/sun4u/starcat/Makefile.targ

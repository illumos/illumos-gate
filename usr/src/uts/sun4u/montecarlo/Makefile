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
#     This makefile drives the production of all MonteCarlo system
#     dependent modules for the sun4u architecture.
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE		= ../..

#
#	Include common rules.
#
include $(UTSBASE)/sun4u/montecarlo/Makefile.montecarlo

def		:=	TARGET= def
all		:=	TARGET= all
install		:=	TARGET= install
install_h	:=	TARGET= install_h
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber
lint		:=	TARGET= lint
#lintlib	:=	TARGET= lintlib
modlintlib	:=	TARGET= modlintlib
modlist		:=	TARGET= modlist
modlist		:=	NO_STATE= -K $$MODSTATE$$$$
clean.lint	:=	TARGET= clean.lint
check		:=	TARGET= check

#
#	Default build targets.
#
.KEEP_STATE:

def all clean.lint clean clobber modlist: $(MONTECARLO_KMODS)

modlintlib:	$(MONTECARLO_KMODS)

install:        $(ROOT_MONTECARLO_DIR) \
		$(USR_MONTECARLO_DIR) \
                $(USR_MONTECARLO_INC_DIR) \
                $(USR_MONTECARLO_SBIN_DIR) \
                $(USR_MONTECARLO_LIB_DIR) \
                .WAIT $(MONTECARLO_KMODS) \
		se.conf ttymux.conf

se.conf:	$(ROOT_MONTECARLO_DRV_DIR_32)
		-@$(RM) $(ROOT_MONTECARLO_DRV_DIR_32)/$@
		$(CP) $(UTSBASE)/sun4u/montecarlo/io/$@ \
		$(ROOT_MONTECARLO_DRV_DIR_32)/$@
		$(CHMOD) $(CFILEMODE) $(ROOT_MONTECARLO_DRV_DIR_32)/$@

ttymux.conf:	$(ROOT_MONTECARLO_DRV_DIR_32)
		-@$(RM) $(ROOT_MONTECARLO_DRV_DIR_32)/$@
		$(CP) $(UTSBASE)/sun4u/montecarlo/io/$@ \
		$(ROOT_MONTECARLO_DRV_DIR_32)/$@
		$(CHMOD) $(CFILEMODE) $(ROOT_MONTECARLO_DRV_DIR_32)/$@

install_h check:	FRC
	@cd sys; pwd; $(MAKE) $(TARGET)

lint:		modlintlib

#
# The 'lint.platmod' target lints the montecarlo platform module against
# the sun4u kernel.  This ends up doing all the kernel cross-checks,
# so it takes a couple of minutes.
# Due to the low ROI, it's not run by default, but it's a good
# idea to run this if you change os/montecarlo.c.
#
LINT_LIBS	 = $(LINT_LIB) \
		   -L$(MONTECARLO_LINT_LIB_DIR) \
		   -L$(LINT_LIB_DIR) $(LINT_KMODS:%=-l%) \
		       $(CLOSED_LINT_KMODS:%=-l%) \
		   -L$(SPARC_LIB_DIR) $(SPARC_LINTS:%=-l%)

lint.platmod:   modlintlib
	@-$(ECHO) "\nMonteCarlo Platform-dependent module: global crosschecks:"
	@-$(LINT) $(LINTFLAGS) $(LINT_LIBS) 2>&1 | $(LGREP.2)

$(MONTECARLO_KMODS): FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

#
#	Include common targets.
#
include $(UTSBASE)/sun4u/montecarlo/Makefile.targ

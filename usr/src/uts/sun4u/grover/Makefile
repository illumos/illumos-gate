#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# uts/sun4u/grover/Makefile
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
#	This makefile drives the production of the sun4u grover platform
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
include $(UTSBASE)/sun4u/grover/Makefile.grover

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

def all clean clean.lint clobber modlist: $(GROVER_KMODS) \
	$(CLOSED_GROVER_KMODS)

modlintlib:	$(GROVER_KMODS) $(CLOSED_GROVER_KMODS)

install:	$(ROOT_GROVER_DIR) \
		$(USR_GROVER_DIR) \
		$(USR_GROVER_INC_DIR) \
		$(USR_GROVER_SBIN_DIR) \
		$(USR_GROVER_LIB_DIR) \
		$(GROVER_KMODS) \
		$(CLOSED_GROVER_KMODS)

check install_h:

lint:		modlintlib

#
# The 'lint.platmod' target lints the grover platform module against the sun4u
# kernel.  This ends up doing all the kernel cross-checks, so it takes a couple
# of minutes.  Due to the low ROI, it's not run by default, but it's a good
# idea to run this if you change os/grover.c.
#
LINT_LIBS	 = $(LINT_LIB) \
		   -L$(GROVER_LINT_LIB_DIR) \
		   -L$(LINT_LIB_DIR) $(LINT_KMODS:%=-l%) \
		       $(CLOSED_LINT_KMODS:%=-l%) \
		   -L$(SPARC_LIB_DIR) $(SPARC_LINTS:%=-l%)

lint.platmod:	modlintlib
	@-$(ECHO) "\nGrover Platform-dependent module: global crosschecks:"
	@-$(LINT) $(LINTFLAGS) $(LINT_LIBS) 2>&1 | $(LGREP.2)

$(GROVER_KMODS): FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

$(CLOSED_GROVER_KMODS): FRC
	cd $(CLOSED)/uts/sun4u/grover/$@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

#
#	Include common targets.
#
include $(UTSBASE)/sun4u/grover/Makefile.targ

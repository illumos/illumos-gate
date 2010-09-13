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
# uts/sun4u/fjlite/Makefile
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
#	This makefile drives the production of the sun4u fjlite platform
#	module.
#
#	sun4u fjlite implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

include $(UTSBASE)/sun4u/fjlite/Makefile.fjlite

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

IMPLEMENTED_PLATFORM	= SUNW,UltraAX-i2

#
#	Default build targets.
#
.KEEP_STATE:

.PARALLEL:	$(FJLITE_KMODS)

def all clean clobber clean.lint modlist:	$(FJLITE_KMODS)

install:	$(ROOT_FJLITE_DIR) $(USR_FJLITE_DIR) \
		.WAIT $(FJLITE_KMODS)

modlintlib:	$(FJLITE_KMODS)

$(FJLITE_KMODS):	FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

install_h check:

lint:	modlintlib .WAIT $(LINT_DEPS)

LINT_LIBS	= $(LINT_LIB) \
			-L$(FJLITE_LINT_LIB_DIR) \
			-L$(LINT_LIB_DIR) $(LINT_KMODS:%=-l%) \
			    $(CLOSED_LINT_KMODS:%=-l%) \
			-L$(SPARC_LIB_DIR) $(SPARC_LINTS:%=-l%)

lint.platmod:   modlintlib
	@-$(ECHO) "\nFJ-lite Platform-dependent module: global crosschecks:"
	@-$(LINT) $(LINTFLAGS) $(LINT_LIBS) 2>&1 | $(LGREP.2)

#
#	Include common targets.
#
include $(UTSBASE)/sun4u/fjlite/Makefile.targ

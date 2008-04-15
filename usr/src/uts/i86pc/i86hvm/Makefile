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
# uts/i86pc/i86hvm/Makefile
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
#	This makefile drives the production of the i86hvm platform modules.
#
#	i86pc implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Include common rules.
#
include $(UTSBASE)/i86pc/i86hvm/Makefile.i86hvm

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

.PARALLEL: $(HVM_KMODS)

def all clean clobber clean.lint modlist modlintlib:	$(HVM_KMODS)

install: install_implementations .WAIT \
	$(HVM_KMODS)

install_implementations: \
	$(ROOT_HVM_DIR) \
	$(ROOT_HVM_DRV_DIR) \
	$(ROOT_HVM_MISC_DIR) \
	$(USR_HVM_DIR)

$(HVM_KMODS):	FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

install_h check:	FRC

lintlib lint:	modlintlib .WAIT $(LINT_DEPS)

#
# The 'lint.platmod' target lints the i86hvm platform modules against the i86pc
# kernel.  This ends up doing all the kernel cross-checks.
#
LINT_TARGET	= lint.platmod
INTEL_LIB_DIR	= $(UTSBASE)/intel/lint-libs/$(OBJS_DIR)
INTEL_LINTS	= genunix
LINT_LIBS	= $(LINT_LIB) \
		  -L$(HVM_LINT_LIB_DIR) \
		  -L$(LINT_LIB_DIR) \
			$(GENUNIX_KMODS:%=-l%) \
			$(PARALLEL_KMODS:%=-l%) \
			$(CLOSED_KMODS:%=-l%) \
		  -L$(INTEL_LIB_DIR) \
			$(INTEL_LINTS:%=-l%)

# workaround for multiply defined errors
lint.platmod := LINTFLAGS += -erroff=E_NAME_MULTIPLY_DEF2

lint.platmod:   modlintlib
	@-$(ECHO) "\ni86hvm platform-dependent module: global crosschecks:"
	@-$(LINT) $(LINTFLAGS) $(LINT_LIBS) 2>&1 | $(LGREP.2)

#
#	Include common targets.
#
include $(UTSBASE)/$(PLATFORM)/i86hvm/Makefile.targ

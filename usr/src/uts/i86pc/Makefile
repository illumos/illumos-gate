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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
#	This makefile drives the production of all implementation architecture
#	dependent modules for the i86pc architecture.
#

UTSBASE = ..

include Makefile.i86pc

#
#	The following are x86 specific (rather than i86pc) specific modules
#	which are required for the i86pc kernel to completely lint. They are
#	not involved in the build in any other way. In order to minimize
#	build time, it is assumed that they are up to date.
#
INTEL_LIB_DIR	 = $(UTSBASE)/intel/lint-libs/$(OBJS_DIR)

INTEL_LINTS	 = genunix

LINT_LIBS	 = $(LINT_LIB) \
		   $(GENUNIX_KMODS:%=$(LINT_LIB_DIR)/llib-l%.ln) \
		   $(PARALLEL_KMODS:%=$(LINT_LIB_DIR)/llib-l%.ln) \
		   $(CLOSED_KMODS:%=$(LINT_LIB_DIR)/llib-l%.ln) \
		   $(INTEL_LINTS:%=$(INTEL_LIB_DIR)/llib-l%.ln)

#
#
#
def		:=	TARGET= def
all		:=	TARGET= all
install		:=	TARGET= install
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber
lint		:=	TARGET= lint
lintlib		:=	TARGET= lintlib
machmodlintlib	:=	TARGET= modlintlib
modlist		:=	TARGET= modlist
modlist	modlist.intel :=	NO_STATE= -K $$MODSTATE$$$$
clean.lint	:=	TARGET= clean.lint
check		:=	TARGET= check

.KEEP_STATE:

.PARALLEL:	$(PARALLEL_KMODS) $(CLOSED_KMODS) $(XMODS) $(CLOSED_XMODS) \
		modlist modlist.intel

INITIAL_TARGETS = \
	genassym \
	unix \
	cpu/scripts

def all clean clobber clean.lint: setup genassym unix .WAIT \
	$(KMODS) $(CLOSED_KMODS) $(XMODS) $(CLOSED_XMODS) $(IMPLEMENTATIONS)

install: install_platforms setup genassym unix .WAIT \
	$(KMODS) $(CLOSED_KMODS) $(XMODS) $(CLOSED_XMODS) $(IMPLEMENTATIONS)

# list the modules under i86pc.
modlist: unix $(KMODS) $(CLOSED_KMODS) $(XMODS) $(CLOSED_XMODS) \
	$(IMPLEMENTATIONS)

# list the modules for Install -k i86pc.
modlist.karch: modlist modlist.intel

modlist.intel:
	@cd $(SRC)/uts/intel; pwd; $(MAKE) $(NO_STATE) modlist

lintlib:	unix

modlintlib:	$(KMODS) $(CLOSED_KMODS)

genassym unix $(KMODS):	FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

setup: FRC
	@cd cpu/scripts; pwd; $(MAKE) $(TARGET)

$(IMPLEMENTATIONS):     FRC
	@cd $@; pwd; THISIMPL=$@ $(MAKE) $(NO_STATE) $(TARGET)

$(XMODS):	FRC
	@if [ -f $@/Makefile  ]; then \
		cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET); \
	else \
		true; \
	fi

$(CLOSED_KMODS):	FRC
	cd $(CLOSED)/uts/i86pc/$@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

$(CLOSED_XMODS):	FRC
	@if [ -f $(CLOSED)/uts/i86pc/$@/Makefile  ]; then \
		cd $(CLOSED)/uts/i86pc/$@; pwd; \
		    $(MAKE) $(NO_STATE) $(TARGET); \
	else \
		true; \
	fi

install_h check:	$(IMPLEMENTATIONS) FRC
	@cd sys; pwd; $(MAKE) $(TARGET)

#
# Definitions for the /platform directory aliases.
# Currently none for i86pc.
#
PLAT_LINKS	=

#
# Make the /platform directories.  This is hardwired here because
# the first stage of the project (KBI) only implements the userland
# changes, but the only reasonable place to record the aliases is
# here in kernel land.
#
install_platforms:	$(ROOT_PSM_DIR) $(USR_PSM_DIR) \
			$(ROOT_PLAT_LINKS) $(USR_PLAT_LINKS) \
			$(OEM_USR_PLAT_LINKS)

#
#	Full kernel lint target.
#
LINT_TARGET	= globallint

# workaround for multiply defined errors
globallint := LINTFLAGS += -erroff=E_NAME_MULTIPLY_DEF2

globallint:
	@-$(ECHO) "\nFULL KERNEL: global crosschecks:"
	@-$(LINT) $(LINTFLAGS) $(LINT_LIBS) 2>&1 | $(LGREP.2)

lint:	lintlib .WAIT modlintlib .WAIT $(INTEL_LINTS) $(LINT_DEPS) \
	$(IMPLEMENTATIONS)

$(INTEL_LINTS):	FRC
	@cd $(UTSBASE)/intel/$@; pwd; $(MAKE) modlintlib

include ../Makefile.targ

#
# Cross-reference customization: build a cross-reference over all of the
# i86pc-related directories.
#
SHARED_XRDIRS	= ../i86pc ../intel ../common
XRDIRS		= $(SHARED_XRDIRS)
$(CLOSED_BUILD)XRDIRS	= $(SHARED_XRDIRS:../%=../% ../../../closed/uts/%)
XRPRUNE	= sun4u sun4

cscope.out tags: FRC
	$(XREF) -x $@

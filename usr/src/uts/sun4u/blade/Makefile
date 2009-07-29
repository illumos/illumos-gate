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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#	This makefile drives the production of the sun4u JBOS - blade platform
#	module.
#
#	sun4u jbos-blade implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

include $(UTSBASE)/sun4u/blade/Makefile.blade

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

IMPLEMENTED_PLATFORM	= SUNW,Serverblade1
LINK1DESTDIR	=	../../../../SUNW,Sun-Blade-100/kernel/drv/sparcv9
BLADE_LINK_1	=	SUNW,Serverblade1/kernel/drv/sparcv9/pmubus
BLADE_PLAT_LINK1 =	$(BLADE_LINK_1:%=$(ROOT_PLAT_DIR)/%)

#
#	Default build targets.
#
.KEEP_STATE:

.PARALLEL:	$(BLADE_KMODS) $(CLOSED_BLADE_KMODS)

def all clean clobber clean.lint modlist: $(BLADE_KMODS) $(CLOSED_BLADE_KMODS)

install:	$(ROOT_BLADE_DIR) \
		$(USR_BLADE_DIR) \
		$(USR_BLADE_INC_DIR) \
		$(USR_BLADE_SBIN_DIR) \
		$(USR_BLADE_LIB_DIR) \
		.WAIT $(BLADE_KMODS) $(CLOSED_BLADE_KMODS) \
		$(BLADE_OPTION) \
		$(BLADE_PLAT_LINK_1)

modlintlib:	$(BLADE_KMODS) $(CLOSED_BLADE_KMODS)

$(BLADE_KMODS):	FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

$(CLOSED_BLADE_KMODS):	FRC
	cd $(CLOSED)/uts/sun4u/blade/$@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

$(BLADE_OPTION):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

install_h check:

lint:	modlintlib .WAIT $(LINT_DEPS)

LINT_LIBS	= $(LINT_LIB) \
			-L$(BLADE_LINT_LIB_DIR) \
			-L$(LINT_LIB_DIR) $(LINT_KMODS:%=-l%) \
			    $(CLOSED_LINT_KMODS:%=-l%) \
			-L$(SPARC_LIB_DIR) $(SPARC_LINTS:%=-l%)

lint.platmod:   modlintlib
	@-$(ECHO) "\nJBOS-blade Platform-dependent module: global crosschecks:"
	@-$(LINT) $(LINTFLAGS) $(LINT_LIBS) 2>&1 | $(LGREP.2)


$(BLADE_PLAT_LINK_1): $(ROOT_BLADE_DRV_DIR)
	$(RM) $@; $(SYMLINK) $(LINK1DESTDIR)/$(@F) $@
#
#	Include common targets.
#
include $(UTSBASE)/sun4u/blade/Makefile.targ

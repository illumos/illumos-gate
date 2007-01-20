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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# uts/intel/ipf/Makefile
#
#	This makefile drives the production of the ipf driver 
#	kernel module.
#
#	intel architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= ipf
OBJECTS		= $(IPF_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(IPF_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(USR_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/common/inet/ipf

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(SRC_CONFFILE)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

MINOR=	    echo $(RELEASE) | cut -d. -f2
CPPFLAGS += -DIPFILTER_LKM -DIPFILTER_LOG -DIPFILTER_LOOKUP -DUSE_INET6
CPPFLAGS += -DSUNDDI -DSOLARIS2=$(MINOR:sh) -DIRE_ILL_CN
LDFLAGS += -dy -Ndrv/ip -Nmisc/md5 -Nmisc/neti

INC_PATH += -I$(UTSBASE)/common/inet/ipf

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
# Please do not carry these forward to new Makefiles.
#
LINTTAGS	+= -erroff=E_STATIC_UNUSED
LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS	+= -erroff=E_PTRDIFF_OVERFLOW
LINTTAGS	+= -erroff=E_ASSIGN_NARROW_CONV

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS)

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS)

sis_check:	sis_check.obj
sis_check.obj: $(ALL_DEPS)
	@$(GREP) -v '#' $(MODULE).objt-symbols.obj64 |$(GREP) . |$(SORT) -u \
	    > $(MODULE).symbols.tmp
	@$(NM) obj64/$(MODULE) |$(GREP) OBJT |$(GREP) -v UNDEF | \
	    $(CUT) -d'|' -f8 |$(SORT) -u > $(MODULE).symbols.tmp.new
	-@$(DIFF) $(MODULE).symbols.tmp $(MODULE).symbols.tmp.new

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ

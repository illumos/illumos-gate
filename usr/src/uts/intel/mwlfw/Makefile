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
#
#	This makefile drives the production of the mwlfw kernel module.
#
#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= mwlfw
OBJECTS		= $(MWLFW_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(MWLFW_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_MISC_DIR)/$(MODULE)

FWOBJ		= $(OBJS_DIR)/$(MODULE).o

OBJECTS		+= $(FWOBJ)

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

LDFLAGS	= 
#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
# Please do not carry these forward to new Makefiles.
#
LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS	+= -erroff=E_PTRDIFF_OVERFLOW
LINTTAGS	+= -erroff=E_ASSIGN_NARROW_CONV
LINTTAGS	+= -erroff=E_STATIC_UNUSED

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS) $(FWOBJ)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS)

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS)


# customized section for transforming firmware binary
ELFWRAP		= elfwrap
BINSRC		= $(UTSBASE)/common/io/mwl/mwl_fw
BINDEST		= $(UTSBASE)/intel/mwlfw
FWBINCOPY	= mw88W8363fw
BOOTBINCOPY	= mwlboot
ORIGIN_FWBIN	= mw88W8363
ORIGIN_BOOTBIN	= mwlboot

#get build type, 32/64
WRAPTYPE	= $(CLASS:%=-%)

#set elfwrap option
WRAPOPT		= $(WRAPTYPE:-32=)

$(FWOBJ):
	cp $(BINSRC)/$(ORIGIN_FWBIN) $(BINDEST)/$(FWBINCOPY)
	cp $(BINSRC)/$(ORIGIN_BOOTBIN) $(BINDEST)/$(BOOTBINCOPY)
	$(ELFWRAP) $(WRAPOPT) -o $@ $(BINDEST)/$(FWBINCOPY) $(BINDEST)/$(BOOTBINCOPY)

CLOBBERFILES	+= $(BINDEST)/$(FWBINCOPY)
CLOBBERFILES	+= $(BINDEST)/$(BOOTBINCOPY)

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ


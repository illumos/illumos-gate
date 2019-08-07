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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE = ../..

#
#       Define the module and object file sets.
#
MODULE		= mc-amd
#
OBJECTS		= $(MCAMD_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(MCAMD_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
SRCDIR		= $(UTSBASE)/intel/io/mc-amd
CONF_SRCDIR	= $(SRCDIR)

MCAMD_OFF_H	= $(OBJS_DIR)/mcamd_off.h
MCAMD_OFF_SRC	= $(SRCDIR)/mcamd_off.in

#
#	Include common rules.
#
include ../Makefile.intel


#
#       Define targets
#
ALL_TARGET      = $(BINARY)
LINT_TARGET     = $(MODULE).lint
INSTALL_TARGET  = $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

#
#	Overrides and additions
#
CPPFLAGS	+= -I$(SRCDIR) -I$(OBJS_DIR) -I$(SRC)/common/mc/mc-amd
CPPFLAGS	+= -I$(SRC)/common/util
CLEANFILES	+= $(MCAMD_OFF_H)
CLOBBERFILES	+= $(MCAMD_OFF_H)

CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= $(CNOWARN_UNINIT)

#
#       Default build targets.
#
.KEEP_STATE:

def:            $(DEF_DEPS)

all:            $(ALL_DEPS)

clean:          $(CLEAN_DEPS)

clobber:        $(CLOBBER_DEPS)

lint:           $(LINT_DEPS)

modlintlib:     $(MODLINTLIB_DEPS)

clean.lint:     $(CLEAN_LINT_DEPS)

install:        $(INSTALL_DEPS)

$(OBJECTS): $(OBJS_DIR) $(MCAMD_OFF_H)
$(LINTS): $(MCAMD_OFF_H)

#
# Create mcamd_off.h
#
$(MCAMD_OFF_H): $(MCAMD_OFF_SRC)
	$(OFFSETS_CREATE) <$(MCAMD_OFF_SRC) >$@

#
#       Include common targets.
#
include ../Makefile.targ

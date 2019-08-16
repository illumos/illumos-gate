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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
#	This makefile drives the production of the drmach loadable module.
#
#	sun4u opl implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../../..

#
#	Define the module and object file sets.
#
MODULE		= drmach 
OBJECTS		= $(DRMACH_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(DRMACH_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_OPL_MISC_DIR)/$(MODULE)

DRMACH_OFFSETS  = $(UTSBASE)/sun4u/opl/ml/drmach_offsets.in
DRMACH_OFFSETS_H        = $(OBJS_DIR)/drmach_offsets.h

#
#	Include common rules.
#
include $(UTSBASE)/sun4u/opl/Makefile.opl

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

CLEANFILES      += $(DRMACH_OFFSETS_H) $(DRMACH_OFFSETS_OUT)

#
# lint pass one enforcement
#
CFLAGS += $(CCVERBOSE)
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-unused-function
CERRWARN += $(CNOWARN_UNINIT)

#
# module dependencies
#
LDFLAGS += -dy -Nmisc/opl_cfg

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

AS_INC_PATH     += -I$(OBJS_DIR)

$(DRMACH_DEPS:%=$(OBJS_DIR)/%):    $(DRMACH_OFFSETS_H)

$(DRMACH_OFFSETS_H): $(GENCONST) $(DRMACH_OFFSETS)
	$(OFFSETS_CREATE) <$(DRMACH_OFFSETS) >$@
	$(GENCONST) >> $@

#
#	Include common targets.
#
include $(UTSBASE)/sun4u/opl/Makefile.targ

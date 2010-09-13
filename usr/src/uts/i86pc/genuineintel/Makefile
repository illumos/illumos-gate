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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE = ../..

#
#       Define the module and object file sets.
#
MODULE		= cpu_ms.GenuineIntel
#
OBJECTS		= $(CPU_GENINTEL_OBJS:%=$(OBJS_DIR)/%)
LINTS           = $(CPU_GENINTEL_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE      = $(ROOT_PSM_CPU_DIR)/$(MODULE)

SRCDIR		= ../cpu/genuineintel

#
#       Include common rules.
#
include ../cpu/Makefile.cpu

#
#	Our lint library has a different name from that of the module we build.
#
LINT_MODULE	= genuineintel

#
#       Define targets
#
ALL_TARGET      = $(BINARY)
LINT_TARGET     = $(LINT_MODULE).lint
INSTALL_TARGET  = $(BINARY) $(ROOTMODULE)

#
#	Overrides and additions
#
CPPFLAGS	+= -I$(SRCDIR) -I$(OBJS_DIR)
ASFLAGS		+= -I$(SRCDIR) -I$(OBJS_DIR)
LDFLAGS		+= -dy -N misc/acpica

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

#
#       Include common targets.
#
include ../Makefile.targ

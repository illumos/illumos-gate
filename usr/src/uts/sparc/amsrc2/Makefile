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
# uts/sparc/amsrc2/Makefile
#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#	This makefile drives the production of the audio mixer
#	sample rate conversion routine #1 (amsrc2).
#
#ident	"%Z%%M%	%I%	%E% SMI"

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE = ../..

#
#	Define the module and object file sets.
#
MODULE		= amsrc2
OBJECTS		= $(AMSRC2_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(AMSRC2_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_MISC_DIR)/$(MODULE)
WARLOCK_OUT	= $(AMSRC2_OBJS:%.o=%.ll)
WARLOCK_OK	= $(MODULE).ok

#
#	Include common rules.
#
include $(UTSBASE)/sparc/Makefile.sparc

#
#	Turn off -xspace so we get all optimizations.
#
SPACEFLAG	=

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

#
#       Overrides
#
ALL_BUILDS	= $(ALL_BUILDSONLY64)
DEF_BUILDS	= $(DEF_BUILDSONLY64)
CLEANLINTFILES	+= $(LINT32_FILES)

# 
#	Overrides, lint pass one enforcement 
# 
CFLAGS		+= $(CCVERBOSE)

#
#	Depends on misc/amsrc2, misc/audiosup, and misc/mixer
#
LDFLAGS		+= -dy -Nmisc/audiosup -Nmisc/mixer

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)
		$(RM) $(WARLOCK_OUT) $(WARLOCK_OK) main.ll

clobber:	$(CLOBBER_DEPS)
		$(RM) $(WARLOCK_OUT) $(WARLOCK_OK) main.ll

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS) lint32

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS)

#
#	Include common targets.
#
include $(UTSBASE)/sparc/Makefile.targ

#
#	Defines for local commands.
#
WARLOCK		= warlock
WLCC		= wlcc
TOUCH		= touch
TEST		= test

#
#	Warlock rules
#

warlock:	main.ll $(WARLOCK_OK)

main.ll:	main.c
	$(WLCC) $(CPPFLAGS) -DDEBUG -o $@ main.c

$(WARLOCK_OK):	$(WARLOCK_OUT)
	$(WARLOCK) $(WARLOCK_OUT) -l main.ll
	$(TOUCH) $(WARLOCK_OK) 

%.ll:	$(UTSBASE)/common/io/audio/sada/amsrc2/%.c main.c
	$(WLCC) $(CPPFLAGS) -DDEBUG -o $@ $<

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
#ident	"%Z%%M%	%I%	%E% SMI"
#
#	This makefile drives the production of the sha2 crypto kernel module.
#
#	intel architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..
COMDIR	= $(COMMONBASE)/crypto/sha2

#
#	Define the module and object file sets.
#
MODULE		= sha2
LINTS		= $(SHA2_OBJS:%.o=$(LINTS_DIR)/%.ln)
SHA2_OBJS_32    =
SHA2_OBJS_64    = sha512-x86_64.o sha256-x86_64.o
SHA2_OBJS       += $(SHA2_OBJS_$(CLASS))
OBJECTS		= $(SHA2_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_CRYPTO_DIR)/$(MODULE)
ROOTLINK	= $(ROOT_MISC_DIR)/$(MODULE)

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
#	Override defaults
#
CLEANFILES += sha512-x86_64.s sha256-x86_64.s

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOTLINK)

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
# Please do not carry these forward to new Makefiles.
#
LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS	+= -erroff=E_SUPPRESSION_DIRECTIVE_UNUSED
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

$(ROOTLINK):	$(ROOT_MISC_DIR) $(ROOTMODULE)
	-$(RM) $@; ln $(ROOTMODULE) $@

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ

$(OBJS_DIR)/%.o: %.s
	$(COMPILE.s) -o $@ ${@F:.o=.s}
	$(POST_PROCESS_O)

$(OBJS_DIR)/%.ln: %.s
	@($(LHEAD) $(LINT.c) ${@F:.ln=.s} $(LTAIL))

sha512-x86_64.s: $(COMDIR)/amd64/sha512-x86_64.pl
	$(PERL) $? $@

sha256-x86_64.s: $(COMDIR)/amd64/sha512-x86_64.pl
	$(PERL) $? $@

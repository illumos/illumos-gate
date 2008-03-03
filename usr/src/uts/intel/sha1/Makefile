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
# uts/intel/sha1/Makefile
#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
#	This makefile drives the production of the sha1 crypto kernel module.
#
#	intel architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..
COMDIR = $(COMMONBASE)/crypto/sha1

#
#	Define the module and object file sets.
#
MODULE		= sha1
LINTS		= $(SHA1_OBJS:%.o=$(LINTS_DIR)/%.ln)
SHA1_OBJS_32	=
SHA1_OBJS_64	= sha1-x86_64.o
SHA1_OBJS	+= $(SHA1_OBJS_$(CLASS))
OBJECTS		= $(SHA1_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_CRYPTO_DIR)/$(MODULE)
ROOTLINK	= $(ROOT_MISC_DIR)/$(MODULE)

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
#	Override defaults
#
CLEANFILES += sha1-x86_64.s

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
# Please do not carry these forward to new Makefiles.
#
LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS	+= -erroff=E_PTRDIFF_OVERFLOW


#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOTLINK)

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

$(OBJS_DIR)/sha1-x86_64.o: sha1-x86_64.s
	$(COMPILE.s) -o $@ ${@F:.o=.s}
	$(POST_PROCESS_O)
 
$(OBJS_DIR)/sha1-x86_64.ln: sha1-x86_64.s
	@($(LHEAD) $(LINT.c) ${@F:.ln=.s} $(LTAIL))

sha1-x86_64.s: $(COMDIR)/amd64/sha1-x86_64.pl
	$(PERL) $? $@

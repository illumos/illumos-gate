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
# uts/intel/elfexec/Makefile
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright 2016 Joyent, Inc.
#

#
#	This makefile drives the production of the elfexec exec kernel
#	module.
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
MODULE		= elfexec
ELFEXEC_OBJS_32	=
ELFEXEC_OBJS_64	= elf32.o elf32_notes.o old32_notes.o
ELFEXEC_OBJS	+= $(ELFEXEC_OBJS_$(CLASS))
OBJECTS		= $(ELFEXEC_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(ELFEXEC_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_EXEC_DIR)/$(MODULE)

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

INC_PATH	+= -I$(UTSBASE)/intel/ia32

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
# Please do not carry these forward to new Makefiles.
#
LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS	+= -erroff=E_PTRDIFF_OVERFLOW
LINTTAGS	+= -erroff=E_ASSIGN_NARROW_CONV

CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-uninitialized

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

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ

.NO_PARALLEL:	$(LINTS)

$(OBJS_DIR)/elf32.o:	$(UTSBASE)/common/exec/elf/elf.c
	$(COMPILE.c) -o $@ -D_ELF32_COMPAT $(UTSBASE)/common/exec/elf/elf.c

$(OBJS_DIR)/elf32_notes.o: $(UTSBASE)/common/exec/elf/elf_notes.c
	$(COMPILE.c) -o $@ -D_ELF32_COMPAT $(UTSBASE)/common/exec/elf/elf_notes.c

$(OBJS_DIR)/old32_notes.o: $(UTSBASE)/common/exec/elf/old_notes.c
	$(COMPILE.c) -o $@ -D_ELF32_COMPAT $(UTSBASE)/common/exec/elf/old_notes.c

$(LINTS_DIR)/elf32.ln:	$(UTSBASE)/common/exec/elf/elf.c
	@($(LHEAD) $(LINT.c) -Celf32 -D_ELF32_COMPAT $(UTSBASE)/common/exec/elf/elf.c $(LTAIL))
	@$(MV) $(@F) $@

$(LINTS_DIR)/elf32_notes.ln: $(UTSBASE)/common/exec/elf/elf_notes.c
	@($(LHEAD) $(LINT.c) -Celf32_notes -D_ELF32_COMPAT $(UTSBASE)/common/exec/elf/elf_notes.c $(LTAIL))
	@$(MV) $(@F) $@

$(LINTS_DIR)/old32_notes.ln: $(UTSBASE)/common/exec/elf/old_notes.c
	@($(LHEAD) $(LINT.c) -Cold32_notes -D_ELF32_COMPAT $(UTSBASE)/common/exec/elf/old_notes.c $(LTAIL))
	@$(MV) $(@F) $@

#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
#	kernel linker/loader makefile.
#
#	x86 architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= krtld
OBJECTS		= $(KRTLD_BOOT_OBJS:%=$(OBJS_DIR)/%) \
		  $(KRTLD_OBJS:%=$(OBJS_DIR)/%)

LINTS		= $(KRTLD_BOOT_OBJS:%.o=$(LINTS_DIR)/%.ln) \
		  $(KRTLD_OBJS:%.o=$(LINTS_DIR)/%.ln)
PICS		= $(KRTLD_BOOT_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_MISC_DIR)/$(MODULE)

INC_PATH_32	= -I$(UTSBASE)/common/krtld -I../ia32/krtld -I$(COMMONBASE)
INC_PATH_64	= -I$(UTSBASE)/common/krtld -I../amd64/krtld -I$(COMMONBASE)
INC_PATH	+= $(INC_PATH_$(CLASS))

MODSUFFIX_32	=
MODSUFFIX_64	= -DMODDIR_SUFFIX=\"amd64\"
MODSUFFIX	= $(MODSUFFIX_$(CLASS))

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

#
#	Overrides.
#
CFLAGS		+= -Wu,-no_got_reloc

KRTLD_CPPFLAGS_32	= -DELF_TARGET_386 -D_KRTLD
KRTLD_CPPFLAGS_64	= -DELF_TARGET_AMD64 -D_KRTLD
CPPFLAGS	+= $(KRTLD_CPPFLAGS_$(CLASS)) $(MODSUFFIX)

MAPFILE		= $(UTSBASE)/common/krtld/mapfile
LDFLAGS		= -e _kobj_boot -M$(MAPFILE) -Breduce -znoversion -zverbose

# krtld uses a mapfile during the link to hide some symbols, thus changing
# their scope from global to local.  This will fool ctfmerge (it won't record
# the changed symbols) unless we tell it to use fuzzy matching.
CTFMRGFLAGS	= -f

PIC_CFLAGS_32	= -K pic
PIC_CFLAGS_64	= -K pic -_gcc=-mcmodel=small
$(PICS)		:= CFLAGS += $(PIC_CFLAGS_$(CLASS))

#
# krtld has its own private copies of these functions and objects
#
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dstrcmp=$(MODULE)_strcmp
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dstrncmp=$(MODULE)_strncmp
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dstrlen=$(MODULE)_strlen
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dstrcpy=$(MODULE)_strcpy
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dstrncpy=$(MODULE)_strncpy
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dstrcat=$(MODULE)_strcat
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dstrchr=$(MODULE)_strchr
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dbzero=$(MODULE)_bzero
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dbcopy=$(MODULE)_bcopy

#
# krtld has variant targets, depending on what the kernel instruction
# set actually is
#
MAKEFILE_RULES_32	= $(UTSBASE)/intel/ia32/Makefile.rules
MAKEFILE_RULES_64	= $(UTSBASE)/intel/amd64/Makefile.rules
include	$(MAKEFILE_RULES_$(CLASS))

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

$(BINARY):	$(MAPFILE)

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ

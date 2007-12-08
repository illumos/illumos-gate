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
# ident	"%Z%%M%	%I%	%E% SMI"
#
#	kernel linker/loader makefile.
#
#	sparc architecture dependent
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

INC_PATH	+= -I$(UTSBASE)/common/krtld -I. -I$(COMMONBASE)

MODSUFFIX_32	=
MODSUFFIX_64	= -DMODDIR_SUFFIX=\"sparcv9\"
MODSUFFIX	= $(MODSUFFIX_$(CLASS))

#
#	Include common rules.
#
include $(UTSBASE)/sparc/Makefile.sparc

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

#
#	Overrides.
#
# For now, Sparc uses its own mapfile.  This will be corrected
# when portions of new boot architecture are made common.
# Our apologies for now.
#
CFLAGS		+= $(CCVERBOSE)
CPPFLAGS	+= -DELF_TARGET_SPARC -D_KRTLD $(MODSUFFIX)
MAPFILE		= $(UTSBASE)/sparc/krtld/mapfile
LDFLAGS		= -e _kobj_boot -M$(MAPFILE) $(BREDUCE) $(ZNOVERSION)

# krtld uses a mapfile during the link to hide some symbols, thus changing
# their scope from global to local.  This will fool ctfmerge (it won't record
# the changed symbols) unless we tell it to use fuzzy matching.
CTFMRGFLAGS	= -f

$(PICS)		:= CFLAGS += -K pic -_gcc=-fno-constant-pools \
		-_gcc=-fno-jump-tables

#
# krtld has its own private copies of these functions and objects
#
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dstrcmp=$(MODULE)_strcmp
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dstrncmp=$(MODULE)_strncmp
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dstrlen=$(MODULE)_strlen
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dstrcpy=$(MODULE)_strcpy
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dstrncpy=$(MODULE)_strncpy
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dstrcat=$(MODULE)_strcat
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dstrlcat=$(MODULE)_strlcat
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dstrchr=$(MODULE)_strchr
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dbzero=$(MODULE)_bzero
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dbcopy=$(MODULE)_bcopy
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dbop_getversion=$(MODULE)_bop_getversion
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dbop_open=$(MODULE)_bop_open
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dbop_read=$(MODULE)_bop_read
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dbop_seek=$(MODULE)_bop_seek
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dbop_close=$(MODULE)_bop_close
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dbop_alloc=$(MODULE)_bop_alloc
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dbop_alloc_virt=$(MODULE)_bop_alloc_virt
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dbop_free=$(MODULE)_bop_free
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dbop_map=$(MODULE)_bop_map
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dbop_unmap=$(MODULE)_bop_unmap
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dbop_quiesce_io=$(MODULE)_bop_quiesce_io
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dbop_getproplen=$(MODULE)_bop_getproplen
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dbop_getprop=$(MODULE)_bop_getprop
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dbop_nextprop=$(MODULE)_bop_nextprop
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dbop_puts=$(MODULE)_bop_puts
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dbop_putsarg=$(MODULE)_bop_putsarg
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dbop_mountroot=$(MODULE)_bop_mountroot
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dbop_unmountroot=$(MODULE)_bop_unmountroot
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dbop_serviceavail=$(MODULE)_bop_serviceavail
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dbop_fstat=$(MODULE)_bop_fstat
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dbop_interpret=$(MODULE)_bop_interpret
$(OBJECTS) $(LINTS)	:= CPPFLAGS += -Dbop_enter_mon=$(MODULE)_bop_enter_mon

#
#	MPSAS defines
#
$(MPSAS_BUILD)CFLAGS	+= -DMPSAS

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
# Please do not carry these forward to new Makefiles.
#
LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS	+= -erroff=E_PTRDIFF_OVERFLOW
LINTTAGS	+= -erroff=E_ASSIGN_NARROW_CONV
LINTTAGS	+= -erroff=E_STATIC_UNUSED
LINTTAGS	+= -erroff=E_SUPPRESSION_DIRECTIVE_UNUSED

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
include $(UTSBASE)/sparc/Makefile.targ

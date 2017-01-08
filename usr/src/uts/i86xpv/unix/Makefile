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
#	This makefile drives the production of unix (and unix.o).
#
#	i86xpv implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
UNIX		= unix
DBOOT		= dboot

OBJECTS		= $(SPECIAL_OBJS:%=$(OBJS_DIR)/%) \
		  $(CORE_OBJS:%=$(OBJS_DIR)/%) \
		  $(KRTLD_OBJS:%=$(OBJS_DIR)/%) \
		  $(MACH_NOT_YET_KMODS:%=$(OBJS_DIR)/%)

LINTS		= $(SPECIAL_OBJS:%.o=$(LINTS_DIR)/%.ln) \
		  $(CORE_OBJS:%.o=$(LINTS_DIR)/%.ln) \
		  $(KRTLD_OBJS:%.o=$(LINTS_DIR)/%.ln) \
		  $(MACH_NOT_YET_KMODS:%.o=$(LINTS_DIR)/%.ln) \
		  $(LINTS_DIR)/vers.ln \
		  $(LINTS_DIR)/modstubs.ln

ROOTMODULE	= $(ROOT_PSM_KERN_DIR)/$(UNIX)

UNIX_BIN	= $(OBJS_DIR)/$(UNIX)

LIBS		= $(GENLIB)

GENUNIX		= genunix
GENUNIX_DIR	= ../../intel/$(GENUNIX)

LIBOPTS		= -L $(GENUNIX_DIR)/$(OBJS_DIR) -l $(GENUNIX)

CTFEXTRAOBJS	= $(OBJS_DIR)/vers.o

DBOOT_OBJS_DIR	= dboot/$(OBJS_DIR)
DBOOT_OBJECTS	= $(DBOOT_OBJS:%=$(DBOOT_OBJS_DIR)/%)
DBOOT_BIN	= $(DBOOT_OBJS_DIR)/$(DBOOT)
DBOOT_O		= $(OBJS_DIR)/$(DBOOT).o
DBOOT_S		= $(DBOOT_O:%.o=%.s)
DBOOT_LINTS	= $(DBOOT_OBJS:%.o=$(DBOOT_OBJS_DIR)/%.ln)
DBOOT_LINT	= $(LINT_$(MACH)_$(CLASS))

#
#	Include common rules.
#
include $(UTSBASE)/i86xpv/Makefile.i86xpv

#
#	Define targets
#
ALL_TARGET	= $(UNIX_BIN)
LINT_TARGET	= $(LINT_LIB) $(DBOOT_LINT_LIB)
INSTALL_TARGET	= $(UNIX_BIN) $(ROOTMODULE)

#
#	This is UNIX_DIR. Use a short path.
#
UNIX_DIR	= .

#
#	Overrides
#
CLEANFILES	+=		\
	$(UNIX_O) $(MODSTUBS_O)	\
	$(OBJS_DIR)/vers.c $(OBJS_DIR)/vers.o \
	$(OBJS_DIR)/dtracestubs.s \
	$(DTRACESTUBS_O) $(DTRACESTUBS)

CLEANFILES	+=		\
	$(DBOOT_O) $(DBOOT_S)	\
	$(DBOOT_OBJECTS)	\
	$(DBOOT_BIN)

CLEANFILES	+=		\
	$(DBOOT_OBJS_DIR)/$(VGATEXT_FONT).c \
	$(OBJS_DIR)/$(VGATEXT_FONT).c

CLEANFILES	+=		\
	$(OBJS_DIR)/fb_swtch_src.o \
	$(OBJS_DIR)/fb_swtch_src \
	$(OBJS_DIR)/fb_swtch.s

CLEANFILES	+= \
	$(ZLIB_OBJS:%.o=$(OBJS_DIR)/%.o) \
	$(ZLIB_OBJS:%.o=$(OBJS_DIR)/%.ln)

CLOBBERFILES	= $(CLEANFILES) $(UNIX_BIN)
CLEANLINTFILES	+= $(LINT_LIB) $(DBOOT_LINT_LIB) $(DBOOT_LINTS)

# instr_size needs a special header
$(OBJS_DIR)/instr_size.o :=	EXTRA_OPTIONS	= -I$(SRC)/common/dis/i386
$(OBJS_DIR)/instr_size.ln :=	EXTRA_OPTIONS	= -I$(SRC)/common/dis/i386

CFLAGS += -DDIS_MEM

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
# Please do not carry these forward to new Makefiles.
#
LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS	+= -erroff=E_SUSPICIOUS_COMPARISON
LINTTAGS	+= -erroff=E_SUPPRESSION_DIRECTIVE_UNUSED
LINTTAGS	+= -erroff=E_STATIC_UNUSED
LINTTAGS	+= -erroff=E_PTRDIFF_OVERFLOW
LINTTAGS	+= -erroff=E_ASSIGN_NARROW_CONV

CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-uninitialized
CERRWARN	+= -_gcc=-Wno-char-subscripts
CERRWARN	+= -_gcc=-Wno-unused-variable
CERRWARN	+= -_gcc=-Wno-unused-function
CERRWARN	+= -_gcc=-Wno-unused-label
CERRWARN	+= -_gcc=-Wno-type-limits
CERRWARN	+= -_gcc=-Wno-clobbered
CERRWARN	+= -_gcc=-Wno-unused-value
CERRWARN	+= -_gcc=-Wno-empty-body

# Ensure that lint sees 'struct cpu' containing a fully declared
# embedded 'struct machcpu'
#
LINTFLAGS	+= -D_MACHDEP -I../../i86pc

#
#	Default build targets.
#
.KEEP_STATE:

def: $(DEF_DEPS)

all: $(ALL_DEPS)

clean: $(CLEAN_DEPS)

clobber: $(CLOBBER_DEPS)

lint: $(LINT_DEPS)

clean.lint: $(CLEAN_LINT_DEPS)

install: $(INSTALL_DEPS)

MAPFILE_32 = $(MAPFILE)
MAPFILE_64 = $(MAPFILE).amd64

MAPFILE_NAME = $(MAPFILE_$(CLASS))

$(UNIX_BIN):	$(UNIX_O) $(MODSTUBS_O) $(MAPFILE_NAME) \
		$(GENLIB) $(DTRACESTUBS) $(DBOOT_O)
	$(LD) -dy -b -o $@ -e dboot_image -znointerp -M $(MAPFILE_NAME) \
	    $(UNIX_O) $(DBOOT_O) $(MODSTUBS_O) $(LIBOPTS) \
	    $(DTRACESTUBS)
	$(CTFMERGE_UNIQUIFY_AGAINST_GENUNIX)
	$(POST_PROCESS)

$(UNIX_O):	$(OBJECTS) $(OBJS_DIR)/vers.o
	$(LD) -r -o $@ $(OBJECTS) $(OBJS_DIR)/vers.o

$(DBOOT_BIN):	$(DBOOT_OBJS_DIR) $(DBOOT_OBJECTS) dboot/Mapfile.dboot
	$(LD) -dn -e _start -M dboot/Mapfile.dboot \
		-o $(DBOOT_BIN) $(DBOOT_OBJECTS)

$(DBOOT_O):	$(DBOOT_BIN)
	@echo "	.data"					> $(DBOOT_S)
	@echo "	.globl	dboot_image"			>> $(DBOOT_S)
	@echo "dboot_image:"				>> $(DBOOT_S)
	$(ELFEXTRACT) $(DBOOT_BIN)			>> $(DBOOT_S)
	$(COMPILE.s) -o $(DBOOT_O) $(DBOOT_S)

$(DBOOT_OBJS_DIR):
	-@mkdir -p $@ 2> /dev/null

#
#	Special rules for generating assym.h for inclusion in assembly files.
#
$(DSF_DIR)/$(OBJS_DIR)/assym.h $(DSF_DIR)/$(OBJS_DIR)/kdi_assym.h:	FRC
	@cd $(DSF_DIR); $(MAKE) all.targ

#
#	The global lint target builds the kernel lint library (llib-lunix.ln)
#	which is equivalent to a lint of /unix.o. Then all kernel modules for
#	this architecture are linted against the kernel lint library.
#
#	Note:	lint errors in the kernel lint library will be repeated for
#		each module. It is important that the kernel lint library
#		be clean to keep the textual output to a reasonable level.
#

$(LINT_LIB):	$(LINT_LIB_DIR) $(LINTS)
	@pwd
	@-$(ECHO) "\n$(UNIX): (library construction):"
	@$(LINT) -o$(UNIX) $(LINTFLAGS) $(LINTS)
	@$(MV) $(@F) $@

$(DBOOT_LINT_LIB):	$(LINT_LIB_DIR) $(DBOOT_LINTS)
	@pwd
	@-$(ECHO) "\n$(DBOOT): (library construction):"
	@$(LINT) -o$(DBOOT) $(DBOOT_LINTFLAGS) $(DBOOT_LINTS)
	@$(MV) $(@F) $@

lintlib:	$(LINT_DEPS)

#
#	Include common targets.
#
include $(UTSBASE)/i86xpv/Makefile.targ

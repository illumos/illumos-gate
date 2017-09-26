#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2013 Pluribus Networks Inc.
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= vmm
OBJECTS		= $(VMM_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(VMM_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(USR_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/i86pc/io/vmm

#
#	Include common rules.
#
include $(UTSBASE)/i86pc/Makefile.i86pc

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

#
#	Overrides and additions
#

# These sources only compile with gcc.  Workaround a confluence of cruft
# regarding dmake and shadow compilation by neutering the sun compiler.
amd64_CC	= $(ONBLD_TOOLS)/bin/$(MACH)/cw -_gcc
CFLAGS 		+= -_cc=-xdryrun

ALL_BUILDS	= $(ALL_BUILDSONLY64)
DEF_BUILDS	= $(DEF_BUILDSONLY64)
PRE_INC_PATH	= -I$(COMPAT)/freebsd -I$(COMPAT)/freebsd/amd64 \
	-I$(CONTRIB)/freebsd -I$(CONTRIB)/freebsd/amd64
INC_PATH	+= -I$(UTSBASE)/i86pc/io/vmm -I$(UTSBASE)/i86pc/io/vmm/io
AS_INC_PATH	+= -I$(UTSBASE)/i86pc/io/vmm -I$(OBJS_DIR)

CFLAGS		+= -_gcc=-Wimplicit-function-declaration

OFFSETS_SRC	= $(CONF_SRCDIR)/offsets.in
ASSYM_H		= $(OBJS_DIR)/vmx_assym.h

CLEANFILES	+= $(ASSYM_H)

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
include $(UTSBASE)/i86pc/Makefile.targ

$(OBJECTS): $(ASSYM_H)

$(ASSYM_H): $(OFFSETS_SRC) $(GENASSYM)
	$(OFFSETS_CREATE) -I../../i86pc/io/vmm < $(OFFSETS_SRC) >$@

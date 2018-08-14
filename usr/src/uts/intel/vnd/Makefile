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
# Copyright 2018 Joyent, Inc.
#

UTSBASE	= ../..

MODULE		= vnd
OBJECTS		= $(VND_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(VND_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)

include $(UTSBASE)/intel/Makefile.intel

LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN

ALL_TARGET	= $(BINARY) $(SRC_CONFILE)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)
CONF_SRCDIR	= $(UTSBASE)/common/io/vnd

CPPFLAGS	+= -I$(UTSBASE)/i86pc
LDFLAGS		+= -dy -Nmisc/neti -Nmisch/hook -Nfs/dev -Nmisc/gsqueue

#
# We use <sys/ctype.h> which causes gcc to think that all of its inline
# functions are defined and unused.
#
CERRWARN	+= -_gcc=-Wno-unused-function

.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS)

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS)

include $(UTSBASE)/intel/Makefile.targ

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
# Copyright (c) 2017 by Delphix. All rights reserved.
#

UTSBASE=	../..

MODULE=		hyperv
OBJECTS=	$(HV_HYPERV_OBJS:%=$(OBJS_DIR)/%)
LINTS=		$(HV_HYPERV_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE=	$(ROOT_MISC_DIR)/$(MODULE)

include		$(UTSBASE)/intel/Makefile.intel

ALL_TARGET=	$(BINARY)
LINT_TARGET=	$(MODULE).lint
INSTALL_TARGET=	$(BINARY) $(ROOTMODULE)

INC_PATH +=	-I$(UTSBASE)/intel/io/hyperv
LDFLAGS	+=	-dy

LINTTAGS +=	-erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS +=	-erroff=E_CONSTANT_CONDITION
LINTTAGS +=	-erroff=E_STATIC_UNUSED
LINTTAGS +=	-erroff=E_FUNC_SET_NOT_USED

.KEEP_STATE:

all:		$(ALL_DEPS)

clean.lint:	$(CLEAN_LINT_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

def:		$(DEF_DEPS)

install:	$(INSTALL_DEPS)

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS)

include		$(UTSBASE)/intel/Makefile.targ

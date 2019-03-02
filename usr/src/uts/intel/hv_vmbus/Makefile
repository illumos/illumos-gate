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

MODULE=		hv_vmbus
OBJECTS=	$(HV_VMBUS_OBJS:%=$(OBJS_DIR)/%)
LINTS=		$(HV_VMBUS_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE=	$(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR=	$(UTSBASE)/intel/io/hyperv/vmbus

include		$(UTSBASE)/intel/Makefile.intel

ALL_TARGET=	$(BINARY) $(CONFMOD)
LINT_TARGET=	$(MODULE).lint
INSTALL_TARGET=	$(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

INC_PATH +=	-I$(UTSBASE)/intel/io/hyperv
INC_PATH +=	-I$(UTSBASE)/i86pc
CPPFLAGS +=	-D_MACHDEP
LDFLAGS	+=	-dy -N misc/hyperv

C99MODE=	-xc99=%all
C99LMODE=	-Xc99=%all

LINTTAGS +=	-erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS +=	-erroff=E_CONSTANT_CONDITION
LINTTAGS +=	-erroff=E_STATIC_UNUSED
LINTTAGS +=	-erroff=E_ASSIGN_NARROW_CONV

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

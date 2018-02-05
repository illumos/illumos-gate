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

UTSBASE=	$(SRC)/uts

MODULE=		rtls
OBJECTS=	$(PV_RTLS_OBJS:%=$(OBJS_DIR)/%)
LINTS=		$(PV_RTLS_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE=	$(ROOT_HVM_DRV_DIR)/$(MODULE)

include		$(UTSBASE)/i86pc/i86hvm/Makefile.i86hvm

LINT_MODULE=	pv_rtls

ALL_TARGET=	$(BINARY)
LINT_TARGET=	$(LINT_MODULE).lint
INSTALL_TARGET=	$(BINARY) $(ROOTMODULE)

LDFLAGS +=	-dy

.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS)

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS)

include		$(UTSBASE)/i86pc/i86hvm/Makefile.targ

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
# Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
#
#	This makefile drives the production of the kernel component of
#	the N-1 Solaris brand
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE =	../..
SN1_BASE =	$(UTSBASE)/common/brand/sn1

#
#	Define the module and object file sets.
#
MODULE =	sn1_brand
OBJECTS =	$(SN1_BRAND_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE =	$(ROOT_PSM_BRAND_DIR)/$(MODULE)

#
#	Include common rules.
#
include $(UTSBASE)/sun4u/Makefile.sun4u

#
#	Define targets
#
ALL_TARGET =		$(BINARY)
INSTALL_TARGET =	$(BINARY) $(ROOTMODULE)

#
#	Update compiler variables.
#
INC_PATH +=	-I$(SN1_BASE) -I$(OBJS_DIR)
LDFLAGS +=	-dy -Nexec/elfexec

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS)

#
#	Include common targets.
#
include $(UTSBASE)/sun4u/Makefile.targ

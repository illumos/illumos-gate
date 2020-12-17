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
# uts/sun4u/fd/Makefile
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
#	This makefile drives the production of the fd driver kernel module.
#
#	sun4u implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= fd
OBJECTS		= $(FD_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_PSM_DRV_DIR)/$(MODULE)

ASSYM_H		= $(OBJS_DIR)/fd_assym.h
FDOFF_C		= $(OBJS_DIR)/fdoffsets.c
FDOFF_S		= $(OBJS_DIR)/fdoffsets.s
FDOFF_TMP	= $(OBJS_DIR)/fdoffsets.tmp

#
#	Include common rules.
#
include $(UTSBASE)/sun4u/Makefile.sun4u

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

#
# Overrides
#
MODSTUBS_DIR	= $(OBJS_DIR)
$(MODSTUBS_O)	:= AS_CPPFLAGS += -DFD_MODULE
$(OBJS_DIR)/fd_asm.o := AS_CPPFLAGS += -I$(OBJS_DIR)
CLEANFILES      += $(MODSTUBS_O) $(ASSYM_H) \
		   $(FDOFF_C) $(FDOFF_S) $(FDOFF_TMP)

#
# For now, disable these warnings; maintainers should endeavor
# to investigate and remove these for maximum coverage.
# Please do not carry these forward to new Makefiles.
#
CFLAGS		+= $(CCVERBOSE)
CERRWARN	+= $(CNOWARN_UNINIT)
CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-char-subscripts

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS)

$(BINARY):      $(ASSYM_H)

#
#	Include common targets.
#
include $(UTSBASE)/sun4u/Makefile.targ

#
#       Assym targets
#
$(ASSYM_H): $(FDOFFSETS)
	$(OFFSETS_CREATE) <$(FDOFFSETS) >$@

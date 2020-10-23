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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE = ../..

#
#       Define the module and object file sets.
#
MODULE		= cpu_ms.AuthenticAMD
#
OBJECTS		= $(CPU_AUTHAMD_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE      = $(ROOT_PSM_CPU_DIR)/$(MODULE)

SRCDIR		= ../cpu/authenticamd

#
#       Include common rules.
#
include $(UTSBASE)/i86xpv/Makefile.i86xpv
include $(UTSBASE)/i86pc/cpu/Makefile.files

#
#       Define targets
#
ALL_TARGET      = $(BINARY)
INSTALL_TARGET  = $(BINARY) $(ROOTMODULE)

#
#	Overrides and additions
#
CPPFLAGS	+= -I$(SRCDIR) -I$(OBJS_DIR)
ASFLAGS		+= -I$(SRCDIR) -I$(OBJS_DIR)
LDFLAGS		+= -dy -N misc/acpica

#
#       Default build targets.
#
.KEEP_STATE:

def:            $(DEF_DEPS)

all:            $(ALL_DEPS)

clean:          $(CLEAN_DEPS)

clobber:        $(CLOBBER_DEPS)

install:        $(INSTALL_DEPS)

#
#       Include common targets.
#
include ../Makefile.targ

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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2016 Joyent, Inc.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE = ../..

#
#       Define the module and object file sets.
#
MODULE		= cpu_ms.AuthenticAMD.15
#
OBJECTS		= $(CPU_AO_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE      = $(ROOT_PSM_CPU_DIR)/$(MODULE)

SRCDIR		= ../cpu/amd_opteron

AO_MCA_DISP_C	= $(OBJS_DIR)/ao_mca_disp.c
AO_MCA_DISP_SRC = $(SRCDIR)/ao_mca_disp.in
AO_GENDISP	= ../cpu/scripts/ao_gendisp

#
#       Include common rules.
#
include ../cpu/Makefile.cpu

#
#       Define targets
#
ALL_TARGET      = $(BINARY)
INSTALL_TARGET  = $(BINARY) $(ROOTMODULE)

#
#	Overrides and additions
#
$(OBJS_DIR)/ao_mca.o :=	CERRWARN	+= -_gcc=-Wno-unused-function
CLEANFILES	+= $(AO_MCA_DISP_C)
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
# Create ao_mca_disp.c
#
$(AO_MCA_DISP_C): $(AO_MCA_DISP_SRC) $(AO_GENDISP)
	$(AO_GENDISP) $(AO_MCA_DISP_SRC) >$@

$(OBJS_DIR)/%.o:		$(OBJS_DIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(CTFCONVERT_O)

#
#       Include common targets.
#
include ../Makefile.targ

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
# uts/i86pc/isa/Makefile
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#
#	This makefile drives the production of the ISA nexus driver
#
#	i86pc implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= isa
OBJECTS		= $(ISANEXUS_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_PSM_DRV_DIR)/$(MODULE)
INC_PATH        += -I$(UTSBASE)/i86pc/sys/acpi

#
#	Include common rules.
#
include $(UTSBASE)/i86pc/Makefile.i86pc

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

$(OBJS_DIR)/isa.o :=	CERRWARN	+= -_gcc=-Wno-unused-function

# needs work
$(OBJS_DIR)/i8237A.o := SMOFF += indenting

CFLAGS += $(CCVERBOSE)

#
#       Dependency
LDFLAGS         += -dy -Nmisc/acpica -Nmisc/busra -Nmisc/pci_autoconfig

#
# Define our version of dma_engine and i8237A interfaces
#
$(OBJECTS) := CPPFLAGS += -Di_dmae_init=$(MODULE)_i_dmae_init
$(OBJECTS) := CPPFLAGS += -Di_dmae_acquire=$(MODULE)_i_dmae_acquire
$(OBJECTS) := CPPFLAGS += -Di_dmae_free=$(MODULE)_i_dmae_free
$(OBJECTS) := CPPFLAGS += -Di_dmae_get_best_mode=$(MODULE)_i_dmae_get_best_mode
$(OBJECTS) := CPPFLAGS += -D_dmae_nxcookie=$(MODULE)__dmae_nxcookie
$(OBJECTS) := CPPFLAGS += -Di_dmae_prog=$(MODULE)_i_dmae_prog
$(OBJECTS) := CPPFLAGS += -Di_dmae_swsetup=$(MODULE)_i_dmae_swsetup
$(OBJECTS) := CPPFLAGS += -Di_dmae_swsetup=$(MODULE)_i_dmae_swsetup
$(OBJECTS) := CPPFLAGS += -Di_dmae_swstart=$(MODULE)_i_dmae_swstart
$(OBJECTS) := CPPFLAGS += -Di_dmae_stop=$(MODULE)_i_dmae_stop
$(OBJECTS) := CPPFLAGS += -Di_dmae_enable=$(MODULE)_i_dmae_enable
$(OBJECTS) := CPPFLAGS += -Di_dmae_disable=$(MODULE)_i_dmae_disable
$(OBJECTS) := CPPFLAGS += -Di_dmae_get_chan_stat=$(MODULE)_i_dmae_get_chan_stat
$(OBJECTS) := CPPFLAGS += -Dd37A_init=$(MODULE)_d37A_init
$(OBJECTS) := CPPFLAGS += -Dd37A_dma_valid=$(MODULE)_d37A_dma_valid
$(OBJECTS) := CPPFLAGS += -Dd37A_dma_release=$(MODULE)_d37A_dma_release
$(OBJECTS) := CPPFLAGS += -Dd37A_dma_disable=$(MODULE)_d37A_dma_disable
$(OBJECTS) := CPPFLAGS += -Dd37A_dma_enable=$(MODULE)_d37A_dma_enable
$(OBJECTS) := CPPFLAGS += -Dd37A_get_best_mode=$(MODULE)_d37A_get_best_mode
$(OBJECTS) := CPPFLAGS += -Dd37A_intr=$(MODULE)_d37A_intr
$(OBJECTS) := CPPFLAGS += -DdEISA_setchain=$(MODULE)_dEISA_setchain
$(OBJECTS) := CPPFLAGS += -Dd37A_prog_chan=$(MODULE)_d37A_prog_chan
$(OBJECTS) := CPPFLAGS += -Dd37A_dma_swsetup=$(MODULE)_d37A_dma_swsetup
$(OBJECTS) := CPPFLAGS += -Dd37A_dma_swstart=$(MODULE)_d37A_dma_swstart
$(OBJECTS) := CPPFLAGS += -Dd37A_dma_stop=$(MODULE)_d37A_dma_stop
$(OBJECTS) := CPPFLAGS += -Dd37A_get_chan_stat=$(MODULE)_d37A_get_chan_stat
$(OBJECTS) := CPPFLAGS += -Dd37A_set_mode=$(MODULE)_d37A_set_mode
$(OBJECTS) := CPPFLAGS += -Dd37A_write_addr=$(MODULE)_d37A_write_addr
$(OBJECTS) := CPPFLAGS += -Dd37A_read_addr=$(MODULE)_d37A_read_addr
$(OBJECTS) := CPPFLAGS += -Dd37A_write_count=$(MODULE)_d37A_write_count
$(OBJECTS) := CPPFLAGS += -Dd37A_read_count=$(MODULE)_d37A_read_count

#
# For now, disable these checks; maintainers should endeavor
# to investigate and remove these for maximum coverage.
# Please do not carry these forward to new Makefiles.
#
CERRWARN	+= -_gcc=-Wno-unused-variable

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
include $(UTSBASE)/i86pc/Makefile.targ

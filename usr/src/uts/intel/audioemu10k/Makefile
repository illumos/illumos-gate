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
# uts/intel/audioemu10k/Makefile
#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#	This makefile drives the production of the audioemu10k driver.
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE = ../..

#
#	Define the module and object file sets.
#
MODULE		= audioemu10k
OBJECTS		= $(AUDIOEMU10K_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(AUDIOEMU10K_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
DSP_SRCDIR	= $(UTSBASE)/common/io/audio/drv/audioemu10k/dsp
DSP_HNAMES	= emu10k_gpr.h emu10k1_dsp.h emu10k2_dsp.h
DSP_HDRS	= $(DSP_HNAMES:%=$(OBJS_DIR)/%)
DSP_SNAMES	= emu10k.dsp emu10k1.mac emu10k2.mac
DSP_SRCS	= $(DSP_SNAMES:%=$(DSP_SRCDIR)/%)
ASM10K		= $(OBJS_DIR)/asm10k

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

LDFLAGS		+= -dy -Ndrv/audio -Nmisc/ac97

CERRWARN	+= -_gcc=-Wno-uninitialized

$(OBJS_DIR)/%.o			:= CPPFLAGS += -I$(OBJS_DIR)
$(OBJS_DIR)/%.ln		:= CPPFLAGS += -I$(OBJS_DIR)
$(OBJS_DIR)/emu10k_gpr.h	:= ASM10KFLAGS = -v -0 -P gpr
$(OBJS_DIR)/emu10k1_dsp.h	:= ASM10KFLAGS = -v -1 -P emu10k1
$(OBJS_DIR)/emu10k2_dsp.h	:= MODEL10K = SBLIVE
$(OBJS_DIR)/emu10k2_dsp.h	:= ASM10KFLAGS = -v -2 -P emu10k2
$(OBJS_DIR)/emu10k2_dsp.h	:= MODEL10K = AUDIGY

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

$(BINARY):	$(OBJS_DIR)/asm10k $(DSP_HDRS)

$(ASM10K):	$(DSP_SRCDIR)/asm10k.c
	$(NATIVECC) $(NATIVE_CFLAGS) -o $@ $(DSP_SRCDIR)/asm10k.c

$(DSP_HDRS): $(ASM10K) $(DSP_SRCS)
	$(CPP) -D$(MODEL10K) -I$(DSP_SRCDIR) $(DSP_SRCDIR)/emu10k.dsp | \
	$(OBJS_DIR)/asm10k $(ASM10KFLAGS) -h $@

CLOBBERFILES += $(ASM10K) $(DSP_HDRS)

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ

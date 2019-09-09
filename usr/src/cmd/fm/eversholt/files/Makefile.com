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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

.SUFFIXES: .eft .esc

ESC=$(SRC)/cmd/fm/eversholt/esc/$(MACH)/esc

include $(SRC)/cmd/Makefile.cmd

ROOT_EFT_ROOT=	$(ROOT)/usr/lib/fm/eft
ROOT_COMMON_EFT_FILES= $(EFT_COMMON_FILES:%=$(ROOT_EFT_ROOT)/%)
USR_PLAT_FM_DIR= $(ROOT)/usr/platform/$(EFT_PLAT)/lib/fm
USR_PLAT_EFT_DIR= $(USR_PLAT_FM_DIR)/eft
USR_PLAT_EFT_FILES= $(EFT_PLAT_FILES:%=$(USR_PLAT_EFT_DIR)/%)

#
# Override the built-in ESC pre-processor with a reference to the one we
# have set in Makefile.master. This ensures that we use the same cpp
# throughout the build.
#
ESC_ENV=_ESC_CPP=$(CPP)

#
# Default target - specify before including Makefile.rootdirs which would
# otherwise provide a default
#
install: all

include $(SRC)/cmd/fm/eversholt/Makefile.rootdirs

all:= FILEMODE =	0444

all: $(ROOT_EFT_ROOT) $(USR_PLAT_EFT_FILES) $(ROOT_COMMON_EFT_FILES)

install_h lint _msg:

clean clobber:
	$(RM) $(EFT_PLAT_FILES) $(EFT_COMMON_FILES) \
	$(USR_PLAT_EFT_FILES) $(ROOT_COMMON_EFT_FILES)

ESCFLAGS= -D_ESC -I$(ROOT)/usr/include
pciexrc.eft := ESCFLAGS += -I$(SRC)/uts/sun4v/io/px

%.eft: ../common/%.esc
	$(ESC_ENV) $(ESC) $(ESCFLAGS) -o $@ $<

%.eft: %.esc
	$(ESC_ENV) $(ESC) $(ESCFLAGS) -o $@ $<

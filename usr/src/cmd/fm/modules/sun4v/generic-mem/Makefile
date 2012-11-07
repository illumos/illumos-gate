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

CLASS = arch
ARCH = sun4v
MODULE = generic-mem
GENERIC_MEM = ../../sun4v/$(MODULE)

SRCS = \
	gmem_main.c \
	gmem_mem.c \
	gmem_dimm.c \
	gmem_memerr.c \
	gmem_page.c \
	gmem_state.c \
	gmem_fmri.c \
	gmem_util.c

include ../../Makefile.plugin

INCDIRS += \
	$(SRC)/uts/sun4 \
	$(SRC)/uts/sparc/v9 \
	$(SRC)/uts/sun4v \
	$(ROOT)/usr/platform/sun4v/include \
	$(GENERIC_MEM)

GMEM_VERSION = "1.0"

LDLIBS += -L$(ROOTLIB)/fm -ltopo
LDFLAGS += -R/usr/lib/fm
CPPFLAGS += $(INCDIRS:%=-I%) -DGMEM_VERSION='$(GMEM_VERSION)' -D$(ARCH)
CERRWARN += -_gcc=-Wno-switch
CERRWARN += -_gcc=-Wno-parentheses

%.o: $(GENERIC_MEM)/%.c
	$(COMPILE.c) -o $@ $<
	$(CTFCONVERT_O)

%.ln: $(GENERIC_MEM)/%.c
	$(LINT.c) -c $<

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

MODULE = cpumem-retire
CLASS = arch
ARCH = sun4v
SRCS = \
	cma_main.c \
	cma_cpu.c \
	cma_cpu_sun4v.c \
	cma_page.c \
	cma_page_sun4v.c

include ../../Makefile.plugin

CMA_VERSION = "1.1"

CPUMEM_RETIRE_COMMON = ../../common/$(MODULE)

INCDIRS = . \
	 $(ROOT)/usr/platform/sun4v/include \
	 $(CPUMEM_RETIRE_COMMON)

CPPFLAGS += $(INCDIRS:%=-I%) -DCMA_VERSION='$(CMA_VERSION)' -Dsun4v
LDFLAGS += -R/usr/lib/fm
LDLIBS += -L$(ROOTLIB)/fm -lldom

%.o: $(CPUMEM_RETIRE_COMMON)/%.c
	$(COMPILE.c) -o $@ $<
	$(CTFCONVERT_O)

%.ln: $(CPUMEM_RETIRE_COMMON)/%.c
	$(LINT.c) -c $<

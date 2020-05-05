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

ARCH = sun4v
PRIDIR=../platform-mem
PIDIR=../sun4vpi

sun4v_SRCS = dimm_sun4v.c mem_mdesc.c pi_meth.c

INCDIRS = $(ROOT)/usr/platform/sun4v/include \
		$(PRIDIR)

# include ../../sun4/chip/Makefile.chip

MODULE = dimm
CLASS = arch
SUN4DIR = ../../sun4/$(MODULE)
MODULESRCS = $($(ARCH)_SRCS)

include ../../Makefile.plugin

INCDIRS += $(SUN4DIR)

CPPFLAGS += $(INCDIRS:%=-I%)

%.o: $(SUN4DIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(CTFCONVERT_O)

# end of what would be body of ../../sun4/mem/Makefile.mem
LDLIBS += -lumem -lmdesc -lldom

%.o: $(PRIDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(CTFCONVERT_O)

%.o: $(PIDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(CTFCONVERT_O)

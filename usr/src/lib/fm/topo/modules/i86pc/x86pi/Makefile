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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.
#

MODULE	= x86pi
ARCH	= i86pc
CLASS	= arch

TOPODIR		= ../../../libtopo/common

UTILDIR		= ../../common/pcibus
BRDIR		= ../../common/hostbridge
UTILSRCS	= did.c did_hash.c did_props.c
X86PISRCS	= x86pi.c x86pi_bay.c x86pi_bboard.c x86pi_chassis.c \
		  x86pi_generic.c x86pi_hostbridge.c x86pi_subr.c
MODULESRCS	= $(X86PISRCS) $(UTILSRCS)

include ../../Makefile.plugin

LDLIBS += -lsmbios -ldevinfo -luutil -lpcidb

CPPFLAGS += -I. -I$(ROOT)/usr/platform/i86pc/include -I$(TOPODIR)
CPPFLAGS += -I$(UTILDIR) -I$(BRDIR)

%.o: $(UTILDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(CTFCONVERT_O)

%.ln: $(UTILDIR)/%.c
	$(LINT.c) -c $<

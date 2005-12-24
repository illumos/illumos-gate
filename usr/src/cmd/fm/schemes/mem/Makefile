#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"

include ../Makefile.com

SCHEME_COMMON = ../common

SRCS = \
	mdesc_devinit.c \
	mem.c \
	mem_disc.c \
	mem_read.c \
	mem_unum.c \
	mem_util.c


LDLIBS += -L$(ROOTLIB)/fm -lmdesc -lrt
LDFLAGS += -R/usr/lib/fm

include ../Makefile.targ

%.o: $(SCHEME_COMMON)/%.c
	$(COMPILE.c) -o $@ $<
	$(CTFCONVERT_O)

%.ln: $(SCHEME_COMMON)/%.c
	$(LINT.c) -erroff=E_BAD_PTR_CAST_ALIGN -v -c $<

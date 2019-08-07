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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

#
# Definitions for targets shared by some subdirs, which have
# dependencies in rcap/common, the path to which must be the value of
# COMMON_DIR.
#

LDFLAGS +=	$(MAPFILE.NGB:%=-M%)

CERRWARN += -_gcc=-Wno-unused-function
CERRWARN += $(CNOWARN_UNINIT)
CERRWARN += -_gcc=-Wno-parentheses

SMOFF += strcpy_overflow

%.o: $(COMMON_DIR)/%.c
	$(COMPILE.c) $<
%.po: $(COMMON_DIR)/%.c
	$(COMPILE.cpp) $< > $<.i
	$(BUILD.po)

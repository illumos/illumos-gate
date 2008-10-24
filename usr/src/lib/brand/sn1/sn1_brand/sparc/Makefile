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
# lib/brand/sn1/sparc/Makefile

ISASRCDIR =		.

include ../Makefile.com

#
# see ../Makefile.com for why we MUST explicity make ld.so.1 our interpreter
#
DYNFLAGS +=		-Wl,-I$(NATIVE_DIR)/usr/lib/ld.so.1
ASFLAGS +=		-xarch=v8plus ${AS_PICFLAGS}

CLEANFILES +=		$(DYNLIB)
CLOBBERFILES +=		$(ROOTLIBS)

install: all $(ROOTLIBS)

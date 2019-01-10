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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

PROG	= aw

include ../Makefile.tools

CFLAGS += $(CCVERBOSE)
CERRWARN += -_gcc=-Wno-uninitialized

# not linted
SMATCH=off

LINTFLAGS += -ux -Xa -errchk=locfmtchk,parentheses

CPPFLAGS +=	-DDEFAULT_AS_DIR='"$(GNU_ROOT)/bin"'
CPPFLAGS +=	-DDEFAULT_AS64_DIR='"$(GNU_ROOT)/bin"'
CPPFLAGS +=	-DDEFAULT_M4_DIR='"/usr/ccs/bin"'
CPPFLAGS +=	-DDEFAULT_M4LIB_DIR='"/usr/ccs/lib"'
CPPFLAGS +=	-DDEFAULT_CPP_DIR='"/usr/ccs/lib"'

.KEEP_STATE:

all:    $(PROG)

install: all .WAIT $(ROOTONBLDMACHPROG)

lint:	lint_PROG

clean:

include ../Makefile.targ

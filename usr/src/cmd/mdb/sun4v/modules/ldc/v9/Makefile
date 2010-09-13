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
# ident	"%Z%%M%	%I%	%E% SMI"
#

MODULE = ldc.so
MDBTGT = kvm

MODSRCS = ldc.c

include ../../../../../Makefile.cmd
include ../../../../../Makefile.cmd.64
include ../../../../sparc/Makefile.sparcv9
include ../../../Makefile.sun4v
include ../../../../Makefile.module

MODSRCS_DIR = ../

CPPFLAGS += -DMP -D_MACHDEP
CPPFLAGS += -Dsun4v
CPPFLAGS += -I$(SRC)/uts/sun4v
CPPFLAGS += -I$(SRC)/uts/sun4
CPPFLAGS += -I$(SRC)/uts/sparc/v9

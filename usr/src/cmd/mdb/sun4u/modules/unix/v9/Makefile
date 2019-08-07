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

MODULE = unix.so
MDBTGT = kvm

MODSRCS = unix.c sfmmu.c

include ../../../../../Makefile.cmd
include ../../../../../Makefile.cmd.64
include ../../../../sparc/Makefile.sparcv9
include ../../../Makefile.sun4u
include ../../../../Makefile.module

CPPFLAGS += -DMP -D_MACHDEP
CPPFLAGS += -I../../../../common
CPPFLAGS += -I$(SRC)/uts/sun4
CPPFLAGS += -I$(SRC)/uts/sun4u
CPPFLAGS += -I$(SRC)/uts/sfmmu
CPPFLAGS += -I$(SRC)/uts/sparc/v9
CERRWARN += $(CNOWARN_UNINIT)

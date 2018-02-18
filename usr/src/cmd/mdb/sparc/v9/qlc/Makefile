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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

MODULE = qlc.so
MDBTGT = kvm

MODSRCS = qlc.c

include ../../../../Makefile.cmd
include ../../../../Makefile.cmd.64
include ../../Makefile.sparcv9
include ../../../Makefile.module

CPPFLAGS += -I$(SRC)/uts/common
CPPFLAGS += -I$(SRC)/uts/common/sys/fibre-channel
CPPFLAGS += -I$(SRC)/uts/common/sys/fibre-channel/fca/qlc
CPPFLAGS += -I$(SRC)/uts/common/sys/fibre-channel/impl

LINTFLAGS64 +=  -erroff=E_STATIC_UNUSED -erroff=E_FUNC_SET_NOT_USED
LINTFLAGS64 +=  -erroff=E_STATIC_UNUSED -erroff=E_FUNC_ARG_UNUSED

CSTD=	$(CSTD_GNU99)
C99LMODE=	-Xc99=%all

CERRWARN +=	-_gcc=-Wno-address

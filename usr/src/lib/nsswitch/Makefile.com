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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

include		$(SRC)/lib/Makefile.lib

SRCDIR =	../common

ROOT32DYNLIB =	$(ROOTLIBDIR)/$(DYNLIB1)
ROOT64DYNLIB =	$(ROOTLIBDIR64)/$(DYNLIB1)


CPPFLAGS +=	-D_REENTRANT

CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	$(CNOWARN_UNINIT)
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-address

# not linted
SMATCH=off

LDLIBS +=	-lc
HSONAME =

CLOBBERFILES +=	$(DYNLIB1)

# Leaf target makefiles establish exactly what they will build by assigning to
# LIBS.  The use of "+=" creates both the default archive library and DYNLIB1,
# use of "=" creates DYNLIB1 only.  Archives are built and installed for some
# libraries as they are required to build things like ufsrestore, rcp.static,
# tar.static, metastat, metainit etc. however they do not get shipped with the
# final product.

.KEEP_STATE:

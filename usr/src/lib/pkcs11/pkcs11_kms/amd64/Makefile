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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#


include ../Makefile.com
include ../../../Makefile.lib.64

LINTCHECKFLAGS += -erroff=E_INCONS_ARG_DECL2 \
		-erroff=E_INCONS_ARG_USED2 \
		-erroff=E_INCONS_VAL_TYPE_DECL2 \
		-erroff=E_INCONS_VAL_TYPE_USED2 \
		-erroff=E_FUNC_DECL_VAR_ARG2

install: all $(ROOTLIBS64) $(ROOTLINKS64)

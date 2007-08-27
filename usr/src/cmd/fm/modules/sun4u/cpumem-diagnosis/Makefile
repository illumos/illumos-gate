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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

ARCH = sun4u

sun4u_SRCS = cmd_ecache.c \
		cmd_dp.c \
		cmd_dperr.c \
		cmd_dp_page.c \
		cmd_hc_opl.c \
		cmd_opl.c \
		cmd_oplerr.c

INCDIRS = $(SRC)/uts/sun4u

include ../../sun4/cpumem-diagnosis/Makefile.cpumem

LDFLAGS += -R/usr/lib/fm

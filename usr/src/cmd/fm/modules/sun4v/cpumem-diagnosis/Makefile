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

ARCH = sun4v

sun4v_SRCS = cmd_hc_sun4v.c \
	     cmd_branch.c

INCDIRS = $(SRC)/uts/sun4v \
	$(ROOT)/usr/platform/sun4v/include

include ../../sun4/cpumem-diagnosis/Makefile.cpumem

LDLIBS += -L$(ROOTLIB)/fm -lmdesc -lldom
LDFLAGS += -R/usr/lib/fm

CERRWARN += -_gcc=-Wno-switch
CERRWARN += -_gcc=-Wno-parentheses

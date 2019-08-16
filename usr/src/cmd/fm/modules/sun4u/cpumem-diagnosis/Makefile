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

ARCH = sun4u

sun4u_SRCS = cmd_ecache.c \
		cmd_dp.c \
		cmd_dperr.c \
		cmd_dp_page.c \
		cmd_hc_opl.c \
		cmd_opl.c \
		cmd_oplerr.c \
		cmd_Lxcache.c \
		cmd_Lxcacheerr.c  \

INCDIRS = $(SRC)/uts/sun4u
INCDIRS += $(SRC)/lib/fm/libfmd_adm/common
INCDIRS += $(SRC)/lib/fm/libfmd_adm/sparcv9

include ../../sun4/cpumem-diagnosis/Makefile.cpumem
LDLIBS += -L$(ROOT)/usr/lib/fm -lfmd_adm
LDFLAGS += -R/usr/lib/fm

CERRWARN += -_gcc=-Wno-switch
CERRWARN += $(CNOWARN_UNINIT)
CERRWARN += -_gcc=-Wno-char-subscripts

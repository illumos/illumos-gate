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
#ident	"%Z%%M%	%I%	%E% SMI"

MISC_LINK_ISA	= misc_link_i386
LX_LINK_ISA	= lx_link_i386
XEN_LINK	= xen_link

LINK_SRCS_i386 = 			\
	$(MISC_LINK_ISA).c		\
	$(LX_LINK_ISA).c		\
	$(XEN_LINK).c

LINK_OBJS_i386 =			\
	$(MISC_LINK_ISA).o		\
	$(LX_LINK_ISA).o		\
	$(XEN_LINK).o

LINK_MODS_i386 =			\
	SUNW_$(MISC_LINK_ISA).so	\
	SUNW_$(LX_LINK_ISA).so		\
	SUNW_$(XEN_LINK).so

include ../Makefile.com

$(LX_LINK_ISA).o $(LX_LINK_ISA).ln $(LX_LINK_ISA).po \
	:= CPPFLAGS += -I$(UTSBASE)/common/brand/lx

$(XEN_LINK).o $(XEN_LINK).ln $(XEN_LINK).po \
	:= CPPFLAGS += -I$(UTSBASE)/i86xpv

install: all

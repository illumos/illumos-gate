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

LIBRARY = libxdr.a
CMNOBJS = xdr.o xdr_array.o xdr_mem.o xdr_refer.o
LOCOBJS = byteorder.o
OBJECTS = $(LOCOBJS) $(CMNOBJS)

include ../Makefile.com

CMNDIR	= $(TOPDIR)/uts/common/rpc
SRCS	= $(LOCOBJS:%.o=$(SRCDIR)/%.c) $(CMNOBJS:%.o=$(CMNDIR)/%.c)

include Makefile.$(MACH).targ

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
# Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# 
# ident	"%Z%%M%	%I%	%E% SMI"
#

LIBRARY = libmd5.a
OBJECTS = md5.o

include ../Makefile.com

CMNDIR  = $(TOPDIR)/common/crypto/md5
SRCS	= $(OBJECTS:%.o=$(CMNDIR)/%.c)
CPPFLAGS += -D__RESTRICT

$(OBJECTS:%=objs/%) := CPPFLAGS += $(CMNDIR)/$(MACH)/$(KARCH)/byteswap.il

include ../Makefile.targ

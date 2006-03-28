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
# ident	"%Z%%M%	%I%	%E% SMI"
#

LIBRARY = libscrypt.a
COBJECTS = hmac_sha1.o des3.o des.o aes.o cbc.o
SHA1_OBJS = sha1.o
OBJECTS = $(COBJECTS) $(SHA1_OBJS)

include ../Makefile.com

CMNDIR  = $(TOPDIR)/common/net/wanboot/crypt
SHA1DIR  = $(TOPDIR)/common/crypto/sha1
SRCS	= $(COBJECTS:%.o=$(CMNDIR)/%.c) $(SHA1_OBJS:%.o=$(SHA1DIR)/%.c)

include ../Makefile.targ

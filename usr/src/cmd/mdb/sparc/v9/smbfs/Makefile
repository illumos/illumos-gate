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
# Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.

MDBTGT		= kvm
MODULE		= smbfs.so
MODSRCS_DIR	= ../../../common/modules/smbfs
MODSRCS		= smbfs.c

include ../../../../Makefile.cmd
include ../../../../Makefile.cmd.64
include ../../Makefile.sparcv9

# This kmod goes in /usr/kernel/kmdb
ROOTKMOD = $(ROOT)/usr/kernel/kmdb$(MACHMODDIR)

include ../../../Makefile.module

CPPFLAGS	+= -I$(SRC)/uts/common/fs/smbclnt
CPPFLAGS	+= -I$(SRC)/uts/common

CSTD=	$(CSTD_GNU99)

# maybe not the best place for this, but
# we need to create this directory.
$(ROOTKMOD):
	$(INS.dir)

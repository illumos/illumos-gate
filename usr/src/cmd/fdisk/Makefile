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
# Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright (c) 2018, Joyent, Inc.

#       Makefile for fdisk

PROG= fdisk
ROOTFS_PROG= $(PROG)

ROOTSBINLINK=	$(ROOTUSRSBIN)/$(PROG)

include ../Makefile.cmd

CPPFLAGS += -D_FILE_OFFSET_BITS=64

# not linted
SMATCH=off

LDLIBS_i386= -lfdisk
LDLIBS_sparc=
LDLIBS += -ladm -lefi $(LDLIBS_$(MACH))

i386_CFLAGS += -D_LARGEFILE64_SOURCE
i386_CFLAGS += -D_FILE_OFFSET_BITS=64

LINTFLAGS += -erroff=E_BAD_PTR_CAST_ALIGN -erroff=E_NAME_DEF_NOT_USED2

all:	$(ROOTFS_PROG)

install: all $(ROOTSBINPROG) $(ROOTSBINLINK)

$(ROOTSBINLINK):	FRC
	-$(RM) $@; $(SYMLINK) ../../sbin/$(PROG) $@

FRC:

clean:

lint:	lint_PROG

include ../Makefile.targ

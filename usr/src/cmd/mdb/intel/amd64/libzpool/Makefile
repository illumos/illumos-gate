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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

MODULE = libzpool.so
MDBTGT = proc

MODSRCS = zfs.c list.c

include ../../../../Makefile.cmd
include ../../../../Makefile.cmd.64
include ../../Makefile.amd64
include ../../../Makefile.module
include ../../../common/modules/zfs/Makefile.zfs

MODSRCS_DIR = ../../../common/modules/zfs
GENUNIX_DIR = ../../../common/modules/genunix

CPPFLAGS += -I../../../../../lib/libzpool/common \
	-I../../../../../uts/common/fs/zfs

C99MODE=	-xc99=%all
C99LMODE=	-Xc99=%all

CERRWARN 	+= -_gcc=-Wno-type-limits

dmod/%.o: $(GENUNIX_DIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(CTFCONVERT_O)

dmod/%.ln: $(GENUNIX_DIR)/%.c
	$(LINT.c) -c $<

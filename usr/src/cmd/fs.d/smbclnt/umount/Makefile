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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/fs.d/smbclnt/umount/Makefile
#

FSTYPE=		smbfs
LIBPROG=	umount
ROOTFS_PROG=	$(LIBPROG)

include		../../Makefile.fstype

COMMON=		$(FSLIB)
OBJS=		$(LIBPROG).o $(COMMON)
SRCS=		$(LIBPROG).c $(FSLIBSRC)
POFILE=		$(LIBPROG).po

CPPFLAGS += -I../.. -I../lib
CFLAGS += $(CCVERBOSE)

CLOBBERFILES	+= $(LIBPROG)

.KEEP_STATE:

all:	$(ROOTFS_PROG)

include		$(SRC)/cmd/fs.d/Makefile.mount.targ

#
# Message catalog
#
POFILE= umount.po

#
# message catalog
#
catalog: $(POFILE)

install:	$(ROOTLIBFSTYPEPROG)

lint:	lint_SRCS

clean:     
	$(RM) $(LIBPROG).o $(POFILE)

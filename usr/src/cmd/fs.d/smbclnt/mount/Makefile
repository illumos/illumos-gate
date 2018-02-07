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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# cmd/fs.d/smbclnt/mount/Makefile
#

FSTYPE=		smbfs
LIBPROG=	mount
ROOTFS_PROG=	$(LIBPROG)

include		../../Makefile.fstype

OBJS=	$(LIBPROG).o
SRCS=	$(LIBPROG).c
POFILE=	$(LIBPROG).po
CLOBBERFILES	+= $(LIBPROG)

$(ROOTLIBFSTYPE)/mount := FILEMODE= 04555

CFLAGS += $(CCVERBOSE)
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-unused-label
CSTD= $(CSTD_GNU99)

LDLIBS += -lsmbfs

CPPFLAGS += -I$(SRC)/uts/common -I$(SRC)/lib/libsmbfs 

# uncomment these for dbx debugging
#COPTFLAG = -g
#CTF_FLAGS =
#CTFCONVERT_O=
#CTFMERGE_LIB=

.KEEP_STATE:

all:	$(ROOTFS_PROG)

POFILE=		mount.po

catalog:	$(POFILE)

install:	$(ROOTLIBFSTYPEPROG)

lint:	lint_SRCS

clean:     
	$(RM) $(OBJS) $(POFILE)

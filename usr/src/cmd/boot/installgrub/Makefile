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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# 

PROG= installgrub

PCFS_SRC= $(SRC)/common/fs/pcfs.c

OBJS= installgrub.o floppy.o pcfs.o
SRCS= installgrub.c floppy.c $(PCFS_SRC)
SBINLINKS= $(PROG)

include ../Makefile.com

CPPFLAGS += -I$(SRC)/uts/i86pc -I$(SRC)/uts/intel -I$(SRC)/uts/common

i386_CFLAGS += -D_LARGEFILE64_SOURCE
i386_CFLAGS += -D_FILE_OFFSET_BITS=64

LDLIBS += -lfdisk

LINTFLAGS += \
	-erroff=E_BAD_PTR_CAST_ALIGN \
	-erroff=E_STATIC_UNUSED \
	-erroff=E_FUNC_RET_MAYBE_IGNORED \
	-erroff=E_FUNC_RET_MAYBE_IGNORED2 \
	-xerroff=E_NAME_DEF_NOT_USED2

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)


# pick pcfs from usr/src/common/fs
pcfs.o:	$(PCFS_SRC)
	$(COMPILE.c) -o $@ $(PCFS_SRC)

install: all $(ROOTSBINPROG) .WAIT $(ROOTUSRSBINLINKS)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

include ../Makefile.targ

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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# cmd/fs.d/smbclnt/smbiod/Makefile
#

FSTYPE=		smbfs
TYPEPROG=	smbiod

include		../../Makefile.fstype

OBJS=	$(TYPEPROG).o
SRCS=	$(TYPEPROG).c
POFILE=	$(TYPEPROG).po

CFLAGS += $(CCVERBOSE)
CSTD= $(CSTD_GNU99)

# This is a multi-thread program but Nevada
# no longer needs -lthread
LDLIBS += -lsmbfs -lumem

CPPFLAGS += -I$(SRC)/lib/libsmbfs \
	-I$(SRC)/uts/common/smbclnt -I$(SRC)/uts/common

# Debugging
${NOT_RELEASE_BUILD} CPPFLAGS += -DDEBUG

# uncomment these for dbx debugging
#COPTFLAG = -g
#CTF_FLAGS =
#CTFCONVERT_O=
#CTFMERGE_LIB=

all:	$(TYPEPROG)

catalog:	$(POFILE)

lint:	lint_SRCS

clean:
	$(RM) $(OBJS) $(POFILE)

.KEEP_STATE:

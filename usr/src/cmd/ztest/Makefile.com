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
# ident	"%Z%%M%	%I%	%E% SMI"
#

PROG= ztest
SRCS= ../$(PROG).c

include ../../Makefile.cmd

INCS += -I../../../lib/libzpool/common 
INCS += -I../../../uts/common/fs/zfs 

LDLIBS += -lumem -lzpool -lm -lnvpair

C99MODE= -xc99=%all
C99LMODE= -Xc99=%all
CFLAGS += -g $(CCVERBOSE)
CFLAGS64 += -g $(CCVERBOSE)
CPPFLAGS += -D_LARGEFILE64_SOURCE=1 -D_REENTRANT $(INCS)

# lint complains about unused _umem_* functions
LINTFLAGS += -xerroff=E_NAME_DEF_NOT_USED2 
LINTFLAGS64 += -xerroff=E_NAME_DEF_NOT_USED2  

.KEEP_STATE:

all: $(PROG)

$(PROG): $(SRCS)
	$(LINK.c) -o $(PROG) $(SRCS) $(LDLIBS)
	$(POST_PROCESS)

clean:

lint:	lint_SRCS

include ../../Makefile.targ

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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include $(SRC)/cmd/wbem/Makefile.wbem

OBJECTS	=	Solaris_MountService.o

LINT_OBJS =	$(OBJECTS:%.o=%.ln)

GENERAL =	$(ROOTWBEMINC) \
		$(SRC)/lib/libfsmgt/common \
		$(SRC)/cmd/wbem/provider/c/include \
		$(SRC)/cmd/wbem/provider/c/filesystems/wbem_nfs/include \
		$(SRC)/cmd/wbem/provider/c/filesystems/common/cmdgeneration \
		$(SRC)/cmd/wbem/provider/c/filesystems/wbem_nfs/common

CPPFLAGS	+= -I. $(GENERAL:%=-I%) -D_REENTRANT -DPIC -D_TS_ERRNO

CFLAGS		+= $(XREGSFLAG) $(C_BIGPICFLAGS)

LINTFLAGS	+= -um
LINTLIBS	= $(LDLIBS.cmd)

POFILE		= _nfs_mount.po
MSGFILES	= $(OBJECTS:%.o=%.i)

CLOBBERFILES	+= $(POFILE)

.KEEP_STATE:

all:		$(OBJECTS)

catalog:	$(POFILES)

install:	all

lint: $(LINT_OBJS)
	$(LINT.c) $(LINTFLAGS) $(LINT_OBJS) $(LINTLIBS)

clean:
		$(RM) $(OBJECTS) $(LINT_OBJS) $(MSGFILES)

check:
		$(CSTYLE) -p -P $(OBJECTS:%.o=%.c) *.h
		$(HDRCHK) *.h

catalog:	$(POFILE)

$(POFILE):	$(MSGFILES)
	$(BUILDPO.msgfiles)

include $(SRC)/cmd/Makefile.targ
include $(SRC)/Makefile.msg.targ

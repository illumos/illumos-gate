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

sparc_SUBDIRS =

i386_SUBDIRS =

ppc_SUBDIRS =

COMMON_SUBDIRS =	mount \
			umount \
			share \
			unshare

SUBDIRS	=		$(COMMON_SUBDIRS) $($(ARCH)_SUBDIRS)

OBJECTS	=	cmdgen.o

LINT_OBJS	= $(OBJECTS:%.o=%.ln)

GENERAL =	. \
		$(ROOTWBEMINC) \
		$(SRC)/cmd/wbem/provider/c/include \
		$(SRC)/cmd/wbem/provider/c/wbem_disk/common \
		$(SRC)/cmd/wbem/provider/c/filesystems/wbem_nfs/include

CPPFLAGS	+= -I. $(GENERAL:%=-I%) -D_REENTRANT -DPIC -D_TS_ERRNO

CFLAGS		+= $(XREGSFLAG) $(C_BIGPICFLAGS)

LINTFLAGS	+= -um
LINTLIBS	= $(LDLIBS.cmd)

POFILES		= $(OBJECTS:%.o=%.po)

all:=		TARGET = all
clean:=		TARGET = clean
clobber:=	TARGET = clobber
install:=	TARGET = install
lint:=		TARGET = lint
check:=		TARGET = check

.KEEP_STATE:

all:		$(OBJECTS) ${SUBDIRS}

catalog:	$(POFILES) ${SUBDIRS}

check:		${SUBDIRS}
		$(CSTYLE) -p -P $(OBJECTS:%.o=%.c) *.h
		$(HDRCHK) *.h

clean:		${SUBDIRS}
		$(RM) $(OBJECTS) $(LINT_OBJS) *.po

install:	all

lint:		$(LINT_OBJS) ${SUBDIRS}
		$(LINT.c) $(LINTFLAGS) $(LINT_OBJS) $(LINTLIBS)

FRC:

${SUBDIRS}:	FRC
		cd $@; pwd; $(MAKE) $(TARGET)

.WAIT:

include $(SRC)/cmd/Makefile.targ

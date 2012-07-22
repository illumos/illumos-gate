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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/cvcd/sparc/sun4u/starcat/cvcd
#
PROG=		cvcd
ROOTFS_PROG=	$(PROG)
PLATFORM=	SUNW,Sun-Fire-15000

#	Create default so empty rules don't confuse make
CLASS=		32

SRCS=		$(PROG:%=%.c)
OBJS=		$(PROG:%=%.o)

include ../../../../Makefile.cmd
include ../../../../../Makefile.psm

FILEMODE= 0755

ROOTPSMPROG	= $(ROOT_PSM_LIB_DIR)/$(PROG)

CPPFLAGS = -I$(USR_PSM_INCL_DIR) -I$(SRC)/uts/sun4u/starcat $(CPPFLAGS.master)
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-uninitialized

LDLIBS +=	-lsocket

.KEEP_STATE:

all: $(ROOTFS_PROG) 

install: all .WAIT $(ROOTPSMPROG)

clean:
	$(RM) $(PROG) $(OBJS)

lint: lint_PROG

include ../../../../Makefile.targ
include ../../../../../Makefile.psm.targ

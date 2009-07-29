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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# usr/src/cmd/prtdscp/sparc/sun4u/Makefile
#

PROG=		prtdscp
ROOTFS_PROG=	$(PROG)
PLATFORM=	SUNW,SPARC-Enterprise

CLASS=		32
SRCS=		$(PROG:%=%.c)
OBJS=		$(PROG:%=%.o)

include	../../../Makefile.cmd
include	../../../../Makefile.psm

LDLIBS +=	-ldscp -lnsl

CFLAGS +=	$(CCVERBOSE)

LDFLAGS	+=	-L$(USR_PSM_LIB_DIR)
LDFLAGS	+=	-R\$$ORIGIN/../lib

LINT_FLAGS=	-c -Nlevel=4 -Ncheck $($(CONCURR_MODE)_FLAGS)

.KEEP_STATE:

# Definitions for installation of the program
FILEMODE=	0755
ROOTPSMPROG	= $(USR_PSM_SBIN_DIR)/$(PROG)

all: $(ROOTFS_PROG)

install: all .WAIT $(ROOTPSMPROG)

clean:
	$(RM) $(PROG) $(OBJS)

lint:
	$(LINT) $(LINT_FLAGS) $(CPPFLAGS) $(SRCS)

include	../../../Makefile.targ
include	../../../../Makefile.psm.targ

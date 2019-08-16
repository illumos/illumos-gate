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
# Copyright (c) 2000 by Sun Microsystems, Inc.
# All rights reserved.
#

PROG = ncaconfd

.KEEP_STATE:

all:	$(PROG)

include ../../../Makefile.cmd
include ../Makefile.lib

LDLIBS += -lsocket -lnsl
CPPFLAGS += -I$(SRC)/uts/common/inet/nca

CERRWARN += $(CNOWARN_UNINIT)

POFILE = ${PROG}.po

install:	all $(ROOTLIBINETPROG)

clean:
	$(RM) $(PROG)

include ../../../Makefile.targ

lint:	lint_PROG

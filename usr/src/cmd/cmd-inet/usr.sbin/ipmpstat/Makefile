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

PROG = ipmpstat
ROOTFS_PROG = $(PROG)
ROOTUSRSBINLINKS = $(PROG:%=$(ROOTUSRSBIN)/%)

include $(SRC)/cmd/Makefile.cmd

C99MODE = $(C99_ENABLE)
CERRWARN += -_gcc=-Wno-uninitialized
LDLIBS += -lipmp -lsocket -lsysevent -lnvpair -lofmt
XGETFLAGS += -a -x $(PROG).xcl

.KEEP_STATE:

all:		$(PROG)

install:	all $(ROOTSBINPROG) $(ROOTUSRSBINLINKS)

clean:

lint:		lint_PROG

$(ROOTUSRSBINLINKS):
	-$(RM) $@; $(SYMLINK) ../../sbin/$(@F) $@

include $(SRC)/cmd/Makefile.targ

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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

PROG= zpool
OBJS= zpool_main.o zpool_vdev.o zpool_iter.o zpool_util.o
SRCS= $(OBJS:%.o=%.c)
POFILES=$(OBJS:%.o=%.po)
POFILE= zpool.po

include ../Makefile.cmd

LDLIBS += -lzfs -lnvpair -ldevid -lefi -ldiskmgt -luutil -lumem

INCS += -I../../common/zfs

CPPFLAGS += -D_LARGEFILE64_SOURCE=1 -D_REENTRANT $(INCS)

# lint complains about unused _umem_* functions
LINTFLAGS += -xerroff=E_NAME_DEF_NOT_USED2 
LINTFLAGS64 += -xerroff=E_NAME_DEF_NOT_USED2  

ROOTUSRSBINLINKS = $(PROG:%=$(ROOTUSRSBIN)/%)

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTSBINPROG) $(ROOTUSRSBINLINKS)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

# Links from /usr/sbin to /sbin
$(ROOTUSRSBINLINKS):
	-$(RM) $@; $(SYMLINK) ../../sbin/$(@F) $@

include ../Makefile.targ

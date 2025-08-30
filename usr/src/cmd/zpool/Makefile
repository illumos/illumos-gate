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
# Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2016 Igor Kozhukhov <ikozhukhov@gmail.com>.
# Copyright (c) 2015 by Delphix. All rights reserved.
# Copyright 2020 Joyent, Inc.
# Copyright 2025 Hans Rosenfeld
#

PROG= zpool
OBJS= zpool_main.o zpool_vdev.o zpool_iter.o zpool_util.o
SRCS= $(OBJS:%.o=%.c)
POFILES=$(OBJS:%.o=%.po)
POFILE= zpool.po

include ../Makefile.cmd
include ../Makefile.cmd.64
include ../Makefile.ctf
include ../stat/Makefile.stat

LDLIBS += -lzfs -lnvpair -ldevid -lefi -ldiskmgt -luutil -lumem -lzutil \
	-lm -lzpool

INCS += -I../../common/zfs -I../../uts/common/fs/zfs
INCS += -I../../lib/libzutil/common

CSTD=	$(CSTD_GNU99)

CPPFLAGS += $(INCS)
$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG

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

# Links from /usr/sbin to /sbin
$(ROOTUSRSBINLINKS):
	-$(RM) $@; $(SYMLINK) ../../sbin/$(@F) $@

include ../Makefile.targ

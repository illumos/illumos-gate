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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2010 Nexenta Systems, Inc. All rights reserved.
# Copyright (c) 2012, 2015 by Delphix. All rights reserved.
# Copyright 2016 Igor Kozhukhov <ikozhukhov@gmail.com>.
#

PROG=		zfs
OBJS=		zfs_main.o zfs_iter.o
SRCS=		$(OBJS:%.o=%.c)
POFILES=	zfs_main.po zfs_iter.po
POFILE=		zfs.po

include ../Makefile.cmd
include ../Makefile.ctf

FSTYPE=         zfs
LINKPROGS=	mount umount
ROOTETCFSTYPE=  $(ROOTETC)/fs/$(FSTYPE)
USRLIBFSTYPE=	$(ROOTLIB)/fs/$(FSTYPE)

LDLIBS += -lzfs_core -lzfs -luutil -lumem -lnvpair -lsec -lidmap

INCS += -I../../common/zfs

C99MODE=	-xc99=%all
C99LMODE=	-Xc99=%all

CPPFLAGS += -D_LARGEFILE64_SOURCE=1 -D_REENTRANT $(INCS)
$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG

# lint complains about unused _umem_* functions
LINTFLAGS += -xerroff=E_NAME_DEF_NOT_USED2
LINTFLAGS64 += -xerroff=E_NAME_DEF_NOT_USED2

ROOTUSRSBINLINKS = $(PROG:%=$(ROOTUSRSBIN)/%)
USRLIBFSTYPELINKS = $(LINKPROGS:%=$(USRLIBFSTYPE)/%)
ROOTETCFSTYPELINKS = $(LINKPROGS:%=$(ROOTETCFSTYPE)/%)

.KEEP_STATE:

.PARALLEL:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTSBINPROG) $(ROOTUSRSBINLINKS) $(USRLIBFSTYPELINKS) \
	$(ROOTETCFSTYPELINKS)

$(POFILE): $(POFILES)
	$(RM) $@
	cat $(POFILES) > $@

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

# Links from /usr/sbin to /sbin
$(ROOTUSRSBINLINKS):
	-$(RM) $@; $(SYMLINK) ../../sbin/$(PROG) $@

# Links from /usr/lib/fs/zfs to /sbin
$(USRLIBFSTYPELINKS):
	-$(RM) $@; $(SYMLINK) ../../../../sbin/$(PROG) $@

# Links from /etc/fs/zfs to /sbin
$(ROOTETCFSTYPELINKS):
	-$(RM) $@; $(SYMLINK) ../../../sbin/$(PROG) $@

FRC:

include ../Makefile.targ

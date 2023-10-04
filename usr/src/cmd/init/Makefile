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
# Copyright (c) 2018, Joyent, Inc.
# Copyright 2023 Oxide Computer Company
# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.

PROG= init
ROOTFS_PROG= $(PROG)

DEFAULTFILES= init.dfl

include ../Makefile.cmd

OBJS = init.o bootbanner.o definit.o ilstr.o
CSTD = $(CSTD_GNU99)
LDLIBS += -lpam -lbsm -lcontract -lscf
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += $(CNOWARN_UNINIT)
CLOBBERFILES= $(STATIC)
CPPFLAGS += -I$(SRC)/common/definit
CPPFLAGS += -DBOOTBANNER1='"$(BOOTBANNER1)"'
CPPFLAGS += -DBOOTBANNER2='"$(BOOTBANNER2)"'
CPPFLAGS += -DBOOTBANNER3='"$(BOOTBANNER3)"'
CPPFLAGS += -DBOOTBANNER4='"$(BOOTBANNER4)"'
CPPFLAGS += -DBOOTBANNER5='"$(BOOTBANNER5)"'

# needs work
SMATCH=off

.KEEP_STATE:

all: $(ROOTFS_PROG)

install: all $(ROOTETCDEFAULTFILES) $(ROOTSBINPROG)
	$(RM) $(ROOTETCPROG)
	$(RM) $(ROOTUSRSBINPROG)
	$(RM) $(ROOTETC)/telinit
	$(SYMLINK) ../sbin/$(PROG) $(ROOTETCPROG)
	$(SYMLINK) ../../sbin/$(PROG) $(ROOTUSRSBINPROG)
	$(SYMLINK) ../sbin/$(PROG) $(ROOTETC)/telinit
	$(RM) $(ROOTETC)/TIMEZONE
	cd $(ROOTETC); $(SYMLINK) default/init TIMEZONE

$(PROG):	$(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

%.o:	$(SRC)/common/bootbanner/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

%.o:	$(SRC)/common/definit/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

%.o:	$(SRC)/common/ilstr/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

test:
	rtest $(PROG)

clean:
	$(RM) $(OBJS)

include ../Makefile.targ

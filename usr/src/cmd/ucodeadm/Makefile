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
# Copyright 2017 RackTop Systems.
# Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
# Copyright 2025 Oxide Computer Company
#

PROG = ucodeadm

PROG_OBJS = ucodeadm.o ucode_errno.o
COMMON_OBJS = ucode_utils_intel.o ucode_utils_amd.o
OBJS = $(PROG_OBJS) $(COMMON_OBJS)
COMMON_SRCDIR = ../../common/ucode
ERROR_HEADER = $(COMMON_SRCDIR)/ucode_errno.h

include	../Makefile.cmd
include	../Makefile.ctf

POFILE = ucodeadm_all.po
POFILES = $(PROG_OBJS:%.o=%.po)

CSTD = $(CSTD_GNU17)
CPPFLAGS += -I$(SRC)/common
CFLAGS	+= $(CCVERBOSE)
LDLIBS += -lgen

DIRMODE = 0755
FILEMODE = 0555

install := TARGET = install
clobber := TARGET = clobber

CLEANFILES += $(PROG) $(OBJS) ucode_errno.c $(POFILES) $(POFILE)

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTUSRSBINPROG)

_msg: ucodeadm_all.po

%.o: $(COMMON_SRCDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

$(PROG): $(OBJS) ucode_errno.c
	$(LINK.c) -o $(PROG) $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

clean:
	-$(RM) $(CLEANFILES)

include	../Makefile.targ

ucode_errno.c: $(COMMON_SRCDIR)/mkerrno.sh $(ERROR_HEADER)
	sh $(COMMON_SRCDIR)/mkerrno.sh $(ERROR_HEADER) > $@

ucode_errno.po := XGETFLAGS += -a

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

FRC:

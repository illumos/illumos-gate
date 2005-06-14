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
# cmd/tar/Makefile

PROG= tar

include ../Makefile.cmd

CPPFLAGS += -D_FILE_OFFSET_BITS=64 -I../../lib/libcmd/inc
SED= sed
DCFILE= $(PROG).dc

DFLTD= $(ROOTETC)/default
DIRS= $(DFLTD)

LDLIBS += -lcmd -lsec

CFLAGS += $(CCVERBOSE)

# This flag is being added only for SCO (x86) compatibility  
CFLAGS += $(iBCS2FLAG)

CPPFLAGS += -DEUC

ROOTSYMLINK=	$(ROOTPROG)

ETCDFLTPROG = $(PROG:%=$(DFLTD)/%)
$(ETCDFLTPROG) := FILEMODE = $(LIBFILEMODE)
$(ETCDFLTPROG) := OWNER = root
$(ETCDFLTPROG) := GROUP = sys

XGETFLAGS += -a -x tar.xcl

.KEEP_STATE:

all: $(PROG) $(PROG).dfl

install: all $(DIRS) $(ROOTUSRSBINPROG) $(ETCDFLTPROG) $(ROOTSYMLINK)
	-$(RM) -r $(ROOTETCPROG)
	-$(SYMLINK) ../usr/sbin/$(PROG) $(ROOTETCPROG)

$(ROOTSYMLINK):
	$(RM) $@; $(SYMLINK) ../sbin/$(PROG) $@

$(DIRS):
	$(INS.dir)

$(DFLTD)/% : %
	$(MV) $(PROG) $(PROG).save
	$(LN) $(PROG).dfl $(PROG)
	$(INS.file)
	$(RM) $(PROG)
	$(MV) $(PROG).save $(PROG)

clean:

lint:	lint_PROG

$(DCFILE):
	$(RM) messages.po
	$(XGETTEXT) -c TRANSLATION_NOTE -t $(PROG).c
	$(SED) -e '/^domain/d' messages.po > $@
	$(RM) messages.po

include ../Makefile.targ

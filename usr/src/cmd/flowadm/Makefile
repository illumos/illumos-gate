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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG=flowadm

ROOTFS_PROG= $(PROG)

POFILE= $(PROG).po
CONFIGFILES= flowadm.conf flowprop.conf

include ../Makefile.cmd

XGETFLAGS += -a -x $(PROG).xcl
LDLIBS += -L$(ROOT)/lib
LDLIBS += -ldladm -lofmt

ROOTCFGDIR=	$(ROOTETC)/dladm
ROOTCFGFILES=	$(CONFIGFILES:%=$(ROOTCFGDIR)/%)

$(ROOTCFGFILES):= FILEMODE= 644

.KEEP_STATE:

all: $(ROOTFS_PROG)

#
# Message catalog
#
_msg: $(POFILE)

$(POFILE): $(PROG).c
	$(RM) $@
	$(COMPILE.cpp) $(PROG).c > $(POFILE).i
	$(XGETTEXT) $(XGETFLAGS) $(POFILE).i
	sed "/^domain/d" messages.po > $@
	$(RM) messages.po $(POFILE).i

install: all $(ROOTSBINPROG) $(ROOTCFGDIR) $(ROOTCFGFILES)
	$(RM) $(ROOTUSRSBINPROG)
	-$(SYMLINK) ../../sbin/$(PROG) $(ROOTUSRSBINPROG)

clean:

lint:	lint_PROG

$(ROOTCFGDIR):
	$(INS.dir)

$(ROOTCFGDIR)/%: $(ROOTCFGDIR) %
	$(INS.file)

include ../Makefile.targ

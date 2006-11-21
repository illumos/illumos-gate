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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#

PROG= dladm
CFGFILES= aggregation.conf linkprop.conf secobj.conf

ROOTFS_PROG=	$(PROG)
ROOTCFGDIR=	$(ROOTETC)/dladm
ROOTCFGFILES=	$(CFGFILES:%=$(ROOTCFGDIR)/%)

include ../Makefile.cmd

LDLIBS += -ldladm -lmacadm -ldlpi -llaadm -lkstat -lwladm -lsecdb -lbsm \
	  -linetutil

$(ROOTCFGFILES) := OWNER= dladm
$(ROOTCFGFILES) := GROUP= sys

$(ROOTCFGDIR)/aggregation.conf $(ROOTCFGDIR)/linkprop.conf := FILEMODE= 644
$(ROOTCFGDIR)/secobj.conf := FILEMODE= 600

.KEEP_STATE:

all: $(ROOTFS_PROG) 

install: all $(ROOTSBINPROG) $(ROOTCFGDIR) $(ROOTCFGFILES)
	$(RM) $(ROOTUSRSBINPROG)
	-$(SYMLINK) ../../sbin/$(PROG) $(ROOTUSRSBINPROG)

clean:

lint:	lint_PROG

$(ROOTCFGDIR):
	$(INS.dir)

$(ROOTCFGDIR)/%: $(ROOTCFGDIR) %
	$(INS.file)

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

include ../Makefile.targ

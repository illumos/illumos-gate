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

PROG= dladm
CFGFILES= secobj.conf

ROOTFS_PROG=	$(PROG)
ROOTCFGDIR=	$(ROOTETC)/dladm
ROOTCFGFILES=	$(CFGFILES:%=$(ROOTCFGDIR)/%)

include ../Makefile.cmd

XGETFLAGS += -a -x $(PROG).xcl
LDLIBS += -L$(ROOT)/lib -lsocket
LDLIBS += -ldladm -ldlpi -lkstat -lsecdb -lbsm -linetutil -ldevinfo
LDLIBS += $(ZLAZYLOAD) -lrstp $(ZNOLAZYLOAD)

CERRWARN += -_gcc=-Wno-switch
CERRWARN += -_gcc=-Wno-unused-label
CERRWARN += -_gcc=-Wno-uninitialized

# For headers from librstp.
LINTFLAGS +=	-erroff=E_TRAILING_COMMA_IN_ENUM

$(ROOTCFGDIR)/secobj.conf := FILEMODE= 660

lint :=	ZLAZYLOAD=
lint :=	ZNOLAZYLOAD=

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

include ../Makefile.targ

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

PROG=		dladm
ROOTFS_PROG=	$(PROG)
OBJS=		dladm.o

CFGFILES=	secobj.conf
ROOTCFGDIR=	$(ROOTETC)/dladm
ROOTCFGFILES=	$(CFGFILES:%=$(ROOTCFGDIR)/%)

include		$(SRC)/cmd/Makefile.cmd
include		$(SRC)/cmd/Makefile.ctf

XGETFLAGS +=	-a -x $(PROG).xcl

LDLIBS +=	-L$(ROOT)/lib -lsocket
LDLIBS +=	-ldladm -ldlpi -lkstat -lsecdb -lbsm -lofmt -linetutil -ldevinfo
LDLIBS +=	$(ZLAZYLOAD) -lrstp $(ZNOLAZYLOAD)

CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	-_gcc=-Wno-unused-label
CERRWARN +=	-_gcc=-Wno-uninitialized

# For headers from librstp.
LINTFLAGS +=	-erroff=E_TRAILING_COMMA_IN_ENUM
lint :=		ZLAZYLOAD=
lint :=		ZNOLAZYLOAD=

$(ROOTCFGDIR)/secobj.conf := FILEMODE= 660

.KEEP_STATE:

all:		$(PROG)

$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

clean:
		$(RM) $(OBJS)

install:	all $(ROOTSBINPROG) $(ROOTCFGDIR) $(ROOTCFGFILES)
		$(RM) $(ROOTUSRSBINPROG)
		-$(SYMLINK) ../../sbin/$(PROG) $(ROOTUSRSBINPROG)

lint:		lint_PROG

$(ROOTCFGDIR):
		$(INS.dir)

$(ROOTCFGDIR)/%: $(ROOTCFGDIR) %
		$(INS.file)

include		$(SRC)/cmd/Makefile.targ

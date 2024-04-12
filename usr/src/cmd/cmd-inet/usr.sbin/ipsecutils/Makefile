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
# Copyright 2024 Oxide Computer Company

PROG=		ikeadm ipsecalgs ipsecconf ipseckey ikecert
SOCKETPROG=	ipsecalgs ipsecconf ipseckey
TSOLPROG=	ipseckey
SRCS=		ikeadm.c ipsecalgs.c ipsecconf.c ipseckey.c
SBINLINKS=	tcpkey

include ../../../Makefile.cmd

MANIFEST=	ipsecalgs.xml policy.xml manual-key.xml tcpkey.xml
SVCMETHOD=	net-tcpkey

ROOTMANIFESTDIR=	$(ROOTSVCNETWORKIPSEC)
$(ROOTMANIFEST)		:= FILEMODE= 444
include ../../Makefile.cmd-inet

ROOTUSRSBINLINKS = $(SBINLINKS:%=$(ROOTUSRSBIN)/%)
$(ROOTUSRSBIN)/tcpkey := INSLINKTARGET = $(ROOTUSRSBIN)/ipseckey

COMMONSRCS=	$(CMDINETCOMMONDIR)/$(COMMONOBJS:.o=.c)
SRCS+=		$(COMMONSRCS)

#
# Message catalog
#
POFILES=	ikeadm.po ipsecalgs.po ipsecconf.po ipseckey.po
POFILE=		ipsecutils.po

all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber

CLOBBERFILES +=	$(PROG) $(POFILES)
CLEANFILES += $(PROG) $(POFILES)

CPPFLAGS +=	-DSYSV -DBSD_COMP -I$(CMDINETCOMMONDIR) -I.
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	$(CNOWARN_UNINIT)
CERRWARN +=	-_gcc=-Wno-switch

# not linted
SMATCH=off

LDLIBS += -lipsecutil -lnsl

LAZYLIBS = $(ZLAZYLOAD) -ltsol $(ZNOLAZYLOAD)

$(TSOLPROG)	:=	LDLIBS += $(LAZYLIBS)
$(SOCKETPROG)	:=	LDLIBS += -lsocket

.KEEP_STATE:

.PARALLEL:

.NO_PARALLEL:	$(CHKMANIFEST)

all: $(PROG)

#
# message catalog
#

$(POFILE): $(POFILES)
	$(RM) $@
	cat $(POFILES) >> $@

$(COMMONOBJS): $(COMMONSRCS)
	$(COMPILE.c) $(COMMONSRCS)

$(ROOTUSRSBINLINKS): $(ROOTUSRSBINPROG)
	$(INS.link)

install: $(PROG) $(ROOTFS_PROG) .WAIT $(ROOTUSRSBINPROG) \
	 $(ROOTUSRSBINLINKS) $(ROOTETCDEFAULTFILES) $(ROOTMANIFEST) \
	 $(ROOTSVCMETHOD) $(ROOTUSRSBINLINKS)

check:	$(CHKMANIFEST)

clean:
	-$(RM) $(CLEANFILES)


include ../../../Makefile.targ

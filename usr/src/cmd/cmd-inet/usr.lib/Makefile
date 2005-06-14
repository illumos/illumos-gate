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

SUBDIRS=	dhcp dsvclockd ike-certutils in.chargend in.daytimed \
		in.discardd in.echod in.dhcpd in.iked in.mpathd in.ndpd \
		in.ripngd in.timed inetd mipagent ncaconfd pppoe slpd wanboot
MSGSUBDIRS=	dsvclockd in.dhcpd inetd ncaconfd wanboot

include ../../Makefile.cmd

POFILES=	dsvclockd/dsvclockd.po in.dhcpd/in.dhcpd.po \
		inetd/inetd.po ncaconfd/ncaconfd.po \
		wanboot/wanboot.po
POFILE=		usr.lib.po

all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber
lint:=		TARGET= lint
_msg:=		TARGET= _msg

.KEEP_STATE:

all install clean clobber lint: $(SUBDIRS)

_msg: $(MSGSUBDIRS) 

#
# The reason this rule checks for the existence of the
# Makefile is that some of the directories do not exist
# in our exportable source builds.
#
$(SUBDIRS): FRC
	@if [ -f $@/Makefile  ]; then \
		cd $@; pwd; $(MAKE) $(TARGET); \
	else \
		true; \
	fi

FRC:

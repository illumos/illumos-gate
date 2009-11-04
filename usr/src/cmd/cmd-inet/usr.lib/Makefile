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

SUBDIRS=	bridged dhcp dsvclockd ilbd in.chargend in.daytimed \
		in.discardd in.echod in.dhcpd in.mpathd in.ndpd \
		in.ripngd in.timed inetd mdnsd ncaconfd pppoe \
		slpd wanboot wpad

MSGSUBDIRS=	dsvclockd ilbd in.dhcpd inetd ncaconfd wanboot

include ../../Makefile.cmd

$(CLOSED_BUILD)SUBDIRS += \
	$(CLOSED)/cmd/cmd-inet/usr.lib/ike-certutils \
	$(CLOSED)/cmd/cmd-inet/usr.lib/in.iked

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
# in our exportable source builds or in OpenSolaris.
#
$(SUBDIRS): FRC
	@if [ -f $@/Makefile  ]; then \
		cd $@; pwd; $(MAKE) $(TARGET); \
	else \
		true; \
	fi

FRC:

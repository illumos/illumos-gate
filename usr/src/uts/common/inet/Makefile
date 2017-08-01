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
# Copyright (c) 2014, 2017 by Delphix. All rights reserved.
#
# uts/common/inet/Makefile
#
# include global definitions
include ../../../Makefile.master

HDRS=	arp.h cc.h common.h ipclassifier.h ip.h ip6.h ipdrop.h ipnet.h \
	ipsecah.h ipsecesp.h ipsec_info.h iptun.h ip6_asp.h ip_if.h ip_ire.h \
	ip_multi.h ip_netinfo.h ip_ndp.h ip_rts.h ipsec_impl.h keysock.h \
	led.h mi.h mib2.h nd.h optcom.h sadb.h sctp_itf.h snmpcom.h tcp.h \
	tcp_sack.h tcp_stack.h tunables.h udp_impl.h rawip_impl.h ipp_common.h \
	ip_ftable.h ip_impl.h ip_stack.h ip_arp.h tcp_impl.h wifi_ioctl.h \
	ip2mac.h ip2mac_impl.h tcp_stats.h

ROOTDIRS= $(ROOT)/usr/include/inet

ROOTHDRS= $(HDRS:%=$(ROOT)/usr/include/inet/%)

CHECKHDRS= $(HDRS:%.h=%.check)

$(ROOTDIRS)/%: %
	$(INS.file)

.KEEP_STATE:

.PARALLEL: $(CHECKHDRS)

install_h: $(ROOTDIRS) $(ROOTHDRS)

$(ROOTDIRS):
	$(INS.dir)

check:	$(CHECKHDRS)

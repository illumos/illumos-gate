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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG=	snoop
OBJS=	nfs4_xdr.o snoop.o snoop_aarp.o snoop_adsp.o snoop_aecho.o \
	snoop_apple.o snoop_arp.o snoop_atp.o snoop_bparam.o \
	snoop_bpdu.o \
	snoop_capture.o snoop_dhcp.o snoop_dhcpv6.o snoop_display.o \
	snoop_dns.o snoop_ether.o \
	snoop_filter.o snoop_http.o snoop_icmp.o snoop_igmp.o snoop_ip.o \
	snoop_ipaddr.o snoop_ipsec.o snoop_isis.o \
	snoop_ldap.o snoop_mip.o snoop_mount.o \
	snoop_nbp.o snoop_netbios.o snoop_nfs.o snoop_nfs3.o snoop_nfs4.o \
	snoop_nfs_acl.o snoop_nis.o snoop_nlm.o snoop_ntp.o \
	snoop_pf.o snoop_ospf.o snoop_ospf6.o snoop_pmap.o snoop_ppp.o \
	snoop_pppoe.o snoop_rip.o snoop_rip6.o snoop_rpc.o snoop_rpcprint.o \
	snoop_rpcsec.o snoop_rport.o snoop_rquota.o snoop_rstat.o snoop_rtmp.o \
	snoop_sctp.o snoop_slp.o snoop_smb.o snoop_socks.o snoop_solarnet.o \
	snoop_tcp.o snoop_tftp.o snoop_trill.o snoop_udp.o snoop_zip.o

SRCS=	$(OBJS:.o=.c)
HDRS=	snoop.h snoop_mip.h at.h snoop_ospf.h snoop_ospf6.h

include	../../../Makefile.cmd

CPPFLAGS += -I. -I$(SRC)/common/net/dhcp \
	-D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
LDLIBS += -ldhcputil -ldlpi -lsocket -lnsl -ltsol
LDFLAGS += $(MAPFILE.NGB:%=-M%)
CERRWARN += -_gcc=-Wno-switch
CERRWARN += -_gcc=-Wno-implicit-function-declaration
CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-clobbered
CERRWARN += -_gcc=-Wno-unused-value
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-unused-label
CERRWARN += -_gcc=-Wno-unused-function

.KEEP_STATE:

.PARALLEL: $(OBJS)

all:	$(PROG)

$(PROG): $(OBJS) $(MAPFILE.NGB)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install:	all $(ROOTUSRSBINPROG)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

include	../../../Makefile.targ

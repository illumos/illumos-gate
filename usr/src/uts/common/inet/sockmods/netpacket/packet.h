/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Joyent, Inc. All rights reserved.
 */

#ifndef _PACKET_H
#define	_PACKET_H

#include <sys/socket_impl.h>
#include <net/if_arp.h>
#include <net/bpf.h>

/*
 * With which we do the reverse of what it libpcap does....
 */
#define	PACKET_OUTGOING		LINUX_SLL_OUTGOING
#define	PACKET_HOST		LINUX_SLL_HOST
#define	PACKET_BROADCAST	LINUX_SLL_BROADCAST
#define	PACKET_MULTICAST	LINUX_SLL_MULTICAST
#define	PACKET_OTHERHOST	LINUX_SLL_OTHERHOST

#define	PACKET_STATISTICS_SHORT	1
#define	PACKET_ADD_MEMBERSHIP	2
#define	PACKET_DROP_MEMBERSHIP	3
#define	PACKET_AUXDATA		4
#define	PACKET_STATISTICS	5


struct packet_mreq {
	uint32_t	mr_ifindex;
	uint16_t	mr_type;
	uint16_t	mr_alen;
	uint8_t		mr_address[8];
};

#define	PACKET_MR_MULTICAST	1
#define	PACKET_MR_PROMISC	2
#define	PACKET_MR_ALLMULTI	3

typedef enum tpkt_status_e {
	TP_STATUS_KERNEL,
	TP_STATUS_USER,
	TP_STATUS_COPY,
	TP_STATUS_LOSING,
	TP_STATUS_CSUMNOTREADY
} tpkt_status_t;

struct tpacket_auxdata {		/* tp_macoff/tp_netoff ?? */
	tpkt_status_t	tp_status;
	uint32_t	tp_len;
	uint32_t	tp_snaplen;
	uint16_t	tp_macoff;
	uint16_t	tp_netoff;
	uint16_t	tp_vlan_vci;
};

struct tpacket_hdr {			/* tp_macoff/tp_netoff ?? */
	uint64_t	tp_status;
	uint32_t	tp_len;
	uint32_t	tp_snaplen;
	uint16_t	tp_macoff;
	uint16_t	tp_netoff;
	uint32_t	tp_sec;
	uint32_t	tp_usec;
};

struct tpacket2_hdr {			/* tp_macoff/tp_netoff ?? */
	tpkt_status_t	tp_status;
	uint32_t	tp_len;
	uint32_t	tp_snaplen;
	uint16_t	tp_macoff;
	uint16_t	tp_netoff;
	uint32_t	tp_sec;
	uint32_t	tp_nsec;
	uint16_t	tp_vlan_tci;
};

struct tpacket_stats {
	uint32_t	tp_packets;
	uint32_t	tp_drops;
};

struct tpacket_stats_short {
	uint16_t	tp_packets;
	uint16_t	tp_drops;
};

struct sock_filter {			/* Fields named from bpf_insn */
	uint16_t	code;
	uint8_t		jt;
	uint8_t		jf;
	uint32_t	k;
};

struct sock_fprog {
	uint16_t		len;
	struct sock_filter	*filter;
};

/*
 * Linux ARPHRD_ symbols needed...
 *
 * The numbers above 50000 are because their real value is unknown from
 * libpcap's source, so a number has been chosen that is unlikely to be
 * confused with the real one on Linux. Those that are already found in
 * Solaris inside <net/if_arp.h> may have a different value to that found
 * in Linux but it should be used instead as the Solaris value originates
 * from the IANA whereas the Linux values seem to ignore it.
 */
/* ARPHRD_AX25				see <net/if_arp.h> */
/* ARPHRD_CHAOS				see <net/if_arp.h> */
#define	ARPHRD_CSLIP			50005
#define	ARPHRD_CSLIP6			50006
#define	ARPHRD_DLCI			15
/* ARPHRD_EETHER			see <net/if_arp.h> */
/* ARPHRD_ETHER				see <net/if_arp.h> */
#define	ARPHRD_FCAL			785
#define	ARPHRD_FCFABRIC			787
#define	ARPHRD_FCPL			786
#define	ARPHRD_FCPP			784
#define	ARPHRD_FRAD			770
#define	ARPHRD_FDDI			774
/* ARPHRD_IEEE802			see <net/if_arp.h> */
#define	ARPHRD_IEEE802_TR		800
#define	ARPHRD_IEEE80211		801
#define	ARPHRD_IEEE80211_PRISM		802
#define	ARPHRD_IEEE80211_RADIOTAP	803
#define	ARPHRD_IRDA			783
#define	ARPHRD_LAPD			8445
#define	ARPHRD_LOCALTLK			50010
#define	ARPHRD_LOOPBACK			50011
/* ARPHRD_METRICOM			see <net/if_arp.h> */
#define	ARPHRD_PRONET			50013
#define	ARPHRD_PPP			50014
#define	ARPHRD_RAWHDLC			518
#define	ARPHRD_SIT			776
#define	ARPHRD_SLIP6			50015
#define	ARPHRD_SLIP			50016
/* ARPHRD_TUNNEL			see <net/if_arp.h> */

#define	ETH_P_ALL			0
#define	ETH_P_802_2			0xaa	/* LSAP_SAP */
#define	ETH_P_803_3			0
#define	ETH_P_IP			0x800
#define	ETH_P_ARP			0x806
#define	ETH_P_IPV6			0x86dd

#ifdef _KERNEL
/*
 * PFP socket structure.
 */
typedef struct pfpsock {
	struct bpf_program		ps_bpf;
	krwlock_t			ps_bpflock;
	sock_upper_handle_t		ps_upper;
	sock_upcalls_t			*ps_upcalls;
	mac_handle_t			ps_mh;
	mac_client_handle_t		ps_mch;
	mac_promisc_handle_t		ps_phd;
	int				ps_type;
	int				ps_proto;
	uint_t				ps_max_sdu;
	boolean_t			ps_bound;
	mac_client_promisc_type_t	ps_promisc;
	boolean_t			ps_auxdata;
	struct tpacket_stats		ps_stats;
	struct sockaddr_ll		ps_sock;
	datalink_id_t			ps_linkid;
	kmutex_t			ps_lock;
	boolean_t			ps_flow_ctrld;
	ulong_t				ps_flow_ctrl_drops;
	timespec_t			ps_timestamp;
	size_t				ps_rcvbuf;
} pfpsock_t;

typedef struct pfp_kstats_s {
	kstat_named_t	kp_recv_mac_hdr_fail;
	kstat_named_t	kp_recv_bad_proto;
	kstat_named_t	kp_recv_alloc_fail;
	kstat_named_t	kp_recv_ok;
	kstat_named_t	kp_recv_fail;
	kstat_named_t	kp_recv_filtered;
	kstat_named_t	kp_recv_flow_cntrld;
	kstat_named_t	kp_send_unbound;
	kstat_named_t	kp_send_failed;
	kstat_named_t	kp_send_too_big;
	kstat_named_t	kp_send_alloc_fail;
	kstat_named_t	kp_send_uiomove_fail;
	kstat_named_t	kp_send_no_memory;
	kstat_named_t	kp_send_open_fail;
	kstat_named_t	kp_send_wrong_family;
	kstat_named_t	kp_send_short_msg;
	kstat_named_t	kp_send_ok;
} pfp_kstats_t;
#endif /* _KERNEL */

#endif /* _PACKET_H */

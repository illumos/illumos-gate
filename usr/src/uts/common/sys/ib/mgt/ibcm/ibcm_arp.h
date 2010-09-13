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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SYS_IB_MGT_IBCM_IBCM_ARP_H
#define	_SYS_IB_MGT_IBCM_IBCM_ARP_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/ib/mgt/ibcm/ibcm_impl.h>
#include <sys/ib/clients/ibd/ibd.h>
#include <inet/ip2mac.h>
#include <inet/ip6.h>

#define	IBCM_ARP_MAX_IFNAME_LEN		24

#define	IBCM_H2N_GID(gid) \
{ \
	uint32_t	*ptr; \
	ptr = (uint32_t *)&gid.gid_prefix; \
	gid.gid_prefix = (uint64_t)(((uint64_t)ntohl(ptr[0]) << 32) | \
			(ntohl(ptr[1]))); \
	ptr = (uint32_t *)&gid.gid_guid; \
	gid.gid_guid = (uint64_t)(((uint64_t)ntohl(ptr[0]) << 32) | \
			(ntohl(ptr[1]))); \
}

#define	IBCM_ARP_PR_RT_PENDING		0x01
#define	IBCM_ARP_PR_RESOLVE_PENDING	0x02

/*
 * Path record wait queue node definition
 */
typedef struct ibcm_arp_prwqn {
	struct ibcm_arp_streams_s *ib_str;
	uint8_t			flags;
	ibt_ip_addr_t		usrc_addr;	/* user supplied src address */
	ibt_ip_addr_t		dst_addr;	/* user supplied dest address */
	ibt_ip_addr_t		src_addr;	/* rts's view of src address */
	ibt_ip_addr_t		gateway;	/* rts returned gateway addr */
	ibt_ip_addr_t		netmask;	/* rts returned netmask */
	char			ifname[IBCM_ARP_MAX_IFNAME_LEN];
	uint16_t		ifproto;
	ipoib_mac_t		src_mac;
	ipoib_mac_t		dst_mac;
	ib_gid_t		sgid;
	ib_gid_t		dgid;
	ip2mac_id_t		ip2mac_id;
} ibcm_arp_prwqn_t;

typedef struct ibcm_arp_streams_s {
	kmutex_t		lock;
	kcondvar_t		cv;
	int			status;
	boolean_t		done;
	ibcm_arp_prwqn_t	*wqnp;
} ibcm_arp_streams_t;

typedef struct ibcm_arp_ip_s {
	datalink_id_t	ip_linkid;
	ib_pkey_t	ip_pkey;
	ib_guid_t	ip_hca_guid;
	ib_gid_t	ip_port_gid;
	sa_family_t	ip_inet_family;
	union {
		struct sockaddr_in	ip_sockaddr;
		struct sockaddr_in6	ip_sockaddr6;
	} ip_sin;
#define	ip_cm_sin		ip_sin.ip_sockaddr
#define	ip_cm_sin6		ip_sin.ip_sockaddr6
	zoneid_t	ip_zoneid;
} ibcm_arp_ip_t;

typedef struct ibcm_arp_ibd_insts_s {
	uint8_t		ibcm_arp_ibd_alloc;
	uint8_t		ibcm_arp_ibd_cnt;
	ibcm_arp_ip_t	*ibcm_arp_ip;
} ibcm_arp_ibd_insts_t;

ibt_status_t ibcm_arp_get_ibaddr(zoneid_t zoneid, ibt_ip_addr_t srcip,
    ibt_ip_addr_t destip, ib_gid_t *sgid, ib_gid_t *dgid,
    ibt_ip_addr_t *saddr_p);
ibt_status_t ibcm_arp_get_ibds(ibcm_arp_ibd_insts_t *ibdp, sa_family_t fam);
void ibcm_arp_free_ibds(ibcm_arp_ibd_insts_t *ibds);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_IB_MGT_IBCM_IBCM_ARP_H */

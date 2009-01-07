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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_IB_MGT_IBCM_IBCM_ARP_H
#define	_SYS_IB_MGT_IBCM_IBCM_ARP_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/ib/mgt/ibcm/ibcm_impl.h>
#include <sys/modhash.h>
#include <sys/ib/clients/ibd/ibd.h>
#include <sys/strsun.h>
#include <sys/socket.h>
#include <sys/stat.h>	/* for S_IFCHR */

/*
 * IPoIB addr lookup completion function
 */
typedef int (*ibcm_arp_pr_comp_func_t) (void *usr_arg, int status);

#define	IBCM_ARP_MAX_IFNAME_LEN		24
#define	IBCM_ARP_RTM_LEN		0x158
#define	IBCM_ARP_XMIT_COUNT		6
#define	IBCM_ARP_XMIT_INTERVAL		1000	/* timeout in milliseconds */
#define	IBCM_ARP_TIMEOUT \
		((IBCM_ARP_XMIT_COUNT + 1) * IBCM_ARP_XMIT_INTERVAL)
#define	IBCM_ARP_IP6_TIMEOUT		1000000	/* timeout in microseconds */

enum {
	IBCM_ARP_PR_RT_PENDING = 0x01,
	IBCM_ARP_PR_ARP_PENDING = 0x02
};

/*
 * Path record wait queue node definition
 */
typedef struct ibcm_arp_prwqn {
	ibcm_arp_pr_comp_func_t	func;	/* user callback function */
	void			*arg;	/* callback function arg */
	timeout_id_t		timeout_id;
	uint8_t			flags;
	ibt_ip_addr_t		usrc_addr;	/* user supplied src address */
	ibt_ip_addr_t		dst_addr;	/* user supplied dest address */
	ibt_ip_addr_t		src_addr;	/* rts's view of src address */
	char			ifname[IBCM_ARP_MAX_IFNAME_LEN];
	int			ibd_instance;
	uint16_t		ifproto;
	ipoib_mac_t		src_mac;
	ipoib_mac_t		dst_mac;
	uint32_t		localroute;		/* user option */
	uint32_t		bound_dev_if;		/* user option */
	ib_gid_t		sgid;
	ib_gid_t		dgid;
	uint8_t			hw_port;
	uint16_t		pkey;
	int			retries;	/* no. of ND retries for ipv6 */
} ibcm_arp_prwqn_t;

typedef struct ibcm_arp_streams_s {
	kmutex_t		lock;
	kcondvar_t		cv;
	queue_t			*arpqueue;
	vnode_t			*arp_vp;
	int			status;
	boolean_t		done;
	ibcm_arp_prwqn_t	*wqnp;
} ibcm_arp_streams_t;

/* GID to IP-Addr and Ip-Addr to GID look-up functions. */

#define	IBCM_ARP_IBD_INSTANCES		4

typedef struct ibcm_arp_ip_s {
	uint8_t		ip_inst;
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
} ibcm_arp_ip_t;

typedef struct ibcm_arp_ibd_insts_s {
	uint8_t		ibcm_arp_ibd_alloc;
	uint8_t		ibcm_arp_ibd_cnt;
	ibcm_arp_ip_t	*ibcm_arp_ip;
} ibcm_arp_ibd_insts_t;

ibt_status_t ibcm_arp_get_ibaddr(ipaddr_t srcip, ipaddr_t destip,
    ib_gid_t *sgid, ib_gid_t *dgid);
ibt_status_t ibcm_arp_get_srcip_plist(ibt_ip_path_attr_t *attr,
    ibt_path_flags_t flags, ibtl_cm_port_list_t **list_p);
ibt_status_t ibcm_arp_get_ibds(ibcm_arp_ibd_insts_t *ibdp);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_IB_MGT_IBCM_IBCM_ARP_H */

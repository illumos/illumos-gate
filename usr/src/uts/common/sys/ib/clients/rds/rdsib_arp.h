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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _RDSIB_ARP_H
#define	_RDSIB_ARP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/ib/ibtl/ibti.h>
#include <sys/ib/ibtl/ibtl_types.h>
#include <sys/ib/ib_pkt_hdrs.h>
#include <sys/modhash.h>
#include <sys/ib/clients/ibd/ibd.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/socket.h>
#include <sys/stat.h>	/* for S_IFCHR */
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip_if.h>
#include <inet/ip_ire.h>
#include <inet/ip_rts.h>
#include <sys/dlpi.h>
#include <net/route.h>

/*
 * Place holder for ipv4 or ipv6 address
 */
typedef struct {
	sa_family_t family;
	union {
		in_addr_t ip4addr;
		in6_addr_t ip6addr;
	} un;
} rds_ipx_addr_t;

/*
 * IPoIB addr lookup completion function
 */
typedef int (*rds_pr_comp_func_t) (void *usr_arg, int status);

/*
 * Path record cache node definition
 */
typedef struct rds_prcn {
	rds_ipx_addr_t dst_addr;	/* requested address */
	rds_ipx_addr_t src_addr;
	rds_ipx_addr_t gateway;	/* gateway to use */
	clock_t last_used_time;	/* last used */
	uint32_t hw_port;	/* source port */
	ibt_hca_hdl_t hca_hdl;	/* hca handle */
	uint16_t pkey;
	ibt_path_info_t path_info;
	ibt_path_attr_t path_attr;
	struct rds_prcn *next;
	struct rds_prcn **p_next;
} rds_prcn_t;

#define	RDS_MAX_IFNAME_LEN		24
#define	RDS_MAX_IP6_RETRIES		6

#define	RDS_ARP_XMIT_COUNT		6
#define	RDS_ARP_XMIT_INTERVAL		1000	/* timeout in milliseconds */
#define	RDS_ARP_TIMEOUT \
		((RDS_ARP_XMIT_COUNT + 1) * RDS_ARP_XMIT_INTERVAL)
#define	RDS_IP6_TIMEOUT			1000000	/* timeout in microseconds */
#define	RDS_PR_CACHE_REAPING_AGE	10	/* in seconds */
#define	RDS_PR_CACHE_REAPING_AGE_USECS	(RDS_PR_CACHE_REAPING_AGE * 1000000)

enum {
	RDS_PR_RT_PENDING = 0x01,
	RDS_PR_ARP_PENDING = 0x02
};

typedef struct {
	ib_guid_t hca_guid;
	ibt_hca_hdl_t hca_hdl;
	uint8_t nports;
	int opened;
} rds_hca_info_t;

/*
 * Path record wait queue node definition
 */
typedef struct rds_prwqn {
	rds_pr_comp_func_t func;	/* user callback function */
	void *arg;			/* callback function arg */
	timeout_id_t timeout_id;
	uint8_t flags;
	rds_ipx_addr_t usrc_addr;	/* user supplied src address */
	rds_ipx_addr_t dst_addr;	/* user supplied dest address */

	rds_ipx_addr_t src_addr;	/* rts's view  of source address */
	rds_ipx_addr_t gateway;		/* rts returned gateway address */
	rds_ipx_addr_t netmask;		/* rts returned netmask */
	char ifname[RDS_MAX_IFNAME_LEN];
	int ibd_instance;
	uint16_t ifproto;
	ipoib_mac_t src_mac;
	ipoib_mac_t dst_mac;
	uint32_t localroute;		/* user option */
	uint32_t bound_dev_if;		/* user option */
	ib_gid_t sgid;
	ib_gid_t dgid;
	uint8_t hw_port;
	uint16_t pkey;
	int retries;			/* no. of ND retries for ipv6 */
} rds_prwqn_t;

typedef struct rds_streams_s {
	kmutex_t	lock;
	kcondvar_t	cv;
	major_t		major;
	queue_t		*ipqueue;
	vnode_t		*ip_vp;
	queue_t		*arpqueue;
	vnode_t		*arp_vp;
	queue_t		*ip6queue;
	vnode_t		*ip6_vp;
	int		status;
	rds_prwqn_t	*wqnp;
} rds_streams_t;

#define	RDS_IPV4_ADDR(a)	(a->un.ip4addr)
#define	RDS_IPV6_ADDR(a)	(a->un.ip6addr)
#define	RDS_IS_V4_ADDR(a)	((a)->family == AF_INET)

/*
 * #define	RDS_IS_V4_ADDR(a)	((a)->family == AF_RDS)
 */
#define	RDS_IS_V6_ADDR(a)	((a)->family == AF_INET6)

#define	RDS_IOCTL		((('P' & 0xff) << 8) | (('R' & 0xff) << 16))

#define	RDS_PR_LOOKUP		(RDS_IOCTL + 1)
#define	IB_HW_LEN		20

typedef struct {
	int family;
	union {
		in_addr_t ip4addr;
		in6_addr_t ip6addr;
	} un;

	uint8_t hwaddr[IB_HW_LEN];
} rds_prreq_t;

#ifdef	__cplusplus
}
#endif

#endif /* _RDSIB_ARP_H */

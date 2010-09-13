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

#ifndef	_VRRPD_IMPL_H
#define	_VRRPD_IMPL_H

#include <sys/queue.h>
#include <libinetutil.h>
#include <libvrrpadm.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Internal data structs to store VRRP instance configuration information
 * and run-time state information.
 */
typedef useconds_t	vrrp_timeout_t;

typedef struct vrrp_vr_s {
	vrrp_vr_conf_t		vvr_conf;
	uint32_t		vvr_master_adver_int;
	char			vvr_vnic[MAXLINKNAMELEN];
	struct vrrp_intf_s	*vvr_pif;
	struct vrrp_intf_s	*vvr_vif;

	/*
	 * Timer reused in master/backup state:
	 *   Master: The Advertisement_Interval (Adver_Timer)
	 *   Backup: The Master_Down_Intervel (Master_Down_timer)
	 */
	vrrp_timeout_t		vvr_timeout;
	iu_timer_id_t		vvr_timer_id;

	/*
	 * Peer information, got from the last adv message received
	 */
	vrrp_peer_t		vvr_peer;
#define	vvr_peer_addr		vvr_peer.vp_addr
#define	vvr_peer_time		vvr_peer.vp_time
#define	vvr_peer_prio		vvr_peer.vp_prio
#define	vvr_peer_adver_int	vvr_peer.vp_adver_int

	vrrp_stateinfo_t	vvr_sinfo;
#define	vvr_state		vvr_sinfo.vs_state
#define	vvr_prev_state		vvr_sinfo.vs_prev_state
#define	vvr_st_time		vvr_sinfo.vs_st_time

	/*
	 * Record the reason why the virtual router stays at the INIT
	 * state, for the diagnose purpose.
	 */
	vrrp_err_t		vvr_err;
	TAILQ_ENTRY(vrrp_vr_s)	vvr_next;
} vrrp_vr_t;

/* IP address/interface cache state flags */
typedef enum {
	NODE_STATE_NONE		= 0,
	NODE_STATE_STALE	= 1,
	NODE_STATE_NEW		= 2
} node_state_t;

/*
 * The ifindex is get by the SIOCGLIFINDEX ioctl, easy to make it part of
 * vrrp_ip_t instead of vrrp_intf_t
 */
typedef struct vrrp_ip_s {
	char			vip_lifname[LIFNAMSIZ];
	vrrp_addr_t		vip_addr;
	uint64_t		vip_flags;
	node_state_t		vip_state;
	TAILQ_ENTRY(vrrp_ip_s)	vip_next;
} vrrp_ip_t;

/*
 * Used for primary interfaces
 */
typedef struct vrrp_primary_ifinfo {
	uint32_t		vpii_nvr;	/* numbers of virtual routers */
	vrrp_ip_t		*vpii_pip;	/* primary IP address */
	iu_event_id_t		vpii_eid;	/* event id of RX socket */
						/* non-zero on the primary if */
} vrrp_primary_ifinfo_t;

/*
 * Used for virtual interfaces
 */
typedef struct vrrp_virtual_ifinfo {
	/*
	 * the state of the VRRP router, used to determine the up/down
	 * state of the virtual IP addresses
	 */
	vrrp_state_t	vvii_state;
} vrrp_virtual_ifinfo_t;

/*
 * VRRP interface structure
 *
 * An interface is either the primary interface which owns the primary IP
 * address or a VNIC interface which owns the virtual IP addresses.
 * As the primary interface, it can be shared by several VRRP routers.
 */
typedef struct vrrp_intf_s {
	char			vvi_ifname[LIFNAMSIZ];
	int			vvi_af;		/* address family */
	node_state_t		vvi_state;
	uint32_t		vvi_ifindex;	/* interface index */
	TAILQ_HEAD(, vrrp_ip_s)	vvi_iplist;	/* IP adddress list */
	TAILQ_ENTRY(vrrp_intf_s) vvi_next;

	/*
	 * Socket fd.
	 * - physical interfaces: used to receive the VRRP packet, and shared
	 *   by all virtual routers on this physical interface.
	 * - vnic interfaces: used to send the VRRP packet.
	 */
	int			vvi_sockfd;

	vrrp_primary_ifinfo_t	pifinfo;	/* Primary interface info */
	vrrp_virtual_ifinfo_t	vifinfo;	/* VNIC interface info */
#define	vvi_nvr		pifinfo.vpii_nvr
#define	vvi_pip		pifinfo.vpii_pip
#define	vvi_eid		pifinfo.vpii_eid
#define	vvi_vr_state	vifinfo.vvii_state
} vrrp_intf_t;

#define	IS_PRIMARY_INTF(intf) \
	(((intf)->vvi_sockfd >= 0) && ((intf)->vvi_eid != -1))

#define	IS_VIRTUAL_INTF(intf) \
	(((intf)->vvi_sockfd >= 0) && ((intf)->vvi_eid == -1))

#define	VRRP_ERR	0	/* error message */
#define	VRRP_WARNING	1
#define	VRRP_NOTICE	2
#define	VRRP_INFO	3
#define	VRRP_DBG0	4	/* debug message, only function calls */
#define	VRRP_DBG1	5	/* detailed debug message */

/*
 * The primary IP address must be brought up; further, in the case of IPv6,
 * the link-local IP address is used as the primary IP address.
 */
#define	QUALIFY_PRIMARY_ADDR(intf, ip)					\
	(((ip)->vip_flags & IFF_UP) && ((intf)->vvi_af != AF_INET6 ||	\
	IN6_IS_ADDR_LINKLOCAL(&(ip)->vip_addr.in6.sin6_addr)))


#ifdef __cplusplus
}
#endif

#endif	/* _VRRPD_IMPL_H */

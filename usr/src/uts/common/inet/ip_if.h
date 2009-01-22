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
/* Copyright (c) 1990 Mentat Inc. */

#ifndef	_INET_IP_IF_H
#define	_INET_IP_IF_H

#include <net/route.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	PREFIX_INFINITY	0xffffffffUL
#define	IP_MAX_HW_LEN	40

#define	IP_LOOPBACK_MTU	(8*1024)

/* DLPI SAPs are in host byte order for all systems */
#define	IP_DL_SAP	0x0800
#define	IP6_DL_SAP	0x86dd

#ifdef	_KERNEL
/*
 * Interface flags actually represent the state/properties of 3 different
 * abstractions of interfaces in IP. Interface flags are set using
 * SIOCS[L]IFFLAGS ioctl. The three abstractions are :
 *
 * 1) Physical interface (phyint) : There is one phyint allocated common
 *    to both IPv4 and IPv6 physical interface instance.
 *
 * 2) Physical interface instance (ill) : This encompasses all the state
 *    that is common across all IP addresses assigned to a physical
 *    interface but different between the IPv4 and IPv6 instance.
 *
 * 3) Logical interface (ipif) : This has state about a single IP address.
 *
 * Values for the various states are derived from the same name space
 * as applications querying the state using SIOCGIFFLAGS/SIOCGLIFFLAGS
 * see only one state returned in lifr_flags which is a union of all
 * the above states/properties. Thus deriving the values from the common
 * name space makes implementation easier. All these values are stored in
 * uint64_t and any other structure/code using these flags should use
 * uint64_ts.
 *
 * As we maintain the interface flags in 3 different flags namely
 * phyint_flags, ill_flags, ipif_flags we define the following flag values
 * to be used within the kernel to reduce potential errors. The ones
 * starting with PHYI_ are supposed to be used with phyint_flags, the ones
 * starting with ILLF_ are supposed to be used with ill_flags and the ones
 * starting with IPIF_ are supposed to be used with ipif_flags. If you see
 * any code with a mismatch i.e phyint_flags & IPIF_UP - it is wrong. Only
 * PHYI_XXX can be used with phyint_flags.
 *
 * NOTE : For EVERY FLAG in if.h, there should be a corresponding value
 * defined HERE and this is the one that should be USED within IP. We
 * use IFF_ flags within IP only when we examine lifr_flags.
 */
#define	IFF_PHYINT_FLAGS	(IFF_LOOPBACK|IFF_RUNNING|IFF_PROMISC| \
    IFF_ALLMULTI|IFF_INTELLIGENT|IFF_MULTI_BCAST|IFF_FAILED|IFF_STANDBY| \
    IFF_INACTIVE|IFF_OFFLINE|IFF_VIRTUAL|IFF_IPMP)

#define	IFF_PHYINTINST_FLAGS	(IFF_DEBUG|IFF_NOTRAILERS|IFF_NOARP| \
    IFF_MULTICAST|IFF_ROUTER|IFF_NONUD|IFF_NORTEXCH|IFF_IPV4|IFF_IPV6| \
    IFF_XRESOLV|IFF_COS_ENABLED)

#define	IFF_LOGINT_FLAGS	(IFF_UP|IFF_BROADCAST|IFF_POINTOPOINT| \
    IFF_UNNUMBERED|IFF_DHCPRUNNING|IFF_PRIVATE|IFF_NOXMIT|IFF_NOLOCAL| \
    IFF_DEPRECATED|IFF_ADDRCONF|IFF_ANYCAST|IFF_NOFAILOVER| \
    IFF_PREFERRED|IFF_TEMPORARY|IFF_FIXEDMTU|IFF_DUPLICATE)

#define	PHYI_LOOPBACK		IFF_LOOPBACK	/* is a loopback net */
#define	PHYI_RUNNING		IFF_RUNNING	/* resources allocated */
#define	PHYI_PROMISC		IFF_PROMISC	/* receive all packets */
#define	PHYI_ALLMULTI		IFF_ALLMULTI	/* receive all multi packets */
#define	PHYI_INTELLIGENT	IFF_INTELLIGENT	/* protocol code on board */
#define	PHYI_MULTI_BCAST	IFF_MULTI_BCAST	/* multicast using broadcast */
#define	PHYI_FAILED		IFF_FAILED	/* NIC has failed */
#define	PHYI_STANDBY		IFF_STANDBY	/* Standby NIC  */
#define	PHYI_INACTIVE		IFF_INACTIVE	/* Standby active or not ? */
#define	PHYI_OFFLINE		IFF_OFFLINE	/* NIC has been offlined */
#define	PHYI_VIRTUAL		IFF_VIRTUAL	/* Will not send or recv pkts */
#define	PHYI_IPMP		IFF_IPMP	/* IPMP meta-interface */

#define	ILLF_DEBUG		IFF_DEBUG	/* turn on debugging */
#define	ILLF_NOTRAILERS		IFF_NOTRAILERS	/* avoid use of trailers */
#define	ILLF_NOARP		IFF_NOARP	/* no ARP for this interface */
#define	ILLF_MULTICAST		IFF_MULTICAST	/* supports multicast */
#define	ILLF_ROUTER		IFF_ROUTER	/* router on this interface */
#define	ILLF_NONUD		IFF_NONUD	/* No NUD on this interface */
#define	ILLF_NORTEXCH		IFF_NORTEXCH	/* No routing info exchange */
#define	ILLF_IPV4		IFF_IPV4	/* IPv4 interface */
#define	ILLF_IPV6		IFF_IPV6	/* IPv6 interface */
#define	ILLF_XRESOLV		IFF_XRESOLV	/* IPv6 external resolver */
#define	ILLF_COS_ENABLED	IFF_COS_ENABLED	/* Is CoS marking supported */

#define	IPIF_UP			IFF_UP		/* interface is up */
#define	IPIF_BROADCAST		IFF_BROADCAST	/* broadcast address valid */
#define	IPIF_POINTOPOINT	IFF_POINTOPOINT	/* point-to-point link */
#define	IPIF_UNNUMBERED		IFF_UNNUMBERED	/* non-unique address */
#define	IPIF_DHCPRUNNING	IFF_DHCPRUNNING	/* DHCP controlled interface */
#define	IPIF_PRIVATE		IFF_PRIVATE	/* do not advertise */
#define	IPIF_NOXMIT		IFF_NOXMIT	/* Do not transmit packets */
#define	IPIF_NOLOCAL		IFF_NOLOCAL	/* Just on-link subnet */
#define	IPIF_DEPRECATED		IFF_DEPRECATED	/* address deprecated */
#define	IPIF_ADDRCONF		IFF_ADDRCONF	/* stateless addrconf */
#define	IPIF_ANYCAST		IFF_ANYCAST	/* Anycast address */
#define	IPIF_NOFAILOVER		IFF_NOFAILOVER	/* No failover on NIC failure */
#define	IPIF_PREFERRED		IFF_PREFERRED	/* Prefer as source address */
#define	IPIF_TEMPORARY		IFF_TEMPORARY	/* RFC3041 */
#define	IPIF_FIXEDMTU		IFF_FIXEDMTU	/* set with SIOCSLIFMTU */
#define	IPIF_DUPLICATE		IFF_DUPLICATE	/* address is in use */

#ifdef DEBUG
#define	ILL_MAC_PERIM_HELD(ill)	ill_mac_perim_held(ill)
#else
#define	ILL_MAC_PERIM_HELD(ill)
#endif

/* for ipif_resolver_up */
enum ip_resolver_action {
	Res_act_initial,		/* initial address establishment */
	Res_act_rebind,			/* IPMP address rebind (new hwaddr) */
	Res_act_defend,			/* address defense */
	Res_act_none			/* do nothing */
};

extern	mblk_t	*ill_arp_alloc(ill_t *, const uchar_t *, caddr_t);
extern	mblk_t	*ipif_area_alloc(ipif_t *, uint_t);
extern	mblk_t	*ipif_ared_alloc(ipif_t *);
extern	mblk_t	*ill_ared_alloc(ill_t *, ipaddr_t);
extern	mblk_t	*ill_arie_alloc(ill_t *, const char *, const void *);
extern	boolean_t ill_dlpi_pending(ill_t *, t_uscalar_t);
extern	void	ill_dlpi_done(ill_t *, t_uscalar_t);
extern	void	ill_dlpi_send(ill_t *, mblk_t *);
extern	void	ill_dlpi_send_deferred(ill_t *);
extern	void	ill_capability_done(ill_t *);

extern	mblk_t	*ill_dlur_gen(uchar_t *, uint_t, t_uscalar_t, t_scalar_t);
/* NOTE: Keep unmodified ill_lookup_on_ifindex for ipp for now */
extern  ill_t	*ill_lookup_on_ifindex_global_instance(uint_t, boolean_t,
    queue_t *, mblk_t *, ipsq_func_t, int *);
extern  ill_t	*ill_lookup_on_ifindex(uint_t, boolean_t, queue_t *, mblk_t *,
    ipsq_func_t, int *, ip_stack_t *);
extern	ill_t	*ill_lookup_on_name(char *, boolean_t,
    boolean_t, queue_t *, mblk_t *, ipsq_func_t, int *, boolean_t *,
    ip_stack_t *);
extern uint_t	ill_get_next_ifindex(uint_t, boolean_t, ip_stack_t *);
extern uint_t	ill_get_ifindex_by_name(char *, ip_stack_t *);
extern	void	ill_ipif_cache_delete(ire_t *, char *);
extern	void	ill_stq_cache_delete(ire_t *, char *);
extern	void	ill_delete(ill_t *);
extern	void	ill_delete_tail(ill_t *);
extern	int	ill_dl_phys(ill_t *, ipif_t *, mblk_t *, queue_t *);
extern	int	ill_dls_info(struct sockaddr_dl *, const ipif_t *);
extern	void	ill_fastpath_ack(ill_t *, mblk_t *);
extern	void	ill_fastpath_nack(ill_t *);
extern	int	ill_fastpath_probe(ill_t *, mblk_t *);
extern	void	ill_fastpath_flush(ill_t *);
extern	int	ill_forward_set(ill_t *, boolean_t);
extern	void	ill_frag_prune(ill_t *, uint_t);
extern	void	ill_frag_free_pkts(ill_t *, ipfb_t *, ipf_t *, int);
extern	time_t	ill_frag_timeout(ill_t *, time_t);
extern	int	ill_init(queue_t *, ill_t *);
extern	void	ill_refresh_bcast(ill_t *);
extern	void	ill_restart_dad(ill_t *, boolean_t);
extern	boolean_t	ill_setdefaulttoken(ill_t *);
extern	int	ill_set_phys_addr(ill_t *, mblk_t *);
extern	void	ill_set_ndmp(ill_t *, mblk_t *, uint_t, uint_t);

extern mblk_t	*ill_pending_mp_get(ill_t *, conn_t **, uint_t);
extern boolean_t ill_pending_mp_add(ill_t *, conn_t *, mblk_t *);
extern	boolean_t ill_is_freeable(ill_t *ill);
extern	void	ill_refhold(ill_t *);
extern	void	ill_refhold_locked(ill_t *);
extern	int	ill_check_and_refhold(ill_t *);
extern	void	ill_refrele(ill_t *);
extern	boolean_t ill_waiter_inc(ill_t *);
extern	void	ill_waiter_dcr(ill_t *);
extern	void	ill_trace_ref(ill_t *);
extern	void	ill_untrace_ref(ill_t *);
extern	boolean_t ill_down_start(queue_t *, mblk_t *);
extern	ill_t	*ill_lookup_group_v6(const in6_addr_t *, zoneid_t,
    ip_stack_t *);

extern	void	ill_capability_ack(ill_t *, mblk_t *);
extern	void	ill_capability_probe(ill_t *);
extern	void	ill_capability_reset(ill_t *, boolean_t);
extern	void	ill_taskq_dispatch(ip_stack_t *);

extern	void	ill_mtu_change(ire_t *, char *);
extern	int	ill_up_ipifs(ill_t *, queue_t *, mblk_t *);
extern uint_t	ill_appaddr_cnt(const ill_t *);
extern uint_t	ill_ptpaddr_cnt(const ill_t *);

extern	void	ip_loopback_cleanup(ip_stack_t *);
extern	void	ipif_get_name(const ipif_t *, char *, int);
extern	ipif_t	*ipif_getby_indexes(uint_t, uint_t, boolean_t, ip_stack_t *);
extern	void	ipif_init(ip_stack_t *);
extern	ipif_t	*ipif_lookup_addr(ipaddr_t, ill_t *, zoneid_t, queue_t *,
    mblk_t *, ipsq_func_t, int *, ip_stack_t *);
extern	boolean_t ip_addr_exists(ipaddr_t, zoneid_t, ip_stack_t *);
extern	ipif_t	*ipif_lookup_addr_v6(const in6_addr_t *, ill_t *, zoneid_t,
    queue_t *, mblk_t *, ipsq_func_t, int *, ip_stack_t *);
extern  boolean_t ip_addr_exists_v6(const in6_addr_t *, zoneid_t,
    ip_stack_t *);
extern	ipif_t	*ipif_lookup_addr_exact_v6(const in6_addr_t *, ill_t *,
    ip_stack_t *);
extern	zoneid_t ipif_lookup_addr_zoneid(ipaddr_t, ill_t *, ip_stack_t *);
extern	zoneid_t ipif_lookup_addr_zoneid_v6(const in6_addr_t *, ill_t *,
    ip_stack_t *);
extern	ipif_t	*ipif_lookup_group(ipaddr_t, zoneid_t, ip_stack_t *);
extern	ipif_t	*ipif_lookup_group_v6(const in6_addr_t *, zoneid_t,
    ip_stack_t *);
extern  ipif_t	*ipif_lookup_interface(ipaddr_t, ipaddr_t,
    queue_t *, mblk_t *, ipsq_func_t, int *, ip_stack_t *);
extern	ipif_t	*ipif_lookup_multicast(ip_stack_t *, zoneid_t, boolean_t);
extern	ipif_t	*ipif_lookup_remote(ill_t *, ipaddr_t, zoneid_t);
extern	ipif_t	*ipif_lookup_onlink_addr(ipaddr_t, zoneid_t, ip_stack_t *);
extern	ipif_t	*ipif_lookup_seqid(ill_t *, uint_t);
extern	boolean_t ipif_lookup_zoneid(ill_t *, zoneid_t, int, ipif_t **);
extern	ipif_t	*ipif_select_source(ill_t *, ipaddr_t, zoneid_t);
extern	boolean_t	ipif_usesrc_avail(ill_t *, zoneid_t);
extern	void	ipif_refhold(ipif_t *);
extern	void	ipif_refhold_locked(ipif_t *);
extern	void	ipif_refrele(ipif_t *);
extern	void	ipif_all_down_tail(ipsq_t *, queue_t *, mblk_t *, void *);
extern	void	ipif_resolver_down(ipif_t *);
extern	int	ipif_resolver_up(ipif_t *, enum ip_resolver_action);
extern	int	ipif_arp_setup_multicast(ipif_t *, mblk_t **);
extern	int	ipif_down(ipif_t *, queue_t *, mblk_t *);
extern	void	ipif_down_tail(ipif_t *);
extern	void	ipif_multicast_down(ipif_t *);
extern	void	ipif_multicast_up(ipif_t *);
extern	void	ipif_ndp_down(ipif_t *);
extern	int	ipif_ndp_up(ipif_t *, boolean_t);
extern	int	ipif_ndp_setup_multicast(ipif_t *, struct nce_s **);
extern	int	ipif_up_done(ipif_t *);
extern	int	ipif_up_done_v6(ipif_t *);
extern	void	ipif_up_notify(ipif_t *);
extern	void	ipif_update_other_ipifs_v6(ipif_t *);
extern	void	ipif_recreate_interface_routes_v6(ipif_t *, ipif_t *);
extern	void	ill_update_source_selection(ill_t *);
extern	ipif_t	*ipif_select_source_v6(ill_t *, const in6_addr_t *, boolean_t,
    uint32_t, zoneid_t);
extern	boolean_t	ipif_cant_setlinklocal(ipif_t *);
extern	int	ipif_setlinklocal(ipif_t *);
extern	void	ipif_set_tun_llink(ill_t *, struct iftun_req *);
extern	ipif_t	*ipif_lookup_on_ifindex(uint_t, boolean_t, zoneid_t, queue_t *,
    mblk_t *, ipsq_func_t, int *, ip_stack_t *);
extern	ipif_t	*ipif_get_next_ipif(ipif_t *curr, ill_t *ill);
extern	void	ipif_ill_refrele_tail(ill_t *ill);
extern	void	ipif_mask_reply(ipif_t *);
extern	int 	ipif_up(ipif_t *, queue_t *, mblk_t *);

extern	void	ipsq_current_start(ipsq_t *, ipif_t *, int);
extern	void	ipsq_current_finish(ipsq_t *);
extern	void	ipsq_enq(ipsq_t *, queue_t *, mblk_t *, ipsq_func_t, int,
    ill_t *);
extern	boolean_t ipsq_enter(ill_t *, boolean_t, int);
extern	ipsq_t	*ipsq_try_enter(ipif_t *, ill_t *, queue_t *, mblk_t *,
    ipsq_func_t, int, boolean_t);
extern	void	ipsq_exit(ipsq_t *);
extern	boolean_t ill_mac_perim_held(ill_t *);
extern mblk_t	*ipsq_pending_mp_get(ipsq_t *, conn_t **);
extern boolean_t ipsq_pending_mp_add(conn_t *, ipif_t *, queue_t *,
    mblk_t *, int);
extern	void	qwriter_ip(ill_t *, queue_t *, mblk_t *, ipsq_func_t, int,
    boolean_t);

typedef	int	ip_extract_func_t(queue_t *, mblk_t *, const ip_ioctl_cmd_t *,
    cmd_info_t *, ipsq_func_t);

extern	ip_extract_func_t ip_extract_arpreq, ip_extract_lifreq;
extern	ip_extract_func_t ip_extract_tunreq;

extern	int	ip_addr_availability_check(ipif_t *);
extern	int	ip_ill_report(queue_t *, mblk_t *, caddr_t, cred_t *);
extern	int	ip_ipif_report(queue_t *, mblk_t *, caddr_t, cred_t *);
extern	void	ip_ll_subnet_defaults(ill_t *, mblk_t *);

extern	int	ip_rt_add(ipaddr_t, ipaddr_t, ipaddr_t, ipaddr_t, int,
    ipif_t *, ire_t **, boolean_t, queue_t *, mblk_t *, ipsq_func_t,
    struct rtsa_s *, ip_stack_t *);
extern	int	ip_rt_add_v6(const in6_addr_t *, const in6_addr_t *,
    const in6_addr_t *, const in6_addr_t *, int, ipif_t *, ire_t **,
    queue_t *, mblk_t *, ipsq_func_t, struct rtsa_s *, ip_stack_t *ipst);
extern	int	ip_rt_delete(ipaddr_t, ipaddr_t, ipaddr_t, uint_t, int,
    ipif_t *, boolean_t, queue_t *, mblk_t *, ipsq_func_t, ip_stack_t *);
extern	int	ip_rt_delete_v6(const in6_addr_t *, const in6_addr_t *,
    const in6_addr_t *, uint_t, int, ipif_t *, queue_t *, mblk_t *,
    ipsq_func_t, ip_stack_t *);
extern int ip_siocdelndp_v6(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_siocqueryndp_v6(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_siocsetndp_v6(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);

extern int ip_siocaddrt(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_siocdelrt(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);

extern int ip_sioctl_addr(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_addr_restart(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_get_addr(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);

extern int ip_sioctl_dstaddr(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_dstaddr_restart(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_get_dstaddr(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);

extern int ip_sioctl_flags(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_flags_restart(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_get_flags(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);

extern int ip_sioctl_mtu(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_get_mtu(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);

extern int ip_sioctl_get_ifconf(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_get_lifconf(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_get_ifnum(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_get_lifnum(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);

extern int ip_sioctl_token(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_get_token(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);

extern int if_unitsel(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int if_unitsel_restart(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);

extern int ip_sioctl_sifname(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);

extern int ip_sioctl_slifname(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_slifname_restart(ipif_t *, sin_t *, queue_t *,
    mblk_t *, ip_ioctl_cmd_t *, void *);

extern int ip_sioctl_slifindex(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_get_lifindex(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);

extern int ip_sioctl_brdaddr(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_get_brdaddr(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);

extern int ip_sioctl_get_muxid(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_muxid(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);

extern int ip_sioctl_netmask(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_get_netmask(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_netmask_restart(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);

extern int ip_sioctl_subnet(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_subnet_restart(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_get_subnet(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);

extern int ip_sioctl_lnkinfo(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_get_lnkinfo(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);

extern int ip_sioctl_metric(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_get_metric(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);

extern int ip_sioctl_arp(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);

extern int ip_sioctl_addif(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_removeif(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_removeif_restart(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);

extern int ip_sioctl_tonlink(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_tmysite(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_tmyaddr(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);

extern int ip_sioctl_tunparam(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);

extern int ip_sioctl_get_binding(ipif_t *, sin_t *, queue_t *,
    mblk_t *, ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_groupname(ipif_t *, sin_t *, queue_t *,
    mblk_t *, ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_get_groupname(ipif_t *, sin_t *, queue_t *,
    mblk_t *, ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_groupinfo(ipif_t *, sin_t *, queue_t *,
    mblk_t *, ip_ioctl_cmd_t *, void *);

extern int ip_sioctl_get_lifzone(ipif_t *, sin_t *, queue_t *,
    mblk_t *, ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_slifzone(ipif_t *, sin_t *, queue_t *,
    mblk_t *, ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_slifzone_restart(ipif_t *, sin_t *, queue_t *,
    mblk_t *, ip_ioctl_cmd_t *, void *);

extern int ip_sioctl_get_lifusesrc(ipif_t *, sin_t *, queue_t *,
    mblk_t *, ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_slifusesrc(ipif_t *, sin_t *, queue_t *,
    mblk_t *, ip_ioctl_cmd_t *, void *);
extern int ip_sioctl_get_lifsrcof(ipif_t *, sin_t *, queue_t *,
    mblk_t *, ip_ioctl_cmd_t *, void *);

extern	void	ip_sioctl_copyin_resume(ipsq_t *, queue_t *, mblk_t *, void *);
extern	void	ip_sioctl_copyin_setup(queue_t *, mblk_t *);
extern	void	ip_sioctl_iocack(ipsq_t *, queue_t *, mblk_t *, void *);
extern	ip_ioctl_cmd_t *ip_sioctl_lookup(int);

extern	void	conn_delete_ire(conn_t *, caddr_t);
extern	boolean_t	phyint_exists(uint_t, ip_stack_t *);

/*
 * Notes on reference tracing on ill, ipif, ire, nce data structures:
 *
 * The current model of references on an ipif or ill is purely based on threads
 * acquiring a reference by doing a lookup on the ill or ipif or by calling a
 * refhold function on the ill or ipif. In particular any data structure that
 * points to an ipif or ill does not explicitly contribute to a reference on the
 * ill or ipif. More details may be seen in the block comment above ipif_down().
 * Thus in the quiescent state an ill or ipif has a refcnt of zero. Similarly
 * when a thread exits, there can't be any references on the ipif or ill due to
 * the exiting thread.
 *
 * As a debugging aid, the refhold and refrele functions call into tracing
 * functions that record the stack trace of the caller and the references
 * acquired or released by the calling thread, hashed by the structure address
 * in thread-specific-data (TSD).  On thread exit, ip_thread_exit destroys the
 * hash, and the destructor for the hash entries (th_trace_free) verifies that
 * there are no outstanding references to the ipif or ill from the exiting
 * thread.
 *
 * In the case of ires and nces, the model is slightly different. Typically each
 * ire pointing to an nce contributes to the nce_refcnt. Similarly a conn_t
 * pointing to an ire also contributes to the ire_refcnt. Excluding the above
 * special cases, the tracing behavior is similar to the tracing on ipif / ill.
 * Traces are neither recorded nor verified in the exception cases, and the code
 * is careful to use the right refhold and refrele functions. On thread exit
 * ire_thread_exit, nce_thread_exit does the verification that are no
 * outstanding references on the ire / nce from the exiting thread.
 *
 * The reference verification is driven from the TSD destructor which calls
 * into IP's verification function ip_thread_exit. This debugging aid may be
 * helpful in tracing missing refrele's on a debug kernel. On a non-debug
 * kernel, these missing refrele's are noticeable only when an interface is
 * being unplumbed, and the unplumb hangs, long after the missing refrele. On a
 * debug kernel, the traces (th_trace_t) which contain the stack backtraces can
 * be examined on a crash dump to locate the missing refrele.
 */

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_IP_IF_H */

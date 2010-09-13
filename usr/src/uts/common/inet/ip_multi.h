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

#ifndef	_INET_IP_MULTI_H
#define	_INET_IP_MULTI_H

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_KERNEL)

#define	INFINITY	0xffffffffU
/*
 * Enum used to pass ilg status to ip_addmulti() and friends. There
 * are three possibilities: the group is being joined from within ip,
 * in which case there is no associated ilg; the group is being joined
 * from an upper layer with an associated ilg that's been newly created
 * by this join; or the upper layer is changing its group membership
 * state (the ilg existed before this call).
 */
typedef enum {
	ILGSTAT_NONE,
	ILGSTAT_NEW,
	ILGSTAT_CHANGE
} ilg_stat_t;

/*
 * Extern functions
 */
extern	mblk_t		*igmp_input(mblk_t *, ip_recv_attr_t *);
extern	void		igmp_joingroup(ilm_t *);
extern	void		igmp_leavegroup(ilm_t *);
extern	void		igmp_slowtimo(void *);
extern	void		igmp_timeout_handler(void *);
extern	void		igmp_statechange(ilm_t *, mcast_record_t, slist_t *);

extern	void		mld_joingroup(ilm_t *);
extern	void		mld_leavegroup(ilm_t *);
extern	void		mld_statechange(ilm_t *, mcast_record_t, slist_t *);
extern	void		mld_slowtimo(void *);

extern	void		ilg_delete_all(conn_t *connp);
extern	boolean_t	conn_hasmembers_ill_withsrc_v4(conn_t *, ipaddr_t,
    ipaddr_t, ill_t *);
extern	boolean_t	conn_hasmembers_ill_withsrc_v6(conn_t *,
    const in6_addr_t *, const in6_addr_t *, ill_t *);

extern void		ill_leave_multicast(ill_t *);
extern void		ill_recover_multicast(ill_t *);
extern void		ip_dlur_to_mhi(ill_t *, mblk_t *,
    struct mac_header_info_s *);

/* These make up the data path interface used by ip_output and ip_input */
extern boolean_t	ill_hasmembers_v4(ill_t *, ipaddr_t);
extern boolean_t	ill_hasmembers_v6(ill_t *, const in6_addr_t *);
extern boolean_t	ill_hasmembers_otherzones_v4(ill_t *, ipaddr_t,
    zoneid_t);
extern boolean_t	ill_hasmembers_otherzones_v6(ill_t *,
    const in6_addr_t *, zoneid_t);
extern zoneid_t		ill_hasmembers_nextzone_v4(ill_t *, ipaddr_t, zoneid_t);
extern zoneid_t		ill_hasmembers_nextzone_v6(ill_t *, const in6_addr_t *,
    zoneid_t);

extern	ilm_t		*ip_addmulti(const in6_addr_t *, ill_t *, zoneid_t,
    int *);
extern	int		ip_delmulti(ilm_t *);
extern	int		ip_mforward(mblk_t *, ip_recv_attr_t *);
extern	void		ip_mroute_decap(mblk_t *, ip_recv_attr_t *);
extern	int		ill_join_allmulti(ill_t *);
extern	void		ill_leave_allmulti(ill_t *);
extern	int		ip_join_allmulti(uint_t, boolean_t, ip_stack_t *);
extern	int		ip_leave_allmulti(uint_t, boolean_t, ip_stack_t *);
extern	void		ip_purge_allmulti(ill_t *);
extern	int		ip_mroute_mrt(mblk_t *, ip_stack_t *);
extern	int		ip_mroute_stats(mblk_t *, ip_stack_t *);
extern	int		ip_mroute_vif(mblk_t *, ip_stack_t *);
extern	int		ip_mrouter_done(ip_stack_t *);
extern	int		ip_mrouter_get(int, conn_t *, uchar_t *);
extern	int		ip_mrouter_set(int, conn_t *, int, uchar_t *, int);
extern	void		ip_mrouter_stack_init(ip_stack_t *);
extern	void		ip_mrouter_stack_destroy(ip_stack_t *);

extern	int		ip_opt_add_group(conn_t *, boolean_t,
    const in6_addr_t *, ipaddr_t, uint_t, mcast_record_t, const in6_addr_t *);
extern	int		ip_opt_delete_group(conn_t *, boolean_t,
    const in6_addr_t *, ipaddr_t, uint_t, mcast_record_t, const in6_addr_t *);

extern  int		mrt_ioctl(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);
extern	int		ip_sioctl_msfilter(ipif_t *, sin_t *, queue_t *,
    mblk_t *, ip_ioctl_cmd_t *, void *);
extern	int		ip_copyin_msfilter(queue_t *, mblk_t *);

extern	mblk_t		*pim_input(mblk_t *, ip_recv_attr_t *);
extern	void		update_conn_ill(ill_t *, ip_stack_t *);
extern	void		reset_mrt_ill(ill_t *);
extern	void		reset_mrt_vif_ipif(ipif_t *);
extern	void		igmp_start_timers(unsigned, ip_stack_t *);
extern	void		mld_start_timers(unsigned, ip_stack_t *);
extern	void		ilm_inactive(ilm_t *);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_IP_MULTI_H */

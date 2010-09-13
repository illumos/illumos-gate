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

#ifndef	_INET_IP_RTS_H
#define	_INET_IP_RTS_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Maximum number of route security attributes that can be
 * configured per route destination through the routing
 * socket message.
 */
#define	TSOL_RTSA_REQUEST_MAX	1	/* one per route destination */

/*
 * Flags for RTS queuing operations.
 */
#define	RTSQ_UNDER_IPMP	0x01	/* send only on RTAW_UNDER_IPMP queues */
#define	RTSQ_NORMAL	0x02	/* send only on normal queues */
#define	RTSQ_ALL	(RTSQ_UNDER_IPMP|RTSQ_NORMAL) /* send on all queues */
#define	RTSQ_DEFAULT	0x04	/* use standard filtering */

#ifdef _KERNEL

extern	void	ip_rts_change(int, ipaddr_t, ipaddr_t,
    ipaddr_t, ipaddr_t, ipaddr_t, int, int,
    int, ip_stack_t *);

extern	void	ip_rts_change_v6(int, const in6_addr_t *, const in6_addr_t *,
    const in6_addr_t *, const in6_addr_t *, const in6_addr_t *, int, int, int,
    ip_stack_t *);

extern	void	ip_rts_ifmsg(const ipif_t *, uint_t);

extern	void	ip_rts_xifmsg(const ipif_t *, uint64_t, uint64_t, uint_t);

extern	void	ip_rts_newaddrmsg(int, int, const ipif_t *, uint_t);

extern	int	ip_rts_request(queue_t *, mblk_t *, cred_t *);

extern	void	ip_rts_register(conn_t *);

extern	void	ip_rts_rtmsg(int, ire_t *, int, ip_stack_t *);

extern	void	ip_rts_unregister(conn_t *);

extern	mblk_t	*rts_alloc_msg(int, int, sa_family_t, uint_t);

extern	size_t	rts_data_msg_size(int, sa_family_t, uint_t);

extern	void	rts_fill_msg_v6(int, int, const in6_addr_t *,
    const in6_addr_t *, const in6_addr_t *, const in6_addr_t *,
    const in6_addr_t *, const in6_addr_t *, const in6_addr_t *,
    const ill_t *, mblk_t *, const tsol_gc_t *);

extern	size_t	rts_header_msg_size(int);

extern void	rts_merge_metrics(iulp_t *, const iulp_t *);

extern	void	rts_queue_input(mblk_t *, conn_t *, sa_family_t, uint_t,
    ip_stack_t *);

extern int ip_rts_request_common(mblk_t *mp, conn_t *, cred_t *);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_IP_RTS_H */

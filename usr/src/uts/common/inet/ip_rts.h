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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_INET_IP_RTS_H
#define	_INET_IP_RTS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Maximum number of route security attributes that can be
 * configured per route destination through the routing
 * socket message.
 */
#define	TSOL_RTSA_REQUEST_MAX	1	/* one per route destination */

#ifdef _KERNEL

extern	void	ip_rts_change(int, ipaddr_t, ipaddr_t,
    ipaddr_t, ipaddr_t, ipaddr_t, int, int,
    int, ip_stack_t *);

extern	void	ip_rts_change_v6(int, const in6_addr_t *, const in6_addr_t *,
    const in6_addr_t *, const in6_addr_t *, const in6_addr_t *, int, int, int,
    ip_stack_t *);

extern	void	ip_rts_ifmsg(const ipif_t *);

extern	void	ip_rts_newaddrmsg(int, int, const ipif_t *);

extern	int	ip_rts_request(queue_t *, mblk_t *, cred_t *);

extern	void	ip_rts_register(conn_t *);

extern	void	ip_rts_rtmsg(int, ire_t *, int, ip_stack_t *);

extern	void	ip_rts_unregister(conn_t *);

extern	mblk_t	*rts_alloc_msg(int, int, sa_family_t, uint_t);

extern	size_t	rts_data_msg_size(int, sa_family_t, uint_t);

extern	void	rts_fill_msg_v6(int, int, const in6_addr_t *,
    const in6_addr_t *, const in6_addr_t *, const in6_addr_t *,
    const in6_addr_t *, const in6_addr_t *, const ipif_t *, mblk_t *,
    uint_t, const tsol_gc_t *);

extern	size_t	rts_header_msg_size(int);

extern	void	rts_queue_input(mblk_t *, queue_t *, sa_family_t,
    ip_stack_t *);
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_IP_RTS_H */

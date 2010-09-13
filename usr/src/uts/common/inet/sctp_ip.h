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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved
 */

#ifndef _INET_SCTP_IP_H
#define	_INET_SCTP_IP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/sctp.h>
#include <inet/sctp/sctp_stack.h>

#define	SCTP_COMMON_HDR_LENGTH	12	/* SCTP common header length */

/* SCTP routines for IP to call. */
extern void ip_fanout_sctp(mblk_t *, ipha_t *, ip6_t *, uint32_t,
    ip_recv_attr_t *);
extern void sctp_ddi_g_init(void);
extern void sctp_ddi_g_destroy(void);
extern conn_t *sctp_find_conn(in6_addr_t *, in6_addr_t *, uint32_t,
    zoneid_t, iaflags_t, sctp_stack_t *);
extern conn_t *sctp_fanout(in6_addr_t *, in6_addr_t *, uint32_t,
    ip_recv_attr_t *, mblk_t *, sctp_stack_t *, sctp_hdr_t *);

extern void sctp_input(conn_t *, ipha_t *, ip6_t *, mblk_t *, ip_recv_attr_t *);
extern void sctp_ootb_input(mblk_t *, ip_recv_attr_t *, ip_stack_t *);
extern void sctp_hash_init(sctp_stack_t *);
extern void sctp_hash_destroy(sctp_stack_t *);
extern uint32_t sctp_cksum(mblk_t *, int);
extern mblk_t *sctp_snmp_get_mib2(queue_t *, mblk_t *, sctp_stack_t *);
extern void sctp_free(conn_t *);

/*
 * SCTP maintains a list of ILLs/IPIFs, these functions are provided by
 * SCTP to keep its interface list up to date.
 */
extern void sctp_update_ill(ill_t *, int);
extern void sctp_update_ipif(ipif_t *, int);
extern void sctp_move_ipif(ipif_t *, ill_t *, ill_t *);
extern void sctp_update_ipif_addr(ipif_t *, in6_addr_t);
extern void sctp_ill_reindex(ill_t *, uint_t);

#define	SCTP_ILL_INSERT		1
#define	SCTP_ILL_REMOVE		2
#define	SCTP_IPIF_REMOVE	3
#define	SCTP_IPIF_UP		4
#define	SCTP_IPIF_DOWN		5
#define	SCTP_IPIF_UPDATE	6

/* IP routines for SCTP to call. */
extern void ip_fanout_sctp_raw(mblk_t *, ipha_t *, ip6_t *, uint32_t,
    ip_recv_attr_t *);

#ifdef __cplusplus
}
#endif

#endif /* _INET_SCTP_IP_H */

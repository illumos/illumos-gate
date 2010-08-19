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
 */

#ifndef _IP_ARP_H
#define	_IP_ARP_H

/*
 * Data-structures and functions related to the IP STREAMS queue that handles
 * packets with the SAP set to 0x806 (ETHERTYPE_ARP).
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <inet/ip.h>
#include <inet/ip_ndp.h>
#include <sys/stream.h>

#ifdef _KERNEL
extern struct streamtab dummymodinfo;

struct arl_ill_common_s;
/*
 * The arl_s structure tracks the state of the associated ARP stream.
 */
typedef struct arl_s {
	queue_t		*arl_rq;
	queue_t		*arl_wq;
	ip_stack_t	*arl_ipst;
	zoneid_t	arl_zoneid;
	cred_t		*arl_credp;
	ip_m_t		arl_media;
	struct arl_ill_common_s *arl_common;
	int		arl_muxid;
	uint_t		arl_ppa;
	t_uscalar_t	arl_sap;
	t_uscalar_t	arl_sap_length;
	uint_t	arl_phys_addr_length;
	char		*arl_name;
	int		arl_name_length;
	t_uscalar_t	arl_mactype;
#define	arl_first_mp_to_free	arl_dlpi_deferred
	mblk_t		*arl_dlpi_deferred;
	mblk_t		*arl_unbind_mp;
	mblk_t		*arl_detach_mp;
#define	arl_last_mp_to_free	arl_detach_mp
	uint_t		arl_state_flags;
	uint_t
		arl_needs_attach:1,
		arl_dlpi_style_set:1,
		arl_pad_to_bit_31:30;
	uint_t		arl_refcnt;
	kcondvar_t	arl_cv;
	t_uscalar_t	arl_dlpi_pending;
	kmutex_t	arl_lock;
	int		arl_error;
} arl_t;

/*
 * The arl_ill_common_t structure is a super-structure that contains pointers
 * to a pair of matching ill_t, arl_t structures. Given an arl_t (or
 * ill_t) the corresponding ill_t (or arl_t) must be obtained by
 * synchronizing on the ai_lock,  and ensuring that the desired ill/arl
 * pointer is non-null, not condemned. The arl_ill_common_t is allocated in
 * arl_init() and freed only when both the ill_t and the arl_t structures
 * become NULL.
 * Lock hierarchy: the ai_lock must be take before the ill_lock or arl_lock.
 */

typedef struct arl_ill_common_s {
	kmutex_t	ai_lock;
	ill_t		*ai_ill;
	arl_t		*ai_arl;
	kcondvar_t	ai_ill_unplumb_done; /* sent from ip_modclose() */
} arl_ill_common_t;

extern	boolean_t	arp_no_defense;

extern	struct module_info arp_mod_info;
extern	int		arp_ll_up(ill_t *);
extern	int		arp_ll_down(ill_t *);
extern	boolean_t	arp_announce(ncec_t *);
extern	boolean_t	arp_probe(ncec_t *);
extern	int		arp_request(ncec_t *, in_addr_t, ill_t *);
extern	void		arp_failure(mblk_t *, ip_recv_attr_t *);
extern	int		arl_wait_for_info_ack(arl_t *);
extern	int		arl_init(queue_t *, arl_t *);
extern	void		arl_set_muxid(ill_t *, int);
extern	int		arl_get_muxid(ill_t *);
extern	void		arp_send_replumb_conf(ill_t *);
extern	void		arp_unbind_complete(ill_t *);
extern  ill_t		*arl_to_ill(arl_t *);
extern	uint32_t	arp_hw_type(t_uscalar_t);
#endif

#define	ARP_RETRANS_TIMER	500 /* time in milliseconds */

/* The following are arl_state_flags */
#define	ARL_LL_SUBNET_PENDING	0x01	/* Waiting for DL_INFO_ACK from drv */
#define	ARL_CONDEMNED		0x02	/* No more new ref's to the ILL */
#define	ARL_DL_UNBIND_IN_PROGRESS	0x04	/* UNBIND_REQ is sent */
#define	ARL_LL_BIND_PENDING	0x0020	/* BIND sent */
#define	ARL_LL_UP		0x0040	/* BIND acked */
#define	ARL_LL_DOWN		0x0080
#define	ARL_LL_UNBOUND		0x0100	/* UNBIND acked */
#define	ARL_LL_REPLUMBING	0x0200	/* replumb in progress */

#ifdef __cplusplus
}
#endif

#endif /* _IP_ARP_H */

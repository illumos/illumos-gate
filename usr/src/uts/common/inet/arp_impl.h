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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_ARP_IMPL_H
#define	_ARP_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#include <sys/types.h>
#include <sys/stream.h>
#include <net/if.h>
#include <sys/netstack.h>

/* ARP kernel hash size; used for mdb support */
#define	ARP_HASH_SIZE	256

/* Named Dispatch Parameter Management Structure */
typedef struct arpparam_s {
	uint32_t	arp_param_min;
	uint32_t	arp_param_max;
	uint32_t	arp_param_value;
	char		*arp_param_name;
} arpparam_t;

/* ARL Structure, one per link level device */
typedef struct arl_s {
	struct arl_s	*arl_next;		/* ARL chain at arl_g_head */
	queue_t		*arl_rq;		/* Read queue pointer */
	queue_t		*arl_wq;		/* Write queue pointer */
	t_uscalar_t	arl_ppa;		/* DL_ATTACH parameter */
	char		arl_name[LIFNAMSIZ];	/* Lower level name */
	mblk_t		*arl_unbind_mp;
	mblk_t		*arl_detach_mp;
	t_uscalar_t	arl_provider_style;	/* From DL_INFO_ACK */
	mblk_t		*arl_queue;		/* Queued commands head */
	mblk_t		*arl_queue_tail;	/* Queued commands tail */
	uint32_t	arl_flags;		/* ARL_F_* values below */
	t_uscalar_t	arl_dlpi_pending;	/* pending DLPI request */
	mblk_t		*arl_dlpi_deferred;	/* Deferred DLPI messages */
	uint_t		arl_state;		/* lower interface state */
	uint_t		arl_closing : 1;	/* stream is closing */
	uint32_t	arl_index;		/* instance number */
	struct arlphy_s	*arl_phy;		/* physical info, if any */
} arl_t;

/*
 * There is no field to get from an arl_t to an arp_stack_t, but this
 * macro does it.
 */
#define	ARL_TO_ARPSTACK(_arl)	(((ar_t *)(_arl)->arl_rq->q_ptr)->ar_as)

/* ARL physical info structure for a link level device */
typedef struct arlphy_s {
	uint32_t	ap_arp_hw_type;		/* hardware type */
	uchar_t		*ap_arp_addr;		/* multicast address to use */
	uchar_t		*ap_hw_addr;		/* hardware address */
	uint32_t	ap_hw_addrlen;		/* hardware address length */
	mblk_t		*ap_xmit_mp;		/* DL_UNITDATA_REQ template */
	t_uscalar_t	ap_xmit_addroff;	/* address offset in xmit_mp */
	t_uscalar_t	ap_xmit_sapoff;		/* sap offset in xmit_mp */
	t_scalar_t	ap_saplen;		/* sap length */
	clock_t		ap_defend_start;	/* start of 1-hour period */
	uint_t		ap_defend_count;	/* # of unbidden broadcasts */
	uint_t		ap_notifies : 1,	/* handles DL_NOTE_LINK */
			ap_link_down : 1;	/* DL_NOTE status */
} arlphy_t;

/* ARP Cache Entry */
typedef struct ace_s {
	struct ace_s	*ace_next;	/* Hash chain next pointer */
	struct ace_s	**ace_ptpn;	/* Pointer to previous next */
	struct arl_s	*ace_arl;	/* Associated arl */
	uint32_t	ace_proto;	/* Protocol for this ace */
	uint32_t	ace_flags;
	uchar_t		*ace_proto_addr;
	uint32_t	ace_proto_addr_length;
	uchar_t		*ace_proto_mask; /* Mask for matching addr */
	uchar_t		*ace_proto_extract_mask; /* For mappings */
	uchar_t		*ace_hw_addr;
	uint32_t	ace_hw_addr_length;
	uint32_t	ace_hw_extract_start;	/* For mappings */
	mblk_t		*ace_mp;		/* mblk we are in */
	mblk_t		*ace_query_mp;		/* outstanding query chain */
	clock_t		ace_last_bcast;		/* last broadcast Response */
	clock_t		ace_xmit_interval;
	int		ace_xmit_count;
} ace_t;

#define	ARPHOOK_INTERESTED_PHYSICAL_IN(as)	\
	(as->as_arp_physical_in_event.he_interested)
#define	ARPHOOK_INTERESTED_PHYSICAL_OUT(as)	\
	(as->as_arp_physical_out_event.he_interested)

#define	ARP_HOOK_IN(_hook, _event, _ilp, _hdr, _fm, _m, as)	\
								\
	if ((_hook).he_interested) {                       	\
		hook_pkt_event_t info;                          \
								\
		info.hpe_protocol = as->as_net_data;		\
		info.hpe_ifp = _ilp;                       	\
		info.hpe_ofp = 0;                       	\
		info.hpe_hdr = _hdr;                            \
		info.hpe_mp = &(_fm);                           \
		info.hpe_mb = _m;                               \
		if (hook_run(as->as_net_data->netd_hooks,	\
		    _event, (hook_data_t)&info) != 0) {		\
			if (_fm != NULL) {                      \
				freemsg(_fm);                   \
				_fm = NULL;                     \
			}                                       \
			_hdr = NULL;                            \
			_m = NULL;                              \
		} else {                                        \
			_hdr = info.hpe_hdr;                    \
			_m = info.hpe_mb;                       \
		}                                               \
	}

#define	ARP_HOOK_OUT(_hook, _event, _olp, _hdr, _fm, _m, as)	\
								\
	if ((_hook).he_interested) {                       	\
		hook_pkt_event_t info;                          \
								\
		info.hpe_protocol = as->as_net_data;		\
		info.hpe_ifp = 0;                       	\
		info.hpe_ofp = _olp;                       	\
		info.hpe_hdr = _hdr;                            \
		info.hpe_mp = &(_fm);                           \
		info.hpe_mb = _m;                               \
		if (hook_run(as->as_net_data->netd_hooks,	\
		    _event, (hook_data_t)&info) != 0) {		\
			if (_fm != NULL) {                      \
				freemsg(_fm);                   \
				_fm = NULL;                     \
			}                                       \
			_hdr = NULL;                            \
			_m = NULL;                              \
		} else {                                        \
			_hdr = info.hpe_hdr;                    \
			_m = info.hpe_mb;                       \
		}                                               \
	}

#define	ACE_EXTERNAL_FLAGS_MASK \
	(ACE_F_PERMANENT | ACE_F_PUBLISH | ACE_F_MAPPING | ACE_F_MYADDR | \
	ACE_F_AUTHORITY)

/*
 * ARP stack instances
 */
struct arp_stack {
	netstack_t	*as_netstack;	/* Common netstack */
	void		*as_head;	/* AR Instance Data List Head */
	caddr_t		as_nd;		/* AR Named Dispatch Head */
	struct arl_s	*as_arl_head;	/* ARL List Head */
	arpparam_t	*as_param_arr; 	/* ndd variable table */

	/* ARP Cache Entry Hash Table */
	ace_t	*as_ce_hash_tbl[ARP_HASH_SIZE];
	ace_t	*as_ce_mask_entries;

	/*
	 * With the introduction of netinfo (neti kernel module),
	 * it is now possible to access data structures in the ARP module
	 * without the code being executed in the context of the IP module,
	 * thus there is no locking being enforced through the use of STREAMS.
	 * as_arl_lock is used to protect as_arl_head list.
	 */
	krwlock_t	as_arl_lock;

	uint32_t	as_arp_index_counter;
	uint32_t	as_arp_counter_wrapped;

	/* arp_neti.c */
	hook_family_t	as_arproot;

	/*
	 * Hooks for ARP
	 */
	hook_event_t	as_arp_physical_in_event;
	hook_event_t	as_arp_physical_out_event;
	hook_event_t	as_arp_nic_events;

	hook_event_token_t	as_arp_physical_in;
	hook_event_token_t	as_arp_physical_out;
	hook_event_token_t	as_arpnicevents;

	net_handle_t	as_net_data;
};
typedef struct arp_stack arp_stack_t;

#define	ARL_F_NOARP	0x01

#define	ARL_S_DOWN	0x00
#define	ARL_S_PENDING	0x01
#define	ARL_S_UP	0x02

/* AR Structure, one per upper stream */
typedef struct ar_s {
	queue_t		*ar_rq;	/* Read queue pointer */
	queue_t		*ar_wq;	/* Write queue pointer */
	arl_t		*ar_arl;	/* Associated arl */
	cred_t		*ar_credp;	/* Credentials associated w/ open */
	struct ar_s	*ar_arl_ip_assoc;	/* ARL - IP association */
	uint32_t
			ar_ip_acked_close : 1,	/* IP has acked the close */
			ar_on_ill_stream : 1;	/* Module below is IP */
	arp_stack_t	*ar_as;
} ar_t;

extern void	arp_hook_init(arp_stack_t *);
extern void	arp_hook_destroy(arp_stack_t *);
extern void	arp_net_init(arp_stack_t *, netstackid_t);
extern void	arp_net_shutdown(arp_stack_t *);
extern void	arp_net_destroy(arp_stack_t *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _ARP_IMPL_H */

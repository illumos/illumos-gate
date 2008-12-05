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

#ifndef	_SYS_MAC_IMPL_H
#define	_SYS_MAC_IMPL_H

#include <sys/modhash.h>
#include <sys/mac_client.h>
#include <sys/mac_provider.h>
#include <net/if.h>
#include <sys/mac_flow_impl.h>
#include <netinet/ip6.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct mac_margin_req_s	mac_margin_req_t;

struct mac_margin_req_s {
	mac_margin_req_t	*mmr_nextp;
	uint_t			mmr_ref;
	uint32_t		mmr_margin;
};

/* Generic linked chain type */
typedef	struct mac_chain_s {
	struct mac_chain_s	*next;
	void			*item;
} mac_chain_t;

/*
 * Generic mac callback list manipulation structures and macros. The mac_cb_t
 * represents a general callback list element embedded in a particular
 * data structure such as a mac_notify_cb_t or a mac_promisc_impl_t.
 * The mac_cb_info_t represents general information about list walkers.
 * Please see the comments above mac_callback_add for more information.
 */
/* mcb_flags */
#define	MCB_CONDEMNED		0x1		/* Logically deleted */
#define	MCB_NOTIFY_CB_T		0x2
#define	MCB_TX_NOTIFY_CB_T	0x4

typedef struct mac_cb_s {
	struct mac_cb_s		*mcb_nextp;	/* Linked list of callbacks */
	void			*mcb_objp;	/* Ptr to enclosing object  */
	size_t			mcb_objsize;	/* Sizeof the enclosing obj */
	uint_t			mcb_flags;
} mac_cb_t;

typedef struct mac_cb_info_s {
	kmutex_t	*mcbi_lockp;
	kcondvar_t	mcbi_cv;
	uint_t		mcbi_del_cnt;		/* Deleted callback cnt */
	uint_t		mcbi_walker_cnt;	/* List walker count */
} mac_cb_info_t;

typedef struct mac_notify_cb_s {
	mac_cb_t	mncb_link;		/* Linked list of callbacks */
	mac_notify_t	mncb_fn;		/* callback function */
	void		*mncb_arg;		/* callback argument */
	struct mac_impl_s *mncb_mip;
} mac_notify_cb_t;

/*
 * mac_callback_add(listinfo, listhead, listelement)
 * mac_callback_remove(listinfo, listhead, listelement)
 */
typedef boolean_t (*mcb_func_t)(mac_cb_info_t *, mac_cb_t **, mac_cb_t *);

#define	MAC_CALLBACK_WALKER_INC(mcbi) {				\
	mutex_enter((mcbi)->mcbi_lockp);			\
	(mcbi)->mcbi_walker_cnt++;				\
	mutex_exit((mcbi)->mcbi_lockp);				\
}

#define	MAC_CALLBACK_WALKER_INC_HELD(mcbi)	(mcbi)->mcbi_walker_cnt++;

#define	MAC_CALLBACK_WALKER_DCR(mcbi, headp) {			\
	mac_cb_t	*rmlist;				\
								\
	mutex_enter((mcbi)->mcbi_lockp);			\
	if (--(mcbi)->mcbi_walker_cnt == 0 && (mcbi)->mcbi_del_cnt != 0) { \
		rmlist = mac_callback_walker_cleanup((mcbi), headp);	\
		mac_callback_free(rmlist);			\
		cv_broadcast(&(mcbi)->mcbi_cv);			\
	}							\
	mutex_exit((mcbi)->mcbi_lockp);				\
}

#define	MAC_PROMISC_WALKER_INC(mip)				\
	MAC_CALLBACK_WALKER_INC(&(mip)->mi_promisc_cb_info)

#define	MAC_PROMISC_WALKER_DCR(mip) {				\
	mac_cb_info_t	*mcbi;					\
								\
	mcbi = &(mip)->mi_promisc_cb_info;			\
	mutex_enter(mcbi->mcbi_lockp);				\
	if (--mcbi->mcbi_walker_cnt == 0 && mcbi->mcbi_del_cnt != 0) { \
		i_mac_promisc_walker_cleanup(mip);		\
		cv_broadcast(&mcbi->mcbi_cv);			\
	}							\
	mutex_exit(mcbi->mcbi_lockp);				\
}

typedef struct mactype_s {
	const char	*mt_ident;
	uint32_t	mt_ref;
	uint_t		mt_type;
	uint_t		mt_nativetype;
	size_t		mt_addr_length;
	uint8_t		*mt_brdcst_addr;
	mactype_ops_t	mt_ops;
	mac_stat_info_t	*mt_stats;	/* array of mac_stat_info_t elements */
	size_t		mt_statcount;	/* number of elements in mt_stats */
	mac_ndd_mapping_t *mt_mapping;
	size_t		mt_mappingcount;
} mactype_t;

/*
 * Multiple rings implementation.
 */
typedef	enum {
	MAC_GROUP_STATE_UNINIT	= 0,	/* initial state of data structure */
	MAC_GROUP_STATE_REGISTERED,	/* hooked with h/w group */
	MAC_GROUP_STATE_RESERVED,	/* group is reserved and opened */
	MAC_GROUP_STATE_SHARED		/* default group shared among */
					/* multiple mac clients */
} mac_group_state_t;

typedef	struct mac_ring_s mac_ring_t;
typedef	struct mac_group_s mac_group_t;

/*
 * Ring data structure for ring control and management.
 */
typedef enum {
	MR_FREE,		/* Available for assignment to flows */
	MR_NEWLY_ADDED,		/* Just assigned to another group */
	MR_INUSE		/* Assigned to an SRS */
} mac_ring_state_t;

/* mr_flag values */
#define	MR_INCIPIENT	0x1
#define	MR_CONDEMNED	0x2
#define	MR_QUIESCE	0x4

struct mac_ring_s {
	int			mr_index;	/* index in the original list */
	mac_ring_type_t		mr_type;	/* ring type */
	mac_ring_t		*mr_next;	/* next ring in the chain */
	mac_group_handle_t	mr_gh;		/* reference to group */

	mac_classify_type_t	mr_classify_type;	/* HW vs SW */
	struct mac_soft_ring_set_s *mr_srs;		/* associated SRS */
	uint_t			mr_refcnt;		/* Ring references */
	/* ring generation no. to guard against drivers using stale rings */
	uint64_t		mr_gen_num;

	kmutex_t		mr_lock;
	kcondvar_t		mr_cv;			/* mr_lock */
	mac_ring_state_t	mr_state;		/* mr_lock */
	uint_t			mr_flag;		/* mr_lock */

	mac_ring_info_t		mr_info;	/* driver supplied info */
};
#define	mr_driver		mr_info.mri_driver
#define	mr_start		mr_info.mri_start
#define	mr_stop			mr_info.mri_stop

#define	MAC_RING_MARK(mr, flag)		\
	(mr)->mr_flag |= flag;

#define	MAC_RING_UNMARK(mr, flag)	\
	(mr)->mr_flag &= ~flag;

/*
 * Reference hold and release on mac_ring_t 'mr'
 */
#define	MR_REFHOLD_LOCKED(mr)		{		\
	ASSERT(MUTEX_HELD(&mr->mr_lock));		\
	(mr)->mr_refcnt++;				\
}

#define	MR_REFRELE(mr)		{	 		\
	mutex_enter(&(mr)->mr_lock);			\
	ASSERT((mr)->mr_refcnt != 0);			\
	(mr)->mr_refcnt--;				\
	if ((mr)->mr_refcnt == 0 &&			\
	    ((mr)->mr_flag & (MR_CONDEMNED | MR_QUIESCE))) \
		cv_signal(&(mr)->mr_cv);		\
	mutex_exit(&(mr)->mr_lock);			\
}

/*
 * Per mac client flow information associated with a RX group.
 * The entire structure is SL protected.
 */
typedef struct mac_grp_client {
	struct mac_grp_client		*mgc_next;
	struct mac_client_impl_s	*mgc_client;
} mac_grp_client_t;

#define	MAC_RX_GROUP_NO_CLIENT(g)	((g)->mrg_clients == NULL)

#define	MAC_RX_GROUP_ONLY_CLIENT(g)			\
	((((g)->mrg_clients != NULL) &&			\
	((g)->mrg_clients->mgc_next == NULL)) ?		\
	(g)->mrg_clients->mgc_client : NULL)

/*
 * Common ring group data structure for ring control and management.
 * The entire structure is SL protected
 */
struct mac_group_s {
	int			mrg_index;	/* index in the list */
	mac_ring_type_t		mrg_type;	/* ring type */
	mac_group_state_t	mrg_state;	/* state of the group */
	mac_group_t		*mrg_next;	/* next ring in the chain */
	mac_handle_t		mrg_mh;		/* reference to MAC */
	mac_ring_t		*mrg_rings;	/* grouped rings */
	uint_t			mrg_cur_count;	/* actual size of group */

	mac_grp_client_t	*mrg_clients;	/* clients list */

	struct mac_client_impl_s *mrg_tx_client; /* TX client pointer */
	mac_group_info_t	mrg_info;	/* driver supplied info */
};

#define	mrg_driver		mrg_info.mgi_driver
#define	mrg_start		mrg_info.mgi_start
#define	mrg_stop		mrg_info.mgi_stop

#define	GROUP_INTR_HANDLE(g)		(g)->mrg_info.mgi_intr.mi_handle
#define	GROUP_INTR_ENABLE_FUNC(g)	(g)->mrg_info.mgi_intr.mi_enable
#define	GROUP_INTR_DISABLE_FUNC(g)	(g)->mrg_info.mgi_intr.mi_disable

#define	MAC_DEFAULT_GROUP(mh)		(((mac_impl_t *)mh)->mi_rx_groups)

#define	MAC_RING_TX_DEFAULT(mip, mp)			\
	((mip->mi_default_tx_ring == NULL) ?		\
	mip->mi_tx(mip->mi_driver, mp) :		\
	mac_ring_tx(mip->mi_default_tx_ring, mp))

#define	MAC_TX(mip, ring, mp, mcip) {					\
	/*								\
	 * If the MAC client has a bound Hybrid I/O share,		\
	 * send the packet through the default tx ring, since		\
	 * the tx rings of this client are now mapped in the		\
	 * guest domain and not accessible from this domain.		\
	 */								\
	if (mcip->mci_share_bound || (ring == NULL))			\
		mp = MAC_RING_TX_DEFAULT(mip, mp);			\
	else								\
		mp = mac_ring_tx(ring, mp);				\
}

/* mci_tx_flag */
#define	MCI_TX_QUIESCE	0x1

typedef struct mac_factory_addr_s {
	boolean_t		mfa_in_use;
	uint8_t			mfa_addr[MAXMACADDRLEN];
	struct mac_client_impl_s	*mfa_client;
} mac_factory_addr_t;

typedef struct mac_mcast_addrs_s {
	struct mac_mcast_addrs_s	*mma_next;
	uint8_t				mma_addr[MAXMACADDRLEN];
	int				mma_ref;
} mac_mcast_addrs_t;

typedef enum {
	MAC_ADDRESS_TYPE_UNICAST_CLASSIFIED = 1,	/* hardware steering */
	MAC_ADDRESS_TYPE_UNICAST_PROMISC		/* promiscuous mode */
} mac_address_type_t;

typedef struct mac_impl_s mac_impl_t;

typedef struct mac_address_s {
	mac_address_type_t	ma_type;		/* address type */
	int			ma_nusers;		/* number of users */
							/* of that address */
	struct mac_address_s	*ma_next;		/* next address */
	uint8_t			ma_addr[MAXMACADDRLEN];	/* address value */
	size_t			ma_len;			/* address length */
	mac_group_t		*ma_group;		/* asscociated group */
	mac_impl_t		*ma_mip;		/* MAC handle */
} mac_address_t;

extern krwlock_t i_mac_impl_lock;
extern mod_hash_t *i_mac_impl_hash;
extern kmem_cache_t *i_mac_impl_cachep;
extern uint_t i_mac_impl_count;

/*
 * Each registered MAC is associated with a mac_impl_t structure. The
 * structure represents the undelying hardware, in terms of definition,
 * resources (transmit, receive rings etc.), callback functions etc. It
 * also holds the table of MAC clients that are configured on the device.
 * The table is used for classifying incoming packets in software.
 *
 * The protection scheme uses 2 elements, a coarse serialization mechanism
 * called perimeter and a finer traditional lock based scheme. More details
 * can be found in the big block comment in mac.c.
 *
 * The protection scheme for each member of the mac_impl_t is described below.
 *
 * Write Once Only (WO): Typically these don't change for the lifetime of the
 * data structure. For example something in mac_impl_t that stays the same
 * from mac_register to mac_unregister, or something in a mac_client_impl_t
 * that stays the same from mac_client_open to mac_client_close.
 *
 * Serializer (SL): Protected by the Serializer. All SLOP operations on a
 * mac endpoint go through the serializer. MTOPs don't care about reading
 * these fields atomically.
 *
 * Lock: Traditional mutex/rw lock. Modify operations still go through the
 * mac serializer, the lock helps synchronize readers with writers.
 */
struct mac_impl_s {
	krwlock_t		mi_rw_lock;
	char			mi_name[LIFNAMSIZ];	/* WO */
	uint32_t		mi_state_flags;
	void			*mi_driver;		/* Driver private, WO */
	mac_info_t		mi_info;		/* WO */
	mactype_t		*mi_type;		/* WO */
	void			*mi_pdata;		/* WO */
	size_t			mi_pdata_size;		/* WO */
	mac_callbacks_t		*mi_callbacks;		/* WO */
	dev_info_t		*mi_dip;		/* WO */
	uint32_t		mi_ref;			/* i_mac_impl_lock */
	uint_t			mi_active;		/* SL */
	link_state_t		mi_linkstate;		/* none */
	link_state_t		mi_lastlinkstate;	/* none */
	uint_t			mi_promisc;		/* SL */
	uint_t			mi_devpromisc;		/* SL */
	kmutex_t		mi_lock;
	uint8_t			mi_addr[MAXMACADDRLEN];	/* mi_rw_lock */
	uint8_t			mi_dstaddr[MAXMACADDRLEN]; /* mi_rw_lock */

	/*
	 * The mac perimeter. All client initiated create/modify operations
	 * on a mac end point go through this.
	 */
	kmutex_t		mi_perim_lock;
	kthread_t		*mi_perim_owner;	/* mi_perim_lock */
	uint_t			mi_perim_ocnt;		/* mi_perim_lock */
	kcondvar_t		mi_perim_cv;		/* mi_perim_lock */

	/* mac notification callbacks */
	kmutex_t		mi_notify_lock;
	mac_cb_info_t		mi_notify_cb_info;	/* mi_notify_lock */
	mac_cb_t		*mi_notify_cb_list;	/* mi_notify_lock */
	kthread_t		*mi_notify_thread;	/* mi_notify_lock */
	uint_t			mi_notify_bits;		/* mi_notify_lock */

	uint32_t		mi_v12n_level;		/* Virt'ion readiness */

	/*
	 * RX groups, ring capability
	 * Fields of this block are SL protected.
	 */
	mac_group_type_t	mi_rx_group_type;	/* grouping type */
	uint_t			mi_rx_group_count;
	mac_group_t		*mi_rx_groups;

	mac_capab_rings_t	mi_rx_rings_cap;

	/*
	 * TX groups and ring capability, SL Protected.
	 */
	mac_group_type_t	mi_tx_group_type;	/* grouping type */
	uint_t			mi_tx_group_count;
	uint_t			mi_tx_group_free;
	mac_group_t		*mi_tx_groups;

	mac_capab_rings_t	mi_tx_rings_cap;

	mac_ring_handle_t	mi_default_tx_ring;

	/*
	 * MAC address list. SL protected.
	 */
	mac_address_t		*mi_addresses;

	/*
	 * This MAC's table of sub-flows
	 */
	flow_tab_t		*mi_flow_tab;		/* WO */

	kstat_t			*mi_ksp;		/* WO */
	uint_t			mi_kstat_count;		/* WO */
	uint_t			mi_nactiveclients;	/* SL */

	/* for broadcast and multicast support */
	struct mac_mcast_addrs_s *mi_mcast_addrs;	/* mi_rw_lock */
	struct mac_bcast_grp_s *mi_bcast_grp;		/* mi_rw_lock */
	uint_t			mi_bcast_ngrps;		/* mi_rw_lock */

	/* list of MAC clients which opened this MAC */
	struct mac_client_impl_s *mi_clients_list;	/* mi_rw_lock */
	uint_t			mi_nclients;		/* mi_rw_lock */

	uint32_t		mi_margin;		/* mi_rw_lock */
	uint_t			mi_sdu_min;		/* mi_rw_lock */
	uint_t			mi_sdu_max;		/* mi_rw_lock */

	/*
	 * Cache of factory MAC addresses provided by the driver. If
	 * the driver doesn't provide multiple factory MAC addresses,
	 * the mi_factory_addr is set to NULL, and mi_factory_addr_num
	 * is set to zero.
	 */
	mac_factory_addr_t	*mi_factory_addr;	/* mi_rw_lock */
	uint_t			mi_factory_addr_num;	/* mi_rw_lock */

	/* for promiscuous mode support */
	kmutex_t		mi_promisc_lock;
	mac_cb_t		*mi_promisc_list;	/* mi_promisc_lock */
	mac_cb_info_t		mi_promisc_cb_info;	/* mi_promisc_lock */

	/* cache of rings over this mac_impl */
	kmutex_t		mi_ring_lock;
	mac_ring_t		*mi_ring_freelist;	/* mi_ring_lock */

	/*
	 * These are used for caching the properties, if any, for the
	 * primary MAC client. If the MAC client is not yet in place
	 * when the properties are set then we cache them here to be
	 * applied to the MAC client when it is created.
	 */
	mac_resource_props_t	mi_resource_props;	/* SL */

	minor_t			mi_minor;		/* WO */
	dev_t			mi_phy_dev;		/* WO */
	uint32_t		mi_oref;		/* SL */
	uint32_t		mi_unsup_note;		/* WO */
	/*
	 * List of margin value requests added by mac clients. This list is
	 * sorted: the first one has the greatest value.
	 */
	mac_margin_req_t	*mi_mmrp;
	mac_priv_prop_t		*mi_priv_prop;
	uint_t			mi_priv_prop_count;

	/*
	 * Hybrid I/O related definitions.
	 */
	mac_capab_share_t	mi_share_capab;

/* This should be the last block in this structure */
#ifdef DEBUG
#define	MAC_PERIM_STACK_DEPTH	15
	int			mi_perim_stack_depth;
	pc_t			mi_perim_stack[MAC_PERIM_STACK_DEPTH];
#endif
};

/* for mi_state_flags */
#define	MIS_DISABLED		0x0001
#define	MIS_IS_VNIC		0x0002
#define	MIS_IS_AGGR		0x0004
#define	MIS_NOTIFY_DONE		0x0008
#define	MIS_EXCLUSIVE		0x0010
#define	MIS_EXCLUSIVE_HELD	0x0020
#define	MIS_LEGACY		0x0040

#define	mi_getstat	mi_callbacks->mc_getstat
#define	mi_start	mi_callbacks->mc_start
#define	mi_stop		mi_callbacks->mc_stop
#define	mi_open		mi_callbacks->mc_open
#define	mi_close	mi_callbacks->mc_close
#define	mi_setpromisc	mi_callbacks->mc_setpromisc
#define	mi_multicst	mi_callbacks->mc_multicst
#define	mi_unicst	mi_callbacks->mc_unicst
#define	mi_tx		mi_callbacks->mc_tx
#define	mi_ioctl	mi_callbacks->mc_ioctl
#define	mi_getcapab	mi_callbacks->mc_getcapab

typedef struct mac_notify_task_arg {
	mac_impl_t		*mnt_mip;
	mac_notify_type_t	mnt_type;
	mac_ring_t		*mnt_ring;
} mac_notify_task_arg_t;

typedef enum {
	MAC_RX_NO_RESERVE,
	MAC_RX_RESERVE_DEFAULT,
	MAC_RX_RESERVE_NONDEFAULT
} mac_rx_group_reserve_type_t;

/*
 * XXX All MAC_DBG_PRTs must be replaced with call to dtrace probes. For now
 * it may be easier to have these printfs for easier debugging
 */
#ifdef DEBUG
extern int mac_dbg;
#define	MAC_DBG_PRT(a)	if (mac_dbg > 0) {(void) printf a; }
#else
#define	MAC_DBG_PRT(a)
#endif

/*
 * The mac_perim_handle_t is an opaque type that encodes the 'mip' pointer
 * and whether internally a mac_open was done when acquiring the perimeter.
 */
#define	MAC_ENCODE_MPH(mph, mh, need_close)		\
	(mph) = (mac_perim_handle_t)((uintptr_t)(mh) | need_close)

#define	MAC_DECODE_MPH(mph, mip, need_close) {		\
	mip = (mac_impl_t *)(((uintptr_t)mph) & ~0x1);	\
	(need_close) = ((uintptr_t)mph & 0x1);		\
}

typedef struct mac_client_impl_s mac_client_impl_t;

extern void	mac_init(void);
extern int	mac_fini(void);

extern void	mac_stat_create(mac_impl_t *);
extern void	mac_stat_destroy(mac_impl_t *);
extern uint64_t	mac_stat_default(mac_impl_t *, uint_t);
extern void	mac_ndd_ioctl(mac_impl_t *, queue_t *, mblk_t *);
extern void	mac_create_soft_ring_kstats(mac_impl_t *, int32_t);
extern boolean_t mac_ip_hdr_length_v6(mblk_t *, ip6_t *, uint16_t *,
    uint8_t *);

extern mblk_t *mac_copymsgchain_cksum(mblk_t *);
extern mblk_t *mac_fix_cksum(mblk_t *);
extern void mac_packet_print(mac_handle_t, mblk_t *);
extern void mac_rx_deliver(void *, mac_resource_handle_t, mblk_t *,
    mac_header_info_t *);
extern void mac_tx_notify(mac_impl_t *);

extern	boolean_t mac_callback_find(mac_cb_info_t *, mac_cb_t **, mac_cb_t *);
extern	void	mac_callback_add(mac_cb_info_t *, mac_cb_t **, mac_cb_t *);
extern	boolean_t mac_callback_remove(mac_cb_info_t *, mac_cb_t **, mac_cb_t *);
extern	void	mac_callback_remove_wait(mac_cb_info_t *);
extern	void	mac_callback_free(mac_cb_t *);
extern	mac_cb_t *mac_callback_walker_cleanup(mac_cb_info_t *, mac_cb_t **);

/* in mac_bcast.c */
extern void mac_bcast_init(void);
extern void mac_bcast_fini(void);
extern mac_impl_t *mac_bcast_grp_mip(void *);
extern int mac_bcast_add(mac_client_impl_t *, const uint8_t *, uint16_t,
    mac_addrtype_t);
extern void mac_bcast_delete(mac_client_impl_t *, const uint8_t *, uint16_t);
extern void mac_bcast_send(void *, void *, mblk_t *, boolean_t);
extern void mac_bcast_grp_free(void *);
extern void mac_bcast_refresh(mac_impl_t *, mac_multicst_t, void *,
    boolean_t);
extern void mac_client_bcast_refresh(mac_client_impl_t *, mac_multicst_t,
    void *, boolean_t);

/*
 * Grouping functions are used internally by MAC layer.
 */
extern int mac_group_addmac(mac_group_t *, const uint8_t *);
extern int mac_group_remmac(mac_group_t *, const uint8_t *);
extern int mac_rx_group_add_flow(mac_client_impl_t *, flow_entry_t *,
    mac_group_t *);
extern mblk_t *mac_ring_tx(mac_ring_handle_t, mblk_t *);
extern mac_ring_t *mac_reserve_tx_ring(mac_impl_t *, mac_ring_t *);
extern void mac_release_tx_ring(mac_ring_handle_t);
extern mac_group_t *mac_reserve_tx_group(mac_impl_t *, mac_share_handle_t);
extern void mac_release_tx_group(mac_impl_t *, mac_group_t *);

/*
 * MAC address functions are used internally by MAC layer.
 */
extern mac_address_t *mac_find_macaddr(mac_impl_t *, uint8_t *);
extern boolean_t mac_check_macaddr_shared(mac_address_t *);
extern int mac_update_macaddr(mac_address_t *, uint8_t *);
extern void mac_freshen_macaddr(mac_address_t *, uint8_t *);
extern void mac_retrieve_macaddr(mac_address_t *, uint8_t *);
extern void mac_init_macaddr(mac_impl_t *);
extern void mac_fini_macaddr(mac_impl_t *);

/*
 * Flow construction/destruction routines.
 * Not meant to be used by mac clients.
 */
extern int mac_link_flow_init(mac_client_handle_t, flow_entry_t *);
extern void mac_link_flow_clean(mac_client_handle_t, flow_entry_t *);

/*
 * Called from mac_provider.c
 */
extern void mac_fanout_recompute(mac_impl_t *);

/*
 * The following functions are used internally by the MAC layer to
 * add/remove/update flows associated with a mac_impl_t. They should
 * never be used directly by MAC clients.
 */
extern int mac_datapath_setup(mac_client_impl_t *, flow_entry_t *, uint32_t);
extern void mac_datapath_teardown(mac_client_impl_t *, flow_entry_t *,
    uint32_t);
extern void mac_srs_group_setup(mac_client_impl_t *, flow_entry_t *,
    mac_group_t *, uint32_t);
extern void mac_srs_group_teardown(mac_client_impl_t *, flow_entry_t *,
	    uint32_t);
extern int mac_rx_classify_flow_quiesce(flow_entry_t *, void *);
extern int mac_rx_classify_flow_restart(flow_entry_t *, void *);
extern void mac_tx_client_quiesce(mac_client_impl_t *, uint_t);
extern void mac_tx_client_restart(mac_client_impl_t *);
extern void mac_client_quiesce(mac_client_impl_t *);
extern void mac_client_restart(mac_client_impl_t *);

extern void mac_flow_update_priority(mac_client_impl_t *, flow_entry_t *);

extern void mac_flow_rem_subflow(flow_entry_t *);
extern void mac_rename_flow(flow_entry_t *, const char *);
extern void mac_flow_set_name(flow_entry_t *, const char *);

extern mblk_t *mac_add_vlan_tag(mblk_t *, uint_t, uint16_t);
extern mblk_t *mac_add_vlan_tag_chain(mblk_t *, uint_t, uint16_t);
extern mblk_t *mac_strip_vlan_tag_chain(mblk_t *);
extern void mac_pkt_drop(void *, mac_resource_handle_t, mblk_t *, boolean_t);
extern mblk_t *mac_rx_flow(mac_handle_t, mac_resource_handle_t, mblk_t *);

extern void i_mac_share_alloc(mac_client_impl_t *);
extern void i_mac_share_free(mac_client_impl_t *);
extern void i_mac_perim_enter(mac_impl_t *);
extern void i_mac_perim_exit(mac_impl_t *);
extern int i_mac_perim_enter_nowait(mac_impl_t *);
extern void i_mac_tx_srs_notify(mac_impl_t *, mac_ring_handle_t);
extern int mac_hold(const char *, mac_impl_t **);
extern void mac_rele(mac_impl_t *);
extern int i_mac_disable(mac_impl_t *);
extern void i_mac_notify(mac_impl_t *, mac_notify_type_t);
extern void i_mac_notify_exit(mac_impl_t *);
extern int mac_start(mac_impl_t *);
extern void mac_stop(mac_impl_t *);
extern void mac_rx_group_unmark(mac_group_t *, uint_t);
extern void mac_tx_client_flush(mac_client_impl_t *);
extern void mac_tx_client_block(mac_client_impl_t *);
extern void mac_tx_client_unblock(mac_client_impl_t *);
extern int i_mac_promisc_set(mac_impl_t *, boolean_t, mac_promisc_type_t);
extern void i_mac_promisc_walker_cleanup(mac_impl_t *);
extern mactype_t *mactype_getplugin(const char *);
extern void mac_addr_factory_init(mac_impl_t *);
extern void mac_addr_factory_fini(mac_impl_t *);
extern void mac_register_priv_prop(mac_impl_t *, mac_priv_prop_t *, uint_t);
extern void mac_unregister_priv_prop(mac_impl_t *);
extern int mac_init_rings(mac_impl_t *, mac_ring_type_t);
extern void mac_free_rings(mac_impl_t *, mac_ring_type_t);

extern int mac_start_group(mac_group_t *);
extern void mac_stop_group(mac_group_t *);
extern int mac_start_ring(mac_ring_t *);
extern void mac_stop_ring(mac_ring_t *);
extern int mac_add_macaddr(mac_impl_t *, mac_group_t *, uint8_t *);
extern int mac_remove_macaddr(mac_address_t *);

extern void mac_set_rx_group_state(mac_group_t *, mac_group_state_t);
extern void mac_rx_group_add_client(mac_group_t *, mac_client_impl_t *);
extern void mac_rx_group_remove_client(mac_group_t *, mac_client_impl_t *)
;
extern int i_mac_group_add_ring(mac_group_t *, mac_ring_t *, int);
extern void i_mac_group_rem_ring(mac_group_t *, mac_ring_t *, boolean_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MAC_IMPL_H */

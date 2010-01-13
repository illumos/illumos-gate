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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_DLD_IMPL_H
#define	_SYS_DLD_IMPL_H

#include <sys/types.h>
#include <sys/list.h>
#include <sys/ethernet.h>
#include <sys/stream.h>
#include <sys/dlpi.h>
#include <sys/dld.h>
#include <sys/dls_impl.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	DLD_CONTROL_MINOR_NAME	"ctl"
#define	DLD_CONTROL_MINOR	0

#define	DLD_CONTROL	0x00000001
#define	DLD_DLPI	0x00000002

typedef enum {
	DLD_UNITDATA,
	DLD_FASTPATH,
	DLD_RAW
} dld_str_mode_t;

typedef enum {
	DLD_UNINITIALIZED,
	DLD_PASSIVE,
	DLD_ACTIVE
} dld_passivestate_t;

/*
 * The dld_str_t object definition and protection scheme for each member
 * is described below. The framework locking mechanism details are described in
 * mac_impl.h and mac.c
 *
 * Write Once Only (WO): Typically these are initialized when the end point
 * is created or initialized and don't change subsequently
 *
 * Serializer (SL): Protected by the Serializer. All modify operations on an
 * end point go through the serializer. Readers don't care about reading
 * these fields atomically, or readers also use the serializer to see the
 * values atomically.
 *
 * Lock: kmutex_t or kwrlock_t lock. Modify operations still go through the
 * serializer, the lock helps synchronize readers with writers.
 */

struct dld_str_s {					/* Protected by */
	/*
	 * Major number of the device
	 */
	major_t			ds_major;		/* WO */

	/*
	 * Ephemeral minor number for the object.
	 */
	minor_t			ds_minor;		/* WO */

	/*
	 * PPA number this stream is attached to.
	 */
	t_uscalar_t		ds_ppa;			/* SL */

	/*
	 * Read/write queues for the stream which the object represents.
	 */
	queue_t			*ds_rq;			/* WO */
	queue_t			*ds_wq;			/* WO */

	/*
	 * Stream is open to DLD_CONTROL (control node) or
	 * DLD_DLPI (DLS provider) node.
	 */
	uint_t			ds_type;		/* WO */

	/*
	 * The following fields are only used for DLD_DLPI type objects.
	 */

	/*
	 * Current DLPI state.
	 */
	t_uscalar_t		ds_dlstate;		/* SL */

	/*
	 * DLPI style
	 */
	t_uscalar_t		ds_style;		/* WO */

	/*
	 * Currently bound DLSAP.
	 */
	uint16_t		ds_sap;			/* SL */

	/*
	 * Handle of the MAC that is used by the data-link interface.
	 */
	mac_handle_t		ds_mh;			/* SL */
	mac_client_handle_t	ds_mch;			/* SL */

	/*
	 * Promiscuity level information.
	 */
	uint32_t		ds_promisc;		/* SL */
	mac_promisc_handle_t	ds_mph;
	mac_promisc_handle_t	ds_vlan_mph;

	/*
	 * Immutable information of the MAC which the channel is using.
	 */
	const mac_info_t	*ds_mip;		/* SL */

	/*
	 * Current packet priority.
	 */
	uint_t			ds_pri;			/* SL */

	/*
	 * Handle of our MAC notification callback.
	 */
	mac_notify_handle_t	ds_mnh;			/* SL */

	/*
	 * Set of enabled DL_NOTE... notifications. (See dlpi.h).
	 */
	uint32_t		ds_notifications;	/* SL */

	/*
	 * Mode: unitdata, fast-path or raw.
	 */
	dld_str_mode_t		ds_mode;		/* SL */

	/*
	 * Native mode state.
	 */
	boolean_t		ds_native;		/* SL */

	/*
	 * IP polling is operational if this flag is set.
	 */
	boolean_t		ds_polling;		/* SL */
	boolean_t		ds_direct;		/* SL */

	/*
	 * LSO is enabled if ds_lso is set.
	 */
	boolean_t		ds_lso;			/* SL */
	uint64_t		ds_lso_max;		/* SL */

	/*
	 * State of DLPI user: may be active (regular network layer),
	 * passive (snoop-like monitoring), or unknown (not yet
	 * determined).
	 */
	dld_passivestate_t	ds_passivestate;	/* SL */

	/*
	 * Dummy mblk used for flow-control.
	 */
	mblk_t			*ds_tx_flow_mp;		/* ds_lock */

	/*
	 * List of queued DLPI requests. These will be processed
	 * by a taskq thread. This block is protected by ds_lock
	 */
	kmutex_t		ds_lock;
	krwlock_t		ds_rw_lock;
	kcondvar_t		ds_datathr_cv;		/* ds_lock */
	uint_t			ds_datathr_cnt;		/* ds_lock */
	mblk_t			*ds_pending_head;	/* ds_lock */
	mblk_t			*ds_pending_tail;	/* ds_lock */
	kcondvar_t		ds_dlpi_pending_cv;	/* ds_lock */
	uint32_t
				ds_dlpi_pending : 1,	/* ds_lock */
				ds_local	: 1,
				ds_pad		: 30;	/* ds_lock */

	dls_link_t		*ds_dlp;		/* SL */
	dls_multicst_addr_t	*ds_dmap;		/* ds_rw_lock */
	dls_rx_t		ds_rx;			/* ds_lock */
	void			*ds_rx_arg;		/* ds_lock */
	uint_t			ds_nactive;		/* SL */
	dld_str_t		*ds_next;		/* SL */
	dls_head_t		*ds_head;
	dls_dl_handle_t		ds_ddh;
	list_node_t		ds_tqlist;

	/*
	 * driver private data set by the driver when calling dld_str_open().
	 */
	void			*ds_private;

	boolean_t		ds_lowlink;		/* SL */
	boolean_t		ds_nonip;		/* SL */
};


#define	DLD_DATATHR_INC(dsp)	{		\
	ASSERT(MUTEX_HELD(&(dsp)->ds_lock));	\
	dsp->ds_datathr_cnt++;			\
}

#define	DLD_DATATHR_DCR(dsp)	{		\
	mutex_enter(&(dsp)->ds_lock);		\
	(dsp)->ds_datathr_cnt--;		\
	if ((dsp)->ds_datathr_cnt == 0)		\
		cv_broadcast(&(dsp)->ds_datathr_cv);	\
	mutex_exit(&(dsp)->ds_lock);		\
}

/*
 * dld_str.c module.
 */

extern void		dld_str_init(void);
extern int		dld_str_fini(void);
extern dld_str_t	*dld_str_create(queue_t *, uint_t, major_t,
    t_uscalar_t);
extern void		dld_str_destroy(dld_str_t *);
extern int		dld_str_attach(dld_str_t *, t_uscalar_t);
extern void		dld_str_detach(dld_str_t *);
extern void		dld_str_rx_raw(void *, mac_resource_handle_t,
    mblk_t *, mac_header_info_t *);
extern void		dld_str_rx_fastpath(void *, mac_resource_handle_t,
    mblk_t *, mac_header_info_t *);
extern void		dld_str_rx_unitdata(void *, mac_resource_handle_t,
    mblk_t *, mac_header_info_t *);
extern void		dld_str_notify_ind(dld_str_t *);
extern mac_tx_cookie_t	str_mdata_fastpath_put(dld_str_t *, mblk_t *,
    uintptr_t, uint16_t);
extern int		dld_flow_ctl_callb(dld_str_t *, uint64_t,
    int (*func)(), void *);

/*
 * dld_proto.c
 */
extern void		dld_proto(dld_str_t *, mblk_t *);
extern void		dld_proto_unitdata_req(dld_str_t *, mblk_t *);
extern void		dld_capabilities_disable(dld_str_t *);
extern void		proto_unitdata_req(dld_str_t *, mblk_t *);

/*
 * dld_flow.c
 */
extern void		flow_rx_pkt_chain(void *, void *, mblk_t *);

/*
 * dld_drv.c
 */
extern mac_handle_t	dld_mac_open(char *dev_name, int *err);
#define	dld_mac_close(mh) mac_close(mh)

/*
 * Options: there should be a separate bit defined here for each
 *          DLD_PROP... defined in dld.h.
 */
#define	DLD_OPT_NO_FASTPATH	0x00000001
#define	DLD_OPT_NO_POLL		0x00000002
#define	DLD_OPT_NO_ZEROCOPY	0x00000004
#define	DLD_OPT_NO_SOFTRING	0x00000008

extern uint32_t		dld_opt;

/*
 * autopush information
 */
typedef struct dld_ap {
	datalink_id_t		da_linkid;
	struct dlautopush	da_ap;

#define	da_anchor		da_ap.dap_anchor
#define	da_npush		da_ap.dap_npush
#define	da_aplist		da_ap.dap_aplist

} dld_ap_t;

/*
 * Useful macros.
 */

#define	DLD_SETQFULL(dsp) {						\
	queue_t *q = (dsp)->ds_wq;					\
									\
	mutex_enter(&(dsp)->ds_lock);					\
	if ((dsp)->ds_tx_flow_mp != NULL) {				\
		(void) putq(q, (dsp)->ds_tx_flow_mp);			\
		(dsp)->ds_tx_flow_mp = NULL;				\
		qenable((dsp)->ds_wq);					\
	}								\
	mutex_exit(&(dsp)->ds_lock);					\
}

/*
 * This is called to check whether we can disable the flow control, and
 * it is usually only needed in TX data-path when the dsp->ds_dlstate is
 * DL_IDLE. Otherwise, it does not hurt to always disable the flow control.
 */
#define	DLD_CLRQFULL(dsp) {					\
	queue_t *q = (dsp)->ds_wq;				\
								\
	mutex_enter(&(dsp)->ds_lock);				\
	if ((dsp)->ds_dlstate != DL_IDLE ||			\
	    !mac_tx_is_flow_blocked((dsp)->ds_mch, NULL)) {	\
		if ((dsp)->ds_tx_flow_mp == NULL)		\
			(dsp)->ds_tx_flow_mp = getq(q);		\
		ASSERT((dsp)->ds_tx_flow_mp != NULL);		\
	}							\
	mutex_exit(&(dsp)->ds_lock);				\
}

#define	DLD_TX(dsp, mp, f_hint, flag)				\
	mac_tx(dsp->ds_mch, mp, f_hint, flag, NULL)

#ifdef DEBUG
#define	DLD_DBG		cmn_err
#else
#define	DLD_DBG		if (0) cmn_err
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DLD_IMPL_H */

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

#ifndef	_SYS_DLD_IMPL_H
#define	_SYS_DLD_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ethernet.h>
#include <sys/stream.h>
#include <sys/dlpi.h>
#include <sys/mac.h>
#include <sys/dls.h>
#include <sys/dld.h>

#ifdef	__cplusplus
extern "C" {
#endif

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

typedef struct dld_str	dld_str_t;
typedef void		(*dld_tx_t)(struct dld_str *, mblk_t *);

/*
 * dld_str_t object definition.
 */
struct dld_str {
	/*
	 * Major number of the device
	 */
	major_t			ds_major;

	/*
	 * Ephemeral minor number for the object.
	 */
	minor_t			ds_minor;

	/*
	 * Read/write queues for the stream which the object represents.
	 */
	queue_t			*ds_rq;
	queue_t			*ds_wq;

	/*
	 * Lock to protect this structure.
	 */
	krwlock_t		ds_lock;

	/*
	 * Stream is open to DLD_CONTROL (control node) or
	 * DLD_DLPI (DLS provider) node.
	 */
	uint_t			ds_type;

	/*
	 * The following fields are only used for DLD_DLPI type objects.
	 */

	/*
	 * Current DLPI state.
	 */
	t_uscalar_t		ds_dlstate;

	/*
	 * DLPI style
	 */
	t_uscalar_t		ds_style;

	/*
	 * Currently bound DLSAP.
	 */
	uint16_t		ds_sap;

	/*
	 * Handle of the data-link channel that is used by this object.
	 */
	dls_channel_t		ds_dc;

	/*
	 * Handle of the MAC that is used by the data-link interface.
	 */
	mac_handle_t		ds_mh;

	/*
	 * VLAN identifier of the data-link interface.
	 */
	uint16_t		ds_vid;

	/*
	 * Promiscuity level information.
	 */
	uint32_t		ds_promisc;

	/*
	 * Immutable information of the MAC which the channel is using.
	 */
	const mac_info_t	*ds_mip;

	/*
	 * Current packet priority.
	 */
	uint_t			ds_pri;

	/*
	 * Handle of our MAC notification callback.
	 */
	mac_notify_handle_t	ds_mnh;

	/*
	 * Set of enabled DL_NOTE... notifications. (See dlpi.h).
	 */
	uint32_t		ds_notifications;

	/*
	 * Cached MAC unicast addresses.
	 */
	uint8_t			ds_fact_addr[MAXMACADDRLEN];
	uint8_t			ds_curr_addr[MAXMACADDRLEN];

	/*
	 * Mode: unitdata, fast-path or raw.
	 */
	dld_str_mode_t		ds_mode;

	/*
	 * Native mode state.
	 */
	boolean_t		ds_native;

	/*
	 * IP polling is operational if this flag is set.
	 */
	boolean_t		ds_polling;
	boolean_t		ds_soft_ring;

	/*
	 * LSO is enabled if ds_lso is set.
	 */
	boolean_t		ds_lso;
	uint64_t		ds_lso_max;

	/*
	 * State of DLPI user: may be active (regular network layer),
	 * passive (snoop-like monitoring), or unknown (not yet
	 * determined).
	 */
	dld_passivestate_t	ds_passivestate;

	/*
	 * Dummy mblk used for flow-control.
	 */
	mblk_t			*ds_tx_flow_mp;

	/*
	 * Internal transmit queue and its parameters.
	 */
	kmutex_t		ds_tx_list_lock;
	mblk_t			*ds_tx_list_head;
	mblk_t			*ds_tx_list_tail;
	uint_t			ds_tx_cnt;
	uint_t			ds_tx_msgcnt;
	timeout_id_t		ds_tx_qdepth_tid;
	boolean_t		ds_tx_qbusy;

	dld_tx_t		ds_tx;
	dld_tx_t		ds_unitdata_tx;
	kmutex_t		ds_tx_lock;
	kcondvar_t		ds_tx_cv;
	uint32_t		ds_intx_cnt;
	boolean_t		ds_detaching;

	/*
	 * Pending control messages to be processed.
	 */
	mblk_t			*ds_pending_head;
	mblk_t			*ds_pending_tail;

	taskqid_t		ds_tid;
	kmutex_t		ds_disp_lock;
	kcondvar_t		ds_disp_cv;
	boolean_t		ds_closing;

	/*
	 * Used to process ioctl message for control node. See comments
	 * above dld_ioctl().
	 */
	void			(*ds_ioctl)(queue_t *, mblk_t *);
} dld_str;

#define	DLD_TX_ENTER(dsp) {					\
	mutex_enter(&(dsp)->ds_tx_lock);			\
	(dsp)->ds_intx_cnt++;					\
	mutex_exit(&(dsp)->ds_tx_lock);				\
}

#define	DLD_TX_EXIT(dsp) {					\
	mutex_enter(&(dsp)->ds_tx_lock);			\
	if ((--(dsp)->ds_intx_cnt == 0) && (dsp)->ds_detaching)	\
		cv_signal(&(dsp)->ds_tx_cv);			\
	mutex_exit(&(dsp)->ds_tx_lock);				\
}

/*
 * Quiesce the traffic.
 */
#define	DLD_TX_QUIESCE(dsp) {						\
	mutex_enter(&(dsp)->ds_tx_lock);				\
	(dsp)->ds_tx = (dsp)->ds_unitdata_tx = NULL;			\
	(dsp)->ds_detaching = B_TRUE;					\
	while ((dsp)->ds_intx_cnt != 0)					\
		cv_wait(&(dsp)->ds_tx_cv, &(dsp)->ds_tx_lock);		\
	(dsp)->ds_detaching = B_FALSE;					\
	mutex_exit(&(dsp)->ds_tx_lock);					\
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

extern void		dld_tx_flush(dld_str_t *);
extern void		dld_str_notify_ind(dld_str_t *);
extern void		dld_tx_single(dld_str_t *, mblk_t *);
extern void		str_mdata_fastpath_put(dld_str_t *, mblk_t *);
extern void		str_mdata_raw_put(dld_str_t *, mblk_t *);

extern void		dld_ioctl(queue_t *, mblk_t *);
extern void		dld_finish_pending_task(dld_str_t *);

/*
 * dld_proto.c
 */
extern void		dld_wput_proto_nondata(dld_str_t *, mblk_t *);
extern void		dld_wput_proto_data(dld_str_t *, mblk_t *);
extern void		dld_capabilities_disable(dld_str_t *);

/*
 * Options: there should be a separate bit defined here for each
 *	  DLD_PROP... defined in dld.h.
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

#define	IMPLY(p, c)	(!(p) || (c))

#ifdef DEBUG
#define	DLD_DBG		cmn_err
#else
#define	DLD_DBG		if (0) cmn_err
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DLD_IMPL_H */

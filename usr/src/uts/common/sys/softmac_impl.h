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

#ifndef	_SYS_SOFTMAC_IMPL_H
#define	_SYS_SOFTMAC_IMPL_H

#include <sys/types.h>
#include <sys/ethernet.h>
#include <sys/taskq.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/strsun.h>
#include <sys/stream.h>
#include <sys/dlpi.h>
#include <sys/mac.h>
#include <sys/mac_provider.h>
#include <sys/mac_client.h>
#include <sys/mac_client_priv.h>
#include <sys/mac_ether.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef void	(*softmac_rx_t)(void *, mac_resource_handle_t, mblk_t *,
		    mac_header_info_t *);

typedef struct softmac_lower_rxinfo_s {
	softmac_rx_t	slr_rx;
	void		*slr_arg;
} softmac_lower_rxinfo_t;

typedef struct softmac_lower_s {
	ldi_handle_t		sl_lh;
	struct softmac		*sl_softmac;
	queue_t			*sl_wq;
	struct softmac_upper_s	*sl_sup;
	softmac_lower_rxinfo_t	*sl_rxinfo;

	/*
	 * When a control message is processed, either sl_pending_prim or
	 * sl_pending_ioctl will be set.  They will be cleared when the
	 * acknowledgement of the specific control message is received
	 * from the underlying legacy driver.
	 */
	kmutex_t		sl_mutex;
	kcondvar_t		sl_cv;
	t_uscalar_t		sl_pending_prim;
	boolean_t		sl_pending_ioctl;
	mblk_t			*sl_ack_mp;
} softmac_lower_t;

typedef enum {
	SOFTMAC_UNINIT,
	SOFTMAC_ATTACH_INPROG,
	SOFTMAC_ATTACH_DONE,
	SOFTMAC_DETACH_INPROG,
} softmac_state_t;

typedef struct softmac_dev_s {
	dev_t	sd_dev;
} softmac_dev_t;

/*
 * smac_flag values.
 */
#define	SOFTMAC_GLDV3		0x01
#define	SOFTMAC_NOSUPP		0x02
#define	SOFTMAC_NEED_RECREATE	0x04
#define	SOFTMAC_NOTIFY_QUIT	0x08

#define	SMAC_NONZERO_NODECNT(softmac)		\
	((softmac->smac_softmac[0] != NULL) +	\
	(softmac->smac_softmac[1] != NULL))

/*
 * The softmac structure allows all minor nodes (at most two, style-1 and
 * style-2) for the same device to be processed.  A softmac_dev_t will be
 * created for each minor node.
 *
 * We try to "register" the mac after all the softmac_dev_t's are processed so
 * that even if DLPI operations fail (because of driver bugs) for one minor
 * node, the other minor node can still be used to register the mac.
 * (Specifically, an incorrect xxx_getinfo() implementation will cause style-2
 * minor node mac registration to fail.)
 *
 * Locking description:
 *	WO: write once, valid the life time.
 */
typedef struct softmac {
	char		smac_devname[MAXNAMELEN];	/* WO */
	major_t		smac_umajor;			/* WO */
	int		smac_uppa;			/* WO */
	uint32_t	smac_cnt;	/* WO, # of minor nodes */

	kmutex_t	smac_mutex;
	kcondvar_t	smac_cv;
	softmac_state_t	smac_state;		/* smac_mutex */
	/*
	 * The smac_hold_cnt field increases when softmac_hold_device() is
	 * called to force the dls_vlan_t of the device to be created.  The
	 * device pre-detach fails if this counter is not 0.
	 */
	uint32_t	smac_hold_cnt;		/* smac_mutex */
	uint32_t	smac_flags;		/* smac_mutex */
	int		smac_attacherr;		/* smac_mutex */
	mac_handle_t	smac_mh;
	softmac_dev_t	*smac_softmac[2];	/* smac_mutex */

	/*
	 * Number of minor nodes whose post-attach routine has succeeded.
	 * This should be the same as the numbers of softmac_dev_t.
	 * Note that it does not imply SOFTMAC_ATTACH_DONE as the taskq might
	 * be still ongoing.
	 */
	uint32_t	smac_attachok_cnt;	/* smac_mutex */
	/*
	 * Number of softmac_dev_t left when pre-detach fails. This is used
	 * to indicate whether postattach is called because of a failed
	 * pre-detach.
	 */
	uint32_t	smac_attached_left;	/* smac_mutex */

	/*
	 * Thread handles the DL_NOTIFY_IND message from the lower stream.
	 */
	kthread_t	*smac_notify_thread;	/* smac_mutex */
	/*
	 * Head and tail of the DL_NOTIFY_IND messsages.
	 */
	mblk_t		*smac_notify_head;	/* smac_mutex */
	mblk_t		*smac_notify_tail;	/* smac_mutex */

	/*
	 * The remaining fields are used to register the MAC for a legacy
	 * device.  They are set in softmac_mac_register() and do not change.
	 * One can access them when mac_register() is done without locks.
	 */

	/*
	 * media type is needed for create <link name, linkid> mapping, so
	 * it is set for GLDv3 device as well
	 */
	uint_t		smac_media;
	/* DLPI style of the underlying device */
	int		smac_style;
	dev_t		smac_dev;
	size_t		smac_saplen;
	size_t		smac_addrlen;
	uchar_t		smac_unicst_addr[MAXMACADDRLEN];
	uint_t		smac_min_sdu;
	uint_t		smac_max_sdu;
	uint32_t	smac_margin;

	/* Notifications the underlying driver can support. */
	uint32_t	smac_notifications;

	/*
	 * Capabilities of the underlying driver.
	 */
	uint32_t	smac_capab_flags;
	uint32_t	smac_hcksum_txflags;
	boolean_t	smac_no_capability_req;
	dl_capab_mdt_t	smac_mdt_capab;
	boolean_t	smac_mdt;

	/*
	 * Lower stream structure, accessed by the MAC provider API. The GLDv3
	 * framework assures it's validity.
	 */
	softmac_lower_t	*smac_lower;

	kmutex_t	smac_active_mutex;
	/*
	 * Set by xxx_active_set() when aggregation is created.
	 */
	boolean_t	smac_active;	/* smac_active_mutex */
	/*
	 * Numbers of the bounded streams in the fast-path mode.
	 */
	uint32_t	smac_nactive;	/* smac_active_mutex */

	kmutex_t	smac_fp_mutex;
	kcondvar_t	smac_fp_cv;
	/*
	 * numbers of clients that request to disable fastpath.
	 */
	uint32_t	smac_fp_disable_clients;	/* smac_fp_mutex */
	boolean_t	smac_fastpath_admin_disabled;	/* smac_fp_mutex */

	/*
	 * stream list over this softmac.
	 */
	list_t			smac_sup_list;		/* smac_fp_mutex */
} softmac_t;

typedef struct smac_ioc_start_s {
	softmac_lower_t	*si_slp;
} smac_ioc_start_t;

#define	SMAC_IOC	('S' << 24 | 'M' << 16 | 'C' << 8)
#define	SMAC_IOC_START	(SMAC_IOC | 0x01)

/*
 * The su_mode of a non-IP/ARP stream is UNKNOWN, and the su_mode of an IP/ARP
 * stream is either SLOWPATH or FASTPATH.
 */
#define	SOFTMAC_UNKNOWN		0x00
#define	SOFTMAC_SLOWPATH	0x01
#define	SOFTMAC_FASTPATH	0x02

typedef struct softmac_switch_req_s {
	list_node_t	ssq_req_list_node;
	uint32_t	ssq_expected_mode;
} softmac_switch_req_t;

#define	DATAPATH_MODE(softmac)						\
	((((softmac)->smac_fp_disable_clients != 0) ||			\
	(softmac)->smac_fastpath_admin_disabled) ? SOFTMAC_SLOWPATH :	\
	SOFTMAC_FASTPATH)


/*
 * Locking description:
 *
 *	WO: Set once and valid for life;
 *	SL: Serialized by the control path (softmac_wput_nondata_task())
 */
typedef struct softmac_upper_s {
	softmac_t		*su_softmac;	/* WO */
	queue_t			*su_rq;		/* WO */
	queue_t			*su_wq;		/* WO */

	/*
	 * List of upper streams that has pending DLPI messages to be processed.
	 */
	list_node_t		su_taskq_list_node; /* softmac_taskq_lock */

	/*
	 * non-NULL for IP/ARP streams in the fast-path mode
	 */
	softmac_lower_t		*su_slp;	/* SL & su_mutex */

	/*
	 * List of all IP/ARP upperstreams on the same softmac (including
	 * the ones in both data-path modes).
	 */
	list_node_t		su_list_node;	/* smac_fp_mutex */

	/*
	 * List of datapath switch requests.
	 */
	list_t			su_req_list;	/* smac_fp_mutex */

	/*
	 * Place holder of RX callbacks used to handles data messages comes
	 * from the dedicated-lower-stream associated with the IP/ARP stream.
	 * Another RX callback is softmac_drop_rxinfo, which is a global
	 * variable.
	 */
	softmac_lower_rxinfo_t	su_rxinfo;		/* WO */
	softmac_lower_rxinfo_t	su_direct_rxinfo;	/* WO */

	/*
	 * Used to serialize the DLPI operation and fastpath<->slowpath
	 * switching over operation.
	 */
	kmutex_t		su_disp_mutex;
	kcondvar_t		su_disp_cv;
	mblk_t			*su_pending_head;	/* su_disp_mutex */
	mblk_t			*su_pending_tail;	/* su_disp_mutex */
	boolean_t		su_dlpi_pending;	/* su_disp_mutex */
	boolean_t		su_closing;		/* su_disp_mutex */

	uint32_t		su_bound : 1,		/* SL */
				su_active : 1,		/* SL */
				su_direct : 1,		/* SL */
				su_is_arp : 1,
				su_pad_to_32:28;

	/*
	 * Used for fastpath data path.
	 */
	kmutex_t		su_mutex;
	kcondvar_t		su_cv;
	mblk_t			*su_tx_flow_mp;		/* su_mutex */
	boolean_t		su_tx_busy;		/* su_mutex */
	/*
	 * Number of softmac_srv() operation in fastpath processing.
	 */
	uint32_t		su_tx_inprocess;	/* su_mutex */
	/*
	 * SOFTMAC_SLOWPATH or SOFTMAC_FASTPATH
	 */
	uint32_t		su_mode;		/* SL & su_mutex */

	/*
	 * Whether this stream is already scheduled in softmac_taskq_list.
	 */
	boolean_t		su_taskq_scheduled;	/* softmac_taskq_lock */

	/*
	 * The DLD_CAPAB_DIRECT related notify callback.
	 */
	mac_tx_notify_t		su_tx_notify_func;	/* su_mutex */
	void			*su_tx_notify_arg;	/* su_mutex */
} softmac_upper_t;

#define	SOFTMAC_EQ_PENDING(sup, mp) {					\
	if ((sup)->su_pending_head == NULL) {				\
		(sup)->su_pending_head = (sup)->su_pending_tail = (mp);	\
	} else {							\
		(sup)->su_pending_tail->b_next = (mp);			\
		(sup)->su_pending_tail = (mp);				\
	}								\
}

#define	SOFTMAC_DQ_PENDING(sup, mpp) {					\
	if ((sup)->su_pending_head == NULL) {				\
		*(mpp) = NULL;						\
	} else {							\
		*(mpp) = (sup)->su_pending_head;			\
		if (((sup)->su_pending_head = (*(mpp))->b_next) == NULL)\
			(sup)->su_pending_tail = NULL;			\
		(*(mpp))->b_next = NULL;				\
	}								\
}

/*
 * A macro to check whether the write-queue of the lower stream is full
 * and packets need to be enqueued.
 *
 * Because softmac is pushed right above the underlying device and
 * _I_INSERT/_I_REMOVE is not processed in the lower stream, it is
 * safe to directly access the q_next pointer.
 */
#define	SOFTMAC_CANPUTNEXT(q)	\
	(!((q)->q_next->q_nfsrv->q_flag & QFULL) || canput((q)->q_next))


extern dev_info_t		*softmac_dip;
#define	SOFTMAC_DEV_NAME	"softmac"

extern int	softmac_send_bind_req(softmac_lower_t *, uint_t);
extern int	softmac_send_unbind_req(softmac_lower_t *);
extern int	softmac_send_notify_req(softmac_lower_t *, uint32_t);
extern int	softmac_send_promisc_req(softmac_lower_t *, t_uscalar_t,
    boolean_t);
extern void	softmac_init();
extern void	softmac_fini();
extern void	softmac_fp_init();
extern void	softmac_fp_fini();
extern boolean_t softmac_busy();
extern int	softmac_fill_capab(ldi_handle_t, softmac_t *);
extern int	softmac_capab_enable(softmac_lower_t *);
extern void	softmac_rput_process_notdata(queue_t *, softmac_upper_t *,
    mblk_t *);
extern void	softmac_rput_process_data(softmac_lower_t *, mblk_t *);
extern int	softmac_output(softmac_lower_t *, mblk_t *, t_uscalar_t,
    t_uscalar_t, mblk_t **);
extern int	softmac_mexchange_error_ack(mblk_t **, t_uscalar_t,
    t_uscalar_t, t_uscalar_t);

extern int	softmac_m_promisc(void *, boolean_t);
extern int	softmac_m_multicst(void *, boolean_t, const uint8_t *);
extern int	softmac_m_unicst(void *, const uint8_t *);
extern void	softmac_m_ioctl(void *, queue_t *, mblk_t *);
extern int	softmac_m_stat(void *, uint_t, uint64_t *);
extern mblk_t	*softmac_m_tx(void *, mblk_t *);
extern int	softmac_proto_tx(softmac_lower_t *, mblk_t *, mblk_t **);
extern void	softmac_ioctl_tx(softmac_lower_t *, mblk_t *, mblk_t **);
extern void	softmac_notify_thread(void *);

extern int	softmac_hold(dev_t, softmac_t **);
extern void	softmac_rele(softmac_t *);
extern int	softmac_lower_setup(softmac_t *, softmac_upper_t *,
    softmac_lower_t **);
extern boolean_t	softmac_active_set(void *);
extern void	softmac_active_clear(void *);
extern int	softmac_fastpath_disable(void *);
extern void	softmac_fastpath_enable(void *);
extern int	softmac_datapath_switch(softmac_t *, boolean_t, boolean_t);

extern void	softmac_wput_data(softmac_upper_t *, mblk_t *);
extern void	softmac_wput_nondata(softmac_upper_t *, mblk_t *);
extern void	softmac_upperstream_close(softmac_upper_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SOFTMAC_IMPL_H */

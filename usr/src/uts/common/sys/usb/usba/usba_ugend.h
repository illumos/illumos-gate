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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_USBA_UGEND_H
#define	_SYS_USBA_UGEND_H


/*
 * UGEN - USB Generic Driver Support
 * This file contains the UGEN specific data structure definitions
 * and UGEN specific macros.
 */
#include <sys/usb/usba/usbai_private.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* ugen handle passed to client drivers as an opaque token */
typedef struct {
	dev_info_t	*hdl_dip;
	uint_t		hdl_flags;
	dev_t		hdl_minor_node_ugen_bits_mask;
	uint_t		hdl_minor_node_ugen_bits_shift;
	uint_t		hdl_minor_node_ugen_bits_limit;

	dev_t		hdl_minor_node_instance_mask;
	uint_t		hdl_minor_node_instance_shift;
	uint_t		hdl_minor_node_instance_limit;

	struct ugen_state *hdl_ugenp;
	char		*hdl_log_name;
	uint_t		hdl_log_name_length;
} usb_ugen_hdl_impl_t;

_NOTE(SCHEME_PROTECTS_DATA("stable data", usb_ugen_hdl_impl_t))

/* devt lookup support */
typedef struct ugen_devt_list_entry {
	struct ugen_devt_list_entry	*list_next;
	struct ugen_devt_list_entry	*list_prev;
	dev_t				list_dev;
	struct ugen_state		*list_state;
} ugen_devt_list_entry_t;

typedef struct ugen_devt_cache_entry  {
	dev_t				cache_dev;
	struct ugen_state		*cache_state;
	uint_t				cache_hit;
} ugen_devt_cache_entry_t;

#define	UGEN_DEVT_CACHE_SIZE 10

/* minor node definition */
#ifdef _LP64
#define	UGEN_MINOR_NODE_SIZE		32
#else
#define	UGEN_MINOR_NODE_SIZE		18
#endif

#define	UGEN_MINOR_INSTANCE_MASK(ugenp) \
		(ugenp)->ug_hdl->hdl_minor_node_instance_mask
#define	UGEN_MINOR_INSTANCE_LIMIT(ugenp) \
		(ugenp)->ug_hdl->hdl_minor_node_instance_limit
#define	UGEN_MINOR_INSTANCE_SHIFT(ugenp) \
		(ugenp)->ug_hdl->hdl_minor_node_instance_shift

#define	UGEN_MINOR_IDX_SHIFT(ugenp) \
		(ugenp)->ug_hdl->hdl_minor_node_ugen_bits_shift
#define	UGEN_MINOR_IDX_LIMIT(ugenp) \
		(ugenp)->ug_hdl->hdl_minor_node_ugen_bits_limit

#define	UGEN_MINOR_GET_IDX(ugenp, dev) \
		((getminor(dev) >> UGEN_MINOR_IDX_SHIFT(ugenp)) & \
		(ugenp)->ug_hdl->hdl_minor_node_ugen_bits_mask)

#define	UGEN_MINOR_INSTANCE(ugenp, dev) \
	(getminor(dev) & UGEN_MINOR_INSTANCE_MASK(ugenp))


#define	UGEN_N_ENDPOINTS		32

/* UGEN specific macros */
#define	UGEN_SETUP_PKT_SIZE		8	/* Ctrl xfer Setup token sz */

/*
 * minor node is contructed as follows for ugen driver (other client
 * drivers that export a ugen interface may have a different layout):
 *
 * 17			 9			0
 * +---------------------+----------------------+
 * | minor index	 |	instance	|
 * +---------------------+----------------------+
 *
 * Note that only 512 endpoint minor nodes can be supported (each
 * endpoint requires a status endpoint as well so we can only support
 * 256 endpoints)
 *
 * the real minor node is:
 *
 * 47	  40	  32	  24	 16	  8	  0
 * +-------+-------+-------+------+-------+-------+
 * | cfgval| cfgidx| iface | alt  |epidx  | type  |
 * +-------+-------+-------+------+-------+-------+
 *
 * We get from the minor code to minor number thru ugen_minor_node_table
 */
typedef uint64_t ugen_minor_t;

#define	UGEN_MINOR_DEV_STAT_NODE	0x00
#define	UGEN_MINOR_EP_XFER_NODE		0x01
#define	UGEN_MINOR_EP_STAT_NODE		0x02
#define	UGEN_OWNS_DEVICE		0x04

#define	UGEN_MINOR_EPIDX_SHIFT		8
#define	UGEN_MINOR_ALT_SHIFT		16
#define	UGEN_MINOR_IF_SHIFT		24
#define	UGEN_MINOR_CFGIDX_SHIFT		32
#define	UGEN_MINOR_CFGVAL_SHIFT		40

#define	UGEN_MINOR_TYPE(ugenp, dev) \
	(ugen_devt2minor((ugenp), (dev)) & 0x3)
#define	UGEN_MINOR_EPIDX(ugenp, dev) \
	((ugen_devt2minor((ugenp), (dev)) >> UGEN_MINOR_EPIDX_SHIFT) & 0xFF)

#define	UGEN_MINOR_ALT(ugenp, dev) \
	((ugen_devt2minor((ugenp), (dev)) >> UGEN_MINOR_ALT_SHIFT) & 0xFF)

#define	UGEN_MINOR_IF(ugenp, dev) \
	((ugen_devt2minor((ugenp), (dev)) >> UGEN_MINOR_IF_SHIFT) & 0xFF)

#define	UGEN_MINOR_CFGIDX(ugenp, dev) \
	((ugen_devt2minor((ugenp), (dev)) >> UGEN_MINOR_CFGIDX_SHIFT) & 0xFF)

#define	UGEN_MINOR_CFGVAL(ugenp, dev) \
	((ugen_devt2minor((ugenp), (dev)) >> UGEN_MINOR_CFGVAL_SHIFT) & 0xFF)


/*
 * According to usb2.0 spec (table 9-13), for all ep, bits 10..0 specify the
 * max pkt size; for high speed ISOC/INTR ep, bits 12..11 specify the number of
 * additional transaction opportunities per microframe.
 */
#define	UGEN_PKT_SIZE(pktsize)	(pktsize & 0x07ff) * (1 + ((pktsize >> 11) & 3))


/*
 * Structure for holding isoc data packets information
 */
typedef struct ugen_isoc_pkt_info {
	ushort_t	isoc_pkts_count;
	uint_t		isoc_pkts_length;
	ugen_isoc_pkt_descr_t    *isoc_pkt_descr; /* array of pkt descr */
} ugen_isoc_pkt_info_t;

/*
 * Endpoint structure
 * Holds all the information needed to manage the endpoint
 */
typedef struct ugen_ep {
	uint_t		ep_state;	/* Endpoint state, see below */
	usb_ep_descr_t	ep_descr;	/* Endpoint descriptor */
	uchar_t		ep_cfgidx;	/* cfg index */
	uchar_t		ep_if;		/* Interface # */
	uchar_t		ep_alt;		/* alternate # */
	uchar_t		ep_done;	/* cmd is done */
	boolean_t	ep_one_xfer;	/* use one xfer on intr IN eps */
	uint_t		ep_lcmd_status;	/* last cmd status */
	int		ep_xfer_oflag;	/* open flag */
	int		ep_stat_oflag;	/* open flag */
	size_t		ep_buf_limit;	/* one second of data */
	usb_pipe_handle_t ep_ph;	/* Endpoint pipe handle */
	usb_pipe_policy_t ep_pipe_policy;
	kmutex_t	ep_mutex;	/* Mutex protecting ugen_ep */
	kcondvar_t	ep_wait_cv;	/* block for completion */
	usb_serialization_t ep_ser_cookie;	/* one xfer at the time */
	mblk_t		*ep_data;	/* IN data (ctrl & intr) */
	struct buf	*ep_bp;		/* save current buf ptr */
	struct pollhead	ep_pollhead;	/* for polling	*/
	ugen_isoc_pkt_info_t ep_isoc_info;	/* for isoc eps */
	int		ep_isoc_in_inited;	/* isoc IN init flag */
} ugen_ep_t;

_NOTE(MUTEX_PROTECTS_DATA(ugen_ep::ep_mutex, ugen_ep))

/* endpoints descriptor access */
#define	UGEN_XFER_TYPE(epp) ((epp)->ep_descr.bmAttributes & USB_EP_ATTR_MASK)
#define	UGEN_XFER_DIR(epp) ((epp)->ep_descr.bEndpointAddress & USB_EP_DIR_IN)
#define	UGEN_XFER_ADDR(epp) ((epp)->ep_descr.bEndpointAddress)

#define	UGEN_INTR_BUF_LIMIT	4096

/* endpoint xfer/stat states */
#define	UGEN_EP_STATE_NONE		0x00
#define	UGEN_EP_STATE_ACTIVE		0x01
#define	UGEN_EP_STATE_XFER_OPEN		0x02
#define	UGEN_EP_STATE_STAT_OPEN		0x04
#define	UGEN_EP_STATE_XS_OPEN		(UGEN_EP_STATE_XFER_OPEN | \
					    UGEN_EP_STATE_STAT_OPEN)
#define	UGEN_EP_STATE_INTR_IN_POLLING_ON		0x10
#define	UGEN_EP_STATE_INTR_IN_POLLING_IS_STOPPED	0x20
#define	UGEN_EP_STATE_INTR_IN_POLL_PENDING		0x40

#define	UGEN_EP_STATE_ISOC_IN_POLLING_ON	0x100
#define	UGEN_EP_STATE_ISOC_IN_POLLING_IS_STOPPED	0x200
#define	UGEN_EP_STATE_ISOC_IN_POLL_PENDING	0x400

_NOTE(DATA_READABLE_WITHOUT_LOCK(ugen_ep::ep_ph))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ugen_ep::ep_descr))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ugen_ep::ep_ser_cookie))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ugen_ep::ep_if))

_NOTE(SCHEME_PROTECTS_DATA("USBA", usb_ctrl_req))
_NOTE(SCHEME_PROTECTS_DATA("USBA", usb_bulk_req))
_NOTE(SCHEME_PROTECTS_DATA("USBA", usb_intr_req))

typedef struct ugen_dev_stat {
	int			dev_oflag;	/* open flag */
	uint_t			dev_stat;	/* internal status */
	uint_t			dev_state;	/* exported state */
	kcondvar_t		dev_wait_cv;	/* block for change */
	struct pollhead		dev_pollhead;	/* for polling */
} ugen_dev_stat_t;

/* dev_stat */
#define	UGEN_DEV_STATUS_INACTIVE	0x0
#define	UGEN_DEV_STATUS_ACTIVE		0x1
#define	UGEN_DEV_STATUS_POLL_PENDING	0x2
#define	UGEN_DEV_STATUS_CHANGED		0x4

/* Power Management support */
typedef struct ugen_power  {
	uint_t			pwr_states;
	int			pwr_busy;		/* busy accounting */
	uint8_t			pwr_wakeup_enabled;
	uint8_t			pwr_current;
} ugen_power_t;

/* UGEN state structure */
typedef struct ugen_state {
	usb_ugen_hdl_impl_t	*ug_hdl;		/* pointer to handle */
	dev_info_t		*ug_dip;		/* Dev info */
	uint_t			ug_instance;		/* Instance number */
	uint_t			ug_dev_state;
	uint_t			ug_dev_stat_state;
	uint_t			ug_open_count;
	uint_t			ug_pending_cmds;
	uint_t			ug_initial_cfgidx;

	/* locks */
	kmutex_t		ug_mutex;		/* Instance mutex */
	usb_serialization_t	ug_ser_cookie;		/* access */

	/* USB debugging system support */
	usb_log_handle_t	ug_log_hdl;

	/* registration data */
	usb_client_dev_data_t	*ug_dev_data;

	/* Endpoint management list */
	ugen_ep_t		ug_ep[UGEN_N_ENDPOINTS];

	/* encoding minor numbers as we only have 8 bits in the minor # */
	ugen_minor_t		*ug_minor_node_table;
	int			ug_minor_node_table_index;
	size_t			ug_minor_node_table_size;

	/* device status management */
	ugen_dev_stat_t		ug_ds;

	/* PM Support */
	ugen_power_t		*ug_pm;

	/* Maximum transfer size for bulk endpoints */
	size_t			ug_max_bulk_xfer_sz;

	/* Used to deallocate allocated resources */
	ushort_t		ug_cleanup_flags;
} ugen_state_t;

_NOTE(SCHEME_PROTECTS_DATA("unshared", buf))

_NOTE(MUTEX_PROTECTS_DATA(ugen_state::ug_mutex, ugen_state))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ugen_state::ug_log_hdl))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ugen_state::ug_hdl))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ugen_state::ug_ser_cookie))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ugen_state::ug_dip))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ugen_state::ug_pm))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ugen_state::ug_instance))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ugen_state::ug_minor_node_table))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ugen_state::ug_minor_node_table_index))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ugen_state::ug_max_bulk_xfer_sz))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ugen_state::ug_dev_data))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ugen_state::ug_cleanup_flags))


/* ugen_cleanup_flags */
#define	UGEN_INIT_LOCKS			0x01

/* additional USB device states */
#define	USB_UGEN_DEV_UNAVAILABLE_RESUME		0x90
#define	USB_UGEN_DEV_UNAVAILABLE_RECONNECT	0x91

/* Debugging information */
#define	UGEN_PRINT_ATTA		0x1
#define	UGEN_PRINT_CBOPS	0x2
#define	UGEN_PRINT_CPR		0x4
#define	UGEN_PRINT_POLL		0x8
#define	UGEN_PRINT_XFER		0x10
#define	UGEN_PRINT_HOTPLUG	0x20
#define	UGEN_PRINT_STAT		0x40
#define	UGEN_PRINT_PM		0x80
#define	UGEN_PRINT_ALL		0xFFFFFFFF

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USBA_UGEND_H */

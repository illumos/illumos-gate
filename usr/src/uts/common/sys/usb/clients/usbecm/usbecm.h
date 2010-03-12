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

#ifndef _SYS_USB_USBETH_H
#define	_SYS_USB_USBETH_H


#include <sys/types.h>
#include <sys/dditypes.h>
#include <sys/mac.h>
#include <sys/note.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct usbecm_state usbecm_state_t;


/*
 * PM support
 */
typedef struct usbecm_power {
	uint8_t		pm_wakeup_enabled;	/* remote wakeup enabled */
	uint8_t		pm_pwr_states;	/* bit mask of power states */
	boolean_t	pm_raise_power;	/* driver is about to raise power */
	uint8_t		pm_cur_power;	/* current power level */
	uint_t		pm_busy_cnt;	/* number of set_busy requests */
} usbecm_pm_t;

struct usbecm_statistics {
	uint32_t	es_upspeed;	/* Upstream bit rate, bps */
	uint32_t	es_downspeed;	/* Downstream bit rate, bps */
	int		es_linkstate;	/* link state */
	uint64_t	es_ipackets;
	uint64_t	es_opackets;
	uint64_t	es_ibytes;
	uint64_t	es_obytes;
	uint64_t	es_ierrors;	/* received frames with errors */
	uint64_t	es_oerrors;	/* transmitted frames with errors */
	uint64_t	es_multircv;	/* received multicast frames */
	uint64_t	es_multixmt;	/* transmitted multicast frames */
	uint64_t	es_brdcstrcv;
	uint64_t	es_brdcstxmt;
	uint64_t	es_macxmt_err;
};

struct usbecm_ds_ops {
	/* Device specific initialization and deinitialization */
	int (*ecm_ds_init)(usbecm_state_t *);
	int (*ecm_ds_fini)(usbecm_state_t *);

	int (*ecm_ds_start)(usbecm_state_t *);
	int (*ecm_ds_stop)(usbecm_state_t *);
	int (*ecm_ds_unicst)(usbecm_state_t *);
	int (*ecm_ds_promisc)(usbecm_state_t *);
	int (*ecm_ds_multicst)(usbecm_state_t *);
	mblk_t *(*ecm_ds_tx)(usbecm_state_t *, mblk_t *);

	int (*ecm_ds_intr_cb)(usbecm_state_t *, mblk_t *);
	int (*ecm_ds_bulkin_cb)(usbecm_state_t *, mblk_t *);
	int (*ecm_ds_bulkout_cb)(usbecm_state_t *, mblk_t *);
};

/*
 * per bulk in/out structure
 */
struct usbecm_state {
	kmutex_t		ecm_mutex;		/* structure lock */
	dev_info_t		*ecm_dip;		/* device info */
	usb_client_dev_data_t	*ecm_dev_data;		/* registration data */
	usb_pipe_handle_t	ecm_def_ph;		/* default pipe hdl */
	usb_log_handle_t	ecm_lh;			/* USBA log handle */
	int			ecm_dev_state;		/* USB device state */
	size_t			ecm_xfer_sz;		/* bulk xfer size */
	size_t			ecm_bulkin_sz;
	usbecm_pm_t		*ecm_pm;		/* PM support */
	mac_handle_t		ecm_mh;			/* mac handle */
	usb_serialization_t	ecm_ser_acc;	/* serialization object */

	uint_t			ecm_cfg_index;	/* config contains ECM ifc */
	uint16_t		ecm_ctrl_if_no;
	uint16_t		ecm_data_if_no;
	uint16_t		ecm_data_if_alt; /* non-compatible device */

	usb_ep_data_t		*ecm_intr_ep;
	usb_ep_data_t		*ecm_bulk_in_ep;
	usb_ep_data_t		*ecm_bulk_out_ep;

	boolean_t		ecm_compatibility;	/* if conform to spec */
	usb_cdc_ecm_descr_t	ecm_desc;	/* if conform to spec */

	uint8_t			ecm_srcaddr[6];	/* source MAC addr */
	uint16_t		ecm_pkt_flt;	/* pkt flt bitmap ECM1.2 T.8 */

	usb_pipe_handle_t	ecm_bulkout_ph;
	int			ecm_bulkout_state;
	usb_pipe_handle_t	ecm_bulkin_ph;
	int			ecm_bulkin_state;
	usb_pipe_handle_t	ecm_intr_ph;
	int			ecm_intr_state;
	struct usbecm_statistics	ecm_stat;
	uint32_t		ecm_init_flags;
	int			ecm_mac_state;
	mblk_t			*ecm_rcv_queue; /* receive queue */
	int			ecm_tx_cnt;

	void			*ecm_priv; /* device private data */
	struct usbecm_ds_ops    *ecm_ds_ops;
};


_NOTE(MUTEX_PROTECTS_DATA(usbecm_state::ecm_mutex, usbecm_state))
_NOTE(MUTEX_PROTECTS_DATA(usbecm_state::ecm_mutex, usbecm_statistics))

_NOTE(DATA_READABLE_WITHOUT_LOCK(usbecm_state::{
	ecm_dip
	ecm_dev_data
	ecm_def_ph
	ecm_lh
	ecm_dev_state
	ecm_xfer_sz
	ecm_compatibility
	ecm_pm
	ecm_mh
	ecm_bulkin_ph
	ecm_bulkout_ph
	ecm_intr_ph
	ecm_ser_acc
	ecm_ctrl_if_no
	ecm_data_if_no
	ecm_data_if_alt
	ecm_desc
	ecm_bulk_in_ep
	ecm_intr_ep
	ecm_bulk_out_ep
	ecm_bulkin_sz
	ecm_priv
	ecm_ds_ops
}))

_NOTE(SCHEME_PROTECTS_DATA("unshared data", mblk_t iocblk))
_NOTE(SCHEME_PROTECTS_DATA("unshared data", usb_bulk_req_t usb_intr_req_t))

/* pipe state */
enum {
	USBECM_PIPE_CLOSED,			/* pipe is closed */
	USBECM_PIPE_IDLE,			/* open but no requests */
	USBECM_PIPE_BUSY,			/* servicing request */
	USBECM_PIPE_CLOSING			/* pipe is closing */
};

enum {
	USBECM_MAC_STOPPED = 0,
	USBECM_MAC_STARTED,
};

/* various tunables */
enum {
	USBECM_BULKOUT_TIMEOUT		= 15,	/* bulkout timeout */
	USBECM_BULKIN_TIMEOUT		= 0	/* bulkin timeout */
};

/* hardware definitions */
enum {
	USBSACM_REQ_OUT	= USB_DEV_REQ_TYPE_CLASS| USB_DEV_REQ_HOST_TO_DEV,
	USBSACM_REQ_IN	= USB_DEV_REQ_TYPE_CLASS | USB_DEV_REQ_DEV_TO_HOST,
	USBSACM_REQ_WRITE_IF		= USBSACM_REQ_OUT | USB_DEV_REQ_RCPT_IF,
	USBSACM_REQ_READ_IF		= USBSACM_REQ_IN | USB_DEV_REQ_RCPT_IF
};

#define	USBECM_INIT_EVENTS	(0x01 << 0)
#define	USBECM_INIT_SER		(0x01 << 1)
#define	USBECM_INIT_MAC		(0x01 << 2)

/* Bit offset for ECM statistics capabilities, CDC ECM Rev 1.2, Table 4 */
#define	ECM_XMIT_OK			0
#define	ECM_RCV_OK			1
#define	ECM_XMIT_ERROR			2
#define	ECM_RCV_ERROR			3
#define	ECM_RCV_NO_BUFFER		4
#define	ECM_DIRECTED_BYTES_XMIT		5
#define	ECM_DIRECTED_FRAMES_XMIT	6
#define	ECM_MULTICAST_BYTES_XMIT	7
#define	ECM_MULTICAST_FRAMES_XMIT	8
#define	ECM_BROADCAST_BYTES_XMIT	9
#define	ECM_BROADCAST_FRAMES_XMIT	10
#define	ECM_DIRECTED_BYTES_RCV		11
#define	ECM_DIRECTED_FRAMES_RCV		12
#define	ECM_MULTICAST_BYTES_RCV		13
#define	ECM_MULTICAST_FRAMES_RCV	14
#define	ECM_BROADCAST_BYTES_RCV		15
#define	ECM_BROADCAST_FRAMES_RCV	16
#define	ECM_RCV_CRC_ERROR		17
#define	ECM_TRANSMIT_QUEUE_LENGTH	18
#define	ECM_RCV_ERROR_ALIGNMENT		19
#define	ECM_XMIT_ONE_COLLISION		20
#define	ECM_XMIT_MORE_COLLISIONS	21
#define	ECM_XMIT_DEFERRED		22
#define	ECM_XMIT_MAX_COLLISIONS		23
#define	ECM_RCV_OVERRUN			24
#define	ECM_XMIT_UNDERRUN		25
#define	ECM_XMIT_HEARTBEAT_FAILURE	26
#define	ECM_XMIT_TIMES_CRS_LOST		27
#define	ECM_XMIT_LATE_COLLISIONS	28

#define	ECM_STAT_CAP_MASK(x)	(1UL << (x))		/* Table 4 */
#define	ECM_STAT_SELECTOR(x)	((x) + 1)	/* Table 9 */

/* ECM class-specific request codes, Table 6 */
#define	CDC_ECM_SET_ETH_MCAST_FLT	0x40
#define	CDC_ECM_SET_ETH_PM_FLT		0x41
#define	CDC_ECM_GET_ETH_PM_FLT		0x42
#define	CDC_ECM_SET_ETH_PKT_FLT		0x43
#define	CDC_ECM_GET_ETH_STAT		0x44

/* ECM Ethernet Pakcet Filter Bitmap, Table 8 */
#define	CDC_ECM_PKT_TYPE_PROMISC	(1<<0)
#define	CDC_ECM_PKT_TYPE_ALL_MCAST	(1<<1) /* all multicast */
#define	CDC_ECM_PKT_TYPE_DIRECTED	(1<<2)
#define	CDC_ECM_PKT_TYPE_BCAST		(1<<3) /* broadcast */
#define	CDC_ECM_PKT_TYPE_MCAST		(1<<4) /* multicast */

#define	PRINT_MASK_ATTA		0x00000001
#define	PRINT_MASK_CLOSE	0x00000002
#define	PRINT_MASK_OPEN		0x00000004
#define	PRINT_MASK_EVENTS	0x00000008
#define	PRINT_MASK_PM		0x00000010
#define	PRINT_MASK_CB		0x00000020
#define	PRINT_MASK_OPS		0x00000040
#define	PRINT_MASK_ALL		0xFFFFFFFF

/* Turn a little endian byte array to a uint32_t */
#define	LE_TO_UINT32(src, des)	{ \
	uint32_t tmp; \
	des = src[3]; \
	des = des << 24; \
	tmp = src[2]; \
	des |= tmp << 16; \
	tmp = src[1]; \
	des |= tmp << 8; \
	des |= src[0]; \
}

#define	isdigit(c)	((c) >= '0' && c <= '9')
#define	toupper(C)	(((C) >= 'a' && (C) <= 'z')? ((C) - 'a' + 'A'): (C))

/* #define	NELEM(a)	(sizeof (a) / sizeof (*(a))) */


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USB_USBETH_H */

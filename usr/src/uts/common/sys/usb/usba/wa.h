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

#ifndef	_SYS_USB_WA_H
#define	_SYS_USB_WA_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/usb/usba.h>
#include <sys/usb/usba/usba_types.h>
#include <sys/id32.h>

/* Wire adapter class extension for descriptors */
typedef struct usb_wa_descr {
	uint8_t		bLength;
	uint8_t		bDescriptorType;
	uint16_t	bcdWAVersion;
	uint8_t		bNumPorts;
	uint8_t		bmAttributes;
	uint16_t	wNumRPipes;
	uint16_t	wRPipeMaxBlock;
	uint8_t		bRPipeBlockSize;
	uint8_t		bPwrOn2PwrGood;
	uint8_t		bNumMMCIEs;
	uint8_t		DeviceRemovable;
} usb_wa_descr_t;

typedef struct usb_wa_rpipe_descr {
	uint8_t		bLength;
	uint8_t		bDescriptorType;
	uint16_t	wRPipeIndex;
	uint16_t	wRequests;
	uint16_t	wBlocks;
	uint16_t	wMaxPacketSize;
	union {
		struct {
			uint8_t	bHSHubAddress;
			uint8_t	bHSHubPort;
		} dwa_value;

		struct {
			uint8_t	bMaxBurst;
			uint8_t	bDeviceInfoIndex;
		} hwa_value;
	} wa_value;

	uint8_t		bSpeed;
	uint8_t		bDeviceAddress;
	uint8_t		bEndpointAddress;
	uint8_t		bDataSequence;
	uint32_t	dwCurrentWindow;
	uint8_t		bMaxDataSequence;
	uint8_t		bInterval;
	uint8_t		bOverTheAirInterval;
	uint8_t		bmAttribute;
	uint8_t		bmCharacteristics;
	uint8_t		bmRetryOptions;
	uint16_t	wNumTransactionErrors;
} usb_wa_rpipe_descr_t;

/* Rpipe bmCharacteristics mask and bits */
#define	USB_RPIPE_CHA_MASK		0x0f
#define	USB_RPIPE_CHA_CTRL		0x01
#define	USB_RRIPE_CHA_ISOC		0x02
#define	USB_RRIPE_CHA_BULK		0x04
#define	USB_RPIPE_CHA_INTR		0x08

/*
 * ************************************************************
 * Wire adapter class request related structures and data types
 * ************************************************************
 */

/* Wire adapter class specific requests */
#define	WA_REQ_ABORT_RPIPE		0x0e
#define	WA_REQ_RESET_RPIPE		0x0f

/* HWA specific requests as host controller, T8-50 */
#define	HWA_REQ_ADD_MMC_IE		0x14
#define	HWA_REQ_REMOVE_MMC_IE		0x15
#define	HWA_REQ_SET_NUM_DNTS		0x16
#define	HWA_REQ_SET_CLUSTER_ID		0x17
#define	HWA_REQ_SET_DEVICE_INFO		0x18
#define	HWA_REQ_GET_TIME		0x19
#define	HWA_REQ_SET_STREAM_IDX		0x1a
#define	HWA_REQ_SET_WUSB_MAS		0x1b
#define	HWA_REQ_CH_STOP			0x1c

/* DWA specific requests */
#define	DWA_REQ_SET_EP_ATTRIB		0x1e

/* wLength for wire adapter class requests */
#define	WA_GET_RPIPE_STATUS_LEN		1
#define	WA_GET_WA_STATUS_LEN		4

/* wLength for HWA specific requests */
#define	WUSB_SET_DEV_INFO_LEN		36
#define	WUSB_SET_WUSB_MAS_LEN		32

/* wLength for DWA specific requests */
#define	DWA_GET_STATUS_LEN		4
#define	DWA_ISOC_EP_ATTRIB_LEN		6

/* Wire adapter class feature selector */
#define	WA_DEV_ENABLE			1
#define	WA_DEV_RESET			2
#define	WA_RPIPE_PAUSE			1
#define	WA_RPIPE_STALL			2

/* Rpipe status bits */
#define	WA_RPIPE_IDLE			0x01
#define	WA_PRIPE_PAUSED			0x02
#define	WA_RPIPE_CONFIGURED		0x04
#define	WA_RPIPE_STALLED		0x08

/* Wire adapter status bits */
#define	WA_HC_ENABLED			0x00000001
#define	WA_HC_RESET_IN_PROGRESS		0x00000002

/* HWA specific definitions */
#define	WUSB_CLASS_IF_REQ_IN_TYPE	(USB_DEV_REQ_DEV_TO_HOST \
					|USB_DEV_REQ_TYPE_CLASS \
					|USB_DEV_REQ_RCPT_IF)

#define	WUSB_CLASS_IF_REQ_OUT_TYPE	(USB_DEV_REQ_HOST_TO_DEV \
					|USB_DEV_REQ_TYPE_CLASS \
					|USB_DEV_REQ_RCPT_IF)

#define	WA_CLASS_RPIPE_REQ_IN_TYPE	(USB_DEV_REQ_DEV_TO_HOST \
					|USB_DEV_REQ_TYPE_CLASS \
					|USB_DEV_REQ_RCPT_RPIPE)

#define	WA_CLASS_RPIPE_REQ_OUT_TYPE	(USB_DEV_REQ_HOST_TO_DEV \
					|USB_DEV_REQ_TYPE_CLASS \
					|USB_DEV_REQ_RCPT_RPIPE)

#define	HWA_TIME_ADJ			0
#define	HWA_TIME_BPST			1
#define	HWA_TIME_WUSB			2

typedef struct hwa_dev_info {
	uint8_t		bmDeviceAvailablilityInfo[32];
	uint8_t		bDeviceAddress;
	uint8_t		wPHYRates[2];
	uint8_t		bmDeviceAttribute;
} hwa_dev_info_t;

/* DWA specific definitions */
typedef struct dwa_isoc_ep_attrib {
	uint16_t	wMaxStreamDelay;
	uint16_t	wOverTheAirPacketSize;
	uint16_t	wReserved;
} dwa_isoc_ep_attrib_t;


/*
 * *****************************************************************
 * Wire adapter class notification related structures and data types
 * *****************************************************************
 */

/* Wire adapter class specific notification */
#define	WA_NOTIF_TYPE_TRANSFER		0x93

typedef struct wa_notif_header {
	uint8_t		bLength;
	uint8_t		bNotifyType;
} wa_notif_header_t;

typedef struct wa_notif_transfer {
	uint8_t		bLength;
	uint8_t		bNotifyType;
	uint8_t		bEndpoint;
	uint8_t		bReserved;
} wa_notif_transfer_t;

/* HWA specific notifications */
#define	HWA_NOTIF_TYPE_BPST_ADJ		0x94
#define	HWA_NOTIF_TYPE_DN_RECEIVED	0x95

typedef struct hwa_notif_bpst_adj {
	uint8_t		bLength;
	uint8_t		bNotifyType;
	uint8_t		bAdjustment;
} hwa_notif_bpst_adj_t;

typedef struct hwa_notif_dn_recvd {
	uint8_t		bLength;
	uint8_t		bNotifyType;
	uint8_t		bSourceDeviceAddr;
	uint8_t		bmAttributes;
	uint8_t		notifdata[1];	/* variable length raw data */
} hwa_notif_dn_recvd_t;

/* DWA specific notifications */
#define	DWA_NOTIF_TYPE_RWAKE		0x91
#define	DWA_NOTIF_TYPE_PORTSTATUS	0x92

typedef struct dwa_notif_rwake {
	uint8_t		bLength;
	uint8_t		bNotifyType;
} dwa_notif_rwake;

typedef struct dwa_notif_portstatus {
	uint8_t		bLength;
	uint8_t		bNotifyType;
	uint8_t		bPortIndex;
} dwa_notif_portstatus;


/*
 * *********************************************************************
 * Wire adapter class transfer request related structures and data types
 * *********************************************************************
 */

/* Wire adapter class transfer requests */
#define	WA_XFER_REQ_TYPE_CTRL		0x80
#define	WA_XFER_REQ_TYPE_BULK_INTR	0x81
#define	WA_XFER_REQ_TYPE_ABORT		0x84
/* HWA specific transfer request */
#define	HWA_XFER_REQ_TYPE_ISOC		0x82

/* Wire adapter class transfer request length */
#define	WA_CTRL_REQ_LEN			0x18
#define	WA_BULK_INTR_REQ_LEN		0x10
#define	WA_ABORT_REQ_LEN		0x08
/* HWA specific transfer request length */
#define	HWA_ISOC_REQ_LEN		0x14

typedef struct wa_ctrl_req {
	uint8_t		bLength;
	uint8_t		bRequestType;
	uint16_t	wRPipe;
	uint32_t	dwTransferID;
	uint32_t	dwTransferLength;
	uint8_t		bTransferSegment;
	uint8_t		bmAttribute;
	uint16_t	wReserved;
	uint8_t		baSetupData[8];
} wa_ctrl_req_t;

/* ctrl request bmAttribute */
#define	WA_CTRL_DIR_MASK		0x01
#define	WA_CTRL_DIR_IN			0x01
#define	WA_CTRL_DIR_OUT			0x00

/* ctrl request bmAttribute valid only for HWA */
#define	WA_CTRL_SECRT_MASK		0x02
#define	WA_CTRL_SECRT_REGULAR		0x00
#define	WA_CTRL_SECRT_NONE		0x02

typedef struct wa_bulk_intr_req {
	uint8_t		bLength;
	uint8_t		bRequestType;
	uint16_t	wRPipe;
	uint32_t	dwTransferID;
	uint32_t	dwTransferLength;
	uint8_t		bTransferSegment;
	uint8_t		bReserved;
	uint16_t	wReserved;
} wa_bulk_intr_req_t;

typedef struct wa_abort_req {
	uint8_t		bLength;
	uint8_t		bRequestType;
	uint16_t	wRPipe;
	uint32_t	dwTransferID;
} wa_abort_req_t;


/* HWA specific transfer request definitions */
typedef struct hwa_isoc_req {
	uint8_t		bLength;
	uint8_t		bRequestType;
	uint16_t	wRPipe;
	uint32_t	dwTransferID;
	uint32_t	dwTransferLength;
	uint8_t		bTransferSegment;
	uint8_t		bReserved;
	uint16_t	wPresentationTime;
	uint32_t	dwNumOfPackets;
} wa_isoc_req_t;

typedef struct hwa_isoc_pkt {
	uint16_t	wLength;
	uint8_t		bPacketType;
	uint8_t		bReserved;
	uint16_t	PacketLength[1];	/* variable length array */
} hwa_isoc_pkt_t;

#define	HWA_ISOC_PKT_INFO_TYPE		0xa0

/* Wire adapter class transfer result */
typedef struct wa_xfer_result {
	uint8_t		bLength;
	uint8_t		bResultType;
	uint32_t	dwTransferID;
	uint32_t	dwTransferLength;
	uint8_t		bTransferSegment;
	uint8_t		bTransferStatus;
	uint32_t	dwNumOfPackets;
} wa_xfer_result_t;

#define	WA_RESULT_TYPE_TRANSFER		0x83
#define	WA_XFER_RESULT_LEN		0x10

enum wa_xfer_status {
	WA_STS_SUCCESS = 0,
	WA_STS_HALTED = 1,
	WA_STS_DATA_BUFFER_ERROR = 2,
	WA_STS_BABBLE = 3,
	WA_STS_NOT_FOUND = 5,
	WA_STS_INSUFFICIENT_RESOURCE = 6,
	WA_STS_TRANSACTION_ERROR = 7,
	WA_STS_ABORTED = 8,
	WA_STS_RPIPE_NOT_READY = 9,
	WA_STS_INVALID_REQ_FORMAT = 10,
	WA_STS_UNEXPECTED_SEGMENT_NUM = 11,
	WA_STS_RPIPE_TYPE_MISMATCH = 12,
	WA_STS_PACKET_DISCARDED = 13,
} wa_xfer_status_t;

#define	WA_RPIPE_STATE_FREE		0	/* not assigned */
#define	WA_RPIPE_STATE_IDLE		1	/* configured but not active */
#define	WA_RPIPE_STATE_ACTIVE		2	/* configured and active */
#define	WA_RPIPE_STATE_PAUSE		3	/* configured and paused */
#define	WA_RPIPE_STATE_ERROR		4	/* error */

#define	WA_RPIPE_DEFAULT_TIMEOUT	5
#define	WA_MAX_SEG_COUNT		128	/* 7bit */
#define	WA_DIR_IN			1
#define	WA_DIR_OUT			0

#define	WA_GET_ID(x)		id32_alloc((void *)(x), KM_NOSLEEP)
#define	WA_LOOKUP_ID(x)		id32_lookup((x))
#define	WA_FREE_ID(x)		id32_free((x))

typedef struct wusb_wa_seg {
	void			*seg_wr;	/* wrapper */
	uint8_t			seg_num;
	uint32_t		seg_id;		/* will delete */
	uint32_t		seg_len;
	uint32_t		seg_actual_len;
	uint8_t			seg_status;	/* WA result status */
	uint8_t			seg_state;	/* segment state */
	uint8_t			seg_done;

	usb_bulk_req_t		*seg_trans_reqp; /* for transfer reqp */
	uint8_t			seg_trans_req_state; /* state:submitted */
	kcondvar_t		seg_trans_cv;

	usb_bulk_req_t		*seg_data_reqp;  /* for out data */
	uint8_t			seg_data_req_state; /* state */
	kcondvar_t		seg_data_cv;
} wusb_wa_seg_t;

_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_wa_seg_t::seg_wr
		wusb_wa_seg_t::seg_num
		wusb_wa_seg_t::seg_id
		wusb_wa_seg_t::seg_len
		wusb_wa_seg_t::seg_trans_reqp
		wusb_wa_seg_t::seg_data_reqp))

struct wusb_wa_trans_wrapper;

typedef struct wusb_wa_rpipe_hdl {
	uint_t			rp_state; /* free, idle, active, pause, err */
	kmutex_t		rp_mutex;
	kcondvar_t		rp_cv;
	uint_t			rp_refcnt;	/* for multiplexing */
	timeout_id_t		rp_timer_id;
	usb_wa_rpipe_descr_t	rp_descr;
	uint8_t			rp_block_chg;	/* wBlocks changed? */
	uint16_t		rp_avail_reqs;	/* available req slots */
	void			*rp_curr_wr;	/* current wr */
	struct wusb_wa_trans_wrapper *rp_timeout_list;	/* timeout list */
} wusb_wa_rpipe_hdl_t;

_NOTE(MUTEX_PROTECTS_DATA(wusb_wa_rpipe_hdl_t::rp_mutex, wusb_wa_rpipe_hdl_t))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_wa_rpipe_hdl_t::rp_descr))

typedef struct wusb_wa_data {
	dev_info_t		*wa_dip;
	void			*wa_private_data;

	kmutex_t		wa_mutex;

	uint8_t			wa_ifno;
	usb_if_descr_t		wa_if_descr;
	usb_wa_descr_t		wa_descr;
	uint16_t		wa_avail_blocks; /* available blocks */

	usb_ep_descr_t		wa_intr_ept;
	usb_ep_descr_t		wa_bulkin_ept;
	usb_ep_descr_t		wa_bulkout_ept;

	uint_t			wa_state;
	usb_pipe_policy_t	wa_pipe_policy;

	usb_pipe_handle_t	wa_default_pipe;

	/* INTR IN ep */
	usb_pipe_handle_t	wa_intr_ph;
	usb_pipe_policy_t	wa_intr_pipe_policy;
	uint_t			wa_intr_pipe_state;

	/* BULK IN ep */
	usb_pipe_handle_t	wa_bulkin_ph;
	usb_pipe_policy_t	wa_bulkin_pipe_policy;
	uint_t			wa_bulkin_pipe_state;

	/* BULK OUT ep */
	usb_pipe_handle_t	wa_bulkout_ph;
	usb_pipe_policy_t	wa_bulkout_pipe_policy;
	uint_t			wa_bulkout_pipe_state;

	uint16_t		wa_num_rpipes;
	wusb_wa_rpipe_hdl_t	*wa_rpipe_hdl;

	int  (*pipe_periodic_req)(struct wusb_wa_data *,
		usba_pipe_handle_data_t *);
	void (*intr_cb)(usb_pipe_handle_t ph, struct usb_intr_req *req);
	void (*intr_exc_cb)(usb_pipe_handle_t ph, struct usb_intr_req *req);
	void (*rpipe_xfer_cb)(dev_info_t *dip, usba_pipe_handle_data_t *ph,
	    struct wusb_wa_trans_wrapper *, usb_cr_t cr);
} wusb_wa_data_t;

_NOTE(MUTEX_PROTECTS_DATA(wusb_wa_data_t::wa_mutex, wusb_wa_data_t))

_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_wa_data_t::wa_dip))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_wa_data_t::wa_default_pipe))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_wa_data_t::wa_bulkout_ph))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_wa_data_t::wa_bulkin_ph))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_wa_data_t::wa_intr_ph))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_wa_data_t::wa_ifno
		wusb_wa_data_t::wa_descr
		wusb_wa_data_t::wa_private_data))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_wa_data_t::rpipe_xfer_cb))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_wa_data_t::pipe_periodic_req))

typedef enum {
	WR_NO_ERROR = 0,
	WR_SEG_REQ_ERR = 1,	/* send seg request error */
	WR_SEG_DAT_ERR = 2,	/* send seg data error */
	WR_XFER_ERR = 3,	/* general xfer error */
	WR_ABORTED = 4,		/* aborted */
	WR_TIMEOUT = 5,		/* timeout */
	WR_INTERRUPTED = 6,	/* user interrupted */
	WR_FINISHED = 7,	/* finished successfully */
} wusb_wa_wr_state_t;

typedef struct wusb_wa_trans_wrapper {
	usba_pipe_handle_data_t	*wr_ph;
	wusb_wa_rpipe_hdl_t	*wr_rp;
	wusb_wa_data_t		*wr_wa_data;
	kcondvar_t		wr_cv;	/* cv, use Rpipe's mutex to protect */
	usb_flags_t		wr_flags;
	uint8_t			wr_type;	/* transfer type */
	uint8_t			wr_nsegs;	/* number of segs */
	uint32_t		wr_max_seglen;	/* max data len per seg */
	uint8_t			wr_dir;		/* transfer direction */
	uint32_t		wr_id;		/* unique id */
	usb_opaque_t		wr_reqp;	/* original reqp */
	int			wr_timeout;
	wusb_wa_seg_t		*wr_seg_array;
	uint8_t			wr_curr_seg;	/* next seg to process */
	wusb_wa_wr_state_t	wr_state;	/* 1 - error, not continue */
	uint8_t			wr_has_aborted; /* boolean */
	uint8_t			wr_seg_done;	/* number of segs done */
	void			(*wr_cb)(wusb_wa_data_t *wa_data,
				struct wusb_wa_trans_wrapper *wr,
				usb_cr_t cr,
				uint_t reset_flag);	/* callback func */

	struct wusb_wa_trans_wrapper *wr_timeout_next; /* timeout list */
} wusb_wa_trans_wrapper_t;

_NOTE(MUTEX_PROTECTS_DATA(wusb_wa_rpipe_hdl_t::rp_mutex,
    wusb_wa_trans_wrapper_t))
_NOTE(MUTEX_PROTECTS_DATA(wusb_wa_rpipe_hdl_t::rp_mutex, wusb_wa_seg_t))

_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_wa_trans_wrapper_t::wr_rp))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_wa_trans_wrapper_t::wr_ph))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_wa_trans_wrapper_t::wr_cb))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_wa_trans_wrapper_t::wr_reqp
		wusb_wa_trans_wrapper_t::wr_dir
		wusb_wa_trans_wrapper_t::wr_nsegs
		wusb_wa_trans_wrapper_t::wr_seg_array
		wusb_wa_trans_wrapper_t::wr_id))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_wa_trans_wrapper_t::wr_wa_data))

typedef struct wusb_secrt_data {
	usb_security_descr_t	secrt_descr;
	uint_t			secrt_n_encry;
	usb_encryption_descr_t	*secrt_encry_descr;
} wusb_secrt_data_t;

typedef struct wusb_wa_cb {
	int  (*pipe_periodic_req)(wusb_wa_data_t *,
		usba_pipe_handle_data_t *);
	void (*intr_cb)(usb_pipe_handle_t ph, struct usb_intr_req *req);
	void (*intr_exc_cb)(usb_pipe_handle_t ph, struct usb_intr_req *req);
	void (*rpipe_xfer_cb)(dev_info_t *dip, usba_pipe_handle_data_t *ph,
	    wusb_wa_trans_wrapper_t *, usb_cr_t cr);
} wusb_wa_cb_t;

#define	WA_PIPE_CLOSED		0x00
#define	WA_PIPE_ACTIVE		0x01
#define	WA_PIPE_STOPPED		0X02
#define	WA_PIPE_CLOSING		0x03
#define	WA_PIPE_RESET		0x04

#define	WA_PIPES_OPENED		0x00000001

int	wusb_parse_wa_descr(usb_wa_descr_t *, usb_alt_if_data_t *);
void	wusb_wa_rpipes_init(wusb_wa_data_t *);
void	wusb_wa_rpipes_fini(wusb_wa_data_t *);
int	wusb_wa_data_init(dev_info_t *, wusb_wa_data_t *, wusb_wa_cb_t *,
	usb_client_dev_data_t *, uint_t, usb_log_handle_t);
void	wusb_wa_data_fini(wusb_wa_data_t *);
int	wusb_wa_get_rpipe_descr(dev_info_t *, usb_pipe_handle_t, uint16_t,
	usb_wa_rpipe_descr_t *, uint_t, usb_log_handle_t);
int	wusb_wa_get_rpipe_descrs(wusb_wa_data_t *, usb_pipe_handle_t,
	uint_t, usb_log_handle_t);
int	wusb_get_wa_status(wusb_wa_data_t *, usb_pipe_handle_t, uint32_t *);
int	wusb_wa_reset(wusb_wa_data_t *, usb_pipe_handle_t);
int	wusb_wa_enable(wusb_wa_data_t *, usb_pipe_handle_t);
int	wusb_wa_disable(wusb_wa_data_t *, usb_pipe_handle_t);
int	wusb_wa_open_pipes(wusb_wa_data_t *);
void	wusb_wa_close_pipes(wusb_wa_data_t *);
int	wusb_wa_start_nep(wusb_wa_data_t *, usb_flags_t);
void	wusb_wa_stop_nep(wusb_wa_data_t *);

int	wusb_wa_get_rpipe(wusb_wa_data_t *, usb_pipe_handle_t, uint8_t,
	wusb_wa_rpipe_hdl_t **, uint_t, usb_log_handle_t);
int	wusb_wa_release_rpipe(wusb_wa_data_t *, wusb_wa_rpipe_hdl_t *);
int	wusb_wa_get_ep_comp_descr(usba_pipe_handle_data_t *,
	usb_ep_comp_descr_t *);
int	wusb_wa_set_rpipe_descr(dev_info_t *, usb_pipe_handle_t,
	usb_wa_rpipe_descr_t *);
int	wusb_wa_set_rpipe_target(dev_info_t *, wusb_wa_data_t *,
	usb_pipe_handle_t, usba_pipe_handle_data_t *, wusb_wa_rpipe_hdl_t *);
int	wusb_wa_rpipe_abort(dev_info_t *, usb_pipe_handle_t,
	wusb_wa_rpipe_hdl_t *);
int	wusb_wa_rpipe_reset(dev_info_t *, usba_pipe_handle_data_t *,
	wusb_wa_rpipe_hdl_t *, int);
int	wusb_wa_get_rpipe_status(dev_info_t *, usb_pipe_handle_t, uint16_t,
	uint8_t	*);
wusb_wa_trans_wrapper_t *
wusb_wa_create_ctrl_wrapper(wusb_wa_data_t *, wusb_wa_rpipe_hdl_t *,
	usba_pipe_handle_data_t	*, usb_ctrl_req_t *, usb_flags_t);
wusb_wa_trans_wrapper_t *
wusb_wa_create_bulk_wrapper(wusb_wa_data_t *, wusb_wa_rpipe_hdl_t *,
	usba_pipe_handle_data_t *, usb_bulk_req_t *, usb_flags_t);
wusb_wa_trans_wrapper_t *
wusb_wa_create_intr_wrapper(wusb_wa_data_t *, wusb_wa_rpipe_hdl_t *,
	usba_pipe_handle_data_t *, usb_intr_req_t *, usb_flags_t);
wusb_wa_trans_wrapper_t *
wusb_wa_alloc_ctrl_resources(wusb_wa_data_t *, wusb_wa_rpipe_hdl_t *,
	usba_pipe_handle_data_t *, usb_ctrl_req_t *, usb_flags_t);
wusb_wa_trans_wrapper_t *
wusb_wa_alloc_bulk_resources(wusb_wa_data_t *, wusb_wa_rpipe_hdl_t *,
	usba_pipe_handle_data_t *, usb_bulk_req_t *, usb_flags_t);
wusb_wa_trans_wrapper_t *
wusb_wa_alloc_intr_resources(wusb_wa_data_t *, wusb_wa_rpipe_hdl_t *,
	usba_pipe_handle_data_t *, usb_intr_req_t *, usb_flags_t);

void	wusb_wa_setup_trans_req(wusb_wa_trans_wrapper_t *, wusb_wa_seg_t *,
	uint8_t);
int	wusb_wa_setup_segs(wusb_wa_data_t *, wusb_wa_trans_wrapper_t *,
	uint32_t, mblk_t *);
void	wusb_wa_free_segs(wusb_wa_trans_wrapper_t *);
void	wusb_wa_free_trans_wrapper(wusb_wa_trans_wrapper_t *);

void	wusb_wa_abort_req(wusb_wa_data_t *, wusb_wa_trans_wrapper_t *,
	uint32_t);
int	wusb_wa_wr_xfer(wusb_wa_data_t *, wusb_wa_rpipe_hdl_t *,
	wusb_wa_trans_wrapper_t *, usb_flags_t);
int	wusb_wa_submit_ctrl_wr(wusb_wa_data_t *, wusb_wa_rpipe_hdl_t *,
	wusb_wa_trans_wrapper_t *, usb_ctrl_req_t *, usb_flags_t);
int	wusb_wa_ctrl_xfer(wusb_wa_data_t *, wusb_wa_rpipe_hdl_t *,
	usba_pipe_handle_data_t *, usb_ctrl_req_t *, usb_flags_t);
int	wusb_wa_submit_bulk_wr(wusb_wa_data_t *, wusb_wa_rpipe_hdl_t *,
	wusb_wa_trans_wrapper_t *, usb_bulk_req_t *, usb_flags_t);
int	wusb_wa_bulk_xfer(wusb_wa_data_t *, wusb_wa_rpipe_hdl_t *,
	usba_pipe_handle_data_t *, usb_bulk_req_t *, usb_flags_t);
int	wusb_wa_submit_intr_wr(wusb_wa_data_t *, wusb_wa_rpipe_hdl_t *,
	wusb_wa_trans_wrapper_t *, usb_intr_req_t *, usb_flags_t);
int	wusb_wa_intr_xfer(wusb_wa_data_t *, wusb_wa_rpipe_hdl_t *,
	usba_pipe_handle_data_t *, usb_intr_req_t *, usb_flags_t);

void	wusb_wa_start_xfer_timer(wusb_wa_rpipe_hdl_t *);

void	wusb_wa_xfer_timeout_handler(void *);
void	wusb_wa_stop_xfer_timer(wusb_wa_trans_wrapper_t *);

void	wusb_wa_clear_dev_ep(usba_pipe_handle_data_t *ph);

int	wusb_wa_get_data(wusb_wa_data_t *, wusb_wa_seg_t *, uint32_t);
int	wusb_wa_get_xfer_result(wusb_wa_data_t *);
void	wusb_wa_check_req_done(wusb_wa_data_t *, wusb_wa_trans_wrapper_t *,
	uint8_t);
void	wusb_wa_handle_ctrl(wusb_wa_data_t *, wusb_wa_trans_wrapper_t *,
	usb_cr_t, uint_t);
void	wusb_wa_handle_bulk(wusb_wa_data_t *, wusb_wa_trans_wrapper_t *,
	usb_cr_t, uint_t);
void	wusb_wa_handle_intr(wusb_wa_data_t *, wusb_wa_trans_wrapper_t *,
	usb_cr_t, uint_t);
void	wusb_wa_callback(wusb_wa_data_t *, usba_pipe_handle_data_t *,
	wusb_wa_trans_wrapper_t *, usb_cr_t);
usb_cr_t wusb_wa_sts2cr(uint8_t);


#ifdef __cplusplus
}
#endif

#endif /* _SYS_USB_WA_H */

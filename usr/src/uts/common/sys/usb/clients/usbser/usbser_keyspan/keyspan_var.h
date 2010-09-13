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

#ifndef _SYS_USB_USBSER_KEYSPAN_VAR_H
#define	_SYS_USB_USBSER_KEYSPAN_VAR_H


/*
 * keyspan implementation definitions
 */

#include <sys/types.h>
#include <sys/dditypes.h>
#include <sys/note.h>

#include <sys/usb/clients/usbser/usbser_dsdi.h>

#include <sys/usb/clients/usbser/usbser_keyspan/usa90msg.h>
#include <sys/usb/clients/usbser/usbser_keyspan/usa49msg.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* product id */
#define	KEYSPAN_USA19HS_PID		0x121
#define	KEYSPAN_USA49WLC_PID		0x12a
#define	KEYSPAN_USA49WG_PID		0x131

#define	KEYSPAN_MAX_PORT_NUM		4

/*
 * forward typedefs needed to resolve recursive header dependencies
 */
typedef struct keyspan_pre_state keyspan_pre_state_t;
typedef struct keyspan_state keyspan_state_t;
typedef struct keyspan_port keyspan_port_t;

#include <sys/usb/clients/usbser/usbser_keyspan/keyspan_pipe.h>

/*
 * temporary soft state for pre_attach
 */
struct keyspan_pre_state {
	dev_info_t		*kb_dip;	/* device info */
	int			kb_instance;	/* instance */
	usb_client_dev_data_t	*kb_dev_data;	/* registration data */
	usb_log_handle_t	kb_lh;		/* USBA log handle */
	keyspan_pipe_t		kb_def_pipe;	/* default pipe */
};

/* Firmware structure */
typedef struct usbser_keyspan_fw_record {
	uint16_t address;
	uint8_t data_len;
	uint8_t data[64];
} usbser_keyspan_fw_record_t;

#define	ezusb_hex_record usbser_keyspan_fw_record

/*
 * PM support
 */
typedef struct keyspan_power {
	uint8_t		pm_wakeup_enabled;	/* remote wakeup enabled */
	uint8_t		pm_pwr_states;	/* bit mask of power states */
	boolean_t	pm_raise_power;	/* driver is about to raise power */
	uint8_t		pm_cur_power;	/* current power level */
	uint_t		pm_busy_cnt;	/* number of set_busy requests */
} keyspan_pm_t;

/*
 * device specific info structure
 */
typedef struct keyspan_dev_spec {

	uint16_t	id_product;	/* product ID value */
	uint8_t		port_cnt;	/* How many ports on the device */
	uint8_t	ctrl_ep_addr;	/* Endpoint used to control the device */
	uint8_t	stat_ep_addr;	/* Endpoint used to get device status */
	uint8_t	dataout_ep_addr[4];	/* Endpoint used to send data */

	/* Endpoint used to get data from device */
	uint8_t	datain_ep_addr[4];
} keyspan_dev_spec_t;

/*
 * To support different keyspan adapters, use union type
 * for different cmd msg format.
 */
typedef union keyspan_port_ctrl_msg {
	keyspan_usa19hs_port_ctrl_msg_t	usa19hs;
	keyspan_usa49_port_ctrl_msg_t usa49;
} keyspan_port_ctrl_msg_t;

/*
 * To support different keyspan adapters, use union type
 * for different status msg format.
 */
typedef union keyspan_port_status_msg {
	keyspan_usa19hs_port_status_msg_t	usa19hs;
	keyspan_usa49_port_status_msg_t usa49;
} keyspan_port_status_msg_t;

/*
 * per device state structure
 */
struct keyspan_state {
	kmutex_t		ks_mutex;	/* structure lock */
	dev_info_t		*ks_dip;	/* device info */
	keyspan_port_t		*ks_ports;	/* per port structs */
	keyspan_dev_spec_t	ks_dev_spec;	/* device specific info */

	/*
	 * we use semaphore to serialize pipe open/close by different ports.
	 * mutex could be used too, but it causes trouble when warlocking
	 * with USBA: some functions inside usb_pipe_close() wait on cv
	 *
	 * since semaphore is only used for serialization during
	 * open/close and suspend/resume, there is no deadlock hazard
	 */
	ksema_t			ks_pipes_sema;

	/*
	 * USBA related
	 */
	usb_client_dev_data_t	*ks_dev_data;	/* registration data */
	usb_event_t		*ks_usb_events;	/* usb events */

	keyspan_pipe_t		ks_def_pipe;	/* default pipe */

	/* bulk in pipe for getting device status */
	keyspan_pipe_t		ks_statin_pipe;

	/* bulk out pipe for sending control cmd to device */
	keyspan_pipe_t		ks_ctrlout_pipe;

	usb_log_handle_t	ks_lh;		/* USBA log handle */
	int			ks_dev_state;	/* USB device state */
	keyspan_pm_t		*ks_pm;		/* PM support */

	/*
	 * The following only used on USA_49WG
	 */
	/* Shared bulk in pipe handle */
	usb_pipe_handle_t	ks_datain_pipe_handle;

	/* counter for opened bulk in pipe */
	uint8_t			ks_datain_open_cnt;

	/* Flag for device reconnect */
	uint8_t			ks_reconnect_flag;

};

_NOTE(MUTEX_PROTECTS_DATA(keyspan_state::ks_mutex, keyspan_state))
_NOTE(DATA_READABLE_WITHOUT_LOCK(keyspan_state::{
	ks_dip
	ks_dev_data
	ks_usb_events
	ks_dev_spec
	ks_ports
	ks_def_pipe
	ks_ctrlout_pipe.pipe_handle
	ks_statin_pipe.pipe_handle
	ks_lh
	ks_pm
}))

/*
 * per port structure
 */
struct keyspan_port {
	kmutex_t	kp_mutex;	/* structure lock */
	keyspan_state_t	*kp_ksp;	/* back pointer to the state */
	char		kp_lh_name[16];	/* log handle name */
	usb_log_handle_t kp_lh;		/* log handle */
	uint_t		kp_port_num;	/* port number */
	int		kp_state;	/* port state */
	int		kp_flags;	/* port flags */
	ds_cb_t		kp_cb;		/* DSD callbacks */
	kcondvar_t	kp_tx_cv;	/* cv to wait for tx completion */
	/*
	 * data receipt and transmit
	 */
	mblk_t		*kp_rx_mp;	/* received data */
	mblk_t		*kp_tx_mp;	/* data to transmit */
	boolean_t	kp_no_more_reads; /* disable reads */

	/* The control cmd sent to the port */
	keyspan_port_ctrl_msg_t	kp_ctrl_msg;

	/* status msg of the port */
	keyspan_port_status_msg_t	kp_status_msg;

	uint_t kp_baud;	/* the current baud speed code */
	uint8_t	kp_lcr;	/* the current lcr value */
	/*
	 * the current port status, including: rts, dtr,
	 * break, loopback, enable.
	 */
	uint8_t	kp_status_flag;

	keyspan_pipe_t		kp_datain_pipe;	/* bulk in data pipe */
	keyspan_pipe_t		kp_dataout_pipe; /* bulk out data pipe */

	uint_t		kp_read_len;	/* max length of bulkin request */
	uint_t		kp_write_len;	/* max length of bulkout request */
};

_NOTE(MUTEX_PROTECTS_DATA(keyspan_port::kp_mutex, keyspan_port))
_NOTE(DATA_READABLE_WITHOUT_LOCK(keyspan_port::{
	kp_ksp
	kp_lh
	kp_port_num
	kp_read_len
	kp_write_len
	kp_cb
	kp_datain_pipe.pipe_handle
	kp_datain_pipe.pipe_ep_descr
}))

/* lock relationships */
_NOTE(LOCK_ORDER(keyspan_state::ks_mutex keyspan_port::kp_mutex))
_NOTE(LOCK_ORDER(keyspan_port::kp_mutex keyspan_pipe::pipe_mutex))

/* port status flags */
enum {
	KEYSPAN_PORT_ENABLE = 0x0001,		/* port is enabled */
	KEYSPAN_PORT_RTS = 0x0002,		/* port's rts is set */
	KEYSPAN_PORT_DTR = 0x0004,		/* port's dtr is set */
	KEYSPAN_PORT_TXBREAK = 0x0008,		/* port is in TX break mod */
	KEYSPAN_PORT_LOOPBACK = 0x0010,		/* port is in loopback mod */

	/* the ctrl cmd sent to this port is responded */
	KEYSPAN_PORT_CTRLRESP = 0x0020,
	KEYSPAN_PORT_RXBREAK = 0x0040		/* port is in RX break mod */
};

/* port state */
enum {
	KEYSPAN_PORT_NOT_INIT = 0,	/* port is not initialized */
	KEYSPAN_PORT_CLOSED,		/* port is closed */
	KEYSPAN_PORT_OPENING,		/* port is being opened */
	KEYSPAN_PORT_OPEN		/* port is open */
};

/* port flags */
enum {
	KEYSPAN_PORT_TX_STOPPED	= 0x0001	/* transmit not allowed */
};

/* various tunables */
enum {
	KEYSPAN_BULK_TIMEOUT		= 3,	/* transfer timeout */
	KEYSPAN_BULKIN_MAX_LEN		= 64,	/* bulk in max length */
	KEYSPAN_BULKIN_MAX_LEN_49WG	= 512,	/* bulk in max length */
	/*
	 * From keyspan spec, USA49WLC max packet length for bulk out transfer
	 * is 64, the format is [status byte][up to 63 data bytes], so the
	 * max data length per transfer is 63 bytes, USA19HS doesn't need
	 * extra status byte. USA49WG max packet length for bulk out transfer
	 * is 512, the format is [status byte][63 data bytes]...[status byte]
	 * [up to 63 data bytes], so the max data length per transfer is 504
	 * bytes, while the port0 use intr out pipe send data, the packet
	 * format is the same as USA49WLC, so the max data length for USA49WG
	 * port0 is 63 bytes.
	 */
	KEYSPAN_BULKOUT_MAX_LEN_19HS	= 64,	/* for 19HS only */
	KEYSPAN_BULKOUT_MAX_LEN_49WLC	= 63,	/* for 49WLC and 49WG port0 */
	KEYSPAN_BULKOUT_MAX_LEN_49WG	= 504,	/* for 49WG other ports */
	KEYSPAN_STATIN_MAX_LEN		= 16	/* status in max length */
};

/* This flag indicates if the firmware already downloaded to the device */
#define	KEYSPAN_FW_FLAG 0x8000

/* Vendor specific ctrl req, used to set/download bytes in the device memory */
#define	KEYSPAN_REQ_SET 0xa0
/* Vendor specific ctrl req, used to send ctrl command for USA_49WG model */
#define	KEYSPAN_SET_CONTROL_REQUEST	0xB0

/*
 * debug printing masks
 */
#define	DPRINT_ATTACH		0x00000001
#define	DPRINT_OPEN		0x00000002
#define	DPRINT_CLOSE		0x00000004
#define	DPRINT_DEF_PIPE		0x00000010
#define	DPRINT_IN_PIPE		0x00000020
#define	DPRINT_OUT_PIPE		0x00000040
#define	DPRINT_INTR_PIPE	0x00000080
#define	DPRINT_PIPE_RESET	0x00000100
#define	DPRINT_IN_DATA		0x00000200
#define	DPRINT_OUT_DATA		0x00000400
#define	DPRINT_CTLOP		0x00000800
#define	DPRINT_HOTPLUG		0x00001000
#define	DPRINT_PM		0x00002000
#define	DPRINT_MASK_ALL		0xFFFFFFFF

/*
 * misc macros
 */
#define	NELEM(a)	(sizeof (a) / sizeof (*(a)))

/* common DSD functions */
int	keyspan_tx_copy_data(keyspan_port_t *, mblk_t *, int);
void	keyspan_tx_start(keyspan_port_t *, int *);
void	keyspan_put_tail(mblk_t **, mblk_t *);
void	keyspan_put_head(mblk_t **, mblk_t *, keyspan_port_t *);

void	keyspan_bulkin_cb(usb_pipe_handle_t, usb_bulk_req_t *);
void	keyspan_bulkout_cb(usb_pipe_handle_t, usb_bulk_req_t *);

int	keyspan_restore_device(keyspan_state_t *);
int	keyspan_send_cmd(keyspan_port_t *);

int	keyspan_dev_is_online(keyspan_state_t *);


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USB_USBSER_KEYSPAN_VAR_H */

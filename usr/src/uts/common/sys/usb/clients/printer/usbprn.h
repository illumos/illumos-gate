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

#ifndef _SYS_USB_USBPRN_H
#define	_SYS_USB_USBPRN_H


#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/usb/usba/usbai_private.h>

/*
 * This header file contains internal driver structures info
 *
 * Write timeout values for 1K of data transfer
 */
#define	USBPRN_XFER_TIMEOUT	90	/* default timeout is 90 seconds */
#define	USBPRN_XFER_TIMEOUT_MIN	1	/* min timeout is 1 second */
#define	USBPRN_XFER_TIMEOUT_MAX	300	/* max timeout is 5 minutes */

/* ps_flags values */
#define	USBPRN_PS_IDLE			0x00 /* no activity on any pipe */
#define	USBPRN_PS_NEED_TO_XFER		0x01 /* transfer to start */

/* Maximum transfer size */
#define	USBPRN_MAX_XFER_SIZE	(8 * 1024)

/*
 * Per pipe state information
 */
typedef struct usbprn_ps {
	usb_ep_descr_t		ps_ept_descr;	/* endpoint descriptor */
	usb_pipe_handle_t	ps_handle;	/* pipe handle */
	usb_pipe_policy_t	ps_policy;	/* pipe policy */
	int			ps_flags;	/* state flags */
	int			ps_cr;		/* save last cr */
} usbprn_ps_t;

_NOTE(SCHEME_PROTECTS_DATA("USBA", usbprn_ps::ps_handle))

/*
 * PM support
 */
typedef struct usbprn_power  {
	/* device busy accounting */
	int		usbprn_pm_busy;
	uint8_t		usbprn_wakeup_enabled;

	/* this is the bit mask of the power states that device has */
	uint8_t		usbprn_pwr_states;

	/* wakeup and power transistion capabilites of an interface */
	uint8_t		usbprn_pm_capabilities;

	uint8_t		usbprn_current_power;
} usbprn_power_t;


/*
 * State structure
 */
typedef struct usbprn_state {
	dev_info_t	*usbprn_dip;		/* per-device info handle */
	int		usbprn_dev_state;	/* USB device state */
	kmutex_t	usbprn_mutex;		/* for general locking */
	int		usbprn_instance;	/* instance number */
	int		usbprn_flags;

	usb_client_dev_data_t *usbprn_dev_data;	/* registration data */

	size_t		usbprn_max_bulk_xfer_size;	/* max txfer size */
	char		*usbprn_device_id;	/* Device id string */
	int		usbprn_device_id_len;	/* Device id length */

	/* serialize access */
	usb_serialization_t usbprn_ser_acc;
	usb_serialization_t usbprn_write_acc;
	usb_serialization_t usbprn_dev_acc;

	/* mblk_t that contains the data to be sent */
	mblk_t		*usbprn_bulk_mp;

	struct	buf	*usbprn_bp;		/* Buffer ptr for strategy */

	usb_pipe_handle_t usbprn_def_ph;	/* default pipe handle */

	usbprn_ps_t	usbprn_bulk_out;	/* bulk out info */
	usbprn_ps_t	usbprn_bulk_in;		/* bulk in info */

	usb_log_handle_t usbprn_log_handle;	/* log handle */
	usb_cfg_descr_t usbprn_config_descr;	/* config desc */
	usb_if_descr_t	 usbprn_if_descr;	/* interface descr */

	char		usbprn_last_status;	/* last port status */

	usbprn_power_t	*usbprn_pm;		/* Power components */

	struct ecpp_transfer_parms usbprn_setparms; /* Set xfer parameters */
	struct prn_timeouts	usbprn_prn_timeouts;	/* prnio timeouts */

	usb_ugen_hdl_t	usbprn_ugen_hdl;		/* ugen support */
} usbprn_state_t;

/* warlock directives, stable data */
_NOTE(MUTEX_PROTECTS_DATA(usbprn_state_t::usbprn_mutex, usbprn_state_t))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usbprn_state_t::usbprn_dip))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usbprn_state_t::usbprn_ugen_hdl))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usbprn_state_t::usbprn_pm))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usbprn_state_t::usbprn_instance))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usbprn_state_t::usbprn_log_handle))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usbprn_state_t::usbprn_if_descr))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usbprn_state_t::usbprn_dev_data))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usbprn_state_t::usbprn_ser_acc))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usbprn_state_t::usbprn_write_acc))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usbprn_state_t::usbprn_dev_acc))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usbprn_state_t::usbprn_def_ph))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usbprn_state_t::usbprn_device_id))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usbprn_state_t::usbprn_device_id_len))
_NOTE(SCHEME_PROTECTS_DATA("stable data", usb_pipe_policy))
_NOTE(SCHEME_PROTECTS_DATA("unshared data", mblk_t))
_NOTE(SCHEME_PROTECTS_DATA("unshared data", usb_bulk_req))


/* Values for usbprn_flags */
#define	USBPRN_LOCKS_INIT_DONE	0x01	/* locks have been init'ed */
#define	USBPRN_OPEN		0x02	/* Device is open */


/* Macros */

/*
 * Check if it the device is not being closed
 * or not being disconnected or not being suspended
 */
#define	USBPRN_DEVICE_ACCESS_OK(s) \
	(((s)->usbprn_flags & USBPRN_OPEN) && \
	(((s)->usbprn_dev_state == USB_DEV_ONLINE)))

/* Check if the pipes are idle or closed */
#define	USBPRN_PIPES_BUSY(s) \
	(((s)->usbprn_default.ps_flags != USBPRN_PS_IDLE) || \
	((s)->usbprn_bulk_out.ps_flags != USBPRN_PS_IDLE) || \
	((s)->usbprn_bulk_in.ps_flags != USBPRN_PS_IDLE))

/*
 * Debug message Masks
 */
#define	PRINT_MASK_ATTA		0x00000001	/* attach/detach */
#define	PRINT_MASK_OPEN		0x00000002
#define	PRINT_MASK_CLOSE	0x00000004
#define	PRINT_MASK_EVENTS	0x00000008
#define	PRINT_MASK_PM		0x00000010
#define	PRINT_MASK_CPR		0x00000020
#define	PRINT_MASK_ALL		0xFFFFFFFF

/* log message breakup */
#define	USBPRN_PRINT_MAXLINE	80

/* max device id length */
#define	USBPRN_MAX_DEVICE_ID_LENGTH	1024

/* ugen support */
#define	USBPRN_MINOR_UGEN_BITS_MASK	0xff
#define	USBPRN_MINOR_INSTANCE_SHIFT	8
#define	USBPRN_MINOR_INSTANCE_MASK	~USBPRN_MINOR_UGEN_BITS_MASK
#define	USBPRN_MINOR_TO_INSTANCE(minor) \
	(((minor) & USBPRN_MINOR_INSTANCE_MASK) >> \
	USBPRN_MINOR_INSTANCE_SHIFT)


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_USBPRN_H */

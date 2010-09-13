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

#ifndef	_SYS_USB_HWAHC_H
#define	_SYS_USB_HWAHC_H

#ifdef	__cplusplus
extern "C" {
#endif


#include <sys/usb/usba/wa.h>
#include <sys/usb/hubd/hub.h>
#include <sys/usb/hubd/hubdvar.h>
#include <sys/usb/usba/hcdi.h>
#include <sys/usb/usba/whcdi.h>
#include <sys/disp.h>
#include <sys/sunldi.h>

/*
 * Power Management support
 */
typedef struct hwahc_power  {
	void		*hwahc_state;	/* points back to hwahc_state */
	uint8_t		hwahc_pwr_states; /* bit mask of device pwr states */
	int		hwahc_pm_busy; /* device busy counting */
	uint8_t		hwahc_wakeup_enabled;

	/* wakeup and power transistion capabilites of an interface */
	uint8_t		hwahc_pm_capabilities;

	/* current power level the device is in */
	uint8_t		hwahc_current_power;
} hwahc_power_t;

_NOTE(DATA_READABLE_WITHOUT_LOCK(hwahc_power_t::hwahc_wakeup_enabled))

/* softstate init state */
#define	HWAHC_LOCK_INITED		0x0001
#define	HWAHC_HUBDI_REGISTERED		0x0002
#define	HWAHC_MINOR_NODE_CREATED	0x0004
#define	HWAHC_EVENTS_REGISTERED		0x0010
#define	HWAHC_HUBREG			0x0020
#define	HWAHC_WA_INITED			0x0040
#define	HWAHC_HCDI_REGISTERED		0x0080
#define	HWAHC_HC_INITED			0x0400
#define	HWAHC_WA_STARTED		0x0800

/* hardware operation state */
#define	HWAHC_HW_STOPPED		0
#define	HWAHC_HW_STARTED		1
#define	HWAHC_HW_CH_STOPPED		2
#define	HWAHC_HW_CH_SUSPEND		3

/* Tracking events registered by children */
#define	HWAHC_CHILD_EVENT_DISCONNECT	0x01
#define	HWAHC_CHILD_EVENT_PRESUSPEND	0x02

/* Host controller software states */
#define	HWAHC_CTRL_INIT_STATE		0	/* Initialization state */
#define	HWAHC_CTRL_SUSPEND_STATE	1	/* Suspend state */
#define	HWAHC_CTRL_OPERATIONAL_STATE	2	/* Operational state */
#define	HWAHC_CTRL_ERROR_STATE		3	/* Error state */

/* Host controller pipe states */
#define	HWAHC_PIPE_STATE_IDLE		1	/* Pipe is in ready state */
#define	HWAHC_PIPE_STATE_ACTIVE		2	/* Pipe is in busy state */
#define	HWAHC_PIPE_STATE_ERROR		3	/* Pipe is in error state */

/* Additional pipe states for the hwahc_pipe_cleanup */
#define	HWAHC_PIPE_STATE_CLOSE		4	/* Pipe close */
#define	HWAHC_PIPE_STATE_RESET		5	/* Pipe reset */
#define	HWAHC_PIPE_STATE_STOP_POLLING	6	/* Pipe stop polling */

typedef struct hwahc_pipe_private {
	usba_pipe_handle_data_t	*pp_pipe_handle;
	uint_t			pp_state;
	usb_pipe_policy_t	pp_policy;
	wusb_wa_rpipe_hdl_t	*pp_rp;
	wusb_dev_info_t		*pp_wdev; /* parent device */

	/*
	 * To support Intr/Isoc IN polling.
	 * Save the original client's request
	 */
	usb_opaque_t		pp_client_periodic_in_reqp;
	kcondvar_t		pp_xfer_cmpl_cv;
} hwahc_pipe_private_t;

_NOTE(DATA_READABLE_WITHOUT_LOCK(hwahc_pipe_private_t::pp_pipe_handle))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hwahc_pipe_private_t::pp_rp))
_NOTE(DATA_READABLE_WITHOUT_LOCK(
    hwahc_pipe_private_t::pp_client_periodic_in_reqp))

/*
 * Softstate structure
 */
typedef struct hwahc_state {
	int			hwahc_instance;
	uint_t			hwahc_flags;
	uint_t			hwahc_dev_state;	/* USB device states */
	usb_log_handle_t	hwahc_log_handle;

	hwahc_power_t		*hwahc_pm;
	dev_info_t		*hwahc_dip;		/* device info handle */

	/* mutex to protect softstate and hw regs */
	kmutex_t		hwahc_mutex;

	hubd_t			*hwahc_hubd;
	int			hwahc_hw_state;		/* hc start flag */
	uint_t			hwahc_open_count;

	int			hwahc_hc_soft_state;	/* driver states. */

	/* default pipe handle as a usba client device */
	usb_pipe_handle_t	hwahc_default_pipe;

	uint_t			hwahc_open_pipe_count;

	/* wire adapter common data */
	wusb_wa_data_t		hwahc_wa_data;
	wusb_secrt_data_t	hwahc_secrt_data;

	/* WUSB HC common data. hold HC and children info */
	wusb_hc_data_t		hwahc_hc_data;

	/* for DN notification */
	usba_list_entry_t	hwahc_dn_notif_queue;
	kthread_t		*hwahc_notif_thread_id;

	/* for transfer result notification */
	kthread_t		*hwahc_result_thread_id;
	kcondvar_t		hwahc_result_thread_cv;

	int8_t			hwahc_bus_pwr; /* bus power event count */

	/* track event registration of children */
	uint8_t			hwahc_child_events[128];

	ndi_event_hdl_t		hwahc_ndi_event_hdl;

	usb_client_dev_data_t	*hwahc_dev_data;	/* registration data */
	usba_hcdi_ops_t		*hwahc_hcdi_ops;	/* HCDI structure */

} hwahc_state_t;

/* warlock directives */
_NOTE(MUTEX_PROTECTS_DATA(hwahc_state_t::hwahc_mutex, hwahc_state_t))
_NOTE(MUTEX_PROTECTS_DATA(hwahc_state_t::hwahc_mutex, hwahc_pipe_private_t))
_NOTE(MUTEX_PROTECTS_DATA(hwahc_state_t::hwahc_mutex,
	hwahc_pipe_private_t::pp_state))
_NOTE(MUTEX_PROTECTS_DATA(hwahc_state_t::hwahc_mutex, hwahc_power_t))

_NOTE(DATA_READABLE_WITHOUT_LOCK(hwahc_state_t::hwahc_log_handle))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hwahc_state_t::hwahc_wa_data))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hwahc_state_t::hwahc_dip))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hwahc_state_t::hwahc_default_pipe))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hwahc_state_t::hwahc_ndi_event_hdl))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hwahc_state_t::hwahc_pm
		hwahc_state_t::hwahc_hubd))

_NOTE(SCHEME_PROTECTS_DATA("stable data", usb_ep_comp_descr))
_NOTE(SCHEME_PROTECTS_DATA("stable data", usba_device_t))

/* Debug masks */
#define	PRINT_MASK_ATTA		0x00000001	/* Attach time */
#define	PRINT_MASK_RPIPES	0x00000002	/* Rpipe management */
#define	PRINT_MASK_HUB		0x00000004	/* Hub related stuff */
#define	PRINT_MASK_EVENTS	0x00000008	/* Intr notification */
#define	PRINT_MASK_SECURITY	0x00000020	/* Security info */
#define	PRINT_MASK_CBOPS	0x00000040	/* CB-OPS */
#define	PRINT_MASK_HCDI		0x00000080	/* HCDI entry points */
#define	PRINT_MASK_DUMPING	0x00000100	/* Dump hwa info */
#define	PRINT_MASK_OPEN		0x00000200	/* Open time */
#define	PRINT_MASK_CLOSE	0x00000400	/* Close time */
#define	PRINT_MASK_PM		0x00000800	/* For pwr mgmt */
#define	PRINT_MASK_ALL		0xFFFFFFFF

#define	HWAHC_MINOR_HUB_BITS_MASK		0xff
#define	HWAHC_MINOR_INSTANCE_MASK		~HWAHC_MINOR_HUB_BITS_MASK
#define	HWAHC_MINOR_INSTANCE_SHIFT	8

#define	HWAHC_MINOR_TO_INSTANCE(minor)	\
		(((minor) & HWAHC_MINOR_INSTANCE_MASK) >> \
		HWAHC_MINOR_INSTANCE_SHIFT)

#define	HWAHC_CONSTRUCT_MINOR(inst)	\
		(inst << HWAHC_MINOR_INSTANCE_SHIFT)

/* base of MAC layer dev address for HWA class device */
#define	HWAHC_DEV_ADDR_BASE		0xA100

typedef struct hwahc_dn_notif_list {
	hwa_notif_dn_recvd_t	*dn_notif;
	usba_list_entry_t	notif_list;
} hwahc_dn_notif_list_t;

_NOTE(MUTEX_PROTECTS_DATA(hwahc_state_t::hwahc_mutex, hwahc_dn_notif_list_t))

/* max elements in notification queue */
#define	HWAHC_MAX_NOTIF			100

/* notification queue drain timeout - 60sec */
#define	HWAHC_NOTIF_DRAIN_TIMEOUT	60

/*
 * cfgadm state values
 */
#define	HWAHC_CFGADM_NORMAL		0	/* normal state */
#define	HWAHC_CFGADM_DISCONNECTED	1	/* logically disconnected */
#define	HWAHC_CFGADM_UNCONFIGURED	2	/* port is unconfigured */
#define	HWAHC_CFGADM_EMPTY		3	/* port is empty */
#define	HWAHC_CFGADM_STILL_REFERENCED	4	/* ndi_devi_offline failed */
#define	HWAHC_CFGADM_CONFIGURED		5	/* port is configured */
#define	HWAHC_CFGADM_INVALID		0xFF	/* invalid state */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_USB_HWAHC_H */

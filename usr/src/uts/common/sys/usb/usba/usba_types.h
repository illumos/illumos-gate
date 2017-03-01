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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */

#ifndef	_SYS_USB_USBA_USBA_TYPES_H
#define	_SYS_USB_USBA_USBA_TYPES_H


#include <sys/taskq.h>
#include <sys/usb/usba/usba_private.h>
#include <sys/usb/usba/usbai_private.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* backup structure for opaque usb_pipe_handle_t */
typedef struct usba_ph_impl {
	kmutex_t			usba_ph_mutex;
	struct usba_pipe_handle_data	*usba_ph_data;	/* actual pipe handle */
	dev_info_t			*usba_ph_dip;	/* owner dip */
	usb_ep_descr_t			usba_ph_ep;	/* save ep descr */
	usb_pipe_policy_t		usba_ph_policy; /* saved pipe policy */
	uint_t				usba_ph_flags;

	/*
	 * usba_ph_ref_count is a count of the number of
	 * concurrent activities on this pipe
	 */
	int				usba_ph_ref_count;

	/* pipe state management */
	usb_pipe_state_t		usba_ph_state;
	int				usba_ph_state_changing;
} usba_ph_impl_t;

_NOTE(MUTEX_PROTECTS_DATA(usba_ph_impl::usba_ph_mutex, usba_ph_impl))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_ph_impl::usba_ph_data))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_ph_impl::usba_ph_dip))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_ph_impl::usba_ph_ep))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_ph_impl::usba_ph_policy))

/* for usba_ph_flags */
#define	USBA_PH_DATA_TOGGLE		0x01	/* mask for data toggle */
#define	USBA_PH_DATA_PERSISTENT 	0x02	/* persistent pipe */


/*
 * usba_pipe_handle_data
 *	allocated by USBA and used by USBA and HCD but opaque to
 *	client driver
 *
 *	pipes can be shared but pipe_handles are unique
 *
 * p_hcd_private is a pointer to private data for HCD. This space
 * is allocated and maintained by HCD
 */
typedef struct	usba_pipe_handle_data {
	struct usba_ph_impl	*p_ph_impl;	/* backpointer to ph_impl */

	/* For linking pipe requests on the pipe */
	usba_list_entry_t	p_queue;

	/* shared usba_device structure */
	struct usba_device	*p_usba_device;	/* set on pipe open */

	/*
	 * Pipe policy and endpoint descriptor for this pipe
	 *
	 * Both the basic and extended endpoints are kept around even though
	 * we're duplicating data as most of the HCI drivers are relying on the
	 * presence of p_ep.
	 */
	usb_pipe_policy_t	p_policy;	/* maintained by USBA */
	usb_ep_descr_t		p_ep;
	usb_ep_xdescr_t		p_xep;

	/* passed during open. needed for reset etc. */
	dev_info_t		*p_dip;

	/* access control */
	kmutex_t		p_mutex;   /* mutex protecting pipe handle */

	/* per-pipe private data for HCD */
	usb_opaque_t		p_hcd_private;

	/* per-pipe private data for client */
	usb_opaque_t		p_client_private;

	/*
	 * p_req_count is the count of number requests active
	 * on this pipe
	 */
	int			p_req_count;

	/* private use by USBA */
	usb_opaque_t		p_usba_private;

	/*
	 * each pipe handle has its own taskq for callbacks and async reqs
	 * Note that this will not be used for normal callbacks if
	 * USB_FLAGS_SERIALIZED_CB is passed to usb_pipe_open().
	 */
	taskq_t			*p_taskq;

	/* thread currently serving the queue */
	kthread_t		*p_thread_id;

	/* cb queue serviced by taskq thread */
	usba_list_entry_t	p_cb_queue;

	/* count for soft interrupts */
	uint_t			p_soft_intr;

	/* flag for special things */
	uint_t			p_spec_flag;

} usba_pipe_handle_data_t;

#define	USBA_PH_FLAG_USE_SOFT_INTR	0x1
#define	USBA_PH_FLAG_TQ_SHARE		0x2	/* Shared TaskQ for callbacks */



/* macro to get the endpoint descriptor */
#define	USBA_DEFAULT_PIPE_EP	0	/* ep 0 is default pipe */
#define	USBA_PH2ENDPOINT(ph)  (((usba_pipe_handle_data_t *)(ph))->p_ep)

#define	USBA_PIPE_CLOSING(state) \
		(((state) == USB_PIPE_STATE_CLOSING) || \
		((state) == USB_PIPE_STATE_CLOSED))

#define	USBA_IS_DEFAULT_PIPE(ph)  ((ph) == \
	(ph)->p_usba_device->usb_ph_list[USBA_DEFAULT_PIPE_EP].usba_ph_data)

_NOTE(MUTEX_PROTECTS_DATA(usba_pipe_handle_data::p_mutex, \
	usba_pipe_handle_data))

/* these should be really stable data */
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_pipe_handle_data::p_ph_impl))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_pipe_handle_data::p_usba_device))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_pipe_handle_data::p_hcd_private))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_pipe_handle_data::p_client_private))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_pipe_handle_data::p_ep))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_pipe_handle_data::p_dip))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_pipe_handle_data::p_taskq))


/*
 * usb_addr:
 *	This is	the USB	address	of a device
 */
typedef	uchar_t usb_addr_t;

#define	USBA_DEFAULT_ADDR	0

/*
 * number of endpoint per device, 16 IN and 16 OUT.
 * this define is used for pipehandle list, pipe reserved list
 * and pipe open count array.
 * these lists are indexed by endpoint number * ((address & direction)? 2 : 1)
 *
 * We use a bit mask for exclusive open tracking and therefore
 * USB_N_ENDPOINTS must be equal to the bit size of int.
 *
 */
#define	USBA_N_ENDPOINTS		32

/*
 * USB spec defines 4 different power states of any usb device.
 * They are D0, D1, D2 & D3. So, we need a total of 5 pm-components
 * 4 for power and 1 for name.
 */
#define	USBA_N_PMCOMP		5

/*
 * usb port status
 */
typedef uint8_t usb_port_status_t;
typedef uint16_t usb_port_t;
typedef uint32_t usb_port_mask_t;

/*
 * Note, faster speeds should always be in increasing values. Various parts of
 * the stack use >= comparisons for things which are true for say anything equal
 * to or greater than USB 2.0.
 */
#define	USBA_LOW_SPEED_DEV	0x1
#define	USBA_FULL_SPEED_DEV	0x2
#define	USBA_HIGH_SPEED_DEV	0x3
#define	USBA_SUPER_SPEED_DEV	0x4

/*
 * NDI event is registered on a per-dip basis. usba_device can be
 * shared by multiple dips, hence the following structure is
 * need to keep per-dip event info.
 */
typedef struct usba_evdata {
	struct usba_evdata	*ev_next;
	dev_info_t		*ev_dip;

	/* NDI evetn service callback ids */
	ddi_callback_id_t	ev_rm_cb_id;
	ddi_callback_id_t	ev_ins_cb_id;
	ddi_callback_id_t	ev_suspend_cb_id;
	ddi_callback_id_t	ev_resume_cb_id;
} usba_evdata_t;

/*
 * a client may request dev_data multiple times (eg. for
 * ugen support) so we need a linked list
 */
typedef struct usb_client_dev_data_list {
	struct usb_client_dev_data_list *cddl_next;
	struct usb_client_dev_data_list *cddl_prev;
	dev_info_t			*cddl_dip;
	usb_client_dev_data_t		*cddl_dev_data;
	uint_t				cddl_ifno;
} usb_client_dev_data_list_t;

/*
 * This	structure uniquely identifies a USB device
 * with all interfaces,	or just one interface of a USB device.
 * usba_device is associated with a devinfo node
 *
 * This	structure is allocated and maintained by USBA and
 * read-only for HCD
 *
 * There can be	multiple clients per device (multi-class
 * device) in which case this structure is shared.
 */
typedef struct usba_device {
	/* for linking all usba_devices on this bus */
	usba_list_entry_t	usb_device_list;

	/* linked list of all pipe handles on this device per endpoint */
	struct usba_ph_impl	usb_ph_list[USBA_N_ENDPOINTS];

	kmutex_t		usb_mutex;   /* protecting usba_device */

	dev_info_t		*usb_dip;

	struct usba_hcdi_ops	*usb_hcdi_ops;	/* ptr to HCD ops */

	struct usba_hubdi	*usb_hubdi;

	usb_addr_t		usb_addr;	/* usb address */

	uchar_t			usb_no_cpr;	/* CPR? */

	dev_info_t		*usb_root_hub_dip;
	struct hubd		*usb_root_hubd;	/* for HC or WA */

	usb_dev_descr_t		*usb_dev_descr;	/* device descriptor */

	uchar_t			*usb_cfg;	/* raw config descriptor */
	size_t			usb_cfg_length; /* length of raw descr */

	char			*usb_mfg_str;	/* manufacturer string */
	char			*usb_product_str;	/* product string */
	char			*usb_serialno_str; /* serial number string */
	char			*usb_preferred_driver; /* user's choice */

	usb_port_status_t	usb_port_status; /* usb hub port status */
	usb_port_t		usb_port;

	/* To support split transactions */
	struct usba_device	*usb_hs_hub_usba_dev; /* HS hub usba device */
	usb_addr_t		usb_hs_hub_addr; /* High speed hub address */
	usb_port_t		usb_hs_hub_port; /* High speed hub port */

	/* For high speed hub bandwidth allocation scheme */
	uint_t			usb_hs_hub_min_bandwidth;
	uint_t			usb_hs_hub_bandwidth[32];

	/* store all config cloud here */
	uchar_t			**usb_cfg_array;
	uint_t			usb_cfg_array_length;

	uint16_t		*usb_cfg_array_len;
	uint_t			usb_cfg_array_len_length;

	uint_t			usb_cfg_value;
	uint_t			usb_active_cfg_ndx;
	char			**usb_cfg_str_descr;
	uchar_t			usb_n_cfgs;
	uchar_t			usb_n_ifs;

	/*
	 * power drawn from hub, if > 0, the power has been
	 * subtracted from the parent hub's power budget
	 */
	uint16_t		usb_pwr_from_hub;

	/* ref count, if > 0, this structure is in use */
	int			usb_ref_count;

	/* list of requests allocated for this device, detects leaks */
	usba_list_entry_t	usb_allocated;		/* alloc'ed reqs list */

	/* NDI event service cookies */
	ddi_eventcookie_t	rm_cookie;
	ddi_eventcookie_t	ins_cookie;
	ddi_eventcookie_t	suspend_cookie;
	ddi_eventcookie_t	resume_cookie;

	/* linked list of callid (per-devinfo) */
	usba_evdata_t		*usb_evdata;

	/* client cleanup checks */
	uchar_t			*usb_client_flags;

	struct {
		dev_info_t *dip;
	}			*usb_client_attach_list;

	usb_client_dev_data_list_t usb_client_dev_data_list;

	struct {
		dev_info_t *dip;
		usb_event_t *ev_data;
	}			*usb_client_ev_cb_list;

	/* Shared task queue implementation. */
	taskq_t			*usb_shared_taskq[USBA_N_ENDPOINTS];
	uchar_t			usb_shared_taskq_ref_count
						[USBA_N_ENDPOINTS];

	/*
	 * Pointer to hub this is under. This is required for some HCDs to
	 * accurately set up the device. Note that some usba_device_t's are
	 * shared by multiple entries, so this is not strictly the parent
	 * device. This would come up if the usb_mid driver was on the scene.
	 * Importantly, this field is always read-only. While this is similar to
	 * the usb_hs_hub_usba_dev, it's always set, regardless if it's a high
	 * speed device or not.
	 */
	struct usba_device	*usb_parent_hub;

	/*
	 * Private data for HCD drivers
	 */
	void			*usb_hcd_private;
} usba_device_t;

#define	USBA_CLIENT_FLAG_SIZE		1
#define	USBA_CLIENT_FLAG_ATTACH		0x01
#define	USBA_CLIENT_FLAG_EV_CBS		0x02
#define	USBA_CLIENT_FLAG_DEV_DATA	0x04

_NOTE(MUTEX_PROTECTS_DATA(usba_device::usb_mutex, usba_device))
_NOTE(MUTEX_PROTECTS_DATA(usba_device::usb_mutex, usba_evdata))

_NOTE(SCHEME_PROTECTS_DATA("chg at attach only",
				usba_evdata::ev_rm_cb_id))
_NOTE(SCHEME_PROTECTS_DATA("chg at attach only",
				usba_evdata::ev_ins_cb_id))
_NOTE(SCHEME_PROTECTS_DATA("chg at attach only",
				usba_evdata::ev_suspend_cb_id))
_NOTE(SCHEME_PROTECTS_DATA("chg at attach only",
				usba_evdata::ev_resume_cb_id))

/* this should be really stable data */
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::usb_serialno_str))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::usb_root_hub_dip))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::usb_root_hubd))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::usb_product_str))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::usb_preferred_driver))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::usb_port))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::usb_n_ifs))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::usb_n_cfgs))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::usb_mfg_str))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::usb_dev_descr))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::usb_ph_list))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::usb_cfg_value))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::usb_cfg_str_descr))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::usb_cfg_length))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::usb_cfg_array))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::usb_cfg_array_len))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::usb_cfg_array_length))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::usb_cfg_array_len_length))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::usb_cfg))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::usb_hcdi_ops))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::usb_addr))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::usb_port_status))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::rm_cookie))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::ins_cookie))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::suspend_cookie))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::resume_cookie))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::usb_client_flags))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::usb_client_attach_list))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::usb_client_ev_cb_list))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usba_device::usb_dip))
_NOTE(SCHEME_PROTECTS_DATA("set at device creation",
					usba_device::usb_shared_taskq))

_NOTE(SCHEME_PROTECTS_DATA("local use only",
				usb_key_descr::bDescriptorType))
_NOTE(SCHEME_PROTECTS_DATA("local use only",
				usb_key_descr::bLength))
/*
 * serialization in drivers
 */
typedef struct usba_serialization_impl {
	dev_info_t	*s_dip;
	kcondvar_t	s_cv;
	kmutex_t	s_mutex;
	kthread_t	*s_thread;
	int		s_count;
	uint_t		s_flag;
} usba_serialization_impl_t;

_NOTE(SCHEME_PROTECTS_DATA("unshared private data",
				usba_serialization_impl))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USB_USBA_USBA_TYPES_H */

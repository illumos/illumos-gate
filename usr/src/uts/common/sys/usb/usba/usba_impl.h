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
 *
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */

#ifndef	_SYS_USB_USBA_USBA_IMPL_H
#define	_SYS_USB_USBA_USBA_IMPL_H


#include <sys/usb/usba.h>
#include <sys/usb/usba/hcdi.h>
#include <sys/usb/usba/hubdi.h>
#include <sys/usb/usba/usba_private.h>
#include <sys/usb/usba/usba_types.h>
#include <sys/taskq.h>
#include <sys/disp.h>

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * UGEN binding values specified in <hcd>.conf files
 */
#define	USBA_UGEN_DEVICE_BINDING	1
#define	USBA_UGEN_INTERFACE_BINDING	2
#define	USBA_UGEN_INTERFACE_ASSOCIATION_BINDING		3

/*
 * Allocating a USB address
 */
#define	USBA_MAX_ADDRESS		127
#define	USBA_ADDRESS_ARRAY_SIZE	((USBA_MAX_ADDRESS+8)/8)

/*
 * async execution of usb_pipe_* functions which have a
 * completion callback parameter (eg. usb_pipe_close(),
 * usb_pipe_reset(), usb_pipe_stop_*_polling()
 */
typedef struct usba_pipe_async_req {
	dev_info_t		*dip;
	struct usba_ph_impl	*ph_impl;
	usb_opaque_t		arg;
	usb_flags_t		usb_flags;
	void			(*callback)(
					usb_pipe_handle_t	ph,
					usb_opaque_t		callback_arg,
					int			rval,
					usb_cb_flags_t		error_code);
	usb_opaque_t		callback_arg;
	int			(*sync_func)(dev_info_t *,
					usba_ph_impl_t *,
					struct usba_pipe_async_req *,
					usb_flags_t);
} usba_pipe_async_req_t;
_NOTE(SCHEME_PROTECTS_DATA("unique per call", usba_pipe_async_req_t))

/* per-pipe taskq */
int	usba_async_ph_req(usba_pipe_handle_data_t *, void (*func)(void *),
							void *, usb_flags_t);

/*
 * usb wrapper around pm_request_power_change to allow for
 * non blocking behavior
 */
typedef struct usba_pm_req {
	dev_info_t	*dip;
	int		comp;
	int		old_level;
	int		level;
	void		(*cb)(void *, int);
	void		*arg;
	uint_t		flags;
} usba_pm_req_t;
_NOTE(SCHEME_PROTECTS_DATA("unique per call", usba_pm_req_t))


/*
 * Request wrappers for control/bulk/interrupt and isoch pipes
 * These are hidden from client driver. They serve as place-holders
 * for doing callbacks
 *
 * Request allocation: wrapper + usb_*_req_t alloc'ed together:
 *
 *		+-----------------------+
 *		|	wr_queue	|		for callbacks
 *		+-----------------------+
 *		|	wr_req	|-------+	wr_req points to
 *		+-----------------------+	|	the req below.
 *		|			|	|
 *		|	....		|	|
 *		|	req_wrapper_t	|	|
 *		|			|	|
 *		+-----------------------+<------+
 *		|			|
 *		|	....		|
 *		| ctrl/bulk/intr/isoch	|
 *		|	req_t	|
 *		|			|
 *		|			|
 *		+-----------------------+
 */
typedef struct usba_req_wrapper {
	/* queueing in either a request or callback queue */
	usba_list_entry_t	wr_queue;

	/*
	 * The request could be control/bulk/intr/isoc
	 * See usbai.h usb_ctrl_req_t/usb_bulk_req_t
	 * usb_intr_req_t/usb_isoc_req_t
	 */
	usb_opaque_t		wr_req;

	/* for allocation tracking in usba_device_t */
	usba_list_entry_t	wr_allocated_list;

	/*
	 * All reqs that are synchronous sleep on this cv
	 * for completion notification.
	 * In hcdi soft interrupt handler we call cv_signal()
	 */
	kcondvar_t		wr_cv;

	/*
	 * This goes hand-in-hand with wr_cv. It is set by the soft intr hdlr
	 * before doing a cv_signal
	 */
	boolean_t		wr_done;
	dev_info_t		*wr_dip;	/* owner */

	usb_opaque_t		wr_hcd_private;	/* for HCD's use */

	usba_pipe_handle_data_t	*wr_ph_data;	/* ptr to pipe handle */

	usb_cr_t		wr_cr;		/* save cr from HCDI */
	usb_cb_flags_t		wr_cb_flags;	/* save cb_flags */
	usb_flags_t		wr_usb_flags;	/* save usb flags from HCDI */
	usb_req_attrs_t		wr_attrs;	/* save attrs from HCDI */

	/* total lenght of wrapper and request */
	size_t			wr_length;
} usba_req_wrapper_t;

_NOTE(SCHEME_PROTECTS_DATA("method", usba_req_wrapper))
_NOTE(SCHEME_PROTECTS_DATA("method", usb_ctrl_req))
_NOTE(SCHEME_PROTECTS_DATA("method", usb_bulk_req))
_NOTE(SCHEME_PROTECTS_DATA("method", usb_intr_req))
_NOTE(SCHEME_PROTECTS_DATA("method", usb_isoc_req))

/* additional flag for wr_usb_flags */
#define	USBA_WRP_FLAGS_WAIT	0x01

/* additional usb flags, not exposed to clients */
#define	USBA_FLAGS_PRIVILEGED	0x02	/* for default pipe operations */

/* Macros to convert wrapper to different request and vice-versa */

/* to get the wr->wr_req field */
#define	USBA_WRP2REQ(wrp)	((wrp)->wr_req)

/* to get the wrapper form the wr_req field */
#define	USBA_REQ2WRP(req)		(usba_req_wrapper_t *)\
				((uintptr_t)(req) - sizeof (usba_req_wrapper_t))

/* to set the the address in the wr_req field */
#define	USBA_SETREQ_ADDR(wrp)	((uintptr_t)(wrp) + sizeof (*(wrp)))

/* to get the 4 xfer type requests */
#define	USBA_WRP2CTRL_REQ(wrp)	((usb_ctrl_req_t *)USBA_WRP2REQ((wrp)))
#define	USBA_WRP2INTR_REQ(wrp)	((usb_intr_req_t *)USBA_WRP2REQ((wrp)))
#define	USBA_WRP2BULK_REQ(wrp)	((usb_bulk_req_t *)USBA_WRP2REQ((wrp)))
#define	USBA_WRP2ISOC_REQ(wrp)	((usb_isoc_req_t *)USBA_WRP2REQ((wrp)))

/* to get pipe_handle from the wrapper */
#define	USBA_WRP2PH_DATA(wrp) \
	(usba_pipe_handle_data_t *)((wrp)->wr_ph_data)

/* to get to the wr_queue from the wrapper */
#define	USBA_WRQUEUE2WRP(queue)	(usba_req_wrapper_t *)(queue)

/* to get to the wr_allocated queue from the wrapper */
#define	USBA_ALLOCQ2WRP(queue)	(usba_req_wrapper_t *)((uintptr_t) \
	(queue)  - sizeof (usba_list_entry_t) - sizeof (usb_opaque_t))


/* alias for pipe handle member p_usba_private */
#define	p_active_cntrl_req_wrp	p_usba_private

/*
 * This function is used to get the HCD private field maintained by USBA.
 * HCD calls this function.
 */
usb_opaque_t usba_hcdi_get_ctrl_req_hcd_private(usb_ctrl_req_t *);

/*
 * This function is used to set the HCD private field maintained by USBA.
 * HCD calls this function.
 */
void	usba_hcdi_set_ctrl_req_hcd_private(usb_ctrl_req_t *, usb_opaque_t);

int	usba_set_usb_address(usba_device_t *);
void	usba_unset_usb_address(usba_device_t *);

/*
 * Per Hub Data Structures
 */
typedef  struct usba_hubdi {
	usba_list_entry_t hubdi_list;	 /* linking in hubdi list */

	dev_info_t	*hubdi_dip;	 /* ptr to devinfo struct */

	int		hubdi_flags;	/* flag options */

} usba_hubdi_t;

/*
 * usba_get_mfg_prod_sn_str:
 *	Return a string containing mfg, product, serial number strings.
 */
char	*usba_get_mfg_prod_sn_str(dev_info_t *, char *, int);

/* return value when user doesn't specify configuration index */
#define	USBA_DEV_CONFIG_INDEX_UNDEFINED	-1

/*
 * prototypes
 */
void	usba_usba_initialization();
void	usba_usba_destroy();

void	usba_usbai_register_initialization();
void	usba_usbai_register_destroy();

void	usba_usbai_initialization();
void	usba_usbai_destroy();

void	usba_hubdi_initialization();
void	usba_hubdi_destroy();

void	usba_devdb_initialization();
void	usba_devdb_destroy();

int	usba_hubdi_register(dev_info_t	*, uint_t);
int	usba_hubdi_unregister(dev_info_t *);

int	usba_is_root_hub(dev_info_t *dip);

usba_device_t *usba_alloc_usba_device(dev_info_t *);
void	usba_free_usba_device(usba_device_t *usba_device_t);
void	usba_clear_data_toggle(usba_device_t *usba_device);

void	usba_start_next_req(usba_pipe_handle_data_t *ph);

int	usba_pipe_check_handle(usba_pipe_handle_data_t *);
int	usba_drain_cbs(usba_pipe_handle_data_t *, usb_cb_flags_t,
			usb_cr_t);
int	usba_pipe_setup_func_call(dev_info_t *,
			int (*sync_func)(dev_info_t *,
				usba_ph_impl_t *, usba_pipe_async_req_t *,
				usb_flags_t),
			usba_ph_impl_t *,
			usb_opaque_t,
			usb_flags_t,
			void (*cb)(usb_pipe_handle_t, usb_opaque_t,
			    int, usb_cb_flags_t),
			usb_opaque_t);


void	usba_pipe_new_state(usba_pipe_handle_data_t *, usb_pipe_state_t);

void usba_add_root_hub(dev_info_t *dip);
void usba_rem_root_hub(dev_info_t *dip);

/*
 * retrieve string descriptors for manufacturer, vendor and serial
 * number
 */
void usba_get_dev_string_descrs(dev_info_t *, usba_device_t *);

/*
 * Check if we are not in interrupt context and have
 * USB_FLAGS_SLEEP flags set.
 */
#define	USBA_CHECK_CONTEXT()	ASSERT(!(servicing_interrupt()))

/*
 * USBA module Masks
 */
#define	DPRINT_MASK_USBA		0x00000001
#define	DPRINT_MASK_USBAI		0x00000002
#define	DPRINT_MASK_HUBDI		0x00000004
#define	DPRINT_MASK_HCDI		0x00000008
#define	DPRINT_MASK_HCDI_DUMPING	0x00000010
#define	DPRINT_MASK_HUBDI_DUMPING	0x00000020
#define	DPRINT_MASK_REGISTER		0x00000040
#define	DPRINT_MASK_DEVDB		0x00000080
#define	DPRINT_MASK_WHCDI		0x00000100
#define	DPRINT_MASK_ALL 		0xFFFFFFFF

typedef struct usba_log_handle_impl {
	dev_info_t	*lh_dip;
	char		*lh_name;
	uint_t		*lh_errlevel;
	uint_t		*lh_mask;
	uint_t		*lh_instance_filter;
	uint_t		lh_flags;
} usba_log_handle_impl_t;

_NOTE(SCHEME_PROTECTS_DATA("USBA managed data", usba_log_handle_impl))

/*
 * Miscellaneous definitions.
 */

/* possible strlen of a USB driver's name */
#define	USBA_DRVNAME_LEN	40

/* strings passed to usb_dprintfN() are this long */
#define	USBA_PRINT_BUF_LEN	256

/*
 * usba_set_node_name() sets a device info node name
 * according to class, subclass, and protocol.
 * a subclass == -1 or protocol == -1 is considered a "don't care".
 */
#define	DONTCARE		((int16_t)-1)
#define	FLAG_INTERFACE_NODE	0
#define	FLAG_DEVICE_NODE	1
#define	FLAG_COMBINED_NODE	2
#define	FLAG_INTERFACE_ASSOCIATION_NODE		3

typedef struct node_name_entry {
	int16_t class;
	int16_t subclass;
	int16_t protocol;
	char	*name;
} node_name_entry_t;


/*
 * USB enumeration statistics support
 */

/* Flags telling which stats usba_update_hotplug_stats should update */
#define	USBA_TOTAL_HOTPLUG_SUCCESS	0x01
#define	USBA_HOTPLUG_SUCCESS		0x02
#define	USBA_TOTAL_HOTPLUG_FAILURE	0x04
#define	USBA_HOTPLUG_FAILURE		0x08

/*
 * Increment enumeration stats indicated by the flags
 */
void	usba_update_hotplug_stats(dev_info_t *, usb_flags_t);

/* Retrieve the current enumeration hotplug statistics */
void	usba_get_hotplug_stats(dev_info_t *,
		ulong_t	*, ulong_t *, ulong_t *,
		ulong_t	*, uchar_t *);

/* Reset the resetable hotplug stats */
void	usba_reset_hotplug_stats(dev_info_t *);


extern usb_log_handle_t usbai_log_handle;
extern	kmutex_t usbai_mutex;

void	usba_req_normal_cb(usba_req_wrapper_t *);
void	usba_req_exc_cb(usba_req_wrapper_t *, usb_cr_t, usb_cb_flags_t);
void	usba_do_req_exc_cb(usba_req_wrapper_t *, usb_cr_t,
						usb_cb_flags_t);
void	usba_req_set_cb_flags(usba_req_wrapper_t *, usb_cb_flags_t);

/*
 * Creating/Destroying children (root hub, and hub children)
 */
int	usba_create_child_devi(dev_info_t *, char *, usba_hcdi_ops_t *,
		dev_info_t *, usb_port_status_t,
		usba_device_t *, dev_info_t **);

int	usba_destroy_child_devi(dev_info_t *, uint_t);

/* utility function to map rval to a meaningful cr */
usb_cr_t usba_rval2cr(int);

/* various conversion functions */
usb_pipe_handle_t	usba_get_dflt_pipe_handle(dev_info_t *);
dev_info_t		*usba_get_dip(usb_pipe_handle_t);
usb_pipe_handle_t	usba_usbdev_to_dflt_pipe_handle(usba_device_t *);
usb_pipe_handle_t	usba_get_pipe_handle(usba_pipe_handle_data_t *);
usba_pipe_handle_data_t *usba_get_ph_data(usb_pipe_handle_t);
usb_pipe_state_t	usba_get_ph_state(usba_pipe_handle_data_t *);
int			usba_get_ph_ref_count(usba_pipe_handle_data_t *);

/* increment and decrement ref_count */
usba_pipe_handle_data_t *usba_hold_ph_data(usb_pipe_handle_t);
void			usba_release_ph_data(usba_ph_impl_t *);

/* close all pipe and mark them persistent */
void			usba_persistent_pipe_close(usba_device_t *);

/* reopen pipes that are marked persistent */
int			usba_persistent_pipe_open(usba_device_t *);

/* check for leaks in hubd and usb_mid */
void	usba_check_for_leaks(usba_device_t *);

/* free request wrappers */
void	usba_req_wrapper_free(usba_req_wrapper_t *);

/* usb device capture for the specific client driver */
typedef struct usb_dev_cap {
	dev_info_t			*dip;
	usb_dev_driver_callback_t	usba_dev_driver_cb;
} usb_dev_cap_t;

usb_dev_cap_t usb_cap;
_NOTE(SCHEME_PROTECTS_DATA("unique device capture data", usb_cap))

#ifdef __cplusplus
}
#endif

#endif /* _SYS_USB_USBA_USBA_IMPL_H */

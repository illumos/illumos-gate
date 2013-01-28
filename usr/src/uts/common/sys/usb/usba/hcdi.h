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

#ifndef	_SYS_USB_HCDI_H
#define	_SYS_USB_HCDI_H


#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/usb/usba/genconsole.h>
#include <sys/usb/usba/usba_types.h>

/*
 * HCD ops structure
 *
 * - this structure defines all entry points into HCD
 *
 * - all client driver USBAI functions that require HCD
 *   involvement go through this ops table
 *
 * - at HCD attach time, the HCD ops are passed to
 *   to the USBA through usba_hcdi_attach()
 *
 * some of these ops implement the semantics of the corresponding
 * USBAI interfaces. Refer to usbai.h for detailed description
 */
#define	HCDI_OPS_VERSION_0 0
#define	HCDI_OPS_VERSION_1 1
#define	HCDI_OPS_VERSION	HCDI_OPS_VERSION_1

typedef struct usba_hcdi_ops {
	int	usba_hcdi_ops_version;	/* implementation version */

	dev_info_t	*usba_hcdi_dip;	/* HCD's devinfo ptr */

	/* can this hcd support pm? */
	int	(*usba_hcdi_pm_support)(dev_info_t *dip);

	/*
	 * usba_hcdi_pipe_open:
	 *	implements the semantics of usb_pipe_open()
	 *	USBA allocate the pipe_handle which contains
	 *	pipe_policy and endpoint pointers
	 */
	int	(*usba_hcdi_pipe_open)(
		usba_pipe_handle_data_t	*pipe_handle,
		usb_flags_t		usb_flags);

	/*
	 * close a pipe
	 */
	int	(*usba_hcdi_pipe_close)(
		usba_pipe_handle_data_t	*pipe_handle,
		usb_flags_t		usb_flags);

	/*
	 * pipe management
	 */
	int	(*usba_hcdi_pipe_reset)(
		usba_pipe_handle_data_t	*pipe_handle,
		usb_flags_t		usb_flags);

	/*
	 * pipe management
	 */
	void	(*usba_hcdi_pipe_reset_data_toggle)(
		usba_pipe_handle_data_t	*pipe_handle);

	/*
	 * data transfer management
	 */
	int	(*usba_hcdi_pipe_ctrl_xfer)(
		usba_pipe_handle_data_t	*pipe_handle,
		usb_ctrl_req_t		*usb_ctrl_req,
		usb_flags_t		usb_flags);

	/*
	 * get HCD limitation on bulk xfer at a time?
	 */
	int	(*usba_hcdi_bulk_transfer_size)(
		usba_device_t		*usba_device,
		size_t			*size);

	/*
	 * do bulk read/write
	 */
	int	(*usba_hcdi_pipe_bulk_xfer)(
		usba_pipe_handle_data_t	*pipe_handle,
		usb_bulk_req_t		*usb_bulk_req,
		usb_flags_t		usb_flags);

	/*
	 * do interrupt pipe read/write
	 */
	int	(*usba_hcdi_pipe_intr_xfer)(
		usba_pipe_handle_data_t	*pipe_handle,
		usb_intr_req_t		*usb_intr_req,
		usb_flags_t		usb_flags);

	/*
	 * stop interrupt pipe polling
	 */
	int	(*usba_hcdi_pipe_stop_intr_polling)(
		usba_pipe_handle_data_t	*pipe_handle,
		usb_flags_t		usb_flags);

	/*
	 * do isoch pipe read/write
	 */
	int	(*usba_hcdi_pipe_isoc_xfer)(
		usba_pipe_handle_data_t	*pipe_handle,
		usb_isoc_req_t		*usb_isoc_req,
		usb_flags_t		usb_flags);

	/*
	 * stop isoc pipe polling
	 */
	int	(*usba_hcdi_pipe_stop_isoc_polling)(
		usba_pipe_handle_data_t	*pipe_handle,
		usb_flags_t		usb_flags);

	/* utility isoc functions */
	int	(*usba_hcdi_get_current_frame_number)(
		usba_device_t		*usba_device,
		usb_frame_number_t	*frame_number);

	int	(*usba_hcdi_get_max_isoc_pkts)(
		usba_device_t		*usba_device,
		uint_t			*max_isoc_pkts_per_request);

	/*
	 * Initialize OBP support for input
	 */
	int	(*usba_hcdi_console_input_init)(
		usba_pipe_handle_data_t		*pipe_handle,
		uchar_t				**obp_buf,
		usb_console_info_impl_t		*console_input_info);

	/*
	 * Free resources allocated by usba_hcdi_console_input_init
	 */
	int	(*usba_hcdi_console_input_fini)(
		usb_console_info_impl_t		*console_input_info);

	/*
	 * Save controller state information
	 */
	int	(*usba_hcdi_console_input_enter)(
		usb_console_info_impl_t		*console_input_info);

	/*
	 * Read character from controller
	 */
	int	(*usba_hcdi_console_read)(
		usb_console_info_impl_t		*console_input_info,
		uint_t				*num_characters);

	/*
	 * Restore controller state information
	 */
	int	(*usba_hcdi_console_input_exit)(
		usb_console_info_impl_t		*console_input_info);


	/*
	 * VERSION 1 ops: support for polled output
	 */
	int	(*usba_hcdi_console_output_init)(
		usba_pipe_handle_data_t		*pipe_handle,
		usb_console_info_impl_t		*console_output_info);

	int	(*usba_hcdi_console_output_fini)(
		usb_console_info_impl_t		*console_output_info);

	int	(*usba_hcdi_console_output_enter)(
		usb_console_info_impl_t		*console_output_info);

	int	(*usba_hcdi_console_write)(
		usb_console_info_impl_t		*console_output_info,
		uchar_t				*buf,
		uint_t				num_characters,
		uint_t				*num_characters_written);

	int	(*usba_hcdi_console_output_exit)(
		usb_console_info_impl_t		*console_output_info);
} usba_hcdi_ops_t;


/*
 * callback support:
 *	this function handles all HCD callbacks as follows:
 *	- USB_FLAGS_SLEEP determines whether the client driver made
 *	  a synchronous or asynchronous USBAI call
 *	- for synchronous calls, the args are copied into the pipe handle
 *		and the sync cv of the pipe handle is signalled
 *	- for async calls and completion_reason = 0, the normal callback
 *		is invoked
 *	- for async calls and completion_reason != 0, the exception
 *		callback is invoked
 */
void
usba_hcdi_cb(usba_pipe_handle_data_t	*ph,
		usb_opaque_t		req,
		usb_cr_t		completion_reason);

/*
 * function to duplicate a interrupt/isoc request (for HCD)
 */
usb_intr_req_t	*usba_hcdi_dup_intr_req(dev_info_t *,
			usb_intr_req_t *, size_t, usb_flags_t);
usb_isoc_req_t	*usba_hcdi_dup_isoc_req(dev_info_t *,
			usb_isoc_req_t *, usb_flags_t);

/* access to private member of requests */
usb_opaque_t	usba_hcdi_get_req_private(usb_opaque_t);
void		usba_hcdi_set_req_private(usb_opaque_t, usb_opaque_t);
usba_pipe_handle_data_t *
		usba_hcdi_get_ph_data(usba_device_t *, uint8_t);

/* data toggle get and set */
uchar_t		usba_hcdi_get_data_toggle(usba_device_t *, uint8_t);
void 		usba_hcdi_set_data_toggle(usba_device_t *, uint8_t, uchar_t);

/*
 * HCD Nexus driver support:
 */

/*
 * hcd_ops allocator/deallocator
 *	USBA allocates the usba_hcdi_ops so we can easily handle
 *	versioning
 */
usba_hcdi_ops_t	*usba_alloc_hcdi_ops();
void		usba_free_hcdi_ops(usba_hcdi_ops_t *);

/*
 * Argument structure for usba_hcdi_register
 */
typedef struct usba_hcdi_register_args {
	uint_t			usba_hcdi_register_version;
	dev_info_t		*usba_hcdi_register_dip;
	usba_hcdi_ops_t		*usba_hcdi_register_ops;
	ddi_dma_attr_t		*usba_hcdi_register_dma_attr;
	ddi_iblock_cookie_t	usba_hcdi_register_iblock_cookie;

} usba_hcdi_register_args_t;

#define	HCDI_REGISTER_VERS_0		0
#define	HCDI_REGISTER_VERSION		HCDI_REGISTER_VERS_0


/*
 * make	this instance known to USBA
 *
 * the HCD must initialize the hcdi_ops before calling this function
 */
int	usba_hcdi_register(usba_hcdi_register_args_t *, uint_t);

/*
 * detach support
 */
void	usba_hcdi_unregister(dev_info_t *);

/*
 * Hotplug kstats named structure
 *
 * Number of types of USB transfers
 */
#define	USB_N_COUNT_KSTATS	4

typedef struct hcdi_hotplug_stats {
	struct kstat_named	hcdi_hotplug_total_success;
	struct kstat_named	hcdi_hotplug_success;
	struct kstat_named	hcdi_hotplug_total_failure;
	struct kstat_named	hcdi_hotplug_failure;
	struct kstat_named	hcdi_device_count;
} hcdi_hotplug_stats_t;

/*
 * USB error kstats named structure
 */
typedef struct hcdi_error_stats {
	/* transport completion codes */
	struct kstat_named	cc_crc;
	struct kstat_named	cc_bitstuffing;
	struct kstat_named	cc_data_toggle_mm;
	struct kstat_named	cc_stall;
	struct kstat_named	cc_dev_not_resp;
	struct kstat_named	cc_pid_checkfailure;
	struct kstat_named	cc_unexp_pid;
	struct kstat_named	cc_data_overrun;
	struct kstat_named	cc_data_underrun;
	struct kstat_named	cc_buffer_overrun;
	struct kstat_named	cc_buffer_underrun;
	struct kstat_named	cc_timeout;
	struct kstat_named	cc_not_accessed;
	struct kstat_named	cc_no_resources;
	struct kstat_named	cc_unspecified_err;
	struct kstat_named	cc_stopped_polling;
	struct kstat_named	cc_pipe_closing;
	struct kstat_named	cc_pipe_reset;
	struct kstat_named	cc_not_supported;
	struct kstat_named	cc_flushed;
} hcdi_error_stats_t;

/*
 * hcdi kstat defines
 * XXX this needs to be a function
 */
#define	HCDI_HOTPLUG_STATS(hcdi)	((hcdi)->hcdi_hotplug_stats)
#define	HCDI_HOTPLUG_STATS_DATA(hcdi)	\
	((hcdi_hotplug_stats_t *)HCDI_HOTPLUG_STATS((hcdi))->ks_data)

#define	HCDI_ERROR_STATS(hcdi)		((hcdi)->hcdi_error_stats)
#define	HCDI_ERROR_STATS_DATA(hcdi)	\
	((hcdi_error_stats_t *)HCDI_ERROR_STATS((hcdi))->ks_data)


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_HCDI_H */

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
 *
 * Copyright 2016 Joyent, Inc.
 */

/*
 * USBA: Solaris USB Architecture support
 *
 * hcdi.c contains the code for client driver callbacks.  A host controller
 * driver registers/unregisters with usba through usba_hcdi_register/unregister.
 *
 * When the transfer has finished, the host controller driver will call into
 * usba with the result.  The call is usba_hcdi_cb().
 *
 * The callback queue is maintained in FIFO order.  usba_hcdi_cb
 * adds to the queue, and hcdi_cb_thread takes the callbacks off the queue
 * and executes them.
 */
#define	USBA_FRAMEWORK
#include <sys/usb/usba/usba_impl.h>
#include <sys/usb/usba/hcdi_impl.h>
#include <sys/kstat.h>
#include <sys/ddi_impldefs.h>

/* function prototypes, XXXX use hcdi_ prefix?	*/
static void usba_hcdi_create_stats(usba_hcdi_t *, int);
static void usba_hcdi_update_error_stats(usba_hcdi_t *, usb_cr_t);
static void usba_hcdi_destroy_stats(usba_hcdi_t *);

/* internal functions */
static uint_t hcdi_soft_intr(caddr_t arg1, caddr_t arg2);

static void hcdi_cb_thread(void *);
static void hcdi_shared_cb_thread(void *);
static void hcdi_do_cb(usba_pipe_handle_data_t *, usba_req_wrapper_t *,
							usba_hcdi_t *);
static void hcdi_autoclearing(usba_req_wrapper_t *);

/* private function from USBAI */
void	usba_pipe_clear(usb_pipe_handle_t);

/* for debug messages */
uint_t	hcdi_errmask	= (uint_t)DPRINT_MASK_ALL;
uint_t	hcdi_errlevel	= USB_LOG_L4;
uint_t	hcdi_instance_debug = (uint_t)-1;

void
usba_hcdi_initialization()
{
}


void
usba_hcdi_destroy()
{
}


/*
 * store hcdi structure in the dip
 */
void
usba_hcdi_set_hcdi(dev_info_t *dip, usba_hcdi_t *hcdi)
{
	ddi_set_driver_private(dip, hcdi);
}


/*
 * retrieve hcdi structure from the dip
 */
usba_hcdi_t *
usba_hcdi_get_hcdi(dev_info_t *dip)
{
	return (ddi_get_driver_private(dip));
}

/*
 * Called by an	HCD to attach an instance of the driver
 *	make this instance known to USBA
 *	the HCD	should initialize usba_hcdi structure prior
 *	to calling this	interface
 */
int
usba_hcdi_register(usba_hcdi_register_args_t *args, uint_t flags)
{
	char		*datap;
	uint_t		soft_prip;
	usba_hcdi_t	*hcdi = kmem_zalloc(sizeof (usba_hcdi_t), KM_SLEEP);

	if (args->usba_hcdi_register_version != HCDI_REGISTER_VERS_0) {
		kmem_free(hcdi, sizeof (usba_hcdi_t));

		return (USB_FAILURE);
	}

	hcdi->hcdi_dip = args->usba_hcdi_register_dip;

	/*
	 * The hcd driver cannot use private data as we're going to store our
	 * data there. If it does, fail the registration immediately.
	 */
	if (ddi_get_driver_private(hcdi->hcdi_dip) != NULL) {
		cmn_err(CE_WARN, "failed attempt to register USB hcd, "
		    "detected private data!");
		kmem_free(hcdi, sizeof (usba_hcdi_t));

		return (USB_FAILURE);
	}


	/*
	 * Create a log_handle
	 */
	hcdi->hcdi_log_handle = usb_alloc_log_hdl(hcdi->hcdi_dip, NULL,
	    &hcdi_errlevel, &hcdi_errmask, &hcdi_instance_debug,
	    0);

	USB_DPRINTF_L4(DPRINT_MASK_HCDI, hcdi->hcdi_log_handle,
	    "usba_hcdi_register: %s", ddi_node_name(hcdi->hcdi_dip));

	/*
	 * Initialize the mutex.  Use the iblock cookie passed in
	 * by the host controller driver.
	 */
	mutex_init(&hcdi->hcdi_mutex, NULL, MUTEX_DRIVER,
	    args->usba_hcdi_register_iblock_cookie);

	/* add soft interrupt */
	if (ddi_intr_add_softint(hcdi->hcdi_dip, &hcdi->hcdi_softint_hdl,
	    DDI_INTR_SOFTPRI_MAX, hcdi_soft_intr, (caddr_t)hcdi) !=
	    DDI_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_HCDI, hcdi->hcdi_log_handle,
		    "usba_hcd_register: add soft interrupt failed");
		mutex_destroy(&hcdi->hcdi_mutex);
		usb_free_log_hdl(hcdi->hcdi_log_handle);
		kmem_free(hcdi, sizeof (usba_hcdi_t));

		return (USB_FAILURE);
	}

	if (ddi_intr_get_softint_pri(hcdi->hcdi_softint_hdl, &soft_prip) !=
	    DDI_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_HCDI, hcdi->hcdi_log_handle,
		    "usba_hcd_register: get soft interrupt priority failed");
		(void) ddi_intr_remove_softint(hcdi->hcdi_softint_hdl);
		mutex_destroy(&hcdi->hcdi_mutex);
		usb_free_log_hdl(hcdi->hcdi_log_handle);
		kmem_free(hcdi, sizeof (usba_hcdi_t));

		return (USB_FAILURE);
	}

	/*
	 * Priority and iblock_cookie are one and the same
	 * (However, retaining hcdi_soft_iblock_cookie for now
	 * assigning it w/ priority. In future all iblock_cookie
	 * could just go)
	 */
	hcdi->hcdi_soft_iblock_cookie =
	    (ddi_iblock_cookie_t)(uintptr_t)soft_prip;

	usba_init_list(&hcdi->hcdi_cb_queue, NULL, NULL);

	hcdi->hcdi_dma_attr	= args->usba_hcdi_register_dma_attr;
	hcdi->hcdi_flags	= flags;
	hcdi->hcdi_ops		= args->usba_hcdi_register_ops;
	hcdi->hcdi_iblock_cookie = args->usba_hcdi_register_iblock_cookie;
	usba_hcdi_create_stats(hcdi, ddi_get_instance(hcdi->hcdi_dip));

	hcdi->hcdi_min_xfer	= hcdi->hcdi_dma_attr->dma_attr_minxfer;
	hcdi->hcdi_min_burst_size =
	    (1<<(ddi_ffs(hcdi->hcdi_dma_attr->dma_attr_burstsizes)-1));
	hcdi->hcdi_max_burst_size =
	    (1<<(ddi_fls(hcdi->hcdi_dma_attr->dma_attr_burstsizes)-1));

	usba_hcdi_set_hcdi(hcdi->hcdi_dip, hcdi);

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY,
	    hcdi->hcdi_dip,
	    DDI_PROP_DONTPASS, "ugen-default-binding", &datap) ==
	    DDI_PROP_SUCCESS) {
		if (strcmp(datap, "device") == 0) {
			hcdi->hcdi_ugen_default_binding =
			    USBA_UGEN_DEVICE_BINDING;
		} else if (strcmp(datap, "interface") == 0) {
			hcdi->hcdi_ugen_default_binding =
			    USBA_UGEN_INTERFACE_BINDING;
		} else if (strcmp(datap, "interface-association") == 0) {
			hcdi->hcdi_ugen_default_binding =
			    USBA_UGEN_INTERFACE_ASSOCIATION_BINDING;
		} else {
			USB_DPRINTF_L2(DPRINT_MASK_HCDI,
			    hcdi->hcdi_log_handle,
			    "illegal value (%s) for "
			    "ugen_default_binding property",
			    datap);
		}
		ddi_prop_free(datap);
	}

	return (USB_SUCCESS);
}


/*
 * Called by an	HCD to detach an instance of the driver
 */
/*ARGSUSED*/
void
usba_hcdi_unregister(dev_info_t *dip)
{
	usba_hcdi_t *hcdi = usba_hcdi_get_hcdi(dip);

	if (hcdi) {
		USB_DPRINTF_L4(DPRINT_MASK_HCDI, hcdi->hcdi_log_handle,
		    "usba_hcdi_unregister: %s", ddi_node_name(dip));

		usba_hcdi_set_hcdi(dip, NULL);

		mutex_destroy(&hcdi->hcdi_mutex);
		usba_hcdi_destroy_stats(hcdi);
		usb_free_log_hdl(hcdi->hcdi_log_handle);

		/* Destroy the soft interrupt */
		(void) ddi_intr_remove_softint(hcdi->hcdi_softint_hdl);
		kmem_free(hcdi, sizeof (usba_hcdi_t));
	}
}


/*
 * alloc usba_hcdi_ops structure
 *	called from the HCD attach routine
 */
usba_hcdi_ops_t *
usba_alloc_hcdi_ops()
{
	usba_hcdi_ops_t	*usba_hcdi_ops;

	usba_hcdi_ops = kmem_zalloc(sizeof (usba_hcdi_ops_t), KM_SLEEP);

	return (usba_hcdi_ops);
}


/*
 * dealloc usba_hcdi_ops structure
 */
void
usba_free_hcdi_ops(usba_hcdi_ops_t *hcdi_ops)
{
	if (hcdi_ops) {
		kmem_free(hcdi_ops, sizeof (usba_hcdi_ops_t));
	}
}


/*
 * Allocate the hotplug kstats structure
 */
void
usba_hcdi_create_stats(usba_hcdi_t *hcdi, int instance)
{
	char			kstatname[KSTAT_STRLEN];
	const char		*dname = ddi_driver_name(hcdi->hcdi_dip);
	hcdi_hotplug_stats_t	*hsp;
	hcdi_error_stats_t	*esp;

	if (HCDI_HOTPLUG_STATS(hcdi) == NULL) {
		(void) snprintf(kstatname, KSTAT_STRLEN, "%s%d,hotplug",
		    dname, instance);
		HCDI_HOTPLUG_STATS(hcdi) = kstat_create("usba", instance,
		    kstatname, "usb_hotplug", KSTAT_TYPE_NAMED,
		    sizeof (hcdi_hotplug_stats_t) / sizeof (kstat_named_t),
		    KSTAT_FLAG_PERSISTENT);

		if (HCDI_HOTPLUG_STATS(hcdi) == NULL) {

			return;
		}

		hsp = HCDI_HOTPLUG_STATS_DATA(hcdi);
		kstat_named_init(&hsp->hcdi_hotplug_total_success,
		    "Total Hotplug Successes", KSTAT_DATA_UINT64);
		kstat_named_init(&hsp->hcdi_hotplug_success,
		    "Hotplug Successes", KSTAT_DATA_UINT64);
		kstat_named_init(&hsp->hcdi_hotplug_total_failure,
		    "Hotplug Total Failures", KSTAT_DATA_UINT64);
		kstat_named_init(&hsp->hcdi_hotplug_failure,
		    "Hotplug Failures", KSTAT_DATA_UINT64);
		kstat_named_init(&hsp->hcdi_device_count,
		    "Device Count", KSTAT_DATA_UINT64);

		HCDI_HOTPLUG_STATS(hcdi)->ks_private = hcdi;
		HCDI_HOTPLUG_STATS(hcdi)->ks_update = nulldev;
		kstat_install(HCDI_HOTPLUG_STATS(hcdi));
	}

	if (HCDI_ERROR_STATS(hcdi) == NULL) {
		(void) snprintf(kstatname, KSTAT_STRLEN, "%s%d,error",
		    dname, instance);
		HCDI_ERROR_STATS(hcdi) = kstat_create("usba", instance,
		    kstatname, "usb_errors", KSTAT_TYPE_NAMED,
		    sizeof (hcdi_error_stats_t) / sizeof (kstat_named_t),
		    KSTAT_FLAG_PERSISTENT);

		if (HCDI_ERROR_STATS(hcdi) == NULL) {

			return;
		}

		esp = HCDI_ERROR_STATS_DATA(hcdi);
		kstat_named_init(&esp->cc_crc, "CRC Errors", KSTAT_DATA_UINT64);
		kstat_named_init(&esp->cc_bitstuffing,
		    "Bit Stuffing Violations", KSTAT_DATA_UINT64);
		kstat_named_init(&esp->cc_data_toggle_mm,
		    "Data Toggle PID Errors", KSTAT_DATA_UINT64);
		kstat_named_init(&esp->cc_stall,
		    "Endpoint Stalls", KSTAT_DATA_UINT64);
		kstat_named_init(&esp->cc_dev_not_resp,
		    "Device Not Responding", KSTAT_DATA_UINT64);
		kstat_named_init(&esp->cc_pid_checkfailure,
		    "PID Check Bit Errors", KSTAT_DATA_UINT64);
		kstat_named_init(&esp->cc_unexp_pid,
		    "Invalid PID Errors", KSTAT_DATA_UINT64);
		kstat_named_init(&esp->cc_data_overrun,
		    "Data Overruns", KSTAT_DATA_UINT64);
		kstat_named_init(&esp->cc_data_underrun,
		    "Data Underruns", KSTAT_DATA_UINT64);
		kstat_named_init(&esp->cc_buffer_overrun,
		    "Buffer Overruns", KSTAT_DATA_UINT64);
		kstat_named_init(&esp->cc_buffer_underrun,
		    "Buffer Underruns", KSTAT_DATA_UINT64);
		kstat_named_init(&esp->cc_timeout,
		    "Command Timed Out", KSTAT_DATA_UINT64);
		kstat_named_init(&esp->cc_not_accessed,
		    "Not Accessed By Hardware", KSTAT_DATA_UINT64);
		kstat_named_init(&esp->cc_no_resources,
		    "No Resources", KSTAT_DATA_UINT64);
		kstat_named_init(&esp->cc_unspecified_err,
		    "Unspecified Error", KSTAT_DATA_UINT64);
		kstat_named_init(&esp->cc_stopped_polling,
		    "Stopped Polling", KSTAT_DATA_UINT64);
		kstat_named_init(&esp->cc_pipe_closing,
		    "Pipe Closing", KSTAT_DATA_UINT64);
		kstat_named_init(&esp->cc_pipe_reset,
		    "Pipe Reset", KSTAT_DATA_UINT64);
		kstat_named_init(&esp->cc_not_supported,
		    "Command Not Supported", KSTAT_DATA_UINT64);
		kstat_named_init(&esp->cc_flushed,
		    "Request Flushed", KSTAT_DATA_UINT64);

		HCDI_ERROR_STATS(hcdi)->ks_private = hcdi;
		HCDI_ERROR_STATS(hcdi)->ks_update = nulldev;
		kstat_install(HCDI_ERROR_STATS(hcdi));
	}
}


/*
 * Do actual error stats
 */
void
usba_hcdi_update_error_stats(usba_hcdi_t *hcdi, usb_cr_t completion_reason)
{
	if (HCDI_ERROR_STATS(hcdi) == NULL) {

		return;
	}

	switch (completion_reason) {
	case USB_CR_OK:
		break;
	case USB_CR_CRC:
		HCDI_ERROR_STATS_DATA(hcdi)->cc_crc.value.ui64++;
		break;
	case USB_CR_BITSTUFFING:
		HCDI_ERROR_STATS_DATA(hcdi)->cc_bitstuffing.value.ui64++;
		break;
	case USB_CR_DATA_TOGGLE_MM:
		HCDI_ERROR_STATS_DATA(hcdi)->cc_data_toggle_mm.value.ui64++;
		break;
	case USB_CR_STALL:
		HCDI_ERROR_STATS_DATA(hcdi)->cc_stall.value.ui64++;
		break;
	case USB_CR_DEV_NOT_RESP:
		HCDI_ERROR_STATS_DATA(hcdi)->cc_dev_not_resp.value.ui64++;
		break;
	case USB_CR_PID_CHECKFAILURE:
		HCDI_ERROR_STATS_DATA(hcdi)->cc_pid_checkfailure.value.ui64++;
		break;
	case USB_CR_UNEXP_PID:
		HCDI_ERROR_STATS_DATA(hcdi)->cc_unexp_pid.value.ui64++;
		break;
	case USB_CR_DATA_OVERRUN:
		HCDI_ERROR_STATS_DATA(hcdi)->cc_data_overrun.value.ui64++;
		break;
	case USB_CR_DATA_UNDERRUN:
		HCDI_ERROR_STATS_DATA(hcdi)->cc_data_underrun.value.ui64++;
		break;
	case USB_CR_BUFFER_OVERRUN:
		HCDI_ERROR_STATS_DATA(hcdi)->cc_buffer_overrun.value.ui64++;
		break;
	case USB_CR_BUFFER_UNDERRUN:
		HCDI_ERROR_STATS_DATA(hcdi)->cc_buffer_underrun.value.ui64++;
		break;
	case USB_CR_TIMEOUT:
		HCDI_ERROR_STATS_DATA(hcdi)->cc_timeout.value.ui64++;
		break;
	case USB_CR_NOT_ACCESSED:
		HCDI_ERROR_STATS_DATA(hcdi)->cc_not_accessed.value.ui64++;
		break;
	case USB_CR_NO_RESOURCES:
		HCDI_ERROR_STATS_DATA(hcdi)->cc_no_resources.value.ui64++;
		break;
	case USB_CR_UNSPECIFIED_ERR:
		HCDI_ERROR_STATS_DATA(hcdi)->cc_unspecified_err.value.ui64++;
		break;
	case USB_CR_STOPPED_POLLING:
		HCDI_ERROR_STATS_DATA(hcdi)->cc_stopped_polling.value.ui64++;
		break;
	case USB_CR_PIPE_CLOSING:
		HCDI_ERROR_STATS_DATA(hcdi)->cc_pipe_closing.value.ui64++;
		break;
	case USB_CR_PIPE_RESET:
		HCDI_ERROR_STATS_DATA(hcdi)->cc_pipe_reset.value.ui64++;
		break;
	case USB_CR_NOT_SUPPORTED:
		HCDI_ERROR_STATS_DATA(hcdi)->cc_not_supported.value.ui64++;
		break;
	case USB_CR_FLUSHED:
		HCDI_ERROR_STATS_DATA(hcdi)->cc_flushed.value.ui64++;
		break;
	default:
		break;
	}
}


/*
 * Destroy the hotplug kstats structure
 */
static void
usba_hcdi_destroy_stats(usba_hcdi_t *hcdi)
{
	if (HCDI_HOTPLUG_STATS(hcdi)) {
		kstat_delete(HCDI_HOTPLUG_STATS(hcdi));
		HCDI_HOTPLUG_STATS(hcdi) = NULL;
	}

	if (HCDI_ERROR_STATS(hcdi)) {
		kstat_delete(HCDI_ERROR_STATS(hcdi));
		HCDI_ERROR_STATS(hcdi) = NULL;
	}
}


/*
 * HCD callback handling
 */
void
usba_hcdi_cb(usba_pipe_handle_data_t *ph_data, usb_opaque_t req,
    usb_cr_t completion_reason)
{

	usba_device_t		*usba_device = ph_data->p_usba_device;
	usba_hcdi_t		*hcdi =	usba_hcdi_get_hcdi(
	    usba_device->usb_root_hub_dip);
	usba_req_wrapper_t	*req_wrp = USBA_REQ2WRP(req);
	usb_ep_descr_t		*eptd = &ph_data->p_ep;

	mutex_enter(&ph_data->p_mutex);

#ifdef DEBUG
	mutex_enter(&ph_data->p_ph_impl->usba_ph_mutex);

	USB_DPRINTF_L4(DPRINT_MASK_HCDI, hcdi->hcdi_log_handle,
	    "usba_hcdi_cb: "
	    "ph_data=0x%p req=0x%p state=%d ref=%d cnt=%d cr=%d",
	    (void *)ph_data, (void *)req, ph_data->p_ph_impl->usba_ph_state,
	    ph_data->p_ph_impl->usba_ph_ref_count, ph_data->p_req_count,
	    completion_reason);

	mutex_exit(&ph_data->p_ph_impl->usba_ph_mutex);
#endif

	/* Set the completion reason */
	switch (eptd->bmAttributes & USB_EP_ATTR_MASK) {
	case USB_EP_ATTR_CONTROL:
		((usb_ctrl_req_t *)req)->
		    ctrl_completion_reason = completion_reason;
		break;
	case USB_EP_ATTR_BULK:
		((usb_bulk_req_t *)req)->
		    bulk_completion_reason = completion_reason;
		break;
	case USB_EP_ATTR_INTR:
		((usb_intr_req_t *)req)->
		    intr_completion_reason = completion_reason;
		break;
	case USB_EP_ATTR_ISOCH:
		((usb_isoc_req_t *)req)->
		    isoc_completion_reason = completion_reason;
		break;
	}

	/*
	 * exception callbacks will still go thru a taskq thread
	 * but should occur after the soft interrupt callback
	 * By design of periodic pipes, polling will stop on any
	 * exception
	 */
	if ((ph_data->p_spec_flag & USBA_PH_FLAG_USE_SOFT_INTR) &&
	    (completion_reason == USB_CR_OK)) {
		ph_data->p_soft_intr++;
		mutex_exit(&ph_data->p_mutex);

		usba_add_to_list(&hcdi->hcdi_cb_queue, &req_wrp->wr_queue);

		if (ddi_intr_trigger_softint(hcdi->hcdi_softint_hdl, NULL) !=
		    DDI_SUCCESS)
			USB_DPRINTF_L2(DPRINT_MASK_HCDI, hcdi->hcdi_log_handle,
			    "usba_hcdi_cb: ddi_intr_trigger_softint  failed");

		return;
	}

	/*
	 * USBA_PH_FLAG_TQ_SHARE is for bulk and intr requests,
	 * USBA_PH_FLAG_USE_SOFT_INTR is only for isoch,
	 * so there are no conflicts.
	 */
	if (ph_data->p_spec_flag & USBA_PH_FLAG_TQ_SHARE) {
		int iface;

		mutex_exit(&ph_data->p_mutex);
		iface = usb_get_if_number(ph_data->p_dip);
		if (iface < 0) {
			/* we own the device, use the first taskq */
			iface = 0;
		}
		if (taskq_dispatch(usba_device->usb_shared_taskq[iface],
		    hcdi_shared_cb_thread, req_wrp, TQ_NOSLEEP) ==
		    NULL) {
			usba_req_exc_cb(req_wrp,
			    USB_CR_NO_RESOURCES, USB_CB_ASYNC_REQ_FAILED);
		}

		return;
	}

	/* Add the callback to the pipehandles callback list */
	usba_add_to_list(&ph_data->p_cb_queue, &req_wrp->wr_queue);

	/* only dispatch if there is no thread running */
	if (ph_data->p_thread_id == 0) {
		if (usba_async_ph_req(ph_data, hcdi_cb_thread,
		    ph_data, USB_FLAGS_NOSLEEP) != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_HCDI, hcdi->hcdi_log_handle,
			    "usba_hcdi_cb: taskq_dispatch failed");
			if (usba_rm_from_list(&ph_data->p_cb_queue,
			    &req_wrp->wr_queue) == USB_SUCCESS) {
				mutex_exit(&ph_data->p_mutex);
				usba_req_exc_cb(req_wrp,
				    USB_CR_NO_RESOURCES,
				    USB_CB_ASYNC_REQ_FAILED);

				return;
			}
		} else {
			ph_data->p_thread_id = (kthread_t *)1;
		}
	}
	mutex_exit(&ph_data->p_mutex);
}


/*
 * thread to perform the callbacks
 */
static void
hcdi_cb_thread(void *arg)
{
	usba_pipe_handle_data_t	*ph_data =
	    (usba_pipe_handle_data_t *)arg;
	usba_ph_impl_t		*ph_impl = ph_data->p_ph_impl;
	usba_hcdi_t		*hcdi = usba_hcdi_get_hcdi(ph_data->
	    p_usba_device->usb_root_hub_dip);
	usba_req_wrapper_t	*req_wrp;

	mutex_enter(&ph_data->p_mutex);
	ASSERT(ph_data->p_thread_id == (kthread_t *)1);
	ph_data->p_thread_id = curthread;

	/*
	 * hold the ph_data. we can't use usba_hold_ph_data() since
	 * it will return NULL if we are closing the pipe which would
	 * then leave all requests stuck in the cb_queue
	 */
	mutex_enter(&ph_impl->usba_ph_mutex);
	ph_impl->usba_ph_ref_count++;

	USB_DPRINTF_L4(DPRINT_MASK_HCDI, hcdi->hcdi_log_handle,
	    "hcdi_cb_thread: ph_data=0x%p ref=%d", (void *)ph_data,
	    ph_impl->usba_ph_ref_count);

	mutex_exit(&ph_impl->usba_ph_mutex);

	/*
	 * wait till soft interrupt callbacks are taken care of
	 */
	while (ph_data->p_soft_intr) {
		mutex_exit(&ph_data->p_mutex);
		delay(1);
		mutex_enter(&ph_data->p_mutex);
	}

	while ((req_wrp = (usba_req_wrapper_t *)
	    usba_rm_first_pvt_from_list(&ph_data->p_cb_queue)) != NULL) {
		hcdi_do_cb(ph_data, req_wrp, hcdi);
	}

	ph_data->p_thread_id = 0;
	mutex_exit(&ph_data->p_mutex);

	USB_DPRINTF_L4(DPRINT_MASK_HCDI, hcdi->hcdi_log_handle,
	    "hcdi_cb_thread done: ph_data=0x%p", (void *)ph_data);

	usba_release_ph_data(ph_impl);
}


static void
hcdi_do_cb(usba_pipe_handle_data_t *ph_data, usba_req_wrapper_t *req_wrp,
    usba_hcdi_t *hcdi)
{
	usb_cr_t		completion_reason;
	usb_req_attrs_t		attrs = req_wrp->wr_attrs;

	switch (req_wrp->wr_ph_data->p_ep.bmAttributes &
	    USB_EP_ATTR_MASK) {
	case USB_EP_ATTR_CONTROL:
		completion_reason =
		    USBA_WRP2CTRL_REQ(req_wrp)->ctrl_completion_reason;
		break;
	case USB_EP_ATTR_INTR:
		completion_reason =
		    USBA_WRP2INTR_REQ(req_wrp)->intr_completion_reason;
		break;
	case USB_EP_ATTR_BULK:
		completion_reason =
		    USBA_WRP2BULK_REQ(req_wrp)->bulk_completion_reason;
		break;
	case USB_EP_ATTR_ISOCH:
		completion_reason =
		    USBA_WRP2ISOC_REQ(req_wrp)->isoc_completion_reason;
		break;
	}
	req_wrp->wr_cr = completion_reason;

	USB_DPRINTF_L4(DPRINT_MASK_HCDI, hcdi->hcdi_log_handle,
	    "hcdi_do_cb: wrp=0x%p cr=0x%x", (void *)req_wrp, completion_reason);

	/*
	 * Normal callbacks:
	 */
	if (completion_reason == USB_CR_OK) {
		mutex_exit(&ph_data->p_mutex);
		usba_req_normal_cb(req_wrp);
		mutex_enter(&ph_data->p_mutex);
	} else {
		usb_pipe_state_t pipe_state;

		USB_DPRINTF_L4(DPRINT_MASK_HCDI, hcdi->hcdi_log_handle,
		    "exception callback handling: attrs=0x%x", attrs);

		/*
		 * In exception callback handling, if we were
		 * not able to clear stall, we need to modify
		 * pipe state. Also if auto-clearing is not set
		 * pipe state needs to be modified.
		 */
		pipe_state = usba_get_ph_state(ph_data);

		if (!USBA_PIPE_CLOSING(pipe_state)) {
			switch (completion_reason) {
			case USB_CR_STOPPED_POLLING:
				if (pipe_state ==
				    USB_PIPE_STATE_ACTIVE) {
					usba_pipe_new_state(ph_data,
					    USB_PIPE_STATE_IDLE);
				}
				break;
			case USB_CR_NOT_SUPPORTED:
				usba_pipe_new_state(ph_data,
				    USB_PIPE_STATE_IDLE);
				break;
			case USB_CR_PIPE_RESET:
			case USB_CR_FLUSHED:
				break;
			default:
				usba_pipe_new_state(ph_data,
				    USB_PIPE_STATE_ERROR);
				break;
			}
		}

		pipe_state = usba_get_ph_state(ph_data);

		mutex_exit(&ph_data->p_mutex);
		if (attrs & USB_ATTRS_PIPE_RESET) {
			if ((completion_reason != USB_CR_PIPE_RESET) &&
			    (pipe_state == USB_PIPE_STATE_ERROR)) {

				hcdi_autoclearing(req_wrp);
			}
		}

		usba_req_exc_cb(req_wrp, 0, 0);
		mutex_enter(&ph_data->p_mutex);
	}

	/* Update the hcdi error kstats */
	if (completion_reason) {
		mutex_enter(&hcdi->hcdi_mutex);
		usba_hcdi_update_error_stats(hcdi, completion_reason);
		mutex_exit(&hcdi->hcdi_mutex);
	}

	/*
	 * Once the callback is finished, release the pipe handle
	 * we start the next request first to avoid that the
	 * pipe gets closed while starting the next request
	 */
	mutex_exit(&ph_data->p_mutex);
	usba_start_next_req(ph_data);

	mutex_enter(&ph_data->p_mutex);
}


/*
 * thread to perform callbacks on the shared queue
 */
static void
hcdi_shared_cb_thread(void *arg)
{
	usba_req_wrapper_t *req_wrp = (usba_req_wrapper_t *)arg;
	usba_pipe_handle_data_t	*ph_data = req_wrp->wr_ph_data;
	usba_ph_impl_t		*ph_impl = ph_data->p_ph_impl;
	usba_hcdi_t		*hcdi = usba_hcdi_get_hcdi(ph_data->
	    p_usba_device->usb_root_hub_dip);
	/*
	 * hold the ph_data. we can't use usba_hold_ph_data() since
	 * it will return NULL if we are closing the pipe which would
	 * then leave all requests stuck in the cb_queue
	 */
	mutex_enter(&ph_impl->usba_ph_mutex);
	ph_impl->usba_ph_ref_count++;

	USB_DPRINTF_L4(DPRINT_MASK_HCDI, hcdi->hcdi_log_handle,
	    "hcdi_shared_cb_thread: ph_data=0x%p ref=%d req=0x%p",
	    (void *)ph_data, ph_impl->usba_ph_ref_count, (void *)req_wrp);
	mutex_exit(&ph_impl->usba_ph_mutex);

	/* do the callback */
	mutex_enter(&ph_data->p_mutex);
	hcdi_do_cb(ph_data, req_wrp, hcdi);
	mutex_exit(&ph_data->p_mutex);

	USB_DPRINTF_L4(DPRINT_MASK_HCDI, hcdi->hcdi_log_handle,
	    "hcdi_cb_thread done: ph_data=0x%p", (void *)ph_data);

	usba_release_ph_data(ph_impl);
}


/*
 * soft interrupt handler
 */
/*ARGSUSED*/
static uint_t
hcdi_soft_intr(caddr_t arg1, caddr_t arg2)
{
	usba_hcdi_t		*hcdi = (void *)arg1;
	usba_req_wrapper_t	*req_wrp;
	int			count = 0;

	while ((req_wrp = (usba_req_wrapper_t *)
	    usba_rm_first_pvt_from_list(&hcdi->hcdi_cb_queue)) != NULL) {
		usba_pipe_handle_data_t *ph_data = req_wrp->wr_ph_data;
		usba_ph_impl_t		*ph_impl = ph_data->p_ph_impl;

		/* hold the pipe */
		mutex_enter(&ph_impl->usba_ph_mutex);
		ph_impl->usba_ph_ref_count++;
		mutex_exit(&ph_impl->usba_ph_mutex);

		/* do the callback */
		usba_req_normal_cb(req_wrp);

		/* decrement the soft interrupt count */
		mutex_enter(&ph_data->p_mutex);
		ph_data->p_soft_intr--;
		mutex_exit(&ph_data->p_mutex);

		/* release the pipe */
		mutex_enter(&ph_impl->usba_ph_mutex);
		ph_impl->usba_ph_ref_count--;
		mutex_exit(&ph_impl->usba_ph_mutex);

		count++;
	}

	return (count == 0 ? DDI_INTR_UNCLAIMED : DDI_INTR_CLAIMED);
}


/*
 * hcdi_autoclearing:
 *	This function is called under the taskq context. It
 *	resets the pipe, and clears the stall, if necessary
 */
static void
hcdi_autoclearing(usba_req_wrapper_t *req_wrp)
{
	usb_cr_t		cr = req_wrp->wr_cr;
	usb_pipe_handle_t	pipe_handle, def_pipe_handle;
	usb_cr_t		completion_reason;
	usb_cb_flags_t		cb_flags;
	int			rval;
	usba_device_t		*usba_device =
	    req_wrp->wr_ph_data->p_usba_device;
	usba_hcdi_t		*hcdi = usba_hcdi_get_hcdi(
	    usba_device->usb_root_hub_dip);
	usb_req_attrs_t		attrs = req_wrp->wr_attrs;

	USB_DPRINTF_L4(DPRINT_MASK_HCDI, hcdi->hcdi_log_handle,
	    "hcdi_autoclearing: wrp=0x%p", (void *)req_wrp);

	pipe_handle = usba_get_pipe_handle(req_wrp->wr_ph_data);
	def_pipe_handle = usba_get_dflt_pipe_handle(req_wrp->wr_ph_data->p_dip);

	/*
	 * first reset the pipe synchronously
	 */
	if ((attrs & USB_ATTRS_PIPE_RESET) == USB_ATTRS_PIPE_RESET) {
		usba_pipe_clear(pipe_handle);
		usba_req_set_cb_flags(req_wrp, USB_CB_RESET_PIPE);
	}

	ASSERT(def_pipe_handle);

	/* Do not clear if this request was a usb_get_status request */
	if ((pipe_handle == def_pipe_handle) &&
	    (USBA_WRP2CTRL_REQ(req_wrp)->ctrl_bRequest ==
	    USB_REQ_GET_STATUS)) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, hcdi->hcdi_log_handle,
		    "hcdi_autoclearing: usb_get_status failed, no clearing");

	/* if default pipe and stall no auto clearing */
	} else if ((pipe_handle == def_pipe_handle) && (cr == USB_CR_STALL)) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, hcdi->hcdi_log_handle,
		    "hcdi_autoclearing: default pipe stalled, no clearing");

		usba_req_set_cb_flags(req_wrp, USB_CB_PROTOCOL_STALL);

	/* else do auto clearing */
	} else if (((attrs & USB_ATTRS_AUTOCLEARING) ==
	    USB_ATTRS_AUTOCLEARING) && (cr == USB_CR_STALL)) {
		ushort_t status = 0;

		rval = usb_get_status(req_wrp->wr_dip, def_pipe_handle,
		    USB_DEV_REQ_DEV_TO_HOST | USB_DEV_REQ_RCPT_EP,
		    req_wrp->wr_ph_data->p_ep.bEndpointAddress,
		    &status, USB_FLAGS_SLEEP);
		if (rval != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_USBAI, hcdi->hcdi_log_handle,
			    "get status (STALL) failed: rval=%d", rval);

			usba_pipe_clear(def_pipe_handle);
		}

		if ((rval != USB_SUCCESS) ||
		    (status & USB_EP_HALT_STATUS)) {
			usba_req_set_cb_flags(req_wrp, USB_CB_FUNCTIONAL_STALL);

			if ((rval = usb_pipe_sync_ctrl_xfer(
			    req_wrp->wr_dip, def_pipe_handle,
			    USB_DEV_REQ_HOST_TO_DEV |
			    USB_DEV_REQ_RCPT_EP,
			    USB_REQ_CLEAR_FEATURE,
			    0,
			    req_wrp->wr_ph_data->p_ep.bEndpointAddress,
			    0,
			    NULL, 0,
			    &completion_reason,
			    &cb_flags, USB_FLAGS_SLEEP)) != USB_SUCCESS) {
				USB_DPRINTF_L2(DPRINT_MASK_USBAI,
				    hcdi->hcdi_log_handle,
				    "auto clearing (STALL) failed: "
				    "rval=%d, cr=0x%x cb=0x%x",
				    rval, completion_reason, cb_flags);

				usba_pipe_clear(def_pipe_handle);
			} else {
				usba_req_set_cb_flags(req_wrp,
				    USB_CB_STALL_CLEARED);
			}
		} else {
			usba_req_set_cb_flags(req_wrp, USB_CB_PROTOCOL_STALL);
		}
	}
}


/*
 * usba_hcdi_get_req_private:
 *	This function is used to get the HCD private field
 *	maintained by USBA. HCD calls this function.
 *
 * Arguments:
 *	req		- pointer to usb_*_req_t
 *
 * Return Values:
 *	wr_hcd_private field from wrapper
 */
usb_opaque_t
usba_hcdi_get_req_private(usb_opaque_t req)
{
	usba_req_wrapper_t *wrp = USBA_REQ2WRP(req);

	return (wrp->wr_hcd_private);
}


/*
 * usba_hcdi_set_req_private:
 *	This function is used to set the HCD private field
 *	maintained by USBA. HCD calls this function.
 *
 * Arguments:
 *	req		- pointer to usb_*_req_t
 *	hcd_private	- wr_hcd_private field from wrapper
 */
void
usba_hcdi_set_req_private(usb_opaque_t req, usb_opaque_t hcd_private)
{
	usba_req_wrapper_t *wrp = USBA_REQ2WRP(req);

	wrp->wr_hcd_private = hcd_private;
}


/* get data toggle information for this endpoint */
uchar_t
usba_hcdi_get_data_toggle(usba_device_t *usba_device, uint8_t ep_addr)
{
	uchar_t		toggle;
	usba_ph_impl_t	*ph_impl;
	int		ep_index;

	ep_index = usb_get_ep_index(ep_addr);
	mutex_enter(&usba_device->usb_mutex);
	ph_impl = &usba_device->usb_ph_list[ep_index];
	mutex_enter(&ph_impl->usba_ph_mutex);
	toggle = (uchar_t)(ph_impl->usba_ph_flags & USBA_PH_DATA_TOGGLE);
	mutex_exit(&ph_impl->usba_ph_mutex);
	mutex_exit(&usba_device->usb_mutex);

	return (toggle);
}


/* set data toggle information for this endpoint */
void
usba_hcdi_set_data_toggle(usba_device_t *usba_device, uint8_t ep_addr,
    uchar_t toggle)
{
	usba_ph_impl_t	*ph_impl;
	int		ep_index;

	ep_index = usb_get_ep_index(ep_addr);
	mutex_enter(&usba_device->usb_mutex);
	ph_impl = &usba_device->usb_ph_list[ep_index];
	mutex_enter(&ph_impl->usba_ph_mutex);
	ph_impl->usba_ph_flags &= ~USBA_PH_DATA_TOGGLE;
	ph_impl->usba_ph_flags |= (USBA_PH_DATA_TOGGLE & toggle);
	mutex_exit(&ph_impl->usba_ph_mutex);
	mutex_exit(&usba_device->usb_mutex);
}


/* get pipe_handle_impl ptr for this ep */
usba_pipe_handle_data_t *
usba_hcdi_get_ph_data(usba_device_t *usba_device, uint8_t ep_addr)
{
	return (usba_device->usb_ph_list[usb_get_ep_index(ep_addr)].
	    usba_ph_data);
}

void *
usba_hcdi_get_device_private(usba_device_t *usba_device)
{
	return (usba_device->usb_hcd_private);
}

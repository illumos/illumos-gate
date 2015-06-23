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


/*
 * USBA: Solaris USB Architecture support
 *
 * all functions exposed to client drivers  have prefix usb_ while all USBA
 * internal functions or functions exposed to HCD or hubd only have prefix
 * usba_
 *
 * this file contains all USBAI pipe management
 *	usb_pipe_open()
 *	usb_pipe_close()
 *	usb_pipe_set_private()
 *	usb_pipe_get_private()
 *	usb_pipe_abort()
 *	usb_pipe_reset()
 *	usb_pipe_drain_reqs()
 */
#define	USBA_FRAMEWORK
#include <sys/usb/usba/usba_impl.h>
#include <sys/usb/usba/hcdi_impl.h>
#include <sys/atomic.h>

extern	pri_t	maxclsyspri;
extern	pri_t	minclsyspri;

/* function prototypes */
static	void	usba_pipe_do_async_func_thread(void *arg);
static	int	usba_pipe_sync_close(dev_info_t *, usba_ph_impl_t *,
			usba_pipe_async_req_t *, usb_flags_t);
static	int	usba_pipe_sync_reset(dev_info_t *, usba_ph_impl_t *,
			usba_pipe_async_req_t *, usb_flags_t);
static	int	usba_pipe_sync_drain_reqs(dev_info_t *, usba_ph_impl_t *,
			usba_pipe_async_req_t *, usb_flags_t);

/* local tunables */
int	usba_drain_timeout = 1000;	/* in ms */

/* return the default pipe for this device */
usb_pipe_handle_t
usba_get_dflt_pipe_handle(dev_info_t *dip)
{
	usba_device_t		*usba_device;
	usb_pipe_handle_t	pipe_handle = NULL;

	if (dip) {
		usba_device = usba_get_usba_device(dip);
		if (usba_device) {
			pipe_handle =
			    (usb_pipe_handle_t)&usba_device->usb_ph_list[0];
		}
	}

	return (pipe_handle);
}


/* return dip owner of pipe_handle */
dev_info_t *
usba_get_dip(usb_pipe_handle_t pipe_handle)
{
	usba_ph_impl_t		*ph_impl = (usba_ph_impl_t *)pipe_handle;
	dev_info_t		*dip = NULL;

	if (ph_impl) {
		mutex_enter(&ph_impl->usba_ph_mutex);
		dip = ph_impl->usba_ph_dip;
		mutex_exit(&ph_impl->usba_ph_mutex);
	}

	return (dip);
}


usb_pipe_handle_t
usba_usbdev_to_dflt_pipe_handle(usba_device_t *usba_device)
{
	usb_pipe_handle_t	pipe_handle = NULL;

	if ((usba_device) &&
	    (usba_device->usb_ph_list[0].usba_ph_data != NULL)) {
		pipe_handle = (usb_pipe_handle_t)&usba_device->usb_ph_list[0];
	}

	return (pipe_handle);
}


usba_pipe_handle_data_t *
usba_get_ph_data(usb_pipe_handle_t pipe_handle)
{
	usba_ph_impl_t		*ph_impl = (usba_ph_impl_t *)pipe_handle;
	usba_pipe_handle_data_t *ph_data = NULL;

	if (ph_impl) {
		mutex_enter(&ph_impl->usba_ph_mutex);
		ASSERT(ph_impl->usba_ph_ref_count >= 0);
		ph_data = ph_impl->usba_ph_data;
		mutex_exit(&ph_impl->usba_ph_mutex);
	}

	return (ph_data);
}


usb_pipe_handle_t
usba_get_pipe_handle(usba_pipe_handle_data_t *ph_data)
{
	usb_pipe_handle_t ph = NULL;

	if (ph_data) {
		mutex_enter(&ph_data->p_mutex);
		ASSERT(ph_data->p_req_count >= 0);
		ph = (usb_pipe_handle_t)ph_data->p_ph_impl;
		mutex_exit(&ph_data->p_mutex);
	}

	return (ph);
}


/*
 * opaque to pipe handle impl translation with incr of ref count. The caller
 * must release ph_data when done. Increment the ref count ensures that
 * the ph_data will not be freed underneath us.
 */
usba_pipe_handle_data_t *
usba_hold_ph_data(usb_pipe_handle_t pipe_handle)
{
	usba_ph_impl_t		*ph_impl = (usba_ph_impl_t *)pipe_handle;
	usba_pipe_handle_data_t *ph_data = NULL;

	if (ph_impl) {
		mutex_enter(&ph_impl->usba_ph_mutex);

		switch (ph_impl->usba_ph_state) {
		case USB_PIPE_STATE_IDLE:
		case USB_PIPE_STATE_ACTIVE:
		case USB_PIPE_STATE_ERROR:
			ph_data = ph_impl->usba_ph_data;
			ph_impl->usba_ph_ref_count++;
			break;
		case USB_PIPE_STATE_CLOSED:
		case USB_PIPE_STATE_CLOSING:
		default:
			break;
		}

		USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usba_hold_ph_data: ph_impl=0x%p state=%d ref=%d",
		    (void *)ph_impl, ph_impl->usba_ph_state,
		    ph_impl->usba_ph_ref_count);

		mutex_exit(&ph_impl->usba_ph_mutex);
	}

	return (ph_data);
}


void
usba_release_ph_data(usba_ph_impl_t *ph_impl)
{
	if (ph_impl) {
		mutex_enter(&ph_impl->usba_ph_mutex);

		USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usba_release_ph_data: "
		    "ph_impl=0x%p state=%d ref=%d",
		    (void *)ph_impl, ph_impl->usba_ph_state,
		    ph_impl->usba_ph_ref_count);

#ifndef __lock_lint
		if (ph_impl->usba_ph_data) {
			USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
			    "usba_release_ph_data: req_count=%d",
			    ph_impl->usba_ph_data->p_req_count);
			ASSERT(ph_impl->usba_ph_data->p_req_count >= 0);
		}
#endif
		ph_impl->usba_ph_ref_count--;
		ASSERT(ph_impl->usba_ph_ref_count >= 0);

		mutex_exit(&ph_impl->usba_ph_mutex);
	}
}


/*
 * get pipe state from ph_data
 */
usb_pipe_state_t
usba_get_ph_state(usba_pipe_handle_data_t *ph_data)
{
	usba_ph_impl_t		*ph_impl = ph_data->p_ph_impl;
	usb_pipe_state_t	pipe_state;

	ASSERT(mutex_owned(&ph_data->p_mutex));
	mutex_enter(&ph_impl->usba_ph_mutex);
	pipe_state = ph_impl->usba_ph_state;
	mutex_exit(&ph_impl->usba_ph_mutex);

	return (pipe_state);
}


/*
 * get ref_count from ph_data
 */
int
usba_get_ph_ref_count(usba_pipe_handle_data_t *ph_data)
{
	usba_ph_impl_t		*ph_impl = ph_data->p_ph_impl;
	int			ref_count;

	mutex_enter(&ph_impl->usba_ph_mutex);
	ref_count = ph_impl->usba_ph_ref_count;
	mutex_exit(&ph_impl->usba_ph_mutex);

	return (ref_count);
}


/*
 * new pipe state
 * We need to hold both pipe mutex and ph_impl mutex
 */
void
usba_pipe_new_state(usba_pipe_handle_data_t *ph_data, usb_pipe_state_t state)
{
	usba_ph_impl_t *ph_impl = ph_data->p_ph_impl;

	ASSERT(mutex_owned(&ph_data->p_mutex));

	mutex_enter(&ph_impl->usba_ph_mutex);
	ASSERT(ph_data->p_req_count >= 0);
	ASSERT(ph_impl->usba_ph_ref_count >= 0);

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_pipe_new_state: "
	    "ph_data=0x%p old=%s new=%s ref=%d req=%d",
	    (void *)ph_data, usb_str_pipe_state(ph_impl->usba_ph_state),
	    usb_str_pipe_state(state),
	    ph_impl->usba_ph_ref_count, ph_data->p_req_count);

	switch (ph_impl->usba_ph_state) {
	case USB_PIPE_STATE_IDLE:
	case USB_PIPE_STATE_ACTIVE:
	case USB_PIPE_STATE_ERROR:
	case USB_PIPE_STATE_CLOSED:
		ph_impl->usba_ph_state = state;
		break;
	case USB_PIPE_STATE_CLOSING:
	default:
		break;
	}
	mutex_exit(&ph_impl->usba_ph_mutex);
}


/*
 * async function execution support
 * Arguments:
 *	dip		- devinfo pointer
 *	sync_func	- function to be executed
 *	ph_impl		- impl pipehandle
 *	arg		- opaque arg
 *	usb_flags	- none
 *	callback	- function to be called on completion, may be NULL
 *	callback_arg	- argument for callback function
 *
 * Note: The caller must do a hold on ph_data
 *	We sleep for memory resources and taskq_dispatch which will ensure
 *	that this function succeeds
 */
int
usba_pipe_setup_func_call(
	dev_info_t	*dip,
	int		(*sync_func)(dev_info_t *,
			    usba_ph_impl_t *, usba_pipe_async_req_t *,
			    usb_flags_t),
	usba_ph_impl_t *ph_impl,
	usb_opaque_t	arg,
	usb_flags_t	usb_flags,
	void		(*callback)(usb_pipe_handle_t,
			    usb_opaque_t, int, usb_cb_flags_t),
	usb_opaque_t	callback_arg)
{
	usba_pipe_async_req_t	*request;
	usb_pipe_handle_t	pipe_handle = (usb_pipe_handle_t)ph_impl;
	usba_pipe_handle_data_t *ph_data = ph_impl->usba_ph_data;
	int			rval = USB_SUCCESS;
	usb_cb_flags_t		callback_flags;

	USB_DPRINTF_L3(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_pipe_setup_func_call: ph_impl=0x%p, func=0x%p",
	    (void *)ph_impl, (void *)sync_func);

	if (((usb_flags & USB_FLAGS_SLEEP) == 0) && (callback == NULL)) {
		usba_release_ph_data(ph_impl);
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usba_pipe_setup_func_call: async request with "
		    "no callback");

		return (USB_INVALID_ARGS);
	}

	request = kmem_zalloc(sizeof (usba_pipe_async_req_t), KM_SLEEP);
	request->dip		= dip;
	request->ph_impl	= ph_impl;
	request->arg		= arg;

	/*
	 * OR in sleep flag. regardless of calling sync_func directly
	 * or in a new thread, we will always wait for completion
	 */
	request->usb_flags	= usb_flags | USB_FLAGS_SLEEP;
	request->sync_func	= sync_func;
	request->callback	= callback;
	request->callback_arg	= callback_arg;

	if (usb_flags & USB_FLAGS_SLEEP) {
		rval = sync_func(dip, ph_impl, request, usb_flags);
		kmem_free(request, sizeof (usba_pipe_async_req_t));

	} else if (usba_async_ph_req(ph_data,
	    usba_pipe_do_async_func_thread,
	    (void *)request, USB_FLAGS_SLEEP) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usb_async_req failed: ph_impl=0x%p, func=0x%p",
		    (void *)ph_impl, (void *)sync_func);

		if (callback) {
			callback_flags =
			    usba_check_intr_context(USB_CB_ASYNC_REQ_FAILED);
			callback(pipe_handle, callback_arg, USB_FAILURE,
			    callback_flags);
		}

		kmem_free(request, sizeof (usba_pipe_async_req_t));
		usba_release_ph_data(ph_impl);
	}

	return (rval);
}


/*
 * taskq thread function to execute function synchronously
 * Note: caller must have done a hold on ph_data
 */
static void
usba_pipe_do_async_func_thread(void *arg)
{
	usba_pipe_async_req_t	*request = (usba_pipe_async_req_t *)arg;
	usba_ph_impl_t		*ph_impl = request->ph_impl;
	usb_pipe_handle_t	pipe_handle = (usb_pipe_handle_t)ph_impl;
	int			rval;
	usb_cb_flags_t		cb_flags = USB_CB_NO_INFO;

	if ((rval = request->sync_func(request->dip, ph_impl,
	    request, request->usb_flags | USB_FLAGS_SLEEP)) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "sync func failed (%d)", rval);
	}

	if (request->callback) {
		request->callback(pipe_handle, request->callback_arg, rval,
		    cb_flags);
	}

	kmem_free(request, sizeof (usba_pipe_async_req_t));
}


/*
 * default endpoint descriptor and pipe policy
 */
usb_ep_descr_t	usba_default_ep_descr =
	{7, 5, 0, USB_EP_ATTR_CONTROL, 8, 0};

/* set some meaningful defaults */
static usb_pipe_policy_t usba_default_ep_pipe_policy = {3};


/*
 * usb_get_ep_index: create an index from endpoint address that can
 * be used to index into endpoint pipe lists
 */
uchar_t
usb_get_ep_index(uint8_t ep_addr)
{
	return ((ep_addr & USB_EP_NUM_MASK) +
	    ((ep_addr & USB_EP_DIR_MASK) ? 16 : 0));
}


/*
 * pipe management
 *	utility functions to init and destroy a pipehandle
 */
static int
usba_init_pipe_handle(dev_info_t *dip,
	usba_device_t		*usba_device,
	usb_ep_descr_t		*ep,
	usb_pipe_policy_t	*pipe_policy,
	usba_ph_impl_t		*ph_impl)
{
	int instance = ddi_get_instance(dip);
	unsigned int def_instance = instance;
	static unsigned int anon_instance = 0;
	char tq_name[TASKQ_NAMELEN];

	usba_pipe_handle_data_t *ph_data = ph_impl->usba_ph_data;
	ddi_iblock_cookie_t	iblock_cookie =
	    usba_hcdi_get_hcdi(usba_device->usb_root_hub_dip)->
	    hcdi_iblock_cookie;

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_init_pipe_handle: "
	    "usba_device=0x%p ep=0x%x", (void *)usba_device,
	    ep->bEndpointAddress);
	mutex_init(&ph_data->p_mutex, NULL, MUTEX_DRIVER, iblock_cookie);

	/* just to keep warlock happy, there is no contention yet */
	mutex_enter(&ph_data->p_mutex);
	mutex_enter(&usba_device->usb_mutex);

	ASSERT(pipe_policy->pp_max_async_reqs);

	if (instance != -1) {
		(void) snprintf(tq_name, sizeof (tq_name),
		    "USB_%s_%x_pipehndl_tq_%d",
		    ddi_driver_name(dip), ep->bEndpointAddress, instance);
	} else {
		def_instance = atomic_inc_32_nv(&anon_instance);

		(void) snprintf(tq_name, sizeof (tq_name),
		    "USB_%s_%x_pipehndl_tq_%d_",
		    ddi_driver_name(dip), ep->bEndpointAddress, def_instance);
	}

	ph_data->p_taskq = taskq_create(tq_name,
	    pipe_policy->pp_max_async_reqs + 1,
	    ((ep->bmAttributes & USB_EP_ATTR_MASK) ==
	    USB_EP_ATTR_ISOCH) ?
	    (maxclsyspri - 5) : minclsyspri,
	    2 * (pipe_policy->pp_max_async_reqs + 1),
	    8 * (pipe_policy->pp_max_async_reqs + 1),
	    TASKQ_PREPOPULATE);

	/*
	 * Create a shared taskq.
	 */
	if (ph_data->p_spec_flag & USBA_PH_FLAG_TQ_SHARE) {
		int iface = usb_get_if_number(dip);
		if (iface < 0) {
			/* we own the device, use first entry */
			iface = 0;
		}

		if (instance != -1) {
			(void) snprintf(tq_name, sizeof (tq_name),
			    "USB_%s_%x_shared_tq_%d",
			    ddi_driver_name(dip), ep->bEndpointAddress,
			    instance);
		} else {
			(void) snprintf(tq_name, sizeof (tq_name),
			    "USB_%s_%x_shared_tq_%d_",
			    ddi_driver_name(dip), ep->bEndpointAddress,
			    def_instance);
		}

		if (usba_device->usb_shared_taskq_ref_count[iface] == 0) {
			usba_device->usb_shared_taskq[iface] =
			    taskq_create(tq_name,
			    1,				/* Number threads. */
			    maxclsyspri - 5,		/* Priority */
			    1,				/* minalloc */
			    USBA_N_ENDPOINTS + 4,	/* maxalloc */
			    TASKQ_PREPOPULATE);
			ASSERT(usba_device->usb_shared_taskq[iface] != NULL);
		}
		usba_device->usb_shared_taskq_ref_count[iface]++;
	}

	ph_data->p_dip		= dip;
	ph_data->p_usba_device	= usba_device;
	ph_data->p_ep		= *ep;
	ph_data->p_ph_impl	= ph_impl;
	if ((ep->bmAttributes & USB_EP_ATTR_MASK) ==
	    USB_EP_ATTR_ISOCH) {
		ph_data->p_spec_flag |= USBA_PH_FLAG_USE_SOFT_INTR;
	}

	/* fix up the MaxPacketSize if it is the default endpoint descr */
	if ((ep == &usba_default_ep_descr) && usba_device) {
		uint16_t	maxpktsize;

		maxpktsize = usba_device->usb_dev_descr->bMaxPacketSize0;
		USB_DPRINTF_L3(DPRINT_MASK_USBAI, usbai_log_handle,
		    "adjusting max packet size from %d to %d",
		    ph_data->p_ep.wMaxPacketSize, maxpktsize);

		ph_data->p_ep.wMaxPacketSize = maxpktsize;
	}

	/* now update usba_ph_impl structure */
	mutex_enter(&ph_impl->usba_ph_mutex);
	ph_impl->usba_ph_dip = dip;
	ph_impl->usba_ph_ep = ph_data->p_ep;
	ph_impl->usba_ph_policy = ph_data->p_policy = *pipe_policy;
	mutex_exit(&ph_impl->usba_ph_mutex);

	usba_init_list(&ph_data->p_queue, (usb_opaque_t)ph_data, iblock_cookie);
	usba_init_list(&ph_data->p_cb_queue, (usb_opaque_t)ph_data,
	    iblock_cookie);
	mutex_exit(&usba_device->usb_mutex);
	mutex_exit(&ph_data->p_mutex);

	return (USB_SUCCESS);
}


static void
usba_taskq_destroy(void *arg)
{
	taskq_destroy((taskq_t *)arg);
}


static void
usba_destroy_pipe_handle(usba_pipe_handle_data_t *ph_data)
{
	usba_ph_impl_t		*ph_impl = ph_data->p_ph_impl;
	int			timeout;
	usba_device_t		*usba_device;

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_destroy_pipe_handle: ph_data=0x%p", (void *)ph_data);

	mutex_enter(&ph_data->p_mutex);
	mutex_enter(&ph_impl->usba_ph_mutex);

	/* check for all activity to drain */
	for (timeout = 0; timeout < usba_drain_timeout; timeout++) {
		if ((ph_impl->usba_ph_ref_count <= 1) &&
		    (ph_data->p_req_count == 0)) {

			break;
		}
		mutex_exit(&ph_data->p_mutex);
		mutex_exit(&ph_impl->usba_ph_mutex);
		delay(drv_usectohz(1000));
		mutex_enter(&ph_data->p_mutex);
		mutex_enter(&ph_impl->usba_ph_mutex);
	}

	/*
	 * set state to closed here so any other thread
	 * that is waiting for the CLOSED state will
	 * continue. Otherwise, taskq_destroy might deadlock
	 */
	ph_impl->usba_ph_data = NULL;
	ph_impl->usba_ph_ref_count = 0;
	ph_impl->usba_ph_state = USB_PIPE_STATE_CLOSED;

	if (ph_data->p_taskq) {
		mutex_exit(&ph_data->p_mutex);
		mutex_exit(&ph_impl->usba_ph_mutex);
		if (taskq_member(ph_data->p_taskq, curthread)) {
			/*
			 * use system taskq to destroy ph's taskq to avoid
			 * deadlock
			 */
			(void) taskq_dispatch(system_taskq,
			    usba_taskq_destroy, ph_data->p_taskq, TQ_SLEEP);
		} else {
			taskq_destroy(ph_data->p_taskq);
		}
	} else {
		mutex_exit(&ph_data->p_mutex);
		mutex_exit(&ph_impl->usba_ph_mutex);
	}

	usba_device = ph_data->p_usba_device;
	mutex_enter(&ph_data->p_mutex);
	if (ph_data->p_spec_flag & USBA_PH_FLAG_TQ_SHARE) {
		int iface = usb_get_if_number(ph_data->p_dip);
		if (iface < 0) {
			/* we own the device, use the first entry */
			iface = 0;
		}
		mutex_enter(&usba_device->usb_mutex);
		if (--usba_device->usb_shared_taskq_ref_count[iface] == 0) {
			ph_data->p_spec_flag &= ~USBA_PH_FLAG_TQ_SHARE;
			if (taskq_member(usba_device->usb_shared_taskq[iface],
			    curthread)) {
				(void) taskq_dispatch(
				    system_taskq,
				    usba_taskq_destroy,
				    usba_device->usb_shared_taskq[iface],
				    TQ_SLEEP);
			} else {
				taskq_destroy(
				    usba_device->usb_shared_taskq[iface]);
			}
		}
		mutex_exit(&usba_device->usb_mutex);
	}
	mutex_exit(&ph_data->p_mutex);


	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_destroy_pipe_handle: destroying ph_data=0x%p",
	    (void *)ph_data);

	usba_destroy_list(&ph_data->p_queue);
	usba_destroy_list(&ph_data->p_cb_queue);

	/* destroy mutexes */
	mutex_destroy(&ph_data->p_mutex);

	kmem_free(ph_data, sizeof (usba_pipe_handle_data_t));
}


/*
 * usba_drain_cbs:
 *	Drain the request callbacks on the pipe handle
 */
int
usba_drain_cbs(usba_pipe_handle_data_t *ph_data, usb_cb_flags_t cb_flags,
	usb_cr_t cr)
{
	usba_req_wrapper_t	*req_wrp;
	int			flush_requests = 1;
	usba_ph_impl_t		*ph_impl = ph_data->p_ph_impl;
	int			timeout;
	int			rval = USB_SUCCESS;

	ASSERT(mutex_owned(&ph_data->p_mutex));

	mutex_enter(&ph_impl->usba_ph_mutex);
	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_drain_cbs: ph_data=0x%p ref=%d req=%d cb=0x%x cr=%d",
	    (void *)ph_data, ph_impl->usba_ph_ref_count, ph_data->p_req_count,
	    cb_flags, cr);
	ASSERT(ph_data->p_req_count >= 0);
	mutex_exit(&ph_impl->usba_ph_mutex);

	if (ph_data->p_dip) {
		if (USBA_IS_DEFAULT_PIPE(ph_data)) {
			USB_DPRINTF_L4(DPRINT_MASK_USBAI,
			    usbai_log_handle,
			    "no flushing on default pipe!");

			flush_requests = 0;
		}
	}

	if (flush_requests) {
		/* flush all requests in the pipehandle queue */
		while ((req_wrp = (usba_req_wrapper_t *)
		    usba_rm_first_pvt_from_list(&ph_data->p_queue)) != NULL) {
			mutex_exit(&ph_data->p_mutex);
			usba_do_req_exc_cb(req_wrp, cr, cb_flags);
			mutex_enter(&ph_data->p_mutex);
		}
	}

	/*
	 * wait for any callbacks in progress but don't wait for
	 * for queued requests on the default pipe
	 */
	for (timeout = 0; (timeout < usba_drain_timeout) &&
	    (ph_data->p_req_count >
	    usba_list_entry_count(&ph_data->p_queue));
	    timeout++) {
		mutex_exit(&ph_data->p_mutex);
		delay(drv_usectohz(1000));
		mutex_enter(&ph_data->p_mutex);
	}

	mutex_enter(&ph_impl->usba_ph_mutex);
	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_drain_cbs done: ph_data=0x%p ref=%d req=%d",
	    (void *)ph_data, ph_impl->usba_ph_ref_count, ph_data->p_req_count);
	mutex_exit(&ph_impl->usba_ph_mutex);

	if (timeout == usba_drain_timeout) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "draining callbacks timed out!");

		rval = USB_FAILURE;
	}

	return (rval);
}


/*
 * usb_pipe_open():
 *
 * Before using any pipe including the default pipe, it should be opened
 * using usb_pipe_open(). On a successful open, a pipe handle is returned
 * for use in other usb_pipe_*() functions
 *
 * The default pipe can only be opened by the hub driver
 *
 * The bandwidth has been allocated and guaranteed on successful
 * opening of an isoc/intr pipes.
 *
 * Only the default pipe can be shared. all other control pipes
 * are excusively opened by default.
 * A pipe policy and endpoint descriptor must always be provided
 * except for default pipe
 *
 * Arguments:
 *	dip		- devinfo ptr
 *	ep		- endpoint descriptor pointer
 *	pipe_policy	- pointer to pipe policy which provides hints on how
 *			  the pipe will be used.
 *	flags		- USB_FLAGS_SLEEP wait for resources
 *			  to become available
 *	pipe_handle	- a pipe handle pointer. On a successful open,
 *			  a pipe_handle is returned in this pointer.
 *
 * Return values:
 *	USB_SUCCESS	 - open succeeded
 *	USB_FAILURE	 - unspecified open failure or pipe is already open
 *	USB_NO_RESOURCES - no resources were available to complete the open
 *	USB_NO_BANDWIDTH - no bandwidth available (isoc/intr pipes)
 *	USB_*		 - refer to usbai.h
 */
int
usb_pipe_open(
	dev_info_t		*dip,
	usb_ep_descr_t		*ep,
	usb_pipe_policy_t	*pipe_policy,
	usb_flags_t		usb_flags,
	usb_pipe_handle_t	*pipe_handle)
{
	usba_device_t		*usba_device;
	int			rval;
	usba_pipe_handle_data_t *ph_data;
	usba_ph_impl_t		*ph_impl;
	uchar_t			ep_index;
	int			kmflag;
	size_t			size;

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_pipe_open:\n\t"
	    "dip=0x%p ep=0x%p pp=0x%p uf=0x%x ph=0x%p",
	    (void *)dip, (void *)ep, (void *)pipe_policy, usb_flags,
	    (void *)pipe_handle);

	if ((dip == NULL) || (pipe_handle == NULL)) {

		return (USB_INVALID_ARGS);
	}

	if (servicing_interrupt() && (usb_flags & USB_FLAGS_SLEEP)) {

		return (USB_INVALID_CONTEXT);
	}
	usba_device = usba_get_usba_device(dip);

	if ((ep != NULL) && (pipe_policy == NULL)) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usb_pipe_open: null pipe policy");

		return (USB_INVALID_ARGS);
	}

	/* is the device still connected? */
	if ((ep != NULL) & DEVI_IS_DEVICE_REMOVED(dip)) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usb_pipe_open: device has been removed");

		return (USB_FAILURE);
	}


	/*
	 * if a null endpoint pointer was passed, use the default
	 * endpoint descriptor
	 */
	if (ep == NULL) {
		if ((usb_flags & USBA_FLAGS_PRIVILEGED) == 0) {
			USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
			    "usb_pipe_open: not allowed to open def pipe");

			return (USB_INVALID_PERM);
		}

		ep = &usba_default_ep_descr;
		pipe_policy = &usba_default_ep_pipe_policy;
	}

	if (usb_flags & USB_FLAGS_SERIALIZED_CB) {
		if (((ep->bmAttributes & USB_EP_ATTR_MASK) ==
		    USB_EP_ATTR_CONTROL) ||
		    ((ep->bmAttributes & USB_EP_ATTR_MASK) ==
		    USB_EP_ATTR_ISOCH)) {
			USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
			    "usb_pipe_open: shared taskq not allowed with "
			    "ctrl or isoch pipe");

			return (USB_INVALID_ARGS);
		}
	}

	kmflag	= (usb_flags & USB_FLAGS_SLEEP) ? KM_SLEEP : KM_NOSLEEP;
	size	= sizeof (usba_pipe_handle_data_t);

	if ((ph_data = kmem_zalloc(size, kmflag)) == NULL) {

		return (USB_NO_RESOURCES);
	}

	/* check if pipe is already open and if so fail */
	ep_index = usb_get_ep_index(ep->bEndpointAddress);
	ph_impl = &usba_device->usb_ph_list[ep_index];

	mutex_enter(&usba_device->usb_mutex);
	mutex_enter(&ph_impl->usba_ph_mutex);

	if (ph_impl->usba_ph_data) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usb_pipe_open: pipe to ep %d already open", ep_index);
		mutex_exit(&ph_impl->usba_ph_mutex);
		mutex_exit(&usba_device->usb_mutex);
		kmem_free(ph_data, size);

		return (USB_BUSY);
	}

	ph_impl->usba_ph_data = ph_data;

	mutex_exit(&ph_impl->usba_ph_mutex);
	mutex_exit(&usba_device->usb_mutex);

	if (usb_flags & USB_FLAGS_SERIALIZED_CB) {
		mutex_enter(&ph_data->p_mutex);
		ph_data->p_spec_flag |= USBA_PH_FLAG_TQ_SHARE;
		mutex_exit(&ph_data->p_mutex);
	}

	/*
	 * allocate and initialize the pipe handle
	 */
	if ((rval = usba_init_pipe_handle(dip, usba_device,
	    ep, pipe_policy, ph_impl)) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usb_pipe_open: pipe init failed (%d)", rval);

		return (rval);
	}
	ph_data = ph_impl->usba_ph_data;

	/*
	 * ask the hcd to open the pipe
	 */
	if ((rval = usba_device->usb_hcdi_ops->usba_hcdi_pipe_open(ph_data,
	    usb_flags)) != USB_SUCCESS) {
		usba_destroy_pipe_handle(ph_data);

		*pipe_handle = NULL;
	} else {
		*pipe_handle = (usb_pipe_handle_t)ph_impl;

		/* set the pipe state after a successful hcd open */
		mutex_enter(&ph_data->p_mutex);
		usba_pipe_new_state(ph_data, USB_PIPE_STATE_IDLE);
		mutex_exit(&ph_data->p_mutex);
	}

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_pipe_open: ph_impl=0x%p (0x%p)",
	    (void *)ph_impl, (void *)ph_data);

	return (rval);
}


/*
 * usb_pipe_close/sync_close:
 *
 * Close a pipe and release all resources and free the pipe_handle.
 * Automatic polling, if active,  will be terminated
 *
 * Arguments:
 *	dip		- devinfo ptr
 *	pipehandle	- pointer to pipehandle. The pipehandle will be
 *			  zeroed on successful completion
 *	flags		- USB_FLAGS_SLEEP:
 *				wait for resources, pipe
 *				to become free, all callbacks completed
 *	callback	- If USB_FLAGS_SLEEP has not been specified, a
 *			  callback will be performed.
 *	callback_arg	- the first argument of the callback. Note that
 *			  the pipehandle will be zeroed and not passed
 *
 * Notes:
 * Pipe close will always succeed regardless whether USB_FLAGS_SLEEP has been
 * specified or not.
 * An async close will always succeed if the hint in the pipe policy
 * has been correct about the max number of async taskq requests required.
 * If there are really no resources, the pipe handle will be linked into
 * a garbage pipe list and periodically checked by USBA until it can be
 * closed. This may cause a hang in the detach of the driver.
 * USBA will prevent the client from submitting more requests to a pipe
 * that is being closed
 * Subsequent usb_pipe_close() requests on the same pipe to USBA will
 * wait for the previous close(s) to finish.
 *
 * Note that once we start closing a pipe, we cannot go back anymore
 * to a normal pipe state
 */
void
usb_pipe_close(dev_info_t	*dip,
		usb_pipe_handle_t pipe_handle,
		usb_flags_t	usb_flags,
		void		(*callback)(
				    usb_pipe_handle_t	pipe_handle,
				    usb_opaque_t	arg,
				    int			rval,
				    usb_cb_flags_t	flags),
		usb_opaque_t	callback_arg)
{
	usba_pipe_handle_data_t *ph_data;
	usba_ph_impl_t	*ph_impl = (usba_ph_impl_t *)pipe_handle;
	usb_cb_flags_t	callback_flags;

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_pipe_close: ph=0x%p", (void *)pipe_handle);

	callback_flags = usba_check_intr_context(USB_CB_NO_INFO);
	if ((dip == NULL) || (pipe_handle == NULL)) {
		if (callback) {
			callback(pipe_handle, callback_arg,
			    USB_INVALID_ARGS, callback_flags);
		} else {
			USB_DPRINTF_L2(DPRINT_MASK_USBAI,
			    usbai_log_handle,
			    "usb_pipe_close: invalid arguments");
		}

		return;
	}

	if ((usb_flags & USBA_FLAGS_PRIVILEGED) == 0) {
		/*
		 * It is the client driver doing the pipe close,
		 * the pipe is no longer persistent then.
		 */
		mutex_enter(&ph_impl->usba_ph_mutex);
		ph_impl->usba_ph_flags &= ~USBA_PH_DATA_PERSISTENT;
		mutex_exit(&ph_impl->usba_ph_mutex);
	}

	if (servicing_interrupt() && (usb_flags & USB_FLAGS_SLEEP)) {
		if (callback) {
			callback(pipe_handle, callback_arg,
			    USB_INVALID_CONTEXT, callback_flags);
		} else {
			USB_DPRINTF_L2(DPRINT_MASK_USBAI,
			    usbai_log_handle,
			    "usb_pipe_close: invalid context");
		}

		return;
	}

	if ((ph_data = usba_hold_ph_data(pipe_handle)) == NULL) {

		/* hold pipehandle anyways since we will decrement later */
		mutex_enter(&ph_impl->usba_ph_mutex);
		ph_impl->usba_ph_ref_count++;
		mutex_exit(&ph_impl->usba_ph_mutex);

		(void) usba_pipe_setup_func_call(dip, usba_pipe_sync_close,
		    ph_impl, NULL, usb_flags, callback, callback_arg);

		return;
	}

	mutex_enter(&ph_data->p_mutex);

	if (USBA_IS_DEFAULT_PIPE(ph_data) &&
	    ((usb_flags & USBA_FLAGS_PRIVILEGED) == 0)) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usb_pipe_close: not allowed to close def pipe");
		mutex_exit(&ph_data->p_mutex);

		usba_release_ph_data(ph_impl);

		if (callback) {
			callback(pipe_handle, callback_arg,
			    USB_INVALID_PIPE, callback_flags);
		} else {
			USB_DPRINTF_L2(DPRINT_MASK_USBAI,
			    usbai_log_handle,
			    "usb_pipe_close: invalid pipe");
		}

		return;
	}

	mutex_exit(&ph_data->p_mutex);

	(void) usba_pipe_setup_func_call(dip, usba_pipe_sync_close,
	    ph_impl, NULL, usb_flags, callback, callback_arg);
}


/*ARGSUSED*/
static int
usba_pipe_sync_close(dev_info_t *dip, usba_ph_impl_t *ph_impl,
	usba_pipe_async_req_t *request, usb_flags_t usb_flags)
{
	usba_device_t		*usba_device;
	usba_pipe_handle_data_t *ph_data = usba_get_ph_data(
	    (usb_pipe_handle_t)ph_impl);
	int			attribute;
	uchar_t			dir;
	int			timeout;

	if (ph_impl == NULL) {

		return (USB_SUCCESS);
	}

	mutex_enter(&ph_impl->usba_ph_mutex);
	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_pipe_sync_close: dip=0x%p ph_data=0x%p state=%d ref=%d",
	    (void *)dip, (void *)ph_data, ph_impl->usba_ph_state,
	    ph_impl->usba_ph_ref_count);

	/*
	 * if another thread opens the pipe again, this loop could
	 * be truly forever
	 */
	if ((ph_data == NULL) ||
	    (ph_impl->usba_ph_state == USB_PIPE_STATE_CLOSING) ||
	    (ph_impl->usba_ph_state == USB_PIPE_STATE_CLOSED)) {
		/* wait forever till really closed */
		mutex_exit(&ph_impl->usba_ph_mutex);
		usba_release_ph_data(ph_impl);

		while (usba_get_ph_data((usb_pipe_handle_t)ph_impl)) {
			delay(1);
		}

		return (USB_SUCCESS);
	}
	ph_impl->usba_ph_state = USB_PIPE_STATE_CLOSING;
	mutex_exit(&ph_impl->usba_ph_mutex);

	mutex_enter(&ph_data->p_mutex);
	mutex_enter(&ph_impl->usba_ph_mutex);

	attribute = ph_data->p_ep.bmAttributes & USB_EP_ATTR_MASK;
	dir = ph_data->p_ep.bEndpointAddress & USB_EP_DIR_MASK;

	usba_device = ph_data->p_usba_device;

	/*
	 * For control and bulk, we will drain till ref_count <= 1 and
	 * req_count == 0 but for isoc and intr IN, we can only wait
	 * till the ref_count === 1 as the req_count will never go to 0
	 */
	for (timeout = 0; timeout < usba_drain_timeout; timeout++) {
		switch (attribute) {
		case USB_EP_ATTR_CONTROL:
		case USB_EP_ATTR_BULK:
			if ((ph_data->p_req_count == 0) &&
			    (ph_impl->usba_ph_ref_count <= 1)) {
				goto done;
			}
			break;
		case USB_EP_ATTR_INTR:
		case USB_EP_ATTR_ISOCH:
			if (dir == USB_EP_DIR_IN) {
				if (ph_impl->usba_ph_ref_count <= 1) {
					goto done;
				}
			} else if ((ph_data->p_req_count == 0) &&
			    (ph_impl->usba_ph_ref_count <= 1)) {
				goto done;
			}
			break;
		}
		mutex_exit(&ph_impl->usba_ph_mutex);
		mutex_exit(&ph_data->p_mutex);
		delay(drv_usectohz(1000));
		mutex_enter(&ph_data->p_mutex);
		mutex_enter(&ph_impl->usba_ph_mutex);
	}
done:

	mutex_exit(&ph_impl->usba_ph_mutex);
	mutex_exit(&ph_data->p_mutex);

	if (timeout >= usba_drain_timeout) {
		int draining_succeeded;

		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "timeout on draining requests, resetting pipe 0x%p",
		    (void *)ph_impl);

		(void) usba_device->usb_hcdi_ops->usba_hcdi_pipe_reset(ph_data,
		    USB_FLAGS_SLEEP);

		mutex_enter(&ph_data->p_mutex);
		draining_succeeded = usba_drain_cbs(ph_data, USB_CB_RESET_PIPE,
		    USB_CR_PIPE_RESET);
		/* this MUST have succeeded */
		ASSERT(draining_succeeded == USB_SUCCESS);
		mutex_exit(&ph_data->p_mutex);

		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "draining requests done");
	}

	if (usba_device->usb_hcdi_ops->usba_hcdi_pipe_close(ph_data,
	    usb_flags) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usba_pipe_sync_close: hcd close failed");
		/* carry on regardless! */
	}

	usba_destroy_pipe_handle(ph_data);

	return (USB_SUCCESS);
}


/*
 * usb_pipe_set_private:
 *	set private client date in the pipe handle
 */
int
usb_pipe_set_private(usb_pipe_handle_t	pipe_handle, usb_opaque_t data)
{
	usba_pipe_handle_data_t *ph_data = usba_hold_ph_data(pipe_handle);

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_pipe_set_private: ");

	if (ph_data == NULL) {

		return (USB_INVALID_PIPE);
	}
	if (USBA_IS_DEFAULT_PIPE(ph_data)) {
		usba_release_ph_data(ph_data->p_ph_impl);

		return (USB_INVALID_PERM);
	}

	mutex_enter(&ph_data->p_mutex);
	ph_data->p_client_private = data;
	mutex_exit(&ph_data->p_mutex);

	usba_release_ph_data(ph_data->p_ph_impl);

	return (USB_SUCCESS);
}


/*
 * usb_pipe_get_private:
 *	get private client date from the pipe handle
 */
usb_opaque_t
usb_pipe_get_private(usb_pipe_handle_t	pipe_handle)
{
	usba_pipe_handle_data_t *ph_data = usba_hold_ph_data(pipe_handle);
	usb_opaque_t		data;

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_pipe_get_private:");

	if (ph_data == NULL) {

		return (NULL);
	}

	mutex_enter(&ph_data->p_mutex);
	data = ph_data->p_client_private;
	mutex_exit(&ph_data->p_mutex);

	usba_release_ph_data(ph_data->p_ph_impl);

	return (data);
}


/*
 * usb_pipe_reset
 * Arguments:
 *	dip		- devinfo pointer
 *	pipe_handle	- opaque pipe handle
 * Returns:
 *	USB_SUCCESS	- pipe successfully reset or request queued
 *	USB_FAILURE	- undetermined failure
 *	USB_INVALID_PIPE - pipe is invalid or already closed
 */
void
usb_pipe_reset(dev_info_t		*dip,
		usb_pipe_handle_t	pipe_handle,
		usb_flags_t		usb_flags,
		void			(*callback)(
					    usb_pipe_handle_t	ph,
					    usb_opaque_t	arg,
					    int			rval,
					    usb_cb_flags_t	flags),
		usb_opaque_t		callback_arg)
{
	usba_ph_impl_t		*ph_impl = (usba_ph_impl_t *)pipe_handle;
	usba_pipe_handle_data_t *ph_data = usba_hold_ph_data(pipe_handle);
	usb_cb_flags_t		callback_flags;

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_pipe_reset: dip=0x%p ph=0x%p uf=0x%x",
	    (void *)dip, (void *)pipe_handle, usb_flags);

	callback_flags = usba_check_intr_context(USB_CB_NO_INFO);

	if ((dip == NULL) || (ph_data == NULL)) {
		if (callback) {
			callback(pipe_handle, callback_arg,
			    USB_INVALID_ARGS, callback_flags);
		} else {
			USB_DPRINTF_L2(DPRINT_MASK_USBAI,
			    usbai_log_handle,
			    "usb_pipe_reset: invalid arguments");
		}

		usba_release_ph_data(ph_impl);

		return;
	}
	if (servicing_interrupt() && (usb_flags & USB_FLAGS_SLEEP)) {
		if (callback) {
			callback(pipe_handle, callback_arg,
			    USB_INVALID_CONTEXT, callback_flags);
		} else {
			USB_DPRINTF_L2(DPRINT_MASK_USBAI,
			    usbai_log_handle,
			    "usb_pipe_reset: invalid context");
		}

		usba_release_ph_data(ph_impl);

		return;
	}

	mutex_enter(&ph_data->p_mutex);

	/* is this the default pipe? */
	if (USBA_IS_DEFAULT_PIPE(ph_data)) {
		if ((usb_flags & USBA_FLAGS_PRIVILEGED) == 0) {
			USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
			    "usb_pipe_reset: not allowed to reset def pipe");
			mutex_exit(&ph_data->p_mutex);

			if (callback) {
				callback(pipe_handle, callback_arg,
				    USB_INVALID_PIPE, callback_flags);
			} else {
				USB_DPRINTF_L2(DPRINT_MASK_USBAI,
				    usbai_log_handle,
				    "usb_pipe_reset: invalid pipe");
			}
			usba_release_ph_data(ph_impl);

			return;
		}
	}
	mutex_exit(&ph_data->p_mutex);

	(void) usba_pipe_setup_func_call(dip,
	    usba_pipe_sync_reset, ph_impl, NULL, usb_flags, callback,
	    callback_arg);
}


/*ARGSUSED*/
int
usba_pipe_sync_reset(dev_info_t	*dip,
	usba_ph_impl_t		*ph_impl,
	usba_pipe_async_req_t	*request,
	usb_flags_t		usb_flags)
{
	int rval, draining_succeeded;
	usba_pipe_handle_data_t *ph_data = usba_get_ph_data((usb_pipe_handle_t)
	    ph_impl);
	usba_device_t		*usba_device;

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_pipe_sync_reset: dip=0x%p ph_data=0x%p uf=0x%x",
	    (void *)dip, (void *)ph_data, usb_flags);

	mutex_enter(&ph_data->p_mutex);
	usba_device = ph_data->p_usba_device;
	mutex_exit(&ph_data->p_mutex);

	rval = usba_device->usb_hcdi_ops->usba_hcdi_pipe_reset(ph_data,
	    usb_flags);
	mutex_enter(&ph_data->p_mutex);

	/*
	 * The host controller has stopped polling of the endpoint.
	 */
	draining_succeeded = usba_drain_cbs(ph_data, USB_CB_RESET_PIPE,
	    USB_CR_PIPE_RESET);

	/* this MUST have succeeded */
	ASSERT(draining_succeeded == USB_SUCCESS);

	usba_pipe_new_state(ph_data, USB_PIPE_STATE_IDLE);
	mutex_exit(&ph_data->p_mutex);

	/*
	 * if there are requests still queued on the default pipe,
	 * start them now
	 */
	usba_start_next_req(ph_data);

	usba_release_ph_data(ph_impl);

	return (rval);
}


/*
 * usba_pipe_clear:
 *	call hcd to clear pipe but don't wait for draining
 */
void
usba_pipe_clear(usb_pipe_handle_t pipe_handle)
{
	usba_pipe_handle_data_t *ph_data = usba_get_ph_data(pipe_handle);
	usba_device_t		*usba_device;
	usba_req_wrapper_t	*req_wrp;
	int			flush_requests = 1;

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_pipe_clear: ph_data=0x%p", (void *)ph_data);

	if (ph_data == NULL) {

		return;
	}

	mutex_enter(&ph_data->p_mutex);
	if (USBA_PIPE_CLOSING(usba_get_ph_state(ph_data))) {
		mutex_exit(&ph_data->p_mutex);

		return;
	}
	usba_device = ph_data->p_usba_device;
	mutex_exit(&ph_data->p_mutex);

	(void) usba_device->usb_hcdi_ops->usba_hcdi_pipe_reset(ph_data,
	    USB_FLAGS_SLEEP);

	mutex_enter(&ph_data->p_mutex);
	if (ph_data->p_dip) {
		if (USBA_IS_DEFAULT_PIPE(ph_data)) {
			USB_DPRINTF_L4(DPRINT_MASK_USBAI,
			    usbai_log_handle,
			    "no flushing on default pipe!");

			flush_requests = 0;
		}
	}

	if (flush_requests) {
		/* flush all requests in the pipehandle queue */
		while ((req_wrp = (usba_req_wrapper_t *)
		    usba_rm_first_pvt_from_list(&ph_data->p_queue)) != NULL) {
			mutex_exit(&ph_data->p_mutex);
			usba_do_req_exc_cb(req_wrp, USB_CR_FLUSHED,
			    USB_CB_RESET_PIPE);
			mutex_enter(&ph_data->p_mutex);
		}
	}

	usba_pipe_new_state(ph_data, USB_PIPE_STATE_IDLE);
	mutex_exit(&ph_data->p_mutex);
}


/*
 *
 * usb_pipe_drain_reqs
 *	this function blocks until there are no more requests
 *	owned by this dip on the pipe
 *
 * Arguments:
 *	dip		- devinfo pointer
 *	pipe_handle	- opaque pipe handle
 *	timeout 	- timeout in seconds
 *	flags		- USB_FLAGS_SLEEP:
 *				wait for completion.
 *	cb		- if USB_FLAGS_SLEEP has not been specified
 *			  this callback function will be called on
 *			  completion. This callback may be NULL
 *			  and no notification of completion will then
 *			  be provided.
 *	cb_arg		- 2nd argument to callback function.
 *
 * callback and callback_arg should be NULL if USB_FLAGS_SLEEP has
 * been specified
 *
 * Returns:
 *	USB_SUCCESS	- pipe successfully reset or request queued
 *	USB_FAILURE	- timeout
 *	USB_*		- refer to usbai.h
 */
int
usb_pipe_drain_reqs(dev_info_t	*dip,
	usb_pipe_handle_t	pipe_handle,
	uint_t			time,
	usb_flags_t		usb_flags,
	void			(*cb)(
				    usb_pipe_handle_t	ph,
				    usb_opaque_t	arg,   /* cb arg */
				    int			rval,
				    usb_cb_flags_t	flags),
	usb_opaque_t		cb_arg)
{
	usba_ph_impl_t		*ph_impl = (usba_ph_impl_t *)pipe_handle;
	usba_pipe_handle_data_t *ph_data = usba_hold_ph_data(pipe_handle);

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_pipe_drain_reqs: dip=0x%p ph_data=0x%p tm=%d uf=0x%x",
	    (void *)dip, (void *)ph_data, time, usb_flags);

	if (ph_data == NULL) {

		return (USB_INVALID_PIPE);
	}
	if (dip == NULL) {
		usba_release_ph_data(ph_impl);

		return (USB_INVALID_ARGS);
	}

	if ((usb_flags & USB_FLAGS_SLEEP) && servicing_interrupt()) {
		usba_release_ph_data(ph_impl);

		return (USB_INVALID_CONTEXT);
	}

	(void) usba_pipe_setup_func_call(dip, usba_pipe_sync_drain_reqs,
	    ph_impl, (usb_opaque_t)((uintptr_t)time), usb_flags, cb, cb_arg);

	return (USB_SUCCESS);
}


/*
 * usba_pipe_sync_drain_reqs
 *	this function blocks until there are no more requests
 *	owned by this dip on the pipe
 *
 * Arguments:
 *	dip		- devinfo pointer
 *	ph_impl		- pipe impl handle
 *	timeout		- timeout in seconds
 * Returns:
 *	USB_SUCCESS	- pipe successfully reset or request queued
 *	USB_FAILURE	- timeout
 *	USB_*		- see usbai.h
 */
/*ARGSUSED*/
int
usba_pipe_sync_drain_reqs(dev_info_t	*dip,
		usba_ph_impl_t		*ph_impl,
		usba_pipe_async_req_t	*request,
		usb_flags_t		usb_flags)
{
	usba_pipe_handle_data_t *ph_data = usba_get_ph_data((usb_pipe_handle_t)
	    ph_impl);
	int		i;
	int		timeout = 100 * (int)((uintptr_t)(request->arg));
						/* delay will be 10 ms */

	mutex_enter(&ph_data->p_mutex);

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_pipe_sync_drain_reqs: "
	    "dip=0x%p ph_data=0x%p timeout=%d ref=%d req=%d",
	    (void *)dip, (void *)ph_data, timeout,
	    usba_get_ph_ref_count(ph_data),
	    ph_data->p_req_count);

	ASSERT(ph_data->p_req_count >= 0);

	/*
	 * for default pipe, we need to check the active request
	 * and the queue
	 * Note that a pipe reset on the default pipe doesn't flush
	 * the queue
	 * for all other pipes we just check ref and req count since
	 * these pipes are unshared
	 */
	if (USBA_IS_DEFAULT_PIPE(ph_data)) {
		for (i = 0; (i < timeout) || (request->arg == 0); i++) {
			usba_list_entry_t *next, *tmpnext;
			usba_req_wrapper_t *req_wrp = (usba_req_wrapper_t *)
			    ph_data->p_active_cntrl_req_wrp;
			int found = 0;
			int count = 0;

			/* active_req_wrp is only for control pipes */
			if ((req_wrp == NULL) || (req_wrp->wr_dip != dip)) {
				/* walk the queue */
				mutex_enter(&ph_data->p_queue.list_mutex);
				next = ph_data->p_queue.next;
				while (next != NULL) {
					mutex_enter(&next->list_mutex);
					req_wrp = (usba_req_wrapper_t *)
					    next->private;
					found = (req_wrp->wr_dip == dip);
					if (found) {
						mutex_exit(&next->list_mutex);

						break;
					}
					tmpnext = next->next;
					mutex_exit(&next->list_mutex);
					next = tmpnext;
					count++;
				}
				mutex_exit(&ph_data->p_queue.list_mutex);
				if (found == 0) {
					break;
				}
			}

			USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
			    "usb_pipe_sync_drain_reqs: "
			    "cnt=%d active_req_wrp=0x%p",
			    count, (void *)ph_data->p_active_cntrl_req_wrp);

			mutex_exit(&ph_data->p_mutex);
			delay(drv_usectohz(10000));
			mutex_enter(&ph_data->p_mutex);
		}
	} else {
		mutex_enter(&ph_data->p_ph_impl->usba_ph_mutex);
		for (i = 0; (i < timeout) || (request->arg == 0); i++) {
			ASSERT(ph_data->p_req_count >= 0);
			if (ph_data->p_req_count ||
			    (ph_data->p_ph_impl->usba_ph_ref_count > 1)) {
				mutex_exit(&ph_data->p_ph_impl->usba_ph_mutex);
				mutex_exit(&ph_data->p_mutex);
				delay(drv_usectohz(10000));
				mutex_enter(&ph_data->p_mutex);
				mutex_enter(&ph_data->p_ph_impl->usba_ph_mutex);
			} else {
				break;
			}
		}
		mutex_exit(&ph_data->p_ph_impl->usba_ph_mutex);
	}

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_pipe_sync_drain_reqs: timeout=%d active_req_wrp=0x%p req=%d",
	    i, (void *)ph_data->p_active_cntrl_req_wrp, ph_data->p_req_count);

	mutex_exit(&ph_data->p_mutex);

	usba_release_ph_data(ph_impl);

	return (i >= timeout ? USB_FAILURE : USB_SUCCESS);
}


/*
 * usba_persistent_pipe_open
 *	Open all the pipes marked persistent for this device
 */
int
usba_persistent_pipe_open(usba_device_t *usba_device)
{
	usba_ph_impl_t		*ph_impl;
	usb_pipe_handle_t	pipe_handle;
	int			i;
	int			rval = USB_SUCCESS;

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_persistent_pipe_open: usba_device=0x%p", (void *)usba_device);

	if (usba_device != NULL) {
		/* default pipe is the first one to be opened */
		mutex_enter(&usba_device->usb_mutex);
		for (i = 0; (rval == USB_SUCCESS) &&
		    (i < USBA_N_ENDPOINTS); i++) {

			ph_impl = &usba_device->usb_ph_list[i];
			mutex_enter(&ph_impl->usba_ph_mutex);
			if (ph_impl->usba_ph_flags & USBA_PH_DATA_PERSISTENT) {
				ph_impl->usba_ph_flags &=
				    ~USBA_PH_DATA_PERSISTENT;
				mutex_exit(&ph_impl->usba_ph_mutex);
				mutex_exit(&usba_device->usb_mutex);

				rval = usb_pipe_open(ph_impl->usba_ph_dip,
				    &ph_impl->usba_ph_ep,
				    &ph_impl->usba_ph_policy,
				    USB_FLAGS_SLEEP | USBA_FLAGS_PRIVILEGED,
				    &pipe_handle);

				USB_DPRINTF_L3(DPRINT_MASK_USBAI,
				    usbai_log_handle,
				    "usba_persistent_pipe_open: "
				    "ep_index=%d, rval=%d", i, rval);
				mutex_enter(&usba_device->usb_mutex);
				mutex_enter(&ph_impl->usba_ph_mutex);
			}
			mutex_exit(&ph_impl->usba_ph_mutex);
		}
		mutex_exit(&usba_device->usb_mutex);
	}

	return (rval);
}


/*
 * usba_persistent_pipe_close
 *	Close all pipes of this device and mark them persistent
 */
void
usba_persistent_pipe_close(usba_device_t *usba_device)
{
	usba_ph_impl_t		*ph_impl;
	usb_pipe_handle_t	pipe_handle;
	int			i;

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_persistent_pipe_close: usba_device=0x%p",
	    (void *)usba_device);

	if (usba_device != NULL) {
		/* default pipe is the last one to be closed */
		mutex_enter(&usba_device->usb_mutex);

		for (i = (USBA_N_ENDPOINTS - 1); i >= 0; i--) {
			ph_impl = &usba_device->usb_ph_list[i];
			if (ph_impl->usba_ph_data != NULL) {
				mutex_enter(&ph_impl->usba_ph_mutex);
				ph_impl->usba_ph_flags |=
				    USBA_PH_DATA_PERSISTENT;
				mutex_exit(&ph_impl->usba_ph_mutex);
				mutex_exit(&usba_device->usb_mutex);

				pipe_handle = (usb_pipe_handle_t)ph_impl;

				usb_pipe_close(ph_impl->usba_ph_dip,
				    pipe_handle,
				    USB_FLAGS_SLEEP | USBA_FLAGS_PRIVILEGED,
				    NULL, NULL);
				mutex_enter(&usba_device->usb_mutex);
				ASSERT(ph_impl->usba_ph_data == NULL);
			}
		}
		mutex_exit(&usba_device->usb_mutex);
	}
}

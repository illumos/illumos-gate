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

/*
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 */

/*
 * UGEN: USB Generic Driver support code
 *
 * This code provides entry points called by the ugen driver or other
 * drivers that want to export a ugen interface
 *
 * The "Universal Generic Driver"  (UGEN) for USB devices provides interfaces
 * to  talk to	USB  devices.  This is	very  useful for  Point of Sale sale
 * devices and other simple  devices like  USB	scanner, USB palm  pilot.
 * The UGEN provides a system call interface to USB  devices  enabling
 * a USB device vendor to  write an  application for his
 * device instead of  writing a driver. This facilitates the vendor to write
 * device management s/w quickly in userland.
 *
 * UGEN supports read/write/poll entry points. An application can be written
 * using  read/write/aioread/aiowrite/poll  system calls to communicate
 * with the device.
 *
 * XXX Theory of Operations
 */
#include <sys/usb/usba/usbai_version.h>
#include <sys/usb/usba.h>
#include <sys/sysmacros.h>
#include <sys/strsun.h>

#include "sys/usb/clients/ugen/usb_ugen.h"
#include "sys/usb/usba/usba_ugen.h"
#include "sys/usb/usba/usba_ugend.h"

/* Debugging information */
uint_t	ugen_errmask		= (uint_t)UGEN_PRINT_ALL;
uint_t	ugen_errlevel		= USB_LOG_L4;
uint_t	ugen_instance_debug	= (uint_t)-1;

/* default endpoint descriptor */
static usb_ep_descr_t  ugen_default_ep_descr =
	{7, 5, 0, USB_EP_ATTR_CONTROL, 8, 0};

/* tunables */
int	ugen_busy_loop		= 60;	/* secs */
int	ugen_ctrl_timeout	= 10;
int	ugen_bulk_timeout	= 10;
int	ugen_intr_timeout	= 10;
int	ugen_enable_pm		= 0;
int	ugen_isoc_buf_limit	= 1000;	/* ms */


/* local function prototypes */
static int	ugen_cleanup(ugen_state_t *);
static int	ugen_cpr_suspend(ugen_state_t *);
static void	ugen_cpr_resume(ugen_state_t *);

static void	ugen_restore_state(ugen_state_t *);
static int	ugen_check_open_flags(ugen_state_t *, dev_t, int);
static int	ugen_strategy(struct buf *);
static void	ugen_minphys(struct buf *);

static void	ugen_pm_init(ugen_state_t *);
static void	ugen_pm_destroy(ugen_state_t *);
static void	ugen_pm_busy_component(ugen_state_t *);
static void	ugen_pm_idle_component(ugen_state_t *);

/* endpoint xfer and status management */
static int	ugen_epxs_init(ugen_state_t *);
static void	ugen_epxs_destroy(ugen_state_t *);
static int	ugen_epxs_data_init(ugen_state_t *, usb_ep_data_t *,
					uchar_t, uchar_t, uchar_t, uchar_t);
static void	ugen_epxs_data_destroy(ugen_state_t *, ugen_ep_t *);
static int	ugen_epxs_minor_nodes_create(ugen_state_t *,
					usb_ep_descr_t *, uchar_t,
					uchar_t, uchar_t, uchar_t);
static int	ugen_epxs_check_open_nodes(ugen_state_t *);

static int	ugen_epx_open(ugen_state_t *, dev_t, int);
static void	ugen_epx_close(ugen_state_t *, dev_t, int);
static void	ugen_epx_shutdown(ugen_state_t *);

static int	ugen_epx_open_pipe(ugen_state_t *, ugen_ep_t *, int);
static void	ugen_epx_close_pipe(ugen_state_t *, ugen_ep_t *);

static int	ugen_epx_req(ugen_state_t *, struct buf *);
static int	ugen_epx_ctrl_req(ugen_state_t *, ugen_ep_t *,
					struct buf *, boolean_t *);
static void	ugen_epx_ctrl_req_cb(usb_pipe_handle_t, usb_ctrl_req_t *);
static int	ugen_epx_bulk_req(ugen_state_t *, ugen_ep_t *,
					struct buf *, boolean_t *);
static void	ugen_epx_bulk_req_cb(usb_pipe_handle_t, usb_bulk_req_t *);
static int	ugen_epx_intr_IN_req(ugen_state_t *, ugen_ep_t *,
					struct buf *, boolean_t *);
static int	ugen_epx_intr_IN_start_polling(ugen_state_t *, ugen_ep_t *);
static void	ugen_epx_intr_IN_stop_polling(ugen_state_t *, ugen_ep_t *);
static void	ugen_epx_intr_IN_req_cb(usb_pipe_handle_t, usb_intr_req_t *);
static int	ugen_epx_intr_OUT_req(ugen_state_t *, ugen_ep_t *,
					struct buf *, boolean_t *);
static void	ugen_epx_intr_OUT_req_cb(usb_pipe_handle_t, usb_intr_req_t *);
static int	ugen_epx_isoc_IN_req(ugen_state_t *, ugen_ep_t *,
					struct buf *, boolean_t *);
static int	ugen_epx_isoc_IN_start_polling(ugen_state_t *, ugen_ep_t *);
static void	ugen_epx_isoc_IN_stop_polling(ugen_state_t *, ugen_ep_t *);
static void	ugen_epx_isoc_IN_req_cb(usb_pipe_handle_t, usb_isoc_req_t *);
static int	ugen_epx_isoc_OUT_req(ugen_state_t *, ugen_ep_t *,
					struct buf *, boolean_t *);
static void	ugen_epx_isoc_OUT_req_cb(usb_pipe_handle_t, usb_isoc_req_t *);

static int	ugen_eps_open(ugen_state_t *, dev_t, int);
static void	ugen_eps_close(ugen_state_t *, dev_t, int);
static int	ugen_eps_req(ugen_state_t *, struct buf *);
static void	ugen_update_ep_descr(ugen_state_t *, ugen_ep_t *);

/* device status management */
static int	ugen_ds_init(ugen_state_t *);
static void	ugen_ds_destroy(ugen_state_t *);
static int	ugen_ds_open(ugen_state_t *, dev_t, int);
static void	ugen_ds_close(ugen_state_t *, dev_t, int);
static int	ugen_ds_req(ugen_state_t *, struct buf *);
static void	ugen_ds_change(ugen_state_t *);
static int	ugen_ds_minor_nodes_create(ugen_state_t *);
static void	ugen_ds_poll_wakeup(ugen_state_t *);

/* utility functions */
static int	ugen_minor_index_create(ugen_state_t *, ugen_minor_t);
static ugen_minor_t ugen_devt2minor(ugen_state_t *, dev_t);
static void	ugen_minor_node_table_create(ugen_state_t *);
static void	ugen_minor_node_table_destroy(ugen_state_t *);
static void	ugen_minor_node_table_shrink(ugen_state_t *);
static int	ugen_cr2lcstat(int);
static void	ugen_check_mask(uint_t, uint_t *, uint_t *);
static int	ugen_is_valid_minor_node(ugen_state_t *, dev_t);

static kmutex_t	ugen_devt_list_mutex;
static ugen_devt_list_entry_t ugen_devt_list;
static ugen_devt_cache_entry_t ugen_devt_cache[UGEN_DEVT_CACHE_SIZE];
static uint_t	ugen_devt_cache_index;
static void	ugen_store_devt(ugen_state_t *, minor_t);
static ugen_state_t *ugen_devt2state(dev_t);
static void	ugen_free_devt(ugen_state_t *);

/*
 * usb_ugen entry points
 *
 * usb_ugen_get_hdl:
 *	allocate and initialize handle
 */
usb_ugen_hdl_t
usb_ugen_get_hdl(dev_info_t *dip, usb_ugen_info_t *usb_ugen_info)
{
	usb_ugen_hdl_impl_t	*hdl = kmem_zalloc(sizeof (*hdl), KM_SLEEP);
	ugen_state_t		*ugenp = kmem_zalloc(sizeof (ugen_state_t),
	    KM_SLEEP);
	uint_t			len, shift, limit;
	int			rval;

	hdl->hdl_ugenp = ugenp;

	/* masks may not overlap */
	if (usb_ugen_info->usb_ugen_minor_node_ugen_bits_mask &
	    usb_ugen_info->usb_ugen_minor_node_instance_mask) {
		usb_ugen_release_hdl((usb_ugen_hdl_t)hdl);

		return (NULL);
	}

	if ((rval = usb_get_dev_data(dip, &ugenp->ug_dev_data,
	    usb_owns_device(dip) ? USB_PARSE_LVL_ALL : USB_PARSE_LVL_IF,
	    0)) != USB_SUCCESS) {
		USB_DPRINTF_L2(UGEN_PRINT_ATTA, ugenp->ug_log_hdl,
		    "usb_ugen_attach: usb_get_dev_data failed, rval=%d", rval);

		return (NULL);
	}

	/* Initialize state structure for this instance */
	mutex_init(&ugenp->ug_mutex, NULL, MUTEX_DRIVER,
	    ugenp->ug_dev_data->dev_iblock_cookie);

	mutex_enter(&ugenp->ug_mutex);
	ugenp->ug_dip		= dip;
	ugenp->ug_instance	= ddi_get_instance(dip);
	ugenp->ug_hdl		= hdl;

	/* Allocate a log handle for debug/error messages */
	if (strcmp(ddi_driver_name(dip), "ugen") != 0) {
		char	*name;

		len = strlen(ddi_driver_name(dip)) + sizeof ("_ugen") + 1;
		name = kmem_alloc(len, KM_SLEEP);
		(void) snprintf(name, len, "%s_ugen", ddi_driver_name(dip));

		ugenp->ug_log_hdl = usb_alloc_log_hdl(dip, name, &ugen_errlevel,
		    &ugen_errmask, &ugen_instance_debug, 0);
		hdl->hdl_log_name = name;
		hdl->hdl_log_name_length = len;
	} else {
		ugenp->ug_log_hdl = usb_alloc_log_hdl(dip, "ugen",
		    &ugen_errlevel,
		    &ugen_errmask, &ugen_instance_debug, 0);
	}

	hdl->hdl_dip = dip;
	hdl->hdl_flags = usb_ugen_info->usb_ugen_flags;

	ugen_check_mask(usb_ugen_info->usb_ugen_minor_node_ugen_bits_mask,
	    &shift, &limit);
	if (limit == 0) {
		usb_ugen_release_hdl((usb_ugen_hdl_t)hdl);
		mutex_exit(&ugenp->ug_mutex);

		return (NULL);
	}
	hdl->hdl_minor_node_ugen_bits_mask = usb_ugen_info->
	    usb_ugen_minor_node_ugen_bits_mask;
	hdl->hdl_minor_node_ugen_bits_shift = shift;
	hdl->hdl_minor_node_ugen_bits_limit = limit;

	ugen_check_mask(usb_ugen_info->usb_ugen_minor_node_instance_mask,
	    &shift, &limit);
	if (limit == 0) {
		usb_ugen_release_hdl((usb_ugen_hdl_t)hdl);
		mutex_exit(&ugenp->ug_mutex);

		return (NULL);
	}

	hdl->hdl_minor_node_instance_mask = usb_ugen_info->
	    usb_ugen_minor_node_instance_mask;
	hdl->hdl_minor_node_instance_shift = shift;
	hdl->hdl_minor_node_instance_limit = limit;

	USB_DPRINTF_L4(UGEN_PRINT_ATTA, ugenp->ug_log_hdl,
	    "usb_ugen_get_hdl: instance shift=%d instance limit=%d",
	    hdl->hdl_minor_node_instance_shift,
	    hdl->hdl_minor_node_instance_limit);

	USB_DPRINTF_L4(UGEN_PRINT_ATTA, ugenp->ug_log_hdl,
	    "usb_ugen_get_hdl: bits shift=%d bits limit=%d",
	    hdl->hdl_minor_node_ugen_bits_shift,
	    hdl->hdl_minor_node_ugen_bits_limit);

	mutex_exit(&ugenp->ug_mutex);

	return ((usb_ugen_hdl_t)hdl);
}


/*
 * usb_ugen_release_hdl:
 *	deallocate a handle
 */
void
usb_ugen_release_hdl(usb_ugen_hdl_t usb_ugen_hdl)
{
	usb_ugen_hdl_impl_t	*usb_ugen_hdl_impl =
	    (usb_ugen_hdl_impl_t *)usb_ugen_hdl;

	if (usb_ugen_hdl_impl) {
		ugen_state_t *ugenp = usb_ugen_hdl_impl->hdl_ugenp;

		if (ugenp) {
			mutex_destroy(&ugenp->ug_mutex);
			usb_free_log_hdl(ugenp->ug_log_hdl);
			usb_free_dev_data(usb_ugen_hdl_impl->hdl_dip,
			    ugenp->ug_dev_data);
			kmem_free(ugenp, sizeof (*ugenp));
		}
		if (usb_ugen_hdl_impl->hdl_log_name) {
			kmem_free(usb_ugen_hdl_impl->hdl_log_name,
			    usb_ugen_hdl_impl->hdl_log_name_length);
		}
		kmem_free(usb_ugen_hdl_impl, sizeof (*usb_ugen_hdl_impl));
	}
}


/*
 * usb_ugen_attach()
 */
int
usb_ugen_attach(usb_ugen_hdl_t usb_ugen_hdl, ddi_attach_cmd_t cmd)
{
	usb_ugen_hdl_impl_t	*usb_ugen_hdl_impl =
	    (usb_ugen_hdl_impl_t *)usb_ugen_hdl;
	ugen_state_t		*ugenp;
	dev_info_t		*dip;

	if (usb_ugen_hdl == NULL) {

		return (USB_FAILURE);
	}

	ugenp = usb_ugen_hdl_impl->hdl_ugenp;
	dip = usb_ugen_hdl_impl->hdl_dip;


	USB_DPRINTF_L4(UGEN_PRINT_ATTA, ugenp->ug_log_hdl,
	    "usb_ugen_attach: cmd=%d", cmd);

	switch (cmd) {
	case DDI_ATTACH:

		break;
	case DDI_RESUME:
		ugen_cpr_resume(ugenp);

		return (USB_SUCCESS);
	default:
		USB_DPRINTF_L2(UGEN_PRINT_ATTA, NULL,
		    "usb_ugen_attach: unknown command");

		return (USB_FAILURE);
	}

	mutex_enter(&ugenp->ug_mutex);
	ugenp->ug_ser_cookie =
	    usb_init_serialization(dip, USB_INIT_SER_CHECK_SAME_THREAD);
	ugenp->ug_cleanup_flags |= UGEN_INIT_LOCKS;

	/* Get maximum bulk transfer size supported by the HCD */
	if (usb_pipe_get_max_bulk_transfer_size(dip,
	    &ugenp->ug_max_bulk_xfer_sz) != USB_SUCCESS) {
		USB_DPRINTF_L2(UGEN_PRINT_ATTA, ugenp->ug_log_hdl,
		    "usb_ugen_attach: Getting max bulk xfer sz failed");
		mutex_exit(&ugenp->ug_mutex);

		goto fail;
	}

	/* table for mapping 48 bit minor codes to 9 bit index (for ugen) */
	ugen_minor_node_table_create(ugenp);

	/* prepare device status node handling */
	if (ugen_ds_init(ugenp) != USB_SUCCESS) {
		USB_DPRINTF_L2(UGEN_PRINT_ATTA, ugenp->ug_log_hdl,
		    "usb_ugen_attach: preparing dev status failed");
		mutex_exit(&ugenp->ug_mutex);

		goto fail;
	}

	/* prepare all available xfer and status endpoints nodes */
	if (ugen_epxs_init(ugenp) != USB_SUCCESS) {
		USB_DPRINTF_L2(UGEN_PRINT_ATTA, ugenp->ug_log_hdl,
		    "usb_ugen_attach: preparing endpoints failed");
		mutex_exit(&ugenp->ug_mutex);

		goto fail;
	}

	/* reduce table size if not all entries are used */
	ugen_minor_node_table_shrink(ugenp);

	/* we are ready to go */
	ugenp->ug_dev_state = USB_DEV_ONLINE;

	mutex_exit(&ugenp->ug_mutex);

	/* prepare PM */
	if (ugenp->ug_hdl->hdl_flags & USB_UGEN_ENABLE_PM) {
		ugen_pm_init(ugenp);
	}

	/*
	 * if ugen driver, kill all child nodes otherwise set cfg fails
	 * if requested
	 */
	if (usb_owns_device(dip) &&
	    (usb_ugen_hdl_impl->hdl_flags & USB_UGEN_REMOVE_CHILDREN)) {
		dev_info_t *cdip;

		/* save cfgidx so we can restore on detach */
		mutex_enter(&ugenp->ug_mutex);
		ugenp->ug_initial_cfgidx = usb_get_current_cfgidx(dip);
		mutex_exit(&ugenp->ug_mutex);

		for (cdip = ddi_get_child(dip); cdip; ) {
			dev_info_t *next = ddi_get_next_sibling(cdip);
			(void) ddi_remove_child(cdip, 0);
			cdip = next;
		}
	}

	return (DDI_SUCCESS);
fail:
	if (ugenp) {
		USB_DPRINTF_L2(UGEN_PRINT_ATTA, ugenp->ug_log_hdl,
		    "attach fail");
		(void) ugen_cleanup(ugenp);
	}

	return (DDI_FAILURE);
}


/*
 * usb_ugen_detach()
 */
int
usb_ugen_detach(usb_ugen_hdl_t usb_ugen_hdl, ddi_detach_cmd_t cmd)
{
	usb_ugen_hdl_impl_t	*usb_ugen_hdl_impl =
	    (usb_ugen_hdl_impl_t *)usb_ugen_hdl;
	int			rval = USB_FAILURE;

	if (usb_ugen_hdl) {
		ugen_state_t *ugenp = usb_ugen_hdl_impl->hdl_ugenp;

		USB_DPRINTF_L4(UGEN_PRINT_ATTA, ugenp->ug_log_hdl,
		    "usb_ugen_detach cmd %d", cmd);

		switch (cmd) {
		case DDI_DETACH:
			rval = ugen_cleanup(ugenp);

			break;
		case DDI_SUSPEND:
			rval = ugen_cpr_suspend(ugenp);

			break;
		default:

			break;
		}
	}

	return (rval);
}


/*
 * ugen_cleanup()
 */
static int
ugen_cleanup(ugen_state_t *ugenp)
{
	dev_info_t *dip = ugenp->ug_dip;

	USB_DPRINTF_L4(UGEN_PRINT_ATTA, ugenp->ug_log_hdl, "ugen_cleanup");

	if (ugenp->ug_cleanup_flags & UGEN_INIT_LOCKS) {

		/* shutdown all endpoints */
		ugen_epx_shutdown(ugenp);

		/*
		 * At this point, no new activity can be initiated.
		 * The driver has disabled hotplug callbacks.
		 * The Solaris framework has disabled
		 * new opens on a device being detached, and does not
		 * allow detaching an open device. PM should power
		 * down while we are detaching
		 *
		 * The following ensures that any other driver
		 * activity must have drained (paranoia)
		 */
		(void) usb_serialize_access(ugenp->ug_ser_cookie,
		    USB_WAIT, 0);
		usb_release_access(ugenp->ug_ser_cookie);

		mutex_enter(&ugenp->ug_mutex);
		ASSERT(ugenp->ug_open_count == 0);
		ASSERT(ugenp->ug_pending_cmds == 0);

		/* dismantle in reverse order */
		ugen_pm_destroy(ugenp);
		ugen_epxs_destroy(ugenp);
		ugen_ds_destroy(ugenp);
		ugen_minor_node_table_destroy(ugenp);


		/* restore to initial configuration */
		if (usb_owns_device(dip) &&
		    (ugenp->ug_dev_state != USB_DEV_DISCONNECTED)) {
			int idx = ugenp->ug_initial_cfgidx;
			mutex_exit(&ugenp->ug_mutex);
			(void) usb_set_cfg(dip, idx,
			    USB_FLAGS_SLEEP, NULL, NULL);
		} else {
			mutex_exit(&ugenp->ug_mutex);
		}

		usb_fini_serialization(ugenp->ug_ser_cookie);
	}

	ddi_prop_remove_all(dip);
	ddi_remove_minor_node(dip, NULL);

	ugen_free_devt(ugenp);

	return (USB_SUCCESS);
}


/*
 * ugen_cpr_suspend
 */
static int
ugen_cpr_suspend(ugen_state_t *ugenp)
{
	int		rval = USB_FAILURE;
	int		i;
	int		prev_state;

	USB_DPRINTF_L4(UGEN_PRINT_CPR, ugenp->ug_log_hdl,
	    "ugen_cpr_suspend:");

	mutex_enter(&ugenp->ug_mutex);
	switch (ugenp->ug_dev_state) {
	case USB_DEV_ONLINE:
	case USB_DEV_DISCONNECTED:
		USB_DPRINTF_L4(UGEN_PRINT_CPR, ugenp->ug_log_hdl,
		    "ugen_cpr_suspend:");

		prev_state = ugenp->ug_dev_state;
		ugenp->ug_dev_state = USB_DEV_SUSPENDED;

		if (ugenp->ug_open_count) {
			/* drain outstanding cmds */
			for (i = 0; i < ugen_busy_loop; i++) {
				if (ugenp->ug_pending_cmds == 0) {

					break;
				}
				mutex_exit(&ugenp->ug_mutex);
				delay(drv_usectohz(100000));
				mutex_enter(&ugenp->ug_mutex);
			}

			/* if still outstanding cmds, fail suspend */
			if (ugenp->ug_pending_cmds) {
				ugenp->ug_dev_state = prev_state;

				USB_DPRINTF_L2(UGEN_PRINT_CPR,
				    ugenp->ug_log_hdl,
				    "ugen_cpr_suspend: pending %d",
				    ugenp->ug_pending_cmds);

				rval =	USB_FAILURE;
				break;
			}

			mutex_exit(&ugenp->ug_mutex);
			(void) usb_serialize_access(ugenp->ug_ser_cookie,
			    USB_WAIT, 0);
			/* close all pipes */
			ugen_epx_shutdown(ugenp);

			usb_release_access(ugenp->ug_ser_cookie);

			mutex_enter(&ugenp->ug_mutex);
		}

		/* wakeup devstat reads and polls */
		ugen_ds_change(ugenp);
		ugen_ds_poll_wakeup(ugenp);

		rval = USB_SUCCESS;
		break;
	case USB_DEV_SUSPENDED:
	case USB_UGEN_DEV_UNAVAILABLE_RESUME:
	case USB_UGEN_DEV_UNAVAILABLE_RECONNECT:
	default:

		break;
	}
	mutex_exit(&ugenp->ug_mutex);

	return (rval);
}

/*
 * ugen_cpr_resume
 */
static void
ugen_cpr_resume(ugen_state_t *ugenp)
{
	USB_DPRINTF_L4(UGEN_PRINT_CPR, ugenp->ug_log_hdl,
	    "ugen_cpr_resume:");

	ugen_restore_state(ugenp);
}

/*
 * usb_ugen_disconnect_ev_cb:
 */
int
usb_ugen_disconnect_ev_cb(usb_ugen_hdl_t usb_ugen_hdl)
{
	usb_ugen_hdl_impl_t	*usb_ugen_hdl_impl =
	    (usb_ugen_hdl_impl_t *)usb_ugen_hdl;
	ugen_state_t		*ugenp;

	if (usb_ugen_hdl_impl == NULL) {

		return (USB_FAILURE);
	}

	ugenp = usb_ugen_hdl_impl->hdl_ugenp;

	USB_DPRINTF_L4(UGEN_PRINT_HOTPLUG, ugenp->ug_log_hdl,
	    "usb_ugen_disconnect_ev_cb:");

	/* get exclusive access */
	(void) usb_serialize_access(ugenp->ug_ser_cookie, USB_WAIT, 0);

	mutex_enter(&ugenp->ug_mutex);
	ugenp->ug_dev_state = USB_DEV_DISCONNECTED;
	if (ugenp->ug_open_count) {
		mutex_exit(&ugenp->ug_mutex);

		/* close all pipes */
		(void) ugen_epx_shutdown(ugenp);

		mutex_enter(&ugenp->ug_mutex);
	}


	/* wakeup devstat reads and polls */
	ugen_ds_change(ugenp);
	ugen_ds_poll_wakeup(ugenp);

	mutex_exit(&ugenp->ug_mutex);
	usb_release_access(ugenp->ug_ser_cookie);

	return (USB_SUCCESS);
}


/*
 * usb_ugen_reconnect_ev_cb:
 */
int
usb_ugen_reconnect_ev_cb(usb_ugen_hdl_t usb_ugen_hdl)
{
	usb_ugen_hdl_impl_t	*usb_ugen_hdl_impl =
	    (usb_ugen_hdl_impl_t *)usb_ugen_hdl;
	ugen_state_t		*ugenp = usb_ugen_hdl_impl->hdl_ugenp;

	USB_DPRINTF_L4(UGEN_PRINT_HOTPLUG, ugenp->ug_log_hdl,
	    "usb_ugen_reconnect_ev_cb:");

	ugen_restore_state(ugenp);

	return (USB_SUCCESS);
}


/*
 * ugen_restore_state:
 *	Check for same device; if a different device is attached, set
 *	the device status to disconnected.
 *	If we were open, then set to UNAVAILABLE until all endpoints have
 *	be closed.
 */
static void
ugen_restore_state(ugen_state_t *ugenp)
{
	dev_info_t *dip = ugenp->ug_dip;

	USB_DPRINTF_L4(UGEN_PRINT_HOTPLUG, ugenp->ug_log_hdl,
	    "ugen_restore_state");

	/* first raise power */
	if (ugenp->ug_hdl->hdl_flags & USB_UGEN_ENABLE_PM) {
		ugen_pm_busy_component(ugenp);
		(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);
	}

	/* Check if we are talking to the same device */
	if (usb_check_same_device(dip, ugenp->ug_log_hdl,
	    USB_LOG_L0, UGEN_PRINT_HOTPLUG, USB_CHK_ALL, NULL) ==
	    USB_FAILURE) {
		mutex_enter(&ugenp->ug_mutex);
		ugenp->ug_dev_state = USB_DEV_DISCONNECTED;

		/* wakeup devstat reads and polls */
		ugen_ds_change(ugenp);
		ugen_ds_poll_wakeup(ugenp);

		mutex_exit(&ugenp->ug_mutex);

		if (ugenp->ug_hdl->hdl_flags & USB_UGEN_ENABLE_PM) {
			ugen_pm_idle_component(ugenp);
		}

		return;
	}

	/*
	 * get exclusive access, we don't want to change state in the
	 * middle of some other actions
	 */
	(void) usb_serialize_access(ugenp->ug_ser_cookie, USB_WAIT, 0);

	mutex_enter(&ugenp->ug_mutex);
	switch (ugenp->ug_dev_state) {
	case USB_DEV_DISCONNECTED:
		ugenp->ug_dev_state = (ugenp->ug_open_count == 0) ?
		    USB_DEV_ONLINE : USB_UGEN_DEV_UNAVAILABLE_RECONNECT;

		break;
	case USB_DEV_SUSPENDED:
		ugenp->ug_dev_state = (ugenp->ug_open_count == 0) ?
		    USB_DEV_ONLINE : USB_UGEN_DEV_UNAVAILABLE_RESUME;

		break;
	}
	USB_DPRINTF_L4(UGEN_PRINT_HOTPLUG, ugenp->ug_log_hdl,
	    "ugen_restore_state: state=%d, opencount=%d",
	    ugenp->ug_dev_state, ugenp->ug_open_count);

	/* wakeup devstat reads and polls */
	ugen_ds_change(ugenp);
	ugen_ds_poll_wakeup(ugenp);

	mutex_exit(&ugenp->ug_mutex);
	usb_release_access(ugenp->ug_ser_cookie);

	if (ugenp->ug_hdl->hdl_flags & USB_UGEN_ENABLE_PM) {
		ugen_pm_idle_component(ugenp);
	}
}


/*
 * usb_ugen_open:
 */
/* ARGSUSED */
int
usb_ugen_open(usb_ugen_hdl_t usb_ugen_hdl, dev_t *devp, int flag, int sflag,
    cred_t *cr)
{
	usb_ugen_hdl_impl_t	*usb_ugen_hdl_impl =
	    (usb_ugen_hdl_impl_t *)usb_ugen_hdl;
	ugen_state_t		*ugenp;
	int			rval;
	int			minor_node_type;

	if (usb_ugen_hdl == NULL) {

		return (EINVAL);
	}

	ugenp = usb_ugen_hdl_impl->hdl_ugenp;

	if (ugen_is_valid_minor_node(ugenp, *devp) != USB_SUCCESS) {

		return (EINVAL);
	}

	minor_node_type = UGEN_MINOR_TYPE(ugenp, *devp);

	USB_DPRINTF_L4(UGEN_PRINT_CBOPS, ugenp->ug_log_hdl,
	    "usb_ugen_open: minor=%u", getminor(*devp));
	USB_DPRINTF_L3(UGEN_PRINT_CBOPS, ugenp->ug_log_hdl,
	    "cfgval=%" PRIu64 " cfgidx=%" PRIu64 " if=%" PRIu64
	    " alt=%" PRIu64 " epidx=%" PRIu64 " type=0x%" PRIx64,
	    UGEN_MINOR_CFGVAL(ugenp, *devp), UGEN_MINOR_CFGIDX(ugenp, *devp),
	    UGEN_MINOR_IF(ugenp, *devp), UGEN_MINOR_ALT(ugenp, *devp),
	    UGEN_MINOR_EPIDX(ugenp, *devp), UGEN_MINOR_TYPE(ugenp, *devp));

	/* first check for legal open flags */
	if ((rval = ugen_check_open_flags(ugenp, *devp, flag)) != 0) {
		USB_DPRINTF_L2(UGEN_PRINT_CBOPS, ugenp->ug_log_hdl,
		    "usb_ugen_open: check failed, rval=%d", rval);

		return (rval);
	}

	/* exclude other threads including other opens */
	if (usb_serialize_access(ugenp->ug_ser_cookie,
	    USB_WAIT_SIG, 0) <= 0) {
		USB_DPRINTF_L2(UGEN_PRINT_CBOPS, ugenp->ug_log_hdl,
		    "usb_ugen_open: interrupted");

		return (EINTR);
	}

	mutex_enter(&ugenp->ug_mutex);

	/* always allow open of dev stat node */
	if (minor_node_type != UGEN_MINOR_DEV_STAT_NODE) {

		/* if we are not online or powered down, fail open */
		switch (ugenp->ug_dev_state) {
		case USB_DEV_ONLINE:

			break;
		case USB_DEV_DISCONNECTED:
			rval = ENODEV;
			mutex_exit(&ugenp->ug_mutex);

			goto done;
		case USB_DEV_SUSPENDED:
		case USB_UGEN_DEV_UNAVAILABLE_RESUME:
		case USB_UGEN_DEV_UNAVAILABLE_RECONNECT:
		default:
			rval = EBADF;
			mutex_exit(&ugenp->ug_mutex);

			goto done;
		}
	}
	mutex_exit(&ugenp->ug_mutex);

	/* open node depending on type */
	switch (minor_node_type) {
	case UGEN_MINOR_EP_XFER_NODE:
		if (ugenp->ug_hdl->hdl_flags & USB_UGEN_ENABLE_PM) {
			ugen_pm_busy_component(ugenp);
			(void) pm_raise_power(ugenp->ug_dip, 0,
			    USB_DEV_OS_FULL_PWR);
		}

		rval = ugen_epx_open(ugenp, *devp, flag);
		if (rval == 0) {
			mutex_enter(&ugenp->ug_mutex);
			ugenp->ug_open_count++;
			mutex_exit(&ugenp->ug_mutex);
		} else {
			if (ugenp->ug_hdl->hdl_flags &
			    USB_UGEN_ENABLE_PM) {
				ugen_pm_idle_component(ugenp);
			}
		}

		break;
	case UGEN_MINOR_EP_STAT_NODE:
		rval = ugen_eps_open(ugenp, *devp, flag);
		if (rval == 0) {
			mutex_enter(&ugenp->ug_mutex);
			ugenp->ug_open_count++;
			mutex_exit(&ugenp->ug_mutex);
		}

		break;
	case UGEN_MINOR_DEV_STAT_NODE:
		rval = ugen_ds_open(ugenp, *devp, flag);

		break;
	default:
		rval = EINVAL;

		break;
	}
done:
	mutex_enter(&ugenp->ug_mutex);

	USB_DPRINTF_L4(UGEN_PRINT_CBOPS, ugenp->ug_log_hdl,
	    "usb_ugen_open: minor=0x%x rval=%d state=%d cnt=%d",
	    getminor(*devp), rval, ugenp->ug_dev_state,
	    ugenp->ug_open_count);

	mutex_exit(&ugenp->ug_mutex);

	usb_release_access(ugenp->ug_ser_cookie);

	return (rval);
}


/*
 * usb_ugen_close()
 */
/* ARGSUSED */
int
usb_ugen_close(usb_ugen_hdl_t usb_ugen_hdl, dev_t dev, int flag, int otype,
    cred_t *cr)
{
	usb_ugen_hdl_impl_t	*usb_ugen_hdl_impl =
	    (usb_ugen_hdl_impl_t *)usb_ugen_hdl;
	ugen_state_t		*ugenp;
	int			minor_node_type;

	if (usb_ugen_hdl == NULL) {

		return (EINVAL);
	}

	ugenp = usb_ugen_hdl_impl->hdl_ugenp;
	if (ugen_is_valid_minor_node(ugenp, dev) != USB_SUCCESS) {

		return (EINVAL);
	}

	minor_node_type = UGEN_MINOR_TYPE(ugenp, dev);

	USB_DPRINTF_L4(UGEN_PRINT_CBOPS, ugenp->ug_log_hdl,
	    "usb_ugen_close: minor=0x%x", getminor(dev));

	/* exclude other threads, including other opens */
	if (usb_serialize_access(ugenp->ug_ser_cookie,
	    USB_WAIT_SIG, 0) <= 0) {
		USB_DPRINTF_L4(UGEN_PRINT_CBOPS, ugenp->ug_log_hdl,
		    "usb_ugen_close: interrupted");

		return (EINTR);
	}

	/* close node depending on type */
	switch (minor_node_type) {
	case UGEN_MINOR_EP_XFER_NODE:
		ugen_epx_close(ugenp, dev, flag);
		if (ugenp->ug_hdl->hdl_flags & USB_UGEN_ENABLE_PM) {
			ugen_pm_idle_component(ugenp);
		}

		break;
	case UGEN_MINOR_EP_STAT_NODE:
		ugen_eps_close(ugenp, dev, flag);

		break;
	case UGEN_MINOR_DEV_STAT_NODE:
		ugen_ds_close(ugenp, dev, flag);

		break;
	default:
		usb_release_access(ugenp->ug_ser_cookie);

		return (EINVAL);
	}

	mutex_enter(&ugenp->ug_mutex);
	if (minor_node_type != UGEN_MINOR_DEV_STAT_NODE) {
		ASSERT(ugenp->ug_open_count > 0);
		if ((--ugenp->ug_open_count == 0) &&
		    ((ugenp->ug_dev_state == USB_UGEN_DEV_UNAVAILABLE_RESUME) ||
		    (ugenp->ug_dev_state ==
		    USB_UGEN_DEV_UNAVAILABLE_RECONNECT))) {
			ugenp->ug_dev_state = USB_DEV_ONLINE;

			/* wakeup devstat reads and polls */
			ugen_ds_change(ugenp);
			ugen_ds_poll_wakeup(ugenp);
		}
	}

	USB_DPRINTF_L4(UGEN_PRINT_CBOPS, ugenp->ug_log_hdl,
	    "usb_ugen_close: minor=0x%x state=%d cnt=%d",
	    getminor(dev), ugenp->ug_dev_state, ugenp->ug_open_count);

	if (ugenp->ug_open_count == 0) {
		ASSERT(ugen_epxs_check_open_nodes(ugenp) == USB_FAILURE);
	}

	mutex_exit(&ugenp->ug_mutex);

	usb_release_access(ugenp->ug_ser_cookie);

	return (0);
}


/*
 * usb_ugen_read/write()
 */
/*ARGSUSED*/
int
usb_ugen_read(usb_ugen_hdl_t usb_ugen_hdl, dev_t dev, struct uio *uiop,
    cred_t *credp)
{
	ugen_state_t		*ugenp;
	usb_ugen_hdl_impl_t	*usb_ugen_hdl_impl =
	    (usb_ugen_hdl_impl_t *)usb_ugen_hdl;

	if (usb_ugen_hdl == NULL) {

		return (EINVAL);
	}
	ugenp = usb_ugen_hdl_impl->hdl_ugenp;

	if (ugen_is_valid_minor_node(ugenp, dev) != USB_SUCCESS) {

		return (EINVAL);
	}

	return (physio(ugen_strategy,
	    (struct buf *)0, dev, B_READ, ugen_minphys, uiop));
}


/*ARGSUSED*/
int
usb_ugen_write(usb_ugen_hdl_t usb_ugen_hdl, dev_t dev, struct uio *uiop,
    cred_t *credp)
{
	ugen_state_t		*ugenp;
	usb_ugen_hdl_impl_t	*usb_ugen_hdl_impl =
	    (usb_ugen_hdl_impl_t *)usb_ugen_hdl;

	if (usb_ugen_hdl == NULL) {

		return (EINVAL);
	}
	ugenp = usb_ugen_hdl_impl->hdl_ugenp;

	if (ugen_is_valid_minor_node(ugenp, dev) != USB_SUCCESS) {

		return (EINVAL);
	}

	return (physio(ugen_strategy,
	    (struct buf *)0, dev, B_WRITE, ugen_minphys, uiop));
}


/*
 * usb_ugen_poll
 */
int
usb_ugen_poll(usb_ugen_hdl_t usb_ugen_hdl, dev_t dev, short events,
    int anyyet,  short *reventsp, struct pollhead **phpp)
{
	usb_ugen_hdl_impl_t	*usb_ugen_hdl_impl =
	    (usb_ugen_hdl_impl_t *)usb_ugen_hdl;
	ugen_state_t		*ugenp;
	int			minor_node_type;
	uint_t			ep_index;
	ugen_ep_t		*epp;

	if (usb_ugen_hdl == NULL) {

		return (EINVAL);
	}

	ugenp = usb_ugen_hdl_impl->hdl_ugenp;
	if (ugen_is_valid_minor_node(ugenp, dev) != USB_SUCCESS) {

		return (EINVAL);
	}

	minor_node_type = UGEN_MINOR_TYPE(ugenp, dev);
	ep_index	= UGEN_MINOR_EPIDX(ugenp, dev);
	epp		= &ugenp->ug_ep[ep_index];

	mutex_enter(&ugenp->ug_mutex);

	USB_DPRINTF_L4(UGEN_PRINT_POLL, ugenp->ug_log_hdl,
	    "usb_ugen_poll: "
	    "dev=0x%lx events=0x%x anyyet=0x%x rev=0x%p type=%d "
	    "devstat=0x%x devstate=0x%x",
	    dev, events, anyyet, (void *)reventsp, minor_node_type,
	    ugenp->ug_ds.dev_stat, ugenp->ug_ds.dev_state);

	*reventsp = 0;

	if (ugenp->ug_dev_state == USB_DEV_ONLINE) {
		switch (minor_node_type) {
		case UGEN_MINOR_EP_XFER_NODE:
			/* if interrupt IN ep and there is data, set POLLIN */
			if ((UGEN_XFER_TYPE(epp) == USB_EP_ATTR_INTR) &&
			    (UGEN_XFER_DIR(epp) & USB_EP_DIR_IN)) {

				/*
				 * if we are not polling, force another
				 * read to kick off polling
				 */
				mutex_enter(&epp->ep_mutex);
				if ((epp->ep_data) ||
				    ((epp->ep_state &
				    UGEN_EP_STATE_INTR_IN_POLLING_ON) == 0)) {
					*reventsp |= POLLIN;
				}

				if ((!*reventsp && !anyyet) ||
				    (events & POLLET)) {
					*phpp = &epp->ep_pollhead;
					epp->ep_state |=
					    UGEN_EP_STATE_INTR_IN_POLL_PENDING;
				}
				mutex_exit(&epp->ep_mutex);

			} else if ((UGEN_XFER_TYPE(epp) == USB_EP_ATTR_ISOCH) &&
			    (UGEN_XFER_DIR(epp) & USB_EP_DIR_IN)) {

				/*
				 * if we are not polling, force another
				 * read to kick off polling
				 */
				mutex_enter(&epp->ep_mutex);
				if ((epp->ep_data) ||
				    ((epp->ep_state &
				    UGEN_EP_STATE_ISOC_IN_POLLING_ON) == 0)) {
					*reventsp |= POLLIN;
				}

				if ((!*reventsp && !anyyet) ||
				    (events & POLLET)) {
					*phpp = &epp->ep_pollhead;
					epp->ep_state |=
					    UGEN_EP_STATE_ISOC_IN_POLL_PENDING;
				}
				mutex_exit(&epp->ep_mutex);

			} else {
				/* no poll on other ep nodes */
				*reventsp |= POLLERR;
			}

			break;
		case UGEN_MINOR_DEV_STAT_NODE:
			if (ugenp->ug_ds.dev_stat & UGEN_DEV_STATUS_CHANGED)
				*reventsp |= POLLIN;

			if ((!*reventsp && !anyyet) || (events & POLLET)) {
				*phpp = &ugenp->ug_ds.dev_pollhead;
				ugenp->ug_ds.dev_stat |=
				    UGEN_DEV_STATUS_POLL_PENDING;
			}

			break;
		case UGEN_MINOR_EP_STAT_NODE:
		default:
			*reventsp |= POLLERR;

			break;
		}
	} else {
		if (ugenp->ug_ds.dev_stat & UGEN_DEV_STATUS_CHANGED)
			*reventsp |= POLLHUP|POLLIN;

		if ((!*reventsp && !anyyet) || (events & POLLET)) {
			*phpp = &ugenp->ug_ds.dev_pollhead;
			ugenp->ug_ds.dev_stat |=
			    UGEN_DEV_STATUS_POLL_PENDING;
		}
	}

	mutex_exit(&ugenp->ug_mutex);

	USB_DPRINTF_L4(UGEN_PRINT_POLL, ugenp->ug_log_hdl,
	    "usb_ugen_poll end: reventsp=0x%x", *reventsp);

	return (0);
}


/*
 * ugen_strategy
 */
static int
ugen_strategy(struct buf *bp)
{
	dev_t		dev = bp->b_edev;
	int		rval = 0;
	ugen_state_t	*ugenp = ugen_devt2state(dev);
	int		minor_node_type = UGEN_MINOR_TYPE(ugenp, dev);

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_strategy: bp=0x%p minor=0x%x", (void *)bp, getminor(dev));

	if (ugen_is_valid_minor_node(ugenp, dev) != USB_SUCCESS) {

		return (EINVAL);
	}

	mutex_enter(&ugenp->ug_mutex);
	ugenp->ug_pending_cmds++;
	mutex_exit(&ugenp->ug_mutex);

	bp_mapin(bp);

	switch (minor_node_type) {
	case UGEN_MINOR_EP_XFER_NODE:
		rval = ugen_epx_req(ugenp, bp);

		break;
	case UGEN_MINOR_EP_STAT_NODE:
		rval = ugen_eps_req(ugenp, bp);

		break;
	case UGEN_MINOR_DEV_STAT_NODE:
		rval = ugen_ds_req(ugenp, bp);

		break;
	default:
		rval = EINVAL;

		break;
	}

	mutex_enter(&ugenp->ug_mutex);
	ugenp->ug_pending_cmds--;

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_strategy: "
	    "bp=0x%p cnt=%lu resid=%lu err=%d minor=0x%x rval=%d #cmds=%d",
	    (void *)bp, bp->b_bcount, bp->b_resid, geterror(bp),
	    getminor(dev), rval, ugenp->ug_pending_cmds);

	mutex_exit(&ugenp->ug_mutex);

	if (rval) {
		if (geterror(bp) == 0) {
			bioerror(bp, rval);
		}
	}

	biodone(bp);

	return (0);
}


/*
 * ugen_minphys:
 */
static void
ugen_minphys(struct buf *bp)
{
	dev_t		dev = bp->b_edev;
	ugen_state_t	*ugenp = ugen_devt2state(dev);
	int		minor_node_type = UGEN_MINOR_TYPE(ugenp, dev);
	uint_t		ep_index = UGEN_MINOR_EPIDX(ugenp, dev);
	ugen_ep_t	*epp = &ugenp->ug_ep[ep_index];

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_phys: bp=0x%p dev=0x%lx index=%d type=0x%x",
	    (void *)bp, dev, ep_index, minor_node_type);

	switch (minor_node_type) {
	case UGEN_MINOR_EP_XFER_NODE:
		switch (UGEN_XFER_TYPE(epp)) {
		case USB_EP_ATTR_BULK:
			if (bp->b_bcount > ugenp->ug_max_bulk_xfer_sz) {
				bp->b_bcount = ugenp->ug_max_bulk_xfer_sz;
			}

			break;
		case USB_EP_ATTR_INTR:
		case USB_EP_ATTR_CONTROL:
		case USB_EP_ATTR_ISOCH:
		default:

			break;
		}
		break;
	case UGEN_MINOR_EP_STAT_NODE:
	case UGEN_MINOR_DEV_STAT_NODE:
	default:

		break;
	}
}

/*
 * Get bmAttributes and bAddress of the endpoint which is going to
 * be opened
 */
static int
ugen_get_ep_descr(ugen_state_t *ugenp, dev_t dev, uint8_t *bmAttr,
    uint8_t *bAddr)
{
	uint_t	alt = UGEN_MINOR_ALT(ugenp, dev);
	uint_t	ifc = UGEN_MINOR_IF(ugenp, dev);
	uint_t	cfgidx = UGEN_MINOR_CFGIDX(ugenp, dev);
	usb_cfg_data_t	*dev_cfg;
	usb_if_data_t	*if_data;
	usb_alt_if_data_t *alt_if_data;
	usb_ep_data_t	*ep_data;
	int ep;
	int epidx = UGEN_MINOR_EPIDX(ugenp, dev);

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "cfg=%d, if=%d, alt=%d, ep=0x%x", cfgidx, ifc,
	    alt, epidx);

	dev_cfg = &ugenp->ug_dev_data->dev_cfg[cfgidx];
	if_data = &dev_cfg->cfg_if[ifc];
	alt_if_data = &if_data->if_alt[alt];
	for (ep = 0; ep < alt_if_data->altif_n_ep; ep++) {
		ep_data = &alt_if_data->altif_ep[ep];

		if (usb_get_ep_index(ep_data->ep_descr.
		    bEndpointAddress) == epidx) {

			*bmAttr = ep_data->ep_descr.bmAttributes;
			*bAddr = ep_data->ep_descr.bEndpointAddress;

			return (USB_SUCCESS);
		}
	}

	return (USB_FAILURE);
}

/*
 * check whether flag is appropriate for node type
 */
static int
ugen_check_open_flags(ugen_state_t *ugenp, dev_t dev, int flag)
{
	ugen_ep_t *epp;
	int	minor_node_type = UGEN_MINOR_TYPE(ugenp, dev);
	int	rval = 0;
	uint8_t bmAttribute;
	uint8_t bAddress;

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_check_open_flags: "
	    "dev=0x%lx, type=0x%x flag=0x%x idx=%" PRIu64,
	    dev, minor_node_type, flag, UGEN_MINOR_EPIDX(ugenp, dev));

	switch (minor_node_type) {
	case UGEN_MINOR_EP_XFER_NODE:
		epp = &ugenp->ug_ep[UGEN_MINOR_EPIDX(ugenp, dev)];

		/*
		 * Endpoints in two altsetting happen to have the same
		 * bEndpointAddress, but they are different type, e.g,
		 * one is BULK and the other is ISOC. They use the same
		 * slot of ug_ep array. It's OK after switch_alt, because
		 * after alt switch, ep info is updated to the new endpoint.
		 * But it's not right here to use the other EP's info for
		 * checking.
		 */
		if (UGEN_MINOR_EPIDX(ugenp, dev) != 0) {
			if ((rval = ugen_get_ep_descr(ugenp, dev, &bmAttribute,
			    &bAddress)) != USB_SUCCESS) {
				USB_DPRINTF_L2(UGEN_PRINT_XFER,
				    ugenp->ug_log_hdl, "ugen_get_descr: fail");

				return (ENODEV);
			}
		} else {
			bmAttribute = ugen_default_ep_descr.bmAttributes;
			bAddress = ugen_default_ep_descr.bEndpointAddress;
		}

		USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
		    "ugen_check_open_flags: epp = %p,"
		    "epp type = %d, bmAttr =0x%x, bAddr = 0x%02x", (void *)epp,
		    UGEN_XFER_TYPE(epp), bmAttribute, bAddress);

		switch (bmAttribute & USB_EP_ATTR_MASK) {
		case USB_EP_ATTR_CONTROL:
			/* read and write must be set, ndelay not allowed */
			if (((flag & (FREAD | FWRITE)) != (FREAD | FWRITE)) ||
			    (flag & (FNDELAY | FNONBLOCK))) {
				rval = EACCES;
			}

			break;
		case USB_EP_ATTR_ISOCH:
			/* read and write must be set */
			if ((flag & (FREAD | FWRITE)) != (FREAD | FWRITE)) {
				rval = EACCES;
			}

			break;
		case USB_EP_ATTR_BULK:
			/* ndelay not allowed */
			if (flag & (FNDELAY | FNONBLOCK)) {
				rval = EACCES;

				break;
			}
			/*FALLTHRU*/
		case USB_EP_ATTR_INTR:
			/* check flag versus direction */
			if ((flag & FWRITE) && (bAddress & USB_EP_DIR_IN)) {
				rval = EACCES;
			}
			if ((flag & FREAD) &&
			    ((bAddress & USB_EP_DIR_IN) == 0)) {
				rval = EACCES;
			}

			break;
		default:
			rval = EINVAL;

			break;
		}
		break;
	case UGEN_MINOR_DEV_STAT_NODE:
		/* only reads are supported */
		if (flag & FWRITE) {
			rval = EACCES;
		}

		break;
	case UGEN_MINOR_EP_STAT_NODE:

		break;
	default:
		rval = EINVAL;

		break;
	}

	return (rval);
}


/*
 * endpoint management
 *
 * create/initialize all endpoint xfer/stat structures
 */
static int
ugen_epxs_init(ugen_state_t *ugenp)
{
	usb_cfg_data_t	*dev_cfg = ugenp->ug_dev_data->dev_cfg;
	uchar_t		cfgidx, cfgval, iface, alt, ep;
	usb_if_data_t	*if_data;
	usb_alt_if_data_t *alt_if_data;
	usb_ep_data_t	*ep_data;

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epxs_init:");

	/* initialize each ep's mutex first */
	for (ep = 0; ep < UGEN_N_ENDPOINTS; ep++) {
		mutex_init(&ugenp->ug_ep[ep].ep_mutex, NULL, MUTEX_DRIVER,
		    ugenp->ug_dev_data->dev_iblock_cookie);
	}

	/* init default ep as it does not have a descriptor */
	if (ugen_epxs_data_init(ugenp, NULL, 0, 0,
	    ugenp->ug_dev_data->dev_curr_if, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(UGEN_PRINT_ATTA, ugenp->ug_log_hdl,
		    "creating default endpoint failed");

		return (USB_FAILURE);
	}

	/*
	 * walk all endpoints of all alternates of all interfaces of
	 * all cfs
	 */
	for (cfgidx = 0; cfgidx < ugenp->ug_dev_data->dev_n_cfg; cfgidx++) {
		dev_cfg = &ugenp->ug_dev_data->dev_cfg[cfgidx];
		cfgval = dev_cfg->cfg_descr.bConfigurationValue;
		for (iface = 0; iface < dev_cfg->cfg_n_if; iface++) {
			if_data = &dev_cfg->cfg_if[iface];
			for (alt = 0; alt < if_data->if_n_alt; alt++) {
				alt_if_data = &if_data->if_alt[alt];
				for (ep = 0; ep < alt_if_data->altif_n_ep;
				    ep++) {
					ep_data = &alt_if_data->altif_ep[ep];
					if (ugen_epxs_data_init(ugenp, ep_data,
					    cfgval, cfgidx, iface, alt) !=
					    USB_SUCCESS) {

						return (USB_FAILURE);
					}
				}
			}
		}
	}

	return (USB_SUCCESS);
}


/*
 * initialize one endpoint structure
 */
static int
ugen_epxs_data_init(ugen_state_t *ugenp, usb_ep_data_t *ep_data,
	uchar_t cfgval, uchar_t cfgidx, uchar_t iface, uchar_t alt)
{
	int			ep_index;
	ugen_ep_t		*epp;
	usb_ep_descr_t		*ep_descr;

	/* is this the default endpoint */
	ep_index = (ep_data == NULL) ? 0 :
	    usb_get_ep_index(ep_data->ep_descr.bEndpointAddress);
	epp = &ugenp->ug_ep[ep_index];

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epxs_data_init: "
	    "cfgval=%d cfgidx=%d iface=%d alt=%d ep_index=%d",
	    cfgval, cfgidx, iface, alt, ep_index);

	ep_descr = (ep_data == NULL) ? &ugen_default_ep_descr :
	    &ep_data->ep_descr;

	mutex_init(&epp->ep_mutex, NULL, MUTEX_DRIVER,
	    ugenp->ug_dev_data->dev_iblock_cookie);

	mutex_enter(&epp->ep_mutex);

	/* initialize if not yet init'ed */
	if (epp->ep_state == UGEN_EP_STATE_NONE) {
		epp->ep_descr		= *ep_descr;
		epp->ep_cfgidx		= cfgidx;
		epp->ep_if		= iface;
		epp->ep_alt		= alt;
		epp->ep_state		= UGEN_EP_STATE_ACTIVE;
		epp->ep_lcmd_status	= USB_LC_STAT_NOERROR;
		epp->ep_pipe_policy.pp_max_async_reqs = 1;

		cv_init(&epp->ep_wait_cv, NULL, CV_DRIVER, NULL);
		epp->ep_ser_cookie	= usb_init_serialization(
		    ugenp->ug_dip, 0);
	}

	mutex_exit(&epp->ep_mutex);

	/* create minor nodes for all alts */

	return (ugen_epxs_minor_nodes_create(ugenp, ep_descr,
	    cfgval, cfgidx, iface, alt));
}


/*
 * undo all endpoint initializations
 */
static void
ugen_epxs_destroy(ugen_state_t *ugenp)
{
	int	i;

	for (i = 0; i < UGEN_N_ENDPOINTS; i++) {
		ugen_epxs_data_destroy(ugenp, &ugenp->ug_ep[i]);
	}
}


static void
ugen_epxs_data_destroy(ugen_state_t *ugenp, ugen_ep_t *epp)
{
	if (epp) {
		ASSERT(epp->ep_ph == NULL);
		mutex_enter(&epp->ep_mutex);
		if (epp->ep_state != UGEN_EP_STATE_NONE) {
			USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
			    "ugen_epxs_destroy: addr=0x%x",
			    UGEN_XFER_ADDR(epp));
			cv_destroy(&epp->ep_wait_cv);
		}
		mutex_exit(&epp->ep_mutex);

		mutex_destroy(&epp->ep_mutex);
		usb_fini_serialization(epp->ep_ser_cookie);
	}
}


/*
 * create endpoint status and xfer minor nodes
 *
 * The actual minor node needs more than 18 bits. We create a table
 * and store the full minor node in this table and use the
 * index in the table as minor node. This allows 256 minor nodes
 * and 1024 instances
 */
static int
ugen_epxs_minor_nodes_create(ugen_state_t *ugenp, usb_ep_descr_t *ep_descr,
    uchar_t cfgval, uchar_t cfgidx, uchar_t iface, uchar_t alt)
{
	char		node_name[32], *type;
	int		vid = ugenp->ug_dev_data->dev_descr->idVendor;
	int		pid = ugenp->ug_dev_data->dev_descr->idProduct;
	minor_t		minor;
	int		minor_index;
	ugen_minor_t	minor_code, minor_code_base;
	int		owns_device = (usb_owns_device(ugenp->ug_dip) ?
	    UGEN_OWNS_DEVICE : 0);
	int		ep_index =
	    usb_get_ep_index(ep_descr->bEndpointAddress);
	int		ep_addr =
	    ep_descr->bEndpointAddress & USB_EP_NUM_MASK;
	int		ep_type =
	    ep_descr->bmAttributes & USB_EP_ATTR_MASK;
	int		ep_dir =
	    ep_descr->bEndpointAddress & USB_EP_DIR_IN;

	USB_DPRINTF_L4(UGEN_PRINT_CBOPS, ugenp->ug_log_hdl,
	    "ugen_epxs_minor_nodes_create: "
	    "cfgval=%d cfgidx=%d if=%d alt=%d ep=0x%x",
	    cfgval, cfgidx, iface, alt, ep_addr);

	if (ugenp->ug_instance >= UGEN_MINOR_INSTANCE_LIMIT(ugenp)) {
		USB_DPRINTF_L0(UGEN_PRINT_CBOPS, ugenp->ug_log_hdl,
		    "instance number too high (%d)", ugenp->ug_instance);

		return (USB_FAILURE);
	}

	/* create stat and xfer minor node */
	minor_code_base =
	    ((ugen_minor_t)cfgval) << UGEN_MINOR_CFGVAL_SHIFT |
	    ((ugen_minor_t)cfgidx) << UGEN_MINOR_CFGIDX_SHIFT |
	    iface << UGEN_MINOR_IF_SHIFT |
	    alt << UGEN_MINOR_ALT_SHIFT |
	    ep_index << UGEN_MINOR_EPIDX_SHIFT | owns_device;
	minor_code = minor_code_base | UGEN_MINOR_EP_XFER_NODE;

	minor_index = ugen_minor_index_create(ugenp, minor_code);
	if (minor_index < 0) {
		USB_DPRINTF_L1(UGEN_PRINT_CBOPS, ugenp->ug_log_hdl,
		    "too many minor nodes, "
		    "cannot create %d.%d.%d.%x",
		    cfgval, iface, alt, ep_addr);
		/* carry on regardless */

		return (USB_SUCCESS);
	}
	minor = (minor_index << UGEN_MINOR_IDX_SHIFT(ugenp)) |
	    ugenp->ug_instance << UGEN_MINOR_INSTANCE_SHIFT(ugenp);

	if (ep_type == USB_EP_ATTR_CONTROL) {
		type = "cntrl";
	} else {
		type = (ep_dir & USB_EP_DIR_IN) ? "in" : "out";
	}

	/*
	 * xfer ep node name:
	 * vid.pid.[in|out|cntrl].[<cfg>.][if<iface>.][<alt>.]<ep addr>
	 */
	if ((ep_addr == 0) && owns_device) {
		(void) sprintf(node_name, "%x.%x.%s%d",
		    vid, pid, type, ep_addr);
	} else if (cfgidx == 0 && alt == 0) {
		(void) sprintf(node_name, "%x.%x.if%d%s%d",
		    vid, pid, iface, type, ep_addr);
	} else if (cfgidx == 0 && alt != 0) {
		(void) sprintf(node_name, "%x.%x.if%d.%d%s%d",
		    vid, pid, iface, alt, type, ep_addr);
	} else if (cfgidx != 0 && alt == 0) {
		(void) sprintf(node_name, "%x.%x.cfg%dif%d%s%d",
		    vid, pid, cfgval, iface, type, ep_addr);
	} else if (cfgidx != 0 && alt != 0) {
		(void) sprintf(node_name, "%x.%x.cfg%dif%d.%d%s%d",
		    vid, pid, cfgval, iface, alt,
		    type, ep_addr);
	}

	USB_DPRINTF_L3(UGEN_PRINT_CBOPS, ugenp->ug_log_hdl,
	    "minor=0x%x index=%d code=0x%" PRIx64 " name=%s",
	    minor, minor_index, minor_code, node_name);

	ASSERT(minor < L_MAXMIN);

	if ((ddi_create_minor_node(ugenp->ug_dip, node_name,
	    S_IFCHR, minor, DDI_NT_UGEN, 0)) != DDI_SUCCESS) {

		return (USB_FAILURE);
	}

	ugen_store_devt(ugenp, minor);

	minor_code = minor_code_base | UGEN_MINOR_EP_STAT_NODE;
	minor_index = ugen_minor_index_create(ugenp, minor_code);
	if (minor_index < 0) {
		USB_DPRINTF_L1(UGEN_PRINT_CBOPS, ugenp->ug_log_hdl,
		    "too many minor nodes, "
		    "cannot create %d.%d.%d.%x stat",
		    cfgval, iface, alt,
		    ep_descr->bEndpointAddress);
		/* carry on regardless */

		return (USB_SUCCESS);
	}
	minor = (minor_index << UGEN_MINOR_IDX_SHIFT(ugenp)) |
	    ugenp->ug_instance << UGEN_MINOR_INSTANCE_SHIFT(ugenp);

	(void) strcat(node_name, "stat");

	USB_DPRINTF_L3(UGEN_PRINT_CBOPS, ugenp->ug_log_hdl,
	    "minor=0x%x index=%d code=0x%" PRIx64 " name=%s",
	    minor, minor_index, minor_code, node_name);

	ASSERT(minor < L_MAXMIN);

	if ((ddi_create_minor_node(ugenp->ug_dip, node_name,
	    S_IFCHR, minor, DDI_NT_UGEN, 0)) != DDI_SUCCESS) {

		return (USB_FAILURE);
	}

	ugen_store_devt(ugenp, minor);

	return (USB_SUCCESS);
}


/*
 * close all non-default pipes and drain default pipe
 */
static void
ugen_epx_shutdown(ugen_state_t *ugenp)
{
	int	i;

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epx_shutdown:");

	for (i = 0; i < UGEN_N_ENDPOINTS; i++) {
		ugen_ep_t *epp = &ugenp->ug_ep[i];
		mutex_enter(&epp->ep_mutex);
		if (epp->ep_state != UGEN_EP_STATE_NONE) {
			mutex_exit(&epp->ep_mutex);
			(void) usb_serialize_access(epp->ep_ser_cookie,
			    USB_WAIT, 0);
			(void) ugen_epx_close_pipe(ugenp, epp);
			usb_release_access(epp->ep_ser_cookie);
		} else {
			mutex_exit(&epp->ep_mutex);
		}
	}
}


/*
 * find cfg index corresponding to cfg value
 */
static int
ugen_cfgval2idx(ugen_state_t *ugenp, uint_t cfgval)
{
	usb_cfg_data_t	*dev_cfg = ugenp->ug_dev_data->dev_cfg;
	int		cfgidx;

	for (cfgidx = 0; cfgidx < ugenp->ug_dev_data->dev_n_cfg; cfgidx++) {
		dev_cfg = &ugenp->ug_dev_data->dev_cfg[cfgidx];
		if (cfgval == dev_cfg->cfg_descr.bConfigurationValue) {

			return (cfgidx);
		}
	}

	ASSERT(cfgidx < ugenp->ug_dev_data->dev_n_cfg);

	return (0);
}


/*
 * check if any node is open
 */
static int
ugen_epxs_check_open_nodes(ugen_state_t *ugenp)
{
	int	i;

	for (i = 1; i < UGEN_N_ENDPOINTS; i++) {
		ugen_ep_t *epp = &ugenp->ug_ep[i];

		mutex_enter(&epp->ep_mutex);

		USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
		    "ugen_epxs_check_open_nodes: epp=%d, ep_state=0x%x",
		    i, epp->ep_state);

		if (epp->ep_state & UGEN_EP_STATE_XS_OPEN) {
			mutex_exit(&epp->ep_mutex);

			return (USB_SUCCESS);
		}
		mutex_exit(&epp->ep_mutex);
	}

	return (USB_FAILURE);
}


/*
 * check if we can switch alternate
 */
static int
ugen_epxs_check_alt_switch(ugen_state_t *ugenp, uchar_t iface, uchar_t cfgidx)
{
	int	i;

	for (i = 1; i < UGEN_N_ENDPOINTS; i++) {
		ugen_ep_t *epp = &ugenp->ug_ep[i];

		mutex_enter(&epp->ep_mutex);

		USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
		    "ugen_epxs_check_alt_switch: epp=%d, ep_state=0x%x",
		    i, epp->ep_state);

		/*
		 * if the endpoint is open and part of this cfg and interface
		 * then we cannot switch alternates
		 */
		if ((epp->ep_state & UGEN_EP_STATE_XS_OPEN) &&
		    (epp->ep_cfgidx == cfgidx) &&
		    (epp->ep_if == iface)) {
			mutex_exit(&epp->ep_mutex);

			return (USB_FAILURE);
		}
		mutex_exit(&epp->ep_mutex);
	}

	return (USB_SUCCESS);
}


/*
 * implicit switch to new cfg and alt
 * If a crummy device fails usb_get_cfg or usb_get_alt_if, we carry on
 * regardless so at least the device can be opened.
 */
static int
ugen_epxs_switch_cfg_alt(ugen_state_t *ugenp, ugen_ep_t *epp, dev_t dev)
{
	int	rval = USB_SUCCESS;
	uint_t	alt;
	uint_t	new_alt = UGEN_MINOR_ALT(ugenp, dev);
	uint_t	new_if = UGEN_MINOR_IF(ugenp, dev);
	uint_t	cur_if = epp->ep_if;
	uint_t	new_cfgidx = UGEN_MINOR_CFGIDX(ugenp, dev);
	uint_t	cur_cfgidx;
	uint_t	cfgval;
	int	switched = 0;

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epxs_switch_cfg_alt: old cfgidx=%d, if=%d alt=%d",
	    epp->ep_cfgidx, epp->ep_if, epp->ep_alt);
	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "new cfgidx=%d, if=%d alt=%d ep_state=0x%x",
	    new_cfgidx, new_if, new_alt, epp->ep_state);

	/* no need to switch if there is only 1 cfg, 1 iface and no alts */
	if ((new_if == 0) && (new_alt == 0) &&
	    (ugenp->ug_dev_data->dev_n_cfg == 1) &&
	    (ugenp->ug_dev_data->dev_cfg[0].cfg_n_if == 1) &&
	    (ugenp->ug_dev_data->
	    dev_cfg[0].cfg_if[new_if].if_n_alt == 1)) {
		USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
		    "no need for switching: n_cfg=%d n_alt=%d",
		    ugenp->ug_dev_data->dev_n_cfg,
		    ugenp->ug_dev_data->
		    dev_cfg[0].cfg_if[new_if].if_n_alt);

		ASSERT(epp->ep_alt == new_alt);
		ASSERT(epp->ep_cfgidx == new_cfgidx);
		ASSERT(epp->ep_if == new_if);

		return (rval);
	}

	/* no switch for default endpoint */
	if (epp->ep_descr.bEndpointAddress == 0) {

		return (rval);
	}

	mutex_exit(&epp->ep_mutex);
	if ((ugenp->ug_dev_data->dev_n_cfg > 1) &&
	    usb_get_cfg(ugenp->ug_dip, &cfgval,
	    USB_FLAGS_SLEEP) == USB_SUCCESS) {

		mutex_enter(&epp->ep_mutex);

		cur_cfgidx = ugen_cfgval2idx(ugenp, cfgval);

		if (new_cfgidx != cur_cfgidx) {
			mutex_exit(&epp->ep_mutex);

			/*
			 * we can't change config if any node
			 * is open
			 */
			if (ugen_epxs_check_open_nodes(ugenp) ==
			    USB_SUCCESS) {
				mutex_enter(&epp->ep_mutex);

				return (USB_BUSY);
			}

			/*
			 * we are going to do this synchronously to
			 * keep it simple.
			 * This should never hang forever.
			 */
			if ((rval = usb_set_cfg(ugenp->ug_dip,
			    new_cfgidx, USB_FLAGS_SLEEP, NULL,
			    NULL)) != USB_SUCCESS) {
				USB_DPRINTF_L2(UGEN_PRINT_XFER,
				    ugenp->ug_log_hdl,
				    "implicit set cfg (%" PRId64
				    ") failed (%d)",
				    UGEN_MINOR_CFGIDX(ugenp, dev), rval);
				mutex_enter(&epp->ep_mutex);

				return (rval);
			}
			mutex_enter(&epp->ep_mutex);
			epp->ep_if = (uchar_t)new_if;
			switched++;
		}
		epp->ep_cfgidx = (uchar_t)new_cfgidx;

		mutex_exit(&epp->ep_mutex);
	}

	/*
	 * implicitly switch to new alternate if
	 * - we have not switched configuration (if we
	 *   we switched config, the alternate must be 0)
	 * - n_alts is > 1
	 * - if the device supports get_alternate iface
	 */
	if ((switched && (new_alt > 0)) ||
	    ((ugenp->ug_dev_data->dev_cfg[new_cfgidx].
	    cfg_if[new_if].if_n_alt > 1) &&
	    (usb_get_alt_if(ugenp->ug_dip, new_if, &alt,
	    USB_FLAGS_SLEEP) == USB_SUCCESS))) {
		if (switched || (alt != new_alt)) {
			if (ugen_epxs_check_alt_switch(ugenp, cur_if,
			    new_cfgidx) != USB_SUCCESS) {
				mutex_enter(&epp->ep_mutex);

				return (USB_BUSY);
			}
			if ((rval = usb_set_alt_if(ugenp->ug_dip, new_if,
			    new_alt, USB_FLAGS_SLEEP, NULL, NULL)) !=
			    USB_SUCCESS) {
				USB_DPRINTF_L2(UGEN_PRINT_XFER,
				    ugenp->ug_log_hdl,
				    "implicit set new alternate "
				    "(%d) failed (%d)", new_alt, rval);
				mutex_enter(&epp->ep_mutex);

				return (rval);
			}
		}
	}

	mutex_enter(&epp->ep_mutex);
	epp->ep_alt = (uchar_t)new_alt;
	ugen_update_ep_descr(ugenp, epp);

	return (rval);
}


/*
 * update endpoint descriptor in ugen_ep structure after
 * switching configuration or alternate
 */
static void
ugen_update_ep_descr(ugen_state_t *ugenp, ugen_ep_t *epp)
{
	usb_cfg_data_t	*dev_cfg = ugenp->ug_dev_data->dev_cfg;
	usb_if_data_t	*if_data;
	usb_alt_if_data_t *alt_if_data;
	usb_ep_data_t	*ep_data;
	int		ep;

	dev_cfg = &ugenp->ug_dev_data->dev_cfg[epp->ep_cfgidx];
	if_data = &dev_cfg->cfg_if[epp->ep_if];
	alt_if_data = &if_data->if_alt[epp->ep_alt];
	for (ep = 0; ep < alt_if_data->altif_n_ep; ep++) {
		ep_data = &alt_if_data->altif_ep[ep];
		if (usb_get_ep_index(ep_data->ep_descr.
		    bEndpointAddress) ==
		    usb_get_ep_index(epp->ep_descr.
		    bEndpointAddress)) {
			epp->ep_descr = ep_data->ep_descr;

			break;
		}
	}
}


/*
 * Xfer endpoint management
 *
 * open an endpoint for xfers
 *
 * Return values: errno
 */
static int
ugen_epx_open(ugen_state_t *ugenp, dev_t dev, int flag)
{
	ugen_ep_t *epp = &ugenp->ug_ep[UGEN_MINOR_EPIDX(ugenp, dev)];
	int	rval;

	mutex_enter(&epp->ep_mutex);

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epx_open: minor=0x%x flag=0x%x ep_state=0x%x",
	    getminor(dev), flag, epp->ep_state);

	ASSERT(epp->ep_state & UGEN_EP_STATE_ACTIVE);

	/* implicit switch to new cfg & alt */
	if ((epp->ep_state & UGEN_EP_STATE_XFER_OPEN) != 0) {
		mutex_exit(&epp->ep_mutex);

		return (EBUSY);
	}
	if ((rval = ugen_epxs_switch_cfg_alt(ugenp, epp, dev)) ==
	    USB_SUCCESS) {
		rval = ugen_epx_open_pipe(ugenp, epp, flag);
	}

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epx_open: state=0x%x", epp->ep_state);

	ASSERT(epp->ep_state & UGEN_EP_STATE_ACTIVE);
	epp->ep_done = epp->ep_lcmd_status = USB_LC_STAT_NOERROR;

	mutex_exit(&epp->ep_mutex);

	return (usb_rval2errno(rval));
}


/*
 * close an endpoint for xfers
 */
static void
ugen_epx_close(ugen_state_t *ugenp, dev_t dev, int flag)
{
	ugen_ep_t *epp = &ugenp->ug_ep[UGEN_MINOR_EPIDX(ugenp, dev)];

	mutex_enter(&epp->ep_mutex);
	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epx_close: dev=0x%lx flag=0x%x state=0x%x", dev, flag,
	    epp->ep_state);
	mutex_exit(&epp->ep_mutex);

	ugen_epx_close_pipe(ugenp, epp);

	mutex_enter(&epp->ep_mutex);
	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epx_close: state=0x%x", epp->ep_state);
	ASSERT(epp->ep_state & UGEN_EP_STATE_ACTIVE);
	ASSERT(epp->ep_bp == NULL);
	ASSERT(epp->ep_done == 0);
	ASSERT(epp->ep_data == NULL);
	mutex_exit(&epp->ep_mutex);
}


/*
 * open pipe for this endpoint
 * If the pipe is an interrupt IN pipe, start polling immediately
 */
static int
ugen_epx_open_pipe(ugen_state_t *ugenp, ugen_ep_t *epp, int flag)
{
	int rval = USB_SUCCESS;

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epx_open_pipe: epp=0x%p flag=%d state=0x%x",
	    (void *)epp, flag, epp->ep_state);

	epp->ep_state |= UGEN_EP_STATE_XFER_OPEN;
	epp->ep_xfer_oflag = flag;

	/* if default pipe, just copy the handle */
	if ((epp->ep_descr.bEndpointAddress & USB_EP_NUM_MASK) == 0) {
		epp->ep_ph = ugenp->ug_dev_data->dev_default_ph;
	} else {
		mutex_exit(&epp->ep_mutex);

		/* open pipe */
		rval = usb_pipe_open(ugenp->ug_dip,
		    &epp->ep_descr, &epp->ep_pipe_policy,
		    USB_FLAGS_SLEEP, &epp->ep_ph);

		mutex_enter(&epp->ep_mutex);

		if (rval == USB_SUCCESS) {
			(void) usb_pipe_set_private(epp->ep_ph,
			    (usb_opaque_t)epp);

			/*
			 * if interrupt IN pipe, and one xfer mode
			 * has not been set, start polling immediately
			 */
			if ((UGEN_XFER_TYPE(epp) == USB_EP_ATTR_INTR) &&
			    (!(epp->ep_one_xfer)) &&
			    (UGEN_XFER_DIR(epp) == USB_EP_DIR_IN)) {
				if ((rval = ugen_epx_intr_IN_start_polling(
				    ugenp, epp)) != USB_SUCCESS) {

					mutex_exit(&epp->ep_mutex);
					usb_pipe_close(ugenp->ug_dip,
					    epp->ep_ph, USB_FLAGS_SLEEP,
					    NULL, NULL);
					mutex_enter(&epp->ep_mutex);

					epp->ep_ph = NULL;
				} else {
					epp->ep_state |=
					    UGEN_EP_STATE_INTR_IN_POLLING_ON;

					/* allow for about 1 sec of data */
					epp->ep_buf_limit =
					    (1000/epp->ep_descr.bInterval) *
					    epp->ep_descr.wMaxPacketSize;
				}
			}

			/* set ep_buf_limit for isoc IN pipe */
			if ((UGEN_XFER_TYPE(epp) == USB_EP_ATTR_ISOCH) &&
			    (UGEN_XFER_DIR(epp) == USB_EP_DIR_IN)) {
				uint16_t max_size;
				uint32_t framecnt;

				max_size =
				    UGEN_PKT_SIZE(epp->ep_descr.wMaxPacketSize);

				/*
				 * wMaxPacketSize bits 10..0 specifies maximum
				 * packet size, which can hold 1024 bytes. If
				 * bits 12..11 is non zero, max_size will be
				 * greater than 1024 and the endpoint is a
				 * high-bandwidth endpoint.
				 */
				if (max_size <= 1024) {
				/*
				 * allowing about 1s data of highspeed and 8s
				 * data of full speed device
				 */
					framecnt = ugen_isoc_buf_limit;
					epp->ep_buf_limit = framecnt *
					    max_size * 8;
				} else {
				/*
				 * allow for about 333 ms data for high-speed
				 * high-bandwidth data
				 */
					framecnt = ugen_isoc_buf_limit/3;
					epp->ep_buf_limit =
					    framecnt * max_size * 8;
				}

				epp->ep_isoc_in_inited = 0;
			}
		}
	}

	if (rval != USB_SUCCESS) {
		epp->ep_state &= ~(UGEN_EP_STATE_XFER_OPEN |
		    UGEN_EP_STATE_INTR_IN_POLLING_ON);
	}

	return (rval);
}


/*
 * close an endpoint pipe
 */
static void
ugen_epx_close_pipe(ugen_state_t *ugenp, ugen_ep_t *epp)
{
	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epx_close_pipe: epp=0x%p", (void *)epp);

	mutex_enter(&epp->ep_mutex);
	if (epp->ep_state & UGEN_EP_STATE_XFER_OPEN) {

		/*  free isoc pipe private data ep_isoc_info.isoc_pkt_descr. */
		if (UGEN_XFER_TYPE(epp) == USB_EP_ATTR_ISOCH) {
			int len;
			int n_pkt;

			if (UGEN_XFER_DIR(epp) == USB_EP_DIR_IN &&
			    (epp->ep_state &
			    UGEN_EP_STATE_ISOC_IN_POLLING_ON)) {
				mutex_exit(&epp->ep_mutex);
				usb_pipe_stop_isoc_polling(epp->ep_ph,
				    USB_FLAGS_SLEEP);
				mutex_enter(&epp->ep_mutex);
			}

			if (epp->ep_isoc_info.isoc_pkt_descr) {
				n_pkt = epp->ep_isoc_info.
				    isoc_pkts_count;
				len = sizeof (ugen_isoc_pkt_descr_t) * n_pkt;

				kmem_free(epp->ep_isoc_info.isoc_pkt_descr,
				    len);

				epp->ep_isoc_info.isoc_pkt_descr = NULL;
			}
			epp->ep_isoc_in_inited = 0;

		}


		epp->ep_state &= ~(UGEN_EP_STATE_XFER_OPEN |
		    UGEN_EP_STATE_INTR_IN_POLLING_IS_STOPPED |
		    UGEN_EP_STATE_INTR_IN_POLLING_ON |
		    UGEN_EP_STATE_ISOC_IN_POLLING_IS_STOPPED |
		    UGEN_EP_STATE_ISOC_IN_POLLING_ON);

		if (epp->ep_ph == ugenp->ug_dev_data->dev_default_ph) {
			mutex_exit(&epp->ep_mutex);

			(void) usb_pipe_drain_reqs(ugenp->ug_dip,
			    epp->ep_ph, 0, USB_FLAGS_SLEEP,
			    NULL, NULL);
			mutex_enter(&epp->ep_mutex);
		} else {
			mutex_exit(&epp->ep_mutex);
			usb_pipe_close(ugenp->ug_dip,
			    epp->ep_ph, USB_FLAGS_SLEEP, NULL, NULL);

			mutex_enter(&epp->ep_mutex);
			epp->ep_ph = NULL;
		}

		freemsg(epp->ep_data);
		epp->ep_ph = NULL;
		epp->ep_data = NULL;
	}
	ASSERT(epp->ep_ph == NULL);
	ASSERT(epp->ep_data == NULL);
	mutex_exit(&epp->ep_mutex);
}


/*
 * start endpoint xfer
 *
 * We first serialize at endpoint level for only one request at the time
 *
 * Return values: errno
 */
static int
ugen_epx_req(ugen_state_t *ugenp, struct buf *bp)
{
	dev_t		dev = bp->b_edev;
	ugen_ep_t	*epp = &ugenp->ug_ep[UGEN_MINOR_EPIDX(ugenp, dev)];
	boolean_t	wait = B_FALSE;
	int		rval = 0;

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epx_req: bp=0x%p dev=0x%lx", (void *)bp, dev);

	/* single thread per endpoint, one request at the time */
	if (usb_serialize_access(epp->ep_ser_cookie, USB_WAIT_SIG, 0) <=
	    0) {

		return (EINTR);
	}

	mutex_enter(&ugenp->ug_mutex);
	switch (ugenp->ug_dev_state) {
	case USB_DEV_ONLINE:

		break;
	case USB_UGEN_DEV_UNAVAILABLE_RECONNECT:
	case USB_DEV_DISCONNECTED:
		mutex_enter(&epp->ep_mutex);
		epp->ep_lcmd_status = USB_LC_STAT_DISCONNECTED;
		mutex_exit(&epp->ep_mutex);
		rval = ENODEV;

		break;
	case USB_UGEN_DEV_UNAVAILABLE_RESUME:
	case USB_DEV_SUSPENDED:
		mutex_enter(&epp->ep_mutex);
		epp->ep_lcmd_status = USB_LC_STAT_SUSPENDED;
		mutex_exit(&epp->ep_mutex);
		rval = EBADF;

		break;
	default:
		mutex_enter(&epp->ep_mutex);
		epp->ep_lcmd_status = USB_LC_STAT_HW_ERR;
		mutex_exit(&epp->ep_mutex);
		rval = EIO;

		break;
	}

#ifndef __lock_lint
	USB_DPRINTF_L3(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epx_req: lcmd_status=0x%x", epp->ep_lcmd_status);
#endif

	mutex_exit(&ugenp->ug_mutex);

	if (rval) {
		usb_release_access(epp->ep_ser_cookie);

		return (rval);
	}

	mutex_enter(&epp->ep_mutex);
	ASSERT(epp->ep_state & UGEN_EP_STATE_XS_OPEN);
	epp->ep_done = 0;
	epp->ep_bp = bp;

	switch (epp->ep_descr.bmAttributes & USB_EP_ATTR_MASK) {
	case USB_EP_ATTR_CONTROL:
		rval = ugen_epx_ctrl_req(ugenp, epp, bp, &wait);

		break;
	case USB_EP_ATTR_BULK:
		rval = ugen_epx_bulk_req(ugenp, epp, bp, &wait);

		break;
	case USB_EP_ATTR_INTR:
		if (bp->b_flags & B_READ) {
			rval = ugen_epx_intr_IN_req(ugenp, epp, bp, &wait);
		} else {
			rval = ugen_epx_intr_OUT_req(ugenp, epp, bp, &wait);
		}

		break;
	case USB_EP_ATTR_ISOCH:
		if (bp->b_flags & B_READ) {
			rval = ugen_epx_isoc_IN_req(ugenp, epp, bp, &wait);
		} else {
			rval = ugen_epx_isoc_OUT_req(ugenp, epp, bp, &wait);
		}

		break;
	default:
		epp->ep_lcmd_status = USB_LC_STAT_INVALID_REQ;
		rval = USB_INVALID_REQUEST;
	}

	/* if the xfer could not immediately be completed, block here */
	if ((rval == USB_SUCCESS) && wait) {
		while (!epp->ep_done) {
			if ((cv_wait_sig(&epp->ep_wait_cv,
			    &epp->ep_mutex) <= 0) && !epp->ep_done) {
				USB_DPRINTF_L2(UGEN_PRINT_XFER,
				    ugenp->ug_log_hdl,
				    "ugen_epx_req: interrupted ep=0x%" PRIx64,
				    UGEN_MINOR_EPIDX(ugenp, dev));

				/*
				 * blow away the request except for dflt pipe
				 * (this is prevented in USBA)
				 */
				mutex_exit(&epp->ep_mutex);
				usb_pipe_reset(ugenp->ug_dip, epp->ep_ph,
				    USB_FLAGS_SLEEP, NULL, NULL);
				(void) usb_pipe_drain_reqs(ugenp->ug_dip,
				    epp->ep_ph, 0,
				    USB_FLAGS_SLEEP, NULL, NULL);

				mutex_enter(&epp->ep_mutex);

				if (geterror(bp) == 0) {
					bioerror(bp, EINTR);
				}
				epp->ep_lcmd_status =
				    USB_LC_STAT_INTERRUPTED;

				break;
			}
			USB_DPRINTF_L3(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
			    "ugen_epx_req: wakeup");
		}
	}

	/* always set lcmd_status if there was a failure */
	if ((rval != USB_SUCCESS) &&
	    (epp->ep_lcmd_status == USB_LC_STAT_NOERROR)) {
		epp->ep_lcmd_status = USB_LC_STAT_UNSPECIFIED_ERR;
	}

	epp->ep_done = 0;
	epp->ep_bp = NULL;
	mutex_exit(&epp->ep_mutex);

	usb_release_access(epp->ep_ser_cookie);
	USB_DPRINTF_L3(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epx_req: done");

	return (usb_rval2errno(rval));
}


/*
 * handle control xfers
 */
static int
ugen_epx_ctrl_req(ugen_state_t *ugenp, ugen_ep_t *epp,
    struct buf *bp, boolean_t *wait)
{
	usb_ctrl_req_t *reqp = NULL;
	uchar_t	*setup = ((uchar_t *)(bp->b_un.b_addr));
	int	rval;
	ushort_t wLength;

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epx_ctrl_req: epp=0x%p state=0x%x bp=0x%p",
	    (void *)epp, epp->ep_state, (void *)bp);

	/* is this a read following a write with setup data? */
	if (bp->b_flags & B_READ) {
		if (epp->ep_data) {
			int ep_len = MBLKL(epp->ep_data);
			int len = min(bp->b_bcount, ep_len);

			bcopy(epp->ep_data->b_rptr, bp->b_un.b_addr, len);
			epp->ep_data->b_rptr += len;
			if (MBLKL(epp->ep_data) == 0) {
				freemsg(epp->ep_data);
				epp->ep_data = NULL;
			}
			bp->b_resid = bp->b_bcount - len;
		} else {
			bp->b_resid = bp->b_bcount;
		}

		return (USB_SUCCESS);
	}

	/* discard old data if any */
	if (epp->ep_data) {
		freemsg(epp->ep_data);
		epp->ep_data = NULL;
	}

	/* allocate and initialize request */
	wLength = (setup[7] << 8) | setup[6];
	reqp = usb_alloc_ctrl_req(ugenp->ug_dip, wLength, USB_FLAGS_NOSLEEP);
	if (reqp == NULL) {
		epp->ep_lcmd_status = USB_LC_STAT_NO_RESOURCES;

		return (USB_NO_RESOURCES);
	}

	/* assume an LE data stream */
	reqp->ctrl_bmRequestType = setup[0];
	reqp->ctrl_bRequest	= setup[1];
	reqp->ctrl_wValue	= (setup[3] << 8) | setup[2];
	reqp->ctrl_wIndex	= (setup[5] << 8) | setup[4];
	reqp->ctrl_wLength	= wLength;
	reqp->ctrl_timeout	= ugen_ctrl_timeout;
	reqp->ctrl_attributes	= USB_ATTRS_AUTOCLEARING |
	    USB_ATTRS_SHORT_XFER_OK;
	reqp->ctrl_cb		= ugen_epx_ctrl_req_cb;
	reqp->ctrl_exc_cb	= ugen_epx_ctrl_req_cb;
	reqp->ctrl_client_private = (usb_opaque_t)ugenp;

	/*
	 * is this a legal request? No accesses to device are
	 * allowed if we don't own the device
	 */
	if (((reqp->ctrl_bmRequestType & USB_DEV_REQ_RCPT_MASK) ==
	    USB_DEV_REQ_RCPT_DEV) &&
	    (((reqp->ctrl_bmRequestType & USB_DEV_REQ_DIR_MASK) ==
	    USB_DEV_REQ_HOST_TO_DEV) &&
	    (usb_owns_device(ugenp->ug_dip) == B_FALSE))) {
		rval = USB_INVALID_PERM;
		epp->ep_lcmd_status = USB_LC_STAT_INVALID_REQ;

		goto fail;
	}

	/* filter out set_cfg and set_if standard requests */
	if ((reqp->ctrl_bmRequestType & USB_DEV_REQ_TYPE_MASK) ==
	    USB_DEV_REQ_TYPE_STANDARD) {
		switch (reqp->ctrl_bRequest) {
		case USB_REQ_SET_CFG:
		case USB_REQ_SET_IF:
			rval = USB_INVALID_REQUEST;
			epp->ep_lcmd_status = USB_LC_STAT_INVALID_REQ;

			goto fail;
		default:

			break;
		}
	}

	/* is this from host to device? */
	if (((reqp->ctrl_bmRequestType & USB_DEV_REQ_DIR_MASK) ==
	    USB_DEV_REQ_HOST_TO_DEV) && reqp->ctrl_wLength) {
		if (((bp->b_bcount - UGEN_SETUP_PKT_SIZE) - wLength) != 0) {
			rval = USB_INVALID_REQUEST;
			epp->ep_lcmd_status = USB_LC_STAT_INVALID_REQ;

			goto fail;
		}
		bcopy(bp->b_un.b_addr + UGEN_SETUP_PKT_SIZE,
		    reqp->ctrl_data->b_wptr, wLength);
		reqp->ctrl_data->b_wptr += wLength;
	} else	if ((reqp->ctrl_bmRequestType & USB_DEV_REQ_DIR_MASK) ==
	    USB_DEV_REQ_DEV_TO_HOST) {
		if (bp->b_bcount != UGEN_SETUP_PKT_SIZE) {
			rval = USB_INVALID_REQUEST;
			epp->ep_lcmd_status = USB_LC_STAT_INVALID_REQ;

			goto fail;
		}
	}

	/* submit the request */
	mutex_exit(&epp->ep_mutex);
	rval = usb_pipe_ctrl_xfer(epp->ep_ph, reqp, USB_FLAGS_NOSLEEP);
	mutex_enter(&epp->ep_mutex);
	if (rval != USB_SUCCESS) {
		epp->ep_lcmd_status =
		    ugen_cr2lcstat(reqp->ctrl_completion_reason);

		goto fail;
	}
done:
	*wait = B_TRUE;

	return (USB_SUCCESS);
fail:
	*wait = B_FALSE;

	usb_free_ctrl_req(reqp);

	return (rval);
}


/*
 * callback for control requests, normal and exception completion
 */
static void
ugen_epx_ctrl_req_cb(usb_pipe_handle_t ph, usb_ctrl_req_t *reqp)
{
	ugen_state_t *ugenp = (ugen_state_t *)reqp->ctrl_client_private;
	ugen_ep_t *epp = (ugen_ep_t *)usb_pipe_get_private(ph);

	if (epp == NULL) {
		epp = &ugenp->ug_ep[0];
	}

	mutex_enter(&epp->ep_mutex);

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epx_ctrl_req_cb:\n\t"
	    "epp=0x%p state=0x%x ph=0x%p reqp=0x%p cr=%d cb=0x%x",
	    (void *)epp, epp->ep_state, (void *)ph, (void *)reqp,
	    reqp->ctrl_completion_reason, reqp->ctrl_cb_flags);

	ASSERT((reqp->ctrl_cb_flags & USB_CB_INTR_CONTEXT) == 0);

	/* save any data for the next read */
	switch (reqp->ctrl_completion_reason) {
	case USB_CR_OK:
		epp->ep_lcmd_status = USB_LC_STAT_NOERROR;

		break;
	case USB_CR_PIPE_RESET:

		break;
	default:
		epp->ep_lcmd_status =
		    ugen_cr2lcstat(reqp->ctrl_completion_reason);
		if (epp->ep_bp) {
			bioerror(epp->ep_bp, EIO);
		}

		break;
	}

	if (reqp->ctrl_data) {
		ASSERT(epp->ep_data == NULL);
		epp->ep_data = reqp->ctrl_data;
		reqp->ctrl_data = NULL;
	}
	epp->ep_done++;
	cv_signal(&epp->ep_wait_cv);
	mutex_exit(&epp->ep_mutex);

	usb_free_ctrl_req(reqp);

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epx_ctrl_req_cb: done");
}


/*
 * handle bulk xfers
 */
static int
ugen_epx_bulk_req(ugen_state_t *ugenp, ugen_ep_t *epp,
    struct buf *bp, boolean_t *wait)
{
	int		rval;
	usb_bulk_req_t	*reqp = usb_alloc_bulk_req(ugenp->ug_dip,
	    bp->b_bcount, USB_FLAGS_NOSLEEP);

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epx_bulk_req: epp=0x%p state=0x%x bp=0x%p",
	    (void *)epp, epp->ep_state, (void *)bp);

	if (reqp == NULL) {
		epp->ep_lcmd_status = USB_LC_STAT_NO_RESOURCES;

		return (USB_NO_RESOURCES);
	}

	ASSERT(epp->ep_state & UGEN_EP_STATE_XS_OPEN);

	/*
	 * the transfer count is limited in minphys with what the HCD can
	 * do
	 */
	reqp->bulk_len		= bp->b_bcount;
	reqp->bulk_timeout	= ugen_bulk_timeout;
	reqp->bulk_client_private = (usb_opaque_t)ugenp;
	reqp->bulk_attributes	= USB_ATTRS_AUTOCLEARING;
	reqp->bulk_cb		= ugen_epx_bulk_req_cb;
	reqp->bulk_exc_cb	= ugen_epx_bulk_req_cb;

	/* copy data into bp for OUT pipes */
	if ((UGEN_XFER_DIR(epp) & USB_EP_DIR_IN) == 0) {
		bcopy(epp->ep_bp->b_un.b_addr, reqp->bulk_data->b_rptr,
		    bp->b_bcount);
		reqp->bulk_data->b_wptr += bp->b_bcount;
	} else {
		reqp->bulk_attributes |= USB_ATTRS_SHORT_XFER_OK;
	}

	mutex_exit(&epp->ep_mutex);
	if ((rval = usb_pipe_bulk_xfer(epp->ep_ph, reqp,
	    USB_FLAGS_NOSLEEP)) != USB_SUCCESS) {
		mutex_enter(&epp->ep_mutex);
		epp->ep_lcmd_status =
		    ugen_cr2lcstat(reqp->bulk_completion_reason);
		usb_free_bulk_req(reqp);
		bioerror(bp, EIO);
	} else {
		mutex_enter(&epp->ep_mutex);
	}
	*wait = (rval == USB_SUCCESS) ? B_TRUE : B_FALSE;

	return (rval);
}


/*
 * normal and exception bulk request callback
 */
static void
ugen_epx_bulk_req_cb(usb_pipe_handle_t ph, usb_bulk_req_t *reqp)
{
	ugen_state_t *ugenp = (ugen_state_t *)reqp->bulk_client_private;
	ugen_ep_t *epp = (ugen_ep_t *)usb_pipe_get_private(ph);

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epx_bulk_req_cb: ph=0x%p reqp=0x%p cr=%d cb=0x%x",
	    (void *)ph, (void *)reqp, reqp->bulk_completion_reason,
	    reqp->bulk_cb_flags);

	ASSERT((reqp->bulk_cb_flags & USB_CB_INTR_CONTEXT) == 0);

	/* epp might be NULL if we are closing the pipe */
	if (epp) {
		mutex_enter(&epp->ep_mutex);
		if (epp->ep_bp && reqp->bulk_data) {
			int len = min(MBLKL(reqp->bulk_data),
			    epp->ep_bp->b_bcount);
			if (UGEN_XFER_DIR(epp) & USB_EP_DIR_IN) {
				if (len) {
					bcopy(reqp->bulk_data->b_rptr,
					    epp->ep_bp->b_un.b_addr, len);
					epp->ep_bp->b_resid =
					    epp->ep_bp->b_bcount - len;
				}
			} else {
				epp->ep_bp->b_resid =
				    epp->ep_bp->b_bcount - len;
			}
		}
		switch (reqp->bulk_completion_reason) {
		case USB_CR_OK:
			epp->ep_lcmd_status = USB_LC_STAT_NOERROR;

			break;
		case USB_CR_PIPE_RESET:

			break;
		default:
			epp->ep_lcmd_status =
			    ugen_cr2lcstat(reqp->bulk_completion_reason);
			if (epp->ep_bp) {
				bioerror(epp->ep_bp, EIO);
			}
		}
		epp->ep_done++;
		cv_signal(&epp->ep_wait_cv);
		mutex_exit(&epp->ep_mutex);
	}

	usb_free_bulk_req(reqp);
}


/*
 * handle intr IN xfers
 */
static int
ugen_epx_intr_IN_req(ugen_state_t *ugenp, ugen_ep_t *epp,
    struct buf *bp, boolean_t *wait)
{
	int	len = 0;
	int	rval = USB_SUCCESS;

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epx_intr_IN_req: epp=0x%p state=0x%x bp=0x%p",
	    (void *)epp, epp->ep_state, (void *)bp);

	*wait = B_FALSE;

	/* can we satisfy this read? */
	if (epp->ep_data) {
		len = min(MBLKL(epp->ep_data),
		    bp->b_bcount);
	}

	/*
	 * if polling not active, restart, and return failure
	 * immediately unless one xfer mode has been requested
	 * if there is some data, return a short read
	 */
	if ((epp->ep_state & UGEN_EP_STATE_INTR_IN_POLLING_ON) == 0) {
		if (len == 0) {
			if (!epp->ep_one_xfer) {
				rval = USB_FAILURE;
				if (epp->ep_lcmd_status ==
				    USB_LC_STAT_NOERROR) {
					epp->ep_lcmd_status =
					    USB_LC_STAT_INTR_BUF_FULL;
				}
			}
			if (ugen_epx_intr_IN_start_polling(ugenp,
			    epp) != USB_SUCCESS) {
				epp->ep_lcmd_status =
				    USB_LC_STAT_INTR_POLLING_FAILED;
			}
			if (epp->ep_one_xfer) {
				*wait = B_TRUE;
			}
			goto done;
		} else if (epp->ep_data && (len < bp->b_bcount)) {
			bcopy(epp->ep_data->b_rptr, bp->b_un.b_addr, len);
			bp->b_resid = bp->b_bcount - len;
			epp->ep_data->b_rptr += len;

			goto done;
		}
	}

	/*
	 * if there is data or FNDELAY, return available data
	 */
	if ((len >= bp->b_bcount) ||
	    (epp->ep_xfer_oflag & (FNDELAY | FNONBLOCK))) {
		if (epp->ep_data) {
			bcopy(epp->ep_data->b_rptr, bp->b_un.b_addr, len);
			epp->ep_data->b_rptr += len;
			bp->b_resid = bp->b_bcount - len;
		} else {
			bp->b_resid = bp->b_bcount;
		}
	} else {
		/* otherwise just wait for data */
		*wait = B_TRUE;
	}

done:
	if (epp->ep_data && (epp->ep_data->b_rptr == epp->ep_data->b_wptr)) {
		freemsg(epp->ep_data);
		epp->ep_data = NULL;
	}

	if (*wait) {
		ASSERT(epp->ep_state & UGEN_EP_STATE_INTR_IN_POLLING_ON);
	}

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epx_intr_IN_req end: rval=%d bcount=%lu len=%d data=0x%p",
	    rval, bp->b_bcount, len, (void *)epp->ep_data);

	return (rval);
}


/*
 * Start polling on interrupt endpoint, synchronously
 */
static int
ugen_epx_intr_IN_start_polling(ugen_state_t *ugenp, ugen_ep_t *epp)
{
	int rval = USB_FAILURE;
	usb_intr_req_t	*reqp;
	usb_flags_t uflag;

	/*
	 * if polling is being stopped, we restart polling in the
	 * interrrupt callback again
	 */
	if (epp->ep_state & UGEN_EP_STATE_INTR_IN_POLLING_IS_STOPPED) {

		return (rval);
	}
	if ((epp->ep_state & UGEN_EP_STATE_INTR_IN_POLLING_ON) == 0) {
		USB_DPRINTF_L3(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
		    "ugen_epx_intr_IN_start_polling: epp=0x%p state=0x%x",
		    (void *)epp, epp->ep_state);

		epp->ep_state |= UGEN_EP_STATE_INTR_IN_POLLING_ON;
		mutex_exit(&epp->ep_mutex);

		reqp = usb_alloc_intr_req(ugenp->ug_dip, 0,
		    USB_FLAGS_SLEEP);
		reqp->intr_client_private = (usb_opaque_t)ugenp;

		reqp->intr_attributes	= USB_ATTRS_AUTOCLEARING |
		    USB_ATTRS_SHORT_XFER_OK;
		mutex_enter(&epp->ep_mutex);
		if (epp->ep_one_xfer) {
			reqp->intr_attributes |= USB_ATTRS_ONE_XFER;
			uflag = USB_FLAGS_NOSLEEP;
		} else {
			uflag = USB_FLAGS_SLEEP;
		}
		mutex_exit(&epp->ep_mutex);

		reqp->intr_len		= epp->ep_descr.wMaxPacketSize;
		reqp->intr_cb		= ugen_epx_intr_IN_req_cb;
		reqp->intr_exc_cb	= ugen_epx_intr_IN_req_cb;


		if ((rval = usb_pipe_intr_xfer(epp->ep_ph, reqp,
		    uflag)) != USB_SUCCESS) {
			USB_DPRINTF_L2(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
			    "ugen_epx_intr_IN_start_polling: failed %d", rval);
			usb_free_intr_req(reqp);
		}
		mutex_enter(&epp->ep_mutex);
		if (rval != USB_SUCCESS) {
			epp->ep_state &= ~UGEN_EP_STATE_INTR_IN_POLLING_ON;
		}
	} else {
		rval = USB_SUCCESS;
	}

	return (rval);
}


/*
 * stop polling on an interrupt endpoint, asynchronously
 */
static void
ugen_epx_intr_IN_stop_polling(ugen_state_t *ugenp, ugen_ep_t *epp)
{
	if ((epp->ep_state & UGEN_EP_STATE_INTR_IN_POLLING_ON) &&
	    ((epp->ep_state & UGEN_EP_STATE_INTR_IN_POLLING_IS_STOPPED) == 0)) {

		USB_DPRINTF_L3(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
		    "ugen_epx_intr_IN_stop_polling: epp=0x%p state=0x%x",
		    (void *)epp, epp->ep_state);

		epp->ep_state |= UGEN_EP_STATE_INTR_IN_POLLING_IS_STOPPED;
		mutex_exit(&epp->ep_mutex);
		usb_pipe_stop_intr_polling(epp->ep_ph, USB_FLAGS_NOSLEEP);
		mutex_enter(&epp->ep_mutex);
	}
}


/*
 * poll management
 */
static void
ugen_epx_intr_IN_poll_wakeup(ugen_state_t *ugenp, ugen_ep_t *epp)
{
	if (epp->ep_state & UGEN_EP_STATE_INTR_IN_POLL_PENDING) {
		struct pollhead *phpp = &epp->ep_pollhead;

		USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
		    "ugen_epx_intr_IN_poll_wakeup: state=0x%x", epp->ep_state);

		epp->ep_state &= ~UGEN_EP_STATE_INTR_IN_POLL_PENDING;
		mutex_exit(&epp->ep_mutex);
		pollwakeup(phpp, POLLIN);
		mutex_enter(&epp->ep_mutex);
	}
}


/*
 * callback functions for interrupt IN pipe
 */
static void
ugen_epx_intr_IN_req_cb(usb_pipe_handle_t ph, usb_intr_req_t *reqp)
{
	ugen_state_t *ugenp = (ugen_state_t *)reqp->intr_client_private;
	ugen_ep_t *epp = (ugen_ep_t *)usb_pipe_get_private(ph);

	if (epp == NULL) {
		/* pipe is closing */

		goto done;
	}

	mutex_enter(&epp->ep_mutex);

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epx_intr_IN_req_cb:\n\t"
	    "epp=0x%p state=0x%x ph=0x%p reqp=0x%p cr=%d cb=0x%x len=%ld",
	    (void *)epp, epp->ep_state, (void *)ph, (void *)reqp,
	    reqp->intr_completion_reason, reqp->intr_cb_flags,
	    (reqp->intr_data == NULL) ? 0 :
	    MBLKL(reqp->intr_data));

	ASSERT((reqp->intr_cb_flags & USB_CB_INTR_CONTEXT) == 0);

	if (epp->ep_data && reqp->intr_data) {
		mblk_t *mp;

		USB_DPRINTF_L3(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
		    "intr ep%x coalesce data", epp->ep_descr.bEndpointAddress);

		/* coalesce the data into one mblk */
		epp->ep_data->b_cont = reqp->intr_data;
		if ((mp = msgpullup(epp->ep_data, -1)) != NULL) {
			reqp->intr_data = NULL;
			freemsg(epp->ep_data);
			epp->ep_data = mp;
		} else {
			USB_DPRINTF_L2(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
			    "msgpullup failed, discard data");
			epp->ep_data->b_cont = NULL;
		}
	} else if (reqp->intr_data) {
		USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
		    "setting ep_data");

		epp->ep_data = reqp->intr_data;
		reqp->intr_data = NULL;
	}

	switch (reqp->intr_completion_reason) {
	case USB_CR_OK:
		epp->ep_lcmd_status = USB_LC_STAT_NOERROR;

		break;
	case USB_CR_PIPE_RESET:
	case USB_CR_STOPPED_POLLING:

		break;
	default:
		epp->ep_lcmd_status =
		    ugen_cr2lcstat(reqp->intr_completion_reason);
		USB_DPRINTF_L2(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
		    "ugen_exp_intr_cb_req: lcmd_status=0x%x",
		    epp->ep_lcmd_status);

		break;
	}

	/* any non-zero completion reason stops polling */
	if ((reqp->intr_completion_reason) ||
	    (epp->ep_one_xfer)) {
		epp->ep_state &= ~(UGEN_EP_STATE_INTR_IN_POLLING_ON |
		    UGEN_EP_STATE_INTR_IN_POLLING_IS_STOPPED);
	}

	/* is there a poll pending? should we stop polling? */
	if (epp->ep_data) {
		USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
		    "ugen_epx_intr_IN_req_cb: data len=0x%lx",
		    MBLKL(epp->ep_data));

		ugen_epx_intr_IN_poll_wakeup(ugenp, epp);

		/* if there is no space left, stop polling */
		if (epp->ep_data &&
		    (MBLKL(epp->ep_data) >=
		    epp->ep_buf_limit)) {
			ugen_epx_intr_IN_stop_polling(ugenp, epp);
		}
	}

	if (reqp->intr_completion_reason && epp->ep_bp) {
		bioerror(epp->ep_bp, EIO);
		epp->ep_done++;
		cv_signal(&epp->ep_wait_cv);

	/* can we satisfy the read now */
	} else if (epp->ep_data && epp->ep_bp &&
	    (!epp->ep_done || epp->ep_one_xfer)) {
		boolean_t wait;

		if ((ugen_epx_intr_IN_req(ugenp, epp, epp->ep_bp, &wait) ==
		    USB_SUCCESS) && (wait == B_FALSE)) {
			epp->ep_done++;
			cv_signal(&epp->ep_wait_cv);
		}
	}
	mutex_exit(&epp->ep_mutex);

done:
	usb_free_intr_req(reqp);
}


/*
 * handle intr OUT xfers
 */
static int
ugen_epx_intr_OUT_req(ugen_state_t *ugenp, ugen_ep_t *epp,
    struct buf *bp, boolean_t *wait)
{
	int	rval = USB_SUCCESS;
	usb_intr_req_t	*reqp;

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epx_intr_OUT_req: epp=0x%p state=0x%x bp=0x%p",
	    (void *)epp, epp->ep_state, (void *)bp);

	reqp = usb_alloc_intr_req(ugenp->ug_dip, bp->b_bcount,
	    USB_FLAGS_NOSLEEP);
	if (reqp == NULL) {
		epp->ep_lcmd_status = USB_LC_STAT_NO_RESOURCES;

		return (USB_NO_RESOURCES);
	}

	ASSERT(epp->ep_state & UGEN_EP_STATE_XS_OPEN);

	reqp->intr_timeout	= ugen_intr_timeout;
	reqp->intr_client_private = (usb_opaque_t)ugenp;
	reqp->intr_len		= bp->b_bcount;
	reqp->intr_attributes	= USB_ATTRS_AUTOCLEARING;
	reqp->intr_cb		= ugen_epx_intr_OUT_req_cb;
	reqp->intr_exc_cb	= ugen_epx_intr_OUT_req_cb;

	/* copy data from bp */
	bcopy(epp->ep_bp->b_un.b_addr, reqp->intr_data->b_rptr,
	    bp->b_bcount);
	reqp->intr_data->b_wptr += bp->b_bcount;

	mutex_exit(&epp->ep_mutex);
	if ((rval = usb_pipe_intr_xfer(epp->ep_ph, reqp,
	    USB_FLAGS_NOSLEEP)) != USB_SUCCESS) {
		mutex_enter(&epp->ep_mutex);
		epp->ep_lcmd_status =
		    ugen_cr2lcstat(reqp->intr_completion_reason);
		usb_free_intr_req(reqp);
		bioerror(bp, EIO);
	} else {
		mutex_enter(&epp->ep_mutex);
	}
	*wait = (rval == USB_SUCCESS) ? B_TRUE : B_FALSE;

	return (rval);
}


/*
 * callback functions for interrupt OUT pipe
 */
static void
ugen_epx_intr_OUT_req_cb(usb_pipe_handle_t ph, usb_intr_req_t *reqp)
{
	ugen_state_t *ugenp = (ugen_state_t *)reqp->intr_client_private;
	ugen_ep_t *epp = (ugen_ep_t *)usb_pipe_get_private(ph);

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epx_intr_OUT_req_cb: ph=0x%p reqp=0x%p cr=%d cb=0x%x",
	    (void *)ph, (void *)reqp, reqp->intr_completion_reason,
	    reqp->intr_cb_flags);

	ASSERT((reqp->intr_cb_flags & USB_CB_INTR_CONTEXT) == 0);

	/* epp might be NULL if we are closing the pipe */
	if (epp) {
		int len;

		mutex_enter(&epp->ep_mutex);
		if (epp->ep_bp) {
			len = min(MBLKL(reqp->intr_data), epp->ep_bp->b_bcount);

			epp->ep_bp->b_resid = epp->ep_bp->b_bcount - len;

			switch (reqp->intr_completion_reason) {
			case USB_CR_OK:
				epp->ep_lcmd_status = USB_LC_STAT_NOERROR;

				break;
			case USB_CR_PIPE_RESET:

				break;
			default:
				epp->ep_lcmd_status =
				    ugen_cr2lcstat(
				    reqp->intr_completion_reason);
				bioerror(epp->ep_bp, EIO);
			}
		}
		epp->ep_done++;
		cv_signal(&epp->ep_wait_cv);
		mutex_exit(&epp->ep_mutex);
	}

	usb_free_intr_req(reqp);
}


/*
 * handle isoc IN xfers
 */
static int
ugen_epx_isoc_IN_req(ugen_state_t *ugenp, ugen_ep_t *epp,
    struct buf *bp, boolean_t *wait)
{
	int rval = USB_SUCCESS;
	ugen_isoc_pkt_descr_t *pkt_descr;
	ushort_t n_pkt;
	uint_t pkts_len, len = 0;

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epx_isoc_IN_req: epp=0x%p state=0x%x bp=0x%p",
	    (void *)epp, epp->ep_state, (void *)bp);

	*wait = B_FALSE;

	/* check if the isoc in pkt info has been initialized */
	pkt_descr = epp->ep_isoc_info.isoc_pkt_descr;
	n_pkt = epp->ep_isoc_info.isoc_pkts_count;
	if ((n_pkt == 0) || (pkt_descr == NULL)) {
		rval = USB_FAILURE;
		epp->ep_lcmd_status = USB_LC_STAT_ISOC_UNINITIALIZED;

		goto done;
	}


	/* For OUT endpoint, return pkts transfer status of last request */
	if (UGEN_XFER_DIR(epp) != USB_EP_DIR_IN) {
		if (bp->b_bcount < sizeof (ugen_isoc_pkt_descr_t) * n_pkt) {
			rval = USB_INVALID_REQUEST;
			epp->ep_lcmd_status = USB_LC_STAT_INVALID_REQ;

			return (rval);
		}
		bcopy(epp->ep_isoc_info.isoc_pkt_descr, bp->b_un.b_addr,
		    n_pkt * sizeof (ugen_isoc_pkt_descr_t));
		epp->ep_lcmd_status = USB_LC_STAT_NOERROR;

		return (USB_SUCCESS);
	}

	/* read length should be the sum of pkt descrs and data length */
	pkts_len = epp->ep_isoc_info.isoc_pkts_length;
	if (bp->b_bcount != pkts_len + sizeof (ugen_isoc_pkt_descr_t) * n_pkt) {
		rval = USB_INVALID_REQUEST;
		epp->ep_lcmd_status = USB_LC_STAT_INVALID_REQ;

		goto done;
	}

	/* can we satisfy this read? */
	if (epp->ep_data) {
		len = min(MBLKL(epp->ep_data),
		    bp->b_bcount);
		/*
		 * every msg block in ep_data must be the size of
		 * pkts_len(payload length) + pkt descrs len
		 */
		ASSERT((len == 0) || (len == bp->b_bcount));
	}

	/*
	 * if polling not active, restart
	 * if there is some data, return the data
	 */
	if ((epp->ep_state & UGEN_EP_STATE_ISOC_IN_POLLING_ON) == 0) {
		if (len == 0) {
			rval = USB_FAILURE;
			if ((rval = ugen_epx_isoc_IN_start_polling(ugenp,
			    epp)) != USB_SUCCESS) {
				epp->ep_lcmd_status =
				    USB_LC_STAT_ISOC_POLLING_FAILED;
			}

			goto done;

		} else if (epp->ep_data && (len >= bp->b_bcount)) {
			bcopy(epp->ep_data->b_rptr, bp->b_un.b_addr,
			    bp->b_bcount);
			bp->b_resid = 0;
			epp->ep_data->b_rptr += bp->b_bcount;

			goto done;
		}
	}

	/*
	 * if there is data or FNDELAY, return available data
	 */
	if (epp->ep_data && (len >= bp->b_bcount)) {
		/* can fulfill this read request */
		bcopy(epp->ep_data->b_rptr, bp->b_un.b_addr, bp->b_bcount);
		epp->ep_data->b_rptr += bp->b_bcount;
		bp->b_resid = 0;
	} else if (epp->ep_xfer_oflag & (FNDELAY | FNONBLOCK)) {
		bp->b_resid = bp->b_bcount;
	} else {
		/* otherwise just wait for data */
		*wait = B_TRUE;
	}

done:
	/* data have been read */
	if (epp->ep_data && (epp->ep_data->b_rptr == epp->ep_data->b_wptr)) {
		mblk_t *mp = NULL;

		/* remove the just read msg block */
		mp = unlinkb(epp->ep_data);
		freemsg(epp->ep_data);

		if (mp) {
			epp->ep_data = mp;
		} else {
			epp->ep_data = NULL;
		}
	}

	if (*wait) {
		ASSERT(epp->ep_state & UGEN_EP_STATE_ISOC_IN_POLLING_ON);
	}

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epx_isoc_IN_req end: rval=%d bcount=%lu len=%d data=0x%p",
	    rval, bp->b_bcount, len, (void *)epp->ep_data);

	return (rval);
}


/*
 * Start polling on isoc endpoint, asynchronously
 */
static int
ugen_epx_isoc_IN_start_polling(ugen_state_t *ugenp, ugen_ep_t *epp)
{
	int rval = USB_FAILURE;
	usb_isoc_req_t	*reqp;
	ugen_isoc_pkt_descr_t *pkt_descr;
	ushort_t n_pkt, pkt;
	uint_t pkts_len;

	/*
	 * if polling is being stopped, we restart polling in the
	 * isoc callback again
	 */
	if (epp->ep_state & UGEN_EP_STATE_ISOC_IN_POLLING_IS_STOPPED) {

		return (rval);
	}

	if ((epp->ep_state & UGEN_EP_STATE_ISOC_IN_POLLING_ON) == 0) {
		USB_DPRINTF_L3(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
		    "ugen_epx_isoc_IN_start_polling: epp=0x%p state=0x%x",
		    (void *)epp, epp->ep_state);

		pkts_len = epp->ep_isoc_info.isoc_pkts_length;
		n_pkt = epp->ep_isoc_info.isoc_pkts_count;
		pkt_descr = epp->ep_isoc_info.isoc_pkt_descr;

		epp->ep_state |= UGEN_EP_STATE_ISOC_IN_POLLING_ON;
		mutex_exit(&epp->ep_mutex);

		if ((reqp = usb_alloc_isoc_req(ugenp->ug_dip, n_pkt, pkts_len,
		    USB_FLAGS_NOSLEEP)) == NULL) {
			USB_DPRINTF_L2(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
			    "ugen_epx_isoc_IN_start_polling: alloc isoc "
			    "req failed");
			mutex_enter(&epp->ep_mutex);
			epp->ep_state &= ~UGEN_EP_STATE_ISOC_IN_POLLING_ON;

			return (USB_NO_RESOURCES);
		}
		reqp->isoc_client_private = (usb_opaque_t)ugenp;

		reqp->isoc_attributes	= USB_ATTRS_AUTOCLEARING |
		    USB_ATTRS_SHORT_XFER_OK | USB_ATTRS_ISOC_XFER_ASAP;

		/*
		 * isoc_pkts_length was defined to be ushort_t. This
		 * has been obsoleted by usb high speed isoc support.
		 * It is set here just for compatibility reason
		 */
		reqp->isoc_pkts_length = 0;

		for (pkt = 0; pkt < n_pkt; pkt++) {
			reqp->isoc_pkt_descr[pkt].isoc_pkt_length =
			    pkt_descr[pkt].dsc_isoc_pkt_len;
		}
		reqp->isoc_pkts_count	= n_pkt;
		reqp->isoc_cb		= ugen_epx_isoc_IN_req_cb;
		reqp->isoc_exc_cb	= ugen_epx_isoc_IN_req_cb;

		if ((rval = usb_pipe_isoc_xfer(epp->ep_ph, reqp,
		    USB_FLAGS_NOSLEEP)) != USB_SUCCESS) {
			USB_DPRINTF_L2(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
			    "ugen_epx_isoc_IN_start_polling: failed %d", rval);
			usb_free_isoc_req(reqp);
		}

		mutex_enter(&epp->ep_mutex);
		if (rval != USB_SUCCESS) {
			epp->ep_state &= ~UGEN_EP_STATE_ISOC_IN_POLLING_ON;
		}
	} else {
		rval = USB_SUCCESS;
	}

	return (rval);
}


/*
 * stop polling on an isoc endpoint, asynchronously
 */
static void
ugen_epx_isoc_IN_stop_polling(ugen_state_t *ugenp, ugen_ep_t *epp)
{
	if ((epp->ep_state & UGEN_EP_STATE_ISOC_IN_POLLING_ON) &&
	    ((epp->ep_state & UGEN_EP_STATE_ISOC_IN_POLLING_IS_STOPPED) == 0)) {
		USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
		    "ugen_epx_isoc_IN_stop_polling: epp=0x%p state=0x%x",
		    (void *)epp, epp->ep_state);

		epp->ep_state |= UGEN_EP_STATE_ISOC_IN_POLLING_IS_STOPPED;
		mutex_exit(&epp->ep_mutex);
		usb_pipe_stop_isoc_polling(epp->ep_ph, USB_FLAGS_NOSLEEP);
		mutex_enter(&epp->ep_mutex);
	}
}


/*
 * poll management
 */
static void
ugen_epx_isoc_IN_poll_wakeup(ugen_state_t *ugenp, ugen_ep_t *epp)
{
	if (epp->ep_state & UGEN_EP_STATE_ISOC_IN_POLL_PENDING) {
		struct pollhead *phpp = &epp->ep_pollhead;

		USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
		    "ugen_epx_isoc_IN_poll_wakeup: state=0x%x", epp->ep_state);

		epp->ep_state &= ~UGEN_EP_STATE_ISOC_IN_POLL_PENDING;
		mutex_exit(&epp->ep_mutex);
		pollwakeup(phpp, POLLIN);
		mutex_enter(&epp->ep_mutex);
	}
}


/*
 * callback functions for isoc IN pipe
 */
static void
ugen_epx_isoc_IN_req_cb(usb_pipe_handle_t ph, usb_isoc_req_t *reqp)
{
	ugen_state_t *ugenp = (ugen_state_t *)reqp->isoc_client_private;
	ugen_ep_t *epp = (ugen_ep_t *)usb_pipe_get_private(ph);

	if (epp == NULL) {
		/* pipe is closing */

		goto done;
	}

	ASSERT(!mutex_owned(&epp->ep_mutex)); /* not owned */

	mutex_enter(&epp->ep_mutex);

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epx_isoc_IN_req_cb: "
	    "epp=0x%p state=0x%x ph=0x%p reqp=0x%p cr=%d cb=0x%x len=%ld "
	    "isoc error count=%d, pkt cnt=%d", (void *)epp, epp->ep_state,
	    (void *)ph, (void *)reqp, reqp->isoc_completion_reason,
	    reqp->isoc_cb_flags, (reqp->isoc_data == NULL) ? 0 :
	    MBLKL(reqp->isoc_data),
	    reqp->isoc_error_count, reqp->isoc_pkts_count);

	/* Too many packet errors during isoc transfer of this request */
	if (reqp->isoc_error_count == reqp->isoc_pkts_count) {
		USB_DPRINTF_L3(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
		    "too many errors(%d) in this req, stop polling",
		    reqp->isoc_error_count);
		epp->ep_lcmd_status = USB_LC_STAT_ISOC_PKT_ERROR;
		ugen_epx_isoc_IN_stop_polling(ugenp, epp);
	}

	/* Data OK */
	if (reqp->isoc_data && !reqp->isoc_completion_reason) {
		mblk_t *mp1 = NULL, *mp2 = NULL;
		usb_isoc_pkt_descr_t *pkt_descr =
		    reqp->isoc_pkt_descr;
		ushort_t i, n_pkt = reqp->isoc_pkts_count;

		for (i = 0; i < n_pkt; i++) {
			USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
			    "pkt %d: len=%d status=%d actual_len=%d", i,
			    pkt_descr[i].isoc_pkt_length,
			    pkt_descr[i].isoc_pkt_status,
			    pkt_descr[i].isoc_pkt_actual_length);

			/* translate cr to ugen lcstat */
			pkt_descr[i].isoc_pkt_status =
			    ugen_cr2lcstat(pkt_descr[i].isoc_pkt_status);
		}

		/* construct data buffer: pkt descriptors + payload */
		mp2 = allocb(sizeof (ugen_isoc_pkt_descr_t) * n_pkt, BPRI_HI);
		if (mp2 == NULL) {
			USB_DPRINTF_L2(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
			    "alloc msgblk failed, discard data");
		} else {
			/* pkt descrs first */
			bcopy(pkt_descr, mp2->b_wptr,
			    sizeof (ugen_isoc_pkt_descr_t) * n_pkt);

			mp2->b_wptr += sizeof (ugen_isoc_pkt_descr_t) * n_pkt;

			/* payload follows */
			linkb(mp2, reqp->isoc_data);

			/* concatenate data bytes in mp2 */
			if ((mp1 = msgpullup(mp2, -1)) != NULL) {
				/*
				 * now we get the required data:
				 *	pkt descrs + payload
				 */
				reqp->isoc_data = NULL;
			} else {
				USB_DPRINTF_L2(UGEN_PRINT_XFER,
				    ugenp->ug_log_hdl,
				    "msgpullup status blk failed, "
				    "discard data");
				mp2->b_cont = NULL;
			}

			freemsg(mp2);
			mp2 = NULL;
		}

		if (epp->ep_data && (mp1 != NULL)) {
			USB_DPRINTF_L3(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
			    "ISOC ep%x coalesce ep_data",
			    epp->ep_descr.bEndpointAddress);

			/* add mp1 to the tail of ep_data */
			linkb(epp->ep_data, mp1);

		} else if (mp1 != NULL) {
			USB_DPRINTF_L3(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
			    "setting ep_data");
			epp->ep_data = mp1;
		}
	}

	switch (reqp->isoc_completion_reason) {
	case USB_CR_OK:
		epp->ep_lcmd_status = USB_LC_STAT_NOERROR;

		break;
	case USB_CR_PIPE_RESET:
	case USB_CR_STOPPED_POLLING:
	case USB_CR_PIPE_CLOSING:

		break;
	default:
		epp->ep_lcmd_status =
		    ugen_cr2lcstat(reqp->isoc_completion_reason);
		USB_DPRINTF_L2(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
		    "ugen_exp_isoc_cb_req: error lcmd_status=0x%x ",
		    epp->ep_lcmd_status);

		break;
	}

	/* any non-zero completion reason signifies polling has stopped */
	if (reqp->isoc_completion_reason) {
		epp->ep_state &= ~(UGEN_EP_STATE_ISOC_IN_POLLING_ON |
		    UGEN_EP_STATE_ISOC_IN_POLLING_IS_STOPPED);
	}


	/* is there a poll pending? should we stop polling? */
	if (epp->ep_data) {
		USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
		    "ugen_epx_isoc_IN_req_cb: data len=0x%lx, limit=0x%lx",
		    msgdsize(epp->ep_data),
		    epp->ep_buf_limit);

		ugen_epx_isoc_IN_poll_wakeup(ugenp, epp);


		/*
		 * Since isoc is unreliable xfer, if buffered data size exceeds
		 * the limit, we just discard and free data in the oldest mblk
		 */
		if (epp->ep_data &&
		    (msgdsize(epp->ep_data) >= epp->ep_buf_limit)) {
			mblk_t *mp = NULL;

			/* exceed buf lenth limit, remove the oldest one */
			USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
			    "ugen_epx_isoc_IN_req_cb: overflow!");
			mp = unlinkb(epp->ep_data);
			if (epp->ep_data) {
				freeb(epp->ep_data);
			}
			epp->ep_data = mp;
		}

	}

	if (reqp->isoc_completion_reason && epp->ep_bp) {
		bioerror(epp->ep_bp, EIO);
		epp->ep_done++;
		cv_signal(&epp->ep_wait_cv);

	} else if (epp->ep_data && epp->ep_bp && !epp->ep_done) {
		boolean_t wait;

		/* can we satisfy the read now */
		if ((ugen_epx_isoc_IN_req(ugenp, epp, epp->ep_bp, &wait) ==
		    USB_SUCCESS) && (wait == B_FALSE)) {
			epp->ep_done++;
			cv_signal(&epp->ep_wait_cv);
		}
	}
	mutex_exit(&epp->ep_mutex);

done:

	usb_free_isoc_req(reqp);
}

/*
 * handle isoc OUT xfers or init isoc IN polling
 */
static int
ugen_epx_isoc_OUT_req(ugen_state_t *ugenp, ugen_ep_t *epp,
    struct buf *bp, boolean_t *wait)
{
	int rval = USB_SUCCESS;
	usb_isoc_req_t *reqp;
	ugen_isoc_pkt_descr_t *pkt_descr;
	ushort_t pkt, n_pkt = 0;
	uint_t pkts_len = 0;
	uint_t head_len;
	char *p;
	ugen_isoc_req_head_t *pkth;

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epx_isoc_OUT_req: epp=0x%p state=0x%x bp=0x%p",
	    (void *)epp, epp->ep_state, (void *)bp);

	*wait = B_FALSE;

	if (bp->b_bcount < sizeof (int)) {
		epp->ep_lcmd_status = USB_LC_STAT_INVALID_REQ;
		rval = USB_INVALID_REQUEST;

		goto done;
	}

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	pkth = (ugen_isoc_req_head_t *)bp->b_un.b_addr;
	n_pkt = pkth->req_isoc_pkts_count;
	head_len = sizeof (ugen_isoc_pkt_descr_t) * n_pkt +
	    sizeof (int);

	if ((n_pkt == 0) ||
	    (n_pkt > usb_get_max_pkts_per_isoc_request(ugenp->ug_dip)) ||
	    (bp->b_bcount < head_len)) {
		USB_DPRINTF_L2(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
		    "Invalid params: bcount=%lu, head_len=%d, pktcnt=%d",
		    bp->b_bcount, head_len, n_pkt);

		epp->ep_lcmd_status = USB_LC_STAT_INVALID_REQ;
		rval = USB_INVALID_REQUEST;

		goto done;
	}

	p = bp->b_un.b_addr;
	p += sizeof (int); /* points to pkt_descrs */

	pkt_descr = kmem_zalloc(sizeof (ugen_isoc_pkt_descr_t) * n_pkt,
	    KM_NOSLEEP);
	if (pkt_descr == NULL) {
		epp->ep_lcmd_status = USB_LC_STAT_NO_RESOURCES;
		rval = USB_NO_RESOURCES;

		goto done;
	}
	bcopy(p, pkt_descr, sizeof (ugen_isoc_pkt_descr_t) * n_pkt);
	p += sizeof (ugen_isoc_pkt_descr_t) * n_pkt;

	/* total packet payload length */
	for (pkt = 0; pkt < n_pkt; pkt++) {
		pkts_len += pkt_descr[pkt].dsc_isoc_pkt_len;
	}

	/*
	 * write length may either be header length for isoc IN endpoint or
	 * the sum of header and data pkts length for isoc OUT endpoint
	 */
	if (((bp->b_bcount != head_len) &&
	    (bp->b_bcount != head_len + pkts_len))) {
		USB_DPRINTF_L2(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
		    "invalid length: bcount=%lu, head_len=%d, pkts_len = %d,"
		    "pktcnt=%d", bp->b_bcount, head_len, pkts_len, n_pkt);

		epp->ep_lcmd_status = USB_LC_STAT_INVALID_REQ;
		kmem_free(pkt_descr, sizeof (ugen_isoc_pkt_descr_t) * n_pkt);
		rval = USB_INVALID_REQUEST;

		goto done;
	}


	ASSERT(epp->ep_state & UGEN_EP_STATE_XS_OPEN);

	/* Set parameters for READ */
	if (bp->b_bcount == head_len) {
		/* must be isoc IN endpoint */
		if ((UGEN_XFER_DIR(epp) & USB_EP_DIR_IN) == 0) {
			epp->ep_lcmd_status = USB_LC_STAT_INVALID_REQ;
			kmem_free(pkt_descr, sizeof (ugen_isoc_pkt_descr_t) *
			    n_pkt);
			rval = USB_INVALID_REQUEST;
			USB_DPRINTF_L2(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
			    "write length invalid for OUT ep%x",
			    epp->ep_descr.bEndpointAddress);

			goto done;
		}

		if (epp->ep_isoc_in_inited) {
			epp->ep_lcmd_status = USB_LC_STAT_INVALID_REQ;
			kmem_free(pkt_descr, sizeof (ugen_isoc_pkt_descr_t) *
			    n_pkt);
			rval = USB_INVALID_REQUEST;
			USB_DPRINTF_L2(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
			    "isoc IN polling fail: already inited, need to"
			    "close the ep before initing again");

			goto done;
		}

		/* save pkts info for the READ */
		epp->ep_isoc_info.isoc_pkts_count = n_pkt;
		epp->ep_isoc_info.isoc_pkts_length = pkts_len;
		epp->ep_isoc_info.isoc_pkt_descr = pkt_descr;

		if ((rval = ugen_epx_isoc_IN_start_polling(ugenp,
		    epp)) != USB_SUCCESS) {
			epp->ep_lcmd_status =
			    USB_LC_STAT_ISOC_POLLING_FAILED;
			kmem_free(pkt_descr, sizeof (ugen_isoc_pkt_descr_t) *
			    n_pkt);
			epp->ep_isoc_info.isoc_pkts_count = 0;
			epp->ep_isoc_info.isoc_pkts_length = 0;
			epp->ep_isoc_info.isoc_pkt_descr = NULL;

			USB_DPRINTF_L2(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
			    "isoc IN start polling failed");

			goto done;
		}

		epp->ep_bp->b_resid = epp->ep_bp->b_bcount - head_len;

		epp->ep_isoc_in_inited++;
		USB_DPRINTF_L3(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
		    "isoc IN ep inited");

		goto done;
	}

	/* must be isoc OUT endpoint */
	if (UGEN_XFER_DIR(epp) & USB_EP_DIR_IN) {
		epp->ep_lcmd_status = USB_LC_STAT_INVALID_REQ;
		kmem_free(pkt_descr, sizeof (ugen_isoc_pkt_descr_t) * n_pkt);
		rval = USB_INVALID_REQUEST;
		USB_DPRINTF_L2(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
		    "write length invalid for an IN ep%x",
		    epp->ep_descr.bEndpointAddress);

		goto done;
	}

	/* OUT endpoint, free previous info if there's any */
	if (epp->ep_isoc_info.isoc_pkt_descr) {
		kmem_free(epp->ep_isoc_info.isoc_pkt_descr,
		    sizeof (ugen_isoc_pkt_descr_t) *
		    epp->ep_isoc_info.isoc_pkts_count);
	}

	/* save pkts info for the WRITE */
	epp->ep_isoc_info.isoc_pkts_count = n_pkt;
	epp->ep_isoc_info.isoc_pkts_length = pkts_len;
	epp->ep_isoc_info.isoc_pkt_descr = pkt_descr;

	reqp = usb_alloc_isoc_req(ugenp->ug_dip, n_pkt, pkts_len,
	    USB_FLAGS_NOSLEEP);
	if (reqp == NULL) {
		epp->ep_lcmd_status = USB_LC_STAT_NO_RESOURCES;
		kmem_free(pkt_descr, sizeof (ugen_isoc_pkt_descr_t) * n_pkt);
		rval = USB_NO_RESOURCES;
		epp->ep_isoc_info.isoc_pkts_count = 0;
		epp->ep_isoc_info.isoc_pkts_length = 0;
		epp->ep_isoc_info.isoc_pkt_descr = NULL;

		USB_DPRINTF_L2(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
		    "alloc isoc out req failed");
		goto done;
	}

	for (pkt = 0; pkt < n_pkt; pkt++) {
		reqp->isoc_pkt_descr[pkt].isoc_pkt_length =
		    pkt_descr[pkt].dsc_isoc_pkt_len;
	}
	reqp->isoc_pkts_count = n_pkt;
	reqp->isoc_client_private = (usb_opaque_t)ugenp;
	reqp->isoc_attributes	= USB_ATTRS_AUTOCLEARING |
	    USB_ATTRS_ISOC_XFER_ASAP;

	reqp->isoc_cb		= ugen_epx_isoc_OUT_req_cb;
	reqp->isoc_exc_cb	= ugen_epx_isoc_OUT_req_cb;

	/* copy data from bp */
	bcopy(p, reqp->isoc_data->b_wptr, pkts_len);
	reqp->isoc_data->b_wptr += pkts_len;

	mutex_exit(&epp->ep_mutex);
	if ((rval = usb_pipe_isoc_xfer(epp->ep_ph, reqp,
	    USB_FLAGS_NOSLEEP)) != USB_SUCCESS) {
		mutex_enter(&epp->ep_mutex);
		epp->ep_lcmd_status =
		    ugen_cr2lcstat(reqp->isoc_completion_reason);
		usb_free_isoc_req(reqp);
		kmem_free(pkt_descr, sizeof (ugen_isoc_pkt_descr_t) * n_pkt);

		epp->ep_isoc_info.isoc_pkt_descr = NULL;
		epp->ep_isoc_info.isoc_pkts_count = 0;
		epp->ep_isoc_info.isoc_pkts_length = 0;

		USB_DPRINTF_L2(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
		    "isoc out xfer failed");

		bioerror(bp, EIO);
	} else {
		mutex_enter(&epp->ep_mutex);
	}
	*wait = (rval == USB_SUCCESS) ? B_TRUE : B_FALSE;

done:
	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epx_isoc_OUT_req end: rval=%d bcount=%lu xfer_len=%d",
	    rval, bp->b_bcount, pkts_len);

	return (rval);
}


/*
 * callback functions for isoc OUT pipe
 */
static void
ugen_epx_isoc_OUT_req_cb(usb_pipe_handle_t ph, usb_isoc_req_t *reqp)
{
	ugen_state_t *ugenp = (ugen_state_t *)reqp->isoc_client_private;
	ugen_ep_t *epp = (ugen_ep_t *)usb_pipe_get_private(ph);

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_epx_isoc_OUT_req_cb: ph=0x%p reqp=0x%p cr=%d cb=0x%x",
	    (void *)ph, (void *)reqp, reqp->isoc_completion_reason,
	    reqp->isoc_cb_flags);

	/* epp might be NULL if we are closing the pipe */
	if (epp) {
		ugen_isoc_pkt_info_t info;

		mutex_enter(&epp->ep_mutex);

		info = epp->ep_isoc_info;
		if (epp->ep_bp) {
			int len, i;
			int headlen;
			usb_isoc_pkt_descr_t *pktdesc;

			pktdesc = reqp->isoc_pkt_descr;
			headlen = info.isoc_pkts_count *
			    sizeof (ugen_isoc_pkt_descr_t);

			len = min(headlen + MBLKL(reqp->isoc_data),
			    epp->ep_bp->b_bcount);

			epp->ep_bp->b_resid = epp->ep_bp->b_bcount - len;


			switch (reqp->isoc_completion_reason) {
			case USB_CR_OK:

				epp->ep_lcmd_status = USB_LC_STAT_NOERROR;

				for (i = 0; i < reqp->isoc_pkts_count; i++) {
					pktdesc[i].isoc_pkt_status =
					    ugen_cr2lcstat(pktdesc[i].
					    isoc_pkt_status);
				}

				/* save the status info */
				bcopy(reqp->isoc_pkt_descr,
				    info.isoc_pkt_descr,
				    (sizeof (ugen_isoc_pkt_descr_t) *
				    info.isoc_pkts_count));

				break;
			case USB_CR_PIPE_RESET:

				break;
			default:
				epp->ep_lcmd_status =
				    ugen_cr2lcstat(
				    reqp->isoc_completion_reason);
				bioerror(epp->ep_bp, EIO);
			}
		}
		epp->ep_done++;
		cv_signal(&epp->ep_wait_cv);
		mutex_exit(&epp->ep_mutex);
	}

	usb_free_isoc_req(reqp);
}


/*
 * Endpoint status node management
 *
 * open/close an endpoint status node.
 *
 * Return values: errno
 */
static int
ugen_eps_open(ugen_state_t *ugenp, dev_t dev, int flag)
{
	ugen_ep_t *epp = &ugenp->ug_ep[UGEN_MINOR_EPIDX(ugenp, dev)];
	int rval = EBUSY;

	mutex_enter(&epp->ep_mutex);
	USB_DPRINTF_L4(UGEN_PRINT_STAT, ugenp->ug_log_hdl,
	    "ugen_eps_open: dev=0x%lx flag=0x%x state=0x%x",
	    dev, flag, epp->ep_state);

	ASSERT(epp->ep_state & UGEN_EP_STATE_ACTIVE);

	/* only one open at the time */
	if ((epp->ep_state & UGEN_EP_STATE_STAT_OPEN) == 0) {
		epp->ep_state |= UGEN_EP_STATE_STAT_OPEN;
		epp->ep_stat_oflag = flag;
		rval = 0;
	}
	mutex_exit(&epp->ep_mutex);

	return (rval);
}


/*
 * close endpoint status
 */
static void
ugen_eps_close(ugen_state_t *ugenp, dev_t dev, int flag)
{
	ugen_ep_t *epp = &ugenp->ug_ep[UGEN_MINOR_EPIDX(ugenp, dev)];

	mutex_enter(&epp->ep_mutex);
	USB_DPRINTF_L4(UGEN_PRINT_STAT, ugenp->ug_log_hdl,
	    "ugen_eps_close: dev=0x%lx flag=0x%x state=0x%x",
	    dev, flag, epp->ep_state);

	epp->ep_state &= ~(UGEN_EP_STATE_STAT_OPEN |
	    UGEN_EP_STATE_INTR_IN_POLL_PENDING |
	    UGEN_EP_STATE_ISOC_IN_POLL_PENDING);
	epp->ep_one_xfer = B_FALSE;

	USB_DPRINTF_L4(UGEN_PRINT_STAT, ugenp->ug_log_hdl,
	    "ugen_eps_close: state=0x%x", epp->ep_state);

	ASSERT(epp->ep_state & UGEN_EP_STATE_ACTIVE);
	mutex_exit(&epp->ep_mutex);
}


/*
 * return status info
 *
 * Return values: errno
 */
static int
ugen_eps_req(ugen_state_t *ugenp, struct buf *bp)
{
	ugen_ep_t *epp = &ugenp->ug_ep[UGEN_MINOR_EPIDX(ugenp, bp->b_edev)];

	mutex_enter(&epp->ep_mutex);
	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_eps_req: bp=0x%p lcmd_status=0x%x bcount=%lu",
	    (void *)bp, epp->ep_lcmd_status, bp->b_bcount);

	if (bp->b_flags & B_READ) {
		int len = min(sizeof (epp->ep_lcmd_status), bp->b_bcount);
		if (len) {
			bcopy(&epp->ep_lcmd_status, bp->b_un.b_addr, len);
		}
		bp->b_resid = bp->b_bcount - len;
	} else {
		USB_DPRINTF_L3(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
		    "ugen_eps_req: control=0x%x",
		    *((char *)(bp->b_un.b_addr)));

		if (epp->ep_state & UGEN_EP_STATE_XFER_OPEN) {
			USB_DPRINTF_L2(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
			    "ugen_eps_req: cannot change one xfer mode if "
			    "endpoint is open");

			mutex_exit(&epp->ep_mutex);

			return (EINVAL);
		}

		if ((epp->ep_descr.bmAttributes & USB_EP_ATTR_INTR) &&
		    (epp->ep_descr.bEndpointAddress & USB_EP_DIR_IN)) {
			epp->ep_one_xfer = (*((char *)(bp->b_un.b_addr)) &
			    USB_EP_INTR_ONE_XFER) ? B_TRUE : B_FALSE;
		} else {
			USB_DPRINTF_L2(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
			    "ugen_eps_req: not an interrupt endpoint");

			mutex_exit(&epp->ep_mutex);

			return (EINVAL);
		}

		bp->b_resid = bp->b_bcount - 1;
	}
	mutex_exit(&epp->ep_mutex);

	return (0);
}


/*
 * device status node management
 */
static int
ugen_ds_init(ugen_state_t *ugenp)
{
	cv_init(&ugenp->ug_ds.dev_wait_cv, NULL, CV_DRIVER, NULL);

	/* Create devstat minor node for this instance */
	if (ugen_ds_minor_nodes_create(ugenp) != USB_SUCCESS) {
		USB_DPRINTF_L2(UGEN_PRINT_ATTA, ugenp->ug_log_hdl,
		    "ugen_create_dev_stat_minor_nodes failed");

		return (USB_FAILURE);
	}


	return (USB_SUCCESS);
}


static void
ugen_ds_destroy(ugen_state_t *ugenp)
{
	cv_destroy(&ugenp->ug_ds.dev_wait_cv);
}


/*
 * open devstat minor node
 *
 * Return values: errno
 */
static int
ugen_ds_open(ugen_state_t *ugenp, dev_t dev, int flag)
{
	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_ds_open: dev=0x%lx flag=0x%x", dev, flag);

	mutex_enter(&ugenp->ug_mutex);
	if ((ugenp->ug_ds.dev_stat & UGEN_DEV_STATUS_ACTIVE) == 0) {
		/*
		 * first read on device node should return status
		 */
		ugenp->ug_ds.dev_stat |= UGEN_DEV_STATUS_CHANGED |
		    UGEN_DEV_STATUS_ACTIVE;
		ugenp->ug_ds.dev_oflag = flag;
		mutex_exit(&ugenp->ug_mutex);

		return (0);
	} else {
		mutex_exit(&ugenp->ug_mutex);

		return (EBUSY);
	}
}


static void
ugen_ds_close(ugen_state_t *ugenp, dev_t dev, int flag)
{
	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_ds_close: dev=0x%lx flag=0x%x", dev, flag);

	mutex_enter(&ugenp->ug_mutex);
	ugenp->ug_ds.dev_stat = UGEN_DEV_STATUS_INACTIVE;
	mutex_exit(&ugenp->ug_mutex);
}


/*
 * request for devstat
 *
 * Return values: errno
 */
static int
ugen_ds_req(ugen_state_t *ugenp, struct buf *bp)
{
	int len = min(sizeof (ugenp->ug_ds.dev_state), bp->b_bcount);

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_ds_req: bp=0x%p", (void *)bp);

	mutex_enter(&ugenp->ug_mutex);
	if ((ugenp->ug_ds.dev_oflag & (FNDELAY | FNONBLOCK)) == 0) {
		while ((ugenp->ug_ds.dev_stat &
		    UGEN_DEV_STATUS_CHANGED) == 0) {
			if (cv_wait_sig(&ugenp->ug_ds.dev_wait_cv,
			    &ugenp->ug_mutex) <= 0) {
				mutex_exit(&ugenp->ug_mutex);

				return (EINTR);
			}
		}
	} else if ((ugenp->ug_ds.dev_stat & UGEN_DEV_STATUS_CHANGED) ==
	    0) {
		bp->b_resid = bp->b_bcount;
		mutex_exit(&ugenp->ug_mutex);

		return (0);
	}

	ugenp->ug_ds.dev_stat &= ~UGEN_DEV_STATUS_CHANGED;
	switch (ugenp->ug_dev_state) {
	case USB_DEV_ONLINE:
		ugenp->ug_ds.dev_state = USB_DEV_STAT_ONLINE;

		break;
	case USB_DEV_DISCONNECTED:
		ugenp->ug_ds.dev_state = USB_DEV_STAT_DISCONNECTED;

		break;
	case USB_DEV_SUSPENDED:
	case USB_UGEN_DEV_UNAVAILABLE_RESUME:
		ugenp->ug_ds.dev_state = USB_DEV_STAT_RESUMED;

		break;
	case USB_UGEN_DEV_UNAVAILABLE_RECONNECT:
	default:
		ugenp->ug_ds.dev_state = USB_DEV_STAT_UNAVAILABLE;

		break;
	}

	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_ds_req: dev_state=0x%x dev_stat=0x%x",
	    ugenp->ug_dev_state, ugenp->ug_ds.dev_stat);

	bcopy(&ugenp->ug_ds.dev_state, bp->b_un.b_addr, len);
	bp->b_resid = bp->b_bcount - len;

	mutex_exit(&ugenp->ug_mutex);

	return (0);
}


static void
ugen_ds_change(ugen_state_t *ugenp)
{
	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_ds_change:");

	ugenp->ug_ds.dev_stat |= UGEN_DEV_STATUS_CHANGED;
	cv_signal(&ugenp->ug_ds.dev_wait_cv);
}


/*
 * poll management
 */
static void
ugen_ds_poll_wakeup(ugen_state_t *ugenp)
{
	USB_DPRINTF_L4(UGEN_PRINT_XFER, ugenp->ug_log_hdl,
	    "ugen_ds_poll_wakeup:");

	if (ugenp->ug_ds.dev_stat & UGEN_DEV_STATUS_POLL_PENDING) {
		struct pollhead *phpp = &ugenp->ug_ds.dev_pollhead;
		ugenp->ug_ds.dev_stat &= ~UGEN_DEV_STATUS_POLL_PENDING;
		mutex_exit(&ugenp->ug_mutex);
		pollwakeup(phpp, POLLIN);
		mutex_enter(&ugenp->ug_mutex);
	}
}


/*
 * minor node management:
 */
static int
ugen_ds_minor_nodes_create(ugen_state_t *ugenp)
{
	char	node_name[32];
	int	vid = ugenp->ug_dev_data->dev_descr->idVendor;
	int	pid = ugenp->ug_dev_data->dev_descr->idProduct;
	minor_t	minor;
	int	minor_index;
	int	owns_device = (usb_owns_device(ugenp->ug_dip) ?
	    UGEN_OWNS_DEVICE : 0);

	USB_DPRINTF_L4(UGEN_PRINT_CBOPS, ugenp->ug_log_hdl,
	    "ugen_ds_minor_nodes_create: idx shift=%d inst shift=%d",
	    UGEN_MINOR_IDX_SHIFT(ugenp),
	    UGEN_MINOR_INSTANCE_SHIFT(ugenp));

	if (ugenp->ug_instance >= UGEN_MINOR_INSTANCE_LIMIT(ugenp)) {
		USB_DPRINTF_L0(UGEN_PRINT_CBOPS, ugenp->ug_log_hdl,
		    "instance number too high (%d)", ugenp->ug_instance);

		return (USB_FAILURE);
	}

	/* create devstat minor node */
	if (owns_device) {
		(void) sprintf(node_name, "%x.%x.devstat", vid, pid);
	} else {
		(void) sprintf(node_name, "%x.%x.if%ddevstat", vid, pid,
		    ugenp->ug_dev_data->dev_curr_if);
	}

	minor_index = ugen_minor_index_create(ugenp,
	    (UGEN_MINOR_DEV_STAT_NODE | owns_device) <<
	    UGEN_MINOR_IDX_SHIFT(ugenp));

	if (minor_index < 0) {
		USB_DPRINTF_L0(UGEN_PRINT_CBOPS, ugenp->ug_log_hdl,
		    "too many minor nodes");

		return (USB_FAILURE);
	}
	minor = (minor_index << UGEN_MINOR_IDX_SHIFT(ugenp)) |
	    ugenp->ug_instance << UGEN_MINOR_INSTANCE_SHIFT(ugenp);

	USB_DPRINTF_L4(UGEN_PRINT_CBOPS, ugenp->ug_log_hdl,
	    "minor=0x%x minor_index=%d name=%s",
	    minor, minor_index, node_name);

	ASSERT(minor < L_MAXMIN);

	if ((ddi_create_minor_node(ugenp->ug_dip, node_name,
	    S_IFCHR, minor, DDI_NT_UGEN, 0)) != DDI_SUCCESS) {

		return (USB_FAILURE);
	}

	ugen_store_devt(ugenp, minor);

	return (USB_SUCCESS);
}


/*
 * utility functions:
 *
 * conversion from completion reason to  USB_LC_STAT_*
 */
static struct ugen_cr2lcstat_entry {
	int	cr;
	int	lcstat;
} ugen_cr2lcstat_table[] = {
	{ USB_CR_OK,			USB_LC_STAT_NOERROR	},
	{ USB_CR_CRC,			USB_LC_STAT_CRC		},
	{ USB_CR_BITSTUFFING,		USB_LC_STAT_BITSTUFFING },
	{ USB_CR_DATA_TOGGLE_MM,	USB_LC_STAT_DATA_TOGGLE_MM },
	{ USB_CR_STALL,			USB_LC_STAT_STALL	},
	{ USB_CR_DEV_NOT_RESP,		USB_LC_STAT_DEV_NOT_RESP },
	{ USB_CR_PID_CHECKFAILURE,	USB_LC_STAT_PID_CHECKFAILURE },
	{ USB_CR_UNEXP_PID,		USB_LC_STAT_UNEXP_PID	},
	{ USB_CR_DATA_OVERRUN,		USB_LC_STAT_DATA_OVERRUN },
	{ USB_CR_DATA_UNDERRUN,		USB_LC_STAT_DATA_UNDERRUN },
	{ USB_CR_BUFFER_OVERRUN,	USB_LC_STAT_BUFFER_OVERRUN },
	{ USB_CR_BUFFER_UNDERRUN,	USB_LC_STAT_BUFFER_UNDERRUN },
	{ USB_CR_TIMEOUT,		USB_LC_STAT_TIMEOUT	},
	{ USB_CR_NOT_ACCESSED,		USB_LC_STAT_NOT_ACCESSED },
	{ USB_CR_NO_RESOURCES,		USB_LC_STAT_NO_BANDWIDTH },
	{ USB_CR_UNSPECIFIED_ERR,	USB_LC_STAT_UNSPECIFIED_ERR },
	{ USB_CR_STOPPED_POLLING,	USB_LC_STAT_HW_ERR	},
	{ USB_CR_PIPE_CLOSING,		USB_LC_STAT_UNSPECIFIED_ERR	},
	{ USB_CR_PIPE_RESET,		USB_LC_STAT_UNSPECIFIED_ERR	},
	{ USB_CR_NOT_SUPPORTED,		USB_LC_STAT_UNSPECIFIED_ERR },
	{ USB_CR_FLUSHED,		USB_LC_STAT_UNSPECIFIED_ERR }
};

#define	UGEN_CR2LCSTAT_TABLE_SIZE (sizeof (ugen_cr2lcstat_table) / \
			sizeof (struct ugen_cr2lcstat_entry))
static int
ugen_cr2lcstat(int cr)
{
	int i;

	for (i = 0; i < UGEN_CR2LCSTAT_TABLE_SIZE; i++) {
		if (ugen_cr2lcstat_table[i].cr == cr) {

			return (ugen_cr2lcstat_table[i].lcstat);
		}
	}

	return (USB_LC_STAT_UNSPECIFIED_ERR);
}


/*
 * create and lookup minor index
 */
static int
ugen_minor_index_create(ugen_state_t *ugenp, ugen_minor_t minor)
{
	int i;

	/* check if already in the table */
	for (i = 1; i < ugenp->ug_minor_node_table_index; i++) {
		if (ugenp->ug_minor_node_table[i] == minor) {

			return (-1);
		}
	}
	if (ugenp->ug_minor_node_table_index <
	    (ugenp->ug_minor_node_table_size/sizeof (ugen_minor_t))) {
		ugenp->ug_minor_node_table[ugenp->
		    ug_minor_node_table_index] = minor;

		USB_DPRINTF_L4(UGEN_PRINT_ATTA, ugenp->ug_log_hdl,
		    "ugen_minor_index_create: %d: 0x%lx",
		    ugenp->ug_minor_node_table_index,
		    (unsigned long)minor);

		return (ugenp->ug_minor_node_table_index++);
	} else {

		return (-1);
	}
}


static ugen_minor_t
ugen_devt2minor(ugen_state_t *ugenp, dev_t dev)
{
	USB_DPRINTF_L4(UGEN_PRINT_CBOPS, ugenp->ug_log_hdl,
	    "ugen_devt2minor: minorindex=%lu, minor=0x%" PRIx64,
	    UGEN_MINOR_GET_IDX(ugenp, dev),
	    ugenp->ug_minor_node_table[UGEN_MINOR_GET_IDX(ugenp, dev)]);

	ASSERT(UGEN_MINOR_GET_IDX(ugenp, dev) <
	    ugenp->ug_minor_node_table_index);

	return (ugenp->ug_minor_node_table[UGEN_MINOR_GET_IDX(ugenp, dev)]);
}


static int
ugen_is_valid_minor_node(ugen_state_t *ugenp, dev_t dev)
{
	int idx = UGEN_MINOR_GET_IDX(ugenp, dev);

	if ((idx < ugenp->ug_minor_node_table_index) &&
	    (idx > 0)) {

		return (USB_SUCCESS);
	}
	USB_DPRINTF_L2(UGEN_PRINT_CBOPS, ugenp->ug_log_hdl,
	    "ugen_is_valid_minor_node: invalid minorindex=%d", idx);

	return (USB_FAILURE);
}


static void
ugen_minor_node_table_create(ugen_state_t *ugenp)
{
	size_t	size = sizeof (ugen_minor_t) * UGEN_MINOR_IDX_LIMIT(ugenp);

	/* allocate the max table size needed, we reduce later */
	ugenp->ug_minor_node_table = kmem_zalloc(size, KM_SLEEP);
	ugenp->ug_minor_node_table_size = size;
	ugenp->ug_minor_node_table_index = 1;
}


static void
ugen_minor_node_table_shrink(ugen_state_t *ugenp)
{
	/* reduce the table size to save some memory */
	if (ugenp->ug_minor_node_table_index < UGEN_MINOR_IDX_LIMIT(ugenp)) {
		size_t newsize = sizeof (ugen_minor_t) *
		    ugenp->ug_minor_node_table_index;
		ugen_minor_t *buf = kmem_zalloc(newsize, KM_SLEEP);

		bcopy(ugenp->ug_minor_node_table, buf, newsize);
		kmem_free(ugenp->ug_minor_node_table,
		    ugenp->ug_minor_node_table_size);
		ugenp->ug_minor_node_table = buf;
		ugenp->ug_minor_node_table_size = newsize;
	}
}


static void
ugen_minor_node_table_destroy(ugen_state_t *ugenp)
{
	if (ugenp->ug_minor_node_table) {
		kmem_free(ugenp->ug_minor_node_table,
		    ugenp->ug_minor_node_table_size);
	}
}


static void
ugen_check_mask(uint_t mask, uint_t *shift, uint_t *limit)
{
	uint_t i, j;

	for (i = 0; i < UGEN_MINOR_NODE_SIZE; i++) {
		if ((1 << i)  & mask) {

			break;
		}
	}

	for (j = i; j < UGEN_MINOR_NODE_SIZE; j++) {
		if (((1 << j) & mask) == 0) {

			break;
		}
	}

	*limit = (i == j) ? 0 : 1 << (j - i);
	*shift = i;
}



/*
 * power management:
 *
 * ugen_pm_init:
 *	Initialize power management and remote wakeup functionality.
 *	No mutex is necessary in this function as it's called only by attach.
 */
static void
ugen_pm_init(ugen_state_t *ugenp)
{
	dev_info_t	*dip = ugenp->ug_dip;
	ugen_power_t	*ugenpm;

	USB_DPRINTF_L4(UGEN_PRINT_PM, ugenp->ug_log_hdl,
	    "ugen_pm_init:");

	/* Allocate the state structure */
	ugenpm = kmem_zalloc(sizeof (ugen_power_t), KM_SLEEP);

	mutex_enter(&ugenp->ug_mutex);
	ugenp->ug_pm = ugenpm;
	ugenpm->pwr_wakeup_enabled = B_FALSE;
	ugenpm->pwr_current = USB_DEV_OS_FULL_PWR;
	mutex_exit(&ugenp->ug_mutex);

	/*
	 * If remote wakeup is not available you may not want to do
	 * power management.
	 */
	if (ugen_enable_pm || usb_handle_remote_wakeup(dip,
	    USB_REMOTE_WAKEUP_ENABLE) == USB_SUCCESS) {
		if (usb_create_pm_components(dip,
		    &ugenpm->pwr_states) == USB_SUCCESS) {
			USB_DPRINTF_L4(UGEN_PRINT_PM,
			    ugenp->ug_log_hdl,
			    "ugen_pm_init: "
			    "created PM components");

			mutex_enter(&ugenp->ug_mutex);
			ugenpm->pwr_wakeup_enabled = B_TRUE;
			mutex_exit(&ugenp->ug_mutex);

			if (pm_raise_power(dip, 0,
			    USB_DEV_OS_FULL_PWR) != DDI_SUCCESS) {
				USB_DPRINTF_L2(UGEN_PRINT_PM,
				    ugenp->ug_log_hdl,
				    "ugen_pm_init: "
				    "raising power failed");
			}
		} else {
			USB_DPRINTF_L2(UGEN_PRINT_PM,
			    ugenp->ug_log_hdl,
			    "ugen_pm_init: "
			    "create_pm_comps failed");
		}
	} else {
		USB_DPRINTF_L2(UGEN_PRINT_PM,
		    ugenp->ug_log_hdl, "ugen_pm_init: "
		    "failure enabling remote wakeup");
	}

	USB_DPRINTF_L4(UGEN_PRINT_PM, ugenp->ug_log_hdl,
	    "ugen_pm_init: end");
}


/*
 * ugen_pm_destroy:
 *	Shut down and destroy power management and remote wakeup functionality.
 */
static void
ugen_pm_destroy(ugen_state_t *ugenp)
{
	dev_info_t *dip = ugenp->ug_dip;

	USB_DPRINTF_L4(UGEN_PRINT_PM, ugenp->ug_log_hdl,
	    "ugen_pm_destroy:");

	if (ugenp->ug_pm) {
		mutex_exit(&ugenp->ug_mutex);
		ugen_pm_busy_component(ugenp);
		mutex_enter(&ugenp->ug_mutex);

		if ((ugenp->ug_pm->pwr_wakeup_enabled) &&
		    (ugenp->ug_dev_state != USB_DEV_DISCONNECTED)) {
			int rval;

			mutex_exit(&ugenp->ug_mutex);
			(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);

			if ((rval = usb_handle_remote_wakeup(dip,
			    USB_REMOTE_WAKEUP_DISABLE)) != USB_SUCCESS) {
				USB_DPRINTF_L4(UGEN_PRINT_PM,
				    ugenp->ug_log_hdl, "ugen_pm_destroy: "
				    "disabling rmt wakeup: rval=%d", rval);
			}
			/*
			 * Since remote wakeup is disabled now,
			 * no one can raise power
			 * and get to device once power is lowered here.
			 */
		} else {
			mutex_exit(&ugenp->ug_mutex);
		}
		(void) pm_lower_power(dip, 0, USB_DEV_OS_PWR_OFF);
		ugen_pm_idle_component(ugenp);

		mutex_enter(&ugenp->ug_mutex);
		kmem_free(ugenp->ug_pm, sizeof (ugen_power_t));
		ugenp->ug_pm = NULL;
	}
}


/*
 * ugen_power :
 *	Power entry point, the workhorse behind pm_raise_power, pm_lower_power,
 *	usb_req_raise_power and usb_req_lower_power.
 */
/*ARGSUSED*/
int
usb_ugen_power(usb_ugen_hdl_t usb_ugen_hdl, int comp, int level)
{
	ugen_power_t		*pm;
	int			rval = USB_FAILURE;
	usb_ugen_hdl_impl_t	*usb_ugen_hdl_impl =
	    (usb_ugen_hdl_impl_t *)usb_ugen_hdl;
	ugen_state_t		*ugenp;
	dev_info_t		*dip;

	if (usb_ugen_hdl == NULL) {

		return (USB_FAILURE);
	}

	ugenp = usb_ugen_hdl_impl->hdl_ugenp;
	dip = ugenp->ug_dip;

	if (ugenp->ug_pm == NULL) {

		return (USB_SUCCESS);
	}

	USB_DPRINTF_L4(UGEN_PRINT_PM, ugenp->ug_log_hdl,
	    "usb_ugen_power: level=%d", level);

	(void) usb_serialize_access(ugenp->ug_ser_cookie,
	    USB_WAIT, 0);
	/*
	 * If we are disconnected/suspended, return success. Note that if we
	 * return failure, bringing down the system will hang when
	 * PM tries to power up all devices
	 */
	mutex_enter(&ugenp->ug_mutex);
	switch (ugenp->ug_dev_state) {
	case USB_DEV_ONLINE:

		break;
	case USB_DEV_DISCONNECTED:
	case USB_DEV_SUSPENDED:
	case USB_UGEN_DEV_UNAVAILABLE_RESUME:
	case USB_UGEN_DEV_UNAVAILABLE_RECONNECT:
	default:
		USB_DPRINTF_L2(UGEN_PRINT_PM, ugenp->ug_log_hdl,
		    "ugen_power: disconnected/suspended "
		    "dev_state=%d", ugenp->ug_dev_state);
		rval = USB_SUCCESS;

		goto done;
	}

	pm = ugenp->ug_pm;

	/* Check if we are transitioning to a legal power level */
	if (USB_DEV_PWRSTATE_OK(pm->pwr_states, level)) {
		USB_DPRINTF_L2(UGEN_PRINT_PM, ugenp->ug_log_hdl,
		    "ugen_power: illegal power level=%d "
		    "pwr_states: 0x%x", level, pm->pwr_states);

		goto done;
	}

	switch (level) {
	case USB_DEV_OS_PWR_OFF :
		switch (ugenp->ug_dev_state) {
		case USB_DEV_ONLINE:
			/* Deny the powerdown request if the device is busy */
			if (ugenp->ug_pm->pwr_busy != 0) {

				break;
			}
			ASSERT(ugenp->ug_open_count == 0);
			ASSERT(ugenp->ug_pending_cmds == 0);
			ugenp->ug_pm->pwr_current = USB_DEV_OS_PWR_OFF;
			mutex_exit(&ugenp->ug_mutex);

			/* Issue USB D3 command to the device here */
			rval = usb_set_device_pwrlvl3(dip);
			mutex_enter(&ugenp->ug_mutex);

			break;
		default:
			rval = USB_SUCCESS;

			break;
		}
		break;
	case USB_DEV_OS_FULL_PWR :
		/*
		 * PM framework tries to put us in full power during system
		 * shutdown.
		 */
		switch (ugenp->ug_dev_state) {
		case USB_UGEN_DEV_UNAVAILABLE_RESUME:
		case USB_UGEN_DEV_UNAVAILABLE_RECONNECT:

			break;
		default:
			ugenp->ug_dev_state = USB_DEV_ONLINE;

			/* wakeup devstat reads and polls */
			ugen_ds_change(ugenp);
			ugen_ds_poll_wakeup(ugenp);

			break;
		}
		ugenp->ug_pm->pwr_current = USB_DEV_OS_FULL_PWR;
		mutex_exit(&ugenp->ug_mutex);
		rval = usb_set_device_pwrlvl0(dip);
		mutex_enter(&ugenp->ug_mutex);

		break;
	default:
		/* Levels 1 and 2 are not supported to keep it simple. */
		USB_DPRINTF_L2(UGEN_PRINT_PM, ugenp->ug_log_hdl,
		    "ugen_power: power level %d not supported", level);

		break;
	}
done:
	mutex_exit(&ugenp->ug_mutex);
	usb_release_access(ugenp->ug_ser_cookie);

	return (rval);
}


static void
ugen_pm_busy_component(ugen_state_t *ugen_statep)
{
	ASSERT(!mutex_owned(&ugen_statep->ug_mutex));

	if (ugen_statep->ug_pm != NULL) {
		mutex_enter(&ugen_statep->ug_mutex);
		ugen_statep->ug_pm->pwr_busy++;

		USB_DPRINTF_L4(UGEN_PRINT_PM, ugen_statep->ug_log_hdl,
		    "ugen_pm_busy_component: %d", ugen_statep->ug_pm->pwr_busy);

		mutex_exit(&ugen_statep->ug_mutex);
		if (pm_busy_component(ugen_statep->ug_dip, 0) != DDI_SUCCESS) {
			mutex_enter(&ugen_statep->ug_mutex);
			ugen_statep->ug_pm->pwr_busy--;

			USB_DPRINTF_L2(UGEN_PRINT_PM, ugen_statep->ug_log_hdl,
			    "ugen_pm_busy_component failed: %d",
			    ugen_statep->ug_pm->pwr_busy);

			mutex_exit(&ugen_statep->ug_mutex);
		}
	}
}


static void
ugen_pm_idle_component(ugen_state_t *ugen_statep)
{
	ASSERT(!mutex_owned(&ugen_statep->ug_mutex));

	if (ugen_statep->ug_pm != NULL) {
		if (pm_idle_component(ugen_statep->ug_dip, 0) == DDI_SUCCESS) {
			mutex_enter(&ugen_statep->ug_mutex);
			ASSERT(ugen_statep->ug_pm->pwr_busy > 0);
			ugen_statep->ug_pm->pwr_busy--;

			USB_DPRINTF_L4(UGEN_PRINT_PM, ugen_statep->ug_log_hdl,
			    "ugen_pm_idle_component: %d",
			    ugen_statep->ug_pm->pwr_busy);

			mutex_exit(&ugen_statep->ug_mutex);
		}
	}
}


/*
 * devt lookup support
 *	In ugen_strategy and ugen_minphys, we only have the devt and need
 *	the ugen_state pointer. Since we don't know instance mask, we can't
 *	easily derive a softstate pointer. Therefore, we use a list
 */
static void
ugen_store_devt(ugen_state_t *ugenp, minor_t minor)
{
	ugen_devt_list_entry_t *e = kmem_zalloc(
	    sizeof (ugen_devt_list_entry_t), KM_SLEEP);
	ugen_devt_list_entry_t *t;

	mutex_enter(&ugen_devt_list_mutex);
	e->list_dev = makedevice(ddi_driver_major(ugenp->ug_dip), minor);
	e->list_state = ugenp;

	t = ugen_devt_list.list_next;

	/* check if the entry is already in the list */
	while (t) {
		ASSERT(t->list_dev != e->list_dev);
		t = t->list_next;
	}

	/* add to the head of the list */
	e->list_next = ugen_devt_list.list_next;
	if (ugen_devt_list.list_next) {
		ugen_devt_list.list_next->list_prev = e;
	}
	ugen_devt_list.list_next = e;
	mutex_exit(&ugen_devt_list_mutex);
}


static ugen_state_t *
ugen_devt2state(dev_t dev)
{
	ugen_devt_list_entry_t *t;
	ugen_state_t	*ugenp = NULL;
	int		index, count;

	mutex_enter(&ugen_devt_list_mutex);

	for (index = ugen_devt_cache_index, count = 0;
	    count < UGEN_DEVT_CACHE_SIZE; count++) {
		if (ugen_devt_cache[index].cache_dev == dev) {
			ugen_devt_cache[index].cache_hit++;
			ugenp = ugen_devt_cache[index].cache_state;

			mutex_exit(&ugen_devt_list_mutex);

			return (ugenp);
		}
		index++;
		index %= UGEN_DEVT_CACHE_SIZE;
	}

	t = ugen_devt_list.list_next;

	while (t) {
		if (t->list_dev == dev) {
			ugenp = t->list_state;
			ugen_devt_cache_index++;
			ugen_devt_cache_index %= UGEN_DEVT_CACHE_SIZE;
			ugen_devt_cache[ugen_devt_cache_index].cache_dev = dev;
			ugen_devt_cache[ugen_devt_cache_index].cache_state =
			    ugenp;
			mutex_exit(&ugen_devt_list_mutex);

			return (ugenp);
		}
		t = t->list_next;
	}
	mutex_exit(&ugen_devt_list_mutex);

	return (ugenp);
}


static void
ugen_free_devt(ugen_state_t *ugenp)
{
	ugen_devt_list_entry_t *e, *next, *prev;
	major_t		major = ddi_driver_major(ugenp->ug_dip);
	int		instance = ddi_get_instance(ugenp->ug_dip);

	mutex_enter(&ugen_devt_list_mutex);
	prev = &ugen_devt_list;
	for (e = prev->list_next; e != 0; e = next) {
		int i = (getminor(e->list_dev) &
		    ugenp->ug_hdl->hdl_minor_node_instance_mask) >>
		    ugenp->ug_hdl->hdl_minor_node_instance_shift;
		int m = getmajor(e->list_dev);

		next = e->list_next;

		if ((i == instance) && (m == major)) {
			prev->list_next = e->list_next;
			if (e->list_next) {
				e->list_next->list_prev = prev;
			}
			kmem_free(e, sizeof (ugen_devt_list_entry_t));
		} else {
			prev = e;
		}
	}

	bzero(ugen_devt_cache, sizeof (ugen_devt_cache));
	ugen_devt_cache_index = 0;
	mutex_exit(&ugen_devt_list_mutex);
}

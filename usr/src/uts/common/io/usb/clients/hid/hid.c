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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2016 Joyent, Inc.
 */


/*
 * Human Interface Device driver (HID)
 *
 * The HID driver is a software driver which acts as a class
 * driver for USB human input devices like keyboard, mouse,
 * joystick etc and provides the class-specific interfaces
 * between these client driver modules and the Universal Serial
 * Bus Driver(USBA).
 *
 * NOTE: This driver is not DDI compliant in that it uses undocumented
 * functions for logging (USB_DPRINTF_L*, usb_alloc_log_hdl, usb_free_log_hdl).
 *
 * Undocumented functions may go away in a future Solaris OS release.
 *
 * Please see the DDK for sample code of these functions, and for the usbskel
 * skeleton template driver which contains scaled-down versions of these
 * functions written in a DDI-compliant way.
 */

#define	USBDRV_MAJOR_VER	2
#define	USBDRV_MINOR_VER	0

#include <sys/usb/usba.h>
#include <sys/usb/usba/genconsole.h>
#include <sys/usb/clients/hid/hid.h>
#include <sys/usb/clients/hid/hid_polled.h>
#include <sys/usb/clients/hidparser/hidparser.h>
#include <sys/usb/clients/hid/hidvar.h>
#include <sys/usb/clients/hid/hidminor.h>
#include <sys/usb/clients/hidparser/hid_parser_driver.h>
#include <sys/stropts.h>
#include <sys/sunddi.h>
#include <sys/stream.h>
#include <sys/strsun.h>

extern int ddi_create_internal_pathname(dev_info_t *, char *, int, minor_t);

/* Debugging support */
uint_t	hid_errmask	= (uint_t)PRINT_MASK_ALL;
uint_t	hid_errlevel	= USB_LOG_L4;
uint_t	hid_instance_debug = (uint_t)-1;

/* tunables */
int	hid_default_pipe_drain_timeout = HID_DEFAULT_PIPE_DRAIN_TIMEOUT;
int	hid_pm_mouse = 1; /* enable remote_wakeup for USB mouse/keyboard */

/* soft state structures */
#define	HID_INITIAL_SOFT_SPACE	4
static void *hid_statep;

/* Callbacks */
static void hid_interrupt_pipe_callback(usb_pipe_handle_t,
		usb_intr_req_t *);
static void hid_default_pipe_callback(usb_pipe_handle_t, usb_ctrl_req_t *);
static void hid_interrupt_pipe_exception_callback(usb_pipe_handle_t,
		usb_intr_req_t *);
static void hid_default_pipe_exception_callback(usb_pipe_handle_t,
		usb_ctrl_req_t *);
static int hid_restore_state_event_callback(dev_info_t *);
static int hid_disconnect_event_callback(dev_info_t *);
static int hid_cpr_suspend(hid_state_t *hidp);
static void hid_cpr_resume(hid_state_t *hidp);
static void hid_power_change_callback(void *arg, int rval);

/* Supporting routines */
static size_t hid_parse_hid_descr(usb_hid_descr_t *, size_t,
		usb_alt_if_data_t *, usb_ep_data_t *);
static int hid_parse_hid_descr_failure(hid_state_t *);
static int hid_handle_report_descriptor(hid_state_t *, int);
static void hid_set_idle(hid_state_t *);
static void hid_set_protocol(hid_state_t *, int);
static void hid_detach_cleanup(dev_info_t *, hid_state_t *);

static int hid_start_intr_polling(hid_state_t *);
static void hid_close_intr_pipe(hid_state_t *);
static int hid_mctl_execute_cmd(queue_t *, int, hid_req_t *,
		mblk_t *);
static int hid_mctl_receive(queue_t *, mblk_t *);
static int hid_send_async_ctrl_request(hid_default_pipe_arg_t *, hid_req_t *,
		uchar_t, int, ushort_t);

static void hid_create_pm_components(dev_info_t *, hid_state_t *);
static int hid_is_pm_enabled(dev_info_t *);
static void hid_restore_device_state(dev_info_t *, hid_state_t *);
static void hid_save_device_state(hid_state_t *);

static void hid_qreply_merror(queue_t *, mblk_t *, uchar_t);
static mblk_t *hid_data2mblk(uchar_t *, int);
static void hid_flush(queue_t *);

static int hid_pwrlvl0(hid_state_t *);
static int hid_pwrlvl1(hid_state_t *);
static int hid_pwrlvl2(hid_state_t *);
static int hid_pwrlvl3(hid_state_t *);
static void hid_pm_busy_component(hid_state_t *);
static void hid_pm_idle_component(hid_state_t *);

static int hid_polled_read(hid_polled_handle_t, uchar_t **);
static int hid_polled_input_enter(hid_polled_handle_t);
static int hid_polled_input_exit(hid_polled_handle_t);
static int hid_polled_input_init(hid_state_t *);
static int hid_polled_input_fini(hid_state_t *);

/* Streams entry points */
static int	hid_open(queue_t *, dev_t *, int, int, cred_t *);
static int	hid_close(queue_t *, int, cred_t *);
static int	hid_wput(queue_t *, mblk_t *);
static int	hid_wsrv(queue_t *);

/* dev_ops entry points */
static int	hid_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int	hid_attach(dev_info_t *, ddi_attach_cmd_t);
static int	hid_detach(dev_info_t *, ddi_detach_cmd_t);
static int	hid_power(dev_info_t *, int, int);

/*
 * Warlock is not aware of the automatic locking mechanisms for
 * streams drivers.  The hid streams enter points are protected by
 * a per module perimeter.  If the locking in hid is a bottleneck
 * per queue pair or per queue locking may be used.  Since warlock
 * is not aware of the streams perimeters, these notes have been added.
 *
 * Note that the perimeters do not protect the driver from callbacks
 * happening while a streams entry point is executing.	So, the hid_mutex
 * has been created to protect the data.
 */
_NOTE(SCHEME_PROTECTS_DATA("unique per call", iocblk))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", datab))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", msgb))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", queue))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", usb_ctrl_req))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", usb_intr_req))

/* module information */
static struct module_info hid_mod_info = {
	0x0ffff,			/* module id number */
	"hid",				/* module name */
	0,				/* min packet size accepted */
	INFPSZ,				/* max packet size accepted */
	512,				/* hi-water mark */
	128				/* lo-water mark */
};

/* read queue information structure */
static struct qinit rinit = {
	NULL,				/* put procedure not needed */
	NULL,				/* service procedure not needed */
	hid_open,			/* called on startup */
	hid_close,			/* called on finish */
	NULL,				/* for future use */
	&hid_mod_info,			/* module information structure */
	NULL				/* module statistics structure */
};

/* write queue information structure */
static struct qinit winit = {
	hid_wput,			/* put procedure */
	hid_wsrv,			/* service procedure */
	NULL,				/* open not used on write side */
	NULL,				/* close not used on write side */
	NULL,				/* for future use */
	&hid_mod_info,			/* module information structure */
	NULL				/* module statistics structure */
};

struct streamtab hid_streamtab = {
	&rinit,
	&winit,
	NULL,			/* not a MUX */
	NULL			/* not a MUX */
};

struct cb_ops hid_cb_ops = {
	nulldev,		/* open  */
	nulldev,		/* close */
	nulldev,		/* strategy */
	nulldev,		/* print */
	nulldev,		/* dump */
	nulldev,		/* read */
	nulldev,		/* write */
	nulldev,		/* ioctl */
	nulldev,		/* devmap */
	nulldev,		/* mmap */
	nulldev,		/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	&hid_streamtab,		/* streamtab  */
	D_MP | D_MTPERQ
};


static struct dev_ops hid_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	hid_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	hid_attach,		/* attach */
	hid_detach,		/* detach */
	nodev,			/* reset */
	&hid_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	hid_power,		/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv hidmodldrv =	{
	&mod_driverops,
	"USB HID Client Driver",
	&hid_ops			/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&hidmodldrv,
	NULL,
};

static usb_event_t hid_events = {
	hid_disconnect_event_callback,
	hid_restore_state_event_callback,
	NULL,
	NULL,
};


int
_init(void)
{
	int rval;

	if (((rval = ddi_soft_state_init(&hid_statep, sizeof (hid_state_t),
	    HID_INITIAL_SOFT_SPACE)) != 0)) {

		return (rval);
	}

	if ((rval = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&hid_statep);
	}

	return (rval);
}


int
_fini(void)
{
	int rval;

	if ((rval = mod_remove(&modlinkage)) != 0) {

		return (rval);
	}

	ddi_soft_state_fini(&hid_statep);

	return (rval);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * hid_info :
 *	Get minor number, soft state structure etc.
 */
/*ARGSUSED*/
static int
hid_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	hid_state_t	*hidp = NULL;
	int		error = DDI_FAILURE;
	minor_t		minor = getminor((dev_t)arg);
	int		instance = HID_MINOR_TO_INSTANCE(minor);

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((hidp = ddi_get_soft_state(hid_statep, instance)) != NULL) {
			*result = hidp->hid_dip;
			if (*result != NULL) {
				error = DDI_SUCCESS;
			}
		} else
			*result = NULL;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		error = DDI_SUCCESS;
		break;
	default:
		break;
	}

	return (error);
}


/*
 * hid_attach :
 *	Gets called at the time of attach. Do allocation,
 *	and initialization of the software structure.
 *	Get all the descriptors, setup the
 *	report descriptor tree by calling hidparser
 *	function.
 */
static int
hid_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{

	int			instance = ddi_get_instance(dip);
	int			parse_hid_descr_error = 0;
	hid_state_t		*hidp = NULL;
	uint32_t		usage_page;
	uint32_t		usage;
	usb_client_dev_data_t	*dev_data;
	usb_alt_if_data_t	*altif_data;
	char			minor_name[HID_MINOR_NAME_LEN];
	usb_ep_data_t		*ep_data;

	switch (cmd) {
		case DDI_ATTACH:
			break;
		case DDI_RESUME:
			hidp = ddi_get_soft_state(hid_statep, instance);
			hid_cpr_resume(hidp);
			return (DDI_SUCCESS);
		default:

			return (DDI_FAILURE);
	}

	/*
	 * Allocate softstate information and get softstate pointer
	 */
	if (ddi_soft_state_zalloc(hid_statep, instance) == DDI_SUCCESS) {
		hidp = ddi_get_soft_state(hid_statep, instance);
	}
	if (hidp == NULL) {

		goto fail;
	}

	hidp->hid_log_handle = usb_alloc_log_hdl(dip, NULL, &hid_errlevel,
	    &hid_errmask, &hid_instance_debug, 0);

	hidp->hid_instance = instance;
	hidp->hid_dip = dip;

	/*
	 * Register with USBA. Just retrieve interface descriptor
	 */
	if (usb_client_attach(dip, USBDRV_VERSION, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hidp->hid_log_handle,
		    "hid_attach: client attach failed");

		goto fail;
	}

	if (usb_get_dev_data(dip, &dev_data, USB_PARSE_LVL_IF, 0) !=
	    USB_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_ATTA, hidp->hid_log_handle,
		    "hid_attach: usb_get_dev_data() failed");

		goto fail;
	}

	/* initialize mutex */
	mutex_init(&hidp->hid_mutex, NULL, MUTEX_DRIVER,
	    dev_data->dev_iblock_cookie);

	hidp->hid_attach_flags	|= HID_LOCK_INIT;

	/* get interface data for alternate 0 */
	altif_data = &dev_data->dev_curr_cfg->
	    cfg_if[dev_data->dev_curr_if].if_alt[0];

	mutex_enter(&hidp->hid_mutex);
	hidp->hid_dev_data	= dev_data;
	hidp->hid_dev_descr	= dev_data->dev_descr;
	hidp->hid_interfaceno	= dev_data->dev_curr_if;
	hidp->hid_if_descr	= altif_data->altif_descr;
	/*
	 * Make sure that the bInterfaceProtocol only has meaning to
	 * Boot Interface Subclass.
	 */
	if (hidp->hid_if_descr.bInterfaceSubClass != BOOT_INTERFACE)
		hidp->hid_if_descr.bInterfaceProtocol = NONE_PROTOCOL;
	mutex_exit(&hidp->hid_mutex);

	if ((ep_data = usb_lookup_ep_data(dip, dev_data,
	    hidp->hid_interfaceno, 0, 0,
	    (uint_t)USB_EP_ATTR_INTR, (uint_t)USB_EP_DIR_IN)) == NULL) {

		USB_DPRINTF_L2(PRINT_MASK_ATTA, hidp->hid_log_handle,
		    "no interrupt IN endpoint found");

		goto fail;
	}

	mutex_enter(&hidp->hid_mutex);
	if (usb_ep_xdescr_fill(USB_EP_XDESCR_CURRENT_VERSION, dip, ep_data,
	    &hidp->hid_ep_intr_xdescr) != USB_SUCCESS) {
		mutex_exit(&hidp->hid_mutex);

		goto fail;
	}

	/*
	 * Attempt to find the hid descriptor, it could be after interface
	 * or after endpoint descriptors
	 */
	if (hid_parse_hid_descr(&hidp->hid_hid_descr, USB_HID_DESCR_SIZE,
	    altif_data, ep_data) != USB_HID_DESCR_SIZE) {
		/*
		 * If parsing of hid descriptor failed and
		 * the device is a keyboard or mouse, use predefined
		 * length and packet size.
		 */
		if (hid_parse_hid_descr_failure(hidp) == USB_FAILURE) {
			mutex_exit(&hidp->hid_mutex);

			goto fail;
		}

		/*
		 * hid descriptor was bad but since
		 * the device is a keyboard or mouse,
		 * we will use the default length
		 * and packet size.
		 */
		parse_hid_descr_error = HID_BAD_DESCR;
	} else {
		/* Parse hid descriptor successful */

		USB_DPRINTF_L3(PRINT_MASK_ATTA, hidp->hid_log_handle,
		    "Hid descriptor:\n\t"
		    "bLength = 0x%x bDescriptorType = 0x%x "
		    "bcdHID = 0x%x\n\t"
		    "bCountryCode = 0x%x bNumDescriptors = 0x%x\n\t"
		    "bReportDescriptorType = 0x%x\n\t"
		    "wReportDescriptorLength = 0x%x",
		    hidp->hid_hid_descr.bLength,
		    hidp->hid_hid_descr.bDescriptorType,
		    hidp->hid_hid_descr.bcdHID,
		    hidp->hid_hid_descr.bCountryCode,
		    hidp->hid_hid_descr.bNumDescriptors,
		    hidp->hid_hid_descr.bReportDescriptorType,
		    hidp->hid_hid_descr.wReportDescriptorLength);
	}

	/*
	 * Save a copy of the default pipe for easy reference
	 */
	hidp->hid_default_pipe = hidp->hid_dev_data->dev_default_ph;

	/* we copied the descriptors we need, free the dev_data */
	usb_free_dev_data(dip, dev_data);
	hidp->hid_dev_data = NULL;

	/*
	 * Don't get the report descriptor if parsing hid descriptor earlier
	 * failed since device probably won't return valid report descriptor
	 * either. Though parsing of hid descriptor failed, we have reached
	 * this point because the device has been identified as a
	 * keyboard or a mouse successfully and the default packet
	 * size and layout(in case of keyboard only) will be used, so it
	 * is ok to go ahead even if parsing of hid descriptor failed and
	 * we will not try to get the report descriptor.
	 */
	if (parse_hid_descr_error != HID_BAD_DESCR) {
		/*
		 * Sun mouse rev 105 is a bit slow in responding to this
		 * request and requires multiple retries
		 */
		int retry;

		/*
		 * Get and parse the report descriptor.
		 * Set the packet size if parsing is successful.
		 * Note that we start retry at 1 to have a delay
		 * in the first iteration.
		 */
		mutex_exit(&hidp->hid_mutex);
		for (retry = 1; retry < HID_RETRY; retry++) {
			if (hid_handle_report_descriptor(hidp,
			    hidp->hid_interfaceno) == USB_SUCCESS) {
				break;
			}
			delay(retry * drv_usectohz(1000));
		}
		if (retry >= HID_RETRY) {

			goto fail;
		}
		mutex_enter(&hidp->hid_mutex);

		/*
		 * If packet size is zero, but the device is identified
		 * as a mouse or a keyboard, use predefined packet
		 * size.
		 */
		if (hidp->hid_packet_size == 0) {
			if (hidp->hid_if_descr.bInterfaceProtocol ==
			    KEYBOARD_PROTOCOL) {
				/* device is a keyboard */
				hidp->hid_packet_size = USBKPSZ;
			} else if (hidp->
			    hid_if_descr.bInterfaceProtocol ==
			    MOUSE_PROTOCOL) {
				/* device is a mouse */
				hidp->hid_packet_size = USBMSSZ;
			} else {
				USB_DPRINTF_L2(PRINT_MASK_ATTA,
				    hidp->hid_log_handle,
				    "Failed to find hid packet size");
				mutex_exit(&hidp->hid_mutex);

				goto fail;
			}
		}
	}

	/*
	 * initialize the pipe policy for the interrupt pipe.
	 */
	hidp->hid_intr_pipe_policy.pp_max_async_reqs = 1;

	/*
	 * Make a clas specific request to SET_IDLE
	 * In this case send no reports if state has not changed.
	 * See HID 7.2.4.
	 */
	mutex_exit(&hidp->hid_mutex);
	hid_set_idle(hidp);

	/* always initialize to report protocol */
	hid_set_protocol(hidp, SET_REPORT_PROTOCOL);
	mutex_enter(&hidp->hid_mutex);

	/*
	 * Create minor node based on information from the
	 * descriptors
	 */
	switch (hidp->hid_if_descr.bInterfaceProtocol) {
	case KEYBOARD_PROTOCOL:
		(void) strcpy(minor_name, "keyboard");

		break;
	case MOUSE_PROTOCOL:
		(void) strcpy(minor_name, "mouse");

		break;
	default:
		/*
		 * If the report descriptor has the GD mouse collection in
		 * its multiple collection, create a minor node and support it.
		 * It is used on some advanced keyboard/mouse set.
		 */
		if (hidparser_lookup_usage_collection(
		    hidp->hid_report_descr, HID_GENERIC_DESKTOP,
		    HID_GD_MOUSE) != HIDPARSER_FAILURE) {
			(void) strcpy(minor_name, "mouse");

			break;
		}

		if (hidparser_get_top_level_collection_usage(
		    hidp->hid_report_descr, &usage_page, &usage) !=
		    HIDPARSER_FAILURE) {
			switch (usage_page) {
			case HID_CONSUMER:
				switch (usage) {
				case HID_CONSUMER_CONTROL:
					(void) strcpy(minor_name,
					    "consumer_control");

					break;
				default:
					(void) sprintf(minor_name,
					    "hid_%d_%d", usage_page, usage);

					break;
				}

				break;
			case HID_GENERIC_DESKTOP:
				switch (usage) {
				case HID_GD_POINTER:
					(void) strcpy(minor_name,
					    "pointer");

					break;
				case HID_GD_MOUSE:
					(void) strcpy(minor_name,
					    "mouse");

					break;
				case HID_GD_KEYBOARD:
					(void) strcpy(minor_name,
					    "keyboard");

					break;
				default:
					(void) sprintf(minor_name,
					    "hid_%d_%d", usage_page, usage);

					break;
				}

				break;
			default:
				(void) sprintf(minor_name,
				    "hid_%d_%d", usage_page, usage);

				break;
			}
		} else {
			USB_DPRINTF_L1(PRINT_MASK_ATTA, hidp->hid_log_handle,
			    "hid_attach: Unsupported HID device");
			mutex_exit(&hidp->hid_mutex);

			goto fail;
		}

		break;
	}

	mutex_exit(&hidp->hid_mutex);

	if ((ddi_create_minor_node(dip, minor_name, S_IFCHR,
	    HID_CONSTRUCT_EXTERNAL_MINOR(instance),
	    DDI_PSEUDO, 0)) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hidp->hid_log_handle,
		    "hid_attach: Could not create minor node");

		goto fail;
	}

	/* create internal path for virtual */
	if (strcmp(minor_name, "mouse") == 0) {
		if (ddi_create_internal_pathname(dip, "internal_mouse", S_IFCHR,
		    HID_CONSTRUCT_INTERNAL_MINOR(instance)) != DDI_SUCCESS) {

			goto fail;
		}
	}

	if (strcmp(minor_name, "keyboard") == 0) {
		if (ddi_create_internal_pathname(dip, "internal_keyboard",
		    S_IFCHR, HID_CONSTRUCT_INTERNAL_MINOR(instance)) !=
		    DDI_SUCCESS) {

			goto fail;
		}
	}

	mutex_enter(&hidp->hid_mutex);
	hidp->hid_attach_flags |= HID_MINOR_NODES;
	hidp->hid_dev_state = USB_DEV_ONLINE;
	mutex_exit(&hidp->hid_mutex);

	/* register for all events */
	if (usb_register_event_cbs(dip, &hid_events, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hidp->hid_log_handle,
		    "usb_register_event_cbs failed");

		goto fail;
	}

	/* now create components to power manage this device */
	hid_create_pm_components(dip, hidp);
	hid_pm_busy_component(hidp);
	(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);
	hid_pm_idle_component(hidp);

	hidp->hid_internal_rq = hidp->hid_external_rq = NULL;
	hidp->hid_internal_flag = hidp->hid_external_flag = 0;
	hidp->hid_inuse_rq = NULL;

	/*
	 * report device
	 */
	ddi_report_dev(dip);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, hidp->hid_log_handle,
	    "hid_attach: End");

	return (DDI_SUCCESS);

fail:
	if (hidp) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hidp->hid_log_handle,
		    "hid_attach: fail");
		hid_detach_cleanup(dip, hidp);
	}

	return (DDI_FAILURE);
}


/*
 * hid_detach :
 *	Gets called at the time of detach.
 */
static int
hid_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	hid_state_t	*hidp;
	int		rval = DDI_FAILURE;

	hidp = ddi_get_soft_state(hid_statep, instance);

	USB_DPRINTF_L4(PRINT_MASK_ALL, hidp->hid_log_handle, "hid_detach");

	switch (cmd) {
	case DDI_DETACH:
		/*
		 * Undo	what we	did in client_attach, freeing resources
		 * and removing	things we installed.  The system
		 * framework guarantees	we are not active with this devinfo
		 * node	in any other entry points at this time.
		 */
		hid_detach_cleanup(dip, hidp);

		return (DDI_SUCCESS);
	case DDI_SUSPEND:
		rval = hid_cpr_suspend(hidp);

		return (rval == USB_SUCCESS ? DDI_SUCCESS : DDI_FAILURE);
	default:
		break;
	}

	return (rval);
}

/*
 * hid_open :
 *	Open entry point: Opens the interrupt pipe.  Sets up queues.
 */
/*ARGSUSED*/
static int
hid_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	int no_of_ep = 0;
	int rval;
	int instance;
	hid_state_t *hidp;
	minor_t minor = getminor(*devp);

	instance = HID_MINOR_TO_INSTANCE(minor);

	hidp = ddi_get_soft_state(hid_statep, instance);
	if (hidp == NULL) {

		return (ENXIO);
	}

	USB_DPRINTF_L4(PRINT_MASK_OPEN, hidp->hid_log_handle,
	    "hid_open: Begin");

	if (sflag) {
		/* clone open NOT supported here */
		return (ENXIO);
	}

	if (!(flag & FREAD)) {
		return (EIO);
	}

	/*
	 * This is a workaround:
	 *	Currently, if we open an already disconnected device, and send
	 *	a CONSOPENPOLL ioctl to it, the system will panic, please refer
	 *	to the processing HID_OPEN_POLLED_INPUT ioctl in the routine
	 *	hid_mctl_receive().
	 *	The consconfig_dacf module need this interface to detect if the
	 *	device is already disconnnected.
	 */
	mutex_enter(&hidp->hid_mutex);
	if (HID_IS_INTERNAL_OPEN(minor) &&
	    (hidp->hid_dev_state == USB_DEV_DISCONNECTED)) {
		mutex_exit(&hidp->hid_mutex);
		return (ENODEV);
	}

	if (HID_IS_INTERNAL_OPEN(minor) &&
	    (hidp->hid_internal_rq != NULL)) {
		ASSERT(hidp->hid_internal_rq == q);

		mutex_exit(&hidp->hid_mutex);
		return (0);
	}

	if ((!HID_IS_INTERNAL_OPEN(minor)) &&
	    (hidp->hid_external_rq != NULL)) {
		ASSERT(hidp->hid_external_rq == q);

		mutex_exit(&hidp->hid_mutex);
		return (0);
	}

	mutex_exit(&hidp->hid_mutex);

	q->q_ptr = hidp;
	WR(q)->q_ptr = hidp;

	mutex_enter(&hidp->hid_mutex);
	if (hidp->hid_inuse_rq != NULL) {
		/* Pipe has already been setup */

		if (HID_IS_INTERNAL_OPEN(minor)) {
			hidp->hid_internal_flag = HID_STREAMS_OPEN;
			hidp->hid_inuse_rq = hidp->hid_internal_rq = q;
		} else {
			hidp->hid_external_flag = HID_STREAMS_OPEN;
			hidp->hid_inuse_rq = hidp->hid_external_rq = q;
		}

		mutex_exit(&hidp->hid_mutex);

		qprocson(q);

		return (0);
	}

	/* Pipe only needs to be opened once */
	hidp->hid_interrupt_pipe = NULL;
	no_of_ep = hidp->hid_if_descr.bNumEndpoints;
	mutex_exit(&hidp->hid_mutex);

	/* Check if interrupt endpoint exists */
	if (no_of_ep > 0) {
		/* Open the interrupt pipe */
		if (usb_pipe_xopen(hidp->hid_dip,
		    &hidp->hid_ep_intr_xdescr,
		    &hidp->hid_intr_pipe_policy, USB_FLAGS_SLEEP,
		    &hidp->hid_interrupt_pipe) !=
		    USB_SUCCESS) {

			q->q_ptr = NULL;
			WR(q)->q_ptr = NULL;
			return (EIO);
		}
	}

	hid_pm_busy_component(hidp);
	(void) pm_raise_power(hidp->hid_dip, 0, USB_DEV_OS_FULL_PWR);

	mutex_enter(&hidp->hid_mutex);
	if (HID_IS_INTERNAL_OPEN(minor)) {
		hidp->hid_internal_flag = HID_STREAMS_OPEN;
		hidp->hid_inuse_rq = hidp->hid_internal_rq = q;
	} else {
		hidp->hid_external_flag = HID_STREAMS_OPEN;
		hidp->hid_inuse_rq = hidp->hid_external_rq = q;
	}

	mutex_exit(&hidp->hid_mutex);

	qprocson(q);

	mutex_enter(&hidp->hid_mutex);

	if ((rval = hid_start_intr_polling(hidp)) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, hidp->hid_log_handle,
		    "unable to start intr pipe polling. rval = %d", rval);

		if (HID_IS_INTERNAL_OPEN(minor))
			hidp->hid_internal_flag = HID_STREAMS_DISMANTLING;
		else
			hidp->hid_external_flag = HID_STREAMS_DISMANTLING;
		mutex_exit(&hidp->hid_mutex);

		usb_pipe_close(hidp->hid_dip, hidp->hid_interrupt_pipe,
		    USB_FLAGS_SLEEP, NULL, NULL);

		mutex_enter(&hidp->hid_mutex);
		hidp->hid_interrupt_pipe = NULL;
		mutex_exit(&hidp->hid_mutex);

		qprocsoff(q);

		mutex_enter(&hidp->hid_mutex);
		if (HID_IS_INTERNAL_OPEN(minor)) {
			hidp->hid_internal_flag = 0;
			hidp->hid_internal_rq = NULL;
			if (hidp->hid_external_flag == HID_STREAMS_OPEN)
				hidp->hid_inuse_rq = hidp->hid_external_rq;
			else
				hidp->hid_inuse_rq = NULL;
		} else {
			hidp->hid_external_flag = 0;
			hidp->hid_external_rq = NULL;
			if (hidp->hid_internal_flag == HID_STREAMS_OPEN)
				hidp->hid_inuse_rq = hidp->hid_internal_rq;
			else
				hidp->hid_inuse_rq = NULL;
		}
		mutex_exit(&hidp->hid_mutex);

		q->q_ptr = NULL;
		WR(q)->q_ptr = NULL;

		hid_pm_idle_component(hidp);

		return (EIO);
	}
	mutex_exit(&hidp->hid_mutex);

	USB_DPRINTF_L4(PRINT_MASK_OPEN, hidp->hid_log_handle, "hid_open: End");

	/*
	 * Keyboard and mouse is Power managed by device activity.
	 * All other devices go busy on open and idle on close.
	 */
	switch (hidp->hid_pm->hid_pm_strategy) {
	case HID_PM_ACTIVITY:
		hid_pm_idle_component(hidp);

		break;
	default:

		break;
	}

	return (0);
}


/*
 * hid_close :
 *	Close entry point.
 */
/*ARGSUSED*/
static int
hid_close(queue_t *q, int flag, cred_t *credp)
{
	hid_state_t	*hidp = (hid_state_t *)q->q_ptr;
	queue_t		*wq;
	mblk_t		*mp;

	USB_DPRINTF_L4(PRINT_MASK_CLOSE, hidp->hid_log_handle, "hid_close:");

	mutex_enter(&hidp->hid_mutex);

	ASSERT((hidp->hid_internal_rq == q) ||
	    (hidp->hid_external_rq == q));

	if (hidp->hid_internal_rq == q)
		hidp->hid_internal_flag = HID_STREAMS_DISMANTLING;
	else
		hidp->hid_external_flag = HID_STREAMS_DISMANTLING;

	mutex_exit(&hidp->hid_mutex);

	/*
	 * In case there are any outstanding requests on
	 * the default pipe, wait forever for them to complete.
	 */
	(void) usb_pipe_drain_reqs(hidp->hid_dip,
	    hidp->hid_default_pipe, 0, USB_FLAGS_SLEEP, NULL, 0);

	mutex_enter(&hidp->hid_mutex);
	wq = WR(q);
	/* drain any M_CTLS on the WQ */
	while (mp = getq(wq)) {
		hid_qreply_merror(wq, mp, EIO);
		mutex_exit(&hidp->hid_mutex);
		hid_pm_idle_component(hidp);
		mutex_enter(&hidp->hid_mutex);
	}
	mutex_exit(&hidp->hid_mutex);

	qprocsoff(q);

	q->q_ptr = NULL;
	wq->q_ptr = NULL;

	mutex_enter(&hidp->hid_mutex);

	if (hidp->hid_internal_rq == q) {
		hidp->hid_internal_rq = NULL;
		hidp->hid_internal_flag = 0;
		if (hidp->hid_inuse_rq == q) {
			/* We are closing the active stream */
			if (hidp->hid_external_flag == HID_STREAMS_OPEN)
				hidp->hid_inuse_rq = hidp->hid_external_rq;
			else
				hidp->hid_inuse_rq = NULL;
		}
	} else {
		hidp->hid_external_rq = NULL;
		hidp->hid_external_flag = 0;
		if (hidp->hid_inuse_rq == q) {
			/* We are closing the active stream */
			if (hidp->hid_internal_flag == HID_STREAMS_OPEN)
				hidp->hid_inuse_rq = hidp->hid_internal_rq;
			else
				hidp->hid_inuse_rq = NULL;
		}
	}

	if (hidp->hid_inuse_rq != NULL) {
		mutex_exit(&hidp->hid_mutex);
		return (0);
	}

	/* all queues are closed, close USB pipes */
	hid_close_intr_pipe(hidp);
	mutex_exit(&hidp->hid_mutex);

	/*
	 * Devices other than keyboard/mouse go idle on close.
	 */
	switch (hidp->hid_pm->hid_pm_strategy) {
	case HID_PM_ACTIVITY:

		break;
	default:
		hid_pm_idle_component(hidp);

		break;
	}
	USB_DPRINTF_L4(PRINT_MASK_CLOSE, hidp->hid_log_handle,
	    "hid_close: End");

	return (0);
}


/*
 * hid_wput :
 *	write put routine for the hid module
 */
static int
hid_wput(queue_t *q, mblk_t *mp)
{
	hid_state_t	*hidp = (hid_state_t *)q->q_ptr;
	int		error = USB_SUCCESS;
	struct iocblk	*iocbp;
	mblk_t		*datap;
	int		direction;
	struct copyresp *crp;
	queue_t		*tmpq;
	int		flag;

	USB_DPRINTF_L4(PRINT_MASK_ALL, hidp->hid_log_handle,
	    "hid_wput: Begin");

	/* See if the upper module is passing the right thing */
	ASSERT(mp != NULL);
	ASSERT(mp->b_datap != NULL);

	switch (mp->b_datap->db_type) {
	case M_FLUSH:  /* Canonical flush handling */
		if (*mp->b_rptr & FLUSHW) {
			flushq(q, FLUSHDATA);
		}

		/* read queue not used so just send up */
		if (*mp->b_rptr & FLUSHR) {
			*mp->b_rptr &= ~FLUSHW;
			qreply(q, mp);
		} else {
			freemsg(mp);
		}

		break;
	case M_IOCTL:
		iocbp = (struct iocblk *)mp->b_rptr;

		/* Only accept transparent ioctls */
		if (iocbp->ioc_count != TRANSPARENT) {
			miocnak(q, mp, 0, EINVAL);
			break;
		}

		switch (iocbp->ioc_cmd) {
		case HIDIOCKMGDIRECT:

			mutex_enter(&hidp->hid_mutex);
			ASSERT(hidp->hid_inuse_rq != NULL);
			mutex_exit(&hidp->hid_mutex);

			if ((datap = allocb(sizeof (int), BPRI_MED)) == NULL) {
				miocnak(q, mp, 0, ENOMEM);
				break;
			}

			mutex_enter(&hidp->hid_mutex);
			if (hidp->hid_inuse_rq == hidp->hid_internal_rq) {
				*(int *)datap->b_wptr = 0;
				datap->b_wptr += sizeof (int);
			} else {
				ASSERT(hidp->hid_inuse_rq ==
				    hidp->hid_external_rq);
				*(int *)datap->b_wptr = 1;
				datap->b_wptr += sizeof (int);
			}
			mutex_exit(&hidp->hid_mutex);

			mcopyout(mp, NULL, sizeof (int), NULL, datap);
			qreply(q, mp);
			break;

		case HIDIOCKMSDIRECT:
			mcopyin(mp, NULL, sizeof (int), NULL);
			qreply(q, mp);
			break;

		default:
			miocnak(q, mp, 0, ENOTTY);
		}

		break;

	case M_IOCDATA:

		crp = (void *)mp->b_rptr;

		if (crp->cp_rval != 0) {
			miocnak(q, mp, 0, EIO);
			break;
		}

		switch (crp->cp_cmd) {
		case HIDIOCKMGDIRECT:
			miocack(q, mp, 0, 0);
			break;

		case HIDIOCKMSDIRECT:
			direction = *(int *)mp->b_cont->b_rptr;

			if ((direction != 0) && (direction != 1)) {
				miocnak(q, mp, 0, EINVAL);
				break;
			}

			mutex_enter(&hidp->hid_mutex);

			if (direction == 0) {
				/* The internal stream is made active */
				flag = hidp->hid_internal_flag;
				tmpq = hidp->hid_internal_rq;
			} else {
				/* The external stream is made active */
				flag = hidp->hid_external_flag;
				tmpq = hidp->hid_external_rq;
			}

			if (flag != HID_STREAMS_OPEN) {
				mutex_exit(&hidp->hid_mutex);
				miocnak(q, mp, 0, EIO);
				break;
			}

			hidp->hid_inuse_rq = tmpq;

			mutex_exit(&hidp->hid_mutex);
			miocack(q, mp, 0, 0);
			break;

		default:
			miocnak(q, mp, 0, ENOTTY);
			break;
		}

		break;

	case M_CTL:
		/* we are busy now */
		hid_pm_busy_component(hidp);

		if (q->q_first) {
			(void) putq(q, mp);
		} else {
			error = hid_mctl_receive(q, mp);
			switch (error) {
			case HID_ENQUEUE:
				/*
				 * put this mblk on the WQ for the wsrv to
				 * process
				 */
				(void) putq(q, mp);

				break;
			case HID_INPROGRESS:
				/* request has been queued to the device */

				break;
			case HID_SUCCESS:
				/*
				 * returned by M_CTLS that are processed
				 * immediately
				 */

				/* FALLTHRU */
			case HID_FAILURE:
			default:
				hid_pm_idle_component(hidp);
				break;
			}
		}
		break;
	default:
		hid_qreply_merror(q, mp, EINVAL);
		error = USB_FAILURE;
		break;
	}

	USB_DPRINTF_L4(PRINT_MASK_ALL, hidp->hid_log_handle,
	    "hid_wput: End");

	return (DDI_SUCCESS);
}


/*
 * hid_wsrv :
 *	Write service routine for hid. When a message arrives through
 *	hid_wput(), it is kept in write queue to be serviced later.
 */
static int
hid_wsrv(queue_t *q)
{
	hid_state_t	*hidp = (hid_state_t *)q->q_ptr;
	int		error;
	mblk_t		*mp;

	USB_DPRINTF_L4(PRINT_MASK_ALL, hidp->hid_log_handle,
	    "hid_wsrv: Begin");

	mutex_enter(&hidp->hid_mutex);
	USB_DPRINTF_L4(PRINT_MASK_ALL, hidp->hid_log_handle,
	    "hid_wsrv: dev_state: %s",
	    usb_str_dev_state(hidp->hid_dev_state));

	/*
	 * raise power if we are powered down. It is OK to block here since
	 * we have a separate thread to process this STREAM
	 */
	if (hidp->hid_dev_state == USB_DEV_PWRED_DOWN) {
		mutex_exit(&hidp->hid_mutex);
		(void) pm_raise_power(hidp->hid_dip, 0, USB_DEV_OS_FULL_PWR);
		mutex_enter(&hidp->hid_mutex);
	}

	/*
	 * continue servicing all the M_CTL's till the queue is empty
	 * or the device gets disconnected or till a hid_close()
	 */
	while ((hidp->hid_dev_state == USB_DEV_ONLINE) &&
	    (HID_STREAMS_FLAG(q, hidp) != HID_STREAMS_DISMANTLING) &&
	    ((mp = getq(q)) != NULL)) {

		/* Send a message down */
		mutex_exit(&hidp->hid_mutex);
		error = hid_mctl_receive(q, mp);
		switch (error) {
		case HID_ENQUEUE:
			/* put this mblk back on q to preserve order */
			(void) putbq(q, mp);

			break;
		case HID_INPROGRESS:
			/* request has been queued to the device */

			break;
		case HID_SUCCESS:
		case HID_FAILURE:
		default:
			hid_pm_idle_component(hidp);

			break;
		}
		mutex_enter(&hidp->hid_mutex);
	}
	mutex_exit(&hidp->hid_mutex);
	USB_DPRINTF_L4(PRINT_MASK_ALL, hidp->hid_log_handle,
	    "hid_wsrv: End");

	return (DDI_SUCCESS);
}


/*
 * hid_power:
 *	power entry point
 */
static int
hid_power(dev_info_t *dip, int comp, int level)
{
	int		instance = ddi_get_instance(dip);
	hid_state_t	*hidp;
	hid_power_t	*hidpm;
	int		retval;

	hidp = ddi_get_soft_state(hid_statep, instance);

	USB_DPRINTF_L3(PRINT_MASK_PM, hidp->hid_log_handle, "hid_power:"
	    " hid_state: comp=%d level=%d", comp, level);

	/* check if we are transitioning to a legal power level */
	mutex_enter(&hidp->hid_mutex);
	hidpm = hidp->hid_pm;

	if (USB_DEV_PWRSTATE_OK(hidpm->hid_pwr_states, level)) {

		USB_DPRINTF_L2(PRINT_MASK_PM, hidp->hid_log_handle,
		    "hid_power: illegal level=%d hid_pwr_states=%d",
		    level, hidpm->hid_pwr_states);

		mutex_exit(&hidp->hid_mutex);

		return (DDI_FAILURE);
	}

	switch (level) {
	case USB_DEV_OS_PWR_OFF:
		retval = hid_pwrlvl0(hidp);
		break;
	case USB_DEV_OS_PWR_1:
		retval = hid_pwrlvl1(hidp);
		break;
	case USB_DEV_OS_PWR_2:
		retval = hid_pwrlvl2(hidp);
		break;
	case USB_DEV_OS_FULL_PWR:
		retval = hid_pwrlvl3(hidp);
		break;
	default:
		retval = USB_FAILURE;
		break;
	}

	mutex_exit(&hidp->hid_mutex);

	return ((retval == USB_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}


/*
 * hid_interrupt_pipe_callback:
 *	Callback function for the hid intr pipe. This function is called by
 *	USBA when a buffer has been filled. This driver does not cook the data,
 *	it just sends the message up.
 */
static void
hid_interrupt_pipe_callback(usb_pipe_handle_t pipe, usb_intr_req_t *req)
{
	hid_state_t *hidp = (hid_state_t *)req->intr_client_private;
	queue_t	*q;

	USB_DPRINTF_L4(PRINT_MASK_ALL, hidp->hid_log_handle,
	    "hid_interrupt_pipe_callback: ph = 0x%p req = 0x%p",
	    (void *)pipe, (void *)req);

	hid_pm_busy_component(hidp);

	mutex_enter(&hidp->hid_mutex);

	/*
	 * If hid_close() is in progress, we shouldn't try accessing queue
	 * Otherwise indicate that a putnext is going to happen, so
	 * if close after this, that should wait for the putnext to finish.
	 */
	if (HID_STREAMS_FLAG(hidp->hid_inuse_rq, hidp) ==
	    HID_STREAMS_OPEN) {
		/*
		 * Check if data can be put to the next queue.
		 */
		if (!canputnext(hidp->hid_inuse_rq)) {
			USB_DPRINTF_L2(PRINT_MASK_ALL, hidp->hid_log_handle,
			    "Buffer flushed when overflowed.");

			/* Flush the queue above */
			hid_flush(hidp->hid_inuse_rq);
			mutex_exit(&hidp->hid_mutex);
		} else {
			q = hidp->hid_inuse_rq;
			mutex_exit(&hidp->hid_mutex);

			/* Put data upstream */
			putnext(q, req->intr_data);

			/* usb_free_intr_req should not free data */
			req->intr_data = NULL;
		}
	} else {
		mutex_exit(&hidp->hid_mutex);
	}

	/* free request and data */
	usb_free_intr_req(req);
	hid_pm_idle_component(hidp);
}


/*
 * hid_default_pipe_callback :
 *	Callback routine for the asynchronous control transfer
 *	Called from hid_send_async_ctrl_request() where we open
 *	the pipe in exclusive mode
 */
static void
hid_default_pipe_callback(usb_pipe_handle_t pipe, usb_ctrl_req_t *req)
{
	hid_default_pipe_arg_t *hid_default_pipe_arg =
	    (hid_default_pipe_arg_t *)req->ctrl_client_private;
	queue_t		*wq = hid_default_pipe_arg->hid_default_pipe_arg_queue;
	queue_t		*rq = RD(wq);
	hid_state_t	*hidp = (hid_state_t *)rq->q_ptr;
	mblk_t		*mctl_mp;
	mblk_t		*data = NULL;

	USB_DPRINTF_L4(PRINT_MASK_ALL, hidp->hid_log_handle,
	    "hid_default_pipe_callback: "
	    "ph = 0x%p, req = 0x%p, data= 0x%p",
	    (void *)pipe, (void *)req, (void *)data);

	ASSERT((req->ctrl_cb_flags & USB_CB_INTR_CONTEXT) == 0);

	if (req->ctrl_data) {
		data = req->ctrl_data;
		req->ctrl_data = NULL;
	}

	/*
	 * Free the b_cont of the original message that was sent down.
	 */
	mctl_mp = hid_default_pipe_arg->hid_default_pipe_arg_mblk;
	freemsg(mctl_mp->b_cont);

	/* chain the mblk received to the original & send it up */
	mctl_mp->b_cont = data;

	if (canputnext(rq)) {
		putnext(rq, mctl_mp);
	} else {
		freemsg(mctl_mp); /* avoid leak */
	}

	/*
	 * Free the argument for the asynchronous callback
	 */
	kmem_free(hid_default_pipe_arg, sizeof (hid_default_pipe_arg_t));

	/*
	 * Free the control pipe request structure.
	 */
	usb_free_ctrl_req(req);

	mutex_enter(&hidp->hid_mutex);
	hidp->hid_default_pipe_req--;
	ASSERT(hidp->hid_default_pipe_req >= 0);
	mutex_exit(&hidp->hid_mutex);

	hid_pm_idle_component(hidp);
	qenable(wq);
}


/*
 * hid_interrupt_pipe_exception_callback:
 *	Exception callback routine for interrupt pipe. If there is any data,
 *	destroy it. No threads are waiting for the exception callback.
 */
/*ARGSUSED*/
static void
hid_interrupt_pipe_exception_callback(usb_pipe_handle_t pipe,
    usb_intr_req_t *req)
{
	hid_state_t	*hidp = (hid_state_t *)req->intr_client_private;
	mblk_t		*data = req->intr_data;
	usb_cb_flags_t	flags = req->intr_cb_flags;
	int		rval;

	USB_DPRINTF_L2(PRINT_MASK_ALL, hidp->hid_log_handle,
	    "hid_interrupt_pipe_exception_callback: "
	    "completion_reason = 0x%x, data = 0x%p, flag = 0x%x",
	    req->intr_completion_reason, (void *)data, req->intr_cb_flags);

	ASSERT((req->intr_cb_flags & USB_CB_INTR_CONTEXT) == 0);

	if (((flags & USB_CB_FUNCTIONAL_STALL) != 0) &&
	    ((flags & USB_CB_STALL_CLEARED) == 0)) {
		USB_DPRINTF_L2(PRINT_MASK_ALL,
		    hidp->hid_log_handle,
		    "hid_interrupt_pipe_exception_callback: "
		    "unable to clear stall.  flags = 0x%x",
		    req->intr_cb_flags);
	}

	mutex_enter(&hidp->hid_mutex);

	switch (req->intr_completion_reason) {
	case USB_CR_STOPPED_POLLING:
	case USB_CR_PIPE_CLOSING:
	default:

		break;
	case USB_CR_PIPE_RESET:
	case USB_CR_NO_RESOURCES:
		if ((hidp->hid_dev_state == USB_DEV_ONLINE) &&
		    ((rval = hid_start_intr_polling(hidp)) !=
		    USB_SUCCESS)) {
			USB_DPRINTF_L2(PRINT_MASK_ALL, hidp->hid_log_handle,
			    "unable to restart interrupt poll. rval = %d",
			    rval);
		}

		break;
	}

	mutex_exit(&hidp->hid_mutex);

	usb_free_intr_req(req);
}


/*
 * hid_default_pipe_exception_callback:
 *	Exception callback routine for default pipe.
 */
/*ARGSUSED*/
static void
hid_default_pipe_exception_callback(usb_pipe_handle_t pipe,
    usb_ctrl_req_t *req)
{
	hid_default_pipe_arg_t *hid_default_pipe_arg =
	    (hid_default_pipe_arg_t *)req->ctrl_client_private;
	queue_t		*wq = hid_default_pipe_arg->hid_default_pipe_arg_queue;
	queue_t		*rq = RD(wq);
	hid_state_t	*hidp = (hid_state_t *)rq->q_ptr;
	usb_cr_t	ctrl_completion_reason = req->ctrl_completion_reason;
	mblk_t		*mp, *data = NULL;

	USB_DPRINTF_L2(PRINT_MASK_ALL, hidp->hid_log_handle,
	    "hid_default_pipe_exception_callback: "
	    "completion_reason = 0x%x, data = 0x%p, flag = 0x%x",
	    ctrl_completion_reason, (void *)data, req->ctrl_cb_flags);

	ASSERT((req->ctrl_cb_flags & USB_CB_INTR_CONTEXT) == 0);

	mp = hid_default_pipe_arg->hid_default_pipe_arg_mblk;

	/*
	 * Pass an error message up. Reuse existing mblk.
	 */
	if (canputnext(rq)) {
		mp->b_datap->db_type = M_ERROR;
		mp->b_rptr = mp->b_datap->db_base;
		mp->b_wptr = mp->b_rptr + sizeof (char);
		*mp->b_rptr = EIO;
		putnext(rq, mp);
	} else {
		freemsg(mp);
	}

	kmem_free(hid_default_pipe_arg, sizeof (hid_default_pipe_arg_t));

	mutex_enter(&hidp->hid_mutex);
	hidp->hid_default_pipe_req--;
	ASSERT(hidp->hid_default_pipe_req >= 0);
	mutex_exit(&hidp->hid_mutex);

	qenable(wq);
	usb_free_ctrl_req(req);
	hid_pm_idle_component(hidp);
}


/*
 * event handling:
 *
 * hid_reconnect_event_callback:
 *	the device was disconnected but this instance not detached, probably
 *	because the device was busy
 *
 *	If the same device, continue with restoring state
 */
static int
hid_restore_state_event_callback(dev_info_t *dip)
{
	hid_state_t	*hidp = (hid_state_t *)ddi_get_soft_state(hid_statep,
	    ddi_get_instance(dip));

	ASSERT(hidp != NULL);

	USB_DPRINTF_L3(PRINT_MASK_EVENTS, hidp->hid_log_handle,
	    "hid_restore_state_event_callback: dip=0x%p", (void *)dip);

	hid_restore_device_state(dip, hidp);

	return (USB_SUCCESS);
}


/*
 * hid_cpr_suspend
 *	Fail suspend if we can't finish outstanding i/o activity.
 */
static int
hid_cpr_suspend(hid_state_t *hidp)
{
	int		rval, prev_state;
	int		retval = USB_FAILURE;

	USB_DPRINTF_L4(PRINT_MASK_EVENTS, hidp->hid_log_handle,
	    "hid_cpr_suspend: dip=0x%p", (void *)hidp->hid_dip);

	mutex_enter(&hidp->hid_mutex);
	switch (hidp->hid_dev_state) {
	case USB_DEV_ONLINE:
	case USB_DEV_PWRED_DOWN:
		prev_state = hidp->hid_dev_state;
		hidp->hid_dev_state = USB_DEV_SUSPENDED;
		mutex_exit(&hidp->hid_mutex);

		/* drain all request outstanding on the default control pipe */
		rval = usb_pipe_drain_reqs(hidp->hid_dip,
		    hidp->hid_default_pipe, hid_default_pipe_drain_timeout,
		    USB_FLAGS_SLEEP, NULL, 0);

		/* fail checkpoint if we haven't finished the job yet */
		mutex_enter(&hidp->hid_mutex);
		if ((rval != USB_SUCCESS) || (hidp->hid_default_pipe_req > 0)) {
			USB_DPRINTF_L2(PRINT_MASK_EVENTS, hidp->hid_log_handle,
			    "hid_cpr_suspend: "
			    "device busy - can't checkpoint");

			/* fall back to previous state */
			hidp->hid_dev_state = prev_state;
		} else {
			retval = USB_SUCCESS;
			hid_save_device_state(hidp);
		}

		break;
	case USB_DEV_DISCONNECTED:
		hidp->hid_dev_state = USB_DEV_SUSPENDED;
		hid_save_device_state(hidp);
		retval = USB_SUCCESS;
		break;
	case USB_DEV_SUSPENDED:
	default:
		USB_DPRINTF_L2(PRINT_MASK_EVENTS, hidp->hid_log_handle,
		    "hid_cpr_suspend: Illegal dev state: %d",
		    hidp->hid_dev_state);

		break;
	}
	mutex_exit(&hidp->hid_mutex);

	return (retval);
}


static void
hid_cpr_resume(hid_state_t *hidp)
{
	USB_DPRINTF_L4(PRINT_MASK_EVENTS, hidp->hid_log_handle,
	    "hid_cpr_resume: dip=0x%p", (void *)hidp->hid_dip);

	hid_restore_device_state(hidp->hid_dip, hidp);
}


/*
 * hid_disconnect_event_callback:
 *	The device has been disconnected. We either wait for
 *	detach or a reconnect event. Close all pipes and timeouts.
 */
static int
hid_disconnect_event_callback(dev_info_t *dip)
{
	hid_state_t	*hidp;
	mblk_t		*mp;

	hidp = (hid_state_t *)ddi_get_soft_state(hid_statep,
	    ddi_get_instance(dip));
	ASSERT(hidp != NULL);

	USB_DPRINTF_L4(PRINT_MASK_EVENTS, hidp->hid_log_handle,
	    "hid_disconnect_event_callback: dip=0x%p", (void *)dip);

	mutex_enter(&hidp->hid_mutex);
	switch (hidp->hid_dev_state) {
	case USB_DEV_ONLINE:
	case USB_DEV_PWRED_DOWN:
		hidp->hid_dev_state = USB_DEV_DISCONNECTED;
		if (HID_IS_OPEN(hidp)) {

			USB_DPRINTF_L2(PRINT_MASK_EVENTS, hidp->hid_log_handle,
			    "busy device has been disconnected");
		}
		hid_save_device_state(hidp);

		/*
		 * Notify applications about device removal, this only
		 * applies to an external (aka. physical) open. For an
		 * internal open, consconfig_dacf closes the queue.
		 */
		if (hidp->hid_external_flag == HID_STREAMS_OPEN) {
			queue_t *q = hidp->hid_external_rq;
			mutex_exit(&hidp->hid_mutex);
			mp = allocb(sizeof (uchar_t), BPRI_HI);
			if (mp != NULL) {
				mp->b_datap->db_type = M_ERROR;
				mp->b_rptr = mp->b_datap->db_base;
				mp->b_wptr = mp->b_rptr + sizeof (char);
				*mp->b_rptr = ENODEV;
				putnext(q, mp);
			}
			mutex_enter(&hidp->hid_mutex);
		}

		break;
	case USB_DEV_SUSPENDED:
		/* we remain suspended */

		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_EVENTS, hidp->hid_log_handle,
		    "hid_disconnect_event_callback: Illegal dev state: %d",
		    hidp->hid_dev_state);

		break;
	}
	mutex_exit(&hidp->hid_mutex);

	return (USB_SUCCESS);
}


/*
 * hid_power_change_callback:
 *	Async callback function to notify pm_raise_power completion
 *	after hid_power entry point is called.
 */
static void
hid_power_change_callback(void *arg, int rval)
{
	hid_state_t	*hidp;
	queue_t		*wq;

	hidp = (hid_state_t *)arg;

	USB_DPRINTF_L4(PRINT_MASK_PM, hidp->hid_log_handle,
	    "hid_power_change_callback - rval: %d", rval);

	mutex_enter(&hidp->hid_mutex);
	hidp->hid_pm->hid_raise_power = B_FALSE;

	if (hidp->hid_dev_state == USB_DEV_ONLINE) {
		wq = WR(hidp->hid_inuse_rq);
		mutex_exit(&hidp->hid_mutex);

		qenable(wq);

	} else {
		mutex_exit(&hidp->hid_mutex);
	}
}


/*
 * hid_parse_hid_descr:
 *	Parse the hid descriptor, check after interface and after
 *	endpoint descriptor
 */
static size_t
hid_parse_hid_descr(usb_hid_descr_t *ret_descr,	size_t ret_buf_len,
    usb_alt_if_data_t *altif_data, usb_ep_data_t *ep_data)
{
	usb_cvs_data_t *cvs;
	int		which_cvs;

	for (which_cvs = 0; which_cvs < altif_data->altif_n_cvs; which_cvs++) {
		cvs = &altif_data->altif_cvs[which_cvs];
		if (cvs->cvs_buf == NULL) {
			continue;
		}
		if (cvs->cvs_buf[1] == USB_DESCR_TYPE_HID) {
			return (usb_parse_data("ccscccs",
			    cvs->cvs_buf, cvs->cvs_buf_len,
			    (void *)ret_descr,
			    (size_t)ret_buf_len));
		}
	}

	/* now try after endpoint */
	for (which_cvs = 0; which_cvs < ep_data->ep_n_cvs; which_cvs++) {
		cvs = &ep_data->ep_cvs[which_cvs];
		if (cvs->cvs_buf == NULL) {
			continue;
		}
		if (cvs->cvs_buf[1] == USB_DESCR_TYPE_HID) {
			return (usb_parse_data("ccscccs",
			    cvs->cvs_buf, cvs->cvs_buf_len,
			    (void *)ret_descr,
			    (size_t)ret_buf_len));
		}
	}

	return (USB_PARSE_ERROR);
}


/*
 * hid_parse_hid_descr_failure:
 *	If parsing of hid descriptor failed and the device is
 *	a keyboard or mouse, use predefined length and packet size.
 */
static int
hid_parse_hid_descr_failure(hid_state_t	*hidp)
{
	/*
	 * Parsing hid descriptor failed, probably because the
	 * device did not return a valid hid descriptor. Check to
	 * see if this is a keyboard or mouse. If so, use the
	 * predefined hid descriptor length and packet size.
	 * Otherwise, detach and return failure.
	 */
	USB_DPRINTF_L1(PRINT_MASK_ATTA, hidp->hid_log_handle,
	    "Parsing of hid descriptor failed");

	if (hidp->hid_if_descr.bInterfaceProtocol == KEYBOARD_PROTOCOL) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hidp->hid_log_handle,
		    "Set hid descriptor length to predefined "
		    "USB_KB_HID_DESCR_LENGTH for keyboard.");

		/* device is a keyboard */
		hidp->hid_hid_descr.wReportDescriptorLength =
		    USB_KB_HID_DESCR_LENGTH;

		hidp->hid_packet_size = USBKPSZ;

	} else if (hidp->hid_if_descr.bInterfaceProtocol ==
	    MOUSE_PROTOCOL) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hidp->hid_log_handle,
		    "Set hid descriptor length to predefined "
		    "USB_MS_HID_DESCR_LENGTH for mouse.");

		/* device is a mouse */
		hidp->hid_hid_descr.wReportDescriptorLength =
		    USB_MS_HID_DESCR_LENGTH;

		hidp->hid_packet_size = USBMSSZ;
	} else {

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


/*
 * hid_handle_report_descriptor:
 *	Get the report descriptor, call hidparser routine to parse
 *	it and query the hidparser tree to get the packet size
 */
static int
hid_handle_report_descriptor(hid_state_t *hidp, int interface)
{
	usb_cr_t		completion_reason;
	usb_cb_flags_t		cb_flags;
	mblk_t			*data = NULL;
	hidparser_packet_info_t	hpack;
	int			i;
	usb_ctrl_setup_t setup = {
	    USB_DEV_REQ_DEV_TO_HOST |	/* bmRequestType */
	    USB_DEV_REQ_RCPT_IF,
	    USB_REQ_GET_DESCR,		/* bRequest */
	    USB_CLASS_DESCR_TYPE_REPORT, /* wValue */
	    0,				/* wIndex: interface, fill in later */
	    0,				/* wLength, fill in later  */
	    0				/* attributes */
	    };

	/*
	 * Parsing hid desciptor was successful earlier.
	 * Get Report Descriptor
	 */
	setup.wIndex = (uint16_t)interface;
	setup.wLength = hidp->hid_hid_descr.wReportDescriptorLength;
	if (usb_pipe_ctrl_xfer_wait(hidp->hid_default_pipe,
	    &setup,
	    &data,				/* data */
	    &completion_reason, &cb_flags, 0) != USB_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_ATTA, hidp->hid_log_handle,
		    "Failed to receive the Report Descriptor");
		freemsg(data);

		return (USB_FAILURE);

	} else {
		int n =  hidp->hid_hid_descr.wReportDescriptorLength;

		ASSERT(data);

		/* Print the report descriptor */
		for (i = 0; i < n; i++) {
			USB_DPRINTF_L3(PRINT_MASK_ATTA, hidp->hid_log_handle,
			    "Index = %d\tvalue =0x%x", i,
			    (int)(data->b_rptr[i]));
		}

		/* Get Report Descriptor was successful */
		if (hidparser_parse_report_descriptor(
		    data->b_rptr,
		    hidp->hid_hid_descr.wReportDescriptorLength,
		    &hidp->hid_hid_descr,
		    &hidp->hid_report_descr) == HIDPARSER_SUCCESS) {

			/* find max intr-in xfer length */
			hidparser_find_max_packet_size_from_report_descriptor(
			    hidp->hid_report_descr, &hpack);
			/* round up to the nearest byte */
			hidp->hid_packet_size = (hpack.max_packet_size + 7) / 8;

			/* if report id is used, add more more byte for it */
			if (hpack.report_id != HID_REPORT_ID_UNDEFINED) {
				hidp->hid_packet_size++;
			}
		} else {
			USB_DPRINTF_L1(PRINT_MASK_ATTA, hidp->hid_log_handle,
			    "Invalid Report Descriptor");
			freemsg(data);

			return (USB_FAILURE);
		}

		freemsg(data);

		return (USB_SUCCESS);
	}
}


/*
 * hid_set_idle:
 *	Make a clas specific request to SET_IDLE.
 *	In this case send no reports if state has not changed.
 *	See HID 7.2.4.
 */
/*ARGSUSED*/
static void
hid_set_idle(hid_state_t *hidp)
{
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	usb_ctrl_setup_t setup = {
	    USB_DEV_REQ_HOST_TO_DEV |	/* bmRequestType */
	    USB_DEV_REQ_TYPE_CLASS |
	    USB_DEV_REQ_RCPT_IF,
	    SET_IDLE,			/* bRequest */
	    DURATION,			/* wValue */
	    0,				/* wIndex: interface, fill in later */
	    0,				/* wLength */
	    0				/* attributes */
	    };

	USB_DPRINTF_L4(PRINT_MASK_ATTA, hidp->hid_log_handle,
	    "hid_set_idle: Begin");

	setup.wIndex = hidp->hid_if_descr.bInterfaceNumber;
	if (usb_pipe_ctrl_xfer_wait(
	    hidp->hid_default_pipe,
	    &setup,
	    NULL,			/* no data to send. */
	    &completion_reason, &cb_flags, 0) != USB_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_ATTA, hidp->hid_log_handle,
		    "Failed while trying to set idle,"
		    "cr = %d, cb_flags = 0x%x\n",
		    completion_reason, cb_flags);
	}
	USB_DPRINTF_L4(PRINT_MASK_ATTA, hidp->hid_log_handle,
	    "hid_set_idle: End");
}


/*
 * hid_set_protocol:
 *	Initialize the device to set the preferred protocol
 */
/*ARGSUSED*/
static void
hid_set_protocol(hid_state_t *hidp, int protocol)
{
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	usb_ctrl_setup_t setup;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, hidp->hid_log_handle,
	    "hid_set_protocol(%d): Begin", protocol);

	/* initialize the setup request */
	setup.bmRequestType = USB_DEV_REQ_HOST_TO_DEV |
	    USB_DEV_REQ_TYPE_CLASS | USB_DEV_REQ_RCPT_IF;
	setup.bRequest = SET_PROTOCOL;
	setup.wValue = (uint16_t)protocol;
	setup.wIndex = hidp->hid_if_descr.bInterfaceNumber;
	setup.wLength = 0;
	setup.attrs = 0;
	if (usb_pipe_ctrl_xfer_wait(
	    hidp->hid_default_pipe,	/* bmRequestType */
	    &setup,
	    NULL,			/* no data to send */
	    &completion_reason, &cb_flags, 0) != USB_SUCCESS) {
		/*
		 * Some devices fail to follow the specification
		 * and instead of STALLing, they continously
		 * NAK the SET_IDLE command. We need to reset
		 * the pipe then, so that ohci doesn't panic.
		 */
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hidp->hid_log_handle,
		    "Failed while trying to set protocol:%d,"
		    "cr =  %d cb_flags = 0x%x\n",
		    completion_reason, cb_flags, protocol);
	}

	USB_DPRINTF_L4(PRINT_MASK_ATTA, hidp->hid_log_handle,
	    "hid_set_protocol: End");
}


/*
 * hid_detach_cleanup:
 *	called by attach and detach for cleanup.
 */
static void
hid_detach_cleanup(dev_info_t *dip, hid_state_t *hidp)
{
	int	flags = hidp->hid_attach_flags;
	int	rval;
	hid_power_t	*hidpm;

	USB_DPRINTF_L4(PRINT_MASK_ALL, hidp->hid_log_handle,
	    "hid_detach_cleanup: Begin");

	if ((hidp->hid_attach_flags & HID_LOCK_INIT) == 0) {

		goto done;
	}

	/*
	 * Disable the event callbacks first, after this point, event
	 * callbacks will never get called. Note we shouldn't hold
	 * mutex while unregistering events because there may be a
	 * competing event callback thread. Event callbacks are done
	 * with ndi mutex held and this can cause a potential deadlock.
	 */
	usb_unregister_event_cbs(dip, &hid_events);

	mutex_enter(&hidp->hid_mutex);

	hidpm = hidp->hid_pm;

	USB_DPRINTF_L2(PRINT_MASK_ALL, hidp->hid_log_handle,
	    "hid_detach_cleanup: hidpm=0x%p", (void *)hidpm);

	if (hidpm && (hidp->hid_dev_state != USB_DEV_DISCONNECTED)) {

		mutex_exit(&hidp->hid_mutex);
		hid_pm_busy_component(hidp);
		if (hid_is_pm_enabled(dip) == USB_SUCCESS) {

			if (hidpm->hid_wakeup_enabled) {

				/* First bring the device to full power */
				(void) pm_raise_power(dip, 0,
				    USB_DEV_OS_FULL_PWR);

				/* Disable remote wakeup */
				rval = usb_handle_remote_wakeup(dip,
				    USB_REMOTE_WAKEUP_DISABLE);

				if (rval != DDI_SUCCESS) {
					USB_DPRINTF_L2(PRINT_MASK_ALL,
					    hidp->hid_log_handle,
					    "hid_detach_cleanup: "
					    "disble remote wakeup failed, "
					    "rval= %d", rval);
				}
			}

			(void) pm_lower_power(dip, 0, USB_DEV_OS_PWR_OFF);
		}
		hid_pm_idle_component(hidp);
		mutex_enter(&hidp->hid_mutex);
	}

	if (hidpm) {
		freemsg(hidpm->hid_pm_pwrup);
		kmem_free(hidpm, sizeof (hid_power_t));
		hidp->hid_pm = NULL;
	}

	mutex_exit(&hidp->hid_mutex);

	if (hidp->hid_report_descr != NULL) {
		(void) hidparser_free_report_descriptor_handle(
		    hidp->hid_report_descr);
	}

	if (flags & HID_MINOR_NODES) {
		ddi_remove_minor_node(dip, NULL);
	}

	mutex_destroy(&hidp->hid_mutex);

	USB_DPRINTF_L4(PRINT_MASK_ALL, hidp->hid_log_handle,
	    "hid_detach_cleanup: End");

done:
	usb_client_detach(dip, hidp->hid_dev_data);
	usb_free_log_hdl(hidp->hid_log_handle);
	ddi_soft_state_free(hid_statep, hidp->hid_instance);

	ddi_prop_remove_all(dip);
}


/*
 * hid_start_intr_polling:
 *	Allocate an interrupt request structure, initialize,
 *	and start interrupt transfers.
 */
static int
hid_start_intr_polling(hid_state_t *hidp)
{
	usb_intr_req_t	*req;
	int rval = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_PM, hidp->hid_log_handle,
	    "hid_start_intr_polling: "
	    "dev_state=%s internal_str_flag=%d external_str_flag=%d ph=0x%p",
	    usb_str_dev_state(hidp->hid_dev_state), hidp->hid_internal_flag,
	    hidp->hid_external_flag, (void *)hidp->hid_interrupt_pipe);

	if (HID_IS_OPEN(hidp) && (hidp->hid_interrupt_pipe != NULL)) {
		/*
		 * initialize interrupt pipe request structure
		 */
		req = usb_alloc_intr_req(hidp->hid_dip, 0, USB_FLAGS_SLEEP);
		req->intr_client_private = (usb_opaque_t)hidp;
		req->intr_attributes = USB_ATTRS_SHORT_XFER_OK |
		    USB_ATTRS_AUTOCLEARING;
		req->intr_len = hidp->hid_packet_size;
		req->intr_cb = hid_interrupt_pipe_callback;
		req->intr_exc_cb = hid_interrupt_pipe_exception_callback;

		/*
		 * Start polling on the interrupt pipe.
		 */
		mutex_exit(&hidp->hid_mutex);

		if ((rval = usb_pipe_intr_xfer(hidp->hid_interrupt_pipe, req,
		    USB_FLAGS_SLEEP)) != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_PM, hidp->hid_log_handle,
			    "hid_start_intr_polling failed: rval = %d",
			    rval);
			usb_free_intr_req(req);
		}

		mutex_enter(&hidp->hid_mutex);
	}

	USB_DPRINTF_L4(PRINT_MASK_PM, hidp->hid_log_handle,
	    "hid_start_intr_polling: done, rval = %d", rval);

	return (rval);
}


/*
 * hid_close_intr_pipe:
 *	close the interrupt pipe after draining all callbacks
 */
static void
hid_close_intr_pipe(hid_state_t *hidp)
{
	USB_DPRINTF_L4(PRINT_MASK_CLOSE, hidp->hid_log_handle,
	    "hid_close_intr_pipe: Begin");

	if (hidp->hid_interrupt_pipe) {
		/*
		 * Close the interrupt pipe
		 */
		mutex_exit(&hidp->hid_mutex);
		usb_pipe_close(hidp->hid_dip, hidp->hid_interrupt_pipe,
		    USB_FLAGS_SLEEP, NULL, NULL);
		mutex_enter(&hidp->hid_mutex);
		hidp->hid_interrupt_pipe = NULL;
	}
	USB_DPRINTF_L4(PRINT_MASK_CLOSE, hidp->hid_log_handle,
	    "hid_close_intr_pipe: End");
}


/*
 * hid_mctl_receive:
 *	Handle M_CTL messages from upper stream.  If
 *	we don't understand the command, free message.
 */
static int
hid_mctl_receive(register queue_t *q, register mblk_t *mp)
{
	hid_state_t	*hidp = (hid_state_t *)q->q_ptr;
	struct iocblk	*iocp;
	int		error = HID_FAILURE;
	uchar_t		request_type;
	hid_req_t	*hid_req_data = NULL;
	hid_polled_input_callback_t hid_polled_input;
	hid_vid_pid_t	hid_vid_pid;

	USB_DPRINTF_L4(PRINT_MASK_ALL, hidp->hid_log_handle,
	    "hid_mctl_receive");

	iocp = (struct iocblk *)mp->b_rptr;

	switch (iocp->ioc_cmd) {
	case HID_SET_REPORT:
		/* FALLTHRU */
	case HID_SET_IDLE:
		/* FALLTHRU */
	case HID_SET_PROTOCOL:
		request_type = USB_DEV_REQ_HOST_TO_DEV |
		    USB_DEV_REQ_RCPT_IF | USB_DEV_REQ_TYPE_CLASS;

		break;
	case HID_GET_REPORT:
		/* FALLTHRU */
	case HID_GET_IDLE:
		/* FALLTHRU */
	case HID_GET_PROTOCOL:
		request_type = USB_DEV_REQ_DEV_TO_HOST |
		    USB_DEV_REQ_RCPT_IF | USB_DEV_REQ_TYPE_CLASS;

		break;
	case HID_GET_PARSER_HANDLE:
		if (canputnext(RD(q))) {
			freemsg(mp->b_cont);
			mp->b_cont = hid_data2mblk(
			    (uchar_t *)&hidp->hid_report_descr,
			    sizeof (hidp->hid_report_descr));
			if (mp->b_cont == NULL) {
				/*
				 * can't allocate mblk, indicate
				 * that nothing is returned
				 */
				iocp->ioc_count = 0;
			} else {
				iocp->ioc_count =
				    sizeof (hidp->hid_report_descr);
			}
			qreply(q, mp);

			return (HID_SUCCESS);
		} else {

			/* retry */
			return (HID_ENQUEUE);
		}
	case HID_GET_VID_PID:
		if (canputnext(RD(q))) {
			freemsg(mp->b_cont);

			hid_vid_pid.VendorId =
			    hidp->hid_dev_descr->idVendor;
			hid_vid_pid.ProductId =
			    hidp->hid_dev_descr->idProduct;

			mp->b_cont = hid_data2mblk(
			    (uchar_t *)&hid_vid_pid, sizeof (hid_vid_pid_t));
			if (mp->b_cont == NULL) {
				/*
				 * can't allocate mblk, indicate that nothing
				 * is being returned.
				 */
				iocp->ioc_count = 0;
			} else {
				iocp->ioc_count =
				    sizeof (hid_vid_pid_t);
			}
			qreply(q, mp);

			return (HID_SUCCESS);
		} else {

			/* retry */
			return (HID_ENQUEUE);
		}
	case HID_OPEN_POLLED_INPUT:
		if (canputnext(RD(q))) {
			freemsg(mp->b_cont);

			/* Initialize the structure */
			hid_polled_input.hid_polled_version =
			    HID_POLLED_INPUT_V0;
			hid_polled_input.hid_polled_read = hid_polled_read;
			hid_polled_input.hid_polled_input_enter =
			    hid_polled_input_enter;
			hid_polled_input.hid_polled_input_exit =
			    hid_polled_input_exit;
			hid_polled_input.hid_polled_input_handle =
			    (hid_polled_handle_t)hidp;

			mp->b_cont = hid_data2mblk(
			    (uchar_t *)&hid_polled_input,
			    sizeof (hid_polled_input_callback_t));
			if (mp->b_cont == NULL) {
				/*
				 * can't allocate mblk, indicate that nothing
				 * is being returned.
				 */
				iocp->ioc_count = 0;
			} else {
				/* Call down into USBA */
				(void) hid_polled_input_init(hidp);

				iocp->ioc_count =
				    sizeof (hid_polled_input_callback_t);
			}
			qreply(q, mp);

			return (HID_SUCCESS);
		} else {

			/* retry */
			return (HID_ENQUEUE);
		}
	case HID_CLOSE_POLLED_INPUT:
		/* Call down into USBA */
		(void) hid_polled_input_fini(hidp);

		iocp->ioc_count = 0;
		qreply(q, mp);

		return (HID_SUCCESS);
	default:
		hid_qreply_merror(q, mp, EINVAL);

		return (HID_FAILURE);
	}

	/*
	 * These (device executable) commands require a hid_req_t.
	 * Make sure one is present
	 */
	if (mp->b_cont == NULL) {
		hid_qreply_merror(q, mp, EINVAL);

		return (error);
	} else {
		hid_req_data = (hid_req_t *)mp->b_cont->b_rptr;
		if ((iocp->ioc_cmd == HID_SET_REPORT) &&
		    (hid_req_data->hid_req_wLength == 0)) {
			hid_qreply_merror(q, mp, EINVAL);

			return (error);
		}
	}

	/*
	 * Check is version no. is correct. This
	 * is coming from the user
	 */
	if (hid_req_data->hid_req_version_no != HID_VERSION_V_0) {
		hid_qreply_merror(q, mp, EINVAL);

		return (error);
	}

	mutex_enter(&hidp->hid_mutex);
	USB_DPRINTF_L4(PRINT_MASK_ALL, hidp->hid_log_handle,
	    "hid_mctl_receive: dev_state=%s",
	    usb_str_dev_state(hidp->hid_dev_state));

	switch (hidp->hid_dev_state) {
	case USB_DEV_PWRED_DOWN:
		/*
		 * get the device full powered. We get a callback
		 * which enables the WQ and kicks off IO
		 */
		hidp->hid_dev_state = USB_DEV_HID_POWER_CHANGE;
		mutex_exit(&hidp->hid_mutex);
		if (usb_req_raise_power(hidp->hid_dip, 0,
		    USB_DEV_OS_FULL_PWR, hid_power_change_callback,
		    hidp, 0) != USB_SUCCESS) {
			/* we retry raising power in wsrv */
			mutex_enter(&hidp->hid_mutex);
			hidp->hid_dev_state = USB_DEV_PWRED_DOWN;
			mutex_exit(&hidp->hid_mutex);
		}
		error = HID_ENQUEUE;

		break;
	case USB_DEV_HID_POWER_CHANGE:
		mutex_exit(&hidp->hid_mutex);
		error = HID_ENQUEUE;

		break;
	case USB_DEV_ONLINE:
		if (HID_STREAMS_FLAG(q, hidp) != HID_STREAMS_DISMANTLING) {
			/* Send a message down */
			mutex_exit(&hidp->hid_mutex);
			error = hid_mctl_execute_cmd(q, request_type,
			    hid_req_data, mp);
			if (error == HID_FAILURE) {
				hid_qreply_merror(q, mp, EIO);
			}
		} else {
			mutex_exit(&hidp->hid_mutex);
			hid_qreply_merror(q, mp, EIO);
		}

		break;
	default:
		mutex_exit(&hidp->hid_mutex);
		hid_qreply_merror(q, mp, EIO);

		break;
	}

	return (error);
}


/*
 * hid_mctl_execute_cmd:
 *	Send the command to the device.
 */
static int
hid_mctl_execute_cmd(queue_t *q, int request_type, hid_req_t *hid_req_data,
    mblk_t *mp)
{
	int		request_index;
	struct iocblk	*iocp;
	hid_default_pipe_arg_t	*def_pipe_arg;
	hid_state_t	*hidp = (hid_state_t *)q->q_ptr;

	iocp = (struct iocblk *)mp->b_rptr;
	USB_DPRINTF_L4(PRINT_MASK_ALL, hidp->hid_log_handle,
	    "hid_mctl_execute_cmd: iocp=0x%p", (void *)iocp);

	request_index = hidp->hid_if_descr.bInterfaceNumber;

	/*
	 * Set up the argument to be passed back to hid
	 * when the asynchronous control callback is
	 * executed.
	 */
	def_pipe_arg = kmem_zalloc(sizeof (hid_default_pipe_arg_t), 0);

	if (def_pipe_arg == NULL) {

		return (HID_FAILURE);
	}

	def_pipe_arg->hid_default_pipe_arg_queue = q;
	def_pipe_arg->hid_default_pipe_arg_mctlmsg.ioc_cmd = iocp->ioc_cmd;
	def_pipe_arg->hid_default_pipe_arg_mctlmsg.ioc_count = 0;
	def_pipe_arg->hid_default_pipe_arg_mblk = mp;

	/*
	 * Send the command down to USBA through default
	 * pipe.
	 */
	if (hid_send_async_ctrl_request(def_pipe_arg, hid_req_data,
	    request_type, iocp->ioc_cmd, request_index) != USB_SUCCESS) {

		kmem_free(def_pipe_arg, sizeof (hid_default_pipe_arg_t));

		return (HID_FAILURE);
	}

	return (HID_INPROGRESS);
}


/*
 * hid_send_async_ctrl_request:
 *	Send an asynchronous control request to USBA.  Since hid is a STREAMS
 *	driver, it is not allowed to wait in its entry points except for the
 *	open and close entry points.  Therefore, hid must use the asynchronous
 *	USBA calls.
 */
static int
hid_send_async_ctrl_request(hid_default_pipe_arg_t *hid_default_pipe_arg,
    hid_req_t *hid_request, uchar_t request_type, int request_request,
    ushort_t request_index)
{
	queue_t		*q = hid_default_pipe_arg->hid_default_pipe_arg_queue;
	hid_state_t	*hidp = (hid_state_t *)q->q_ptr;
	usb_ctrl_req_t	*ctrl_req;
	int		rval;
	size_t		length = 0;

	USB_DPRINTF_L4(PRINT_MASK_ALL, hidp->hid_log_handle,
	    "hid_send_async_ctrl_request: "
	    "rq_type=%d rq_rq=%d index=%d",
	    request_type, request_request, request_index);

	mutex_enter(&hidp->hid_mutex);
	hidp->hid_default_pipe_req++;
	mutex_exit(&hidp->hid_mutex);

	/*
	 * Note that ctrl_req->ctrl_data should be allocated by usba
	 * only for IN requests. OUT request(e.g SET_REPORT) can have a
	 * non-zero wLength value but ctrl_data would be allocated by
	 * client for them.
	 */
	if (hid_request->hid_req_wLength >= MAX_REPORT_DATA) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, hidp->hid_log_handle,
		    "hid_req_wLength is exceeded");
		return (USB_FAILURE);
	}
	if ((request_type & USB_DEV_REQ_DIR_MASK) == USB_DEV_REQ_DEV_TO_HOST) {
		length = hid_request->hid_req_wLength;
	}

	if ((ctrl_req = usb_alloc_ctrl_req(hidp->hid_dip, length, 0)) == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, hidp->hid_log_handle,
		    "unable to alloc ctrl req. async trans failed");
		mutex_enter(&hidp->hid_mutex);
		hidp->hid_default_pipe_req--;
		ASSERT(hidp->hid_default_pipe_req >= 0);
		mutex_exit(&hidp->hid_mutex);

		return (USB_FAILURE);
	}

	if ((request_type & USB_DEV_REQ_DIR_MASK) == USB_DEV_REQ_HOST_TO_DEV) {
		ASSERT((length == 0) && (ctrl_req->ctrl_data == NULL));
	}

	ctrl_req->ctrl_bmRequestType	= request_type;
	ctrl_req->ctrl_bRequest		= (uint8_t)request_request;
	ctrl_req->ctrl_wValue		= hid_request->hid_req_wValue;
	ctrl_req->ctrl_wIndex		= request_index;
	ctrl_req->ctrl_wLength		= hid_request->hid_req_wLength;
	/* host to device: create a msg from hid_req_data */
	if ((request_type & USB_DEV_REQ_DIR_MASK) == USB_DEV_REQ_HOST_TO_DEV) {
		mblk_t *pblk = allocb(hid_request->hid_req_wLength, BPRI_HI);
		if (pblk == NULL) {
			usb_free_ctrl_req(ctrl_req);
			return (USB_FAILURE);
		}
		bcopy(hid_request->hid_req_data, pblk->b_wptr,
		    hid_request->hid_req_wLength);
		pblk->b_wptr += hid_request->hid_req_wLength;
		ctrl_req->ctrl_data = pblk;
	}
	ctrl_req->ctrl_attributes	= USB_ATTRS_AUTOCLEARING;
	ctrl_req->ctrl_client_private	= (usb_opaque_t)hid_default_pipe_arg;
	ctrl_req->ctrl_cb		= hid_default_pipe_callback;
	ctrl_req->ctrl_exc_cb		= hid_default_pipe_exception_callback;

	if ((rval = usb_pipe_ctrl_xfer(hidp->hid_default_pipe,
	    ctrl_req, 0)) != USB_SUCCESS) {
		mutex_enter(&hidp->hid_mutex);
		hidp->hid_default_pipe_req--;
		ASSERT(hidp->hid_default_pipe_req >= 0);
		mutex_exit(&hidp->hid_mutex);

		usb_free_ctrl_req(ctrl_req);
		USB_DPRINTF_L2(PRINT_MASK_ALL, hidp->hid_log_handle,
		    "usb_pipe_ctrl_xfer() failed. rval = %d", rval);

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}

/*
 * hid_create_pm_components:
 *	Create the pm components required for power management.
 *	For keyboard/mouse, the components is created only if the device
 *	supports a remote wakeup.
 *	For other hid devices they are created unconditionally.
 */
static void
hid_create_pm_components(dev_info_t *dip, hid_state_t *hidp)
{
	hid_power_t	*hidpm;
	uint_t		pwr_states;

	USB_DPRINTF_L4(PRINT_MASK_PM, hidp->hid_log_handle,
	    "hid_create_pm_components: Begin");

	/* Allocate the state structure */
	hidpm = kmem_zalloc(sizeof (hid_power_t), KM_SLEEP);
	hidp->hid_pm = hidpm;
	hidpm->hid_state = hidp;
	hidpm->hid_raise_power = B_FALSE;
	hidpm->hid_pm_capabilities = 0;
	hidpm->hid_current_power = USB_DEV_OS_FULL_PWR;

	switch (hidp->hid_if_descr.bInterfaceProtocol) {
	case KEYBOARD_PROTOCOL:
	case MOUSE_PROTOCOL:
		hidpm->hid_pm_strategy = HID_PM_ACTIVITY;
		if ((hid_is_pm_enabled(dip) == USB_SUCCESS) &&
		    (usb_handle_remote_wakeup(dip, USB_REMOTE_WAKEUP_ENABLE) ==
		    USB_SUCCESS)) {

			USB_DPRINTF_L3(PRINT_MASK_PM, hidp->hid_log_handle,
			    "hid_create_pm_components: Remote Wakeup Enabled");

			if (usb_create_pm_components(dip, &pwr_states) ==
			    USB_SUCCESS) {
				hidpm->hid_wakeup_enabled = 1;
				hidpm->hid_pwr_states = (uint8_t)pwr_states;
			}
		}

		break;
	default:
		hidpm->hid_pm_strategy = HID_PM_OPEN_CLOSE;
		if ((hid_is_pm_enabled(dip) == USB_SUCCESS) &&
		    (usb_create_pm_components(dip, &pwr_states) ==
		    USB_SUCCESS)) {
			hidpm->hid_wakeup_enabled = 0;
			hidpm->hid_pwr_states = (uint8_t)pwr_states;
		}

		break;
	}

	USB_DPRINTF_L4(PRINT_MASK_PM, hidp->hid_log_handle,
	    "hid_create_pm_components: END");
}


/*
 * hid_is_pm_enabled
 *	Check if the device is pm enabled. Always enable
 *	pm on the new SUN mouse
 */
static int
hid_is_pm_enabled(dev_info_t *dip)
{
	hid_state_t	*hidp = ddi_get_soft_state(hid_statep,
	    ddi_get_instance(dip));

	if (strcmp(ddi_node_name(dip), "mouse") == 0) {
		/* check for overrides first */
		if (hid_pm_mouse ||
		    (ddi_prop_exists(DDI_DEV_T_ANY, dip,
		    (DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
		    "hid-mouse-pm-enable") == 1)) {

			return (USB_SUCCESS);
		}

		/*
		 * Always enable PM for 1.05 or greater SUN mouse
		 * hidp->hid_dev_descr won't be NULL.
		 */
		if ((hidp->hid_dev_descr->idVendor ==
		    HID_SUN_MOUSE_VENDOR_ID) &&
		    (hidp->hid_dev_descr->idProduct ==
		    HID_SUN_MOUSE_PROD_ID) &&
		    (hidp->hid_dev_descr->bcdDevice >=
		    HID_SUN_MOUSE_BCDDEVICE)) {

			return (USB_SUCCESS);
		}
	} else {

		return (USB_SUCCESS);
	}

	return (USB_FAILURE);
}


/*
 * hid_save_device_state
 *	Save the current device/driver state.
 */
static void
hid_save_device_state(hid_state_t *hidp)
{
	struct iocblk	*mctlmsg;
	mblk_t		*mp;
	queue_t		*q;

	USB_DPRINTF_L4(PRINT_MASK_EVENTS, hidp->hid_log_handle,
	    "hid_save_device_state");

	if (!(HID_IS_OPEN(hidp)))
		return;

	if (hidp->hid_internal_flag == HID_STREAMS_OPEN) {
		/*
		 * Send MCTLs up indicating that the device
		 * will loose its state
		 */
		q = hidp->hid_internal_rq;

		mutex_exit(&hidp->hid_mutex);
		if (canputnext(q)) {
			mp = allocb(sizeof (struct iocblk), BPRI_HI);
			if (mp != NULL) {
				mp->b_datap->db_type = M_CTL;
				mctlmsg = (struct iocblk *)
				    mp->b_datap->db_base;
				mctlmsg->ioc_cmd = HID_DISCONNECT_EVENT;
				mctlmsg->ioc_count = 0;
				putnext(q, mp);
			}
		}
		mutex_enter(&hidp->hid_mutex);
	}

	if (hidp->hid_external_flag == HID_STREAMS_OPEN) {
		/*
		 * Send MCTLs up indicating that the device
		 * will loose its state
		 */
		q = hidp->hid_external_rq;

		mutex_exit(&hidp->hid_mutex);
		if (canputnext(q)) {
			mp = allocb(sizeof (struct iocblk), BPRI_HI);
			if (mp != NULL) {
				mp->b_datap->db_type = M_CTL;
				mctlmsg = (struct iocblk *)
				    mp->b_datap->db_base;
				mctlmsg->ioc_cmd = HID_DISCONNECT_EVENT;
				mctlmsg->ioc_count = 0;
				putnext(q, mp);
			}
		}
		mutex_enter(&hidp->hid_mutex);
	}

	mutex_exit(&hidp->hid_mutex);
	/* stop polling on the intr pipe */
	usb_pipe_stop_intr_polling(hidp->hid_interrupt_pipe, USB_FLAGS_SLEEP);
	mutex_enter(&hidp->hid_mutex);
}


/*
 * hid_restore_device_state:
 *	Set original configuration of the device.
 *	Reopen intr pipe.
 *	Enable wrq - this starts new transactions on the control pipe.
 */
static void
hid_restore_device_state(dev_info_t *dip, hid_state_t *hidp)
{
	int		rval;
	hid_power_t	*hidpm;
	struct iocblk	*mctlmsg;
	mblk_t		*mp;
	queue_t		*q;

	hid_pm_busy_component(hidp);
	mutex_enter(&hidp->hid_mutex);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, hidp->hid_log_handle,
	    "hid_restore_device_state: %s",
	    usb_str_dev_state(hidp->hid_dev_state));

	hidpm = hidp->hid_pm;
	mutex_exit(&hidp->hid_mutex);

	/* First bring the device to full power */
	(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);

	mutex_enter(&hidp->hid_mutex);
	if (hidp->hid_dev_state == USB_DEV_ONLINE) {
		/*
		 * We failed the checkpoint, there is no need to restore
		 * the device state
		 */
		mutex_exit(&hidp->hid_mutex);
		hid_pm_idle_component(hidp);

		return;
	}
	mutex_exit(&hidp->hid_mutex);


	/* Check if we are talking to the same device */
	if (usb_check_same_device(dip, hidp->hid_log_handle, USB_LOG_L2,
	    PRINT_MASK_ALL, USB_CHK_BASIC|USB_CHK_CFG, NULL) != USB_SUCCESS) {

		/* change the device state from suspended to disconnected */
		mutex_enter(&hidp->hid_mutex);
		hidp->hid_dev_state = USB_DEV_DISCONNECTED;
		mutex_exit(&hidp->hid_mutex);
		hid_pm_idle_component(hidp);
		goto nodev;
	}

	hid_set_idle(hidp);
	hid_set_protocol(hidp, SET_REPORT_PROTOCOL);

	mutex_enter(&hidp->hid_mutex);
	/* if the device had remote wakeup earlier, enable it again */
	if (hidpm->hid_wakeup_enabled) {
		mutex_exit(&hidp->hid_mutex);

		if ((rval = usb_handle_remote_wakeup(hidp->hid_dip,
		    USB_REMOTE_WAKEUP_ENABLE)) != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA,
			    hidp->hid_log_handle,
			    "usb_handle_remote_wakeup failed (%d)", rval);
		}

		mutex_enter(&hidp->hid_mutex);
	}

	/*
	 * restart polling on the interrupt pipe only if the device
	 * was previously operational (open)
	 */
	if (HID_IS_OPEN(hidp)) {
		if ((rval = hid_start_intr_polling(hidp)) != USB_SUCCESS) {
			USB_DPRINTF_L3(PRINT_MASK_ATTA, hidp->hid_log_handle,
			    "hid_restore_device_state:"
			    "unable to restart intr pipe poll"
			    " rval = %d ", rval);
			/*
			 * change the device state from
			 * suspended to disconnected
			 */
			hidp->hid_dev_state = USB_DEV_DISCONNECTED;
			mutex_exit(&hidp->hid_mutex);
			hid_pm_idle_component(hidp);
			goto nodev;
		}

		if (hidp->hid_dev_state == USB_DEV_DISCONNECTED) {
			USB_DPRINTF_L2(PRINT_MASK_EVENTS, hidp->hid_log_handle,
			    "device is being re-connected");
		}

		/* set the device state ONLINE */
		hidp->hid_dev_state = USB_DEV_ONLINE;

		/* inform upstream modules that the device is back */
		if (hidp->hid_internal_flag == HID_STREAMS_OPEN) {
			q = hidp->hid_internal_rq;

			mutex_exit(&hidp->hid_mutex);
			if (canputnext(q)) {
				mp = allocb(sizeof (struct iocblk), BPRI_HI);
				if (mp != NULL) {
					mp->b_datap->db_type = M_CTL;
					mctlmsg = (struct iocblk *)
					    mp->b_datap->db_base;
					mctlmsg->ioc_cmd = HID_CONNECT_EVENT;
					mctlmsg->ioc_count = 0;
					putnext(q, mp);
				}
			}
			/* enable write side q */
			qenable(WR(q));
			mutex_enter(&hidp->hid_mutex);
		}

		if (hidp->hid_external_flag == HID_STREAMS_OPEN) {
			q = hidp->hid_external_rq;

			mutex_exit(&hidp->hid_mutex);
			if (canputnext(q)) {
				mp = allocb(sizeof (struct iocblk), BPRI_HI);
				if (mp != NULL) {
					mp->b_datap->db_type = M_CTL;
					mctlmsg = (struct iocblk *)
					    mp->b_datap->db_base;
					mctlmsg->ioc_cmd = HID_CONNECT_EVENT;
					mctlmsg->ioc_count = 0;
					putnext(q, mp);
				}
			}
			/* enable write side q */
			qenable(WR(q));
			mutex_enter(&hidp->hid_mutex);
		}
	} else {
		/* set the device state ONLINE */
		hidp->hid_dev_state = USB_DEV_ONLINE;
	}

	mutex_exit(&hidp->hid_mutex);
	hid_pm_idle_component(hidp);
	return;

nodev:
	/*
	 * Notify applications about device removal. This only
	 * applies to an external (aka. physical) open. Not sure how to
	 * notify consconfig to close the internal minor node.
	 */
	mutex_enter(&hidp->hid_mutex);

	if ((q = hidp->hid_external_rq) == NULL) {
		mutex_exit(&hidp->hid_mutex);
		return;
	}

	mutex_exit(&hidp->hid_mutex);
	mp = allocb(sizeof (uchar_t), BPRI_HI);
	if (mp != NULL) {
		mp->b_datap->db_type = M_ERROR;
		mp->b_rptr = mp->b_datap->db_base;
		mp->b_wptr = mp->b_rptr + sizeof (char);
		*mp->b_rptr = ENODEV;
		putnext(q, mp);
	}
}


/*
 * hid_qreply_merror:
 *	Pass an error message up.
 */
static void
hid_qreply_merror(queue_t *q, mblk_t *mp, uchar_t errval)
{
	mp->b_datap->db_type = M_ERROR;
	if (mp->b_cont) {
		freemsg(mp->b_cont);
		mp->b_cont = NULL;
	}
	mp->b_rptr = mp->b_datap->db_base;
	mp->b_wptr = mp->b_rptr + sizeof (char);
	*mp->b_rptr = errval;

	qreply(q, mp);
}


/*
 * hid_data2mblk:
 *	Form an mblk from the given data
 */
static mblk_t *
hid_data2mblk(uchar_t *buf, int len)
{
	mblk_t	*mp = NULL;

	if (len >= 0) {
		mp = allocb(len, BPRI_HI);
		if (mp) {
			bcopy(buf, mp->b_datap->db_base, len);
			mp->b_wptr += len;
		}
	}

	return (mp);
}


/*
 * hid_flush :
 *	Flush data already sent upstreams to client module.
 */
static void
hid_flush(queue_t *q)
{
	/*
	 * Flush pending data already sent upstream
	 */
	if ((q != NULL) && (q->q_next != NULL)) {
		(void) putnextctl1(q, M_FLUSH, FLUSHR);
	}
}


static void
hid_pm_busy_component(hid_state_t *hid_statep)
{
	ASSERT(!mutex_owned(&hid_statep->hid_mutex));

	if (hid_statep->hid_pm != NULL) {
		mutex_enter(&hid_statep->hid_mutex);
		hid_statep->hid_pm->hid_pm_busy++;

		USB_DPRINTF_L4(PRINT_MASK_PM, hid_statep->hid_log_handle,
		    "hid_pm_busy_component: %d",
		    hid_statep->hid_pm->hid_pm_busy);

		mutex_exit(&hid_statep->hid_mutex);
		if (pm_busy_component(hid_statep->hid_dip, 0) != DDI_SUCCESS) {
			mutex_enter(&hid_statep->hid_mutex);
			hid_statep->hid_pm->hid_pm_busy--;

			USB_DPRINTF_L2(PRINT_MASK_PM,
			    hid_statep->hid_log_handle,
			    "hid_pm_busy_component failed: %d",
			    hid_statep->hid_pm->hid_pm_busy);

			mutex_exit(&hid_statep->hid_mutex);
		}

	}
}


static void
hid_pm_idle_component(hid_state_t *hid_statep)
{
	ASSERT(!mutex_owned(&hid_statep->hid_mutex));

	if (hid_statep->hid_pm != NULL) {
		if (pm_idle_component(hid_statep->hid_dip, 0) == DDI_SUCCESS) {
			mutex_enter(&hid_statep->hid_mutex);
			ASSERT(hid_statep->hid_pm->hid_pm_busy > 0);
			hid_statep->hid_pm->hid_pm_busy--;

			USB_DPRINTF_L4(PRINT_MASK_PM,
			    hid_statep->hid_log_handle,
			    "hid_pm_idle_component: %d",
			    hid_statep->hid_pm->hid_pm_busy);

			mutex_exit(&hid_statep->hid_mutex);
		}
	}
}


/*
 * hid_pwrlvl0:
 *	Functions to handle power transition for various levels
 *	These functions act as place holders to issue USB commands
 *	to the devices to change their power levels
 */
static int
hid_pwrlvl0(hid_state_t *hidp)
{
	hid_power_t	*hidpm;
	int		rval;
	struct iocblk	*mctlmsg;
	mblk_t		*mp_lowpwr, *mp_fullpwr;
	queue_t		*q;

	hidpm = hidp->hid_pm;

	switch (hidp->hid_dev_state) {
	case USB_DEV_ONLINE:
		/* Deny the powerdown request if the device is busy */
		if (hidpm->hid_pm_busy != 0) {

			return (USB_FAILURE);
		}

		if (HID_IS_OPEN(hidp)) {
			q = hidp->hid_inuse_rq;
			mutex_exit(&hidp->hid_mutex);
			if (canputnext(q)) {
				/* try to preallocate mblks */
				mp_lowpwr = allocb(
				    (int)sizeof (struct iocblk), BPRI_HI);
				mp_fullpwr = allocb(
				    (int)sizeof (struct iocblk), BPRI_HI);
				if ((mp_lowpwr != NULL) &&
				    (mp_fullpwr != NULL)) {
					/* stop polling */
					usb_pipe_stop_intr_polling(
					    hidp->hid_interrupt_pipe,
					    USB_FLAGS_SLEEP);

					/*
					 * Send an MCTL up indicating that
					 * we are powering off
					 */
					mp_lowpwr->b_datap->db_type = M_CTL;
					mctlmsg = (struct iocblk *)
					    mp_lowpwr->b_datap->db_base;
					mctlmsg->ioc_cmd = HID_POWER_OFF;
					mctlmsg->ioc_count = 0;
					putnext(q, mp_lowpwr);

					/* save the full powr mblk */
					mutex_enter(&hidp->hid_mutex);
					hidpm->hid_pm_pwrup = mp_fullpwr;
				} else {
					/*
					 * Since we failed to allocate one
					 * or more mblks, we fail attempt
					 * to go into low power this time
					 */
					freemsg(mp_lowpwr);
					freemsg(mp_fullpwr);
					mutex_enter(&hidp->hid_mutex);

					return (USB_FAILURE);
				}
			} else {
				/*
				 * Since we can't send an mblk up,
				 * we fail this attempt to go to low power
				 */
				mutex_enter(&hidp->hid_mutex);

				return (USB_FAILURE);
			}
		}

		mutex_exit(&hidp->hid_mutex);
		/* Issue USB D3 command to the device here */
		rval = usb_set_device_pwrlvl3(hidp->hid_dip);
		ASSERT(rval == USB_SUCCESS);

		mutex_enter(&hidp->hid_mutex);
		hidp->hid_dev_state = USB_DEV_PWRED_DOWN;
		hidpm->hid_current_power = USB_DEV_OS_PWR_OFF;

		/* FALLTHRU */
	case USB_DEV_DISCONNECTED:
	case USB_DEV_SUSPENDED:
	case USB_DEV_PWRED_DOWN:
	default:
		break;
	}

	return (USB_SUCCESS);
}


/* ARGSUSED */
static int
hid_pwrlvl1(hid_state_t *hidp)
{
	int		rval;

	/* Issue USB D2 command to the device here */
	rval = usb_set_device_pwrlvl2(hidp->hid_dip);
	ASSERT(rval == USB_SUCCESS);

	return (USB_FAILURE);
}


/* ARGSUSED */
static int
hid_pwrlvl2(hid_state_t *hidp)
{
	int		rval;

	rval = usb_set_device_pwrlvl1(hidp->hid_dip);
	ASSERT(rval == USB_SUCCESS);

	return (USB_FAILURE);
}


static int
hid_pwrlvl3(hid_state_t *hidp)
{
	hid_power_t	*hidpm;
	int		rval;
	struct iocblk	*mctlmsg;
	mblk_t		*mp;
	queue_t		*q;

	hidpm = hidp->hid_pm;

	switch (hidp->hid_dev_state) {
	case USB_DEV_HID_POWER_CHANGE:
	case USB_DEV_PWRED_DOWN:
		/* Issue USB D0 command to the device here */
		rval = usb_set_device_pwrlvl0(hidp->hid_dip);
		ASSERT(rval == USB_SUCCESS);

		if (HID_IS_OPEN(hidp)) {
			/* restart polling on intr pipe */
			rval = hid_start_intr_polling(hidp);
			if (rval != USB_SUCCESS) {
				USB_DPRINTF_L2(PRINT_MASK_EVENTS,
				    hidp->hid_log_handle,
				    "unable to restart intr polling rval = %d",
				    rval);

				return (USB_FAILURE);
			}

			/* Send an MCTL up indicating device in full  power */
			q = hidp->hid_inuse_rq;
			mp = hidpm->hid_pm_pwrup;
			hidpm->hid_pm_pwrup = NULL;
			mutex_exit(&hidp->hid_mutex);
			if (canputnext(q)) {
				mp->b_datap->db_type = M_CTL;
				mctlmsg = (struct iocblk *)
				    mp->b_datap->db_base;
				mctlmsg->ioc_cmd = HID_FULL_POWER;
				mctlmsg->ioc_count = 0;
				putnext(q, mp);
			} else {
				freemsg(mp);
			}
			mutex_enter(&hidp->hid_mutex);
		}

		hidp->hid_dev_state = USB_DEV_ONLINE;
		hidpm->hid_current_power = USB_DEV_OS_FULL_PWR;

		/* FALLTHRU */
	case USB_DEV_DISCONNECTED:
	case USB_DEV_SUSPENDED:
	case USB_DEV_ONLINE:

		return (USB_SUCCESS);
	default:
		USB_DPRINTF_L2(PRINT_MASK_EVENTS, hidp->hid_log_handle,
		    "hid_pwrlvl3: Improper State");

		return (USB_FAILURE);
	}
}


/*
 * hid_polled_input_init :
 *	This routine calls down to the lower layers to initialize any state
 *	information.  This routine initializes the lower layers for input.
 */
static int
hid_polled_input_init(hid_state_t *hidp)
{
	USB_DPRINTF_L4(PRINT_MASK_ALL, hidp->hid_log_handle,
	    "hid_polled_input_init");

	/*
	 * Call the lower layers to intialize any state information
	 * that they will need to provide the polled characters.
	 */
	if (usb_console_input_init(hidp->hid_dip, hidp->hid_interrupt_pipe,
	    &hidp->hid_polled_raw_buf,
	    &hidp->hid_polled_console_info) != USB_SUCCESS) {
		/*
		 * If for some reason the lower layers cannot initialized, then
		 * bail.
		 */
		(void) hid_polled_input_fini(hidp);

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


/*
 * hid_polled_input_fini:
 *	This routine is called when we are done using this device as an input
 *	device.
 */
static int
hid_polled_input_fini(hid_state_t *hidp)
{
	USB_DPRINTF_L4(PRINT_MASK_ALL, hidp->hid_log_handle,
	    "hid_polled_input_fini");

	/*
	 * Call the lower layers to free any state information
	 * only if polled input has been initialised.
	 */
	if ((hidp->hid_polled_console_info) &&
	    (usb_console_input_fini(hidp->hid_polled_console_info) !=
	    USB_SUCCESS)) {

		return (USB_FAILURE);
	}
	hidp->hid_polled_console_info = NULL;

	return (USB_SUCCESS);
}


/*
 * hid_polled_input_enter:
 *	This is the routine that is called in polled mode to save the USB
 *	state information before using the USB keyboard as an input device.
 *	This routine, and all of the routines that it calls, are responsible
 *	for saving any state information so that it can be restored when
 *	polling mode is over.
 */
static int
/* ARGSUSED */
hid_polled_input_enter(hid_polled_handle_t hid_polled_inputp)
{
	hid_state_t *hidp = (hid_state_t *)hid_polled_inputp;

	/*
	 * Call the lower layers to tell them to save any state information.
	 */
	(void) usb_console_input_enter(hidp->hid_polled_console_info);

	return (USB_SUCCESS);
}


/*
 * hid_polled_read :
 *	This is the routine that is called in polled mode when it wants to read
 *	a character.  We will call to the lower layers to see if there is any
 *	input data available.  If there is USB scancodes available, we will
 *	give them back.
 */
static int
hid_polled_read(hid_polled_handle_t hid_polled_input, uchar_t **buffer)
{
	hid_state_t *hidp = (hid_state_t *)hid_polled_input;
	uint_t			num_bytes;

	/*
	 * Call the lower layers to get the character from the controller.
	 * The lower layers will return the number of characters that
	 * were put in the raw buffer.	The address of the raw buffer
	 * was passed down to the lower layers during hid_polled_init.
	 */
	if (usb_console_read(hidp->hid_polled_console_info,
	    &num_bytes) != USB_SUCCESS) {

		return (0);
	}

	_NOTE(NO_COMPETING_THREADS_NOW);

	*buffer = hidp->hid_polled_raw_buf;

	_NOTE(COMPETING_THREADS_NOW);

	/*
	 * Return the number of characters that were copied into the
	 * polled buffer.
	 */
	return (num_bytes);
}


/*
 * hid_polled_input_exit :
 *	This is the routine that is called in polled mode  when it is giving up
 *	control of the USB keyboard.  This routine, and the lower layer routines
 *	that it calls, are responsible for restoring the controller state to the
 *	state it was in before polled mode.
 */
static int
hid_polled_input_exit(hid_polled_handle_t hid_polled_inputp)
{
	hid_state_t *hidp = (hid_state_t *)hid_polled_inputp;

	/*
	 * Call the lower layers to restore any state information.
	 */
	(void) usb_console_input_exit(hidp->hid_polled_console_info);

	return (0);
}

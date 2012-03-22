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
/*
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 */

/*
 * The Data Transfer Interface driver for Host Wire Adapter device
 *
 * HWA device has two interfaces, one is the data transfer interface,
 * another is the radio control interface. This driver (hwahc) is only
 * for data transfer interface support, but it depends on the radio
 * control interface driver (hwarc) to work. That means the hwarc
 * driver must be loaded while the hwahc is working. This is now
 * ensured by holding hwarc open until hwahc detaches or powers down.
 *
 * The data transfer interface has three endpoints besides the default
 * control endpoint which is shared between the two interfaces. The
 * three endpoints are:
 *
 * - notification endpoint (intr in type, for asynchronous event
 * notifications and transfer status notifications)
 *
 * - data transfer OUT endpoint (bulk out type, for sending transfer
 * requests and transfer data from the host to the HWA device)
 *
 * - data transfer IN endpoint (bulk in type, for returning transfer
 * status and transfer data from the HWA device to the host)
 *
 * The HWA device is a USB 2.0 device, so it supports the standard USB
 * requests defined in chapter 9 of USB 2.0 specification as other USB
 * client devices. But its most important functionality is to work as
 * a wireless USB host. This means the hwahc driver needs to supply
 * host controller functionalities, which include children hotplug
 * support and data transfer support to children device endpoints.
 *
 * So hwahc driver is implemented as a nexus driver and it follows the
 * event mechanism in existing USBA framework to support children
 * hotplug events.
 *
 * The hwahc driver works as the root-hub on wireless USB bus. And it
 * relays data transfers to/from wireless bus to the USB bus where ehci/
 * ohci/uhci works as the root-hub. This makes a bus cascading topology.
 *
 * The data transfer to/from wireless device endpoints is implemented by
 * remote pipe (rpipe) mechanism. The rpipe descriptor on the HWA defines
 * the attributes of a wireless USB transfer, such as the transfer type,
 * the target device address, the target endpoint address and the max
 * packet size. And the transfer requests through data transfer OUT
 * endpoint will take a certain rpipe as the transfer target, thus
 * fulfills the data transfer across buses. Refer to chapter 8 of WUSB
 * 1.0 specification for details of this.
 */

#define	USBDRV_MAJOR_VER	2
#define	USBDRV_MINOR_VER	0

#include <sys/usb/hwa/hwahc/hwahc.h>
#include <sys/usb/hwa/hwahc/hwahc_util.h>
#include <sys/usb/usba/wa.h>
#include <sys/usb/usba/wusba.h>
#include <sys/usb/usba/whcdi.h>
#include <sys/usb/usba.h>
#include <sys/usb/usba/usba_impl.h>
#include <sys/usb/usba/usba_devdb.h>	/* for usba_devdb_refresh */
#include <sys/usb/hubd/hubdvar.h>
#include <sys/usb/hubd/hubd_impl.h>	/* for hubd_ioctl_data_t */
#include <sys/strsubr.h>	/* for allocb_wait */
#include <sys/strsun.h>		/* for MBLKL macro */
#include <sys/fs/dv_node.h>	/* for devfs_clean */
#include <sys/uwb/uwbai.h>	/* for uwb ioctls */
#include <sys/random.h>

void *hwahc_statep;

/* number of instances */
#define	HWAHC_INSTS	1

/* default value for set number DNTS slots request */
#define	HWAHC_DEFAULT_DNTS_INTERVAL	2 /* ms */
#define	HWAHC_DEFAULT_DNTS_SLOT_NUM	4


/* debug support */
uint_t	hwahc_errmask	= (uint_t)PRINT_MASK_ALL;
uint_t	hwahc_errlevel	= USB_LOG_L4;
uint_t	hwahc_instance_debug = (uint_t)-1;

/* bus config debug flag */
uint_t	hwahc_bus_config_debug = 0;
uint8_t	hwahc_enable_trust_timeout = 1;


/*
 * Use the default GTK for the whole life of HWA driver.
 * Not so compatible with WUSB spec.
 */
static uint8_t	dft_gtk[16];
static uint8_t	dft_gtkid[3];

extern usb_log_handle_t	whcdi_log_handle;

/*
 * Function Prototypes
 */
/* driver operations (dev_ops) entry points */
static int	hwahc_open(dev_t *, int, int, cred_t *);
static int	hwahc_close(dev_t, int, int, cred_t *);
static int	hwahc_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static int	hwahc_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int	hwahc_attach(dev_info_t *, ddi_attach_cmd_t);
static int	hwahc_detach(dev_info_t *, ddi_detach_cmd_t);
static int	hwahc_power(dev_info_t *, int, int);

/* bus_ops entry points */
static int	hwahc_bus_ctl(dev_info_t *, dev_info_t *, ddi_ctl_enum_t,
		void *, void *);
static int	hwahc_busop_get_eventcookie(dev_info_t *, dev_info_t *,
		char *, ddi_eventcookie_t *);
static int	hwahc_busop_add_eventcall(
		dev_info_t *, dev_info_t *, ddi_eventcookie_t,
		void (*)(dev_info_t *, ddi_eventcookie_t, void *, void *),
		void *, ddi_callback_id_t *);
static int	hwahc_busop_remove_eventcall(dev_info_t *, ddi_callback_id_t);
static int	hwahc_bus_config(dev_info_t *, uint_t, ddi_bus_config_op_t,
		void *, dev_info_t **);
static int	hwahc_bus_unconfig(dev_info_t *, uint_t, ddi_bus_config_op_t,
		void *);

/* hotplug and power management supporting functions */
static int	hwahc_disconnect_event_cb(dev_info_t *dip);
static int	hwahc_reconnect_event_cb(dev_info_t *dip);
static int	hwahc_pre_suspend_event_cb(dev_info_t *dip);
static int	hwahc_post_resume_event_cb(dev_info_t *dip);
static int	hwahc_cpr_suspend(dev_info_t *);
static int	hwahc_cpr_resume(dev_info_t *);
static void	hwahc_restore_device_state(dev_info_t *, hwahc_state_t *);
static void	hwahc_run_callbacks(hwahc_state_t *, usba_event_t);
static void	hwahc_post_event(hwahc_state_t *, usb_port_t, usba_event_t);

static int	hwahc_cleanup(dev_info_t *, hwahc_state_t *);
static void	hwahc_create_pm_components(dev_info_t *, hwahc_state_t *);
static void	hwahc_destroy_pm_components(hwahc_state_t *);
static void	hwahc_pm_busy_component(hwahc_state_t *);
static void	hwahc_pm_idle_component(hwahc_state_t *);
static int	hwahc_pwrlvl0(hwahc_state_t *);
static int	hwahc_pwrlvl1(hwahc_state_t *);
static int	hwahc_pwrlvl2(hwahc_state_t *);
static int	hwahc_pwrlvl3(hwahc_state_t *);
static int	hwahc_hc_channel_suspend(hwahc_state_t *);

/* hardware initialization and deinitialization functions */
static int	hwahc_parse_security_data(wusb_secrt_data_t *,
		usb_cfg_data_t *);
static void	hwahc_print_secrt_data(hwahc_state_t *);

static int	hwahc_hub_attach(hwahc_state_t *);
static int	hwahc_hub_detach(hwahc_state_t *);

static int	hwahc_hc_initial_start(hwahc_state_t *);
static int	hwahc_hc_final_stop(hwahc_state_t *);
static int	hwahc_wa_start(hwahc_state_t *);
static void	hwahc_wa_stop(hwahc_state_t *);
static int	hwahc_hc_channel_start(hwahc_state_t *);
static int	hwahc_hc_channel_stop(hwahc_state_t *);
static void	hwahc_hc_data_init(hwahc_state_t *);
static void	hwahc_hc_data_fini(hwahc_state_t *);

/* ioctl support */
static int	hwahc_cfgadm_ioctl(hwahc_state_t *, int, intptr_t, int,
		cred_t *, int *);
static int	hwahc_wusb_ioctl(hwahc_state_t *, int, intptr_t, int,
		cred_t *, int *);

/* callbacks registered to USBA */
static void	hwahc_disconnect_dev(dev_info_t *, usb_port_t);
static void	hwahc_reconnect_dev(dev_info_t *, usb_port_t);
static int	hwahc_create_child(dev_info_t *, usb_port_t);
static int	hwahc_destroy_child(dev_info_t *, usb_port_t);
static int	hwahc_cleanup_child(dev_info_t *);
static int	hwahc_delete_child(dev_info_t *, usb_port_t, uint_t, boolean_t);

/* data transfer and notification handling */
static void	hwahc_intr_cb(usb_pipe_handle_t, struct usb_intr_req *);
static void	hwahc_intr_exc_cb(usb_pipe_handle_t, struct usb_intr_req *);
static void	hwahc_handle_notif(hwahc_state_t *, mblk_t *);
static void	hwahc_handle_xfer_result(hwahc_state_t *, uint8_t);
static void	hwahc_stop_result_thread(hwahc_state_t *);
static void	hwahc_result_thread(void *);
static void	hwahc_handle_dn_notif(hwahc_state_t *, hwa_notif_dn_recvd_t *);
static void	hwahc_notif_thread(void *);
static void	hwahc_handle_dn(hwahc_state_t *, hwa_notif_dn_recvd_t *);
static void	hwahc_drain_notif_queue(hwahc_state_t *);
static void	hwahc_rpipe_xfer_cb(dev_info_t *, usba_pipe_handle_data_t *,
		wusb_wa_trans_wrapper_t *, usb_cr_t);

static void	hwahc_trust_timeout_handler(void *arg);
static void	hwahc_stop_trust_timer(wusb_dev_info_t *dev);

static int hwahc_pipe_submit_periodic_req(wusb_wa_data_t *wa_data,
	usba_pipe_handle_data_t *ph);

/* hwa specific requests */
static int	hwahc_set_chid(hwahc_state_t *, uint8_t *);

/* helper functions */
static usb_port_t hwahc_get_port_num(hwahc_state_t *, struct devctl_iocdata *);
static dev_info_t *hwahc_get_child_dip(hwahc_state_t *, usb_port_t);

static struct cb_ops hwahc_cb_ops = {
	hwahc_open,			/* Open */
	hwahc_close,			/* Close */
	nodev,				/* Strategy */
	nodev,				/* Print */
	nodev,				/* Dump */
	nodev,				/* Read */
	nodev,				/* Write */
	hwahc_ioctl,			/* Ioctl */
	nodev,				/* Devmap */
	nodev,				/* Mmap */
	nodev,				/* Segmap */
	nochpoll,			/* Poll */
	ddi_prop_op,			/* cb_prop_op */
	NULL,				/* Streamtab */
	D_MP				/* Driver compatibility flag */
};

static struct bus_ops hwahc_busops = {
	BUSO_REV,
	nullbusmap,			/* bus_map */
	NULL,				/* bus_get_intrspec */
	NULL,				/* bus_add_intrspec */
	NULL,				/* bus_remove_intrspec */
	NULL,				/* bus_map_fault */
	NULL,				/* bus_dma_map */
	ddi_dma_allochdl,
	ddi_dma_freehdl,
	ddi_dma_bindhdl,
	ddi_dma_unbindhdl,
	ddi_dma_flush,
	ddi_dma_win,
	ddi_dma_mctl,			/* bus_dma_ctl */
	hwahc_bus_ctl,			/* bus_ctl */
	ddi_bus_prop_op,		/* bus_prop_op */
	hwahc_busop_get_eventcookie,	/* bus_get_eventcookie */
	hwahc_busop_add_eventcall,	/* bus_add_eventcall */
	hwahc_busop_remove_eventcall,	/* bus_remove_eventcall */
	NULL,				/* bus_post_event */
	NULL,				/* bus_intr_ctl */
	hwahc_bus_config,		/* bus_config */
	hwahc_bus_unconfig,		/* bus_unconfig */
	NULL,				/* bus_fm_init */
	NULL,				/* bus_fm_fini */
	NULL,				/* bus_fm_access_enter */
	NULL,				/* bus_fm_access_exit */
	NULL,				/* bus_power */
};

static struct dev_ops hwahc_ops = {
	DEVO_REV,			/* Devo_rev */
	0,				/* Refcnt */
	hwahc_info,			/* Info */
	nulldev,			/* Identify */
	nulldev,			/* Probe */
	hwahc_attach,			/* Attach */
	hwahc_detach,			/* Detach */
	nodev,				/* Reset */
	&hwahc_cb_ops,			/* Driver operations */
	&hwahc_busops,			/* Bus operations */
	hwahc_power,			/* Power */
	ddi_quiesce_not_needed,		/* devo_quiesce */
};

static struct modldrv hwahc_modldrv =	{
	&mod_driverops,
	"WUSB hwa-hc driver",
	&hwahc_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&hwahc_modldrv,
	NULL
};

/* events from parent */
static usb_event_t hwahc_events = {
	hwahc_disconnect_event_cb,
	hwahc_reconnect_event_cb,
	hwahc_pre_suspend_event_cb,
	hwahc_post_resume_event_cb
};

/*
 * events support for children
 * A map tween USBA_EVENTs and DDI_EVENTs.
 */
static ndi_event_definition_t hwahc_ndi_event_defs[] = {
	{USBA_EVENT_TAG_HOT_REMOVAL, DDI_DEVI_REMOVE_EVENT, EPL_KERNEL,
						NDI_EVENT_POST_TO_ALL},
	{USBA_EVENT_TAG_HOT_INSERTION, DDI_DEVI_INSERT_EVENT, EPL_KERNEL,
						NDI_EVENT_POST_TO_ALL},
	{USBA_EVENT_TAG_POST_RESUME, USBA_POST_RESUME_EVENT, EPL_KERNEL,
						NDI_EVENT_POST_TO_ALL},
	{USBA_EVENT_TAG_PRE_SUSPEND, USBA_PRE_SUSPEND_EVENT, EPL_KERNEL,
						NDI_EVENT_POST_TO_ALL}
};

#define	HWAHC_N_NDI_EVENTS \
	(sizeof (hwahc_ndi_event_defs) / sizeof (ndi_event_definition_t))

static	ndi_event_set_t hwahc_ndi_events = {
	NDI_EVENTS_REV1, HWAHC_N_NDI_EVENTS, hwahc_ndi_event_defs};

/* transfer callbacks */
static wusb_wa_cb_t hwahc_cbs = {
	hwahc_pipe_submit_periodic_req,
	hwahc_intr_cb,
	hwahc_intr_exc_cb,
	hwahc_rpipe_xfer_cb
};


/*
 * Module-wide initialization routine.
 */
int
_init(void)
{
	int rval;

	if ((rval = ddi_soft_state_init(&hwahc_statep, sizeof (hwahc_state_t),
	    HWAHC_INSTS)) != 0) {

		return (rval);
	}

	if ((rval = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&hwahc_statep);
	}

	return (rval);
}


/*
 * Module-wide tear-down routine.
 */
int
_fini(void)
{
	int rval;

	if ((rval = mod_remove(&modlinkage)) == 0) {
		/* Release per module resources */
		ddi_soft_state_fini(&hwahc_statep);
	}

	return (rval);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * hwahc_info:
 *	Get minor number, instance number, etc.
 */
/*ARGSUSED*/
static int
hwahc_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
	void *arg, void **result)
{
	hwahc_state_t	*hwahcp;
	int error = DDI_FAILURE;
	int instance = HWAHC_MINOR_TO_INSTANCE(getminor((dev_t)arg));

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((hwahcp = ddi_get_soft_state(hwahc_statep,
		    instance)) != NULL) {
			*result = hwahcp->hwahc_dip;
			if (*result != NULL) {
				error = DDI_SUCCESS;
			}
		} else {
			*result = NULL;
		}
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
 * hwahc_attach:
 *	Attach or resume.
 *
 *	For attach, initialize state and device, including:
 *		state variables, locks, device node,
 *		resource initialization, event registration,
 *		device registration with system
 *		power management, hotplugging
 *	For resume, restore device and state
 */
static int
hwahc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int				instance = ddi_get_instance(dip);
	hwahc_state_t			*hwahcp = NULL;
	usb_client_dev_data_t		*dev_data;
	struct usb_cfg_data		*cfg_data;
	usba_hcdi_register_args_t	hcdi_args;
	int				rval;
	char *pathname;

	USB_DPRINTF_L3(PRINT_MASK_ATTA, NULL, "hwahc_attach: cmd=%d", cmd);

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		(void) hwahc_cpr_resume(dip);

		return (DDI_SUCCESS);
	default:
		USB_DPRINTF_L2(PRINT_MASK_ATTA, NULL,
		    "hwahc_attach: failed");

		return (DDI_FAILURE);
	}

	/*
	 * Allocate soft state information.
	 */
	rval = ddi_soft_state_zalloc(hwahc_statep, instance);
	if (rval != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, NULL,
		    "hwahc_attach: cannot allocate soft state for instance %d",
		    instance);

		return (USB_FAILURE);
	}

	hwahcp = ddi_get_soft_state(hwahc_statep, instance);
	if (hwahcp == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, NULL,
		    "hwahc_attach: get soft state failed for instance %d",
		    instance);

		return (USB_FAILURE);
	}

	hwahcp->hwahc_log_handle = usb_alloc_log_hdl(dip, "hwahc",
	    &hwahc_errlevel, &hwahc_errmask, &hwahc_instance_debug, 0);

	/* initialize hc state */
	hwahcp->hwahc_hc_soft_state = HWAHC_CTRL_INIT_STATE;
	hwahcp->hwahc_dip = dip;
	hwahcp->hwahc_instance = instance;

	/* register with USBA as client driver */
	if (usb_client_attach(dip, USBDRV_VERSION, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_attach: client attach failed");

		goto fail;
	}

	if (usb_get_dev_data(dip, &dev_data, USB_PARSE_LVL_IF, 0) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_attach: cannot get dev_data");

		goto fail;
	}

	/* initialize mutex and cv */
	mutex_init(&hwahcp->hwahc_mutex, NULL, MUTEX_DRIVER,
	    dev_data->dev_iblock_cookie);
	cv_init(&hwahcp->hwahc_result_thread_cv, NULL, CV_DRIVER, NULL);

	hwahcp->hwahc_flags |= HWAHC_LOCK_INITED;
	hwahcp->hwahc_dev_data = dev_data;

	/* initialize data transfer function related structure */
	if (wusb_wa_data_init(dip, &hwahcp->hwahc_wa_data, &hwahc_cbs,
	    dev_data, PRINT_MASK_ATTA,
	    hwahcp->hwahc_log_handle) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_attach: init wa data failed");

		goto fail;
	}

	hwahcp->hwahc_flags |= HWAHC_WA_INITED;
	cfg_data = dev_data->dev_curr_cfg;

	/* parse the security descrs from the configuration descr cloud */
	if (hwahc_parse_security_data(&hwahcp->hwahc_secrt_data, cfg_data) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_attach: parse security descrs failed");

		goto fail;
	}

	hwahcp->hwahc_default_pipe = dev_data->dev_default_ph;
	hwahcp->hwahc_wa_data.wa_private_data = (void *)hwahcp;
	hwahcp->hwahc_wa_data.wa_default_pipe = hwahcp->hwahc_default_pipe;

	usb_free_descr_tree(dip, dev_data);

	hwahcp->hwahc_dev_state = USB_DEV_ONLINE;

	/* now create components to power manage this device */
	hwahc_create_pm_components(dip, hwahcp);

	/*
	 * Event definition and registration
	 *
	 * allocate a new NDI event handle as a nexus driver
	 */
	(void) ndi_event_alloc_hdl(dip, 0, &hwahcp->hwahc_ndi_event_hdl,
	    NDI_SLEEP);

	/*
	 * bind our NDI events with the event handle,
	 * i.e. Define the events set we're to support as a nexus driver.
	 *
	 * These events will be used by bus_ops functions to register callbacks.
	 */
	if (ndi_event_bind_set(hwahcp->hwahc_ndi_event_hdl, &hwahc_ndi_events,
	    NDI_SLEEP)) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_attach: binding event set failed");

		goto fail;
	}


	/*
	 * Register USB events to USBA(the parent) to get callbacks as a
	 * child of (root) hub
	 */
	if (usb_register_event_cbs(dip, &hwahc_events, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_attach: register_events failed");

		goto fail;
	}

	hwahcp->hwahc_flags |= HWAHC_EVENTS_REGISTERED;

	/* create minor nodes */
	if (ddi_create_minor_node(dip, "hwahc", S_IFCHR,
	    instance << HWAHC_MINOR_INSTANCE_SHIFT,
	    DDI_NT_NEXUS, 0) != DDI_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_attach: cannot create minor node");

		goto fail;
	}

	hwahcp->hwahc_flags |= HWAHC_MINOR_NODE_CREATED;

	hwahcp->hwahc_hcdi_ops = hwahc_alloc_hcdi_ops(hwahcp);

	/* register this hc instance with usba HCD interface */
	hcdi_args.usba_hcdi_register_version = HCDI_REGISTER_VERSION;
	hcdi_args.usba_hcdi_register_dip = dip;
	hcdi_args.usba_hcdi_register_ops = hwahcp->hwahc_hcdi_ops;

	/* use parent dma attr here */
	hcdi_args.usba_hcdi_register_dma_attr = usba_get_hc_dma_attr(dip);
	hcdi_args.usba_hcdi_register_iblock_cookie = NULL;

	if (usba_hcdi_register(&hcdi_args, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_attach: usba_hcdi_register failed");

		goto fail;
	}

	hwahcp->hwahc_flags |= HWAHC_HCDI_REGISTERED;

	/* create hub minor node and register to usba HUBD interface */
	if (hwahc_hub_attach(hwahcp) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_attach: hub attach failed");

		goto fail;
	}
	hwahcp->hwahc_flags |= HWAHC_HUBREG;

	/* intialize WUSB host function related structure */
	hwahc_hc_data_init(hwahcp);
	hwahcp->hwahc_flags |= HWAHC_HC_INITED;

	/* can be combined with wusb_wa_data_init() */
	if (hwahc_wa_start(hwahcp) != USB_SUCCESS) {

		goto fail;
	}

	hwahcp->hwahc_flags |= HWAHC_WA_STARTED;

	/* report this dev */
	ddi_report_dev(dip);

	hwahc_pm_idle_component(hwahcp);

	mutex_enter(&(hwahcp->hwahc_mutex));
	hwahc_print_secrt_data(hwahcp);
	mutex_exit(&(hwahcp->hwahc_mutex));

	if (uwb_dev_online(dip) != USB_SUCCESS) {
		goto fail;
	}

	return (DDI_SUCCESS);

fail:
	pathname = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	/* log this message to usba_debug_buf */
	USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
	    "cannot attach %s", ddi_pathname(dip, pathname));

	kmem_free(pathname, MAXPATHLEN);

	if (hwahcp) {
		hwahc_pm_idle_component(hwahcp);

		rval = hwahc_cleanup(dip, hwahcp);
		if (rval != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA,
			    hwahcp->hwahc_log_handle,
			    "failure to complete cleanup after attach failure");
		}
	}

	return (DDI_FAILURE);
}


/*
 * hwahc_detach:
 *	detach or suspend driver instance
 *
 * Note: in detach, only contention threads is from pm and disconnnect.
 */
static int
hwahc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		instance = ddi_get_instance(dip);
	hwahc_state_t	*hwahcp = ddi_get_soft_state(hwahc_statep, instance);
	int		rval = DDI_FAILURE;


	USB_DPRINTF_L3(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
	    "hwahc_detach: cmd = %d", cmd);

	switch (cmd) {
	case DDI_DETACH:
		USB_DPRINTF_L3(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "offline uwb device for dip: 0x%p", (void *)dip);
		/* offline the hwarc interface */
		(void) uwb_dev_offline(dip);
		if (hwahcp) {
			rval = hwahc_cleanup(dip, hwahcp);
		}

		break;
	case DDI_SUSPEND:
		rval = hwahc_cpr_suspend(dip);

		break;
	default:

		break;
	}

	return ((rval == USB_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}


/*
 * hwahc_cleanup:
 *	clean up on attach failure or detach
 */
static int
hwahc_cleanup(dev_info_t *dip, hwahc_state_t *hwahcp)
{
	USB_DPRINTF_L4(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
	    "hwahc_cleanup: start");

	if ((hwahcp->hwahc_flags & HWAHC_LOCK_INITED) == 0) {

		goto done;
	}

	/*
	 * deallocate events, if events are still registered
	 * (ie. children still attached) then we have to fail the detach
	 */
	if (hwahcp->hwahc_ndi_event_hdl &&
	    (ndi_event_free_hdl(hwahcp->hwahc_ndi_event_hdl) != NDI_SUCCESS)) {

		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_cleanup: ndi_event_free_hdl failed");

		return (USB_FAILURE);
	}

	if (hwahcp->hwahc_flags & HWAHC_EVENTS_REGISTERED) {
		/* unregister events */
		usb_unregister_event_cbs(dip, &hwahc_events);
	}

	if (hwahcp->hwahc_flags & HWAHC_HCDI_REGISTERED) {
		/* unregister the instance with usba HCD interface */
		usba_hcdi_unregister(hwahcp->hwahc_dip);
	}

	mutex_enter(&hwahcp->hwahc_mutex);

	if (hwahcp->hwahc_hw_state != HWAHC_HW_STOPPED) {
		/* stop the hw if it is enabled */
		(void) hwahc_hc_final_stop(hwahcp);
	}

	if (hwahcp->hwahc_flags & HWAHC_WA_STARTED) {
		/* can be combined with wusb_wa_data_fini() */
		mutex_exit(&hwahcp->hwahc_mutex);
		hwahc_wa_stop(hwahcp);
		mutex_enter(&hwahcp->hwahc_mutex);
	}

	if (hwahcp->hwahc_flags & HWAHC_HC_INITED) {
		/* deinitialize the WUSB host function related structure */
		hwahc_hc_data_fini(hwahcp);
	}

	mutex_exit(&hwahcp->hwahc_mutex);

	if (hwahcp->hwahc_pm) {
		/* destroy power management components */
		hwahc_destroy_pm_components(hwahcp);
	}

	if (hwahcp->hwahc_flags & HWAHC_HUBREG) {
		/* unregister the instance from usba HUBD interface */
		if (hwahc_hub_detach(hwahcp) != USB_SUCCESS) {

			return (USB_FAILURE);
		}
	}

	if (hwahcp->hwahc_hcdi_ops) {
		usba_free_hcdi_ops(hwahcp->hwahc_hcdi_ops);
	}

	mutex_enter(&hwahcp->hwahc_mutex);
	if (hwahcp->hwahc_secrt_data.secrt_encry_descr) {
		/* free security descrs */
		kmem_free(hwahcp->hwahc_secrt_data.secrt_encry_descr,
		    sizeof (usb_encryption_descr_t) *
		    hwahcp->hwahc_secrt_data.secrt_n_encry);
	}

	if (hwahcp->hwahc_flags & HWAHC_WA_INITED) {
		/* deinitialize data transfer function related structure */
		wusb_wa_data_fini(&hwahcp->hwahc_wa_data);
	}
	mutex_exit(&hwahcp->hwahc_mutex);

	if (hwahcp->hwahc_flags & HWAHC_MINOR_NODE_CREATED) {
		/* remove all the minor nodes */
		ddi_remove_minor_node(dip, NULL);
	}

	/* destroy mutex and cv */
	mutex_destroy(&hwahcp->hwahc_mutex);
	cv_destroy(&hwahcp->hwahc_result_thread_cv);

done:
	/* unregister the client driver from usba */
	usb_client_detach(dip, hwahcp->hwahc_dev_data);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
	    "hwahc_cleanup: end");

	usb_free_log_hdl(hwahcp->hwahc_log_handle);

	/* remove all properties created */
	ddi_prop_remove_all(dip);

	/* free the soft state information */
	ddi_soft_state_free(hwahc_statep, ddi_get_instance(dip));

	return (USB_SUCCESS);
}


/*ARGSUSED*/
static int
hwahc_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
	hwahc_state_t	*hwahcp;

	if ((hwahcp = ddi_get_soft_state(hwahc_statep,
	    HWAHC_MINOR_TO_INSTANCE(getminor(*devp)))) == NULL) {

		return (ENXIO);
	}

	USB_DPRINTF_L4(PRINT_MASK_OPEN, hwahcp->hwahc_log_handle,
	    "hwahc_open: start");

	mutex_enter(&hwahcp->hwahc_mutex);
	/* exclusive open */
	if ((flag & FEXCL) && (hwahcp->hwahc_open_count > 0)) {
		mutex_exit(&hwahcp->hwahc_mutex);

		return (EBUSY);
	}

	if ((hwahcp->hwahc_dev_state == USB_DEV_DISCONNECTED) ||
	    (hwahcp->hwahc_dev_state == USB_DEV_SUSPENDED)) {
		mutex_exit(&hwahcp->hwahc_mutex);

		return (EIO);
	}

	hwahcp->hwahc_open_count++;

	mutex_exit(&hwahcp->hwahc_mutex);

	/* raise to full power and keep it until close */
	hwahc_pm_busy_component(hwahcp);
	(void) pm_raise_power(hwahcp->hwahc_dip, 0, USB_DEV_OS_FULL_PWR);

	USB_DPRINTF_L4(PRINT_MASK_OPEN, hwahcp->hwahc_log_handle,
	    "hwahc_open: end");

	return (0);
}


/*ARGSUSED*/
static int
hwahc_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	hwahc_state_t	*hwahcp;

	if ((hwahcp = ddi_get_soft_state(hwahc_statep,
	    HWAHC_MINOR_TO_INSTANCE(getminor(dev)))) == NULL) {

		return (ENXIO);
	}

	USB_DPRINTF_L4(PRINT_MASK_CLOSE, hwahcp->hwahc_log_handle,
	    "hwahc_close: start");

	mutex_enter(&hwahcp->hwahc_mutex);
	if (hwahcp->hwahc_open_count == 0) {
		USB_DPRINTF_L2(PRINT_MASK_CLOSE, hwahcp->hwahc_log_handle,
		    "hwahc_close: already closed");
		mutex_exit(&hwahcp->hwahc_mutex);

		return (EINVAL);
	}

	hwahcp->hwahc_open_count--;
	mutex_exit(&hwahcp->hwahc_mutex);

	hwahc_pm_idle_component(hwahcp);

	USB_DPRINTF_L4(PRINT_MASK_CLOSE, hwahcp->hwahc_log_handle,
	    "hwahc_close: end");

	return (0);
}

/* retrieve port number from devctl data */
static usb_port_t
hwahc_get_port_num(hwahc_state_t *hwahcp, struct devctl_iocdata *dcp)
{
	int32_t port;

	ASSERT(mutex_owned(&hwahcp->hwahc_mutex));

	/* Get which port to operate on.  */
	if (nvlist_lookup_int32(ndi_dc_get_ap_data(dcp), "port", &port) != 0) {
		USB_DPRINTF_L2(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
		    "hwahc_get_port_num: port lookup failed");
		port = 0;
	}

	USB_DPRINTF_L4(PRINT_MASK_CBOPS,  hwahcp->hwahc_log_handle,
	    "hwahc_get_port_num: hwahcp=0x%p, port=%d", (void *)hwahcp,
	    port);

	return ((usb_port_t)port);
}

/* return the child dip on a certain port */
static dev_info_t *
hwahc_get_child_dip(hwahc_state_t *hwahcp, usb_port_t port)
{
	wusb_hc_data_t		*hc_data;
	dev_info_t		*child_dip;

	hc_data = &hwahcp->hwahc_hc_data;

	/* check port range to prevent an illegal number */
	if (port > hc_data->hc_num_ports) {
		return (NULL);
	}

	mutex_enter(&hc_data->hc_mutex);
	child_dip = hc_data->hc_children_dips[port];
	mutex_exit(&hc_data->hc_mutex);

	return (child_dip);
}

/*
 * hwahc_cfgadm_state:
 *
 *	child_dip list		child_state		cfgadm_state
 *	--------------		----------		------------
 *	!= NULL			connected		configured or
 *							unconfigured
 *	!= NULL			not connected		disconnect but
 *							busy/still referenced
 *	NULL			connected		logically disconnected
 *	NULL			not connected		empty
 */
static uint_t
hwahc_cfgadm_state(hwahc_state_t *hwahcp, usb_port_t port)
{
	uint_t		state;
	dev_info_t	*child_dip = hwahc_get_child_dip(hwahcp, port);
	wusb_hc_data_t	*hc_data = &hwahcp->hwahc_hc_data;
	wusb_dev_info_t	*dev_info;

	if (child_dip == NULL) {

		return (HWAHC_CFGADM_INVALID);
	}

	mutex_enter(&hc_data->hc_mutex);
	dev_info = hc_data->hc_dev_infos[port];
	if (dev_info) {
		if (dev_info->wdev_state == WUSB_STATE_CONFIGURED) {
			if (child_dip &&
			    (DEVI_IS_DEVICE_OFFLINE(child_dip) ||
			    !i_ddi_devi_attached(child_dip))) {
				state = HWAHC_CFGADM_UNCONFIGURED;
			} else if (!child_dip) {
				state = HWAHC_CFGADM_UNCONFIGURED;
			} else {
				state = HWAHC_CFGADM_CONFIGURED;
			}
		} else if (dev_info->wdev_state == WUSB_STATE_UNCONNTED) {
			if (child_dip) {
				state = HWAHC_CFGADM_STILL_REFERENCED;
			} else {
				state = HWAHC_CFGADM_DISCONNECTED;
			}
		} else {
			if (child_dip) {
				state = HWAHC_CFGADM_STILL_REFERENCED;
			} else {
				state = HWAHC_CFGADM_UNCONFIGURED;
			}
		}
	} else {
		state = HWAHC_CFGADM_EMPTY;
	}
	mutex_exit(&hc_data->hc_mutex);

	USB_DPRINTF_L4(PRINT_MASK_CBOPS,  hwahcp->hwahc_log_handle,
	    "hwahc_cfgadm_state: hwahcp=0x%p, port=%d state=0x%x",
	    (void *) hwahcp, port, state);

	return (state);
}

/* cfgadm ioctl support, now only implements list function */
/* ARGSUSED */
static int
hwahc_cfgadm_ioctl(hwahc_state_t *hwahcp, int cmd, intptr_t arg,
	int mode, cred_t *credp, int *rvalp)
{
	dev_info_t		*rh_dip;
	dev_info_t		*child_dip;
	struct devctl_iocdata	*dcp = NULL;
	usb_port_t		port = 0;
	devctl_ap_state_t	ap_state;
	int			circ, rh_circ, prh_circ;
	int			rv = 0;
	char			*msg;

	/* read devctl ioctl data */
	if ((cmd != DEVCTL_AP_CONTROL) &&
	    (ndi_dc_allochdl((void *)arg, &dcp) != NDI_SUCCESS)) {

		return (EFAULT);
	}

	mutex_enter(&hwahcp->hwahc_mutex);

	rh_dip = hwahcp->hwahc_hubd->h_usba_device->usb_root_hub_dip;

	switch (cmd) {
	case DEVCTL_AP_DISCONNECT:
	case DEVCTL_AP_UNCONFIGURE:
	case DEVCTL_AP_CONFIGURE:
		if (hwahcp->hwahc_dev_state == USB_DEV_DISCONNECTED) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA,
			    hwahcp->hwahc_log_handle,
			    "hwahc_cfgadm_ioctl: dev already gone");
			mutex_exit(&hwahcp->hwahc_mutex);
			if (dcp) {
				ndi_dc_freehdl(dcp);
			}

			return (EIO);
		}
		/* FALLTHROUGH */
	case DEVCTL_AP_GETSTATE:
		if ((port = hwahc_get_port_num(hwahcp, dcp)) == 0) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA,
			    hwahcp->hwahc_log_handle,
			    "hwahc_cfgadm_ioctl: bad port");
			mutex_exit(&hwahcp->hwahc_mutex);
			if (dcp) {
				ndi_dc_freehdl(dcp);
			}

			return (EINVAL);
		}
		break;
	case DEVCTL_AP_CONTROL:

		break;
	default:
		mutex_exit(&hwahcp->hwahc_mutex);
		if (dcp) {
			ndi_dc_freehdl(dcp);
		}

		return (ENOTTY);
	}

	/* should not happen, just in case */
	if (hwahcp->hwahc_dev_state == USB_DEV_SUSPENDED) {
		mutex_exit(&hwahcp->hwahc_mutex);
		if (dcp) {
			ndi_dc_freehdl(dcp);
		}

		return (EIO);
	}

	mutex_exit(&hwahcp->hwahc_mutex);

	ndi_devi_enter(ddi_get_parent(rh_dip), &prh_circ);
	ndi_devi_enter(rh_dip, &rh_circ);
	ndi_devi_enter(hwahcp->hwahc_dip, &circ);

	mutex_enter(&hwahcp->hwahc_mutex);

	switch (cmd) {
	case DEVCTL_AP_DISCONNECT:
		/* TODO: not supported now */
		rv = EIO;
		break;
	case DEVCTL_AP_UNCONFIGURE:
		/* TODO: not supported now */
		rv = EIO;
		break;
	case DEVCTL_AP_CONFIGURE:
		/* TODO: not supported now */
		rv = EIO;
		break;
	case DEVCTL_AP_GETSTATE:
		switch (hwahc_cfgadm_state(hwahcp, port)) {
		case HWAHC_CFGADM_DISCONNECTED:
			/* port previously 'disconnected' by cfgadm */
			ap_state.ap_rstate = AP_RSTATE_DISCONNECTED;
			ap_state.ap_ostate = AP_OSTATE_UNCONFIGURED;
			ap_state.ap_condition = AP_COND_OK;

			break;
		case HWAHC_CFGADM_UNCONFIGURED:
			ap_state.ap_rstate = AP_RSTATE_CONNECTED;
			ap_state.ap_ostate = AP_OSTATE_UNCONFIGURED;
			ap_state.ap_condition = AP_COND_OK;

			break;
		case HWAHC_CFGADM_CONFIGURED:
			ap_state.ap_rstate = AP_RSTATE_CONNECTED;
			ap_state.ap_ostate = AP_OSTATE_CONFIGURED;
			ap_state.ap_condition = AP_COND_OK;

			break;
		case HWAHC_CFGADM_STILL_REFERENCED:
			ap_state.ap_rstate = AP_RSTATE_EMPTY;
			ap_state.ap_ostate = AP_OSTATE_CONFIGURED;
			ap_state.ap_condition = AP_COND_UNUSABLE;

			break;
		case HWAHC_CFGADM_EMPTY:
		default:
			ap_state.ap_rstate = AP_RSTATE_EMPTY;
			ap_state.ap_ostate = AP_OSTATE_UNCONFIGURED;
			ap_state.ap_condition = AP_COND_OK;

			break;
		}

		ap_state.ap_last_change = (time_t)-1;
		ap_state.ap_error_code = 0;
		ap_state.ap_in_transition = 0;

		USB_DPRINTF_L4(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
		    "DEVCTL_AP_GETSTATE: "
		    "ostate=0x%x, rstate=0x%x, condition=0x%x",
		    ap_state.ap_ostate,
		    ap_state.ap_rstate, ap_state.ap_condition);

		/* copy the return-AP-state information to the user space */
		if (ndi_dc_return_ap_state(&ap_state, dcp) != NDI_SUCCESS) {
			rv = EFAULT;
		}

		break;
	case DEVCTL_AP_CONTROL:
	{
		/*
		 * Generic devctl for hardware-specific functionality.
		 * For list of sub-commands see hubd_impl.h
		 */
		hubd_ioctl_data_t	ioc;	/* for 64 byte copies */

		/* copy user ioctl data in first */
#ifdef _MULTI_DATAMODEL
		if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
			hubd_ioctl_data_32_t ioc32;

			if (ddi_copyin((void *)arg, (void *)&ioc32,
			    sizeof (ioc32), mode) != 0) {
				rv = EFAULT;

				break;
			}
			ioc.cmd		= (uint_t)ioc32.cmd;
			ioc.port	= (uint_t)ioc32.port;
			ioc.get_size	= (uint_t)ioc32.get_size;
			ioc.buf		= (caddr_t)(uintptr_t)ioc32.buf;
			ioc.bufsiz	= (uint_t)ioc32.bufsiz;
			ioc.misc_arg	= (uint_t)ioc32.misc_arg;
		} else
#endif /* _MULTI_DATAMODEL */
		if (ddi_copyin((void *)arg, (void *)&ioc, sizeof (ioc),
		    mode) != 0) {
			rv = EFAULT;

			break;
		}

		USB_DPRINTF_L3(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
		    "DEVCTL_AP_CONTROL: ioc: cmd=0x%x port=%d get_size=%d"
		    "\n\tbuf=0x%p, bufsiz=%d,  misc_arg=%d", ioc.cmd,
		    ioc.port, ioc.get_size, (void *) ioc.buf, ioc.bufsiz,
		    ioc.misc_arg);

		/*
		 * To avoid BE/LE and 32/64 issues, a get_size always
		 * returns a 32-bit number.
		 */
		if (ioc.get_size != 0 && ioc.bufsiz != (sizeof (uint32_t))) {
			rv = EINVAL;

			break;
		}

		switch (ioc.cmd) {
		case USB_DESCR_TYPE_DEV:
			msg = "DEVCTL_AP_CONTROL: GET_DEVICE_DESC";
			if (ioc.get_size) {
				/* uint32 so this works 32/64 */
				uint32_t size = sizeof (usb_dev_descr_t);

				if (ddi_copyout((void *)&size, ioc.buf,
				    ioc.bufsiz, mode) != 0) {
					USB_DPRINTF_L2(PRINT_MASK_CBOPS,
					    hwahcp->hwahc_log_handle,
					    "%s: get_size copyout failed", msg);
					rv = EIO;

					break;
				}
			} else {	/* send out the actual descr */
				usb_dev_descr_t *dev_descrp;

				/* check child_dip */
				if ((child_dip = hwahc_get_child_dip(hwahcp,
				    ioc.port)) == NULL) {
					rv = EINVAL;

					break;
				}

				dev_descrp = usb_get_dev_descr(child_dip);
				if (ioc.bufsiz != sizeof (*dev_descrp)) {
					USB_DPRINTF_L2(PRINT_MASK_CBOPS,
					    hwahcp->hwahc_log_handle,
					    "%s: bufsize passed (%d) != sizeof "
					    "usba_device_descr_t (%d)", msg,
					    ioc.bufsiz, dev_descrp->bLength);
					rv = EINVAL;

					break;
				}

				if (ddi_copyout((void *)dev_descrp,
				    ioc.buf, ioc.bufsiz, mode) != 0) {
					USB_DPRINTF_L2(PRINT_MASK_CBOPS,
					    hwahcp->hwahc_log_handle,
					    "%s: copyout failed.", msg);
					rv = EIO;

					break;
				}
			}
			break;
		case USB_DESCR_TYPE_CFG:
		{
			usba_device_t	*child_ud = NULL;
			uint32_t	idx = ioc.misc_arg;
			uint32_t	cfg_len = 0;

			if ((child_dip =
			    hwahc_get_child_dip(hwahcp, ioc.port)) == NULL) {
				rv = EINVAL;

				break;
			}
			child_ud = usba_get_usba_device(child_dip);
			cfg_len = (uint32_t)child_ud->usb_cfg_array_len[idx];

			msg = "DEVCTL_AP_CONTROL: GET_CONFIG_DESC";
			if (ioc.get_size) {
				if (ddi_copyout((void *)&cfg_len, ioc.buf,
				    ioc.bufsiz, mode) != 0) {
					USB_DPRINTF_L2(PRINT_MASK_CBOPS,
					    hwahcp->hwahc_log_handle,
					    "%s: get_size copyout failed", msg);
					rv = EIO;

					break;
				}
			} else {	/* send out the actual descr */
				uchar_t *cfg_descr =
				    child_ud->usb_cfg_array[idx];

				if (ioc.bufsiz != cfg_len) {
					USB_DPRINTF_L2(PRINT_MASK_CBOPS,
					    hwahcp->hwahc_log_handle,
					    "%s: bufsize passed (%d) != size "
					    "of cfg_descr (%d)", msg,
					    ioc.bufsiz, cfg_len);
					rv = EINVAL;

					break;
				}

				if (ddi_copyout((void *)cfg_descr,
				    ioc.buf, ioc.bufsiz, mode) != 0) {
					USB_DPRINTF_L2(PRINT_MASK_CBOPS,
					    hwahcp->hwahc_log_handle,
					    "%s: copyout failed.", msg);
					rv = EIO;

					break;
				}
			}
			break;
		}
		case USB_DESCR_TYPE_STRING:
		{
			char		*str;
			uint32_t	size;
			usba_device_t	*usba_device;

			msg = "DEVCTL_AP_CONTROL: GET_STRING_DESCR";
			USB_DPRINTF_L4(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "%s: string request: %d", msg, ioc.misc_arg);

			/* recheck */
			if ((child_dip =
			    hwahc_get_child_dip(hwahcp, ioc.port)) == NULL) {
				rv = EINVAL;

				break;
			}
			usba_device = usba_get_usba_device(child_dip);

			switch (ioc.misc_arg) {
			case HUBD_MFG_STR:
				str = usba_device->usb_mfg_str;

				break;
			case HUBD_PRODUCT_STR:
				str = usba_device->usb_product_str;

				break;
			case HUBD_SERIALNO_STR:
				str = usba_device->usb_serialno_str;

				break;
			case HUBD_CFG_DESCR_STR:
				mutex_enter(&usba_device->usb_mutex);
				str = usba_device->usb_cfg_str_descr[
				    usba_device->usb_active_cfg_ndx];
				mutex_exit(&usba_device->usb_mutex);

				break;
			default:
				USB_DPRINTF_L2(PRINT_MASK_CBOPS,
				    hwahcp->hwahc_log_handle,
				    "%s: Invalid string request", msg);
				rv = EINVAL;

				break;
			} /* end of switch */

			if (rv != 0) {

				break;
			}

			size = (str != NULL) ? strlen(str) + 1 : 0;
			if (ioc.get_size) {
				if (ddi_copyout((void *)&size, ioc.buf,
				    ioc.bufsiz, mode) != 0) {
					USB_DPRINTF_L2(PRINT_MASK_CBOPS,
					    hwahcp->hwahc_log_handle,
					    "%s: copyout of size failed.", msg);
					rv = EIO;

					break;
				}
			} else {
				if (size == 0) {
					USB_DPRINTF_L2(PRINT_MASK_CBOPS,
					    hwahcp->hwahc_log_handle,
					    "%s: String is NULL", msg);
					rv = EINVAL;

					break;
				}

				if (ioc.bufsiz != size) {
					USB_DPRINTF_L2(PRINT_MASK_CBOPS,
					    hwahcp->hwahc_log_handle,
					    "%s: string buf size wrong", msg);
					rv = EINVAL;

					break;
				}

				if (ddi_copyout((void *)str, ioc.buf,
				    ioc.bufsiz, mode) != 0) {
					USB_DPRINTF_L2(PRINT_MASK_CBOPS,
					    hwahcp->hwahc_log_handle,
					    "%s: copyout failed.", msg);
					rv = EIO;

					break;
				}
			}
			break;
		}
		case HUBD_GET_CFGADM_NAME:
		{
			uint32_t   name_len;
			const char *name;

			/* recheck */
			if ((child_dip =
			    hwahc_get_child_dip(hwahcp, ioc.port)) == NULL) {
				rv = EINVAL;

				break;
			}
			name = ddi_node_name(child_dip);
			if (name == NULL) {
				name = "unsupported";
			}
			name_len = strlen(name) + 1;

			msg = "DEVCTL_AP_CONTROL: HUBD_GET_CFGADM_NAME";
			USB_DPRINTF_L4(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "%s: name=%s name_len=%d", msg, name, name_len);

			if (ioc.get_size) {
				if (ddi_copyout((void *)&name_len,
				    ioc.buf, ioc.bufsiz, mode) != 0) {
					USB_DPRINTF_L2(PRINT_MASK_CBOPS,
					    hwahcp->hwahc_log_handle,
					    "%s: copyout of size failed", msg);
					rv = EIO;

					break;
				}
			} else {
				if (ioc.bufsiz != name_len) {
					USB_DPRINTF_L2(PRINT_MASK_CBOPS,
					    hwahcp->hwahc_log_handle,
					    "%s: string buf length wrong", msg);
					rv = EINVAL;

					break;
				}

				if (ddi_copyout((void *)name, ioc.buf,
				    ioc.bufsiz, mode) != 0) {
					USB_DPRINTF_L2(PRINT_MASK_CBOPS,
					    hwahcp->hwahc_log_handle,
					    "%s: copyout failed.", msg);
					rv = EIO;

					break;
				}
			}

			break;
		}

		/*
		 * Return the config index for the currently-configured
		 * configuration.
		 */
		case HUBD_GET_CURRENT_CONFIG:
		{
			uint_t		config_index;
			uint32_t	size = sizeof (config_index);
			usba_device_t	*usba_device;

			msg = "DEVCTL_AP_CONTROL: GET_CURRENT_CONFIG";
			USB_DPRINTF_L4(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle, "%s", msg);

			/*
			 * Return the config index for the configuration
			 * currently in use.
			 * Recheck if child_dip exists
			 */
			if ((child_dip =
			    hwahc_get_child_dip(hwahcp, ioc.port)) == NULL) {
				rv = EINVAL;

				break;
			}

			usba_device = usba_get_usba_device(child_dip);
			mutex_enter(&usba_device->usb_mutex);
			config_index = usba_device->usb_active_cfg_ndx;
			mutex_exit(&usba_device->usb_mutex);

			if (ioc.get_size) {
				if (ddi_copyout((void *)&size,
				    ioc.buf, ioc.bufsiz, mode) != 0) {
					USB_DPRINTF_L2(PRINT_MASK_CBOPS,
					    hwahcp->hwahc_log_handle,
					    "%s: copyout of size failed.", msg);
					rv = EIO;

					break;
				}
			} else {
				if (ioc.bufsiz != size) {
					USB_DPRINTF_L2(PRINT_MASK_CBOPS,
					    hwahcp->hwahc_log_handle,
					    "%s: buffer size wrong", msg);
					rv = EINVAL;

					break;
				}
				if (ddi_copyout((void *)&config_index,
				    ioc.buf, ioc.bufsiz, mode) != 0) {
					USB_DPRINTF_L2(PRINT_MASK_CBOPS,
					    hwahcp->hwahc_log_handle,
					    "%s: copyout failed", msg);
					rv = EIO;
				}
			}

			break;
		}
		case HUBD_GET_DEVICE_PATH:
		{
			char		*path;
			uint32_t	size;

			msg = "DEVCTL_AP_CONTROL: GET_DEVICE_PATH";
			USB_DPRINTF_L4(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle, "%s", msg);

			/* Recheck if child_dip exists */
			if ((child_dip =
			    hwahc_get_child_dip(hwahcp, ioc.port)) == NULL) {
				rv = EINVAL;

				break;
			}

			/* ddi_pathname doesn't supply /devices, so we do. */
			path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
			(void) strcpy(path, "/devices");
			(void) ddi_pathname(child_dip, path + strlen(path));
			size = strlen(path) + 1;

			USB_DPRINTF_L4(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "%s: device path=%s  size=%d", msg, path, size);

			if (ioc.get_size) {
				if (ddi_copyout((void *)&size,
				    ioc.buf, ioc.bufsiz, mode) != 0) {

					USB_DPRINTF_L2(PRINT_MASK_CBOPS,
					    hwahcp->hwahc_log_handle,
					    "%s: copyout of size failed.", msg);
					rv = EIO;
				}
			} else {
				if (ioc.bufsiz != size) {
					USB_DPRINTF_L2(PRINT_MASK_CBOPS,
					    hwahcp->hwahc_log_handle,
					    "%s: buffer wrong size.", msg);
					rv = EINVAL;
				} else if (ddi_copyout((void *)path,
				    ioc.buf, ioc.bufsiz, mode) != 0) {
					USB_DPRINTF_L2(PRINT_MASK_CBOPS,
					    hwahcp->hwahc_log_handle,
					    "%s: copyout failed.", msg);
					rv = EIO;
				}
			}
			kmem_free(path, MAXPATHLEN);

			break;
		}
		case HUBD_REFRESH_DEVDB:
			msg = "DEVCTL_AP_CONTROL: HUBD_REFRESH_DEVDB";
			USB_DPRINTF_L4(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle, "%s", msg);

			if ((rv = usba_devdb_refresh()) != USB_SUCCESS) {
				USB_DPRINTF_L2(PRINT_MASK_CBOPS,
				    hwahcp->hwahc_log_handle,
				    "%s: Failed: %d", msg, rv);
				rv = EIO;
			}

			break;
		default:
			rv = ENOTSUP;
		}	/* end switch */

		break;
	}

	default:
		rv = ENOTTY;
	}

	if (dcp) {
		ndi_dc_freehdl(dcp);
	}

	mutex_exit(&hwahcp->hwahc_mutex);

	ndi_devi_exit(hwahcp->hwahc_dip, circ);
	ndi_devi_exit(rh_dip, rh_circ);
	ndi_devi_exit(ddi_get_parent(rh_dip), prh_circ);

	return (rv);
}

/* update CHID for the hc driver, return 0 on success */
static int
hwahc_set_chid(hwahc_state_t *hwahcp, uint8_t *chid)
{
	wusb_hc_data_t	*hc_data = &hwahcp->hwahc_hc_data;

	ASSERT(!mutex_owned(&hc_data->hc_mutex));

	/* same as the old CHID, return success */
	if (memcmp(chid, hc_data->hc_chid, 16) == 0) {

		return (0);
	}

	/*
	 * stop hw from working before updating CHID
	 * this may not be necessary but so far we don't know
	 * other ways to do it safely
	 */
	if (hwahcp->hwahc_hw_state == HWAHC_HW_STARTED) {
		/* use final_stop to fully stop the hwa */
		if (hwahc_hc_final_stop(hwahcp) != USB_SUCCESS) {

			return (EIO);
		}

		mutex_enter(&hc_data->hc_mutex);
		(void) memcpy(hc_data->hc_chid, chid, 16);
		mutex_exit(&hc_data->hc_mutex);

		/* restart the host */
		if (hwahc_hc_initial_start(hwahcp) != USB_SUCCESS) {

			return (EIO);
		}

		return (0);
	}

	/* hc is stopped or partially stopped, simply update */
	mutex_enter(&hc_data->hc_mutex);
	(void) memcpy(hc_data->hc_chid, chid, 16);
	mutex_exit(&hc_data->hc_mutex);

	return (0);
}

/*
 * wusbadm ioctl support
 */
/* ARGSUSED */
static int
hwahc_wusb_ioctl(hwahc_state_t *hwahcp, int cmd, intptr_t arg,
	int mode, cred_t *credp, int *rvalp)
{
	int		rv = 0;
	wusb_hc_data_t	*hc_data = &hwahcp->hwahc_hc_data;

	if (drv_priv(credp) != 0) {
		USB_DPRINTF_L3(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
		    "hwahc_wusb_ioctl: user must have SYS_DEVICE privilege,"
		    "cmd=%x", cmd);

		return (EPERM);
	}

	mutex_enter(&hwahcp->hwahc_mutex);

	switch (cmd) {
	case WUSB_HC_GET_DSTATE: /* Get device state: wusbadm list */
	{
		wusb_hc_get_dstate_t	state;
		usb_port_t		port = 0;

		if (ddi_copyin((void *)arg, (void *)&state, sizeof (state),
		    mode) != 0) {
			rv = EFAULT;

			break;
		}

		mutex_enter(&hc_data->hc_mutex);

		if (wusb_hc_is_dev_connected(hc_data, &state.cdid[0], &port)) {
			state.state = hc_data->hc_dev_infos[port]->wdev_state;
		} else {
			/* cdid not found */
			state.state = WUSB_STATE_UNCONNTED;
		}

		USB_DPRINTF_L3(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
		    "hwahc_wusb_ioctl: hc_data=%p, port = %d, state=%d",
		    (void *) hc_data, port, state.state);

		mutex_exit(&hc_data->hc_mutex);

		if (state.state == WUSB_STATE_CONFIGURED) {
			/* Get the bind device node name of this child */
			(void) memset(state.nodename, 0, MAX_USB_NODENAME);
			(void) snprintf(state.nodename, MAX_USB_NODENAME, "%s",
			    ddi_node_name(hwahc_get_child_dip(hwahcp, port)));

			USB_DPRINTF_L3(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "WUSB_HC_GET_DSTATE: nodename %s", state.nodename);
		}

		if (ddi_copyout((void *)&state, (void *)arg,
		    sizeof (state), mode) != 0) {
			USB_DPRINTF_L2(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "WUSB_HC_GET_DSTATE: copyout failed");
			rv = EIO;
		}

		break;
	}

	case WUSB_HC_GET_MAC_ADDR: /* Get host MAC addr */
	{
		uint8_t		mac_addr[6];

		bzero(mac_addr, 6);

		/*
		 * get UWB 48-bit mac address
		 * Section 8.6.2.2.
		 */
		if (uwb_get_mac_addr(hwahcp->hwahc_dip, mac_addr) !=
		    USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "WUSB_HC_GET_MAC_ADDR: get mac failed");
			rv = EIO;

			break;
		}

		if (ddi_copyout((void *)mac_addr, (void *)arg,
		    6, mode) != 0) {
			USB_DPRINTF_L2(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "WUSB_HC_GET_MAC_ADDR: copyout failed");
			rv = EIO;
		}

		break;
	}
	case WUSB_HC_ADD_CC:
	{
	/*
	 * add a new device CC to host's list: wusbadm associate
	 * Or, the application can pass in a fake CC with only CHID set
	 * to set the host's CHID.
	 */
		wusb_hc_cc_list_t	*cc_list;

		cc_list = kmem_zalloc(sizeof (wusb_hc_cc_list_t), KM_SLEEP);

		if (ddi_copyin((void *)arg, (void *)&cc_list->cc,
		    sizeof (wusb_cc_t), mode) != 0) {
			rv = EFAULT;
			kmem_free(cc_list, sizeof (wusb_hc_cc_list_t));

			break;
		}

		/* update CHID only when cc list is empty */
		mutex_enter(&hc_data->hc_mutex);
		if (hc_data->hc_cc_list == NULL) {
			mutex_exit(&hc_data->hc_mutex);

			if ((rv = hwahc_set_chid(hwahcp,
			    cc_list->cc.CHID)) != 0) {
				kmem_free(cc_list, sizeof (wusb_hc_cc_list_t));

				break;
			}

			mutex_enter(&hc_data->hc_mutex);
		} else {
			/* fail if the CHID in the new CC does not match */
			if (memcmp(cc_list->cc.CHID, hc_data->hc_chid,
			    16) != 0) {
				rv = EINVAL;
				kmem_free(cc_list, sizeof (wusb_hc_cc_list_t));

				mutex_exit(&hc_data->hc_mutex);
				break;
			}
		}
		cc_list->next = NULL;

		wusb_hc_add_cc(&hc_data->hc_cc_list, cc_list);
		mutex_exit(&hc_data->hc_mutex);

		break;
	}
	case WUSB_HC_REM_CC:
	{
		wusb_cc_t	cc;
		usb_port_t	port;

		if (ddi_copyin((void *)arg, (void *)&cc, sizeof (wusb_cc_t),
		    mode) != 0) {
			rv = EFAULT;

			break;
		}

		/* check if the CHID in the CC matches */
		if (memcmp(cc.CHID, hc_data->hc_chid, 16) != 0) {
			rv = EINVAL;

			break;
		}

		/* if the device is connected, disconnect it first */
		mutex_enter(&hc_data->hc_mutex);
		if (wusb_hc_is_dev_connected(hc_data, cc.CDID, &port)) {
			mutex_exit(&hc_data->hc_mutex);
			mutex_exit(&hwahcp->hwahc_mutex);
			/*
			 * clean up host side state, device not
			 * really disconnected. But user can safely remove
			 * the device now.
			 */
			(void) hwahc_destroy_child(hc_data->hc_dip, port);
			mutex_enter(&hwahcp->hwahc_mutex);
			mutex_enter(&hc_data->hc_mutex);
		}

		wusb_hc_rem_cc(&hc_data->hc_cc_list, &cc);
		mutex_exit(&hc_data->hc_mutex);

		break;
	}
	case WUSB_HC_SET_CHANNEL: /* for debug purpose */
	{
		uint8_t	channel;

		channel = (uint8_t)arg;

		if (hwahcp->hwahc_hc_data.hc_channel == channel) {
			USB_DPRINTF_L2(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "WUSB_HC_SET_CHANNEL ioctl: same as existing");

			break;
		}

		if (hwahcp->hwahc_hw_state != HWAHC_HW_STOPPED) {
			/* beacon is already started, stop it first */
			if (uwb_stop_beacon(hwahcp->hwahc_dip) != USB_SUCCESS) {
				USB_DPRINTF_L2(PRINT_MASK_CBOPS,
				    hwahcp->hwahc_log_handle,
				    "WUSB_HC_SET_CHANNEL ioctl: "
				    "stop beacon failed");
				rv = EIO;

				break;
			}
			/* update channel number */
			hwahcp->hwahc_hc_data.hc_channel = channel;
			/* restart beacon on the new channel */
			if (uwb_start_beacon(hwahcp->hwahc_dip,
			    channel) != USB_SUCCESS) {
				USB_DPRINTF_L2(PRINT_MASK_CBOPS,
				    hwahcp->hwahc_log_handle,
				    "WUSB_HC_SET_CHANNEL ioctl: "
				    "restart beacon failed");
				rv = EIO;
			}

			break;
		}

		/* beacon is not started, simply update channel number */
		hwahcp->hwahc_hc_data.hc_channel = channel;

		break;
	}
	case WUSB_HC_START:
	{
		int	flag;


		flag = (int)arg;

		if (hwahcp->hwahc_hw_state == HWAHC_HW_STARTED) {
			USB_DPRINTF_L2(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "WUSB_HC_START ioctl: already started");

			break;
		}

		/*
		 * now we start hc only when the cc list is not NULL
		 * this limitation may be removed if we support
		 * numeric association, but CHID needs to be set
		 * in advance for the hc to work
		 */
		mutex_enter(&hc_data->hc_mutex);
		if (hc_data->hc_cc_list == NULL) {
			USB_DPRINTF_L2(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "WUSB_HC_START ioctl: cc list not inited");
			rv = EINVAL;

			mutex_exit(&hc_data->hc_mutex);

			break;
		}
		mutex_exit(&hc_data->hc_mutex);

		/* cannot be both */
		if ((flag & WUSB_HC_INITIAL_START) && (flag &
		    WUSB_HC_CHANNEL_START)) {
			USB_DPRINTF_L2(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "WUSB_HC_START ioctl: flag cannot coexist");
			rv = EINVAL;

			break;
		}

		/*
		 * init Mac layer 16-bit dev addr. it is important for
		 * authentication. It'd be better to let UWB provide
		 * this address.
		 */
		mutex_enter(&hc_data->hc_mutex);
		if (hc_data->hc_addr == 0) {
			uint16_t dev_addr = HWAHC_DEV_ADDR_BASE +
			    ddi_get_instance(hwahcp->hwahc_dip);

			mutex_exit(&hc_data->hc_mutex);
			/* set UWB 16-bit dev address */
			if (uwb_set_dev_addr(hwahcp->hwahc_dip,
			    dev_addr) != USB_SUCCESS) {
				USB_DPRINTF_L2(PRINT_MASK_CBOPS,
				    hwahcp->hwahc_log_handle,
				    "WUSB_HC_START ioctl: set dev addr failed");
				rv = EIO;

				break;
			}

			/* verify the dev addr is set correctly */
			if (uwb_get_dev_addr(hwahcp->hwahc_dip,
			    &dev_addr) != USB_SUCCESS) {
				USB_DPRINTF_L2(PRINT_MASK_CBOPS,
				    hwahcp->hwahc_log_handle,
				    "WUSB_HC_START ioctl: get dev addr failed");
				rv = EIO;

				break;
			}

			mutex_enter(&hc_data->hc_mutex);
			hc_data->hc_addr = dev_addr;
			USB_DPRINTF_L2(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "host dev addr = 0x%x", dev_addr);
		}
		mutex_exit(&hc_data->hc_mutex);

		/* start functions of wusb host */
		if ((flag & WUSB_HC_INITIAL_START) &&
		    (hwahcp->hwahc_hw_state == HWAHC_HW_STOPPED)) {
			if (hwahc_hc_initial_start(hwahcp) != USB_SUCCESS) {
				rv = EIO;
			}
		} else if ((flag & WUSB_HC_CHANNEL_START) &&
		    (hwahcp->hwahc_hw_state == HWAHC_HW_CH_STOPPED)) {
			if (hwahc_hc_channel_start(hwahcp) != USB_SUCCESS) {
				rv = EIO;
			}
		} else {
			USB_DPRINTF_L2(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "WUSB_HC_START ioctl: unknown flag (%d) or "
			    "state (%d)", flag, hwahcp->hwahc_hw_state);
			rv = EINVAL;
		}

		break;
	}
	case WUSB_HC_STOP:
	{
		int	flag;

		flag = (int)arg;

		/* cannot be both */
		if ((flag & WUSB_HC_FINAL_STOP) && (flag &
		    WUSB_HC_CHANNEL_STOP)) {
			USB_DPRINTF_L2(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "WUSB_HC_STOP ioctl: flag cannot coexist");
			rv = EINVAL;

			break;
		}

		if (flag & WUSB_HC_FINAL_STOP) {
			if (hwahc_hc_final_stop(hwahcp) != USB_SUCCESS) {
				rv = EIO;
			}
		} else if (flag & WUSB_HC_CHANNEL_STOP) {
			if (hwahc_hc_channel_stop(hwahcp) != USB_SUCCESS) {
				rv = EIO;
			}
		} else {
			/* must be one of the STOP flag */
			USB_DPRINTF_L2(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "WUSB_HC_STOP ioctl: invalid flag = %d", flag);
			rv = EINVAL;
		}

		/* REM_ALL_CC flag is optional */
		if ((rv == 0) && (flag & WUSB_HC_REM_ALL_CC)) {
			mutex_enter(&hc_data->hc_mutex);
			if (hc_data->hc_cc_list) {
				wusb_hc_free_cc_list(hc_data->hc_cc_list);
				hc_data->hc_cc_list = NULL;
			}
			mutex_exit(&hc_data->hc_mutex);
		}

		break;
	}
	case WUSB_HC_GET_HSTATE:
	{
		int	state;

		if (hwahcp->hwahc_dev_state == USB_DEV_DISCONNECTED) {
			state = WUSB_HC_DISCONNTED;
		} else {
			switch (hwahcp->hwahc_hw_state) {
			case HWAHC_HW_STOPPED:
				state = WUSB_HC_STOPPED;
				break;
			case HWAHC_HW_STARTED:
				state = WUSB_HC_STARTED;
				break;
			case HWAHC_HW_CH_STOPPED:
				/*
				 * app can mark the hwa as disabled
				 * for this state
				 */
				state = WUSB_HC_CH_STOPPED;
				break;
			}
		}

		if (ddi_copyout((void *)&state, (void *)arg,
		    sizeof (int), mode) != 0) {
			USB_DPRINTF_L2(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "WUSB_HC_GET_HSTATE: copyout failed");
			rv = EIO;
		}

		break;
	}
	default:
		USB_DPRINTF_L2(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
		    "hwahc_ioctl: unsupported command");

		rv = ENOTSUP;
	}
	mutex_exit(&hwahcp->hwahc_mutex);

	return (rv);
}

static int
hwahc_ioctl(dev_t dev, int cmd, intptr_t arg,
	int mode, cred_t *credp, int *rvalp)
{
	hwahc_state_t	*hwahcp;
	int		rval;

	if ((hwahcp = ddi_get_soft_state(hwahc_statep,
	    HWAHC_MINOR_TO_INSTANCE(getminor(dev)))) == NULL) {

		return (ENXIO);
	}

	USB_DPRINTF_L4(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
	    "hwahc_ioctl: cmd=%x, arg=%lx, mode=%x, cred=%p, rval=%p dev=0x%lx",
	    cmd, arg, mode, (void *) credp, (void *) rvalp, dev);

	if (IS_DEVCTL(cmd)) {
		/* for cfgadm cmd support */
		rval = hwahc_cfgadm_ioctl(hwahcp, cmd, arg, mode, credp, rvalp);
	} else {
		/* for wusbadm cmd support */
		rval = hwahc_wusb_ioctl(hwahcp, cmd, arg, mode, credp, rvalp);
	}

	return (rval);
}

/* return the port number corresponding the child dip */
static usb_port_t
hwahc_child_dip2port(hwahc_state_t *hwahcp, dev_info_t *dip)
{
	usb_port_t	port;
	wusb_hc_data_t	*hc_data = &hwahcp->hwahc_hc_data;

	mutex_enter(&hc_data->hc_mutex);
	for (port = 1; port <= hc_data->hc_num_ports; port++) {
		if (hc_data->hc_children_dips[port] == dip) {

			break;
		}
	}
	ASSERT(port <= hc_data->hc_num_ports);
	mutex_exit(&hc_data->hc_mutex);

	return (port);
}

/*
 * child post attach/detach notification
 */
static void
hwahc_post_attach(hwahc_state_t *hwahcp, dev_info_t *rdip,
	struct attachspec *as)
{
	/* we don't need additional process for post-attach now */
	USB_DPRINTF_L3(PRINT_MASK_EVENTS, hwahcp->hwahc_log_handle,
	    "hwahc_post_attach: rdip = 0x%p result = %d", (void *) rdip,
	    as->result);
}

static void
hwahc_post_detach(hwahc_state_t *hwahcp, dev_info_t *rdip,
	struct detachspec *as)
{
	/* we don't need additional process for post-detach now */
	USB_DPRINTF_L3(PRINT_MASK_EVENTS, hwahcp->hwahc_log_handle,
	    "hwahc_post_detach: rdip = 0x%p result = %d", (void *) rdip,
	    as->result);
}

/*
 * bus ctl support.
 * To support different operations, such as a PreAttach preparation,
 * PostAttach operations. HWA only process the interested operations.
 * Other general ones are processed by usba_bus_ctl().
 */
static int
hwahc_bus_ctl(dev_info_t *dip, /* dip could be the parent */
	dev_info_t	*rdip, /* rdip is the dev node to be operated */
	ddi_ctl_enum_t	op,
	void		*arg,
	void		*result)
{
	usba_device_t *usba_device = usba_get_usba_device(rdip);
	dev_info_t *hubdip = usba_device->usb_root_hub_dip;
	hwahc_state_t *hwahcp;
	struct attachspec *as;
	struct detachspec *ds;

	if ((hwahcp = ddi_get_soft_state(hwahc_statep,
	    ddi_get_instance(dip))) == NULL) {

		return (DDI_FAILURE);
	}

	USB_DPRINTF_L2(PRINT_MASK_EVENTS, hwahcp->hwahc_log_handle,
	    "hwahc_bus_ctl:\n\t"
	    "dip = 0x%p, rdip = 0x%p, op = 0x%x, arg = 0x%p",
	    (void *) dip, (void *) rdip, op, (void *) arg);

	switch (op) {
	case DDI_CTLOPS_ATTACH:
		as = (struct attachspec *)arg;

		switch (as->when) {
		case DDI_PRE :
			/* nothing to do basically */
			USB_DPRINTF_L2(PRINT_MASK_EVENTS,
			    hwahcp->hwahc_log_handle,
			    "DDI_PRE DDI_CTLOPS_ATTACH");
			break;
		case DDI_POST :
			hwahc_post_attach(hwahcp, rdip,
			    (struct attachspec *)arg);
			break;
		}

		break;
	case DDI_CTLOPS_DETACH:
		ds = (struct detachspec *)arg;

		switch (ds->when) {
		case DDI_PRE :
			/* nothing to do basically */
			USB_DPRINTF_L2(PRINT_MASK_EVENTS,
			    hwahcp->hwahc_log_handle,
			    "DDI_PRE DDI_CTLOPS_DETACH");
			break;
		case DDI_POST :
			hwahc_post_detach(hwahcp, rdip,
			    (struct detachspec *)arg);
			break;
		}

		break;
	case DDI_CTLOPS_REPORTDEV: /* the workhorse behind ddi_report_dev */
	{
		char *name, compat_name[64];

		if (usb_owns_device(rdip)) {
			(void) snprintf(compat_name,
			    sizeof (compat_name),
			    "usb%x,%x",
			    usba_device->usb_dev_descr->idVendor,
			    usba_device->usb_dev_descr->idProduct);
		} else if (usba_owns_ia(rdip)) {
			(void) snprintf(compat_name,
			    sizeof (compat_name),
			    "usbia%x,%x.config%x.%x",
			    usba_device->usb_dev_descr->idVendor,
			    usba_device->usb_dev_descr->idProduct,
			    usba_device->usb_cfg_value,
			    usb_get_if_number(rdip));
		} else {
			(void) snprintf(compat_name,
			    sizeof (compat_name),
			    "usbif%x,%x.config%x.%x",
			    usba_device->usb_dev_descr->idVendor,
			    usba_device->usb_dev_descr->idProduct,
			    usba_device->usb_cfg_value,
			    usb_get_if_number(rdip));
		}

		cmn_err(CE_CONT,
		    "?USB %x.%x %s (%s) operating wirelessly with "
		    "HWA device: "
		    "%s@%s, %s%d at bus address %d\n",
		    (usba_device->usb_dev_descr->bcdUSB & 0xff00) >> 8,
		    usba_device->usb_dev_descr->bcdUSB & 0xff,
		    (usb_owns_device(rdip) ? "device" :
		    ((usba_owns_ia(rdip) ? "interface-association" :
		    "interface"))),
		    compat_name,
		    ddi_node_name(rdip), ddi_get_name_addr(rdip),
		    ddi_driver_name(rdip),
		    ddi_get_instance(rdip), usba_device->usb_addr);

		name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
		(void) usba_get_mfg_prod_sn_str(rdip, name, MAXNAMELEN);
		if (name[0] != '\0') {
			cmn_err(CE_CONT, "?\t%s\n", name);
		}
		kmem_free(name, MAXNAMELEN);

		break;
	}
	default:
		/* pass to usba to handle */
		return (usba_bus_ctl(hubdip, rdip, op, arg, result));
	}

	return (DDI_SUCCESS);
}

/*
 * bus enumeration entry points
 *  Configures the named device(BUS_CONFIG_ONE) or all devices under
 *  the nexus(BUS_CONFIG_ALL). Drives devinfo state to DS_READY,i.e.device
 *  is fully operational.
 *
 *  This operation is driven from devfs(reading /devices), devctl, libdevinfo;
 *  or from within the kernel to attach a boot device or layered underlying
 *  driver.
 */
static int
hwahc_bus_config(dev_info_t *dip, uint_t flag, ddi_bus_config_op_t op,
	void *arg, dev_info_t **child)
{
	hwahc_state_t	*hwahcp;
	int		rval, circ;

	if ((hwahcp = ddi_get_soft_state(hwahc_statep,
	    ddi_get_instance(dip))) == NULL) {

		return (NDI_FAILURE);
	}

	USB_DPRINTF_L3(PRINT_MASK_EVENTS, hwahcp->hwahc_log_handle,
	    "hwahc_bus_config: op=%d", op);

	if (hwahc_bus_config_debug) {
		flag |= NDI_DEVI_DEBUG;
	}

	ndi_devi_enter(dip, &circ);
	rval = ndi_busop_bus_config(dip, flag, op, arg, child, 0);
	ndi_devi_exit(dip, circ);

	return (rval);
}

/*
 * Unconfigures the named device or all devices under the nexus. The
 * devinfo state is not DS_READY anymore.
 * This operations is driven by modunload, devctl or DR branch removal or
 * rem_drv(1M).
 */
static int
hwahc_bus_unconfig(dev_info_t *dip, uint_t flag, ddi_bus_config_op_t op,
	void *arg)
{
	hwahc_state_t	*hwahcp;
	wusb_hc_data_t	*hc_data;
	dev_info_t	*cdip;
	usb_port_t	port;
	int		rval, circ;

	if ((hwahcp = ddi_get_soft_state(hwahc_statep,
	    ddi_get_instance(dip))) == NULL) {

		return (NDI_FAILURE);
	}

	USB_DPRINTF_L3(PRINT_MASK_EVENTS, hwahcp->hwahc_log_handle,
	    "hwahc_bus_unconfig: op=%d", op);

	if (hwahc_bus_config_debug) {
		flag |= NDI_DEVI_DEBUG;
	}

	if ((op == BUS_UNCONFIG_ALL) && (flag & NDI_AUTODETACH) == 0) {
		flag |= NDI_DEVI_REMOVE;
	}

	/* serialize access */
	ndi_devi_enter(dip, &circ);

	/* unconfig children, detach them */
	rval = ndi_busop_bus_unconfig(dip, flag, op, arg);

	/* logically zap children's list */
	hc_data = &hwahcp->hwahc_hc_data;

	mutex_enter(&hc_data->hc_mutex);
	for (port = 1; port <= hc_data->hc_num_ports; port++) {
		hc_data->hc_children_state[port] |= WUSB_CHILD_ZAP;
	}
	mutex_exit(&hc_data->hc_mutex);

	/* fill in what's left */
	for (cdip = ddi_get_child(dip); cdip;
	    cdip = ddi_get_next_sibling(cdip)) {
		usba_device_t *usba_device = usba_get_usba_device(cdip);

		if (usba_device == NULL) {

			continue;
		}
		mutex_enter(&hc_data->hc_mutex);
		port = usba_device->usb_port;
		hc_data->hc_children_dips[port] = cdip;
		hc_data->hc_children_state[port] &= ~WUSB_CHILD_ZAP;
		mutex_exit(&hc_data->hc_mutex);
	}

	/* physically zap the children we didn't find */
	mutex_enter(&hc_data->hc_mutex);
	for (port = 1; port <= hc_data->hc_num_ports; port++) {
		if (hc_data->hc_children_state[port] & WUSB_CHILD_ZAP) {
			wusb_dev_info_t		*dev_info;
			wusb_secrt_data_t	*csecrt_data;
			usba_device_t		*child_ud;

			USB_DPRINTF_L3(PRINT_MASK_EVENTS,
			    hwahcp->hwahc_log_handle,
			    "hwahc_bus_unconfig: physically zap port %d", port);

			child_ud = hc_data->hc_usba_devices[port];
			mutex_exit(&hc_data->hc_mutex);
			/* zap the dip and usba_device structure as well */
			usba_free_usba_device(child_ud);
			mutex_enter(&hc_data->hc_mutex);
			hc_data->hc_usba_devices[port] = NULL;

			/* dip freed in usba_destroy_child_devi */
			hc_data->hc_children_dips[port] = NULL;
			hc_data->hc_children_state[port] &= ~WUSB_CHILD_ZAP;

			/* free hc_dev_infos[port] */
			dev_info = hc_data->hc_dev_infos[port];
			if (dev_info == NULL) {

				continue;
			}

			/* stop the device's trust timer before deallocate it */
			hwahc_stop_trust_timer(dev_info);

			if (dev_info->wdev_secrt_data.secrt_encry_descr) {
				csecrt_data = &dev_info->wdev_secrt_data;
				kmem_free(csecrt_data->secrt_encry_descr,
				    sizeof (usb_encryption_descr_t) *
				    csecrt_data->secrt_n_encry);
			}
			if (dev_info->wdev_uwb_descr) {
				kmem_free(dev_info->wdev_uwb_descr,
				    sizeof (usb_uwb_cap_descr_t));
			}
			kmem_free(dev_info, sizeof (wusb_dev_info_t));
			hc_data->hc_dev_infos[port] = NULL;
		}
	}
	mutex_exit(&hc_data->hc_mutex);

	ndi_devi_exit(dip, circ);

	USB_DPRINTF_L3(PRINT_MASK_EVENTS, hwahcp->hwahc_log_handle,
	    "hwahc_bus_unconfig: rval=%d", rval);

	return (rval);
}

/*
 * busctl event support
 *
 * Called by ndi_busop_get_eventcookie(). Return a event cookie
 * associated with one event name.
 * The eventname should be the one we defined in hwahc_ndi_event_defs
 */
static int
hwahc_busop_get_eventcookie(dev_info_t *dip,
	dev_info_t	*rdip,
	char		*eventname,
	ddi_eventcookie_t *cookie)
{
	hwahc_state_t	*hwahcp;

	if ((hwahcp = ddi_get_soft_state(hwahc_statep,
	    ddi_get_instance(dip))) == NULL) {

		return (NDI_FAILURE);
	}

	USB_DPRINTF_L3(PRINT_MASK_EVENTS, hwahcp->hwahc_log_handle,
	    "hwahc_busop_get_eventcookie: dip=0x%p, rdip=0x%p, "
	    "event=%s", (void *)dip, (void *)rdip, eventname);
	USB_DPRINTF_L3(PRINT_MASK_EVENTS, hwahcp->hwahc_log_handle,
	    "(dip=%s%d, rdip=%s%d)",
	    ddi_driver_name(dip), ddi_get_instance(dip),
	    ddi_driver_name(rdip), ddi_get_instance(rdip));

	/* return event cookie, iblock cookie, and level */
	return (ndi_event_retrieve_cookie(hwahcp->hwahc_ndi_event_hdl,
	    rdip, eventname, cookie, NDI_EVENT_NOPASS));
}

/*
 * Add event handler for a given event cookie
 */
static int
hwahc_busop_add_eventcall(dev_info_t *dip,
	dev_info_t	*rdip,
	ddi_eventcookie_t cookie,
	void		(*callback)(dev_info_t *dip,
			ddi_eventcookie_t cookie, void *arg,
			void *bus_impldata),
	void *arg, ddi_callback_id_t *cb_id)
{
	hwahc_state_t	*hwahcp;
	usb_port_t	port;

	if ((hwahcp = ddi_get_soft_state(hwahc_statep,
	    ddi_get_instance(dip))) == NULL) {

		return (NDI_FAILURE);
	}

	port = hwahc_child_dip2port(hwahcp, rdip);

	mutex_enter(&hwahcp->hwahc_mutex);

	USB_DPRINTF_L3(PRINT_MASK_EVENTS, hwahcp->hwahc_log_handle,
	    "hwahc_busop_add_eventcall: dip=0x%p, rdip=0x%p "
	    "cookie=0x%p, cb=0x%p, arg=0x%p",
	    (void *)dip, (void *)rdip, (void *)cookie, (void *)callback, arg);
	USB_DPRINTF_L3(PRINT_MASK_EVENTS, hwahcp->hwahc_log_handle,
	    "(dip=%s%d, rdip=%s%d, event=%s)",
	    ddi_driver_name(dip), ddi_get_instance(dip),
	    ddi_driver_name(rdip), ddi_get_instance(rdip),
	    ndi_event_cookie_to_name(hwahcp->hwahc_ndi_event_hdl, cookie));

	/* Set flag on children registering events */
	switch (ndi_event_cookie_to_tag(hwahcp->hwahc_ndi_event_hdl, cookie)) {
	case USBA_EVENT_TAG_HOT_REMOVAL:
		hwahcp->hwahc_child_events[port] |=
		    HWAHC_CHILD_EVENT_DISCONNECT;

		break;
	case USBA_EVENT_TAG_PRE_SUSPEND:
		hwahcp->hwahc_child_events[port] |=
		    HWAHC_CHILD_EVENT_PRESUSPEND;

		break;
	default:

		break;
	}

	mutex_exit(&hwahcp->hwahc_mutex);

	/* add callback to our event set */
	return (ndi_event_add_callback(hwahcp->hwahc_ndi_event_hdl,
	    rdip, cookie, callback, arg, NDI_SLEEP, cb_id));

}


/*
 * Remove a callback previously added by bus_add_eventcall()
 */
static int
hwahc_busop_remove_eventcall(dev_info_t *dip, ddi_callback_id_t cb_id)
{
	hwahc_state_t	*hwahcp;
	ndi_event_callbacks_t *id = (ndi_event_callbacks_t *)cb_id;

	if ((hwahcp = ddi_get_soft_state(hwahc_statep,
	    ddi_get_instance(dip))) == NULL) {

		return (NDI_FAILURE);
	}

	USB_DPRINTF_L3(PRINT_MASK_EVENTS, hwahcp->hwahc_log_handle,
	    "hwahc_busop_remove_eventcall: dip=0x%p, rdip=0x%p "
	    "cookie=0x%p", (void *)dip, (void *) id->ndi_evtcb_dip,
	    (void *)id->ndi_evtcb_cookie);
	USB_DPRINTF_L3(PRINT_MASK_EVENTS, hwahcp->hwahc_log_handle,
	    "(dip=%s%d, rdip=%s%d, event=%s)",
	    ddi_driver_name(dip), ddi_get_instance(dip),
	    ddi_driver_name(id->ndi_evtcb_dip),
	    ddi_get_instance(id->ndi_evtcb_dip),
	    ndi_event_cookie_to_name(hwahcp->hwahc_ndi_event_hdl,
	    id->ndi_evtcb_cookie));

	/* remove event registration from our event set */
	return (ndi_event_remove_callback(hwahcp->hwahc_ndi_event_hdl, cb_id));
}

/*
 * hwahc_post_event
 *	post event to a single child on the port depending on the type, i.e.
 *	to invoke the child's registered callback.
 */
static void
hwahc_post_event(hwahc_state_t *hwahcp, usb_port_t port, usba_event_t type)
{
	int		rval;
	dev_info_t	*dip;
	usba_device_t	*usba_device;
	ddi_eventcookie_t cookie, rm_cookie, suspend_cookie;
	wusb_hc_data_t	*hc_data = &hwahcp->hwahc_hc_data;

	USB_DPRINTF_L4(PRINT_MASK_EVENTS, hwahcp->hwahc_log_handle,
	    "hwahc_post_event: port=%d event=%s", port,
	    ndi_event_tag_to_name(hwahcp->hwahc_ndi_event_hdl, type));

	cookie = ndi_event_tag_to_cookie(hwahcp->hwahc_ndi_event_hdl, type);
	rm_cookie = ndi_event_tag_to_cookie(hwahcp->hwahc_ndi_event_hdl,
	    USBA_EVENT_TAG_HOT_REMOVAL);
	suspend_cookie = ndi_event_tag_to_cookie(hwahcp->hwahc_ndi_event_hdl,
	    USBA_EVENT_TAG_PRE_SUSPEND);

	/*
	 * Hotplug daemon may be attaching a driver that may be registering
	 * event callbacks. So it already has got the device tree lock and
	 * event handle mutex. So to prevent a deadlock while posting events,
	 * we grab and release the locks in the same order.
	 */
	mutex_enter(&hwahcp->hwahc_mutex);
	dip = hwahcp->hwahc_hc_data.hc_children_dips[port];
	usba_device = hwahcp->hwahc_hc_data.hc_usba_devices[port];
	mutex_exit((&hwahcp->hwahc_mutex));

	switch (type) {
	case USBA_EVENT_TAG_HOT_REMOVAL:
		/* stop this device's timer to prevent its further process */
		mutex_enter(&hc_data->hc_mutex);

		hwahc_stop_trust_timer(hc_data->hc_dev_infos[port]);
		mutex_exit(&hc_data->hc_mutex);

		/* Clear the registered event flag */
		mutex_enter(&hwahcp->hwahc_mutex);
		hwahcp->hwahc_child_events[port] &=
		    ~HWAHC_CHILD_EVENT_DISCONNECT;
		mutex_exit(&hwahcp->hwahc_mutex);

		(void) ndi_event_do_callback(hwahcp->hwahc_ndi_event_hdl,
		    dip, cookie, NULL);
		usba_persistent_pipe_close(usba_device);

		/*
		 * Mark the dip for deletion only after the driver has
		 * seen the disconnect event to prevent cleanup thread
		 * from stepping in between.
		 */
#ifndef __lock_lint
		mutex_enter(&DEVI(dip)->devi_lock);
		DEVI_SET_DEVICE_REMOVED(dip);
		mutex_exit(&DEVI(dip)->devi_lock);
#endif

		break;
	case USBA_EVENT_TAG_PRE_SUSPEND:
		mutex_enter(&hwahcp->hwahc_mutex);
		hwahcp->hwahc_child_events[port] &=
		    ~HWAHC_CHILD_EVENT_PRESUSPEND;
		mutex_exit(&hwahcp->hwahc_mutex);

		(void) ndi_event_do_callback(hwahcp->hwahc_ndi_event_hdl,
		    dip, cookie, NULL);
		/*
		 * persistent pipe close for this event is taken care by the
		 * caller after verfying that all children can suspend
		 */

		break;
	case USBA_EVENT_TAG_HOT_INSERTION:
		/*
		 * Check if this child has missed the disconnect event before
		 * it registered for event callbacks
		 */
		mutex_enter(&hwahcp->hwahc_mutex);
		if (hwahcp->hwahc_child_events[port] &
		    HWAHC_CHILD_EVENT_DISCONNECT) {
			/* clear the flag and post disconnect event */
			hwahcp->hwahc_child_events[port] &=
			    ~HWAHC_CHILD_EVENT_DISCONNECT;
			mutex_exit(&hwahcp->hwahc_mutex);

			(void) ndi_event_do_callback(
			    hwahcp->hwahc_ndi_event_hdl,
			    dip, rm_cookie, NULL);
			usba_persistent_pipe_close(usba_device);
			mutex_enter(&hwahcp->hwahc_mutex);
		}
		mutex_exit(&hwahcp->hwahc_mutex);

		/*
		 * Mark the dip as reinserted to prevent cleanup thread
		 * from stepping in.
		 */
#ifndef __lock_lint
		mutex_enter(&(DEVI(dip)->devi_lock));
		DEVI_SET_DEVICE_REINSERTED(dip);
		mutex_exit(&(DEVI(dip)->devi_lock));
#endif

		rval = usba_persistent_pipe_open(usba_device);
		if (rval != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_EVENTS,
			    hwahcp->hwahc_log_handle,
			    "failed to reopen all pipes on reconnect");
		}

		(void) ndi_event_do_callback(hwahcp->hwahc_ndi_event_hdl,
		    dip, cookie, NULL);

		/*
		 * We might see a connect event only if hotplug thread for
		 * disconnect event don't run in time.
		 * Set the flag again, so we don't miss posting a
		 * disconnect event.
		 */
		mutex_enter(&hwahcp->hwahc_mutex);
		hwahcp->hwahc_child_events[port] |=
		    HWAHC_CHILD_EVENT_DISCONNECT;
		mutex_exit(&hwahcp->hwahc_mutex);

		break;
	case USBA_EVENT_TAG_POST_RESUME:
		/*
		 * Check if this child has missed the pre-suspend event before
		 * it registered for event callbacks
		 */
		mutex_enter(&hwahcp->hwahc_mutex);
		if (hwahcp->hwahc_child_events[port] &
		    HWAHC_CHILD_EVENT_PRESUSPEND) {
			/* clear the flag and post pre_suspend event */
			hwahcp->hwahc_child_events[port] &=
			    ~HWAHC_CHILD_EVENT_PRESUSPEND;
			mutex_exit(&hwahcp->hwahc_mutex);
			(void) ndi_event_do_callback(
			    hwahcp->hwahc_ndi_event_hdl,
			    dip, suspend_cookie, NULL);
			mutex_enter(&hwahcp->hwahc_mutex);
		}
		mutex_exit(&hwahcp->hwahc_mutex);

		mutex_enter(&usba_device->usb_mutex);
		usba_device->usb_no_cpr = 0;
		mutex_exit(&usba_device->usb_mutex);

		/*
		 * Since the pipe has already been opened by whub
		 * at DDI_RESUME time, there is no need for a
		 * persistent pipe open
		 */
		(void) ndi_event_do_callback(hwahcp->hwahc_ndi_event_hdl,
		    dip, cookie, NULL);

		/*
		 * Set the flag again, so we don't miss posting a
		 * pre-suspend event. This enforces a tighter
		 * dev_state model.
		 */
		mutex_enter(&hwahcp->hwahc_mutex);
		hwahcp->hwahc_child_events[port] |=
		    HWAHC_CHILD_EVENT_PRESUSPEND;
		mutex_exit(&hwahcp->hwahc_mutex);
		break;
	}
}

/*
 * hwahc_run_callbacks:
 *	Send an event to all children
 */
static void
hwahc_run_callbacks(hwahc_state_t *hwahcp, usba_event_t type)
{
	usb_port_t	port;
	wusb_hc_data_t	*hc_data = &hwahcp->hwahc_hc_data;

	USB_DPRINTF_L4(PRINT_MASK_EVENTS, hwahcp->hwahc_log_handle,
	    "hwahc_run_callbacks:");

	mutex_enter(&hc_data->hc_mutex);
	for (port = 1; port <= hc_data->hc_num_ports; port++) {
		if (hc_data->hc_children_dips[port]) {
			mutex_exit(&hc_data->hc_mutex);
			hwahc_post_event(hwahcp, port, type);
			mutex_enter(&hc_data->hc_mutex);
		}
	}
	mutex_exit(&hc_data->hc_mutex);
}

/*
 * hwahc_disconnect_event_cb:
 *	Called when hwa device hotplug-removed.
 *		Close pipes
 *		Post event to child
 *		Set state to DISCONNECTED
 */
static int
hwahc_disconnect_event_cb(dev_info_t *dip)
{
	int		instance = ddi_get_instance(dip);
	hwahc_state_t	*hwahcp;
	int		circ;

	if ((hwahcp = ddi_get_soft_state(hwahc_statep, instance)) == NULL) {

		return (USB_FAILURE);
	}

	USB_DPRINTF_L4(PRINT_MASK_EVENTS, hwahcp->hwahc_log_handle,
	    "hwahc_disconnect_event_cb: dip = 0x%p", (void *)dip);

	ndi_devi_enter(dip, &circ);

	mutex_enter(&hwahcp->hwahc_mutex);

	USB_DPRINTF_L4(PRINT_MASK_EVENTS, hwahcp->hwahc_log_handle,
	    "hwahc_disconnect_event_cb: devstate= %d hw-state=%d",
	    hwahcp->hwahc_dev_state, hwahcp->hwahc_hw_state);
	switch (hwahcp->hwahc_dev_state) {
	case USB_DEV_ONLINE:
	case USB_DEV_PWRED_DOWN:
		hwahcp->hwahc_dev_state = USB_DEV_DISCONNECTED;

		if (hwahcp->hwahc_hw_state != HWAHC_HW_STOPPED) {
			mutex_exit(&hwahcp->hwahc_mutex);
			wusb_wa_stop_nep(&hwahcp->hwahc_wa_data);
			mutex_enter(&hwahcp->hwahc_mutex);
			hwahc_stop_result_thread(hwahcp);
			hwahc_drain_notif_queue(hwahcp);
		}
		/* FALLTHROUGH */
	case USB_DEV_SUSPENDED:
		/* remain in this state */
		mutex_exit(&hwahcp->hwahc_mutex);
		hwahc_run_callbacks(hwahcp, USBA_EVENT_TAG_HOT_REMOVAL);
		mutex_enter(&hwahcp->hwahc_mutex);

		hwahcp->hwahc_hc_soft_state = HWAHC_CTRL_INIT_STATE;

		break;
	case USB_DEV_DISCONNECTED:
		USB_DPRINTF_L2(PRINT_MASK_EVENTS, hwahcp->hwahc_log_handle,
		    "hwahc_disconnect_event_cb: already disconnected");

		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_EVENTS, hwahcp->hwahc_log_handle,
		    "hwahc_disconnect_event_cb: illegal devstate=%d",
		    hwahcp->hwahc_dev_state);

		break;
	}
	mutex_exit(&hwahcp->hwahc_mutex);

	ndi_devi_exit(dip, circ);

	return (USB_SUCCESS);
}


/*
 * hwahc_reconnect_event_cb:
 *	Called with device hotplug-inserted
 *		Restore state
 */
static int
hwahc_reconnect_event_cb(dev_info_t *dip)
{
	int		instance = ddi_get_instance(dip);
	hwahc_state_t	*hwahcp;
	int		circ;


	if ((hwahcp = ddi_get_soft_state(hwahc_statep, instance)) == NULL) {

		return (USB_FAILURE);
	}

	USB_DPRINTF_L4(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
	    "hwahc_reconnect_event_cb: dip = 0x%p", (void *)dip);

	ndi_devi_enter(dip, &circ);
	hwahc_restore_device_state(dip, hwahcp);
	ndi_devi_exit(dip, circ);

	return (USB_SUCCESS);
}


/*
 * hwahc_pre_suspend_event_cb:
 *	Called before HWA device suspend
 */
static int
hwahc_pre_suspend_event_cb(dev_info_t *dip)
{
	int		instance = ddi_get_instance(dip);
	hwahc_state_t	*hwahcp;
	int		circ;

	if ((hwahcp = ddi_get_soft_state(hwahc_statep, instance)) == NULL) {

		return (USB_FAILURE);
	}

	USB_DPRINTF_L4(PRINT_MASK_EVENTS, hwahcp->hwahc_log_handle,
	    "hwahc_pre_suspend_event_cb: dip = 0x%p", (void *)dip);

	mutex_enter(&hwahcp->hwahc_mutex);
	USB_DPRINTF_L4(PRINT_MASK_PM, hwahcp->hwahc_log_handle,
	    "hwahc_pre_suspend_event_cb: start, hw state = %d, softstate = %d",
	    hwahcp->hwahc_hw_state, hwahcp->hwahc_hc_soft_state);
	mutex_exit(&hwahcp->hwahc_mutex);

	/* keep PM out till we see a cpr resume */
	(void) hwahc_pm_busy_component(hwahcp);
	(void) pm_raise_power(hwahcp->hwahc_dip, 0, USB_DEV_OS_FULL_PWR);

	ndi_devi_enter(dip, &circ);
	hwahc_run_callbacks(hwahcp, USBA_EVENT_TAG_PRE_SUSPEND);
	ndi_devi_exit(dip, circ);

	/*
	 * rc driver is always suspended first, that fails the hc suspend.
	 * need to suspend hc before rc is suspended, so move the suspend
	 * operations here
	 */
	mutex_enter(&hwahcp->hwahc_mutex);
	if (hwahcp->hwahc_dev_state != USB_DEV_ONLINE) {
		USB_DPRINTF_L3(PRINT_MASK_EVENTS, hwahcp->hwahc_log_handle,
		    "hwahc_pre_suspend_event_cb: dev_state = %d",
		    hwahcp->hwahc_dev_state);
		mutex_exit(&hwahcp->hwahc_mutex);

		return (USB_SUCCESS);
	}

	if (hwahcp->hwahc_hw_state == HWAHC_HW_STARTED) {
		/*
		 * notify children the host is going to stop
		 */
		(void) hwahc_hc_channel_suspend(hwahcp);
	}

	/* stop the hc from functioning */
	if (hwahcp->hwahc_hw_state != HWAHC_HW_STOPPED) {
		mutex_exit(&hwahcp->hwahc_mutex);
		wusb_wa_stop_nep(&hwahcp->hwahc_wa_data);

		mutex_enter(&hwahcp->hwahc_mutex);
		hwahc_stop_result_thread(hwahcp);
		hwahc_drain_notif_queue(hwahcp);

		mutex_exit(&hwahcp->hwahc_mutex);
		(void) wusb_wa_disable(&hwahcp->hwahc_wa_data,
		    hwahcp->hwahc_default_pipe);
		mutex_enter(&hwahcp->hwahc_mutex);

	}

	USB_DPRINTF_L4(PRINT_MASK_PM, hwahcp->hwahc_log_handle,
	    "hwahc_pre_suspend_event_cb: end, devstate=%d "
	    "hwstate=%d softstate = %d",
	    hwahcp->hwahc_dev_state, hwahcp->hwahc_hw_state,
	    hwahcp->hwahc_hc_soft_state);

	mutex_exit(&hwahcp->hwahc_mutex);

	return (USB_SUCCESS);
}


/*
 * hwahc_post_resume_event_cb:
 *	Call after HWA device resume
 */
static int
hwahc_post_resume_event_cb(dev_info_t *dip)
{
	int		instance = ddi_get_instance(dip);
	hwahc_state_t	*hwahcp;
	int		circ;

	if ((hwahcp = ddi_get_soft_state(hwahc_statep, instance)) == NULL) {

		return (USB_FAILURE);
	}

	USB_DPRINTF_L4(PRINT_MASK_EVENTS, hwahcp->hwahc_log_handle,
	    "hwahc_post_resume_event_cb: dip = 0x%p", (void *)dip);

	mutex_enter(&hwahcp->hwahc_mutex);

	USB_DPRINTF_L4(PRINT_MASK_PM, hwahcp->hwahc_log_handle,
	    "hwahc_post_resume_event_cb: start, hw state = %d, softstate = %d",
	    hwahcp->hwahc_hw_state, hwahcp->hwahc_hc_soft_state);
	mutex_exit(&hwahcp->hwahc_mutex);

	ndi_devi_enter(dip, &circ);

	/* need to place hc restore here to make sure rc has resumed */
	hwahc_restore_device_state(dip, hwahcp);

	hwahc_run_callbacks(hwahcp, USBA_EVENT_TAG_POST_RESUME);

	ndi_devi_exit(dip, circ);

	/* enable PM */
	(void) hwahc_pm_idle_component(hwahcp);

	return (USB_SUCCESS);
}


/*
 * hwahc_restore_device_state:
 *	Called during hotplug-reconnect and resume.
 *		re-enable power management
 *		Verify the device is the same as before the disconnect/suspend.
 *		Restore device state
 *		Thaw any IO which was frozen.
 *		Quiesce device.  (Other routines will activate if thawed IO.)
 *		Set device online.
 *		Leave device disconnected if there are problems.
 */
static void
hwahc_restore_device_state(dev_info_t *dip, hwahc_state_t *hwahcp)
{
	int	rval;
	int	old_hw_state;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
	    "hwahc_restore_device_state: dip = 0x%p", (void *)dip);

	mutex_enter(&hwahcp->hwahc_mutex);

	ASSERT((hwahcp->hwahc_dev_state == USB_DEV_DISCONNECTED) ||
	    (hwahcp->hwahc_dev_state == USB_DEV_SUSPENDED));

	/* raise power */
	mutex_exit(&hwahcp->hwahc_mutex);
	hwahc_pm_busy_component(hwahcp);
	(void) pm_raise_power(hwahcp->hwahc_dip, 0, USB_DEV_OS_FULL_PWR);

	/*
	 * Check if we are talking to the same device
	 * Some host controllers may see all devices disconnected
	 * when they just resume. This may be a cause of not
	 * finding the same device.
	 *
	 * Some HWA devices need to download firmware when it is
	 * powered on. Before the firmware is downloaded, the device
	 * will look differently.
	 */
	if (usb_check_same_device(dip, hwahcp->hwahc_log_handle,
	    USB_LOG_L0, PRINT_MASK_ALL,
	    USB_CHK_BASIC | USB_CHK_SERIAL | USB_CHK_VIDPID, NULL) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_restore_device_state: not the same device");
		/* change the device state from suspended to disconnected */
		mutex_enter(&hwahcp->hwahc_mutex);
		hwahcp->hwahc_dev_state = USB_DEV_DISCONNECTED;
		hwahcp->hwahc_hc_soft_state = HWAHC_CTRL_ERROR_STATE;
		mutex_exit(&hwahcp->hwahc_mutex);
		hwahc_pm_idle_component(hwahcp);

		return;
	}

	USB_DPRINTF_L3(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
	    "hwahc_restore_device_state: Hwahc has been reconnected but"
	    " data may have been lost");

	mutex_enter(&hwahcp->hwahc_mutex);

	/* reinitialize the hw */
	hwahcp->hwahc_dev_state = USB_DEV_ONLINE;
	hwahcp->hwahc_hc_soft_state = HWAHC_CTRL_INIT_STATE;

	if (hwahcp->hwahc_hw_state == HWAHC_HW_STOPPED) {
		mutex_exit(&hwahcp->hwahc_mutex);
		/* no need to start hc */
		hwahc_pm_idle_component(hwahcp);
		USB_DPRINTF_L3(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_restore_device_state: stopped hwa");

		return;
	}


	rval = wusb_hc_set_cluster_id(&hwahcp->hwahc_hc_data,
	    hwahcp->hwahc_hc_data.hc_cluster_id);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_restore_device_state: set cluster id fails");

		goto err;
	}

	if (hwahcp->hwahc_hw_state == HWAHC_HW_STARTED) {
		old_hw_state = hwahcp->hwahc_hw_state;
		hwahcp->hwahc_hw_state = HWAHC_HW_CH_STOPPED;
		rval = hwahc_hc_channel_start(hwahcp);
		if (rval != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA,
			    hwahcp->hwahc_log_handle,
			    "hwahc_restore_device_state: start hc fails");
			hwahcp->hwahc_hw_state = old_hw_state;

			goto err;
		}
		hwahcp->hwahc_hw_state = old_hw_state;
	}

	rval = wusb_hc_set_num_dnts(&hwahcp->hwahc_hc_data,
	    HWAHC_DEFAULT_DNTS_INTERVAL, HWAHC_DEFAULT_DNTS_SLOT_NUM);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_restore_device_state: set num dnts fails");

		goto err;
	}

	/* set default GTK */
	rval = wusb_hc_set_gtk(&hwahcp->hwahc_hc_data, dft_gtk, dft_gtkid);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_restore_device_state: set gtk fails");

		goto err;
	}

	mutex_exit(&hwahcp->hwahc_mutex);

	rval = wusb_wa_enable(&hwahcp->hwahc_wa_data,
	    hwahcp->hwahc_default_pipe);
	mutex_enter(&hwahcp->hwahc_mutex);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_restore_device_state: enable wa fails");

		goto err;
	}

	/*
	 * This is a workaround, sometimes the ioctl and reconnect will
	 * happen at the sametime, so the ioctl will start nep which makes
	 * the below sart nep fail. Need more work to do to avoid such
	 * issues
	 */
	(void) wusb_wa_stop_nep(&hwahcp->hwahc_wa_data);

	rval = wusb_wa_start_nep(&hwahcp->hwahc_wa_data, USB_FLAGS_SLEEP);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_restore_device_state: start notifep fails rval =%d",
		    rval);
		mutex_exit(&hwahcp->hwahc_mutex);
		(void) wusb_wa_disable(&hwahcp->hwahc_wa_data,
		    hwahcp->hwahc_default_pipe);
		mutex_enter(&hwahcp->hwahc_mutex);

		goto err;
	}

	/* Handle transfer results on bulk-in ep */
	rval = hwahc_start_result_thread(hwahcp);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_restore_device_state: start result thread fails");
		mutex_exit(&hwahcp->hwahc_mutex);
		wusb_wa_stop_nep(&hwahcp->hwahc_wa_data);
		(void) wusb_wa_disable(&hwahcp->hwahc_wa_data,
		    hwahcp->hwahc_default_pipe);
		mutex_enter(&hwahcp->hwahc_mutex);

		goto err;
	}

	/* if the device had remote wakeup earlier, enable it again */
	if (hwahcp->hwahc_pm && hwahcp->hwahc_pm->hwahc_wakeup_enabled) {
		mutex_exit(&hwahcp->hwahc_mutex);
		(void) usb_handle_remote_wakeup(hwahcp->hwahc_dip,
		    USB_REMOTE_WAKEUP_ENABLE);
		mutex_enter(&hwahcp->hwahc_mutex);
	}

	hwahcp->hwahc_hw_state = HWAHC_HW_STARTED;
	hwahcp->hwahc_hc_soft_state = HWAHC_CTRL_OPERATIONAL_STATE;
	mutex_exit(&hwahcp->hwahc_mutex);
	hwahc_pm_idle_component(hwahcp);

	return;

err:
	hwahcp->hwahc_hw_state = HWAHC_HW_STOPPED;
	mutex_exit(&hwahcp->hwahc_mutex);
	hwahc_pm_idle_component(hwahcp);
}


/*
 * hwahc_cpr_suspend:
 *	Clean up device.
 *	Wait for any IO to finish, then close pipes.
 *	Quiesce device.
 * due to the dependency on hwarc, the actual suspend operations are
 * moved to hwahc_pre_suspend_event_cb function.
 */
static int
hwahc_cpr_suspend(dev_info_t *dip)
{
	int		instance = ddi_get_instance(dip);
	hwahc_state_t	*hwahcp = ddi_get_soft_state(hwahc_statep, instance);

	if (hwahcp == NULL) {

		return (USB_FAILURE);
	}

	USB_DPRINTF_L4(PRINT_MASK_PM, hwahcp->hwahc_log_handle,
	    "hwahc_cpr_suspend: start");

	mutex_enter(&hwahcp->hwahc_mutex);

	/* Don't suspend if the device is open. */
	if (hwahcp->hwahc_open_count > 0) {
		USB_DPRINTF_L2(PRINT_MASK_PM, hwahcp->hwahc_log_handle,
		    "hwahc_cpr_suspend: Device is open, cannot suspend");
		mutex_exit(&hwahcp->hwahc_mutex);

		return (USB_FAILURE);
	}

	mutex_exit(&hwahcp->hwahc_mutex);
	/* raise power */
	hwahc_pm_busy_component(hwahcp);
	(void) pm_raise_power(hwahcp->hwahc_dip, 0, USB_DEV_OS_FULL_PWR);

	mutex_enter(&hwahcp->hwahc_mutex);
	switch (hwahcp->hwahc_dev_state) {
	case USB_DEV_ONLINE:
	/* real suspend operations put in pre_suspend function */
		/* FALLTHRU */
	case USB_DEV_DISCONNECTED:
	case USB_DEV_PWRED_DOWN:
		hwahcp->hwahc_dev_state = USB_DEV_SUSPENDED;
		hwahcp->hwahc_hw_state = HWAHC_HW_CH_SUSPEND;

		break;
	case USB_DEV_SUSPENDED:
	default:
		USB_DPRINTF_L2(PRINT_MASK_PM, hwahcp->hwahc_log_handle,
		    "hwahc_cpr_suspend: illegal dev state=%d",
		    hwahcp->hwahc_dev_state);

		break;
	}

	mutex_exit(&hwahcp->hwahc_mutex);
	hwahc_pm_idle_component(hwahcp);

	USB_DPRINTF_L4(PRINT_MASK_PM, hwahcp->hwahc_log_handle,
	    "hwahc_cpr_suspend: end");

	return (USB_SUCCESS);
}


/*
 * hwahc_cpr_resume:
 *
 *	hwahc_restore_device_state marks success by putting device back online
 */
static int
hwahc_cpr_resume(dev_info_t *dip)
{
	int		instance = ddi_get_instance(dip);
	hwahc_state_t	*hwahcp = ddi_get_soft_state(hwahc_statep, instance);

	if (hwahcp == NULL) {

		return (USB_FAILURE);
	}

	USB_DPRINTF_L4(PRINT_MASK_PM, hwahcp->hwahc_log_handle,
	    "hwahc_cpr_resume: hw state = %d, softstate = %d",
	    hwahcp->hwahc_hw_state, hwahcp->hwahc_hc_soft_state);

	/*
	 * rc is always resumed after hc. restoring hc before rc would fail.
	 * move the restoring operations to hwahc_post_resume_event_cb.
	 */

	return (USB_SUCCESS);
}

/*
 * hwahc_create_pm_components:
 *	Create power managements components
 */
static void
hwahc_create_pm_components(dev_info_t *dip, hwahc_state_t *hwahcp)
{
	hwahc_power_t	*hwahcpm;
	uint_t		pwr_states;

	USB_DPRINTF_L4(PRINT_MASK_PM, hwahcp->hwahc_log_handle,
	    "hwahc_create_pm_components: Begin");

	/* Allocate the state structure */
	hwahcpm = kmem_zalloc(sizeof (hwahc_power_t), KM_SLEEP);
	hwahcp->hwahc_pm = hwahcpm;
	hwahcpm->hwahc_state = hwahcp;
	hwahcpm->hwahc_pm_capabilities = 0;
	hwahcpm->hwahc_current_power = USB_DEV_OS_FULL_PWR;

	if (usb_create_pm_components(dip, &pwr_states) == USB_SUCCESS) {
		USB_DPRINTF_L3(PRINT_MASK_PM, hwahcp->hwahc_log_handle,
		    "hwahc_create_pm_components: created PM components");

		if (usb_handle_remote_wakeup(dip,
		    USB_REMOTE_WAKEUP_ENABLE) == USB_SUCCESS) {
			hwahcpm->hwahc_wakeup_enabled = 1;
		}
		hwahcpm->hwahc_pwr_states = (uint8_t)pwr_states;
		/* make device busy till end of attach */
		hwahc_pm_busy_component(hwahcp);
		(void) pm_raise_power(hwahcp->hwahc_dip, 0,
		    USB_DEV_OS_FULL_PWR);
	} else {
		USB_DPRINTF_L3(PRINT_MASK_PM, hwahcp->hwahc_log_handle,
		    "hwahc_create_pm_components: failed");
	}

	USB_DPRINTF_L4(PRINT_MASK_PM, hwahcp->hwahc_log_handle,
	    "hwahc_create_pm_components: End");
}

/*
 * hwahc_destroy_pm_components:
 *	Shut down and destroy power management and remote wakeup functionality
 */
static void
hwahc_destroy_pm_components(hwahc_state_t *hwahcp)
{
	USB_DPRINTF_L4(PRINT_MASK_PM, hwahcp->hwahc_log_handle,
	    "hwahc_destroy_pm_components: Begin");

	ASSERT(!mutex_owned(&hwahcp->hwahc_mutex));

	mutex_enter(&hwahcp->hwahc_mutex);
	if (hwahcp->hwahc_pm && (hwahcp->hwahc_dev_state !=
	    USB_DEV_DISCONNECTED)) {
		mutex_exit(&hwahcp->hwahc_mutex);
		hwahc_pm_busy_component(hwahcp);
		mutex_enter(&hwahcp->hwahc_mutex);

		if (hwahcp->hwahc_pm->hwahc_wakeup_enabled) {
			int rval;

			mutex_exit(&hwahcp->hwahc_mutex);
			(void) pm_raise_power(hwahcp->hwahc_dip, 0,
			    USB_DEV_OS_FULL_PWR);

			if ((rval = usb_handle_remote_wakeup(
			    hwahcp->hwahc_dip,
			    USB_REMOTE_WAKEUP_DISABLE)) !=
			    USB_SUCCESS) {
				USB_DPRINTF_L3(PRINT_MASK_PM,
				    hwahcp->hwahc_log_handle,
				    "hwahc_destroy_pm_components: "
				    "Error disabling rmt wakeup: rval = %d",
				    rval);
			}
		} else {
			mutex_exit(&hwahcp->hwahc_mutex);
		}

		/*
		 * Since remote wakeup is disabled now,
		 * no one can raise power and get to device
		 * once power is lowered here.
		 */
		(void) pm_lower_power(hwahcp->hwahc_dip, 0, USB_DEV_OS_PWR_OFF);

		hwahc_pm_idle_component(hwahcp);
		mutex_enter(&hwahcp->hwahc_mutex);
	}

	if (hwahcp->hwahc_pm) {
		kmem_free(hwahcp->hwahc_pm, sizeof (hwahc_power_t));
		hwahcp->hwahc_pm = NULL;
	}
	mutex_exit(&hwahcp->hwahc_mutex);

	USB_DPRINTF_L4(PRINT_MASK_PM, hwahcp->hwahc_log_handle,
	    "hwahc_destroy_pm_components: End");
}

/* mark component busy */
static void
hwahc_pm_busy_component(hwahc_state_t *hwahcp)
{
	ASSERT(!mutex_owned(&hwahcp->hwahc_mutex));

	if (hwahcp->hwahc_pm != NULL) {
		mutex_enter(&hwahcp->hwahc_mutex);
		hwahcp->hwahc_pm->hwahc_pm_busy++;
		USB_DPRINTF_L4(PRINT_MASK_PM, hwahcp->hwahc_log_handle,
		    "hwahc_pm_busy_component: %d",
		    hwahcp->hwahc_pm->hwahc_pm_busy);
		mutex_exit(&hwahcp->hwahc_mutex);

		if (pm_busy_component(hwahcp->hwahc_dip, 0) !=
		    DDI_SUCCESS) {
			mutex_enter(&hwahcp->hwahc_mutex);
			hwahcp->hwahc_pm->hwahc_pm_busy--;
			USB_DPRINTF_L2(PRINT_MASK_PM,
			    hwahcp->hwahc_log_handle,
			    "hwahc_pm_busy_component failed: %d",
			    hwahcp->hwahc_pm->hwahc_pm_busy);
			mutex_exit(&hwahcp->hwahc_mutex);
		}
	}
}

/* mark component idle */
static void
hwahc_pm_idle_component(hwahc_state_t *hwahcp)
{
	ASSERT(!mutex_owned(&hwahcp->hwahc_mutex));

	if (hwahcp->hwahc_pm != NULL) {

		if (pm_idle_component(hwahcp->hwahc_dip, 0) ==
		    DDI_SUCCESS) {
			mutex_enter(&hwahcp->hwahc_mutex);
			ASSERT(hwahcp->hwahc_pm->hwahc_pm_busy > 0);
			hwahcp->hwahc_pm->hwahc_pm_busy--;
			USB_DPRINTF_L4(PRINT_MASK_PM,
			    hwahcp->hwahc_log_handle,
			    "hwahc_pm_idle_component: %d",
			    hwahcp->hwahc_pm->hwahc_pm_busy);
			mutex_exit(&hwahcp->hwahc_mutex);
		}
	}
}

/*
 * hwahc_power :
 *	Power entry point, the workhorse behind pm_raise_power, pm_lower_power,
 *	usb_req_raise_power and usb_req_lower_power.
 */
/* ARGSUSED */
static int
hwahc_power(dev_info_t *dip, int comp, int level)
{
	hwahc_state_t	*hwahcp;
	hwahc_power_t	*pm;
	int		rval = USB_FAILURE;

	hwahcp = ddi_get_soft_state(hwahc_statep, ddi_get_instance(dip));

	if (hwahcp == NULL) {

		return (DDI_FAILURE);
	}

	USB_DPRINTF_L4(PRINT_MASK_PM, hwahcp->hwahc_log_handle,
	    "hwahc_power: dip = 0x%p", (void *)dip);

	mutex_enter(&hwahcp->hwahc_mutex);

	if (hwahcp->hwahc_pm == NULL) {

		goto done;
	}

	pm = hwahcp->hwahc_pm;

	/* Check if we are transitioning to a legal power level */
	if (USB_DEV_PWRSTATE_OK(pm->hwahc_pwr_states, level)) {
		USB_DPRINTF_L2(PRINT_MASK_PM, hwahcp->hwahc_log_handle,
		    "hwahc_power: illegal power level = %d "
		    "pwr_states: %x", level, pm->hwahc_pwr_states);

		goto done;
	}

	switch (level) {
	case USB_DEV_OS_PWR_OFF :
		rval = hwahc_pwrlvl0(hwahcp);

		break;
	case USB_DEV_OS_PWR_1:
		rval = hwahc_pwrlvl1(hwahcp);

		break;
	case USB_DEV_OS_PWR_2:
		rval = hwahc_pwrlvl2(hwahcp);

		break;
	case USB_DEV_OS_FULL_PWR :
		rval = hwahc_pwrlvl3(hwahcp);

		break;
	}
done:
	mutex_exit(&hwahcp->hwahc_mutex);

	return ((rval == USB_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}

/*
 * hwahc_pwrlvl0:
 * Functions to handle power transition for OS levels 0 -> 3
 *	OS 0 <--> USB D3, no or minimal power
 */
static int
hwahc_pwrlvl0(hwahc_state_t *hwahcp)
{
	int	rval;

	USB_DPRINTF_L4(PRINT_MASK_PM, hwahcp->hwahc_log_handle,
	    "hwahc_pwrlvl0: %d", hwahcp->hwahc_pm->hwahc_pm_busy);

	switch (hwahcp->hwahc_dev_state) {
	case USB_DEV_ONLINE:
		/* Deny the powerdown request if the device is busy */
		if (hwahcp->hwahc_pm->hwahc_pm_busy != 0) {
			USB_DPRINTF_L2(PRINT_MASK_PM,
			    hwahcp->hwahc_log_handle,
			    "hwahc_pwrlvl0: hwahc_pm is busy");

			return (USB_FAILURE);
		}
		/*
		 * only when final_stop gets called, we allow the system
		 * to do PM on us. At this moment, we don't need to do
		 * more operations other than those in final_stop.
		 */

		/* Issue USB D3 command to the device here */
		rval = usb_set_device_pwrlvl3(hwahcp->hwahc_dip);
		ASSERT(rval == USB_SUCCESS);

		hwahcp->hwahc_dev_state = USB_DEV_PWRED_DOWN;

		hwahcp->hwahc_pm->hwahc_current_power = USB_DEV_OS_PWR_OFF;

		break;
	case USB_DEV_DISCONNECTED:
	case USB_DEV_SUSPENDED:
	case USB_DEV_PWRED_DOWN:
	default:
		break;
	}

	return (USB_SUCCESS);
}

/*
 * hwahc_pwrlvl1:
 *	Functions to handle power transition to OS levels -> 2
 *	OS level 1 <--> D2
 */
static int
hwahc_pwrlvl1(hwahc_state_t *hwahcp)
{
	int	rval;

	USB_DPRINTF_L4(PRINT_MASK_PM, hwahcp->hwahc_log_handle,
	    "hwahc_pwrlvl1:");

	/* Issue USB D2 command to the device here */
	rval = usb_set_device_pwrlvl2(hwahcp->hwahc_dip);
	ASSERT(rval == USB_SUCCESS);

	return (USB_FAILURE);
}

/*
 * hwahc_pwrlvl2:
 *	Functions to handle power transition to OS levels -> 1
 *	OS leve 2 <--> D1
 */
static int
hwahc_pwrlvl2(hwahc_state_t *hwahcp)
{
	int	rval;

	USB_DPRINTF_L4(PRINT_MASK_PM, hwahcp->hwahc_log_handle,
	    "hwahc_pwrlvl2:");

	/* Issue USB D1 command to the device here */
	rval = usb_set_device_pwrlvl1(hwahcp->hwahc_dip);
	ASSERT(rval == USB_SUCCESS);

	return (USB_FAILURE);
}


/*
 * hwahc_pwrlvl3:
 *	Functions to handle power transition to OS level -> 0
 *	OS level 3 <--> D0 (full power)
 */
static int
hwahc_pwrlvl3(hwahc_state_t *hwahcp)
{
	USB_DPRINTF_L4(PRINT_MASK_PM, hwahcp->hwahc_log_handle,
	    "hwahc_pwrlvl3: %d", hwahcp->hwahc_pm->hwahc_pm_busy);

	ASSERT(mutex_owned(&hwahcp->hwahc_mutex));

	switch (hwahcp->hwahc_dev_state) {
	case USB_DEV_PWRED_DOWN:
		/* Issue USB D0 command to the device here */
		(void) usb_set_device_pwrlvl0(hwahcp->hwahc_dip);

		/*
		 * Due to our current PM policy, it's not possible
		 * for hwa to be in USB_DEV_PWRED_DOWN between
		 * initial_start and final_stop. If it's PWRED_DOWN,
		 * it should not start. We don't need to resume
		 * soft or hardware state in this case.
		 */
		if (hwahcp->hwahc_hw_state == HWAHC_HW_STOPPED) {
			/* no need to start hc */
			hwahcp->hwahc_dev_state = USB_DEV_ONLINE;
			hwahcp->hwahc_pm->hwahc_current_power =
			    USB_DEV_OS_FULL_PWR;

			return (USB_SUCCESS);
		}

		hwahcp->hwahc_pm->hwahc_current_power = USB_DEV_OS_FULL_PWR;

		/* FALLTHRU */
	case USB_DEV_ONLINE:
		/* we are already in full power */
		/* FALLTHRU */
	case USB_DEV_DISCONNECTED:
	case USB_DEV_SUSPENDED:
		/*
		 * PM framework tries to put you in full power
		 * during system shutdown. If we are disconnected
		 * return success. Also, we should not change state
		 * when we are disconnected or suspended or about to
		 * transition to that state
		 */

		return (USB_SUCCESS);
	default:
		USB_DPRINTF_L4(PRINT_MASK_PM, hwahcp->hwahc_log_handle,
		    "hwahc_pwrlvl3: illegal dev_state=%d",
		    hwahcp->hwahc_dev_state);


		return (USB_FAILURE);
	}
}

/*
 * Host power management: stop channel
 * 	See Section 4.16.2.1 for details
 *	See Section 8.1.0 for HWA suspend/resume
 */
static int
hwahc_hc_channel_suspend(hwahc_state_t *hwahcp)
{
	int			rval;

	USB_DPRINTF_L4(PRINT_MASK_PM, hwahcp->hwahc_log_handle,
	    "hwahc_hc_channel_suspend:");

	ASSERT(mutex_owned(&hwahcp->hwahc_mutex));

	/* no need to suspend if host hw was not started */
	if (hwahcp->hwahc_hw_state != HWAHC_HW_STARTED) {
		USB_DPRINTF_L3(PRINT_MASK_PM, hwahcp->hwahc_log_handle,
		    "hwahc_hc_channel_suspend: hw already stopped");

		return (USB_SUCCESS);
	}

	if (hwahcp->hwahc_hw_state == HWAHC_HW_CH_SUSPEND) {
		USB_DPRINTF_L3(PRINT_MASK_PM, hwahcp->hwahc_log_handle,
		    "hwahc_hc_channel_suspend: already suspended");

		return (USB_SUCCESS);
	}

	mutex_exit(&hwahcp->hwahc_mutex);
	/* suspend host, refer to WUSB 1.0 spec 8.5.3.14 */
	rval = wusb_hc_stop_ch(&hwahcp->hwahc_hc_data, 10000); /* 10ms */
	mutex_enter(&hwahcp->hwahc_mutex);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_PM, hwahcp->hwahc_log_handle,
		    "hwahc_hc_channel_suspend: wusb channel stop fails");

		return (rval);
	}

	hwahcp->hwahc_hw_state = HWAHC_HW_CH_SUSPEND;

	return (USB_SUCCESS);
}

/*
 * Parse security descriptors, see T.8-43
 * 	put result in secrt_data
 */
static int
hwahc_parse_security_data(wusb_secrt_data_t *secrt_data,
	usb_cfg_data_t *cfg_data)
{
	int		i, j;
	usb_cvs_data_t	*cvs_data;
	size_t		count, len;

	if ((secrt_data == NULL) || (cfg_data == NULL)) {
		return (USB_INVALID_ARGS);
	}

	for (i = 0; i < cfg_data->cfg_n_cvs; i++) {
		cvs_data = &cfg_data->cfg_cvs[i];
		if (cvs_data == NULL) {
			continue;
		}
		if (cvs_data->cvs_buf[1] == USB_DESCR_TYPE_SECURITY) {
			count = usb_parse_data("ccsc",
			    cvs_data->cvs_buf, cvs_data->cvs_buf_len,
			    (void *)&secrt_data->secrt_descr,
			    (size_t)USB_SECURITY_DESCR_SIZE);
			if (count != USB_SECURITY_DESCR_SIZE) {

				return (USB_FAILURE);
			} else {
				secrt_data->secrt_n_encry =
				    secrt_data->secrt_descr.bNumEncryptionTypes;
				len = sizeof (usb_encryption_descr_t) *
				    secrt_data->secrt_n_encry;

				secrt_data->secrt_encry_descr =
				    (usb_encryption_descr_t *)kmem_alloc(len,
				    KM_SLEEP);

				for (j = 0; j < secrt_data->secrt_n_encry;
				    j++) {
					cvs_data =
					    &cfg_data->cfg_cvs[i + j + 1];
					if (cvs_data->cvs_buf[1] !=
					    USB_DESCR_TYPE_ENCRYPTION) {
						kmem_free(secrt_data->
						    secrt_encry_descr, len);

						return (USB_FAILURE);
					}

					/* Table 7-34 */
					count = usb_parse_data("ccccc",
					    cvs_data->cvs_buf,
					    cvs_data->cvs_buf_len,
					    (void *)&secrt_data->
					    secrt_encry_descr[j],
					    USB_ENCRYPTION_DESCR_SIZE);
					if (count !=
					    USB_ENCRYPTION_DESCR_SIZE) {
						kmem_free(secrt_data->
						    secrt_encry_descr, len);

						return (USB_FAILURE);

					}
				}
				return (USB_SUCCESS);
			}
		}
	}

	return (USB_FAILURE);
}

/* initialize wusb_hc_data_t structure */
static void
hwahc_hc_data_init(hwahc_state_t *hwahcp)
{
	wusb_hc_data_t	*hc_data = &hwahcp->hwahc_hc_data;

	hc_data->hc_dip = hwahcp->hwahc_dip;
	hc_data->hc_private_data = (void *)hwahcp;

	(void) memset(hc_data->hc_chid, 0, sizeof (hc_data->hc_chid));

	hc_data->hc_num_mmcies = hwahcp->hwahc_wa_data.wa_descr.bNumMMCIEs;

	ASSERT(hc_data->hc_num_mmcies != 0);

	hc_data->hc_mmcie_list = kmem_zalloc((hc_data->hc_num_mmcies *
	    sizeof (wusb_ie_header_t *)), KM_SLEEP);

	/* initialize frequently used IE */
	hc_data->hc_alive_ie.bIEIdentifier = WUSB_IE_DEV_KEEPALIVE;

	/* register callbacks */
	hc_data->disconnect_dev = hwahc_disconnect_dev;
	hc_data->reconnect_dev = hwahc_reconnect_dev;
	hc_data->create_child = hwahc_create_child;
	hc_data->destroy_child = hwahc_destroy_child;

	/* HWA HC operation functions */
	hc_data->set_encrypt = hwahc_set_encrypt;
	hc_data->set_ptk = hwahc_set_ptk;
	hc_data->set_gtk = hwahc_set_gtk;
	hc_data->set_device_info = hwahc_set_device_info;
	hc_data->set_cluster_id = hwahc_set_cluster_id;
	hc_data->set_stream_idx = hwahc_set_stream_idx;
	hc_data->set_wusb_mas = hwahc_set_wusb_mas;
	hc_data->add_mmc_ie = hwahc_add_mmc_ie;
	hc_data->rem_mmc_ie = hwahc_remove_mmc_ie;
	hc_data->stop_ch = hwahc_stop_ch;
	hc_data->set_num_dnts = hwahc_set_num_dnts;
	hc_data->get_time = hwahc_get_time;

	hc_data->hc_num_ports = hwahcp->hwahc_wa_data.wa_descr.bNumPorts;

	hc_data->hc_cd_list_length = (sizeof (dev_info_t **)) *
	    (hc_data->hc_num_ports + 1);

	hc_data->hc_children_dips = (dev_info_t **)kmem_zalloc(
	    hc_data->hc_cd_list_length, KM_SLEEP);
	hc_data->hc_usba_devices = (usba_device_t **)kmem_zalloc(
	    hc_data->hc_cd_list_length, KM_SLEEP);
	hc_data->hc_dev_infos = (wusb_dev_info_t **)kmem_zalloc(
	    hc_data->hc_cd_list_length, KM_SLEEP);

	mutex_init(&hc_data->hc_mutex, NULL, MUTEX_DRIVER, NULL);
}

/* deinitialize wusb_hc_data_t structure */
static void
hwahc_hc_data_fini(hwahc_state_t *hwahcp)
{
	int			i;
	wusb_hc_data_t		*hc_data = &hwahcp->hwahc_hc_data;
	wusb_ie_header_t	*hdr;

#ifdef DEBUG
	usb_port_t	port;
#endif

	if (hc_data->hc_mmcie_list) {
		/* Free all recorded IEs except statically allocated IEs */
		for (i = 0; i < hc_data->hc_num_mmcies; i++) {
			if (hc_data->hc_mmcie_list[i] != NULL) {
				hdr = hc_data->hc_mmcie_list[i];
				if ((hdr->bIEIdentifier !=
				    WUSB_IE_DEV_KEEPALIVE)) {
					kmem_free(hdr, hdr->bLength);
				}
				hc_data->hc_mmcie_list[i] = NULL;
			}
		}

		kmem_free(hc_data->hc_mmcie_list,
		    hc_data->hc_num_mmcies * sizeof (wusb_ie_header_t *));
	}

	if (hc_data->hc_cluster_id) {
		wusb_hc_free_cluster_id(hc_data->hc_cluster_id);
	}

	if (hc_data->hc_cc_list) {
		wusb_hc_free_cc_list(hc_data->hc_cc_list);
	}

#ifdef DEBUG
	for (port = 1; port <= hc_data->hc_num_ports; port++) {
		ASSERT(hc_data->hc_usba_devices[port] == NULL);
		ASSERT(hc_data->hc_children_dips[port] == NULL);
		ASSERT(hc_data->hc_dev_infos[port] == NULL);
	}
#endif

	kmem_free(hc_data->hc_children_dips, hc_data->hc_cd_list_length);
	kmem_free(hc_data->hc_usba_devices, hc_data->hc_cd_list_length);
	kmem_free(hc_data->hc_dev_infos, hc_data->hc_cd_list_length);

	mutex_destroy(&hc_data->hc_mutex);
}

/* fully start the HWA hw */
static int
hwahc_hc_initial_start(hwahc_state_t *hwahcp)
{
	uint8_t	stream_idx;
	uint8_t	mas[WUSB_SET_WUSB_MAS_LEN];
	int	rval;
	uint8_t	cluster_id = 0;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
	    "hwahc_hc_initial_start:");

	ASSERT(mutex_owned(&hwahcp->hwahc_mutex));

	if (hwahcp->hwahc_dev_state != USB_DEV_ONLINE) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_hc_initial_start: invalid dev state = %d",
		    hwahcp->hwahc_dev_state);

		return (USB_INVALID_REQUEST);
	}

	if (hwahcp->hwahc_hw_state != HWAHC_HW_STOPPED) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_hc_initial_start: invalid hw state");

		return (USB_INVALID_REQUEST);
	}

	/*
	 * start beacon of radio layer
	 * We're not sure if previouse channel is occupied or not. So, let
	 * UWB allocates a free channel for this hwa. Then we can start
	 * beacon.
	 */
	hwahcp->hwahc_hc_data.hc_channel =
	    uwb_allocate_channel(hwahcp->hwahc_dip);
	if (hwahcp->hwahc_hc_data.hc_channel  == 0) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA,
		    hwahcp->hwahc_log_handle,
		    "wusb_hc_initial_start: channel = %d",
		    hwahcp->hwahc_hc_data.hc_channel);
		return (USB_FAILURE);
	}

	if ((rval = uwb_start_beacon(hwahcp->hwahc_dip,
	    hwahcp->hwahc_hc_data.hc_channel)) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA,
		    hwahcp->hwahc_log_handle,
		    "wusb_hc_initial_start: start uwb beacon failed");

		return (rval);
	}

	mutex_exit(&hwahcp->hwahc_mutex);
	/* reset wire adapter */
	rval = wusb_wa_reset(&hwahcp->hwahc_wa_data,
	    hwahcp->hwahc_default_pipe);
	mutex_enter(&hwahcp->hwahc_mutex);
	if (rval != SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_hc_initial_start: reset wa fails");

		goto err;
	}

	/* reuse the old cluster id or assign one */
	if (hwahcp->hwahc_hc_data.hc_cluster_id) {
		cluster_id = hwahcp->hwahc_hc_data.hc_cluster_id;
	} else {
		cluster_id = wusb_hc_get_cluster_id();
		if (cluster_id == 0) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA,
			    hwahcp->hwahc_log_handle,
			    "hwahc_hc_initial_start: cannot get cluster id");
			rval = USB_NO_RESOURCES;

			goto err;
		}
	}

	mutex_exit(&hwahcp->hwahc_mutex);
	/* set cluster id for the wusb channel */
	rval = wusb_hc_set_cluster_id(&hwahcp->hwahc_hc_data, cluster_id);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_hc_initial_start: set cluster id %d fails",
		    cluster_id);
		mutex_enter(&hwahcp->hwahc_mutex);

		goto err;
	}

	/* UWB should be responsible for assigning stream index */
	stream_idx = 1;

	rval = wusb_hc_set_stream_idx(&hwahcp->hwahc_hc_data, stream_idx);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_hc_initial_start: set stream idx %d fails",
		    stream_idx);
		mutex_enter(&hwahcp->hwahc_mutex);

		goto err;
	}

	/* set dnts slot */
	rval = wusb_hc_set_num_dnts(&hwahcp->hwahc_hc_data,
	    HWAHC_DEFAULT_DNTS_INTERVAL, HWAHC_DEFAULT_DNTS_SLOT_NUM);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_hc_initial_start: set num dnts fails");
		mutex_enter(&hwahcp->hwahc_mutex);

		goto err;
	}

	/* set host info IE */
	rval = wusb_hc_add_host_info(&hwahcp->hwahc_hc_data, stream_idx);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_hc_initial_start: add hostinfo ie fails");
		mutex_enter(&hwahcp->hwahc_mutex);

		goto err;
	}

	/* reserve MAS slots for the host, need a way to assign */
	(void) memset(mas, 0xff, WUSB_SET_WUSB_MAS_LEN);
	mas[0] = 0xf0;	/* the first 4 slots are for beacons */
	rval = wusb_hc_set_wusb_mas(&hwahcp->hwahc_hc_data, mas);
	mutex_enter(&hwahcp->hwahc_mutex);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_hc_initial_start: set wusb mas fails");

		goto err;
	}

	/* record the available MAS slots */
	(void) memcpy(hwahcp->hwahc_hc_data.hc_mas, mas, WUSB_SET_WUSB_MAS_LEN);

	/* Set initial GTK/TKID to random values */
	(void) random_get_pseudo_bytes(dft_gtk, 16);
	(void) random_get_pseudo_bytes(dft_gtkid, 3);

	/* set default GTK, need a way to dynamically compute it */
	mutex_exit(&hwahcp->hwahc_mutex);
	rval = wusb_hc_set_gtk(&hwahcp->hwahc_hc_data, dft_gtk, dft_gtkid);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_hc_initial_start: set gtk fails");
		mutex_enter(&hwahcp->hwahc_mutex);

		goto err;
	}

	/* enable wire adapter */
	rval = wusb_wa_enable(&hwahcp->hwahc_wa_data,
	    hwahcp->hwahc_default_pipe);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_hc_initial_start: enable wa fails");
		mutex_enter(&hwahcp->hwahc_mutex);

		goto err;
	}

	/* Start Notification endpoint */
	rval = wusb_wa_start_nep(&hwahcp->hwahc_wa_data, USB_FLAGS_SLEEP);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_hc_initial_start: start notification ep fails");
		(void) wusb_wa_disable(&hwahcp->hwahc_wa_data,
		    hwahcp->hwahc_default_pipe);

		mutex_enter(&hwahcp->hwahc_mutex);

		goto err;
	}

	mutex_enter(&hwahcp->hwahc_mutex);

	/*
	 * Handle transfer results on bulk-in ep
	 * The bulk-in ep needs to be polled no matter the completion
	 * notification is received or not to avoid miss result.
	 */
	rval = hwahc_start_result_thread(hwahcp);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_hc_initial_start: start result thread fails, "
		    "rval = %d", rval);
		mutex_exit(&hwahcp->hwahc_mutex);
		wusb_wa_stop_nep(&hwahcp->hwahc_wa_data);
		(void) wusb_wa_disable(&hwahcp->hwahc_wa_data,
		    hwahcp->hwahc_default_pipe);
		mutex_enter(&hwahcp->hwahc_mutex);

		goto err;
	}
	USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
	    "hwahc_hc_initial_start: start result thread success");

	hwahcp->hwahc_hw_state = HWAHC_HW_STARTED;
	hwahcp->hwahc_hc_soft_state = HWAHC_CTRL_OPERATIONAL_STATE;

	/* Don't do PM on an active beacon hwa until explicitly stopped */
	mutex_exit(&hwahcp->hwahc_mutex);
	hwahc_pm_busy_component(hwahcp);
	mutex_enter(&hwahcp->hwahc_mutex);

	return (USB_SUCCESS);

err:
	if (cluster_id != 0) {
		wusb_hc_free_cluster_id(cluster_id);
	}

	mutex_exit(&hwahcp->hwahc_mutex);
	(void) uwb_stop_beacon(hwahcp->hwahc_dip);
	mutex_enter(&hwahcp->hwahc_mutex);

	return (rval);
}

/* entirely stop the HWA from working */
static int
hwahc_hc_final_stop(hwahc_state_t *hwahcp)
{
	USB_DPRINTF_L4(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
	    "hwahc_hc_final_stop:");

	ASSERT(mutex_owned(&hwahcp->hwahc_mutex));

	if (hwahcp->hwahc_hw_state == HWAHC_HW_STOPPED) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_hc_final_stop: already stopped");

		return (USB_SUCCESS);
	}

	if (hwahcp->hwahc_dev_state == USB_DEV_SUSPENDED) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_hc_final_stop: invalid dev state = %d",
		    hwahcp->hwahc_dev_state);

		return (USB_INVALID_REQUEST);
	}

	/* might have been powered down before detaching */
	mutex_exit(&hwahcp->hwahc_mutex);
	(void) pm_raise_power(hwahcp->hwahc_dip, 0, USB_DEV_OS_FULL_PWR);
	mutex_enter(&hwahcp->hwahc_mutex);

	if (hwahcp->hwahc_dev_state != USB_DEV_DISCONNECTED) {
		/* notify children the host is going to stop */
		(void) hwahc_hc_channel_suspend(hwahcp);

		/* release mutex here to avoid deadlock with exc_cb */
		mutex_exit(&hwahcp->hwahc_mutex);

		/* stop notification endpoint */
		wusb_wa_stop_nep(&hwahcp->hwahc_wa_data);
		mutex_enter(&hwahcp->hwahc_mutex);

		/* stop bulk-in ept from listening result */
		hwahc_stop_result_thread(hwahcp);

		/* drain the device notifications */
		hwahc_drain_notif_queue(hwahcp);

		/* disable wire adapter */
		mutex_exit(&hwahcp->hwahc_mutex);
		(void) wusb_wa_disable(&hwahcp->hwahc_wa_data,
		    hwahcp->hwahc_default_pipe);

		/* stop beaconing. Not necessary to unreserve mas */
		(void) uwb_stop_beacon(hwahcp->hwahc_dip);

		wusb_hc_rem_host_info(&hwahcp->hwahc_hc_data);

		/* Manually remove all connected children */
		hwahc_run_callbacks(hwahcp, USBA_EVENT_TAG_HOT_REMOVAL);

		/* delete all the children */
		(void) hwahc_cleanup_child(hwahcp->hwahc_dip);
		mutex_enter(&hwahcp->hwahc_mutex);
	}

	/*
	 * we make it busy at hwahc_hc_initial_start(). This idle operation
	 * is to match that busy operation.
	 * All other busy/idle operations should have been matched.
	 */
	if ((hwahcp->hwahc_hw_state == HWAHC_HW_STARTED) &&
	    (hwahcp->hwahc_hc_soft_state == HWAHC_CTRL_OPERATIONAL_STATE)) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_hc_final_stop: pm_busy=%d",
		    hwahcp->hwahc_pm->hwahc_pm_busy);
		mutex_exit(&hwahcp->hwahc_mutex);
		hwahc_pm_idle_component(hwahcp);
		mutex_enter(&hwahcp->hwahc_mutex);
	}

	hwahcp->hwahc_hw_state = HWAHC_HW_STOPPED;
	if (hwahcp->hwahc_hc_soft_state == HWAHC_CTRL_OPERATIONAL_STATE) {
		hwahcp->hwahc_hc_soft_state = HWAHC_CTRL_INIT_STATE;
	}

	return (USB_SUCCESS);
}

/*
 * init WUSB channel, this is only part of the full hw start operations
 * including setting wusb channel stream idx, wusb MAS slots reservation
 * and adding host info IE
 */
static int
hwahc_hc_channel_start(hwahc_state_t *hwahcp)
{
	uint8_t			stream_idx;
	uint8_t			mas[WUSB_SET_WUSB_MAS_LEN];
	int			rval;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
	    "hwahc_hc_channel_start:");

	ASSERT(mutex_owned(&hwahcp->hwahc_mutex));

	if (hwahcp->hwahc_dev_state != USB_DEV_ONLINE) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_hc_channel_start: invalid dev_state = %d",
		    hwahcp->hwahc_dev_state);

		return (USB_INVALID_REQUEST);
	}

	if (hwahcp->hwahc_hw_state != HWAHC_HW_CH_STOPPED) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_hc_channel_start: invalid hw state");

		return (USB_INVALID_REQUEST);
	}

	/* set stream idx */
	stream_idx = 1;

	mutex_exit(&hwahcp->hwahc_mutex);
	rval = wusb_hc_set_stream_idx(&hwahcp->hwahc_hc_data, stream_idx);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_hc_channel_start: set stream idx %d fails",
		    stream_idx);
		mutex_enter(&hwahcp->hwahc_mutex);

		return (rval);
	}

	/* reserve MAS slots for the host. Should be allocated by UWB */
	(void) memset(mas, 0xff, WUSB_SET_WUSB_MAS_LEN);
	mas[0] = 0xf0;	/* for beacons */
	rval = wusb_hc_set_wusb_mas(&hwahcp->hwahc_hc_data, mas);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_hc_channel_start: set wusb mas fails");
		mutex_enter(&hwahcp->hwahc_mutex);

		return (rval);
	}
	(void) memcpy(hwahcp->hwahc_hc_data.hc_mas, mas, WUSB_SET_WUSB_MAS_LEN);

	/* set host info IE */
	rval = wusb_hc_add_host_info(&hwahcp->hwahc_hc_data, stream_idx);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_hc_channel_start: add hostinfo ie fails");
		mutex_enter(&hwahcp->hwahc_mutex);

		return (rval);
	}

	mutex_enter(&hwahcp->hwahc_mutex);
	hwahcp->hwahc_hw_state = HWAHC_HW_STARTED;
	hwahcp->hwahc_hc_soft_state = HWAHC_CTRL_OPERATIONAL_STATE;

	/* do not PM this device, once we're ready to accept DN */
	mutex_exit(&hwahcp->hwahc_mutex);
	hwahc_pm_busy_component(hwahcp);
	mutex_enter(&hwahcp->hwahc_mutex);

	return (USB_SUCCESS);
}

/*
 * stop WUSB channel, this only stops part of the hw function
 * it mainly unreserve the MAS slots and remove the host info IE
 */
static int
hwahc_hc_channel_stop(hwahc_state_t *hwahcp)
{
	uint8_t			stream_idx;
	uint8_t			mas[WUSB_SET_WUSB_MAS_LEN];
	int			rval;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
	    "hwahc_hc_channel_stop:");

	ASSERT(mutex_owned(&hwahcp->hwahc_mutex));

	if (hwahcp->hwahc_dev_state != USB_DEV_ONLINE) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_hc_channel_stop: invalid dev state %d",
		    hwahcp->hwahc_dev_state);

		return (USB_INVALID_REQUEST);
	}

	if (hwahcp->hwahc_hw_state == HWAHC_HW_CH_STOPPED) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_hc_channel_stop: already partially stopped");

		return (USB_SUCCESS);
	}

	if (hwahcp->hwahc_hw_state == HWAHC_HW_STOPPED) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_hc_channel_stop: already stopped, invalid state");

		return (USB_INVALID_REQUEST);
	}

	/* send host disconect IE so that the children know to disconnect */
	mutex_exit(&hwahcp->hwahc_mutex);
	rval = wusb_hc_send_host_disconnect(&hwahcp->hwahc_hc_data);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_hc_channel_stop: send host disconnect ie fails");

		mutex_enter(&hwahcp->hwahc_mutex);

		return (rval);
	}

	/* remove host info IE */
	wusb_hc_rem_host_info(&hwahcp->hwahc_hc_data);

	/* unset stream idx */
	stream_idx = 0;

	rval = wusb_hc_set_stream_idx(&hwahcp->hwahc_hc_data, stream_idx);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_hc_channel_stop: set stream idx 0 fails");
		mutex_enter(&hwahcp->hwahc_mutex);

		return (rval);
	}

	/* unreserve MAS slots */
	(void) memset(mas, 0, WUSB_SET_WUSB_MAS_LEN);
	rval = wusb_hc_set_wusb_mas(&hwahcp->hwahc_hc_data, mas);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_hc_channel_stop: set null wusb mas fails");
		mutex_enter(&hwahcp->hwahc_mutex);

		return (rval);
	}

	mutex_enter(&hwahcp->hwahc_mutex);
	(void) memcpy(hwahcp->hwahc_hc_data.hc_mas, mas, WUSB_SET_WUSB_MAS_LEN);

	hwahcp->hwahc_hw_state = HWAHC_HW_CH_STOPPED;

	/* Channel is stopped, can be PM'ed */
	mutex_exit(&hwahcp->hwahc_mutex);
	hwahc_pm_idle_component(hwahcp);
	mutex_enter(&hwahcp->hwahc_mutex);

	return (USB_SUCCESS);
}

/* initialize data transfer related resources */
static int
hwahc_wa_start(hwahc_state_t *hwahcp)
{
	int	rval;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
	    "hwahc_wa_start:");

	/* get all rpipe descrs */
	if ((rval = wusb_wa_get_rpipe_descrs(&hwahcp->hwahc_wa_data,
	    hwahcp->hwahc_default_pipe, PRINT_MASK_ATTA,
	    hwahcp->hwahc_log_handle)) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_wa_start: get rpipe descrs fails, rval=%d", rval);

		return (rval);
	}

	/* open all data transfer epts */
	if ((rval = wusb_wa_open_pipes(&hwahcp->hwahc_wa_data)) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_wa_start: open pipes fails, rval=%d", rval);
		(void) wusb_wa_disable(&hwahcp->hwahc_wa_data,
		    hwahcp->hwahc_default_pipe);

		return (rval);
	}

	/* init notification list */
	usba_init_list(&hwahcp->hwahc_dn_notif_queue, NULL,
	    hwahcp->hwahc_dev_data->dev_iblock_cookie);

	return (USB_SUCCESS);
}

/* deinitialize data transfer related resources */
static void
hwahc_wa_stop(hwahc_state_t *hwahcp)
{
	USB_DPRINTF_L4(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
	    "hwahc_wa_stop:");

	usba_destroy_list(&hwahcp->hwahc_dn_notif_queue);
	wusb_wa_close_pipes(&hwahcp->hwahc_wa_data);
}

/*
 * HUBD related initialization
 * To mimic standard hub attach process to create a fake "root hub"
 * for HWA
 */
static int
hwahc_hub_attach(hwahc_state_t *hwahcp)
{
	hubd_t		*hubd = NULL;
	dev_info_t	*dip = hwahcp->hwahc_dip;
	int		instance = ddi_get_instance(dip);
	int		i;
	int		rval;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
	    "hwahc_hub_attach:");

	if (ndi_prop_create_boolean(DDI_DEV_T_NONE, dip,
	    "wire-adapter") != NDI_SUCCESS) {

		return (USB_FAILURE);
	}

	/* allocate hubd structure */
	hubd = hwahcp->hwahc_hubd = kmem_zalloc(sizeof (hubd_t), KM_SLEEP);

	hubd->h_log_handle = usb_alloc_log_hdl(dip, "husb", &hubd_errlevel,
	    &hubd_errmask, &hubd_instance_debug, 0);
	hubd->h_usba_device = usba_get_usba_device(dip);
	hubd->h_usba_device->usb_is_wa = TRUE;
	hubd->h_dip = dip;
	hubd->h_instance = instance;
	hubd->h_ignore_pwr_budget = B_TRUE;
	hubd->h_cleanup_child = hwahc_cleanup_child;

	mutex_enter(&hubd->h_usba_device->usb_mutex);
	hubd->h_usba_device->usb_root_hubd = hubd;
	mutex_exit(&hubd->h_usba_device->usb_mutex);

	if (usb_get_dev_data(dip, &hubd->h_dev_data,
	    USB_PARSE_LVL_IF, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "cannot get dev_data");

		goto fail;
	}

	/* init hubd mutex */
	mutex_init(HUBD_MUTEX(hubd), NULL, MUTEX_DRIVER,
	    hubd->h_dev_data->dev_iblock_cookie);

	usb_free_descr_tree(dip, hubd->h_dev_data);

	hubd->h_init_state |= HUBD_LOCKS_DONE;

	/* register the instance to usba HUBDI */
	rval = usba_hubdi_register(dip, 0);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "usba_hubdi_register failed");

		goto fail;
	}

	mutex_enter(HUBD_MUTEX(hubd));
	hubd->h_init_state |= HUBD_HUBDI_REGISTERED;

	hubd->h_ancestry_str = (char *)kmem_zalloc(HUBD_APID_NAMELEN,
	    KM_SLEEP);
	hubd_get_ancestry_str(hubd);

	/* create cfgadm minor nodes */
	for (i = 1; i <= hwahcp->hwahc_wa_data.wa_descr.bNumPorts; i++) {
		char ap_name[HUBD_APID_NAMELEN];

		(void) snprintf(ap_name, HUBD_APID_NAMELEN, "%s%d",
		    hubd->h_ancestry_str, i);
		USB_DPRINTF_L3(DPRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "ap_name=%s", ap_name);

		if (ddi_create_minor_node(dip, ap_name, S_IFCHR,
		    (instance << HWAHC_MINOR_INSTANCE_SHIFT) | i,
		    DDI_NT_USB_ATTACHMENT_POINT, 0) != DDI_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
			    "cannot create attachment point node (%d)",
			    instance);
			mutex_exit(HUBD_MUTEX(hubd));

			goto fail;
		}
	}
	i = hwahcp->hwahc_wa_data.wa_descr.bNumPorts;
	mutex_exit(HUBD_MUTEX(hubd));

	/* create hubd minor node */
	if (ddi_create_minor_node(dip, "hubd", S_IFCHR,
	    instance << HWAHC_MINOR_INSTANCE_SHIFT,
	    DDI_NT_NEXUS, 0) != DDI_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "cannot create devctl minor node (%d)", instance);

		goto fail;
	}

	mutex_enter(HUBD_MUTEX(hubd));
	hubd->h_init_state |= HUBD_MINOR_NODE_CREATED;
	mutex_exit(HUBD_MUTEX(hubd));

	if (ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "usb-port-count", i) != DDI_PROP_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "usb-port-count update failed");
	}

	return (USB_SUCCESS);

fail:
	if (hwahc_hub_detach(hwahcp) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "fail to cleanup after hub attach failure");
	}

	return (USB_FAILURE);
}

/* HUBD related deinitialization */
static int
hwahc_hub_detach(hwahc_state_t *hwahcp)
{
	hubd_t		*hubd = hwahcp->hwahc_hubd;
	dev_info_t	*dip = hwahcp->hwahc_dip;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
	    "hwahc_hub_detach:");

	if ((hubd->h_init_state & HUBD_LOCKS_DONE) == 0) {
		goto done;
	}

	if (hubd->h_init_state & HUBD_MINOR_NODE_CREATED) {
		/* remove minor nodes */
		ddi_remove_minor_node(dip, NULL);
	}

	if (hubd->h_init_state & HUBD_HUBDI_REGISTERED) {
		/* unregister with usba HUBDI */
		(void) usba_hubdi_unregister(dip);
	}

	if (hubd->h_init_state & HUBD_LOCKS_DONE) {
		mutex_destroy(HUBD_MUTEX(hubd));
	}

	if (hubd->h_ancestry_str) {
		kmem_free(hubd->h_ancestry_str, HUBD_APID_NAMELEN);
	}

done:
	if (hubd->h_dev_data) {
		/* unregister client from usba */
		usb_client_detach(dip, hubd->h_dev_data);
	}

	usb_free_log_hdl(hubd->h_log_handle);
	kmem_free(hubd, sizeof (hubd_t));
	ddi_prop_remove_all(dip);

	return (USB_SUCCESS);
}

/* print security descrs */
static void
hwahc_print_secrt_data(hwahc_state_t *hwahcp)
{
	int			i;
	wusb_secrt_data_t	*secrt_data = &hwahcp->hwahc_secrt_data;

	USB_DPRINTF_L3(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
	    "The Host Wire Adapter security descriptor:");
	USB_DPRINTF_L3(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
	    "bLength = 0x%x\t\t bDescriptorType = 0x%x",
	    secrt_data->secrt_descr.bLength,
	    secrt_data->secrt_descr.bDescriptorType);
	USB_DPRINTF_L3(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
	    "wTotalLength = 0x%x\t bNumEncryptionTypes = 0x%x",
	    secrt_data->secrt_descr.wTotalLength,
	    secrt_data->secrt_descr.bNumEncryptionTypes);

	for (i = 0; i < secrt_data->secrt_n_encry; i++) {
		USB_DPRINTF_L3(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "The Host Wire Adapter encryption descriptor %d:", i + 1);
		USB_DPRINTF_L3(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "bLength = 0x%x\t\t bDescriptorType = 0x%x",
		    secrt_data->secrt_encry_descr[i].bLength,
		    secrt_data->secrt_encry_descr[i].bDescriptorType);
		USB_DPRINTF_L3(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "bEncryptionType = 0x%x\t bEncryptionValue = 0x%x",
		    secrt_data->secrt_encry_descr[i].bEncryptionType,
		    secrt_data->secrt_encry_descr[i].bEncryptionValue);
		USB_DPRINTF_L3(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "bAuthKeyIndex = 0x%x",
		    secrt_data->secrt_encry_descr[i].bAuthKeyIndex);
	}
}

/* drain device notifications */
static void
hwahc_drain_notif_queue(hwahc_state_t *hwahcp)
{
	int	i;

	ASSERT(mutex_owned(&hwahcp->hwahc_mutex));

	USB_DPRINTF_L4(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
	    "hwahc_drain_notif_queue: started");

	if ((hwahcp->hwahc_notif_thread_id == NULL) &&
	    (usba_list_entry_count(&hwahcp->hwahc_dn_notif_queue) != 0)) {
		/* kick off a notif thread to drain the queue */
		if (usb_async_req(hwahcp->hwahc_dip, hwahc_notif_thread,
		    (void *)hwahcp, 0) != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "hwahc_drain_notif_queue: no notif thread started");
		} else {
			hwahcp->hwahc_notif_thread_id = (kthread_t *)1;
		}
	}

	for (i = 0; i < HWAHC_NOTIF_DRAIN_TIMEOUT; i++) {
		/* loop until the queue is completed or it timeouts */
		if ((hwahcp->hwahc_notif_thread_id == NULL) &&
		    (usba_list_entry_count(&hwahcp->hwahc_dn_notif_queue) ==
		    0)) {

			break;
		}
		mutex_exit(&hwahcp->hwahc_mutex);
		delay(drv_usectohz(1000000));
		mutex_enter(&hwahcp->hwahc_mutex);
	}

	/* cleanup the queue if not completed */
	while (usba_list_entry_count(&hwahcp->hwahc_dn_notif_queue) != 0) {
		hwahc_dn_notif_list_t	*nlist;

		nlist = (hwahc_dn_notif_list_t *)usba_rm_first_pvt_from_list(
		    &hwahcp->hwahc_dn_notif_queue);
		ASSERT(nlist != NULL);
		ASSERT(nlist->dn_notif != NULL);
		usba_destroy_list(&nlist->notif_list);
		kmem_free(nlist->dn_notif, nlist->dn_notif->bLength);
		kmem_free(nlist, sizeof (hwahc_dn_notif_list_t));
	}

	USB_DPRINTF_L4(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
	    "hwahc_drain_notif_queue: ended");
}


/* normal callback for notification ept */
static void
hwahc_intr_cb(usb_pipe_handle_t ph, struct usb_intr_req *reqp)
{
	dev_info_t		*dip = (USBA_REQ2WRP(reqp))->wr_dip;
	hwahc_state_t		*hwahcp;
	mblk_t			*data = reqp->intr_data;

	ASSERT(dip != NULL);
	hwahcp = ddi_get_soft_state(hwahc_statep, ddi_get_instance(dip));
	ASSERT(hwahcp != NULL);

	USB_DPRINTF_L4(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
	    "hwahc_intr_cb: ph = 0x%p reqp = 0x%p", (void *)ph,
	    (void *)reqp);

	ASSERT((reqp->intr_cb_flags & USB_CB_INTR_CONTEXT) == 0);

	if (data == NULL) {
		usb_free_intr_req(reqp);

		return;
	}

	/* handle the notification */
	hwahc_handle_notif(hwahcp, data);

	usb_free_intr_req(reqp);
}

/*
 * See Section 8.3.3.3 for Transfer Notification format and
 * Section 8.5.4 for HWA specific notifications.
 *	Three kinds of Notifications:
 *		- Transfer Completion
 *		- DN Received
 *		- BPST ADJ
 */
/* handle the notification according to notification type */
static void
hwahc_handle_notif(hwahc_state_t *hwahcp, mblk_t *data)
{
	int			len;
	uint8_t			*p;
	wa_notif_header_t	*hdr;

	if (data == NULL) {

		return;
	}

	len = MBLKL(data);
	p = data->b_rptr;
	USB_DPRINTF_L3(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
	    "hwahc_handle_notif: data len = %d", len);

	/*
	 * according to WUSB 1.0/8.1.2, multiple notifications might be sent
	 * at a time, need to parse one by one
	 */
	while (len > 0) {
		if (len < 2) {
			USB_DPRINTF_L2(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "hwahc_handle_notif: short packet len = %d",
			    len);

			break;
		}

		hdr = (wa_notif_header_t *)p;
		if (len < hdr->bLength) {
			USB_DPRINTF_L2(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "hwahc_handle_notif: length not match, "
			    "hdr length = %d, actual length = %d",
			    hdr->bLength, len);

			break;
		}

		switch (hdr->bNotifyType) {
		case WA_NOTIF_TYPE_TRANSFER:
		{
			uint8_t		ept = p[2];

			/* deal with transfer completion notification */
			hwahc_handle_xfer_result(hwahcp, ept);

			break;
		}
		case HWA_NOTIF_TYPE_DN_RECEIVED:
		{
			hwa_notif_dn_recvd_t	*dn_notif;

			dn_notif = kmem_alloc(hdr->bLength, KM_NOSLEEP);
			(void) memcpy(dn_notif, p, hdr->bLength);

			/* deal with device notification */
			hwahc_handle_dn_notif(hwahcp, dn_notif);

			break;
		}
		case HWA_NOTIF_TYPE_BPST_ADJ:
			USB_DPRINTF_L3(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "hwahc_handle_notif: received BPST adjust "
			    "notification, bAdjustment = %d", p[2]);

			break;
		default:
			USB_DPRINTF_L2(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "hwahc_handle_notif: unknown notification 0x%x",
			    hdr->bNotifyType);

			break;
		}
		p += hdr->bLength;
		len -= hdr->bLength;
	}
}

/*
 * start listening on bulk-in ept for transfer result
 *
 * Dispatches a task to read the BULK IN endpoint to get the result of
 * last request. usb_async_req() will have system_taskq to process the tasks.
 */
int
hwahc_start_result_thread(hwahc_state_t *hwahcp)
{
	wusb_wa_data_t *wa_data;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
	    "hwahc_start_result_thread:");

	ASSERT(mutex_owned(&hwahcp->hwahc_mutex));

	if (hwahcp->hwahc_result_thread_id != 0) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_start_result_thread: already started");

		return (USB_SUCCESS);
	}

	wa_data = &hwahcp->hwahc_wa_data;

	mutex_enter(&wa_data->wa_mutex);
	if ((wa_data->wa_bulkin_ph != NULL) &&
	    (wa_data->wa_bulkin_pipe_state != WA_PIPE_STOPPED)) {
		mutex_exit(&wa_data->wa_mutex);

		return (USB_INVALID_PIPE);
	}
	mutex_exit(&wa_data->wa_mutex);

	if (wa_data->wa_bulkin_ph == NULL) {
		mutex_exit(&hwahcp->hwahc_mutex);
		if (usb_pipe_open(wa_data->wa_dip, &wa_data->wa_bulkin_ept,
		    &wa_data->wa_pipe_policy, USB_FLAGS_SLEEP,
		    &wa_data->wa_bulkin_ph) != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA,
			    hwahcp->hwahc_log_handle,
			    "hwahc_start_result_thread: open pipe failed");


			mutex_enter(&hwahcp->hwahc_mutex);
			return (USB_FAILURE);
		}
		mutex_enter(&hwahcp->hwahc_mutex);

		mutex_enter(&wa_data->wa_mutex);
		wa_data->wa_bulkin_pipe_state = WA_PIPE_STOPPED;
		mutex_exit(&wa_data->wa_mutex);
	}

	/* kick off an asynchronous thread to handle transfer result */
	if (usb_async_req(hwahcp->hwahc_dip, hwahc_result_thread,
	    (void *)hwahcp, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_start_result_thread: failed to start result thread");

		return (USB_FAILURE);
	}
	hwahcp->hwahc_result_thread_id = (kthread_t *)1;

	/* pipe state is active while the result thread is on */
	mutex_enter(&wa_data->wa_mutex);
	wa_data->wa_bulkin_pipe_state = WA_PIPE_ACTIVE;
	mutex_exit(&wa_data->wa_mutex);

	return (USB_SUCCESS);
}

/* stop the bulk-in ept from listening */
static void
hwahc_stop_result_thread(hwahc_state_t *hwahcp)
{
	wusb_wa_data_t *wa_data;

	ASSERT(mutex_owned(&hwahcp->hwahc_mutex));

	USB_DPRINTF_L4(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
	    "hwahc_stop_result_thread:");

	if (hwahcp->hwahc_result_thread_id == 0) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_stop_result_thread: already stopped");

		return;
	}

	wa_data = &hwahcp->hwahc_wa_data;
	mutex_enter(&wa_data->wa_mutex);
	if ((wa_data->wa_bulkin_ph == NULL) ||
	    (wa_data->wa_bulkin_pipe_state != WA_PIPE_ACTIVE)) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
		    "hwahc_stop_result_thread: invalid pipe state");

		mutex_exit(&wa_data->wa_mutex);

		return;
	}
	mutex_exit(&wa_data->wa_mutex);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
	    "hwahc_stop_result_thread: reset hwa bulk-in pipe");
	mutex_exit(&hwahcp->hwahc_mutex);
	usb_pipe_reset(wa_data->wa_dip, wa_data->wa_bulkin_ph,
	    USB_FLAGS_SLEEP, NULL, NULL);

	/*
	 * have to close pipe here to fail the bulk-in transfer
	 * that never timeouts
	 */
	USB_DPRINTF_L4(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
	    "hwahc_stop_result_thread: close hwa bulk-in pipe");
	usb_pipe_close(wa_data->wa_dip, wa_data->wa_bulkin_ph,
	    USB_FLAGS_SLEEP, NULL, NULL);
	mutex_enter(&hwahcp->hwahc_mutex);

	mutex_enter(&wa_data->wa_mutex);
	wa_data->wa_bulkin_ph = NULL;
	wa_data->wa_bulkin_pipe_state = WA_PIPE_STOPPED;
	mutex_exit(&wa_data->wa_mutex);

	while (hwahcp->hwahc_result_thread_id != 0) {
		/* wait the result thread to exit */
		cv_wait(&hwahcp->hwahc_result_thread_cv, &hwahcp->hwahc_mutex);
	}
}

/*
 * keep listening for transfer result by setting timeout to 0 while the
 * bulk-in pipe is active
 * the thread would be stopped by closing bulk-in pipe or encountering
 * transaction error, eg, hot-removal of hwa device
 */
static void
hwahc_result_thread(void *arg)
{
	hwahc_state_t	*hwahcp = (hwahc_state_t *)arg;
	wusb_wa_data_t	*wa_data = &hwahcp->hwahc_wa_data;
	int		rval;
	uint8_t		retry = 0;

	mutex_enter(&hwahcp->hwahc_mutex);
	ASSERT(hwahcp->hwahc_result_thread_id == (kthread_t *)1);
	hwahcp->hwahc_result_thread_id = curthread;
	USB_DPRINTF_L4(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
	    "hwahc_result_thread: started, thread_id=0x%p",
	    (void *)hwahcp->hwahc_result_thread_id);

	/* keep polling the bulk IN endpoint to get the result */
	mutex_enter(&wa_data->wa_mutex);
	while (wa_data->wa_bulkin_pipe_state == WA_PIPE_ACTIVE) {
		mutex_exit(&wa_data->wa_mutex);
		mutex_exit(&hwahcp->hwahc_mutex);

		if ((rval = wusb_wa_get_xfer_result(wa_data)) != USB_SUCCESS) {
			retry++;
			USB_DPRINTF_L2(PRINT_MASK_ATTA,
			    hwahcp->hwahc_log_handle,
			    "hwahc_result_thread: get xfer result failed, "
			    "rval = %d, retry = %d", rval, retry);

			/* retry 3 times upon failure */
			if (retry >= 3) {
				mutex_enter(&hwahcp->hwahc_mutex);
				mutex_enter(&wa_data->wa_mutex);

				break;
			}
		}

		mutex_enter(&hwahcp->hwahc_mutex);
		mutex_enter(&wa_data->wa_mutex);
	}

	hwahcp->hwahc_result_thread_id = 0;
	wa_data->wa_bulkin_pipe_state = WA_PIPE_STOPPED;
	mutex_exit(&wa_data->wa_mutex);

	/* signal to the thread requesting stopping if any */
	cv_signal(&hwahcp->hwahc_result_thread_cv);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
	    "hwahc_result_thread: ended");

	mutex_exit(&hwahcp->hwahc_mutex);
}

/*
 * nothing to do here, just check if the ept number in the transfer
 * completion notification is valid
 * the actual handling of transfer result is performed by the result thread
 */
static void
hwahc_handle_xfer_result(hwahc_state_t *hwahcp, uint8_t ept)
{
	usb_ep_descr_t	*epdt;

	USB_DPRINTF_L4(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
	    "hwahc_handle_xfer_result: result on ept %d", ept);

	epdt = &hwahcp->hwahc_wa_data.wa_bulkin_ept;

	/* the result should be on the bulk-in ept */
	if ((epdt->bEndpointAddress & USB_EP_NUM_MASK) != ept) {
		USB_DPRINTF_L2(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
		    "hwahc_handle_xfer_result: ept number not match");

		return;
	}
}


/*
 * Section 8.5.4.2.
 *	Copy the DN Notification and add it to the instance's global
 *	nofication list. If the worker thread is not started yet, start
 *	it.
 */
static void
hwahc_handle_dn_notif(hwahc_state_t *hwahcp, hwa_notif_dn_recvd_t *dn_notif)
{
	hwahc_dn_notif_list_t	*nlist;

	USB_DPRINTF_L4(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
	    "hwahc_handle_dn_notif: notif = 0x%p", (void *)dn_notif);

	nlist = kmem_zalloc(sizeof (hwahc_dn_notif_list_t), KM_NOSLEEP);

	mutex_enter(&hwahcp->hwahc_mutex);
	nlist->dn_notif = dn_notif;

	usba_init_list(&nlist->notif_list, (usb_opaque_t)nlist,
	    hwahcp->hwahc_dev_data->dev_iblock_cookie);

	/* queue the new notification to the list */
	usba_add_to_list(&hwahcp->hwahc_dn_notif_queue, &nlist->notif_list);

	/* handle the notification queue with an asynchronous thread */
	if (hwahcp->hwahc_notif_thread_id == 0) {
		if (usb_async_req(hwahcp->hwahc_dip, hwahc_notif_thread,
		    (void *)hwahcp, 0) != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "hwahc_handle_dn_notif: no notif thread started");
			mutex_exit(&hwahcp->hwahc_mutex);

			return;
		}
		hwahcp->hwahc_notif_thread_id = (kthread_t *)1;
	}

	mutex_exit(&hwahcp->hwahc_mutex);
}

/* handle the notifications in the notification queue in sequence */
static void
hwahc_notif_thread(void *arg)
{
	hwahc_state_t		*hwahcp = (hwahc_state_t *)arg;
	hwahc_dn_notif_list_t	*nlist;
	hwa_notif_dn_recvd_t	*dn_notif;

	mutex_enter(&hwahcp->hwahc_mutex);
	ASSERT(hwahcp->hwahc_notif_thread_id == (kthread_t *)1);
	hwahcp->hwahc_notif_thread_id = curthread;

	USB_DPRINTF_L4(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
	    "hwahc_notif_thread: started, thread_id=0x%p",
	    (void *)hwahcp->hwahc_notif_thread_id);

	while (usba_list_entry_count(&hwahcp->hwahc_dn_notif_queue) != 0) {
		/*
		 * first in first out, only one notification will be handled
		 * at a time, so it assures no racing in attach or detach
		 */
		if ((nlist =
		    (hwahc_dn_notif_list_t *)usba_rm_first_pvt_from_list(
		    &hwahcp->hwahc_dn_notif_queue)) == NULL) {

			continue;
		}
		dn_notif = nlist->dn_notif;
		mutex_exit(&hwahcp->hwahc_mutex);
		hwahc_handle_dn(hwahcp, dn_notif);
		usba_destroy_list(&nlist->notif_list);
		kmem_free(nlist, sizeof (hwahc_dn_notif_list_t));
		mutex_enter(&hwahcp->hwahc_mutex);
	}

	hwahcp->hwahc_notif_thread_id = 0;

	USB_DPRINTF_L4(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
	    "hwahc_notif_thread: ended");

	mutex_exit(&hwahcp->hwahc_mutex);
}

/* Set the child device's active bit to 1 */
static void
hwahc_set_device_active(hwahc_state_t *hwahcp, uint8_t devaddr)
{
	wusb_dev_info_t *dev_info;
	wusb_hc_data_t *hc_data = &hwahcp->hwahc_hc_data;
	int i;

	mutex_enter(&hc_data->hc_mutex);
	for (i = 1; i <= hc_data->hc_num_ports; i++) {
		dev_info = hc_data->hc_dev_infos[i];
		if ((dev_info != NULL) && (dev_info->wdev_addr == devaddr)) {
			dev_info->wdev_active = 1;
			USB_DPRINTF_L3(DPRINT_MASK_EVENTS,
			    hwahcp->hwahc_log_handle,
			    "hwahc_set_device_active:device(%p) updated ",
			    (void *)dev_info);

			break;
		}
	}
	mutex_exit(&hc_data->hc_mutex);
}

/*
 * handle a specific device notification
 * assuming the raw data in HWA DN_RECEIVED notification pkt includes
 * no more than one dn pkt
 */
static void
hwahc_handle_dn(hwahc_state_t *hwahcp, hwa_notif_dn_recvd_t *dn_notif)
{
	uint8_t			*p;
	size_t			len;
	uint8_t			dntype;
	int circ;
	wusb_hc_data_t		*hc_data = &hwahcp->hwahc_hc_data;

	if (dn_notif->bLength < 4) {
		USB_DPRINTF_L2(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
		    "hwahc_handle_dn: bLength too short %d", dn_notif->bLength);
		kmem_free(dn_notif, dn_notif->bLength);

		return;
	}

	p = dn_notif->notifdata;
	len = dn_notif->bLength - 4;

	/*
	 * WUSB Errata 06.12 specifies that the raw data in the DN_RECEIVED
	 * notification must not include the WUSB header, but only the bType
	 * and Notification specific data
	 */
	if (len == 0) {
		USB_DPRINTF_L2(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
		    "hwahc_handle_dn: no raw data");
		kmem_free(dn_notif, dn_notif->bLength);

		return;
	}
	dntype = *p;

	/* update the device's status bit, no matter what the DN is */
	hwahc_set_device_active(hwahcp, dn_notif->bSourceDeviceAddr);

	ndi_devi_enter(hwahcp->hwahc_dip, &circ);
	switch (dntype) {
	case WUSB_DN_CONNECT:
		/* DN_Connect */
		wusb_hc_handle_dn_connect(
		    hc_data, hwahcp->hwahc_default_pipe,
		    hwahcp->hwahc_wa_data.wa_ifno, p, len,
		    &hwahcp->hwahc_secrt_data);

		break;
	case WUSB_DN_DISCONNECT:
		/* DN_Disconnect */
		wusb_hc_handle_dn_disconnect(
		    hc_data, dn_notif->bSourceDeviceAddr,
		    p, len);

		break;
	case WUSB_DN_ALIVE:
		/* We only send KeepAlive IE to one device at a comment */
		mutex_enter(&hc_data->hc_mutex);
		if (dn_notif->bSourceDeviceAddr ==
		    hc_data->hc_alive_ie.bDeviceAddress[0]) {
			mutex_exit(&hc_data->hc_mutex);
			wusb_hc_rem_ie(hc_data,
			    (wusb_ie_header_t *)&hc_data->hc_alive_ie);
			mutex_enter(&hc_data->hc_mutex);
		}
		mutex_exit(&hc_data->hc_mutex);

		break;
	case WUSB_DN_EPRDY:
	case WUSB_DN_MASAVAILCHANGED:
	case WUSB_DN_REMOTEWAKEUP:
	case WUSB_DN_SLEEP:
	default:
		USB_DPRINTF_L4(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
		    "hwahc_handle_dn: dn type 0x%x not supported yet",
		    dntype);

		break;
	}

	kmem_free(dn_notif, dn_notif->bLength);
	ndi_devi_exit(hwahcp->hwahc_dip, circ);
}

/* exceptional callback for notification ept */
/* ARGSUSED */
static void
hwahc_intr_exc_cb(usb_pipe_handle_t ph, struct usb_intr_req *reqp)
{
	dev_info_t	*dip = (USBA_REQ2WRP(reqp))->wr_dip;
	hwahc_state_t	*hwahcp;

	ASSERT(dip != NULL);
	hwahcp = ddi_get_soft_state(hwahc_statep, ddi_get_instance(dip));
	ASSERT(hwahcp != NULL);

	USB_DPRINTF_L2(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
	    "hwahc_intr_exc_cb: receive intr exception cb, cr=%d",
	    reqp->intr_completion_reason);

	ASSERT((reqp->intr_cb_flags & USB_CB_INTR_CONTEXT) == 0);

	mutex_enter(&hwahcp->hwahc_mutex);

	switch (reqp->intr_completion_reason) {
	case USB_CR_PIPE_RESET:
		/* only restart nep after autoclearing */
		if (hwahcp->hwahc_dev_state == USB_DEV_ONLINE) {
			hwahcp->hwahc_wa_data.wa_intr_pipe_state =
			    WA_PIPE_STOPPED;
			mutex_exit(&hwahcp->hwahc_mutex);
			(void) wusb_wa_start_nep(&hwahcp->hwahc_wa_data,
			    USB_FLAGS_NOSLEEP);
			mutex_enter(&hwahcp->hwahc_mutex);
		}

		break;
	case USB_CR_DEV_NOT_RESP:
	case USB_CR_STOPPED_POLLING:
	case USB_CR_PIPE_CLOSING:
	case USB_CR_UNSPECIFIED_ERR:
		/* never restart nep on these conditions */
	default:
		/* for all others, wait for the autoclearing PIPE_RESET cb */

		break;
	}

	usb_free_intr_req(reqp);
	mutex_exit(&hwahcp->hwahc_mutex);
}

/*
 * callback function called by WA to resubmit a periodic request for
 * interrupt polling or isochronous transfer.
 */
static int
hwahc_pipe_submit_periodic_req(wusb_wa_data_t *wa_data,
	usba_pipe_handle_data_t *ph)
{
	hwahc_state_t *hwahcp = wa_data->wa_private_data;
	hwahc_pipe_private_t *pp = (hwahc_pipe_private_t *)ph->p_hcd_private;
	int rval;

	mutex_enter(&hwahcp->hwahc_mutex);

	USB_DPRINTF_L4(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
	    "hwahc_pipe_submit_periodic_req: hwahcp=0x%p, pp=0x%p,"
	    " pipe state = %d", (void *)hwahcp, (void *)pp, pp->pp_state);

	if (pp->pp_state != HWAHC_PIPE_STATE_ACTIVE) {
		/* pipe error or pipe closing, don't resubmit any more */
		USB_DPRINTF_L4(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
		    "hwahc_pipe_submit_periodic_req: pipe not active = %d",
		    pp->pp_state);

		mutex_exit(&hwahcp->hwahc_mutex);

		return (USB_PIPE_ERROR);
	}

	mutex_exit(&hwahcp->hwahc_mutex);

	/* re-submit the original request */
	rval = wusb_wa_intr_xfer(wa_data, pp->pp_rp, ph,
	    (usb_intr_req_t *)pp->pp_client_periodic_in_reqp, 0);

	return (rval);
}

/* call HCD callback for completion handling */
static void
hwahc_rpipe_xfer_cb(dev_info_t *dip, usba_pipe_handle_data_t *ph,
	wusb_wa_trans_wrapper_t *wr, usb_cr_t cr)
{
	hwahc_state_t		*hwahcp;
	hwahc_pipe_private_t	*pp;
	usb_opaque_t		req;
	wusb_hc_data_t		*hc_data;

	hwahcp = ddi_get_soft_state(hwahc_statep, ddi_get_instance(dip));
	if (hwahcp == NULL) {

		return;
	}

	hc_data = &hwahcp->hwahc_hc_data;

	mutex_enter(&hwahcp->hwahc_mutex);
	USB_DPRINTF_L3(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
	    "hwahc_rpipe_xfer_cb: ph = 0x%p, wr = 0x%p cr = 0x%x",
	    (void *)ph, (void *)wr, cr);

	pp = (hwahc_pipe_private_t *)ph->p_hcd_private;

	mutex_enter(&hc_data->hc_mutex);
	pp->pp_wdev->wdev_active = 1; /* this device is active on xfer */
	mutex_exit(&hc_data->hc_mutex);

	switch (cr) {
	case USB_CR_OK:
		break;
	case USB_CR_NOT_SUPPORTED:
	case USB_CR_NO_RESOURCES:
	case USB_CR_PIPE_RESET:
	case USB_CR_STOPPED_POLLING:
		pp->pp_state = HWAHC_PIPE_STATE_IDLE;
		break;
	case USB_CR_PIPE_CLOSING:
		break;
	default:
		pp->pp_state = HWAHC_PIPE_STATE_ERROR;

		break;
	}

	if (wr && wr->wr_reqp) {
		req = wr->wr_reqp;

		mutex_enter(&wr->wr_rp->rp_mutex);
		wr->wr_reqp = NULL;
		mutex_exit(&wr->wr_rp->rp_mutex);

	} else { /* periodic pipe cleanup */

		/* the original request is cleared and returned to client */
		req = pp->pp_client_periodic_in_reqp;
		pp->pp_client_periodic_in_reqp = NULL;
	}

	mutex_exit(&hwahcp->hwahc_mutex);

	USB_DPRINTF_L3(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
	    "hwahc_rpipe_xfer_cb: call usba_hcdi_cb for req= 0x%p",
	    (void *)req);

	usba_hcdi_cb(ph, req, cr);
}

/* post disconnect event to child on a certain port */
static void
hwahc_disconnect_dev(dev_info_t *dip, usb_port_t port)
{
	hwahc_state_t	*hwahcp;
	int		circ;
	dev_info_t	*child_dip;

	if ((hwahcp = ddi_get_soft_state(hwahc_statep,
	    ddi_get_instance(dip))) == NULL) {

		return;
	}

	ndi_devi_enter(dip, &circ);
	mutex_enter(&hwahcp->hwahc_mutex);

	child_dip = hwahcp->hwahc_hc_data.hc_children_dips[port];
	if ((hwahcp->hwahc_dev_state == USB_DEV_ONLINE) && child_dip) {
		mutex_exit(&hwahcp->hwahc_mutex);

		/* if the child driver remains attached */
		if (i_ddi_devi_attached(child_dip)) {
			hwahc_post_event(hwahcp, port,
			    USBA_EVENT_TAG_HOT_REMOVAL);
		}
		mutex_enter(&hwahcp->hwahc_mutex);
	}

	mutex_exit(&hwahcp->hwahc_mutex);
	ndi_devi_exit(dip, circ);
}

/* post reconect event to child on a certain port */
static void
hwahc_reconnect_dev(dev_info_t *dip, usb_port_t port)
{
	hwahc_state_t	*hwahcp;
	int		circ;

	if ((hwahcp = ddi_get_soft_state(hwahc_statep,
	    ddi_get_instance(dip))) == NULL) {

		return;
	}
	ndi_devi_enter(dip, &circ);
	mutex_enter(&hwahcp->hwahc_mutex);

	if ((hwahcp->hwahc_dev_state == USB_DEV_ONLINE) &&
	    (hwahcp->hwahc_hc_data.hc_children_dips[port])) {
		mutex_exit(&hwahcp->hwahc_mutex);
		hwahc_post_event(hwahcp, port, USBA_EVENT_TAG_HOT_INSERTION);
		mutex_enter(&hwahcp->hwahc_mutex);
	}

	mutex_exit(&hwahcp->hwahc_mutex);
	ndi_devi_exit(dip, circ);
}


/*
 * Device TrustTimeout timer operations:
 * hwahc_start_trust_timer: start the trust timer for a newly connected device
 * hwahc_trust_timeout_handler: timer handler
 * hwahc_stop_trust_timer: stop a device's trust timer
 */
static void
hwahc_start_trust_timer(wusb_dev_info_t *dev)
{
	if (hwahc_enable_trust_timeout == 0) {

		return;
	}

	if (dev->wdev_trust_timer == NULL) {
		dev->wdev_trust_timer = timeout(hwahc_trust_timeout_handler,
		    (void *)dev, drv_usectohz(WUSB_TRUST_TIMEOUT_US));
	}
}

/* timeout handler for device TrustTimeout. See section 4.14 */
static void
hwahc_trust_timeout_handler(void *arg)
{
	wusb_dev_info_t *dev = (wusb_dev_info_t *)arg;
	usb_port_t port;
	uint16_t   dev_addr;
	wusb_hc_data_t *hc_data = dev->wdev_hc;
	uint8_t	retry = 3;
	int rval;

	mutex_enter(&hc_data->hc_mutex);

	dev->wdev_trust_timer = 0;
	dev_addr = dev->wdev_addr;

	if (dev->wdev_active == 1) {
	/* device is active during the past period. Restart the timer */
		dev->wdev_active = 0; /* expect device DN set it to 1 */
	} else {
		/* send a KeepAlive IE to query the device */
		for (retry = 0; retry < 3; retry++) {
			mutex_exit(&hc_data->hc_mutex);
			rval = wusb_hc_send_keepalive_ie(hc_data,
			    dev_addr);
			mutex_enter(&hc_data->hc_mutex);

			if (rval == USB_SUCCESS) {
				break;
			}
			/* retry 3 times if fail to send KeepAlive IE */
		}

		if (dev->wdev_active == 0) {
			/* still no activity! Delete this device */
			if (wusb_hc_is_dev_connected(hc_data, dev->wdev_cdid,
			    &port)) {
				mutex_exit(&hc_data->hc_mutex);
				(void) hwahc_destroy_child(hc_data->hc_dip,
				    port);

				/* the device comes to the end of its life */
				return;
			}
		}
	}

	/* active or we received DN during query */
	hwahc_start_trust_timer(dev);

	mutex_exit(&hc_data->hc_mutex);
}

/* stop a child device's trust timeout handler */
void
hwahc_stop_trust_timer(wusb_dev_info_t *dev)
{
	timeout_id_t tid;
	wusb_hc_data_t *hc_data = dev->wdev_hc;

	ASSERT(mutex_owned(&hc_data->hc_mutex));

	if (hwahc_enable_trust_timeout == 0) {
		return;
	}

	tid = dev->wdev_trust_timer;

	dev->wdev_trust_timer = NULL;
	mutex_exit(&hc_data->hc_mutex);

	if (tid != NULL) {
		(void) untimeout(tid);
	}

	mutex_enter(&hc_data->hc_mutex);
}

/* configure child device and attach child on a certain port */
static int
hwahc_create_child(dev_info_t *dip, usb_port_t port)
{
	hwahc_state_t		*hwahcp;
	wusb_hc_data_t		*hc_data;
	wusb_dev_info_t		*dev_info;
	usb_pipe_handle_t	ph;
	int			rval;
	dev_info_t		*child_dip;
	usba_device_t		*child_ud = NULL;
	mblk_t			*pdata = NULL;
	usb_cr_t		completion_reason;
	usb_cb_flags_t		cb_flags;
	size_t			size;
	uint8_t			address;
	int			user_conf_index;
	uint_t			config_index;
	int			prh_circ, rh_circ, circ;
	dev_info_t		*rh_dip;
	usb_dev_descr_t		usb_dev_descr;

	if ((hwahcp = ddi_get_soft_state(hwahc_statep,
	    ddi_get_instance(dip))) == NULL) {

		return (USB_INVALID_ARGS);
	}

	rh_dip = hwahcp->hwahc_hubd->h_usba_device->usb_root_hub_dip;
	ndi_hold_devi(dip);	/* avoid racing with dev detach */
	/* exclude other threads */
	ndi_devi_enter(ddi_get_parent(rh_dip), &prh_circ);
	ndi_devi_enter(rh_dip, &rh_circ);
	ndi_devi_enter(dip, &circ);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*dev_info));

	hc_data = &hwahcp->hwahc_hc_data;
	mutex_enter(&hc_data->hc_mutex);
	dev_info = hc_data->hc_dev_infos[port];

	/* Created in whcdi.c before authed */
	child_dip = hc_data->hc_children_dips[port];

	child_ud = usba_get_usba_device(child_dip);
	ph = dev_info->wdev_ph;

	mutex_exit(&hc_data->hc_mutex);
	/*
	 * HWA maintains the address space as a separate bus and
	 * will not occupy parent's address space
	 */
	address = child_ud->usb_addr;
	if (address < 0x80) {
		USB_DPRINTF_L3(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
		    "hwahc_create_child: reconnecting, address = %d",
		    address);

	} else {
		/* SetAddress(0) */
		if ((rval = usb_pipe_sync_ctrl_xfer(child_dip, ph,
		    USB_DEV_REQ_HOST_TO_DEV,
		    USB_REQ_SET_ADDRESS,	/* bRequest */
		    0,				/* wValue */
		    0,				/* wIndex */
		    0,				/* wLength */
		    NULL, 0,
		    &completion_reason, &cb_flags, 0)) != USB_SUCCESS) {
			char buffer[64];
			USB_DPRINTF_L2(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "setting address failed (cr=%s cb_flags=%s "
			    "rval=%d)", usb_str_cr(completion_reason),
			    usb_str_cb_flags(cb_flags, buffer, sizeof (buffer)),
			    rval);

			goto done;
		}

		USB_DPRINTF_L3(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
		    "set address 0 done");

		usb_pipe_close(child_dip, ph,
		    USB_FLAGS_SLEEP | USBA_FLAGS_PRIVILEGED, NULL, NULL);

		child_ud->usb_addr = 0;
		dev_info->wdev_addr = 0;
		dev_info->wdev_ph = NULL;

		/* need to be called each time dev addr is changed */
		if ((rval = wusb_hc_set_device_info(&hwahcp->hwahc_hc_data,
		    port)) != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "update device info failed, rval = %d", rval);

			goto done;
		}

		/* new ph is stored in usba_device */
		if ((rval = usb_pipe_open(child_dip, NULL, NULL,
		    USB_FLAGS_SLEEP | USBA_FLAGS_PRIVILEGED, &ph)) !=
		    USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "usb_pipe_open failed (%d)", rval);

			goto done;
		}

		/* provide at least 2ms time for address change, 7.3.1.3 */
		delay(drv_usectohz(2000));

		/* start normal enumeration process */
		/*
		 * wusb bus address has 1:1 relationship with port number
		 * and wusb bus address starts from 2, so as to follow
		 * the convention that USB bus address 1 is reserved for
		 * host controller device. As such, only 126 WUSB devices
		 * are supported on a WUSB host
		 */
		address = port + 1;
		if (address >= 0x80) {
			USB_DPRINTF_L3(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "hwahc_create_child: address for port %d exceeds "
			    "0x80", port);
			rval = USB_FAILURE;

			goto done;
		}
		/* Set the address of the device */
		if ((rval = usb_pipe_sync_ctrl_xfer(child_dip, ph,
		    USB_DEV_REQ_HOST_TO_DEV,
		    USB_REQ_SET_ADDRESS,	/* bRequest */
		    address,			/* wValue */
		    0,				/* wIndex */
		    0,				/* wLength */
		    NULL, 0,
		    &completion_reason, &cb_flags, 0)) != USB_SUCCESS) {
			char buffer[64];
			USB_DPRINTF_L2(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "setting address failed (cr=%s cb_flags=%s "
			    "rval=%d)", usb_str_cr(completion_reason),
			    usb_str_cb_flags(cb_flags, buffer, sizeof (buffer)),
			    rval);

			goto done;
		}

		USB_DPRINTF_L3(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
		    "set address 0x%x done", address);

		usb_pipe_close(child_dip, ph,
		    USB_FLAGS_SLEEP | USBA_FLAGS_PRIVILEGED, NULL, NULL);

		child_ud->usb_addr = address;
		dev_info->wdev_addr = address;
		dev_info->wdev_ph = NULL;

		if ((rval = wusb_hc_set_device_info(&hwahcp->hwahc_hc_data,
		    port)) != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "update device info failed, rval = %d", rval);

			goto done;
		}

		/* new ph is stored in usba_device */
		if ((rval = usb_pipe_open(child_dip, NULL, NULL,
		    USB_FLAGS_SLEEP | USBA_FLAGS_PRIVILEGED, &ph)) !=
		    USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_CBOPS,
			    hwahcp->hwahc_log_handle,
			    "usb_pipe_open failed (%d)", rval);

			goto done;
		}

		/* provide at least 2ms time for address change, 7.3.1.3 */
		delay(drv_usectohz(2000));
	}

	/* get device descriptor ignoring device reconnection */
	rval = usb_pipe_sync_ctrl_xfer(child_dip, ph,
	    USB_DEV_REQ_DEV_TO_HOST | USB_DEV_REQ_TYPE_STANDARD,
	    USB_REQ_GET_DESCR,			/* bRequest */
	    USB_DESCR_TYPE_SETUP_DEV,		/* wValue */
	    0,					/* wIndex */
	    512,				/* wLength */
	    &pdata, USB_ATTRS_SHORT_XFER_OK,
	    &completion_reason, &cb_flags, 0);

	if (rval != USB_SUCCESS) {
		if (pdata) {
			freemsg(pdata);
			pdata = NULL;
		}

		USB_DPRINTF_L2(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
		    "hwahc_create_child: get device descriptor failed "
		    "(%s 0x%x %d)", usb_str_cr(completion_reason),
		    cb_flags, rval);

		goto done;
	}

	ASSERT(pdata != NULL);
	size = usb_parse_dev_descr(
	    pdata->b_rptr,
	    MBLKL(pdata),
	    &usb_dev_descr,
	    sizeof (usb_dev_descr_t));
	freemsg(pdata);

	if (size < USB_DEV_DESCR_SIZE) {
		USB_DPRINTF_L2(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
		    "hwahc_create_child: get device descriptor size = %lu "
		    "expected size = %u", size, USB_DEV_DESCR_SIZE);
		rval = USB_FAILURE;

		goto done;
	}

	bcopy(&usb_dev_descr, child_ud->usb_dev_descr,
	    sizeof (usb_dev_descr_t));
	child_ud->usb_n_cfgs = usb_dev_descr.bNumConfigurations;

	if (usb_dev_descr.bNumConfigurations == 0) {
		USB_DPRINTF_L2(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
		    "device descriptor:\n\t"
		    "l=0x%x type=0x%x USB=0x%x class=0x%x subclass=0x%x\n\t"
		    "protocol=0x%x maxpktsize=0x%x "
		    "Vid=0x%x Pid=0x%x rel=0x%x\n\t"
		    "Mfg=0x%x P=0x%x sn=0x%x #config=0x%x",
		    usb_dev_descr.bLength, usb_dev_descr.bDescriptorType,
		    usb_dev_descr.bcdUSB, usb_dev_descr.bDeviceClass,
		    usb_dev_descr.bDeviceSubClass,
		    usb_dev_descr.bDeviceProtocol,
		    usb_dev_descr.bMaxPacketSize0,
		    usb_dev_descr.idVendor,
		    usb_dev_descr.idProduct, usb_dev_descr.bcdDevice,
		    usb_dev_descr.iManufacturer, usb_dev_descr.iProduct,
		    usb_dev_descr.iSerialNumber,
		    usb_dev_descr.bNumConfigurations);

		rval = USB_FAILURE;

		goto done;
	}

	/* get the device string descriptor(s) */
	usba_get_dev_string_descrs(child_dip, child_ud);

	/* retrieve config cloud for all configurations */
	rval = hubd_get_all_device_config_cloud(hwahcp->hwahc_hubd,
	    child_dip, child_ud);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
		    "failed to get configuration descriptor(s)");

		goto done;
	}

	/* get the preferred configuration for this device */
	user_conf_index = hubd_select_device_configuration(hwahcp->hwahc_hubd,
	    port, child_dip, child_ud);

	/* Check if the user selected configuration index is in range */
	if ((user_conf_index >= usb_dev_descr.bNumConfigurations) ||
	    (user_conf_index < 0)) {
		USB_DPRINTF_L2(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
		    "Configuration index for device idVendor=%d "
		    "idProduct=%d is=%d, and is out of range[0..%d]",
		    usb_dev_descr.idVendor, usb_dev_descr.idProduct,
		    user_conf_index, usb_dev_descr.bNumConfigurations - 1);

		/* treat this as user didn't specify configuration */
		user_conf_index = USBA_DEV_CONFIG_INDEX_UNDEFINED;
	}

	if (user_conf_index == USBA_DEV_CONFIG_INDEX_UNDEFINED) {
		if (child_ud->usb_preferred_driver) {
			/*
			 * It is the job of the "preferred driver" to put the
			 * device in the desired configuration. Till then
			 * put the device in config index 0.
			 */
			/* h_ignore_pwr_budget = TRUE, not care the power */
			if ((rval = usba_hubdi_check_power_budget(dip, child_ud,
			    USB_DEV_DEFAULT_CONFIG_INDEX)) != USB_SUCCESS) {

				goto done;
			}

			child_dip = hubd_ready_device(hwahcp->hwahc_hubd,
			    child_dip, child_ud, USB_DEV_DEFAULT_CONFIG_INDEX);

			/*
			 * Assign the dip before onlining to avoid race
			 * with busctl
			 */
			mutex_enter(&hc_data->hc_mutex);
			hc_data->hc_children_dips[port] = child_dip;
			mutex_exit(&hc_data->hc_mutex);

			(void) usba_bind_driver(child_dip);
		} else {
			/*
			 * loop through all the configurations to see if we
			 * can find a driver for any one config. If not, set
			 * the device in config_index 0
			 */
			rval = USB_FAILURE;
			for (config_index = 0;
			    (config_index < usb_dev_descr.bNumConfigurations) &&
			    (rval != USB_SUCCESS); config_index++) {

				child_dip = hubd_ready_device(
				    hwahcp->hwahc_hubd,
				    child_dip, child_ud, config_index);

				/*
				 * Assign the dip before onlining to avoid race
				 * with busctl
				 */
				mutex_enter(&hc_data->hc_mutex);
				hc_data->hc_children_dips[port] = child_dip;
				mutex_exit(&hc_data->hc_mutex);

				rval = usba_bind_driver(child_dip);

				if (rval == USB_SUCCESS) {
					/* always succeed for WUSB device */
					if ((usba_hubdi_check_power_budget(dip,
					    child_ud, config_index)) !=
					    USB_SUCCESS) {
						rval = USB_FAILURE;

						goto done;
					}
				}
			}

			if (rval != USB_SUCCESS) {
				if ((usba_hubdi_check_power_budget(dip,
				    child_ud, 0)) != USB_SUCCESS) {

					goto done;
				}

				child_dip = hubd_ready_device(
				    hwahcp->hwahc_hubd,
				    child_dip, child_ud, 0);
				mutex_enter(&hc_data->hc_mutex);
				hc_data->hc_children_dips[port] = child_dip;
				mutex_exit(&hc_data->hc_mutex);
			}
		} /* end else loop all configs */
	} else {
		if ((usba_hubdi_check_power_budget(dip, child_ud,
		    (uint_t)user_conf_index)) != USB_SUCCESS) {
			rval = USB_FAILURE;

			goto done;
		}

		child_dip = hubd_ready_device(hwahcp->hwahc_hubd, child_dip,
		    child_ud, (uint_t)user_conf_index);

		/*
		 * Assign the dip before onlining to avoid race
		 * with busctl
		 */
		mutex_enter(&hc_data->hc_mutex);
		hc_data->hc_children_dips[port] = child_dip;
		mutex_exit(&hc_data->hc_mutex);

		(void) usba_bind_driver(child_dip);

		rval = USB_SUCCESS;
	}

	/* workaround for non response after ctrl write */
	usb_pipe_close(child_dip, ph,
	    USB_FLAGS_SLEEP | USBA_FLAGS_PRIVILEGED, NULL, NULL);

	if ((rval = usb_pipe_open(child_dip, NULL, NULL,
	    USB_FLAGS_SLEEP | USBA_FLAGS_PRIVILEGED, &ph)) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_CBOPS,
		    hwahcp->hwahc_log_handle,
		    "usb_pipe_open failed (%d)", rval);

		goto done;
	}

done:
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*dev_info));

	ndi_devi_exit(dip, circ);
	ndi_devi_exit(rh_dip, rh_circ);
	ndi_devi_exit(ddi_get_parent(rh_dip), prh_circ);

	(void) devfs_clean(rh_dip, NULL, 0);

	if (rval == USB_SUCCESS) {
		(void) ndi_devi_online(child_dip, 0);

		USB_DPRINTF_L2(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
		    "hwahc_create_child: create timer for child %p",
		    (void *)dev_info);

		mutex_enter(&hc_data->hc_mutex);
		hwahc_start_trust_timer(dev_info);
		mutex_exit(&hc_data->hc_mutex);
	}

	ndi_rele_devi(dip);

	return (rval);
}

/* offline child on a certain port */
static int
hwahc_destroy_child(dev_info_t *dip, usb_port_t port)
{
	hwahc_state_t	*hwahcp;

	if ((hwahcp = ddi_get_soft_state(hwahc_statep,
	    ddi_get_instance(dip))) == NULL) {

		return (USB_INVALID_ARGS);
	}

	hwahc_post_event(hwahcp, port, USBA_EVENT_TAG_HOT_REMOVAL);

	USB_DPRINTF_L3(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
	    "hwahc_destroy_child: scheduling cleanup");

	/* schedule cleanup thread */
	hubd_schedule_cleanup(hwahcp->hwahc_hubd->h_usba_device->
	    usb_root_hub_dip);

	return (USB_SUCCESS);
}

/*
 * called by cleanup thread to offline child and cleanup child resources
 * Child's callback functions have been called before calling this routine.
 *	dip - hwahc's dip
 */
static int
hwahc_cleanup_child(dev_info_t *dip)
{
	hwahc_state_t	*hwahcp;
	wusb_hc_data_t	*hc_data;
	usb_port_t	port;

	if ((hwahcp = ddi_get_soft_state(hwahc_statep,
	    ddi_get_instance(dip))) == NULL) {

		return (USB_INVALID_ARGS);
	}

	hc_data = &hwahcp->hwahc_hc_data;
	mutex_enter(&hc_data->hc_mutex);
	for (port = 1; port <= hc_data->hc_num_ports; port++) {
		dev_info_t *cdip = hc_data->hc_children_dips[port];

		if (cdip == NULL || DEVI_IS_DEVICE_REMOVED(cdip) == 0) {

			continue;
		}

		/*
		 * child's callback has been called and its dip has been
		 * marked REMOVED. Do further cleanup in hwa driver for
		 * this child.
		 */
		mutex_exit(&hc_data->hc_mutex);
		(void) hwahc_delete_child(dip, port, NDI_DEVI_REMOVE, B_TRUE);
		mutex_enter(&hc_data->hc_mutex);
	}
	mutex_exit(&hc_data->hc_mutex);

	return (USB_SUCCESS);
}

/* offline child and cleanup child resources */
static int
hwahc_delete_child(dev_info_t *dip, usb_port_t port, uint_t flag,
	boolean_t retry)
{
	hwahc_state_t	*hwahcp;
	dev_info_t	*child_dip;
	usba_device_t	*usba_device;
	wusb_hc_data_t	*hc_data;
	int		rval;

	if ((hwahcp = ddi_get_soft_state(hwahc_statep,
	    ddi_get_instance(dip))) == NULL) {

		return (USB_INVALID_ARGS);
	}

	child_dip = hwahc_get_child_dip(hwahcp, port);
	if (child_dip == NULL) {

		return (USB_SUCCESS);
	}

	usba_device = usba_get_usba_device(child_dip);
	hc_data = &hwahcp->hwahc_hc_data;

	USB_DPRINTF_L4(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
	    "hwahc_delete_child: port=%d, dip=0x%p usba_device=0x%p",
	    port, (void *)child_dip, (void *)usba_device);

	if (usba_device) {
		usba_hubdi_incr_power_budget(dip, usba_device);
	}

	/* remove this child's dip. If it's <DS_INITIALIZED, free it */
	rval = usba_destroy_child_devi(child_dip, flag);

	if ((rval == USB_SUCCESS) && (flag & NDI_DEVI_REMOVE)) {
		/*
		 * if the child was still < DS_INITIALIZED
		 * then our bus_unconfig was not called and
		 * we have to zap the child here
		 */
		mutex_enter(&hc_data->hc_mutex);
		if (hc_data->hc_children_dips[port] == child_dip) {
			usba_device_t *ud = hc_data->hc_usba_devices[port];
			wusb_dev_info_t *dev_info = hc_data->hc_dev_infos[port];

			hc_data->hc_children_dips[port] = NULL;
			if (ud) {
				mutex_exit(&hc_data->hc_mutex);

				mutex_enter(&ud->usb_mutex);
				ud->usb_ref_count = 0;
				mutex_exit(&ud->usb_mutex);

				usba_free_usba_device(ud);
				mutex_enter(&hc_data->hc_mutex);
				hc_data->hc_usba_devices[port] = NULL;
			}

			/* free the child's wusb_dev_info data */
			if (dev_info) {
				wusb_secrt_data_t *secrt_data;

				if (dev_info->
				    wdev_secrt_data.secrt_encry_descr) {
					secrt_data = &dev_info->wdev_secrt_data;
					kmem_free(secrt_data->secrt_encry_descr,
					    sizeof (usb_encryption_descr_t) *
					    secrt_data->secrt_n_encry);
				}
				if (dev_info->wdev_uwb_descr) {
					kmem_free(dev_info->wdev_uwb_descr,
					    sizeof (usb_uwb_cap_descr_t));
				}
				kmem_free(dev_info, sizeof (wusb_dev_info_t));
				hc_data->hc_dev_infos[port] = NULL;
			}
		}
		mutex_exit(&hc_data->hc_mutex);
	}

	if ((rval != USB_SUCCESS) && retry) {

		hubd_schedule_cleanup(usba_device->usb_root_hub_dip);
	}

	return (rval);
}

/*
 * Set encryption type for WUSB host, refer to WUSB 1.0/8.5.3.6
 * index = port number - 1
 */
int
hwahc_set_dev_encrypt(usb_pipe_handle_t ph, uint8_t ifc,
	usb_port_t index, wusb_secrt_data_t *secrt_data, uint8_t type)
{
	int16_t			value;
	usb_ctrl_setup_t	setup;
	usb_cr_t		cr;
	usb_cb_flags_t		cb_flags;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "hwahc_set_dev_encrypt: device index = %d", index);

	if (type == USB_ENC_TYPE_UNSECURE) {
		value = 0;
	} else if (type == USB_ENC_TYPE_CCM_1) {
		if (secrt_data == NULL) {

			return (USB_INVALID_ARGS);
		}

		value = wusb_get_ccm_encryption_value(secrt_data);
		if (value == -1) {
			USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "hwahc_set_dev_encrypt: cannot find ccm "
			    "encryption type");

			return (USB_FAILURE);
		}
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "hwahc_set_dev_encrypt: ccm encryption value is %d",
		    value);
	} else {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "hwahc_set_dev_encrypt: unsupported encryption type %d",
		    type);

		return (USB_INVALID_ARGS);
	}

	setup.bmRequestType = USB_DEV_REQ_HOST_TO_DEV |
	    USB_DEV_REQ_TYPE_CLASS | USB_DEV_REQ_RCPT_IF;
	setup.bRequest = USB_REQ_SET_ENCRYPTION;
	setup.wValue = (uint16_t)value;
	setup.wIndex = (index << 8) | ifc;
	setup.wLength = 0;
	setup.attrs = USB_ATTRS_NONE;

	USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "bmRequestType=0x%x, bRequest=0x%x, wValue=0x%x, wIndex=0x%x",
	    setup.bmRequestType, setup.bRequest, setup.wValue, setup.wIndex);

	return (usb_pipe_ctrl_xfer_wait(ph, &setup, NULL,
	    &cr, &cb_flags, USB_FLAGS_SLEEP));
}

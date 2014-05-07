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
 * Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * USBA: Solaris USB Architecture support for the hub
 * including root hub
 * Most of the code for hubd resides in this file and
 * is shared between the HCD root hub support and hubd
 */
#define	USBA_FRAMEWORK
#include <sys/usb/usba.h>
#include <sys/usb/usba/usba_devdb.h>
#include <sys/sunndi.h>
#include <sys/usb/usba/usba_impl.h>
#include <sys/usb/usba/usba_types.h>
#include <sys/usb/usba/hubdi.h>
#include <sys/usb/usba/hcdi_impl.h>
#include <sys/usb/hubd/hub.h>
#include <sys/usb/hubd/hubdvar.h>
#include <sys/usb/hubd/hubd_impl.h>
#include <sys/kobj.h>
#include <sys/kobj_lex.h>
#include <sys/fs/dv_node.h>
#include <sys/strsun.h>

/*
 * External functions
 */
extern boolean_t consconfig_console_is_ready(void);

/*
 * Prototypes for static functions
 */
static	int	usba_hubdi_bus_ctl(
			dev_info_t		*dip,
			dev_info_t		*rdip,
			ddi_ctl_enum_t		op,
			void			*arg,
			void			*result);

static int	usba_hubdi_map_fault(
			dev_info_t		*dip,
			dev_info_t		*rdip,
			struct hat		*hat,
			struct seg		*seg,
			caddr_t 		addr,
			struct devpage		*dp,
			pfn_t			pfn,
			uint_t			prot,
			uint_t			lock);

static int hubd_busop_get_eventcookie(dev_info_t *dip,
			dev_info_t *rdip,
			char *eventname,
			ddi_eventcookie_t *cookie);
static int hubd_busop_add_eventcall(dev_info_t *dip,
			dev_info_t *rdip,
			ddi_eventcookie_t cookie,
			void (*callback)(dev_info_t *dip,
				ddi_eventcookie_t cookie, void *arg,
				void *bus_impldata),
			void *arg, ddi_callback_id_t *cb_id);
static int hubd_busop_remove_eventcall(dev_info_t *dip,
			ddi_callback_id_t cb_id);
static int hubd_bus_config(dev_info_t *dip,
			uint_t flag,
			ddi_bus_config_op_t op,
			void *arg,
			dev_info_t **child);
static int hubd_bus_unconfig(dev_info_t *dip,
			uint_t flag,
			ddi_bus_config_op_t op,
			void *arg);
static int hubd_bus_power(dev_info_t *dip, void *impl_arg,
			pm_bus_power_op_t op, void *arg, void *result);

static usb_port_t  hubd_get_port_num(hubd_t *, struct devctl_iocdata *);
static dev_info_t *hubd_get_child_dip(hubd_t *, usb_port_t);
static uint_t hubd_cfgadm_state(hubd_t *, usb_port_t);
static int hubd_toggle_port(hubd_t *, usb_port_t);
static void hubd_register_cpr_callback(hubd_t *);
static void hubd_unregister_cpr_callback(hubd_t *);

/*
 * Busops vector for USB HUB's
 */
struct bus_ops usba_hubdi_busops =	{
	BUSO_REV,
	nullbusmap,			/* bus_map */
	NULL,				/* bus_get_intrspec */
	NULL,				/* bus_add_intrspec */
	NULL,				/* bus_remove_intrspec */
	usba_hubdi_map_fault,		/* bus_map_fault */
	NULL,				/* bus_dma_map */
	ddi_dma_allochdl,
	ddi_dma_freehdl,
	ddi_dma_bindhdl,
	ddi_dma_unbindhdl,
	ddi_dma_flush,
	ddi_dma_win,
	ddi_dma_mctl,			/* bus_dma_ctl */
	usba_hubdi_bus_ctl,		/* bus_ctl */
	ddi_bus_prop_op,		/* bus_prop_op */
	hubd_busop_get_eventcookie,
	hubd_busop_add_eventcall,
	hubd_busop_remove_eventcall,
	NULL,				/* bus_post_event */
	NULL,				/* bus_intr_ctl */
	hubd_bus_config,		/* bus_config */
	hubd_bus_unconfig,		/* bus_unconfig */
	NULL,				/* bus_fm_init */
	NULL,				/* bus_fm_fini */
	NULL,				/* bus_fm_access_enter */
	NULL,				/* bus_fm_access_exit */
	hubd_bus_power			/* bus_power */
};

#define	USB_HUB_INTEL_VID	0x8087
#define	USB_HUB_INTEL_PID	0x0020

/*
 * local variables
 */
static kmutex_t	usba_hubdi_mutex;	/* protects USBA HUB data structures */

static usba_list_entry_t	usba_hubdi_list;

usb_log_handle_t	hubdi_log_handle;
uint_t			hubdi_errlevel = USB_LOG_L4;
uint_t			hubdi_errmask = (uint_t)-1;
uint8_t			hubdi_min_pm_threshold = 5; /* seconds */
uint8_t			hubdi_reset_delay = 20; /* seconds */
extern int modrootloaded;

/*
 * initialize private data
 */
void
usba_hubdi_initialization()
{
	hubdi_log_handle = usb_alloc_log_hdl(NULL, "hubdi", &hubdi_errlevel,
	    &hubdi_errmask, NULL, 0);

	USB_DPRINTF_L4(DPRINT_MASK_HUBDI, hubdi_log_handle,
	    "usba_hubdi_initialization");

	mutex_init(&usba_hubdi_mutex, NULL, MUTEX_DRIVER, NULL);

	usba_init_list(&usba_hubdi_list, NULL, NULL);
}


void
usba_hubdi_destroy()
{
	USB_DPRINTF_L4(DPRINT_MASK_HUBDI, hubdi_log_handle,
	    "usba_hubdi_destroy");

	mutex_destroy(&usba_hubdi_mutex);
	usba_destroy_list(&usba_hubdi_list);

	usb_free_log_hdl(hubdi_log_handle);
}


/*
 * Called by an	HUB to attach an instance of the driver
 *	make this instance known to USBA
 *	the HUB	should initialize usba_hubdi structure prior
 *	to calling this	interface
 */
int
usba_hubdi_register(dev_info_t	*dip,
		uint_t		flags)
{
	usba_hubdi_t *hubdi = kmem_zalloc(sizeof (usba_hubdi_t), KM_SLEEP);
	usba_device_t *usba_device = usba_get_usba_device(dip);

	USB_DPRINTF_L4(DPRINT_MASK_HUBDI, hubdi_log_handle,
	    "usba_hubdi_register: %s", ddi_node_name(dip));

	hubdi->hubdi_dip = dip;
	hubdi->hubdi_flags = flags;

	usba_device->usb_hubdi = hubdi;

	/*
	 * add this hubdi instance to the list of known hubdi's
	 */
	usba_init_list(&hubdi->hubdi_list, (usb_opaque_t)hubdi,
	    usba_hcdi_get_hcdi(usba_device->usb_root_hub_dip)->
	    hcdi_iblock_cookie);
	mutex_enter(&usba_hubdi_mutex);
	usba_add_to_list(&usba_hubdi_list, &hubdi->hubdi_list);
	mutex_exit(&usba_hubdi_mutex);

	return (DDI_SUCCESS);
}


/*
 * Called by an	HUB to detach an instance of the driver
 */
int
usba_hubdi_unregister(dev_info_t *dip)
{
	usba_device_t *usba_device = usba_get_usba_device(dip);
	usba_hubdi_t *hubdi = usba_device->usb_hubdi;

	USB_DPRINTF_L4(DPRINT_MASK_HUBDI, hubdi_log_handle,
	    "usba_hubdi_unregister: %s", ddi_node_name(dip));

	mutex_enter(&usba_hubdi_mutex);
	(void) usba_rm_from_list(&usba_hubdi_list, &hubdi->hubdi_list);
	mutex_exit(&usba_hubdi_mutex);

	usba_destroy_list(&hubdi->hubdi_list);

	kmem_free(hubdi, sizeof (usba_hubdi_t));

	return (DDI_SUCCESS);
}


/*
 * misc bus routines currently not used
 */
/*ARGSUSED*/
static int
usba_hubdi_map_fault(dev_info_t *dip,
	dev_info_t	*rdip,
	struct hat	*hat,
	struct seg	*seg,
	caddr_t 	addr,
	struct devpage	*dp,
	pfn_t		pfn,
	uint_t		prot,
	uint_t		lock)
{
	return (DDI_FAILURE);
}


/*
 * root hub support. the root hub uses the same devi as the HCD
 */
int
usba_hubdi_bind_root_hub(dev_info_t *dip,
	uchar_t	*root_hub_config_descriptor,
	size_t config_length,
	usb_dev_descr_t *root_hub_device_descriptor)
{
	usba_device_t *usba_device;
	usba_hcdi_t *hcdi = usba_hcdi_get_hcdi(dip);
	hubd_t	*root_hubd;
	usb_pipe_handle_t ph = NULL;
	dev_info_t *child = ddi_get_child(dip);

	if (ndi_prop_create_boolean(DDI_DEV_T_NONE, dip,
	    "root-hub") != NDI_SUCCESS) {

		return (USB_FAILURE);
	}

	usba_add_root_hub(dip);

	root_hubd = kmem_zalloc(sizeof (hubd_t), KM_SLEEP);

	/*
	 * create and initialize a usba_device structure
	 */
	usba_device = usba_alloc_usba_device(dip);

	mutex_enter(&usba_device->usb_mutex);
	usba_device->usb_hcdi_ops = hcdi->hcdi_ops;
	usba_device->usb_cfg = root_hub_config_descriptor;
	usba_device->usb_cfg_length = config_length;
	usba_device->usb_dev_descr = root_hub_device_descriptor;
	usba_device->usb_port = 1;
	usba_device->usb_addr = ROOT_HUB_ADDR;
	usba_device->usb_root_hubd = root_hubd;
	usba_device->usb_cfg_array = kmem_zalloc(sizeof (uchar_t *),
	    KM_SLEEP);
	usba_device->usb_cfg_array_length = sizeof (uchar_t *);

	usba_device->usb_cfg_array_len = kmem_zalloc(sizeof (uint16_t),
	    KM_SLEEP);
	usba_device->usb_cfg_array_len_length = sizeof (uint16_t);

	usba_device->usb_cfg_array[0] = root_hub_config_descriptor;
	usba_device->usb_cfg_array_len[0] =
	    sizeof (root_hub_config_descriptor);

	usba_device->usb_cfg_str_descr = kmem_zalloc(sizeof (uchar_t *),
	    KM_SLEEP);
	usba_device->usb_n_cfgs = 1;
	usba_device->usb_n_ifs = 1;
	usba_device->usb_dip = dip;

	usba_device->usb_client_flags = kmem_zalloc(
	    usba_device->usb_n_ifs * USBA_CLIENT_FLAG_SIZE, KM_SLEEP);

	usba_device->usb_client_attach_list = kmem_zalloc(
	    usba_device->usb_n_ifs *
	    sizeof (*usba_device->usb_client_attach_list), KM_SLEEP);

	usba_device->usb_client_ev_cb_list = kmem_zalloc(
	    usba_device->usb_n_ifs *
	    sizeof (*usba_device->usb_client_ev_cb_list), KM_SLEEP);

	/*
	 * The bDeviceProtocol field of root hub device specifies,
	 * whether root hub is a High or Full speed usb device.
	 */
	if (root_hub_device_descriptor->bDeviceProtocol) {
		usba_device->usb_port_status = USBA_HIGH_SPEED_DEV;
	} else {
		usba_device->usb_port_status = USBA_FULL_SPEED_DEV;
	}

	mutex_exit(&usba_device->usb_mutex);

	usba_set_usba_device(dip, usba_device);

	/*
	 * For the root hub the default pipe is not yet open
	 */
	if (usb_pipe_open(dip, NULL, NULL,
	    USB_FLAGS_SLEEP | USBA_FLAGS_PRIVILEGED, &ph) != USB_SUCCESS) {
		goto fail;
	}

	/*
	 * kill off all OBP children, they may not be fully
	 * enumerated
	 */
	while (child) {
		dev_info_t *next = ddi_get_next_sibling(child);
		(void) ddi_remove_child(child, 0);
		child = next;
	}

	/*
	 * "attach" the root hub driver
	 */
	if (usba_hubdi_attach(dip, DDI_ATTACH) != DDI_SUCCESS) {
		goto fail;
	}

	return (USB_SUCCESS);

fail:
	(void) ndi_prop_remove(DDI_DEV_T_NONE, dip, "root-hub");

	usba_rem_root_hub(dip);

	if (ph) {
		usb_pipe_close(dip, ph,
		    USB_FLAGS_SLEEP | USBA_FLAGS_PRIVILEGED, NULL, NULL);
	}

	kmem_free(usba_device->usb_cfg_array,
	    usba_device->usb_cfg_array_length);
	kmem_free(usba_device->usb_cfg_array_len,
	    usba_device->usb_cfg_array_len_length);

	kmem_free(usba_device->usb_cfg_str_descr, sizeof (uchar_t *));

	usba_free_usba_device(usba_device);

	usba_set_usba_device(dip, NULL);
	if (root_hubd) {
		kmem_free(root_hubd, sizeof (hubd_t));
	}

	return (USB_FAILURE);
}


int
usba_hubdi_unbind_root_hub(dev_info_t *dip)
{
	usba_device_t *usba_device;

	/* was root hub attached? */
	if (!(usba_is_root_hub(dip))) {

		/* return success anyway */
		return (USB_SUCCESS);
	}

	/*
	 * usba_hubdi_detach also closes the default pipe
	 * and removes properties so there is no need to
	 * do it here
	 */
	if (usba_hubdi_detach(dip, DDI_DETACH) != DDI_SUCCESS) {

		if (DEVI_IS_ATTACHING(dip)) {
			USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubdi_log_handle,
			    "failure to unbind root hub after attach failure");
		}

		return (USB_FAILURE);
	}

	usba_device = usba_get_usba_device(dip);

	kmem_free(usba_device->usb_root_hubd, sizeof (hubd_t));

	kmem_free(usba_device->usb_cfg_array,
	    usba_device->usb_cfg_array_length);
	kmem_free(usba_device->usb_cfg_array_len,
	    usba_device->usb_cfg_array_len_length);

	kmem_free(usba_device->usb_cfg_str_descr, sizeof (uchar_t *));

	usba_free_usba_device(usba_device);

	usba_rem_root_hub(dip);

	(void) ndi_prop_remove(DDI_DEV_T_NONE, dip, "root-hub");

	return (USB_SUCCESS);
}


/*
 * Actual Hub Driver support code:
 *	shared by root hub and non-root hubs
 */
#include <sys/usb/usba/usbai_version.h>

/* Debugging support */
uint_t hubd_errlevel	= USB_LOG_L4;
uint_t hubd_errmask	= (uint_t)DPRINT_MASK_ALL;
uint_t hubd_instance_debug = (uint_t)-1;
static uint_t hubdi_bus_config_debug = 0;

_NOTE(DATA_READABLE_WITHOUT_LOCK(hubd_errlevel))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hubd_errmask))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hubd_instance_debug))

_NOTE(SCHEME_PROTECTS_DATA("unique", msgb))
_NOTE(SCHEME_PROTECTS_DATA("unique", dev_info))


/*
 * local variables:
 *
 * Amount of time to wait between resetting the port and accessing
 * the device.	The value is in microseconds.
 */
static uint_t hubd_device_delay = 1000000;

/*
 * enumeration retry
 */
#define	HUBD_PORT_RETRY 5
static uint_t hubd_retry_enumerate = HUBD_PORT_RETRY;

/*
 * Stale hotremoved device cleanup delay
 */
#define	HUBD_STALE_DIP_CLEANUP_DELAY	5000000
static uint_t hubd_dip_cleanup_delay = HUBD_STALE_DIP_CLEANUP_DELAY;

/*
 * retries for USB suspend and resume
 */
#define	HUBD_SUS_RES_RETRY	2

void	*hubd_statep;

/*
 * prototypes
 */
static int hubd_cleanup(dev_info_t *dip, hubd_t  *hubd);
static int hubd_check_ports(hubd_t  *hubd);

static int  hubd_open_intr_pipe(hubd_t *hubd);
static void hubd_start_polling(hubd_t *hubd, int always);
static void hubd_stop_polling(hubd_t *hubd);
static void hubd_close_intr_pipe(hubd_t *hubd);

static void hubd_read_cb(usb_pipe_handle_t pipe, usb_intr_req_t *req);
static void hubd_exception_cb(usb_pipe_handle_t pipe,
						usb_intr_req_t *req);
static void hubd_hotplug_thread(void *arg);
static void hubd_reset_thread(void *arg);
static int hubd_create_child(dev_info_t *dip,
		hubd_t		*hubd,
		usba_device_t	*usba_device,
		usb_port_status_t port_status,
		usb_port_t	port,
		int		iteration);

static int hubd_delete_child(hubd_t *hubd, usb_port_t port, uint_t flag,
	boolean_t retry);

static int hubd_get_hub_descriptor(hubd_t *hubd);

static int hubd_get_hub_status_words(hubd_t *hubd, uint16_t *status);

static int hubd_reset_port(hubd_t *hubd, usb_port_t port);

static int hubd_get_hub_status(hubd_t *hubd);

static int hubd_handle_port_connect(hubd_t *hubd, usb_port_t port);

static int hubd_disable_port(hubd_t *hubd, usb_port_t port);

static int hubd_enable_port(hubd_t *hubd, usb_port_t port);
static int hubd_recover_disabled_port(hubd_t *hubd, usb_port_t port);

static int hubd_determine_port_status(hubd_t *hubd, usb_port_t port,
	uint16_t *status, uint16_t *change, uint_t ack_flag);

static int hubd_enable_all_port_power(hubd_t *hubd);
static int hubd_disable_all_port_power(hubd_t *hubd);
static int hubd_disable_port_power(hubd_t *hubd, usb_port_t port);
static int hubd_enable_port_power(hubd_t *hubd, usb_port_t port);

static void hubd_free_usba_device(hubd_t *hubd, usba_device_t *usba_device);

static int hubd_can_suspend(hubd_t *hubd);
static void hubd_restore_device_state(dev_info_t *dip, hubd_t *hubd);
static int hubd_setdevaddr(hubd_t *hubd, usb_port_t port);
static void hubd_setdevconfig(hubd_t *hubd, usb_port_t port);

static int hubd_register_events(hubd_t *hubd);
static void hubd_do_callback(hubd_t *hubd, dev_info_t *dip,
	ddi_eventcookie_t cookie);
static void hubd_run_callbacks(hubd_t *hubd, usba_event_t type);
static void hubd_post_event(hubd_t *hubd, usb_port_t port, usba_event_t type);
static void hubd_create_pm_components(dev_info_t *dip, hubd_t *hubd);

static int hubd_disconnect_event_cb(dev_info_t *dip);
static int hubd_reconnect_event_cb(dev_info_t *dip);
static int hubd_pre_suspend_event_cb(dev_info_t *dip);
static int hubd_post_resume_event_cb(dev_info_t *dip);
static int hubd_cpr_suspend(hubd_t *hubd);
static void hubd_cpr_resume(dev_info_t *dip);
static int hubd_restore_state_cb(dev_info_t *dip);
static int hubd_check_same_device(hubd_t *hubd, usb_port_t port);

static int hubd_init_power_budget(hubd_t *hubd);

static ndi_event_definition_t hubd_ndi_event_defs[] = {
	{USBA_EVENT_TAG_HOT_REMOVAL, DDI_DEVI_REMOVE_EVENT, EPL_KERNEL,
						NDI_EVENT_POST_TO_ALL},
	{USBA_EVENT_TAG_HOT_INSERTION, DDI_DEVI_INSERT_EVENT, EPL_KERNEL,
						NDI_EVENT_POST_TO_ALL},
	{USBA_EVENT_TAG_POST_RESUME, USBA_POST_RESUME_EVENT, EPL_KERNEL,
						NDI_EVENT_POST_TO_ALL},
	{USBA_EVENT_TAG_PRE_SUSPEND, USBA_PRE_SUSPEND_EVENT, EPL_KERNEL,
						NDI_EVENT_POST_TO_ALL}
};

#define	HUBD_N_NDI_EVENTS \
	(sizeof (hubd_ndi_event_defs) / sizeof (ndi_event_definition_t))

static ndi_event_set_t hubd_ndi_events = {
	NDI_EVENTS_REV1, HUBD_N_NDI_EVENTS, hubd_ndi_event_defs};

/* events received from parent */
static usb_event_t hubd_events = {
	hubd_disconnect_event_cb,
	hubd_reconnect_event_cb,
	hubd_pre_suspend_event_cb,
	hubd_post_resume_event_cb
};


/*
 * hubd_get_soft_state() returns the hubd soft state
 *
 * WUSB support extends this function to support wire adapter class
 * devices. The hubd soft state for the wire adapter class device
 * would be stored in usb_root_hubd field of the usba_device structure,
 * just as the USB host controller drivers do.
 */
hubd_t *
hubd_get_soft_state(dev_info_t *dip)
{
	if (dip == NULL) {

		return (NULL);
	}

	if (usba_is_root_hub(dip) || usba_is_wa(dip)) {
		usba_device_t *usba_device = usba_get_usba_device(dip);

		return (usba_device->usb_root_hubd);
	} else {
		int instance = ddi_get_instance(dip);

		return (ddi_get_soft_state(hubd_statep, instance));
	}
}


/*
 * PM support functions:
 */
/*ARGSUSED*/
static void
hubd_pm_busy_component(hubd_t *hubd, dev_info_t *dip, int component)
{
	if (hubd->h_hubpm != NULL) {
		hubd->h_hubpm->hubp_busy_pm++;
		mutex_exit(HUBD_MUTEX(hubd));
		if (pm_busy_component(dip, 0) != DDI_SUCCESS) {
			mutex_enter(HUBD_MUTEX(hubd));
			hubd->h_hubpm->hubp_busy_pm--;
			mutex_exit(HUBD_MUTEX(hubd));
		}
		mutex_enter(HUBD_MUTEX(hubd));
		USB_DPRINTF_L4(DPRINT_MASK_PM, hubd->h_log_handle,
		    "hubd_pm_busy_component: %d", hubd->h_hubpm->hubp_busy_pm);
	}
}


/*ARGSUSED*/
static void
hubd_pm_idle_component(hubd_t *hubd, dev_info_t *dip, int component)
{
	if (hubd->h_hubpm != NULL) {
		mutex_exit(HUBD_MUTEX(hubd));
		if (pm_idle_component(dip, 0) == DDI_SUCCESS) {
			mutex_enter(HUBD_MUTEX(hubd));
			ASSERT(hubd->h_hubpm->hubp_busy_pm > 0);
			hubd->h_hubpm->hubp_busy_pm--;
			mutex_exit(HUBD_MUTEX(hubd));
		}
		mutex_enter(HUBD_MUTEX(hubd));
		USB_DPRINTF_L4(DPRINT_MASK_PM, hubd->h_log_handle,
		    "hubd_pm_idle_component: %d", hubd->h_hubpm->hubp_busy_pm);
	}
}


/*
 * track power level changes for children of this instance
 */
static void
hubd_set_child_pwrlvl(hubd_t *hubd, usb_port_t port, uint8_t power)
{
	int	old_power, new_power, pwr;
	usb_port_t	portno;
	hub_power_t	*hubpm;

	USB_DPRINTF_L4(DPRINT_MASK_PM, hubd->h_log_handle,
	    "hubd_set_child_pwrlvl: port=%d power=%d",
	    port, power);

	mutex_enter(HUBD_MUTEX(hubd));
	hubpm = hubd->h_hubpm;

	old_power = 0;
	for (portno = 1; portno <= hubd->h_hub_descr.bNbrPorts; portno++) {
		old_power += hubpm->hubp_child_pwrstate[portno];
	}

	/* assign the port power */
	pwr = hubd->h_hubpm->hubp_child_pwrstate[port];
	hubd->h_hubpm->hubp_child_pwrstate[port] = power;
	new_power = old_power - pwr + power;

	USB_DPRINTF_L4(DPRINT_MASK_PM, hubd->h_log_handle,
	    "hubd_set_child_pwrlvl: new_power=%d old_power=%d",
	    new_power, old_power);

	if ((new_power > 0) && (old_power == 0)) {
		/* we have the first child coming out of low power */
		(void) hubd_pm_busy_component(hubd, hubd->h_dip, 0);
	} else if ((new_power == 0) && (old_power > 0)) {
		/* we have the last child going to low power */
		(void) hubd_pm_idle_component(hubd, hubd->h_dip, 0);
	}
	mutex_exit(HUBD_MUTEX(hubd));
}


/*
 * given a child dip, locate its port number
 */
static usb_port_t
hubd_child_dip2port(hubd_t *hubd, dev_info_t *dip)
{
	usb_port_t	port;

	mutex_enter(HUBD_MUTEX(hubd));
	for (port = 1; port <= hubd->h_hub_descr.bNbrPorts; port++) {
		if (hubd->h_children_dips[port] == dip) {

			break;
		}
	}
	ASSERT(port <= hubd->h_hub_descr.bNbrPorts);
	mutex_exit(HUBD_MUTEX(hubd));

	return (port);
}


/*
 * if the hub can be put into low power mode, return success
 * NOTE: suspend here means going to lower power, not CPR suspend.
 */
static int
hubd_can_suspend(hubd_t *hubd)
{
	hub_power_t	*hubpm;
	int		total_power = 0;
	usb_port_t	port;

	hubpm = hubd->h_hubpm;

	if (DEVI_IS_DETACHING(hubd->h_dip)) {

		return (USB_SUCCESS);
	}

	/*
	 * Don't go to lower power if haven't been at full power for enough
	 * time to let hotplug thread kickoff.
	 */
	if (gethrtime() < (hubpm->hubp_time_at_full_power +
	    hubpm->hubp_min_pm_threshold)) {

		return (USB_FAILURE);
	}

	for (port = 1; (total_power == 0) &&
	    (port <= hubd->h_hub_descr.bNbrPorts); port++) {
		total_power += hubpm->hubp_child_pwrstate[port];
	}

	USB_DPRINTF_L4(DPRINT_MASK_PM, hubd->h_log_handle,
	    "hubd_can_suspend: %d", total_power);

	return (total_power ? USB_FAILURE : USB_SUCCESS);
}


/*
 * resume port depending on current device state
 */
static int
hubd_resume_port(hubd_t *hubd, usb_port_t port)
{
	int		rval, retry;
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	uint16_t	status;
	uint16_t	change;
	int		retval = USB_FAILURE;

	mutex_enter(HUBD_MUTEX(hubd));

	USB_DPRINTF_L4(DPRINT_MASK_PM, hubd->h_log_handle,
	    "hubd_resume_port: port=%d state=0x%x (%s)", port,
	    hubd->h_dev_state, usb_str_dev_state(hubd->h_dev_state));

	switch (hubd->h_dev_state) {
	case USB_DEV_HUB_CHILD_PWRLVL:
		/*
		 * This could be a bus ctl for a port other than the one
		 * that has a remote wakeup condition. So check.
		 */
		if ((hubd->h_port_state[port] & PORT_STATUS_PSS) == 0) {
			/* the port isn't suspended, so don't resume */
			retval = USB_SUCCESS;

			USB_DPRINTF_L2(DPRINT_MASK_PM, hubd->h_log_handle,
			    "hubd_resume_port: port=%d not suspended", port);

			break;
		}
		/*
		 * Device has initiated a wakeup.
		 * Issue a ClearFeature(PortSuspend)
		 */
		mutex_exit(HUBD_MUTEX(hubd));
		if ((rval = usb_pipe_sync_ctrl_xfer(hubd->h_dip,
		    hubd->h_default_pipe,
		    HUB_HANDLE_PORT_FEATURE_TYPE,
		    USB_REQ_CLEAR_FEATURE,
		    CFS_PORT_SUSPEND,
		    port,
		    0, NULL, 0,
		    &completion_reason, &cb_flags, 0)) != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_PM, hubd->h_log_handle,
			    "ClearFeature(PortSuspend) fails "
			    "rval=%d cr=%d cb=0x%x", rval,
			    completion_reason, cb_flags);
		}
		mutex_enter(HUBD_MUTEX(hubd));

		/* either way ack changes on the port */
		(void) hubd_determine_port_status(hubd, port,
		    &status, &change, PORT_CHANGE_PSSC);
		retval = USB_SUCCESS;

		break;
	case USB_DEV_HUB_STATE_RECOVER:
		/*
		 * When hubd's connect event callback posts a connect
		 * event to its child, it results in this busctl call
		 * which is valid
		 */
		/* FALLTHRU */
	case USB_DEV_ONLINE:
		if (((hubd->h_port_state[port] & PORT_STATUS_CCS) == 0) ||
		    ((hubd->h_port_state[port] & PORT_STATUS_PSS) == 0)) {
			/*
			 * the port isn't suspended, or connected
			 * so don't resume
			 */
			retval = USB_SUCCESS;

			USB_DPRINTF_L2(DPRINT_MASK_PM, hubd->h_log_handle,
			    "hubd_resume_port: port=%d not suspended", port);

			break;
		}
		/*
		 * prevent kicking off the hotplug thread
		 */
		hubd->h_hotplug_thread++;
		hubd_stop_polling(hubd);

		/* Now ClearFeature(PortSuspend) */
		for (retry = 0; retry < HUBD_SUS_RES_RETRY; retry++) {
			mutex_exit(HUBD_MUTEX(hubd));
			rval = usb_pipe_sync_ctrl_xfer(hubd->h_dip,
			    hubd->h_default_pipe,
			    HUB_HANDLE_PORT_FEATURE_TYPE,
			    USB_REQ_CLEAR_FEATURE,
			    CFS_PORT_SUSPEND,
			    port,
			    0, NULL, 0,
			    &completion_reason, &cb_flags, 0);
			mutex_enter(HUBD_MUTEX(hubd));
			if (rval != USB_SUCCESS) {
				USB_DPRINTF_L2(DPRINT_MASK_PM,
				    hubd->h_log_handle,
				    "ClearFeature(PortSuspend) fails"
				    "rval=%d cr=%d cb=0x%x", rval,
				    completion_reason, cb_flags);
			} else {
				/*
				 * As per spec section 11.9 and 7.1.7.7
				 * hub need to provide at least 20ms of
				 * resume signalling, and s/w provide 10ms of
				 * recovery time before accessing the port.
				 */
				mutex_exit(HUBD_MUTEX(hubd));
				delay(drv_usectohz(40000));
				mutex_enter(HUBD_MUTEX(hubd));
				(void) hubd_determine_port_status(hubd, port,
				    &status, &change, PORT_CHANGE_PSSC);

				if ((status & PORT_STATUS_PSS) == 0) {
					/* the port did finally resume */
					retval = USB_SUCCESS;

					break;
				}
			}
		}

		/* allow hotplug thread again */
		hubd->h_hotplug_thread--;
		hubd_start_polling(hubd, 0);

		break;
	case USB_DEV_DISCONNECTED:
		/* Ignore - NO Operation */
		retval = USB_SUCCESS;

		break;
	case USB_DEV_SUSPENDED:
	case USB_DEV_PWRED_DOWN:
	default:
		USB_DPRINTF_L2(DPRINT_MASK_PM, hubd->h_log_handle,
		    "Improper state for port Resume");

		break;
	}
	mutex_exit(HUBD_MUTEX(hubd));

	return (retval);
}


/*
 * suspend port depending on device state
 */
static int
hubd_suspend_port(hubd_t *hubd, usb_port_t port)
{
	int		rval, retry;
	int		retval = USB_FAILURE;
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	uint16_t	status;
	uint16_t	change;

	USB_DPRINTF_L4(DPRINT_MASK_PM, hubd->h_log_handle,
	    "hubd_suspend_port: port=%d", port);

	mutex_enter(HUBD_MUTEX(hubd));

	switch (hubd->h_dev_state) {
	case USB_DEV_HUB_STATE_RECOVER:
		/*
		 * When hubd's connect event callback posts a connect
		 * event to its child, it results in this busctl call
		 * which is valid
		 */
		/* FALLTHRU */
	case USB_DEV_HUB_CHILD_PWRLVL:
		/*
		 * When one child is resuming, the other could timeout
		 * and go to low power mode, which is valid
		 */
		/* FALLTHRU */
	case USB_DEV_ONLINE:
		hubd->h_hotplug_thread++;
		hubd_stop_polling(hubd);

		/*
		 * Some devices start an unprovoked resume.  According to spec,
		 * normal resume time for port is 10ms.  Wait for double that
		 * time, then check to be sure port is really suspended.
		 */
		for (retry = 0; retry < HUBD_SUS_RES_RETRY; retry++) {
			/* Now SetFeature(PortSuspend) */
			mutex_exit(HUBD_MUTEX(hubd));
			if ((rval = usb_pipe_sync_ctrl_xfer(hubd->h_dip,
			    hubd->h_default_pipe,
			    HUB_HANDLE_PORT_FEATURE_TYPE,
			    USB_REQ_SET_FEATURE,
			    CFS_PORT_SUSPEND,
			    port,
			    0, NULL, 0,
			    &completion_reason, &cb_flags, 0)) !=
			    USB_SUCCESS) {
				USB_DPRINTF_L2(DPRINT_MASK_PM,
				    hubd->h_log_handle,
				    "SetFeature(PortSuspend) fails"
				    "rval=%d cr=%d cb=0x%x",
				    rval, completion_reason, cb_flags);
			}

			/*
			 * some devices start an unprovoked resume
			 * wait and check port status after some time
			 */
			delay(drv_usectohz(20000));

			/* either ways ack changes on the port */
			mutex_enter(HUBD_MUTEX(hubd));
			(void) hubd_determine_port_status(hubd, port,
			    &status, &change, PORT_CHANGE_PSSC);
			if (status & PORT_STATUS_PSS) {
				/* the port is indeed suspended */
				retval = USB_SUCCESS;

				break;
			} else {
				USB_DPRINTF_L0(DPRINT_MASK_PM,
				    hubd->h_log_handle,
				    "hubdi: port%d failed to be suspended!",
				    port);
			}
		}

		hubd->h_hotplug_thread--;
		hubd_start_polling(hubd, 0);

		break;

	case USB_DEV_DISCONNECTED:
		/* Ignore - No Operation */
		retval = USB_SUCCESS;

		break;

	case USB_DEV_SUSPENDED:
	case USB_DEV_PWRED_DOWN:
	default:
		USB_DPRINTF_L2(DPRINT_MASK_PM, hubd->h_log_handle,
		    "Improper state for port Suspend");

		break;
	}
	mutex_exit(HUBD_MUTEX(hubd));

	return (retval);
}


/*
 * child post attach/detach notifications
 */
static void
hubd_post_attach(hubd_t *hubd, usb_port_t port, struct attachspec *as)
{
	dev_info_t	*dip;

	USB_DPRINTF_L4(DPRINT_MASK_ATTA, hubd->h_log_handle,
	    "hubd_post_attach: port=%d result=%d",
	    port, as->result);

	if (as->result == DDI_SUCCESS) {
		/*
		 * Check if the child created wants to be power managed.
		 * If yes, the childs power level gets automatically tracked
		 * by DDI_CTLOPS_POWER busctl.
		 * If no, we set power of the new child by default
		 * to USB_DEV_OS_FULL_PWR. Because we should never suspend.
		 */
		mutex_enter(HUBD_MUTEX(hubd));
		dip = hubd->h_children_dips[port];
		mutex_exit(HUBD_MUTEX(hubd));
		if (DEVI(dip)->devi_pm_info == NULL) {
			hubd_set_child_pwrlvl(hubd, port, USB_DEV_OS_FULL_PWR);
		}
	}
}


static void
hubd_post_detach(hubd_t *hubd, usb_port_t port, struct detachspec *ds)
{
	USB_DPRINTF_L4(DPRINT_MASK_ATTA, hubd->h_log_handle,
	    "hubd_post_detach: port=%d result=%d", port, ds->result);

	/*
	 * if the device is successfully detached and is the
	 * last device to detach, mark component as idle
	 */
	mutex_enter(HUBD_MUTEX(hubd));
	if (ds->result == DDI_SUCCESS) {
		usba_device_t	*usba_device = hubd->h_usba_devices[port];
		dev_info_t	*pdip = hubd->h_dip;
		mutex_exit(HUBD_MUTEX(hubd));

		usba_hubdi_incr_power_budget(pdip, usba_device);

		/*
		 * We set power of the detached child
		 * to 0, so that we can suspend if all
		 * our children are gone
		 */
		hubd_set_child_pwrlvl(hubd, port, USB_DEV_OS_PWR_OFF);

		/* check for leaks on detaching */
		if ((usba_device) && (ds->cmd == DDI_DETACH)) {
			usba_check_for_leaks(usba_device);
		}
	} else {
		mutex_exit(HUBD_MUTEX(hubd));
	}
}


/*
 * hubd_post_power
 *	After the child's power entry point has been called
 *	we record its power level in our local struct.
 *	If the device has powered off, we suspend port
 */
static int
hubd_post_power(hubd_t *hubd, usb_port_t port, pm_bp_child_pwrchg_t *bpc,
    int result)
{
	int	retval = USB_SUCCESS;

	USB_DPRINTF_L4(DPRINT_MASK_PM, hubd->h_log_handle,
	    "hubd_post_power: port=%d", port);

	if (result == DDI_SUCCESS) {

		/* record this power in our local struct */
		hubd_set_child_pwrlvl(hubd, port, bpc->bpc_nlevel);

		if (bpc->bpc_nlevel == USB_DEV_OS_PWR_OFF) {

			/* now suspend the port */
			retval = hubd_suspend_port(hubd, port);
		} else if (bpc->bpc_nlevel == USB_DEV_OS_FULL_PWR) {

			/* make sure the port is resumed */
			retval = hubd_resume_port(hubd, port);
		}
	} else {

		/* record old power in our local struct */
		hubd_set_child_pwrlvl(hubd, port, bpc->bpc_olevel);

		if (bpc->bpc_olevel == USB_DEV_OS_PWR_OFF) {

			/*
			 * As this device failed to transition from
			 * power off state, suspend the port again
			 */
			retval = hubd_suspend_port(hubd, port);
		}
	}

	return (retval);
}


/*
 * bus ctl notifications are handled here, the rest goes up to root hub/hcd
 */
static int
usba_hubdi_bus_ctl(dev_info_t *dip,
	dev_info_t	*rdip,
	ddi_ctl_enum_t	op,
	void		*arg,
	void		*result)
{
	usba_device_t *hub_usba_device = usba_get_usba_device(rdip);
	dev_info_t *root_hub_dip = hub_usba_device->usb_root_hub_dip;
	struct attachspec *as;
	struct detachspec *ds;
	hubd_t		*hubd;
	usb_port_t	port;
	int		circ, rval;
	int		retval = DDI_FAILURE;

	hubd = hubd_get_soft_state(dip);

	mutex_enter(HUBD_MUTEX(hubd));

	/* flag that we are currently running bus_ctl */
	hubd->h_bus_ctls++;
	mutex_exit(HUBD_MUTEX(hubd));

	USB_DPRINTF_L3(DPRINT_MASK_HUBDI, hubd->h_log_handle,
	    "usba_hubdi_bus_ctl:\n\t"
	    "dip=0x%p, rdip=0x%p, op=0x%x, arg=0x%p",
	    (void *)dip, (void *)rdip, op, arg);

	switch (op) {
	case DDI_CTLOPS_ATTACH:
		as = (struct attachspec *)arg;
		port = hubd_child_dip2port(hubd, rdip);

		/* there is nothing to do at resume time */
		if (as->cmd == DDI_RESUME) {
			break;
		}

		/* serialize access */
		ndi_devi_enter(hubd->h_dip, &circ);

		switch (as->when) {
		case DDI_PRE:
			USB_DPRINTF_L4(DPRINT_MASK_PM, hubd->h_log_handle,
			    "DDI_PRE DDI_CTLOPS_ATTACH: dip=%p, port=%d",
			    (void *)rdip, port);

			mutex_enter(HUBD_MUTEX(hubd));
			hubd->h_port_state[port] |= HUBD_CHILD_ATTACHING;

			/* Go busy here.  Matching idle is DDI_POST case. */
			(void) hubd_pm_busy_component(hubd, dip, 0);
			mutex_exit(HUBD_MUTEX(hubd));

			/*
			 * if we suspended the port previously
			 * because child went to low power state, and
			 * someone unloaded the driver, the port would
			 * still be suspended and needs to be resumed
			 */
			rval = hubd_resume_port(hubd, port);
			if (rval == USB_SUCCESS) {
				retval = DDI_SUCCESS;
			}

			break;
		case DDI_POST:
			USB_DPRINTF_L4(DPRINT_MASK_PM, hubd->h_log_handle,
			    "DDI_POST DDI_CTLOPS_ATTACH: dip=%p, port=%d",
			    (void *)rdip, port);

			mutex_enter(HUBD_MUTEX(hubd));
			hubd->h_port_state[port] &= ~HUBD_CHILD_ATTACHING;
			mutex_exit(HUBD_MUTEX(hubd));

			hubd_post_attach(hubd, port, (struct attachspec *)arg);
			retval = DDI_SUCCESS;
			mutex_enter(HUBD_MUTEX(hubd));

			/* Matching idle call for DDI_PRE busy call. */
			(void) hubd_pm_idle_component(hubd, dip, 0);
			mutex_exit(HUBD_MUTEX(hubd));
		}
		ndi_devi_exit(hubd->h_dip, circ);

		break;
	case DDI_CTLOPS_DETACH:
		ds = (struct detachspec *)arg;
		port = hubd_child_dip2port(hubd, rdip);

		/* there is nothing to do at suspend time */
		if (ds->cmd == DDI_SUSPEND) {
			break;
		}

		/* serialize access */
		ndi_devi_enter(hubd->h_dip, &circ);

		switch (ds->when) {
		case DDI_PRE:
			USB_DPRINTF_L4(DPRINT_MASK_PM, hubd->h_log_handle,
			    "DDI_PRE DDI_CTLOPS_DETACH: dip=%p port=%d",
			    (void *)rdip, port);

			mutex_enter(HUBD_MUTEX(hubd));
			hubd->h_port_state[port] |= HUBD_CHILD_DETACHING;

			/* Go busy here.  Matching idle is DDI_POST case. */
			(void) hubd_pm_busy_component(hubd, dip, 0);

			mutex_exit(HUBD_MUTEX(hubd));
			retval = DDI_SUCCESS;

			break;
		case DDI_POST:
			USB_DPRINTF_L4(DPRINT_MASK_PM, hubd->h_log_handle,
			    "DDI_POST DDI_CTLOPS_DETACH: dip=%p port=%d",
			    (void *)rdip, port);

			mutex_enter(HUBD_MUTEX(hubd));
			hubd->h_port_state[port] &= ~HUBD_CHILD_DETACHING;
			mutex_exit(HUBD_MUTEX(hubd));

			/* Matching idle call for DDI_PRE busy call. */
			hubd_post_detach(hubd, port, (struct detachspec *)arg);
			retval = DDI_SUCCESS;
			mutex_enter(HUBD_MUTEX(hubd));
			(void) hubd_pm_idle_component(hubd, dip, 0);
			mutex_exit(HUBD_MUTEX(hubd));

			break;
		}
		ndi_devi_exit(hubd->h_dip, circ);

		break;
	default:
		retval = usba_bus_ctl(root_hub_dip, rdip, op, arg, result);
	}

	/* decrement bus_ctls count */
	mutex_enter(HUBD_MUTEX(hubd));
	hubd->h_bus_ctls--;
	ASSERT(hubd->h_bus_ctls >= 0);
	mutex_exit(HUBD_MUTEX(hubd));

	return (retval);
}

/*
 * hubd_config_one:
 * 	enumerate one child according to 'port'
 */

static boolean_t
hubd_config_one(hubd_t *hubd, int port)
{
	uint16_t	status, change;
	dev_info_t	*hdip = hubd->h_dip;
	dev_info_t	*rh_dip = hubd->h_usba_device->usb_root_hub_dip;
	boolean_t	online_child = B_FALSE, found = B_FALSE;
	int		prh_circ, rh_circ, circ;

	USB_DPRINTF_L4(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "hubd_config_one:  started, hubd_reset_port = 0x%x", port);

	ndi_hold_devi(hdip); /* so we don't race with detach */

	/*
	 * this ensures one config activity per system at a time.
	 * we enter the parent PCI node to have this serialization.
	 * this also excludes ioctls and deathrow thread
	 */
	ndi_devi_enter(ddi_get_parent(rh_dip), &prh_circ);
	ndi_devi_enter(rh_dip, &rh_circ);

	/* exclude other threads */
	ndi_devi_enter(hdip, &circ);
	mutex_enter(HUBD_MUTEX(hubd));

	hubd_pm_busy_component(hubd, hubd->h_dip, 0);

	if (!hubd->h_children_dips[port]) {

		(void) hubd_determine_port_status(hubd, port,
		    &status, &change, HUBD_ACK_ALL_CHANGES);

		if (status & PORT_STATUS_CCS) {
			online_child |=	(hubd_handle_port_connect(hubd,
			    port) == USB_SUCCESS);
			found = online_child;
		}
	} else {
		found = B_TRUE;
	}

	mutex_exit(HUBD_MUTEX(hubd));

	ndi_devi_exit(hdip, circ);
	ndi_devi_exit(rh_dip, rh_circ);
	ndi_devi_exit(ddi_get_parent(rh_dip), prh_circ);

	if (online_child) {
		USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "hubd_config_one: onlining child");

		(void) ndi_devi_online(hubd->h_dip, 0);
	}

	mutex_enter(HUBD_MUTEX(hubd));

	(void) hubd_pm_idle_component(hubd, hubd->h_dip, 0);

	USB_DPRINTF_L4(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "hubd_config_one: exit");

	mutex_exit(HUBD_MUTEX(hubd));

	ndi_rele_devi(hdip);

	return (found);
}

/*
 * bus enumeration entry points
 */
static int
hubd_bus_config(dev_info_t *dip, uint_t flag, ddi_bus_config_op_t op,
    void *arg, dev_info_t **child)
{
	hubd_t	*hubd = hubd_get_soft_state(dip);
	int	rval, circ;
	long port;

	USB_DPRINTF_L4(DPRINT_MASK_PM, hubd->h_log_handle,
	    "hubd_bus_config: op=%d", op);

	if (hubdi_bus_config_debug) {
		flag |= NDI_DEVI_DEBUG;
	}

	if (op == BUS_CONFIG_ONE) {
		boolean_t found;
		char cname[80];
		char *name, *addr;

		USB_DPRINTF_L2(DPRINT_MASK_PM, hubd->h_log_handle,
		    "hubd_bus_config: op=%d (BUS_CONFIG_ONE)", op);

		(void) snprintf(cname, 80, "%s", (char *)arg);
		/* split name into "name@addr" parts */
		i_ddi_parse_name(cname, &name, &addr, NULL);
		if (addr && *addr) {
			(void) ddi_strtol(addr, NULL, 16, &port);
		} else {
			return (NDI_FAILURE);
		}

		found = hubd_config_one(hubd, port);

		if (found == 0) {
			return (NDI_FAILURE);
		}

	}
	ndi_devi_enter(hubd->h_dip, &circ);
	rval = ndi_busop_bus_config(dip, flag, op, arg, child, 0);
	ndi_devi_exit(hubd->h_dip, circ);

	return (rval);
}


static int
hubd_bus_unconfig(dev_info_t *dip, uint_t flag, ddi_bus_config_op_t op,
    void *arg)
{
	hubd_t		*hubd = hubd_get_soft_state(dip);
	dev_info_t	*cdip;
	usb_port_t	port;
	int		circ;
	int		rval;

	USB_DPRINTF_L4(DPRINT_MASK_PM, hubd->h_log_handle,
	    "hubd_bus_unconfig: op=%d", op);

	if (hubdi_bus_config_debug) {
		flag |= NDI_DEVI_DEBUG;
	}

	if ((op == BUS_UNCONFIG_ALL) && (flag & NDI_AUTODETACH) == 0) {
		flag |= NDI_DEVI_REMOVE;
	}

	/* serialize access */
	ndi_devi_enter(dip, &circ);

	rval = ndi_busop_bus_unconfig(dip, flag, op, arg);

	/* logically zap children's list */
	mutex_enter(HUBD_MUTEX(hubd));
	for (port = 1; port <= hubd->h_hub_descr.bNbrPorts; port++) {
		hubd->h_port_state[port] |= HUBD_CHILD_ZAP;
	}
	mutex_exit(HUBD_MUTEX(hubd));

	/* fill in what's left */
	for (cdip = ddi_get_child(dip); cdip;
	    cdip = ddi_get_next_sibling(cdip)) {
		usba_device_t *usba_device = usba_get_usba_device(cdip);

		if (usba_device == NULL) {

			continue;
		}
		mutex_enter(HUBD_MUTEX(hubd));
		port = usba_device->usb_port;
		hubd->h_children_dips[port] = cdip;
		hubd->h_port_state[port] &= ~HUBD_CHILD_ZAP;
		mutex_exit(HUBD_MUTEX(hubd));
	}

	/* physically zap the children we didn't find */
	mutex_enter(HUBD_MUTEX(hubd));
	for (port = 1; port <= hubd->h_hub_descr.bNbrPorts; port++) {
		if (hubd->h_port_state[port] &	HUBD_CHILD_ZAP) {
			/* zap the dip and usba_device structure as well */
			hubd_free_usba_device(hubd, hubd->h_usba_devices[port]);
			hubd->h_children_dips[port] = NULL;
			hubd->h_port_state[port] &= ~HUBD_CHILD_ZAP;
		}
	}
	mutex_exit(HUBD_MUTEX(hubd));

	ndi_devi_exit(dip, circ);

	USB_DPRINTF_L4(DPRINT_MASK_PM, hubd->h_log_handle,
	    "hubd_bus_unconfig: rval=%d", rval);

	return (rval);
}


/* bus_power entry point */
static int
hubd_bus_power(dev_info_t *dip, void *impl_arg, pm_bus_power_op_t op,
    void *arg, void *result)
{
	hubd_t		*hubd;
	int		rval, pwrup_res;
	usb_port_t	port;
	int		retval = DDI_FAILURE;
	pm_bp_child_pwrchg_t	*bpc;
	pm_bp_nexus_pwrup_t	bpn;

	hubd = hubd_get_soft_state(dip);

	USB_DPRINTF_L4(DPRINT_MASK_HUBDI, hubd->h_log_handle,
	    "hubd_bus_power: dip=%p, impl_arg=%p, power_op=%d, arg=%p, "
	    "result=%d\n", (void *)dip, impl_arg, op, arg, *(int *)result);

	bpc = (pm_bp_child_pwrchg_t *)arg;

	mutex_enter(HUBD_MUTEX(hubd));
	hubd->h_bus_pwr++;
	mutex_exit(HUBD_MUTEX(hubd));

	switch (op) {
	case BUS_POWER_PRE_NOTIFICATION:
		port = hubd_child_dip2port(hubd, bpc->bpc_dip);
		USB_DPRINTF_L3(DPRINT_MASK_HUBDI, hubd->h_log_handle,
		    "hubd_bus_power: BUS_POWER_PRE_NOTIFICATION, port=%d",
		    port);

		/* go to full power if we are powered down */
		mutex_enter(HUBD_MUTEX(hubd));

		/*
		 * If this case completes normally, idle will be in
		 * hubd_bus_power / BUS_POWER_POST_NOTIFICATION
		 */
		hubd_pm_busy_component(hubd, dip, 0);

		/*
		 * raise power only if we have created the components
		 * and are currently in low power
		 */
		if ((hubd->h_dev_state == USB_DEV_PWRED_DOWN) &&
		    hubd->h_hubpm->hubp_wakeup_enabled) {
			mutex_exit(HUBD_MUTEX(hubd));

			bpn.bpn_comp = 0;
			bpn.bpn_dip = dip;
			bpn.bpn_level = USB_DEV_OS_FULL_PWR;
			bpn.bpn_private = bpc->bpc_private;

			rval = pm_busop_bus_power(dip, impl_arg,
			    BUS_POWER_NEXUS_PWRUP, (void *)&bpn,
			    (void *)&pwrup_res);

			if (rval != DDI_SUCCESS || pwrup_res != DDI_SUCCESS) {
				mutex_enter(HUBD_MUTEX(hubd));
				hubd_pm_idle_component(hubd, dip, 0);
				mutex_exit(HUBD_MUTEX(hubd));

				break;
			}
			mutex_enter(HUBD_MUTEX(hubd));
		}

		/* indicate that child is changing power level */
		hubd->h_port_state[port] |= HUBD_CHILD_PWRLVL_CHNG;
		mutex_exit(HUBD_MUTEX(hubd));

		if ((bpc->bpc_olevel == 0) &&
		    (bpc->bpc_nlevel > bpc->bpc_olevel)) {
			/*
			 * this child is transitioning from power off
			 * to power on state - resume port
			 */
			rval = hubd_resume_port(hubd, port);
			if (rval == USB_SUCCESS) {
				retval = DDI_SUCCESS;
			} else {
				/* reset this flag on failure */
				mutex_enter(HUBD_MUTEX(hubd));
				hubd->h_port_state[port] &=
				    ~HUBD_CHILD_PWRLVL_CHNG;
				hubd_pm_idle_component(hubd, dip, 0);
				mutex_exit(HUBD_MUTEX(hubd));
			}
		} else {
			retval = DDI_SUCCESS;
		}

		break;
	case BUS_POWER_POST_NOTIFICATION:
		port = hubd_child_dip2port(hubd, bpc->bpc_dip);
		USB_DPRINTF_L3(DPRINT_MASK_HUBDI, hubd->h_log_handle,
		    "hubd_bus_power: BUS_POWER_POST_NOTIFICATION, port=%d",
		    port);

		mutex_enter(HUBD_MUTEX(hubd));
		hubd->h_port_state[port] &= ~HUBD_CHILD_PWRLVL_CHNG;
		mutex_exit(HUBD_MUTEX(hubd));

		/* record child's pwr and suspend port if required */
		rval = hubd_post_power(hubd, port, bpc, *(int *)result);
		if (rval == USB_SUCCESS) {

			retval = DDI_SUCCESS;
		}

		mutex_enter(HUBD_MUTEX(hubd));

		/*
		 * Matching idle for the busy in
		 * hubd_bus_power / BUS_POWER_PRE_NOTIFICATION
		 */
		hubd_pm_idle_component(hubd, dip, 0);

		mutex_exit(HUBD_MUTEX(hubd));

		break;
	default:
		retval = pm_busop_bus_power(dip, impl_arg, op, arg, result);

		break;
	}

	mutex_enter(HUBD_MUTEX(hubd));
	hubd->h_bus_pwr--;
	mutex_exit(HUBD_MUTEX(hubd));

	return (retval);
}


/*
 * functions to handle power transition for OS levels 0 -> 3
 */
static int
hubd_pwrlvl0(hubd_t *hubd)
{
	hub_power_t	*hubpm;

	/* We can't power down if hotplug thread is running */
	if (hubd->h_hotplug_thread || hubd->h_hubpm->hubp_busy_pm ||
	    (hubd_can_suspend(hubd) == USB_FAILURE)) {

		return (USB_FAILURE);
	}

	switch (hubd->h_dev_state) {
	case USB_DEV_ONLINE:
		hubpm = hubd->h_hubpm;

		/*
		 * To avoid race with bus_power pre_notify on check over
		 * dev_state, we need to correctly set the dev state
		 * before the mutex is dropped in stop polling.
		 */
		hubd->h_dev_state = USB_DEV_PWRED_DOWN;
		hubpm->hubp_current_power = USB_DEV_OS_PWR_OFF;

		/*
		 * if we are the root hub, do not stop polling
		 * otherwise, we will never see a resume
		 */
		if (usba_is_root_hub(hubd->h_dip)) {
			/* place holder to implement Global Suspend */
			USB_DPRINTF_L2(DPRINT_MASK_PM, hubd->h_log_handle,
			    "Global Suspend: Not Yet Implemented");
		} else {
			hubd_stop_polling(hubd);
		}

		/* Issue USB D3 command to the device here */
		(void) usb_set_device_pwrlvl3(hubd->h_dip);

		break;
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
hubd_pwrlvl1(hubd_t *hubd)
{
	/* Issue USB D2 command to the device here */
	(void) usb_set_device_pwrlvl2(hubd->h_dip);

	return (USB_FAILURE);
}


/* ARGSUSED */
static int
hubd_pwrlvl2(hubd_t *hubd)
{
	/* Issue USB D1 command to the device here */
	(void) usb_set_device_pwrlvl1(hubd->h_dip);

	return (USB_FAILURE);
}


static int
hubd_pwrlvl3(hubd_t *hubd)
{
	hub_power_t	*hubpm;
	int		rval;

	USB_DPRINTF_L2(DPRINT_MASK_PM, hubd->h_log_handle, "hubd_pwrlvl3");

	hubpm = hubd->h_hubpm;
	switch (hubd->h_dev_state) {
	case USB_DEV_PWRED_DOWN:
		ASSERT(hubpm->hubp_current_power == USB_DEV_OS_PWR_OFF);
		if (usba_is_root_hub(hubd->h_dip)) {
			/* implement global resume here */
			USB_DPRINTF_L2(DPRINT_MASK_PM,
			    hubd->h_log_handle,
			    "Global Resume: Not Yet Implemented");
		}
		/* Issue USB D0 command to the device here */
		rval = usb_set_device_pwrlvl0(hubd->h_dip);
		ASSERT(rval == USB_SUCCESS);
		hubd->h_dev_state = USB_DEV_ONLINE;
		hubpm->hubp_current_power = USB_DEV_OS_FULL_PWR;
		hubpm->hubp_time_at_full_power = gethrtime();
		hubd_start_polling(hubd, 0);

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
		USB_DPRINTF_L2(DPRINT_MASK_PM, hubd->h_log_handle,
		    "hubd_pwrlvl3: Illegal dev_state=%d", hubd->h_dev_state);

		return (USB_FAILURE);
	}
}


/* power entry point */
/* ARGSUSED */
int
usba_hubdi_power(dev_info_t *dip, int comp, int level)
{
	hubd_t		*hubd;
	hub_power_t	*hubpm;
	int		retval;
	int		circ;

	hubd = hubd_get_soft_state(dip);
	USB_DPRINTF_L3(DPRINT_MASK_HUBDI, hubd->h_log_handle,
	    "usba_hubdi_power: level=%d", level);

	ndi_devi_enter(dip, &circ);

	mutex_enter(HUBD_MUTEX(hubd));
	hubpm = hubd->h_hubpm;

	/* check if we are transitioning to a legal power level */
	if (USB_DEV_PWRSTATE_OK(hubpm->hubp_pwr_states, level)) {
		USB_DPRINTF_L2(DPRINT_MASK_HUBDI, hubd->h_log_handle,
		    "usba_hubdi_power: illegal power level=%d "
		    "hubp_pwr_states=0x%x", level, hubpm->hubp_pwr_states);
		mutex_exit(HUBD_MUTEX(hubd));

		ndi_devi_exit(dip, circ);

		return (DDI_FAILURE);
	}

	switch (level) {
	case USB_DEV_OS_PWR_OFF:
		retval = hubd_pwrlvl0(hubd);

		break;
	case USB_DEV_OS_PWR_1:
		retval = hubd_pwrlvl1(hubd);

		break;
	case USB_DEV_OS_PWR_2:
		retval = hubd_pwrlvl2(hubd);

		break;
	case USB_DEV_OS_FULL_PWR:
		retval = hubd_pwrlvl3(hubd);

		break;
	}
	mutex_exit(HUBD_MUTEX(hubd));

	ndi_devi_exit(dip, circ);

	return ((retval == USB_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}


/* power entry point for the root hub */
int
usba_hubdi_root_hub_power(dev_info_t *dip, int comp, int level)
{
	return (usba_hubdi_power(dip, comp, level));
}


/*
 * standard driver entry points support code
 */
int
usba_hubdi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			instance = ddi_get_instance(dip);
	hubd_t			*hubd = NULL;
	int			i, rval;
	int			minor;
	uint8_t			ports_count;
	char			*log_name = NULL;
	const char		*root_hub_drvname;
	usb_ep_data_t		*ep_data;
	usba_device_t		*child_ud = NULL;
	usb_dev_descr_t		*usb_dev_descr;
	usb_port_status_t	parent_port_status, child_port_status;

	USB_DPRINTF_L4(DPRINT_MASK_ATTA, hubdi_log_handle,
	    "hubd_attach instance %d, cmd=0x%x", instance, cmd);

	switch (cmd) {
	case DDI_ATTACH:

		break;
	case DDI_RESUME:
		hubd_cpr_resume(dip);

		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	/*
	 * Allocate softc information.
	 */
	if (usba_is_root_hub(dip)) {
		/* soft state has already been allocated */
		hubd = hubd_get_soft_state(dip);
		minor = HUBD_IS_ROOT_HUB;

		/* generate readable labels for different root hubs */
		root_hub_drvname = ddi_driver_name(dip);
		if (strcmp(root_hub_drvname, "ehci") == 0) {
			log_name = "eusb";
		} else if (strcmp(root_hub_drvname, "uhci") == 0) {
			log_name = "uusb";
		} else {
			/* std. for ohci */
			log_name = "usb";
		}
	} else {
		rval = ddi_soft_state_zalloc(hubd_statep, instance);
		minor = 0;

		if (rval != DDI_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubdi_log_handle,
			    "cannot allocate soft state (%d)", instance);
			goto fail;
		}

		hubd = hubd_get_soft_state(dip);
		if (hubd == NULL) {
			goto fail;
		}
	}

	hubd->h_log_handle = usb_alloc_log_hdl(dip, log_name, &hubd_errlevel,
	    &hubd_errmask, &hubd_instance_debug, 0);

	hubd->h_usba_device	= child_ud = usba_get_usba_device(dip);
	hubd->h_dip		= dip;
	hubd->h_instance	= instance;

	mutex_enter(&child_ud->usb_mutex);
	child_port_status = child_ud->usb_port_status;
	usb_dev_descr = child_ud->usb_dev_descr;
	parent_port_status = (child_ud->usb_hs_hub_usba_dev) ?
	    child_ud->usb_hs_hub_usba_dev->usb_port_status : 0;
	mutex_exit(&child_ud->usb_mutex);

	if ((child_port_status == USBA_FULL_SPEED_DEV) &&
	    (parent_port_status == USBA_HIGH_SPEED_DEV) &&
	    (usb_dev_descr->bcdUSB == 0x100)) {
		USB_DPRINTF_L0(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "Use of a USB1.0 hub behind a high speed port may "
		    "cause unexpected failures");
	}

	hubd->h_pipe_policy.pp_max_async_reqs = 1;

	/* register with USBA as client driver */
	if (usb_client_attach(dip, USBDRV_VERSION, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "client attach failed");

		goto fail;
	}

	if (usb_get_dev_data(dip, &hubd->h_dev_data,
	    USB_PARSE_LVL_IF, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "cannot get dev_data");

		goto fail;
	}

	if ((ep_data = usb_lookup_ep_data(dip, hubd->h_dev_data,
	    hubd->h_dev_data->dev_curr_if, 0, 0,
	    (uint_t)USB_EP_ATTR_INTR, (uint_t)USB_EP_DIR_IN)) == NULL) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "no interrupt IN endpoint found");

		goto fail;
	}

	hubd->h_ep1_descr = ep_data->ep_descr;
	hubd->h_default_pipe = hubd->h_dev_data->dev_default_ph;

	mutex_init(HUBD_MUTEX(hubd), NULL, MUTEX_DRIVER,
	    hubd->h_dev_data->dev_iblock_cookie);
	cv_init(&hubd->h_cv_reset_port, NULL, CV_DRIVER, NULL);
	cv_init(&hubd->h_cv_hotplug_dev, NULL, CV_DRIVER, NULL);

	hubd->h_init_state |= HUBD_LOCKS_DONE;

	usb_free_descr_tree(dip, hubd->h_dev_data);

	/*
	 * register this hub instance with usba
	 */
	rval = usba_hubdi_register(dip, 0);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "usba_hubdi_register failed");
		goto fail;
	}

	mutex_enter(HUBD_MUTEX(hubd));
	hubd->h_init_state |= HUBD_HUBDI_REGISTERED;
	hubd->h_dev_state = USB_DEV_ONLINE;
	mutex_exit(HUBD_MUTEX(hubd));

	/* now create components to power manage this device */
	hubd_create_pm_components(dip, hubd);

	/*
	 * Event handling: definition and registration
	 *
	 * first the  definition:
	 * get event handle
	 */
	(void) ndi_event_alloc_hdl(dip, 0, &hubd->h_ndi_event_hdl, NDI_SLEEP);

	/* bind event set to the handle */
	if (ndi_event_bind_set(hubd->h_ndi_event_hdl, &hubd_ndi_events,
	    NDI_SLEEP)) {
		USB_DPRINTF_L3(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "binding event set failed");

		goto fail;
	}

	/* event registration */
	if (hubd_register_events(hubd) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "hubd_register_events failed");

		goto fail;
	}

	mutex_enter(HUBD_MUTEX(hubd));
	hubd->h_init_state |= HUBD_EVENTS_REGISTERED;

	if ((hubd_get_hub_descriptor(hubd)) != USB_SUCCESS) {
		mutex_exit(HUBD_MUTEX(hubd));

		goto fail;
	}

	if (ddi_prop_exists(DDI_DEV_T_ANY, dip,
	    (DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
	    "hub-ignore-power-budget") == 1) {
		hubd->h_ignore_pwr_budget = B_TRUE;
	} else {
		hubd->h_ignore_pwr_budget = B_FALSE;

		/* initialize hub power budget variables */
		if (hubd_init_power_budget(hubd) != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
			    "hubd_init_power_budget failed");
			mutex_exit(HUBD_MUTEX(hubd));

			goto fail;
		}
	}

	/* initialize and create children */
	if (hubd_check_ports(hubd) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "hubd_check_ports failed");
		mutex_exit(HUBD_MUTEX(hubd));

		goto fail;
	}

	/*
	 * create cfgadm nodes
	 */
	hubd->h_ancestry_str = (char *)kmem_zalloc(HUBD_APID_NAMELEN, KM_SLEEP);
	hubd_get_ancestry_str(hubd);

	USB_DPRINTF_L4(DPRINT_MASK_ATTA, hubd->h_log_handle,
	    "#ports=0x%x", hubd->h_hub_descr.bNbrPorts);

	for (i = 1; i <= hubd->h_hub_descr.bNbrPorts; i++) {
		char ap_name[HUBD_APID_NAMELEN];

		(void) snprintf(ap_name, HUBD_APID_NAMELEN, "%s%d",
		    hubd->h_ancestry_str, i);
		USB_DPRINTF_L4(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "ap_name=%s", ap_name);

		if (ddi_create_minor_node(dip, ap_name, S_IFCHR, instance,
		    DDI_NT_USB_ATTACHMENT_POINT, 0) != DDI_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
			    "cannot create attachment point node (%d)",
			    instance);
			mutex_exit(HUBD_MUTEX(hubd));

			goto fail;
		}
	}

	ports_count = hubd->h_hub_descr.bNbrPorts;
	mutex_exit(HUBD_MUTEX(hubd));

	/* create minor nodes */
	if (ddi_create_minor_node(dip, "hubd", S_IFCHR,
	    instance | minor, DDI_NT_NEXUS, 0) != DDI_SUCCESS) {

		USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "cannot create devctl minor node (%d)", instance);

		goto fail;
	}

	mutex_enter(HUBD_MUTEX(hubd));
	hubd->h_init_state |= HUBD_MINOR_NODE_CREATED;
	mutex_exit(HUBD_MUTEX(hubd));

	if (ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "usb-port-count", ports_count) != DDI_PROP_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "usb-port-count update failed");
	}

	/*
	 * host controller driver has already reported this dev
	 * if we are the root hub
	 */
	if (!usba_is_root_hub(dip)) {
		ddi_report_dev(dip);
	}

	/* enable deathrow thread */
	hubd->h_cleanup_enabled = B_TRUE;
	mutex_enter(HUBD_MUTEX(hubd));
	hubd_pm_idle_component(hubd, dip, 0);
	mutex_exit(HUBD_MUTEX(hubd));

	return (DDI_SUCCESS);

fail:
	{
		char *pathname = kmem_alloc(MAXPATHLEN, KM_SLEEP);

		USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubdi_log_handle,
		    "cannot attach %s", ddi_pathname(dip, pathname));

		kmem_free(pathname, MAXPATHLEN);
	}

	mutex_enter(HUBD_MUTEX(hubd));
	hubd_pm_idle_component(hubd, dip, 0);
	mutex_exit(HUBD_MUTEX(hubd));

	if (hubd) {
		rval = hubd_cleanup(dip, hubd);
		if (rval != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubdi_log_handle,
			    "failure to complete cleanup after attach failure");
		}
	}

	return (DDI_FAILURE);
}


int
usba_hubdi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	hubd_t	*hubd = hubd_get_soft_state(dip);
	int	rval;

	USB_DPRINTF_L4(DPRINT_MASK_ATTA, hubd->h_log_handle,
	    "hubd_detach: cmd=0x%x", cmd);

	switch (cmd) {
	case DDI_DETACH:
		rval = hubd_cleanup(dip, hubd);

		return ((rval == USB_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
	case DDI_SUSPEND:
		rval = hubd_cpr_suspend(hubd);

		return ((rval == USB_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
	default:
		return (DDI_FAILURE);
	}
}


/*
 * hubd_setdevaddr
 *	set the device addrs on this port
 */
static int
hubd_setdevaddr(hubd_t *hubd, usb_port_t port)
{
	int		rval;
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	usb_pipe_handle_t ph;
	dev_info_t	*child_dip = NULL;
	uchar_t		address = 0;
	usba_device_t	*usba_device;
	int		retry = 0;
	long		time_delay;

	USB_DPRINTF_L4(DPRINT_MASK_ATTA, hubd->h_log_handle,
	    "hubd_setdevaddr: port=%d", port);

	ASSERT(mutex_owned(HUBD_MUTEX(hubd)));

	child_dip = hubd->h_children_dips[port];
	address = hubd->h_usba_devices[port]->usb_addr;
	usba_device = hubd->h_usba_devices[port];

	/* close the default pipe with addr x */
	mutex_exit(HUBD_MUTEX(hubd));
	ph = usba_get_dflt_pipe_handle(child_dip);
	usb_pipe_close(child_dip, ph,
	    USB_FLAGS_SLEEP | USBA_FLAGS_PRIVILEGED, NULL, NULL);
	mutex_enter(HUBD_MUTEX(hubd));

	/*
	 * As this device has been reset, temporarily
	 * assign the default address
	 */
	mutex_enter(&usba_device->usb_mutex);
	address = usba_device->usb_addr;
	usba_device->usb_addr = USBA_DEFAULT_ADDR;
	mutex_exit(&usba_device->usb_mutex);

	mutex_exit(HUBD_MUTEX(hubd));

	time_delay = drv_usectohz(hubd_device_delay / 20);
	for (retry = 0; retry < hubd_retry_enumerate; retry++) {

		/* open child's default pipe with USBA_DEFAULT_ADDR */
		if (usb_pipe_open(child_dip, NULL, NULL,
		    USB_FLAGS_SLEEP | USBA_FLAGS_PRIVILEGED, &ph) !=
		    USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
			    "hubd_setdevaddr: Unable to open default pipe");

			break;
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
			USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
			    "hubd_setdevaddr(%d): rval=%d cr=%d cb_fl=0x%x",
			    retry, rval, completion_reason, cb_flags);
		}

		usb_pipe_close(child_dip, ph,
		    USB_FLAGS_SLEEP | USBA_FLAGS_PRIVILEGED, NULL, NULL);

		if (rval == USB_SUCCESS) {

			break;
		}

		delay(time_delay);
	}

	/* Reset to the old address */
	mutex_enter(&usba_device->usb_mutex);
	usba_device->usb_addr = address;
	mutex_exit(&usba_device->usb_mutex);
	mutex_enter(HUBD_MUTEX(hubd));

	usba_clear_data_toggle(usba_device);

	return (rval);
}


/*
 * hubd_setdevconfig
 *	set the device addrs on this port
 */
static void
hubd_setdevconfig(hubd_t *hubd, usb_port_t port)
{
	int			rval;
	usb_cr_t		completion_reason;
	usb_cb_flags_t		cb_flags;
	usb_pipe_handle_t	ph;
	dev_info_t		*child_dip = NULL;
	usba_device_t		*usba_device = NULL;
	uint16_t		config_value;

	USB_DPRINTF_L4(DPRINT_MASK_ATTA, hubd->h_log_handle,
	    "hubd_setdevconfig: port=%d", port);

	ASSERT(mutex_owned(HUBD_MUTEX(hubd)));

	child_dip = hubd->h_children_dips[port];
	usba_device = hubd->h_usba_devices[port];
	config_value = hubd->h_usba_devices[port]->usb_cfg_value;
	mutex_exit(HUBD_MUTEX(hubd));

	/* open the default control pipe */
	if ((rval = usb_pipe_open(child_dip, NULL, NULL,
	    USB_FLAGS_SLEEP | USBA_FLAGS_PRIVILEGED, &ph)) ==
	    USB_SUCCESS) {

		/* Set the default configuration of the device */
		if ((rval = usb_pipe_sync_ctrl_xfer(child_dip, ph,
		    USB_DEV_REQ_HOST_TO_DEV,
		    USB_REQ_SET_CFG,		/* bRequest */
		    config_value,		/* wValue */
		    0,				/* wIndex */
		    0,				/* wLength */
		    NULL, 0,
		    &completion_reason, &cb_flags, 0)) != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
			    "hubd_setdevconfig: set device config failed: "
			    "cr=%d cb_fl=0x%x rval=%d",
			    completion_reason, cb_flags, rval);
		}
		/*
		 * After setting the configuration, we make this default
		 * control pipe persistent, so that it gets re-opened
		 * on posting a connect event
		 */
		usba_persistent_pipe_close(usba_device);
	} else {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "pipe open fails: rval=%d", rval);
	}
	mutex_enter(HUBD_MUTEX(hubd));
}


/*ARGSUSED*/
static int
hubd_check_disconnected_ports(dev_info_t *dip, void *arg)
{
	int circ;
	usb_port_t port;
	hubd_t *hubd;
	major_t hub_major = ddi_name_to_major("hubd");
	major_t hwahc_major = ddi_name_to_major("hwahc");
	major_t usbmid_major = ddi_name_to_major("usb_mid");

	/*
	 * make sure dip is a usb hub, major of root hub is HCD
	 * major
	 */
	if (!usba_is_root_hub(dip)) {
		if (ddi_driver_major(dip) == usbmid_major) {
			/*
			 * need to walk the children since it might be a
			 * HWA device
			 */

			return (DDI_WALK_CONTINUE);
		}

		/* TODO: DWA device may also need special handling */

		if (((ddi_driver_major(dip) != hub_major) &&
		    (ddi_driver_major(dip) != hwahc_major)) ||
		    !i_ddi_devi_attached(dip)) {

			return (DDI_WALK_PRUNECHILD);
		}
	}

	hubd = hubd_get_soft_state(dip);
	if (hubd == NULL) {

		return (DDI_WALK_PRUNECHILD);
	}

	/* walk child list and remove nodes with flag DEVI_DEVICE_REMOVED */
	ndi_devi_enter(dip, &circ);

	if (ddi_driver_major(dip) != hwahc_major) {
		/* for normal usb hub or root hub */
		mutex_enter(HUBD_MUTEX(hubd));
		for (port = 1; port <= hubd->h_hub_descr.bNbrPorts; port++) {
			dev_info_t *cdip = hubd->h_children_dips[port];

			if (cdip == NULL || DEVI_IS_DEVICE_REMOVED(cdip) == 0) {

				continue;
			}

			(void) hubd_delete_child(hubd, port, NDI_DEVI_REMOVE,
			    B_TRUE);
		}
		mutex_exit(HUBD_MUTEX(hubd));
	} else {
		/* for HWA */
		if (hubd->h_cleanup_child != NULL) {
			if (hubd->h_cleanup_child(dip) != USB_SUCCESS) {
				ndi_devi_exit(dip, circ);

				return (DDI_WALK_PRUNECHILD);
			}
		} else {
			ndi_devi_exit(dip, circ);

			return (DDI_WALK_PRUNECHILD);
		}
	}

	ndi_devi_exit(dip, circ);

	/* skip siblings of root hub */
	if (usba_is_root_hub(dip)) {

		return (DDI_WALK_PRUNESIB);
	}

	return (DDI_WALK_CONTINUE);
}


/*
 * this thread will walk all children under the root hub for this
 * USB bus instance and attempt to remove them
 */
static void
hubd_root_hub_cleanup_thread(void *arg)
{
	int circ;
	hubd_t *root_hubd = (hubd_t *)arg;
	dev_info_t *rh_dip = root_hubd->h_dip;
#ifndef __lock_lint
	callb_cpr_t cprinfo;

	CALLB_CPR_INIT(&cprinfo, HUBD_MUTEX(root_hubd), callb_generic_cpr,
	    "USB root hub");
#endif

	for (;;) {
		/* don't race with detach */
		ndi_hold_devi(rh_dip);

		mutex_enter(HUBD_MUTEX(root_hubd));
		root_hubd->h_cleanup_needed = 0;
		mutex_exit(HUBD_MUTEX(root_hubd));

		(void) devfs_clean(rh_dip, NULL, 0);

		ndi_devi_enter(ddi_get_parent(rh_dip), &circ);
		ddi_walk_devs(rh_dip, hubd_check_disconnected_ports,
		    NULL);
#ifdef __lock_lint
		(void) hubd_check_disconnected_ports(rh_dip, NULL);
#endif
		ndi_devi_exit(ddi_get_parent(rh_dip), circ);

		/* quit if we are not enabled anymore */
		mutex_enter(HUBD_MUTEX(root_hubd));
		if ((root_hubd->h_cleanup_enabled == B_FALSE) ||
		    (root_hubd->h_cleanup_needed == B_FALSE)) {
			root_hubd->h_cleanup_active = B_FALSE;
			mutex_exit(HUBD_MUTEX(root_hubd));
			ndi_rele_devi(rh_dip);

			break;
		}
		mutex_exit(HUBD_MUTEX(root_hubd));
		ndi_rele_devi(rh_dip);

#ifndef __lock_lint
		mutex_enter(HUBD_MUTEX(root_hubd));
		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		mutex_exit(HUBD_MUTEX(root_hubd));

		delay(drv_usectohz(hubd_dip_cleanup_delay));

		mutex_enter(HUBD_MUTEX(root_hubd));
		CALLB_CPR_SAFE_END(&cprinfo, HUBD_MUTEX(root_hubd));
		mutex_exit(HUBD_MUTEX(root_hubd));
#endif
	}

#ifndef __lock_lint
	mutex_enter(HUBD_MUTEX(root_hubd));
	CALLB_CPR_EXIT(&cprinfo);
#endif
}


void
hubd_schedule_cleanup(dev_info_t *rh_dip)
{
	hubd_t	*root_hubd;

	/*
	 * The usb_root_hub_dip pointer for the child hub of the WUSB
	 * wire adapter class device points to the wire adapter, not
	 * the root hub. Need to find the real root hub dip so that
	 * the cleanup thread only starts from the root hub.
	 */
	while (!usba_is_root_hub(rh_dip)) {
		root_hubd = hubd_get_soft_state(rh_dip);
		if (root_hubd != NULL) {
			rh_dip = root_hubd->h_usba_device->usb_root_hub_dip;
			if (rh_dip == NULL) {
				USB_DPRINTF_L2(DPRINT_MASK_ATTA,
				    root_hubd->h_log_handle,
				    "hubd_schedule_cleanup: null rh dip");

				return;
			}
		} else {
			USB_DPRINTF_L2(DPRINT_MASK_ATTA,
			    root_hubd->h_log_handle,
			    "hubd_schedule_cleanup: cannot find root hub");

			return;
		}
	}
	root_hubd = hubd_get_soft_state(rh_dip);

	mutex_enter(HUBD_MUTEX(root_hubd));
	root_hubd->h_cleanup_needed = B_TRUE;
	if (root_hubd->h_cleanup_enabled && !(root_hubd->h_cleanup_active)) {
		root_hubd->h_cleanup_active = B_TRUE;
		mutex_exit(HUBD_MUTEX(root_hubd));
		(void) thread_create(NULL, 0,
		    hubd_root_hub_cleanup_thread,
		    (void *)root_hubd, 0, &p0, TS_RUN,
		    minclsyspri);
	} else {
		mutex_exit(HUBD_MUTEX(root_hubd));
	}
}


/*
 * hubd_restore_device_state:
 *	- set config for the hub
 *	- power cycle all the ports
 *	- for each port that was connected
 *		- reset port
 *		- assign addrs to the device on this port
 *	- restart polling
 *	- reset suspend flag
 */
static void
hubd_restore_device_state(dev_info_t *dip, hubd_t *hubd)
{
	int		rval;
	int		retry;
	uint_t		hub_prev_state;
	usb_port_t	port;
	uint16_t	status;
	uint16_t	change;
	dev_info_t	*ch_dip;
	boolean_t	ehci_root_hub;

	USB_DPRINTF_L4(DPRINT_MASK_ATTA, hubd->h_log_handle,
	    "hubd_restore_device_state:");

	mutex_enter(HUBD_MUTEX(hubd));
	hub_prev_state = hubd->h_dev_state;
	ASSERT(hub_prev_state != USB_DEV_PWRED_DOWN);

	/* First bring the device to full power */
	(void) hubd_pm_busy_component(hubd, dip, 0);
	mutex_exit(HUBD_MUTEX(hubd));

	(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);

	if (!usba_is_root_hub(dip) &&
	    (usb_check_same_device(dip, hubd->h_log_handle, USB_LOG_L0,
	    DPRINT_MASK_HOTPLUG,
	    USB_CHK_BASIC|USB_CHK_CFG, NULL) != USB_SUCCESS)) {

		/* change the device state to disconnected */
		mutex_enter(HUBD_MUTEX(hubd));
		hubd->h_dev_state = USB_DEV_DISCONNECTED;
		(void) hubd_pm_idle_component(hubd, dip, 0);
		mutex_exit(HUBD_MUTEX(hubd));

		return;
	}

	ehci_root_hub = (strcmp(ddi_driver_name(dip), "ehci") == 0);

	mutex_enter(HUBD_MUTEX(hubd));
	/* First turn off all port power */
	rval = hubd_disable_all_port_power(hubd);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L3(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "hubd_restore_device_state:"
		    "turning off port power failed");
	}

	/* Settling time before turning on again */
	mutex_exit(HUBD_MUTEX(hubd));
	delay(drv_usectohz(hubd_device_delay / 100));
	mutex_enter(HUBD_MUTEX(hubd));

	/* enable power on all ports so we can see connects */
	if (hubd_enable_all_port_power(hubd) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "hubd_restore_device_state: turn on port power failed");

		/* disable whatever was enabled */
		(void) hubd_disable_all_port_power(hubd);

		(void) hubd_pm_idle_component(hubd, dip, 0);
		mutex_exit(HUBD_MUTEX(hubd));

		return;
	}

	/*
	 * wait at least 3 frames before accessing devices
	 * (note that delay's minimal time is one clock tick which
	 * is 10ms unless hires_tick has been changed)
	 */
	mutex_exit(HUBD_MUTEX(hubd));
	delay(drv_usectohz(10000));
	mutex_enter(HUBD_MUTEX(hubd));

	hubd->h_dev_state = USB_DEV_HUB_STATE_RECOVER;

	for (port = 1; port <= hubd->h_hub_descr.bNbrPorts; port++) {
		USB_DPRINTF_L3(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "hubd_restore_device_state: port=%d", port);

		/*
		 * the childen_dips list may have dips that have been
		 * already deallocated. we only get a post_detach notification
		 * but not a destroy notification
		 */
		ch_dip = hubd->h_children_dips[port];
		if (ch_dip) {
			/* get port status */
			(void) hubd_determine_port_status(hubd, port,
			    &status, &change, PORT_CHANGE_CSC);

			/* check if it is truly connected */
			if (status & PORT_STATUS_CCS) {
				/*
				 * Now reset port and assign the device
				 * its original address
				 */
				retry = 0;
				do {
					(void) hubd_reset_port(hubd, port);

					/* required for ppx */
					(void) hubd_enable_port(hubd, port);

					if (retry) {
						mutex_exit(HUBD_MUTEX(hubd));
						delay(drv_usectohz(
						    hubd_device_delay/2));
						mutex_enter(HUBD_MUTEX(hubd));
					}

					rval = hubd_setdevaddr(hubd, port);
					retry++;
				} while ((rval != USB_SUCCESS) &&
				    (retry < hubd_retry_enumerate));

				hubd_setdevconfig(hubd, port);

				if (hub_prev_state == USB_DEV_DISCONNECTED) {
					/* post a connect event */
					mutex_exit(HUBD_MUTEX(hubd));
					hubd_post_event(hubd, port,
					    USBA_EVENT_TAG_HOT_INSERTION);
					mutex_enter(HUBD_MUTEX(hubd));
				} else {
					/*
					 * Since we have this device connected
					 * mark it reinserted to prevent
					 * cleanup thread from stepping in.
					 */
					mutex_exit(HUBD_MUTEX(hubd));
					mutex_enter(&(DEVI(ch_dip)->devi_lock));
					DEVI_SET_DEVICE_REINSERTED(ch_dip);
					mutex_exit(&(DEVI(ch_dip)->devi_lock));

					/*
					 * reopen pipes for children for
					 * their DDI_RESUME
					 */
					rval = usba_persistent_pipe_open(
					    usba_get_usba_device(ch_dip));
					mutex_enter(HUBD_MUTEX(hubd));
					ASSERT(rval == USB_SUCCESS);
				}
			} else {
				/*
				 * Mark this dip for deletion as the device
				 * is not physically present, and schedule
				 * cleanup thread upon post resume
				 */
				mutex_exit(HUBD_MUTEX(hubd));

				USB_DPRINTF_L2(DPRINT_MASK_ATTA,
				    hubd->h_log_handle,
				    "hubd_restore_device_state: "
				    "dip=%p on port=%d marked for cleanup",
				    (void *)ch_dip, port);
				mutex_enter(&(DEVI(ch_dip)->devi_lock));
				DEVI_SET_DEVICE_REMOVED(ch_dip);
				mutex_exit(&(DEVI(ch_dip)->devi_lock));

				mutex_enter(HUBD_MUTEX(hubd));
			}
		} else if (ehci_root_hub) {
			/* get port status */
			(void) hubd_determine_port_status(hubd, port,
			    &status, &change, PORT_CHANGE_CSC);

			/* check if it is truly connected */
			if (status & PORT_STATUS_CCS) {
				/*
				 * reset the port to find out if we have
				 * 2.0 device connected or 1.X. A 2.0
				 * device will still be seen as connected,
				 * while a 1.X device will switch over to
				 * the companion controller.
				 */
				(void) hubd_reset_port(hubd, port);

				(void) hubd_determine_port_status(hubd, port,
				    &status, &change, PORT_CHANGE_CSC);

				if (status &
				    (PORT_STATUS_CCS | PORT_STATUS_HSDA)) {
					/*
					 * We have a USB 2.0 device
					 * connected. Power cycle this port
					 * so that hotplug thread can
					 * enumerate this device.
					 */
					(void) hubd_toggle_port(hubd, port);
				} else {
					USB_DPRINTF_L2(DPRINT_MASK_ATTA,
					    hubd->h_log_handle,
					    "hubd_restore_device_state: "
					    "device on port %d switched over",
					    port);
				}
			}

		}
	}


	/* if the device had remote wakeup earlier, enable it again */
	if (hubd->h_hubpm->hubp_wakeup_enabled) {
		mutex_exit(HUBD_MUTEX(hubd));
		(void) usb_handle_remote_wakeup(hubd->h_dip,
		    USB_REMOTE_WAKEUP_ENABLE);
		mutex_enter(HUBD_MUTEX(hubd));
	}

	hubd->h_dev_state = USB_DEV_ONLINE;
	hubd_start_polling(hubd, 0);
	(void) hubd_pm_idle_component(hubd, dip, 0);
	mutex_exit(HUBD_MUTEX(hubd));
}


/*
 * hubd_cleanup:
 *	cleanup hubd and deallocate. this function is called for
 *	handling attach failures and detaching including dynamic
 *	reconfiguration. If called from attaching, it must clean
 *	up the whole thing and return success.
 */
/*ARGSUSED*/
static int
hubd_cleanup(dev_info_t *dip, hubd_t *hubd)
{
	int		circ, rval, old_dev_state;
	hub_power_t	*hubpm;
#ifdef DEBUG
	usb_port_t	port;
#endif

	USB_DPRINTF_L4(DPRINT_MASK_ATTA, hubd->h_log_handle,
	    "hubd_cleanup:");

	if ((hubd->h_init_state & HUBD_LOCKS_DONE) == 0) {
		goto done;
	}

	/* ensure we are the only one active */
	ndi_devi_enter(dip, &circ);

	mutex_enter(HUBD_MUTEX(hubd));

	/* Cleanup failure is only allowed if called from detach */
	if (DEVI_IS_DETACHING(dip)) {
		dev_info_t *rh_dip = hubd->h_usba_device->usb_root_hub_dip;

		/*
		 * We are being called from detach.
		 * Fail immediately if the hotplug thread is running
		 * else set the dev_state to disconnected so that
		 * hotplug thread just exits without doing anything.
		 */
		if (hubd->h_bus_ctls || hubd->h_bus_pwr ||
		    hubd->h_hotplug_thread) {
			mutex_exit(HUBD_MUTEX(hubd));
			ndi_devi_exit(dip, circ);

			USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
			    "hubd_cleanup: hotplug thread/bus ctl active "
			    "- failing detach");

			return (USB_FAILURE);
		}

		/*
		 * if the deathrow thread is still active or about
		 * to become active, fail detach
		 * the roothup can only be detached if nexus drivers
		 * are unloaded or explicitly offlined
		 */
		if (rh_dip == dip) {
			if (hubd->h_cleanup_needed ||
			    hubd->h_cleanup_active) {
				mutex_exit(HUBD_MUTEX(hubd));
				ndi_devi_exit(dip, circ);

				USB_DPRINTF_L2(DPRINT_MASK_ATTA,
				    hubd->h_log_handle,
				    "hubd_cleanup: deathrow still active?"
				    "- failing detach");

				return (USB_FAILURE);
			}
		}
	}

	old_dev_state = hubd->h_dev_state;
	hubd->h_dev_state = USB_DEV_DISCONNECTED;

	USB_DPRINTF_L4(DPRINT_MASK_ATTA, hubd->h_log_handle,
	    "hubd_cleanup: stop polling");
	hubd_close_intr_pipe(hubd);

	ASSERT((hubd->h_bus_ctls || hubd->h_bus_pwr ||
	    hubd->h_hotplug_thread) == 0);
	mutex_exit(HUBD_MUTEX(hubd));

	/*
	 * deallocate events, if events are still registered
	 * (ie. children still attached) then we have to fail the detach
	 */
	if (hubd->h_ndi_event_hdl) {

		rval = ndi_event_free_hdl(hubd->h_ndi_event_hdl);
		if (DEVI_IS_ATTACHING(dip)) {

			/* It must return success if attaching. */
			ASSERT(rval == NDI_SUCCESS);

		} else if (rval != NDI_SUCCESS) {

			USB_DPRINTF_L2(DPRINT_MASK_ALL, hubd->h_log_handle,
			    "hubd_cleanup: ndi_event_free_hdl failed");
			ndi_devi_exit(dip, circ);

			return (USB_FAILURE);

		}
	}

	mutex_enter(HUBD_MUTEX(hubd));

	if (hubd->h_init_state & HUBD_CHILDREN_CREATED) {
#ifdef DEBUG
		for (port = 1; port <= hubd->h_hub_descr.bNbrPorts; port++) {
			ASSERT(hubd->h_usba_devices[port] == NULL);
			ASSERT(hubd->h_children_dips[port] == NULL);
		}
#endif
		kmem_free(hubd->h_children_dips, hubd->h_cd_list_length);
		kmem_free(hubd->h_usba_devices, hubd->h_cd_list_length);
	}

	/*
	 * Disable the event callbacks first, after this point, event
	 * callbacks will never get called. Note we shouldn't hold
	 * mutex while unregistering events because there may be a
	 * competing event callback thread. Event callbacks are done
	 * with ndi mutex held and this can cause a potential deadlock.
	 * Note that cleanup can't fail after deregistration of events.
	 */
	if (hubd->h_init_state &  HUBD_EVENTS_REGISTERED) {
		mutex_exit(HUBD_MUTEX(hubd));
		usb_unregister_event_cbs(dip, &hubd_events);
		hubd_unregister_cpr_callback(hubd);
		mutex_enter(HUBD_MUTEX(hubd));
	}

	/* restore the old dev state so that device can be put into low power */
	hubd->h_dev_state = old_dev_state;
	hubpm = hubd->h_hubpm;

	if ((hubpm) && (hubd->h_dev_state != USB_DEV_DISCONNECTED)) {
		(void) hubd_pm_busy_component(hubd, dip, 0);
		mutex_exit(HUBD_MUTEX(hubd));
		if (hubd->h_hubpm->hubp_wakeup_enabled) {
			/*
			 * Bring the hub to full power before
			 * issuing the disable remote wakeup command
			 */
			(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);

			if ((rval = usb_handle_remote_wakeup(hubd->h_dip,
			    USB_REMOTE_WAKEUP_DISABLE)) != USB_SUCCESS) {
				USB_DPRINTF_L2(DPRINT_MASK_PM,
				    hubd->h_log_handle,
				    "hubd_cleanup: disable remote wakeup "
				    "fails=%d", rval);
			}
		}

		(void) pm_lower_power(hubd->h_dip, 0, USB_DEV_OS_PWR_OFF);

		mutex_enter(HUBD_MUTEX(hubd));
		(void) hubd_pm_idle_component(hubd, dip, 0);
	}

	if (hubpm) {
		if (hubpm->hubp_child_pwrstate) {
			kmem_free(hubpm->hubp_child_pwrstate,
			    MAX_PORTS + 1);
		}
		kmem_free(hubpm, sizeof (hub_power_t));
	}
	mutex_exit(HUBD_MUTEX(hubd));

	USB_DPRINTF_L4(DPRINT_MASK_ATTA, hubd->h_log_handle,
	    "hubd_cleanup: freeing space");

	if (hubd->h_init_state & HUBD_HUBDI_REGISTERED) {
		rval = usba_hubdi_unregister(dip);
		ASSERT(rval == USB_SUCCESS);
	}

	if (hubd->h_init_state & HUBD_LOCKS_DONE) {
		mutex_destroy(HUBD_MUTEX(hubd));
		cv_destroy(&hubd->h_cv_reset_port);
		cv_destroy(&hubd->h_cv_hotplug_dev);
	}

	ndi_devi_exit(dip, circ);

	if (hubd->h_init_state & HUBD_MINOR_NODE_CREATED) {
		ddi_remove_minor_node(dip, NULL);
	}

	if (usba_is_root_hub(dip)) {
		usb_pipe_close(dip, hubd->h_default_pipe,
		    USB_FLAGS_SLEEP | USBA_FLAGS_PRIVILEGED, NULL, NULL);
	}

done:
	if (hubd->h_ancestry_str) {
		kmem_free(hubd->h_ancestry_str, HUBD_APID_NAMELEN);
	}

	usb_client_detach(dip, hubd->h_dev_data);

	usb_free_log_hdl(hubd->h_log_handle);

	if (!usba_is_root_hub(dip)) {
		ddi_soft_state_free(hubd_statep, ddi_get_instance(dip));
	}

	ddi_prop_remove_all(dip);

	return (USB_SUCCESS);
}


/*
 * hubd_determine_port_connection:
 *	Determine which port is in connect status but does not
 *	have connect status change bit set, and mark port change
 *	bit accordingly.
 *	This function is applied during hub attach time.
 */
static usb_port_mask_t
hubd_determine_port_connection(hubd_t	*hubd)
{
	usb_port_t	port;
	usb_hub_descr_t	*hub_descr;
	uint16_t	status;
	uint16_t	change;
	usb_port_mask_t	port_change = 0;

	ASSERT(mutex_owned(HUBD_MUTEX(hubd)));

	hub_descr = &hubd->h_hub_descr;

	for (port = 1; port <= hub_descr->bNbrPorts; port++) {

		(void) hubd_determine_port_status(hubd, port, &status,
		    &change, 0);

		/* Check if port is in connect status */
		if (!(status & PORT_STATUS_CCS)) {

			continue;
		}

		/*
		 * Check if port Connect Status Change bit has been set.
		 * If already set, the connection will be handled by
		 * intr polling callback, not during attach.
		 */
		if (change & PORT_CHANGE_CSC) {

			continue;
		}

		port_change |= 1 << port;
	}

	return (port_change);
}


/*
 * hubd_check_ports:
 *	- get hub descriptor
 *	- check initial port status
 *	- enable power on all ports
 *	- enable polling on ep1
 */
static int
hubd_check_ports(hubd_t  *hubd)
{
	int			rval;
	usb_port_mask_t		port_change = 0;
	hubd_hotplug_arg_t	*arg;

	ASSERT(mutex_owned(HUBD_MUTEX(hubd)));

	USB_DPRINTF_L4(DPRINT_MASK_PORT, hubd->h_log_handle,
	    "hubd_check_ports: addr=0x%x", usb_get_addr(hubd->h_dip));

	/*
	 * First turn off all port power
	 */
	if ((rval = hubd_disable_all_port_power(hubd)) != USB_SUCCESS) {

		/* disable whatever was enabled */
		(void) hubd_disable_all_port_power(hubd);

		return (rval);
	}

	/*
	 * do not switch on immediately (instantly on root hub)
	 * and allow time to settle
	 */
	mutex_exit(HUBD_MUTEX(hubd));
	delay(drv_usectohz(10000));
	mutex_enter(HUBD_MUTEX(hubd));

	/*
	 * enable power on all ports so we can see connects
	 */
	if ((rval = hubd_enable_all_port_power(hubd)) != USB_SUCCESS) {
		/* disable whatever was enabled */
		(void) hubd_disable_all_port_power(hubd);

		return (rval);
	}

	/* wait at least 3 frames before accessing devices */
	mutex_exit(HUBD_MUTEX(hubd));
	delay(drv_usectohz(10000));
	mutex_enter(HUBD_MUTEX(hubd));

	/*
	 * allocate arrays for saving the dips of each child per port
	 *
	 * ports go from 1 - n, allocate 1 more entry
	 */
	hubd->h_cd_list_length =
	    (sizeof (dev_info_t **)) * (hubd->h_hub_descr.bNbrPorts + 1);

	hubd->h_children_dips = (dev_info_t **)kmem_zalloc(
	    hubd->h_cd_list_length, KM_SLEEP);
	hubd->h_usba_devices = (usba_device_t **)kmem_zalloc(
	    hubd->h_cd_list_length, KM_SLEEP);

	hubd->h_init_state |= HUBD_CHILDREN_CREATED;

	mutex_exit(HUBD_MUTEX(hubd));
	arg = (hubd_hotplug_arg_t *)kmem_zalloc(
	    sizeof (hubd_hotplug_arg_t), KM_SLEEP);
	mutex_enter(HUBD_MUTEX(hubd));

	if ((rval = hubd_open_intr_pipe(hubd)) != USB_SUCCESS) {
		kmem_free(arg, sizeof (hubd_hotplug_arg_t));

		return (rval);
	}

	hubd_start_polling(hubd, 0);

	/*
	 * Some hub devices, like the embedded hub in the CKS ErgoMagic
	 * keyboard, may only have connection status bit set, but not
	 * have connect status change bit set when a device has been
	 * connected to its downstream port before the hub is enumerated.
	 * Then when the hub is in enumeration, the devices connected to
	 * it cannot be detected by the intr pipe and won't be enumerated.
	 * We need to check such situation here and enumerate the downstream
	 * devices for such hubs.
	 */
	port_change = hubd_determine_port_connection(hubd);

	if (port_change) {
		hubd_pm_busy_component(hubd, hubd->h_dip, 0);

		arg->hubd = hubd;
		arg->hotplug_during_attach = B_TRUE;
		hubd->h_port_change |= port_change;

		USB_DPRINTF_L3(DPRINT_MASK_PORT, hubd->h_log_handle,
		    "hubd_check_ports: port change=0x%x, need to connect",
		    hubd->h_port_change);

		if (usb_async_req(hubd->h_dip, hubd_hotplug_thread,
		    (void *)arg, 0) == USB_SUCCESS) {
			hubd->h_hotplug_thread++;
		} else {
			/* mark this device as idle */
			hubd_pm_idle_component(hubd, hubd->h_dip, 0);
			kmem_free(arg, sizeof (hubd_hotplug_arg_t));
		}
	} else {
		kmem_free(arg, sizeof (hubd_hotplug_arg_t));
	}

	USB_DPRINTF_L4(DPRINT_MASK_ATTA, hubd->h_log_handle,
	    "hubd_check_ports done");

	return (USB_SUCCESS);
}


/*
 * hubd_get_hub_descriptor:
 */
static int
hubd_get_hub_descriptor(hubd_t *hubd)
{
	usb_hub_descr_t	*hub_descr = &hubd->h_hub_descr;
	mblk_t		*data = NULL;
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	uint16_t	length;
	int		rval;
	usb_req_attrs_t attr = 0;

	USB_DPRINTF_L4(DPRINT_MASK_HUB, hubd->h_log_handle,
	    "hubd_get_hub_descriptor:");

	if ((hubd->h_dev_data->dev_descr->idVendor == USB_HUB_INTEL_VID) &&
	    (hubd->h_dev_data->dev_descr->idProduct == USB_HUB_INTEL_PID)) {
		attr = USB_ATTRS_SHORT_XFER_OK;
	}

	ASSERT(mutex_owned(HUBD_MUTEX(hubd)));
	ASSERT(hubd->h_default_pipe != 0);

	/* get hub descriptor length first by requesting 8 bytes only */
	mutex_exit(HUBD_MUTEX(hubd));

	if ((rval = usb_pipe_sync_ctrl_xfer(hubd->h_dip,
	    hubd->h_default_pipe,
	    HUB_CLASS_REQ_TYPE,
	    USB_REQ_GET_DESCR,		/* bRequest */
	    USB_DESCR_TYPE_SETUP_HUB,	/* wValue */
	    0,				/* wIndex */
	    8,				/* wLength */
	    &data, 0,
	    &completion_reason, &cb_flags, 0)) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "get hub descriptor failed: cr=%d cb_fl=0x%x rval=%d",
		    completion_reason, cb_flags, rval);
		freemsg(data);
		mutex_enter(HUBD_MUTEX(hubd));

		return (rval);
	}

	length = *(data->b_rptr);

	if (length > 8) {
		freemsg(data);
		data = NULL;

		/* get complete hub descriptor */
		rval = usb_pipe_sync_ctrl_xfer(hubd->h_dip,
		    hubd->h_default_pipe,
		    HUB_CLASS_REQ_TYPE,
		    USB_REQ_GET_DESCR,		/* bRequest */
		    USB_DESCR_TYPE_SETUP_HUB,	/* wValue */
		    0,				/* wIndex */
		    length,			/* wLength */
		    &data, attr,
		    &completion_reason, &cb_flags, 0);

		/*
		 * Hub descriptor data less than 9 bytes is not valid and
		 * may cause trouble if we use it. See USB2.0 Tab11-13.
		 */
		if ((rval != USB_SUCCESS) || (MBLKL(data) <= 8)) {
			USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
			    "get hub descriptor failed: "
			    "cr=%d cb_fl=0x%x rval=%d, len=%ld",
			    completion_reason, cb_flags, rval,
			    (data)?MBLKL(data):0);
			freemsg(data);
			mutex_enter(HUBD_MUTEX(hubd));

			return (rval);
		}
	}

	mutex_enter(HUBD_MUTEX(hubd));

	/* parse the hub descriptor */
	/* only 32 ports are supported at present */
	ASSERT(*(data->b_rptr + 2) <= 32);
	if (usb_parse_CV_descr("cccscccccc",
	    data->b_rptr, MBLKL(data),
	    (void *)hub_descr, sizeof (usb_hub_descr_t)) == 0) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "parsing hub descriptor failed");

		freemsg(data);

		return (USB_FAILURE);
	}

	freemsg(data);

	USB_DPRINTF_L4(DPRINT_MASK_ATTA, hubd->h_log_handle,
	    "rval=0x%x bNbrPorts=0x%x wHubChars=0x%x "
	    "PwrOn2PwrGood=0x%x HubContrCurrent=%dmA", rval,
	    hub_descr->bNbrPorts, hub_descr->wHubCharacteristics,
	    hub_descr->bPwrOn2PwrGood, hub_descr->bHubContrCurrent);

	if (hub_descr->bNbrPorts > MAX_PORTS) {
		USB_DPRINTF_L0(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "Hub driver supports max of %d ports on hub. "
		    "Hence using the first %d port of %d ports available",
		    MAX_PORTS, MAX_PORTS, hub_descr->bNbrPorts);

		hub_descr->bNbrPorts = MAX_PORTS;
	}

	return (USB_SUCCESS);
}


/*
 * hubd_get_hub_status_words:
 */
static int
hubd_get_hub_status_words(hubd_t *hubd, uint16_t *status)
{
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	mblk_t		*data = NULL;

	ASSERT(mutex_owned(HUBD_MUTEX(hubd)));

	mutex_exit(HUBD_MUTEX(hubd));

	if (usb_pipe_sync_ctrl_xfer(hubd->h_dip, hubd->h_default_pipe,
	    HUB_CLASS_REQ_TYPE,
	    USB_REQ_GET_STATUS,
	    0,
	    0,
	    GET_STATUS_LENGTH,
	    &data, 0,
	    &completion_reason, &cb_flags, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_HUB, hubd->h_log_handle,
		    "get hub status failed: cr=%d cb=0x%x",
		    completion_reason, cb_flags);

		if (data) {
			freemsg(data);
		}

		mutex_enter(HUBD_MUTEX(hubd));

		return (USB_FAILURE);
	}

	mutex_enter(HUBD_MUTEX(hubd));

	status[0] = (*(data->b_rptr + 1) << 8) | *(data->b_rptr);
	status[1] = (*(data->b_rptr + 3) << 8) | *(data->b_rptr + 2);

	USB_DPRINTF_L3(DPRINT_MASK_HUB, hubd->h_log_handle,
	    "hub status=0x%x change=0x%x", status[0], status[1]);

	freemsg(data);

	return (USB_SUCCESS);
}


/*
 * hubd_open_intr_pipe:
 *	we read all descriptors first for curiosity and then simply
 *	open the pipe
 */
static int
hubd_open_intr_pipe(hubd_t	*hubd)
{
	int			rval;

	USB_DPRINTF_L4(DPRINT_MASK_HUB, hubd->h_log_handle,
	    "hubd_open_intr_pipe:");

	ASSERT(hubd->h_intr_pipe_state == HUBD_INTR_PIPE_IDLE);

	hubd->h_intr_pipe_state = HUBD_INTR_PIPE_OPENING;
	mutex_exit(HUBD_MUTEX(hubd));

	if ((rval = usb_pipe_open(hubd->h_dip,
	    &hubd->h_ep1_descr, &hubd->h_pipe_policy,
	    0, &hubd->h_ep1_ph)) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_HUB, hubd->h_log_handle,
		    "open intr pipe failed (%d)", rval);

		mutex_enter(HUBD_MUTEX(hubd));
		hubd->h_intr_pipe_state = HUBD_INTR_PIPE_IDLE;

		return (rval);
	}

	mutex_enter(HUBD_MUTEX(hubd));
	hubd->h_intr_pipe_state = HUBD_INTR_PIPE_ACTIVE;

	USB_DPRINTF_L4(DPRINT_MASK_HUB, hubd->h_log_handle,
	    "open intr pipe succeeded, ph=0x%p", (void *)hubd->h_ep1_ph);

	return (USB_SUCCESS);
}


/*
 * hubd_start_polling:
 *	start or restart the polling
 */
static void
hubd_start_polling(hubd_t *hubd, int always)
{
	usb_intr_req_t	*reqp;
	int			rval;
	usb_pipe_state_t	pipe_state;

	USB_DPRINTF_L4(DPRINT_MASK_HUB, hubd->h_log_handle,
	    "start polling: always=%d dev_state=%d pipe_state=%d\n\t"
	    "thread=%d ep1_ph=0x%p",
	    always, hubd->h_dev_state, hubd->h_intr_pipe_state,
	    hubd->h_hotplug_thread, (void *)hubd->h_ep1_ph);

	/*
	 * start or restart polling on the intr pipe
	 * only if hotplug thread is not running
	 */
	if ((always == HUBD_ALWAYS_START_POLLING) ||
	    ((hubd->h_dev_state == USB_DEV_ONLINE) &&
	    (hubd->h_intr_pipe_state == HUBD_INTR_PIPE_ACTIVE) &&
	    (hubd->h_hotplug_thread == 0) && hubd->h_ep1_ph)) {
		USB_DPRINTF_L4(DPRINT_MASK_HUB, hubd->h_log_handle,
		    "start polling requested");

		reqp = usb_alloc_intr_req(hubd->h_dip, 0, USB_FLAGS_SLEEP);

		reqp->intr_client_private = (usb_opaque_t)hubd;
		reqp->intr_attributes = USB_ATTRS_SHORT_XFER_OK |
		    USB_ATTRS_AUTOCLEARING;
		reqp->intr_len = hubd->h_ep1_descr.wMaxPacketSize;
		reqp->intr_cb = hubd_read_cb;
		reqp->intr_exc_cb = hubd_exception_cb;
		mutex_exit(HUBD_MUTEX(hubd));
		if ((rval = usb_pipe_intr_xfer(hubd->h_ep1_ph, reqp,
		    USB_FLAGS_SLEEP)) != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_HUB, hubd->h_log_handle,
			    "start polling failed, rval=%d", rval);
			usb_free_intr_req(reqp);
		}

		rval = usb_pipe_get_state(hubd->h_ep1_ph, &pipe_state,
		    USB_FLAGS_SLEEP);
		if (pipe_state != USB_PIPE_STATE_ACTIVE) {
			USB_DPRINTF_L2(DPRINT_MASK_PORT, hubd->h_log_handle,
			    "intr pipe state=%d, rval=%d", pipe_state, rval);
		}
		USB_DPRINTF_L4(DPRINT_MASK_HUB, hubd->h_log_handle,
		    "start polling request 0x%p", (void *)reqp);

		mutex_enter(HUBD_MUTEX(hubd));
	}
}


/*
 * hubd_stop_polling
 *	stop polling but do not close the pipe
 */
static void
hubd_stop_polling(hubd_t *hubd)
{
	int			rval;
	usb_pipe_state_t	pipe_state;

	if (hubd->h_ep1_ph) {
		USB_DPRINTF_L4(DPRINT_MASK_PORT, hubd->h_log_handle,
		    "hubd_stop_polling:");
		hubd->h_intr_pipe_state = HUBD_INTR_PIPE_STOPPED;
		mutex_exit(HUBD_MUTEX(hubd));

		usb_pipe_stop_intr_polling(hubd->h_ep1_ph, USB_FLAGS_SLEEP);
		rval = usb_pipe_get_state(hubd->h_ep1_ph, &pipe_state,
		    USB_FLAGS_SLEEP);

		if (pipe_state != USB_PIPE_STATE_IDLE) {
			USB_DPRINTF_L2(DPRINT_MASK_PORT, hubd->h_log_handle,
			    "intr pipe state=%d, rval=%d", pipe_state, rval);
		}
		mutex_enter(HUBD_MUTEX(hubd));
		if (hubd->h_intr_pipe_state == HUBD_INTR_PIPE_STOPPED) {
			hubd->h_intr_pipe_state = HUBD_INTR_PIPE_ACTIVE;
		}
	}
}


/*
 * hubd_close_intr_pipe:
 *	close the pipe (which also stops the polling
 *	and wait for the hotplug thread to exit
 */
static void
hubd_close_intr_pipe(hubd_t *hubd)
{
	USB_DPRINTF_L4(DPRINT_MASK_HUB, hubd->h_log_handle,
	    "hubd_close_intr_pipe:");

	/*
	 * Now that no async operation is outstanding on pipe,
	 * we can change the state to HUBD_INTR_PIPE_CLOSING
	 */
	hubd->h_intr_pipe_state = HUBD_INTR_PIPE_CLOSING;

	ASSERT(hubd->h_hotplug_thread == 0);

	if (hubd->h_ep1_ph) {
		mutex_exit(HUBD_MUTEX(hubd));
		usb_pipe_close(hubd->h_dip, hubd->h_ep1_ph, USB_FLAGS_SLEEP,
		    NULL, NULL);
		mutex_enter(HUBD_MUTEX(hubd));
		hubd->h_ep1_ph = NULL;
	}

	hubd->h_intr_pipe_state = HUBD_INTR_PIPE_IDLE;
}


/*
 * hubd_exception_cb
 *	interrupt ep1 exception callback function.
 *	this callback executes in taskq thread context and assumes
 *	autoclearing
 */
/*ARGSUSED*/
static void
hubd_exception_cb(usb_pipe_handle_t pipe, usb_intr_req_t *reqp)
{
	hubd_t		*hubd = (hubd_t *)(reqp->intr_client_private);

	USB_DPRINTF_L2(DPRINT_MASK_CALLBACK, hubd->h_log_handle,
	    "hubd_exception_cb: "
	    "req=0x%p cr=%d data=0x%p cb_flags=0x%x", (void *)reqp,
	    reqp->intr_completion_reason, (void *)reqp->intr_data,
	    reqp->intr_cb_flags);

	ASSERT((reqp->intr_cb_flags & USB_CB_INTR_CONTEXT) == 0);

	mutex_enter(HUBD_MUTEX(hubd));
	(void) hubd_pm_busy_component(hubd, hubd->h_dip, 0);

	switch (reqp->intr_completion_reason) {
	case USB_CR_PIPE_RESET:
		/* only restart polling after autoclearing */
		if ((hubd->h_intr_pipe_state == HUBD_INTR_PIPE_ACTIVE) &&
		    (hubd->h_port_reset_wait == 0)) {
			hubd_start_polling(hubd, 0);
		}

		break;
	case USB_CR_DEV_NOT_RESP:
	case USB_CR_STOPPED_POLLING:
	case USB_CR_PIPE_CLOSING:
	case USB_CR_UNSPECIFIED_ERR:
		/* never restart polling on these conditions */
	default:
		/* for all others, wait for the autoclearing PIPE_RESET cb */

		break;
	}

	usb_free_intr_req(reqp);
	(void) hubd_pm_idle_component(hubd, hubd->h_dip, 0);
	mutex_exit(HUBD_MUTEX(hubd));
}


/*
 * helper function to convert LE bytes to a portmask
 */
static usb_port_mask_t
hubd_mblk2portmask(mblk_t *data)
{
	int len = min(MBLKL(data), sizeof (usb_port_mask_t));
	usb_port_mask_t rval = 0;
	int i;

	for (i = 0; i < len; i++) {
		rval |= data->b_rptr[i] << (i * 8);
	}

	return (rval);
}


/*
 * hubd_read_cb:
 *	interrupt ep1 callback function
 *
 *	the status indicates just a change on the pipe with no indication
 *	of what the change was
 *
 *	known conditions:
 *		- reset port completion
 *		- connect
 *		- disconnect
 *
 *	for handling the hotplugging, create a new thread that can do
 *	synchronous usba calls
 */
static void
hubd_read_cb(usb_pipe_handle_t pipe, usb_intr_req_t *reqp)
{
	hubd_t		*hubd = (hubd_t *)(reqp->intr_client_private);
	size_t		length;
	mblk_t		*data = reqp->intr_data;
	int		mem_flag = 0;
	hubd_hotplug_arg_t *arg;

	USB_DPRINTF_L4(DPRINT_MASK_HUB, hubd->h_log_handle,
	    "hubd_read_cb: ph=0x%p req=0x%p", (void *)pipe, (void *)reqp);

	ASSERT((reqp->intr_cb_flags & USB_CB_INTR_CONTEXT) == 0);

	/*
	 * At present, we are not handling notification for completion of
	 * asynchronous pipe reset, for which this data ptr could be NULL
	 */

	if (data == NULL) {
		usb_free_intr_req(reqp);

		return;
	}

	arg = (hubd_hotplug_arg_t *)kmem_zalloc(
	    sizeof (hubd_hotplug_arg_t), KM_SLEEP);
	mem_flag = 1;

	mutex_enter(HUBD_MUTEX(hubd));

	if ((hubd->h_dev_state == USB_DEV_SUSPENDED) ||
	    (hubd->h_intr_pipe_state != HUBD_INTR_PIPE_ACTIVE)) {
		mutex_exit(HUBD_MUTEX(hubd));
		usb_free_intr_req(reqp);
		kmem_free(arg, sizeof (hubd_hotplug_arg_t));

		return;
	}

	ASSERT(hubd->h_ep1_ph == pipe);

	length = MBLKL(data);

	/*
	 * Only look at the data and startup the hotplug thread if
	 * there actually is data.
	 */
	if (length != 0) {
		usb_port_mask_t port_change = hubd_mblk2portmask(data);

		/*
		 * if a port change was already reported and we are waiting for
		 * reset port completion then wake up the hotplug thread which
		 * should be waiting on reset port completion
		 *
		 * if there is disconnect event instead of reset completion, let
		 * the hotplug thread figure this out
		 */

		/* remove the reset wait bits from the status */
		hubd->h_port_change |= port_change &
		    ~hubd->h_port_reset_wait;

		USB_DPRINTF_L3(DPRINT_MASK_CALLBACK, hubd->h_log_handle,
		    "port change=0x%x port_reset_wait=0x%x",
		    hubd->h_port_change, hubd->h_port_reset_wait);

		/* there should be only one reset bit active at the time */
		if (hubd->h_port_reset_wait & port_change) {
			hubd->h_port_reset_wait = 0;
			cv_signal(&hubd->h_cv_reset_port);
		}

		/*
		 * kick off the thread only if device is ONLINE and it is not
		 * during attaching or detaching
		 */
		if ((hubd->h_dev_state == USB_DEV_ONLINE) &&
		    (!DEVI_IS_ATTACHING(hubd->h_dip)) &&
		    (!DEVI_IS_DETACHING(hubd->h_dip)) &&
		    (hubd->h_port_change) &&
		    (hubd->h_hotplug_thread == 0)) {
			USB_DPRINTF_L3(DPRINT_MASK_CALLBACK, hubd->h_log_handle,
			    "creating hotplug thread: "
			    "dev_state=%d", hubd->h_dev_state);

			/*
			 * Mark this device as busy. The will be marked idle
			 * if the async req fails or at the exit of  hotplug
			 * thread
			 */
			(void) hubd_pm_busy_component(hubd, hubd->h_dip, 0);

			arg->hubd = hubd;
			arg->hotplug_during_attach = B_FALSE;

			if (usb_async_req(hubd->h_dip,
			    hubd_hotplug_thread,
			    (void *)arg, 0) == USB_SUCCESS) {
				hubd->h_hotplug_thread++;
				mem_flag = 0;
			} else {
				/* mark this device as idle */
				(void) hubd_pm_idle_component(hubd,
				    hubd->h_dip, 0);
			}
		}
	}
	mutex_exit(HUBD_MUTEX(hubd));

	if (mem_flag == 1) {
		kmem_free(arg, sizeof (hubd_hotplug_arg_t));
	}

	usb_free_intr_req(reqp);
}


/*
 * hubd_hotplug_thread:
 *	handles resetting of port, and creating children
 *
 *	the ports to check are indicated in h_port_change bit mask
 * XXX note that one time poll doesn't work on the root hub
 */
static void
hubd_hotplug_thread(void *arg)
{
	hubd_hotplug_arg_t *hd_arg = (hubd_hotplug_arg_t *)arg;
	hubd_t		*hubd = hd_arg->hubd;
	boolean_t	attach_flg = hd_arg->hotplug_during_attach;
	usb_port_t	port;
	uint16_t	nports;
	uint16_t	status, change;
	hub_power_t	*hubpm;
	dev_info_t	*hdip = hubd->h_dip;
	dev_info_t	*rh_dip = hubd->h_usba_device->usb_root_hub_dip;
	dev_info_t	*child_dip;
	boolean_t	online_child = B_FALSE;
	boolean_t	offline_child = B_FALSE;
	boolean_t	pwrup_child = B_FALSE;
	int		prh_circ, rh_circ, chld_circ, circ, old_state;

	USB_DPRINTF_L4(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "hubd_hotplug_thread:  started");

	/*
	 * Before console is init'd, we temporarily block the hotplug
	 * threads so that BUS_CONFIG_ONE through hubd_bus_config() can be
	 * processed quickly. This reduces the time needed for vfs_mountroot()
	 * to mount the root FS from a USB disk. And on SPARC platform,
	 * in order to load 'consconfig' successfully after OBP is gone,
	 * we need to check 'modrootloaded' to make sure root filesystem is
	 * available.
	 */
	while (!modrootloaded || !consconfig_console_is_ready()) {
		delay(drv_usectohz(10000));
	}

	kmem_free(arg, sizeof (hubd_hotplug_arg_t));

	/*
	 * if our bus power entry point is active, process the change
	 * on the next notification of interrupt pipe
	 */
	mutex_enter(HUBD_MUTEX(hubd));
	if (hubd->h_bus_pwr || (hubd->h_hotplug_thread > 1)) {
		hubd->h_hotplug_thread--;

		/* mark this device as idle */
		hubd_pm_idle_component(hubd, hubd->h_dip, 0);
		mutex_exit(HUBD_MUTEX(hubd));

		USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "hubd_hotplug_thread: "
		    "bus_power in progress/hotplugging undesirable - quit");

		return;
	}
	mutex_exit(HUBD_MUTEX(hubd));

	ndi_hold_devi(hdip); /* so we don't race with detach */

	mutex_enter(HUBD_MUTEX(hubd));

	/* is this the root hub? */
	if (hdip == rh_dip) {
		if (hubd->h_dev_state == USB_DEV_PWRED_DOWN) {
			hubpm = hubd->h_hubpm;

			/* mark the root hub as full power */
			hubpm->hubp_current_power = USB_DEV_OS_FULL_PWR;
			hubpm->hubp_time_at_full_power = gethrtime();
			mutex_exit(HUBD_MUTEX(hubd));

			USB_DPRINTF_L4(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
			    "hubd_hotplug_thread: call pm_power_has_changed");

			(void) pm_power_has_changed(hdip, 0,
			    USB_DEV_OS_FULL_PWR);

			mutex_enter(HUBD_MUTEX(hubd));
			hubd->h_dev_state = USB_DEV_ONLINE;
		}

	} else {
		USB_DPRINTF_L4(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "hubd_hotplug_thread: not root hub");
	}

	mutex_exit(HUBD_MUTEX(hubd));

	/*
	 * this ensures one hotplug activity per system at a time.
	 * we enter the parent PCI node to have this serialization.
	 * this also excludes ioctls and deathrow thread
	 * (a bit crude but easier to debug)
	 */
	ndi_devi_enter(ddi_get_parent(rh_dip), &prh_circ);
	ndi_devi_enter(rh_dip, &rh_circ);

	/* exclude other threads */
	ndi_devi_enter(hdip, &circ);
	mutex_enter(HUBD_MUTEX(hubd));

	ASSERT(hubd->h_intr_pipe_state == HUBD_INTR_PIPE_ACTIVE);

	nports = hubd->h_hub_descr.bNbrPorts;

	hubd_stop_polling(hubd);

	while ((hubd->h_dev_state == USB_DEV_ONLINE) &&
	    (hubd->h_port_change)) {
		/*
		 * The 0th bit is the hub status change bit.
		 * handle loss of local power here
		 */
		if (hubd->h_port_change & HUB_CHANGE_STATUS) {
			USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
			    "hubd_hotplug_thread: hub status change!");

			/*
			 * This should be handled properly.  For now,
			 * mask off the bit.
			 */
			hubd->h_port_change &= ~HUB_CHANGE_STATUS;

			/*
			 * check and ack hub status
			 * this causes stall conditions
			 * when local power is removed
			 */
			(void) hubd_get_hub_status(hubd);
		}

		for (port = 1; port <= nports; port++) {
			usb_port_mask_t port_mask;
			boolean_t was_connected;

			port_mask = 1 << port;
			was_connected =
			    (hubd->h_port_state[port] & PORT_STATUS_CCS) &&
			    (hubd->h_children_dips[port]);

			USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
			    "hubd_hotplug_thread: "
			    "port %d mask=0x%x change=0x%x connected=0x%x",
			    port, port_mask, hubd->h_port_change,
			    was_connected);

			/*
			 * is this a port connection that changed?
			 */
			if ((hubd->h_port_change & port_mask) == 0) {

				continue;
			}
			hubd->h_port_change &= ~port_mask;

			/* ack all changes */
			(void) hubd_determine_port_status(hubd, port,
			    &status, &change, HUBD_ACK_ALL_CHANGES);

			USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
			    "handle port %d:\n\t"
			    "new status=0x%x change=0x%x was_conn=0x%x ",
			    port, status, change, was_connected);

			/* Recover a disabled port */
			if (change & PORT_CHANGE_PESC) {
				USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG,
				    hubd->h_log_handle,
				    "port%d Disabled - "
				    "status=0x%x, change=0x%x",
				    port, status, change);

				/*
				 * if the port was connected and is still
				 * connected, recover the port
				 */
				if (was_connected && (status &
				    PORT_STATUS_CCS)) {
					online_child |=
					    (hubd_recover_disabled_port(hubd,
					    port) == USB_SUCCESS);
				}
			}

			/*
			 * Now check what changed on the port
			 */
			if ((change & PORT_CHANGE_CSC) || attach_flg) {
				if ((status & PORT_STATUS_CCS) &&
				    (!was_connected)) {
					/* new device plugged in */
					online_child |=
					    (hubd_handle_port_connect(hubd,
					    port) == USB_SUCCESS);

				} else if ((status & PORT_STATUS_CCS) &&
				    was_connected) {
					/*
					 * In this case we can never be sure
					 * if the device indeed got hotplugged
					 * or the hub is falsely reporting the
					 * change.
					 */
					child_dip = hubd->h_children_dips[port];

					mutex_exit(HUBD_MUTEX(hubd));
					/*
					 * this ensures we do not race with
					 * other threads which are detaching
					 * the child driver at the same time.
					 */
					ndi_devi_enter(child_dip, &chld_circ);
					/*
					 * Now check if the driver remains
					 * attached.
					 */
					if (i_ddi_devi_attached(child_dip)) {
						/*
						 * first post a disconnect event
						 * to the child.
						 */
						hubd_post_event(hubd, port,
						    USBA_EVENT_TAG_HOT_REMOVAL);
						mutex_enter(HUBD_MUTEX(hubd));

						/*
						 * then reset the port and
						 * recover the device
						 */
						online_child |=
						    (hubd_handle_port_connect(
						    hubd, port) == USB_SUCCESS);

						mutex_exit(HUBD_MUTEX(hubd));
					}

					ndi_devi_exit(child_dip, chld_circ);
					mutex_enter(HUBD_MUTEX(hubd));
				} else if (was_connected) {
					/* this is a disconnect */
					mutex_exit(HUBD_MUTEX(hubd));
					hubd_post_event(hubd, port,
					    USBA_EVENT_TAG_HOT_REMOVAL);
					mutex_enter(HUBD_MUTEX(hubd));

					offline_child = B_TRUE;
				}
			}

			/*
			 * Check if any port is coming out of suspend
			 */
			if (change & PORT_CHANGE_PSSC) {
				/* a resuming device could have disconnected */
				if (was_connected &&
				    hubd->h_children_dips[port]) {

					/* device on this port resuming */
					dev_info_t *dip;

					dip = hubd->h_children_dips[port];

					/*
					 * Don't raise power on detaching child
					 */
					if (!DEVI_IS_DETACHING(dip)) {
						/*
						 * As this child is not
						 * detaching, we set this
						 * flag, causing bus_ctls
						 * to stall detach till
						 * pm_raise_power returns
						 * and flag it for a deferred
						 * raise_power.
						 *
						 * pm_raise_power is deferred
						 * because we need to release
						 * the locks first.
						 */
						hubd->h_port_state[port] |=
						    HUBD_CHILD_RAISE_POWER;
						pwrup_child = B_TRUE;
						mutex_exit(HUBD_MUTEX(hubd));

						/*
						 * make sure that child
						 * doesn't disappear
						 */
						ndi_hold_devi(dip);

						mutex_enter(HUBD_MUTEX(hubd));
					}
				}
			}

			/*
			 * Check if the port is over-current
			 */
			if (change & PORT_CHANGE_OCIC) {
				USB_DPRINTF_L1(DPRINT_MASK_HOTPLUG,
				    hubd->h_log_handle,
				    "Port%d in over current condition, "
				    "please check the attached device to "
				    "clear the condition. The system will "
				    "try to recover the port, but if not "
				    "successful, you need to re-connect "
				    "the hub or reboot the system to bring "
				    "the port back to work", port);

				if (!(status & PORT_STATUS_PPS)) {
					/*
					 * Try to enable port power, but
					 * possibly fail. Ignore failure
					 */
					(void) hubd_enable_port_power(hubd,
					    port);

					/*
					 * Delay some time to avoid
					 * over-current event to happen
					 * too frequently in some cases
					 */
					mutex_exit(HUBD_MUTEX(hubd));
					delay(drv_usectohz(500000));
					mutex_enter(HUBD_MUTEX(hubd));
				}
			}
		}
	}

	/* release locks so we can do a devfs_clean */
	mutex_exit(HUBD_MUTEX(hubd));

	/* delete cached dv_node's but drop locks first */
	ndi_devi_exit(hdip, circ);
	ndi_devi_exit(rh_dip, rh_circ);
	ndi_devi_exit(ddi_get_parent(rh_dip), prh_circ);

	(void) devfs_clean(rh_dip, NULL, 0);

	/* now check if any children need onlining */
	if (online_child) {
		USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "hubd_hotplug_thread: onlining children");

		(void) ndi_devi_online(hubd->h_dip, 0);
	}

	/* now check if any disconnected devices need to be cleaned up */
	if (offline_child) {
		USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "hubd_hotplug_thread: scheduling cleanup");

		hubd_schedule_cleanup(hubd->h_usba_device->usb_root_hub_dip);
	}

	mutex_enter(HUBD_MUTEX(hubd));

	/* now raise power on the children that have woken up */
	if (pwrup_child) {
		old_state = hubd->h_dev_state;
		hubd->h_dev_state = USB_DEV_HUB_CHILD_PWRLVL;
		for (port = 1; port <= nports; port++) {
			if (hubd->h_port_state[port] & HUBD_CHILD_RAISE_POWER) {
				dev_info_t *dip = hubd->h_children_dips[port];

				mutex_exit(HUBD_MUTEX(hubd));

				/* Get the device to full power */
				(void) pm_busy_component(dip, 0);
				(void) pm_raise_power(dip, 0,
				    USB_DEV_OS_FULL_PWR);
				(void) pm_idle_component(dip, 0);

				/* release the hold on the child */
				ndi_rele_devi(dip);
				mutex_enter(HUBD_MUTEX(hubd));
				hubd->h_port_state[port] &=
				    ~HUBD_CHILD_RAISE_POWER;
			}
		}
		/*
		 * make sure that we don't accidentally
		 * over write the disconnect state
		 */
		if (hubd->h_dev_state == USB_DEV_HUB_CHILD_PWRLVL) {
			hubd->h_dev_state = old_state;
		}
	}

	/*
	 * start polling can immediately kick off read callback
	 * we need to set the h_hotplug_thread to 0 so that
	 * the callback is not dropped
	 *
	 * if there is device during reset, still stop polling to avoid the
	 * read callback interrupting the reset, the polling will be started
	 * in hubd_reset_thread.
	 */
	for (port = 1; port <= MAX_PORTS; port++) {
		if (hubd->h_reset_port[port]) {

			break;
		}
	}
	if (port > MAX_PORTS) {
		hubd_start_polling(hubd, HUBD_ALWAYS_START_POLLING);
	}

	/*
	 * Earlier we would set the h_hotplug_thread = 0 before
	 * polling was restarted  so that
	 * if there is any root hub status change interrupt, we can still kick
	 * off the hotplug thread. This was valid when this interrupt was
	 * delivered in hardware, and only ONE interrupt would be delivered.
	 * Now that we poll on the root hub looking for status change in
	 * software, this assignment is no longer required.
	 */
	hubd->h_hotplug_thread--;

	/* mark this device as idle */
	(void) hubd_pm_idle_component(hubd, hubd->h_dip, 0);

	cv_broadcast(&hubd->h_cv_hotplug_dev);

	USB_DPRINTF_L4(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "hubd_hotplug_thread: exit");

	mutex_exit(HUBD_MUTEX(hubd));

	ndi_rele_devi(hdip);
}


/*
 * hubd_handle_port_connect:
 *	Transition a port from Disabled to Enabled.  Ensure that the
 *	port is in the correct state before attempting to
 *	access the device.
 */
static int
hubd_handle_port_connect(hubd_t *hubd, usb_port_t port)
{
	int			rval;
	int			retry;
	long			time_delay;
	long			settling_time;
	uint16_t		status;
	uint16_t		change;
	usb_addr_t		hubd_usb_addr;
	usba_device_t		*usba_device;
	usb_port_status_t	port_status = 0;
	usb_port_status_t	hub_port_status = 0;

	/* Get the hub address and port status */
	usba_device = hubd->h_usba_device;
	mutex_enter(&usba_device->usb_mutex);
	hubd_usb_addr = usba_device->usb_addr;
	hub_port_status = usba_device->usb_port_status;
	mutex_exit(&usba_device->usb_mutex);

	/*
	 * If a device is connected, transition the
	 * port from Disabled to the Enabled state.
	 * The device will receive downstream packets
	 * in the Enabled state.
	 *
	 * reset port and wait for the hub to report
	 * completion
	 */
	change = status = 0;

	/*
	 * According to section 9.1.2 of USB 2.0 spec, the host should
	 * wait for atleast 100ms to allow completion of an insertion
	 * process and for power at the device to become stable.
	 * We wait for 200 ms
	 */
	settling_time = drv_usectohz(hubd_device_delay / 5);
	mutex_exit(HUBD_MUTEX(hubd));
	delay(settling_time);
	mutex_enter(HUBD_MUTEX(hubd));

	/* calculate 600 ms delay time */
	time_delay = (6 * drv_usectohz(hubd_device_delay)) / 10;

	for (retry = 0; (hubd->h_dev_state == USB_DEV_ONLINE) &&
	    (retry < hubd_retry_enumerate); retry++) {
		USB_DPRINTF_L4(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "resetting port%d, retry=%d", port, retry);

		if ((rval = hubd_reset_port(hubd, port)) != USB_SUCCESS) {
			(void) hubd_determine_port_status(hubd,
			    port, &status, &change, 0);

			/* continue only if port is still connected */
			if (status & PORT_STATUS_CCS) {
				continue;
			}

			/* carry on regardless */
		}

		/*
		 * according to USB 2.0 spec section 11.24.2.7.1.2
		 * at the end of port reset, the hub enables the port.
		 * But for some strange reasons, uhci port remains disabled.
		 * And because the port remains disabled for the settling
		 * time below, the device connected to the port gets wedged
		 * - fails to enumerate (device not responding)
		 * Hence, we enable it here immediately and later again after
		 * the delay
		 */
		(void) hubd_enable_port(hubd, port);

		/* we skip this delay in the first iteration */
		if (retry) {
			/*
			 * delay for device to signal disconnect/connect so
			 * that hub properly recognizes the speed of the device
			 */
			mutex_exit(HUBD_MUTEX(hubd));
			delay(settling_time);
			mutex_enter(HUBD_MUTEX(hubd));

			/*
			 * When a low speed device is connected to any port of
			 * PPX it has to be explicitly enabled
			 * Also, if device intentionally signals
			 * disconnect/connect, it will disable the port.
			 * So enable it again.
			 */
			(void) hubd_enable_port(hubd, port);
		}

		if ((rval = hubd_determine_port_status(hubd, port, &status,
		    &change, 0)) != USB_SUCCESS) {

			USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
			    "getting status failed (%d)", rval);

			(void) hubd_disable_port(hubd, port);

			continue;
		}

		if (status & PORT_STATUS_POCI) {
			USB_DPRINTF_L0(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
			    "port %d overcurrent", port);

			(void) hubd_disable_port(hubd, port);

			/* ack changes */
			(void) hubd_determine_port_status(hubd,
			    port, &status, &change, PORT_CHANGE_OCIC);

			continue;
		}

		/* is status really OK? */
		if ((status & PORT_STATUS_OK) != PORT_STATUS_OK) {
			USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
			    "port %d status (0x%x) not OK on retry %d",
			    port, status, retry);

			/* check if we still have the connection */
			if (!(status & PORT_STATUS_CCS)) {
				/* lost connection, set exit condition */
				retry = hubd_retry_enumerate;

				break;
			}
		} else {
			/*
			 * Determine if the device is high or full
			 * or low speed.
			 */
			if (status & PORT_STATUS_LSDA) {
				port_status = USBA_LOW_SPEED_DEV;
			} else if (status & PORT_STATUS_HSDA) {
				port_status = USBA_HIGH_SPEED_DEV;
			} else {
				port_status = USBA_FULL_SPEED_DEV;
			}

			USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
			    "creating child port%d, status=0x%x "
			    "port status=0x%x",
			    port, status, port_status);

			/*
			 * if the child already exists, set addrs and config
			 * to the device post connect event to the child
			 */
			if (hubd->h_children_dips[port]) {
				/* set addrs to this device */
				rval = hubd_setdevaddr(hubd, port);

				/*
				 * This delay is important for the CATC hub
				 * to enumerate. But, avoid delay in the first
				 * iteration
				 */
				if (retry) {
					mutex_exit(HUBD_MUTEX(hubd));
					delay(drv_usectohz(
					    hubd_device_delay/100));
					mutex_enter(HUBD_MUTEX(hubd));
				}

				if (rval == USB_SUCCESS) {
					/*
					 * if the port is resetting, check if
					 * device's descriptors have changed.
					 */
					if ((hubd->h_reset_port[port]) &&
					    (hubd_check_same_device(hubd,
					    port) != USB_SUCCESS)) {
						retry = hubd_retry_enumerate;

						break;
					}

					/*
					 * set the default config for
					 * this device
					 */
					hubd_setdevconfig(hubd, port);

					/*
					 * if we are doing Default reset, do
					 * not post reconnect event since we
					 * don't know where reset function is
					 * called.
					 */
					if (hubd->h_reset_port[port]) {

						return (USB_SUCCESS);
					}

					/*
					 * indicate to the child that
					 * it is online again
					 */
					mutex_exit(HUBD_MUTEX(hubd));
					hubd_post_event(hubd, port,
					    USBA_EVENT_TAG_HOT_INSERTION);
					mutex_enter(HUBD_MUTEX(hubd));

					return (USB_SUCCESS);
				}
			} else {
				/*
				 * We need to release access here
				 * so that busctls on other ports can
				 * continue and don't cause a deadlock
				 * when busctl and removal of prom node
				 * takes concurrently. This also ensures
				 * busctls for attach of successfully
				 * enumerated devices on other ports can
				 * continue concurrently with the process
				 * of enumerating the new devices. This
				 * reduces the overall boot time of the system.
				 */
				rval = hubd_create_child(hubd->h_dip,
				    hubd,
				    hubd->h_usba_device,
				    port_status, port,
				    retry);
				if (rval == USB_SUCCESS) {
					usba_update_hotplug_stats(hubd->h_dip,
					    USBA_TOTAL_HOTPLUG_SUCCESS|
					    USBA_HOTPLUG_SUCCESS);
					hubd->h_total_hotplug_success++;

					if (retry > 0) {
						USB_DPRINTF_L2(
						    DPRINT_MASK_HOTPLUG,
						    hubd->h_log_handle,
						    "device on port %d "
						    "enumerated after %d %s",
						    port, retry,
						    (retry > 1) ? "retries" :
						    "retry");

					}

					return (USB_SUCCESS);
				}
			}
		}

		/* wait a while until it settles? */
		USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "disabling port %d again", port);

		(void) hubd_disable_port(hubd, port);
		if (retry) {
			mutex_exit(HUBD_MUTEX(hubd));
			delay(time_delay);
			mutex_enter(HUBD_MUTEX(hubd));
		}

		USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "retrying on port %d", port);
	}

	if (retry >= hubd_retry_enumerate) {
		/*
		 * If it is a High Speed Root Hub and connected device
		 * Is a Low/Full Speed, it will be handled by USB 1.1
		 * Host Controller. In this case, USB 2.0 Host Controller
		 * will transfer the ownership of this port to USB 1.1
		 * Host Controller. So don't display any error message on
		 * the console.
		 */
		if ((hubd_usb_addr == ROOT_HUB_ADDR) &&
		    (hub_port_status == USBA_HIGH_SPEED_DEV) &&
		    (port_status != USBA_HIGH_SPEED_DEV)) {
			USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG,
			    hubd->h_log_handle,
			    "hubd_handle_port_connect: Low/Full speed "
			    "device is connected to High Speed root hub");
		} else {
			USB_DPRINTF_L0(DPRINT_MASK_HOTPLUG,
			    hubd->h_log_handle,
			    "Connecting device on port %d failed", port);
		}

		(void) hubd_disable_port(hubd, port);
		usba_update_hotplug_stats(hubd->h_dip,
		    USBA_TOTAL_HOTPLUG_FAILURE|USBA_HOTPLUG_FAILURE);
		hubd->h_total_hotplug_failure++;

		/*
		 * the port should be automagically
		 * disabled but just in case, we do
		 * it here
		 */
		(void) hubd_disable_port(hubd, port);

		/* ack all changes because we disabled this port */
		(void) hubd_determine_port_status(hubd,
		    port, &status, &change, HUBD_ACK_ALL_CHANGES);

	}

	return (USB_FAILURE);
}


/*
 * hubd_get_hub_status:
 */
static int
hubd_get_hub_status(hubd_t *hubd)
{
	int		rval;
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	uint16_t	stword[2];
	uint16_t	status;
	uint16_t	change;
	usb_cfg_descr_t	cfg_descr;
	size_t		cfg_length;
	uchar_t		*usb_cfg;
	uint8_t		MaxPower;
	usb_hub_descr_t	*hub_descr;
	usb_port_t	port;

	USB_DPRINTF_L4(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "hubd_get_hub_status:");

	ASSERT(mutex_owned(HUBD_MUTEX(hubd)));

	if ((hubd_get_hub_status_words(hubd, stword)) != USB_SUCCESS) {

		return (USB_FAILURE);
	}
	status = stword[0];
	change = stword[1];

	mutex_exit(HUBD_MUTEX(hubd));

	/* Obtain the raw configuration descriptor */
	usb_cfg = usb_get_raw_cfg_data(hubd->h_dip, &cfg_length);

	/* get configuration descriptor */
	rval = usb_parse_cfg_descr(usb_cfg, cfg_length,
	    &cfg_descr, USB_CFG_DESCR_SIZE);

	if (rval != USB_CFG_DESCR_SIZE) {

		USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "get hub configuration descriptor failed.");

		mutex_enter(HUBD_MUTEX(hubd));

		return (USB_FAILURE);
	} else {
		MaxPower = cfg_descr.bMaxPower;
	}

	/* check if local power status changed. */
	if (change & C_HUB_LOCAL_POWER_STATUS) {

		/*
		 * local power has been lost, check the maximum
		 * power consumption of current configuration.
		 * see USB2.0 spec Table 11-12.
		 */
		if (status & HUB_LOCAL_POWER_STATUS) {

			if (MaxPower == 0) {

				/*
				 * Self-powered only hub. Because it could
				 * not draw any power from USB bus.
				 * It can't work well on this condition.
				 */
				USB_DPRINTF_L1(DPRINT_MASK_HOTPLUG,
				    hubd->h_log_handle,
				    "local power has been lost, "
				    "please disconnect hub");
			} else {

				/*
				 * Bus-powered only or self/bus-powered hub.
				 */
				USB_DPRINTF_L1(DPRINT_MASK_HOTPLUG,
				    hubd->h_log_handle,
				    "local power has been lost,"
				    "the hub could draw %d"
				    " mA power from the USB bus.",
				    2*MaxPower);
			}

		}

		USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "clearing feature C_HUB_LOCAL_POWER ");

		if ((rval = usb_pipe_sync_ctrl_xfer(hubd->h_dip,
		    hubd->h_default_pipe,
		    HUB_HANDLE_HUB_FEATURE_TYPE,
		    USB_REQ_CLEAR_FEATURE,
		    CFS_C_HUB_LOCAL_POWER,
		    0,
		    0,
		    NULL, 0,
		    &completion_reason, &cb_flags, 0)) != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG,
			    hubd->h_log_handle,
			    "clear feature C_HUB_LOCAL_POWER "
			    "failed (%d 0x%x %d)",
			    rval, completion_reason, cb_flags);
		}

	}

	if (change & C_HUB_OVER_CURRENT) {

		if (status & HUB_OVER_CURRENT) {

			if (usba_is_root_hub(hubd->h_dip)) {
				/*
				 * The root hub should be automatically
				 * recovered when over-current condition is
				 * cleared. But there might be exception and
				 * need user interaction to recover.
				 */
				USB_DPRINTF_L0(DPRINT_MASK_HOTPLUG,
				    hubd->h_log_handle,
				    "Root hub over current condition, "
				    "please check your system to clear the "
				    "condition as soon as possible. And you "
				    "may need to reboot the system to bring "
				    "the root hub back to work if it cannot "
				    "recover automatically");
			} else {
				/*
				 * The driver would try to recover port power
				 * on over current condition. When the recovery
				 * fails, the user may still need to offline
				 * this hub in order to recover.
				 * The port power is automatically disabled,
				 * so we won't see disconnects.
				 */
				USB_DPRINTF_L0(DPRINT_MASK_HOTPLUG,
				    hubd->h_log_handle,
				    "Hub global over current condition, "
				    "please disconnect the devices connected "
				    "to the hub to clear the condition. And "
				    "you may need to re-connect the hub if "
				    "the ports do not work");
			}
		}

		USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "clearing feature C_HUB_OVER_CURRENT");

		if ((rval = usb_pipe_sync_ctrl_xfer(hubd->h_dip,
		    hubd->h_default_pipe,
		    HUB_HANDLE_HUB_FEATURE_TYPE,
		    USB_REQ_CLEAR_FEATURE,
		    CFS_C_HUB_OVER_CURRENT,
		    0,
		    0,
		    NULL, 0,
		    &completion_reason, &cb_flags, 0)) != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG,
			    hubd->h_log_handle,
			    "clear feature C_HUB_OVER_CURRENT "
			    "failed (%d 0x%x %d)",
			    rval, completion_reason, cb_flags);
		}

		/*
		 * Try to recover all port power if they are turned off.
		 * Don't do this for root hub, but rely on the root hub
		 * to recover itself.
		 */
		if (!usba_is_root_hub(hubd->h_dip)) {

			mutex_enter(HUBD_MUTEX(hubd));

			/*
			 * Only check the power status of the 1st port
			 * since all port power status should be the same.
			 */
			(void) hubd_determine_port_status(hubd, 1, &status,
			    &change, 0);

			if (status & PORT_STATUS_PPS) {

				return (USB_SUCCESS);
			}

			hub_descr = &hubd->h_hub_descr;

			for (port = 1; port <= hub_descr->bNbrPorts;
			    port++) {

				(void) hubd_enable_port_power(hubd, port);
			}

			mutex_exit(HUBD_MUTEX(hubd));

			/*
			 * Delay some time to avoid over-current event
			 * to happen too frequently in some cases
			 */
			delay(drv_usectohz(500000));
		}
	}

	mutex_enter(HUBD_MUTEX(hubd));

	return (USB_SUCCESS);
}


/*
 * hubd_reset_port:
 */
static int
hubd_reset_port(hubd_t *hubd, usb_port_t port)
{
	int	rval;
	usb_cr_t completion_reason;
	usb_cb_flags_t cb_flags;
	usb_port_mask_t port_mask = 1 << port;
	mblk_t	*data;
	uint16_t status;
	uint16_t change;
	int	i;
	clock_t	delta;

	USB_DPRINTF_L4(DPRINT_MASK_PORT, hubd->h_log_handle,
	    "hubd_reset_port: port=%d", port);

	ASSERT(mutex_owned(HUBD_MUTEX(hubd)));

	hubd->h_port_reset_wait |= port_mask;

	mutex_exit(HUBD_MUTEX(hubd));

	if ((rval = usb_pipe_sync_ctrl_xfer(hubd->h_dip,
	    hubd->h_default_pipe,
	    HUB_HANDLE_PORT_FEATURE_TYPE,
	    USB_REQ_SET_FEATURE,
	    CFS_PORT_RESET,
	    port,
	    0,
	    NULL, 0,
	    &completion_reason, &cb_flags, 0)) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_PORT, hubd->h_log_handle,
		    "reset port%d failed (%d 0x%x %d)",
		    port, completion_reason, cb_flags, rval);

		mutex_enter(HUBD_MUTEX(hubd));

		return (USB_FAILURE);
	}

	mutex_enter(HUBD_MUTEX(hubd));

	USB_DPRINTF_L4(DPRINT_MASK_PORT, hubd->h_log_handle,
	    "waiting on cv for reset completion");

	/*
	 * wait for port status change event
	 */
	delta = drv_usectohz(hubd_device_delay / 10);
	for (i = 0; i < hubd_retry_enumerate; i++) {
		/*
		 * start polling ep1 for receiving notification on
		 * reset completion
		 */
		hubd_start_polling(hubd, HUBD_ALWAYS_START_POLLING);

		/*
		 * sleep a max of 100ms for reset completion
		 * notification to be received
		 */
		if (hubd->h_port_reset_wait & port_mask) {
			rval = cv_reltimedwait(&hubd->h_cv_reset_port,
			    &hubd->h_mutex, delta, TR_CLOCK_TICK);
			if ((rval <= 0) &&
			    (hubd->h_port_reset_wait & port_mask)) {
				/* we got woken up because of a timeout */
				USB_DPRINTF_L2(DPRINT_MASK_PORT,
				    hubd->h_log_handle,
				    "timeout: reset port=%d failed", port);

				hubd->h_port_reset_wait &=  ~port_mask;

				hubd_stop_polling(hubd);

				return (USB_FAILURE);
			}
		}

		USB_DPRINTF_L4(DPRINT_MASK_PORT, hubd->h_log_handle,
		    "reset completion received");

		hubd_stop_polling(hubd);

		data = NULL;

		/* check status to determine whether reset completed */
		mutex_exit(HUBD_MUTEX(hubd));
		if ((rval = usb_pipe_sync_ctrl_xfer(hubd->h_dip,
		    hubd->h_default_pipe,
		    HUB_GET_PORT_STATUS_TYPE,
		    USB_REQ_GET_STATUS,
		    0,
		    port,
		    GET_STATUS_LENGTH,
		    &data, 0,
		    &completion_reason, &cb_flags, 0)) != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_PORT,
			    hubd->h_log_handle,
			    "get status port%d failed (%d 0x%x %d)",
			    port, completion_reason, cb_flags, rval);

			if (data) {
				freemsg(data);
				data = NULL;
			}
			mutex_enter(HUBD_MUTEX(hubd));

			continue;
		}

		status = (*(data->b_rptr + 1) << 8) | *(data->b_rptr);
		change = (*(data->b_rptr + 3) << 8) | *(data->b_rptr + 2);

		freemsg(data);

		/* continue only if port is still connected */
		if (!(status & PORT_STATUS_CCS)) {

			/* lost connection, set exit condition */
			i = hubd_retry_enumerate;

			mutex_enter(HUBD_MUTEX(hubd));

			break;
		}

		if (status & PORT_STATUS_PRS) {
			USB_DPRINTF_L3(DPRINT_MASK_PORT, hubd->h_log_handle,
			    "port%d reset active", port);
			mutex_enter(HUBD_MUTEX(hubd));

			continue;
		} else {
			USB_DPRINTF_L3(DPRINT_MASK_PORT, hubd->h_log_handle,
			    "port%d reset inactive", port);
		}

		if (change & PORT_CHANGE_PRSC) {
			USB_DPRINTF_L3(DPRINT_MASK_PORT, hubd->h_log_handle,
			    "clearing feature CFS_C_PORT_RESET");

			if (usb_pipe_sync_ctrl_xfer(hubd->h_dip,
			    hubd->h_default_pipe,
			    HUB_HANDLE_PORT_FEATURE_TYPE,
			    USB_REQ_CLEAR_FEATURE,
			    CFS_C_PORT_RESET,
			    port,
			    0,
			    NULL, 0,
			    &completion_reason, &cb_flags, 0) != USB_SUCCESS) {
				USB_DPRINTF_L2(DPRINT_MASK_PORT,
				    hubd->h_log_handle,
				    "clear feature CFS_C_PORT_RESET"
				    " port%d failed (%d 0x%x %d)",
				    port, completion_reason, cb_flags, rval);
			}
		}
		mutex_enter(HUBD_MUTEX(hubd));

		break;
	}

	if (i >= hubd_retry_enumerate) {
		/* port reset has failed */
		rval = USB_FAILURE;
	}

	return (rval);
}


/*
 * hubd_enable_port:
 *	this may fail if the hub as been disconnected
 */
static int
hubd_enable_port(hubd_t *hubd, usb_port_t port)
{
	int	rval;
	usb_cr_t completion_reason;
	usb_cb_flags_t cb_flags;

	USB_DPRINTF_L4(DPRINT_MASK_PORT, hubd->h_log_handle,
	    "hubd_enable_port: port=%d", port);

	ASSERT(mutex_owned(HUBD_MUTEX(hubd)));

	mutex_exit(HUBD_MUTEX(hubd));

	/* Do not issue a SetFeature(PORT_ENABLE) on external hubs */
	if (!usba_is_root_hub(hubd->h_dip)) {
		mutex_enter(HUBD_MUTEX(hubd));

		return (USB_SUCCESS);
	}

	if ((rval = usb_pipe_sync_ctrl_xfer(hubd->h_dip,
	    hubd->h_default_pipe,
	    HUB_HANDLE_PORT_FEATURE_TYPE,
	    USB_REQ_SET_FEATURE,
	    CFS_PORT_ENABLE,
	    port,
	    0,
	    NULL, 0,
	    &completion_reason, &cb_flags, 0)) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_PORT, hubd->h_log_handle,
		    "enable port%d failed (%d 0x%x %d)",
		    port, completion_reason, cb_flags, rval);
	}

	mutex_enter(HUBD_MUTEX(hubd));

	USB_DPRINTF_L4(DPRINT_MASK_PORT, hubd->h_log_handle,
	    "enabling port done");

	return (rval);
}


/*
 * hubd_disable_port
 */
static int
hubd_disable_port(hubd_t *hubd, usb_port_t port)
{
	int	rval;
	usb_cr_t completion_reason;
	usb_cb_flags_t cb_flags;

	USB_DPRINTF_L4(DPRINT_MASK_PORT, hubd->h_log_handle,
	    "hubd_disable_port: port=%d", port);

	ASSERT(mutex_owned(HUBD_MUTEX(hubd)));

	mutex_exit(HUBD_MUTEX(hubd));

	if ((rval = usb_pipe_sync_ctrl_xfer(hubd->h_dip,
	    hubd->h_default_pipe,
	    HUB_HANDLE_PORT_FEATURE_TYPE,
	    USB_REQ_CLEAR_FEATURE,
	    CFS_PORT_ENABLE,
	    port,
	    0,
	    NULL, 0,
	    &completion_reason, &cb_flags, 0)) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_PORT, hubd->h_log_handle,
		    "disable port%d failed (%d 0x%x %d)", port,
		    completion_reason, cb_flags, rval);
		mutex_enter(HUBD_MUTEX(hubd));

		return (USB_FAILURE);
	}

	USB_DPRINTF_L3(DPRINT_MASK_PORT, hubd->h_log_handle,
	    "clearing feature CFS_C_PORT_ENABLE");

	if ((rval = usb_pipe_sync_ctrl_xfer(hubd->h_dip,
	    hubd->h_default_pipe,
	    HUB_HANDLE_PORT_FEATURE_TYPE,
	    USB_REQ_CLEAR_FEATURE,
	    CFS_C_PORT_ENABLE,
	    port,
	    0,
	    NULL, 0,
	    &completion_reason, &cb_flags, 0)) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_PORT,
		    hubd->h_log_handle,
		    "clear feature CFS_C_PORT_ENABLE port%d failed "
		    "(%d 0x%x %d)",
		    port, completion_reason, cb_flags, rval);

		mutex_enter(HUBD_MUTEX(hubd));

		return (USB_FAILURE);
	}

	mutex_enter(HUBD_MUTEX(hubd));

	return (USB_SUCCESS);
}


/*
 * hubd_determine_port_status:
 */
static int
hubd_determine_port_status(hubd_t *hubd, usb_port_t port,
		uint16_t *status, uint16_t *change, uint_t ack_flag)
{
	int rval;
	mblk_t	*data = NULL;
	usb_cr_t completion_reason;
	usb_cb_flags_t cb_flags;

	USB_DPRINTF_L4(DPRINT_MASK_PORT, hubd->h_log_handle,
	    "hubd_determine_port_status: port=%d, state=0x%x ack=0x%x", port,
	    hubd->h_port_state[port], ack_flag);

	ASSERT(mutex_owned(HUBD_MUTEX(hubd)));

	mutex_exit(HUBD_MUTEX(hubd));

	if ((rval = usb_pipe_sync_ctrl_xfer(hubd->h_dip,
	    hubd->h_default_pipe,
	    HUB_GET_PORT_STATUS_TYPE,
	    USB_REQ_GET_STATUS,
	    0,
	    port,
	    GET_STATUS_LENGTH,
	    &data, 0,
	    &completion_reason, &cb_flags, 0)) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_PORT, hubd->h_log_handle,
		    "port=%d get status failed (%d 0x%x %d)",
		    port, completion_reason, cb_flags, rval);

		if (data) {
			freemsg(data);
		}

		*status = *change = 0;
		mutex_enter(HUBD_MUTEX(hubd));

		return (rval);
	}

	mutex_enter(HUBD_MUTEX(hubd));
	if (MBLKL(data) != GET_STATUS_LENGTH) {
		USB_DPRINTF_L2(DPRINT_MASK_PORT, hubd->h_log_handle,
		    "port %d: length incorrect %ld",
		    port, MBLKL(data));
		freemsg(data);
		*status = *change = 0;

		return (rval);
	}


	*status = (*(data->b_rptr + 1) << 8) | *(data->b_rptr);
	*change = (*(data->b_rptr + 3) << 8) | *(data->b_rptr + 2);

	USB_DPRINTF_L3(DPRINT_MASK_PORT, hubd->h_log_handle,
	    "port%d status=0x%x, change=0x%x", port, *status, *change);

	freemsg(data);

	if (*status & PORT_STATUS_CCS) {
		USB_DPRINTF_L3(DPRINT_MASK_PORT, hubd->h_log_handle,
		    "port%d connected", port);

		hubd->h_port_state[port] |= (PORT_STATUS_CCS & ack_flag);
	} else {
		USB_DPRINTF_L3(DPRINT_MASK_PORT, hubd->h_log_handle,
		    "port%d disconnected", port);

		hubd->h_port_state[port] &= ~(PORT_STATUS_CCS & ack_flag);
	}

	if (*status & PORT_STATUS_PES) {
		USB_DPRINTF_L3(DPRINT_MASK_PORT, hubd->h_log_handle,
		    "port%d enabled", port);

		hubd->h_port_state[port] |= (PORT_STATUS_PES & ack_flag);
	} else {
		USB_DPRINTF_L3(DPRINT_MASK_PORT, hubd->h_log_handle,
		    "port%d disabled", port);

		hubd->h_port_state[port] &= ~(PORT_STATUS_PES & ack_flag);
	}

	if (*status & PORT_STATUS_PSS) {
		USB_DPRINTF_L3(DPRINT_MASK_PORT, hubd->h_log_handle,
		    "port%d suspended", port);

		hubd->h_port_state[port] |= (PORT_STATUS_PSS & ack_flag);
	} else {
		USB_DPRINTF_L3(DPRINT_MASK_PORT, hubd->h_log_handle,
		    "port%d not suspended", port);

		hubd->h_port_state[port] &= ~(PORT_STATUS_PSS & ack_flag);
	}

	if (*change & PORT_CHANGE_PRSC) {
		USB_DPRINTF_L3(DPRINT_MASK_PORT, hubd->h_log_handle,
		    "port%d reset completed", port);

		hubd->h_port_state[port] |= (PORT_CHANGE_PRSC & ack_flag);
	} else {

		hubd->h_port_state[port] &= ~(PORT_CHANGE_PRSC & ack_flag);
	}

	if (*status & PORT_STATUS_POCI) {
		USB_DPRINTF_L2(DPRINT_MASK_PORT, hubd->h_log_handle,
		    "port%d overcurrent!", port);

		hubd->h_port_state[port] |= (PORT_STATUS_POCI & ack_flag);
	} else {

		hubd->h_port_state[port] &= ~(PORT_STATUS_POCI & ack_flag);
	}

	if (*status & PORT_STATUS_PRS) {
		USB_DPRINTF_L3(DPRINT_MASK_PORT, hubd->h_log_handle,
		    "port%d reset active", port);

		hubd->h_port_state[port] |= (PORT_STATUS_PRS & ack_flag);
	} else {
		USB_DPRINTF_L3(DPRINT_MASK_PORT, hubd->h_log_handle,
		    "port%d reset inactive", port);

		hubd->h_port_state[port] &= ~(PORT_STATUS_PRS & ack_flag);
	}
	if (*status & PORT_STATUS_PPS) {
		USB_DPRINTF_L3(DPRINT_MASK_PORT, hubd->h_log_handle,
		    "port%d power on", port);

		hubd->h_port_state[port] |= (PORT_STATUS_PPS & ack_flag);
	} else {
		USB_DPRINTF_L3(DPRINT_MASK_PORT, hubd->h_log_handle,
		    "port%d power off", port);

		hubd->h_port_state[port] &= ~(PORT_STATUS_PPS & ack_flag);
	}
	if (*status & PORT_STATUS_LSDA) {
		USB_DPRINTF_L3(DPRINT_MASK_PORT, hubd->h_log_handle,
		    "port%d low speed", port);

		hubd->h_port_state[port] |= (PORT_STATUS_LSDA & ack_flag);
	} else {
		hubd->h_port_state[port] &= ~(PORT_STATUS_LSDA & ack_flag);
		if (*status & PORT_STATUS_HSDA) {
			USB_DPRINTF_L3(DPRINT_MASK_PORT,
			    hubd->h_log_handle, "port%d "
			    "high speed", port);

			hubd->h_port_state[port] |=
			    (PORT_STATUS_HSDA & ack_flag);
		} else {
			USB_DPRINTF_L3(DPRINT_MASK_PORT,
			    hubd->h_log_handle, "port%d "
			    "full speed", port);

			hubd->h_port_state[port] &=
			    ~(PORT_STATUS_HSDA & ack_flag);
		}
	}

	/*
	 * Acknowledge connection, enable, reset status
	 */
	if (ack_flag) {
		mutex_exit(HUBD_MUTEX(hubd));
		if (*change & PORT_CHANGE_CSC & ack_flag) {
			USB_DPRINTF_L3(DPRINT_MASK_PORT, hubd->h_log_handle,
			    "clearing feature CFS_C_PORT_CONNECTION");
			if ((rval = usb_pipe_sync_ctrl_xfer(hubd->h_dip,
			    hubd->h_default_pipe,
			    HUB_HANDLE_PORT_FEATURE_TYPE,
			    USB_REQ_CLEAR_FEATURE,
			    CFS_C_PORT_CONNECTION,
			    port,
			    0, NULL, 0,
			    &completion_reason, &cb_flags, 0)) !=
			    USB_SUCCESS) {
				USB_DPRINTF_L2(DPRINT_MASK_PORT,
				    hubd->h_log_handle,
				    "clear feature CFS_C_PORT_CONNECTION"
				    " port%d failed (%d 0x%x %d)",
				    port, completion_reason, cb_flags, rval);
			}
		}
		if (*change & PORT_CHANGE_PESC & ack_flag) {
			USB_DPRINTF_L3(DPRINT_MASK_PORT, hubd->h_log_handle,
			    "clearing feature CFS_C_PORT_ENABLE");
			if ((rval = usb_pipe_sync_ctrl_xfer(hubd->h_dip,
			    hubd->h_default_pipe,
			    HUB_HANDLE_PORT_FEATURE_TYPE,
			    USB_REQ_CLEAR_FEATURE,
			    CFS_C_PORT_ENABLE,
			    port,
			    0, NULL, 0,
			    &completion_reason, &cb_flags, 0)) !=
			    USB_SUCCESS) {
				USB_DPRINTF_L2(DPRINT_MASK_PORT,
				    hubd->h_log_handle,
				    "clear feature CFS_C_PORT_ENABLE"
				    " port%d failed (%d 0x%x %d)",
				    port, completion_reason, cb_flags, rval);
			}
		}
		if (*change & PORT_CHANGE_PSSC & ack_flag) {
			USB_DPRINTF_L3(DPRINT_MASK_PORT, hubd->h_log_handle,
			    "clearing feature CFS_C_PORT_SUSPEND");

			if ((rval = usb_pipe_sync_ctrl_xfer(hubd->h_dip,
			    hubd->h_default_pipe,
			    HUB_HANDLE_PORT_FEATURE_TYPE,
			    USB_REQ_CLEAR_FEATURE,
			    CFS_C_PORT_SUSPEND,
			    port,
			    0, NULL, 0,
			    &completion_reason, &cb_flags, 0)) !=
			    USB_SUCCESS) {
				USB_DPRINTF_L2(DPRINT_MASK_PORT,
				    hubd->h_log_handle,
				    "clear feature CFS_C_PORT_SUSPEND"
				    " port%d failed (%d 0x%x %d)",
				    port, completion_reason, cb_flags, rval);
			}
		}
		if (*change & PORT_CHANGE_OCIC & ack_flag) {
			USB_DPRINTF_L3(DPRINT_MASK_PORT, hubd->h_log_handle,
			    "clearing feature CFS_C_PORT_OVER_CURRENT");

			if ((rval = usb_pipe_sync_ctrl_xfer(hubd->h_dip,
			    hubd->h_default_pipe,
			    HUB_HANDLE_PORT_FEATURE_TYPE,
			    USB_REQ_CLEAR_FEATURE,
			    CFS_C_PORT_OVER_CURRENT,
			    port,
			    0, NULL, 0,
			    &completion_reason, &cb_flags, 0)) !=
			    USB_SUCCESS) {
				USB_DPRINTF_L2(DPRINT_MASK_PORT,
				    hubd->h_log_handle,
				    "clear feature CFS_C_PORT_OVER_CURRENT"
				    " port%d failed (%d 0x%x %d)",
				    port, completion_reason, cb_flags, rval);
			}
		}
		if (*change & PORT_CHANGE_PRSC & ack_flag) {
			USB_DPRINTF_L3(DPRINT_MASK_PORT, hubd->h_log_handle,
			    "clearing feature CFS_C_PORT_RESET");
			if ((rval = usb_pipe_sync_ctrl_xfer(hubd->h_dip,
			    hubd->h_default_pipe,
			    HUB_HANDLE_PORT_FEATURE_TYPE,
			    USB_REQ_CLEAR_FEATURE,
			    CFS_C_PORT_RESET,
			    port,
			    0, NULL, 0,
			    &completion_reason, &cb_flags, 0)) !=
			    USB_SUCCESS) {
				USB_DPRINTF_L2(DPRINT_MASK_PORT,
				    hubd->h_log_handle,
				    "clear feature CFS_C_PORT_RESET"
				    " port%d failed (%d 0x%x %d)",
				    port, completion_reason, cb_flags, rval);
			}
		}
		mutex_enter(HUBD_MUTEX(hubd));
	}

	USB_DPRINTF_L4(DPRINT_MASK_PORT, hubd->h_log_handle,
	    "new port%d state 0x%x", port, hubd->h_port_state[port]);


	return (USB_SUCCESS);
}


/*
 * hubd_recover_disabled_port
 * if the port got disabled because of an error
 * enable it. If hub doesn't suport enable port,
 * reset the port to bring the device to life again
 */
static int
hubd_recover_disabled_port(hubd_t *hubd, usb_port_t port)
{
	uint16_t	status;
	uint16_t	change;
	int		rval = USB_FAILURE;

	/* first try enabling the port */
	(void) hubd_enable_port(hubd, port);

	/* read the port status */
	(void) hubd_determine_port_status(hubd, port, &status, &change,
	    PORT_CHANGE_PESC);

	if (status & PORT_STATUS_PES) {
		USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "Port%d now Enabled", port);
	} else if (status & PORT_STATUS_CCS) {
		/* first post a disconnect event to the child */
		mutex_exit(HUBD_MUTEX(hubd));
		hubd_post_event(hubd, port, USBA_EVENT_TAG_HOT_REMOVAL);
		mutex_enter(HUBD_MUTEX(hubd));

		/* then reset the port and recover the device */
		rval = hubd_handle_port_connect(hubd, port);

		USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "Port%d now Enabled by force", port);
	}

	return (rval);
}


/*
 * hubd_enable_all_port_power:
 */
static int
hubd_enable_all_port_power(hubd_t *hubd)
{
	usb_hub_descr_t	*hub_descr;
	int		wait;
	usb_port_t	port;
	uint_t		retry;
	uint16_t	status;
	uint16_t	change;

	USB_DPRINTF_L4(DPRINT_MASK_PORT, hubd->h_log_handle,
	    "hubd_enable_all_port_power");

	ASSERT(mutex_owned(HUBD_MUTEX(hubd)));

	hub_descr = &hubd->h_hub_descr;

	/*
	 * According to section 11.11 of USB, for hubs with no power
	 * switches, bPwrOn2PwrGood is zero. But we wait for some
	 * arbitrary time to enable power to become stable.
	 *
	 * If an hub supports port power switching, we need to wait
	 * at least 20ms before accessing corresponding usb port.
	 */
	if ((hub_descr->wHubCharacteristics &
	    HUB_CHARS_NO_POWER_SWITCHING) || (!hub_descr->bPwrOn2PwrGood)) {
		wait = hubd_device_delay / 10;
	} else {
		wait = max(HUB_DEFAULT_POPG,
		    hub_descr->bPwrOn2PwrGood) * 2 * 1000;
	}

	USB_DPRINTF_L4(DPRINT_MASK_PORT, hubd->h_log_handle,
	    "hubd_enable_all_port_power: popg=%d wait=%d",
	    hub_descr->bPwrOn2PwrGood, wait);

	/*
	 * Enable power per port. we ignore gang power and power mask
	 * and always enable all ports one by one.
	 */
	for (port = 1; port <= hub_descr->bNbrPorts; port++) {
		/*
		 * Transition the port from the Powered Off to the
		 * Disconnected state by supplying power to the port.
		 */
		USB_DPRINTF_L4(DPRINT_MASK_PORT,
		    hubd->h_log_handle,
		    "hubd_enable_all_port_power: power port=%d", port);

		(void) hubd_enable_port_power(hubd, port);
	}

	mutex_exit(HUBD_MUTEX(hubd));
	delay(drv_usectohz(wait));
	mutex_enter(HUBD_MUTEX(hubd));

	/* For retry if any, use some extra delay */
	wait = max(wait, hubd_device_delay / 10);

	/* Check each port power status for a given usb hub */
	for (port = 1; port <= hub_descr->bNbrPorts; port++) {

		/* Get port status */
		(void) hubd_determine_port_status(hubd, port,
		    &status, &change, 0);

		for (retry = 0; ((!(status & PORT_STATUS_PPS)) &&
		    (retry < HUBD_PORT_RETRY)); retry++) {

			USB_DPRINTF_L2(DPRINT_MASK_PORT, hubd->h_log_handle,
			    "Retry is in progress %d: port %d status %d",
			    retry, port, status);

			(void) hubd_enable_port_power(hubd, port);

			mutex_exit(HUBD_MUTEX(hubd));
			delay(drv_usectohz(wait));
			mutex_enter(HUBD_MUTEX(hubd));

			/* Get port status */
			(void) hubd_determine_port_status(hubd, port,
			    &status, &change, 0);
		}

		/* Print warning message if port has no power */
		if (!(status & PORT_STATUS_PPS)) {

			USB_DPRINTF_L2(DPRINT_MASK_PORT, hubd->h_log_handle,
			    "hubd_enable_all_port_power: port %d power-on "
			    "failed, port status 0x%x", port, status);
		}
	}

	return (USB_SUCCESS);
}


/*
 * hubd_enable_port_power:
 *	enable individual port power
 */
static int
hubd_enable_port_power(hubd_t *hubd, usb_port_t port)
{
	int		rval;
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;

	USB_DPRINTF_L4(DPRINT_MASK_PORT, hubd->h_log_handle,
	    "hubd_enable_port_power: port=%d", port);

	ASSERT(mutex_owned(HUBD_MUTEX(hubd)));
	ASSERT(hubd->h_default_pipe != 0);

	mutex_exit(HUBD_MUTEX(hubd));

	if ((rval = usb_pipe_sync_ctrl_xfer(hubd->h_dip,
	    hubd->h_default_pipe,
	    HUB_HANDLE_PORT_FEATURE_TYPE,
	    USB_REQ_SET_FEATURE,
	    CFS_PORT_POWER,
	    port,
	    0, NULL, 0,
	    &completion_reason, &cb_flags, 0)) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_PORT, hubd->h_log_handle,
		    "set port power failed (%d 0x%x %d)",
		    completion_reason, cb_flags, rval);
		mutex_enter(HUBD_MUTEX(hubd));

		return (USB_FAILURE);
	} else {
		mutex_enter(HUBD_MUTEX(hubd));
		hubd->h_port_state[port] |= PORT_STATUS_PPS;

		return (USB_SUCCESS);
	}
}


/*
 * hubd_disable_all_port_power:
 */
static int
hubd_disable_all_port_power(hubd_t *hubd)
{
	usb_port_t port;

	USB_DPRINTF_L4(DPRINT_MASK_PORT, hubd->h_log_handle,
	    "hubd_disable_all_port_power");

	ASSERT(mutex_owned(HUBD_MUTEX(hubd)));

	/*
	 * disable power per port, ignore gang power and power mask
	 */
	for (port = 1; port <= hubd->h_hub_descr.bNbrPorts; port++) {
		(void) hubd_disable_port_power(hubd, port);
	}

	return (USB_SUCCESS);
}


/*
 * hubd_disable_port_power:
 *	disable individual port power
 */
static int
hubd_disable_port_power(hubd_t *hubd, usb_port_t port)
{
	int		rval;
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;

	USB_DPRINTF_L4(DPRINT_MASK_PORT, hubd->h_log_handle,
	    "hubd_disable_port_power: port=%d", port);

	ASSERT(mutex_owned(HUBD_MUTEX(hubd)));

	mutex_exit(HUBD_MUTEX(hubd));

	if ((rval = usb_pipe_sync_ctrl_xfer(hubd->h_dip,
	    hubd->h_default_pipe,
	    HUB_HANDLE_PORT_FEATURE_TYPE,
	    USB_REQ_CLEAR_FEATURE,
	    CFS_PORT_POWER,
	    port,
	    0, NULL, 0,
	    &completion_reason, &cb_flags, 0)) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_PORT, hubd->h_log_handle,
		    "clearing port%d power failed (%d 0x%x %d)",
		    port, completion_reason, cb_flags, rval);

		mutex_enter(HUBD_MUTEX(hubd));

		return (USB_FAILURE);
	} else {

		mutex_enter(HUBD_MUTEX(hubd));
		ASSERT(completion_reason == 0);
		hubd->h_port_state[port] &= ~PORT_STATUS_PPS;

		return (USB_SUCCESS);
	}
}


/*
 * Search the database of user preferences and find out the preferred
 * configuration for this new device
 */
int
hubd_select_device_configuration(hubd_t *hubd, usb_port_t port,
	dev_info_t *child_dip, usba_device_t *child_ud)
{
	char		*pathname = NULL;
	char		*tmp_path = NULL;
	int		user_conf;
	int		pathlen;
	usb_dev_descr_t	*usbdev_ptr;
	usba_configrec_t *user_pref;

	mutex_enter(&child_ud->usb_mutex);
	usbdev_ptr = child_ud->usb_dev_descr;
	mutex_exit(&child_ud->usb_mutex);

	/* try to get pathname for this device */
	tmp_path = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(child_dip, tmp_path);

	pathlen = strlen(tmp_path) + 32;
	pathname = kmem_zalloc(pathlen, KM_SLEEP);

	/*
	 * We haven't initialized the node and it doesn't have an address
	 * yet. Append port number to the physical pathname
	 */
	(void) sprintf(pathname, "%s@%d", tmp_path, port);

	USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "hubd_select_device_configuration: Device=%s\n\t"
	    "Child path=%s",
	    usba_get_mfg_prod_sn_str(child_dip, tmp_path, MAXPATHLEN),
	    pathname);
	kmem_free(tmp_path, MAXPATHLEN);


	/* database search for user preferences */
	user_pref = usba_devdb_get_user_preferences(usbdev_ptr->idVendor,
	    usbdev_ptr->idProduct, child_ud->usb_serialno_str, pathname);

	if (user_pref) {
		USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "hubd_select_device_configuration: "
		    "usba_devdb_get_user_preferences "
		    "return user_conf=%d\npreferred driver=%s path=%s",
		    user_pref->cfg_index, user_pref->driver,
		    user_pref->pathname);

		user_conf = user_pref->cfg_index;

		if (user_pref->driver) {
			mutex_enter(&child_ud->usb_mutex);
			child_ud->usb_preferred_driver = user_pref->driver;
			mutex_exit(&child_ud->usb_mutex);
		}
	} else {
		USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "hubd_select_device_configuration: No match found");

		/* select default configuration for this device */
		user_conf = USBA_DEV_CONFIG_INDEX_UNDEFINED;
	}
	kmem_free(pathname, pathlen);

	/* if the device has just one configuration, set default value */
	if (usbdev_ptr->bNumConfigurations == 1) {
		user_conf = USB_DEV_DEFAULT_CONFIG_INDEX;
	}

	return (user_conf);
}


/*
 * Retrieves config cloud for this configuration
 */
int
hubd_get_this_config_cloud(hubd_t *hubd, dev_info_t *dip,
	usba_device_t *child_ud, uint16_t conf_index)
{
	usb_cfg_descr_t	*confdescr;
	mblk_t		*pdata = NULL;
	int		rval;
	size_t		size;
	char		*tmpbuf;
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	usb_pipe_handle_t	def_ph;

	USB_DPRINTF_L4(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "hubd_get_this_config_cloud: conf_index=%d", conf_index);


	/* alloc temporary space for config descriptor */
	confdescr = (usb_cfg_descr_t *)kmem_zalloc(USB_CFG_DESCR_SIZE,
	    KM_SLEEP);

	/* alloc temporary space for string descriptor */
	tmpbuf = kmem_zalloc(USB_MAXSTRINGLEN, KM_SLEEP);

	def_ph = usba_get_dflt_pipe_handle(dip);

	if ((rval = usb_pipe_sync_ctrl_xfer(dip, def_ph,
	    USB_DEV_REQ_DEV_TO_HOST | USB_DEV_REQ_TYPE_STANDARD,
	    USB_REQ_GET_DESCR,
	    USB_DESCR_TYPE_SETUP_CFG | conf_index,
	    0,
	    USB_CFG_DESCR_SIZE,
	    &pdata,
	    0,
	    &completion_reason,
	    &cb_flags,
	    0)) == USB_SUCCESS) {

		/* this must be true since we didn't allow data underruns */
		if (MBLKL(pdata) != USB_CFG_DESCR_SIZE) {
			USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
			    "device returned incorrect configuration "
			    "descriptor size.");

			rval = USB_FAILURE;
			goto done;
		}

		/*
		 * Parse the configuration descriptor
		 */
		size = usb_parse_cfg_descr(pdata->b_rptr,
		    MBLKL(pdata), confdescr,
		    USB_CFG_DESCR_SIZE);

		/* if parse cfg descr error, it should return failure */
		if (size == USB_PARSE_ERROR) {

			if (pdata->b_rptr[1] != USB_DESCR_TYPE_CFG) {
				USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG,
				    hubd->h_log_handle,
				    "device returned incorrect "
				    "configuration descriptor type.");
			}
			rval = USB_FAILURE;
			goto done;
		}

		if (confdescr->wTotalLength < USB_CFG_DESCR_SIZE) {
			USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG,
			    hubd->h_log_handle,
			    "device returned incorrect "
			    "configuration descriptor size.");

			rval = USB_FAILURE;
			goto done;
		}

		freemsg(pdata);
		pdata = NULL;

		/* Now fetch the complete config cloud */
		if ((rval = usb_pipe_sync_ctrl_xfer(dip, def_ph,
		    USB_DEV_REQ_DEV_TO_HOST | USB_DEV_REQ_TYPE_STANDARD,
		    USB_REQ_GET_DESCR,
		    USB_DESCR_TYPE_SETUP_CFG | conf_index,
		    0,
		    confdescr->wTotalLength,
		    &pdata,
		    0,
		    &completion_reason,
		    &cb_flags,
		    0)) == USB_SUCCESS) {

			if (MBLKL(pdata) !=
			    confdescr->wTotalLength) {

				USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG,
				    hubd->h_log_handle,
				    "device returned incorrect "
				    "configuration descriptor.");

				rval = USB_FAILURE;
				goto done;
			}

			/*
			 * copy config descriptor into usba_device
			 */
			mutex_enter(&child_ud->usb_mutex);
			child_ud->usb_cfg_array[conf_index] =
			    kmem_alloc(confdescr->wTotalLength, KM_SLEEP);
			child_ud->usb_cfg_array_len[conf_index] =
			    confdescr->wTotalLength;
			bcopy((caddr_t)pdata->b_rptr,
			    (caddr_t)child_ud->usb_cfg_array[conf_index],
			    confdescr->wTotalLength);
			mutex_exit(&child_ud->usb_mutex);

			/*
			 * retrieve string descriptor describing this
			 * configuration
			 */
			if (confdescr->iConfiguration) {

				USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG,
				    hubd->h_log_handle,
				    "Get conf str descr for config_index=%d",
				    conf_index);

				/*
				 * Now fetch the string descriptor describing
				 * this configuration
				 */
				if ((rval = usb_get_string_descr(dip,
				    USB_LANG_ID, confdescr->iConfiguration,
				    tmpbuf, USB_MAXSTRINGLEN)) ==
				    USB_SUCCESS) {
					size = strlen(tmpbuf);
					if (size > 0) {
						child_ud->usb_cfg_str_descr
						    [conf_index] = (char *)
						    kmem_zalloc(size + 1,
						    KM_SLEEP);
						(void) strcpy(
						    child_ud->usb_cfg_str_descr
						    [conf_index], tmpbuf);
					}
				} else {
					USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG,
					    hubd->h_log_handle,
					    "hubd_get_this_config_cloud: "
					    "getting config string (%d) "
					    "failed",
					    confdescr->iConfiguration);

					/* ignore this error */
					rval = USB_SUCCESS;
				}
			}
		}
	}

done:
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "hubd_get_this_config_cloud: "
		    "error in retrieving config descriptor for "
		    "config index=%d rval=%d cr=%d",
		    conf_index, rval, completion_reason);
	}

	if (pdata) {
		freemsg(pdata);
		pdata = NULL;
	}

	kmem_free(confdescr, USB_CFG_DESCR_SIZE);
	kmem_free(tmpbuf, USB_MAXSTRINGLEN);

	return (rval);
}


/*
 * Retrieves the entire config cloud for all configurations of the device
 */
int
hubd_get_all_device_config_cloud(hubd_t *hubd, dev_info_t *dip,
	usba_device_t *child_ud)
{
	int		rval = USB_SUCCESS;
	int		ncfgs;
	uint16_t	size;
	uint16_t	conf_index;
	uchar_t		**cfg_array;
	uint16_t	*cfg_array_len;
	char		**str_descr;

	USB_DPRINTF_L4(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "hubd_get_all_device_config_cloud: Start");

	/* alloc pointer array for conf. descriptors */
	mutex_enter(&child_ud->usb_mutex);
	ncfgs = child_ud->usb_n_cfgs;
	mutex_exit(&child_ud->usb_mutex);

	size = sizeof (uchar_t *) * ncfgs;
	cfg_array = kmem_zalloc(size, KM_SLEEP);
	cfg_array_len = kmem_zalloc(ncfgs * sizeof (uint16_t), KM_SLEEP);
	str_descr = kmem_zalloc(size, KM_SLEEP);

	mutex_enter(&child_ud->usb_mutex);
	child_ud->usb_cfg_array = cfg_array;
	child_ud->usb_cfg_array_len = cfg_array_len;
	child_ud->usb_cfg_array_length = size;
	child_ud->usb_cfg_array_len_length = ncfgs * sizeof (uint16_t);
	child_ud->usb_cfg_str_descr = str_descr;
	mutex_exit(&child_ud->usb_mutex);

	/* Get configuration descriptor for each configuration */
	for (conf_index = 0; (conf_index < ncfgs) &&
	    (rval == USB_SUCCESS); conf_index++) {

		rval = hubd_get_this_config_cloud(hubd, dip, child_ud,
		    conf_index);
	}

	return (rval);
}


/*
 * hubd_ready_device:
 *	Update the usba_device structure
 *	Set the given configuration
 *	Prepares the device node for driver to online. If an existing
 *	OBP node is found, it will switch to the OBP node.
 */
dev_info_t *
hubd_ready_device(hubd_t *hubd, dev_info_t *child_dip, usba_device_t *child_ud,
    uint_t config_index)
{
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	size_t		size;
	usb_cfg_descr_t	config_descriptor;
	usb_pipe_handle_t def_ph;
	usba_pipe_handle_data_t	*ph;

	USB_DPRINTF_L4(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "hubd_ready_device: dip=0x%p, user_conf_index=%d",
	    (void *)child_dip, config_index);

	size = usb_parse_cfg_descr(
	    child_ud->usb_cfg_array[config_index], USB_CFG_DESCR_SIZE,
	    &config_descriptor, USB_CFG_DESCR_SIZE);
	ASSERT(size == USB_CFG_DESCR_SIZE);

	def_ph = usba_get_dflt_pipe_handle(child_dip);

	/* Set the configuration */
	(void) usb_pipe_sync_ctrl_xfer(child_dip, def_ph,
	    USB_DEV_REQ_HOST_TO_DEV,
	    USB_REQ_SET_CFG,	/* bRequest */
	    config_descriptor.bConfigurationValue,	/* wValue */
	    0,				/* wIndex */
	    0,				/* wLength */
	    NULL,
	    0,
	    &completion_reason,
	    &cb_flags,
	    0);

	mutex_enter(&child_ud->usb_mutex);
	child_ud->usb_active_cfg_ndx	= config_index;
	child_ud->usb_cfg		= child_ud->usb_cfg_array[config_index];
	child_ud->usb_cfg_length	= config_descriptor.wTotalLength;
	child_ud->usb_cfg_value 	= config_descriptor.bConfigurationValue;
	child_ud->usb_n_ifs		= config_descriptor.bNumInterfaces;
	child_ud->usb_dip		= child_dip;

	child_ud->usb_client_flags	= kmem_zalloc(
	    child_ud->usb_n_ifs * USBA_CLIENT_FLAG_SIZE, KM_SLEEP);

	child_ud->usb_client_attach_list = kmem_zalloc(
	    child_ud->usb_n_ifs *
	    sizeof (*child_ud->usb_client_attach_list), KM_SLEEP);

	child_ud->usb_client_ev_cb_list = kmem_zalloc(
	    child_ud->usb_n_ifs *
	    sizeof (*child_ud->usb_client_ev_cb_list), KM_SLEEP);

	mutex_exit(&child_ud->usb_mutex);

	/* ready the device node */
	child_dip = usba_ready_device_node(child_dip);

	/* set owner of default pipe to child dip */
	ph = usba_get_ph_data(def_ph);
	mutex_enter(&ph->p_mutex);
	mutex_enter(&ph->p_ph_impl->usba_ph_mutex);
	ph->p_ph_impl->usba_ph_dip = ph->p_dip = child_dip;
	mutex_exit(&ph->p_ph_impl->usba_ph_mutex);
	mutex_exit(&ph->p_mutex);

	return (child_dip);
}


/*
 * hubd_create_child
 *	- create child dip
 *	- open default pipe
 *	- get device descriptor
 *	- set the address
 *	- get device string descriptors
 *	- get the entire config cloud (all configurations) of the device
 *	- set user preferred configuration
 *	- close default pipe
 *	- load appropriate driver(s)
 */
static int
hubd_create_child(dev_info_t *dip,
		hubd_t		*hubd,
		usba_device_t	*hubd_ud,
		usb_port_status_t port_status,
		usb_port_t	port,
		int		iteration)
{
	dev_info_t		*child_dip = NULL;
	usb_dev_descr_t	usb_dev_descr;
	int			rval;
	usba_device_t		*child_ud = NULL;
	usba_device_t		*parent_ud = NULL;
	usb_pipe_handle_t	ph = NULL; /* default pipe handle */
	mblk_t			*pdata = NULL;
	usb_cr_t		completion_reason;
	int			user_conf_index;
	uint_t			config_index;
	usb_cb_flags_t		cb_flags;
	uchar_t			address = 0;
	uint16_t		length;
	size_t			size;
	usb_addr_t		parent_usb_addr;
	usb_port_t		parent_usb_port;
	usba_device_t		*parent_usba_dev;
	usb_port_status_t	parent_port_status;

	USB_DPRINTF_L4(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "hubd_create_child: port=%d", port);

	ASSERT(mutex_owned(HUBD_MUTEX(hubd)));
	ASSERT(hubd->h_usba_devices[port] == NULL);

	mutex_exit(HUBD_MUTEX(hubd));

	/*
	 * create a dip which can be used to open the pipe. we set
	 * the name after getting the descriptors from the device
	 */
	rval = usba_create_child_devi(dip,
	    "device",		/* driver name */
	    hubd_ud->usb_hcdi_ops, /* usba_hcdi ops */
	    hubd_ud->usb_root_hub_dip,
	    port_status,		/* low speed device */
	    child_ud,
	    &child_dip);

	if (rval != USB_SUCCESS) {

		USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "usb_create_child_devi failed (%d)", rval);

		goto fail_cleanup;
	}

	child_ud = usba_get_usba_device(child_dip);
	ASSERT(child_ud != NULL);

	parent_ud = hubd->h_usba_device;
	mutex_enter(&parent_ud->usb_mutex);
	parent_port_status = parent_ud->usb_port_status;

	/*
	 * To support split transactions, update address and port
	 * of high speed hub to which given device is connected.
	 */
	if (parent_port_status == USBA_HIGH_SPEED_DEV) {
		parent_usba_dev = parent_ud;
		parent_usb_addr = parent_ud->usb_addr;
		parent_usb_port = port;
	} else {
		parent_usba_dev = parent_ud->usb_hs_hub_usba_dev;
		parent_usb_addr = parent_ud->usb_hs_hub_addr;
		parent_usb_port = parent_ud->usb_hs_hub_port;
	}
	mutex_exit(&parent_ud->usb_mutex);

	mutex_enter(&child_ud->usb_mutex);
	address = child_ud->usb_addr;
	child_ud->usb_addr = 0;
	child_ud->usb_dev_descr = kmem_alloc(sizeof (usb_dev_descr_t),
	    KM_SLEEP);
	bzero(&usb_dev_descr, sizeof (usb_dev_descr_t));
	usb_dev_descr.bMaxPacketSize0 =
	    (port_status == USBA_LOW_SPEED_DEV) ? 8 : 64;
	bcopy(&usb_dev_descr, child_ud->usb_dev_descr,
	    sizeof (usb_dev_descr_t));
	child_ud->usb_port = port;
	child_ud->usb_hs_hub_usba_dev = parent_usba_dev;
	child_ud->usb_hs_hub_addr = parent_usb_addr;
	child_ud->usb_hs_hub_port = parent_usb_port;
	mutex_exit(&child_ud->usb_mutex);

	/* Open the default pipe */
	if ((rval = usb_pipe_open(child_dip, NULL, NULL,
	    USB_FLAGS_SLEEP | USBA_FLAGS_PRIVILEGED, &ph)) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "usb_pipe_open failed (%d)", rval);

		goto fail_cleanup;
	}

	/*
	 * get device descriptor
	 */
	USB_DPRINTF_L4(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "hubd_create_child: get device descriptor: 64 bytes");

	rval = usb_pipe_sync_ctrl_xfer(child_dip, ph,
	    USB_DEV_REQ_DEV_TO_HOST | USB_DEV_REQ_TYPE_STANDARD,
	    USB_REQ_GET_DESCR,			/* bRequest */
	    USB_DESCR_TYPE_SETUP_DEV,		/* wValue */
	    0,					/* wIndex */
	    64,					/* wLength */
	    &pdata, USB_ATTRS_SHORT_XFER_OK,
	    &completion_reason, &cb_flags, 0);

	if ((rval != USB_SUCCESS) &&
	    (!((completion_reason == USB_CR_DATA_OVERRUN) && pdata))) {

		/*
		 * rval != USB_SUCCESS AND
		 * completion_reason != USB_CR_DATA_OVERRUN
		 * pdata could be != NULL.
		 * Free pdata now to prevent memory leak.
		 */
		freemsg(pdata);
		pdata = NULL;

		USB_DPRINTF_L4(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "hubd_create_child: get device descriptor: 8 bytes");

		rval = usb_pipe_sync_ctrl_xfer(child_dip, ph,
		    USB_DEV_REQ_DEV_TO_HOST | USB_DEV_REQ_TYPE_STANDARD,
		    USB_REQ_GET_DESCR,			/* bRequest */
		    USB_DESCR_TYPE_SETUP_DEV,		/* wValue */
		    0,					/* wIndex */
		    8,					/* wLength */
		    &pdata, USB_ATTRS_NONE,
		    &completion_reason, &cb_flags, 0);

		if (rval != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
			    "getting device descriptor failed (%s 0x%x %d)",
			    usb_str_cr(completion_reason), cb_flags, rval);
			goto fail_cleanup;
		}
	} else {
		ASSERT(completion_reason == USB_CR_OK);
	}

	ASSERT(pdata != NULL);

	size = usb_parse_dev_descr(
	    pdata->b_rptr,
	    MBLKL(pdata),
	    &usb_dev_descr,
	    sizeof (usb_dev_descr_t));

	USB_DPRINTF_L4(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "parsing device descriptor returned %lu", size);

	length = *(pdata->b_rptr);
	freemsg(pdata);
	pdata = NULL;
	if (size < 8) {
		USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "get device descriptor returned %lu bytes", size);

		goto fail_cleanup;
	}

	if (length < 8) {
		USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "fail enumeration: bLength=%d", length);

		goto fail_cleanup;
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
		USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "setting address failed (cr=%s cb_flags=%s rval=%d)",
		    usb_str_cr(completion_reason),
		    usb_str_cb_flags(cb_flags, buffer, sizeof (buffer)),
		    rval);

		goto fail_cleanup;
	}

	USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "set address 0x%x done", address);

	/* now close the pipe for addr 0 */
	usb_pipe_close(child_dip, ph,
	    USB_FLAGS_SLEEP | USBA_FLAGS_PRIVILEGED, NULL, NULL);

	/*
	 * This delay is important for the CATC hub to enumerate
	 * But, avoid delay in the first iteration
	 */
	if (iteration) {
		delay(drv_usectohz(hubd_device_delay/100));
	}

	/* assign the address in the usba_device structure */
	mutex_enter(&child_ud->usb_mutex);
	child_ud->usb_addr = address;
	child_ud->usb_no_cpr = 0;
	child_ud->usb_port_status = port_status;
	/* save this device descriptor */
	bcopy(&usb_dev_descr, child_ud->usb_dev_descr,
	    sizeof (usb_dev_descr_t));
	child_ud->usb_n_cfgs = usb_dev_descr.bNumConfigurations;
	mutex_exit(&child_ud->usb_mutex);

	/* re-open the pipe for the device with the new address */
	if ((rval = usb_pipe_open(child_dip, NULL, NULL,
	    USB_FLAGS_SLEEP | USBA_FLAGS_PRIVILEGED, &ph)) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "usb_pipe_open failed (%d)", rval);

		goto fail_cleanup;
	}

	/*
	 * Get full device descriptor only if we have not received full
	 * device descriptor earlier.
	 */
	if (size < length) {
		USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "hubd_create_child: get full device descriptor: "
		    "%d bytes", length);

		if ((rval = usb_pipe_sync_ctrl_xfer(child_dip, ph,
		    USB_DEV_REQ_DEV_TO_HOST | USB_DEV_REQ_TYPE_STANDARD,
		    USB_REQ_GET_DESCR,			/* bRequest */
		    USB_DESCR_TYPE_SETUP_DEV,		/* wValue */
		    0,					/* wIndex */
		    length,				/* wLength */
		    &pdata, 0,
		    &completion_reason, &cb_flags, 0)) != USB_SUCCESS) {
			freemsg(pdata);
			pdata = NULL;

			USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG,
			    hubd->h_log_handle,
			    "hubd_create_child: get full device descriptor: "
			    "64 bytes");

			rval = usb_pipe_sync_ctrl_xfer(child_dip, ph,
			    USB_DEV_REQ_DEV_TO_HOST |
			    USB_DEV_REQ_TYPE_STANDARD,
			    USB_REQ_GET_DESCR,		/* bRequest */
			    USB_DESCR_TYPE_SETUP_DEV,	/* wValue */
			    0,				/* wIndex */
			    64,				/* wLength */
			    &pdata, USB_ATTRS_SHORT_XFER_OK,
			    &completion_reason, &cb_flags, 0);

			/* we have to trust the data now */
			if (pdata) {
				int len = *(pdata->b_rptr);

				length = MBLKL(pdata);
				if (length < len) {

					goto fail_cleanup;
				}
			} else if (rval != USB_SUCCESS) {
				USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG,
				    hubd->h_log_handle,
				    "getting device descriptor failed "
				    "(%d 0x%x %d)",
				    completion_reason, cb_flags, rval);

				goto fail_cleanup;
			}
		}

		size = usb_parse_dev_descr(
		    pdata->b_rptr,
		    MBLKL(pdata),
		    &usb_dev_descr,
		    sizeof (usb_dev_descr_t));

		USB_DPRINTF_L4(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "parsing device descriptor returned %lu", size);

		/*
		 * For now, free the data
		 * eventually, each configuration may need to be looked at
		 */
		freemsg(pdata);
		pdata = NULL;

		if (size != USB_DEV_DESCR_SIZE) {
			USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
			    "fail enumeration: descriptor size=%lu "
			    "expected size=%u", size, USB_DEV_DESCR_SIZE);

			goto fail_cleanup;
		}

		/*
		 * save the device descriptor in usba_device since it is needed
		 * later on again
		 */
		mutex_enter(&child_ud->usb_mutex);
		bcopy(&usb_dev_descr, child_ud->usb_dev_descr,
		    sizeof (usb_dev_descr_t));
		child_ud->usb_n_cfgs = usb_dev_descr.bNumConfigurations;
		mutex_exit(&child_ud->usb_mutex);
	}

	if (usb_dev_descr.bNumConfigurations == 0) {
		USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
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
		goto fail_cleanup;
	}


	/* get the device string descriptor(s) */
	usba_get_dev_string_descrs(child_dip, child_ud);

	/* retrieve config cloud for all configurations */
	rval = hubd_get_all_device_config_cloud(hubd, child_dip, child_ud);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "failed to get configuration descriptor(s)");

		goto fail_cleanup;
	}

	/* get the preferred configuration for this device */
	user_conf_index = hubd_select_device_configuration(hubd, port,
	    child_dip, child_ud);

	/* Check if the user selected configuration index is in range */
	if ((user_conf_index >= usb_dev_descr.bNumConfigurations) ||
	    (user_conf_index < 0)) {
		USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "Configuration index for device idVendor=%d "
		    "idProduct=%d is=%d, and is out of range[0..%d]",
		    usb_dev_descr.idVendor, usb_dev_descr.idProduct,
		    user_conf_index, usb_dev_descr.bNumConfigurations - 1);

		/* treat this as user didn't specify configuration */
		user_conf_index = USBA_DEV_CONFIG_INDEX_UNDEFINED;
	}


	/*
	 * Warn users of a performance hit if connecting a
	 * High Speed behind a 1.1 hub, which is behind a
	 * 2.0 port.
	 */
	if ((parent_port_status != USBA_HIGH_SPEED_DEV) &&
	    !(usba_is_root_hub(parent_ud->usb_dip)) &&
	    (parent_usb_addr)) {

		/*
		 * Now that we know the root port is a high speed port
		 * and that the parent port is not a high speed port,
		 * let's find out if the device itself is a high speed
		 * device.  If it is a high speed device,
		 * USB_DESCR_TYPE_SETUP_DEV_QLF should return a value,
		 * otherwise the command will fail.
		 */
		rval = usb_pipe_sync_ctrl_xfer(child_dip, ph,
		    USB_DEV_REQ_DEV_TO_HOST | USB_DEV_REQ_TYPE_STANDARD,
		    USB_REQ_GET_DESCR,			/* bRequest */
		    USB_DESCR_TYPE_SETUP_DEV_QLF,	/* wValue */
		    0,					/* wIndex */
		    10,					/* wLength */
		    &pdata, USB_ATTRS_SHORT_XFER_OK,
		    &completion_reason, &cb_flags, 0);

		if (pdata) {
			freemsg(pdata);
			pdata = NULL;
		}

		/*
		 * USB_DESCR_TYPE_SETUP_DEV_QLF query was successful
		 * that means this is a high speed device behind a
		 * high speed root hub, but running at full speed
		 * because there is a full speed hub in the middle.
		 */
		if (rval == USB_SUCCESS) {
			USB_DPRINTF_L0(DPRINT_MASK_HOTPLUG,
			    hubd->h_log_handle,
			    "Connecting a high speed device to a "
			    "non high speed hub (port %d) will result "
			    "in a loss of performance.	Please connect "
			    "the device to a high speed hub to get "
			    "the maximum performance.",
			    port);
		}
	}

	/*
	 * Now we try to online the device by attaching a driver
	 * The following truth table illustrates the logic:-
	 * Cfgndx	Driver	Action
	 * 0		0	loop all configs for driver with full
	 *			compatible properties.
	 * 0		1	set first configuration,
	 *			compatible prop = drivername.
	 * 1		0	Set config, full compatible prop
	 * 1		1	Set config, compatible prop = drivername.
	 *
	 * Note:
	 *	cfgndx = user_conf_index
	 *	Driver = usb_preferred_driver
	 */
	if (user_conf_index == USBA_DEV_CONFIG_INDEX_UNDEFINED) {
		if (child_ud->usb_preferred_driver) {
			/*
			 * It is the job of the "preferred driver" to put the
			 * device in the desired configuration. Till then
			 * put the device in config index 0.
			 */
			if ((rval = usba_hubdi_check_power_budget(dip, child_ud,
			    USB_DEV_DEFAULT_CONFIG_INDEX)) != USB_SUCCESS) {

				goto fail_cleanup;
			}

			child_dip = hubd_ready_device(hubd, child_dip,
			    child_ud, USB_DEV_DEFAULT_CONFIG_INDEX);

			/*
			 * Assign the dip before onlining to avoid race
			 * with busctl
			 */
			mutex_enter(HUBD_MUTEX(hubd));
			hubd->h_children_dips[port] = child_dip;
			mutex_exit(HUBD_MUTEX(hubd));

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

				child_dip = hubd_ready_device(hubd, child_dip,
				    child_ud, config_index);

				/*
				 * Assign the dip before onlining to avoid race
				 * with busctl
				 */
				mutex_enter(HUBD_MUTEX(hubd));
				hubd->h_children_dips[port] = child_dip;
				mutex_exit(HUBD_MUTEX(hubd));

				rval = usba_bind_driver(child_dip);

				/*
				 * Normally power budget should be checked
				 * before device is configured. A failure in
				 * power budget checking will stop the device
				 * from being configured with current
				 * config_index and may enable the device to
				 * be configured in another configuration.
				 * This may break the user experience that a
				 * device which previously worked in config
				 * A now works in config B after power budget
				 * control is enabled. To avoid such situation,
				 * power budget checking is moved here and will
				 * fail the child creation directly if config
				 * A exceeds the power available.
				 */
				if (rval == USB_SUCCESS) {
					if ((usba_hubdi_check_power_budget(dip,
					    child_ud, config_index)) !=
					    USB_SUCCESS) {

						goto fail_cleanup;
					}
				}
			}
			if (rval != USB_SUCCESS) {

				if ((usba_hubdi_check_power_budget(dip,
				    child_ud, 0)) != USB_SUCCESS) {

					goto fail_cleanup;
				}

				child_dip = hubd_ready_device(hubd, child_dip,
				    child_ud, 0);
				mutex_enter(HUBD_MUTEX(hubd));
				hubd->h_children_dips[port] = child_dip;
				mutex_exit(HUBD_MUTEX(hubd));
			}
		} /* end else loop all configs */
	} else {

		if ((usba_hubdi_check_power_budget(dip, child_ud,
		    (uint_t)user_conf_index)) != USB_SUCCESS) {

			goto fail_cleanup;
		}

		child_dip = hubd_ready_device(hubd, child_dip,
		    child_ud, (uint_t)user_conf_index);

		/*
		 * Assign the dip before onlining to avoid race
		 * with busctl
		 */
		mutex_enter(HUBD_MUTEX(hubd));
		hubd->h_children_dips[port] = child_dip;
		mutex_exit(HUBD_MUTEX(hubd));

		(void) usba_bind_driver(child_dip);
	}

	usba_hubdi_decr_power_budget(dip, child_ud);

	mutex_enter(HUBD_MUTEX(hubd));
	if (hubd->h_usba_devices[port] == NULL) {
		hubd->h_usba_devices[port] = usba_get_usba_device(child_dip);
	} else {
		ASSERT(hubd->h_usba_devices[port] ==
		    usba_get_usba_device(child_dip));
	}

	return (USB_SUCCESS);


fail_cleanup:
	USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "hubd_create_child: fail_cleanup");

	mutex_enter(HUBD_MUTEX(hubd));
	hubd->h_children_dips[port] = NULL;
	mutex_exit(HUBD_MUTEX(hubd));

	if (pdata) {
		freemsg(pdata);
	}

	if (ph) {
		usb_pipe_close(child_dip, ph,
		    USB_FLAGS_SLEEP | USBA_FLAGS_PRIVILEGED, NULL, NULL);
	}

	if (child_dip) {
		int rval = usba_destroy_child_devi(child_dip,
		    NDI_DEVI_REMOVE);
		if (rval != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
			    "failure to remove child node");
		}
	}

	if (child_ud) {
		/* to make sure we free the address */
		mutex_enter(&child_ud->usb_mutex);
		child_ud->usb_addr = address;
		ASSERT(child_ud->usb_ref_count == 0);
		mutex_exit(&child_ud->usb_mutex);

		mutex_enter(HUBD_MUTEX(hubd));
		if (hubd->h_usba_devices[port] == NULL) {
			mutex_exit(HUBD_MUTEX(hubd));
			usba_free_usba_device(child_ud);
		} else {
			hubd_free_usba_device(hubd, hubd->h_usba_devices[port]);
			mutex_exit(HUBD_MUTEX(hubd));
		}
	}

	mutex_enter(HUBD_MUTEX(hubd));

	return (USB_FAILURE);
}


/*
 * hubd_delete_child:
 *	- free usb address
 *	- lookup child dips, there may be multiple on this port
 *	- offline each child devi
 */
static int
hubd_delete_child(hubd_t *hubd, usb_port_t port, uint_t flag, boolean_t retry)
{
	dev_info_t	*child_dip;
	usba_device_t	*usba_device;
	int		rval = USB_SUCCESS;

	child_dip = hubd->h_children_dips[port];
	usba_device = hubd->h_usba_devices[port];

	USB_DPRINTF_L4(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "hubd_delete_child: port=%d, dip=0x%p usba_device=0x%p",
	    port, (void *)child_dip, (void *)usba_device);

	mutex_exit(HUBD_MUTEX(hubd));
	if (child_dip) {
		USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "hubd_delete_child:\n\t"
		    "dip = 0x%p (%s) at port %d",
		    (void *)child_dip, ddi_node_name(child_dip), port);

		if (usba_device) {
			usba_hubdi_incr_power_budget(hubd->h_dip, usba_device);
		}

		rval = usba_destroy_child_devi(child_dip, flag);

		if ((rval != USB_SUCCESS) && usba_is_hwa(child_dip)) {
			/*
			 * This is only useful for HWA device node.
			 * Since hwahc interface must hold hwarc interface
			 * open until hwahc is detached, the first call to
			 * ndi_devi_unconfig_one() can only offline hwahc
			 * driver but not hwarc driver. Need to make a second
			 * call to ndi_devi_unconfig_one() to make the hwarc
			 * driver detach.
			 */
			rval = usba_destroy_child_devi(child_dip, flag);
		}

		if ((rval == USB_SUCCESS) && (flag & NDI_DEVI_REMOVE)) {
			/*
			 * if the child was still < DS_INITIALIZED
			 * then our bus_unconfig was not called and
			 * we have to zap the child here
			 */
			mutex_enter(HUBD_MUTEX(hubd));
			if (hubd->h_children_dips[port] == child_dip) {
				usba_device_t *ud =
				    hubd->h_usba_devices[port];
					hubd->h_children_dips[port] = NULL;
				if (ud) {
					mutex_exit(HUBD_MUTEX(hubd));

					mutex_enter(&ud->usb_mutex);
					ud->usb_ref_count = 0;
					mutex_exit(&ud->usb_mutex);

					usba_free_usba_device(ud);
					mutex_enter(HUBD_MUTEX(hubd));
					hubd->h_usba_devices[port] = NULL;
				}
			}
			mutex_exit(HUBD_MUTEX(hubd));
		}
	}

	if ((rval != USB_SUCCESS) && retry) {

		hubd_schedule_cleanup(usba_device->usb_root_hub_dip);
	}
	mutex_enter(HUBD_MUTEX(hubd));

	return (rval);
}


/*
 * hubd_free_usba_device:
 *	free usb device structure unless it is associated with
 *	the root hub which is handled differently
 */
static void
hubd_free_usba_device(hubd_t *hubd, usba_device_t *usba_device)
{
	USB_DPRINTF_L4(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "hubd_free_usba_device: hubd=0x%p, usba_device=0x%p",
	    (void *)hubd, (void *)usba_device);

	if (usba_device && (usba_device->usb_addr != ROOT_HUB_ADDR)) {
		usb_port_t port = usba_device->usb_port;
		dev_info_t *dip = hubd->h_children_dips[port];

#ifdef DEBUG
		if (dip) {
			ASSERT(i_ddi_node_state(dip) < DS_INITIALIZED);
		}
#endif

		port = usba_device->usb_port;
		hubd->h_usba_devices[port] = NULL;

		mutex_exit(HUBD_MUTEX(hubd));
		usba_free_usba_device(usba_device);
		mutex_enter(HUBD_MUTEX(hubd));
	}
}


/*
 * event support
 *
 * busctl event support
 */
static int
hubd_busop_get_eventcookie(dev_info_t *dip,
	dev_info_t	*rdip,
	char		*eventname,
	ddi_eventcookie_t *cookie)
{
	hubd_t	*hubd = (hubd_t *)hubd_get_soft_state(dip);

	USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "hubd_busop_get_eventcookie: dip=0x%p, rdip=0x%p, "
	    "event=%s", (void *)dip, (void *)rdip, eventname);
	USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "(dip=%s%d, rdip=%s%d)",
	    ddi_driver_name(dip), ddi_get_instance(dip),
	    ddi_driver_name(rdip), ddi_get_instance(rdip));

	/* return event cookie, iblock cookie, and level */
	return (ndi_event_retrieve_cookie(hubd->h_ndi_event_hdl,
	    rdip, eventname, cookie, NDI_EVENT_NOPASS));
}


static int
hubd_busop_add_eventcall(dev_info_t *dip,
	dev_info_t	*rdip,
	ddi_eventcookie_t cookie,
	void		(*callback)(dev_info_t *dip,
			ddi_eventcookie_t cookie, void *arg,
			void *bus_impldata),
	void *arg, ddi_callback_id_t *cb_id)
{
	hubd_t	*hubd = (hubd_t *)hubd_get_soft_state(dip);
	usb_port_t port = hubd_child_dip2port(hubd, rdip);

	USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "hubd_busop_add_eventcall: dip=0x%p, rdip=0x%p "
	    "cookie=0x%p, cb=0x%p, arg=0x%p",
	    (void *)dip, (void *)rdip, (void *)cookie, (void *)callback, arg);
	USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "(dip=%s%d, rdip=%s%d, event=%s)",
	    ddi_driver_name(dip), ddi_get_instance(dip),
	    ddi_driver_name(rdip), ddi_get_instance(rdip),
	    ndi_event_cookie_to_name(hubd->h_ndi_event_hdl, cookie));

	/* Set flag on children registering events */
	switch (ndi_event_cookie_to_tag(hubd->h_ndi_event_hdl, cookie)) {
	case USBA_EVENT_TAG_HOT_REMOVAL:
		mutex_enter(HUBD_MUTEX(hubd));
		hubd->h_child_events[port] |= HUBD_CHILD_EVENT_DISCONNECT;
		mutex_exit(HUBD_MUTEX(hubd));

		break;
	case USBA_EVENT_TAG_PRE_SUSPEND:
		mutex_enter(HUBD_MUTEX(hubd));
		hubd->h_child_events[port] |= HUBD_CHILD_EVENT_PRESUSPEND;
		mutex_exit(HUBD_MUTEX(hubd));

		break;
	default:

		break;
	}

	/* add callback to our event set */
	return (ndi_event_add_callback(hubd->h_ndi_event_hdl,
	    rdip, cookie, callback, arg, NDI_SLEEP, cb_id));
}


static int
hubd_busop_remove_eventcall(dev_info_t *dip, ddi_callback_id_t cb_id)
{
	hubd_t	*hubd = (hubd_t *)hubd_get_soft_state(dip);
	ndi_event_callbacks_t *id = (ndi_event_callbacks_t *)cb_id;

	USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "hubd_busop_remove_eventcall: dip=0x%p, rdip=0x%p "
	    "cookie=0x%p", (void *)dip, (void *)id->ndi_evtcb_dip,
	    (void *)id->ndi_evtcb_cookie);
	USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "(dip=%s%d, rdip=%s%d, event=%s)",
	    ddi_driver_name(dip), ddi_get_instance(dip),
	    ddi_driver_name(id->ndi_evtcb_dip),
	    ddi_get_instance(id->ndi_evtcb_dip),
	    ndi_event_cookie_to_name(hubd->h_ndi_event_hdl,
	    id->ndi_evtcb_cookie));

	/* remove event registration from our event set */
	return (ndi_event_remove_callback(hubd->h_ndi_event_hdl, cb_id));
}


/*
 * event distribution
 *
 * hubd_do_callback:
 *	Post this event to the specified child
 */
static void
hubd_do_callback(hubd_t *hubd, dev_info_t *cdip, ddi_eventcookie_t cookie)
{
	USB_DPRINTF_L4(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "hubd_do_callback");

	(void) ndi_event_do_callback(hubd->h_ndi_event_hdl, cdip, cookie, NULL);
}


/*
 * hubd_run_callbacks:
 *	Send this event to all children
 */
static void
hubd_run_callbacks(hubd_t *hubd, usba_event_t type)
{
	usb_port_t	port;

	USB_DPRINTF_L4(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "hubd_run_callbacks");

	mutex_enter(HUBD_MUTEX(hubd));
	for (port = 1; port <= hubd->h_hub_descr.bNbrPorts; port++) {
		/*
		 * the childen_dips list may have dips that have been
		 * already deallocated. we only get a post_detach notification
		 * but not a destroy notification
		 */
		if (hubd->h_children_dips[port]) {
			mutex_exit(HUBD_MUTEX(hubd));
			hubd_post_event(hubd, port, type);
			mutex_enter(HUBD_MUTEX(hubd));
		}
	}
	mutex_exit(HUBD_MUTEX(hubd));
}


/*
 * hubd_post_event
 *	post event to a child on the port depending on the type
 */
static void
hubd_post_event(hubd_t *hubd, usb_port_t port, usba_event_t type)
{
	int	rval;
	dev_info_t	*dip;
	usba_device_t	*usba_device;
	ddi_eventcookie_t cookie, rm_cookie, suspend_cookie;

	USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "hubd_post_event: port=%d event=%s", port,
	    ndi_event_tag_to_name(hubd->h_ndi_event_hdl, type));

	cookie = ndi_event_tag_to_cookie(hubd->h_ndi_event_hdl, type);
	rm_cookie = ndi_event_tag_to_cookie(hubd->h_ndi_event_hdl,
	    USBA_EVENT_TAG_HOT_REMOVAL);
	suspend_cookie = ndi_event_tag_to_cookie(hubd->h_ndi_event_hdl,
	    USBA_EVENT_TAG_PRE_SUSPEND);

	/*
	 * Hotplug daemon may be attaching a driver that may be registering
	 * event callbacks. So it already has got the device tree lock and
	 * event handle mutex. So to prevent a deadlock while posting events,
	 * we grab and release the locks in the same order.
	 */
	mutex_enter(HUBD_MUTEX(hubd));
	dip = hubd->h_children_dips[port];
	usba_device = hubd->h_usba_devices[port];
	mutex_exit(HUBD_MUTEX(hubd));

	switch (type) {
	case USBA_EVENT_TAG_HOT_REMOVAL:
		/* Clear the registered event flag */
		mutex_enter(HUBD_MUTEX(hubd));
		hubd->h_child_events[port] &= ~HUBD_CHILD_EVENT_DISCONNECT;
		mutex_exit(HUBD_MUTEX(hubd));

		hubd_do_callback(hubd, dip, cookie);
		usba_persistent_pipe_close(usba_device);

		/*
		 * Mark the dip for deletion only after the driver has
		 * seen the disconnect event to prevent cleanup thread
		 * from stepping in between.
		 */
		mutex_enter(&(DEVI(dip)->devi_lock));
		DEVI_SET_DEVICE_REMOVED(dip);
		mutex_exit(&(DEVI(dip)->devi_lock));

		break;
	case USBA_EVENT_TAG_PRE_SUSPEND:
		mutex_enter(HUBD_MUTEX(hubd));
		hubd->h_child_events[port] &= ~HUBD_CHILD_EVENT_PRESUSPEND;
		mutex_exit(HUBD_MUTEX(hubd));

		hubd_do_callback(hubd, dip, cookie);
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
		mutex_enter(HUBD_MUTEX(hubd));
		if (hubd->h_child_events[port] & HUBD_CHILD_EVENT_DISCONNECT) {
			/* clear the flag and post disconnect event */
			hubd->h_child_events[port] &=
			    ~HUBD_CHILD_EVENT_DISCONNECT;
			mutex_exit(HUBD_MUTEX(hubd));
			hubd_do_callback(hubd, dip, rm_cookie);
			usba_persistent_pipe_close(usba_device);
			mutex_enter(HUBD_MUTEX(hubd));
		}
		mutex_exit(HUBD_MUTEX(hubd));

		/*
		 * Mark the dip as reinserted to prevent cleanup thread
		 * from stepping in.
		 */
		mutex_enter(&(DEVI(dip)->devi_lock));
		DEVI_SET_DEVICE_REINSERTED(dip);
		mutex_exit(&(DEVI(dip)->devi_lock));

		rval = usba_persistent_pipe_open(usba_device);
		if (rval != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG,
			    hubd->h_log_handle,
			    "failed to reopen all pipes on reconnect");
		}

		hubd_do_callback(hubd, dip, cookie);

		/*
		 * We might see a connect event only if hotplug thread for
		 * disconnect event don't run in time.
		 * Set the flag again, so we don't miss posting a
		 * disconnect event.
		 */
		mutex_enter(HUBD_MUTEX(hubd));
		hubd->h_child_events[port] |= HUBD_CHILD_EVENT_DISCONNECT;
		mutex_exit(HUBD_MUTEX(hubd));

		break;
	case USBA_EVENT_TAG_POST_RESUME:
		/*
		 * Check if this child has missed the pre-suspend event before
		 * it registered for event callbacks
		 */
		mutex_enter(HUBD_MUTEX(hubd));
		if (hubd->h_child_events[port] & HUBD_CHILD_EVENT_PRESUSPEND) {
			/* clear the flag and post pre_suspend event */
			hubd->h_port_state[port] &=
			    ~HUBD_CHILD_EVENT_PRESUSPEND;
			mutex_exit(HUBD_MUTEX(hubd));
			hubd_do_callback(hubd, dip, suspend_cookie);
			mutex_enter(HUBD_MUTEX(hubd));
		}
		mutex_exit(HUBD_MUTEX(hubd));

		mutex_enter(&usba_device->usb_mutex);
		usba_device->usb_no_cpr = 0;
		mutex_exit(&usba_device->usb_mutex);

		/*
		 * Since the pipe has already been opened by hub
		 * at DDI_RESUME time, there is no need for a
		 * persistent pipe open
		 */
		hubd_do_callback(hubd, dip, cookie);

		/*
		 * Set the flag again, so we don't miss posting a
		 * pre-suspend event. This enforces a tighter
		 * dev_state model.
		 */
		mutex_enter(HUBD_MUTEX(hubd));
		hubd->h_child_events[port] |= HUBD_CHILD_EVENT_PRESUSPEND;
		mutex_exit(HUBD_MUTEX(hubd));
		break;
	}
}


/*
 * handling of events coming from above
 */
static int
hubd_disconnect_event_cb(dev_info_t *dip)
{
	hubd_t		*hubd = (hubd_t *)hubd_get_soft_state(dip);
	usb_port_t	port, nports;
	usba_device_t	*usba_dev;
	usba_event_t	tag = USBA_EVENT_TAG_HOT_REMOVAL;
	int		circ;

	USB_DPRINTF_L4(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "hubd_disconnect_event_cb: tag=%d", tag);

	ndi_devi_enter(dip, &circ);

	mutex_enter(HUBD_MUTEX(hubd));
	switch (hubd->h_dev_state) {
	case USB_DEV_ONLINE:
	case USB_DEV_PWRED_DOWN:
		hubd->h_dev_state = USB_DEV_DISCONNECTED;
		/* stop polling on the interrupt pipe */
		hubd_stop_polling(hubd);

		/* FALLTHROUGH */
	case USB_DEV_SUSPENDED:
		/* we remain in this state */
		mutex_exit(HUBD_MUTEX(hubd));
		hubd_run_callbacks(hubd, tag);
		mutex_enter(HUBD_MUTEX(hubd));

		/* close all the open pipes of our children */
		nports = hubd->h_hub_descr.bNbrPorts;
		for (port = 1; port <= nports; port++) {
			usba_dev = hubd->h_usba_devices[port];
			if (usba_dev != NULL) {
				mutex_exit(HUBD_MUTEX(hubd));
				usba_persistent_pipe_close(usba_dev);
				mutex_enter(HUBD_MUTEX(hubd));
			}
		}

		break;
	case USB_DEV_DISCONNECTED:
		/* avoid passing multiple disconnects to children */
		USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "hubd_disconnect_event_cb: Already disconnected");

		break;
	default:
		USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "hubd_disconnect_event_cb: Illegal devstate=%d",
		    hubd->h_dev_state);

		break;
	}
	mutex_exit(HUBD_MUTEX(hubd));

	ndi_devi_exit(dip, circ);

	return (USB_SUCCESS);
}


static int
hubd_reconnect_event_cb(dev_info_t *dip)
{
	int	rval, circ;

	ndi_devi_enter(dip, &circ);
	rval = hubd_restore_state_cb(dip);
	ndi_devi_exit(dip, circ);

	return (rval);
}


/*
 * hubd_pre_suspend_event_cb
 *	propogate event for binary compatibility of old drivers
 */
static int
hubd_pre_suspend_event_cb(dev_info_t *dip)
{
	int	circ;
	hubd_t	*hubd = (hubd_t *)hubd_get_soft_state(dip);

	USB_DPRINTF_L4(DPRINT_MASK_EVENTS, hubd->h_log_handle,
	    "hubd_pre_suspend_event_cb");

	/* disable hotplug thread */
	mutex_enter(HUBD_MUTEX(hubd));
	hubd->h_hotplug_thread++;
	hubd_stop_polling(hubd);

	/* keep PM out till we see a cpr resume */
	(void) hubd_pm_busy_component(hubd, hubd->h_dip, 0);
	mutex_exit(HUBD_MUTEX(hubd));

	ndi_devi_enter(dip, &circ);
	hubd_run_callbacks(hubd, USBA_EVENT_TAG_PRE_SUSPEND);
	ndi_devi_exit(dip, circ);

	return (USB_SUCCESS);
}


/*
 * hubd_post_resume_event_cb
 *	propogate event for binary compatibility of old drivers
 */
static int
hubd_post_resume_event_cb(dev_info_t *dip)
{
	int	circ;
	hubd_t	*hubd = (hubd_t *)hubd_get_soft_state(dip);

	USB_DPRINTF_L4(DPRINT_MASK_EVENTS, hubd->h_log_handle,
	    "hubd_post_resume_event_cb");

	ndi_devi_enter(dip, &circ);
	hubd_run_callbacks(hubd, USBA_EVENT_TAG_POST_RESUME);
	ndi_devi_exit(dip, circ);

	mutex_enter(HUBD_MUTEX(hubd));

	/* enable PM */
	(void) hubd_pm_idle_component(hubd, hubd->h_dip, 0);

	/* allow hotplug thread */
	hubd->h_hotplug_thread--;

	/* start polling */
	hubd_start_polling(hubd, 0);
	mutex_exit(HUBD_MUTEX(hubd));

	return (USB_SUCCESS);
}


/*
 * hubd_cpr_suspend
 *	save the current state of the driver/device
 */
static int
hubd_cpr_suspend(hubd_t *hubd)
{
	usb_port_t	port, nports;
	usba_device_t	*usba_dev;
	uchar_t		no_cpr = 0;
	int		rval = USB_FAILURE;

	USB_DPRINTF_L4(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "hubd_cpr_suspend: Begin");

	/* Make sure device is powered up to save state. */
	mutex_enter(HUBD_MUTEX(hubd));
	hubd_pm_busy_component(hubd, hubd->h_dip, 0);
	mutex_exit(HUBD_MUTEX(hubd));

	/* bring the device to full power */
	(void) pm_raise_power(hubd->h_dip, 0, USB_DEV_OS_FULL_PWR);
	mutex_enter(HUBD_MUTEX(hubd));

	switch (hubd->h_dev_state) {
	case USB_DEV_ONLINE:
	case USB_DEV_PWRED_DOWN:
	case USB_DEV_DISCONNECTED:
		/* find out if all our children have been quiesced */
		nports = hubd->h_hub_descr.bNbrPorts;
		for (port = 1; (no_cpr == 0) && (port <= nports); port++) {
			usba_dev = hubd->h_usba_devices[port];
			if (usba_dev != NULL) {
				mutex_enter(&usba_dev->usb_mutex);
				no_cpr += usba_dev->usb_no_cpr;
				mutex_exit(&usba_dev->usb_mutex);
			}
		}
		if (no_cpr > 0) {
			USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
			    "Children busy - can't checkpoint");
			/* remain in same state to fail checkpoint */

			break;
		} else {
			/*
			 * do not suspend if our hotplug thread
			 * or the deathrow thread is active
			 */
			if ((hubd->h_hotplug_thread > 1) ||
			    (hubd->h_cleanup_active == B_TRUE)) {
				USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG,
				    hubd->h_log_handle,
				    "hotplug thread active  - can't cpr");
				/* remain in same state to fail checkpoint */

				break;
			}

			/* quiesce ourselves now */
			hubd_stop_polling(hubd);

			/* close all the open pipes of our children */
			for (port = 1; port <= nports; port++) {
				usba_dev = hubd->h_usba_devices[port];
				if (usba_dev != NULL) {
					mutex_exit(HUBD_MUTEX(hubd));
					usba_persistent_pipe_close(usba_dev);
					if (hubd_suspend_port(hubd, port)) {
						USB_DPRINTF_L0(
						    DPRINT_MASK_HOTPLUG,
						    hubd->h_log_handle,
						    "suspending port %d failed",
						    port);
					}
					mutex_enter(HUBD_MUTEX(hubd));
				}

			}
			hubd->h_dev_state = USB_DEV_SUSPENDED;

			/*
			 * if we are the root hub, we close our pipes
			 * ourselves.
			 */
			if (usba_is_root_hub(hubd->h_dip)) {
				mutex_exit(HUBD_MUTEX(hubd));
				usba_persistent_pipe_close(
				    usba_get_usba_device(hubd->h_dip));
				mutex_enter(HUBD_MUTEX(hubd));
			}
			rval = USB_SUCCESS;

			break;
		}
	case USB_DEV_SUSPENDED:
	default:
		USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "hubd_cpr_suspend: Illegal dev state=%d",
		    hubd->h_dev_state);

		break;
	}

	hubd_pm_idle_component(hubd, hubd->h_dip, 0);
	mutex_exit(HUBD_MUTEX(hubd));

	return (rval);
}

static void
hubd_cpr_resume(dev_info_t *dip)
{
	int	rval, circ;

	ndi_devi_enter(dip, &circ);
	/*
	 * if we are the root hub, we open our pipes
	 * ourselves.
	 */
	if (usba_is_root_hub(dip)) {
		rval = usba_persistent_pipe_open(
		    usba_get_usba_device(dip));
		ASSERT(rval == USB_SUCCESS);
	}
	(void) hubd_restore_state_cb(dip);
	ndi_devi_exit(dip, circ);
}


/*
 * hubd_restore_state_cb
 *	Event callback to restore device state
 */
static int
hubd_restore_state_cb(dev_info_t *dip)
{
	hubd_t	*hubd = (hubd_t *)hubd_get_soft_state(dip);

	USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "hubd_restore_state_cb: Begin");

	/* restore the state of this device */
	hubd_restore_device_state(dip, hubd);

	return (USB_SUCCESS);
}


/*
 * registering for events
 */
static int
hubd_register_events(hubd_t *hubd)
{
	int		rval = USB_SUCCESS;

	if (usba_is_root_hub(hubd->h_dip)) {
		hubd_register_cpr_callback(hubd);
	} else {
		rval = usb_register_event_cbs(hubd->h_dip, &hubd_events, 0);
	}

	return (rval);
}


/*
 * hubd cpr callback related functions
 *
 * hubd_cpr_post_user_callb:
 *	This function is called during checkpoint & resume -
 *		1. after user threads are stopped during checkpoint
 *		2. after kernel threads are resumed during resume
 */
/* ARGSUSED */
static boolean_t
hubd_cpr_post_user_callb(void *arg, int code)
{
	hubd_cpr_t	*cpr_cb = (hubd_cpr_t *)arg;
	hubd_t		*hubd = cpr_cb->statep;
	int		retry = 0;

	USB_DPRINTF_L4(DPRINT_MASK_EVENTS, hubd->h_log_handle,
	    "hubd_cpr_post_user_callb");

	switch (code) {
	case CB_CODE_CPR_CHKPT:
		USB_DPRINTF_L3(DPRINT_MASK_EVENTS, hubd->h_log_handle,
		    "hubd_cpr_post_user_callb: CB_CODE_CPR_CHKPT");

		mutex_enter(HUBD_MUTEX(hubd));

		/* turn off deathrow thread */
		hubd->h_cleanup_enabled = B_FALSE;

		/* give up if deathrow thread doesn't exit */
		while ((hubd->h_cleanup_active == B_TRUE) && (retry++ < 3)) {
			mutex_exit(HUBD_MUTEX(hubd));
			delay(drv_usectohz(hubd_dip_cleanup_delay));

			USB_DPRINTF_L2(DPRINT_MASK_EVENTS, hubd->h_log_handle,
			    "hubd_cpr_post_user_callb, waiting for "
			    "deathrow thread to exit");
			mutex_enter(HUBD_MUTEX(hubd));
		}

		mutex_exit(HUBD_MUTEX(hubd));

		/* save the state of the device */
		(void) hubd_pre_suspend_event_cb(hubd->h_dip);

		return (B_TRUE);
	case CB_CODE_CPR_RESUME:
		USB_DPRINTF_L3(DPRINT_MASK_EVENTS, hubd->h_log_handle,
		    "hubd_cpr_post_user_callb: CB_CODE_CPR_RESUME");

		/* restore the state of the device */
		(void) hubd_post_resume_event_cb(hubd->h_dip);

		/* turn on deathrow thread */
		mutex_enter(HUBD_MUTEX(hubd));
		hubd->h_cleanup_enabled = B_TRUE;
		mutex_exit(HUBD_MUTEX(hubd));

		hubd_schedule_cleanup(hubd->h_usba_device->usb_root_hub_dip);

		return (B_TRUE);
	default:

		return (B_FALSE);
	}

}


/* register callback with cpr framework */
void
hubd_register_cpr_callback(hubd_t *hubd)
{
	USB_DPRINTF_L4(DPRINT_MASK_EVENTS, hubd->h_log_handle,
	    "hubd_register_cpr_callback");

	mutex_enter(HUBD_MUTEX(hubd));
	hubd->h_cpr_cb =
	    (hubd_cpr_t *)kmem_zalloc(sizeof (hubd_cpr_t), KM_SLEEP);
	mutex_exit(HUBD_MUTEX(hubd));
	mutex_init(&hubd->h_cpr_cb->lockp, NULL, MUTEX_DRIVER,
	    hubd->h_dev_data->dev_iblock_cookie);
	hubd->h_cpr_cb->statep = hubd;
	hubd->h_cpr_cb->cpr.cc_lockp = &hubd->h_cpr_cb->lockp;
	hubd->h_cpr_cb->cpr.cc_id = callb_add(hubd_cpr_post_user_callb,
	    (void *)hubd->h_cpr_cb, CB_CL_CPR_POST_USER, "hubd");
}


/* unregister callback with cpr framework */
void
hubd_unregister_cpr_callback(hubd_t *hubd)
{
	USB_DPRINTF_L4(DPRINT_MASK_EVENTS, hubd->h_log_handle,
	    "hubd_unregister_cpr_callback");

	if (hubd->h_cpr_cb) {
		(void) callb_delete(hubd->h_cpr_cb->cpr.cc_id);
		mutex_destroy(&hubd->h_cpr_cb->lockp);
		mutex_enter(HUBD_MUTEX(hubd));
		kmem_free(hubd->h_cpr_cb, sizeof (hubd_cpr_t));
		mutex_exit(HUBD_MUTEX(hubd));
	}
}


/*
 * Power management
 *
 * create the pm components required for power management
 */
static void
hubd_create_pm_components(dev_info_t *dip, hubd_t *hubd)
{
	hub_power_t	*hubpm;

	USB_DPRINTF_L4(DPRINT_MASK_PM, hubd->h_log_handle,
	    "hubd_create_pm_components: Begin");

	/* Allocate the state structure */
	hubpm = kmem_zalloc(sizeof (hub_power_t), KM_SLEEP);

	hubd->h_hubpm = hubpm;
	hubpm->hubp_hubd = hubd;
	hubpm->hubp_pm_capabilities = 0;
	hubpm->hubp_current_power = USB_DEV_OS_FULL_PWR;
	hubpm->hubp_time_at_full_power = gethrtime();
	hubpm->hubp_min_pm_threshold = hubdi_min_pm_threshold * NANOSEC;

	/* alloc memory to save power states of children */
	hubpm->hubp_child_pwrstate = (uint8_t *)
	    kmem_zalloc(MAX_PORTS + 1, KM_SLEEP);

	/*
	 * if the enable remote wakeup fails
	 * we still want to enable
	 * parent notification so we can PM the children
	 */
	usb_enable_parent_notification(dip);

	if (usb_handle_remote_wakeup(dip,
	    USB_REMOTE_WAKEUP_ENABLE) == USB_SUCCESS) {
		uint_t		pwr_states;

		USB_DPRINTF_L2(DPRINT_MASK_PM, hubd->h_log_handle,
		    "hubd_create_pm_components: "
		    "Remote Wakeup Enabled");

		if (usb_create_pm_components(dip, &pwr_states) ==
		    USB_SUCCESS) {
			mutex_enter(HUBD_MUTEX(hubd));
			hubpm->hubp_wakeup_enabled = 1;
			hubpm->hubp_pwr_states = (uint8_t)pwr_states;

			/* we are busy now till end of the attach */
			hubd_pm_busy_component(hubd, dip, 0);
			mutex_exit(HUBD_MUTEX(hubd));

			/* bring the device to full power */
			(void) pm_raise_power(dip, 0,
			    USB_DEV_OS_FULL_PWR);
		}
	}

	USB_DPRINTF_L4(DPRINT_MASK_PM, hubd->h_log_handle,
	    "hubd_create_pm_components: END");
}


/*
 * Attachment point management
 */
/* ARGSUSED */
int
usba_hubdi_open(dev_info_t *dip, dev_t *devp, int flags, int otyp,
	cred_t *credp)
{
	hubd_t *hubd;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	hubd = hubd_get_soft_state(dip);
	if (hubd == NULL) {
		return (ENXIO);
	}

	USB_DPRINTF_L4(DPRINT_MASK_CBOPS, hubd->h_log_handle,
	    "hubd_open:");

	mutex_enter(HUBD_MUTEX(hubd));
	if ((flags & FEXCL) && (hubd->h_softstate & HUBD_SS_ISOPEN)) {
		mutex_exit(HUBD_MUTEX(hubd));

		return (EBUSY);
	}

	hubd->h_softstate |= HUBD_SS_ISOPEN;
	mutex_exit(HUBD_MUTEX(hubd));

	USB_DPRINTF_L4(DPRINT_MASK_CBOPS, hubd->h_log_handle, "opened");

	return (0);
}


/* ARGSUSED */
int
usba_hubdi_close(dev_info_t *dip, dev_t dev, int flag, int otyp,
	cred_t *credp)
{
	hubd_t *hubd;

	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	hubd = hubd_get_soft_state(dip);

	if (hubd == NULL) {
		return (ENXIO);
	}

	USB_DPRINTF_L4(DPRINT_MASK_CBOPS, hubd->h_log_handle, "hubd_close:");

	mutex_enter(HUBD_MUTEX(hubd));
	hubd->h_softstate &= ~HUBD_SS_ISOPEN;
	mutex_exit(HUBD_MUTEX(hubd));

	USB_DPRINTF_L4(DPRINT_MASK_CBOPS, hubd->h_log_handle, "closed");

	return (0);
}


/*
 * hubd_ioctl: cfgadm controls
 */
/* ARGSUSED */
int
usba_hubdi_ioctl(dev_info_t *self, dev_t dev, int cmd, intptr_t arg,
	int mode, cred_t *credp, int *rvalp)
{
	int			rv = 0;
	char			*msg;	/* for messages */
	hubd_t			*hubd;
	usb_port_t		port = 0;
	dev_info_t		*child_dip = NULL;
	dev_info_t		*rh_dip;
	devctl_ap_state_t	ap_state;
	struct devctl_iocdata	*dcp = NULL;
	usb_pipe_state_t	prev_pipe_state = 0;
	int			circ, rh_circ, prh_circ;

	if ((hubd = hubd_get_soft_state(self)) == NULL) {

		return (ENXIO);
	}

	rh_dip = hubd->h_usba_device->usb_root_hub_dip;

	USB_DPRINTF_L4(DPRINT_MASK_CBOPS, hubd->h_log_handle,
	    "usba_hubdi_ioctl: "
	    "cmd=%x, arg=%lx, mode=%x, cred=%p, rval=%p dev=0x%lx",
	    cmd, arg, mode, (void *)credp, (void *)rvalp, dev);

	/* read devctl ioctl data */
	if ((cmd != DEVCTL_AP_CONTROL) &&
	    (ndi_dc_allochdl((void *)arg, &dcp) != NDI_SUCCESS)) {

		return (EFAULT);
	}

	/*
	 * make sure the hub is connected before trying any
	 * of the following operations:
	 * configure, connect, disconnect
	 */
	mutex_enter(HUBD_MUTEX(hubd));

	switch (cmd) {
	case DEVCTL_AP_DISCONNECT:
	case DEVCTL_AP_UNCONFIGURE:
	case DEVCTL_AP_CONFIGURE:
		if (hubd->h_dev_state == USB_DEV_DISCONNECTED) {
			USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
			    "hubd: already gone");
			mutex_exit(HUBD_MUTEX(hubd));
			if (dcp) {
				ndi_dc_freehdl(dcp);
			}

			return (EIO);
		}

		/* FALLTHROUGH */
	case DEVCTL_AP_GETSTATE:
		if ((port = hubd_get_port_num(hubd, dcp)) == 0) {
			USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
			    "hubd: bad port");
			mutex_exit(HUBD_MUTEX(hubd));
			if (dcp) {
				ndi_dc_freehdl(dcp);
			}

			return (EINVAL);
		}
		break;

	case DEVCTL_AP_CONTROL:

		break;
	default:
		mutex_exit(HUBD_MUTEX(hubd));
		if (dcp) {
			ndi_dc_freehdl(dcp);
		}

		return (ENOTTY);
	}

	/* should not happen, just in case */
	if (hubd->h_dev_state == USB_DEV_SUSPENDED) {
		mutex_exit(HUBD_MUTEX(hubd));
		if (dcp) {
			ndi_dc_freehdl(dcp);
		}

		return (EIO);
	}

	if (hubd->h_reset_port[port]) {
		USB_DPRINTF_L2(DPRINT_MASK_CBOPS, hubd->h_log_handle,
		    "This port is resetting, just return");
		mutex_exit(HUBD_MUTEX(hubd));
		if (dcp) {
			ndi_dc_freehdl(dcp);
		}

		return (EIO);
	}

	hubd_pm_busy_component(hubd, hubd->h_dip, 0);
	mutex_exit(HUBD_MUTEX(hubd));

	/* go full power */
	(void) pm_raise_power(hubd->h_dip, 0, USB_DEV_OS_FULL_PWR);

	ndi_devi_enter(ddi_get_parent(rh_dip), &prh_circ);
	ndi_devi_enter(rh_dip, &rh_circ);
	ndi_devi_enter(hubd->h_dip, &circ);

	mutex_enter(HUBD_MUTEX(hubd));

	hubd->h_hotplug_thread++;

	/* stop polling if it was active */
	if (hubd->h_ep1_ph) {
		mutex_exit(HUBD_MUTEX(hubd));
		(void) usb_pipe_get_state(hubd->h_ep1_ph, &prev_pipe_state,
		    USB_FLAGS_SLEEP);
		mutex_enter(HUBD_MUTEX(hubd));

		if (prev_pipe_state == USB_PIPE_STATE_ACTIVE) {
			hubd_stop_polling(hubd);
		}
	}

	switch (cmd) {
	case DEVCTL_AP_DISCONNECT:
		if (hubd_delete_child(hubd, port,
		    NDI_DEVI_REMOVE, B_FALSE) != USB_SUCCESS) {
			rv = EIO;
		}

		break;
	case DEVCTL_AP_UNCONFIGURE:
		if (hubd_delete_child(hubd, port,
		    NDI_UNCONFIG, B_FALSE) != USB_SUCCESS) {
			rv = EIO;
		}

		break;
	case DEVCTL_AP_CONFIGURE:
		/* toggle port */
		if (hubd_toggle_port(hubd, port) != USB_SUCCESS) {
			rv = EIO;

			break;
		}

		(void) hubd_handle_port_connect(hubd, port);
		child_dip = hubd_get_child_dip(hubd, port);
		mutex_exit(HUBD_MUTEX(hubd));

		ndi_devi_exit(hubd->h_dip, circ);
		ndi_devi_exit(rh_dip, rh_circ);
		ndi_devi_exit(ddi_get_parent(rh_dip), prh_circ);
		if (child_dip == NULL) {
			rv = EIO;
		} else {
			ndi_hold_devi(child_dip);
			if (ndi_devi_online(child_dip, 0) != NDI_SUCCESS)
				rv = EIO;
			ndi_rele_devi(child_dip);
		}
		ndi_devi_enter(ddi_get_parent(rh_dip), &prh_circ);
		ndi_devi_enter(rh_dip, &rh_circ);
		ndi_devi_enter(hubd->h_dip, &circ);

		mutex_enter(HUBD_MUTEX(hubd));

		break;
	case DEVCTL_AP_GETSTATE:
		switch (hubd_cfgadm_state(hubd, port)) {
		case HUBD_CFGADM_DISCONNECTED:
			/* port previously 'disconnected' by cfgadm */
			ap_state.ap_rstate = AP_RSTATE_DISCONNECTED;
			ap_state.ap_ostate = AP_OSTATE_UNCONFIGURED;
			ap_state.ap_condition = AP_COND_OK;

			break;
		case HUBD_CFGADM_UNCONFIGURED:
			ap_state.ap_rstate = AP_RSTATE_CONNECTED;
			ap_state.ap_ostate = AP_OSTATE_UNCONFIGURED;
			ap_state.ap_condition = AP_COND_OK;

			break;
		case HUBD_CFGADM_CONFIGURED:
			ap_state.ap_rstate = AP_RSTATE_CONNECTED;
			ap_state.ap_ostate = AP_OSTATE_CONFIGURED;
			ap_state.ap_condition = AP_COND_OK;

			break;
		case HUBD_CFGADM_STILL_REFERENCED:
			ap_state.ap_rstate = AP_RSTATE_EMPTY;
			ap_state.ap_ostate = AP_OSTATE_CONFIGURED;
			ap_state.ap_condition = AP_COND_UNUSABLE;

			break;
		case HUBD_CFGADM_EMPTY:
		default:
			ap_state.ap_rstate = AP_RSTATE_EMPTY;
			ap_state.ap_ostate = AP_OSTATE_UNCONFIGURED;
			ap_state.ap_condition = AP_COND_OK;

			break;
		}

		ap_state.ap_last_change = (time_t)-1;
		ap_state.ap_error_code = 0;
		ap_state.ap_in_transition = 0;

		USB_DPRINTF_L4(DPRINT_MASK_CBOPS, hubd->h_log_handle,
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

		USB_DPRINTF_L3(DPRINT_MASK_CBOPS, hubd->h_log_handle,
		    "DEVCTL_AP_CONTROL: ioc: cmd=0x%x port=%d get_size=%d"
		    "\n\tbuf=0x%p, bufsiz=%d,  misc_arg=%d", ioc.cmd,
		    ioc.port, ioc.get_size, (void *)ioc.buf, ioc.bufsiz,
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
					USB_DPRINTF_L2(DPRINT_MASK_CBOPS,
					    hubd->h_log_handle,
					    "%s: get_size copyout failed", msg);
					rv = EIO;

					break;
				}
			} else {	/* send out the actual descr */
				usb_dev_descr_t *dev_descrp;

				/* check child_dip */
				if ((child_dip = hubd_get_child_dip(hubd,
				    ioc.port)) == NULL) {
					rv = EINVAL;

					break;
				}

				dev_descrp = usb_get_dev_descr(child_dip);
				if (ioc.bufsiz != sizeof (*dev_descrp)) {
					USB_DPRINTF_L2(DPRINT_MASK_CBOPS,
					    hubd->h_log_handle,
					    "%s: bufsize passed (%d) != sizeof "
					    "usba_device_descr_t (%d)", msg,
					    ioc.bufsiz, dev_descrp->bLength);
					rv = EINVAL;

					break;
				}

				if (ddi_copyout((void *)dev_descrp,
				    ioc.buf, ioc.bufsiz, mode) != 0) {
					USB_DPRINTF_L2(DPRINT_MASK_CBOPS,
					    hubd->h_log_handle,
					    "%s: copyout failed.", msg);
					rv = EIO;

					break;
				}
			}
			break;
		case USB_DESCR_TYPE_STRING:
		{
			char		*str;
			uint32_t	size;
			usba_device_t	*usba_device;

			msg = "DEVCTL_AP_CONTROL: GET_STRING_DESCR";
			USB_DPRINTF_L4(DPRINT_MASK_CBOPS, hubd->h_log_handle,
			    "%s: string request: %d", msg, ioc.misc_arg);

			/* recheck */
			if ((child_dip = hubd_get_child_dip(hubd, ioc.port)) ==
			    NULL) {
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
				USB_DPRINTF_L2(DPRINT_MASK_CBOPS,
				    hubd->h_log_handle,
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
					USB_DPRINTF_L2(DPRINT_MASK_CBOPS,
					    hubd->h_log_handle,
					    "%s: copyout of size failed.", msg);
					rv = EIO;

					break;
				}
			} else {
				if (size == 0) {
					USB_DPRINTF_L3(DPRINT_MASK_CBOPS,
					    hubd->h_log_handle,
					    "%s: String is NULL", msg);
					rv = EINVAL;

					break;
				}

				if (ioc.bufsiz != size) {
					USB_DPRINTF_L2(DPRINT_MASK_CBOPS,
					    hubd->h_log_handle,
					    "%s: string buf size wrong", msg);
					rv = EINVAL;

					break;
				}

				if (ddi_copyout((void *)str, ioc.buf,
				    ioc.bufsiz, mode) != 0) {
					USB_DPRINTF_L2(DPRINT_MASK_CBOPS,
					    hubd->h_log_handle,
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
			if ((child_dip = hubd_get_child_dip(hubd, ioc.port)) ==
			    NULL) {
				rv = EINVAL;

				break;
			}
			name = ddi_node_name(child_dip);
			if (name == NULL) {
				name = "unsupported";
			}
			name_len = strlen(name) + 1;

			msg = "DEVCTL_AP_CONTROL: HUBD_GET_CFGADM_NAME";
			USB_DPRINTF_L4(DPRINT_MASK_CBOPS, hubd->h_log_handle,
			    "%s: name=%s name_len=%d", msg, name, name_len);

			if (ioc.get_size) {
				if (ddi_copyout((void *)&name_len,
				    ioc.buf, ioc.bufsiz, mode) != 0) {
					USB_DPRINTF_L2(DPRINT_MASK_CBOPS,
					    hubd->h_log_handle,
					    "%s: copyout of size failed", msg);
					rv = EIO;

					break;
				}
			} else {
				if (ioc.bufsiz != name_len) {
					USB_DPRINTF_L2(DPRINT_MASK_CBOPS,
					    hubd->h_log_handle,
					    "%s: string buf length wrong", msg);
					rv = EINVAL;

					break;
				}

				if (ddi_copyout((void *)name, ioc.buf,
				    ioc.bufsiz, mode) != 0) {
					USB_DPRINTF_L2(DPRINT_MASK_CBOPS,
					    hubd->h_log_handle,
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
			USB_DPRINTF_L4(DPRINT_MASK_CBOPS, hubd->h_log_handle,
			    "%s", msg);

			/*
			 * Return the config index for the configuration
			 * currently in use.
			 * Recheck if child_dip exists
			 */
			if ((child_dip = hubd_get_child_dip(hubd, ioc.port)) ==
			    NULL) {
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
					USB_DPRINTF_L2(DPRINT_MASK_CBOPS,
					    hubd->h_log_handle,
					    "%s: copyout of size failed.", msg);
					rv = EIO;

					break;
				}
			} else {
				if (ioc.bufsiz != size) {
					USB_DPRINTF_L2(DPRINT_MASK_CBOPS,
					    hubd->h_log_handle,
					    "%s: buffer size wrong", msg);
					rv = EINVAL;

					break;
				}
				if (ddi_copyout((void *)&config_index,
				    ioc.buf, ioc.bufsiz, mode) != 0) {
					USB_DPRINTF_L2(DPRINT_MASK_CBOPS,
					    hubd->h_log_handle,
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
			USB_DPRINTF_L4(DPRINT_MASK_CBOPS, hubd->h_log_handle,
			    "%s", msg);

			/* Recheck if child_dip exists */
			if ((child_dip = hubd_get_child_dip(hubd, ioc.port)) ==
			    NULL) {
				rv = EINVAL;

				break;
			}

			/* ddi_pathname doesn't supply /devices, so we do. */
			path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
			(void) strcpy(path, "/devices");
			(void) ddi_pathname(child_dip, path + strlen(path));
			size = strlen(path) + 1;

			USB_DPRINTF_L4(DPRINT_MASK_CBOPS, hubd->h_log_handle,
			    "%s: device path=%s  size=%d", msg, path, size);

			if (ioc.get_size) {
				if (ddi_copyout((void *)&size,
				    ioc.buf, ioc.bufsiz, mode) != 0) {

					USB_DPRINTF_L2(DPRINT_MASK_CBOPS,
					    hubd->h_log_handle,
					    "%s: copyout of size failed.", msg);
					rv = EIO;
				}
			} else {
				if (ioc.bufsiz != size) {
					USB_DPRINTF_L2(DPRINT_MASK_CBOPS,
					    hubd->h_log_handle,
					    "%s: buffer wrong size.", msg);
					rv = EINVAL;
				} else if (ddi_copyout((void *)path,
				    ioc.buf, ioc.bufsiz, mode) != 0) {
					USB_DPRINTF_L2(DPRINT_MASK_CBOPS,
					    hubd->h_log_handle,
					    "%s: copyout failed.", msg);
					rv = EIO;
				}
			}
			kmem_free(path, MAXPATHLEN);

			break;
		}
		case HUBD_REFRESH_DEVDB:
			msg = "DEVCTL_AP_CONTROL: HUBD_REFRESH_DEVDB";
			USB_DPRINTF_L3(DPRINT_MASK_CBOPS, hubd->h_log_handle,
			    "%s", msg);

			if ((rv = usba_devdb_refresh()) != USB_SUCCESS) {
				USB_DPRINTF_L2(DPRINT_MASK_CBOPS,
				    hubd->h_log_handle,
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

	/* allow hotplug thread now */
	hubd->h_hotplug_thread--;

	if ((hubd->h_dev_state == USB_DEV_ONLINE) &&
	    hubd->h_ep1_ph && (prev_pipe_state == USB_PIPE_STATE_ACTIVE)) {
		hubd_start_polling(hubd, 0);
	}
	mutex_exit(HUBD_MUTEX(hubd));

	ndi_devi_exit(hubd->h_dip, circ);
	ndi_devi_exit(rh_dip, rh_circ);
	ndi_devi_exit(ddi_get_parent(rh_dip), prh_circ);

	mutex_enter(HUBD_MUTEX(hubd));
	hubd_pm_idle_component(hubd, hubd->h_dip, 0);
	mutex_exit(HUBD_MUTEX(hubd));

	return (rv);
}


/*
 * Helper func used only to help construct the names for the attachment point
 * minor nodes.  Used only in usba_hubdi_attach.
 * Returns whether it found ancestry or not (USB_SUCCESS if yes).
 * ports between the root hub and the device represented by dip.
 * E.g.,  "2.4.3.1" means this device is
 *	plugged into port 1 of a hub that is
 *	plugged into port 3 of a hub that is
 *	plugged into port 4 of a hub that is
 *	plugged into port 2 of the root hub.
 * NOTE: Max ap_id path len is HUBD_APID_NAMELEN (32 chars), which is
 * more than sufficient (as hubs are a max 6 levels deep, port needs 3
 * chars plus NULL each)
 */
void
hubd_get_ancestry_str(hubd_t *hubd)
{
	char		ap_name[HUBD_APID_NAMELEN];
	dev_info_t	*pdip;
	hubd_t		*phubd;
	usb_port_t	port;

	USB_DPRINTF_L4(DPRINT_MASK_ATTA, hubd->h_log_handle,
	    "hubd_get_ancestry_str: hubd=0x%p", (void *)hubd);

	ASSERT(mutex_owned(HUBD_MUTEX(hubd)));

	/*
	 * The function is extended to support wire adapter class
	 * devices introduced by WUSB spec. The node name is no
	 * longer "hub" only.
	 * Generate the ap_id str based on the parent and child
	 * relationship instead of retrieving it from the hub
	 * device path, which simplifies the algorithm.
	 */
	if (usba_is_root_hub(hubd->h_dip)) {
		hubd->h_ancestry_str[0] = '\0';
	} else {
		port = hubd->h_usba_device->usb_port;
		mutex_exit(HUBD_MUTEX(hubd));

		pdip = ddi_get_parent(hubd->h_dip);
		/*
		 * The parent of wire adapter device might be usb_mid.
		 * Need to look further up for hub device
		 */
		if (strcmp(ddi_driver_name(pdip), "usb_mid") == 0) {
			pdip = ddi_get_parent(pdip);
			ASSERT(pdip != NULL);
		}

		phubd = hubd_get_soft_state(pdip);

		mutex_enter(HUBD_MUTEX(phubd));
		(void) snprintf(ap_name, HUBD_APID_NAMELEN, "%s%d",
		    phubd->h_ancestry_str, port);
		mutex_exit(HUBD_MUTEX(phubd));

		mutex_enter(HUBD_MUTEX(hubd));
		(void) strcpy(hubd->h_ancestry_str, ap_name);
		(void) strcat(hubd->h_ancestry_str, ".");
	}
}


/* Get which port to operate on.  */
static usb_port_t
hubd_get_port_num(hubd_t *hubd, struct devctl_iocdata *dcp)
{
	int32_t port;

	ASSERT(mutex_owned(HUBD_MUTEX(hubd)));

	/* Get which port to operate on.  */
	if (nvlist_lookup_int32(ndi_dc_get_ap_data(dcp), "port", &port) != 0) {
		USB_DPRINTF_L2(DPRINT_MASK_CBOPS, hubd->h_log_handle,
		    "hubd_get_port_num: port lookup failed");
		port = 0;
	}

	USB_DPRINTF_L4(DPRINT_MASK_CBOPS,  hubd->h_log_handle,
	    "hubd_get_port_num: hubd=0x%p, port=%d", (void *)hubd, port);

	return ((usb_port_t)port);
}


/* check if child still exists */
static dev_info_t *
hubd_get_child_dip(hubd_t *hubd, usb_port_t port)
{
	dev_info_t *child_dip = hubd->h_children_dips[port];

	USB_DPRINTF_L4(DPRINT_MASK_CBOPS,  hubd->h_log_handle,
	    "hubd_get_child_dip: hubd=0x%p, port=%d", (void *)hubd, port);

	ASSERT(mutex_owned(HUBD_MUTEX(hubd)));

	return (child_dip);
}


/*
 * hubd_cfgadm_state:
 *
 *	child_dip list		port_state		cfgadm_state
 *	--------------		----------		------------
 *	!= NULL			connected		configured or
 *							unconfigured
 *	!= NULL			not connected		disconnect but
 *							busy/still referenced
 *	NULL			connected		logically disconnected
 *	NULL			not connected		empty
 */
static uint_t
hubd_cfgadm_state(hubd_t *hubd, usb_port_t port)
{
	uint_t		state;
	dev_info_t	*child_dip = hubd_get_child_dip(hubd, port);

	if (child_dip) {
		if (hubd->h_port_state[port] & PORT_STATUS_CCS) {
			/*
			 * connected,  now check if driver exists
			 */
			if (DEVI_IS_DEVICE_OFFLINE(child_dip) ||
			    !i_ddi_devi_attached(child_dip)) {
				state = HUBD_CFGADM_UNCONFIGURED;
			} else {
				state = HUBD_CFGADM_CONFIGURED;
			}
		} else {
			/*
			 * this means that the dip is around for
			 * a device that is still referenced but
			 * has been yanked out. So the cfgadm info
			 * for this state should be EMPTY (port empty)
			 * and CONFIGURED (dip still valid).
			 */
			state = HUBD_CFGADM_STILL_REFERENCED;
		}
	} else {
		/* connected but no child dip */
		if (hubd->h_port_state[port] & PORT_STATUS_CCS) {
			/* logically disconnected */
			state = HUBD_CFGADM_DISCONNECTED;
		} else {
			/* physically disconnected */
			state = HUBD_CFGADM_EMPTY;
		}
	}

	USB_DPRINTF_L4(DPRINT_MASK_CBOPS,  hubd->h_log_handle,
	    "hubd_cfgadm_state: hubd=0x%p, port=%d state=0x%x",
	    (void *)hubd, port, state);

	return (state);
}


/*
 * hubd_toggle_port:
 */
static int
hubd_toggle_port(hubd_t *hubd, usb_port_t port)
{
	usb_hub_descr_t	*hub_descr;
	int		wait;
	uint_t		retry;
	uint16_t	status;
	uint16_t	change;

	USB_DPRINTF_L4(DPRINT_MASK_CBOPS,  hubd->h_log_handle,
	    "hubd_toggle_port: hubd=0x%p, port=%d", (void *)hubd, port);

	if ((hubd_disable_port_power(hubd, port)) != USB_SUCCESS) {

		return (USB_FAILURE);
	}

	/*
	 * see hubd_enable_all_port_power() which
	 * requires longer delay for hubs.
	 */
	mutex_exit(HUBD_MUTEX(hubd));
	delay(drv_usectohz(hubd_device_delay / 10));
	mutex_enter(HUBD_MUTEX(hubd));

	hub_descr = &hubd->h_hub_descr;

	/*
	 * According to section 11.11 of USB, for hubs with no power
	 * switches, bPwrOn2PwrGood is zero. But we wait for some
	 * arbitrary time to enable power to become stable.
	 *
	 * If an hub supports port power swicthing, we need to wait
	 * at least 20ms before accesing corresonding usb port.
	 */
	if ((hub_descr->wHubCharacteristics &
	    HUB_CHARS_NO_POWER_SWITCHING) || (!hub_descr->bPwrOn2PwrGood)) {
		wait = hubd_device_delay / 10;
	} else {
		wait = max(HUB_DEFAULT_POPG,
		    hub_descr->bPwrOn2PwrGood) * 2 * 1000;
	}

	USB_DPRINTF_L3(DPRINT_MASK_PORT, hubd->h_log_handle,
	    "hubd_toggle_port: popg=%d wait=%d",
	    hub_descr->bPwrOn2PwrGood, wait);

	retry = 0;

	do {
		(void) hubd_enable_port_power(hubd, port);

		mutex_exit(HUBD_MUTEX(hubd));
		delay(drv_usectohz(wait));
		mutex_enter(HUBD_MUTEX(hubd));

		/* Get port status */
		(void) hubd_determine_port_status(hubd, port,
		    &status, &change, 0);

		/* For retry if any, use some extra delay */
		wait = max(wait, hubd_device_delay / 10);

		retry++;

	} while ((!(status & PORT_STATUS_PPS)) && (retry < HUBD_PORT_RETRY));

	/* Print warning message if port has no power */
	if (!(status & PORT_STATUS_PPS)) {

		USB_DPRINTF_L2(DPRINT_MASK_PORT, hubd->h_log_handle,
		    "hubd_toggle_port: port %d power-on failed, "
		    "port status 0x%x", port, status);

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


/*
 * hubd_init_power_budget:
 *	Init power budget variables in hubd structure. According
 *	to USB spec, the power budget rules are:
 *	1. local-powered hubs including root-hubs can supply
 *	   500mA to each port at maximum
 *	2. two bus-powered hubs are not allowed to concatenate
 *	3. bus-powered hubs can supply 100mA to each port at
 *	   maximum, and the power consumed by all downstream
 *	   ports and the hub itself cannot exceed the max power
 *	   supplied by the upstream port, i.e., 500mA
 *	The routine is only called during hub attach time
 */
static int
hubd_init_power_budget(hubd_t *hubd)
{
	uint16_t	status = 0;
	usba_device_t	*hubd_ud = NULL;
	size_t		size;
	usb_cfg_descr_t	cfg_descr;
	dev_info_t	*pdip = NULL;
	hubd_t		*phubd = NULL;

	if (hubd->h_ignore_pwr_budget) {

		return (USB_SUCCESS);
	}

	USB_DPRINTF_L4(DPRINT_MASK_HUB, hubd->h_log_handle,
	    "hubd_init_power_budget:");

	ASSERT(mutex_owned(HUBD_MUTEX(hubd)));
	ASSERT(hubd->h_default_pipe != 0);
	mutex_exit(HUBD_MUTEX(hubd));

	/* get device status */
	if ((usb_get_status(hubd->h_dip, hubd->h_default_pipe,
	    HUB_GET_DEVICE_STATUS_TYPE,
	    0, &status, 0)) != USB_SUCCESS) {
		mutex_enter(HUBD_MUTEX(hubd));

		return (USB_FAILURE);
	}

	hubd_ud = usba_get_usba_device(hubd->h_dip);

	size = usb_parse_cfg_descr(hubd_ud->usb_cfg, hubd_ud->usb_cfg_length,
	    &cfg_descr, USB_CFG_DESCR_SIZE);

	if (size != USB_CFG_DESCR_SIZE) {
		USB_DPRINTF_L2(DPRINT_MASK_HUB, hubd->h_log_handle,
		    "get hub configuration descriptor failed");
		mutex_enter(HUBD_MUTEX(hubd));

		return (USB_FAILURE);
	}

	mutex_enter(HUBD_MUTEX(hubd));

	hubd->h_local_pwr_capable = (cfg_descr.bmAttributes &
	    USB_CFG_ATTR_SELFPWR);

	if (hubd->h_local_pwr_capable) {
		USB_DPRINTF_L3(DPRINT_MASK_HUB, hubd->h_log_handle,
		    "hub is capable of local power");
	}

	hubd->h_local_pwr_on = (status &
	    USB_DEV_SLF_PWRD_STATUS) && hubd->h_local_pwr_capable;

	if (hubd->h_local_pwr_on) {
		USB_DPRINTF_L3(DPRINT_MASK_HUB, hubd->h_log_handle,
		    "hub is local-powered");

		hubd->h_pwr_limit = (USB_PWR_UNIT_LOAD *
		    USB_HIGH_PWR_VALUE) / USB_CFG_DESCR_PWR_UNIT;
	} else {
		hubd->h_pwr_limit = (USB_PWR_UNIT_LOAD *
		    USB_LOW_PWR_VALUE) / USB_CFG_DESCR_PWR_UNIT;

		hubd->h_pwr_left = (USB_PWR_UNIT_LOAD *
		    USB_HIGH_PWR_VALUE) / USB_CFG_DESCR_PWR_UNIT;

		ASSERT(!usba_is_root_hub(hubd->h_dip));

		if (!usba_is_root_hub(hubd->h_dip)) {
			/*
			 * two bus-powered hubs are not
			 * allowed to be concatenated
			 */
			mutex_exit(HUBD_MUTEX(hubd));

			pdip = ddi_get_parent(hubd->h_dip);
			phubd = hubd_get_soft_state(pdip);
			ASSERT(phubd != NULL);

			if (!phubd->h_ignore_pwr_budget) {
				mutex_enter(HUBD_MUTEX(phubd));
				if (phubd->h_local_pwr_on == B_FALSE) {
					USB_DPRINTF_L1(DPRINT_MASK_HUB,
					    hubd->h_log_handle,
					    "two bus-powered hubs cannot "
					    "be concatenated");

					mutex_exit(HUBD_MUTEX(phubd));
					mutex_enter(HUBD_MUTEX(hubd));

					return (USB_FAILURE);
				}
				mutex_exit(HUBD_MUTEX(phubd));
			}

			mutex_enter(HUBD_MUTEX(hubd));

			USB_DPRINTF_L3(DPRINT_MASK_HUB, hubd->h_log_handle,
			    "hub is bus-powered");
		} else {
			USB_DPRINTF_L3(DPRINT_MASK_HUB, hubd->h_log_handle,
			    "root-hub must be local-powered");
		}

		/*
		 * Subtract the power consumed by the hub itself
		 * and get the power that can be supplied to
		 * downstream ports
		 */
		hubd->h_pwr_left -=
		    hubd->h_hub_descr.bHubContrCurrent /
		    USB_CFG_DESCR_PWR_UNIT;
		if (hubd->h_pwr_left < 0) {
			USB_DPRINTF_L2(DPRINT_MASK_HUB, hubd->h_log_handle,
			    "hubd->h_pwr_left is less than bHubContrCurrent, "
			    "should fail");

			return (USB_FAILURE);
		}
	}

	return (USB_SUCCESS);
}


/*
 * usba_hubdi_check_power_budget:
 *	Check if the hub has enough power budget to allow a
 *	child device to select a configuration of config_index.
 */
int
usba_hubdi_check_power_budget(dev_info_t *dip, usba_device_t *child_ud,
	uint_t config_index)
{
	int16_t		pwr_left, pwr_limit, pwr_required;
	size_t		size;
	usb_cfg_descr_t cfg_descr;
	hubd_t		*hubd;

	if ((hubd = hubd_get_soft_state(dip)) == NULL) {

		return (USB_FAILURE);
	}

	if (hubd->h_ignore_pwr_budget) {

		return (USB_SUCCESS);
	}

	USB_DPRINTF_L4(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "usba_hubdi_check_power_budget: "
	    "dip=0x%p child_ud=0x%p conf_index=%d", (void *)dip,
	    (void *)child_ud, config_index);

	mutex_enter(HUBD_MUTEX(hubd));
	pwr_limit = hubd->h_pwr_limit;
	if (hubd->h_local_pwr_on == B_FALSE) {
		pwr_left = hubd->h_pwr_left;
		pwr_limit = (pwr_limit <= pwr_left) ? pwr_limit : pwr_left;
	}
	mutex_exit(HUBD_MUTEX(hubd));

	USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "usba_hubdi_check_power_budget: "
	    "available power is %dmA", pwr_limit * USB_CFG_DESCR_PWR_UNIT);

	size = usb_parse_cfg_descr(
	    child_ud->usb_cfg_array[config_index], USB_CFG_DESCR_SIZE,
	    &cfg_descr, USB_CFG_DESCR_SIZE);

	if (size != USB_CFG_DESCR_SIZE) {
		USB_DPRINTF_L2(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "get hub configuration descriptor failed");

		return (USB_FAILURE);
	}

	pwr_required = cfg_descr.bMaxPower;

	USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "usba_hubdi_check_power_budget: "
	    "child bmAttributes=0x%x bMaxPower=%d "
	    "with config_index=%d", cfg_descr.bmAttributes,
	    pwr_required, config_index);

	if (pwr_required > pwr_limit) {
		USB_DPRINTF_L1(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "configuration %d for device %s %s at port %d "
		    "exceeds power available for this port, please "
		    "re-insert your device into another hub port which "
		    "has enough power",
		    config_index,
		    child_ud->usb_mfg_str,
		    child_ud->usb_product_str,
		    child_ud->usb_port);

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


/*
 * usba_hubdi_incr_power_budget:
 *	Increase the hub power budget value when a child device
 *	is removed from a bus-powered hub port.
 */
void
usba_hubdi_incr_power_budget(dev_info_t *dip, usba_device_t *child_ud)
{
	uint16_t	pwr_value;
	hubd_t		*hubd = hubd_get_soft_state(dip);

	ASSERT(hubd != NULL);

	if (hubd->h_ignore_pwr_budget) {

		return;
	}

	USB_DPRINTF_L4(DPRINT_MASK_ATTA, hubd->h_log_handle,
	    "usba_hubdi_incr_power_budget: "
	    "dip=0x%p child_ud=0x%p", (void *)dip, (void *)child_ud);

	mutex_enter(HUBD_MUTEX(hubd));
	if (hubd->h_local_pwr_on == B_TRUE) {
		USB_DPRINTF_L3(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "usba_hubdi_incr_power_budget: "
		    "hub is local powered");
		mutex_exit(HUBD_MUTEX(hubd));

		return;
	}
	mutex_exit(HUBD_MUTEX(hubd));

	mutex_enter(&child_ud->usb_mutex);
	if (child_ud->usb_pwr_from_hub == 0) {
		mutex_exit(&child_ud->usb_mutex);

		return;
	}
	pwr_value = child_ud->usb_pwr_from_hub;
	mutex_exit(&child_ud->usb_mutex);

	mutex_enter(HUBD_MUTEX(hubd));
	hubd->h_pwr_left += pwr_value;

	USB_DPRINTF_L3(DPRINT_MASK_ATTA, hubd->h_log_handle,
	    "usba_hubdi_incr_power_budget: "
	    "available power is %dmA, increased by %dmA",
	    hubd->h_pwr_left * USB_CFG_DESCR_PWR_UNIT,
	    pwr_value * USB_CFG_DESCR_PWR_UNIT);

	mutex_exit(HUBD_MUTEX(hubd));

	mutex_enter(&child_ud->usb_mutex);
	child_ud->usb_pwr_from_hub = 0;
	mutex_exit(&child_ud->usb_mutex);
}


/*
 * usba_hubdi_decr_power_budget:
 *	Decrease the hub power budget value when a child device
 *	is inserted to a bus-powered hub port.
 */
void
usba_hubdi_decr_power_budget(dev_info_t *dip, usba_device_t *child_ud)
{
	uint16_t	pwr_value;
	size_t		size;
	usb_cfg_descr_t	cfg_descr;
	hubd_t		*hubd = hubd_get_soft_state(dip);

	ASSERT(hubd != NULL);

	if (hubd->h_ignore_pwr_budget) {

		return;
	}

	USB_DPRINTF_L4(DPRINT_MASK_ATTA, hubd->h_log_handle,
	    "usba_hubdi_decr_power_budget: "
	    "dip=0x%p child_ud=0x%p", (void *)dip, (void *)child_ud);

	mutex_enter(HUBD_MUTEX(hubd));
	if (hubd->h_local_pwr_on == B_TRUE) {
		USB_DPRINTF_L3(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "usba_hubdi_decr_power_budget: "
		    "hub is local powered");
		mutex_exit(HUBD_MUTEX(hubd));

		return;
	}
	mutex_exit(HUBD_MUTEX(hubd));

	mutex_enter(&child_ud->usb_mutex);
	if (child_ud->usb_pwr_from_hub > 0) {
		mutex_exit(&child_ud->usb_mutex);

		return;
	}
	mutex_exit(&child_ud->usb_mutex);

	size = usb_parse_cfg_descr(
	    child_ud->usb_cfg, child_ud->usb_cfg_length,
	    &cfg_descr, USB_CFG_DESCR_SIZE);
	ASSERT(size == USB_CFG_DESCR_SIZE);

	mutex_enter(HUBD_MUTEX(hubd));
	pwr_value = cfg_descr.bMaxPower;
	hubd->h_pwr_left -= pwr_value;
	ASSERT(hubd->h_pwr_left >= 0);

	USB_DPRINTF_L3(DPRINT_MASK_ATTA, hubd->h_log_handle,
	    "usba_hubdi_decr_power_budget: "
	    "available power is %dmA, decreased by %dmA",
	    hubd->h_pwr_left * USB_CFG_DESCR_PWR_UNIT,
	    pwr_value * USB_CFG_DESCR_PWR_UNIT);

	mutex_exit(HUBD_MUTEX(hubd));

	mutex_enter(&child_ud->usb_mutex);
	child_ud->usb_pwr_from_hub = pwr_value;
	mutex_exit(&child_ud->usb_mutex);
}

/*
 * hubd_wait_for_hotplug_exit:
 *	Waiting for the exit of the running hotplug thread or ioctl thread.
 */
static int
hubd_wait_for_hotplug_exit(hubd_t *hubd)
{
	clock_t		until = drv_usectohz(1000000);
	int		rval;

	ASSERT(mutex_owned(HUBD_MUTEX(hubd)));

	if (hubd->h_hotplug_thread) {
		USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "waiting for hubd hotplug thread exit");
		rval = cv_reltimedwait(&hubd->h_cv_hotplug_dev,
		    &hubd->h_mutex, until, TR_CLOCK_TICK);

		if ((rval <= 0) && (hubd->h_hotplug_thread)) {

			return (USB_FAILURE);
		}
	}

	return (USB_SUCCESS);
}

/*
 * hubd_reset_thread:
 *	handles the "USB_RESET_LVL_REATTACH" reset of usb device.
 *
 *	- delete the child (force detaching the device and its children)
 *	- reset the corresponding parent hub port
 *	- create the child (force re-attaching the device and its children)
 */
static void
hubd_reset_thread(void *arg)
{
	hubd_reset_arg_t *hd_arg = (hubd_reset_arg_t *)arg;
	hubd_t		*hubd = hd_arg->hubd;
	uint16_t	reset_port = hd_arg->reset_port;
	uint16_t	status, change;
	hub_power_t	*hubpm;
	dev_info_t	*hdip = hubd->h_dip;
	dev_info_t	*rh_dip = hubd->h_usba_device->usb_root_hub_dip;
	dev_info_t	*child_dip;
	boolean_t	online_child = B_FALSE;
	int		prh_circ, rh_circ, circ, devinst;
	char		*devname;
	int		i = 0;
	int		rval = USB_FAILURE;

	USB_DPRINTF_L4(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "hubd_reset_thread:  started, hubd_reset_port = 0x%x", reset_port);

	kmem_free(arg, sizeof (hubd_reset_arg_t));

	mutex_enter(HUBD_MUTEX(hubd));

	child_dip = hubd->h_children_dips[reset_port];
	ASSERT(child_dip != NULL);

	devname = (char *)ddi_driver_name(child_dip);
	devinst = ddi_get_instance(child_dip);

	/* if our bus power entry point is active, quit the reset */
	if (hubd->h_bus_pwr) {
		USB_DPRINTF_L0(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "%s%d is under bus power management, cannot be reset. "
		    "Please disconnect and reconnect this device.",
		    devname, devinst);

		goto Fail;
	}

	if (hubd_wait_for_hotplug_exit(hubd) == USB_FAILURE) {
		/* we got woken up because of a timeout */
		USB_DPRINTF_L0(DPRINT_MASK_HOTPLUG,
		    hubd->h_log_handle, "Time out when resetting the device"
		    " %s%d. Please disconnect and reconnect this device.",
		    devname, devinst);

		goto Fail;
	}

	hubd->h_hotplug_thread++;

	/* is this the root hub? */
	if ((hdip == rh_dip) &&
	    (hubd->h_dev_state == USB_DEV_PWRED_DOWN)) {
		hubpm = hubd->h_hubpm;

		/* mark the root hub as full power */
		hubpm->hubp_current_power = USB_DEV_OS_FULL_PWR;
		hubpm->hubp_time_at_full_power = gethrtime();
		mutex_exit(HUBD_MUTEX(hubd));

		USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "hubd_reset_thread: call pm_power_has_changed");

		(void) pm_power_has_changed(hdip, 0,
		    USB_DEV_OS_FULL_PWR);

		mutex_enter(HUBD_MUTEX(hubd));
		hubd->h_dev_state = USB_DEV_ONLINE;
	}

	mutex_exit(HUBD_MUTEX(hubd));

	/*
	 * this ensures one reset activity per system at a time.
	 * we enter the parent PCI node to have this serialization.
	 * this also excludes ioctls and deathrow thread
	 */
	ndi_devi_enter(ddi_get_parent(rh_dip), &prh_circ);
	ndi_devi_enter(rh_dip, &rh_circ);

	/* exclude other threads */
	ndi_devi_enter(hdip, &circ);
	mutex_enter(HUBD_MUTEX(hubd));

	/*
	 * We need to make sure that the child is still online for a hotplug
	 * thread could have inserted which detached the child.
	 */
	if (hubd->h_children_dips[reset_port]) {
		mutex_exit(HUBD_MUTEX(hubd));
		/* First disconnect the device */
		hubd_post_event(hubd, reset_port, USBA_EVENT_TAG_HOT_REMOVAL);

		/* delete cached dv_node's but drop locks first */
		ndi_devi_exit(hdip, circ);
		ndi_devi_exit(rh_dip, rh_circ);
		ndi_devi_exit(ddi_get_parent(rh_dip), prh_circ);

		(void) devfs_clean(rh_dip, NULL, DV_CLEAN_FORCE);

		/*
		 * workaround only for storage device. When it's able to force
		 * detach a driver, this code can be removed safely.
		 *
		 * If we're to reset storage device and the device is used, we
		 * will wait at most extra 20s for applications to exit and
		 * close the device. This is especially useful for HAL-based
		 * applications.
		 */
		if ((strcmp(devname, "scsa2usb") == 0) &&
		    DEVI(child_dip)->devi_ref != 0) {
			while (i++ < hubdi_reset_delay) {
				mutex_enter(HUBD_MUTEX(hubd));
				rval = hubd_delete_child(hubd, reset_port,
				    NDI_DEVI_REMOVE, B_FALSE);
				mutex_exit(HUBD_MUTEX(hubd));
				if (rval == USB_SUCCESS)
					break;

				delay(drv_usectohz(1000000)); /* 1s */
			}
		}

		ndi_devi_enter(ddi_get_parent(rh_dip), &prh_circ);
		ndi_devi_enter(rh_dip, &rh_circ);
		ndi_devi_enter(hdip, &circ);

		mutex_enter(HUBD_MUTEX(hubd));

		/* Then force detaching the device */
		if ((rval != USB_SUCCESS) && (hubd_delete_child(hubd,
		    reset_port, NDI_DEVI_REMOVE, B_FALSE) != USB_SUCCESS)) {
			USB_DPRINTF_L0(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
			    "%s%d cannot be reset due to other applications "
			    "are using it, please first close these "
			    "applications, then disconnect and reconnect"
			    "the device.", devname, devinst);

			mutex_exit(HUBD_MUTEX(hubd));
			/* post a re-connect event */
			hubd_post_event(hubd, reset_port,
			    USBA_EVENT_TAG_HOT_INSERTION);
			mutex_enter(HUBD_MUTEX(hubd));
		} else {
			(void) hubd_determine_port_status(hubd, reset_port,
			    &status, &change, HUBD_ACK_ALL_CHANGES);

			/* Reset the parent hubd port and create new child */
			if (status & PORT_STATUS_CCS) {
				online_child |=	(hubd_handle_port_connect(hubd,
				    reset_port) == USB_SUCCESS);
			}
		}
	}

	/* release locks so we can do a devfs_clean */
	mutex_exit(HUBD_MUTEX(hubd));

	/* delete cached dv_node's but drop locks first */
	ndi_devi_exit(hdip, circ);
	ndi_devi_exit(rh_dip, rh_circ);
	ndi_devi_exit(ddi_get_parent(rh_dip), prh_circ);

	(void) devfs_clean(rh_dip, NULL, 0);

	/* now check if any children need onlining */
	if (online_child) {
		USB_DPRINTF_L3(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
		    "hubd_reset_thread: onlining children");

		(void) ndi_devi_online(hubd->h_dip, 0);
	}

	mutex_enter(HUBD_MUTEX(hubd));

	/* allow hotplug thread now */
	hubd->h_hotplug_thread--;
Fail:
	hubd_start_polling(hubd, 0);

	/* mark this device as idle */
	(void) hubd_pm_idle_component(hubd, hubd->h_dip, 0);

	USB_DPRINTF_L4(DPRINT_MASK_HOTPLUG, hubd->h_log_handle,
	    "hubd_reset_thread: exit, %d", hubd->h_hotplug_thread);

	hubd->h_reset_port[reset_port] = B_FALSE;

	mutex_exit(HUBD_MUTEX(hubd));

	ndi_rele_devi(hdip);
}

/*
 * hubd_check_same_device:
 *	- open the default pipe of the device.
 *	- compare the old and new descriptors of the device.
 *	- close the default pipe.
 */
static int
hubd_check_same_device(hubd_t *hubd, usb_port_t port)
{
	dev_info_t		*dip = hubd->h_children_dips[port];
	usb_pipe_handle_t	ph;
	int			rval = USB_FAILURE;

	ASSERT(mutex_owned(HUBD_MUTEX(hubd)));

	mutex_exit(HUBD_MUTEX(hubd));
	/* Open the default pipe to operate the device */
	if (usb_pipe_open(dip, NULL, NULL,
	    USB_FLAGS_SLEEP| USBA_FLAGS_PRIVILEGED,
	    &ph) == USB_SUCCESS) {
		/*
		 * Check that if the device's descriptors are different
		 * from the values saved before the port reset.
		 */
		rval = usb_check_same_device(dip,
		    hubd->h_log_handle, USB_LOG_L0,
		    DPRINT_MASK_ALL, USB_CHK_ALL, NULL);

		usb_pipe_close(dip, ph, USB_FLAGS_SLEEP |
		    USBA_FLAGS_PRIVILEGED, NULL, NULL);
	}
	mutex_enter(HUBD_MUTEX(hubd));

	return (rval);
}

/*
 * usba_hubdi_reset_device
 *	Called by usb_reset_device to handle usb device reset.
 */
int
usba_hubdi_reset_device(dev_info_t *dip, usb_dev_reset_lvl_t reset_level)
{
	hubd_t			*hubd;
	usb_port_t		port = 0;
	dev_info_t		*hdip;
	usb_pipe_state_t	prev_pipe_state = 0;
	usba_device_t		*usba_device;
	hubd_reset_arg_t	*arg;
	int			i, ph_open_cnt;
	int			rval = USB_FAILURE;

	if ((!dip) || usba_is_root_hub(dip)) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubdi_log_handle,
		    "usba_hubdi_reset_device: NULL dip or root hub");

		return (USB_INVALID_ARGS);
	}

	if (!usb_owns_device(dip)) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubdi_log_handle,
		    "usba_hubdi_reset_device: Not owns the device");

		return (USB_INVALID_PERM);
	}

	if ((reset_level != USB_RESET_LVL_REATTACH) &&
	    (reset_level != USB_RESET_LVL_DEFAULT)) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubdi_log_handle,
		    "usba_hubdi_reset_device: Unknown flags");

		return (USB_INVALID_ARGS);
	}

	if ((hdip = ddi_get_parent(dip)) == NULL) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubdi_log_handle,
		    "usba_hubdi_reset_device: fail to get parent hub");

		return (USB_INVALID_ARGS);
	}

	if ((hubd = hubd_get_soft_state(hdip)) == NULL) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubdi_log_handle,
		    "usba_hubdi_reset_device: fail to get hub softstate");

		return (USB_INVALID_ARGS);
	}

	mutex_enter(HUBD_MUTEX(hubd));

	/* make sure the hub is connected before trying any kinds of reset. */
	if ((hubd->h_dev_state == USB_DEV_DISCONNECTED) ||
	    (hubd->h_dev_state == USB_DEV_SUSPENDED)) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "usb_reset_device: the state %d of the hub/roothub "
		    "associated to the device 0x%p is incorrect",
		    hubd->h_dev_state, (void *)dip);
		mutex_exit(HUBD_MUTEX(hubd));

		return (USB_INVALID_ARGS);
	}

	mutex_exit(HUBD_MUTEX(hubd));

	port = hubd_child_dip2port(hubd, dip);

	mutex_enter(HUBD_MUTEX(hubd));

	if (hubd->h_reset_port[port]) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "usb_reset_device: the corresponding port is resetting");
		mutex_exit(HUBD_MUTEX(hubd));

		return (USB_SUCCESS);
	}

	/*
	 * For Default reset, client drivers should first close all the pipes
	 * except default pipe before calling the function, also should not
	 * call the function during interrupt context.
	 */
	if (reset_level == USB_RESET_LVL_DEFAULT) {
		usba_device = hubd->h_usba_devices[port];
		mutex_exit(HUBD_MUTEX(hubd));

		if (servicing_interrupt()) {
			USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
			    "usb_reset_device: during interrput context, quit");

			return (USB_INVALID_CONTEXT);
		}
		/* Check if all the pipes have been closed */
		for (ph_open_cnt = 0, i = 1; i < USBA_N_ENDPOINTS; i++) {
			if (usba_device->usb_ph_list[i].usba_ph_data) {
				ph_open_cnt++;
				break;
			}
		}
		if (ph_open_cnt) {
			USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
			    "usb_reset_device: %d pipes are still open",
			    ph_open_cnt);

			return (USB_BUSY);
		}
		mutex_enter(HUBD_MUTEX(hubd));
	}

	/* Don't perform reset while the device is detaching */
	if (hubd->h_port_state[port] & HUBD_CHILD_DETACHING) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
		    "usb_reset_device: the device is detaching, "
		    "cannot be reset");
		mutex_exit(HUBD_MUTEX(hubd));

		return (USB_FAILURE);
	}

	hubd->h_reset_port[port] = B_TRUE;
	hdip = hubd->h_dip;
	mutex_exit(HUBD_MUTEX(hubd));

	/* Don't allow hub detached during the reset */
	ndi_hold_devi(hdip);

	mutex_enter(HUBD_MUTEX(hubd));
	hubd_pm_busy_component(hubd, hdip, 0);
	mutex_exit(HUBD_MUTEX(hubd));
	/* go full power */
	(void) pm_raise_power(hdip, 0, USB_DEV_OS_FULL_PWR);
	mutex_enter(HUBD_MUTEX(hubd));

	hubd->h_hotplug_thread++;

	/* stop polling if it was active */
	if (hubd->h_ep1_ph) {
		mutex_exit(HUBD_MUTEX(hubd));
		(void) usb_pipe_get_state(hubd->h_ep1_ph, &prev_pipe_state,
		    USB_FLAGS_SLEEP);
		mutex_enter(HUBD_MUTEX(hubd));

		if (prev_pipe_state == USB_PIPE_STATE_ACTIVE) {
			hubd_stop_polling(hubd);
		}
	}

	switch (reset_level) {
	case USB_RESET_LVL_REATTACH:
		mutex_exit(HUBD_MUTEX(hubd));
		arg = (hubd_reset_arg_t *)kmem_zalloc(
		    sizeof (hubd_reset_arg_t), KM_SLEEP);
		arg->hubd = hubd;
		arg->reset_port = port;
		mutex_enter(HUBD_MUTEX(hubd));

		if ((rval = usb_async_req(hdip, hubd_reset_thread,
		    (void *)arg, 0)) == USB_SUCCESS) {
			hubd->h_hotplug_thread--;
			mutex_exit(HUBD_MUTEX(hubd));

			return (USB_SUCCESS);
		} else {
			USB_DPRINTF_L2(DPRINT_MASK_ATTA, hubd->h_log_handle,
			    "Cannot create reset thread, the device %s%d failed"
			    " to reset", ddi_driver_name(dip),
			    ddi_get_instance(dip));

			kmem_free(arg, sizeof (hubd_reset_arg_t));
		}

		break;
	case USB_RESET_LVL_DEFAULT:
		/*
		 * Reset hub port and then recover device's address, set back
		 * device's configuration, hubd_handle_port_connect() will
		 * handle errors happened during this process.
		 */
		if ((rval = hubd_handle_port_connect(hubd, port))
		    == USB_SUCCESS) {
			mutex_exit(HUBD_MUTEX(hubd));
			/* re-open the default pipe */
			rval = usba_persistent_pipe_open(usba_device);
			mutex_enter(HUBD_MUTEX(hubd));
			if (rval != USB_SUCCESS) {
				USB_DPRINTF_L2(DPRINT_MASK_ATTA,
				    hubd->h_log_handle, "failed to reopen "
				    "default pipe after reset, disable hub"
				    "port for %s%d", ddi_driver_name(dip),
				    ddi_get_instance(dip));
				/*
				 * Disable port to set out a hotplug thread
				 * which will handle errors.
				 */
				(void) hubd_disable_port(hubd, port);
			}
		}

		break;
	default:

		break;
	}

	/* allow hotplug thread now */
	hubd->h_hotplug_thread--;

	if ((hubd->h_dev_state == USB_DEV_ONLINE) && hubd->h_ep1_ph &&
	    (prev_pipe_state == USB_PIPE_STATE_ACTIVE)) {
		hubd_start_polling(hubd, 0);
	}

	hubd_pm_idle_component(hubd, hdip, 0);

	/* Clear reset mark for the port. */
	hubd->h_reset_port[port] = B_FALSE;

	mutex_exit(HUBD_MUTEX(hubd));

	ndi_rele_devi(hdip);

	return (rval);
}

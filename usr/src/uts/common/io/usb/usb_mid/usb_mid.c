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
 */
/*
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 * Copyright 2023 Oxide Computer Company
 */

/*
 * usb multi interface and common class driver
 *
 *	this driver attempts to attach each interface to a driver
 *	and may eventually handle common class features such as
 *	shared endpoints
 */

#if defined(lint) && !defined(DEBUG)
#define	DEBUG	1
#endif
#include <sys/usb/usba/usbai_version.h>
#include <sys/usb/usba.h>
#include <sys/usb/usba/usba_types.h>
#include <sys/usb/usba/usba_impl.h>
#include <sys/usb/usba/usba_ugen.h>
#include <sys/usb/usb_mid/usb_midvar.h>

void usba_free_evdata(usba_evdata_t *);

/* Debugging support */
uint_t usb_mid_errlevel = USB_LOG_L4;
uint_t usb_mid_errmask = (uint_t)DPRINT_MASK_ALL;
uint_t usb_mid_instance_debug = (uint_t)-1;
uint_t usb_mid_bus_config_debug = 0;

_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_mid_errlevel))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_mid_errmask))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_mid_instance_debug))

_NOTE(SCHEME_PROTECTS_DATA("unique", msgb))
_NOTE(SCHEME_PROTECTS_DATA("unique", dev_info))
_NOTE(SCHEME_PROTECTS_DATA("unique", usb_pipe_policy))

/*
 * Hotplug support
 * Leaf ops (hotplug controls for client devices)
 */
static int usb_mid_open(dev_t *, int, int, cred_t *);
static int usb_mid_close(dev_t, int, int, cred_t *);
static int usb_mid_read(dev_t, struct uio *, cred_t *);
static int usb_mid_write(dev_t, struct uio *, cred_t *);
static int usb_mid_poll(dev_t, short, int,  short *,
					struct pollhead **);

static struct cb_ops usb_mid_cb_ops = {
	usb_mid_open,
	usb_mid_close,
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	usb_mid_read,	/* read */
	usb_mid_write,	/* write */
	nodev,
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	usb_mid_poll,	/* poll */
	ddi_prop_op,	/* prop_op */
	NULL,
	D_MP
};

static int usb_mid_busop_get_eventcookie(dev_info_t *dip,
			dev_info_t *rdip,
			char *eventname,
			ddi_eventcookie_t *cookie);
static int usb_mid_busop_add_eventcall(dev_info_t *dip,
			dev_info_t *rdip,
			ddi_eventcookie_t cookie,
			void (*callback)(dev_info_t *dip,
				ddi_eventcookie_t cookie, void *arg,
				void *bus_impldata),
			void *arg, ddi_callback_id_t *cb_id);
static int usb_mid_busop_remove_eventcall(dev_info_t *dip,
			ddi_callback_id_t cb_id);
static int usb_mid_busop_post_event(dev_info_t *dip,
			dev_info_t *rdip,
			ddi_eventcookie_t cookie,
			void *bus_impldata);
static int usb_mid_bus_config(dev_info_t *dip,
			uint_t flag,
			ddi_bus_config_op_t op,
			void *arg,
			dev_info_t **child);
static int usb_mid_bus_unconfig(dev_info_t *dip,
			uint_t flag,
			ddi_bus_config_op_t op,
			void *arg);


/*
 * autoconfiguration data and routines.
 */
static int	usb_mid_info(dev_info_t *, ddi_info_cmd_t,
				void *, void **);
static int	usb_mid_attach(dev_info_t *, ddi_attach_cmd_t);
static int	usb_mid_detach(dev_info_t *, ddi_detach_cmd_t);

/* other routines */
static void usb_mid_create_pm_components(dev_info_t *, usb_mid_t *);
static int usb_mid_bus_ctl(dev_info_t *, dev_info_t	*,
				ddi_ctl_enum_t, void *, void *);
static int usb_mid_power(dev_info_t *, int, int);
static int usb_mid_restore_device_state(dev_info_t *, usb_mid_t *);
static usb_mid_t  *usb_mid_obtain_state(dev_info_t *);
static void usb_mid_event_cb(dev_info_t *, ddi_eventcookie_t, void *, void *);

/*
 * Busops vector
 */
static struct bus_ops usb_mid_busops = {
	BUSO_REV,
	nullbusmap,			/* bus_map */
	NULL,				/* bus_get_intrspec */
	NULL,				/* bus_add_intrspec */
	NULL,				/* bus_remove_intrspec */
	NULL,				/* XXXX bus_map_fault */
	NULL,				/* bus_dma_map */
	ddi_dma_allochdl,
	ddi_dma_freehdl,
	ddi_dma_bindhdl,
	ddi_dma_unbindhdl,
	ddi_dma_flush,
	ddi_dma_win,
	ddi_dma_mctl,			/* bus_dma_ctl */
	usb_mid_bus_ctl,		/* bus_ctl */
	ddi_bus_prop_op,		/* bus_prop_op */
	usb_mid_busop_get_eventcookie,
	usb_mid_busop_add_eventcall,
	usb_mid_busop_remove_eventcall,
	usb_mid_busop_post_event,	/* bus_post_event */
	NULL,				/* bus_intr_ctl */
	usb_mid_bus_config,		/* bus_config */
	usb_mid_bus_unconfig,		/* bus_unconfig */
	NULL,				/* bus_fm_init */
	NULL,				/* bus_fm_fini */
	NULL,				/* bus_fm_access_enter */
	NULL,				/* bus_fm_access_exit */
	NULL				/* bus_power */
};


static struct dev_ops usb_mid_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	usb_mid_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	usb_mid_attach,		/* attach */
	usb_mid_detach,		/* detach */
	nodev,			/* reset */
	&usb_mid_cb_ops,	/* driver operations */
	&usb_mid_busops,	/* bus operations */
	usb_mid_power,		/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module. This one is a driver */
	"USB Multi Interface Driver", /* Name of the module. */
	&usb_mid_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

#define	USB_MID_INITIAL_SOFT_SPACE 4
static	void	*usb_mid_statep;


/*
 * prototypes
 */
static void usb_mid_create_children(usb_mid_t *usb_mid);
static int usb_mid_cleanup(dev_info_t *dip, usb_mid_t	*usb_mid);

/*
 * event definition
 */
static ndi_event_definition_t usb_mid_ndi_event_defs[] = {
	{USBA_EVENT_TAG_HOT_REMOVAL, DDI_DEVI_REMOVE_EVENT, EPL_KERNEL,
						NDI_EVENT_POST_TO_ALL},
	{USBA_EVENT_TAG_HOT_INSERTION, DDI_DEVI_INSERT_EVENT, EPL_KERNEL,
						NDI_EVENT_POST_TO_ALL},
	{USBA_EVENT_TAG_POST_RESUME, USBA_POST_RESUME_EVENT, EPL_KERNEL,
						NDI_EVENT_POST_TO_ALL},
	{USBA_EVENT_TAG_PRE_SUSPEND, USBA_PRE_SUSPEND_EVENT, EPL_KERNEL,
						NDI_EVENT_POST_TO_ALL}
};

#define	USB_MID_N_NDI_EVENTS \
	(sizeof (usb_mid_ndi_event_defs) / sizeof (ndi_event_definition_t))

static	ndi_event_set_t usb_mid_ndi_events = {
	NDI_EVENTS_REV1, USB_MID_N_NDI_EVENTS, usb_mid_ndi_event_defs};


/*
 * standard driver entry points
 */
int
_init(void)
{
	int rval;

	rval = ddi_soft_state_init(&usb_mid_statep, sizeof (struct usb_mid),
	    USB_MID_INITIAL_SOFT_SPACE);
	if (rval != 0) {
		return (rval);
	}

	if ((rval = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&usb_mid_statep);
		return (rval);
	}

	return (rval);
}


int
_fini(void)
{
	int	rval;

	rval = mod_remove(&modlinkage);

	if (rval) {
		return (rval);
	}

	ddi_soft_state_fini(&usb_mid_statep);

	return (rval);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*ARGSUSED*/
static int
usb_mid_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	usb_mid_t	*usb_mid;
	int		instance =
	    USB_MID_MINOR_TO_INSTANCE(getminor((dev_t)arg));
	int		error = DDI_FAILURE;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((usb_mid = ddi_get_soft_state(usb_mid_statep,
		    instance)) != NULL) {
			*result = (void *)usb_mid->mi_dip;
			if (*result != NULL) {
				error = DDI_SUCCESS;
			}
		} else {
			*result = NULL;
		}
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(intptr_t)instance;
		error = DDI_SUCCESS;
		break;
	default:
		break;
	}

	return (error);
}


/*
 * child  post attach/detach notification
 */
static void
usb_mid_post_attach(usb_mid_t *usb_mid, uint8_t ifno, struct attachspec *as)
{
	USB_DPRINTF_L2(DPRINT_MASK_PM, usb_mid->mi_log_handle,
	    "usb_mid_post_attach: ifno = %d result = %d", ifno, as->result);

	/* if child successfully attached, set power */
	if (as->result == DDI_SUCCESS) {
		/*
		 * Check if the child created wants to be power managed.
		 * If yes, the childs power level gets automatically tracked
		 * by DDI_CTLOPS_POWER busctl.
		 * If no, we set power of the new child by default
		 * to USB_DEV_OS_FULL_PWR. Because we should never suspend.
		 */
		mutex_enter(&usb_mid->mi_mutex);
		usb_mid->mi_attach_count++;
		mutex_exit(&usb_mid->mi_mutex);
	}
}


static void
usb_mid_post_detach(usb_mid_t *usb_mid, uint8_t ifno, struct detachspec *ds)
{
	USB_DPRINTF_L2(DPRINT_MASK_PM, usb_mid->mi_log_handle,
	    "usb_mid_post_detach: ifno = %d result = %d", ifno, ds->result);

	/*
	 * if the device is successfully detached,
	 * mark component as idle
	 */
	if (ds->result == DDI_SUCCESS) {
		usba_device_t *usba_device =
		    usba_get_usba_device(usb_mid->mi_dip);

		mutex_enter(&usb_mid->mi_mutex);

		/* check for leaks except when where is a ugen open */
		if ((ds->cmd == DDI_DETACH) &&
		    (--usb_mid->mi_attach_count == 0) && usba_device &&
		    (usb_mid->mi_ugen_open_count == 0)) {
			usba_check_for_leaks(usba_device);
		}
		mutex_exit(&usb_mid->mi_mutex);
	}
}


/*
 * bus ctl support. we handle notifications here and the
 * rest goes up to root hub/hcd
 */
/*ARGSUSED*/
static int
usb_mid_bus_ctl(dev_info_t *dip,
	dev_info_t	*rdip,
	ddi_ctl_enum_t	op,
	void		*arg,
	void		*result)
{
	usba_device_t *hub_usba_device = usba_get_usba_device(rdip);
	dev_info_t *root_hub_dip = hub_usba_device->usb_root_hub_dip;
	usb_mid_t  *usb_mid;
	struct attachspec *as;
	struct detachspec *ds;

	usb_mid = usb_mid_obtain_state(dip);

	USB_DPRINTF_L2(DPRINT_MASK_PM, usb_mid->mi_log_handle,
	    "usb_mid_bus_ctl:\n\t"
	    "dip = 0x%p, rdip = 0x%p, op = 0x%x, arg = 0x%p",
	    (void *)dip, (void *)rdip, op, arg);

	switch (op) {
	case DDI_CTLOPS_ATTACH:
		as = (struct attachspec *)arg;

		switch (as->when) {
		case DDI_PRE :
			/* nothing to do basically */
			USB_DPRINTF_L2(DPRINT_MASK_PM, usb_mid->mi_log_handle,
			    "DDI_PRE DDI_CTLOPS_ATTACH");
			break;
		case DDI_POST :
			usb_mid_post_attach(usb_mid, usba_get_ifno(rdip),
			    (struct attachspec *)arg);
			break;
		}

		break;
	case DDI_CTLOPS_DETACH:
		ds = (struct detachspec *)arg;

		switch (ds->when) {
		case DDI_PRE :
			/* nothing to do basically */
			USB_DPRINTF_L2(DPRINT_MASK_PM, usb_mid->mi_log_handle,
			    "DDI_PRE DDI_CTLOPS_DETACH");
			break;
		case DDI_POST :
			usb_mid_post_detach(usb_mid, usba_get_ifno(rdip),
			    (struct detachspec *)arg);
			break;
		}

		break;
	default:
		/* pass to root hub to handle */
		return (usba_bus_ctl(root_hub_dip, rdip, op, arg, result));
	}

	return (DDI_SUCCESS);
}


/*
 * bus enumeration entry points
 */
static int
usb_mid_bus_config(dev_info_t *dip, uint_t flag, ddi_bus_config_op_t op,
    void *arg, dev_info_t **child)
{
	int		rval;
	usb_mid_t	*usb_mid = usb_mid_obtain_state(dip);

	USB_DPRINTF_L2(DPRINT_MASK_ALL, usb_mid->mi_log_handle,
	    "usb_mid_bus_config: op=%d", op);

	if (usb_mid_bus_config_debug) {
		flag |= NDI_DEVI_DEBUG;
	}

	ndi_devi_enter(dip);

	/* enumerate each interface below us */
	mutex_enter(&usb_mid->mi_mutex);
	usb_mid_create_children(usb_mid);
	mutex_exit(&usb_mid->mi_mutex);

	rval = ndi_busop_bus_config(dip, flag, op, arg, child, 0);
	ndi_devi_exit(dip);

	return (rval);
}


static int
usb_mid_bus_unconfig(dev_info_t *dip, uint_t flag, ddi_bus_config_op_t op,
    void *arg)
{
	usb_mid_t  *usb_mid = usb_mid_obtain_state(dip);

	dev_info_t	*cdip, *mdip;
	int		interface;
	int		rval = NDI_SUCCESS;

	USB_DPRINTF_L4(DPRINT_MASK_ALL, usb_mid->mi_log_handle,
	    "usb_mid_bus_unconfig: op=%d", op);

	if (usb_mid_bus_config_debug) {
		flag |= NDI_DEVI_DEBUG;
	}

	/*
	 * first offline and if offlining successful, then
	 * remove children
	 */
	if (op == BUS_UNCONFIG_ALL) {
		flag &= ~(NDI_DEVI_REMOVE | NDI_UNCONFIG);
	}

	ndi_devi_enter(dip);
	rval = ndi_busop_bus_unconfig(dip, flag, op, arg);

	if (op == BUS_UNCONFIG_ALL && rval == NDI_SUCCESS &&
	    (flag & NDI_AUTODETACH) == 0) {
		flag |= NDI_DEVI_REMOVE;
		rval = ndi_busop_bus_unconfig(dip, flag, op, arg);
	}

	/* update children's list */
	mutex_enter(&usb_mid->mi_mutex);
	for (interface = 0; usb_mid->mi_children_dips &&
	    (interface < usb_mid->mi_n_ifs) &&
	    (usb_mid->mi_children_ifs[interface]); interface++) {
		mdip = usb_mid->mi_children_dips[interface];

		/* now search if this dip still exists */
		for (cdip = ddi_get_child(dip); cdip && (cdip != mdip); )
			cdip = ddi_get_next_sibling(cdip);

		if (cdip != mdip) {
			/* we lost the dip on this interface */
			usb_mid->mi_children_dips[interface] = NULL;
		} else if (cdip) {
			/*
			 * keep in DS_INITALIZED to prevent parent
			 * from detaching
			 */
			(void) ddi_initchild(ddi_get_parent(cdip), cdip);
		}
	}
	mutex_exit(&usb_mid->mi_mutex);

	ndi_devi_exit(dip);

	USB_DPRINTF_L4(DPRINT_MASK_ALL, usb_mid->mi_log_handle,
	    "usb_mid_bus_config: rval=%d", rval);

	return (rval);
}


/* power entry point */
/* ARGSUSED */
static int
usb_mid_power(dev_info_t *dip, int comp, int level)
{
	usb_mid_t		*usb_mid;
	usb_common_power_t	*midpm;
	int			rval = DDI_FAILURE;

	usb_mid =  usb_mid_obtain_state(dip);

	USB_DPRINTF_L4(DPRINT_MASK_PM, usb_mid->mi_log_handle,
	    "usb_mid_power: Begin: usb_mid = %p, level = %d",
	    (void *)usb_mid, level);

	mutex_enter(&usb_mid->mi_mutex);
	midpm = usb_mid->mi_pm;

	/* check if we are transitioning to a legal power level */
	if (USB_DEV_PWRSTATE_OK(midpm->uc_pwr_states, level)) {
		USB_DPRINTF_L2(DPRINT_MASK_PM, usb_mid->mi_log_handle,
		    "usb_mid_power: illegal power level = %d "
		    "uc_pwr_states = %x", level, midpm->uc_pwr_states);

		mutex_exit(&usb_mid->mi_mutex);

		return (rval);
	}

	rval = usba_common_power(dip, &(midpm->uc_current_power),
	    &(usb_mid->mi_dev_state), level);

	mutex_exit(&usb_mid->mi_mutex);

	return (rval);
}


/*
 * attach/resume entry point
 */
static int
usb_mid_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		instance = ddi_get_instance(dip);
	usb_mid_t	*usb_mid = NULL;
	uint_t		n_ifs, i;
	size_t		size;

	switch (cmd) {
	case DDI_ATTACH:

		break;
	case DDI_RESUME:
		usb_mid = (usb_mid_t *)ddi_get_soft_state(usb_mid_statep,
		    instance);
		(void) usb_mid_restore_device_state(dip, usb_mid);

		if (usb_mid->mi_ugen_hdl) {
			(void) usb_ugen_attach(usb_mid->mi_ugen_hdl,
			    DDI_RESUME);
		}

		return (DDI_SUCCESS);
	default:

		return (DDI_FAILURE);
	}

	/*
	 * Attach:
	 *
	 * Allocate soft state and initialize
	 */
	if (ddi_soft_state_zalloc(usb_mid_statep, instance) != DDI_SUCCESS) {
		goto fail;
	}

	usb_mid = ddi_get_soft_state(usb_mid_statep, instance);
	if (usb_mid == NULL) {

		goto fail;
	}

	/* allocate handle for logging of messages */
	usb_mid->mi_log_handle = usb_alloc_log_hdl(dip, "mid",
	    &usb_mid_errlevel,
	    &usb_mid_errmask, &usb_mid_instance_debug,
	    0);

	usb_mid->mi_usba_device = usba_get_usba_device(dip);
	usb_mid->mi_dip	= dip;
	usb_mid->mi_instance = instance;
	usb_mid->mi_n_ifs = usb_mid->mi_usba_device->usb_n_ifs;

	/* attach client driver to USBA */
	if (usb_client_attach(dip, USBDRV_VERSION, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, usb_mid->mi_log_handle,
		    "usb_client_attach failed");
		goto fail;
	}
	if (usb_get_dev_data(dip, &usb_mid->mi_dev_data, USB_PARSE_LVL_NONE,
	    0) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, usb_mid->mi_log_handle,
		    "usb_get_dev_data failed");
		goto fail;
	}

	mutex_init(&usb_mid->mi_mutex, NULL, MUTEX_DRIVER,
	    usb_mid->mi_dev_data->dev_iblock_cookie);

	usb_free_dev_data(dip, usb_mid->mi_dev_data);
	usb_mid->mi_dev_data = NULL;

	usb_mid->mi_init_state |= USB_MID_LOCK_INIT;

	if (ddi_create_minor_node(dip, "usb_mid", S_IFCHR,
	    instance << USB_MID_MINOR_INSTANCE_SHIFT,
	    DDI_NT_NEXUS, 0) != DDI_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, usb_mid->mi_log_handle,
		    "cannot create devctl minor node");
		goto fail;
	}

	usb_mid->mi_init_state |= USB_MID_MINOR_NODE_CREATED;

	/*
	 * allocate array for keeping track of child dips
	 */
	n_ifs = usb_mid->mi_n_ifs;
	usb_mid->mi_cd_list_length = size = (sizeof (dev_info_t *)) * n_ifs;

	usb_mid->mi_children_dips = kmem_zalloc(size, KM_SLEEP);
	usb_mid->mi_child_events = kmem_zalloc(sizeof (uint8_t) * n_ifs,
	    KM_SLEEP);
	usb_mid->mi_children_ifs = kmem_zalloc(sizeof (uint_t) * n_ifs,
	    KM_SLEEP);
	for (i = 0; i < n_ifs; i++) {
		usb_mid->mi_children_ifs[i] = 1;
	}

	/*
	 * Event handling: definition and registration
	 * get event handle for events that we have defined
	 */
	(void) ndi_event_alloc_hdl(dip, 0, &usb_mid->mi_ndi_event_hdl,
	    NDI_SLEEP);

	/* bind event set to the handle */
	if (ndi_event_bind_set(usb_mid->mi_ndi_event_hdl, &usb_mid_ndi_events,
	    NDI_SLEEP)) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, usb_mid->mi_log_handle,
		    "usb_mid_attach: binding event set failed");

		goto fail;
	}

	usb_mid->mi_dev_state = USB_DEV_ONLINE;

	/*
	 * now create components to power manage this device
	 * before attaching children
	 */
	usb_mid_create_pm_components(dip, usb_mid);

	/* event registration for events from our parent */
	usba_common_register_events(usb_mid->mi_dip, 1, usb_mid_event_cb);

	usb_mid->mi_init_state |= USB_MID_EVENTS_REGISTERED;

	ddi_report_dev(dip);

	return (DDI_SUCCESS);

fail:
	USB_DPRINTF_L2(DPRINT_MASK_ATTA, NULL, "usb_mid%d cannot attach",
	    instance);

	if (usb_mid) {
		(void) usb_mid_cleanup(dip, usb_mid);
	}

	return (DDI_FAILURE);
}


/* detach or suspend this instance */
static int
usb_mid_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	usb_mid_t	*usb_mid = usb_mid_obtain_state(dip);

	USB_DPRINTF_L4(DPRINT_MASK_ATTA, usb_mid->mi_log_handle,
	    "usb_mid_detach: cmd = 0x%x", cmd);

	switch (cmd) {
	case DDI_DETACH:

		return (usb_mid_cleanup(dip, usb_mid));
	case DDI_SUSPEND:
		/* nothing to do */
		mutex_enter(&usb_mid->mi_mutex);
		usb_mid->mi_dev_state = USB_DEV_SUSPENDED;
		mutex_exit(&usb_mid->mi_mutex);

		if (usb_mid->mi_ugen_hdl) {
			int rval = usb_ugen_detach(usb_mid->mi_ugen_hdl,
			    DDI_SUSPEND);
			return (rval == USB_SUCCESS ? DDI_SUCCESS :
			    DDI_FAILURE);
		}

		return (DDI_SUCCESS);
	default:

		return (DDI_FAILURE);
	}

	_NOTE(NOT_REACHED)
	/* NOTREACHED */
}

/*
 * usb_mid_cleanup:
 *	cleanup usb_mid and deallocate. this function is called for
 *	handling attach failures and detaching including dynamic
 *	reconfiguration
 */
/*ARGSUSED*/
static int
usb_mid_cleanup(dev_info_t *dip, usb_mid_t *usb_mid)
{
	usb_common_power_t	*midpm;
	int		rval;

	USB_DPRINTF_L4(DPRINT_MASK_ATTA, usb_mid->mi_log_handle,
	    "usb_mid_cleanup:");

	if ((usb_mid->mi_init_state & USB_MID_LOCK_INIT) == 0) {

		goto done;
	}

	/*
	 * deallocate events, if events are still registered
	 * (ie. children still attached) then we have to fail the detach
	 */
	if (usb_mid->mi_ndi_event_hdl &&
	    (ndi_event_free_hdl(usb_mid->mi_ndi_event_hdl) != NDI_SUCCESS)) {

		USB_DPRINTF_L2(DPRINT_MASK_ATTA, usb_mid->mi_log_handle,
		    "usb_mid_cleanup: ndi_event_free_hdl failed");

		return (DDI_FAILURE);
	}

	/*
	 * Disable the event callbacks, after this point, event
	 * callbacks will never get called. Note we shouldn't hold
	 * mutex while unregistering events because there may be a
	 * competing event callback thread. Event callbacks are done
	 * with ndi mutex held and this can cause a potential deadlock.
	 * Note that cleanup can't fail after deregistration of events.
	 */
	if (usb_mid->mi_init_state & USB_MID_EVENTS_REGISTERED) {
		usba_common_unregister_events(usb_mid->mi_dip, 1);
	}

	midpm = usb_mid->mi_pm;

	mutex_enter(&usb_mid->mi_mutex);

	if ((midpm) && (usb_mid->mi_dev_state != USB_DEV_DISCONNECTED)) {

		mutex_exit(&usb_mid->mi_mutex);

		(void) pm_busy_component(dip, 0);
		if (midpm->uc_wakeup_enabled) {

			/* First bring the device to full power */
			(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);

			rval = usb_handle_remote_wakeup(dip,
			    USB_REMOTE_WAKEUP_DISABLE);

			if (rval != DDI_SUCCESS) {
				USB_DPRINTF_L2(DPRINT_MASK_EVENTS,
				    usb_mid->mi_log_handle,
				    "usb_cleanup: disable remote "
				    "wakeup failed, rval=%d", rval);
			}
		}

		(void) pm_lower_power(usb_mid->mi_dip, 0, USB_DEV_OS_PWR_OFF);
		(void) pm_idle_component(dip, 0);
	} else {
		mutex_exit(&usb_mid->mi_mutex);
	}

	if (midpm) {
		kmem_free(midpm, sizeof (usb_common_power_t));
	}

	/* free children list */
	if (usb_mid->mi_children_dips) {
		kmem_free(usb_mid->mi_children_dips,
		    usb_mid->mi_cd_list_length);
	}

	if (usb_mid->mi_child_events) {
		kmem_free(usb_mid->mi_child_events, sizeof (uint8_t) *
		    usb_mid->mi_n_ifs);
	}

	if (usb_mid->mi_children_ifs) {
		kmem_free(usb_mid->mi_children_ifs, sizeof (uint_t) *
		    usb_mid->mi_n_ifs);
	}

	if (usb_mid->mi_init_state & USB_MID_MINOR_NODE_CREATED) {
		ddi_remove_minor_node(dip, NULL);
	}

	mutex_destroy(&usb_mid->mi_mutex);

done:
	usb_client_detach(dip, usb_mid->mi_dev_data);

	if (usb_mid->mi_ugen_hdl) {
		(void) usb_ugen_detach(usb_mid->mi_ugen_hdl, DDI_DETACH);
		usb_ugen_release_hdl(usb_mid->mi_ugen_hdl);
	}

	usb_free_log_hdl(usb_mid->mi_log_handle);
	ddi_soft_state_free(usb_mid_statep, ddi_get_instance(dip));

	ddi_prop_remove_all(dip);

	return (DDI_SUCCESS);
}


static void
usb_mid_ugen_attach(usb_mid_t *usb_mid, boolean_t remove_children)
{
	_NOTE(NO_COMPETING_THREADS_NOW);

	if (usb_mid->mi_ugen_hdl == NULL) {
		usb_ugen_info_t usb_ugen_info;
		int		rval;
		usb_ugen_hdl_t	hdl;

		USB_DPRINTF_L4(DPRINT_MASK_ATTA, usb_mid->mi_log_handle,
		    "usb_mid_ugen_attach: get handle");

		bzero(&usb_ugen_info, sizeof (usb_ugen_info));

		usb_ugen_info.usb_ugen_flags = (remove_children ?
		    USB_UGEN_REMOVE_CHILDREN : 0);
		usb_ugen_info.usb_ugen_minor_node_ugen_bits_mask =
		    (dev_t)USB_MID_MINOR_UGEN_BITS_MASK;
		usb_ugen_info.usb_ugen_minor_node_instance_mask =
		    (dev_t)~USB_MID_MINOR_UGEN_BITS_MASK;

		mutex_exit(&usb_mid->mi_mutex);
		hdl = usb_ugen_get_hdl(usb_mid->mi_dip,
		    &usb_ugen_info);

		if ((rval = usb_ugen_attach(hdl, DDI_ATTACH)) != USB_SUCCESS) {
			USB_DPRINTF_L4(DPRINT_MASK_ATTA, usb_mid->mi_log_handle,
			    "failed to create ugen support (%d)", rval);
			usb_ugen_release_hdl(hdl);

			mutex_enter(&usb_mid->mi_mutex);
		} else {
			mutex_enter(&usb_mid->mi_mutex);
			usb_mid->mi_ugen_hdl = hdl;
		}
	}

#ifndef lint
	_NOTE(COMPETING_THREADS_NOW);
#endif
}


/*
 * usb_mid_create_children:
 */
static void
usb_mid_create_children(usb_mid_t *usb_mid)
{
	usba_device_t		*usba_device;
	uint_t			n_ifs, if_count;
	uint_t			i, j;
	dev_info_t		*cdip, *ia_dip;
	uint_t			ugen_bound = 0;
	uint_t			bound_children = 0;

	usba_device = usba_get_usba_device(usb_mid->mi_dip);

	USB_DPRINTF_L4(DPRINT_MASK_ATTA, usb_mid->mi_log_handle,
	    "usb_mid_attach_child_drivers: port = %d, address = %d",
	    usba_device->usb_port, usba_device->usb_addr);

	if (usb_mid->mi_removed_children) {

			return;
	}

	n_ifs = usb_mid->mi_n_ifs;
	if_count = 1;

	USB_DPRINTF_L4(DPRINT_MASK_ATTA, usb_mid->mi_log_handle,
	    "usb_mid_create_children: #interfaces = %d", n_ifs);

	/*
	 * create all children if not already present
	 */
	for (i = 0; i < n_ifs; i += if_count) {

		/* ignore since this if is included by an ia */
		if (usb_mid->mi_children_ifs[i] == 0) {

			continue;
		}

		if (usb_mid->mi_children_dips[i] != NULL) {
			if (i_ddi_node_state(
			    usb_mid->mi_children_dips[i]) >=
			    DS_BOUND) {
					bound_children++;
			}

			continue;
		}

		mutex_exit(&usb_mid->mi_mutex);
		ia_dip = usba_ready_interface_association_node(usb_mid->mi_dip,
		    i, &if_count);

		if (ia_dip != NULL) {
			if (usba_bind_driver(ia_dip) == USB_SUCCESS) {
				bound_children++;
				if (strcmp(ddi_driver_name(ia_dip),
				    "ugen") == 0) {
					ugen_bound++;
				}
			}

			/*
			 * IA node owns if_count interfaces.
			 * The rest interfaces own none.
			 */
			mutex_enter(&usb_mid->mi_mutex);
			usb_mid->mi_children_dips[i] = ia_dip;
			usb_mid->mi_children_ifs[i] = if_count;
			for (j = i + 1; j < i + if_count; j++) {
				usb_mid->mi_children_ifs[j] = 0;
			}

			continue;
		}

		cdip = usba_ready_interface_node(usb_mid->mi_dip, i);

		if (cdip != NULL) {
			if (usba_bind_driver(cdip) ==
			    USB_SUCCESS) {
				bound_children++;
				if (strcmp(ddi_driver_name(cdip),
				    "ugen") == 0) {
					ugen_bound++;
				}
			}

			/*
			 * interface node owns 1 interface always.
			 */
			mutex_enter(&usb_mid->mi_mutex);
			usb_mid->mi_children_dips[i] = cdip;
			usb_mid->mi_children_ifs[i] = 1;
			mutex_exit(&usb_mid->mi_mutex);

		}

		mutex_enter(&usb_mid->mi_mutex);
	}

	usb_mid->mi_removed_children = (bound_children ? B_FALSE : B_TRUE);

	/*
	 * if there are no ugen interface children, create ugen support at
	 * device level, use a separate thread because we may be at interrupt
	 * level
	 */
	if ((ugen_bound == 0) && (usb_mid->mi_ugen_hdl == NULL)) {
		/*
		 * we only need to remove the children if there are
		 * multiple configurations which would fail if there
		 * are child interfaces
		 */
		if ((usb_mid->mi_removed_children == B_FALSE) &&
		    (usba_device->usb_n_cfgs > 1)) {
			USB_DPRINTF_L1(DPRINT_MASK_ATTA,
			    usb_mid->mi_log_handle,
			    "can't support ugen for multiple "
			    "configurations devices that have attached "
			    "child interface drivers");
		} else {
			usb_mid_ugen_attach(usb_mid,
			    usb_mid->mi_removed_children);
		}
	}
}


/*
 * event support
 */
static int
usb_mid_busop_get_eventcookie(dev_info_t *dip,
	dev_info_t *rdip, char *eventname, ddi_eventcookie_t *cookie)
{
	usb_mid_t  *usb_mid = usb_mid_obtain_state(dip);

	USB_DPRINTF_L3(DPRINT_MASK_EVENTS, usb_mid->mi_log_handle,
	    "usb_mid_busop_get_eventcookie: dip=0x%p, rdip=0x%p, "
	    "event=%s", (void *)dip, (void *)rdip, eventname);
	USB_DPRINTF_L3(DPRINT_MASK_EVENTS, usb_mid->mi_log_handle,
	    "(dip=%s%d rdip=%s%d)",
	    ddi_driver_name(dip), ddi_get_instance(dip),
	    ddi_driver_name(rdip), ddi_get_instance(rdip));

	/* return event cookie, iblock cookie, and level */
	return (ndi_event_retrieve_cookie(usb_mid->mi_ndi_event_hdl,
	    rdip, eventname, cookie, NDI_EVENT_NOPASS));
}


static int
usb_mid_busop_add_eventcall(dev_info_t *dip,
	dev_info_t *rdip,
	ddi_eventcookie_t cookie,
	void (*callback)(dev_info_t *dip,
	    ddi_eventcookie_t cookie, void *arg,
	    void *bus_impldata),
	void *arg, ddi_callback_id_t *cb_id)
{
	usb_mid_t  *usb_mid = usb_mid_obtain_state(dip);
	int	ifno = usba_get_ifno(rdip);

	USB_DPRINTF_L3(DPRINT_MASK_EVENTS, usb_mid->mi_log_handle,
	    "usb_mid_busop_add_eventcall: dip=0x%p, rdip=0x%p "
	    "cookie=0x%p, cb=0x%p, arg=0x%p",
	    (void *)dip, (void *)rdip, (void *)cookie, (void *)callback, arg);
	USB_DPRINTF_L3(DPRINT_MASK_EVENTS, usb_mid->mi_log_handle,
	    "(dip=%s%d rdip=%s%d event=%s)",
	    ddi_driver_name(dip), ddi_get_instance(dip),
	    ddi_driver_name(rdip), ddi_get_instance(rdip),
	    ndi_event_cookie_to_name(usb_mid->mi_ndi_event_hdl, cookie));

	/* Set flag on children registering events */
	switch (ndi_event_cookie_to_tag(usb_mid->mi_ndi_event_hdl, cookie)) {
	case USBA_EVENT_TAG_HOT_REMOVAL:
		mutex_enter(&usb_mid->mi_mutex);
		usb_mid->mi_child_events[ifno] |=
		    USB_MID_CHILD_EVENT_DISCONNECT;
		mutex_exit(&usb_mid->mi_mutex);

		break;
	case USBA_EVENT_TAG_PRE_SUSPEND:
		mutex_enter(&usb_mid->mi_mutex);
		usb_mid->mi_child_events[ifno] |=
		    USB_MID_CHILD_EVENT_PRESUSPEND;
		mutex_exit(&usb_mid->mi_mutex);

		break;
	default:

		break;
	}
	/* add callback (perform registration) */
	return (ndi_event_add_callback(usb_mid->mi_ndi_event_hdl,
	    rdip, cookie, callback, arg, NDI_SLEEP, cb_id));
}


static int
usb_mid_busop_remove_eventcall(dev_info_t *dip, ddi_callback_id_t cb_id)
{
	usb_mid_t  *usb_mid = usb_mid_obtain_state(dip);
	ndi_event_callbacks_t *cb = (ndi_event_callbacks_t *)cb_id;

	ASSERT(cb);

	USB_DPRINTF_L3(DPRINT_MASK_EVENTS, usb_mid->mi_log_handle,
	    "usb_mid_busop_remove_eventcall: dip=0x%p, rdip=0x%p "
	    "cookie=0x%p", (void *)dip, (void *)cb->ndi_evtcb_dip,
	    (void *)cb->ndi_evtcb_cookie);
	USB_DPRINTF_L3(DPRINT_MASK_EVENTS, usb_mid->mi_log_handle,
	    "(dip=%s%d rdip=%s%d event=%s)",
	    ddi_driver_name(dip), ddi_get_instance(dip),
	    ddi_driver_name(cb->ndi_evtcb_dip),
	    ddi_get_instance(cb->ndi_evtcb_dip),
	    ndi_event_cookie_to_name(usb_mid->mi_ndi_event_hdl,
	    cb->ndi_evtcb_cookie));

	/* remove event registration from our event set */
	return (ndi_event_remove_callback(usb_mid->mi_ndi_event_hdl, cb_id));
}


static int
usb_mid_busop_post_event(dev_info_t *dip,
	dev_info_t *rdip,
	ddi_eventcookie_t cookie,
	void *bus_impldata)
{
	usb_mid_t  *usb_mid = usb_mid_obtain_state(dip);

	USB_DPRINTF_L3(DPRINT_MASK_EVENTS, usb_mid->mi_log_handle,
	    "usb_mid_busop_post_event: dip=0x%p, rdip=0x%p "
	    "cookie=0x%p, impl=0x%p",
	    (void *)dip, (void *)rdip, (void *)cookie, bus_impldata);
	USB_DPRINTF_L3(DPRINT_MASK_EVENTS, usb_mid->mi_log_handle,
	    "(dip=%s%d rdip=%s%d event=%s)",
	    ddi_driver_name(dip), ddi_get_instance(dip),
	    ddi_driver_name(rdip), ddi_get_instance(rdip),
	    ndi_event_cookie_to_name(usb_mid->mi_ndi_event_hdl, cookie));

	/* post event to all children registered for this event */
	return (ndi_event_run_callbacks(usb_mid->mi_ndi_event_hdl, rdip,
	    cookie, bus_impldata));
}


/*
 * usb_mid_restore_device_state
 *	set the original configuration of the device
 */
static int
usb_mid_restore_device_state(dev_info_t *dip, usb_mid_t *usb_mid)
{
	usb_common_power_t		*midpm;

	USB_DPRINTF_L4(DPRINT_MASK_EVENTS, usb_mid->mi_log_handle,
	    "usb_mid_restore_device_state: usb_mid = %p", (void *)usb_mid);

	mutex_enter(&usb_mid->mi_mutex);
	midpm = usb_mid->mi_pm;
	mutex_exit(&usb_mid->mi_mutex);

	/* First bring the device to full power */
	(void) pm_busy_component(dip, 0);
	(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);

	if (usb_check_same_device(dip, usb_mid->mi_log_handle, USB_LOG_L0,
	    DPRINT_MASK_EVENTS, USB_CHK_VIDPID, NULL) != USB_SUCCESS) {

		/* change the device state from suspended to disconnected */
		mutex_enter(&usb_mid->mi_mutex);
		usb_mid->mi_dev_state = USB_DEV_DISCONNECTED;
		mutex_exit(&usb_mid->mi_mutex);
		(void) pm_idle_component(dip, 0);

		return (USB_FAILURE);
	}

	/*
	 * if the device had remote wakeup earlier,
	 * enable it again
	 */
	if (midpm->uc_wakeup_enabled) {
		(void) usb_handle_remote_wakeup(usb_mid->mi_dip,
		    USB_REMOTE_WAKEUP_ENABLE);
	}

	mutex_enter(&usb_mid->mi_mutex);
	usb_mid->mi_dev_state = USB_DEV_ONLINE;
	mutex_exit(&usb_mid->mi_mutex);

	(void) pm_idle_component(dip, 0);

	return (USB_SUCCESS);
}


/*
 * usb_mid_event_cb()
 *	handle disconnect and connect events
 */
static void
usb_mid_event_cb(dev_info_t *dip, ddi_eventcookie_t cookie,
	void *arg, void *bus_impldata)
{
	int		i, tag;
	usb_mid_t	*usb_mid = usb_mid_obtain_state(dip);
	dev_info_t	*child_dip;
	ddi_eventcookie_t rm_cookie, ins_cookie, suspend_cookie, resume_cookie;

	USB_DPRINTF_L4(DPRINT_MASK_EVENTS, usb_mid->mi_log_handle,
	    "usb_mid_event_cb: dip=0x%p, cookie=0x%p, "
	    "arg=0x%p, impl=0x%p",
	    (void *)dip, (void *)cookie, arg, bus_impldata);
	USB_DPRINTF_L4(DPRINT_MASK_EVENTS, usb_mid->mi_log_handle,
	    "(dip=%s%d event=%s)",
	    ddi_driver_name(dip), ddi_get_instance(dip),
	    ndi_event_cookie_to_name(usb_mid->mi_ndi_event_hdl, cookie));

	tag = NDI_EVENT_TAG(cookie);
	rm_cookie = ndi_event_tag_to_cookie(
	    usb_mid->mi_ndi_event_hdl, USBA_EVENT_TAG_HOT_REMOVAL);
	suspend_cookie = ndi_event_tag_to_cookie(
	    usb_mid->mi_ndi_event_hdl, USBA_EVENT_TAG_PRE_SUSPEND);
	ins_cookie = ndi_event_tag_to_cookie(
	    usb_mid->mi_ndi_event_hdl, USBA_EVENT_TAG_HOT_INSERTION);
	resume_cookie = ndi_event_tag_to_cookie(
	    usb_mid->mi_ndi_event_hdl, USBA_EVENT_TAG_POST_RESUME);

	mutex_enter(&usb_mid->mi_mutex);
	switch (tag) {
	case USBA_EVENT_TAG_HOT_REMOVAL:
		if (usb_mid->mi_dev_state == USB_DEV_DISCONNECTED) {
			USB_DPRINTF_L2(DPRINT_MASK_EVENTS,
			    usb_mid->mi_log_handle,
			    "usb_mid_event_cb: Device already disconnected");
		} else {
			/* we are disconnected so set our state now */
			usb_mid->mi_dev_state = USB_DEV_DISCONNECTED;
			for (i = 0; i < usb_mid->mi_n_ifs; i++) {
				usb_mid->mi_child_events[i] &= ~
				    USB_MID_CHILD_EVENT_DISCONNECT;
			}
			mutex_exit(&usb_mid->mi_mutex);

			/* pass disconnect event to all the children */
			(void) ndi_event_run_callbacks(
			    usb_mid->mi_ndi_event_hdl, NULL,
			    rm_cookie, bus_impldata);

			if (usb_mid->mi_ugen_hdl) {
				(void) usb_ugen_disconnect_ev_cb(
				    usb_mid->mi_ugen_hdl);
			}
			mutex_enter(&usb_mid->mi_mutex);
		}
		break;
	case USBA_EVENT_TAG_PRE_SUSPEND:
		/* set our state *after* suspending children */
		mutex_exit(&usb_mid->mi_mutex);

		/* pass pre_suspend event to all the children */
		(void) ndi_event_run_callbacks(usb_mid->mi_ndi_event_hdl,
		    NULL, suspend_cookie, bus_impldata);

		mutex_enter(&usb_mid->mi_mutex);
		for (i = 0; i < usb_mid->mi_n_ifs; i++) {
			usb_mid->mi_child_events[i] &= ~
			    USB_MID_CHILD_EVENT_PRESUSPEND;
		}
		break;
	case USBA_EVENT_TAG_HOT_INSERTION:
		mutex_exit(&usb_mid->mi_mutex);
		if (usb_mid_restore_device_state(dip, usb_mid) == USB_SUCCESS) {

			/*
			 * Check to see if this child has missed the disconnect
			 * event before it registered for event cb
			 */
			mutex_enter(&usb_mid->mi_mutex);
			for (i = 0; i < usb_mid->mi_n_ifs; i++) {
				if ((usb_mid->mi_child_events[i] &
				    USB_MID_CHILD_EVENT_DISCONNECT) &&
				    usb_mid->mi_children_ifs[i]) {
					usb_mid->mi_child_events[i] &=
					    ~USB_MID_CHILD_EVENT_DISCONNECT;
					child_dip =
					    usb_mid->mi_children_dips[i];
					mutex_exit(&usb_mid->mi_mutex);

					/* post the missed disconnect */
					(void) ndi_event_do_callback(
					    usb_mid->mi_ndi_event_hdl,
					    child_dip,
					    rm_cookie,
					    bus_impldata);
					mutex_enter(&usb_mid->mi_mutex);
				}
			}
			mutex_exit(&usb_mid->mi_mutex);

			/* pass reconnect event to all the children */
			(void) ndi_event_run_callbacks(
			    usb_mid->mi_ndi_event_hdl, NULL,
			    ins_cookie, bus_impldata);

			if (usb_mid->mi_ugen_hdl) {
				(void) usb_ugen_reconnect_ev_cb(
				    usb_mid->mi_ugen_hdl);
			}
		}
		mutex_enter(&usb_mid->mi_mutex);
		break;
	case USBA_EVENT_TAG_POST_RESUME:
		/*
		 * Check to see if this child has missed the pre-suspend
		 * event before it registered for event cb
		 */
		for (i = 0; i < usb_mid->mi_n_ifs; i++) {
			if ((usb_mid->mi_child_events[i] &
			    USB_MID_CHILD_EVENT_PRESUSPEND) &&
			    usb_mid->mi_children_ifs[i]) {
				usb_mid->mi_child_events[i] &=
				    ~USB_MID_CHILD_EVENT_PRESUSPEND;
				child_dip = usb_mid->mi_children_dips[i];
				mutex_exit(&usb_mid->mi_mutex);

				/* post the missed pre-suspend event */
				(void) ndi_event_do_callback(
				    usb_mid->mi_ndi_event_hdl,
				    child_dip, suspend_cookie,
				    bus_impldata);
				mutex_enter(&usb_mid->mi_mutex);
			}
		}
		mutex_exit(&usb_mid->mi_mutex);

		/* pass post_resume event to all the children */
		(void) ndi_event_run_callbacks(usb_mid->mi_ndi_event_hdl,
		    NULL, resume_cookie, bus_impldata);

		mutex_enter(&usb_mid->mi_mutex);
		break;
	}
	mutex_exit(&usb_mid->mi_mutex);

}


/*
 * create the pm components required for power management
 */
static void
usb_mid_create_pm_components(dev_info_t *dip, usb_mid_t *usb_mid)
{
	usb_common_power_t	*midpm;
	uint_t		pwr_states;

	USB_DPRINTF_L4(DPRINT_MASK_PM, usb_mid->mi_log_handle,
	    "usb_mid_create_pm_components: Begin");

	/* Allocate the PM state structure */
	midpm = kmem_zalloc(sizeof (usb_common_power_t), KM_SLEEP);

	mutex_enter(&usb_mid->mi_mutex);
	usb_mid->mi_pm = midpm;
	midpm->uc_usb_statep = usb_mid;
	midpm->uc_pm_capabilities = 0; /* XXXX should this be 0?? */
	midpm->uc_current_power = USB_DEV_OS_FULL_PWR;
	mutex_exit(&usb_mid->mi_mutex);

	/*
	 * By not enabling parental notification, PM enforces
	 * "strict parental dependency" meaning, usb_mid won't
	 * power off until any of its children are in full power.
	 */

	/*
	 * there are 3 scenarios:
	 * 1. a well behaved device should have remote wakeup
	 * at interface and device level. If the interface
	 * wakes up, usb_mid will wake up
	 * 2. if the device doesn't have remote wake up and
	 * the interface has, PM will still work, ie.
	 * the interfaces wakes up and usb_mid wakes up
	 * 3. if neither the interface nor device has remote
	 * wakeup, the interface will wake up when it is opened
	 * and goes to sleep after being closed for a while
	 * In this case usb_mid should also go to sleep shortly
	 * thereafter
	 * In all scenarios it doesn't really matter whether
	 * remote wakeup at the device level is enabled or not
	 * but we do it anyways
	 */
	if (usb_handle_remote_wakeup(dip, USB_REMOTE_WAKEUP_ENABLE) ==
	    USB_SUCCESS) {
		USB_DPRINTF_L3(DPRINT_MASK_PM, usb_mid->mi_log_handle,
		    "usb_mid_create_pm_components: "
		    "Remote Wakeup Enabled");
		midpm->uc_wakeup_enabled = 1;
	}

	if (usb_create_pm_components(dip, &pwr_states) ==
	    USB_SUCCESS) {
		midpm->uc_pwr_states = (uint8_t)pwr_states;
		(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);
	}

	USB_DPRINTF_L4(DPRINT_MASK_PM, usb_mid->mi_log_handle,
	    "usb_mid_create_pm_components: End");
}


/*
 * usb_mid_obtain_state:
 */
usb_mid_t *
usb_mid_obtain_state(dev_info_t *dip)
{
	int instance = ddi_get_instance(dip);
	usb_mid_t *statep = ddi_get_soft_state(usb_mid_statep, instance);

	ASSERT(statep != NULL);

	return (statep);
}


/*
 * ugen support
 */
/* ARGSUSED3 */
static int
usb_mid_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	struct usb_mid *usb_mid;
	int	rval;

	if ((usb_mid = ddi_get_soft_state(usb_mid_statep,
	    USB_MID_MINOR_TO_INSTANCE(getminor(*devp)))) == NULL) {

		return (ENXIO);
	}

	USB_DPRINTF_L4(DPRINT_MASK_CBOPS, usb_mid->mi_log_handle,
	    "usb_mid_open: usb_mid = 0x%p *devp = 0x%lx",
	    (void *)usb_mid, *devp);

	/* First bring the device to full power */
	(void) pm_busy_component(usb_mid->mi_dip, 0);
	(void) pm_raise_power(usb_mid->mi_dip, 0, USB_DEV_OS_FULL_PWR);


	rval = usb_ugen_open(usb_mid->mi_ugen_hdl, devp, flags, otyp,
	    credp);
	if (rval) {
		(void) pm_idle_component(usb_mid->mi_dip, 0);
	} else {
		/*
		 * since all ugen opens are exclusive we can count the
		 * opens
		 */
		mutex_enter(&usb_mid->mi_mutex);
		usb_mid->mi_ugen_open_count++;
		mutex_exit(&usb_mid->mi_mutex);
	}

	return (rval);
}


/* ARGSUSED */
static int
usb_mid_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	struct usb_mid *usb_mid;
	int rval;

	if ((usb_mid = ddi_get_soft_state(usb_mid_statep,
	    USB_MID_MINOR_TO_INSTANCE(getminor(dev)))) == NULL) {

		return (ENXIO);
	}

	rval = usb_ugen_close(usb_mid->mi_ugen_hdl, dev, flag, otyp,
	    credp);
	if (rval == 0) {
		(void) pm_idle_component(usb_mid->mi_dip, 0);
		mutex_enter(&usb_mid->mi_mutex);
		usb_mid->mi_ugen_open_count--;
		mutex_exit(&usb_mid->mi_mutex);
	}

	return (rval);
}


static int
usb_mid_read(dev_t dev, struct uio *uio, cred_t *credp)
{
	struct usb_mid *usb_mid;

	if ((usb_mid = ddi_get_soft_state(usb_mid_statep,
	    USB_MID_MINOR_TO_INSTANCE(getminor(dev)))) == NULL) {

		return (ENXIO);
	}

	return (usb_ugen_read(usb_mid->mi_ugen_hdl, dev, uio, credp));
}


static int
usb_mid_write(dev_t dev, struct uio *uio, cred_t *credp)
{
	struct usb_mid *usb_mid;

	if ((usb_mid = ddi_get_soft_state(usb_mid_statep,
	    USB_MID_MINOR_TO_INSTANCE(getminor(dev)))) == NULL) {

		return (ENXIO);
	}

	return (usb_ugen_write(usb_mid->mi_ugen_hdl, dev, uio, credp));
}


static int
usb_mid_poll(dev_t dev, short events, int anyyet,  short *reventsp,
    struct pollhead **phpp)
{
	struct usb_mid *usb_mid;

	if ((usb_mid = ddi_get_soft_state(usb_mid_statep,
	    USB_MID_MINOR_TO_INSTANCE(getminor(dev)))) == NULL) {

		return (ENXIO);
	}

	return (usb_ugen_poll(usb_mid->mi_ugen_hdl, dev, events,
	    anyyet, reventsp, phpp));
}

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
 * Copyright 2023 Oxide Computer Company
 */

/*
 * usb interface association driver
 *
 *	this driver attempts to the interface association node and
 *	creates/manages child nodes for the included interfaces.
 */

#if defined(lint) && !defined(DEBUG)
#define	DEBUG	1
#endif
#include <sys/usb/usba/usbai_version.h>
#include <sys/usb/usba.h>
#include <sys/usb/usba/usba_types.h>
#include <sys/usb/usba/usba_impl.h>
#include <sys/usb/usb_ia/usb_iavar.h>

/* Debugging support */
uint_t usb_ia_errlevel = USB_LOG_L4;
uint_t usb_ia_errmask = (uint_t)DPRINT_MASK_ALL;
uint_t usb_ia_instance_debug = (uint_t)-1;
uint_t usb_ia_bus_config_debug = 0;

_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ia_errlevel))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ia_errmask))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ia_instance_debug))

_NOTE(SCHEME_PROTECTS_DATA("unique", msgb))
_NOTE(SCHEME_PROTECTS_DATA("unique", dev_info))
_NOTE(SCHEME_PROTECTS_DATA("unique", usb_pipe_policy))

static struct cb_ops usb_ia_cb_ops = {
	nodev,		/* open */
	nodev,		/* close */
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	nodev,		/* ioctl */
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* poll */
	ddi_prop_op,	/* prop_op */
	NULL,		/* aread */
	D_MP
};

static int usb_ia_busop_get_eventcookie(dev_info_t *dip,
			dev_info_t *rdip,
			char *eventname,
			ddi_eventcookie_t *cookie);
static int usb_ia_busop_add_eventcall(dev_info_t *dip,
			dev_info_t *rdip,
			ddi_eventcookie_t cookie,
			void (*callback)(dev_info_t *dip,
				ddi_eventcookie_t cookie, void *arg,
				void *bus_impldata),
			void *arg, ddi_callback_id_t *cb_id);
static int usb_ia_busop_remove_eventcall(dev_info_t *dip,
			ddi_callback_id_t cb_id);
static int usb_ia_busop_post_event(dev_info_t *dip,
			dev_info_t *rdip,
			ddi_eventcookie_t cookie,
			void *bus_impldata);
static int usb_ia_bus_config(dev_info_t *dip,
			uint_t flag,
			ddi_bus_config_op_t op,
			void *arg,
			dev_info_t **child);
static int usb_ia_bus_unconfig(dev_info_t *dip,
			uint_t flag,
			ddi_bus_config_op_t op,
			void *arg);

/*
 * autoconfiguration data and routines.
 */
static int	usb_ia_info(dev_info_t *, ddi_info_cmd_t,
				void *, void **);
static int	usb_ia_attach(dev_info_t *, ddi_attach_cmd_t);
static int	usb_ia_detach(dev_info_t *, ddi_detach_cmd_t);

/* other routines */
static void usb_ia_create_pm_components(dev_info_t *, usb_ia_t *);
static int usb_ia_bus_ctl(dev_info_t *, dev_info_t	*,
				ddi_ctl_enum_t, void *, void *);
static int usb_ia_power(dev_info_t *, int, int);
static int usb_ia_restore_device_state(dev_info_t *, usb_ia_t *);
static usb_ia_t  *usb_ia_obtain_state(dev_info_t *);
static void usb_ia_event_cb(dev_info_t *, ddi_eventcookie_t, void *, void *);

/* prototypes */
static void usb_ia_create_children(usb_ia_t *);
static int usb_ia_cleanup(usb_ia_t *);

/*
 * Busops vector
 */
static struct bus_ops usb_ia_busops = {
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
	usb_ia_bus_ctl,		/* bus_ctl */
	ddi_bus_prop_op,		/* bus_prop_op */
	usb_ia_busop_get_eventcookie,
	usb_ia_busop_add_eventcall,
	usb_ia_busop_remove_eventcall,
	usb_ia_busop_post_event,	/* bus_post_event */
	NULL,				/* bus_intr_ctl */
	usb_ia_bus_config,		/* bus_config */
	usb_ia_bus_unconfig,		/* bus_unconfig */
	NULL,				/* bus_fm_init */
	NULL,				/* bus_fm_fini */
	NULL,				/* bus_fm_access_enter */
	NULL,				/* bus_fm_access_exit */
	NULL				/* bus_power */
};


static struct dev_ops usb_ia_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	usb_ia_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	usb_ia_attach,		/* attach */
	usb_ia_detach,		/* detach */
	nodev,			/* reset */
	&usb_ia_cb_ops,	/* driver operations */
	&usb_ia_busops,	/* bus operations */
	usb_ia_power,		/* power */
	ddi_quiesce_not_needed,	/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module. This one is a driver */
	"USB Interface Association Driver", /* Name of the module. */
	&usb_ia_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

#define	USB_IA_INITIAL_SOFT_SPACE 4
static	void	*usb_ia_statep;

/*
 * event definition
 */
static ndi_event_definition_t usb_ia_ndi_event_defs[] = {
	{USBA_EVENT_TAG_HOT_REMOVAL, DDI_DEVI_REMOVE_EVENT, EPL_KERNEL,
						NDI_EVENT_POST_TO_ALL},
	{USBA_EVENT_TAG_HOT_INSERTION, DDI_DEVI_INSERT_EVENT, EPL_KERNEL,
						NDI_EVENT_POST_TO_ALL},
	{USBA_EVENT_TAG_POST_RESUME, USBA_POST_RESUME_EVENT, EPL_KERNEL,
						NDI_EVENT_POST_TO_ALL},
	{USBA_EVENT_TAG_PRE_SUSPEND, USBA_PRE_SUSPEND_EVENT, EPL_KERNEL,
						NDI_EVENT_POST_TO_ALL}
};

#define	USB_IA_N_NDI_EVENTS \
	(sizeof (usb_ia_ndi_event_defs) / sizeof (ndi_event_definition_t))

static	ndi_event_set_t usb_ia_ndi_events = {
	NDI_EVENTS_REV1, USB_IA_N_NDI_EVENTS, usb_ia_ndi_event_defs};


/*
 * standard driver entry points
 */
int
_init(void)
{
	int rval;

	rval = ddi_soft_state_init(&usb_ia_statep, sizeof (struct usb_ia),
	    USB_IA_INITIAL_SOFT_SPACE);
	if (rval != 0) {
		return (rval);
	}

	if ((rval = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&usb_ia_statep);
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

	ddi_soft_state_fini(&usb_ia_statep);

	return (rval);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*ARGSUSED*/
static int
usb_ia_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	usb_ia_t	*usb_ia;
	int		instance = getminor((dev_t)arg);
	int		error = DDI_FAILURE;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((usb_ia = ddi_get_soft_state(usb_ia_statep,
		    instance)) != NULL) {
			*result = (void *)usb_ia->ia_dip;
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
usb_ia_post_attach(usb_ia_t *usb_ia, uint8_t ifno, struct attachspec *as)
{
	USB_DPRINTF_L4(DPRINT_MASK_PM, usb_ia->ia_log_handle,
	    "usb_ia_post_attach: ifno = %d result = %d", ifno, as->result);

}


static void
usb_ia_post_detach(usb_ia_t *usb_ia, uint8_t ifno, struct detachspec *ds)
{
	USB_DPRINTF_L4(DPRINT_MASK_PM, usb_ia->ia_log_handle,
	    "usb_ia_post_detach: ifno = %d result = %d", ifno, ds->result);

}


/*
 * bus ctl support. we handle notifications here and the
 * rest goes up to root hub/hcd
 */
/*ARGSUSED*/
static int
usb_ia_bus_ctl(dev_info_t *dip,
	dev_info_t	*rdip,
	ddi_ctl_enum_t	op,
	void		*arg,
	void		*result)
{
	usba_device_t *hub_usba_device = usba_get_usba_device(rdip);
	dev_info_t *root_hub_dip = hub_usba_device->usb_root_hub_dip;
	usb_ia_t  *usb_ia;
	struct attachspec *as;
	struct detachspec *ds;

	usb_ia = usb_ia_obtain_state(dip);

	USB_DPRINTF_L4(DPRINT_MASK_PM, usb_ia->ia_log_handle,
	    "usb_ia_bus_ctl:\n\t"
	    "dip = 0x%p, rdip = 0x%p, op = 0x%x, arg = 0x%p",
	    (void *)dip, (void *)rdip, op, arg);

	switch (op) {
	case DDI_CTLOPS_ATTACH:
		as = (struct attachspec *)arg;

		switch (as->when) {
		case DDI_PRE :
			/* nothing to do basically */
			USB_DPRINTF_L2(DPRINT_MASK_PM, usb_ia->ia_log_handle,
			    "DDI_PRE DDI_CTLOPS_ATTACH");
			break;
		case DDI_POST :
			usb_ia_post_attach(usb_ia, usba_get_ifno(rdip),
			    (struct attachspec *)arg);
			break;
		}

		break;
	case DDI_CTLOPS_DETACH:
		ds = (struct detachspec *)arg;

		switch (ds->when) {
		case DDI_PRE :
			/* nothing to do basically */
			USB_DPRINTF_L2(DPRINT_MASK_PM, usb_ia->ia_log_handle,
			    "DDI_PRE DDI_CTLOPS_DETACH");
			break;
		case DDI_POST :
			usb_ia_post_detach(usb_ia, usba_get_ifno(rdip),
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
usb_ia_bus_config(dev_info_t *dip, uint_t flag, ddi_bus_config_op_t op,
    void *arg, dev_info_t **child)
{
	int		rval;
	usb_ia_t	*usb_ia = usb_ia_obtain_state(dip);

	USB_DPRINTF_L4(DPRINT_MASK_ALL, usb_ia->ia_log_handle,
	    "usb_ia_bus_config: op=%d", op);

	if (usb_ia_bus_config_debug) {
		flag |= NDI_DEVI_DEBUG;
	}

	ndi_devi_enter(dip);

	/* enumerate each interface below us */
	mutex_enter(&usb_ia->ia_mutex);
	usb_ia_create_children(usb_ia);
	mutex_exit(&usb_ia->ia_mutex);

	rval = ndi_busop_bus_config(dip, flag, op, arg, child, 0);
	ndi_devi_exit(dip);

	return (rval);
}


static int
usb_ia_bus_unconfig(dev_info_t *dip, uint_t flag, ddi_bus_config_op_t op,
    void *arg)
{
	usb_ia_t  *usb_ia = usb_ia_obtain_state(dip);

	dev_info_t	*cdip, *mdip;
	int		interface;
	int		rval = NDI_SUCCESS;

	USB_DPRINTF_L4(DPRINT_MASK_ALL, usb_ia->ia_log_handle,
	    "usb_ia_bus_unconfig: op=%d", op);

	if (usb_ia_bus_config_debug) {
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
	mutex_enter(&usb_ia->ia_mutex);
	for (interface = 0; usb_ia->ia_children_dips &&
	    (interface < usb_ia->ia_n_ifs); interface++) {
		mdip = usb_ia->ia_children_dips[interface];

		/* now search if this dip still exists */
		for (cdip = ddi_get_child(dip); cdip && (cdip != mdip); )
			cdip = ddi_get_next_sibling(cdip);

		if (cdip != mdip) {
			/* we lost the dip on this interface */
			usb_ia->ia_children_dips[interface] = NULL;
		} else if (cdip) {
			/*
			 * keep in DS_INITALIZED to prevent parent
			 * from detaching
			 */
			(void) ddi_initchild(ddi_get_parent(cdip), cdip);
		}
	}
	mutex_exit(&usb_ia->ia_mutex);

	ndi_devi_exit(dip);

	USB_DPRINTF_L4(DPRINT_MASK_ALL, usb_ia->ia_log_handle,
	    "usb_ia_bus_config: rval=%d", rval);

	return (rval);
}


/* power entry point */
/* ARGSUSED */
static int
usb_ia_power(dev_info_t *dip, int comp, int level)
{
	usb_ia_t		*usb_ia;
	usb_common_power_t	*pm;
	int			rval = DDI_FAILURE;

	usb_ia = usb_ia_obtain_state(dip);

	USB_DPRINTF_L4(DPRINT_MASK_PM, usb_ia->ia_log_handle,
	    "usb_ia_power: Begin: usb_ia = %p, level = %d",
	    (void *)usb_ia, level);

	mutex_enter(&usb_ia->ia_mutex);
	pm = usb_ia->ia_pm;

	/* check if we are transitioning to a legal power level */
	if (USB_DEV_PWRSTATE_OK(pm->uc_pwr_states, level)) {
		USB_DPRINTF_L2(DPRINT_MASK_PM, usb_ia->ia_log_handle,
		    "usb_ia_power: illegal power level = %d "
		    "uc_pwr_states = %x", level, pm->uc_pwr_states);

		mutex_exit(&usb_ia->ia_mutex);

		return (rval);
	}

	rval = usba_common_power(dip, &(pm->uc_current_power),
	    &(usb_ia->ia_dev_state), level);

	mutex_exit(&usb_ia->ia_mutex);

	return (rval);
}

/*
 * attach/resume entry point
 */
static int
usb_ia_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		instance = ddi_get_instance(dip);
	usb_ia_t	*usb_ia = NULL;
	uint_t		n_ifs;
	size_t		size;

	switch (cmd) {
	case DDI_ATTACH:

		break;
	case DDI_RESUME:
		usb_ia = ddi_get_soft_state(usb_ia_statep, instance);
		(void) usb_ia_restore_device_state(dip, usb_ia);

		return (DDI_SUCCESS);
	default:

		return (DDI_FAILURE);
	}

	/*
	 * Attach:
	 *
	 * Allocate soft state and initialize
	 */
	if (ddi_soft_state_zalloc(usb_ia_statep, instance) != DDI_SUCCESS) {
		goto fail;
	}

	usb_ia = ddi_get_soft_state(usb_ia_statep, instance);
	if (usb_ia == NULL) {

		goto fail;
	}

	/* allocate handle for logging of messages */
	usb_ia->ia_log_handle = usb_alloc_log_hdl(dip, "ia",
	    &usb_ia_errlevel,
	    &usb_ia_errmask, &usb_ia_instance_debug,
	    0);

	usb_ia->ia_dip	= dip;
	usb_ia->ia_instance = instance;
	usb_ia->ia_first_if = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "interface", -1);
	usb_ia->ia_n_ifs = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "interface-count", -1);

	if (usb_ia->ia_first_if < 0 || usb_ia->ia_n_ifs < 0) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, usb_ia->ia_log_handle,
		    "interface-association property failed");

		goto fail;
	}

	/* attach client driver to USBA */
	if (usb_client_attach(dip, USBDRV_VERSION, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, usb_ia->ia_log_handle,
		    "usb_client_attach failed");
		goto fail;
	}
	if (usb_get_dev_data(dip, &usb_ia->ia_dev_data, USB_PARSE_LVL_NONE,
	    0) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, usb_ia->ia_log_handle,
		    "usb_get_dev_data failed");
		goto fail;
	}

	mutex_init(&usb_ia->ia_mutex, NULL, MUTEX_DRIVER,
	    usb_ia->ia_dev_data->dev_iblock_cookie);

	usb_free_dev_data(dip, usb_ia->ia_dev_data);
	usb_ia->ia_dev_data = NULL;

	usb_ia->ia_init_state |= USB_IA_LOCK_INIT;

	if (ddi_create_minor_node(dip, "usb_ia", S_IFCHR, instance,
	    DDI_NT_NEXUS, 0) != DDI_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, usb_ia->ia_log_handle,
		    "cannot create devctl minor node");
		goto fail;
	}

	usb_ia->ia_init_state |= USB_IA_MINOR_NODE_CREATED;

	/*
	 * allocate array for keeping track of child dips
	 */
	n_ifs = usb_ia->ia_n_ifs;
	usb_ia->ia_cd_list_length = size = (sizeof (dev_info_t *)) * n_ifs;

	usb_ia->ia_children_dips = kmem_zalloc(size, KM_SLEEP);
	usb_ia->ia_child_events = kmem_zalloc(sizeof (uint8_t) * n_ifs,
	    KM_SLEEP);
	/*
	 * Event handling: definition and registration
	 * get event handle for events that we have defined
	 */
	(void) ndi_event_alloc_hdl(dip, 0, &usb_ia->ia_ndi_event_hdl,
	    NDI_SLEEP);

	/* bind event set to the handle */
	if (ndi_event_bind_set(usb_ia->ia_ndi_event_hdl, &usb_ia_ndi_events,
	    NDI_SLEEP)) {
		USB_DPRINTF_L2(DPRINT_MASK_ATTA, usb_ia->ia_log_handle,
		    "usb_ia_attach: binding event set failed");

		goto fail;
	}

	usb_ia->ia_dev_state = USB_DEV_ONLINE;

	/*
	 * now create components to power manage this device
	 * before attaching children
	 */
	usb_ia_create_pm_components(dip, usb_ia);

	/* event registration for events from our parent */
	usba_common_register_events(dip, n_ifs, usb_ia_event_cb);

	usb_ia->ia_init_state |= USB_IA_EVENTS_REGISTERED;

	ddi_report_dev(dip);

	return (DDI_SUCCESS);

fail:
	USB_DPRINTF_L2(DPRINT_MASK_ATTA, NULL, "usb_ia%d cannot attach",
	    instance);

	if (usb_ia) {
		(void) usb_ia_cleanup(usb_ia);
	}

	return (DDI_FAILURE);
}


/* detach or suspend this instance */
static int
usb_ia_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	usb_ia_t	*usb_ia = usb_ia_obtain_state(dip);

	USB_DPRINTF_L4(DPRINT_MASK_ATTA, usb_ia->ia_log_handle,
	    "usb_ia_detach: cmd = 0x%x", cmd);

	switch (cmd) {
	case DDI_DETACH:

		return (usb_ia_cleanup(usb_ia));
	case DDI_SUSPEND:
		/* nothing to do */
		mutex_enter(&usb_ia->ia_mutex);
		usb_ia->ia_dev_state = USB_DEV_SUSPENDED;
		mutex_exit(&usb_ia->ia_mutex);

		return (DDI_SUCCESS);
	default:

		return (DDI_FAILURE);
	}

	_NOTE(NOT_REACHED)
	/* NOTREACHED */
}


/*
 * usb_ia_cleanup:
 *	cleanup usb_ia and deallocate. this function is called for
 *	handling attach failures and detaching including dynamic
 *	reconfiguration
 */
/*ARGSUSED*/
static int
usb_ia_cleanup(usb_ia_t *usb_ia)
{
	usb_common_power_t	*iapm;
	int			rval;
	dev_info_t	*dip = usb_ia->ia_dip;

	USB_DPRINTF_L4(DPRINT_MASK_ATTA, usb_ia->ia_log_handle,
	    "usb_ia_cleanup:");

	if ((usb_ia->ia_init_state & USB_IA_LOCK_INIT) == 0) {

		goto done;
	}

	/*
	 * deallocate events, if events are still registered
	 * (ie. children still attached) then we have to fail the detach
	 */
	if (usb_ia->ia_ndi_event_hdl &&
	    (ndi_event_free_hdl(usb_ia->ia_ndi_event_hdl) != NDI_SUCCESS)) {

		USB_DPRINTF_L2(DPRINT_MASK_ATTA, usb_ia->ia_log_handle,
		    "usb_ia_cleanup: ndi_event_free_hdl failed");

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
	if (usb_ia->ia_init_state & USB_IA_EVENTS_REGISTERED) {

		usba_common_unregister_events(usb_ia->ia_dip, usb_ia->ia_n_ifs);
	}

	iapm = usb_ia->ia_pm;

	mutex_enter(&usb_ia->ia_mutex);

	if ((iapm) && (usb_ia->ia_dev_state != USB_DEV_DISCONNECTED)) {

		mutex_exit(&usb_ia->ia_mutex);

		(void) pm_busy_component(dip, 0);
		if (iapm->uc_wakeup_enabled) {

			/* First bring the device to full power */
			(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);

			rval = usb_handle_remote_wakeup(dip,
			    USB_REMOTE_WAKEUP_DISABLE);

			if (rval != DDI_SUCCESS) {
				USB_DPRINTF_L2(DPRINT_MASK_EVENTS,
				    usb_ia->ia_log_handle,
				    "usb_cleanup: disable remote "
				    "wakeup failed, rval=%d", rval);
			}
		}

		(void) pm_lower_power(usb_ia->ia_dip, 0, USB_DEV_OS_PWR_OFF);
		(void) pm_idle_component(dip, 0);
	} else {
		mutex_exit(&usb_ia->ia_mutex);
	}

	if (iapm) {
		kmem_free(iapm, sizeof (usb_common_power_t));
	}

	/* free children list */
	if (usb_ia->ia_children_dips) {
		kmem_free(usb_ia->ia_children_dips,
		    usb_ia->ia_cd_list_length);
	}

	if (usb_ia->ia_child_events) {
		kmem_free(usb_ia->ia_child_events, sizeof (uint8_t) *
		    usb_ia->ia_n_ifs);
	}

	if (usb_ia->ia_init_state & USB_IA_MINOR_NODE_CREATED) {
		ddi_remove_minor_node(dip, NULL);
	}

	mutex_destroy(&usb_ia->ia_mutex);

done:
	usb_client_detach(dip, usb_ia->ia_dev_data);

	usb_free_log_hdl(usb_ia->ia_log_handle);
	ddi_soft_state_free(usb_ia_statep, ddi_get_instance(dip));

	ddi_prop_remove_all(dip);

	return (DDI_SUCCESS);
}

/*
 * usb_ia_create_children:
 */
static void
usb_ia_create_children(usb_ia_t *usb_ia)
{
	usba_device_t		*usba_device;
	uint_t			n_ifs, first_if;
	uint_t			i;
	dev_info_t		*cdip;

	usba_device = usba_get_usba_device(usb_ia->ia_dip);

	USB_DPRINTF_L4(DPRINT_MASK_ATTA, usb_ia->ia_log_handle,
	    "usb_ia_attach_child_drivers: port = %d, address = %d",
	    usba_device->usb_port, usba_device->usb_addr);

	n_ifs = usb_ia->ia_n_ifs;
	first_if = usb_ia->ia_first_if;

	/*
	 * create all children if not already present
	 */
	for (i = 0; i < n_ifs; i++) {
		if (usb_ia->ia_children_dips[i] != NULL) {

			continue;
		}

		mutex_exit(&usb_ia->ia_mutex);
		cdip = usba_ready_interface_node(usb_ia->ia_dip, first_if + i);
		mutex_enter(&usb_ia->ia_mutex);

		if (cdip != NULL) {
			(void) usba_bind_driver(cdip);
			usb_ia->ia_children_dips[i] = cdip;
		}
	}

}


/*
 * event support
 */
static int
usb_ia_busop_get_eventcookie(dev_info_t *dip,
	dev_info_t *rdip, char *eventname, ddi_eventcookie_t *cookie)
{
	usb_ia_t  *usb_ia = usb_ia_obtain_state(dip);

	USB_DPRINTF_L4(DPRINT_MASK_EVENTS, usb_ia->ia_log_handle,
	    "usb_ia_busop_get_eventcookie: dip=0x%p, rdip=0x%p, "
	    "event=%s", (void *)dip, (void *)rdip, eventname);
	USB_DPRINTF_L3(DPRINT_MASK_EVENTS, usb_ia->ia_log_handle,
	    "(dip=%s%d rdip=%s%d)",
	    ddi_driver_name(dip), ddi_get_instance(dip),
	    ddi_driver_name(rdip), ddi_get_instance(rdip));

	/* return event cookie, iblock cookie, and level */
	return (ndi_event_retrieve_cookie(usb_ia->ia_ndi_event_hdl,
	    rdip, eventname, cookie, NDI_EVENT_NOPASS));
}


static int
usb_ia_busop_add_eventcall(dev_info_t *dip,
	dev_info_t *rdip,
	ddi_eventcookie_t cookie,
	void (*callback)(dev_info_t *dip,
	    ddi_eventcookie_t cookie, void *arg,
	    void *bus_impldata),
	void *arg, ddi_callback_id_t *cb_id)
{
	int	ifno;
	usb_ia_t  *usb_ia = usb_ia_obtain_state(dip);

	mutex_enter(&usb_ia->ia_mutex);
	ifno = usba_get_ifno(rdip)- usb_ia->ia_first_if;
	mutex_exit(&usb_ia->ia_mutex);

	if (ifno < 0) {
		ifno = 0;
	}

	USB_DPRINTF_L4(DPRINT_MASK_EVENTS, usb_ia->ia_log_handle,
	    "usb_ia_busop_add_eventcall: dip=0x%p, rdip=0x%p "
	    "cookie=0x%p, cb=0x%p, arg=0x%p",
	    (void *)dip, (void *)rdip, (void *)cookie, (void *)callback, arg);
	USB_DPRINTF_L3(DPRINT_MASK_EVENTS, usb_ia->ia_log_handle,
	    "(dip=%s%d rdip=%s%d event=%s)",
	    ddi_driver_name(dip), ddi_get_instance(dip),
	    ddi_driver_name(rdip), ddi_get_instance(rdip),
	    ndi_event_cookie_to_name(usb_ia->ia_ndi_event_hdl, cookie));

	/* Set flag on children registering events */
	switch (ndi_event_cookie_to_tag(usb_ia->ia_ndi_event_hdl, cookie)) {
	case USBA_EVENT_TAG_HOT_REMOVAL:
		mutex_enter(&usb_ia->ia_mutex);
		usb_ia->ia_child_events[ifno] |=
		    USB_IA_CHILD_EVENT_DISCONNECT;
		mutex_exit(&usb_ia->ia_mutex);

		break;
	case USBA_EVENT_TAG_PRE_SUSPEND:
		mutex_enter(&usb_ia->ia_mutex);
		usb_ia->ia_child_events[ifno] |=
		    USB_IA_CHILD_EVENT_PRESUSPEND;
		mutex_exit(&usb_ia->ia_mutex);

		break;
	default:

		break;
	}
	/* add callback (perform registration) */
	return (ndi_event_add_callback(usb_ia->ia_ndi_event_hdl,
	    rdip, cookie, callback, arg, NDI_SLEEP, cb_id));
}


static int
usb_ia_busop_remove_eventcall(dev_info_t *dip, ddi_callback_id_t cb_id)
{
	usb_ia_t  *usb_ia = usb_ia_obtain_state(dip);
	ndi_event_callbacks_t *cb = (ndi_event_callbacks_t *)cb_id;

	ASSERT(cb);

	USB_DPRINTF_L4(DPRINT_MASK_EVENTS, usb_ia->ia_log_handle,
	    "usb_ia_busop_remove_eventcall: dip=0x%p, rdip=0x%p "
	    "cookie=0x%p", (void *)dip, (void *)cb->ndi_evtcb_dip,
	    (void *)cb->ndi_evtcb_cookie);
	USB_DPRINTF_L3(DPRINT_MASK_EVENTS, usb_ia->ia_log_handle,
	    "(dip=%s%d rdip=%s%d event=%s)",
	    ddi_driver_name(dip), ddi_get_instance(dip),
	    ddi_driver_name(cb->ndi_evtcb_dip),
	    ddi_get_instance(cb->ndi_evtcb_dip),
	    ndi_event_cookie_to_name(usb_ia->ia_ndi_event_hdl,
	    cb->ndi_evtcb_cookie));

	/* remove event registration from our event set */
	return (ndi_event_remove_callback(usb_ia->ia_ndi_event_hdl, cb_id));
}


static int
usb_ia_busop_post_event(dev_info_t *dip,
	dev_info_t *rdip,
	ddi_eventcookie_t cookie,
	void *bus_impldata)
{
	usb_ia_t  *usb_ia = usb_ia_obtain_state(dip);

	USB_DPRINTF_L4(DPRINT_MASK_EVENTS, usb_ia->ia_log_handle,
	    "usb_ia_busop_post_event: dip=0x%p, rdip=0x%p "
	    "cookie=0x%p, impl=0x%p",
	    (void *)dip, (void *)rdip, (void *)cookie, bus_impldata);
	USB_DPRINTF_L3(DPRINT_MASK_EVENTS, usb_ia->ia_log_handle,
	    "(dip=%s%d rdip=%s%d event=%s)",
	    ddi_driver_name(dip), ddi_get_instance(dip),
	    ddi_driver_name(rdip), ddi_get_instance(rdip),
	    ndi_event_cookie_to_name(usb_ia->ia_ndi_event_hdl, cookie));

	/* post event to all children registered for this event */
	return (ndi_event_run_callbacks(usb_ia->ia_ndi_event_hdl, rdip,
	    cookie, bus_impldata));
}


/*
 * usb_ia_restore_device_state
 *	set the original configuration of the device
 */
static int
usb_ia_restore_device_state(dev_info_t *dip, usb_ia_t *usb_ia)
{
	usb_common_power_t	*iapm;

	USB_DPRINTF_L4(DPRINT_MASK_EVENTS, usb_ia->ia_log_handle,
	    "usb_ia_restore_device_state: usb_ia = %p", (void *)usb_ia);

	mutex_enter(&usb_ia->ia_mutex);
	iapm = usb_ia->ia_pm;
	mutex_exit(&usb_ia->ia_mutex);

	/* First bring the device to full power */
	(void) pm_busy_component(dip, 0);
	(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);

	if (usb_check_same_device(dip, usb_ia->ia_log_handle, USB_LOG_L0,
	    DPRINT_MASK_EVENTS, USB_CHK_VIDPID, NULL) != USB_SUCCESS) {

		/* change the device state from suspended to disconnected */
		mutex_enter(&usb_ia->ia_mutex);
		usb_ia->ia_dev_state = USB_DEV_DISCONNECTED;
		mutex_exit(&usb_ia->ia_mutex);
		(void) pm_idle_component(dip, 0);

		return (USB_FAILURE);
	}

	/*
	 * if the device had remote wakeup earlier,
	 * enable it again
	 */
	if (iapm->uc_wakeup_enabled) {
		(void) usb_handle_remote_wakeup(usb_ia->ia_dip,
		    USB_REMOTE_WAKEUP_ENABLE);
	}

	mutex_enter(&usb_ia->ia_mutex);
	usb_ia->ia_dev_state = USB_DEV_ONLINE;
	mutex_exit(&usb_ia->ia_mutex);

	(void) pm_idle_component(dip, 0);

	return (USB_SUCCESS);
}


/*
 * usb_ia_event_cb()
 *	handle disconnect and connect events
 */
static void
usb_ia_event_cb(dev_info_t *dip, ddi_eventcookie_t cookie,
	void *arg, void *bus_impldata)
{
	int		i, tag;
	usb_ia_t	*usb_ia = usb_ia_obtain_state(dip);
	dev_info_t	*child_dip;
	ddi_eventcookie_t rm_cookie, ins_cookie, suspend_cookie, resume_cookie;

	USB_DPRINTF_L4(DPRINT_MASK_EVENTS, usb_ia->ia_log_handle,
	    "usb_ia_event_cb: dip=0x%p, cookie=0x%p, "
	    "arg=0x%p, impl=0x%p",
	    (void *)dip, (void *)cookie, arg, bus_impldata);
	USB_DPRINTF_L4(DPRINT_MASK_EVENTS, usb_ia->ia_log_handle,
	    "(dip=%s%d event=%s)",
	    ddi_driver_name(dip), ddi_get_instance(dip),
	    ndi_event_cookie_to_name(usb_ia->ia_ndi_event_hdl, cookie));

	tag = NDI_EVENT_TAG(cookie);
	rm_cookie = ndi_event_tag_to_cookie(
	    usb_ia->ia_ndi_event_hdl, USBA_EVENT_TAG_HOT_REMOVAL);
	suspend_cookie = ndi_event_tag_to_cookie(
	    usb_ia->ia_ndi_event_hdl, USBA_EVENT_TAG_PRE_SUSPEND);
	ins_cookie = ndi_event_tag_to_cookie(
	    usb_ia->ia_ndi_event_hdl, USBA_EVENT_TAG_HOT_INSERTION);
	resume_cookie = ndi_event_tag_to_cookie(
	    usb_ia->ia_ndi_event_hdl, USBA_EVENT_TAG_POST_RESUME);

	mutex_enter(&usb_ia->ia_mutex);
	switch (tag) {
	case USBA_EVENT_TAG_HOT_REMOVAL:
		if (usb_ia->ia_dev_state == USB_DEV_DISCONNECTED) {
			USB_DPRINTF_L2(DPRINT_MASK_EVENTS,
			    usb_ia->ia_log_handle,
			    "usb_ia_event_cb: Device already disconnected");
		} else {
			/* we are disconnected so set our state now */
			usb_ia->ia_dev_state = USB_DEV_DISCONNECTED;
			for (i = 0; i < usb_ia->ia_n_ifs; i++) {
				usb_ia->ia_child_events[i] &= ~
				    USB_IA_CHILD_EVENT_DISCONNECT;
			}
			mutex_exit(&usb_ia->ia_mutex);

			/* pass disconnect event to all the children */
			(void) ndi_event_run_callbacks(
			    usb_ia->ia_ndi_event_hdl, NULL,
			    rm_cookie, bus_impldata);

			mutex_enter(&usb_ia->ia_mutex);
		}
		break;
	case USBA_EVENT_TAG_PRE_SUSPEND:
		/* set our state *after* suspending children */
		mutex_exit(&usb_ia->ia_mutex);

		/* pass pre_suspend event to all the children */
		(void) ndi_event_run_callbacks(usb_ia->ia_ndi_event_hdl,
		    NULL, suspend_cookie, bus_impldata);

		mutex_enter(&usb_ia->ia_mutex);
		for (i = 0; i < usb_ia->ia_n_ifs; i++) {
			usb_ia->ia_child_events[i] &= ~
			    USB_IA_CHILD_EVENT_PRESUSPEND;
		}
		break;
	case USBA_EVENT_TAG_HOT_INSERTION:
		mutex_exit(&usb_ia->ia_mutex);
		if (usb_ia_restore_device_state(dip, usb_ia) == USB_SUCCESS) {

			/*
			 * Check to see if this child has missed the disconnect
			 * event before it registered for event cb
			 */
			mutex_enter(&usb_ia->ia_mutex);
			for (i = 0; i < usb_ia->ia_n_ifs; i++) {
				if (usb_ia->ia_child_events[i] &
				    USB_IA_CHILD_EVENT_DISCONNECT) {
					usb_ia->ia_child_events[i] &=
					    ~USB_IA_CHILD_EVENT_DISCONNECT;
					child_dip =
					    usb_ia->ia_children_dips[i];
					mutex_exit(&usb_ia->ia_mutex);

					/* post the missed disconnect */
					(void) ndi_event_do_callback(
					    usb_ia->ia_ndi_event_hdl,
					    child_dip,
					    rm_cookie,
					    bus_impldata);
					mutex_enter(&usb_ia->ia_mutex);
				}
			}
			mutex_exit(&usb_ia->ia_mutex);

			/* pass reconnect event to all the children */
			(void) ndi_event_run_callbacks(
			    usb_ia->ia_ndi_event_hdl, NULL,
			    ins_cookie, bus_impldata);

		}
		mutex_enter(&usb_ia->ia_mutex);
		break;
	case USBA_EVENT_TAG_POST_RESUME:
		/*
		 * Check to see if this child has missed the pre-suspend
		 * event before it registered for event cb
		 */
		for (i = 0; i < usb_ia->ia_n_ifs; i++) {
			if (usb_ia->ia_child_events[i] &
			    USB_IA_CHILD_EVENT_PRESUSPEND) {
				usb_ia->ia_child_events[i] &=
				    ~USB_IA_CHILD_EVENT_PRESUSPEND;
				child_dip = usb_ia->ia_children_dips[i];
				mutex_exit(&usb_ia->ia_mutex);

				/* post the missed pre-suspend event */
				(void) ndi_event_do_callback(
				    usb_ia->ia_ndi_event_hdl,
				    child_dip, suspend_cookie,
				    bus_impldata);
				mutex_enter(&usb_ia->ia_mutex);
			}
		}
		mutex_exit(&usb_ia->ia_mutex);

		/* pass post_resume event to all the children */
		(void) ndi_event_run_callbacks(usb_ia->ia_ndi_event_hdl,
		    NULL, resume_cookie, bus_impldata);

		mutex_enter(&usb_ia->ia_mutex);
		break;
	}
	mutex_exit(&usb_ia->ia_mutex);

}

/*
 * create the pm components required for power management
 */
static void
usb_ia_create_pm_components(dev_info_t *dip, usb_ia_t *usb_ia)
{
	usb_common_power_t	*iapm;
	uint_t			pwr_states;

	USB_DPRINTF_L4(DPRINT_MASK_PM, usb_ia->ia_log_handle,
	    "usb_ia_create_pm_components: Begin");

	/* Allocate the PM state structure */
	iapm = kmem_zalloc(sizeof (usb_common_power_t), KM_SLEEP);

	mutex_enter(&usb_ia->ia_mutex);
	usb_ia->ia_pm = iapm;
	iapm->uc_usb_statep = usb_ia;
	iapm->uc_pm_capabilities = 0; /* XXXX should this be 0?? */
	iapm->uc_current_power = USB_DEV_OS_FULL_PWR;
	mutex_exit(&usb_ia->ia_mutex);

	/*
	 * By not enabling parental notification, PM enforces
	 * "strict parental dependency" meaning, usb_ia won't
	 * power off until any of its children are in full power.
	 */

	/*
	 * there are 3 scenarios:
	 * 1. a well behaved device should have remote wakeup
	 * at interface and device level. If the interface
	 * wakes up, usb_ia will wake up
	 * 2. if the device doesn't have remote wake up and
	 * the interface has, PM will still work, ie.
	 * the interfaces wakes up and usb_ia wakes up
	 * 3. if neither the interface nor device has remote
	 * wakeup, the interface will wake up when it is opened
	 * and goes to sleep after being closed for a while
	 * In this case usb_ia should also go to sleep shortly
	 * thereafter
	 * In all scenarios it doesn't really matter whether
	 * remote wakeup at the device level is enabled or not
	 * but we do it anyways
	 */
	if (usb_handle_remote_wakeup(dip, USB_REMOTE_WAKEUP_ENABLE) ==
	    USB_SUCCESS) {
		USB_DPRINTF_L3(DPRINT_MASK_PM, usb_ia->ia_log_handle,
		    "usb_ia_create_pm_components: "
		    "Remote Wakeup Enabled");
		iapm->uc_wakeup_enabled = 1;
	}

	if (usb_create_pm_components(dip, &pwr_states) ==
	    USB_SUCCESS) {
		iapm->uc_pwr_states = (uint8_t)pwr_states;
		(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);
	}

	USB_DPRINTF_L4(DPRINT_MASK_PM, usb_ia->ia_log_handle,
	    "usb_ia_create_pm_components: End");
}


/*
 * usb_ia_obtain_state:
 */
static usb_ia_t *
usb_ia_obtain_state(dev_info_t *dip)
{
	int instance = ddi_get_instance(dip);
	usb_ia_t *statep = ddi_get_soft_state(usb_ia_statep, instance);

	ASSERT(statep != NULL);

	return (statep);
}

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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * pseudo bus nexus driver
 * hotplug framework test facility
 */

/*
 * The pshot driver can be used to exercise the i/o framework together
 * with devfs by configuring an arbitrarily complex device tree.
 *
 * The pshot driver is rooted at /devices/pshot.  The following commands
 * illustrate the operation of devfs together with pshot's bus_config.
 * The first command demonstrates that, like the magician showing there's
 * nothing up their sleeve, /devices/pshot is empty.  The second command
 * conjures up a branch of pshot nodes.  Note that pshot's bus_config is
 * called sequentially by devfs for each node, as part of the pathname
 * resolution, and that each pshot node is fully configured and
 * attached before that node's bus_config is called to configure the
 * next child down the tree.  The final result is a "disk" node configured
 * at the bottom of the named hierarchy of pshot nodes.
 *
 *	#
 *	# ls /devices/pshot
 *	#
 *	# ls -ld /devices/pshot/pshot@0/pshot@1/pshot@2/disk@3,0
 *	drwxr-xr-x   2 root     sys          512 Feb  6 15:10
 *		/devices/pshot/pshot@0/pshot@1/pshot@2/disk@3,0
 *
 * pshot supports some unique behaviors as aids for test error cases.
 *
 * Match these special address formats to behavior:
 *
 *	err.*		- induce bus_config error
 *	delay		- induce 1 second of bus_config delay time
 *	delay,n		- induce n seconds of bus_config delay time
 *	wait		- induce 1 second of bus_config wait time
 *	wait,n		- induce n seconds of bus_config wait time
 *	failinit.*	- induce error at INITCHILD
 *	failprobe.*	- induce error at probe
 *	failattach.*	- induce error at attach
 */

#if defined(lint) && !defined(DEBUG)
#define	DEBUG	1
#endif

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/ddi_impldefs.h>
#include <sys/autoconf.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/modctl.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/devctl.h>
#include <sys/disp.h>
#include <sys/utsname.h>
#include <sys/pshot.h>
#include <sys/debug.h>

static int pshot_log		= 0;
static int pshot_devctl_debug	= 0;
static int pshot_debug_busy	= 0;

static void *pshot_softstatep;

static int pshot_prop_autoattach;

#define	MAXPWR	3


/*
 * device configuration data
 */

/* should keep in sync with current release */
static struct {
	char *name;
	char *val;
} pshot_nodetypes[] = {
	{"DDI_NT_SERIAL", DDI_NT_SERIAL},
	{"DDI_NT_SERIAL_MB", DDI_NT_SERIAL_MB},
	{"DDI_NT_SERIAL_DO", DDI_NT_SERIAL_DO},
	{"DDI_NT_SERIAL_MB_DO", DDI_NT_SERIAL_MB_DO},
	{"DDI_NT_SERIAL_LOMCON", DDI_NT_SERIAL_LOMCON},
	{"DDI_NT_BLOCK", DDI_NT_BLOCK},
	{"DDI_NT_BLOCK_CHAN", DDI_NT_BLOCK_CHAN},
	{"DDI_NT_BLOCK_WWN", DDI_NT_BLOCK_WWN},
	{"DDI_NT_BLOCK_SAS", DDI_NT_BLOCK_SAS},
	{"DDI_NT_CD", DDI_NT_CD},
	{"DDI_NT_CD_CHAN", DDI_NT_CD_CHAN},
	{"DDI_NT_FD", DDI_NT_FD},
	{"DDI_NT_ENCLOSURE", DDI_NT_ENCLOSURE},
	{"DDI_NT_SCSI_ENCLOSURE", DDI_NT_SCSI_ENCLOSURE},
	{"DDI_NT_TAPE", DDI_NT_TAPE},
	{"DDI_NT_NET", DDI_NT_NET},
	{"DDI_NT_DISPLAY", DDI_NT_DISPLAY},
	{"DDI_PSEUDO", DDI_PSEUDO},
	{"DDI_NT_AUDIO", DDI_NT_AUDIO},
	{"DDI_NT_MOUSE", DDI_NT_MOUSE},
	{"DDI_NT_KEYBOARD", DDI_NT_KEYBOARD},
	{"DDI_NT_PARALLEL", DDI_NT_PARALLEL},
	{"DDI_NT_PRINTER", DDI_NT_PRINTER},
	{"DDI_NT_UGEN", DDI_NT_UGEN},
	{"DDI_NT_NEXUS", DDI_NT_NEXUS},
	{"DDI_NT_SCSI_NEXUS", DDI_NT_SCSI_NEXUS},
	{"DDI_NT_ATTACHMENT_POINT", DDI_NT_ATTACHMENT_POINT},
	{"DDI_NT_SCSI_ATTACHMENT_POINT", DDI_NT_SCSI_ATTACHMENT_POINT},
	{"DDI_NT_PCI_ATTACHMENT_POINT", DDI_NT_PCI_ATTACHMENT_POINT},
	{"DDI_NT_SBD_ATTACHMENT_POINT", DDI_NT_SBD_ATTACHMENT_POINT},
	{"DDI_NT_FC_ATTACHMENT_POINT", DDI_NT_FC_ATTACHMENT_POINT},
	{"DDI_NT_USB_ATTACHMENT_POINT", DDI_NT_USB_ATTACHMENT_POINT},
	{"DDI_NT_BLOCK_FABRIC", DDI_NT_BLOCK_FABRIC},
	{"DDI_NT_AV_ASYNC", DDI_NT_AV_ASYNC},
	{"DDI_NT_AV_ISOCH", DDI_NT_AV_ISOCH},
	{ NULL, NULL }
};

/* Node name */
static char *pshot_compat_diskname = "cdisk";

/* Compatible names... */
static char *pshot_compat_psramdisks[] = {
	"psramhead",
	"psramrom",
	"psramdisk",
	"psramd",
	"psramwhat"
};

/*
 * devices "natively" supported by pshot (i.e. included with SUNWiotu)
 * used to initialize pshot_devices with
 */
static pshot_device_t pshot_stock_devices[] = {
	{"disk",	DDI_NT_BLOCK,		"gen_drv"},
	{"disk_chan",	DDI_NT_BLOCK_CHAN,	"gen_drv"},
	{"disk_wwn",	DDI_NT_BLOCK_WWN,	"gen_drv"},
	{"disk_cdrom",	DDI_NT_CD,		"gen_drv"},
	{"disk_cdrom.chan", DDI_NT_CD_CHAN,	"gen_drv"},
/* Note: use bad_drv to force attach errors */
	{"disk_fd",	DDI_NT_FD,		"bad_drv"},
	{"tape",	DDI_NT_TAPE,		"gen_drv"},
	{"net",		DDI_NT_NET,		"gen_drv"},
	{"display",	DDI_NT_DISPLAY,		"gen_drv"},
	{"pseudo",	DDI_PSEUDO,		"gen_drv"},
	{"audio",	DDI_NT_AUDIO,		"gen_drv"},
	{"mouse",	DDI_NT_MOUSE,		"gen_drv"},
	{"keyboard",	DDI_NT_KEYBOARD,	"gen_drv"},
	{"nexus",	DDI_NT_NEXUS,		"pshot"}
};
#define	PSHOT_N_STOCK_DEVICES \
	(sizeof (pshot_stock_devices) / sizeof (pshot_device_t))

static pshot_device_t *pshot_devices = NULL;
static size_t pshot_devices_len = 0;

/* protects <pshot_devices>, <pshot_devices_len> */
static kmutex_t pshot_devices_lock;


/*
 * event testing
 */

static ndi_event_definition_t pshot_ndi_event_defs[] = {
{ PSHOT_EVENT_TAG_OFFLINE, PSHOT_EVENT_NAME_DEV_OFFLINE,
	EPL_INTERRUPT, NDI_EVENT_POST_TO_ALL },

{ PSHOT_EVENT_TAG_DEV_RESET, PSHOT_EVENT_NAME_DEV_RESET,
	EPL_INTERRUPT, NDI_EVENT_POST_TO_TGT },

{ PSHOT_EVENT_TAG_BUS_RESET, PSHOT_EVENT_NAME_BUS_RESET,
	EPL_INTERRUPT, NDI_EVENT_POST_TO_ALL },

{ PSHOT_EVENT_TAG_BUS_QUIESCE, PSHOT_EVENT_NAME_BUS_QUIESCE,
	EPL_INTERRUPT, NDI_EVENT_POST_TO_ALL },

{ PSHOT_EVENT_TAG_BUS_UNQUIESCE, PSHOT_EVENT_NAME_BUS_UNQUIESCE,
	EPL_INTERRUPT, NDI_EVENT_POST_TO_ALL },

{ PSHOT_EVENT_TAG_TEST_POST, PSHOT_EVENT_NAME_BUS_TEST_POST,
	EPL_INTERRUPT, NDI_EVENT_POST_TO_TGT }
};


#define	PSHOT_N_NDI_EVENTS \
	(sizeof (pshot_ndi_event_defs) / sizeof (ndi_event_definition_t))

#ifdef DEBUG

static ndi_event_definition_t pshot_test_events[] = {
{ 10, "test event 0", EPL_INTERRUPT, NDI_EVENT_POST_TO_ALL },
{ 11, "test event 1", EPL_KERNEL, NDI_EVENT_POST_TO_TGT },
{ 12, "test event 2", EPL_INTERRUPT, NDI_EVENT_POST_TO_TGT },
{ 13, "test event 3", EPL_INTERRUPT, NDI_EVENT_POST_TO_ALL },
{ 14, "test event 4", EPL_KERNEL, NDI_EVENT_POST_TO_ALL},
{ 15, "test event 5", EPL_INTERRUPT, NDI_EVENT_POST_TO_ALL },
{ 16, "test event 6", EPL_KERNEL, NDI_EVENT_POST_TO_ALL },
{ 17, "test event 7", EPL_INTERRUPT, NDI_EVENT_POST_TO_ALL }
};

static ndi_event_definition_t pshot_test_events_high[] = {
{ 20, "test event high 0", EPL_HIGHLEVEL, NDI_EVENT_POST_TO_ALL}
};

#define	PSHOT_N_TEST_EVENTS \
	(sizeof (pshot_test_events)/sizeof (ndi_event_definition_t))
#endif

struct register_events {
	char		*event_name;
	ddi_eventcookie_t event_cookie;
	void	(*event_callback)
			(dev_info_t *,
			ddi_eventcookie_t,
			void *arg,
			void *impldata);
	ddi_callback_id_t cb_id;
};

struct register_events pshot_register_events[] = {
{ PSHOT_EVENT_NAME_DEV_OFFLINE, 0, pshot_event_cb, 0 },
{ PSHOT_EVENT_NAME_DEV_RESET, 0, pshot_event_cb, 0 },
{ PSHOT_EVENT_NAME_BUS_RESET, 0, pshot_event_cb, 0 },
{ PSHOT_EVENT_NAME_BUS_QUIESCE, 0, pshot_event_cb, 0 },
{ PSHOT_EVENT_NAME_BUS_UNQUIESCE, 0, pshot_event_cb, 0 },
{ PSHOT_EVENT_NAME_BUS_TEST_POST, 0, pshot_event_cb, 0 }
};

#define	PSHOT_N_DDI_EVENTS \
	(sizeof (pshot_register_events) / sizeof (struct register_events))


#ifdef DEBUG

static struct register_events pshot_register_test[] = {
{ "test event 0", 0, pshot_event_cb_test, 0},
{ "test event 1", 0, pshot_event_cb_test, 0},
{ "test event 2", 0, pshot_event_cb_test, 0},
{ "test event 3", 0, pshot_event_cb_test, 0},
{ "test event 4", 0, pshot_event_cb_test, 0},
{ "test event 5", 0, pshot_event_cb_test, 0},
{ "test event 6", 0, pshot_event_cb_test, 0},
{ "test event 7", 0, pshot_event_cb_test, 0}
};


static struct register_events pshot_register_high_test[] = {
	{"test event high 0", 0, pshot_event_cb_test, 0}
};

#endif /* DEBUG */

static struct {
	int ioctl_int;
	char *ioctl_char;
} pshot_devctls[] = {
	{DEVCTL_DEVICE_GETSTATE, "DEVCTL_DEVICE_GETSTATE"},
	{DEVCTL_DEVICE_ONLINE, "DEVCTL_DEVICE_ONLINE"},
	{DEVCTL_DEVICE_OFFLINE, "DEVCTL_DEVICE_OFFLINE"},
	{DEVCTL_DEVICE_REMOVE, "DEVCTL_DEVICE_REMOVE"},
	{DEVCTL_BUS_GETSTATE, "DEVCTL_BUS_GETSTATE"},
	{DEVCTL_BUS_DEV_CREATE, "DEVCTL_BUS_DEV_CREATE"},
	{DEVCTL_BUS_RESET, "DEVCTL_BUS_RESET"},
	{DEVCTL_BUS_RESETALL, "DEVCTL_BUS_RESETALL"},
	{0, NULL}
};

static struct bus_ops pshot_bus_ops = {
	BUSO_REV,			/* busops_rev */
	nullbusmap,			/* bus_map */
	NULL,				/* bus_get_intrspec */
	NULL,				/* bus_add_interspec */
	NULL,				/* bus_remove_interspec */
	i_ddi_map_fault,		/* bus_map_fault */
	NULL,				/* bus_dma_map */
	ddi_dma_allochdl,		/* bus_dma_allochdl */
	ddi_dma_freehdl,		/* bus_dma_freehdl */
	ddi_dma_bindhdl,		/* bus_dma_bindhdl */
	ddi_dma_unbindhdl,		/* bus_dma_unbindhdl */
	ddi_dma_flush,			/* bus_dma_flush */
	ddi_dma_win,			/* bus_dma_win */
	ddi_dma_mctl,			/* bus_dma_ctl */
	pshot_ctl,			/* bus_ctl */
	ddi_bus_prop_op,		/* bus_prop_op */
	pshot_get_eventcookie,		/* bus_get_eventcookie */
	pshot_add_eventcall,		/* bus_add_eventcall */
	pshot_remove_eventcall,		/* bus_remove_event */
	pshot_post_event,		/* bus_post_event */
	NULL,				/* bus_intr_ctl */
	pshot_bus_config,		/* bus_config */
	pshot_bus_unconfig,		/* bus_unconfig */
	NULL,				/* bus_fm_init */
	NULL,				/* bus_fm_fini */
	NULL,				/* bus_fm_access_enter */
	NULL,				/* bus_fm_access_exit */
	pshot_bus_power,		/* bus_power */
	pshot_bus_introp		/* bus_intr_op */
};

static struct cb_ops pshot_cb_ops = {
	pshot_open,			/* open */
	pshot_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	pshot_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* flags */
	CB_REV,				/* cb_rev */
	nodev,				/* aread */
	nodev,				/* awrite */
};

static struct dev_ops pshot_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	pshot_info,		/* getinfo */
	nulldev,		/* identify */
	pshot_probe,		/* probe */
	pshot_attach,		/* attach */
	pshot_detach,		/* detach */
	nodev,			/* reset */
	&pshot_cb_ops,		/* driver operations */
	&pshot_bus_ops,		/* bus operations */
	pshot_power,		/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */

};


/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,
	"pshotnex",
	&pshot_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};


/*
 * pshot_devices is set up on the first attach and destroyed on fini
 *
 * therefore PSHOT_PROP_DEV* properties may be set just for the root device,
 * instead of being set globably, in pshot.conf by specifying the properties
 * on a single line in the form:
 *	name="pshot" parent="/" <dev props ..>
 * to unclutter a device tree snapshot.
 * this of course produces a long single line that may wrap around several
 * times on screen
 */

int
_init(void)
{
	int rv;

	rv = ddi_soft_state_init(&pshot_softstatep, sizeof (pshot_t), 0);

	if (rv != DDI_SUCCESS)
		return (rv);

	mutex_init(&pshot_devices_lock, NULL, MUTEX_DRIVER, NULL);
	pshot_devices = NULL;
	pshot_devices_len = 0;

	if ((rv = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&pshot_softstatep);
		mutex_destroy(&pshot_devices_lock);
	}
	return (rv);
}

int
_fini(void)
{
	int rv;

	if ((rv = mod_remove(&modlinkage)) != 0)
		return (rv);

	ddi_soft_state_fini(&pshot_softstatep);
	mutex_destroy(&pshot_devices_lock);
	if (pshot_devices)
		pshot_devices_free(pshot_devices, pshot_devices_len);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*ARGSUSED*/
static int
pshot_probe(dev_info_t *devi)
{
	int	instance = ddi_get_instance(devi);
	char	*bus_addr;

	/*
	 * Hook for tests to force probe fail
	 */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, devi, 0, "bus-addr",
	    &bus_addr) == DDI_PROP_SUCCESS) {
		if (strncmp(bus_addr, "failprobe", 9) == 0) {
			if (pshot_debug)
				cmn_err(CE_CONT, "pshot%d: "
				    "%s forced probe failure\n",
				    instance, bus_addr);
			ddi_prop_free(bus_addr);
			return (DDI_PROBE_FAILURE);
		}
		ddi_prop_free(bus_addr);
	}

	return (DDI_PROBE_SUCCESS);
}


/*ARGSUSED*/
static int
pshot_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int instance;
	minor_t minor;
	pshot_t *pshot;

	minor = getminor((dev_t)arg);
	instance = pshot_minor_decode_inst(minor);
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		pshot = ddi_get_soft_state(pshot_softstatep, instance);
		if (pshot == NULL) {
			cmn_err(CE_WARN, "pshot_info: get soft state failed "
			    "on minor %u, instance %d", minor, instance);
			return (DDI_FAILURE);
		}
		*result = (void *)pshot->dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		break;
	default:
		cmn_err(CE_WARN, "pshot_info: unrecognized cmd 0x%x on "
		    "minor %u, instance %d", infocmd, minor, instance);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


static int
pshot_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int instance = ddi_get_instance(devi);
	pshot_t *pshot;
	int rval, i;
	int prop_flags = DDI_PROP_DONTPASS | DDI_PROP_NOTPROM;
	char *bus_addr;
	char *pm_comp[] = {
		"NAME=bus",
		"0=B3",
		"1=B2",
		"2=B1",
		"3=B0"};
	char *pm_hw_state = {"needs-suspend-resume"};

	pshot_prop_autoattach = ddi_prop_get_int(DDI_DEV_T_ANY, devi,
	    prop_flags, "autoattach", 0);

	switch (cmd) {

	case DDI_ATTACH:
		if (pshot_debug)
			cmn_err(CE_CONT, "attach: %s%d/pshot%d\n",
			    ddi_get_name(ddi_get_parent(devi)),
			    ddi_get_instance(ddi_get_parent(devi)),
			    instance);

		/*
		 * Hook for tests to force attach fail
		 */
		if ((ddi_prop_lookup_string(DDI_DEV_T_ANY, devi, 0, "bus-addr",
		    &bus_addr) == DDI_PROP_SUCCESS) && bus_addr != NULL) {
			if (strncmp(bus_addr, "failattach", 10) == 0) {
				if (pshot_debug)
					cmn_err(CE_CONT, "pshot%d: "
					    "%s forced attach failure\n",
					    instance, bus_addr);
				ddi_prop_free(bus_addr);
				return (DDI_FAILURE);
			}
			ddi_prop_free(bus_addr);
		}

		/*
		 * minor nodes setup
		 */
		if (ddi_soft_state_zalloc(pshot_softstatep, instance) !=
		    DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
		pshot = ddi_get_soft_state(pshot_softstatep, instance);
		pshot->dip = devi;
		pshot->instance = instance;
		mutex_init(&pshot->lock, NULL, MUTEX_DRIVER, NULL);

		/* set each minor, then create on dip all together */

		i = PSHOT_NODENUM_DEVCTL;
		pshot->nodes[i].pshot = pshot;
		pshot->nodes[i].minor = pshot_minor_encode(instance, i);
		(void) strncpy(pshot->nodes[i].name, PSHOT_NODENAME_DEVCTL,
		    PSHOT_MAX_MINOR_NAMELEN);

		i = PSHOT_NODENUM_TESTCTL;
		pshot->nodes[i].pshot = pshot;
		pshot->nodes[i].minor = pshot_minor_encode(instance, i);
		(void) strncpy(pshot->nodes[i].name, PSHOT_NODENAME_TESTCTL,
		    PSHOT_MAX_MINOR_NAMELEN);

		/* this assumes contiguous a filling */
		for (i = 0; i <= PSHOT_MAX_NODENUM; i++) {
			if (ddi_create_minor_node(devi, pshot->nodes[i].name,
			    S_IFCHR, pshot->nodes[i].minor, DDI_NT_NEXUS, 0) !=
			    DDI_SUCCESS) {
				cmn_err(CE_WARN, "attach: cannot create "
				    "minor %s", pshot->nodes[i].name);
				goto FAIL_ATTACH;
			}
		}

		/*
		 * pshot_devices setup
		 */
		if (pshot_devices_setup(devi)) {
			cmn_err(CE_WARN, "attach: pshot devices setup "
			    "failed");
			goto FAIL_ATTACH;
		}

		/*
		 * events setup
		 */
		for (i = 0; i < PSHOT_N_DDI_EVENTS; i++) {
			rval =	ddi_get_eventcookie(devi,
			    pshot_register_events[i].event_name,
			    &pshot_register_events[i].event_cookie);

			if (pshot_debug)
				cmn_err(CE_CONT, "pshot%d: event=%s:"
				    "ddi_get_eventcookie rval=%d\n",
				    instance,
				    pshot_register_events[i].event_name, rval);

			if (rval == DDI_SUCCESS) {
				rval = ddi_add_event_handler(devi,
				    pshot_register_events[i].event_cookie,
				    pshot_register_events[i].event_callback,
				    (void *)pshot,
				    &pshot->callback_cache[i]);

				if (pshot_debug)
					cmn_err(CE_CONT, "pshot%d: event=%s: "
					    "ddi_add_event_handler rval=%d\n",
					    instance,
					    pshot_register_events[i].event_name,
					    rval);
			}
		}

#ifdef DEBUG
		if (pshot_event_test_enable) {
			pshot_event_test((void *)pshot);
			(void) timeout(pshot_event_test_post_one, (void *)pshot,
			    instance * drv_usectohz(60000000));
		}
#endif

		/*
		 * allocate an ndi event handle
		 */
		if (ndi_event_alloc_hdl(devi, NULL, &pshot->ndi_event_hdl,
		    NDI_SLEEP) != NDI_SUCCESS) {
			goto FAIL_ATTACH;
		}

		pshot->ndi_events.ndi_events_version = NDI_EVENTS_REV1;
		pshot->ndi_events.ndi_n_events = PSHOT_N_NDI_EVENTS;
		pshot->ndi_events.ndi_event_defs = pshot_ndi_event_defs;

		if (ndi_event_bind_set(pshot->ndi_event_hdl, &pshot->ndi_events,
		    NDI_SLEEP) != NDI_SUCCESS) {
			cmn_err(CE_CONT, "pshot%d bind set failed\n",
			    instance);
		}

		/*
		 * setup a test for nexus auto-attach iff we are
		 * a second level pshot node (parent == /SUNW,pshot)
		 * enable by setting "autoattach=1" in pshot.conf
		 */
		if ((PARENT_IS_PSHOT(devi)) && (pshot_prop_autoattach != 0) &&
		    (ddi_get_instance(ddi_get_parent(devi))) == 0)
			pshot_setup_autoattach(devi);

		/*
		 * initialize internal state to idle: busy = 0,
		 * power level = -1
		 */
		mutex_enter(&pshot->lock);
		pshot->busy = 0;
		pshot->busy_ioctl = 0;
		pshot->level = -1;
		pshot->state &= ~STRICT_PARENT;
		pshot->state |= PM_SUPPORTED;
		mutex_exit(&pshot->lock);

		/*
		 * Create the "pm-want-child-notification?" property
		 * for the root node /devices/pshot
		 */
		if (instance == 0) {
			if (pshot_debug) {
				cmn_err(CE_CONT, "pshot%d: DDI_ATTACH:\n\t"
				    " create the"
				    " \"pm-want-child-notification?\" property"
				    " for the root node\n", instance);
			}
			if (ddi_prop_create(DDI_DEV_T_NONE, devi, 0,
			    "pm-want-child-notification?", NULL, 0)
			    != DDI_PROP_SUCCESS) {
				cmn_err(CE_WARN, "%s%d:\n\t"
				    " unable to create the"
				    " \"pm-want-child-notification?\""
				    " property", ddi_get_name(devi),
				    ddi_get_instance(devi));

				goto FAIL_ATTACH;
			}
		}

		/*
		 * Check if the pm-want-child-notification? property was
		 * created in pshot_bus_config_setup_nexus() by the parent.
		 * Set the STRICT_PARENT flag if not.
		 */
		if (ddi_prop_exists(DDI_DEV_T_ANY, devi,
		    (DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
		    "pm-want-child-notification?") != 1) {
			if (pshot_debug) {
				cmn_err(CE_CONT, "pshot%d: DDI_ATTACH:"
				    " STRICT PARENT\n", instance);
			}
			mutex_enter(&pshot->lock);
			pshot->state |= STRICT_PARENT;
			mutex_exit(&pshot->lock);
		} else {
			if (pshot_debug) {
				cmn_err(CE_CONT, "pshot%d: DDI_ATTACH:"
				    " INVOLVED PARENT\n", instance);
			}
			mutex_enter(&pshot->lock);
			pshot->state &= ~STRICT_PARENT;
			mutex_exit(&pshot->lock);
		}

		/*
		 * create the pm-components property: one component
		 * with 4 power levels.
		 * - skip for pshot@XXX,nopm and pshot@XXX,nopm_strict:
		 * "no-pm-components" property
		 */
		if (ddi_prop_exists(DDI_DEV_T_ANY, devi,
		    (DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
		    "no-pm-components") == 0) {
			if (pshot_debug) {
				cmn_err(CE_CONT, "pshot%d: DDI_ATTACH:"
				    " create the \"pm_components\" property\n",
				    instance);
			}
			if (ddi_prop_update_string_array(DDI_DEV_T_NONE, devi,
			    "pm-components", pm_comp, 5) != DDI_PROP_SUCCESS) {
				cmn_err(CE_WARN, "%s%d: DDI_ATTACH:\n\t"
				    " unable to create the \"pm-components\""
				    " property", ddi_get_name(devi),
				    ddi_get_instance(devi));

				goto FAIL_ATTACH;
			}
		} else {
			if (pshot_debug) {
				cmn_err(CE_CONT, "pshot%d: DDI_ATTACH:"
				    " NO-PM_COMPONENTS PARENT\n", instance);
			}
			mutex_enter(&pshot->lock);
			pshot->state &= ~PM_SUPPORTED;
			mutex_exit(&pshot->lock);
		}

		/*
		 * create the property needed to get DDI_SUSPEND
		 * and DDI_RESUME calls
		 */
		if (pshot_debug) {
			cmn_err(CE_CONT, "pshot%d: DDI_ATTACH:"
			    " create pm-hardware-state property\n",
			    instance);
		}
		if (ddi_prop_update_string(DDI_DEV_T_NONE, devi,
		    "pm-hardware-state", pm_hw_state) != DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN, "%s%d: DDI_ATTACH:\n\t"
			    " unable to create the \"pm-hardware-state\""
			    " property", ddi_get_name(devi),
			    ddi_get_instance(devi));

			goto FAIL_ATTACH;
		}

		/*
		 * set power level to max via pm_raise_power(),
		 * - skip if PM_SUPPORTED is not set (pshot@XXX,nopm)
		 */
		if (pshot->state & PM_SUPPORTED) {
			if (pshot_debug) {
				cmn_err(CE_CONT, "pshot%d: DDI_ATTACH:"
				    " raise power to MAXPWR\n", instance);
			}
			if (pm_raise_power(pshot->dip, 0, MAXPWR) !=
			    DDI_SUCCESS) {
				cmn_err(CE_WARN, "%s%d: DDI_ATTACH:"
				    " pm_raise_power failed",
				    ddi_get_name(devi),
				    ddi_get_instance(devi));

				goto FAIL_ATTACH;

			}
		}

		if (pshot_log)
			cmn_err(CE_CONT, "pshot%d attached\n", instance);
		ddi_report_dev(devi);

		return (DDI_SUCCESS);
		/*NOTREACHED*/
FAIL_ATTACH:
		ddi_remove_minor_node(devi, NULL);
		mutex_destroy(&pshot->lock);
		ddi_soft_state_free(pshot_softstatep, instance);
		return (DDI_FAILURE);

	case DDI_RESUME:
		if (pshot_debug) {
			cmn_err(CE_CONT, "pshot%d: DDI_RESUME: resuming\n",
			    instance);
		}
		pshot = ddi_get_soft_state(pshot_softstatep, instance);

		/*
		 * set power level to max via pm_raise_power(),
		 * - skip if PM_SUPPORTED is not set (pshot@XXX,nopm)
		 */
		if (pshot->state & PM_SUPPORTED) {
			if (pshot_debug) {
				cmn_err(CE_CONT, "pshot%d: DDI_RESUME:"
				    " raise power to MAXPWR\n", instance);
			}
			if (pm_raise_power(pshot->dip, 0, MAXPWR) !=
			    DDI_SUCCESS) {
				cmn_err(CE_WARN, "%s%d: DDI_RESUME:"
				    " pm_raise_power failed",
				    ddi_get_name(devi),
				    ddi_get_instance(devi));
			}
		}

		if (pshot_debug) {
			cmn_err(CE_CONT, "pshot%d: DDI_RESUME: resumed\n",
			    instance);
		}
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

static int
pshot_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(devi);
	int i, rval;
	pshot_t *pshot = ddi_get_soft_state(pshot_softstatep, instance);
	int level_tmp;

	if (pshot == NULL)
		return (DDI_FAILURE);

	switch (cmd) {

	case DDI_DETACH:
		if (pshot_debug)
			cmn_err(CE_CONT, "pshot%d: DDI_DETACH\n", instance);
		/*
		 * power off component 0
		 * - skip if PM_SUPPORTED is not set (pshot@XXX,nopm)
		 */
		if (pshot->state & PM_SUPPORTED) {
			if (pshot_debug) {
				cmn_err(CE_CONT, "pshot%d: DDI_DETACH:"
				    " power off\n", instance);
			}
			if (pm_lower_power(pshot->dip, 0, 0) != DDI_SUCCESS) {
				cmn_err(CE_WARN, "%s%d: DDI_DETACH:\n\t"
				    "pm_lower_power failed for comp 0 to"
				    " level 0", ddi_get_name(devi),
				    ddi_get_instance(devi));

				return (DDI_FAILURE);
			}

			/*
			 * Check if the power level is actually OFF.
			 * Issue pm_power_has_changed if not.
			 */
			mutex_enter(&pshot->lock);
			if (pshot->level != 0) {
				if (pshot_debug) {
					cmn_err(CE_NOTE, "pshot%d:"
					    " DDI_DETACH: power off via"
					    " pm_power_has_changed instead\n",
					    instance);
				}
				level_tmp = pshot->level;
				pshot->level = 0;
				if (pm_power_has_changed(pshot->dip, 0, 0) !=
				    DDI_SUCCESS) {
					if (pshot_debug) {
						cmn_err(CE_NOTE, "pshot%d:"
						    " DDI_DETACH:"
						    " pm_power_has_changed"
						    " failed\n", instance);
					}
					pshot->level = level_tmp;
					mutex_exit(&pshot->lock);

					return (DDI_FAILURE);
				}
			}
			mutex_exit(&pshot->lock);
		}

		for (i = 0; i < PSHOT_N_DDI_EVENTS; i++) {
			if (pshot->callback_cache[i] != NULL) {
				rval = ddi_remove_event_handler(
				    pshot->callback_cache[i]);
				ASSERT(rval == DDI_SUCCESS);
			}
		}

#ifdef DEBUG
		for (i = 0; i < PSHOT_N_TEST_EVENTS; i++) {
			if (pshot->test_callback_cache[i] != NULL) {
				rval = ddi_remove_event_handler(
				    pshot->test_callback_cache[i]);
				ASSERT(rval == DDI_SUCCESS);
			}
		}
#endif
		rval = ndi_event_free_hdl(pshot->ndi_event_hdl);
		ASSERT(rval == DDI_SUCCESS);

		if (pshot_log)
			cmn_err(CE_CONT, "pshot%d detached\n", instance);

		ddi_remove_minor_node(devi, NULL);
		mutex_destroy(&pshot->lock);
		ddi_soft_state_free(pshot_softstatep, instance);
		break;

	case DDI_SUSPEND:
		if (pshot_debug)
			cmn_err(CE_CONT, "pshot%d: DDI_SUSPEND\n", instance);
		/*
		 * fail the suspend if FAIL_SUSPEND_FLAG is set.
		 * clear the FAIL_SUSPEND_FLAG flag
		 */
		mutex_enter(&pshot->lock);
		if (pshot->state & FAIL_SUSPEND_FLAG) {
			if (pshot_debug) {
				cmn_err(CE_CONT, "pshot%d:"
				    " FAIL_SUSPEND_FLAG set, fail suspend\n",
				    ddi_get_instance(devi));
			}
			pshot->state &= ~FAIL_SUSPEND_FLAG;
			rval = DDI_FAILURE;
		} else {
			rval = DDI_SUCCESS;
		}
		mutex_exit(&pshot->lock);

		/*
		 * power OFF via pm_power_has_changed
		 */
		mutex_enter(&pshot->lock);
		if (pshot->state & PM_SUPPORTED) {
			if (pshot_debug) {
				cmn_err(CE_CONT, "pshot%d: DDI_SUSPEND:"
				    " power off via pm_power_has_changed\n",
				    instance);
			}
			level_tmp = pshot->level;
			pshot->level = 0;
			if (pm_power_has_changed(pshot->dip, 0, 0) !=
			    DDI_SUCCESS) {
				if (pshot_debug) {
					cmn_err(CE_NOTE, "pshot%d:"
					    " DDI_SUSPEND:"
					    " pm_power_has_changed failed\n",
					    instance);
				}
				pshot->level = level_tmp;
				rval = DDI_FAILURE;
			}
		}
		mutex_exit(&pshot->lock);
		return (rval);

	default:
		break;
	}

	return (DDI_SUCCESS);
}


/*
 * returns number of bits to represent <val>
 */
static size_t
pshot_numbits(size_t val)
{
	size_t bitcnt;

	if (val == 0)
		return (0);
	for (bitcnt = 1; 1 << bitcnt < val; bitcnt++)
		;
	return (bitcnt);
}

/*
 * returns a minor number encoded with instance <inst> and an index <nodenum>
 * that identifies the minor node for this instance
 */
static minor_t
pshot_minor_encode(int inst, minor_t nodenum)
{
	return (((minor_t)inst << PSHOT_NODENUM_BITS()) |
	    (((1 << PSHOT_NODENUM_BITS()) - 1) & nodenum));
}

/*
 * returns instance of <minor>
 */
static int
pshot_minor_decode_inst(minor_t minor)
{
	return (minor >> PSHOT_NODENUM_BITS());
}

/*
 * returns node number indexing a minor node for the instance in <minor>
 */
static minor_t
pshot_minor_decode_nodenum(minor_t minor)
{
	return (minor & ((1 << PSHOT_NODENUM_BITS()) - 1));
}


/*
 * pshot_bus_introp: pshot convert an interrupt number to an
 *			   interrupt. NO OP for pseudo drivers.
 */
/*ARGSUSED*/
static int
pshot_bus_introp(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	return (DDI_FAILURE);
}
static int
pshot_ctl(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t ctlop, void *arg, void *result)
{
	int instance;
	pshot_t *pshot;
	char *childname;
	int childinstance;
	char *name;
	int circ;
	struct attachspec *as;
	struct detachspec *ds;
	int rval = DDI_SUCCESS;
	int no_pm_components_child;

	name = ddi_get_name(dip);
	instance = ddi_get_instance(dip);
	pshot = ddi_get_soft_state(pshot_softstatep, instance);
	if (pshot == NULL) {
		return (ENXIO);
	}

	switch (ctlop) {
	case DDI_CTLOPS_REPORTDEV:
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);
		cmn_err(CE_CONT, "?pshot-device: %s%d\n",
		    ddi_get_name(rdip), ddi_get_instance(rdip));
		return (DDI_SUCCESS);

	case DDI_CTLOPS_INITCHILD:
	{
		dev_info_t *child = (dev_info_t *)arg;

		if (pshot_debug) {
			cmn_err(CE_CONT, "initchild %s%d/%s%d state 0x%x\n",
			    ddi_get_name(dip), ddi_get_instance(dip),
			    ddi_node_name(child), ddi_get_instance(child),
			    DEVI(child)->devi_state);
		}

		return (pshot_initchild(dip, child));
	}

	case DDI_CTLOPS_UNINITCHILD:
	{
		dev_info_t *child = (dev_info_t *)arg;

		if (pshot_debug) {
			cmn_err(CE_CONT, "uninitchild %s%d/%s%d state 0x%x\n",
			    ddi_get_name(dip), ddi_get_instance(dip),
			    ddi_node_name(child), ddi_get_instance(child),
			    DEVI(child)->devi_state);
		}

		return (pshot_uninitchild(dip, child));
	}

	case DDI_CTLOPS_DMAPMAPC:
	case DDI_CTLOPS_REPORTINT:
	case DDI_CTLOPS_REGSIZE:
	case DDI_CTLOPS_NREGS:
	case DDI_CTLOPS_SIDDEV:
	case DDI_CTLOPS_SLAVEONLY:
	case DDI_CTLOPS_AFFINITY:
	case DDI_CTLOPS_POKE:
	case DDI_CTLOPS_PEEK:
		/*
		 * These ops correspond to functions that "shouldn't" be called
		 * by a pseudo driver.  So we whine when we're called.
		 */
		cmn_err(CE_CONT, "%s%d: invalid op (%d) from %s%d\n",
		    ddi_get_name(dip), ddi_get_instance(dip),
		    ctlop, ddi_get_name(rdip), ddi_get_instance(rdip));
		return (DDI_FAILURE);

	case DDI_CTLOPS_ATTACH:
	{
		dev_info_t *child = (dev_info_t *)rdip;
		childname = ddi_node_name(child);
		childinstance = ddi_get_instance(child);
		as = (struct attachspec *)arg;

		no_pm_components_child = 0;
		if (ddi_prop_exists(DDI_DEV_T_ANY, child,
		    (DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
		    "no-pm-components") == 1) {
			no_pm_components_child = 1;
		}
		if (pshot_debug) {
			cmn_err(CE_CONT, "%s%d: ctl_attach %s%d [%d]\n",
			    name, instance, childname, childinstance,
			    no_pm_components_child);
		}

		ndi_devi_enter(dip, &circ);

		switch (as->when) {
		case DDI_PRE:
			/*
			 * Mark nexus busy before a child attaches.
			 * - skip if PM_SUPPORTED is not set (pshot@XXX,nopm
			 * - pshot@XXX,nopm_strict)
			 */
			if (!(pshot->state & PM_SUPPORTED))
				break;
			mutex_enter(&pshot->lock);
			++(pshot->busy);
			if (pshot_debug_busy) {
				cmn_err(CE_CONT, "%s%d:"
				    " ctl_attach_pre: busy for %s%d:"
				    " busy = %d\n", name, instance,
				    childname, childinstance,
				    pshot->busy);
			}
			mutex_exit(&pshot->lock);
			rval = pm_busy_component(dip, 0);
			ASSERT(rval == DDI_SUCCESS);
			break;
		case DDI_POST:
			/*
			 * Mark nexus idle after a child attaches.
			 * - skip if PM_SUPPORTED is not set (pshot@XXX,nopm).
			 * - also skip if this is not a stict parent and
			 * - the child is a tape device or a no-pm-components
			 * - nexus node.
			 */
			if (!(pshot->state & PM_SUPPORTED) ||
			    (strcmp(childname, "tape") == 0 &&
			    !(pshot->state & STRICT_PARENT)) ||
			    no_pm_components_child)
				break;
			mutex_enter(&pshot->lock);
			ASSERT(pshot->busy > 0);
			--pshot->busy;
			if (pshot_debug_busy) {
				cmn_err(CE_CONT, "%s%d:"
				    " ctl_attach_post: idle for %s%d:"
				    " busy = %d\n", name, instance,
				    childname, childinstance,
				    pshot->busy);
			}
			mutex_exit(&pshot->lock);
			rval = pm_idle_component(dip, 0);
			ASSERT(rval == DDI_SUCCESS);
			break;
		}

		ndi_devi_exit(dip, circ);

		return (rval);
	}
	case DDI_CTLOPS_DETACH:
		{
		dev_info_t *child = (dev_info_t *)rdip;
		childname = ddi_node_name(child);
		childinstance = ddi_get_instance(child);
		ds = (struct detachspec *)arg;

		no_pm_components_child = 0;
		if (ddi_prop_exists(DDI_DEV_T_ANY, child,
		    (DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
		    "no-pm-components") == 1) {
			no_pm_components_child = 1;
		}
		if (pshot_debug) {
			cmn_err(CE_CONT,
			    "%s%d: ctl_detach %s%d [%d]\n",
			    name, instance, childname, childinstance,
			    no_pm_components_child);
		}

		ndi_devi_enter(dip, &circ);

		switch (ds->when) {
		case DDI_PRE:
			/*
			 * Mark nexus busy before a child detaches.
			 * - skip if PM_SUPPORTED is not set (pshot@XXX,nopm
			 * - pshot@XXX,nopm_strict), or if the child is a
			 * - no-pm-components nexus node.
			 */
			if (!(pshot->state & PM_SUPPORTED) ||
			    (strcmp(childname, "tape") == 0 &&
			    !(pshot->state & STRICT_PARENT)) ||
			    no_pm_components_child)
				break;
			mutex_enter(&pshot->lock);
			++(pshot->busy);
			if (pshot_debug_busy) {
				cmn_err(CE_CONT, "%s%d:"
				    " ctl_detach_pre: busy for %s%d:"
				    " busy = %d\n", name, instance,
				    childname, childinstance,
				    pshot->busy);
			}
			mutex_exit(&pshot->lock);
			rval = pm_busy_component(dip, 0);
			ASSERT(rval == DDI_SUCCESS);

			break;
		case DDI_POST:
			/*
			 * Mark nexus idle after a child detaches.
			 * - skip if PM_SUPPORTED is not set (pshot@XXX,nopm)
			 */
			if (!(pshot->state & PM_SUPPORTED))
				break;
			mutex_enter(&pshot->lock);
			ASSERT(pshot->busy > 0);
			--pshot->busy;
			if (pshot_debug_busy) {
				cmn_err(CE_CONT, "%s%d:"
				    " ctl_detach_post: idle for %s%d:"
				    " busy = %d\n", name, instance,
				    childname, childinstance,
				    pshot->busy);
			}
			mutex_exit(&pshot->lock);
			rval = pm_idle_component(dip, 0);
			ASSERT(rval == DDI_SUCCESS);

			/*
			 * Mark the driver idle if the NO_INVOL_FLAG
			 * is set. This is needed to make sure the
			 * parent is idle after the child detaches
			 * without calling pm_lower_power().
			 * Clear the NO_INVOL_FLAG.
			 * - also mark idle if a tape device has detached
			 */
			if (!(pshot->state & NO_INVOL_FLAG))
				break;
			mutex_enter(&pshot->lock);
			ASSERT(pshot->busy > 0);
			--pshot->busy;
			if (pshot_debug_busy) {
				cmn_err(CE_CONT, "%s%d:"
				    " ctl_detach_post: NO_INVOL:"
				    " idle for %s%d: busy = %d\n",
				    name, instance, childname,
				    childinstance, pshot->busy);
			}
			pshot->state &= ~NO_INVOL_FLAG;
			mutex_exit(&pshot->lock);
			rval = pm_idle_component(dip, 0);
			ASSERT(rval == DDI_SUCCESS);

			break;
		}

		ndi_devi_exit(dip, circ);

		return (rval);
	}

	case DDI_CTLOPS_BTOP:
	case DDI_CTLOPS_BTOPR:
	case DDI_CTLOPS_DVMAPAGESIZE:
	case DDI_CTLOPS_IOMIN:
	case DDI_CTLOPS_PTOB:
	default:
		/*
		 * The ops that we pass up (default).  We pass up memory
		 * allocation oriented ops that we receive - these may be
		 * associated with pseudo HBA drivers below us with target
		 * drivers below them that use ddi memory allocation
		 * interfaces like scsi_alloc_consistent_buf.
		 */
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));
	}
}

/*ARGSUSED0*/
static int
pshot_power(dev_info_t *dip, int cmpt, int level)
{
	pshot_t *pshot;
	int instance = ddi_get_instance(dip);
	char *name = ddi_node_name(dip);
	int circ;
	int rv;

	pshot = ddi_get_soft_state(pshot_softstatep, instance);
	if (pshot == NULL) {

		return (DDI_FAILURE);
	}

	ndi_devi_enter(dip, &circ);

	/*
	 * set POWER_FLAG when power() is called.
	 * ioctl(DEVCT_PM_POWER) is a clear on read call.
	 */
	mutex_enter(&pshot->lock);
	pshot->state |= POWER_FLAG;
	/*
	 * refuse to power OFF if the component is busy
	 */
	if (pshot->busy != 0 && pshot->level > level) {
		cmn_err(CE_WARN, "%s%d: power: REFUSING POWER LEVEL CHANGE"
		    " (%d->%d), DEVICE NOT IDLE: busy = %d",
		    name, instance, pshot->level, level, pshot->busy);
		rv = DDI_FAILURE;
	} else {
		if (pshot_debug) {
			cmn_err(CE_CONT, "%s%d: power: comp %d (%d->%d)\n",
			    name, instance, cmpt, pshot->level, level);
		}
		pshot->level = level;
		rv = DDI_SUCCESS;
	}
	mutex_exit(&pshot->lock);

	ndi_devi_exit(dip, circ);

	return (rv);
}

/*ARGSUSED0*/
static int
pshot_bus_power(dev_info_t *dip, void *impl_arg, pm_bus_power_op_t op,
    void *arg, void *result)

{
	int 				ret;
	int 				instance = ddi_get_instance(dip);
	char				*name = ddi_node_name(dip);
	pshot_t 			*pshot;
	pm_bp_child_pwrchg_t		*bpc;
	pm_bp_nexus_pwrup_t		bpn;
	pm_bp_has_changed_t		*bphc;
	int				pwrup_res;
	int				ret_failed = 0;
	int				pwrup_res_failed = 0;

	pshot = ddi_get_soft_state(pshot_softstatep, instance);
	if (pshot == NULL) {

		return (DDI_FAILURE);
	}

	switch (op) {
	case BUS_POWER_PRE_NOTIFICATION:
		bpc = (pm_bp_child_pwrchg_t *)arg;
		if (pshot_debug) {
			cmn_err(CE_CONT, "%s%d: pre_bus_power:"
			    " %s%d comp %d (%d->%d)\n",
			    name, instance, ddi_node_name(bpc->bpc_dip),
			    ddi_get_instance(bpc->bpc_dip),
			    bpc->bpc_comp, bpc->bpc_olevel,
			    bpc->bpc_nlevel);
		}

		/*
		 * mark parent busy if old_level is either -1 or 0,
		 * and new level is == MAXPWR
		 * - skip if PM_SUPPORTED is not set (pshot@XXX,nopm)
		 */
		if ((bpc->bpc_comp == 0 && bpc->bpc_nlevel == MAXPWR &&
		    bpc->bpc_olevel <= 0) && (pshot->state & PM_SUPPORTED)) {
			mutex_enter(&pshot->lock);
			++(pshot->busy);
			if (pshot_debug_busy) {
				cmn_err(CE_CONT,
				    "%s%d: pre_bus_power:"
				    " busy parent for %s%d (%d->%d): "
				    " busy = %d\n",
				    name, instance,
				    ddi_node_name(bpc->bpc_dip),
				    ddi_get_instance(bpc->bpc_dip),
				    bpc->bpc_olevel, bpc->bpc_nlevel,
				    pshot->busy);
			}
			mutex_exit(&pshot->lock);
			ret = pm_busy_component(dip, 0);
			ASSERT(ret == DDI_SUCCESS);
		}

		/*
		 * if new_level > 0, power up parent, if not already at
		 * MAXPWR, via pm_busop_bus_power
		 * - skip for the no-pm nexus (pshot@XXX,nopm)
		 */
		if (bpc->bpc_comp == 0 && bpc->bpc_nlevel > 0 &&
		    pshot->level < MAXPWR && (pshot->state & PM_SUPPORTED)) {
			/*
			 * stuff the bpn struct
			 */
			bpn.bpn_comp = 0;
			bpn.bpn_level = MAXPWR;
			bpn.bpn_private = bpc->bpc_private;
			bpn.bpn_dip = dip;

			/*
			 * ask pm to power parent up
			 */
			if (pshot_debug) {
				cmn_err(CE_CONT, "%s%d: pre_bus_power:"
				    " pm_busop_bus_power on parent for %s%d"
				    " (%d->%d): enter", name, instance,
				    ddi_node_name(bpc->bpc_dip),
				    ddi_get_instance(bpc->bpc_dip),
				    bpc->bpc_olevel, bpc->bpc_nlevel);
			}
			ret = pm_busop_bus_power(dip, impl_arg,
			    BUS_POWER_NEXUS_PWRUP, (void *)&bpn,
			    (void *)&pwrup_res);

			/*
			 * check the return status individually,
			 * idle parent and exit if either failed.
			 */
			if (ret != DDI_SUCCESS) {
				cmn_err(CE_WARN,
				    "%s%d: pre_bus_power:"
				    " pm_busop_bus_power FAILED (ret) FOR"
				    " %s%d (%d->%d)",
				    name, instance,
				    ddi_node_name(bpc->bpc_dip),
				    ddi_get_instance(bpc->bpc_dip),
				    bpc->bpc_olevel, bpc->bpc_nlevel);
				ret_failed = 1;
			}
			if (pwrup_res != DDI_SUCCESS) {
				cmn_err(CE_WARN,
				    "%s%d: pre_bus_power:"
				    " pm_busop_bus_power FAILED (pwrup_res)"
				    " FOR %s%d (%d->%d)",
				    name, instance,
				    ddi_node_name(bpc->bpc_dip),
				    ddi_get_instance(bpc->bpc_dip),
				    bpc->bpc_olevel, bpc->bpc_nlevel);
				pwrup_res_failed = 1;
			}
			if (ret_failed || pwrup_res_failed) {
				/*
				 * decrement the busy count if it
				 * had been incremented.
				 */
				if ((bpc->bpc_comp == 0 &&
				    bpc->bpc_nlevel == MAXPWR &&
				    bpc->bpc_olevel <= 0) &&
				    (pshot->state & PM_SUPPORTED)) {
					mutex_enter(&pshot->lock);
					ASSERT(pshot->busy > 0);
					--(pshot->busy);
					if (pshot_debug_busy) {
						cmn_err(CE_CONT, "%s%d:"
						    " pm_busop_bus_power"
						    " failed: idle parent for"
						    " %s%d (%d->%d):"
						    " busy = %d\n",
						    name, instance,
						    ddi_node_name(
						    bpc->bpc_dip),
						    ddi_get_instance(
						    bpc->bpc_dip),
						    bpc->bpc_olevel,
						    bpc->bpc_nlevel,
						    pshot->busy);
					}
					mutex_exit(&pshot->lock);
					ret = pm_idle_component(dip, 0);
					ASSERT(ret == DDI_SUCCESS);
				}
				return (DDI_FAILURE);

			} else {
				if (pshot_debug) {
					cmn_err(CE_CONT,
					    "%s%d: pre_bus_power:"
					    " pm_busop_bus_power on parent"
					    " for %s%d (%d->%d)\n",
					    name, instance,
					    ddi_node_name(bpc->bpc_dip),
					    ddi_get_instance(bpc->bpc_dip),
					    bpc->bpc_olevel, bpc->bpc_nlevel);
				}
			}
		}
		break;

	case BUS_POWER_POST_NOTIFICATION:
		bpc = (pm_bp_child_pwrchg_t *)arg;
		if (pshot_debug) {
			cmn_err(CE_CONT, "%s%d: post_bus_power:"
			    " %s%d comp %d (%d->%d) result %d\n",
			    name, instance, ddi_node_name(bpc->bpc_dip),
			    ddi_get_instance(bpc->bpc_dip),
			    bpc->bpc_comp, bpc->bpc_olevel,
			    bpc->bpc_nlevel, *(int *)result);
		}

		/*
		 * handle pm_busop_bus_power() failure case.
		 * mark parent idle if had been marked busy.
		 * - skip if PM_SUPPORTED is not set (pshot@XXX,nopm)
		 */
		if (*(int *)result != DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "pshot%d: post_bus_power_failed:"
			    " pm_busop_bus_power FAILED FOR %s%d (%d->%d)",
			    instance, ddi_node_name(bpc->bpc_dip),
			    ddi_get_instance(bpc->bpc_dip),
			    bpc->bpc_olevel, bpc->bpc_nlevel);

			if ((bpc->bpc_comp == 0 && bpc->bpc_nlevel == MAXPWR &&
			    bpc->bpc_olevel <= 0) &&
			    (pshot->state & PM_SUPPORTED)) {
				mutex_enter(&pshot->lock);
				ASSERT(pshot->busy > 0);
				--(pshot->busy);
				if (pshot_debug_busy) {
					cmn_err(CE_CONT, "%s%d:"
					    " post_bus_power_failed:"
					    " idle parent for %s%d"
					    " (%d->%d): busy = %d\n",
					    name, instance,
					    ddi_node_name(bpc->bpc_dip),
					    ddi_get_instance(bpc->bpc_dip),
					    bpc->bpc_olevel, bpc->bpc_nlevel,
					    pshot->busy);
				}
				mutex_exit(&pshot->lock);
				ret = pm_idle_component(dip, 0);
				ASSERT(ret == DDI_SUCCESS);
			}
		}

		/*
		 * Mark nexus idle when a child's comp 0
		 * is set to level 0 from level 1, 2, or 3 only.
		 * And only if result arg == DDI_SUCCESS.
		 * This will leave the parent busy when the child
		 * does not call pm_lower_power() on detach after
		 * unsetting the NO_LOWER_POWER flag.
		 * If so, need to notify the parent to mark itself
		 * idle anyway, else the no-involumtary-power-cycles
		 * test cases will report false passes!
		 * - skip if PM_SUPPORTED is not set (pshot@XXX,nopm)
		 */
		if ((bpc->bpc_comp == 0 && bpc->bpc_nlevel == 0 &&
		    !(bpc->bpc_olevel <= 0) &&
		    *(int *)result == DDI_SUCCESS) &&
		    (pshot->state & PM_SUPPORTED)) {
			mutex_enter(&pshot->lock);
			ASSERT(pshot->busy > 0);
			--(pshot->busy);
			if (pshot_debug_busy) {
				cmn_err(CE_CONT,
				    "%s%d: post_bus_power:"
				    " idle parent for %s%d (%d->%d):"
				    " busy = %d\n", name, instance,
				    ddi_node_name(bpc->bpc_dip),
				    ddi_get_instance(bpc->bpc_dip),
				    bpc->bpc_olevel, bpc->bpc_nlevel,
				    pshot->busy);
			}
			mutex_exit(&pshot->lock);
			ret = pm_idle_component(dip, 0);
			ASSERT(ret == DDI_SUCCESS);
		}
		break;

	case BUS_POWER_HAS_CHANGED:
		bphc = (pm_bp_has_changed_t *)arg;
		if (pshot_debug) {
			cmn_err(CE_CONT, "%s%d: has_changed_bus_power:"
			    " %s%d comp %d (%d->%d) result %d\n",
			    name, instance, ddi_node_name(bphc->bphc_dip),
			    ddi_get_instance(bphc->bphc_dip),
			    bphc->bphc_comp, bphc->bphc_olevel,
			    bphc->bphc_nlevel, *(int *)result);
		}

		/*
		 * Mark nexus idle when a child's comp 0
		 * is set to level 0 from levels 1, 2, or 3 only.
		 *
		 * If powering up child leaf/nexus nodes via
		 * pm_power_has_changed() calls, first issue
		 * DEVCTL_PM_BUSY_COMP ioctl to mark parent busy
		 * before powering the parent up, then power up the
		 * child node.
		 * - skip if PM_SUPPORTED is not set (pshot@XXX,nopm)
		 */
		if ((bphc->bphc_comp == 0 && bphc->bphc_nlevel == 0 &&
		    !(bphc->bphc_olevel <= 0)) &&
		    pshot->state & PM_SUPPORTED) {
			mutex_enter(&pshot->lock);
			ASSERT(pshot->busy > 0);
			--(pshot->busy);
			if (pshot_debug_busy) {
				cmn_err(CE_CONT,
				    "%s%d: has_changed_bus_power:"
				    " idle parent for %s%d (%d->%d):"
				    " busy = %d\n", name, instance,
				    ddi_node_name(bphc->bphc_dip),
				    ddi_get_instance(bphc->bphc_dip),
				    bphc->bphc_olevel,
				    bphc->bphc_nlevel, pshot->busy);
			}
			mutex_exit(&pshot->lock);
			ret = pm_idle_component(dip, 0);
			ASSERT(ret == DDI_SUCCESS);
		}
		break;

	default:
		return (pm_busop_bus_power(dip, impl_arg, op, arg, result));

	}

	return (DDI_SUCCESS);
}

static int
pshot_initchild(dev_info_t *dip, dev_info_t *child)
{
	char	name[64];
	char	*bus_addr;
	char	*c_nodename;
	int	bus_id;
	dev_info_t *enum_child;
	int	enum_base;
	int	enum_extent;


	/* check for bus_enum node */

#ifdef	NOT_USED
	if (impl_ddi_merge_child(child) != DDI_SUCCESS)
		return (DDI_FAILURE);
#endif

	enum_base = ddi_prop_get_int(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "busid_ebase", 0);

	enum_extent = ddi_prop_get_int(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS, "busid_range", 0);

	/*
	 * bus enumeration node
	 */
	if ((enum_base != 0) && (enum_extent != 0))	{
		c_nodename = ddi_node_name(child);
		bus_id = enum_base;
		for (; bus_id < enum_extent; bus_id++) {
			if (ndi_devi_alloc(dip, c_nodename, DEVI_PSEUDO_NODEID,
			    &enum_child) != NDI_SUCCESS)
				return (DDI_FAILURE);

			(void) sprintf(name, "%d", bus_id);
			if (ndi_prop_update_string(DDI_DEV_T_NONE, enum_child,
			    "bus-addr", name) != DDI_PROP_SUCCESS) {
				(void) ndi_devi_free(enum_child);
				return (DDI_FAILURE);
			}

			if (ndi_devi_online(enum_child, 0) !=
			    DDI_SUCCESS) {
				(void) ndi_devi_free(enum_child);
				return (DDI_FAILURE);
			}
		}
		/*
		 * fail the enumeration node itself
		 */
		return (DDI_FAILURE);
	}

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, child, 0, "bus-addr",
	    &bus_addr) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "pshot_initchild: bus-addr not defined (%s)",
		    ddi_node_name(child));
		return (DDI_NOT_WELL_FORMED);
	}

	if (strlen(bus_addr) == 0) {
		cmn_err(CE_WARN, "pshot_initchild: NULL bus-addr (%s)",
		    ddi_node_name(child));
		ddi_prop_free(bus_addr);
		return (DDI_FAILURE);
	}

	if (strncmp(bus_addr, "failinit", 8) == 0) {
		if (pshot_debug)
			cmn_err(CE_CONT,
			    "pshot%d: %s forced INITCHILD failure\n",
			    ddi_get_instance(dip), bus_addr);
		ddi_prop_free(bus_addr);
		return (DDI_FAILURE);
	}

	if (pshot_log) {
		cmn_err(CE_CONT, "initchild %s%d/%s@%s\n",
		    ddi_get_name(dip), ddi_get_instance(dip),
		    ddi_node_name(child), bus_addr);
	}

	ddi_set_name_addr(child, bus_addr);
	ddi_prop_free(bus_addr);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
pshot_uninitchild(dev_info_t *dip, dev_info_t *child)
{
	ddi_set_name_addr(child, NULL);
	return (DDI_SUCCESS);
}


/*
 * devctl IOCTL support
 */
/* ARGSUSED */
static int
pshot_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	int instance;
	pshot_t *pshot;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	instance = pshot_minor_decode_inst(getminor(*devp));
	if ((pshot = ddi_get_soft_state(pshot_softstatep, instance)) == NULL)
		return (ENXIO);

	/*
	 * Access is currently determined on a per-instance basis.
	 * If we want per-node, then need to add state and lock members to
	 * pshot_minor_t
	 */
	mutex_enter(&pshot->lock);
	if (((flags & FEXCL) && (pshot->state & IS_OPEN)) ||
	    (!(flags & FEXCL) && (pshot->state & IS_OPEN_EXCL))) {
		mutex_exit(&pshot->lock);
		return (EBUSY);
	}
	pshot->state |= IS_OPEN;
	if (flags & FEXCL)
		pshot->state |= IS_OPEN_EXCL;

	if (pshot_debug)
		cmn_err(CE_CONT, "pshot%d open\n", instance);

	mutex_exit(&pshot->lock);
	return (0);
}

/*
 * pshot_close
 */
/* ARGSUSED */
static int
pshot_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	int instance;
	pshot_t *pshot;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	instance = pshot_minor_decode_inst(getminor(dev));
	if ((pshot = ddi_get_soft_state(pshot_softstatep, instance)) == NULL)
		return (ENXIO);

	mutex_enter(&pshot->lock);
	pshot->state &= ~(IS_OPEN | IS_OPEN_EXCL);
	mutex_exit(&pshot->lock);
	if (pshot_debug)
		cmn_err(CE_CONT, "pshot%d closed\n", instance);
	return (0);
}


/*
 * pshot_ioctl: redirects to appropriate command handler based on various
 * 	criteria
 */
/* ARGSUSED */
static int
pshot_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	pshot_t *pshot;
	int instance;
	minor_t nodenum;
	char *nodename;

	instance = pshot_minor_decode_inst(getminor(dev));
	if ((pshot = ddi_get_soft_state(pshot_softstatep, instance)) == NULL)
		return (ENXIO);

	nodenum = pshot_minor_decode_nodenum(getminor(dev));
	nodename = pshot->nodes[nodenum].name;

	if (pshot_debug)
		cmn_err(CE_CONT,
		    "pshot%d ioctl: dev=%p, cmd=%x, arg=%p, mode=%x\n",
		    instance, (void *)dev, cmd, (void *)arg, mode);

	if (strcmp(nodename, PSHOT_NODENAME_DEVCTL) == 0)
		return (pshot_devctl(pshot, nodenum, cmd, arg, mode, credp,
		    rvalp));

	if (strcmp(nodename, PSHOT_NODENAME_TESTCTL) == 0)
		return (pshot_testctl(pshot, nodenum, cmd, arg, mode, credp,
		    rvalp));

	cmn_err(CE_WARN, "pshot_ioctl: unmatched nodename on minor %u",
	    pshot->nodes[nodenum].minor);
	return (ENXIO);
}


/*
 * pshot_devctl: handle DEVCTL operations
 */
/* ARGSUSED */
static int
pshot_devctl(pshot_t *pshot, minor_t nodenum, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp)
{
	dev_info_t *self;
	dev_info_t *child = NULL;
	struct devctl_iocdata *dcp;
	uint_t state;
	int rv = 0;
	uint_t flags;
	int instance;
	int i;
	int ret;

	self = pshot->dip;

	flags = (pshot_devctl_debug) ? NDI_DEVI_DEBUG : 0;
	instance = pshot->instance;

	/*
	 * We can use the generic implementation for these ioctls
	 */
	for (i = 0; pshot_devctls[i].ioctl_int != 0; i++) {
		if (pshot_devctls[i].ioctl_int == cmd) {
			if (pshot_debug)
				cmn_err(CE_CONT, "pshot%d devctl: %s",
				    instance, pshot_devctls[i].ioctl_char);
		}
	}
	switch (cmd) {
	case DEVCTL_DEVICE_GETSTATE:
	case DEVCTL_DEVICE_ONLINE:
	case DEVCTL_DEVICE_OFFLINE:
	case DEVCTL_DEVICE_REMOVE:
	case DEVCTL_BUS_GETSTATE:
	case DEVCTL_BUS_DEV_CREATE:
		rv = ndi_devctl_ioctl(self, cmd, arg, mode, flags);
		if (pshot_debug && rv != 0) {
			cmn_err(CE_CONT, "pshot%d ndi_devctl_ioctl:"
			    " failed, rv = %d", instance, rv);
		}

		return (rv);
	}

	/*
	 * read devctl ioctl data
	 */
	if (ndi_dc_allochdl((void *)arg, &dcp) != NDI_SUCCESS)
		return (EFAULT);

	switch (cmd) {

	case DEVCTL_DEVICE_RESET:
		if (pshot_debug)
			cmn_err(CE_CONT, "pshot%d devctl:"
			    " DEVCTL_DEVICE_RESET\n", instance);
		rv = pshot_event(pshot, PSHOT_EVENT_TAG_DEV_RESET,
		    child, (void *)self);
		ASSERT(rv == NDI_SUCCESS);
		break;

	case DEVCTL_BUS_QUIESCE:
		if (pshot_debug)
			cmn_err(CE_CONT, "pshot%d devctl:"
			    " DEVCTL_BUS_QUIESCE\n", instance);
		if (ndi_get_bus_state(self, &state) == NDI_SUCCESS) {
			if (state == BUS_QUIESCED) {
				break;
			}
			(void) ndi_set_bus_state(self, BUS_QUIESCED);
		}
		rv = pshot_event(pshot, PSHOT_EVENT_TAG_BUS_QUIESCE,
		    child, (void *)self);
		ASSERT(rv == NDI_SUCCESS);

		break;

	case DEVCTL_BUS_UNQUIESCE:
		if (pshot_debug)
			cmn_err(CE_CONT, "pshot%d devctl:"
			    " DEVCTL_BUS_UNQUIESCE\n", instance);
		if (ndi_get_bus_state(self, &state) == NDI_SUCCESS) {
			if (state == BUS_ACTIVE) {
				break;
			}
		}

		/*
		 * quiesce the bus through bus-specific means
		 */
		(void) ndi_set_bus_state(self, BUS_ACTIVE);
		rv = pshot_event(pshot, PSHOT_EVENT_TAG_BUS_UNQUIESCE,
		    child, (void *)self);
		ASSERT(rv == NDI_SUCCESS);
		break;

	case DEVCTL_BUS_RESET:
	case DEVCTL_BUS_RESETALL:
		/*
		 * no reset support for the pseudo bus
		 * but if there were....
		 */
		rv = pshot_event(pshot, PSHOT_EVENT_TAG_BUS_RESET,
		    child, (void *)self);
		ASSERT(rv == NDI_SUCCESS);
		break;

	/*
	 * PM related ioctls
	 */
	case DEVCTL_PM_BUSY_COMP:
		/*
		 * mark component 0 busy.
		 * Keep track of ioctl updates to the busy count
		 * via pshot->busy_ioctl.
		 */
		if (pshot_debug) {
			cmn_err(CE_CONT, "pshot%d devctl:"
			    " DEVCTL_PM_BUSY_COMP\n", instance);
		}
		mutex_enter(&pshot->lock);
		++(pshot->busy);
		++(pshot->busy_ioctl);
		if (pshot_debug_busy) {
			cmn_err(CE_CONT, "pshot%d:"
			    " DEVCTL_PM_BUSY_COMP comp 0 busy"
			    " %d busy_ioctl %d\n", instance, pshot->busy,
			    pshot->busy_ioctl);
		}
		mutex_exit(&pshot->lock);
		ret = pm_busy_component(pshot->dip, 0);
		ASSERT(ret == DDI_SUCCESS);

		break;

	case DEVCTL_PM_BUSY_COMP_TEST:
		/*
		 * test bus's busy state
		 */
		if (pshot_debug) {
			cmn_err(CE_CONT, "pshot%d devctl:"
			    " DEVCTL_PM_BUSY_COMP_TEST\n", instance);
		}
		mutex_enter(&pshot->lock);
		state = pshot->busy;
		if (copyout(&state, dcp->cpyout_buf,
		    sizeof (uint_t)) != 0) {
			cmn_err(CE_WARN, "pshot%d devctl:"
			    " DEVCTL_PM_BUSY_COMP_TEST: copyout failed",
			    instance);
			rv = EINVAL;
		}
		if (pshot_debug_busy) {
			cmn_err(CE_CONT, "pshot%d: DEVCTL_PM_BUSY_COMP_TEST:"
			    " comp 0 busy %d busy_ioctl %d\n", instance,
			    state, pshot->busy_ioctl);
		}
		mutex_exit(&pshot->lock);
		break;

	case DEVCTL_PM_IDLE_COMP:
		/*
		 * mark component 0 idle.
		 * NOP if pshot->busy_ioctl <= 0.
		 */
		if (pshot_debug) {
			cmn_err(CE_CONT, "pshot%d devctl:"
			    " DEVCTL_PM_IDLE_COMP\n", instance);
		}
		mutex_enter(&pshot->lock);
		if (pshot->busy_ioctl > 0) {
			ASSERT(pshot->busy > 0);
			--(pshot->busy);
			--(pshot->busy_ioctl);
			if (pshot_debug_busy) {
				cmn_err(CE_CONT, "pshot%d:"
				    " DEVCTL_PM_IDLE_COM: comp 0"
				    " busy %d busy_ioctl %d\n", instance,
				    pshot->busy, pshot->busy_ioctl);
			}
			mutex_exit(&pshot->lock);
			ret = pm_idle_component(pshot->dip, 0);
			ASSERT(ret == DDI_SUCCESS);

		} else {
			mutex_exit(&pshot->lock);
		}
		break;

	case DEVCTL_PM_RAISE_PWR:
		/*
		 * raise component 0 to full power level MAXPWR via a
		 * pm_raise_power() call
		 */
		if (pshot_debug) {
			cmn_err(CE_CONT, "pshot%d devctl:"
			    " DEVCTL_PM_RAISE_PWR\n", instance);
		}
		if (pm_raise_power(pshot->dip, 0, MAXPWR) != DDI_SUCCESS) {
			rv = EINVAL;
		} else {
			mutex_enter(&pshot->lock);
			if (pshot_debug) {
				cmn_err(CE_CONT, "pshot%d:"
				    " DEVCTL_PM_RAISE_POWER: comp 0"
				    " to level %d\n", instance, pshot->level);
			}
			mutex_exit(&pshot->lock);
		}
		break;

	case DEVCTL_PM_LOWER_PWR:
		/*
		 * pm_lower_power() call for negative testing
		 * expected to fail.
		 */
		if (pshot_debug) {
			cmn_err(CE_CONT, "pshot%d devctl:"
			    " DEVCTL_PM_LOWER_PWR\n", instance);
		}
		if (pm_lower_power(pshot->dip, 0, 0) != DDI_SUCCESS) {
			rv = EINVAL;
		} else {
			mutex_enter(&pshot->lock);
			if (pshot_debug) {
				cmn_err(CE_CONT, "pshot%d:"
				    " DEVCTL_PM_LOWER_POWER comp 0"
				    " to level %d\n", instance, pshot->level);
			}
			mutex_exit(&pshot->lock);
		}
		break;

	case DEVCTL_PM_CHANGE_PWR_LOW:
		/*
		 * inform the PM framework that component 0 has changed
		 * power level to 0 via a pm_power_has_changed() call
		 */
		if (pshot_debug) {
			cmn_err(CE_CONT, "pshot%d devctl:"
			    " DEVCTL_PM_CHANGE_PWR_LOW\n", instance);
		}
		mutex_enter(&pshot->lock);
		pshot->level = 0;
		if (pm_power_has_changed(pshot->dip, 0, 0) != DDI_SUCCESS) {
			rv = EINVAL;
		} else {
			if (pshot_debug) {
				cmn_err(CE_CONT, "pshot%d:"
				    " DEVCTL_PM_CHANGE_PWR_LOW comp 0 to"
				    " level %d\n", instance, pshot->level);
			}
		}
		mutex_exit(&pshot->lock);
		break;

	case DEVCTL_PM_CHANGE_PWR_HIGH:
		/*
		 * inform the PM framework that component 0 has changed
		 * power level to MAXPWR via a pm_power_has_changed() call
		 */
		if (pshot_debug) {
			cmn_err(CE_CONT, "pshot%d devctl:"
			    " DEVCTL_PM_CHANGE_PWR_HIGH\n", instance);
		}
		mutex_enter(&pshot->lock);
		pshot->level = MAXPWR;
		if (pm_power_has_changed(pshot->dip, 0, MAXPWR)
		    != DDI_SUCCESS) {
			rv = EINVAL;
		} else {
			if (pshot_debug) {
				cmn_err(CE_CONT, "pshot%d:"
				    " DEVCTL_PM_CHANGE_PWR_HIGH comp 0 to"
				    " level %d\n", instance, pshot->level);
			}
		}
		mutex_exit(&pshot->lock);
		break;

	case DEVCTL_PM_POWER:
		/*
		 * test if the pshot_power() routine has been called,
		 * then clear
		 */
		if (pshot_debug) {
			cmn_err(CE_CONT, "pshot%d devctl:"
			    " DEVCTL_PM_POWER\n", instance);
		}
		mutex_enter(&pshot->lock);
		state = (pshot->state & POWER_FLAG) ? 1 : 0;
		if (copyout(&state, dcp->cpyout_buf,
		    sizeof (uint_t)) != 0) {
			cmn_err(CE_WARN, "pshot%d devctl:"
			    " DEVCTL_PM_POWER: copyout failed",
			    instance);
			rv = EINVAL;
		}
		if (pshot_debug) {
			cmn_err(CE_CONT, "pshot%d: DEVCTL_PM_POWER:"
			    " POWER_FLAG = %d\n", instance, state);
		}
		pshot->state &= ~POWER_FLAG;
		mutex_exit(&pshot->lock);
		break;

	case DEVCTL_PM_FAIL_SUSPEND:
		/*
		 * fail DDI_SUSPEND
		 */
		if (pshot_debug) {
			cmn_err(CE_CONT, "pshot%d devctl:"
			    " DEVCTL_PM_FAIL_SUSPEND\n", instance);
		}
		mutex_enter(&pshot->lock);
		pshot->state |= FAIL_SUSPEND_FLAG;
		mutex_exit(&pshot->lock);
		if (pshot_debug) {
			cmn_err(CE_CONT, "pshot%d: DEVCTL_PM_FAIL_SUSPEND\n",
			    instance);
		}
		break;

	case DEVCTL_PM_BUS_STRICT_TEST:
		/*
		 * test the STRICT_PARENT flag:
		 *	set => STRICT PARENT
		 *	not set => INVOLVED PARENT
		 */
		mutex_enter(&pshot->lock);
		state = (pshot->state & STRICT_PARENT) ? 1 : 0;
		if (copyout(&state, dcp->cpyout_buf,
		    sizeof (uint_t)) != 0) {
			cmn_err(CE_WARN, "pshot%d devctl:"
			    " DEVCTL_PM_BUS_STRICT_TEST: copyout failed",
			    instance);
			rv = EINVAL;
		}
		if (pshot_debug) {
			cmn_err(CE_CONT, "pshot%d devctl:"
			    " DEVCTL_PM_BUS_STRICT_TEST: type = %s\n",
			    instance, ((state == 0) ? "INVOLVED" : "STRICT"));
		}
		mutex_exit(&pshot->lock);
		break;

	case DEVCTL_PM_BUS_NO_INVOL:
		/*
		 * Set the NO_INVOL_FLAG flag to
		 * notify the driver that the child will not
		 * call pm_lower_power() on detach.
		 * The driver needs to mark itself idle twice
		 * during DDI_CTLOPS_DETACH (post).
		 */
		if (pshot_debug) {
			cmn_err(CE_CONT, "pshot%d devctl:"
			    " DEVCTL_PM_BUS_NO_INVOL\n", instance);
		}
		mutex_enter(&pshot->lock);
		pshot->state |= NO_INVOL_FLAG;
		mutex_exit(&pshot->lock);
		break;

	default:
		rv = ENOTTY;
	}

	ndi_dc_freehdl(dcp);
	return (rv);
}


/*
 * pshot_testctl: handle other test operations
 *	- If <cmd> is a DEVCTL cmd, then <arg> is a dev_t indicating which
 *	  child to direct the DEVCTL to, if applicable;
 *	  furthermore, any cmd here can be sent by layered ioctls (unlike
 *	  those to pshot_devctl() which must come from userland)
 */
/* ARGSUSED */
static int
pshot_testctl(pshot_t *pshot, minor_t nodenum, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp)
{
	dev_info_t *self;
	dev_info_t *child = NULL;
	uint_t state;
	int rv = 0;
	int instance;
	int i;

	/* uint_t flags; */

	/* flags = (pshot_devctl_debug) ? NDI_DEVI_DEBUG : 0; */
	self = pshot->dip;
	instance = pshot->instance;

	if (cmd & DEVCTL_IOC) {
		child = e_ddi_hold_devi_by_dev((dev_t)arg, 0);
	}

	for (i = 0; pshot_devctls[i].ioctl_int != 0; i++) {
		if (pshot_devctls[i].ioctl_int == cmd) {
			if (pshot_debug)
				cmn_err(CE_CONT, "pshot%d devctl: %s",
				    instance, pshot_devctls[i].ioctl_char);
		}
	}
	switch (cmd) {
	case DEVCTL_DEVICE_RESET:
		if (pshot_debug)
			cmn_err(CE_CONT, "pshot%d testctl:"
			    " DEVCTL_PM_POWER\n", instance);
		rv = pshot_event(pshot, PSHOT_EVENT_TAG_DEV_RESET,
		    child, (void *)self);
		ASSERT(rv == NDI_SUCCESS);
		break;

	case DEVCTL_BUS_QUIESCE:
		if (pshot_debug)
			cmn_err(CE_CONT, "pshot%d testctl:"
			    " DEVCTL_PM_POWER\n", instance);
		if (ndi_get_bus_state(self, &state) == NDI_SUCCESS) {
			if (state == BUS_QUIESCED) {
				break;
			}
			(void) ndi_set_bus_state(self, BUS_QUIESCED);
		}
		rv = pshot_event(pshot, PSHOT_EVENT_TAG_BUS_QUIESCE,
		    child, (void *)self);
		ASSERT(rv == NDI_SUCCESS);

		break;

	case DEVCTL_BUS_UNQUIESCE:
		if (pshot_debug)
			cmn_err(CE_CONT, "pshot%d testctl:"
			    " DEVCTL_PM_POWER\n", instance);
		if (ndi_get_bus_state(self, &state) == NDI_SUCCESS) {
			if (state == BUS_ACTIVE) {
				break;
			}
		}

		/*
		 * quiesce the bus through bus-specific means
		 */
		(void) ndi_set_bus_state(self, BUS_ACTIVE);
		rv = pshot_event(pshot, PSHOT_EVENT_TAG_BUS_UNQUIESCE,
		    child, (void *)self);
		ASSERT(rv == NDI_SUCCESS);
		break;

	case DEVCTL_BUS_RESET:
	case DEVCTL_BUS_RESETALL:
		/*
		 * no reset support for the pseudo bus
		 * but if there were....
		 */
		rv = pshot_event(pshot, PSHOT_EVENT_TAG_BUS_RESET,
		    child, (void *)self);
		ASSERT(rv == NDI_SUCCESS);
		break;

	default:
		rv = ENOTTY;
	}

	if (child != NULL)
		ddi_release_devi(child);
	return (rv);
}


static int
pshot_get_eventcookie(dev_info_t *dip, dev_info_t *rdip,
	char *eventname, ddi_eventcookie_t *event_cookiep)
{
	int	instance = ddi_get_instance(dip);
	pshot_t *pshot = ddi_get_soft_state(pshot_softstatep, instance);

	if (pshot_debug)
		cmn_err(CE_CONT, "pshot%d: "
		    "pshot_get_eventcookie:\n\t"
		    "dip = 0x%p rdip = 0x%p (%s/%d) eventname = %s\n",
		    instance, (void *)dip, (void *)rdip,
		    ddi_node_name(rdip), ddi_get_instance(rdip),
		    eventname);


	return (ndi_event_retrieve_cookie(pshot->ndi_event_hdl,
	    rdip, eventname, event_cookiep, NDI_EVENT_NOPASS));
}

static int
pshot_add_eventcall(dev_info_t *dip, dev_info_t *rdip,
	ddi_eventcookie_t cookie,
	void (*callback)(), void *arg, ddi_callback_id_t *cb_id)
{
	int	instance = ddi_get_instance(dip);
	pshot_t *pshot = ddi_get_soft_state(pshot_softstatep, instance);

	if (pshot_debug)
		cmn_err(CE_CONT, "pshot%d: "
		    "pshot_add_eventcall:\n\t"
		    "dip = 0x%p rdip = 0x%p (%s%d)\n\tcookie = 0x%p (%s)\n\t"
		    "cb = 0x%p, arg = 0x%p\n",
		    instance, (void *)dip, (void *)rdip,
		    ddi_node_name(rdip), ddi_get_instance(rdip), (void *)cookie,
		    NDI_EVENT_NAME(cookie), (void *)callback, arg);

	/* add callback to our event handle */
	return (ndi_event_add_callback(pshot->ndi_event_hdl, rdip,
	    cookie, callback, arg, NDI_SLEEP, cb_id));
}

static int
pshot_remove_eventcall(dev_info_t *dip, ddi_callback_id_t cb_id)
{

	ndi_event_callbacks_t *cb = (ndi_event_callbacks_t *)cb_id;

	int instance = ddi_get_instance(dip);
	pshot_t *pshot = ddi_get_soft_state(pshot_softstatep, instance);

	ASSERT(cb);

	if (pshot_debug)
		cmn_err(CE_CONT, "pshot%d: "
		    "pshot_remove_eventcall:\n\t"
		    "dip = 0x%p rdip = 0x%p (%s%d)\n\tcookie = 0x%p (%s)\n",
		    instance, (void *)dip, (void *)cb->ndi_evtcb_dip,
		    ddi_node_name(cb->ndi_evtcb_dip),
		    ddi_get_instance(cb->ndi_evtcb_dip),
		    (void *)cb->ndi_evtcb_cookie,
		    NDI_EVENT_NAME(cb->ndi_evtcb_cookie));

	return (ndi_event_remove_callback(pshot->ndi_event_hdl, cb_id));
}

static int
pshot_post_event(dev_info_t *dip, dev_info_t *rdip,
	ddi_eventcookie_t cookie, void *impl_data)
{
	int	instance = ddi_get_instance(dip);
	pshot_t *pshot = ddi_get_soft_state(pshot_softstatep, instance);

	if (pshot_debug) {
		if (rdip) {
			cmn_err(CE_CONT, "pshot%d: "
			    "pshot_post_event:\n\t"
			    "dip = 0x%p rdip = 0x%p (%s%d\n\t"
			    "cookie = 0x%p (%s)\n\tbus_impl = 0x%p\n",
			    instance, (void *)dip, (void *)rdip,
			    ddi_node_name(rdip), ddi_get_instance(rdip),
			    (void *)cookie,
			    NDI_EVENT_NAME(cookie), impl_data);
		} else {
			cmn_err(CE_CONT, "pshot%d: "
			    "pshot_post_event:\n\t"
			    "dip = 0x%p cookie = 0x%p (%s) bus_impl = 0x%p\n",
			    instance, (void *)dip, (void *)cookie,
			    NDI_EVENT_NAME(cookie), impl_data);
		}
	}

	/*  run callbacks for this event */
	return (ndi_event_run_callbacks(pshot->ndi_event_hdl, rdip,
	    cookie, impl_data));
}

/*
 * the nexus driver will generate events
 * that need to go to children
 */
static int
pshot_event(pshot_t *pshot, int event_tag, dev_info_t *child,
	void *bus_impldata)
{
	ddi_eventcookie_t cookie = ndi_event_tag_to_cookie(
	    pshot->ndi_event_hdl, event_tag);

	if (pshot_debug) {
		if (child) {
			cmn_err(CE_CONT, "pshot%d: "
			    "pshot_event: event_tag = 0x%x (%s)\n\t"
			    "child = 0x%p (%s%d) bus_impl = 0x%p (%s%d)\n",
			    pshot->instance, event_tag,
			    ndi_event_tag_to_name(pshot->ndi_event_hdl,
			    event_tag),
			    (void *)child, ddi_node_name(child),
			    ddi_get_instance(child), bus_impldata,
			    ddi_node_name((dev_info_t *)bus_impldata),
			    ddi_get_instance((dev_info_t *)bus_impldata));
		} else {
			cmn_err(CE_CONT, "pshot%d: "
			    "pshot_event: event_tag = 0x%x (%s)\n\t"
			    "child = NULL,  bus_impl = 0x%p (%s%d)\n",
			    pshot->instance, event_tag,
			    ndi_event_tag_to_name(pshot->ndi_event_hdl,
			    event_tag),
			    bus_impldata,
			    ddi_node_name((dev_info_t *)bus_impldata),
			    ddi_get_instance((dev_info_t *)bus_impldata));
		}
	}

	return (ndi_event_run_callbacks(pshot->ndi_event_hdl,
	    child, cookie, bus_impldata));
}


/*
 * the pshot driver event notification callback
 */
static void
pshot_event_cb(dev_info_t *dip, ddi_eventcookie_t cookie,
	void *arg, void *bus_impldata)
{
	pshot_t *pshot = (pshot_t *)arg;
	int event_tag;

	/* look up the event */
	event_tag = NDI_EVENT_TAG(cookie);

	if (pshot_debug) {
		cmn_err(CE_CONT, "pshot%d: "
		    "pshot_event_cb:\n\t"
		    "dip = 0x%p cookie = 0x%p (%s), tag = 0x%x\n\t"
		    "arg = 0x%p bus_impl = 0x%p (%s%d)\n",
		    pshot->instance, (void *)dip, (void *)cookie,
		    NDI_EVENT_NAME(cookie), event_tag, arg, bus_impldata,
		    ddi_node_name((dev_info_t *)bus_impldata),
		    ddi_get_instance((dev_info_t *)bus_impldata));
	}

	switch (event_tag) {
	case PSHOT_EVENT_TAG_OFFLINE:
	case PSHOT_EVENT_TAG_BUS_RESET:
	case PSHOT_EVENT_TAG_BUS_QUIESCE:
	case PSHOT_EVENT_TAG_BUS_UNQUIESCE:
		/* notify all subscribers of the this event */
		(void) ndi_event_run_callbacks(pshot->ndi_event_hdl,
		    NULL, cookie, bus_impldata);
		if (pshot_debug) {
			cmn_err(CE_CONT, "pshot%d: event=%s\n\t"
			    "pshot_event_cb\n", pshot->instance,
			    NDI_EVENT_NAME(cookie));
		}
		/*FALLTHRU*/
	case PSHOT_EVENT_TAG_TEST_POST:
	case PSHOT_EVENT_TAG_DEV_RESET:
	default:
		return;
	}
}

static int
pshot_bus_config(dev_info_t *parent, uint_t flags,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp)
{
	int		rval;
	char		*devname;
	char		*devstr, *cname, *caddr;
	int		devstrlen;
	int		circ;
	pshot_t		*pshot;
	int		instance = ddi_get_instance(parent);

	if (pshot_debug) {
		flags |= NDI_DEVI_DEBUG;
		cmn_err(CE_CONT,
		    "pshot%d: bus_config %s flags=0x%x\n",
		    ddi_get_instance(parent),
		    (op == BUS_CONFIG_ONE) ? (char *)arg : "", flags);
	}

	pshot = ddi_get_soft_state(pshot_softstatep, instance);
	if (pshot == NULL) {

		return (NDI_FAILURE);
	}

	/*
	 * Hold the nexus across the bus_config
	 */
	ndi_devi_enter(parent, &circ);

	switch (op) {
	case BUS_CONFIG_ONE:

		/*
		 * lookup and hold child device, create if not found
		 */
		devname = (char *)arg;
		devstrlen = strlen(devname) + 1;
		devstr = i_ddi_strdup(devname, KM_SLEEP);
		i_ddi_parse_name(devstr, &cname, &caddr, NULL);

		/*
		 * The framework ensures that the node has
		 * a name but each nexus is responsible for
		 * the bus address name space.  This driver
		 * requires that a bus address be specified,
		 * as will most nexus drivers.
		 */
		ASSERT(cname && strlen(cname) > 0);
		if (caddr == NULL || strlen(caddr) == 0) {
			cmn_err(CE_WARN,
			    "pshot%d: malformed name %s (no bus address)",
			    ddi_get_instance(parent), devname);
			kmem_free(devstr, devstrlen);
			ndi_devi_exit(parent, circ);
			return (NDI_FAILURE);
		}

		/*
		 * Handle a few special cases for testing purposes
		 */
		rval = pshot_bus_config_test_specials(parent,
		    devname, cname, caddr);

		if (rval == NDI_SUCCESS) {
			/*
			 * Set up either a leaf or nexus device
			 */
			if (strcmp(cname, "pshot") == 0) {
				rval = pshot_bus_config_setup_nexus(parent,
				    cname, caddr);
			} else {
				rval = pshot_bus_config_setup_leaf(parent,
				    cname, caddr);
			}
		}

		kmem_free(devstr, devstrlen);
		break;

	case BUS_CONFIG_DRIVER:
	case BUS_CONFIG_ALL:
		rval = NDI_SUCCESS;
		break;

	default:
		rval = NDI_FAILURE;
		break;
	}

	if (rval == NDI_SUCCESS)
		rval = ndi_busop_bus_config(parent, flags, op, arg, childp, 0);

	ndi_devi_exit(parent, circ);

	if (pshot_debug)
		cmn_err(CE_CONT, "pshot%d: bus_config %s\n",
		    ddi_get_instance(parent),
		    (rval == NDI_SUCCESS) ? "ok" : "failed");

	return (rval);
}

static int
pshot_bus_unconfig(dev_info_t *parent, uint_t flags,
    ddi_bus_config_op_t op, void *arg)
{
	major_t		major;
	int		rval = NDI_SUCCESS;
	int		circ;

	if (pshot_debug) {
		flags |= NDI_DEVI_DEBUG;
		cmn_err(CE_CONT,
		    "pshot%d: bus_unconfig %s flags=0x%x\n",
		    ddi_get_instance(parent),
		    (op == BUS_UNCONFIG_ONE) ? (char *)arg : "", flags);
	}

	/*
	 * Hold the nexus across the bus_unconfig
	 */
	ndi_devi_enter(parent, &circ);

	switch (op) {
	case BUS_UNCONFIG_ONE:
		/*
		 * Nothing special required here
		 */
		if (pshot_debug) {
			cmn_err(CE_CONT, "pshot%d: bus_unconfig:"
			    " BUS_UNCONFIG_ONE\n", ddi_get_instance(parent));
		}
		break;

	case BUS_UNCONFIG_DRIVER:
		if (pshot_debug > 0) {
			major = (major_t)(uintptr_t)arg;
			cmn_err(CE_CONT,
			    "pshot%d: BUS_UNCONFIG_DRIVER: %s\n",
			    ddi_get_instance(parent),
			    ddi_major_to_name(major));
		}
		break;

	case BUS_UNCONFIG_ALL:
		if (pshot_debug) {
			cmn_err(CE_CONT, "pshot%d: bus_unconfig:"
			    " BUS_UNCONFIG_ALL\n", ddi_get_instance(parent));
		}
		break;

	default:
		if (pshot_debug) {
			cmn_err(CE_CONT, "pshot%d: bus_unconfig: DEFAULT\n",
			    ddi_get_instance(parent));
		}
		rval = NDI_FAILURE;
	}

	if (rval == NDI_SUCCESS)
		rval = ndi_busop_bus_unconfig(parent, flags, op, arg);

	ndi_devi_exit(parent, circ);

	if (pshot_debug)
		cmn_err(CE_CONT, "pshot%d: bus_unconfig %s\n",
		    ddi_get_instance(parent),
		    (rval == NDI_SUCCESS) ? "ok" : "failed");

	return (rval);
}

static dev_info_t *
pshot_findchild(dev_info_t *pdip, char *cname, char *caddr)
{
	dev_info_t *dip;
	char *addr;

	ASSERT(cname != NULL && caddr != NULL);
	ASSERT(DEVI_BUSY_OWNED(pdip));

	for (dip = ddi_get_child(pdip); dip != NULL;
	    dip = ddi_get_next_sibling(dip)) {
		if (strcmp(cname, ddi_node_name(dip)) != 0)
			continue;

		if ((addr = ddi_get_name_addr(dip)) == NULL) {
			if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, 0,
			    "bus-addr", &addr) == DDI_PROP_SUCCESS) {
				if (strcmp(caddr, addr) == 0) {
					ddi_prop_free(addr);
					return (dip);
				}
				ddi_prop_free(addr);
			}
		} else {
			if (strcmp(caddr, addr) == 0)
				return (dip);
		}
	}

	return (NULL);
}

static void
pshot_nexus_properties(dev_info_t *parent, dev_info_t *child, char *cname,
    char *caddr)
{
	char *extension;

	/*
	 * extract the address extension
	 */
	extension = strstr(caddr, ",");
	if (extension != NULL) {
		++extension;
	} else {
		extension = "null";
	}

	/*
	 * Create the "pm-want-child-notification?" property for all
	 * nodes that do not have the "pm_strict" or "nopm_strict"
	 * extension
	 */
	if (strcmp(extension, "pm_strict") != 0 &&
	    strcmp(extension, "nopm_strict") != 0) {
		if (ddi_prop_exists(DDI_DEV_T_ANY, child,
		    (DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
		    "pm-want-child-notification?") == 0) {
			if (pshot_debug) {
				cmn_err(CE_CONT, "pshot%d:"
				    " nexus_properties:\n\tcreate the"
				    " \"pm-want-child-notification?\""
				    " property for %s@%s\n",
				    ddi_get_instance(parent), cname, caddr);
			}
			if (ddi_prop_create(DDI_DEV_T_NONE, child, 0,
			    "pm-want-child-notification?", NULL, 0)
			    != DDI_PROP_SUCCESS) {
				cmn_err(CE_WARN, "pshot%d:"
				    " nexus_properties:\n\tunable to create"
				    " the \"pm-want-child-notification?\""
				    " property for %s@%s",
				    ddi_get_instance(parent), cname, caddr);
			}
		}
	}

	/*
	 * Create the "no-pm-components" property for all nodes
	 * with extension "nopm" or "nopm_strict"
	 */
	if (strcmp(extension, "nopm") == 0 ||
	    strcmp(extension, "nopm_strict") == 0) {
		if (ddi_prop_exists(DDI_DEV_T_ANY, child,
		    (DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
		    "no-pm-components") == 0) {
			if (pshot_debug) {
				cmn_err(CE_CONT, "pshot%d:"
				    " nexus_properties:\n\tcreate the"
				    " \"no-pm-components\""
				    " property for %s@%s\n",
				    ddi_get_instance(parent), cname, caddr);
			}
			if (ddi_prop_create(DDI_DEV_T_NONE, child, 0,
			    "no-pm-components", NULL, 0)
			    != DDI_PROP_SUCCESS) {
				cmn_err(CE_WARN, "pshot%d:"
				    " nexus_properties:\n\tunable to create"
				    " the \"no-pm-components\""
				    " property for %s@%s",
				    ddi_get_instance(parent), cname, caddr);
			}
		}
	}
}

static void
pshot_leaf_properties(dev_info_t *parent, dev_info_t *child, char *cname,
    char *caddr)
{
	char *extension;

	/*
	 * extract the address extension
	 */
	extension = strstr(caddr, ",");
	if (extension != NULL) {
		++extension;
	} else {
		extension = "null";
	}

	/*
	 * Create the "no-involuntary-power-cycles" property for
	 * all leaf nodes with extension "no_invol"
	 */
	if (strcmp(extension, "no_invol") == 0) {
		if (ddi_prop_exists(DDI_DEV_T_ANY, child,
		    (DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
		    "no-involuntary-power-cycles") == 0) {
			if (pshot_debug) {
				cmn_err(CE_CONT, "pshot%d:"
				    " leaf_properties:\n\tcreate the"
				    " \"no-involuntary-power-cycles\""
				    " property for %s@%s\n",
				    ddi_get_instance(parent), cname, caddr);
			}
			if (ddi_prop_create(DDI_DEV_T_NONE, child,
			    DDI_PROP_CANSLEEP,
			    "no-involuntary-power-cycles", NULL, 0)
			    != DDI_PROP_SUCCESS) {
				cmn_err(CE_WARN, "pshot%d:"
				    " leaf_properties:\n\tunable to create the"
				    " \"no-involuntary-power-cycles\""
				    " property for %s@%s",
				    ddi_get_instance(parent), cname, caddr);
			}
		}
	}

	/*
	 * Create the "dependency-property" property for all leaf
	 * nodes with extension "dep_prop"
	 * to be used with the PM_ADD_DEPENDENT_PROPERTY ioctl
	 */
	if (strcmp(extension, "dep_prop") == 0) {
		if (ddi_prop_exists(DDI_DEV_T_ANY, child,
		    (DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
		    "dependency-property") == 0) {
			if (pshot_debug) {
				cmn_err(CE_CONT, "pshot%d:"
				    " leaf_properties:\n\tcreate the"
				    " \"dependency-property\""
				    " property for %s@%s\n",
				    ddi_get_instance(parent), cname, caddr);
			}
			if (ddi_prop_create(DDI_DEV_T_NONE, child,
			    DDI_PROP_CANSLEEP, "dependency-property", NULL, 0)
			    != DDI_PROP_SUCCESS) {
				cmn_err(CE_WARN, "pshot%d:"
				    " leaf_properties:\n\tunable to create the"
				    " \"dependency-property\" property for"
				    " %s@%s", ddi_get_instance(parent),
				    cname, caddr);
			}
		}
	}
}

/*
 * BUS_CONFIG_ONE: setup a child nexus instance.
 */
static int
pshot_bus_config_setup_nexus(dev_info_t *parent, char *cname, char *caddr)
{
	dev_info_t *child;
	int rval;

	ASSERT(parent != 0);
	ASSERT(cname != NULL);
	ASSERT(caddr != NULL);

	child = pshot_findchild(parent, cname, caddr);
	if (child) {
		if (pshot_debug) {
			cmn_err(CE_CONT,
			    "pshot%d: bus_config one %s@%s found\n",
			    ddi_get_instance(parent), cname, caddr);
		}

		/*
		 * create the "pm-want-child-notification?" property
		 * for this child, if it doesn't already exist
		 */
		(void) pshot_nexus_properties(parent, child, cname, caddr);

		return (NDI_SUCCESS);
	}

	ndi_devi_alloc_sleep(parent, cname, DEVI_SID_NODEID, &child);
	ASSERT(child != NULL);

	if (ndi_prop_update_string(DDI_DEV_T_NONE, child,
	    "bus-addr", caddr) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "pshot%d: _prop_update %s@%s failed",
		    ddi_get_instance(parent), cname, caddr);
		(void) ndi_devi_free(child);
		return (NDI_FAILURE);
	}

	rval = ndi_devi_bind_driver(child, 0);
	if (rval != NDI_SUCCESS) {
		cmn_err(CE_WARN, "pshot%d: bind_driver %s failed",
		    ddi_get_instance(parent), cname);
		(void) ndi_devi_free(child);
		return (NDI_FAILURE);
	}

	/*
	 * create the "pm-want-child-notification?" property
	 */
	(void) pshot_nexus_properties(parent, child, cname, caddr);

	return (NDI_SUCCESS);
}

/*
 * BUS_CONFIG_ONE: setup a child leaf device instance.
 * for testing purposes, we will create nodes of a variety of types.
 */
static int
pshot_bus_config_setup_leaf(dev_info_t *parent, char *cname, char *caddr)
{
	dev_info_t *child;
	char *compat_name;
	char *nodetype;
	int rval;
	int i;

	ASSERT(parent != 0);
	ASSERT(cname != NULL);
	ASSERT(caddr != NULL);

	/*
	 * if we already have a node with this name, return it
	 */
	if ((child = pshot_findchild(parent, cname, caddr)) != NULL) {
		/*
		 * create the "no-involuntary-power-cycles" or
		 * the "dependency-property" property, if they
		 * don't already exit
		 */
		(void) pshot_leaf_properties(parent, child, cname, caddr);

		return (NDI_SUCCESS);
	}

	ndi_devi_alloc_sleep(parent, cname, DEVI_SID_NODEID, &child);
	ASSERT(child != NULL);

	if (ndi_prop_update_string(DDI_DEV_T_NONE, child, "bus-addr",
	    caddr) != DDI_PROP_SUCCESS) {
		(void) ndi_devi_free(child);
		return (NDI_FAILURE);
	}

	/*
	 * test compatible naming
	 * if the child nodename is "cdisk", attach the list of compatible
	 * named disks
	 */
	if (strcmp(cname, pshot_compat_diskname) == 0) {
		if ((ndi_prop_update_string_array(DDI_DEV_T_NONE,
		    child, "compatible", (char **)pshot_compat_psramdisks,
		    5)) != DDI_PROP_SUCCESS) {
			(void) ndi_devi_free(child);
			return (NDI_FAILURE);
		}
	} else {
		for (i = 0; i < pshot_devices_len && pshot_devices[i].name;
		    i++) {
			if (strcmp(cname, pshot_devices[i].name) == 0) {
				compat_name = pshot_devices[i].compat;
				nodetype = pshot_devices[i].nodetype;
				if (pshot_debug) {
					cmn_err(CE_CONT, "pshot%d: %s %s %s\n",
					    ddi_get_instance(parent), cname,
					    compat_name, nodetype);
				}
				if ((ndi_prop_update_string_array(
				    DDI_DEV_T_NONE, child, "compatible",
				    &compat_name, 1)) != DDI_PROP_SUCCESS) {
					(void) ndi_devi_free(child);
					return (NDI_FAILURE);
				}
				if ((ndi_prop_update_string(
				    DDI_DEV_T_NONE, child, "node-type",
				    nodetype)) != DDI_PROP_SUCCESS) {
					(void) ndi_devi_free(child);
					return (NDI_FAILURE);
				}
			}
		}
	}

	rval = ndi_devi_bind_driver(child, 0);
	if (rval != NDI_SUCCESS) {
		cmn_err(CE_WARN, "pshot%d: bind_driver %s failed",
		    ddi_get_instance(parent), cname);
		(void) ndi_devi_free(child);
		return (NDI_FAILURE);
	}

	/*
	 * create the "no-involuntary-power-cycles" or
	 * the "dependency-property" property
	 */
	(void) pshot_leaf_properties(parent, child, cname, caddr);

	return (NDI_SUCCESS);
}

/*
 * Handle some special cases for testing bus_config via pshot
 *
 * Match these special address formats to behavior:
 *
 *	err.*		- induce bus_config error
 *	delay		- induce 1 second of bus_config delay time
 *	delay,n		- induce n seconds of bus_config delay time
 *	wait		- induce 1 second of bus_config wait time
 *	wait,n		- induce n seconds of bus_config wait time
 *	failinit.*	- induce error at INITCHILD
 *	failprobe.*	- induce error at probe
 *	failattach.*	- induce error at attach
 */
/*ARGSUSED*/
static int
pshot_bus_config_test_specials(dev_info_t *parent, char *devname,
	char *cname, char *caddr)
{
	char	*p;
	int	n;

	if (strncmp(caddr, "err", 3) == 0) {
		if (pshot_debug)
			cmn_err(CE_CONT,
			    "pshot%d: %s forced failure\n",
			    ddi_get_instance(parent), devname);
		return (NDI_FAILURE);
	}

	/*
	 * The delay and wait strings have the same effect.
	 * The "wait[,]" support should be removed once the
	 * devfs test suites are fixed.
	 * NOTE: delay should not be called from interrupt context
	 */
	ASSERT(!servicing_interrupt());

	if (strncmp(caddr, "delay,", 6) == 0) {
		p = caddr+6;
		n = stoi(&p);
		if (*p != 0)
			n = 1;
		if (pshot_debug)
			cmn_err(CE_CONT,
			    "pshot%d: %s delay %d second\n",
			    ddi_get_instance(parent), devname, n);
		delay(n * drv_usectohz(1000000));
	} else if (strncmp(caddr, "delay", 5) == 0) {
		if (pshot_debug)
			cmn_err(CE_CONT,
			    "pshot%d: %s delay 1 second\n",
			    ddi_get_instance(parent), devname);
		delay(drv_usectohz(1000000));
	} else if (strncmp(caddr, "wait,", 5) == 0) {
		p = caddr+5;
		n = stoi(&p);
		if (*p != 0)
			n = 1;
		if (pshot_debug)
			cmn_err(CE_CONT,
			    "pshot%d: %s wait %d second\n",
			    ddi_get_instance(parent), devname, n);
		delay(n * drv_usectohz(1000000));
	} else if (strncmp(caddr, "wait", 4) == 0) {
		if (pshot_debug)
			cmn_err(CE_CONT,
			    "pshot%d: %s wait 1 second\n",
			    ddi_get_instance(parent), devname);
		delay(drv_usectohz(1000000));
	}

	return (NDI_SUCCESS);
}

/*
 * translate nodetype name to actual value
 */
static char *
pshot_str2nt(char *str)
{
	int i;

	for (i = 0; pshot_nodetypes[i].name; i++) {
		if (strcmp(pshot_nodetypes[i].name, str) == 0)
			return (pshot_nodetypes[i].val);
	}
	return (NULL);
}

/*
 * grows array pointed to by <dstp>, with <src> data
 * <dstlen> = # elements of the original <*dstp>
 * <srclen> = # elements of <src>
 *
 * on success, returns 0 and a pointer to the new array through <dstp> with
 * <srclen> + <dstlen> number of elements;
 * else returns non-zero
 *
 * a NULL <*dstp> is OK (a NULL <dstp> is not) and so is a zero <dstlen>
 */
static int
pshot_devices_grow(pshot_device_t **dstp, size_t dstlen,
    const pshot_device_t *src, size_t srclen)
{
	size_t i;
	pshot_device_t *newdst;

	newdst = kmem_alloc((srclen + dstlen) * sizeof (*src),
	    KM_SLEEP);

	/* keep old pointers and dup new ones */
	if (*dstp)
		bcopy(*dstp, newdst, dstlen * sizeof (*src));
	for (i = 0; i < srclen; i++) {
		newdst[i + dstlen].name =
		    i_ddi_strdup(src[i].name, KM_SLEEP);

		newdst[i + dstlen].nodetype =
		    i_ddi_strdup(src[i].nodetype, KM_SLEEP);

		newdst[i + dstlen].compat =
		    i_ddi_strdup(src[i].compat, KM_SLEEP);
	}

	/* do last */
	if (*dstp)
		kmem_free(*dstp, dstlen * sizeof (*src));
	*dstp = newdst;
	return (0);
}

/*
 * free a pshot_device_t array <dp> with <len> elements
 * null pointers within the elements are ok
 */
static void
pshot_devices_free(pshot_device_t *dp, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (dp[i].name)
			kmem_free(dp[i].name, strlen(dp[i].name) + 1);
		if (dp[i].nodetype)
			kmem_free(dp[i].nodetype, strlen(dp[i].nodetype) + 1);
		if (dp[i].compat)
			kmem_free(dp[i].compat, strlen(dp[i].compat) + 1);
	}
	kmem_free(dp, len * sizeof (*dp));
}

/*
 * returns an array of pshot_device_t parsed from <dip>'s properties
 *
 * property structure (i.e. pshot.conf) for pshot:
 *
 * corresponding         |   pshot_device_t array elements
 * pshot_device_t        |
 * member by prop name   |   [0]            [1]           [2]
 * ----------------------|--------------|-------------|-----------------------
 * <PSHOT_PROP_DEVNAME>  ="disk",        "tape",       "testdev";
 * <PSHOT_PROP_DEVNT>    ="DDI_NT_BLOCK","DDI_NT_TAPE","ddi_testdev_nodetype";
 * <PSHOT_PROP_DEVCOMPAT>="testdrv",     "testdrv",    "testdrv";
 *
 *
 * if any of these properties are specified, then:
 * - all the members must be specified
 * - the number of elements for each string array property must be the same
 * - no empty strings allowed
 * - nodetypes (PSHOT_PROP_DEVNT) must be the nodetype name as specified in
 *   sys/sunddi.h
 *
 * NOTE: the pshot_nodetypes[] table should be kept in sync with the list
 * of ddi nodetypes.  It's not normally critical to always be in sync so
 * keeping this up-to-date can usually be done "on-demand".
 *
 * if <flags> & PSHOT_DEV_ANYNT, then custom nodetype strings are allowed.
 * these will be duplicated verbatim
 */
static pshot_device_t *
pshot_devices_from_props(dev_info_t *dip, size_t *lenp, int flags)
{
	pshot_device_t *devarr = NULL;
	char **name_arr = NULL, **nt_arr = NULL, **compat_arr = NULL;
	uint_t name_arr_len, nt_arr_len, compat_arr_len;
	uint_t i;
	char *str;

	if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, dip, 0,
	    PSHOT_PROP_DEVNAME, &name_arr, &name_arr_len) !=
	    DDI_PROP_SUCCESS)
		name_arr = NULL;

	if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, dip, 0,
	    PSHOT_PROP_DEVNT, &nt_arr, &nt_arr_len) !=
	    DDI_PROP_SUCCESS)
		nt_arr = NULL;

	if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, dip, 0,
	    PSHOT_PROP_DEVCOMPAT, &compat_arr, &compat_arr_len) !=
	    DDI_PROP_SUCCESS)
		compat_arr = NULL;

	/*
	 * warn about any incorrect usage, if specified
	 */
	if (!(name_arr || nt_arr || compat_arr))
		return (NULL);

	if (!(name_arr && nt_arr && compat_arr) ||
	    (name_arr_len != nt_arr_len) ||
	    (name_arr_len != compat_arr_len))
		goto FAIL;

	for (i = 0; i < name_arr_len; i++) {
		if (*name_arr[i] == '\0' ||
		    *nt_arr[i] == '\0' ||
		    *compat_arr[i] == '\0')
			goto FAIL;
	}

	devarr = kmem_zalloc(name_arr_len * sizeof (*devarr), KM_SLEEP);
	for (i = 0; i < name_arr_len; i++) {
		devarr[i].name = i_ddi_strdup(name_arr[i], KM_SLEEP);
		devarr[i].compat = i_ddi_strdup(compat_arr[i], KM_SLEEP);

		if ((str = pshot_str2nt(nt_arr[i])) == NULL)
			if (flags & PSHOT_DEV_ANYNT)
				str = nt_arr[i];
			else
				goto FAIL;
		devarr[i].nodetype = i_ddi_strdup(str, KM_SLEEP);
	}
	ddi_prop_free(name_arr);
	ddi_prop_free(nt_arr);
	ddi_prop_free(compat_arr);

	/* set <*lenp> ONLY on success */
	*lenp = name_arr_len;

	return (devarr);
	/*NOTREACHED*/
FAIL:
	cmn_err(CE_WARN, "malformed device specification property");
	if (name_arr)
		ddi_prop_free(name_arr);
	if (nt_arr)
		ddi_prop_free(nt_arr);
	if (compat_arr)
		ddi_prop_free(compat_arr);
	if (devarr)
		pshot_devices_free(devarr, name_arr_len);
	return (NULL);
}

/*
 * if global <pshot_devices> was not set up already (i.e. is NULL):
 *	sets up global <pshot_devices> and <pshot_devices_len>,
 *	using device properties	from <dip> and global <pshot_stock_devices>.
 *	device properties, if any, overrides pshot_stock_devices.
 *
 * returns 0 on success (or if pshot_devices already set up)
 *
 * INTERNAL LOCKING: <pshot_devices_lock>
 */
static int
pshot_devices_setup(dev_info_t *dip)
{
	pshot_device_t *newdevs = NULL;
	size_t newdevs_len = 0;
	int rv = 0;

	mutex_enter(&pshot_devices_lock);
	if (pshot_devices != NULL)
		goto FAIL;

	ASSERT(pshot_devices_len == 0);

	newdevs = pshot_devices_from_props(dip, &newdevs_len, PSHOT_DEV_ANYNT);
	rv = pshot_devices_grow(&newdevs, newdevs_len, pshot_stock_devices,
	    PSHOT_N_STOCK_DEVICES);
	if (rv != 0) {
		cmn_err(CE_WARN, "pshot_devices_setup: pshot_devices_grow "
		    "failed");
		goto FAIL;
	}
	newdevs_len += PSHOT_N_STOCK_DEVICES;

	pshot_devices = newdevs;
	pshot_devices_len = newdevs_len;
	rv = 0;
FAIL:
	if (rv && newdevs)
		pshot_devices_free(newdevs, newdevs_len);
	mutex_exit(&pshot_devices_lock);
	return (rv);
}


#ifdef NOTNEEDED
/* ARGSUSED */
static int
pshot_probe_family(dev_info_t *self, ddi_probe_method_t probe_how,
    dev_info_t **return_dip)
{
	char name[64];
	uint_t bus_id;
	dev_info_t *child;

	for (bus_id = 10; bus_id < 20; bus_id++) {
		(void) sprintf(name, "%d", bus_id);
		if ((ndi_devi_alloc(self, "psramd", DEVI_SID_NODEID,
		    &child)) != NDI_SUCCESS) {
			return (DDI_FAILURE);
		}

		if (ndi_prop_update_string(DDI_DEV_T_NONE, child,
		    "bus-addr", name) != DDI_PROP_SUCCESS) {
			(void) ndi_devi_free(child);
			if (return_dip != NULL)
				*return_dip = (dev_info_t *)NULL;
			return (DDI_FAILURE);
		}

		if (ndi_devi_online(child, 0) != NDI_SUCCESS) {
			return (DDI_FAILURE);
		}
	}
	return (DDI_SUCCESS);
}

static int
strtoi(char *str)
{
	int c;
	int val;

	for (val = 0, c = *str++; c >= '0' && c <= '9'; c = *str++) {
		val *= 10;
		val += c - '0';
	}
	return (val);
}

#endif

static void
pshot_setup_autoattach(dev_info_t *devi)
{
	dev_info_t *l1child, *l2child;
	int rv;

	rv = ndi_devi_alloc(devi, "pshot", DEVI_SID_NODEID, &l1child);
	if (rv == NDI_SUCCESS) {
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, l1child,
		    "bus-addr", "0");
		rv =  ndi_devi_alloc(l1child, "port", DEVI_SID_NODEID,
		    &l2child);
		if (rv == NDI_SUCCESS)
			(void) ndi_prop_update_string(DDI_DEV_T_NONE,
			    l2child, "bus-addr", "99");
	}

	rv = ndi_devi_alloc(devi, "port", DEVI_SID_NODEID, &l1child);
	if (rv == NDI_SUCCESS)
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, l1child,
		    "bus-addr", "99");

	rv = ndi_devi_alloc(devi, "gen_drv", DEVI_SID_NODEID, &l1child);
	if (rv == NDI_SUCCESS)
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, l1child,
		    "bus-addr", "99");

	rv = ndi_devi_alloc(devi, "no_driver", DEVI_SID_NODEID, &l1child);
	if (rv == NDI_SUCCESS)
		(void) ndi_devi_alloc(l1child, "no_driver", DEVI_SID_NODEID,
		    &l2child);
}

#ifdef PRUNE_SNUBS

#define	PRUNE_THIS_NODE(d) (((d)->devi_node_name != NULL) && \
	(DEVI_PROM_NODE((d)->devi_nodeid)) && \
	((d)->devi_addr == NULL))
/*
 * test code to remove OBP nodes that have not attached
 */
static void
prune_snubs(const char *name)
{
	struct dev_info *nex_dip, *cdip, *cndip;
	int maj;
	int rv;

	maj = ddi_name_to_major((char *)name);
	if (maj != -1) {
		nex_dip = (struct dev_info *)devnamesp[maj].dn_head;
		while (nex_dip != NULL) {
			cndip = ddi_get_child(nex_dip);
			while ((cdip = cndip) != NULL) {
				cndip = cdip->devi_sibling;
				if (PRUNE_THIS_NODE(cdip)) {
					cmn_err(CE_NOTE,
					    "parent %s@%s pruning node %s",
					    nex_dip->devi_node_name,
					    nex_dip->devi_addr,
					    cdip->devi_node_name);
					rv = ndi_devi_offline(cdip,
					    NDI_DEVI_REMOVE);
					if (rv != NDI_SUCCESS)
						cmn_err(CE_NOTE,
						    "failed to prune node, "
						    "err %d", rv);
				}
			}
		nex_dip = nex_dip->devi_next;
		}
	}
}

#endif /* PRUBE_SNUBS */

#ifdef KERNEL_DEVICE_TREE_WALKER
static kthread_id_t pwt;
static kmutex_t pwl;
static kcondvar_t pwcv;

static void
pshot_walk_tree()
{
	static int pshot_devnode(dev_info_t *dip, void * arg);

	dev_info_t *root = ddi_root_node();
	ddi_walk_devs(root, pshot_devnode, NULL);
}

static void
pshot_walk_thread()
{
	static void pshot_timeout(void *arg);
	static kthread_id_t pwt;

	pwt = curthread;
	mutex_init(&pwl, NULL, MUTEX_DRIVER, NULL);
	cv_init(&pwcv, NULL, CV_DRIVER, NULL);

	while (1) {
		pshot_walk_tree();
		mutex_enter(&pwl);
		(void) timeout(pshot_timeout, NULL, 5 * drv_usectohz(1000000));
		cv_wait(&pwcv, &pwl);
		mutex_exit(&pwl);
	}
}

static void
pshot_timeout(void *arg)
{
	mutex_enter(&pwl);
	cv_signal(&pwcv);
	mutex_exit(&pwl);
}

static int
pshot_devnode(dev_info_t *dip, void *arg)
{
	dev_info_t *f_dip;

	if (dip != ddi_root_node()) {
		f_dip = ndi_devi_find((dev_info_t *)DEVI(dip)->devi_parent,
		    DEVI(dip)->devi_node_name, DEVI(dip)->devi_addr);
		if (f_dip != dip) {
			cmn_err(CE_NOTE, "!pshot_devnode: failed lookup"
			    "node (%s/%s@%s)\n",
			    DEVI(DEVI(dip)->devi_parent)->devi_node_name,
			    (DEVI(dip)->devi_node_name ?
			    DEVI(dip)->devi_node_name : "NULL"),
			    (DEVI(dip)->devi_addr ? DEVI(dip)->devi_addr :
			    "NULL"));
		}
	}
	return (DDI_WALK_CONTINUE);
}
#endif /* KERNEL_DEVICE_TREE_WALKER */

#ifdef DEBUG
static void
pshot_event_cb_test(dev_info_t *dip, ddi_eventcookie_t cookie,
	void *arg, void *bus_impldata)
{
	pshot_t *softstate = (pshot_t *)arg;
	int event_tag;

	/* look up the event */
	event_tag = NDI_EVENT_TAG(cookie);
	cmn_err(CE_CONT, "pshot_event_cb_test:\n\t"
	    "dip = 0x%p cookie = 0x%p (%s), tag = %d\n\t"
	    "arg = 0x%p bus_impl = 0x%p\n",
	    (void *)dip, (void *)cookie, NDI_EVENT_NAME(cookie),
	    event_tag, (void *)softstate, (void *)bus_impldata);

}

static void
pshot_event_test(void *arg)
{
	pshot_t *pshot = (pshot_t *)arg;
	ndi_event_hdl_t hdl;
	ndi_event_set_t	events;
	int i, rval;

	(void) ndi_event_alloc_hdl(pshot->dip, NULL, &hdl, NDI_SLEEP);

	events.ndi_events_version = NDI_EVENTS_REV1;
	events.ndi_n_events = PSHOT_N_TEST_EVENTS;
	events.ndi_event_defs = pshot_test_events;

	cmn_err(CE_CONT, "pshot: binding set of 8 events\n");
	delay(drv_usectohz(1000000));
	rval = ndi_event_bind_set(hdl, &events, NDI_SLEEP);
	cmn_err(CE_CONT, "pshot: ndi_event_bind_set rval = %d\n", rval);

	cmn_err(CE_CONT, "pshot: binding the same set of 8 events\n");
	delay(drv_usectohz(1000000));
	rval = ndi_event_bind_set(hdl, &events, NDI_SLEEP);
	cmn_err(CE_CONT, "pshot: ndi_event_bind_set rval = %d\n", rval);

	cmn_err(CE_CONT, "pshot: unbinding  all events\n");
	delay(drv_usectohz(1000000));
	rval = ndi_event_unbind_set(hdl, &events, NDI_SLEEP);
	cmn_err(CE_CONT, "pshot: ndi_event_unbind_set rval = %d\n", rval);


	cmn_err(CE_CONT, "pshot: binding one highlevel event\n");
	delay(drv_usectohz(1000000));
	events.ndi_n_events = 1;
	events.ndi_event_defs = pshot_test_events_high;
	rval = ndi_event_bind_set(hdl, &events, NDI_SLEEP);
	cmn_err(CE_CONT, "pshot: ndi_event_bind_set rval = %d\n", rval);

	cmn_err(CE_CONT, "pshot: binding the same set of 8 events\n");
	delay(drv_usectohz(1000000));
	events.ndi_n_events = PSHOT_N_TEST_EVENTS;
	events.ndi_event_defs = pshot_test_events;
	rval = ndi_event_bind_set(hdl, &events, NDI_SLEEP);
	cmn_err(CE_CONT, "pshot: ndi_event_bind_set rval = %d\n", rval);

	cmn_err(CE_CONT, "pshot: unbinding one highlevel event\n");
	delay(drv_usectohz(1000000));
	events.ndi_n_events = 1;
	events.ndi_event_defs = pshot_test_events_high;
	rval = ndi_event_unbind_set(hdl, &events, NDI_SLEEP);
	cmn_err(CE_CONT, "pshot: ndi_event_bind_set rval = %d\n", rval);

	cmn_err(CE_CONT, "pshot: binding one highlevel event\n");
	delay(drv_usectohz(1000000));
	events.ndi_n_events = 1;
	events.ndi_event_defs = pshot_test_events_high;
	rval = ndi_event_bind_set(hdl, &events, NDI_SLEEP);
	cmn_err(CE_CONT, "pshot: ndi_event_bind_set rval = %d\n", rval);

	cmn_err(CE_CONT, "pshot: unbinding one highlevel event\n");
	delay(drv_usectohz(1000000));
	events.ndi_n_events = 1;
	events.ndi_event_defs = pshot_test_events_high;
	rval = ndi_event_unbind_set(hdl, &events, NDI_SLEEP);
	cmn_err(CE_CONT, "pshot: ndi_event_bind_set rval = %d\n", rval);

	cmn_err(CE_CONT, "pshot: binding the same set of 8 events\n");
	delay(drv_usectohz(1000000));
	events.ndi_n_events = PSHOT_N_TEST_EVENTS;
	events.ndi_event_defs = pshot_test_events;
	rval = ndi_event_bind_set(hdl, &events, NDI_SLEEP);
	cmn_err(CE_CONT, "pshot: ndi_event_bind_set rval = %d\n", rval);

	cmn_err(CE_CONT, "pshot: unbinding first 2 events\n");
	delay(drv_usectohz(1000000));
	events.ndi_n_events = 2;
	events.ndi_event_defs = pshot_test_events;
	rval = ndi_event_unbind_set(hdl, &events, NDI_SLEEP);
	cmn_err(CE_CONT, "pshot: ndi_event_unbind_set rval = %d\n", rval);

	cmn_err(CE_CONT, "pshot: unbinding first 2 events again\n");
	delay(drv_usectohz(1000000));
	events.ndi_n_events = 2;
	events.ndi_event_defs = pshot_test_events;
	rval = ndi_event_unbind_set(hdl, &events, NDI_SLEEP);
	cmn_err(CE_CONT, "pshot: ndi_event_unbind_set rval = %d\n", rval);

	cmn_err(CE_CONT, "pshot: unbinding  middle 2 events\n");
	delay(drv_usectohz(1000000));
	events.ndi_n_events = 2;
	events.ndi_event_defs = &pshot_test_events[4];
	rval = ndi_event_unbind_set(hdl, &events, NDI_SLEEP);
	cmn_err(CE_CONT, "pshot: ndi_event_unbind_set rval = %d\n", rval);

	cmn_err(CE_CONT, "pshot: binding those 2 events back\n");
	delay(drv_usectohz(1000000));
	events.ndi_n_events = 2;
	events.ndi_event_defs = &pshot_test_events[4];
	rval = ndi_event_bind_set(hdl, &events, NDI_SLEEP);
	cmn_err(CE_CONT, "pshot: ndi_event_bind_set rval = %d\n", rval);

	cmn_err(CE_CONT, "pshot: unbinding  2 events\n");
	delay(drv_usectohz(1000000));
	events.ndi_n_events = 2;
	events.ndi_event_defs = &pshot_test_events[4];
	rval = ndi_event_unbind_set(hdl, &events, NDI_SLEEP);
	cmn_err(CE_CONT, "pshot: ndi_event_unbind_set rval = %d\n", rval);

	cmn_err(CE_CONT, "pshot: unbinding  all events\n");
	delay(drv_usectohz(1000000));
	events.ndi_n_events = PSHOT_N_TEST_EVENTS;
	events.ndi_event_defs = pshot_test_events;
	rval = ndi_event_unbind_set(hdl, &events, NDI_SLEEP);
	cmn_err(CE_CONT, "pshot: ndi_event_unbind_set rval = %d\n", rval);

	cmn_err(CE_CONT, "pshot: unbinding  1 event\n");
	delay(drv_usectohz(1000000));
	events.ndi_n_events = 1;
	events.ndi_event_defs = &pshot_test_events[2];
	rval = ndi_event_unbind_set(hdl, &events, NDI_SLEEP);
	cmn_err(CE_CONT, "pshot: ndi_event_unbind_set rval = %d\n", rval);

	cmn_err(CE_CONT, "pshot: unbinding  1 event\n");
	delay(drv_usectohz(1000000));
	events.ndi_n_events = 1;
	events.ndi_event_defs = &pshot_test_events[3];
	rval = ndi_event_unbind_set(hdl, &events, NDI_SLEEP);
	cmn_err(CE_CONT, "pshot: ndi_event_unbind_set rval = %d\n", rval);

	cmn_err(CE_CONT, "pshot: unbinding  1 event\n");
	delay(drv_usectohz(1000000));
	events.ndi_n_events = 1;
	events.ndi_event_defs = &pshot_test_events[6];
	rval = ndi_event_unbind_set(hdl, &events, NDI_SLEEP);
	cmn_err(CE_CONT, "pshot: ndi_event_unbind_set rval = %d\n", rval);

	cmn_err(CE_CONT, "pshot: unbinding  1 event\n");
	delay(drv_usectohz(1000000));
	events.ndi_n_events = 1;
	events.ndi_event_defs = &pshot_test_events[7];
	rval = ndi_event_unbind_set(hdl, &events, NDI_SLEEP);
	cmn_err(CE_CONT, "pshot: ndi_event_unbind_set rval = %d\n", rval);

	events.ndi_n_events = PSHOT_N_TEST_EVENTS;
	events.ndi_event_defs = pshot_test_events;

	cmn_err(CE_CONT, "pshot: binding set of 8 events\n");
	delay(drv_usectohz(1000000));
	rval = ndi_event_bind_set(hdl, &events, NDI_SLEEP);
	cmn_err(CE_CONT, "pshot: ndi_event_bind_set rval = %d\n", rval);

	cmn_err(CE_CONT, "pshot: adding 8 callbacks\n");
	delay(drv_usectohz(1000000));
	for (i = 0; i < 8; i++) {
		rval = ndi_event_add_callback(hdl, pshot->dip,
		    ndi_event_tag_to_cookie(hdl,
		    pshot_test_events[i].ndi_event_tag),
		    pshot_event_cb_test,
		    (void *)(uintptr_t)pshot_test_events[i].ndi_event_tag,
		    NDI_SLEEP, &pshot->test_callback_cache[i]);
		ASSERT(rval == NDI_SUCCESS);
	}

	cmn_err(CE_CONT, "pshot: event callbacks\n");

	for (i = 10; i < 18; i++) {
		ddi_eventcookie_t cookie = ndi_event_tag_to_cookie(hdl, i);

		rval = ndi_event_run_callbacks(hdl, pshot->dip, cookie,
		    (void *)hdl);

		cmn_err(CE_CONT, "pshot: callback, tag=%d rval=%d\n",
		    i, rval);
		delay(drv_usectohz(1000000));
	}

	cmn_err(CE_CONT, "pshot: redo event callbacks\n");

	for (i = 10; i < 18; i++) {
		ddi_eventcookie_t cookie = ndi_event_tag_to_cookie(hdl, i);

		rval = ndi_event_run_callbacks(hdl,
		    pshot->dip, cookie, (void *)hdl);

		cmn_err(CE_CONT, "pshot: callback, tag=%d rval=%d\n",
		    i, rval);
		delay(drv_usectohz(1000000));
	}

	cmn_err(CE_CONT, "pshot: removing 8 callbacks\n");
	delay(drv_usectohz(1000000));

	for (i = 0; i < 8; i++) {
		(void) ndi_event_remove_callback(hdl,
		    pshot->test_callback_cache[i]);

		pshot->test_callback_cache[i] = 0;
	}

	cmn_err(CE_CONT, "pshot: freeing handle with bound set\n");
	delay(drv_usectohz(1000000));

	rval =	ndi_event_free_hdl(hdl);

	ASSERT(rval == NDI_SUCCESS);

}

void
pshot_event_test_post_one(void *arg)
{
	pshot_t	*pshot = (pshot_t *)arg;
	int rval;
	ddi_eventcookie_t cookie;

	cmn_err(CE_CONT, "pshot%d: pshot_event_post_one event\n",
	    pshot->instance);

	if (ddi_get_eventcookie(pshot->dip, PSHOT_EVENT_NAME_BUS_TEST_POST,
	    &cookie) != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "pshot_bus_test_post cookie not found");
		return;
	}

	rval = ndi_post_event(pshot->dip, pshot->dip, cookie, NULL);

	cmn_err(CE_CONT, "pshot%d: pshot_event_post_one rval=%d\n",
	    pshot->instance, rval);

	(void) timeout(pshot_event_test_post_one, (void *)pshot,
	    pshot->instance * drv_usectohz(60000000));

}
#endif /* DEBUG */

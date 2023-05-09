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
 * Copyright 2023 Oxide Computer Company
 */

/*
 * **********************************************************************
 * Extension module for PCI nexus drivers to support PCI Hot Plug feature.
 *
 * DESCRIPTION:
 *    This module basically implements "devctl" and Attachment Point device
 *    nodes for hot plug operations. The cb_ops functions needed for access
 *    to these device nodes are also implemented. For hotplug operations
 *    on Attachment Points it interacts with the hotplug services (HPS)
 *    framework. A pci nexus driver would simply call pcihp_init() in its
 *    attach() function and pcihp_uninit() call in its detach() function.
 * **********************************************************************
 */

#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/modctl.h>
#include <sys/autoconf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ndi_impldefs.h>
#include <sys/ddipropdefs.h>
#include <sys/open.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/pci.h>
#include <sys/pci_impl.h>
#include <sys/devctl.h>
#include <sys/hotplug/hpcsvc.h>
#include <sys/hotplug/pci/pcicfg.h>
#include <sys/hotplug/pci/pcihp.h>
#include <sys/sysevent.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/dr.h>
#include <sys/fs/dv_node.h>

/*
 * NOTE:
 * This module depends on PCI Configurator module (misc/pcicfg),
 * Hot Plug Services framework module (misc/hpcsvc) and Bus Resource
 * Allocator module (misc/busra).
 */

/*
 * ************************************************************************
 * *** Implementation specific data structures/definitions.		***
 * ************************************************************************
 */

/* soft state */
typedef enum { PCIHP_SOFT_STATE_CLOSED, PCIHP_SOFT_STATE_OPEN,
		PCIHP_SOFT_STATE_OPEN_EXCL } pcihp_soft_state_t;

#define	PCI_MAX_DEVS	32	/* max. number of devices on a pci bus */

/* the following correspond to sysevent defined subclasses */
#define	PCIHP_DR_AP_STATE_CHANGE	0
#define	PCIHP_DR_REQ			1

/*  pcihp_get_soft_state() command argument */
#define	PCIHP_DR_NOOP			0
#define	PCIHP_DR_BUS_CONFIGURE		1
#define	PCIHP_DR_BUS_UNCONFIGURE	2
#define	PCIHP_DR_SLOT_ENTER		4
#define	PCIHP_DR_SLOT_EXIT		8

/*  hot plug bus state */
enum { PCIHP_BUS_INITIALIZING, PCIHP_BUS_UNCONFIGURED,
		PCIHP_BUS_CONFIGURED };

/*
 * Soft state structure associated with each hot plug pci bus instance.
 */
typedef struct pcihp {
	struct pcihp		*nextp;

	/* devinfo pointer to the pci bus node */
	dev_info_t		*dip;

	/* soft state flags: PCIHP_SOFT_STATE_* */
	pcihp_soft_state_t	soft_state;

	/* global mutex to serialize exclusive access to the bus */
	kmutex_t		mutex;

	/* slot information structure */
	struct pcihp_slotinfo {
		hpc_slot_t	slot_hdl;	/* HPS slot handle */
		ap_rstate_t	rstate;		/* state of Receptacle */
		ap_ostate_t	ostate;		/* state of the Occupant */
		ap_condition_t	condition;	/* condition of the occupant */
		time32_t	last_change;	/* XXX needed? */
		uint32_t	event_mask;	/* last event mask registered */
		char		*name;		/* slot logical name */
		uint_t		slot_flags;
		uint16_t	slot_type;	/* slot type: pci or cpci */
		uint16_t	slot_capabilities; /* 64bit, etc. */
		int		hs_csr_location; /* Location of HS_CSR */
		kmutex_t	slot_mutex;	/* mutex to serialize hotplug */
						/* operations on the slot */
	} slotinfo[PCI_MAX_DEVS];

	/* misc. bus attributes */
	uint_t			bus_flags;
	uint_t			bus_state;
	uint_t			slots_active;
} pcihp_t;

/*
 * Bit definitions for slot_flags field:
 *
 *	PCIHP_SLOT_AUTO_CFG_EN	This flags is set if nexus can do auto
 *				configuration of hot plugged card on this slot
 *				if the hardware reports the hot plug events.
 *
 *	PCIHP_SLOT_DISABLED	Slot is disabled for hotplug operations.
 *
 *	PCIHP_SLOT_NOT_HEALTHY	HEALTHY# signal is not OK on this slot.
 */
#define	PCIHP_SLOT_AUTO_CFG_EN		0x1
#define	PCIHP_SLOT_DISABLED		0x2
#define	PCIHP_SLOT_NOT_HEALTHY		0x4
#define	PCIHP_SLOT_DEV_NON_HOTPLUG	0x8
#define	PCIHP_SLOT_ENUM_INS_PENDING	0x10
#define	PCIHP_SLOT_ENUM_EXT_PENDING	0x20

/*
 * Bit definitions for bus_flags field:
 *
 *	PCIHP_BUS_66MHZ	Bus is running at 66Mhz.
 */
#define	PCIHP_BUS_66MHZ		0x1
#define	PCIHP_BUS_ENUM_RADIAL	0x2

#define	PCIHP_DEVICES_STR		"/devices"

/*
 * control structure for tree walk during configure/unconfigure operation.
 */
struct pcihp_config_ctrl {
	int	pci_dev;	/* PCI device number for the slot */
	uint_t	flags;		/* control flags (see below) */
	int	op;		/* operation: PCIHP_ONLINE or PCIHP_OFFLINE */
	int	rv;		/* return error code */
	dev_info_t *dip;	/* dip at which the (first) error occurred */
	hpc_occupant_info_t *occupant;
};

/*
 * control flags for configure/unconfigure operations on the tree.
 *
 * PCIHP_CFG_CONTINUE	continue the operation ignoring errors
 */
#define	PCIHP_CFG_CONTINUE	0x1

#define	PCIHP_ONLINE	1
#define	PCIHP_OFFLINE	0


/* Leaf ops (hotplug controls for target devices) */
static int pcihp_open(dev_t *, int, int, cred_t *);
static int pcihp_close(dev_t, int, int, cred_t *);
static int pcihp_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

#ifdef DEBUG
static int pcihp_debug = 0;
#define	PCIHP_DEBUG(args)	if (pcihp_debug >= 1) cmn_err args
#define	PCIHP_DEBUG2(args)	if (pcihp_debug >= 2) cmn_err args
#else
#define	PCIHP_DEBUG(args)
#define	PCIHP_DEBUG2(args)
#endif

/*
 * We process ENUM# event one device at a time ie. as soon as we detect
 * that a device has the right ENUM# conditions, we return. If the following
 * variable is set to non-zero, we scan all the devices on the bus
 * for ENUM# conditions.
 */
static int pcihp_enum_scan_all = 0;
/*
 * If HSC driver cannot determine the board type (for example: it may not
 * be possible to differentiate between a Basic Hotswap, Non Hotswap or
 * Non-friendly Full hotswap board), the default board type is assigned
 * to be as defined by the following variable.
 */
static int pcihp_cpci_board_type = HPC_BOARD_CPCI_NON_HS;
static int pcihp_cpci_led_blink = 30;
/*
 * It was noted that the blue LED when written on/off would cause INS/EXT
 * bit to be set causing an extra interrupt. Although the cPCI specifications
 * does not imply this, this behavior is seen with some FHS silicons.
 * Also, handling the INS/EXT bit would control the LED being On/Off.
 * Until the behavior is confirmed, this flag could be used to enable or
 * disable handling the LED.
 * 0 means the silicons handles the LED behavior via the INS/EXT bit.
 * 1 means the software must explicitly do the LED behavior.
 */
static int pcihp_cpci_blue_led = 1;

/* static functions */
static pcihp_t *pcihp_create_soft_state(dev_info_t *dip);
static void pcihp_destroy_soft_state(dev_info_t *dip);
static pcihp_t *pcihp_get_soft_state(dev_info_t *dip, int cmd, int *rv);
static int pcihp_configure_ap(pcihp_t *pcihp_p, int pci_dev);
static int pcihp_unconfigure_ap(pcihp_t *pcihp_p, int pci_dev);
static int pcihp_new_slot_state(dev_info_t *, hpc_slot_t,
	hpc_slot_info_t *, int);
static int pcihp_configure(dev_info_t *, void *);
static bool_t pcihp_check_status(dev_info_t *);
static int pcihp_event_handler(caddr_t, uint_t);
static dev_info_t *pcihp_devi_find(dev_info_t *dip, uint_t dev, uint_t func);
static int pcihp_match_dev(dev_info_t *dip, void *hdl);
static int pcihp_get_hs_csr(struct pcihp_slotinfo *, ddi_acc_handle_t,
	uint8_t *);
static void pcihp_set_hs_csr(struct pcihp_slotinfo *, ddi_acc_handle_t,
	uint8_t *);
static int pcihp_get_hs_csr_location(ddi_acc_handle_t);
static int pcihp_handle_enum(pcihp_t *, int, int, int);
static void pcihp_hs_csr_op(pcihp_t *, int, int);
static int pcihp_enum_slot(pcihp_t *, struct pcihp_slotinfo *, int, int, int);
static int pcihp_handle_enum_extraction(pcihp_t *, int, int, int);
static int pcihp_handle_enum_insertion(pcihp_t *, int, int, int);
static int pcihp_add_dummy_reg_property(dev_info_t *, uint_t, uint_t, uint_t);
static int pcihp_config_setup(dev_info_t **, ddi_acc_handle_t *,
			dev_info_t **, int, pcihp_t *);
static void pcihp_config_teardown(ddi_acc_handle_t *,
			dev_info_t **, int, pcihp_t *);
static int pcihp_get_board_type(struct pcihp_slotinfo *);
/* sysevent function */
static void pcihp_gen_sysevent(char *, int, int, dev_info_t *, int);

static int pcihp_list_occupants(dev_info_t *, void *);
static int pcihp_indirect_map(dev_info_t *dip);

#if 0
static void pcihp_probe_slot_state(dev_info_t *, int, hpc_slot_state_t *);
#endif

int pcihp_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp);

struct cb_ops pcihp_cb_ops = {
	pcihp_open,			/* open */
	pcihp_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	pcihp_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	pcihp_prop_op,			/* cb_prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};

/*
 * local data
 */

int pcihp_autocfg_enabled = 1; /* auto config is enabled by default */

static kmutex_t pcihp_mutex; /* mutex to protect the following data */
static pcihp_t *pcihp_head = NULL;

static kmutex_t pcihp_open_mutex; /* mutex to protect open/close/uninit */
static int	pci_devlink_flags = 0;

/*
 * Module linkage information for the kernel.
 */
extern struct mod_ops mod_miscops;
static struct modlmisc modlmisc = {
	&mod_miscops,
	"PCI nexus hotplug support",
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modlmisc,
	NULL
};

int
_init(void)
{
	int error;

	mutex_init(&pcihp_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&pcihp_open_mutex, NULL, MUTEX_DRIVER, NULL);
	if ((error = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&pcihp_open_mutex);
		mutex_destroy(&pcihp_mutex);
	}

	return (error);
}

int
_fini(void)
{
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static	pcihp_t *
pcihp_create_soft_state(
	dev_info_t *dip)
{
	pcihp_t	*pcihp_p;

	pcihp_p = kmem_zalloc(sizeof (struct pcihp), KM_SLEEP);

	pcihp_p->dip = dip;
	mutex_init(&pcihp_p->mutex, NULL, MUTEX_DRIVER, NULL);

	mutex_enter(&pcihp_mutex);
	pcihp_p->nextp = pcihp_head;
	pcihp_head = pcihp_p;
	pcihp_p->bus_state = PCIHP_BUS_INITIALIZING;
	pcihp_p->slots_active = 0;
	mutex_exit(&pcihp_mutex);

	return (pcihp_p);
}

static	void
pcihp_destroy_soft_state(
	dev_info_t *dip)
{
	pcihp_t	*p;
	pcihp_t	**pp;

	mutex_enter(&pcihp_mutex);
	pp = &pcihp_head;
	while ((p = *pp) != NULL) {
		if (p->dip == dip) {
			*pp = p->nextp;
			kmem_free(p, sizeof (struct pcihp));
			break;
		}
		pp = &(p->nextp);
	}
	mutex_exit(&pcihp_mutex);
}

/*
 * This function should be imported by client nexus drivers as their
 * devo_getinfo() entry point.
 */

/* ARGSUSED */
int
pcihp_info(
	dev_info_t	*dip,
	ddi_info_cmd_t	cmd,
	void		*arg,
	void		**result)
{
	pcihp_t		*pcihp_p;
	major_t		major;
	minor_t		minor;
	int		instance;

	major = getmajor((dev_t)arg);
	minor = getminor((dev_t)arg);
	instance = PCIHP_AP_MINOR_NUM_TO_INSTANCE(minor);

	switch (cmd) {
	default:
		return (DDI_FAILURE);

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(intptr_t)instance;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2DEVINFO:
		mutex_enter(&pcihp_mutex);
		pcihp_p = pcihp_head;
		while (pcihp_p != NULL) {
			if (ddi_driver_major(pcihp_p->dip) ==
			    major && ddi_get_instance(pcihp_p->dip) ==
			    instance) {
				*result = (void *)pcihp_p->dip;
				mutex_exit(&pcihp_mutex);
				return (DDI_SUCCESS);
			}
			pcihp_p = pcihp_p->nextp;
		}
		mutex_exit(&pcihp_mutex);
		return (DDI_FAILURE);
	}
}

/*
 * This function retrieves the hot plug soft state and performs the
 * following primitive commands while the soft state is locked:
 * mark the bus unconfigured, increment slot activity, decrement
 * slot activity and noop.
 */

/* ARGSUSED */
static	pcihp_t *
pcihp_get_soft_state(
	dev_info_t	*dip, int cmd, int *rv)
{
	pcihp_t		*pcihp_p;

	*rv = PCIHP_SUCCESS;
	mutex_enter(&pcihp_mutex);
	pcihp_p = pcihp_head;
	while (pcihp_p != NULL) {
		if (pcihp_p->dip == dip) {
			switch (cmd) {
			case PCIHP_DR_BUS_UNCONFIGURE:
				if (pcihp_p->slots_active == 0)
					pcihp_p->bus_state =
					    PCIHP_BUS_UNCONFIGURED;
				else
					*rv = PCIHP_FAILURE;
				break;
			case PCIHP_DR_SLOT_ENTER:
				if (pcihp_p->bus_state ==
				    PCIHP_BUS_UNCONFIGURED)
					*rv = PCIHP_FAILURE;
				else
					pcihp_p->slots_active++;
				break;
			case PCIHP_DR_SLOT_EXIT:
				ASSERT(pcihp_p->slots_active > 0);
				if (pcihp_p->slots_active == 0)
					cmn_err(CE_PANIC,
					    "pcihp (%s%d): mismatched slot"
					    " activity",
					    ddi_driver_name(dip),
					    ddi_get_instance(dip));
				else
					pcihp_p->slots_active--;
				break;
			case PCIHP_DR_NOOP:
				break;
			default:
				*rv = PCIHP_FAILURE;
				break;
			}
			mutex_exit(&pcihp_mutex);
			return (pcihp_p);
		}
		pcihp_p = pcihp_p->nextp;
	}
	mutex_exit(&pcihp_mutex);

	return (NULL);
}

/* ARGSUSED3 */
static int
pcihp_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	dev_info_t *self;
	pcihp_t *pcihp_p;
	minor_t	minor;
	int pci_dev;
	int rv;

	/*
	 * Make sure the open is for the right file type.
	 */
	if (otyp != OTYP_CHR)
		return (EINVAL);

	mutex_enter(&pcihp_open_mutex);
	/*
	 * Get the soft state structure.
	 */
	if (pcihp_info(NULL, DDI_INFO_DEVT2DEVINFO, (void *)*devp,
	    (void **)&self) != DDI_SUCCESS) {
		mutex_exit(&pcihp_open_mutex);
		return (ENXIO);
	}

	pcihp_p = pcihp_get_soft_state(self, PCIHP_DR_NOOP, &rv);
	ASSERT(pcihp_p != NULL);

	mutex_enter(&pcihp_p->mutex);

	/*
	 * If the pci_dev is valid then the minor device is an
	 * AP. Otherwise it is ":devctl" minor device.
	 */
	minor = getminor(*devp);
	pci_dev = PCIHP_AP_MINOR_NUM_TO_PCI_DEVNUM(minor);
	if (pci_dev < PCI_MAX_DEVS) {
		struct pcihp_slotinfo *slotinfop;

		slotinfop = &pcihp_p->slotinfo[pci_dev];
		if (slotinfop->slot_hdl == NULL) {
			mutex_exit(&pcihp_p->mutex);
			mutex_exit(&pcihp_open_mutex);
			return (ENXIO);
		}
	}

	/*
	 * Handle the open by tracking the device state.
	 *
	 * Note: Needs review w.r.t exclusive access to AP or the bus.
	 * Currently in the pci plug-in we don't use EXCL open at all
	 * so the code below implements EXCL access on the bus.
	 */

	/* enforce exclusive access to the bus */
	if ((pcihp_p->soft_state == PCIHP_SOFT_STATE_OPEN_EXCL) ||
	    ((flags & FEXCL) &&
	    (pcihp_p->soft_state != PCIHP_SOFT_STATE_CLOSED))) {
		mutex_exit(&pcihp_p->mutex);
		mutex_exit(&pcihp_open_mutex);
		return (EBUSY);
	}

	if (flags & FEXCL)
		pcihp_p->soft_state = PCIHP_SOFT_STATE_OPEN_EXCL;
	else
		pcihp_p->soft_state = PCIHP_SOFT_STATE_OPEN;

	mutex_exit(&pcihp_p->mutex);
	mutex_exit(&pcihp_open_mutex);

	return (0);
}

/* ARGSUSED */
static int
pcihp_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	dev_info_t *self;
	pcihp_t *pcihp_p;
	int rv;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	mutex_enter(&pcihp_open_mutex);

	if (pcihp_info(NULL, DDI_INFO_DEVT2DEVINFO, (void *)dev,
	    (void **)&self) != DDI_SUCCESS) {
		mutex_exit(&pcihp_open_mutex);
		return (ENXIO);
	}

	pcihp_p = pcihp_get_soft_state(self, PCIHP_DR_NOOP, &rv);
	ASSERT(pcihp_p != NULL);

	mutex_enter(&pcihp_p->mutex);
	pcihp_p->soft_state = PCIHP_SOFT_STATE_CLOSED;
	mutex_exit(&pcihp_p->mutex);

	mutex_exit(&pcihp_open_mutex);

	return (0);
}

static int
pcihp_list_occupants(dev_info_t *dip, void *hdl)
{
	int pci_dev;
	struct pcihp_config_ctrl *ctrl = (struct pcihp_config_ctrl *)hdl;
	pci_regspec_t *pci_rp;
	int length;
	major_t major;

	/*
	 * Get the PCI device number information from the devinfo
	 * node. Since the node may not have the address field
	 * setup (this is done in the DDI_INITCHILD of the parent)
	 * we look up the 'reg' property to decode that information.
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "reg", (int **)&pci_rp,
	    (uint_t *)&length) != DDI_PROP_SUCCESS) {
		ctrl->rv = DDI_FAILURE;
		ctrl->dip = dip;
		return (DDI_WALK_TERMINATE);
	}

	/* get the pci device id information */
	pci_dev = PCI_REG_DEV_G(pci_rp->pci_phys_hi);

	/*
	 * free the memory allocated by ddi_prop_lookup_int_array
	 */
	ddi_prop_free(pci_rp);

	/*
	 * Match the node for the device number of the slot.
	 */
	if (pci_dev == ctrl->pci_dev) { /* node is a match */

		major = ddi_driver_major(dip);

		/*
		 * If the node is not yet attached, then don't list it
		 * as an occupant. This is valid, since nothing can be
		 * consuming it until it is attached, and cfgadm will
		 * ask for the property explicitly which will cause it
		 * to be re-freshed right before checking with rcm.
		 */
		if ((major == -1) || !i_ddi_devi_attached(dip))
			return (DDI_WALK_PRUNECHILD);

		/*
		 * If we have used all our occupants then print mesage
		 * and terminate walk.
		 */
		if (ctrl->occupant->i >= HPC_MAX_OCCUPANTS) {
			cmn_err(CE_WARN,
			    "pcihp (%s%d): unable to list all occupants",
			    ddi_driver_name(ddi_get_parent(dip)),
			    ddi_get_instance(ddi_get_parent(dip)));
			return (DDI_WALK_TERMINATE);
		}

		/*
		 * No need to hold the dip as ddi_walk_devs
		 * has already arranged that for us.
		 */
		ctrl->occupant->id[ctrl->occupant->i] =
		    kmem_alloc(sizeof (char[MAXPATHLEN]), KM_SLEEP);
		(void) ddi_pathname(dip,
		    (char *)ctrl->occupant->id[ctrl->occupant->i]);
		ctrl->occupant->i++;
	}

	/*
	 * continue the walk to the next sibling to look for a match
	 * or to find other nodes if this card is a multi-function card.
	 */
	return (DDI_WALK_PRUNECHILD);
}

static void
pcihp_create_occupant_props_nolock(dev_info_t *self, dev_t dev, int pci_dev)
{
	struct pcihp_config_ctrl ctrl;
	hpc_occupant_info_t *occupant;
	int i;

	occupant = kmem_alloc(sizeof (hpc_occupant_info_t), KM_SLEEP);
	occupant->i = 0;

	ctrl.flags = 0;
	ctrl.dip = NULL;
	ctrl.rv = NDI_SUCCESS;
	ctrl.pci_dev = pci_dev;
	ctrl.op = 55; /* should define DRYRUN */
	ctrl.occupant = occupant;

	ddi_walk_devs(ddi_get_child(self), pcihp_list_occupants,
	    (void *)&ctrl);

	if (occupant->i == 0) {
		/* no occupants right now, need to create stub property */
		char *c[] = { "" };
		(void) ddi_prop_update_string_array(dev, self, "pci-occupant",
		    c, 1);
	} else {
		(void) ddi_prop_update_string_array(dev, self, "pci-occupant",
		    occupant->id, occupant->i);
	}
	for (i = 0; i < occupant->i; i++) {
		kmem_free(occupant->id[i], sizeof (char[MAXPATHLEN]));
	}

	kmem_free(occupant, sizeof (hpc_occupant_info_t));
}

static void
pcihp_create_occupant_props(dev_info_t *self, dev_t dev, int pci_dev)
{
	ndi_devi_enter(self);
	pcihp_create_occupant_props_nolock(self, dev, pci_dev);
	ndi_devi_exit(self);
}

static void
pcihp_delete_occupant_props(dev_info_t *dip, dev_t dev)
{
	if (ddi_prop_remove(dev, dip, "pci-occupant")
	    != DDI_PROP_SUCCESS)
		return; /* add error handling */

}

/*
 * pcihp_ioctl: devctl hotplug controls
 */
/* ARGSUSED */
static int
pcihp_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
	int *rvalp)
{
	pcihp_t *pcihp_p;
	dev_info_t *self;
	struct devctl_iocdata *dcp;
	uint_t bus_state;
	int rv = 0;
	int pci_dev;
	struct pcihp_slotinfo *slotinfop;
	hpc_slot_state_t rstate;
	devctl_ap_state_t ap_state;
	struct hpc_control_data hpc_ctrldata;
	struct hpc_led_info led_info;
	time_t time;
	int state_locking;
	int state_unlocking;
	int rval;
	char *pathname = NULL;

	/*
	 * read devctl ioctl data before soft state retrieval
	 */
	if ((cmd != DEVCTL_AP_CONTROL) &&
	    ndi_dc_allochdl((void *)arg, &dcp) != NDI_SUCCESS)
		return (EFAULT);

	if (pcihp_info(NULL, DDI_INFO_DEVT2DEVINFO, (void *)dev,
	    (void **)&self) != DDI_SUCCESS) {
		if (cmd != DEVCTL_AP_CONTROL)
			ndi_dc_freehdl(dcp);
		return (ENXIO);
	}

	switch (cmd) {
	case DEVCTL_AP_INSERT:
	case DEVCTL_AP_REMOVE:
	case DEVCTL_AP_CONNECT:
	case DEVCTL_AP_DISCONNECT:
	case DEVCTL_AP_CONFIGURE:
	case DEVCTL_AP_UNCONFIGURE:
	case DEVCTL_AP_GETSTATE:
	case DEVCTL_AP_CONTROL:
		state_locking = PCIHP_DR_SLOT_ENTER;
		state_unlocking = PCIHP_DR_SLOT_EXIT;
		break;
	default:
		state_locking = PCIHP_DR_NOOP;
		state_unlocking = PCIHP_DR_NOOP;
		break;
	}

	pcihp_p = pcihp_get_soft_state(self, state_locking, &rval);
	ASSERT(pcihp_p != NULL);

	if (rval == PCIHP_FAILURE) {
		(void) ddi_pathname(pcihp_p->dip, pathname);
		PCIHP_DEBUG((CE_WARN, "Hot Plug bus %s instance is unconfigured"
		    " while slot activity is requested\n", pathname));
		if (cmd != DEVCTL_AP_CONTROL)
			ndi_dc_freehdl(dcp);
		return (EBUSY);
	}

	/*
	 * For attachment points the lower 8 bits of the minor number is the
	 * PCI device number.
	 */
	pci_dev = PCIHP_AP_MINOR_NUM_TO_PCI_DEVNUM(getminor(dev));

	/*
	 * We can use the generic implementation for these ioctls
	 */
	switch (cmd) {
	case DEVCTL_DEVICE_GETSTATE:
	case DEVCTL_DEVICE_ONLINE:
	case DEVCTL_DEVICE_OFFLINE:
	case DEVCTL_BUS_GETSTATE:
		rv = ndi_devctl_ioctl(self, cmd, arg, mode, 0);
		ndi_dc_freehdl(dcp);
		return (rv);
	default:
		break;
	}

	switch (cmd) {

	case DEVCTL_DEVICE_RESET:
		rv = ENOTSUP;
		break;

	case DEVCTL_BUS_QUIESCE:
		if (ndi_get_bus_state(self, &bus_state) == NDI_SUCCESS)
			if (bus_state == BUS_QUIESCED)
				break;
		(void) ndi_set_bus_state(self, BUS_QUIESCED);
		break;

	case DEVCTL_BUS_UNQUIESCE:
		if (ndi_get_bus_state(self, &bus_state) == NDI_SUCCESS)
			if (bus_state == BUS_ACTIVE)
				break;
		(void) ndi_set_bus_state(self, BUS_ACTIVE);
		break;

	case DEVCTL_BUS_RESET:
		rv = ENOTSUP;
		break;

	case DEVCTL_BUS_RESETALL:
		rv = ENOTSUP;
		break;

	case DEVCTL_AP_CONNECT:
	case DEVCTL_AP_DISCONNECT:
		/*
		 * CONNECT(DISCONNECT) the hot plug slot to(from) the bus.
		 *
		 * For cPCI slots this operation is a nop so the HPC
		 * driver may return success if it is a valid operation.
		 */
	case DEVCTL_AP_INSERT:
	case DEVCTL_AP_REMOVE:
		/*
		 * Prepare the slot for INSERT/REMOVE operation.
		 */

		/*
		 * check for valid request:
		 *	1. It is a hotplug slot.
		 *	2. The slot has no occupant that is in
		 *	   the 'configured' state.
		 */
		if (pci_dev >= PCI_MAX_DEVS) {
			rv = ENXIO;
			break;
		}
		slotinfop = &pcihp_p->slotinfo[pci_dev];

		mutex_enter(&slotinfop->slot_mutex);

		if ((slotinfop->slot_hdl == NULL) ||
		    (slotinfop->slot_flags & PCIHP_SLOT_DISABLED)) {
			rv = ENXIO;
			mutex_exit(&slotinfop->slot_mutex);
			break;
		}

		/* the slot occupant must be in the UNCONFIGURED state */
		if (slotinfop->ostate != AP_OSTATE_UNCONFIGURED) {
			rv = EINVAL;
			mutex_exit(&slotinfop->slot_mutex);
			break;
		}
		/*
		 * Call the HPC driver to perform the operation on the slot.
		 */

		switch (cmd) {
		case DEVCTL_AP_INSERT:
			rv = hpc_nexus_insert(slotinfop->slot_hdl, NULL, 0);
			break;
		case DEVCTL_AP_REMOVE:
			rv = hpc_nexus_remove(slotinfop->slot_hdl, NULL, 0);
			break;
		case DEVCTL_AP_CONNECT:
			rv = hpc_nexus_connect(slotinfop->slot_hdl, NULL, 0);
			if (rv == HPC_SUCCESS) {
				slotinfop->rstate = AP_RSTATE_CONNECTED;

				if (drv_getparm(TIME, (void *)&time) !=
				    DDI_SUCCESS)
					slotinfop->last_change = (time_t)-1;
				else
					slotinfop->last_change = (time32_t)time;

				slotinfop = &pcihp_p->slotinfo[pci_dev];
				pcihp_gen_sysevent(slotinfop->name,
				    PCIHP_DR_AP_STATE_CHANGE,
				    SE_NO_HINT, pcihp_p->dip,
				    KM_SLEEP);
			}
			break;
		case DEVCTL_AP_DISCONNECT:
			rv = hpc_nexus_disconnect(slotinfop->slot_hdl, NULL, 0);
			if (rv == HPC_SUCCESS) {
				slotinfop->rstate = AP_RSTATE_DISCONNECTED;

				if (drv_getparm(TIME, (void *)&time) !=
				    DDI_SUCCESS)
					slotinfop->last_change = (time_t)-1;
				else
					slotinfop->last_change = (time32_t)time;

				slotinfop = &pcihp_p->slotinfo[pci_dev];
				pcihp_gen_sysevent(slotinfop->name,
				    PCIHP_DR_AP_STATE_CHANGE,
				    SE_NO_HINT, pcihp_p->dip,
				    KM_SLEEP);
			}
			break;
		}
		mutex_exit(&slotinfop->slot_mutex);

		switch (rv) {
		case HPC_ERR_INVALID:
			rv = ENXIO;
			break;
		case HPC_ERR_NOTSUPPORTED:
			rv = ENOTSUP;
			break;
		case HPC_ERR_FAILED:
			rv = EIO;
			break;
		}

		break;

	case DEVCTL_AP_CONFIGURE:
		/*
		 * **************************************
		 * CONFIGURE the occupant in the slot.
		 * **************************************
		 */
		slotinfop = &pcihp_p->slotinfo[pci_dev];

		mutex_enter(&slotinfop->slot_mutex);

		rv = pcihp_configure_ap(pcihp_p, pci_dev);
		if (rv == HPC_SUCCESS) {
			pcihp_gen_sysevent(slotinfop->name,
			    PCIHP_DR_AP_STATE_CHANGE,
			    SE_NO_HINT, pcihp_p->dip, KM_SLEEP);
			pcihp_create_occupant_props(self, dev, pci_dev);
		}
		mutex_exit(&slotinfop->slot_mutex);

		break;

	case DEVCTL_AP_UNCONFIGURE:
		/*
		 * **************************************
		 * UNCONFIGURE the occupant in the slot.
		 * **************************************
		 */
		slotinfop = &pcihp_p->slotinfo[pci_dev];

		mutex_enter(&slotinfop->slot_mutex);

		rv = pcihp_unconfigure_ap(pcihp_p, pci_dev);

		if (rv == HPC_SUCCESS) {
			pcihp_gen_sysevent(slotinfop->name,
			    PCIHP_DR_AP_STATE_CHANGE,
			    SE_NO_HINT, pcihp_p->dip, KM_SLEEP);
			pcihp_delete_occupant_props(pcihp_p->dip, dev);
		}
		mutex_exit(&slotinfop->slot_mutex);

		break;

	case DEVCTL_AP_GETSTATE:
	{
		int mutex_held;

		/*
		 * return the state of Attachment Point.
		 *
		 * If the occupant is in UNCONFIGURED state then
		 * we should get the receptacle state from the
		 * HPC driver because the receptacle state
		 * maintained in the nexus may not be accurate.
		 */

		/*
		 * check for valid request:
		 *	1. It is a hotplug slot.
		 */
		slotinfop = &pcihp_p->slotinfo[pci_dev];

		/* try to acquire the slot mutex */
		mutex_held = mutex_tryenter(&slotinfop->slot_mutex);

		if (pci_dev >= PCI_MAX_DEVS || slotinfop->slot_hdl == NULL) {
			rv = ENXIO;
			if (mutex_held) {
				mutex_exit(&slotinfop->slot_mutex);
			}
			break;
		}

		if (slotinfop->ostate == AP_OSTATE_UNCONFIGURED) {
			if (hpc_nexus_control(slotinfop->slot_hdl,
			    HPC_CTRL_GET_SLOT_STATE, (caddr_t)&rstate) != 0) {
				rv = EIO;
				if (mutex_held)
					mutex_exit(&slotinfop->slot_mutex);
				break;
			}
			slotinfop->rstate = (ap_rstate_t)rstate;
		}

		ap_state.ap_rstate = slotinfop->rstate;
		ap_state.ap_ostate = slotinfop->ostate;
		ap_state.ap_condition = slotinfop->condition;
		ap_state.ap_last_change = slotinfop->last_change;
		ap_state.ap_error_code = 0; /* XXX */
		if (mutex_held)
			ap_state.ap_in_transition = 0; /* AP is not busy */
		else
			ap_state.ap_in_transition = 1; /* AP is busy */

		if (mutex_held)
			mutex_exit(&slotinfop->slot_mutex);

		/* copy the return-AP-state information to the user space */
		if (ndi_dc_return_ap_state(&ap_state, dcp) != NDI_SUCCESS)
			rv = EFAULT;

		break;

	}
	case DEVCTL_AP_CONTROL:
		/*
		 * HPC control functions:
		 *	HPC_CTRL_ENABLE_SLOT/HPC_CTRL_DISABLE_SLOT
		 *		Changes the state of the slot and preserves
		 *		the state across the reboot.
		 *	HPC_CTRL_ENABLE_AUTOCFG/HPC_CTRL_DISABLE_AUTOCFG
		 *		Enables or disables the auto configuration
		 *		of hot plugged occupant if the hardware
		 *		supports notification of the hot plug
		 *		events.
		 *	HPC_CTRL_GET_LED_STATE/HPC_CTRL_SET_LED_STATE
		 *		Controls the state of an LED.
		 *	HPC_CTRL_GET_SLOT_INFO
		 *		Get slot information data structure
		 *		(hpc_slot_info_t).
		 *	HPC_CTRL_GET_BOARD_TYPE
		 *		Get board type information (hpc_board_type_t).
		 *	HPC_CTRL_GET_CARD_INFO
		 *		Get card information (hpc_card_info_t).
		 *
		 * These control functions are used by the cfgadm plug-in
		 * to implement "-x" and "-v" options.
		 */

		/* copy user ioctl data first */
		switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32: {
			struct hpc_control32_data hpc_ctrldata32;

			if (copyin((void *)arg, (void *)&hpc_ctrldata32,
				sizeof (struct hpc_control32_data)) != 0) {
				rv = EFAULT;
				break;
			}
			hpc_ctrldata.cmd = hpc_ctrldata32.cmd;
			hpc_ctrldata.data =
			    (void *)(intptr_t)hpc_ctrldata32.data;
			break;
		}
		case DDI_MODEL_NONE:
			if (copyin((void *)arg, (void *)&hpc_ctrldata,
			    sizeof (struct hpc_control_data)) != 0) {
				rv = EFAULT;
			}
			break;
		default:
			rv = EFAULT;
			break;
		}
		if (rv == EFAULT)
			break;
		/*
		 * check for valid request:
		 *	1. It is a hotplug slot.
		 */
		slotinfop = &pcihp_p->slotinfo[pci_dev];

		mutex_enter(&slotinfop->slot_mutex);

		if (pci_dev >= PCI_MAX_DEVS || slotinfop->slot_hdl == NULL) {
			rv = ENXIO;
			mutex_exit(&slotinfop->slot_mutex);
			break;
		}

		switch (hpc_ctrldata.cmd) {

		case HPC_CTRL_GET_LED_STATE:
			/* copy the led info from the user space */
			if (copyin(hpc_ctrldata.data, (void *)&led_info,
			    sizeof (hpc_led_info_t)) != 0) {
				rv = EFAULT;
				break;
			}

			/* get the state of LED information */
			if (hpc_nexus_control(slotinfop->slot_hdl,
			    HPC_CTRL_GET_LED_STATE, (caddr_t)&led_info) != 0) {

				if (rv != ENOTSUP)
					rv = EIO;

				break;
			}

			/* copy the led info to the user space */
			if (copyout((void *)&led_info, hpc_ctrldata.data,
			    sizeof (hpc_led_info_t)) != 0) {
				rv = EFAULT;
				break;
			}

			break;

		case HPC_CTRL_SET_LED_STATE:
			/* copy the led info from the user space */
			if (copyin(hpc_ctrldata.data, (void *)&led_info,
			    sizeof (hpc_led_info_t)) != 0) {
				rv = EFAULT;
				break;
			}

			/* set the state of an LED */
			rv = hpc_nexus_control(slotinfop->slot_hdl,
			    HPC_CTRL_SET_LED_STATE, (caddr_t)&led_info);

			/*
			 * If the Hotswap Controller does not support
			 * LED management (as you would find typically
			 * in the cPCI industry), then we handle the
			 * blue LED on/off/blink operations, just in
			 * case it helps slot identification.
			 */
			if ((rv == HPC_ERR_NOTSUPPORTED) &&
			    (slotinfop->slot_type & HPC_SLOT_TYPE_CPCI)) {
				if (led_info.led != HPC_ATTN_LED)
					break;

				switch (led_info.state) {
				case HPC_LED_OFF:
					pcihp_hs_csr_op(pcihp_p,
					    pci_dev,
					    HPC_EVENT_SLOT_BLUE_LED_OFF);
					rv = 0;
					break;
				case HPC_LED_ON:
					/*
					 * Please note that leaving
					 * LED ON could be dangerous
					 * as it means it is Ok to
					 * remove the board, which
					 * is not what we want to
					 * convey. So it is upto the
					 * user to take care of this
					 * situation and usage.
					 *
					 * Normally, a Blink command
					 * is more appropriate for
					 * identifying a board.
					 */
					pcihp_hs_csr_op(pcihp_p,
					    pci_dev,
					    HPC_EVENT_SLOT_BLUE_LED_ON);
					rv = 0;
					break;
				case HPC_LED_BLINK:
				{
					int bl;

					for (bl = 0; bl < 2; bl++) {
						pcihp_hs_csr_op(pcihp_p,
						    pci_dev,
						    HPC_EVENT_SLOT_BLUE_LED_ON);
						delay(pcihp_cpci_led_blink);
					pcihp_hs_csr_op(pcihp_p,
					    pci_dev,
					    HPC_EVENT_SLOT_BLUE_LED_OFF);
						delay(pcihp_cpci_led_blink);
					}
					rv = 0;
					break;
				}
				default:
					break;
				}
			}

			if (rv == HPC_ERR_FAILED)
				rv = EIO;
			break;

		case HPC_CTRL_ENABLE_SLOT:

			/*
			 * If slot already enabled, do not send a duplicate
			 * control message to the HPC driver.
			 */
			if ((slotinfop->slot_flags & PCIHP_SLOT_DISABLED) == 0)
				break;

			/* tell the HPC driver also */
			if (hpc_nexus_control(slotinfop->slot_hdl,
			    HPC_CTRL_ENABLE_SLOT, NULL) != HPC_SUCCESS) {
				rv = EIO;
				break;
			}

			/*
			 * Enable the slot for hotplug operations.
			 */
			slotinfop->slot_flags &= ~PCIHP_SLOT_DISABLED;

			slotinfop->condition = AP_COND_UNKNOWN;

			/* XXX need to preserve this state across reboot? */

			break;

		case HPC_CTRL_DISABLE_SLOT:

			/* Do not disable if occupant configured */
			if (slotinfop->ostate == AP_OSTATE_CONFIGURED) {
				rv = EAGAIN;
				break;
			}

			/* tell the HPC driver also */
			if (hpc_nexus_control(slotinfop->slot_hdl,
			    HPC_CTRL_DISABLE_SLOT, NULL) != HPC_SUCCESS) {
				rv = EIO;
				break;
			}

			/*
			 * Disable the slot for hotplug operations.
			 */
			slotinfop->slot_flags |= PCIHP_SLOT_DISABLED;

			slotinfop->condition = AP_COND_UNUSABLE;

			/* XXX need to preserve this state across reboot? */

			break;

		case HPC_CTRL_ENABLE_AUTOCFG:
			/*
			 * Enable auto configuration on this slot.
			 */
			slotinfop->slot_flags |= PCIHP_SLOT_AUTO_CFG_EN;

			/* tell the HPC driver also */
			(void) hpc_nexus_control(slotinfop->slot_hdl,
			    HPC_CTRL_ENABLE_AUTOCFG, NULL);

			if (slotinfop->slot_type & HPC_SLOT_TYPE_CPCI)
				pcihp_hs_csr_op(pcihp_p, pci_dev,
				    HPC_EVENT_ENABLE_ENUM);
			break;

		case HPC_CTRL_DISABLE_AUTOCFG:
			/*
			 * Disable auto configuration on this slot.
			 */
			slotinfop->slot_flags &= ~PCIHP_SLOT_AUTO_CFG_EN;

			/* tell the HPC driver also */
			(void) hpc_nexus_control(slotinfop->slot_hdl,
			    HPC_CTRL_DISABLE_AUTOCFG, NULL);

			if (slotinfop->slot_type & HPC_SLOT_TYPE_CPCI)
				pcihp_hs_csr_op(pcihp_p, pci_dev,
				    HPC_EVENT_DISABLE_ENUM);
			break;

		case HPC_CTRL_GET_BOARD_TYPE:
		{
			hpc_board_type_t board_type;

			/*
			 * Get board type data structure, hpc_board_type_t.
			 */
			board_type = pcihp_get_board_type(slotinfop);
			if (board_type == -1) {
				rv = ENXIO;
				break;
			}

			/* copy the board type info to the user space */
			if (copyout((void *)&board_type, hpc_ctrldata.data,
			    sizeof (hpc_board_type_t)) != 0) {
				rv = ENXIO;
				break;
			}

			break;
		}

		case HPC_CTRL_GET_SLOT_INFO:
		{
			hpc_slot_info_t slot_info;

			/*
			 * Get slot information structure, hpc_slot_info_t.
			 */
			slot_info.version = HPC_SLOT_INFO_VERSION;
			slot_info.slot_type = slotinfop->slot_type;
			slot_info.pci_slot_capabilities =
			    slotinfop->slot_capabilities;
			slot_info.pci_dev_num = (uint16_t)pci_dev;
			(void) strcpy(slot_info.pci_slot_name, slotinfop->name);

			/* copy the slot info structure to the user space */
			if (copyout((void *)&slot_info, hpc_ctrldata.data,
			    sizeof (hpc_slot_info_t)) != 0) {
				rv = EFAULT;
				break;
			}

			break;
		}

		case HPC_CTRL_GET_CARD_INFO:
		{
			hpc_card_info_t card_info;
			ddi_acc_handle_t handle;
			dev_info_t *cdip;

			/*
			 * Get card information structure, hpc_card_info_t.
			 */

			/* verify that the card is configured */
			if ((slotinfop->ostate != AP_OSTATE_CONFIGURED) ||
			    ((cdip = pcihp_devi_find(self,
			    pci_dev, 0)) == NULL)) {
				/*
				 * either the card is not present or
				 * it is not configured.
				 */
				rv = ENXIO;
				break;
			}

			/*
			 * If declared failed, don't allow Config operations.
			 * Otherwise, if good or failing, it is assumed Ok
			 * to get config data.
			 */
			if (slotinfop->condition == AP_COND_FAILED) {
				rv = EIO;
				break;
			}

			/* get the information from the PCI config header */
			/* for the function 0.				  */
			if (pci_config_setup(cdip, &handle) != DDI_SUCCESS) {
				rv = EIO;
				break;
			}
			card_info.prog_class = pci_config_get8(handle,
			    PCI_CONF_PROGCLASS);
			card_info.base_class = pci_config_get8(handle,
			    PCI_CONF_BASCLASS);
			card_info.sub_class = pci_config_get8(handle,
			    PCI_CONF_SUBCLASS);
			card_info.header_type = pci_config_get8(handle,
			    PCI_CONF_HEADER);
			pci_config_teardown(&handle);

			/* copy the card info structure to the user space */
			if (copyout((void *)&card_info, hpc_ctrldata.data,
			    sizeof (hpc_card_info_t)) != 0) {
				rv = EFAULT;
				break;
			}

			break;
		}

		default:
			rv = EINVAL;
			break;
		}

		mutex_exit(&slotinfop->slot_mutex);

		break;

	default:
		rv = ENOTTY;
	}

	if (cmd != DEVCTL_AP_CONTROL)
		ndi_dc_freehdl(dcp);

	(void) pcihp_get_soft_state(self, state_unlocking, &rval);

	return (rv);
}

/*
 * **************************************
 * CONFIGURE the occupant in the slot.
 * **************************************
 */
static int
pcihp_configure_ap(pcihp_t *pcihp_p, int pci_dev)
{
	dev_info_t *self = pcihp_p->dip;
	int rv = HPC_SUCCESS;
	struct pcihp_slotinfo *slotinfop;
	hpc_slot_state_t rstate;
	struct pcihp_config_ctrl ctrl;
	time_t time;

	/*
	 * check for valid request:
	 *	1. It is a hotplug slot.
	 *	2. The receptacle is in the CONNECTED state.
	 */
	slotinfop = &pcihp_p->slotinfo[pci_dev];



	if ((pci_dev >= PCI_MAX_DEVS) || (slotinfop->slot_hdl == NULL) ||
	    (slotinfop->slot_flags & PCIHP_SLOT_DISABLED)) {

		return (ENXIO);
	}

	/*
	 * If the occupant is already in (partially?) configured
	 * state then call the ndi_devi_online() on the device
	 * subtree(s) for this attachment point.
	 */

	if (slotinfop->ostate == AP_OSTATE_CONFIGURED) {
		ctrl.flags = PCIHP_CFG_CONTINUE;
		ctrl.rv = NDI_SUCCESS;
		ctrl.dip = NULL;
		ctrl.pci_dev = pci_dev;
		ctrl.op = PCIHP_ONLINE;

		ndi_devi_enter(self);
		ddi_walk_devs(ddi_get_child(self), pcihp_configure,
		    (void *)&ctrl);
		ndi_devi_exit(self);

		if (ctrl.rv != NDI_SUCCESS) {
			/*
			 * one or more of the devices are not
			 * onlined. How is this to be reported?
			 */
			cmn_err(CE_WARN,
			    "pcihp (%s%d): failed to attach one or"
			    " more drivers for the card in the slot %s",
			    ddi_driver_name(self), ddi_get_instance(self),
			    slotinfop->name);
			/* rv = EFAULT; */
		}
		/* tell HPC driver that the occupant is configured */
		(void) hpc_nexus_control(slotinfop->slot_hdl,
		    HPC_CTRL_DEV_CONFIGURED, NULL);

		if (drv_getparm(TIME, (void *)&time) != DDI_SUCCESS)
			slotinfop->last_change = (time_t)-1;
		else
			slotinfop->last_change = (time32_t)time;


		return (rv);
	}

	/*
	 * Occupant is in the UNCONFIGURED state.
	 */

	/* Check if the receptacle is in the CONNECTED state. */
	if (hpc_nexus_control(slotinfop->slot_hdl,
	    HPC_CTRL_GET_SLOT_STATE, (caddr_t)&rstate) != 0) {

		return (ENXIO);
	}

	if (rstate == HPC_SLOT_EMPTY) {
		/* error. slot is empty */

		return (ENXIO);
	}

	if (rstate != HPC_SLOT_CONNECTED) {
		/* error. either the slot is empty or connect failed */

		return (ENXIO);
	}

	slotinfop->rstate = AP_RSTATE_CONNECTED; /* record rstate */

	/* Turn INS and LED off, and start configuration. */
	if (slotinfop->slot_type & HPC_SLOT_TYPE_CPCI) {
		pcihp_hs_csr_op(pcihp_p, pci_dev, HPC_EVENT_SLOT_CONFIGURE);
		if (pcihp_cpci_blue_led)
			pcihp_hs_csr_op(pcihp_p, pci_dev,
			    HPC_EVENT_SLOT_BLUE_LED_OFF);
		slotinfop->slot_flags &= ~PCIHP_SLOT_ENUM_INS_PENDING;
	}

	(void) hpc_nexus_control(slotinfop->slot_hdl,
	    HPC_CTRL_DEV_CONFIG_START, NULL);

	/*
	 * Call the configurator to configure the card.
	 */
	if (pcicfg_configure(self, pci_dev, PCICFG_ALL_FUNC, 0)
	    != PCICFG_SUCCESS) {
		if (slotinfop->slot_type & HPC_SLOT_TYPE_CPCI) {
			if (pcihp_cpci_blue_led)
				pcihp_hs_csr_op(pcihp_p, pci_dev,
				    HPC_EVENT_SLOT_BLUE_LED_ON);
			pcihp_hs_csr_op(pcihp_p, pci_dev,
			    HPC_EVENT_SLOT_UNCONFIGURE);
		}
		/* tell HPC driver occupant configure Error */
		(void) hpc_nexus_control(slotinfop->slot_hdl,
		    HPC_CTRL_DEV_CONFIG_FAILURE, NULL);

		return (EIO);
	}

	/* record the occupant state as CONFIGURED */
	slotinfop->ostate = AP_OSTATE_CONFIGURED;
	slotinfop->condition = AP_COND_OK;

	/* now, online all the devices in the AP */
	ctrl.flags = PCIHP_CFG_CONTINUE;
	ctrl.rv = NDI_SUCCESS;
	ctrl.dip = NULL;
	ctrl.pci_dev = pci_dev;
	ctrl.op = PCIHP_ONLINE;

	ndi_devi_enter(self);
	ddi_walk_devs(ddi_get_child(self), pcihp_configure, (void *)&ctrl);
	ndi_devi_exit(self);

	if (ctrl.rv != NDI_SUCCESS) {
		/*
		 * one or more of the devices are not
		 * ONLINE'd. How is this to be
		 * reported?
		 */
		cmn_err(CE_WARN,
		    "pcihp (%s%d): failed to attach one or"
		    " more drivers for the card in the slot %s",
		    ddi_driver_name(pcihp_p->dip),
		    ddi_get_instance(pcihp_p->dip),
		    slotinfop->name);
		/* rv = EFAULT; */
	}
	/* store HS_CSR location.  No events, jut a read operation. */
	if (slotinfop->slot_type & HPC_SLOT_TYPE_CPCI)
		pcihp_hs_csr_op(pcihp_p, pci_dev, -1);

	/* tell HPC driver that the occupant is configured */
	(void) hpc_nexus_control(slotinfop->slot_hdl,
	    HPC_CTRL_DEV_CONFIGURED, NULL);


	return (rv);
}

/*
 * **************************************
 * UNCONFIGURE the occupant in the slot.
 * **************************************
 */
static int
pcihp_unconfigure_ap(pcihp_t *pcihp_p, int pci_dev)
{
	dev_info_t *self = pcihp_p->dip;
	int rv = HPC_SUCCESS;
	struct pcihp_slotinfo *slotinfop;
	struct pcihp_config_ctrl ctrl;
	time_t time;

	/*
	 * check for valid request:
	 *	1. It is a hotplug slot.
	 *	2. The occupant is in the CONFIGURED state.
	 */
	slotinfop = &pcihp_p->slotinfo[pci_dev];



	if ((pci_dev >= PCI_MAX_DEVS) || (slotinfop->slot_hdl == NULL) ||
	    (slotinfop->slot_flags & PCIHP_SLOT_DISABLED)) {

		return (ENXIO);
	}
	/*
	 * The following may not need to be there, as we should
	 * support unconfiguring of boards and free resources
	 * even when the board is not hotswappable. But this is
	 * the only way, we may be able to tell the system
	 * administrator that it is not a hotswap board since
	 * disconnect operation is never called.
	 * This way we help the system administrator from not
	 * accidentally removing a non hotswap board and
	 * possibly destroying it. May be this behavior can
	 * be a default, and can be enabled or disabled via
	 * a global flag.
	 */
	if (slotinfop->slot_type & HPC_SLOT_TYPE_CPCI) {
		if (slotinfop->slot_flags & PCIHP_SLOT_DEV_NON_HOTPLUG) {
			/* Operation unsupported if no HS board/slot */
			return (ENOTSUP);
		}
	}

	/*
	 * If the occupant is in the CONFIGURED state then
	 * call the configurator to unconfigure the slot.
	 */
	if (slotinfop->ostate == AP_OSTATE_CONFIGURED) {

		/*
		 * since potential state change is imminent mask
		 * enum events to prevent the slot from being re-configured
		 */
		pcihp_hs_csr_op(pcihp_p, pci_dev, HPC_EVENT_DISABLE_ENUM);

		/*
		 * Detach all the drivers for the devices in the
		 * slot. Call pcihp_configure() to do this.
		 */
		ctrl.flags = 0;
		ctrl.rv = NDI_SUCCESS;
		ctrl.dip = NULL;
		ctrl.pci_dev = pci_dev;
		ctrl.op = PCIHP_OFFLINE;

		(void) devfs_clean(self, NULL, DV_CLEAN_FORCE);
		ndi_devi_enter(self);
		ddi_walk_devs(ddi_get_child(self), pcihp_configure,
		    (void *)&ctrl);
		ndi_devi_exit(self);

		if (ctrl.rv != NDI_SUCCESS) {
			/*
			 * Failed to detach one or more drivers
			 * Restore the state of drivers which
			 * are offlined during this operation.
			 */
			ctrl.flags = 0;
			ctrl.rv = NDI_SUCCESS;
			ctrl.dip = NULL;
			ctrl.pci_dev = pci_dev;
			ctrl.op = PCIHP_ONLINE;

			ndi_devi_enter(self);
			ddi_walk_devs(ddi_get_child(self),
			    pcihp_configure, (void *)&ctrl);
			ndi_devi_exit(self);

			/* tell HPC driver that the occupant is Busy */
			(void) hpc_nexus_control(slotinfop->slot_hdl,
			    HPC_CTRL_DEV_UNCONFIG_FAILURE, NULL);

			rv = EBUSY;
		} else {
			(void) hpc_nexus_control(slotinfop->slot_hdl,
			    HPC_CTRL_DEV_UNCONFIG_START, NULL);

			if (pcicfg_unconfigure(self, pci_dev,
			    PCICFG_ALL_FUNC, 0) == PCICFG_SUCCESS) {
				/*
				 * Now that resources are freed,
				 * clear EXT and Turn LED ON.
				 */
				if (slotinfop->slot_type & HPC_SLOT_TYPE_CPCI) {
					pcihp_hs_csr_op(pcihp_p, pci_dev,
					    HPC_EVENT_SLOT_UNCONFIGURE);
					if (pcihp_cpci_blue_led)
						pcihp_hs_csr_op(pcihp_p,
						    pci_dev,
						    HPC_EVENT_SLOT_BLUE_LED_ON);
					slotinfop->hs_csr_location = 0;
					slotinfop->slot_flags &=
					    ~(PCIHP_SLOT_DEV_NON_HOTPLUG|
					    PCIHP_SLOT_ENUM_EXT_PENDING);
				}
				slotinfop->ostate = AP_OSTATE_UNCONFIGURED;
				slotinfop->condition = AP_COND_UNKNOWN;
				/*
				 * send the notification of state change
				 * to the HPC driver.
				 */
				(void) hpc_nexus_control(slotinfop->slot_hdl,
				    HPC_CTRL_DEV_UNCONFIGURED,
				    NULL);
			} else {
				/* tell HPC driver occupant unconfigure Error */
				(void) hpc_nexus_control(slotinfop->slot_hdl,
				    HPC_CTRL_DEV_UNCONFIG_FAILURE, NULL);

				rv = EIO;
			}
		}
	}

	if (drv_getparm(TIME, (void *)&time) != DDI_SUCCESS)
		slotinfop->last_change = (time_t)-1;
	else
		slotinfop->last_change = (time32_t)time;



	/* unmask enum events again */
	if ((slotinfop->slot_flags & PCIHP_SLOT_AUTO_CFG_EN) == 0) {
		pcihp_hs_csr_op(pcihp_p, pci_dev, HPC_EVENT_ENABLE_ENUM);
	}

	return (rv);
}

/*
 * Accessor function to return pointer to the pci hotplug
 * cb_ops structure.
 */
struct cb_ops *
pcihp_get_cb_ops()
{
	return (&pcihp_cb_ops);
}

/*
 * Setup function to initialize hot plug feature. Returns DDI_SUCCESS
 * for successful initialization, otherwise it returns DDI_FAILURE.
 *
 * It is assumed that this this function is called from the attach()
 * entry point of the PCI nexus driver.
 */

int
pcihp_init(dev_info_t *dip)
{
	pcihp_t *pcihp_p;
	int i;
	caddr_t enum_data;
	int enum_size;
	int rv;

	mutex_enter(&pcihp_open_mutex);

	/*
	 * Make sure that it is not already initialized.
	 */
	if (pcihp_get_soft_state(dip, PCIHP_DR_NOOP, &rv) != NULL) {
		cmn_err(CE_WARN, "%s%d: pcihp instance already initialized!",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		goto cleanup;
	}

	/*
	 * Initialize soft state structure for the bus instance.
	 */
	if ((pcihp_p = pcihp_create_soft_state(dip)) == NULL) {
		cmn_err(CE_WARN, "%s%d: can't allocate pcihp structure",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		goto cleanup;
	}

	pcihp_p->soft_state = PCIHP_SOFT_STATE_CLOSED;
	/* XXX if bus is running at 66Mhz then set PCI_BUS_66MHZ bit */
	pcihp_p->bus_flags = 0;	/* XXX FIX IT */

	/*
	 * If a platform wishes to implement Radial ENUM# routing
	 * a property "enum-impl" must be presented to us with a
	 * string value "radial".
	 * This helps us not go for polling operation (default)
	 * during a ENUM# event.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, 0, "enum-impl",
	    (caddr_t)&enum_data, &enum_size) == DDI_PROP_SUCCESS) {
		if (strcmp(enum_data, "radial") == 0) {
			pcihp_p->bus_flags |= PCIHP_BUS_ENUM_RADIAL;
		}
		kmem_free(enum_data, enum_size);
	}

	for (i = 0; i < PCI_MAX_DEVS; i++) {
		/* initialize slot mutex */
		mutex_init(&pcihp_p->slotinfo[i].slot_mutex, NULL,
		    MUTEX_DRIVER, NULL);
	}

	/*
	 *  register the bus instance with the HPS framework.
	 */
	if (hpc_nexus_register_bus(dip, pcihp_new_slot_state, 0) != 0) {
		cmn_err(CE_WARN, "%s%d: failed to register the bus with HPS",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		goto cleanup1;
	}

	/*
	 * Create the "devctl" minor for hot plug support. The minor
	 * number for "devctl" node is in the same format as the AP
	 * minor nodes.
	 */
	if (ddi_create_minor_node(dip, "devctl", S_IFCHR,
	    PCIHP_AP_MINOR_NUM(ddi_get_instance(dip), PCIHP_DEVCTL_MINOR),
	    DDI_NT_NEXUS, 0) != DDI_SUCCESS)
		goto cleanup2;

	/*
	 * Setup resource maps for this bus node. (Note: This can
	 * be done from the attach(9E) of the nexus itself.)
	 */
	(void) pci_resource_setup(dip);

	pcihp_p->bus_state = PCIHP_BUS_CONFIGURED;

	mutex_exit(&pcihp_open_mutex);

	return (DDI_SUCCESS);

cleanup2:
	(void) hpc_nexus_unregister_bus(dip);
cleanup1:
	for (i = 0; i < PCI_MAX_DEVS; i++)
		mutex_destroy(&pcihp_p->slotinfo[i].slot_mutex);
	pcihp_destroy_soft_state(dip);
cleanup:
	mutex_exit(&pcihp_open_mutex);
	return (DDI_FAILURE);
}

/*
 * pcihp_uninit()
 *
 * The bus instance is going away, cleanup any data associated with
 * the management of hot plug slots. It is assumed that this function
 * is called from detach() routine of the PCI nexus driver. Also,
 * it is assumed that no devices on the bus are in the configured state.
 */
int
pcihp_uninit(dev_info_t *dip)
{
	pcihp_t *pcihp_p;
	int i, j;
	int rv;

	mutex_enter(&pcihp_open_mutex);
	/* get a pointer to the soft state structure */
	pcihp_p = pcihp_get_soft_state(dip, PCIHP_DR_BUS_UNCONFIGURE, &rv);
	ASSERT(pcihp_p != NULL);

	/* slot mutexes should prevent any configure/unconfigure access */
	for (i = 0; i < PCI_MAX_DEVS; i++) {
		if (!mutex_tryenter(&pcihp_p->slotinfo[i].slot_mutex)) {
			for (j = 0; j < i; j++) {
				mutex_exit(&pcihp_p->slotinfo[j].slot_mutex);
			}
			mutex_exit(&pcihp_open_mutex);
			return (DDI_FAILURE);
		}
	}

	if ((pcihp_p->soft_state != PCIHP_SOFT_STATE_CLOSED) ||
	    (rv == PCIHP_FAILURE)) {
		cmn_err(CE_WARN, "%s%d: pcihp instance is busy",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		for (i = 0; i < PCI_MAX_DEVS; i++) {
			mutex_exit(&pcihp_p->slotinfo[i].slot_mutex);
		}
		mutex_exit(&pcihp_open_mutex);
		return (DDI_FAILURE);
	}

	/*
	 * Unregister the bus with the HPS.
	 *
	 * (Note: It is assumed that the HPS framework uninstalls
	 *  event handlers for all the hot plug slots on this bus.)
	 */
	(void) hpc_nexus_unregister_bus(dip);

	/* Free up any kmem_alloc'd memory for slot info table. */
	for (i = 0; i < PCI_MAX_DEVS; i++) {
		/* free up slot name strings */
		if (pcihp_p->slotinfo[i].name != NULL)
			kmem_free(pcihp_p->slotinfo[i].name,
			    strlen(pcihp_p->slotinfo[i].name) + 1);
	}

	/* destroy slot mutexes */
	for (i = 0; i < PCI_MAX_DEVS; i++)
		mutex_destroy(&pcihp_p->slotinfo[i].slot_mutex);

	ddi_remove_minor_node(dip, NULL);

	/* free up the soft state structure */
	pcihp_destroy_soft_state(dip);

	/*
	 * Destroy resource maps for this bus node. (Note: This can
	 * be done from the detach(9E) of the nexus itself.)
	 */
	(void) pci_resource_destroy(dip);

	mutex_exit(&pcihp_open_mutex);

	return (DDI_SUCCESS);
}

/*
 * pcihp_new_slot_state()
 *
 * This function is called by the HPS when it finds a hot plug
 * slot is added or being removed from the hot plug framework.
 * It returns 0 for success and HPC_ERR_FAILED for errors.
 */
static int
pcihp_new_slot_state(dev_info_t *dip, hpc_slot_t hdl,
	hpc_slot_info_t *slot_info, int slot_state)
{
	pcihp_t *pcihp_p;
	struct pcihp_slotinfo *slotinfop;
	int pci_dev;
	minor_t ap_minor;
	major_t ap_major;
	int rv = 0;
	time_t time;
	int auto_enable = 1;
	int rval;

	/* get a pointer to the soft state structure */
	pcihp_p = pcihp_get_soft_state(dip, PCIHP_DR_SLOT_ENTER, &rval);
	ASSERT(pcihp_p != NULL);

	if (rval == PCIHP_FAILURE) {
		PCIHP_DEBUG((CE_WARN, "pcihp instance is unconfigured"
		    " while slot activity is requested\n"));
		return (HPC_ERR_FAILED);
	}

	pci_dev = slot_info->pci_dev_num;
	slotinfop = &pcihp_p->slotinfo[pci_dev];

	mutex_enter(&slotinfop->slot_mutex);

	switch (slot_state) {

	case HPC_SLOT_ONLINE:

		/*
		 * Make sure the slot is not already ONLINE (paranoia?).
		 * (Note: Should this be simply an ASSERTION?)
		 */
		if (slotinfop->slot_hdl != NULL) {
			PCIHP_DEBUG((CE_WARN,
			    "pcihp (%s%d): pci slot (dev %x) already ONLINE!!",
			    ddi_driver_name(dip), ddi_get_instance(dip),
			    pci_dev));
			rv = HPC_ERR_FAILED;
			break;
		}

		/*
		 * Add the hot plug slot to the bus.
		 */

		/* create the AP minor node */
		ap_minor = PCIHP_AP_MINOR_NUM(ddi_get_instance(dip), pci_dev);
		if (ddi_create_minor_node(dip, slot_info->pci_slot_name,
		    S_IFCHR, ap_minor,
		    DDI_NT_PCI_ATTACHMENT_POINT, 0) == DDI_FAILURE) {
			cmn_err(CE_WARN,
			    "pcihp (%s%d): ddi_create_minor_node failed"
			    " for pci dev %x", ddi_driver_name(dip),
			    ddi_get_instance(dip), pci_dev);
			rv = HPC_ERR_FAILED;
			break;
		}

		/* save the slot handle */
		slotinfop->slot_hdl = hdl;

		/* setup event handler for all hardware events on the slot */
		ap_major = ddi_driver_major(dip);
		if (hpc_install_event_handler(hdl, -1, pcihp_event_handler,
		    (caddr_t)makedevice(ap_major, ap_minor)) != 0) {
			cmn_err(CE_WARN,
			    "pcihp (%s%d): install event handler failed"
			    " for pci dev %x", ddi_driver_name(dip),
			    ddi_get_instance(dip), pci_dev);
			rv = HPC_ERR_FAILED;
			break;
		}
		slotinfop->event_mask = (uint32_t)0xFFFFFFFF;

		pcihp_create_occupant_props(dip, makedevice(ap_major,
		    ap_minor), pci_dev);

		/* set default auto configuration enabled flag for this slot */
		slotinfop->slot_flags = pcihp_autocfg_enabled;

		/* copy the slot information */
		slotinfop->name =
		    kmem_alloc(strlen(slot_info->pci_slot_name) + 1, KM_SLEEP);
		(void) strcpy(slotinfop->name, slot_info->pci_slot_name);
		slotinfop->slot_type = slot_info->slot_type;
		slotinfop->hs_csr_location = 0;
		slotinfop->slot_capabilities = slot_info->pci_slot_capabilities;
		if (slot_info->slot_flags & HPC_SLOT_NO_AUTO_ENABLE)
			auto_enable = 0;

		if (slot_info->slot_flags & HPC_SLOT_CREATE_DEVLINK) {
			pci_devlink_flags |= (1 << pci_dev);
			(void) ddi_prop_update_int(DDI_DEV_T_NONE,
			    dip, "ap-names", pci_devlink_flags);
		}

		PCIHP_DEBUG((CE_NOTE,
		    "pcihp (%s%d): pci slot (dev %x) ONLINE\n",
		    ddi_driver_name(dip), ddi_get_instance(dip), pci_dev));

		/*
		 * The slot may have an occupant that was configured
		 * at boot time. If we find a devinfo node in the tree
		 * for this slot (i.e pci device number) then we
		 * record the occupant state as CONFIGURED.
		 */
		if (pcihp_devi_find(dip, pci_dev, 0) != NULL) {
			/* we have a configured occupant */
			slotinfop->ostate = AP_OSTATE_CONFIGURED;
			slotinfop->rstate = AP_RSTATE_CONNECTED;
			slotinfop->condition = AP_COND_OK;

			if (slotinfop->slot_type & HPC_SLOT_TYPE_CPCI) {
				/* this will set slot flags too. */
				(void) pcihp_get_board_type(slotinfop);
				pcihp_hs_csr_op(pcihp_p, pci_dev,
				    HPC_EVENT_SLOT_CONFIGURE);
				if (pcihp_cpci_blue_led)
					pcihp_hs_csr_op(pcihp_p, pci_dev,
					    HPC_EVENT_SLOT_BLUE_LED_OFF);
				/* ENUM# enabled by default for cPCI devices */
				slotinfop->slot_flags |= PCIHP_SLOT_AUTO_CFG_EN;
				slotinfop->slot_flags &=
				    ~PCIHP_SLOT_ENUM_INS_PENDING;
			}

			/* tell HPC driver that the occupant is configured */
			(void) hpc_nexus_control(slotinfop->slot_hdl,
			    HPC_CTRL_DEV_CONFIGURED, NULL);

			/*
			 * Tell sysevent listeners that slot has
			 * changed state.  At minimum, this is useful
			 * when a PCI-E Chassis (containing Occupants) is
			 * hotplugged.  In this case, the following will
			 * announce that the Occupant in the Receptacle
			 * in the Chassis had a state-change.
			 */
			pcihp_gen_sysevent(slotinfop->name,
			    PCIHP_DR_AP_STATE_CHANGE, SE_NO_HINT,
			    pcihp_p->dip, KM_SLEEP);
		} else {
			struct pcihp_config_ctrl ctrl;

			slotinfop->ostate = AP_OSTATE_UNCONFIGURED;
			slotinfop->rstate = AP_RSTATE_EMPTY;
			slotinfop->condition = AP_COND_UNKNOWN;

			if (!auto_enable) {	/* no further action */
				break;
			}

			/*
			 * We enable power to the slot and try to
			 * configure if there is any card present.
			 *
			 * Note: This case is possible if the BIOS or
			 * firmware doesn't enable the slots during
			 * soft reboot.
			 */
			if (hpc_nexus_connect(slotinfop->slot_hdl,
			    NULL, 0) != HPC_SUCCESS)
				break;

			if (slotinfop->slot_type & HPC_SLOT_TYPE_CPCI) {
				pcihp_hs_csr_op(pcihp_p, pci_dev,
				    HPC_EVENT_SLOT_CONFIGURE);
				if (pcihp_cpci_blue_led)
					pcihp_hs_csr_op(pcihp_p, pci_dev,
					    HPC_EVENT_SLOT_BLUE_LED_OFF);
				slotinfop->slot_flags |= PCIHP_SLOT_AUTO_CFG_EN;
				slotinfop->slot_flags &=
				    ~PCIHP_SLOT_ENUM_INS_PENDING;
			}

			(void) hpc_nexus_control(slotinfop->slot_hdl,
			    HPC_CTRL_DEV_CONFIG_START, NULL);

			/*
			 * Call the configurator to configure the card.
			 */
			if (pcicfg_configure(dip, pci_dev, PCICFG_ALL_FUNC, 0)
			    != PCICFG_SUCCESS) {
				if (slotinfop->slot_type & HPC_SLOT_TYPE_CPCI) {
					if (pcihp_cpci_blue_led)
						pcihp_hs_csr_op(pcihp_p,
						    pci_dev,
						    HPC_EVENT_SLOT_BLUE_LED_ON);
					pcihp_hs_csr_op(pcihp_p, pci_dev,
					    HPC_EVENT_SLOT_UNCONFIGURE);
				}

				/* tell HPC driver occupant configure Error */
				(void) hpc_nexus_control(slotinfop->slot_hdl,
				    HPC_CTRL_DEV_CONFIG_FAILURE, NULL);

				/*
				 * call HPC driver to turn off the power for
				 * the slot.
				 */
				(void) hpc_nexus_disconnect(slotinfop->slot_hdl,
				    NULL, 0);
			} else {
				/* record the occupant state as CONFIGURED */
				slotinfop->ostate = AP_OSTATE_CONFIGURED;
				slotinfop->rstate = AP_RSTATE_CONNECTED;
				slotinfop->condition = AP_COND_OK;

				/* now, online all the devices in the AP */
				ctrl.flags = PCIHP_CFG_CONTINUE;
				ctrl.rv = NDI_SUCCESS;
				ctrl.dip = NULL;
				ctrl.pci_dev = pci_dev;
				ctrl.op = PCIHP_ONLINE;
				/*
				 * the following sets slot_flags and
				 * hs_csr_location too.
				 */
				(void) pcihp_get_board_type(slotinfop);

				ndi_devi_enter(dip);
				ddi_walk_devs(ddi_get_child(dip),
				    pcihp_configure, (void *)&ctrl);
				ndi_devi_exit(dip);

				if (ctrl.rv != NDI_SUCCESS) {
					/*
					 * one or more of the devices are not
					 * ONLINE'd. How is this to be
					 * reported?
					 */
					cmn_err(CE_WARN,
					    "pcihp (%s%d): failed to attach"
					    " one or more drivers for the"
					    " card in the slot %s",
					    ddi_driver_name(dip),
					    ddi_get_instance(dip),
					    slotinfop->name);
				}

				/* tell HPC driver the Occupant is Configured */
				(void) hpc_nexus_control(slotinfop->slot_hdl,
				    HPC_CTRL_DEV_CONFIGURED, NULL);

				/*
				 * Tell sysevent listeners that slot has
				 * changed state.  At minimum, this is useful
				 * when a PCI-E Chassis (containing Occupants)
				 * is hotplugged.  In this case, the following
				 * will announce that the Occupant in the
				 * Receptacle in the Chassis had a state-change.
				 */
				pcihp_gen_sysevent(slotinfop->name,
				    PCIHP_DR_AP_STATE_CHANGE, SE_NO_HINT,
				    pcihp_p->dip, KM_SLEEP);
			}
		}

		break;

	case HPC_SLOT_OFFLINE:
		/*
		 * A hot plug slot is being removed from the bus.
		 * Make sure there is no occupant configured on the
		 * slot before removing the AP minor node.
		 */
		if (slotinfop->ostate != AP_OSTATE_UNCONFIGURED) {
			cmn_err(CE_WARN, "pcihp (%s%d): Card is still in "
			    "configured state for pci dev %x",
			    ddi_driver_name(dip), ddi_get_instance(dip),
			    pci_dev);
			rv = HPC_ERR_FAILED;
			break;
		}

		/*
		 * If the AP device is in open state then return
		 * error.
		 */
		if (pcihp_p->soft_state != PCIHP_SOFT_STATE_CLOSED) {
			rv = HPC_ERR_FAILED;
			break;
		}
		if (slot_info->slot_flags & HPC_SLOT_CREATE_DEVLINK) {
			pci_devlink_flags &= ~(1 << pci_dev);
			(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip,
			    "ap-names", pci_devlink_flags);
		}

		/* remove the minor node */
		ddi_remove_minor_node(dip, slotinfop->name);

		/* free up the memory for the name string */
		kmem_free(slotinfop->name, strlen(slotinfop->name) + 1);

		/* update the slot info data */
		slotinfop->name = NULL;
		slotinfop->slot_hdl = NULL;

		PCIHP_DEBUG((CE_NOTE,
		    "pcihp (%s%d): pci slot (dev %x) OFFLINE\n",
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    slot_info->pci_dev_num));

		break;
	default:
		cmn_err(CE_WARN,
		    "pcihp_new_slot_state: unknown slot_state %d", slot_state);
		rv = HPC_ERR_FAILED;
	}

	if (rv == 0) {
		if (drv_getparm(TIME, (void *)&time) != DDI_SUCCESS)
			slotinfop->last_change = (time_t)-1;
		else
			slotinfop->last_change = (time32_t)time;
	}

	mutex_exit(&slotinfop->slot_mutex);

	(void) pcihp_get_soft_state(dip, PCIHP_DR_SLOT_EXIT, &rval);

	return (rv);
}

/*
 * Event handler. It is assumed that this function is called from
 * a kernel context only.
 *
 * Parameters:
 *	slot_arg	AP minor number.
 *	event_mask	Event that occurred.
 */

static int
pcihp_event_handler(caddr_t slot_arg, uint_t event_mask)
{
	dev_t ap_dev = (dev_t)slot_arg;
	dev_info_t *self;
	pcihp_t *pcihp_p;
	int pci_dev;
	int rv = HPC_EVENT_CLAIMED;
	struct pcihp_slotinfo *slotinfop;
	struct pcihp_config_ctrl ctrl;
	int rval;
	int hint;
	hpc_slot_state_t rstate;
	struct hpc_led_info led_info;

	/*
	 * Get the soft state structure.
	 */
	if (pcihp_info(NULL, DDI_INFO_DEVT2DEVINFO, (void *)ap_dev,
	    (void **)&self) != DDI_SUCCESS)
		return (ENXIO);

	pcihp_p = pcihp_get_soft_state(self, PCIHP_DR_SLOT_ENTER, &rval);
	ASSERT(pcihp_p != NULL);

	if (rval == PCIHP_FAILURE) {
		PCIHP_DEBUG((CE_WARN, "pcihp instance is unconfigured"
		    " while slot activity is requested\n"));
		return (-1);
	}

	/* get the PCI device number for the slot */
	pci_dev = PCIHP_AP_MINOR_NUM_TO_PCI_DEVNUM(getminor(ap_dev));

	slotinfop = &pcihp_p->slotinfo[pci_dev];

	/*
	 * All the events that may be handled in interrupt context should be
	 * free of any mutex usage.
	 */
	switch (event_mask) {

	case HPC_EVENT_CLEAR_ENUM:
		/*
		 * Check and clear ENUM# interrupt status. This may be
		 * called by the Hotswap controller driver when it is
		 * operating in a full hotswap system where the
		 * platform may not have control on globally disabling ENUM#.
		 * In such cases, the intent is to clear interrupt and
		 * process the interrupt in non-interrupt context.
		 * This is the first part of the ENUM# event processing.
		 */
		PCIHP_DEBUG((CE_NOTE, "pcihp (%s%d): ENUM# is generated"
		    " on the bus (for slot %s ?)",
		    ddi_driver_name(pcihp_p->dip),
		    ddi_get_instance(pcihp_p->dip), slotinfop->name));

		/* this is the only event coming through in interrupt context */
		rv = pcihp_handle_enum(pcihp_p, pci_dev, PCIHP_CLEAR_ENUM,
		    KM_NOSLEEP);

		(void) pcihp_get_soft_state(self, PCIHP_DR_SLOT_EXIT, &rval);

		return (rv);
	default:
		break;
	}

	mutex_enter(&slotinfop->slot_mutex);

	if (hpc_nexus_control(slotinfop->slot_hdl,
	    HPC_CTRL_GET_SLOT_STATE, (caddr_t)&rstate) != 0)
		rv = HPC_ERR_FAILED;

	slotinfop->rstate = (ap_rstate_t)rstate;

	switch (event_mask) {

	case HPC_EVENT_SLOT_INSERTION:
		/*
		 * A card is inserted in the slot. Just report this
		 * event and return.
		 */
		cmn_err(CE_NOTE, "pcihp (%s%d): card is inserted"
		    " in the slot %s (pci dev %x)",
		    ddi_driver_name(pcihp_p->dip),
		    ddi_get_instance(pcihp_p->dip),
		    slotinfop->name, pci_dev);

		/* +++ HOOK for RCM to report this hotplug event? +++ */

		break;

	case HPC_EVENT_SLOT_CONFIGURE:
		/*
		 * Configure the occupant that is just inserted in the slot.
		 * The receptacle may or may not be in the connected state. If
		 * the receptacle is not connected and the auto configuration
		 * is enabled on this slot then connect the slot. If auto
		 * configuration is enabled then configure the card.
		 */
		if ((slotinfop->slot_flags & PCIHP_SLOT_AUTO_CFG_EN) == 0) {
			/*
			 * auto configuration is disabled. Tell someone
			 * like RCM about this hotplug event?
			 */
			cmn_err(CE_NOTE, "pcihp (%s%d): SLOT_CONFIGURE event"
			    " occurred for pci dev %x (slot %s),"
			    " Slot disabled for auto-configuration.",
			    ddi_driver_name(pcihp_p->dip),
			    ddi_get_instance(pcihp_p->dip), pci_dev,
			    slotinfop->name);

			/* +++ HOOK for RCM to report this hotplug event? +++ */

			break;
		}

		if (slotinfop->ostate == AP_OSTATE_CONFIGURED) {
			cmn_err(CE_WARN, "pcihp (%s%d): SLOT_CONFIGURE event"
			    " re-occurred for pci dev %x (slot %s),",
			    ddi_driver_name(pcihp_p->dip),
			    ddi_get_instance(pcihp_p->dip), pci_dev,
			    slotinfop->name);
			mutex_exit(&slotinfop->slot_mutex);

			(void) pcihp_get_soft_state(self, PCIHP_DR_SLOT_EXIT,
			    &rval);

			return (EAGAIN);
		}

		/*
		 * Auto configuration is enabled. First, make sure the
		 * receptacle is in the CONNECTED state.
		 */
		if ((rv = hpc_nexus_connect(slotinfop->slot_hdl,
		    NULL, 0)) == HPC_SUCCESS) {
			/* record rstate */
			slotinfop->rstate = AP_RSTATE_CONNECTED;
		}

		/* Clear INS and Turn LED Off and start configuring. */
		if (slotinfop->slot_type & HPC_SLOT_TYPE_CPCI) {
			pcihp_hs_csr_op(pcihp_p, pci_dev,
			    HPC_EVENT_SLOT_CONFIGURE);
			if (pcihp_cpci_blue_led)
				pcihp_hs_csr_op(pcihp_p, pci_dev,
				    HPC_EVENT_SLOT_BLUE_LED_OFF);
		}

		(void) hpc_nexus_control(slotinfop->slot_hdl,
		    HPC_CTRL_DEV_CONFIG_START, NULL);

		/*
		 * Call the configurator to configure the card.
		 */
		if (pcicfg_configure(pcihp_p->dip, pci_dev, PCICFG_ALL_FUNC, 0)
		    != PCICFG_SUCCESS) {
			if (slotinfop->slot_type & HPC_SLOT_TYPE_CPCI) {
				if (pcihp_cpci_blue_led)
					pcihp_hs_csr_op(pcihp_p, pci_dev,
					    HPC_EVENT_SLOT_BLUE_LED_ON);
				pcihp_hs_csr_op(pcihp_p, pci_dev,
				    HPC_EVENT_SLOT_UNCONFIGURE);
			}
			/* failed to configure the card */
			cmn_err(CE_WARN, "pcihp (%s%d): failed to configure"
			    " the card in the slot %s",
			    ddi_driver_name(pcihp_p->dip),
			    ddi_get_instance(pcihp_p->dip),
			    slotinfop->name);
			/* failed to configure; disconnect the slot */
			if (hpc_nexus_disconnect(slotinfop->slot_hdl,
			    NULL, 0) == HPC_SUCCESS) {
				slotinfop->rstate = AP_RSTATE_DISCONNECTED;
			}

			/* tell HPC driver occupant configure Error */
			(void) hpc_nexus_control(slotinfop->slot_hdl,
			    HPC_CTRL_DEV_CONFIG_FAILURE, NULL);
		} else {
			/* record the occupant state as CONFIGURED */
			slotinfop->ostate = AP_OSTATE_CONFIGURED;
			slotinfop->condition = AP_COND_OK;

			/* now, online all the devices in the AP */
			ctrl.flags = PCIHP_CFG_CONTINUE;
			ctrl.rv = NDI_SUCCESS;
			ctrl.dip = NULL;
			ctrl.pci_dev = pci_dev;
			ctrl.op = PCIHP_ONLINE;
				(void) pcihp_get_board_type(slotinfop);

			ndi_devi_enter(pcihp_p->dip);
			ddi_walk_devs(ddi_get_child(pcihp_p->dip),
			    pcihp_configure, (void *)&ctrl);
			ndi_devi_exit(pcihp_p->dip);

			if (ctrl.rv != NDI_SUCCESS) {
				/*
				 * one or more of the devices are not
				 * ONLINE'd. How is this to be
				 * reported?
				 */
				cmn_err(CE_WARN,
				    "pcihp (%s%d): failed to attach one or"
				    " more drivers for the card in"
				    " the slot %s",
				    ddi_driver_name(pcihp_p->dip),
				    ddi_get_instance(pcihp_p->dip),
				    slotinfop->name);
			}

			/* tell HPC driver that the occupant is configured */
			(void) hpc_nexus_control(slotinfop->slot_hdl,
			    HPC_CTRL_DEV_CONFIGURED, NULL);

			cmn_err(CE_NOTE, "pcihp (%s%d): card is CONFIGURED"
			    " in the slot %s (pci dev %x)",
			    ddi_driver_name(pcihp_p->dip),
			    ddi_get_instance(pcihp_p->dip),
			    slotinfop->name, pci_dev);
		}

		break;

	case HPC_EVENT_SLOT_UNCONFIGURE:
		/*
		 * Unconfigure the occupant in this slot.
		 */
		if ((slotinfop->slot_flags & PCIHP_SLOT_AUTO_CFG_EN) == 0) {
			/*
			 * auto configuration is disabled. Tell someone
			 * like RCM about this hotplug event?
			 */
			cmn_err(CE_NOTE, "pcihp (%s%d): SLOT_UNCONFIGURE event"
			    " for pci dev %x (slot %s) ignored,"
			    " Slot disabled for auto-configuration.",
			    ddi_driver_name(pcihp_p->dip),
			    ddi_get_instance(pcihp_p->dip), pci_dev,
			    slotinfop->name);

			/* +++ HOOK for RCM to report this hotplug event? +++ */

			break;
		}

		if (slotinfop->ostate == AP_OSTATE_UNCONFIGURED) {
			cmn_err(CE_WARN, "pcihp (%s%d): SLOT_UNCONFIGURE "
			    "event re-occurred for pci dev %x (slot %s),",
			    ddi_driver_name(pcihp_p->dip),
			    ddi_get_instance(pcihp_p->dip), pci_dev,
			    slotinfop->name);
			mutex_exit(&slotinfop->slot_mutex);

			(void) pcihp_get_soft_state(self, PCIHP_DR_SLOT_EXIT,
			    &rval);

			return (EAGAIN);
		}
		/*
		 * If the occupant is in the CONFIGURED state then
		 * call the configurator to unconfigure the slot.
		 */
		if (slotinfop->ostate == AP_OSTATE_CONFIGURED) {
			/*
			 * Detach all the drivers for the devices in the
			 * slot. Call pcihp_configure() to offline the
			 * devices.
			 */
			ctrl.flags = 0;
			ctrl.rv = NDI_SUCCESS;
			ctrl.dip = NULL;
			ctrl.pci_dev = pci_dev;
			ctrl.op = PCIHP_OFFLINE;

			(void) devfs_clean(pcihp_p->dip, NULL, DV_CLEAN_FORCE);
			ndi_devi_enter(pcihp_p->dip);
			ddi_walk_devs(ddi_get_child(pcihp_p->dip),
			    pcihp_configure, (void *)&ctrl);
			ndi_devi_exit(pcihp_p->dip);

			if (ctrl.rv != NDI_SUCCESS) {
				/*
				 * Failed to detach one or more drivers.
				 * Restore the status for the drivers
				 * which are offlined during this step.
				 */
				ctrl.flags = PCIHP_CFG_CONTINUE;
				ctrl.rv = NDI_SUCCESS;
				ctrl.dip = NULL;
				ctrl.pci_dev = pci_dev;
				ctrl.op = PCIHP_ONLINE;

				ndi_devi_enter(pcihp_p->dip);
				ddi_walk_devs(ddi_get_child(pcihp_p->dip),
				    pcihp_configure, (void *)&ctrl);
				ndi_devi_exit(pcihp_p->dip);
				rv = HPC_ERR_FAILED;
			} else {
				(void) hpc_nexus_control(slotinfop->slot_hdl,
				    HPC_CTRL_DEV_UNCONFIG_START, NULL);

				if (pcicfg_unconfigure(pcihp_p->dip, pci_dev,
				    PCICFG_ALL_FUNC, 0) == PCICFG_SUCCESS) {

				/* Resources freed. Turn LED on. Clear EXT. */
				if (slotinfop->slot_type & HPC_SLOT_TYPE_CPCI) {
					if (pcihp_cpci_blue_led)
						pcihp_hs_csr_op(pcihp_p,
						    pci_dev,
						    HPC_EVENT_SLOT_BLUE_LED_ON);
					pcihp_hs_csr_op(pcihp_p, pci_dev,
					    HPC_EVENT_SLOT_UNCONFIGURE);
					slotinfop->hs_csr_location = 0;
					slotinfop->slot_flags &=
					    ~PCIHP_SLOT_DEV_NON_HOTPLUG;
				}
					slotinfop->ostate =
					    AP_OSTATE_UNCONFIGURED;
					slotinfop->condition = AP_COND_UNKNOWN;
					/*
					 * send the notification of state change
					 * to the HPC driver.
					 */
					(void) hpc_nexus_control(
					    slotinfop->slot_hdl,
					    HPC_CTRL_DEV_UNCONFIGURED, NULL);
					/* disconnect the slot */
					if (hpc_nexus_disconnect(
					    slotinfop->slot_hdl,
					    NULL, 0) == HPC_SUCCESS) {
						slotinfop->rstate =
						    AP_RSTATE_DISCONNECTED;
					}

					cmn_err(CE_NOTE,
					    "pcihp (%s%d): card is UNCONFIGURED"
					    " in the slot %s (pci dev %x)",
					    ddi_driver_name(pcihp_p->dip),
					    ddi_get_instance(pcihp_p->dip),
					    slotinfop->name, pci_dev);
				} else {
					/* tell HPC driver occupant is Busy */
					(void) hpc_nexus_control(
					    slotinfop->slot_hdl,
					    HPC_CTRL_DEV_UNCONFIG_FAILURE,
					    NULL);

					rv = HPC_ERR_FAILED;
				}
			}
		}

		/* +++ HOOK for RCM to report this hotplug event? +++ */

		break;

	case HPC_EVENT_SLOT_REMOVAL:
		/*
		 * Card is removed from the slot. The card must have been
		 * unconfigured before this event.
		 */
		if (slotinfop->ostate != AP_OSTATE_UNCONFIGURED) {
			slotinfop->condition = AP_COND_FAILED;
			cmn_err(CE_WARN, "pcihp (%s%d): card is removed"
			    " from the slot %s",
			    ddi_driver_name(pcihp_p->dip),
			    ddi_get_instance(pcihp_p->dip),
			    slotinfop->name);
		} else {
			slotinfop->condition = AP_COND_UNKNOWN;
			cmn_err(CE_NOTE, "pcihp (%s%d): card is removed"
			    " from the slot %s",
			    ddi_driver_name(pcihp_p->dip),
			    ddi_get_instance(pcihp_p->dip),
			    slotinfop->name);
		}

		slotinfop->rstate = AP_RSTATE_EMPTY;

		/* +++ HOOK for RCM to report this hotplug event? +++ */

		break;

	case HPC_EVENT_SLOT_POWER_ON:
		/*
		 * Slot is connected to the bus. i.e the card is powered
		 * on. Are there any error conditions to be checked?
		 */
		PCIHP_DEBUG((CE_NOTE, "pcihp (%s%d): card is powered"
		    " on in the slot %s",
		    ddi_driver_name(pcihp_p->dip),
		    ddi_get_instance(pcihp_p->dip),
		    slotinfop->name));

		slotinfop->rstate = AP_RSTATE_CONNECTED; /* record rstate */

		/* +++ HOOK for RCM to report this hotplug event? +++ */

		break;

	case HPC_EVENT_SLOT_POWER_OFF:
		/*
		 * Slot is disconnected from the bus. i.e the card is powered
		 * off. Are there any error conditions to be checked?
		 */
		PCIHP_DEBUG((CE_NOTE, "pcihp (%s%d): card is powered"
		    " off in the slot %s",
		    ddi_driver_name(pcihp_p->dip),
		    ddi_get_instance(pcihp_p->dip),
		    slotinfop->name));

		slotinfop->rstate = AP_RSTATE_DISCONNECTED; /* record rstate */

		/* +++ HOOK for RCM to report this hotplug event? +++ */

		break;

	case HPC_EVENT_SLOT_LATCH_SHUT:
		/*
		 * Latch on the slot is closed.
		 */
		cmn_err(CE_NOTE, "pcihp (%s%d): latch is shut for the slot %s",
		    ddi_driver_name(pcihp_p->dip),
		    ddi_get_instance(pcihp_p->dip),
		    slotinfop->name);

		/* +++ HOOK for RCM to report this hotplug event? +++ */

		break;

	case HPC_EVENT_SLOT_LATCH_OPEN:
		/*
		 * Latch on the slot is open.
		 */
		cmn_err(CE_NOTE, "pcihp (%s%d): latch is open for the slot %s",
		    ddi_driver_name(pcihp_p->dip),
		    ddi_get_instance(pcihp_p->dip),
		    slotinfop->name);

		/* +++ HOOK for RCM to report this hotplug event? +++ */

		break;

	case HPC_EVENT_PROCESS_ENUM:
		/*
		 * HSC knows the device number of the slot where the
		 * ENUM# was triggered.
		 * Now finish the necessary actions to be taken on that
		 * slot. Please note that the interrupt is already cleared.
		 * This is the second(last) part of the ENUM# event processing.
		 */
		PCIHP_DEBUG((CE_NOTE, "pcihp (%s%d): processing ENUM#"
		    " for slot %s",
		    ddi_driver_name(pcihp_p->dip),
		    ddi_get_instance(pcihp_p->dip),
		    slotinfop->name));

		mutex_exit(&slotinfop->slot_mutex);
		rv = pcihp_enum_slot(pcihp_p, slotinfop, pci_dev,
		    PCIHP_HANDLE_ENUM, KM_SLEEP);
		mutex_enter(&slotinfop->slot_mutex);

		/* +++ HOOK for RCM to report this hotplug event? +++ */

		break;

	case HPC_EVENT_BUS_ENUM:
		/*
		 * Same as HPC_EVENT_SLOT_ENUM as defined the PSARC doc.
		 * This term is used for better clarity of its usage.
		 *
		 * ENUM signal occurred on the bus. It may be from this
		 * slot or any other hotplug slot on the bus.
		 *
		 * It is NOT recommended that the hotswap controller uses
		 * event without queuing as NDI and other DDI calls may not
		 * necessarily be invokable in interrupt context.
		 * Hence the hotswap controller driver should use the
		 * CLEAR_ENUM event which returns the slot device number
		 * and then call HPC_EVENT_PROCESS_ENUM event with queuing.
		 *
		 * This can be used when the hotswap controller is
		 * implementing a polled event mechanism to do the
		 * necessary actions in a single call.
		 */
		PCIHP_DEBUG((CE_NOTE, "pcihp (%s%d): ENUM# is generated"
		    " on the bus (for slot %s ?)",
		    ddi_driver_name(pcihp_p->dip),
		    ddi_get_instance(pcihp_p->dip),
		    slotinfop->name));

		mutex_exit(&slotinfop->slot_mutex);
		rv = pcihp_handle_enum(pcihp_p, pci_dev, PCIHP_HANDLE_ENUM,
		    KM_SLEEP);
		mutex_enter(&slotinfop->slot_mutex);

		/* +++ HOOK for RCM to report this hotplug event? +++ */

		break;

	case HPC_EVENT_SLOT_BLUE_LED_ON:

		/*
		 * Request to turn Hot Swap Blue LED on.
		 */
		PCIHP_DEBUG((CE_NOTE, "pcihp (%s%d): Request To Turn On Blue "
		    "LED on the bus (for slot %s ?)",
		    ddi_driver_name(pcihp_p->dip),
		    ddi_get_instance(pcihp_p->dip),
		    slotinfop->name));

		pcihp_hs_csr_op(pcihp_p, pci_dev, HPC_EVENT_SLOT_BLUE_LED_ON);
		break;

	case HPC_EVENT_DISABLE_ENUM:
		/*
		 * Disable ENUM# which disables auto configuration on this slot
		 */
		if (slotinfop->slot_type & HPC_SLOT_TYPE_CPCI) {
			pcihp_hs_csr_op(pcihp_p, pci_dev,
			    HPC_EVENT_DISABLE_ENUM);
			slotinfop->slot_flags &= ~PCIHP_SLOT_AUTO_CFG_EN;
		}
		break;

	case HPC_EVENT_ENABLE_ENUM:
		/*
		 * Enable ENUM# which enables auto configuration on this slot.
		 */
		if (slotinfop->slot_type & HPC_SLOT_TYPE_CPCI) {
			pcihp_hs_csr_op(pcihp_p, pci_dev,
			    HPC_EVENT_ENABLE_ENUM);
			slotinfop->slot_flags |= PCIHP_SLOT_AUTO_CFG_EN;
		}
		break;

	case HPC_EVENT_SLOT_BLUE_LED_OFF:

		/*
		 * Request to turn Hot Swap Blue LED off.
		 */
		PCIHP_DEBUG((CE_NOTE, "pcihp (%s%d): Request To Turn Off Blue "
		    "LED on the bus (for slot %s ?)",
		    ddi_driver_name(pcihp_p->dip),
		    ddi_get_instance(pcihp_p->dip),
		    slotinfop->name));

		pcihp_hs_csr_op(pcihp_p, pci_dev, HPC_EVENT_SLOT_BLUE_LED_OFF);

		break;

	case HPC_EVENT_SLOT_NOT_HEALTHY:
		/*
		 * HEALTHY# signal on this slot is not OK.
		 */
		PCIHP_DEBUG((CE_NOTE, "pcihp (%s%d): HEALTHY# signal is not OK"
		    " for this slot %s",
		    ddi_driver_name(pcihp_p->dip),
		    ddi_get_instance(pcihp_p->dip),
		    slotinfop->name));

		/* record the state in slot_flags field */
		slotinfop->slot_flags |= PCIHP_SLOT_NOT_HEALTHY;
		slotinfop->condition = AP_COND_FAILED;

		/* +++ HOOK for RCM to report this hotplug event? +++ */

		break;

	case HPC_EVENT_SLOT_HEALTHY_OK:
		/*
		 * HEALTHY# signal on this slot is OK now.
		 */
		PCIHP_DEBUG((CE_NOTE, "pcihp (%s%d): HEALTHY# signal is OK now"
		    " for this slot %s",
		    ddi_driver_name(pcihp_p->dip),
		    ddi_get_instance(pcihp_p->dip),
		    slotinfop->name));

		/* update the state in slot_flags field */
		slotinfop->slot_flags &= ~PCIHP_SLOT_NOT_HEALTHY;
		slotinfop->condition = AP_COND_OK;

		/* +++ HOOK for RCM to report this hotplug event? +++ */

		break;

	case HPC_EVENT_SLOT_ATTN:
		/*
		 * Attention button is pressed.
		 */
		if (((slotinfop->slot_flags & PCIHP_SLOT_AUTO_CFG_EN) == 0) ||
		    (slotinfop->slot_flags & PCIHP_SLOT_DISABLED)) {
			/*
			 * either auto-conifiguration or the slot is disabled,
			 * ignore this event.
			 */
			break;
		}

		if (slotinfop->ostate == AP_OSTATE_UNCONFIGURED)
			hint = SE_INCOMING_RES;
		else
			hint = SE_OUTGOING_RES;

		if (ddi_getprop(DDI_DEV_T_ANY, pcihp_p->dip, DDI_PROP_DONTPASS,
		    "inkernel-autoconfig", 0) == 0) {
			pcihp_gen_sysevent(slotinfop->name, PCIHP_DR_REQ, hint,
			    pcihp_p->dip, KM_SLEEP);
			break;
		}

		if ((slotinfop->ostate == AP_OSTATE_UNCONFIGURED) &&
		    (slotinfop->rstate != AP_RSTATE_EMPTY) &&
		    (slotinfop->condition != AP_COND_FAILED)) {
			if (slotinfop->rstate == AP_RSTATE_DISCONNECTED) {
				rv = hpc_nexus_connect(slotinfop->slot_hdl,
				    NULL, 0);
				if (rv == HPC_SUCCESS)
					slotinfop->rstate = AP_RSTATE_CONNECTED;
				else
					break;
			}

			rv = pcihp_configure_ap(pcihp_p, pci_dev);

		} else if ((slotinfop->ostate == AP_OSTATE_CONFIGURED) &&
		    (slotinfop->rstate == AP_RSTATE_CONNECTED) &&
		    (slotinfop->condition != AP_COND_FAILED)) {
			rv = pcihp_unconfigure_ap(pcihp_p, pci_dev);

			if (rv != HPC_SUCCESS)
				break;

			rv = hpc_nexus_disconnect(slotinfop->slot_hdl,
			    NULL, 0);
			if (rv == HPC_SUCCESS)
				slotinfop->rstate = AP_RSTATE_DISCONNECTED;
		}

		break;

	case HPC_EVENT_SLOT_POWER_FAULT:
		/*
		 * Power fault is detected.
		 */
		cmn_err(CE_NOTE, "pcihp (%s%d): power-fault"
		    " for this slot %s",
		    ddi_driver_name(pcihp_p->dip),
		    ddi_get_instance(pcihp_p->dip),
		    slotinfop->name);

		/* turn on ATTN led */
		led_info.led = HPC_ATTN_LED;
		led_info.state = HPC_LED_ON;
		rv = hpc_nexus_control(slotinfop->slot_hdl,
		    HPC_CTRL_SET_LED_STATE, (caddr_t)&led_info);

		if (slotinfop->rstate == AP_RSTATE_CONNECTED)
			(void) hpc_nexus_disconnect(slotinfop->slot_hdl,
			    NULL, 0);

		slotinfop->condition = AP_COND_FAILED;

		pcihp_gen_sysevent(slotinfop->name, PCIHP_DR_AP_STATE_CHANGE,
		    SE_NO_HINT, pcihp_p->dip, KM_SLEEP);

		break;

	default:
		cmn_err(CE_NOTE, "pcihp (%s%d): unknown event %x"
		    " for this slot %s",
		    ddi_driver_name(pcihp_p->dip),
		    ddi_get_instance(pcihp_p->dip), event_mask,
		    slotinfop->name);

		/* +++ HOOK for RCM to report this hotplug event? +++ */

		break;
	}

	mutex_exit(&slotinfop->slot_mutex);

	(void) pcihp_get_soft_state(self, PCIHP_DR_SLOT_EXIT, &rval);

	return (rv);
}

/*
 * This function is called to online or offline the devices for an
 * attachment point. If the PCI device number of the node matches
 * with the device number of the specified hot plug slot then
 * the operation is performed.
 */
static int
pcihp_configure(dev_info_t *dip, void *hdl)
{
	int pci_dev;
	struct pcihp_config_ctrl *ctrl = (struct pcihp_config_ctrl *)hdl;
	int rv;
	pci_regspec_t *pci_rp;
	int length;

	/*
	 * Get the PCI device number information from the devinfo
	 * node. Since the node may not have the address field
	 * setup (this is done in the DDI_INITCHILD of the parent)
	 * we look up the 'reg' property to decode that information.
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", (int **)&pci_rp, (uint_t *)&length) != DDI_PROP_SUCCESS) {
		ctrl->rv = DDI_FAILURE;
		ctrl->dip = dip;
		return (DDI_WALK_TERMINATE);
	}

	/* get the pci device id information */
	pci_dev = PCI_REG_DEV_G(pci_rp->pci_phys_hi);

	/*
	 * free the memory allocated by ddi_prop_lookup_int_array
	 */
	ddi_prop_free(pci_rp);

	/*
	 * Match the node for the device number of the slot.
	 */
	if (pci_dev == ctrl->pci_dev) {	/* node is a match */
		if (ctrl->op == PCIHP_ONLINE) {
			/* it is CONFIGURE operation */

			/* skip this device if it is disabled or faulty */
			if (pcihp_check_status(dip) == B_FALSE) {
				return (DDI_WALK_PRUNECHILD);
			}

			rv = ndi_devi_online(dip, NDI_ONLINE_ATTACH|NDI_CONFIG);
		} else {
			/*
			 * it is UNCONFIGURE operation.
			 */
			rv = ndi_devi_offline(dip, NDI_UNCONFIG);
		}
		if (rv != NDI_SUCCESS) {
			/* failed to attach/detach the driver(s) */
			ctrl->rv = rv;
			ctrl->dip = dip;
			/* terminate the search if specified */
			if (!(ctrl->flags & PCIHP_CFG_CONTINUE))
				return (DDI_WALK_TERMINATE);
		}
	}

	/*
	 * continue the walk to the next sibling to look for a match
	 * or to find other nodes if this card is a multi-function card.
	 */
	return (DDI_WALK_PRUNECHILD);
}

/*
 * Check the device for a 'status' property.  A conforming device
 * should have a status of "okay", "disabled", "fail", or "fail-xxx".
 *
 * Return FALSE for a conforming device that is disabled or faulted.
 * Return TRUE in every other case.
 */
static bool_t
pcihp_check_status(dev_info_t *dip)
{
	char *status_prop;
	bool_t rv = B_TRUE;

	/* try to get the 'status' property */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "status", &status_prop) == DDI_PROP_SUCCESS) {

		/*
		 * test if the status is "disabled", "fail", or
		 * "fail-xxx".
		 */
		if (strcmp(status_prop, "disabled") == 0) {
			rv = B_FALSE;
			PCIHP_DEBUG((CE_NOTE,
			    "pcihp (%s%d): device is in disabled state",
			    ddi_driver_name(dip), ddi_get_instance(dip)));
		} else if (strncmp(status_prop, "fail", 4) == 0) {
			rv = B_FALSE;
			cmn_err(CE_WARN,
			    "pcihp (%s%d): device is in fault state (%s)",
			    ddi_driver_name(dip), ddi_get_instance(dip),
			    status_prop);
		}

		ddi_prop_free(status_prop);
	}

	return (rv);
}

/* control structure used to find a device in the devinfo tree */
struct pcihp_find_ctrl {
	uint_t		device;
	uint_t		function;
	dev_info_t	*dip;
};

static dev_info_t *
pcihp_devi_find(dev_info_t *dip, uint_t device, uint_t function)
{
	struct pcihp_find_ctrl ctrl;

	ctrl.device = device;
	ctrl.function = function;
	ctrl.dip = NULL;

	ndi_devi_enter(dip);
	ddi_walk_devs(ddi_get_child(dip), pcihp_match_dev, (void *)&ctrl);
	ndi_devi_exit(dip);

	return (ctrl.dip);
}

static int
pcihp_match_dev(dev_info_t *dip, void *hdl)
{
	struct pcihp_find_ctrl *ctrl = (struct pcihp_find_ctrl *)hdl;
	pci_regspec_t *pci_rp;
	int length;
	int pci_dev;
	int pci_func;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", (int **)&pci_rp, (uint_t *)&length) != DDI_PROP_SUCCESS) {
		ctrl->dip = NULL;
		return (DDI_WALK_TERMINATE);
	}

	/* get the PCI device address info */
	pci_dev = PCI_REG_DEV_G(pci_rp->pci_phys_hi);
	pci_func = PCI_REG_FUNC_G(pci_rp->pci_phys_hi);

	/*
	 * free the memory allocated by ddi_prop_lookup_int_array
	 */
	ddi_prop_free(pci_rp);


	if ((pci_dev == ctrl->device) && (pci_func == ctrl->function)) {
		/* found the match for the specified device address */
		ctrl->dip = dip;
		return (DDI_WALK_TERMINATE);
	}

	/*
	 * continue the walk to the next sibling to look for a match.
	 */
	return (DDI_WALK_PRUNECHILD);
}

#if 0
/*
 * Probe the configuration space of the slot to determine the receptacle
 * state. There may not be any devinfo tree created for this slot.
 */
static void
pcihp_probe_slot_state(dev_info_t *dip, int dev, hpc_slot_state_t *rstatep)
{
	/* XXX FIX IT */
}
#endif

/*
 * This routine is called when a ENUM# assertion is detected for a bus.
 * Since ENUM# may be bussed, the slot that asserted ENUM# may not be known.
 * The HPC Driver passes the handle of a slot that is its best guess.
 * If the best guess slot is the one that asserted ENUM#, the proper handling
 * will be done.  If its not, all possible slots will be locked at until
 * one that is asserting ENUM is found.
 * Also, indicate to the HSC to turn on ENUM# after it is serviced,
 * incase if it was disabled by the HSC due to the nature of asynchronous
 * delivery of interrupt by the framework.
 *
 * opcode has the following meanings.
 * PCIHP_CLEAR_ENUM = just clear interrupt and return the PCI device no. if
 *			success, else return -1.
 * PCIHP_HANDLE_ENUM = clear interrupt and handle interrupt also.
 *
 */
static int
pcihp_handle_enum(pcihp_t *pcihp_p, int favorite_pci_dev, int opcode,
	int kmflag)
{
	struct pcihp_slotinfo *slotinfop;
	int pci_dev, rc, event_serviced = 0;

	/*
	 * Handle ENUM# condition for the "favorite" slot first.
	 */
	slotinfop = &pcihp_p->slotinfo[favorite_pci_dev];
	if (slotinfop) {
		/*
		 * First try the "favorite" pci device.  This is the device
		 * associated with the handle passed by the HPC Driver.
		 */
		rc = pcihp_enum_slot(pcihp_p, slotinfop, favorite_pci_dev,
		    opcode, kmflag);
		if (rc != HPC_EVENT_UNCLAIMED) {	/* indicates success */
			event_serviced = 1;
			/* This MUST be a non-DEBUG feature. */
			if (! pcihp_enum_scan_all) {
				return (rc);
			}
		}
	}

	/*
	 * If ENUM# is implemented as a radial signal, then there is no
	 * need to further poll the slots.
	 */
	if (pcihp_p->bus_flags & PCIHP_BUS_ENUM_RADIAL)
		goto enum_service_check;

	/*
	 * If the "favorite" pci device didn't assert ENUM#, then
	 * try the rest.  Once we find and handle a device that asserted
	 * ENUM#, then we will terminate the walk by returning unless
	 * scan-all flag is set.
	 */
	for (pci_dev = 0; pci_dev < PCI_MAX_DEVS; pci_dev++) {
		if (pci_dev != favorite_pci_dev) {
			slotinfop = &pcihp_p->slotinfo[pci_dev];
			if (slotinfop == NULL) {
				continue;
			}
			/* Only CPCI devices support ENUM# generation. */
			if (!(slotinfop->slot_type & HPC_SLOT_TYPE_CPCI))
				continue;
			rc = pcihp_enum_slot(pcihp_p, slotinfop, pci_dev,
			    opcode, kmflag);
			if (rc != HPC_EVENT_UNCLAIMED) {
				event_serviced = 1;
				/* This MUST be a non-DEBUG feature. */
				if (! pcihp_enum_scan_all)
					break;
			}
		}
	}

enum_service_check:
	if (event_serviced) {
		return (rc);
	}

	/* No ENUM# event found, Return */
	return (HPC_EVENT_UNCLAIMED);
}

/*
 * This routine attempts to handle a possible ENUM# assertion case for a
 * specified slot.  This only works for adapters that implement Hot Swap
 * Friendly Silicon.  If the slot's HS_CSR is read and it specifies ENUM#
 * has been asserted, either the insertion or removal handlers will be
 * called.
 */
static int
pcihp_enum_slot(pcihp_t *pcihp_p, struct pcihp_slotinfo *slotinfop, int pci_dev,
		int opcode, int kmflag)
{
	ddi_acc_handle_t handle;
	dev_info_t *dip, *new_child = NULL;
	int result, rv = -1;
	uint8_t hs_csr;

	if (pcihp_config_setup(&dip, &handle, &new_child, pci_dev,
	    pcihp_p) != DDI_SUCCESS) {
		return (HPC_EVENT_UNCLAIMED);
	}

	/*
	 * Read the device's HS_CSR.
	 */
	result = pcihp_get_hs_csr(slotinfop, handle, (uint8_t *)&hs_csr);
	PCIHP_DEBUG((CE_NOTE, "pcihp (%s%d): hs_csr = %x, flags = %x",
	    ddi_driver_name(pcihp_p->dip), ddi_get_instance(pcihp_p->dip),
	    hs_csr, slotinfop->slot_flags));
	/*
	 * we teardown our device map here, because in case of an
	 * extraction event, our nodes would be freed and a teardown
	 * will cause problems.
	 */
	pcihp_config_teardown(&handle, &new_child, pci_dev, pcihp_p);

	if (result == PCIHP_SUCCESS) {

		/* If ENUM# is masked, then it is not us. Some other device */
		if ((hs_csr & HS_CSR_EIM) && (opcode == PCIHP_CLEAR_ENUM))
			return (HPC_EVENT_UNCLAIMED);
		/*
		 * This device supports Full Hot Swap and implements
		 * the Hot Swap Control and Status Register.
		 */
		if ((hs_csr & HS_CSR_INS) ||
		    (slotinfop->slot_flags & PCIHP_SLOT_ENUM_INS_PENDING)) {
			/* handle insertion ENUM */
			PCIHP_DEBUG((CE_NOTE, "pcihp (%s%d): "
			    "Handle Insertion ENUM (INS) "
			    "on the bus (for slot %s ?)",
			    ddi_driver_name(pcihp_p->dip),
			    ddi_get_instance(pcihp_p->dip),
			    slotinfop->name));

			/*
			 * generate sysevent
			 */

			if (opcode == PCIHP_CLEAR_ENUM)
				pcihp_gen_sysevent(slotinfop->name,
				    PCIHP_DR_REQ,
				    SE_INCOMING_RES, pcihp_p->dip,
				    kmflag);

			rv = pcihp_handle_enum_insertion(pcihp_p, pci_dev,
			    opcode, kmflag);

		} else if ((hs_csr & HS_CSR_EXT) ||
		    (slotinfop->slot_flags & PCIHP_SLOT_ENUM_EXT_PENDING)) {
			/* handle extraction ENUM */
			PCIHP_DEBUG((CE_NOTE, "pcihp (%s%d): "
			    "Handle Extraction ENUM (EXT) "
			    "on the bus (for slot %s ?)",
			    ddi_driver_name(pcihp_p->dip),
			    ddi_get_instance(pcihp_p->dip),
			    slotinfop->name));

			/*
			 * generate sysevent
			 */

			if (opcode == PCIHP_CLEAR_ENUM)
				pcihp_gen_sysevent(slotinfop->name,
				    PCIHP_DR_REQ,
				    SE_OUTGOING_RES,
				    pcihp_p->dip,
				    kmflag);

			rv = pcihp_handle_enum_extraction(pcihp_p, pci_dev,
			    opcode, kmflag);
		}
		if (opcode == PCIHP_CLEAR_ENUM) {
			if (rv == PCIHP_SUCCESS)
				rv = pci_dev;
			else
				rv = HPC_EVENT_UNCLAIMED;
		}
	}

	return (rv);
}

/*
 * This routine is called when a ENUM# caused by lifting the lever
 * is detected.  If the occupant is configured, it will be unconfigured.
 * If the occupant is already unconfigured or is successfully unconfigured,
 * the blue LED on the adapter is illuminated which means its OK to remove.
 * Please note that the lock must be released before invoking the
 * generic AP unconfigure function.
 */
static int
pcihp_handle_enum_extraction(pcihp_t *pcihp_p, int pci_dev, int opcode,
	int kmflag)
{
	struct pcihp_slotinfo *slotinfop;
	int rv = PCIHP_FAILURE;

	slotinfop = &pcihp_p->slotinfo[pci_dev];

	/*
	 * It was observed that, clearing the EXT bit turned the LED ON.
	 * This is a BIG problem in case if the unconfigure operation
	 * failed because the board was busy.
	 * In order to avoid this confusing situation (LED ON but the board
	 * is not unconfigured), we instead decided not to clear EXT but
	 * disable further ENUM# from this slot. Disabling ENUM# clears
	 * the interrupt.
	 * Finally before returning we clear the interrupt and enable
	 * ENUM# back again from this slot.
	 */
	pcihp_hs_csr_op(pcihp_p, pci_dev, HPC_EVENT_DISABLE_ENUM);
	if (opcode == PCIHP_CLEAR_ENUM) {
		slotinfop->slot_flags |= PCIHP_SLOT_ENUM_EXT_PENDING;
		return (PCIHP_SUCCESS);
	}

	mutex_enter(&slotinfop->slot_mutex);
	rv = pcihp_unconfigure_ap(pcihp_p, pci_dev);
	mutex_exit(&slotinfop->slot_mutex);
	if (rv != HPC_SUCCESS && rv != EBUSY) {
		cmn_err(CE_NOTE, "%s%d: PCI device %x Failed on Unconfigure",
		    ddi_driver_name(pcihp_p->dip),
		    ddi_get_instance(pcihp_p->dip), pci_dev);
	}
	if (rv == EBUSY)
		cmn_err(CE_NOTE, "%s%d: PCI device %x Busy",
		    ddi_driver_name(pcihp_p->dip),
		    ddi_get_instance(pcihp_p->dip), pci_dev);
	if (rv) {
		if (pcihp_cpci_blue_led)
			pcihp_hs_csr_op(pcihp_p, pci_dev,
			    HPC_EVENT_SLOT_BLUE_LED_OFF);
	}
	/*
	 * we must clear interrupt in case the unconfigure didn't do it
	 * due to a duplicate interrupt. Extraction is success.
	 */
	pcihp_hs_csr_op(pcihp_p, pci_dev, HPC_EVENT_SLOT_UNCONFIGURE);

	if (!rv) {
		/*
		 * Sys Event Notification.
		 */
		pcihp_gen_sysevent(slotinfop->name, PCIHP_DR_AP_STATE_CHANGE,
		    SE_HINT_REMOVE, pcihp_p->dip, kmflag);
	}

	/*
	 * Enable interrupts back from this board.
	 * This could potentially be problematic in case if the user is
	 * quick enough to extract the board.
	 * But we must do it just in case if the switch is closed again.
	 */
	pcihp_hs_csr_op(pcihp_p, pci_dev, HPC_EVENT_ENABLE_ENUM);
	slotinfop->slot_flags &= ~PCIHP_SLOT_ENUM_EXT_PENDING;
	return (rv);
}

/*
 * This routine is called when a ENUM# caused by when an adapter insertion
 * is detected.  If the occupant is successfully configured (i.e. PCI resources
 * successfully assigned, the blue LED is left off, otherwise if configuration
 * is not successful, the blue LED is illuminated.
 * Please note that the lock must be released before invoking the
 * generic AP configure function.
 */
static int
pcihp_handle_enum_insertion(pcihp_t *pcihp_p, int pci_dev, int opcode,
	int kmflag)
{
	struct pcihp_slotinfo *slotinfop;
	int rv = PCIHP_FAILURE;
	minor_t ap_minor;
	major_t ap_major;

	slotinfop = &pcihp_p->slotinfo[pci_dev];
	slotinfop->hs_csr_location = 0;
	/* we clear the interrupt here. This is a must here. */
	pcihp_hs_csr_op(pcihp_p, pci_dev, HPC_EVENT_SLOT_CONFIGURE);
	/*
	 * disable further interrupt from this board till it is
	 * configured.
	 */
	pcihp_hs_csr_op(pcihp_p, pci_dev, HPC_EVENT_DISABLE_ENUM);
	if (opcode == PCIHP_CLEAR_ENUM) {
		slotinfop->slot_flags |= PCIHP_SLOT_ENUM_INS_PENDING;
		return (PCIHP_SUCCESS);
	}

	if ((slotinfop->slot_flags & PCIHP_SLOT_AUTO_CFG_EN) ==
	    PCIHP_SLOT_AUTO_CFG_EN) {
		mutex_enter(&slotinfop->slot_mutex);
		rv = pcihp_configure_ap(pcihp_p, pci_dev);
		mutex_exit(&slotinfop->slot_mutex);
		if (rv != HPC_SUCCESS) {	/* configure failed */
			cmn_err(CE_NOTE, "%s%d: PCI device %x Failed on"
			    " Configure", ddi_driver_name(pcihp_p->dip),
			    ddi_get_instance(pcihp_p->dip), pci_dev);
			if (pcihp_cpci_blue_led)
				pcihp_hs_csr_op(pcihp_p, pci_dev,
				    HPC_EVENT_SLOT_BLUE_LED_ON);
		}

		/* pcihp_hs_csr_op(pcihp_p, pci_dev, HPC_EVENT_CLEAR_ENUM); */
		pcihp_hs_csr_op(pcihp_p, pci_dev, HPC_EVENT_ENABLE_ENUM);

		if (!rv) {
			ap_major = ddi_driver_major(pcihp_p->dip);
			ap_minor = PCIHP_AP_MINOR_NUM(
			    ddi_get_instance(pcihp_p->dip), pci_dev);
			pcihp_create_occupant_props(pcihp_p->dip,
			    makedevice(ap_major, ap_minor), pci_dev);

			/*
			 * Sys Event Notification.
			 */
			pcihp_gen_sysevent(slotinfop->name,
			    PCIHP_DR_AP_STATE_CHANGE,
			    SE_HINT_INSERT, pcihp_p->dip, kmflag);
		}

	} else
		rv = PCIHP_SUCCESS;
	slotinfop->slot_flags &= ~PCIHP_SLOT_ENUM_INS_PENDING;
	return (rv);
}

/*
 * Read the Hot Swap Control and Status Register (HS_CSR) and
 * place the result in the location pointed to be hs_csr.
 */
static int
pcihp_get_hs_csr(struct pcihp_slotinfo *slotinfop,
    ddi_acc_handle_t config_handle, uint8_t *hs_csr)
{
	if (slotinfop->hs_csr_location == -1)
		return (PCIHP_FAILURE);

	if (slotinfop->hs_csr_location == 0) {
		slotinfop->hs_csr_location =
		    pcihp_get_hs_csr_location(config_handle);

		if (slotinfop->hs_csr_location == -1)
			return (PCIHP_FAILURE);
	}
	*hs_csr = pci_config_get8(config_handle, slotinfop->hs_csr_location);
	return (PCIHP_SUCCESS);
}

/*
 * Write the Hot Swap Control and Status Register (HS_CSR) with
 * the value being pointed at by hs_csr.
 */
static void
pcihp_set_hs_csr(struct pcihp_slotinfo *slotinfop,
    ddi_acc_handle_t config_handle, uint8_t *hs_csr)
{
	if (slotinfop->hs_csr_location == -1)
		return;
	if (slotinfop->hs_csr_location == 0) {
		slotinfop->hs_csr_location =
		    pcihp_get_hs_csr_location(config_handle);
		if (slotinfop->hs_csr_location == -1)
			return;
	}
	pci_config_put8(config_handle, slotinfop->hs_csr_location, *hs_csr);
	PCIHP_DEBUG((CE_NOTE, "hs_csr wrote %x, read %x", *hs_csr,
	    pci_config_get8(config_handle, slotinfop->hs_csr_location)));
}

static int
pcihp_get_hs_csr_location(ddi_acc_handle_t config_handle)
{
	uint8_t	cap_id;
	uint_t	cap_id_loc;
	uint16_t	status;
	int location = -1;
#define	PCI_STAT_ECP_SUPP	0x10

	/*
	 * Need to check the Status register for ECP support first.
	 * Also please note that for type 1 devices, the
	 * offset could change. Should support type 1 next.
	 */
	status = pci_config_get16(config_handle, PCI_CONF_STAT);
	if (!(status & PCI_STAT_ECP_SUPP)) {
		PCIHP_DEBUG((CE_NOTE, "No Ext Capabilities for device\n"));
		return (-1);
	}
	cap_id_loc = pci_config_get8(config_handle, PCI_CONF_EXTCAP);

	/*
	 * Walk the list of capabilities, but don't walk past the end
	 * of the Configuration Space Header.
	 */
	while ((cap_id_loc) && (cap_id_loc < PCI_CONF_HDR_SIZE)) {

		cap_id = pci_config_get8(config_handle, cap_id_loc);

		if (cap_id == CPCI_HOTSWAP_CAPID) {
			location = cap_id_loc + PCI_ECP_HS_CSR;
			break;
		}
		cap_id_loc = pci_config_get8(config_handle,
		    cap_id_loc + 1);
	}
	return (location);
}

static int
pcihp_add_dummy_reg_property(dev_info_t *dip,
    uint_t bus, uint_t device, uint_t func)
{
	pci_regspec_t dummy_reg;

	bzero(&dummy_reg, sizeof (dummy_reg));

	dummy_reg.pci_phys_hi = PCIHP_MAKE_REG_HIGH(bus, device, func, 0);

	return (ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "reg", (int *)&dummy_reg, sizeof (pci_regspec_t)/sizeof (int)));
}

static void
pcihp_hs_csr_op(pcihp_t *pcihp_p, int pci_dev, int event)
{
	struct pcihp_slotinfo *slotinfop;
	ddi_acc_handle_t config_handle;
	dev_info_t *dip, *new_child = NULL;
	uint8_t hs_csr;
	int result;

	slotinfop = &pcihp_p->slotinfo[pci_dev];

	if (pcihp_config_setup(&dip, &config_handle, &new_child, pci_dev,
	    pcihp_p) != DDI_SUCCESS) {
		return;
	}

	result = pcihp_get_hs_csr(slotinfop, config_handle, (uint8_t *)&hs_csr);
	if ((result != PCIHP_SUCCESS) || (event == -1)) {
		pcihp_config_teardown(&config_handle, &new_child, pci_dev,
		    pcihp_p);
		return;
	}

	hs_csr &= 0xf;
	switch (event) {
		case HPC_EVENT_SLOT_BLUE_LED_ON:
			hs_csr |= HS_CSR_LOO;
			break;
		case HPC_EVENT_SLOT_BLUE_LED_OFF:
			hs_csr &= ~HS_CSR_LOO;
			break;
		case HPC_EVENT_SLOT_CONFIGURE:
			hs_csr |= HS_CSR_INS;	/* clear INS */
			break;
		case HPC_EVENT_CLEAR_ENUM:
			hs_csr |= (HS_CSR_INS | HS_CSR_EXT);
			break;
		case HPC_EVENT_SLOT_UNCONFIGURE:
			hs_csr |= HS_CSR_EXT;	/* clear EXT */
			break;
		case HPC_EVENT_ENABLE_ENUM:
			hs_csr &= ~HS_CSR_EIM;
			break;
		case HPC_EVENT_DISABLE_ENUM:
			hs_csr |= HS_CSR_EIM;
			break;
		case HPC_EVENT_SLOT_NOT_HEALTHY:
		case HPC_EVENT_SLOT_HEALTHY_OK:
		default:
			break;
	}
	pcihp_set_hs_csr(slotinfop, config_handle, (uint8_t *)&hs_csr);
	pcihp_config_teardown(&config_handle, &new_child, pci_dev, pcihp_p);
}

static int
pcihp_config_setup(dev_info_t **dip, ddi_acc_handle_t *handle,
			dev_info_t **new_child, int pci_dev, pcihp_t *pcihp_p)
{
	dev_info_t *pdip = pcihp_p->dip;
	int bus, len, rc = DDI_SUCCESS;
	struct pcihp_slotinfo *slotinfop;
	hpc_slot_state_t rstate;
	ddi_acc_hdl_t *hp;
	pci_bus_range_t pci_bus_range;

	slotinfop = &pcihp_p->slotinfo[pci_dev];

	/*
	 * If declared failed, don't allow Config operations.
	 * Otherwise, if good or failing, it is assumed Ok
	 * to get config data.
	 */
	if (slotinfop->condition == AP_COND_FAILED) {
		return (PCIHP_FAILURE);
	}
	/*
	 * check to see if there is a hardware present first.
	 * If no hardware present, no need to probe this slot.
	 * We can do this first probably as a first step towards
	 * safeguarding from accidental removal (we don't support it!).
	 */
	if (hpc_nexus_control(slotinfop->slot_hdl, HPC_CTRL_GET_SLOT_STATE,
	    (caddr_t)&rstate) != 0) {
		return (DDI_FAILURE);
	}

	if (rstate != HPC_SLOT_CONNECTED) {
		/* error. slot must be connected */
		return (DDI_FAILURE);
	}
	*new_child = NULL;

	/*
	 * If there is no dip then we need to see if an
	 * adapter has just been hot plugged.
	 */
	len = sizeof (pci_bus_range_t);
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, pdip,
	    0, "bus-range",
	    (caddr_t)&pci_bus_range, &len) != DDI_SUCCESS) {

		return (PCIHP_FAILURE);
	}

	/* primary bus number of this bus node */
	bus = pci_bus_range.lo;

	if (ndi_devi_alloc(pdip, DEVI_PSEUDO_NEXNAME,
	    (pnode_t)DEVI_SID_NODEID, dip) != NDI_SUCCESS) {

		PCIHP_DEBUG((CE_NOTE, "Failed to alloc probe node\n"));
		return (PCIHP_FAILURE);
	}

	if (pcihp_add_dummy_reg_property(*dip, bus,
	    pci_dev, 0) != DDI_SUCCESS) {

		(void) ndi_devi_free(*dip);
		return (PCIHP_FAILURE);
	}

	/*
	 * Probe for a device. Possibly a non (c)PCI board could be sitting
	 * here which would never respond to PCI config cycles - in which
	 * case we return. Eventually a configure operation would fail.
	 */
	if (pci_config_setup(*dip, handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "Cannot set config space map for"
		    " pci device number %d", pci_dev);
		(void) ndi_devi_free(*dip);
		return (PCIHP_FAILURE);
	}

	/*
	 * See if there is any PCI HW at this location
	 * by reading the Vendor ID.  If it returns with 0xffff
	 * then there is no hardware at this location.
	 */
	if (pcihp_indirect_map(*dip) == DDI_SUCCESS) {
		if (pci_config_get16(*handle, 0) == 0xffff) {
			pci_config_teardown(handle);
			(void) ndi_devi_free(*dip);
			return (PCIHP_FAILURE);
		}
	} else {
		/* Check if mapping is OK */
		hp = impl_acc_hdl_get(*handle);

		if (ddi_peek16(*dip, (int16_t *)(hp->ah_addr),
		    (int16_t *)0) != DDI_SUCCESS) {
#ifdef DEBUG
			cmn_err(CE_WARN, "Cannot Map PCI config space for "
			    "device number %d", pci_dev);
#endif
			pci_config_teardown(handle);
			(void) ndi_devi_free(*dip);
			return (PCIHP_FAILURE);
		}
	}

	*new_child = *dip;
	return (rc);

}

static void
pcihp_config_teardown(ddi_acc_handle_t *handle,
			dev_info_t **new_child, int pci_dev, pcihp_t *pcihp_p)
{
	struct pcihp_slotinfo *slotinfop = &pcihp_p->slotinfo[pci_dev];

	pci_config_teardown(handle);
	if (*new_child) {
		(void) ndi_devi_free(*new_child);
		/*
		 * If occupant not configured, reset HS_CSR location
		 * so that we reprobe. This covers cases where
		 * the receptacle had a status change without a
		 * notification to the framework.
		 */
		if (slotinfop->ostate != AP_OSTATE_CONFIGURED)
			slotinfop->hs_csr_location = 0;
	}
}

static int
pcihp_get_board_type(struct pcihp_slotinfo *slotinfop)
{
	hpc_board_type_t board_type;

	/*
	 * Get board type data structure, hpc_board_type_t.
	 */
	if (hpc_nexus_control(slotinfop->slot_hdl, HPC_CTRL_GET_BOARD_TYPE,
	    (caddr_t)&board_type) != 0) {

		cmn_err(CE_WARN, "Cannot Get Board Type..");
		return (-1);
	}

	/*
	 * We expect the Hotswap Controller to tell us if the board is
	 * a hotswap board or not, as it probably cannot differentiate
	 * between a basic hotswap board, a non hotswap board and a
	 * hotswap nonfriendly board.
	 * So here is the logic to differentiate between the various
	 * types of cPCI boards.
	 * In case if the HSC returns board type as unknown, we assign
	 * the default board type as defined by a configurable variable
	 * for a BHS, nonfriendly FHS and non HS board.
	 */
	if (slotinfop->slot_type & HPC_SLOT_TYPE_CPCI) {
		if (slotinfop->hs_csr_location > 0)
			board_type = HPC_BOARD_CPCI_FULL_HS;
		else {
			if (board_type == HPC_BOARD_CPCI_HS) {
				if (slotinfop->hs_csr_location == -1)
					board_type = HPC_BOARD_CPCI_BASIC_HS;
			}
			if (board_type == HPC_BOARD_UNKNOWN) {
				if (slotinfop->hs_csr_location == -1) {
					board_type = pcihp_cpci_board_type;
				} else if (slotinfop->hs_csr_location != 0) {
					board_type = HPC_BOARD_CPCI_FULL_HS;
				}
			}
		}
		/*
		 * If board type is a non hotswap board, then we must
		 * deny a unconfigure operation. So set this flag.
		 * Strictly speaking, there is no reason not to disallow
		 * a unconfigure operation on nonhotswap boards. But this
		 * is the only way we can prevent a user from accidentally
		 * removing the board and damaging it.
		 */
		if (board_type == HPC_BOARD_CPCI_NON_HS)
			slotinfop->slot_flags |= PCIHP_SLOT_DEV_NON_HOTPLUG;
		else
			slotinfop->slot_flags &= ~PCIHP_SLOT_DEV_NON_HOTPLUG;
	}
	return (board_type);
}


/*
 * Generate the System Event with a possible hint.
 */
static void
pcihp_gen_sysevent(char *slot_name, int event_sub_class, int hint,
				dev_info_t *self, int kmflag)
{

	int err;
	char *ev_subclass = NULL;
	sysevent_id_t eid;
	nvlist_t *ev_attr_list = NULL;
	char attach_pnt[MAXPATHLEN];

	/*
	 * Minor device name (AP) will be bus path
	 * concatenated with slot name
	 */

	(void) strcpy(attach_pnt, PCIHP_DEVICES_STR);
	(void) ddi_pathname(self, attach_pnt + strlen(PCIHP_DEVICES_STR));
	(void) strcat(attach_pnt, ":");
	(void) strcat(attach_pnt, slot_name);
	err = nvlist_alloc(&ev_attr_list, NV_UNIQUE_NAME_TYPE, kmflag);
	if (err != 0) {
		cmn_err(CE_WARN,
		    "%s%d: Failed to allocate memory "
		    "for event attributes%s", ddi_driver_name(self),
		    ddi_get_instance(self), ESC_DR_AP_STATE_CHANGE);
		return;
	}

	switch (event_sub_class) {

	/* event sub class: ESC_DR_AP_STATE_CHANGE */
	case PCIHP_DR_AP_STATE_CHANGE:

		ev_subclass = ESC_DR_AP_STATE_CHANGE;

		switch (hint) {

		case SE_NO_HINT:	/* fall through */
		case SE_HINT_INSERT:	/* fall through */
		case SE_HINT_REMOVE:


			err = nvlist_add_string(ev_attr_list, DR_HINT,
			    SE_HINT2STR(hint));

			if (err != 0) {
				cmn_err(CE_WARN, "%s%d: Failed to add attr [%s]"
				    " for %s event", ddi_driver_name(self),
				    ddi_get_instance(self),
				    DR_HINT, ESC_DR_AP_STATE_CHANGE);
				nvlist_free(ev_attr_list);
				return;
			}
			break;

		default:
			cmn_err(CE_WARN, "%s%d: Unknown hint on sysevent",
			    ddi_driver_name(self), ddi_get_instance(self));
			nvlist_free(ev_attr_list);
			return;
		}

		break;

	/* event sub class: ESC_DR_REQ */
	case PCIHP_DR_REQ:

		ev_subclass = ESC_DR_REQ;

		switch (hint) {

		case SE_INVESTIGATE_RES:	/* fall through */
		case SE_INCOMING_RES:	/* fall through */
		case SE_OUTGOING_RES:	/* fall through */

			err = nvlist_add_string(ev_attr_list, DR_REQ_TYPE,
			    SE_REQ2STR(hint));

			if (err != 0) {
				cmn_err(CE_WARN,
				    "%s%d: Failed to add attr [%s] "
				    "for %s event", ddi_driver_name(self),
				    ddi_get_instance(self),
				    DR_REQ_TYPE, ESC_DR_REQ);
				nvlist_free(ev_attr_list);
				return;
			}
			break;

		default:
			cmn_err(CE_WARN, "%s%d:  Unknown hint on sysevent",
			    ddi_driver_name(self), ddi_get_instance(self));
			nvlist_free(ev_attr_list);
			return;
		}

		break;

	default:
		cmn_err(CE_WARN, "%s%d:  Unknown Event subclass",
		    ddi_driver_name(self), ddi_get_instance(self));
		nvlist_free(ev_attr_list);
		return;
	}

	/*
	 * Add attachment point as attribute (common attribute)
	 */

	err = nvlist_add_string(ev_attr_list, DR_AP_ID, attach_pnt);

	if (err != 0) {
		cmn_err(CE_WARN, "%s%d: Failed to add attr [%s] for %s event",
		    ddi_driver_name(self), ddi_get_instance(self),
		    DR_AP_ID, EC_DR);
		nvlist_free(ev_attr_list);
		return;
	}


	/*
	 * Log this event with sysevent framework.
	 */

	err = ddi_log_sysevent(self, DDI_VENDOR_SUNW, EC_DR,
	    ev_subclass, ev_attr_list, &eid,
	    ((kmflag == KM_SLEEP) ? DDI_SLEEP : DDI_NOSLEEP));
	if (err != 0) {
		cmn_err(CE_WARN, "%s%d: Failed to log %s event",
		    ddi_driver_name(self), ddi_get_instance(self), EC_DR);
	}

	nvlist_free(ev_attr_list);
}

int
pcihp_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp)
{
	int pci_dev;

	if (dev == DDI_DEV_T_ANY)
		goto skip;

	if (strcmp(name, "pci-occupant") == 0) {
		pci_dev = PCIHP_AP_MINOR_NUM_TO_PCI_DEVNUM(getminor(dev));
		pcihp_create_occupant_props(dip, dev, pci_dev);
	}
	/* other cases... */
skip:
	return (ddi_prop_op(dev, dip, prop_op, flags, name, valuep, lengthp));
}

/*
 * this function is called only for SPARC platforms, where we may have
 * a mix n' match of direct vs indirectly mapped configuration space.
 * On x86, this function should always return success since the configuration
 * space is always indirect mapped.
 */
/*ARGSUSED*/
static int
pcihp_indirect_map(dev_info_t *dip)
{
#if defined(__sparc)
	int rc = DDI_FAILURE;

	if (ddi_prop_get_int(DDI_DEV_T_ANY, ddi_get_parent(dip), 0,
	    PCI_DEV_CONF_MAP_PROP, DDI_FAILURE) != DDI_FAILURE)
		rc = DDI_SUCCESS;
	else
		if (ddi_prop_get_int(DDI_DEV_T_ANY, ddi_get_parent(dip),
		    0, PCI_BUS_CONF_MAP_PROP, DDI_FAILURE) != DDI_FAILURE)
			rc = DDI_SUCCESS;
	return (rc);
#else
	return (DDI_SUCCESS);
#endif
}

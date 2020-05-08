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
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/obpdefs.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/autoconf.h>
#include <sys/stat.h>
#include <sys/serengeti.h>
#include <sys/ssm.h>
#include <sys/sgsbbc_mailbox.h>
#include <sys/sgevents.h>
#include <sys/sysevent.h>
#include <sys/sysevent/dr.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/ndi_impldefs.h>
#include <sys/ddifm.h>
#include <sys/ndifm.h>
#include <sys/sbd_ioctl.h>

/* Useful debugging Stuff */
#include <sys/nexusdebug.h>

/*
 * module ssm.c
 *
 * This module is a nexus driver designed to support the ssm nexus driver
 * and all children below it. This driver does not handle any of the
 * DDI functions passed up to it by the ssm driver, but instead allows
 * them to bubble up to the root node.
 */


/*
 * Function prototypes
 */
extern int plat_max_boards();

static int
ssm_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result);

static int
ssm_attach(dev_info_t *, ddi_attach_cmd_t);

static int
ssm_detach(dev_info_t *, ddi_detach_cmd_t);

static int
ssm_open(dev_t *, int, int, cred_t *);

static int
ssm_close(dev_t, int, int, cred_t *);

static int
ssm_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static int
ssm_ctlops(dev_info_t *, dev_info_t *, ddi_ctl_enum_t, void *, void *);

static int
ssm_make_nodes(dev_info_t *dip, int instance, int ssm_nodeid);

static int
ssm_generate_event(int node, int board, int hint);

/*
 * FMA error callback
 * Register error handling callback with our parent. We will just call
 * our children's error callbacks and return their status.
 */
static int
ssm_err_callback(dev_info_t *dip, ddi_fm_error_t *derr, const void *impl_data);

/*
 * fm_init busop to initialize our children
 */
static int
ssm_fm_init_child(dev_info_t *dip, dev_info_t *tdip, int cap,
    ddi_iblock_cookie_t *ibc);

/*
 * init/fini routines to alloc/dealloc fm structures and
 * register/unregister our callback.
 */
static void
ssm_fm_init(struct ssm_soft_state *softsp);

static void
ssm_fm_fini(struct ssm_soft_state *softsp);

/*
 * DR event handlers
 * We want to register the event handlers once for all instances. In the
 * other hand we have register them after the sbbc has been attached.
 * event_initialize gives us the logic of only registering the events only
 * once
 */
int event_initialized = 0;
uint_t ssm_dr_event_handler(char *);

/*
 * Event lock and state
 */
static kmutex_t ssm_event_lock;
int ssm_event_state;

/*
 * DR event msg and payload
 */
static sbbc_msg_t event_msg;
static sg_system_fru_descriptor_t payload;

struct ssm_node2inst {
	int	nodeid;		/* serengeti node #, NOT prom nodeid */
	int	inst;
	struct ssm_node2inst *next;
};
static kmutex_t ssm_node2inst_lock;
static struct ssm_node2inst ssm_node2inst_map = {-1, -1, NULL};


/*
 * Configuration data structures
 */
static struct bus_ops ssm_bus_ops = {
	BUSO_REV,
	ddi_bus_map,		/* map */
	0,			/* get_intrspec */
	0,			/* add_intrspec */
	0,			/* remove_intrspec */
	i_ddi_map_fault,	/* map_fault */
	0,			/* dma_map */
	ddi_dma_allochdl,
	ddi_dma_freehdl,
	ddi_dma_bindhdl,
	ddi_dma_unbindhdl,
	ddi_dma_flush,
	ddi_dma_win,
	ddi_dma_mctl,		/* dma_ctl */
	ssm_ctlops,		/* ctl */
	ddi_bus_prop_op,	/* prop_op */
	ndi_busop_get_eventcookie,
	ndi_busop_add_eventcall,
	ndi_busop_remove_eventcall,
	ndi_post_event,
	0,
	0,
	0,
	ssm_fm_init_child,
	NULL,
	NULL,
	NULL,
	0,
	i_ddi_intr_ops
};

static struct cb_ops ssm_cb_ops = {
	ssm_open,			/* open */
	ssm_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	ssm_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* cb_prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};

static struct dev_ops ssm_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt */
	ssm_info,		/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	ssm_attach,		/* attach */
	ssm_detach,		/* detach */
	nulldev,		/* reset */
	&ssm_cb_ops,		/* driver operations */
	&ssm_bus_ops,		/* bus_ops */
	nulldev,		/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * Driver globals
 */
static void *ssm_softstates;		/* ssm soft state hook */

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"SSM Nexus",		/* name of module */
	&ssm_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,		/* rev */
	(void *)&modldrv,
	NULL
};

static int ssm_loaded_sbd = FALSE;
kmutex_t ssm_lock;
static int init_child(dev_info_t *child);

/*
 * These are the module initialization routines.
 */

int
_init(void)
{
	int error;

#if defined(DEBUG)
	debug_print_level = 0x0;
#endif

	/* Initialize soft state pointer. */
	if ((error = ddi_soft_state_init(&ssm_softstates,
	    sizeof (struct ssm_soft_state), SSM_MAX_INSTANCES)) != 0)
		return (error);

	/* Install the module. */
	error = mod_install(&modlinkage);
	if (error != 0)
		ddi_soft_state_fini(&ssm_softstates);

	mutex_init(&ssm_lock, NULL, MUTEX_DRIVER, NULL);

	return (error);
}

int
_fini(void)
{
	int error;

	/* Remove the module. */
	if ((error = mod_remove(&modlinkage)) != 0)
		return (error);

	/*
	 * Unregister the event handler
	 */
	(void) sbbc_mbox_unreg_intr(MBOX_EVENT_GENERIC, ssm_dr_event_handler);
	mutex_destroy(&ssm_event_lock);

	/* Free the soft state info. */
	ddi_soft_state_fini(&ssm_softstates);
	mutex_destroy(&ssm_lock);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* device driver entry points */

/*
 * info entry point:
 */

/* ARGSUSED */
static int
ssm_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t	dev;
	int	instance;

	if (infocmd == DDI_INFO_DEVT2INSTANCE) {
		dev = (dev_t)arg;
		instance = (getminor(dev) >> SSM_INSTANCE_SHIFT);
		*result = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

/*
 * attach entry point:
 */

static int
ssm_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int instance;
	struct ssm_soft_state *softsp;
	struct ssm_node2inst *prev, *sp, *tsp;

	DPRINTF(SSM_ATTACH_DEBUG, ("ssm_attach\n"));

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(devi);

	if (ddi_soft_state_zalloc(ssm_softstates, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);

	softsp = ddi_get_soft_state(ssm_softstates, instance);

	/* Set the dip in the soft state */
	softsp->dip = devi;
	softsp->top_node = devi;
	mutex_init(&softsp->ssm_sft_lock, NULL, MUTEX_DRIVER, NULL);

	DPRINTF(SSM_ATTACH_DEBUG, ("ssm-%d: devi= 0x%p, softsp=0x%p\n",
	    instance, (void *)devi, (void *)softsp));

	if ((softsp->ssm_nodeid = (int)ddi_getprop(DDI_DEV_T_ANY, softsp->dip,
	    DDI_PROP_DONTPASS, "nodeid", -1)) == -1) {
		cmn_err(CE_WARN, "ssm%d: unable to retrieve %s property",
		    instance, "nodeid");
		ddi_soft_state_free(ssm_softstates, instance);
		return (DDI_FAILURE);
	}

	/* nothing to suspend/resume here */
	(void) ddi_prop_create(DDI_DEV_T_NONE, devi, DDI_PROP_CANSLEEP,
	    "pm-hardware-state", (caddr_t)"no-suspend-resume",
	    strlen("no-suspend-resume") + 1);

#if DEBUG
	if (ddi_create_minor_node(devi, "debug", S_IFCHR, instance,
	    DDI_NT_NEXUS, 0) != DDI_SUCCESS) {
		ddi_soft_state_free(ssm_softstates, instance);
		return (DDI_FAILURE);
	}
#endif

	if (ssm_make_nodes(devi, instance, softsp->ssm_nodeid)) {
		cmn_err(CE_WARN, "ssm:%s:%d: failed to make nodes",
		    ddi_driver_name(devi), instance);
		ddi_remove_minor_node(devi, NULL);
		ddi_soft_state_free(ssm_softstates, instance);
		return (DDI_FAILURE);
	}
	ssm_fm_init(softsp);
	ddi_report_dev(devi);

	if (event_initialized == 0) {
		int rv;
		/*
		 * Register DR event handler
		 */
		mutex_init(&ssm_event_lock,  NULL, MUTEX_DRIVER, NULL);
		event_msg.msg_buf = (caddr_t)&payload;
		event_msg.msg_len = sizeof (payload);

		rv = sbbc_mbox_reg_intr(MBOX_EVENT_GENERIC,
		    ssm_dr_event_handler, &event_msg,
		    (uint_t *)&ssm_event_state, &ssm_event_lock);

		if (rv == EINVAL)
		event_initialized = 1;
	}

	/*
	 * Preallocate to avoid sleeping with ssm_node2inst_lock held -
	 * low level interrupts use this mutex.
	 */
	tsp = kmem_zalloc(sizeof (struct ssm_node2inst), KM_SLEEP);

	mutex_enter(&ssm_node2inst_lock);

	for (prev = NULL, sp = &ssm_node2inst_map; sp != NULL;
	    prev = sp, sp = sp->next) {
		ASSERT(sp->inst != instance);
		ASSERT(sp->nodeid != softsp->ssm_nodeid);
		if (sp->inst == -1)
			break;
	}

	if (sp == NULL) {
		ASSERT(prev->next == NULL);
		sp = prev->next = tsp;
		tsp = NULL;
		sp->next = NULL;
	}

	sp->inst = instance;
	sp->nodeid = softsp->ssm_nodeid;

	mutex_exit(&ssm_node2inst_lock);

	if (tsp != NULL)
		kmem_free(tsp, sizeof (struct ssm_node2inst));

	return (DDI_SUCCESS);
}

/*
 * detach entry point:
 */
/*ARGSUSED*/
static int
ssm_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int instance, rv;
	int (*sbd_teardown_instance) (int, caddr_t);
	ssm_sbdp_info_t	sbdp_info;
	struct ssm_soft_state *softsp;
	struct ssm_node2inst *prev, *sp;

	instance = ddi_get_instance(devi);
	softsp = ddi_get_soft_state(ssm_softstates, instance);

	if (softsp == NULL) {
		cmn_err(CE_WARN,
		    "ssm_open bad instance number %d", instance);
		return (ENXIO);
	}

	instance = ddi_get_instance(devi);

	switch (cmd) {
	case DDI_DETACH:
		ddi_remove_minor_node(devi, NULL);

		sbd_teardown_instance = (int (*) (int, caddr_t))
		    modlookup("misc/sbd", "sbd_teardown_instance");

		if (!sbd_teardown_instance) {
			cmn_err(CE_WARN, "cannot find sbd_teardown_instance");
			return (DDI_FAILURE);
		}

		sbdp_info.instance = instance;
		sbdp_info.wnode = softsp->ssm_nodeid;
		rv = (*sbd_teardown_instance)(instance, (caddr_t)&sbdp_info);

		if (rv != DDI_SUCCESS) {
			cmn_err(CE_WARN, "cannot run sbd_teardown_instance");
			return (DDI_FAILURE);
		}
		ssm_fm_fini(softsp);
		mutex_destroy(&softsp->ssm_sft_lock);
		ddi_soft_state_free(ssm_softstates, instance);

		mutex_enter(&ssm_node2inst_lock);
		for (prev = NULL, sp = &ssm_node2inst_map; sp != NULL;
		    prev = sp, sp = sp->next) {
			/* Only the head of the list can persist if unused */
			ASSERT(prev == NULL || sp->inst != -1);
			if (sp->inst == instance)
				break;
		}
		ASSERT(sp != NULL);

		if (sp != &ssm_node2inst_map) {
			prev->next = sp->next;
			kmem_free(sp, sizeof (struct ssm_node2inst));
		} else {
			/*
			 * Invalidate the head element, but retain the rest
			 * of the list - "next" is still valid.
			 */

			sp->nodeid = -1;
			sp->inst = -1;
		}
		mutex_exit(&ssm_node2inst_lock);

		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

extern void make_ddi_ppd(dev_info_t *, struct ddi_parent_private_data **);
extern struct ddi_parent_private_data *init_regspec_64(dev_info_t *);

static int
name_child(dev_info_t *child, char *name, int namelen)
{
	struct regspec *rp;
	struct ddi_parent_private_data *pdptr;
	int portid = 0;
	int regbase = -1;
	extern uint_t root_phys_addr_lo_mask;

	make_ddi_ppd(child, &pdptr);
	ddi_set_parent_data(child, pdptr);

	name[0] = '\0';
	if (sparc_pd_getnreg(child) == 0)
		return (DDI_SUCCESS);

	rp = sparc_pd_getreg(child, 0);

	portid = ddi_prop_get_int(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS, "portid", -1);
	if (portid == -1) {
		cmn_err(CE_WARN, "could not find portid property in %s",
		    DEVI(child)->devi_node_name);
	} else {
		regbase = rp->regspec_addr & root_phys_addr_lo_mask;
	}
	(void) snprintf(name, namelen, "%x,%x", portid, regbase);
	return (DDI_SUCCESS);
}

static int
init_child(dev_info_t *child)
{
	char name[MAXNAMELEN];

	(void) name_child(child, name, MAXNAMELEN);
	ddi_set_name_addr(child, name);
	if ((ndi_dev_is_persistent_node(child) == 0) &&
	    (ndi_merge_node(child, name_child) == DDI_SUCCESS)) {
		impl_ddi_sunbus_removechild(child);
		return (DDI_FAILURE);
	}

	(void) init_regspec_64(child);
	return (DDI_SUCCESS);
}

/*
 * Control ops entry point:
 *
 * Requests handled completely:
 *      DDI_CTLOPS_INITCHILD
 *      DDI_CTLOPS_UNINITCHILD
 *	DDI_CTLOPS_REPORTDEV
 * All others are passed to the parent.
 * The name of the ssm node is ssm@nodeid,0.
 * ssm is the equivalent of rootnex.
 */
static int
ssm_ctlops(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t op, void *arg,
    void *result)
{
	int rval;

	switch (op) {
	case DDI_CTLOPS_INITCHILD: {
		DPRINTF(SSM_CTLOPS_DEBUG, ("DDI_CTLOPS_INITCHILD\n"));
		return (init_child((dev_info_t *)arg));
	}

	case DDI_CTLOPS_UNINITCHILD: {
		DPRINTF(SSM_CTLOPS_DEBUG, ("DDI_CTLOPS_UNINITCHILD\n"));
		impl_ddi_sunbus_removechild((dev_info_t *)arg);
		return (DDI_SUCCESS);
	}

	case DDI_CTLOPS_REPORTDEV: {
		char buf[80];
		char *p = buf;
		dev_info_t *parent;
		int portid;

		DPRINTF(SSM_CTLOPS_DEBUG, ("DDI_CTLOPS_REPORTDEV\n"));
		parent = ddi_get_parent(rdip);

		(void) sprintf(p, "%s%d at %s%d", DEVI(rdip)->devi_name,
		    DEVI(rdip)->devi_instance, ddi_get_name(parent),
		    ddi_get_instance(parent));
		p += strlen(p);

		/* Fetch Safari Extended Agent ID of this device. */
		portid = (int)ddi_getprop(DDI_DEV_T_ANY, rdip,
		    DDI_PROP_DONTPASS, "portid", -1);

		/*
		 * If this is one of the ssm children it will have
		 * portid property and its parent will be ssm.
		 * In this case report Node number and Safari id.
		 */
		if (portid != -1 &&
		    strcmp("ssm", ddi_get_name(parent)) == 0) {
			struct regspec *rp;
			int node;
			int safid;
			int n;

			rp = sparc_pd_getreg(rdip, 0);
			n = sparc_pd_getnreg(rdip);
			ASSERT(n > 0);

			node  = SG_PORTID_TO_NODEID(portid);
			safid = SG_PORTID_TO_SAFARI_ID(portid);

			(void) strcpy(p, ": ");
			p += strlen(p);

			(void) sprintf(p, "Node %d Safari id %d 0x%x%s",
			    node, safid,
			    rp->regspec_addr,
			    (n > 1 ? "" : " ..."));
			p += strlen(p);
		}

		cmn_err(CE_CONT, "?%s\n", buf);
		rval = DDI_SUCCESS;

		break;
	}

	default:
		rval = ddi_ctlops(dip, rdip, op, arg, result);

		break;
	}

	return (rval);
}

/*ARGSUSED*/
static int
ssm_make_nodes(dev_info_t *dip, int instance, int ssm_nodeid)
{
	int		rv;
	minor_t		minor_num, bd;
	auto char	filename[20];

	for (bd = 0; bd < plat_max_boards(); bd++) {
		if (SG_BOARD_IS_CPU_TYPE(bd))
			(void) sprintf(filename, "N%d.SB%d", ssm_nodeid, bd);
		else
			(void) sprintf(filename, "N%d.IB%d", ssm_nodeid, bd);

		minor_num = (instance << SSM_INSTANCE_SHIFT) | bd;

		rv = ddi_create_minor_node(dip, filename, S_IFCHR,
		    minor_num, DDI_NT_SBD_ATTACHMENT_POINT, 0);
		if (rv == DDI_FAILURE) {
			cmn_err(CE_WARN,
			    "ssm_make_nodes:%d: failed to create "
			    "minor node (%s, 0x%x)",
			    instance, filename, minor_num);
			return (-1);
		}
	}

	return (0);
}


/* ARGSUSED */
static int
ssm_open(dev_t *devi, int flags, int otyp, cred_t *credp)
{
	struct ssm_soft_state *softsp;
	minor_t board, instance;
	int (*sbd_setup_instance)(int, dev_info_t *, int, int, caddr_t);
	ssm_sbdp_info_t	sbdp_info;
	int rv;

	instance = (getminor(*devi) >> SSM_INSTANCE_SHIFT);

	softsp = ddi_get_soft_state(ssm_softstates, instance);
	if (softsp == NULL) {
		cmn_err(CE_WARN, "ssm_open bad instance number %d", instance);
		return (ENXIO);
	}

	board = (getminor(*devi) & SSM_BOARD_MASK);

	if (board < 0 || board > plat_max_boards()) {
		return (ENXIO);
	}

	mutex_enter(&ssm_lock);
	if (instance == 0 && ssm_loaded_sbd == FALSE) {

		if (modload("misc", "sbd") == -1) {
			cmn_err(CE_WARN, "ssm_open: cannot load sbd");
			mutex_exit(&ssm_lock);
			return (EIO);
		}
		ssm_loaded_sbd = TRUE;
	}
	mutex_exit(&ssm_lock);

	mutex_enter(&softsp->ssm_sft_lock);
	if (softsp->initialized == FALSE) {

		if (softsp->top_node == NULL) {
			cmn_err(CE_WARN, "cannot find ssm top dnode");
			mutex_exit(&softsp->ssm_sft_lock);
			return (EIO);
		}

		sbd_setup_instance = (int (*)(int, dev_info_t *, int, int,
		    caddr_t))modlookup("misc/sbd", "sbd_setup_instance");

		if (!sbd_setup_instance) {
			cmn_err(CE_WARN, "cannot find sbd_setup_instance");
			mutex_exit(&softsp->ssm_sft_lock);
			return (EIO);
		}

		sbdp_info.instance = instance;
		sbdp_info.wnode = softsp->ssm_nodeid;

		rv = (*sbd_setup_instance)(instance, softsp->top_node,
		    plat_max_boards(), softsp->ssm_nodeid,
		    (caddr_t)&sbdp_info);
		if (rv != DDI_SUCCESS) {
			cmn_err(CE_WARN, "cannot run sbd_setup_instance");
			mutex_exit(&softsp->ssm_sft_lock);
			return (EIO);
		}
		softsp->initialized = TRUE;
	}
	mutex_exit(&softsp->ssm_sft_lock);

	return (DDI_SUCCESS);
}


/* ARGSUSED */
static int
ssm_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	struct ssm_soft_state *softsp;
	minor_t board, instance;

	instance = (getminor(dev) >> SSM_INSTANCE_SHIFT);

	softsp = ddi_get_soft_state(ssm_softstates, instance);
	if (softsp == NULL)
		return (ENXIO);

	board = (getminor(dev) & SSM_BOARD_MASK);

	if (board < 0 || board > plat_max_boards())
		return (ENXIO);

	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
ssm_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	struct ssm_soft_state *softsp;
	char *addr;
	struct devctl_iocdata *dcp;
	int instance, rv = 0;
	int (*sbd_ioctl) (dev_t, int, intptr_t, int, char *);

	instance = (getminor(dev) >> SSM_INSTANCE_SHIFT);
	softsp = ddi_get_soft_state(ssm_softstates, instance);
	if (softsp == NULL)
		return (ENXIO);

	switch (cmd) {

	case DEVCTL_BUS_CONFIGURE:
		/*
		 * read devctl ioctl data
		 */
		if (ndi_dc_allochdl((void *)arg, &dcp) != NDI_SUCCESS)
			return (EFAULT);

		addr = ndi_dc_getaddr(dcp);
		cmn_err(CE_NOTE,
		    "DEVCTL_BUS_CONFIGURE: device id is %s\n", addr);
		ndi_dc_freehdl(dcp);
		break;

	case DEVCTL_BUS_UNCONFIGURE:
		if (ndi_dc_allochdl((void *)arg, &dcp) != NDI_SUCCESS)
			return (EFAULT);

		addr = ndi_dc_getaddr(dcp);
		cmn_err(CE_NOTE,
		    "DEVCTL_BUS_UNCONFIGURE: device id is %s\n", addr);
		ndi_dc_freehdl(dcp);
		break;

#ifdef DEBUG
	case SSM_TEARDOWN_SBD: {
		ssm_sbdp_info_t	sbdp_info;
		int (*sbd_teardown_instance) (int, caddr_t);
		sbd_teardown_instance = (int (*) (int, caddr_t))
		    modlookup("misc/sbd", "sbd_teardown_instance");

		if (!sbd_teardown_instance) {
			cmn_err(CE_WARN, "cannot find sbd_teardown_instance");
			return (EFAULT);
		}

		sbdp_info.instance = instance;
		sbdp_info.wnode = softsp->ssm_nodeid;
		rv = (*sbd_teardown_instance)(instance, (caddr_t)&sbdp_info);
		if (rv != DDI_SUCCESS) {
			cmn_err(CE_WARN, "cannot run sbd_teardown_instance");
			return (EFAULT);
		}

		ssm_loaded_sbd = FALSE;
		softsp->initialized = FALSE;
	}
#endif


	default: {
		char	event = 0;

		sbd_ioctl = (int (*) (dev_t, int, intptr_t, int, char *))
		    modlookup("misc/sbd", "sbd_ioctl");

		if (sbd_ioctl)
			rv = (*sbd_ioctl) (dev, cmd, arg, mode, &event);
		else {
			cmn_err(CE_WARN, "cannot find sbd_ioctl");
			return (ENXIO);
		}
		/*
		 * Check to see if we need to send an event
		 */
		if (event == 1) {
			int slot;
			int hint = SE_NO_HINT;

			if (rv == 0) {
				if (cmd == SBD_CMD_CONNECT ||
				    cmd == SBD_CMD_CONFIGURE)
					hint = SE_HINT_INSERT;
				else if (cmd == SBD_CMD_UNCONFIGURE ||
				    cmd == SBD_CMD_DISCONNECT)
					hint = SE_HINT_REMOVE;
			}

			slot = (getminor(dev) & SSM_BOARD_MASK);
			(void) ssm_generate_event(softsp->ssm_nodeid, slot,
			    hint);
		}
		break;
	}
	}

	return (rv);
}

void
ssm_get_attch_pnt(int node, int board, char *attach_pnt)
{
	struct ssm_node2inst	*sp;

	/*
	 * Hold this mutex, until we are done so that ssm dip
	 * doesn't detach.
	 */
	mutex_enter(&ssm_node2inst_lock);

	for (sp = &ssm_node2inst_map; sp != NULL; sp = sp->next) {
		if (sp->inst == -1)
			continue;
		if (sp->nodeid == node)
			break;
	}

	if (sp == NULL) {
		/* We didn't find the ssm dip, return failure */
		attach_pnt[0] = '\0';
		mutex_exit(&ssm_node2inst_lock);
		return;
	}

	/*
	 * we have the instance, and the board, construct the attch pnt
	 */
	if (SG_BOARD_IS_CPU_TYPE(board))
		(void) sprintf(attach_pnt, "ssm%d:N%d.SB%d",
		    sp->inst, node, board);
	else
		(void) sprintf(attach_pnt, "ssm%d:N%d.IB%d",
		    sp->inst, node, board);

	mutex_exit(&ssm_node2inst_lock);
}

/*
 * Generate an event to sysevent
 */
static int
ssm_generate_event(int node, int board, int hint)
{
	sysevent_t			*ev;
	sysevent_id_t			eid;
	int				rv = 0;
	sysevent_value_t		evnt_val;
	sysevent_attr_list_t		*evnt_attr_list = NULL;
	char				attach_pnt[MAXPATHLEN];


	attach_pnt[0] = '\0';
	ssm_get_attch_pnt(node, board, attach_pnt);

	if (attach_pnt[0] == '\0')
		return (-1);

	ev = sysevent_alloc(EC_DR, ESC_DR_AP_STATE_CHANGE, EP_DDI,
	    KM_SLEEP);
	evnt_val.value_type = SE_DATA_TYPE_STRING;
	evnt_val.value.sv_string = attach_pnt;

	rv = sysevent_add_attr(&evnt_attr_list, DR_AP_ID, &evnt_val, KM_SLEEP);
	if (rv != 0) {
		cmn_err(CE_WARN, "Failed to add attr [%s] for %s event",
		    DR_AP_ID, EC_DR);
		sysevent_free(ev);
		return (rv);
	}

	/*
	 * Add the hint
	 */
	evnt_val.value_type = SE_DATA_TYPE_STRING;
	evnt_val.value.sv_string = SE_HINT2STR(hint);

	rv = sysevent_add_attr(&evnt_attr_list, DR_HINT, &evnt_val, KM_SLEEP);
	if (rv != 0) {
		cmn_err(CE_WARN, "Failed to add attr [%s] for %s event",
		    DR_HINT, EC_DR);
		sysevent_free_attr(evnt_attr_list);
		sysevent_free(ev);
		return (-1);
	}

	if (sysevent_attach_attributes(ev, evnt_attr_list) != 0) {
		cmn_err(CE_WARN, "Failed to attach attr list for %s event",
		    EC_DR);
		sysevent_free_attr(evnt_attr_list);
		sysevent_free(ev);
		return (-1);
	}

	rv = log_sysevent(ev, KM_NOSLEEP, &eid);
	if (rv != 0) {
		cmn_err(CE_WARN, "ssm_dr_event_handler: failed to log event");
	}

	sysevent_free(ev);

	return (rv);
}

/*
 * DR Event Handler
 */
uint_t
ssm_dr_event_handler(char *arg)
{
	sg_system_fru_descriptor_t	*fdp;
	int				hint;


	fdp = (sg_system_fru_descriptor_t *)(((sbbc_msg_t *)arg)->msg_buf);
	if (fdp == NULL) {
		DPRINTF(SSM_EVENT_DEBUG,
		    ("ssm_dr_event_handler: ARG is null\n"));
		return (DDI_INTR_CLAIMED);
	}
#ifdef DEBUG
	DPRINTF(SSM_EVENT_DEBUG, ("ssm_dr_event_handler called\n"));
	DPRINTF(SSM_EVENT_DEBUG, ("\tnode\t%d\n", fdp->node));
	DPRINTF(SSM_EVENT_DEBUG, ("\tslot\t%d\n", fdp->slot));
	DPRINTF(SSM_EVENT_DEBUG, ("\tparent_hdl\t0x%lx\n", fdp->parent_hdl));
	DPRINTF(SSM_EVENT_DEBUG, ("\tchild_hdl\t0x%lx\n", fdp->child_hdl));
	DPRINTF(SSM_EVENT_DEBUG, ("\tevent_details\t%s\n",
	    EVNT2STR(fdp->event_details)));
#endif

	switch (fdp->event_details) {
	case SG_EVT_BOARD_ABSENT:
		hint = SE_HINT_REMOVE;
		break;
	case SG_EVT_BOARD_PRESENT:
		hint = SE_HINT_INSERT;
		break;
	default:
		hint = SE_NO_HINT;
		break;

	}

	(void) ssm_generate_event(fdp->node, fdp->slot, hint);

	return (DDI_INTR_CLAIMED);
}

/*
 * Initialize our FMA resources
 */
static void
ssm_fm_init(struct ssm_soft_state *softsp)
{
	softsp->ssm_fm_cap = DDI_FM_EREPORT_CAPABLE | DDI_FM_ERRCB_CAPABLE |
	    DDI_FM_ACCCHK_CAPABLE | DDI_FM_DMACHK_CAPABLE;

	/*
	 * Request or capability level and get our parents capability
	 * and ibc.
	 */
	ddi_fm_init(softsp->dip, &softsp->ssm_fm_cap, &softsp->ssm_fm_ibc);
	ASSERT((softsp->ssm_fm_cap & DDI_FM_EREPORT_CAPABLE) &&
	    (softsp->ssm_fm_cap & DDI_FM_ERRCB_CAPABLE));
	/*
	 * Register error callback with our parent.
	 */
	ddi_fm_handler_register(softsp->dip, ssm_err_callback, NULL);
}

/*
 * Breakdown our FMA resources
 */
static void
ssm_fm_fini(struct ssm_soft_state *softsp)
{
	/*
	 * Clean up allocated fm structures
	 */
	ASSERT(softsp->ssm_fm_cap & DDI_FM_EREPORT_CAPABLE);
	ddi_fm_handler_unregister(softsp->dip);
	ddi_fm_fini(softsp->dip);
}

/*
 * Initialize FMA resources for children devices. Called when
 * child calls ddi_fm_init().
 */
/*ARGSUSED*/
static int
ssm_fm_init_child(dev_info_t *dip, dev_info_t *tdip, int cap,
    ddi_iblock_cookie_t *ibc)
{
	struct ssm_soft_state *softsp = ddi_get_soft_state(ssm_softstates,
	    ddi_get_instance(dip));

	*ibc = softsp->ssm_fm_ibc;
	return (softsp->ssm_fm_cap);
}

/*
 * FMA registered error callback
 */
/*ARGSUSED*/
static int
ssm_err_callback(dev_info_t *dip, ddi_fm_error_t *derr, const void *impl_data)
{
	/* Call our children error handlers */
	return (ndi_fm_handler_dispatch(dip, NULL, derr));
}

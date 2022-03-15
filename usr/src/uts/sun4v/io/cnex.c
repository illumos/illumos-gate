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
 * Logical domain channel devices are devices implemented entirely
 * in software; cnex is the nexus for channel-devices. They use
 * the HV channel interfaces via the LDC transport module to send
 * and receive data and to register callbacks.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/devops.h>
#include <sys/instance.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/systm.h>
#include <sys/mkdev.h>
#include <sys/machsystm.h>
#include <sys/intreg.h>
#include <sys/intr.h>
#include <sys/ddi_intr_impl.h>
#include <sys/ivintr.h>
#include <sys/hypervisor_api.h>
#include <sys/ldc.h>
#include <sys/cnex.h>
#include <sys/mach_descrip.h>
#include <sys/hsvc.h>
#include <sys/sdt.h>

/*
 * Internal functions/information
 */
static struct cnex_intr_map cnex_class_to_intr[] = {
	{LDC_DEV_GENERIC,	PIL_3,	 0},
	{LDC_DEV_BLK,		PIL_4,	10},
	{LDC_DEV_BLK_SVC,	PIL_3,	10},
	{LDC_DEV_NT,		PIL_6,	35},
	{LDC_DEV_NT_SVC,	PIL_4,	35},
	{LDC_DEV_SERIAL,	PIL_6,	 0}
};
#define	CNEX_MAX_DEVS (sizeof (cnex_class_to_intr) / \
				sizeof (cnex_class_to_intr[0]))

#define	CNEX_TX_INTR_WEIGHT	0

#define	SUN4V_REG_SPEC2CFG_HDL(x)	((x >> 32) & ~(0xfull << 28))

static clock_t cnex_wait_usecs = 1000; /* wait time in usecs */
static int cnex_wait_retries = 3;
static void *cnex_state;

static uint_t cnex_intr_wrapper(caddr_t arg);
static dev_info_t *cnex_find_chan_dip(dev_info_t *dip, uint64_t chan_id,
    md_t *mdp, mde_cookie_t mde);

/*
 * Channel Interrupt Distribution
 *
 * In order to balance interrupts among available CPUs, we use
 * the intr_dist_cpuid_{add,remove}_device_weight() interface to
 * assign weights to channel interrupts. These weights, which are
 * defined in the cnex_intr_map structure, influence which CPU
 * is returned by intr_dist_cpuid() when called via the cnex
 * interrupt redistribution callback cnex_intr_redist().
 * Interrupts for VIO devclass channels are given more weight than
 * other interrupts because they are expected to occur more
 * frequently and have a larger impact on overall performance.
 * Transmit interrupts are given a zero weight because they are
 * not used.
 *
 * The interrupt weights influence the target CPU selection when
 * interrupts are redistributed and when they are added. However,
 * removal of interrupts can unbalance the distribution even if
 * they are removed in converse order--compared to the order they
 * are added. This can occur when interrupts are removed after
 * redistribution occurs.
 *
 * Channel interrupt weights affect interrupt-CPU distribution
 * relative to other weighted interrupts on the system. For VIO
 * devclass channels, values are chosen to match those used by
 * the PCI express nexus driver for net and storage devices.
 */
static void cnex_intr_redist(void *arg, int32_t weight_max, int32_t weight);
static int cnex_intr_new_cpu(cnex_soft_state_t *ssp, cnex_intr_t *iinfo);
static int cnex_intr_dis_wait(cnex_soft_state_t *ssp, cnex_intr_t *iinfo);
static int32_t cnex_class_weight(ldc_dev_t devclass);

/*
 * Debug info
 */
#ifdef DEBUG

/*
 * Print debug messages
 *
 * set cnexdbg to 0xf for enabling all msgs
 * 0x8 - Errors
 * 0x4 - Warnings
 * 0x2 - All debug messages
 * 0x1 - Minimal debug messages
 */

int cnexdbg = 0x8;

static void
cnexdebug(const char *fmt, ...)
{
	char buf[512];
	va_list ap;

	va_start(ap, fmt);
	(void) vsprintf(buf, fmt, ap);
	va_end(ap);

	cmn_err(CE_CONT, "%s\n", buf);
}

#define	D1		\
if (cnexdbg & 0x01)	\
	cnexdebug

#define	D2		\
if (cnexdbg & 0x02)	\
	cnexdebug

#define	DWARN		\
if (cnexdbg & 0x04)	\
	cnexdebug

#define	DERR		\
if (cnexdbg & 0x08)	\
	cnexdebug

#else

#define	D1
#define	D2
#define	DWARN
#define	DERR

#endif

/*
 * Config information
 */
static int cnex_attach(dev_info_t *, ddi_attach_cmd_t);
static int cnex_detach(dev_info_t *, ddi_detach_cmd_t);
static int cnex_open(dev_t *, int, int, cred_t *);
static int cnex_close(dev_t, int, int, cred_t *);
static int cnex_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int cnex_ctl(dev_info_t *, dev_info_t *, ddi_ctl_enum_t, void *,
    void *);

static struct bus_ops cnex_bus_ops = {
	BUSO_REV,
	nullbusmap,		/* bus_map */
	NULL,			/* bus_get_intrspec */
	NULL,			/* bus_add_intrspec */
	NULL,			/* bus_remove_intrspec */
	i_ddi_map_fault,	/* bus_map_fault */
	ddi_no_dma_map,		/* bus_dma_map */
	ddi_no_dma_allochdl,	/* bus_dma_allochdl */
	NULL,			/* bus_dma_freehdl */
	NULL,			/* bus_dma_bindhdl */
	NULL,			/* bus_dma_unbindhdl */
	NULL,			/* bus_dma_flush */
	NULL,			/* bus_dma_win */
	NULL,			/* bus_dma_ctl */
	cnex_ctl,		/* bus_ctl */
	ddi_bus_prop_op,	/* bus_prop_op */
	0,			/* bus_get_eventcookie */
	0,			/* bus_add_eventcall */
	0,			/* bus_remove_eventcall	*/
	0,			/* bus_post_event */
	NULL,			/* bus_intr_ctl */
	NULL,			/* bus_config */
	NULL,			/* bus_unconfig */
	NULL,			/* bus_fm_init */
	NULL,			/* bus_fm_fini */
	NULL,			/* bus_fm_access_enter */
	NULL,			/* bus_fm_access_exit */
	NULL,			/* bus_power */
	NULL			/* bus_intr_op */
};

static struct cb_ops cnex_cb_ops = {
	cnex_open,			/* open */
	cnex_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	cnex_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* cb_prop_op */
	0,				/* streamtab  */
	D_MP | D_NEW | D_HOTPLUG	/* Driver compatibility flag */
};

static struct dev_ops cnex_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	ddi_getinfo_1to1,	/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	cnex_attach,		/* attach */
	cnex_detach,		/* detach */
	nodev,			/* reset */
	&cnex_cb_ops,		/* driver operations */
	&cnex_bus_ops,		/* bus operations */
	nulldev,		/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,
	"sun4v channel-devices nexus",
	&cnex_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

int
_init(void)
{
	int err;
	uint64_t majornum;
	uint64_t minornum;

	/*
	 * Check HV intr group api versioning.
	 * Note that cnex assumes interrupt cookies is
	 * in version 1.0 of the intr group api.
	 */
	if ((err = hsvc_version(HSVC_GROUP_INTR, &majornum, &minornum)) != 0) {
		cmn_err(CE_WARN, "cnex: failed to get intr api "
		    "group versioning errno=%d", err);
		return (err);
	} else if ((majornum != 1) && (majornum != 2)) {
		cmn_err(CE_WARN, "cnex: unsupported intr api group: "
		    "maj:0x%lx, min:0x%lx", majornum, minornum);
		return (ENOTSUP);
	}

	if ((err = ddi_soft_state_init(&cnex_state,
	    sizeof (cnex_soft_state_t), 0)) != 0) {
		return (err);
	}
	if ((err = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&cnex_state);
		return (err);
	}
	return (0);
}

int
_fini(void)
{
	int err;

	if ((err = mod_remove(&modlinkage)) != 0)
		return (err);
	ddi_soft_state_fini(&cnex_state);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Callback function invoked by the interrupt redistribution
 * framework. This will redirect interrupts at CPUs that are
 * currently available in the system.
 *
 * Note: any interrupts with weight greater than or equal to
 * weight_max must be redistributed when this callback is
 * invoked with (weight == weight_max) which will be once per
 * redistribution.
 */
/*ARGSUSED*/
static void
cnex_intr_redist(void *arg, int32_t weight_max, int32_t weight)
{
	cnex_ldc_t		*cldcp;
	cnex_soft_state_t	*cnex_ssp = arg;

	ASSERT(cnex_ssp != NULL);
	mutex_enter(&cnex_ssp->clist_lock);

	cldcp = cnex_ssp->clist;
	while (cldcp != NULL) {

		mutex_enter(&cldcp->lock);

		if (cldcp->tx.hdlr && (cldcp->tx.weight == weight ||
		    (weight_max == weight && cldcp->tx.weight > weight))) {
			(void) cnex_intr_new_cpu(cnex_ssp, &cldcp->tx);
		}

		if (cldcp->rx.hdlr && (cldcp->rx.weight == weight ||
		    (weight_max == weight && cldcp->rx.weight > weight))) {
			(void) cnex_intr_new_cpu(cnex_ssp, &cldcp->rx);
		}

		mutex_exit(&cldcp->lock);

		/* next channel */
		cldcp = cldcp->next;
	}

	mutex_exit(&cnex_ssp->clist_lock);
}

/*
 * Internal function to replace the CPU used by an interrupt
 * during interrupt redistribution.
 */
static int
cnex_intr_new_cpu(cnex_soft_state_t *ssp, cnex_intr_t *iinfo)
{
	int	intr_state;
	int 	rv;

	/* Determine if the interrupt is enabled */
	rv = hvldc_intr_getvalid(ssp->cfghdl, iinfo->ino, &intr_state);
	if (rv) {
		DWARN("cnex_intr_new_cpu: rx ino=0x%llx, can't get valid\n",
		    iinfo->ino);
		return (rv);
	}

	/* If it is enabled, disable it */
	if (intr_state == HV_INTR_VALID) {
		rv = cnex_intr_dis_wait(ssp, iinfo);
		if (rv) {
			return (rv);
		}
	}

	/* Target the interrupt at a new CPU. */
	iinfo->cpuid = intr_dist_cpuid();
	(void) hvldc_intr_settarget(ssp->cfghdl, iinfo->ino, iinfo->cpuid);
	intr_dist_cpuid_add_device_weight(iinfo->cpuid, iinfo->dip,
	    iinfo->weight);

	/* Re-enable the interrupt if it was enabled */
	if (intr_state == HV_INTR_VALID) {
		(void) hvldc_intr_setvalid(ssp->cfghdl, iinfo->ino,
		    HV_INTR_VALID);
	}

	return (0);
}

/*
 * Internal function to disable an interrupt and wait
 * for any pending interrupts to finish.
 */
static int
cnex_intr_dis_wait(cnex_soft_state_t *ssp, cnex_intr_t *iinfo)
{
	int rv, intr_state, retries;

	/* disable interrupts */
	rv = hvldc_intr_setvalid(ssp->cfghdl, iinfo->ino, HV_INTR_NOTVALID);
	if (rv) {
		DWARN("cnex_intr_dis_wait: ino=0x%llx, can't set valid\n",
		    iinfo->ino);
		return (ENXIO);
	}

	/*
	 * Make a best effort to wait for pending interrupts
	 * to finish. There is not much we can do if we timeout.
	 */
	retries = 0;

	do {
		rv = hvldc_intr_getstate(ssp->cfghdl, iinfo->ino, &intr_state);
		if (rv) {
			DWARN("cnex_intr_dis_wait: ino=0x%llx, can't get "
			    "state\n", iinfo->ino);
			return (ENXIO);
		}

		if (intr_state != HV_INTR_DELIVERED_STATE)
			break;

		drv_usecwait(cnex_wait_usecs);

	} while (!panicstr && ++retries <= cnex_wait_retries);

	return (0);
}

/*
 * Returns the interrupt weight to use for the specified devclass.
 */
static int32_t
cnex_class_weight(ldc_dev_t devclass)
{
	int idx;

	for (idx = 0; idx < CNEX_MAX_DEVS; idx++) {
		if (devclass == cnex_class_to_intr[idx].devclass) {
			return (cnex_class_to_intr[idx].weight);
		}
	}

	/*
	 * If this code is reached, the specified devclass is
	 * invalid. New devclasses should be added to
	 * cnex_class_to_intr.
	 */
	ASSERT(0);

	return (0);
}

/*
 * Exported interface to register a LDC endpoint with
 * the channel nexus
 */
static int
cnex_reg_chan(dev_info_t *dip, uint64_t id, ldc_dev_t devclass)
{
	int		idx;
	cnex_ldc_t	*cldcp;
	cnex_ldc_t	*new_cldcp;
	int		listsz, num_nodes, num_channels;
	md_t		*mdp = NULL;
	mde_cookie_t	rootnode, *listp = NULL;
	uint64_t	tmp_id;
	uint64_t	rxino = (uint64_t)-1;
	uint64_t	txino = (uint64_t)-1;
	cnex_soft_state_t *cnex_ssp;
	int		status, instance;
	dev_info_t	*chan_dip = NULL;

	/* Get device instance and structure */
	instance = ddi_get_instance(dip);
	cnex_ssp = ddi_get_soft_state(cnex_state, instance);

	/* Check to see if channel is already registered */
	mutex_enter(&cnex_ssp->clist_lock);
	cldcp = cnex_ssp->clist;
	while (cldcp) {
		if (cldcp->id == id) {
			DWARN("cnex_reg_chan: channel 0x%llx exists\n", id);
			mutex_exit(&cnex_ssp->clist_lock);
			return (EINVAL);
		}
		cldcp = cldcp->next;
	}
	mutex_exit(&cnex_ssp->clist_lock);

	/* Get the Tx/Rx inos from the MD */
	if ((mdp = md_get_handle()) == NULL) {
		DWARN("cnex_reg_chan: cannot init MD\n");
		return (ENXIO);
	}
	num_nodes = md_node_count(mdp);
	ASSERT(num_nodes > 0);

	listsz = num_nodes * sizeof (mde_cookie_t);
	listp = (mde_cookie_t *)kmem_zalloc(listsz, KM_SLEEP);

	rootnode = md_root_node(mdp);

	/* search for all channel_endpoint nodes */
	num_channels = md_scan_dag(mdp, rootnode,
	    md_find_name(mdp, "channel-endpoint"),
	    md_find_name(mdp, "fwd"), listp);
	if (num_channels <= 0) {
		DWARN("cnex_reg_chan: invalid channel id\n");
		kmem_free(listp, listsz);
		(void) md_fini_handle(mdp);
		return (EINVAL);
	}

	for (idx = 0; idx < num_channels; idx++) {

		/* Get the channel ID */
		status = md_get_prop_val(mdp, listp[idx], "id", &tmp_id);
		if (status) {
			DWARN("cnex_reg_chan: cannot read LDC ID\n");
			kmem_free(listp, listsz);
			(void) md_fini_handle(mdp);
			return (ENXIO);
		}
		if (tmp_id != id)
			continue;

		/* Get the Tx and Rx ino */
		status = md_get_prop_val(mdp, listp[idx], "tx-ino", &txino);
		if (status) {
			DWARN("cnex_reg_chan: cannot read Tx ino\n");
			kmem_free(listp, listsz);
			(void) md_fini_handle(mdp);
			return (ENXIO);
		}
		status = md_get_prop_val(mdp, listp[idx], "rx-ino", &rxino);
		if (status) {
			DWARN("cnex_reg_chan: cannot read Rx ino\n");
			kmem_free(listp, listsz);
			(void) md_fini_handle(mdp);
			return (ENXIO);
		}
		chan_dip = cnex_find_chan_dip(dip, id, mdp, listp[idx]);
		ASSERT(chan_dip != NULL);
	}
	kmem_free(listp, listsz);
	(void) md_fini_handle(mdp);

	/*
	 * check to see if we looped through the list of channel IDs without
	 * matching one (i.e. an 'ino' has not been initialised).
	 */
	if ((rxino == -1) || (txino == -1)) {
		DERR("cnex_reg_chan: no ID matching '%llx' in MD\n", id);
		return (ENOENT);
	}

	/* Allocate a new channel structure */
	new_cldcp = kmem_zalloc(sizeof (*new_cldcp), KM_SLEEP);

	/* Initialize the channel */
	mutex_init(&new_cldcp->lock, NULL, MUTEX_DRIVER, NULL);

	new_cldcp->id = id;
	new_cldcp->tx.ino = txino;
	new_cldcp->rx.ino = rxino;
	new_cldcp->devclass = devclass;
	new_cldcp->tx.weight = CNEX_TX_INTR_WEIGHT;
	new_cldcp->rx.weight = cnex_class_weight(devclass);
	new_cldcp->dip = chan_dip;

	/*
	 * Add channel to nexus channel list.
	 * Check again to see if channel is already registered since
	 * clist_lock was dropped above.
	 */
	mutex_enter(&cnex_ssp->clist_lock);
	cldcp = cnex_ssp->clist;
	while (cldcp) {
		if (cldcp->id == id) {
			DWARN("cnex_reg_chan: channel 0x%llx exists\n", id);
			mutex_exit(&cnex_ssp->clist_lock);
			mutex_destroy(&new_cldcp->lock);
			kmem_free(new_cldcp, sizeof (*new_cldcp));
			return (EINVAL);
		}
		cldcp = cldcp->next;
	}
	new_cldcp->next = cnex_ssp->clist;
	cnex_ssp->clist = new_cldcp;
	mutex_exit(&cnex_ssp->clist_lock);

	return (0);
}

/*
 * Add Tx/Rx interrupt handler for the channel
 */
static int
cnex_add_intr(dev_info_t *dip, uint64_t id, cnex_intrtype_t itype,
    uint_t (*hdlr)(), caddr_t arg1, caddr_t arg2)
{
	int		rv, idx, pil;
	cnex_ldc_t	*cldcp;
	cnex_intr_t	*iinfo;
	cnex_soft_state_t *cnex_ssp;
	int		instance;

	/* Get device instance and structure */
	instance = ddi_get_instance(dip);
	cnex_ssp = ddi_get_soft_state(cnex_state, instance);

	/* get channel info */
	mutex_enter(&cnex_ssp->clist_lock);
	cldcp = cnex_ssp->clist;
	while (cldcp) {
		if (cldcp->id == id)
			break;
		cldcp = cldcp->next;
	}
	if (cldcp == NULL) {
		DWARN("cnex_add_intr: channel 0x%llx does not exist\n", id);
		mutex_exit(&cnex_ssp->clist_lock);
		return (EINVAL);
	}
	mutex_exit(&cnex_ssp->clist_lock);

	/* get channel lock */
	mutex_enter(&cldcp->lock);

	/* get interrupt type */
	if (itype == CNEX_TX_INTR) {
		iinfo = &(cldcp->tx);
	} else if (itype == CNEX_RX_INTR) {
		iinfo = &(cldcp->rx);
	} else {
		DWARN("cnex_add_intr: invalid interrupt type\n", id);
		mutex_exit(&cldcp->lock);
		return (EINVAL);
	}

	/* check if a handler is already added */
	if (iinfo->hdlr != 0) {
		DWARN("cnex_add_intr: interrupt handler exists\n");
		mutex_exit(&cldcp->lock);
		return (EINVAL);
	}

	/* save interrupt handler info */
	iinfo->hdlr = hdlr;
	iinfo->arg1 = arg1;
	iinfo->arg2 = arg2;

	/* save data for DTrace probes used by intrstat(8) */
	iinfo->dip = cldcp->dip;
	iinfo->id = cldcp->id;

	iinfo->icookie = MINVINTR_COOKIE + iinfo->ino;

	/*
	 * Verify that the ino does not generate a cookie which
	 * is outside the (MINVINTR_COOKIE, MAXIVNUM) range of the
	 * system interrupt table.
	 */
	if (iinfo->icookie >= MAXIVNUM || iinfo->icookie < MINVINTR_COOKIE) {
		DWARN("cnex_add_intr: invalid cookie %x ino %x\n",
		    iinfo->icookie, iinfo->ino);
		mutex_exit(&cldcp->lock);
		return (EINVAL);
	}

	D1("cnex_add_intr: add hdlr, cfghdl=0x%llx, ino=0x%llx, "
	    "cookie=0x%llx\n", cnex_ssp->cfghdl, iinfo->ino, iinfo->icookie);

	/* Pick a PIL on the basis of the channel's devclass */
	for (idx = 0, pil = PIL_3; idx < CNEX_MAX_DEVS; idx++) {
		if (cldcp->devclass == cnex_class_to_intr[idx].devclass) {
			pil = cnex_class_to_intr[idx].pil;
			break;
		}
	}

	/* add interrupt to solaris ivec table */
	if (add_ivintr(iinfo->icookie, pil, (intrfunc)cnex_intr_wrapper,
	    (caddr_t)iinfo, NULL, NULL) != 0) {
		DWARN("cnex_add_intr: add_ivintr fail cookie %x ino %x\n",
		    iinfo->icookie, iinfo->ino);
		mutex_exit(&cldcp->lock);
		return (EINVAL);
	}

	/* set the cookie in the HV */
	rv = hvldc_intr_setcookie(cnex_ssp->cfghdl, iinfo->ino, iinfo->icookie);

	/* pick next CPU in the domain for this channel */
	iinfo->cpuid = intr_dist_cpuid();

	/* set the target CPU and then enable interrupts */
	rv = hvldc_intr_settarget(cnex_ssp->cfghdl, iinfo->ino, iinfo->cpuid);
	if (rv) {
		DWARN("cnex_add_intr: ino=0x%llx, cannot set target cpu\n",
		    iinfo->ino);
		goto hv_error;
	}
	rv = hvldc_intr_setstate(cnex_ssp->cfghdl, iinfo->ino,
	    HV_INTR_IDLE_STATE);
	if (rv) {
		DWARN("cnex_add_intr: ino=0x%llx, cannot set state\n",
		    iinfo->ino);
		goto hv_error;
	}
	rv = hvldc_intr_setvalid(cnex_ssp->cfghdl, iinfo->ino, HV_INTR_VALID);
	if (rv) {
		DWARN("cnex_add_intr: ino=0x%llx, cannot set valid\n",
		    iinfo->ino);
		goto hv_error;
	}

	intr_dist_cpuid_add_device_weight(iinfo->cpuid, iinfo->dip,
	    iinfo->weight);

	mutex_exit(&cldcp->lock);
	return (0);

hv_error:
	(void) rem_ivintr(iinfo->icookie, pil);
	mutex_exit(&cldcp->lock);
	return (ENXIO);
}


/*
 * Exported interface to unregister a LDC endpoint with
 * the channel nexus
 */
static int
cnex_unreg_chan(dev_info_t *dip, uint64_t id)
{
	cnex_ldc_t	*cldcp, *prev_cldcp;
	cnex_soft_state_t *cnex_ssp;
	int		instance;

	/* Get device instance and structure */
	instance = ddi_get_instance(dip);
	cnex_ssp = ddi_get_soft_state(cnex_state, instance);

	/* find and remove channel from list */
	mutex_enter(&cnex_ssp->clist_lock);
	prev_cldcp = NULL;
	cldcp = cnex_ssp->clist;
	while (cldcp) {
		if (cldcp->id == id)
			break;
		prev_cldcp = cldcp;
		cldcp = cldcp->next;
	}

	if (cldcp == 0) {
		DWARN("cnex_unreg_chan: invalid channel %d\n", id);
		mutex_exit(&cnex_ssp->clist_lock);
		return (EINVAL);
	}

	if (cldcp->tx.hdlr || cldcp->rx.hdlr) {
		DWARN("cnex_unreg_chan: handlers still exist: chan %lx\n", id);
		mutex_exit(&cnex_ssp->clist_lock);
		return (ENXIO);
	}

	if (prev_cldcp)
		prev_cldcp->next = cldcp->next;
	else
		cnex_ssp->clist = cldcp->next;

	mutex_exit(&cnex_ssp->clist_lock);

	/* destroy mutex */
	mutex_destroy(&cldcp->lock);

	/* free channel */
	kmem_free(cldcp, sizeof (*cldcp));

	return (0);
}

/*
 * Remove Tx/Rx interrupt handler for the channel
 */
static int
cnex_rem_intr(dev_info_t *dip, uint64_t id, cnex_intrtype_t itype)
{
	int			rv, idx, pil;
	cnex_ldc_t		*cldcp;
	cnex_intr_t		*iinfo;
	cnex_soft_state_t	*cnex_ssp;
	int			instance, istate;

	/* Get device instance and structure */
	instance = ddi_get_instance(dip);
	cnex_ssp = ddi_get_soft_state(cnex_state, instance);

	/* get channel info */
	mutex_enter(&cnex_ssp->clist_lock);
	cldcp = cnex_ssp->clist;
	while (cldcp) {
		if (cldcp->id == id)
			break;
		cldcp = cldcp->next;
	}
	if (cldcp == NULL) {
		DWARN("cnex_rem_intr: channel 0x%llx does not exist\n", id);
		mutex_exit(&cnex_ssp->clist_lock);
		return (EINVAL);
	}
	mutex_exit(&cnex_ssp->clist_lock);

	/* get rid of the channel intr handler */
	mutex_enter(&cldcp->lock);

	/* get interrupt type */
	if (itype == CNEX_TX_INTR) {
		iinfo = &(cldcp->tx);
	} else if (itype == CNEX_RX_INTR) {
		iinfo = &(cldcp->rx);
	} else {
		DWARN("cnex_rem_intr: invalid interrupt type\n");
		mutex_exit(&cldcp->lock);
		return (EINVAL);
	}

	D1("cnex_rem_intr: interrupt ino=0x%x\n", iinfo->ino);

	/* check if a handler is already added */
	if (iinfo->hdlr == 0) {
		DWARN("cnex_rem_intr: interrupt handler does not exist\n");
		mutex_exit(&cldcp->lock);
		return (EINVAL);
	}

	D1("cnex_rem_intr: set intr to invalid ino=0x%x\n", iinfo->ino);
	rv = hvldc_intr_setvalid(cnex_ssp->cfghdl,
	    iinfo->ino, HV_INTR_NOTVALID);
	if (rv) {
		DWARN("cnex_rem_intr: cannot set valid ino=%x\n", iinfo->ino);
		mutex_exit(&cldcp->lock);
		return (ENXIO);
	}

	/*
	 * Check if there are pending interrupts. If interrupts are
	 * pending return EAGAIN.
	 */
	rv = hvldc_intr_getstate(cnex_ssp->cfghdl, iinfo->ino, &istate);
	if (rv) {
		DWARN("cnex_rem_intr: ino=0x%llx, cannot get state\n",
		    iinfo->ino);
		mutex_exit(&cldcp->lock);
		return (ENXIO);
	}

	/* if interrupts are still pending print warning */
	if (istate != HV_INTR_IDLE_STATE) {
		DWARN("cnex_rem_intr: cannot remove intr busy ino=%x\n",
		    iinfo->ino);
		mutex_exit(&cldcp->lock);
		return (EAGAIN);
	}

	/* Pick a PIL on the basis of the channel's devclass */
	for (idx = 0, pil = PIL_3; idx < CNEX_MAX_DEVS; idx++) {
		if (cldcp->devclass == cnex_class_to_intr[idx].devclass) {
			pil = cnex_class_to_intr[idx].pil;
			break;
		}
	}

	intr_dist_cpuid_rem_device_weight(iinfo->cpuid, iinfo->dip);

	/* remove interrupt */
	(void) rem_ivintr(iinfo->icookie, pil);

	/* clear interrupt info */
	bzero(iinfo, sizeof (*iinfo));

	mutex_exit(&cldcp->lock);

	return (0);
}


/*
 * Clear pending Tx/Rx interrupt
 */
static int
cnex_clr_intr(dev_info_t *dip, uint64_t id, cnex_intrtype_t itype)
{
	int			rv;
	cnex_ldc_t		*cldcp;
	cnex_intr_t		*iinfo;
	cnex_soft_state_t	*cnex_ssp;
	int			instance;

	/* Get device instance and structure */
	instance = ddi_get_instance(dip);
	cnex_ssp = ddi_get_soft_state(cnex_state, instance);

	/* get channel info */
	mutex_enter(&cnex_ssp->clist_lock);
	cldcp = cnex_ssp->clist;
	while (cldcp) {
		if (cldcp->id == id)
			break;
		cldcp = cldcp->next;
	}
	if (cldcp == NULL) {
		DWARN("cnex_clr_intr: channel 0x%llx does not exist\n", id);
		mutex_exit(&cnex_ssp->clist_lock);
		return (EINVAL);
	}
	mutex_exit(&cnex_ssp->clist_lock);

	mutex_enter(&cldcp->lock);

	/* get interrupt type */
	if (itype == CNEX_TX_INTR) {
		iinfo = &(cldcp->tx);
	} else if (itype == CNEX_RX_INTR) {
		iinfo = &(cldcp->rx);
	} else {
		DWARN("cnex_clr_intr: invalid interrupt type\n");
		mutex_exit(&cldcp->lock);
		return (EINVAL);
	}

	D1("%s: interrupt ino=0x%x\n", __func__, iinfo->ino);

	/* check if a handler is already added */
	if (iinfo->hdlr == 0) {
		DWARN("cnex_clr_intr: interrupt handler does not exist\n");
		mutex_exit(&cldcp->lock);
		return (EINVAL);
	}

	rv = hvldc_intr_setstate(cnex_ssp->cfghdl, iinfo->ino,
	    HV_INTR_IDLE_STATE);
	if (rv) {
		DWARN("cnex_clr_intr: cannot clear interrupt state\n");
		mutex_exit(&cldcp->lock);
		return (ENXIO);
	}

	mutex_exit(&cldcp->lock);

	return (0);
}

/*
 * Channel nexus interrupt handler wrapper
 */
static uint_t
cnex_intr_wrapper(caddr_t arg)
{
	int 			res;
	uint_t 			(*handler)();
	caddr_t 		handler_arg1;
	caddr_t 		handler_arg2;
	cnex_intr_t 		*iinfo = (cnex_intr_t *)arg;

	ASSERT(iinfo != NULL);

	handler = iinfo->hdlr;
	handler_arg1 = iinfo->arg1;
	handler_arg2 = iinfo->arg2;

	/*
	 * The 'interrupt__start' and 'interrupt__complete' probes
	 * are provided to support 'intrstat' command. These probes
	 * help monitor the interrupts on a per device basis only.
	 * In order to provide the ability to monitor the
	 * activity on a per channel basis, two additional
	 * probes('channelintr__start','channelintr__complete')
	 * are provided here.
	 */
	DTRACE_PROBE4(channelintr__start, uint64_t, iinfo->id,
	    cnex_intr_t *, iinfo, void *, handler, caddr_t, handler_arg1);

	DTRACE_PROBE4(interrupt__start, dev_info_t, iinfo->dip,
	    void *, handler, caddr_t, handler_arg1, caddr_t, handler_arg2);

	D1("cnex_intr_wrapper:ino=0x%llx invoke client handler\n", iinfo->ino);
	res = (*handler)(handler_arg1, handler_arg2);

	DTRACE_PROBE4(interrupt__complete, dev_info_t, iinfo->dip,
	    void *, handler, caddr_t, handler_arg1, int, res);

	DTRACE_PROBE4(channelintr__complete, uint64_t, iinfo->id,
	    cnex_intr_t *, iinfo, void *, handler, caddr_t, handler_arg1);

	return (res);
}

/*ARGSUSED*/
static int
cnex_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int 		rv, instance, reglen;
	cnex_regspec_t	*reg_p;
	ldc_cnex_t	cinfo;
	cnex_soft_state_t *cnex_ssp;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	/*
	 * Get the instance specific soft state structure.
	 * Save the devi for this instance in the soft_state data.
	 */
	instance = ddi_get_instance(devi);
	if (ddi_soft_state_zalloc(cnex_state, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);
	cnex_ssp = ddi_get_soft_state(cnex_state, instance);

	cnex_ssp->devi = devi;
	cnex_ssp->clist = NULL;

	if (ddi_getlongprop(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
	    "reg", (caddr_t)&reg_p, &reglen) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/* get the sun4v config handle for this device */
	cnex_ssp->cfghdl = SUN4V_REG_SPEC2CFG_HDL(reg_p->physaddr);
	kmem_free(reg_p, reglen);

	D1("cnex_attach: cfghdl=0x%llx\n", cnex_ssp->cfghdl);

	/* init channel list mutex */
	mutex_init(&cnex_ssp->clist_lock, NULL, MUTEX_DRIVER, NULL);

	/* Register with LDC module */
	cinfo.dip = devi;
	cinfo.reg_chan = cnex_reg_chan;
	cinfo.unreg_chan = cnex_unreg_chan;
	cinfo.add_intr = cnex_add_intr;
	cinfo.rem_intr = cnex_rem_intr;
	cinfo.clr_intr = cnex_clr_intr;

	/*
	 * LDC register will fail if an nexus instance had already
	 * registered with the LDC framework
	 */
	rv = ldc_register(&cinfo);
	if (rv) {
		DWARN("cnex_attach: unable to register with LDC\n");
		ddi_soft_state_free(cnex_state, instance);
		mutex_destroy(&cnex_ssp->clist_lock);
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(devi, "devctl", S_IFCHR, instance,
	    DDI_NT_NEXUS, 0) != DDI_SUCCESS) {
		ddi_remove_minor_node(devi, NULL);
		ddi_soft_state_free(cnex_state, instance);
		mutex_destroy(&cnex_ssp->clist_lock);
		return (DDI_FAILURE);
	}

	/* Add interrupt redistribution callback. */
	intr_dist_add_weighted(cnex_intr_redist, cnex_ssp);

	ddi_report_dev(devi);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
cnex_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int 		instance;
	ldc_cnex_t	cinfo;
	cnex_soft_state_t *cnex_ssp;

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(devi);
	cnex_ssp = ddi_get_soft_state(cnex_state, instance);

	/* check if there are any channels still registered */
	if (cnex_ssp->clist) {
		cmn_err(CE_WARN, "?cnex_dettach: channels registered %d\n",
		    ddi_get_instance(devi));
		return (DDI_FAILURE);
	}

	/* Unregister with LDC module */
	cinfo.dip = devi;
	(void) ldc_unregister(&cinfo);

	/* Remove interrupt redistribution callback. */
	intr_dist_rem_weighted(cnex_intr_redist, cnex_ssp);

	/* destroy mutex */
	mutex_destroy(&cnex_ssp->clist_lock);

	/* free soft state structure */
	ddi_soft_state_free(cnex_state, instance);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
cnex_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	int instance;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	instance = getminor(*devp);
	if (ddi_get_soft_state(cnex_state, instance) == NULL)
		return (ENXIO);

	return (0);
}

/*ARGSUSED*/
static int
cnex_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	int instance;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	instance = getminor(dev);
	if (ddi_get_soft_state(cnex_state, instance) == NULL)
		return (ENXIO);

	return (0);
}

/*ARGSUSED*/
static int
cnex_ioctl(dev_t dev,
    int cmd, intptr_t arg, int mode, cred_t *cred_p, int *rval_p)
{
	int instance;
	cnex_soft_state_t *cnex_ssp;

	instance = getminor(dev);
	if ((cnex_ssp = ddi_get_soft_state(cnex_state, instance)) == NULL)
		return (ENXIO);
	ASSERT(cnex_ssp->devi);
	return (ndi_devctl_ioctl(cnex_ssp->devi, cmd, arg, mode, 0));
}

static int
cnex_ctl(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t ctlop,
    void *arg, void *result)
{
	char		name[MAXNAMELEN];
	uint32_t	reglen;
	int		*cnex_regspec;

	switch (ctlop) {
	case DDI_CTLOPS_REPORTDEV:
		if (rdip == NULL)
			return (DDI_FAILURE);
		cmn_err(CE_CONT, "?channel-device: %s%d\n",
		    ddi_driver_name(rdip), ddi_get_instance(rdip));
		return (DDI_SUCCESS);

	case DDI_CTLOPS_INITCHILD:
	{
		dev_info_t *child = (dev_info_t *)arg;

		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, child,
		    DDI_PROP_DONTPASS, "reg",
		    &cnex_regspec, &reglen) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}

		(void) snprintf(name, sizeof (name), "%x", *cnex_regspec);
		ddi_set_name_addr(child, name);
		ddi_set_parent_data(child, NULL);
		ddi_prop_free(cnex_regspec);
		return (DDI_SUCCESS);
	}

	case DDI_CTLOPS_UNINITCHILD:
	{
		dev_info_t *child = (dev_info_t *)arg;

		NDI_CONFIG_DEBUG((CE_NOTE,
		    "DDI_CTLOPS_UNINITCHILD(%s, instance=%d)",
		    ddi_driver_name(child), DEVI(child)->devi_instance));

		ddi_set_name_addr(child, NULL);

		return (DDI_SUCCESS);
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
		 * by a channel-device driver.  So we whine when we're called.
		 */
		cmn_err(CE_WARN, "%s%d: invalid op (%d) from %s%d\n",
		    ddi_driver_name(dip), ddi_get_instance(dip), ctlop,
		    ddi_driver_name(rdip), ddi_get_instance(rdip));
		return (DDI_FAILURE);

	case DDI_CTLOPS_ATTACH:
	case DDI_CTLOPS_BTOP:
	case DDI_CTLOPS_BTOPR:
	case DDI_CTLOPS_DETACH:
	case DDI_CTLOPS_DVMAPAGESIZE:
	case DDI_CTLOPS_IOMIN:
	case DDI_CTLOPS_POWER:
	case DDI_CTLOPS_PTOB:
	default:
		/*
		 * Everything else (e.g. PTOB/BTOP/BTOPR requests) we pass up
		 */
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));
	}
}

/*
 * cnex_find_chan_dip -- Find the dip of a device that is corresponding
 * 	to the specific channel. Below are the details on how the dip
 *	is derived.
 *
 *	- In the MD, the cfg-handle is expected to be unique for
 *	  virtual-device nodes that have the same 'name' property value.
 *	  This value is expected to be the same as that of "reg" property
 *	  of the corresponding OBP device node.
 *
 *	- The value of the 'name' property of a virtual-device node
 *	  in the MD is expected to be the same for the corresponding
 *	  OBP device node.
 *
 *	- Find the virtual-device node corresponding to a channel-endpoint
 *	  by walking backwards. Then obtain the values for the 'name' and
 *	  'cfg-handle' properties.
 *
 *	- Walk all the children of the cnex, find a matching dip which
 *	  has the same 'name' and 'reg' property values.
 *
 *	- The channels that have no corresponding device driver are
 *	  treated as if they  correspond to the cnex driver,
 *	  that is, return cnex dip for them. This means, the
 *	  cnex acts as an umbrella device driver. Note, this is
 *	  for 'intrstat' statistics purposes only. As a result of this,
 *	  the 'intrstat' shows cnex as the device that is servicing the
 *	  interrupts corresponding to these channels.
 *
 *	  For now, only one such case is known, that is, the channels that
 *	  are used by the "domain-services".
 */
static dev_info_t *
cnex_find_chan_dip(dev_info_t *dip, uint64_t chan_id,
    md_t *mdp, mde_cookie_t mde)
{
	int listsz;
	int num_nodes;
	int num_devs;
	uint64_t cfghdl;
	char *md_name;
	mde_cookie_t *listp;
	dev_info_t *cdip = NULL;

	num_nodes = md_node_count(mdp);
	ASSERT(num_nodes > 0);
	listsz = num_nodes * sizeof (mde_cookie_t);
	listp = (mde_cookie_t *)kmem_zalloc(listsz, KM_SLEEP);

	num_devs = md_scan_dag(mdp, mde, md_find_name(mdp, "virtual-device"),
	    md_find_name(mdp, "back"), listp);
	ASSERT(num_devs <= 1);
	if (num_devs <= 0) {
		DWARN("cnex_find_chan_dip:channel(0x%llx): "
		    "No virtual-device found\n", chan_id);
		goto fdip_exit;
	}
	if (md_get_prop_str(mdp, listp[0], "name", &md_name) != 0) {
		DWARN("cnex_find_chan_dip:channel(0x%llx): "
		    "name property not found\n", chan_id);
		goto fdip_exit;
	}

	D1("cnex_find_chan_dip: channel(0x%llx): virtual-device "
	    "name property value = %s\n", chan_id, md_name);

	if (md_get_prop_val(mdp, listp[0], "cfg-handle", &cfghdl) != 0) {
		DWARN("cnex_find_chan_dip:channel(0x%llx): virtual-device's "
		    "cfg-handle property not found\n", chan_id);
		goto fdip_exit;
	}

	D1("cnex_find_chan_dip:channel(0x%llx): virtual-device cfg-handle "
	    " property value = 0x%x\n", chan_id, cfghdl);

	for (cdip = ddi_get_child(dip); cdip != NULL;
	    cdip = ddi_get_next_sibling(cdip)) {

		int *cnex_regspec;
		uint32_t reglen;
		char	*dev_name;

		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, cdip,
		    DDI_PROP_DONTPASS, "name",
		    &dev_name) != DDI_PROP_SUCCESS) {
			DWARN("cnex_find_chan_dip: name property not"
			    " found for dip(0x%p)\n", cdip);
			continue;
		}
		if (strcmp(md_name, dev_name) != 0) {
			ddi_prop_free(dev_name);
			continue;
		}
		ddi_prop_free(dev_name);
		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, cdip,
		    DDI_PROP_DONTPASS, "reg",
		    &cnex_regspec, &reglen) != DDI_SUCCESS) {
			DWARN("cnex_find_chan_dip: reg property not"
			    " found for dip(0x%p)\n", cdip);
			continue;
		}
		if (*cnex_regspec == cfghdl) {
			D1("cnex_find_chan_dip:channel(0x%llx): found "
			    "dip(0x%p) drvname=%s\n", chan_id, cdip,
			    ddi_driver_name(cdip));
			ddi_prop_free(cnex_regspec);
			break;
		}
		ddi_prop_free(cnex_regspec);
	}

fdip_exit:
	if (cdip == NULL) {
		/*
		 * If a virtual-device node exists but no dip found,
		 * then for now print a DEBUG error message only.
		 */
		if (num_devs > 0) {
			DERR("cnex_find_chan_dip:channel(0x%llx): "
			    "No device found\n", chan_id);
		}

		/* If no dip was found, return cnex device's dip. */
		cdip = dip;
	}

	kmem_free(listp, listsz);
	D1("cnex_find_chan_dip:channel(0x%llx): returning dip=0x%p\n",
	    chan_id, cdip);
	return (cdip);
}

/* -------------------------------------------------------------------------- */

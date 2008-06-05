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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/obpdefs.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/open.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/x_call.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/ivintr.h>
#include <sys/intr.h>
#include <sys/intreg.h>
#include <sys/autoconf.h>
#include <sys/modctl.h>
#include <sys/spl.h>
#include <sys/async.h>
#include <sys/mc.h>
#include <sys/mc-us3.h>
#include <sys/cpu_module.h>
#include <sys/platform_module.h>

/*
 * Function prototypes
 */

static int mc_open(dev_t *, int, int, cred_t *);
static int mc_close(dev_t, int, int, cred_t *);
static int mc_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int mc_attach(dev_info_t *, ddi_attach_cmd_t);
static int mc_detach(dev_info_t *, ddi_detach_cmd_t);

/*
 * Configuration data structures
 */
static struct cb_ops mc_cb_ops = {
	mc_open,			/* open */
	mc_close,			/* close */
	nulldev,			/* strategy */
	nulldev,			/* print */
	nodev,				/* dump */
	nulldev,			/* read */
	nulldev,			/* write */
	mc_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* cb_prop_op */
	0,				/* streamtab */
	D_MP | D_NEW | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* cb_aread */
	nodev				/* cb_awrite */
};

static struct dev_ops mc_ops = {
	DEVO_REV,			/* rev */
	0,				/* refcnt  */
	ddi_getinfo_1to1,		/* getinfo */
	nulldev,			/* identify */
	nulldev,			/* probe */
	mc_attach,			/* attach */
	mc_detach,			/* detach */
	nulldev,			/* reset */
	&mc_cb_ops,			/* cb_ops */
	(struct bus_ops *)0,		/* bus_ops */
	nulldev				/* power */
};

/*
 * Driver globals
 */
static void *mcp;
static int nmcs = 0;
static int seg_id = 0;
static int nsegments = 0;
static uint64_t memsize = 0;
static int maxbanks = 0;

static mc_dlist_t *seg_head, *seg_tail, *bank_head, *bank_tail;
static mc_dlist_t *mctrl_head, *mctrl_tail, *dgrp_head, *dgrp_tail;
static mc_dlist_t *device_head, *device_tail;

static kmutex_t	mcmutex;
static kmutex_t	mcdatamutex;

static krwlock_t mcdimmsids_rw;

/* pointer to cache of DIMM serial ids */
static dimm_sid_cache_t	*mc_dimm_sids;
static int		max_entries;

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,			/* module type, this one is a driver */
	"Memory-controller: %I%",	/* module name */
	&mc_ops,			/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,		/* rev */
	(void *)&modldrv,
	NULL
};

static int mc_get_mem_unum(int synd_code, uint64_t paddr, char *buf,
    int buflen, int *lenp);
static int mc_get_mem_info(int synd_code, uint64_t paddr,
    uint64_t *mem_sizep, uint64_t *seg_sizep, uint64_t *bank_sizep,
    int *segsp, int *banksp, int *mcidp);
static int mc_get_mem_sid(int mcid, int dimm, char *buf, int buflen, int *lenp);
static int mc_get_mem_offset(uint64_t paddr, uint64_t *offp);
static int mc_get_mem_addr(int mcid, char *sid, uint64_t off, uint64_t *paddr);
static int mc_init_sid_cache(void);
static int mc_get_mcregs(struct mc_soft_state *);
static void mc_construct(int mc_id, void *dimminfop);
static int mlayout_add(int mc_id, int bank_no, uint64_t reg, void *dimminfop);
static void mlayout_del(int mc_id, int delete);
static struct seg_info *seg_match_base(u_longlong_t base);
static void mc_node_add(mc_dlist_t *node, mc_dlist_t **head, mc_dlist_t **tail);
static void mc_node_del(mc_dlist_t *node, mc_dlist_t **head, mc_dlist_t **tail);
static mc_dlist_t *mc_node_get(int id, mc_dlist_t *head);
static void mc_add_mem_unum_label(char *buf, int mcid, int bank, int dimm);
static int mc_populate_sid_cache(void);
static int mc_get_sid_cache_index(int mcid);
static void mc_update_bank(struct bank_info *bank);

#pragma weak p2get_mem_unum
#pragma weak p2get_mem_info
#pragma weak p2get_mem_sid
#pragma weak p2get_mem_offset
#pragma	weak p2get_mem_addr
#pragma weak p2init_sid_cache
#pragma weak plat_add_mem_unum_label
#pragma weak plat_alloc_sid_cache
#pragma weak plat_populate_sid_cache

#define	QWORD_SIZE		144
#define	QWORD_SIZE_BYTES	(QWORD_SIZE / 8)

/*
 * These are the module initialization routines.
 */

int
_init(void)
{
	int error;

	if ((error = ddi_soft_state_init(&mcp,
	    sizeof (struct mc_soft_state), 1)) != 0)
		return (error);

	error =  mod_install(&modlinkage);
	if (error == 0) {
		mutex_init(&mcmutex, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&mcdatamutex, NULL, MUTEX_DRIVER, NULL);
		rw_init(&mcdimmsids_rw, NULL, RW_DRIVER, NULL);
	}

	return (error);
}

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) != 0)
		return (error);

	ddi_soft_state_fini(&mcp);
	mutex_destroy(&mcmutex);
	mutex_destroy(&mcdatamutex);
	rw_destroy(&mcdimmsids_rw);

	if (mc_dimm_sids)
		kmem_free(mc_dimm_sids, sizeof (dimm_sid_cache_t) *
		    max_entries);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
mc_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	struct mc_soft_state *softsp;
	struct dimm_info *dimminfop;
	int instance, len, err;

	/* get the instance of this devi */
	instance = ddi_get_instance(devi);

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		/* get the soft state pointer for this device node */
		softsp = ddi_get_soft_state(mcp, instance);
		DPRINTF(MC_ATTACH_DEBUG, ("mc%d: DDI_RESUME: updating MADRs\n",
		    instance));
		/*
		 * During resume, the source and target board's bank_infos
		 * need to be updated with the new mc MADR values.  This is
		 * implemented with existing functionality by first removing
		 * the props and allocated data structs, and then adding them
		 * back in.
		 */
		if (ddi_prop_exists(DDI_DEV_T_ANY, softsp->dip,
		    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS,
		    MEM_CFG_PROP_NAME) == 1) {
			(void) ddi_prop_remove(DDI_DEV_T_NONE, softsp->dip,
			    MEM_CFG_PROP_NAME);
		}
		mlayout_del(softsp->portid, 0);
		if (mc_get_mcregs(softsp) == -1) {
			cmn_err(CE_WARN, "mc_attach: mc%d DDI_RESUME failure\n",
			    instance);
		}
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(mcp, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);

	softsp = ddi_get_soft_state(mcp, instance);

	/* Set the dip in the soft state */
	softsp->dip = devi;

	if ((softsp->portid = (int)ddi_getprop(DDI_DEV_T_ANY, softsp->dip,
	    DDI_PROP_DONTPASS, "portid", -1)) == -1) {
		DPRINTF(MC_ATTACH_DEBUG, ("mc%d: unable to get %s property",
		    instance, "portid"));
		goto bad;
	}

	DPRINTF(MC_ATTACH_DEBUG, ("mc%d ATTACH: portid %d, cpuid %d\n",
	    instance, softsp->portid, CPU->cpu_id));

	/* map in the registers for this device. */
	if (ddi_map_regs(softsp->dip, 0, (caddr_t *)&softsp->mc_base, 0, 0)) {
		DPRINTF(MC_ATTACH_DEBUG, ("mc%d: unable to map registers",
		    instance));
		goto bad;
	}

	/*
	 * Get the label of dimms and pin routing information at memory-layout
	 * property if the memory controller is enabled.
	 *
	 * Basically every memory-controller node on every machine should
	 * have one of these properties unless the memory controller is
	 * physically not capable of having memory attached to it, e.g.
	 * Excalibur's slave processor.
	 */
	err = ddi_getlongprop(DDI_DEV_T_ANY, softsp->dip, DDI_PROP_DONTPASS,
	    "memory-layout", (caddr_t)&dimminfop, &len);
	if (err == DDI_PROP_SUCCESS) {
		/*
		 * Set the pointer and size of property in the soft state
		 */
		softsp->memlayoutp = dimminfop;
		softsp->size = len;
	} else if (err == DDI_PROP_NOT_FOUND) {
		/*
		 * This is a disable MC. Clear out the pointer and size
		 * of property in the soft state
		 */
		softsp->memlayoutp = NULL;
		softsp->size = 0;
	} else {
		DPRINTF(MC_ATTACH_DEBUG, ("mc%d is disabled: dimminfop %p\n",
		    instance, dimminfop));
		goto bad2;
	}

	DPRINTF(MC_ATTACH_DEBUG, ("mc%d: dimminfop=0x%p data=0x%lx len=%d\n",
	    instance, dimminfop, *(uint64_t *)dimminfop, len));

	/* Get MC registers and construct all needed data structure */
	if (mc_get_mcregs(softsp) == -1)
		goto bad1;

	mutex_enter(&mcmutex);
	if (nmcs == 1) {
		if (&p2get_mem_unum)
			p2get_mem_unum = mc_get_mem_unum;
		if (&p2get_mem_info)
			p2get_mem_info = mc_get_mem_info;
		if (&p2get_mem_sid)
			p2get_mem_sid = mc_get_mem_sid;
		if (&p2get_mem_offset)
			p2get_mem_offset = mc_get_mem_offset;
		if (&p2get_mem_addr)
			p2get_mem_addr = mc_get_mem_addr;
		if (&p2init_sid_cache)
			p2init_sid_cache = mc_init_sid_cache;
	}

	mutex_exit(&mcmutex);

	/*
	 * Update DIMM serial id information if the DIMM serial id
	 * cache has already been initialized.
	 */
	if (mc_dimm_sids) {
		rw_enter(&mcdimmsids_rw, RW_WRITER);
		(void) mc_populate_sid_cache();
		rw_exit(&mcdimmsids_rw);
	}

	if (ddi_create_minor_node(devi, "mc-us3", S_IFCHR, instance,
	    "ddi_mem_ctrl", 0) != DDI_SUCCESS) {
		DPRINTF(MC_ATTACH_DEBUG, ("mc_attach: create_minor_node"
		    " failed \n"));
		goto bad1;
	}

	ddi_report_dev(devi);
	return (DDI_SUCCESS);

bad1:
	/* release all allocated data struture for this MC */
	mlayout_del(softsp->portid, 0);
	if (softsp->memlayoutp != NULL)
		kmem_free(softsp->memlayoutp, softsp->size);

	/* remove the libdevinfo property */
	if (ddi_prop_exists(DDI_DEV_T_ANY, softsp->dip,
	    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS,
	    MEM_CFG_PROP_NAME) == 1) {
		(void) ddi_prop_remove(DDI_DEV_T_NONE, softsp->dip,
		    MEM_CFG_PROP_NAME);
	}

bad2:
	/* unmap the registers for this device. */
	ddi_unmap_regs(softsp->dip, 0, (caddr_t *)&softsp->mc_base, 0, 0);

bad:
	ddi_soft_state_free(mcp, instance);
	return (DDI_FAILURE);
}

/* ARGSUSED */
static int
mc_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int instance;
	struct mc_soft_state *softsp;

	/* get the instance of this devi */
	instance = ddi_get_instance(devi);

	/* get the soft state pointer for this device node */
	softsp = ddi_get_soft_state(mcp, instance);

	switch (cmd) {
	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	case DDI_DETACH:
		break;

	default:
		return (DDI_FAILURE);
	}

	DPRINTF(MC_DETACH_DEBUG, ("mc%d DETACH: portid= %d, table 0x%p\n",
	    instance, softsp->portid, softsp->memlayoutp));

	/* remove the libdevinfo property */
	if (ddi_prop_exists(DDI_DEV_T_ANY, softsp->dip,
	    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS,
	    MEM_CFG_PROP_NAME) == 1) {
		(void) ddi_prop_remove(DDI_DEV_T_NONE, softsp->dip,
		    MEM_CFG_PROP_NAME);
	}

	/* release all allocated data struture for this MC */
	mlayout_del(softsp->portid, 1);
	if (softsp->memlayoutp != NULL)
		kmem_free(softsp->memlayoutp, softsp->size);

	/* unmap the registers */
	ddi_unmap_regs(softsp->dip, 0, (caddr_t *)&softsp->mc_base, 0, 0);

	mutex_enter(&mcmutex);
	if (nmcs == 0) {
		if (&p2get_mem_unum)
			p2get_mem_unum = NULL;
		if (&p2get_mem_info)
			p2get_mem_info = NULL;
		if (&p2get_mem_sid)
			p2get_mem_sid = NULL;
		if (&p2get_mem_offset)
			p2get_mem_offset = NULL;
		if (&p2get_mem_addr)
			p2get_mem_addr = NULL;
		if (&p2init_sid_cache)
			p2init_sid_cache = NULL;
	}

	mutex_exit(&mcmutex);

	ddi_remove_minor_node(devi, NULL);

	/* free up the soft state */
	ddi_soft_state_free(mcp, instance);

	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
mc_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{

	/* verify that otyp is appropriate */
	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	return (0);
}

/* ARGSUSED */
static int
mc_close(dev_t devp, int flag, int otyp, cred_t *credp)
{
	return (0);
}

/*
 * cmd includes MCIOC_MEMCONF, MCIOC_MEM, MCIOC_SEG, MCIOC_BANK, MCIOC_DEVGRP,
 * MCIOC_CTRLCONF, MCIOC_CONTROL.
 *
 * MCIOC_MEM, MCIOC_SEG, MCIOC_CTRLCONF, and MCIOC_CONTROL are
 * associated with various length struct. If given number is less than the
 * number in kernel, update the number and return EINVAL so that user could
 * allocate enough space for it.
 *
 */

/* ARGSUSED */
static int
mc_ioctl(dev_t dev, int cmd, intptr_t arg, int flag, cred_t *cred_p,
	int *rval_p)
{
	size_t	size;
	struct mc_memconf mcmconf;
	struct mc_memory *mcmem, mcmem_in;
	struct mc_segment *mcseg, mcseg_in;
	struct mc_bank mcbank;
	struct mc_devgrp mcdevgrp;
	struct mc_ctrlconf *mcctrlconf, mcctrlconf_in;
	struct mc_control *mccontrol, mccontrol_in;
	struct seg_info *seg = NULL;
	struct bank_info *bank = NULL;
	struct dgrp_info *dgrp = NULL;
	struct mctrl_info *mcport;
	mc_dlist_t *mctrl;
	int i, status = 0;
	cpu_t *cpu;

	switch (cmd) {
	case MCIOC_MEMCONF:
		mutex_enter(&mcdatamutex);

		mcmconf.nmcs = nmcs;
		mcmconf.nsegments = nsegments;
		mcmconf.nbanks = maxbanks;
		mcmconf.ndevgrps = NDGRPS;
		mcmconf.ndevs = NDIMMS;
		mcmconf.len_dev = MAX_DEVLEN;
		mcmconf.xfer_size = TRANSFER_SIZE;

		mutex_exit(&mcdatamutex);

		if (copyout(&mcmconf, (void *)arg, sizeof (struct mc_memconf)))
			return (EFAULT);
		return (0);

	/*
	 * input: nsegments and allocate space for various length of segmentids
	 *
	 * return    0: size, number of segments, and all segment ids,
	 *		where glocal and local ids are identical.
	 *	EINVAL: if the given nsegments is less than that in kernel and
	 *		nsegments of struct will be updated.
	 *	EFAULT: if other errors in kernel.
	 */
	case MCIOC_MEM:
		if (copyin((void *)arg, &mcmem_in,
		    sizeof (struct mc_memory)) != 0)
			return (EFAULT);

		mutex_enter(&mcdatamutex);
		if (mcmem_in.nsegments < nsegments) {
			mcmem_in.nsegments = nsegments;
			if (copyout(&mcmem_in, (void *)arg,
			    sizeof (struct mc_memory)))
				status = EFAULT;
			else
				status = EINVAL;

			mutex_exit(&mcdatamutex);
			return (status);
		}

		size = sizeof (struct mc_memory) + (nsegments - 1) *
		    sizeof (mcmem->segmentids[0]);
		mcmem = kmem_zalloc(size, KM_SLEEP);

		mcmem->size = memsize;
		mcmem->nsegments = nsegments;
		seg = (struct seg_info *)seg_head;
		for (i = 0; i < nsegments; i++) {
			ASSERT(seg != NULL);
			mcmem->segmentids[i].globalid = seg->seg_node.id;
			mcmem->segmentids[i].localid = seg->seg_node.id;
			seg = (struct seg_info *)seg->seg_node.next;
		}
		mutex_exit(&mcdatamutex);

		if (copyout(mcmem, (void *)arg, size))
			status = EFAULT;

		kmem_free(mcmem, size);
		return (status);

	/*
	 * input: id, nbanks and allocate space for various length of bankids
	 *
	 * return    0: base, size, number of banks, and all bank ids,
	 *		where global id is unique of all banks and local id
	 *		is only unique for mc.
	 *	EINVAL: either id isn't found or if given nbanks is less than
	 *		that in kernel and nbanks of struct will be updated.
	 *	EFAULT: if other errors in kernel.
	 */
	case MCIOC_SEG:

		if (copyin((void *)arg, &mcseg_in,
		    sizeof (struct mc_segment)) != 0)
			return (EFAULT);

		mutex_enter(&mcdatamutex);
		if ((seg = (struct seg_info *)mc_node_get(mcseg_in.id,
		    seg_head)) == NULL) {
			DPRINTF(MC_CMD_DEBUG, ("MCIOC_SEG: seg not match, "
			    "id %d\n", mcseg_in.id));
			mutex_exit(&mcdatamutex);
			return (EFAULT);
		}

		if (mcseg_in.nbanks < seg->nbanks) {
			mcseg_in.nbanks = seg->nbanks;
			if (copyout(&mcseg_in, (void *)arg,
			    sizeof (struct mc_segment)))
				status = EFAULT;
			else
				status = EINVAL;

			mutex_exit(&mcdatamutex);
			return (status);
		}

		size = sizeof (struct mc_segment) + (seg->nbanks - 1) *
		    sizeof (mcseg->bankids[0]);
		mcseg = kmem_zalloc(size, KM_SLEEP);

		mcseg->id = seg->seg_node.id;
		mcseg->ifactor = seg->ifactor;
		mcseg->base = seg->base;
		mcseg->size = seg->size;
		mcseg->nbanks = seg->nbanks;

		bank = seg->hb_inseg;

		DPRINTF(MC_CMD_DEBUG, ("MCIOC_SEG:nbanks %d seg 0x%p bank %p\n",
		    seg->nbanks, seg, bank));

		i = 0;
		while (bank != NULL) {
			DPRINTF(MC_CMD_DEBUG, ("MCIOC_SEG:idx %d bank_id %d\n",
			    i, bank->bank_node.id));
			mcseg->bankids[i].globalid = bank->bank_node.id;
			mcseg->bankids[i++].localid =
			    bank->local_id;
			bank = bank->n_inseg;
		}
		ASSERT(i == seg->nbanks);
		mutex_exit(&mcdatamutex);

		if (copyout(mcseg, (void *)arg, size))
			status = EFAULT;

		kmem_free(mcseg, size);
		return (status);

	/*
	 * input: id
	 *
	 * return    0: mask, match, size, and devgrpid,
	 *		where global id is unique of all devgrps and local id
	 *		is only unique for mc.
	 *	EINVAL: if id isn't found
	 *	EFAULT: if other errors in kernel.
	 */
	case MCIOC_BANK:
		if (copyin((void *)arg, &mcbank, sizeof (struct mc_bank)) != 0)
			return (EFAULT);

		DPRINTF(MC_CMD_DEBUG, ("MCIOC_BANK: bank id %d\n", mcbank.id));

		mutex_enter(&mcdatamutex);

		if ((bank = (struct bank_info *)mc_node_get(mcbank.id,
		    bank_head)) == NULL) {
			mutex_exit(&mcdatamutex);
			return (EINVAL);
		}

		DPRINTF(MC_CMD_DEBUG, ("MCIOC_BANK: bank %d (0x%p) valid %hu\n",
		    bank->bank_node.id, bank, bank->valid));

		/*
		 * If (Physic Address & MASK) == MATCH, Physic Address is
		 * located at this bank. The lower physical address bits
		 * are at [9-6].
		 */
		mcbank.mask = (~(bank->lk | ~(MADR_LK_MASK >>
		    MADR_LK_SHIFT))) << MADR_LPA_SHIFT;
		mcbank.match = bank->lm << MADR_LPA_SHIFT;
		mcbank.size = bank->size;
		mcbank.devgrpid.globalid = bank->devgrp_id;
		mcbank.devgrpid.localid = bank->devgrp_id % NDGRPS;

		mutex_exit(&mcdatamutex);

		if (copyout(&mcbank, (void *)arg, sizeof (struct mc_bank)))
			return (EFAULT);
		return (0);

	/*
	 * input:id and allocate space for various length of deviceids
	 *
	 * return    0: size and number of devices.
	 *	EINVAL: id isn't found
	 *	EFAULT: if other errors in kernel.
	 */
	case MCIOC_DEVGRP:

		if (copyin((void *)arg, &mcdevgrp,
		    sizeof (struct mc_devgrp)) != 0)
			return (EFAULT);

		mutex_enter(&mcdatamutex);
		if ((dgrp = (struct dgrp_info *)mc_node_get(mcdevgrp.id,
		    dgrp_head)) == NULL) {
			DPRINTF(MC_CMD_DEBUG, ("MCIOC_DEVGRP: not match, id "
			    "%d\n", mcdevgrp.id));
			mutex_exit(&mcdatamutex);
			return (EINVAL);
		}

		mcdevgrp.ndevices = dgrp->ndevices;
		mcdevgrp.size = dgrp->size;

		mutex_exit(&mcdatamutex);

		if (copyout(&mcdevgrp, (void *)arg, sizeof (struct mc_devgrp)))
			status = EFAULT;

		return (status);

	/*
	 * input: nmcs and allocate space for various length of mcids
	 *
	 * return    0: number of mc, and all mcids,
	 *		where glocal and local ids are identical.
	 *	EINVAL: if the given nmcs is less than that in kernel and
	 *		nmcs of struct will be updated.
	 *	EFAULT: if other errors in kernel.
	 */
	case MCIOC_CTRLCONF:
		if (copyin((void *)arg, &mcctrlconf_in,
		    sizeof (struct mc_ctrlconf)) != 0)
			return (EFAULT);

		mutex_enter(&mcdatamutex);
		if (mcctrlconf_in.nmcs < nmcs) {
			mcctrlconf_in.nmcs = nmcs;
			if (copyout(&mcctrlconf_in, (void *)arg,
			    sizeof (struct mc_ctrlconf)))
				status = EFAULT;
			else
				status = EINVAL;

			mutex_exit(&mcdatamutex);
			return (status);
		}

		/*
		 * Cannot just use the size of the struct because of the various
		 * length struct
		 */
		size = sizeof (struct mc_ctrlconf) + ((nmcs - 1) *
		    sizeof (mcctrlconf->mcids[0]));
		mcctrlconf = kmem_zalloc(size, KM_SLEEP);

		mcctrlconf->nmcs = nmcs;

		/* Get all MC ids and add to mcctrlconf */
		mctrl = mctrl_head;
		i = 0;
		while (mctrl != NULL) {
			mcctrlconf->mcids[i].globalid = mctrl->id;
			mcctrlconf->mcids[i].localid = mctrl->id;
			i++;
			mctrl = mctrl->next;
		}
		ASSERT(i == nmcs);

		mutex_exit(&mcdatamutex);

		if (copyout(mcctrlconf, (void *)arg, size))
			status = EFAULT;

		kmem_free(mcctrlconf, size);
		return (status);

	/*
	 * input:id, ndevgrps and allocate space for various length of devgrpids
	 *
	 * return    0: number of devgrp, and all devgrpids,
	 *		is unique of all devgrps and local id is only unique
	 *		for mc.
	 *	EINVAL: either if id isn't found or if the given ndevgrps is
	 *		less than that in kernel and ndevgrps of struct will
	 *		be updated.
	 *	EFAULT: if other errors in kernel.
	 */
	case MCIOC_CONTROL:
		if (copyin((void *)arg, &mccontrol_in,
		    sizeof (struct mc_control)) != 0)
			return (EFAULT);

		mutex_enter(&mcdatamutex);
		if ((mcport = (struct mctrl_info *)mc_node_get(mccontrol_in.id,
		    mctrl_head)) == NULL) {
			mutex_exit(&mcdatamutex);
			return (EINVAL);
		}

		/*
		 * mcport->ndevgrps zero means Memory Controller is disable.
		 */
		if ((mccontrol_in.ndevgrps < mcport->ndevgrps) ||
		    (mcport->ndevgrps == 0)) {
			mccontrol_in.ndevgrps = mcport->ndevgrps;
			if (copyout(&mccontrol_in, (void *)arg,
			    sizeof (struct mc_control)))
				status = EFAULT;
			else if (mcport->ndevgrps != 0)
				status = EINVAL;

			mutex_exit(&mcdatamutex);
			return (status);
		}

		size = sizeof (struct mc_control) + (mcport->ndevgrps - 1) *
		    sizeof (mccontrol->devgrpids[0]);
		mccontrol = kmem_zalloc(size, KM_SLEEP);

		mccontrol->id = mcport->mctrl_node.id;
		mccontrol->ndevgrps = mcport->ndevgrps;
		for (i = 0; i < mcport->ndevgrps; i++) {
			mccontrol->devgrpids[i].globalid = mcport->devgrpids[i];
			mccontrol->devgrpids[i].localid =
			    mcport->devgrpids[i] % NDGRPS;
			DPRINTF(MC_CMD_DEBUG, ("MCIOC_CONTROL: devgrp id %lu\n",
			    *(uint64_t *)&mccontrol->devgrpids[i]));
		}
		mutex_exit(&mcdatamutex);

		if (copyout(mccontrol, (void *)arg, size))
			status = EFAULT;

		kmem_free(mccontrol, size);
		return (status);

	/*
	 * input:id
	 *
	 * return    0: CPU flushed successfully.
	 *	EINVAL: the id wasn't found
	 */
	case MCIOC_ECFLUSH:
		mutex_enter(&cpu_lock);
		cpu = cpu_get((processorid_t)arg);
		mutex_exit(&cpu_lock);
		if (cpu == NULL)
			return (EINVAL);

		xc_one(arg, (xcfunc_t *)cpu_flush_ecache, 0, 0);

		return (0);

	default:
		DPRINTF(MC_CMD_DEBUG, ("DEFAULT: cmd is wrong\n"));
		return (EFAULT);
	}
}

/*
 * Get Memory Address Decoding Registers and construct list.
 * flag is to workaround Cheetah's restriction where register cannot be mapped
 * if port id(MC registers on it) == cpu id(process is running on it).
 */
static int
mc_get_mcregs(struct mc_soft_state *softsp)
{
	int i;
	int err = 0;
	uint64_t madreg;
	uint64_t ma_reg_array[NBANKS];	/* there are NBANKS of madrs */

	/* Construct lists for MC, mctrl_info, dgrp_info, and device_info */
	mc_construct(softsp->portid, softsp->memlayoutp);

	/*
	 * If memlayoutp is NULL, the Memory Controller is disable, and
	 * doesn't need to create any bank and segment.
	 */
	if (softsp->memlayoutp == NULL)
		goto exit;

	/*
	 * Get the content of 4 Memory Address Decoding Registers, and
	 * construct lists of logical banks and segments.
	 */
	for (i = 0; i < NBANKS; i++) {
		DPRINTF(MC_REG_DEBUG, ("get_mcregs: mapreg=0x%p portid=%d "
		    "cpu=%d\n", softsp->mc_base, softsp->portid, CPU->cpu_id));

		kpreempt_disable();
		if (softsp->portid == (cpunodes[CPU->cpu_id].portid))
			madreg = get_mcr(MADR0OFFSET + (i * REGOFFSET));
		else
			madreg = *((uint64_t *)(softsp->mc_base + MADR0OFFSET +
			    (i * REGOFFSET)));
		kpreempt_enable();

		DPRINTF(MC_REG_DEBUG, ("get_mcregs 2: memlayoutp=0x%p madreg "
		    "reg=0x%lx\n", softsp->memlayoutp, madreg));

		ma_reg_array[i] = madreg;

		if ((err = mlayout_add(softsp->portid, i, madreg,
		    softsp->memlayoutp)) == -1)
			break;
	}

	/*
	 * Create the logical bank property for this mc node. This
	 * property is an encoded array of the madr for each logical
	 * bank (there are NBANKS of these).
	 */
	if (ddi_prop_exists(DDI_DEV_T_ANY, softsp->dip,
	    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS,
	    MEM_CFG_PROP_NAME) != 1) {
		(void) ddi_prop_create(DDI_DEV_T_NONE, softsp->dip,
		    DDI_PROP_CANSLEEP, MEM_CFG_PROP_NAME,
		    (caddr_t)&ma_reg_array, sizeof (ma_reg_array));
	}

exit:
	if (!err) {
		mutex_enter(&mcdatamutex);
		nmcs++;
		mutex_exit(&mcdatamutex);
	}
	return (err);
}

/*
 * Translate a <DIMM, offset> pair to a physical address.
 */
static int
mc_offset_to_addr(struct seg_info *seg,
    struct bank_info *bank, uint64_t off, uint64_t *addr)
{
	uint64_t base, size, line, remainder;
	uint32_t ifactor;

	/*
	 * Compute the half-dimm size in bytes.
	 * Note that bank->size represents the number of data bytes,
	 * and does not include the additional bits used for ecc, mtag,
	 * and mtag ecc information in each 144-bit checkword.
	 * For calculating the offset to a checkword we need the size
	 * including the additional 8 bytes for each 64 data bytes of
	 * a cache line.
	 */
	size = ((bank->size / 4) / 64) * 72;

	/*
	 * Check if the offset is within this bank. This depends on the position
	 * of the bank, i.e., whether it is the front bank or the back bank.
	 */
	base = size * bank->pos;

	if ((off < base) || (off >= (base + size)))
		return (-1);

	/*
	 * Compute the offset within the half-dimm.
	 */
	off -= base;

	/*
	 * Compute the line within the half-dimm. This is the same as the line
	 * within the bank since each DIMM in a bank contributes uniformly
	 * 144 bits (18 bytes) to a cache line.
	 */
	line = off / QWORD_SIZE_BYTES;

	remainder = off % QWORD_SIZE_BYTES;

	/*
	 * Compute the line within the segment.
	 * The bank->lm field indicates the order in which cache lines are
	 * distributed across the banks of a segment (See the Cheetah PRM).
	 * The interleave factor the bank is programmed with is used instead
	 * of the segment interleave factor since a segment can be composed
	 * of banks with different interleave factors if the banks are not
	 * uniform in size.
	 */
	ifactor = (bank->lk ^ 0xF) + 1;
	line = (line * ifactor) + bank->lm;

	/*
	 * Compute the physical address assuming that there are 64 data bytes
	 * in a cache line.
	 */
	*addr = (line << 6) + seg->base;
	*addr += remainder * 16;

	return (0);
}

/*
 * Translate a physical address to a <DIMM, offset> pair.
 */
static void
mc_addr_to_offset(struct seg_info *seg,
    struct bank_info *bank, uint64_t addr, uint64_t *off)
{
	uint64_t base, size, line, remainder;
	uint32_t ifactor;

	/*
	 * Compute the line within the segment assuming that there are 64 data
	 * bytes in a cache line.
	 */
	line = (addr - seg->base) / 64;

	/*
	 * The lm (lower match) field from the Memory Address Decoding Register
	 * for this bank determines which lines within a memory segment this
	 * bank should respond to.  These are the actual address bits the
	 * interleave is done over (See the Cheetah PRM).
	 * In other words, the lm field indicates the order in which the cache
	 * lines are distributed across the banks of a segment, and thusly it
	 * can be used to compute the line within this bank. This is the same as
	 * the line within the half-dimm. This is because each DIMM in a bank
	 * contributes uniformly to every cache line.
	 */
	ifactor = (bank->lk ^ 0xF) + 1;
	line = (line - bank->lm)/ifactor;

	/*
	 * Compute the offset within the half-dimm. This depends on whether
	 * or not the bank is a front logical bank or a back logical bank.
	 */
	*off = line * QWORD_SIZE_BYTES;

	/*
	 * Compute the half-dimm size in bytes.
	 * Note that bank->size represents the number of data bytes,
	 * and does not include the additional bits used for ecc, mtag,
	 * and mtag ecc information in each 144-bit quadword.
	 * For calculating the offset to a checkword we need the size
	 * including the additional 8 bytes for each 64 data bytes of
	 * a cache line.
	 */
	size = ((bank->size / 4) / 64) * 72;

	/*
	 * Compute the offset within the dimm to the nearest line. This depends
	 * on whether or not the bank is a front logical bank or a back logical
	 * bank.
	 */
	base = size * bank->pos;
	*off += base;

	remainder = (addr - seg->base) % 64;
	remainder /= 16;
	*off += remainder;
}

/*
 * A cache line is composed of four quadwords with the associated ECC, the
 * MTag along with its associated ECC. This is depicted below:
 *
 * |                    Data                    |   ECC   | Mtag |MTag ECC|
 *  127                                         0 8       0 2    0 3      0
 *
 * synd_code will be mapped as the following order to mc_get_mem_unum.
 *  143                                         16        7      4        0
 *
 * |  Quadword  0  |  Quadword  1  |  Quadword  2  |  Quadword  3  |
 *  575         432 431         288 287         144 143		   0
 *
 * dimm table: each bit at a cache line needs two bits to present one of
 *      four dimms. So it needs 144 bytes(576 * 2 / 8). The content is in
 *      big edian order, i.e. dimm_table[0] presents for bit 572 to 575.
 *
 * pin table: each bit at a cache line needs one byte to present pin position,
 *      where max. is 230. So it needs 576 bytes. The order of table index is
 *      the same as bit position at a cache line, i.e. pin_table[0] presents
 *      for bit 0, Mtag ECC 0 of Quadword 3.
 *
 * This is a mapping from syndrome code to QuadWord Logical layout at Safari.
 * Referring to Figure 3-4, Excalibur Architecture Manual.
 * This table could be moved to cheetah.c if other platform teams agree with
 * the bit layout at QuadWord.
 */

static uint8_t qwordmap[] =
{
16,   17,  18,  19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,  30,  31,
32,   33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,
48,   49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  62,  63,
64,   65,  66,  67,  68,  69,  70,  71,  72,  73,  74,  75,  76,  77,  78,  79,
80,   81,  82,  83,  84,  85,  86,  87,  88,  89,  90,  91,  92,  93,  94,  95,
96,   97,  98,  99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127,
128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
7,    8,   9,  10,  11,  12,  13,  14,  15,   4,   5,   6,   0,   1,   2,   3,
};


/* ARGSUSED */
static int
mc_get_mem_unum(int synd_code, uint64_t paddr, char *buf, int buflen, int *lenp)
{
	int i, upper_pa, lower_pa, dimmoffset;
	int quadword, pos_cacheline, position, index, idx4dimm;
	int qwlayout = synd_code;
	short offset, data;
	char unum[UNUM_NAMLEN];
	struct dimm_info *dimmp;
	struct pin_info *pinp;
	struct bank_info *bank;

	/*
	 * Enforce old Openboot requirement for synd code, either a single-bit
	 * code from 0..QWORD_SIZE-1 or -1 (multi-bit error).
	 */
	if (qwlayout < -1 || qwlayout >= QWORD_SIZE)
		return (EINVAL);

	unum[0] = '\0';

	upper_pa = (paddr & MADR_UPA_MASK) >> MADR_UPA_SHIFT;
	lower_pa = (paddr & MADR_LPA_MASK) >> MADR_LPA_SHIFT;

	DPRINTF(MC_GUNUM_DEBUG, ("qwlayout %d\n", qwlayout));

	/*
	 * Scan all logical banks to get one responding to the physical
	 * address. Then compute the index to look up dimm and pin tables
	 * to generate the unum.
	 */
	mutex_enter(&mcdatamutex);
	bank = (struct bank_info *)bank_head;
	while (bank != NULL) {
		int bankid, mcid, bankno_permc;

		bankid = bank->bank_node.id;
		bankno_permc = bankid % NBANKS;
		mcid = bankid / NBANKS;

		/*
		 * The Address Decoding logic decodes the different fields
		 * in the Memory Address Decoding register to determine
		 * whether a particular logical bank should respond to a
		 * physical address.
		 */
		if ((!bank->valid) || ((~(~(upper_pa ^ bank->um) |
		    bank->uk)) || (~(~(lower_pa ^ bank->lm) | bank->lk)))) {
			bank = (struct bank_info *)bank->bank_node.next;
			continue;
		}

		dimmoffset = (bankno_permc % NDGRPS) * NDIMMS;

		dimmp = (struct dimm_info *)bank->dimminfop;
		ASSERT(dimmp != NULL);

		if ((qwlayout >= 0) && (qwlayout < QWORD_SIZE)) {
			/*
			 * single-bit error handling, we can identify specific
			 * DIMM.
			 */

			pinp = (struct pin_info *)&dimmp->data[0];

			if (!dimmp->sym_flag)
				pinp++;

			quadword = (paddr & 0x3f) / 16;
			/* or quadword = (paddr >> 4) % 4; */
			pos_cacheline = ((3 - quadword) * QWORD_SIZE) +
			    qwordmap[qwlayout];
			position = 575 - pos_cacheline;
			index = position * 2 / 8;
			offset = position % 4;

			/*
			 * Trade-off: We couldn't add pin number to
			 * unum string because statistic number
			 * pumps up at the corresponding dimm not pin.
			 * (void) sprintf(unum, "Pin %1u ", (uint_t)
			 * pinp->pintable[pos_cacheline]);
			 */
			DPRINTF(MC_GUNUM_DEBUG, ("Pin number %1u\n",
			    (uint_t)pinp->pintable[pos_cacheline]));
			data = pinp->dimmtable[index];
			idx4dimm = (data >> ((3 - offset) * 2)) & 3;

			(void) strncpy(unum,
			    (char *)dimmp->label[dimmoffset + idx4dimm],
			    UNUM_NAMLEN);
			DPRINTF(MC_GUNUM_DEBUG, ("unum %s\n", unum));
			/*
			 * platform hook for adding label information to unum.
			 */
			mc_add_mem_unum_label(unum, mcid, bankno_permc,
			    idx4dimm);
		} else {
			char *p = unum;
			size_t res = UNUM_NAMLEN;

			/*
			 * multi-bit error handling, we can only identify
			 * bank of DIMMs.
			 */

			for (i = 0; (i < NDIMMS) && (res > 0); i++) {
				(void) snprintf(p, res, "%s%s",
				    i == 0 ? "" : " ",
				    (char *)dimmp->label[dimmoffset + i]);
				res -= strlen(p);
				p += strlen(p);
			}

			/*
			 * platform hook for adding label information
			 * to unum.
			 */
			mc_add_mem_unum_label(unum, mcid, bankno_permc, -1);
		}
		mutex_exit(&mcdatamutex);
		if ((strlen(unum) >= UNUM_NAMLEN) ||
		    (strlen(unum) >= buflen)) {
			return (ENAMETOOLONG);
		} else {
			(void) strncpy(buf, unum, buflen);
			*lenp = strlen(buf);
			return (0);
		}
	}	/* end of while loop for logical bank list */

	mutex_exit(&mcdatamutex);
	return (ENXIO);
}

/* ARGSUSED */
static int
mc_get_mem_offset(uint64_t paddr, uint64_t *offp)
{
	int upper_pa, lower_pa;
	struct bank_info *bank;
	struct seg_info *seg;

	upper_pa = (paddr & MADR_UPA_MASK) >> MADR_UPA_SHIFT;
	lower_pa = (paddr & MADR_LPA_MASK) >> MADR_LPA_SHIFT;

	/*
	 * Scan all logical banks to get one responding to the physical
	 * address.
	 */
	mutex_enter(&mcdatamutex);
	bank = (struct bank_info *)bank_head;
	while (bank != NULL) {
		/*
		 * The Address Decoding logic decodes the different fields
		 * in the Memory Address Decoding register to determine
		 * whether a particular logical bank should respond to a
		 * physical address.
		 */
		if ((!bank->valid) || ((~(~(upper_pa ^ bank->um) |
		    bank->uk)) || (~(~(lower_pa ^ bank->lm) | bank->lk)))) {
			bank = (struct bank_info *)bank->bank_node.next;
			continue;
		}

		seg = (struct seg_info *)mc_node_get(bank->seg_id, seg_head);
		ASSERT(seg != NULL);
		ASSERT(paddr >= seg->base);

		mc_addr_to_offset(seg, bank, paddr, offp);

		mutex_exit(&mcdatamutex);
		return (0);
	}

	mutex_exit(&mcdatamutex);
	return (ENXIO);
}

/*
 * Translate a DIMM <id, offset> pair to a physical address.
 */
static int
mc_get_mem_addr(int mcid, char *sid, uint64_t off, uint64_t *paddr)
{
	struct seg_info *seg;
	struct bank_info *bank;
	int first_seg_id;
	int i, found;

	ASSERT(sid != NULL);

	mutex_enter(&mcdatamutex);

	rw_enter(&mcdimmsids_rw, RW_READER);

	/*
	 * If DIMM serial ids have not been cached yet, tell the
	 * caller to try again.
	 */
	if (mc_dimm_sids == NULL) {
		rw_exit(&mcdimmsids_rw);
		return (EAGAIN);
	}

	for (i = 0; i < max_entries; i++) {
		if (mc_dimm_sids[i].mcid == mcid)
			break;
	}

	if (i == max_entries) {
		rw_exit(&mcdimmsids_rw);
		mutex_exit(&mcdatamutex);
		return (ENODEV);
	}

	first_seg_id = mc_dimm_sids[i].seg_id;

	seg = (struct seg_info *)mc_node_get(first_seg_id, seg_head);

	rw_exit(&mcdimmsids_rw);

	if (seg == NULL) {
		mutex_exit(&mcdatamutex);
		return (ENODEV);
	}

	found = 0;

	for (bank = seg->hb_inseg; bank; bank = bank->n_inseg) {
		ASSERT(bank->valid);

		for (i = 0; i < NDIMMS; i++) {
			if (strncmp((char *)bank->dimmsidp[i], sid,
			    DIMM_SERIAL_ID_LEN)  == 0)
				break;
		}

		if (i == NDIMMS)
			continue;

		if (mc_offset_to_addr(seg, bank, off, paddr) == -1)
			continue;
		found = 1;
		break;
	}

	if (found) {
		mutex_exit(&mcdatamutex);
		return (0);
	}

	/*
	 * If a bank wasn't found, it may be in another segment.
	 * This can happen if the different logical banks of an MC
	 * have different interleave factors.  To deal with this
	 * possibility, we'll do a brute-force search for banks
	 * for this MC with a different seg id then above.
	 */
	bank = (struct bank_info *)bank_head;
	while (bank != NULL) {

		if (!bank->valid) {
			bank = (struct bank_info *)bank->bank_node.next;
			continue;
		}

		if (bank->bank_node.id / NBANKS != mcid) {
			bank = (struct bank_info *)bank->bank_node.next;
			continue;
		}

		/* Ignore banks in the segment we looked in above. */
		if (bank->seg_id == mc_dimm_sids[i].seg_id) {
			bank = (struct bank_info *)bank->bank_node.next;
			continue;
		}

		for (i = 0; i < NDIMMS; i++) {
			if (strncmp((char *)bank->dimmsidp[i], sid,
			    DIMM_SERIAL_ID_LEN)  == 0)
				break;
		}

		if (i == NDIMMS) {
			bank = (struct bank_info *)bank->bank_node.next;
			continue;
		}

		seg = (struct seg_info *)mc_node_get(bank->seg_id, seg_head);

		if (mc_offset_to_addr(seg, bank, off, paddr) == -1) {
			bank = (struct bank_info *)bank->bank_node.next;
			continue;
		}

		found = 1;
		break;
	}

	mutex_exit(&mcdatamutex);

	if (found)
		return (0);
	else
		return (ENOENT);
}

static int
mc_get_mem_info(int synd_code, uint64_t paddr,
    uint64_t *mem_sizep, uint64_t *seg_sizep, uint64_t *bank_sizep,
    int *segsp, int *banksp, int *mcidp)
{
	int upper_pa, lower_pa;
	struct bank_info *bankp;

	if (synd_code < -1 || synd_code >= QWORD_SIZE)
		return (EINVAL);

	upper_pa = (paddr & MADR_UPA_MASK) >> MADR_UPA_SHIFT;
	lower_pa = (paddr & MADR_LPA_MASK) >> MADR_LPA_SHIFT;

	/*
	 * Scan all logical banks to get one responding to the physical
	 * address.
	 */
	mutex_enter(&mcdatamutex);
	bankp = (struct bank_info *)bank_head;
	while (bankp != NULL) {
		struct seg_info *segp;
		int bankid, mcid;

		bankid = bankp->bank_node.id;
		mcid = bankid / NBANKS;

		/*
		 * The Address Decoding logic decodes the different fields
		 * in the Memory Address Decoding register to determine
		 * whether a particular logical bank should respond to a
		 * physical address.
		 */
		if ((!bankp->valid) || ((~(~(upper_pa ^ bankp->um) |
		    bankp->uk)) || (~(~(lower_pa ^ bankp->lm) | bankp->lk)))) {
			bankp = (struct bank_info *)bankp->bank_node.next;
			continue;
		}

		/*
		 * Get the corresponding segment.
		 */
		if ((segp = (struct seg_info *)mc_node_get(bankp->seg_id,
		    seg_head)) == NULL) {
			mutex_exit(&mcdatamutex);
			return (EFAULT);
		}

		*mem_sizep = memsize;
		*seg_sizep = segp->size;
		*bank_sizep = bankp->size;
		*segsp = nsegments;
		*banksp = segp->nbanks;
		*mcidp = mcid;

		mutex_exit(&mcdatamutex);

		return (0);

	}	/* end of while loop for logical bank list */

	mutex_exit(&mcdatamutex);
	return (ENXIO);
}

/*
 * Construct lists for an enabled MC where size of memory is 0.
 * The lists are connected as follows:
 * Attached MC -> device group list -> device list(per devgrp).
 */
static void
mc_construct(int mc_id, void *dimminfop)
{
	int i, j, idx, dmidx;
	struct mctrl_info *mctrl;
	struct dgrp_info *dgrp;
	struct device_info *dev;
	struct	dimm_info *dimmp = (struct  dimm_info *)dimminfop;

	mutex_enter(&mcdatamutex);
	/* allocate for mctrl_info and bank_info */
	if ((mctrl = (struct mctrl_info *)mc_node_get(mc_id,
	    mctrl_head)) != NULL) {
		cmn_err(CE_WARN, "mc_construct: mctrl %d exists\n", mc_id);
		mutex_exit(&mcdatamutex);
		return;
	}

	mctrl = kmem_zalloc(sizeof (struct mctrl_info), KM_SLEEP);

	/*
	 * If dimminfop is NULL, the Memory Controller is disable, and
	 * the number of device group will be zero.
	 */
	if (dimminfop == NULL) {
		mctrl->mctrl_node.id = mc_id;
		mctrl->ndevgrps = 0;
		mc_node_add((mc_dlist_t *)mctrl, &mctrl_head, &mctrl_tail);
		mutex_exit(&mcdatamutex);
		return;
	}

	/* add the entry on dgrp_info list */
	for (i = 0; i < NDGRPS; i++) {
		idx = mc_id * NDGRPS + i;
		mctrl->devgrpids[i] = idx;
		if ((dgrp = (struct dgrp_info *)mc_node_get(idx, dgrp_head))
		    != NULL) {
			cmn_err(CE_WARN, "mc_construct: devgrp %d exists\n",
			    idx);
			continue;
		}

		dgrp = kmem_zalloc(sizeof (struct dgrp_info), KM_SLEEP);

		/* add the entry on device_info list */
		for (j = 0; j < NDIMMS; j++) {
			dmidx = idx * NDIMMS + j;
			dgrp->deviceids[j] = dmidx;
			if ((dev = (struct device_info *)
			    mc_node_get(dmidx, device_head)) != NULL) {
				cmn_err(CE_WARN, "mc_construct: device %d "
				    "exists\n", dmidx);
				continue;
			}
			dev = kmem_zalloc(sizeof (struct device_info),
			    KM_SLEEP);
			dev->dev_node.id = dmidx;
			dev->size = 0;
			(void) strncpy(dev->label, (char *)
			    dimmp->label[i * NDIMMS + j], MAX_DEVLEN);

			mc_node_add((mc_dlist_t *)dev, &device_head,
			    &device_tail);
		}	/* for loop for constructing device_info */

		dgrp->dgrp_node.id = idx;
		dgrp->ndevices = NDIMMS;
		dgrp->size = 0;
		mc_node_add((mc_dlist_t *)dgrp, &dgrp_head, &dgrp_tail);

	}	/* end of for loop for constructing dgrp_info list */

	mctrl->mctrl_node.id = mc_id;
	mctrl->ndevgrps = NDGRPS;
	mc_node_add((mc_dlist_t *)mctrl, &mctrl_head, &mctrl_tail);
	mutex_exit(&mcdatamutex);
}

/*
 * Construct lists for Memory Configuration at logical viewpoint.
 *
 * Retrieve information from Memory Address Decoding Register and set up
 * bank and segment lists. Link bank to its corresponding device group, and
 * update size of device group and devices. Also connect bank to the segment.
 *
 * Memory Address Decoding Register
 * -------------------------------------------------------------------------
 * |63|62    53|52      41|40  37|36     20|19 18|17  14|13 12|11  8|7     0|
 * |-----------|----------|------|---------|-----|------|-----|-----|-------|
 * |V |    -   |    UK    |   -  |    UM   |  -  |  LK  |  -  | LM  |   -   |
 * -------------------------------------------------------------------------
 *
 */

static int
mlayout_add(int mc_id, int bank_no, uint64_t reg, void *dimminfop)
{
	int i, dmidx, idx;
	uint32_t ifactor;
	int status = 0;
	uint64_t size, base;
	struct seg_info *seg_curr;
	struct bank_info *bank_curr;
	struct dgrp_info *dgrp;
	struct device_info *dev;
	union {
		struct {
			uint64_t valid	: 1;
			uint64_t resrv1	: 10;
			uint64_t uk	: 12;
			uint64_t resrv2	: 4;
			uint64_t um	: 17;
			uint64_t resrv3	: 2;
			uint64_t lk	: 4;
			uint64_t resrv4	: 2;
			uint64_t lm	: 4;
			uint64_t resrv5	: 8;
		} _s;
		uint64_t madreg;
	} mcreg;

	mcreg.madreg = reg;

	DPRINTF(MC_CNSTRC_DEBUG, ("mlayout_add: mc_id %d, bank num "
	    "%d, reg 0x%lx\n", mc_id, bank_no, reg));

	/* add the entry on bank_info list */
	idx = mc_id * NBANKS + bank_no;

	mutex_enter(&mcdatamutex);
	if ((bank_curr = (struct bank_info *)mc_node_get(idx, bank_head))
	    != NULL) {
		cmn_err(CE_WARN, "mlayout_add: bank %d exists\n", bank_no);
		goto exit;
	}

	bank_curr = kmem_zalloc(sizeof (struct bank_info), KM_SLEEP);
	bank_curr->bank_node.id = idx;
	bank_curr->valid = mcreg._s.valid;
	bank_curr->dimminfop = dimminfop;

	if (!mcreg._s.valid) {
		mc_node_add((mc_dlist_t *)bank_curr, &bank_head, &bank_tail);
		goto exit;
	}

	/*
	 * size of a logical bank = size of segment / interleave factor
	 * This fomula is not only working for regular configuration,
	 * i.e. number of banks at a segment equals to the max
	 * interleave factor, but also for special case, say 3 bank
	 * interleave. One bank is 2 way interleave and other two are
	 * 4 way. So the sizes of banks are size of segment/2 and /4
	 * respectively.
	 */
	ifactor = (mcreg._s.lk ^ 0xF) + 1;
	size = (((mcreg._s.uk & 0x3FF) + 1) * 0x4000000) / ifactor;
	base = mcreg._s.um & ~mcreg._s.uk;
	base <<= MADR_UPA_SHIFT;

	bank_curr->uk = mcreg._s.uk;
	bank_curr->um = mcreg._s.um;
	bank_curr->lk = mcreg._s.lk;
	bank_curr->lm = mcreg._s.lm;
	bank_curr->size = size;

	/*
	 * The bank's position depends on which halves of the DIMMs it consists
	 * of. The front-side halves of the 4 DIMMs constitute the front bank
	 * and the back-side halves constitute the back bank. Bank numbers
	 * 0 and 1 are front-side banks and bank numbers 2 and 3 are back side
	 * banks.
	 */
	bank_curr->pos = bank_no >> 1;
	ASSERT((bank_curr->pos == 0) || (bank_curr->pos == 1));

	DPRINTF(MC_CNSTRC_DEBUG, ("mlayout_add 3: logical bank num %d, "
	"lk 0x%x uk 0x%x um 0x%x ifactor 0x%x size 0x%lx base 0x%lx\n",
	    idx, mcreg._s.lk, mcreg._s.uk, mcreg._s.um, ifactor, size, base));

	/* connect the entry and update the size on dgrp_info list */
	idx = mc_id * NDGRPS + (bank_no % NDGRPS);
	if ((dgrp = (struct dgrp_info *)mc_node_get(idx, dgrp_head)) == NULL) {
		/* all avaiable dgrp should be linked at mc_construct */
		cmn_err(CE_WARN, "mlayout_add: dgrp %d doesn't exist\n", idx);
		kmem_free(bank_curr, sizeof (struct bank_info));
		status = -1;
		goto exit;
	}

	bank_curr->devgrp_id = idx;
	dgrp->size += size;

	/* Update the size of entry on device_info list */
	for (i = 0; i < NDIMMS; i++) {
		dmidx = dgrp->dgrp_node.id * NDIMMS + i;
		dgrp->deviceids[i] = dmidx;

		/* avaiable device should be linked at mc_construct */
		if ((dev = (struct device_info *)mc_node_get(dmidx,
		    device_head)) == NULL) {
			cmn_err(CE_WARN, "mlayout_add:dev %d doesn't exist\n",
			    dmidx);
			kmem_free(bank_curr, sizeof (struct bank_info));
			status = -1;
			goto exit;
		}

		dev->size += (size / NDIMMS);

		DPRINTF(MC_CNSTRC_DEBUG, ("mlayout_add DIMM:id %d, size %lu\n",
		    dmidx, size));
	}

	/*
	 * Get the segment by matching the base address, link this bank
	 * to the segment. If not matched, allocate a new segment and
	 * add it at segment list.
	 */
	if (seg_curr = seg_match_base(base)) {
		seg_curr->nbanks++;
		seg_curr->size += size;
		if (ifactor > seg_curr->ifactor)
			seg_curr->ifactor = ifactor;
		bank_curr->seg_id = seg_curr->seg_node.id;
	} else {
		seg_curr = (struct seg_info *)
		    kmem_zalloc(sizeof (struct seg_info), KM_SLEEP);
		bank_curr->seg_id = seg_id;
		seg_curr->seg_node.id = seg_id++;
		seg_curr->base = base;
		seg_curr->size = size;
		seg_curr->nbanks = 1;
		seg_curr->ifactor = ifactor;
		mc_node_add((mc_dlist_t *)seg_curr, &seg_head, &seg_tail);

		nsegments++;
	}

	/* Get the local id of bank which is only unique per segment. */
	bank_curr->local_id = seg_curr->nbanks - 1;

	/* add bank at the end of the list; not sorted by bankid */
	if (seg_curr->hb_inseg != NULL) {
		bank_curr->p_inseg = seg_curr->tb_inseg;
		bank_curr->n_inseg = seg_curr->tb_inseg->n_inseg;
		seg_curr->tb_inseg->n_inseg = bank_curr;
		seg_curr->tb_inseg = bank_curr;
	} else {
		bank_curr->n_inseg = bank_curr->p_inseg = NULL;
		seg_curr->hb_inseg = seg_curr->tb_inseg = bank_curr;
	}
	DPRINTF(MC_CNSTRC_DEBUG, ("mlayout_add: + bank to seg, id %d\n",
	    seg_curr->seg_node.id));

	if (mc_dimm_sids) {
		rw_enter(&mcdimmsids_rw, RW_WRITER);
		mc_update_bank(bank_curr);
		rw_exit(&mcdimmsids_rw);
	}
	mc_node_add((mc_dlist_t *)bank_curr, &bank_head, &bank_tail);

	memsize += size;
	if (seg_curr->nbanks > maxbanks)
		maxbanks = seg_curr->nbanks;

exit:
	mutex_exit(&mcdatamutex);
	return (status);
}

/*
 * Delete nodes related to the given MC on mc, device group, device,
 * and bank lists. Moreover, delete corresponding segment if its connected
 * banks are all removed.
 *
 * The "delete" argument is 1 if this is called as a result of DDI_DETACH. In
 * this case, the DIMM data structures need to be deleted. The argument is
 * 0 if this called as a result of DDI_SUSPEND/DDI_RESUME. In this case,
 * the DIMM data structures are left alone.
 */
static void
mlayout_del(int mc_id, int delete)
{
	int i, j, dgrpid, devid, bankid, ndevgrps;
	struct seg_info *seg;
	struct bank_info *bank_curr;
	struct mctrl_info *mctrl;
	mc_dlist_t *dgrp_ptr;
	mc_dlist_t *dev_ptr;
	uint64_t base;

	mutex_enter(&mcdatamutex);

	/* delete mctrl_info */
	if ((mctrl = (struct mctrl_info *)mc_node_get(mc_id, mctrl_head)) !=
	    NULL) {
		ndevgrps = mctrl->ndevgrps;
		mc_node_del((mc_dlist_t *)mctrl, &mctrl_head, &mctrl_tail);
		kmem_free(mctrl, sizeof (struct mctrl_info));
		nmcs--;

		/*
		 * There is no other list left for disabled MC.
		 */
		if (ndevgrps == 0) {
			mutex_exit(&mcdatamutex);
			return;
		}
	} else
		cmn_err(CE_WARN, "MC mlayout_del: mctrl is not found\n");

	/* Delete device groups and devices of the detached MC */
	for (i = 0; i < NDGRPS; i++) {
		dgrpid = mc_id * NDGRPS + i;
		if (!(dgrp_ptr = mc_node_get(dgrpid, dgrp_head))) {
			cmn_err(CE_WARN, "mlayout_del: no devgrp %d\n", dgrpid);
			continue;
		}

		for (j = 0; j < NDIMMS; j++) {
			devid = dgrpid * NDIMMS + j;
			if (dev_ptr = mc_node_get(devid, device_head)) {
				mc_node_del(dev_ptr, &device_head,
				    &device_tail);
				kmem_free(dev_ptr, sizeof (struct device_info));
			} else {
				cmn_err(CE_WARN, "mlayout_del: no dev %d\n",
				    devid);
			}
		}

		mc_node_del(dgrp_ptr, &dgrp_head, &dgrp_tail);
		kmem_free(dgrp_ptr, sizeof (struct dgrp_info));
	}

	/* Delete banks and segments if it has no bank */
	for (i = 0; i < NBANKS; i++) {
		bankid = mc_id * NBANKS + i;
		DPRINTF(MC_DESTRC_DEBUG, ("bank id %d\n", bankid));
		if (!(bank_curr = (struct bank_info *)mc_node_get(bankid,
		    bank_head))) {
			cmn_err(CE_WARN, "mlayout_del: no bank %d\n", bankid);
			continue;
		}

		if (bank_curr->valid) {
			base = bank_curr->um & ~bank_curr->uk;
			base <<= MADR_UPA_SHIFT;
			bank_curr->valid = 0;
			memsize -= bank_curr->size;

			/* Delete bank at segment and segment if no bank left */
			if (!(seg = seg_match_base(base))) {
				cmn_err(CE_WARN, "mlayout_del: no seg\n");
				mc_node_del((mc_dlist_t *)bank_curr, &bank_head,
				    &bank_tail);
				kmem_free(bank_curr, sizeof (struct bank_info));
				continue;
			}

			/* update the bank list at the segment */
			if (bank_curr->n_inseg == NULL) {
				/* node is at the tail of list */
				seg->tb_inseg = bank_curr->p_inseg;
			} else {
				bank_curr->n_inseg->p_inseg =
				    bank_curr->p_inseg;
			}

			if (bank_curr->p_inseg == NULL) {
				/* node is at the head of list */
				seg->hb_inseg = bank_curr->n_inseg;
			} else {
				bank_curr->p_inseg->n_inseg =
				    bank_curr->n_inseg;
			}

			seg->nbanks--;
			seg->size -= bank_curr->size;

			if (seg->nbanks == 0) {
				mc_node_del((mc_dlist_t *)seg, &seg_head,
				    &seg_tail);
				kmem_free(seg, sizeof (struct seg_info));
				nsegments--;
			}

		}
		mc_node_del((mc_dlist_t *)bank_curr, &bank_head, &bank_tail);
		kmem_free(bank_curr, sizeof (struct bank_info));
	}	/* end of for loop for four banks */

	if (mc_dimm_sids && delete) {
		rw_enter(&mcdimmsids_rw, RW_WRITER);
		i = mc_get_sid_cache_index(mc_id);
		if (i >= 0) {
			mc_dimm_sids[i].state = MC_DIMM_SIDS_INVALID;
			if (mc_dimm_sids[i].sids) {
				kmem_free(mc_dimm_sids[i].sids,
				    sizeof (dimm_sid_t) * (NDGRPS * NDIMMS));
				mc_dimm_sids[i].sids = NULL;
			}
		}
		rw_exit(&mcdimmsids_rw);
	}

	mutex_exit(&mcdatamutex);
}

/*
 * Search the segment in the list starting at seg_head by base address
 * input: base address
 * return: pointer of found segment or null if not found.
 */
static struct seg_info *
seg_match_base(u_longlong_t base)
{
	static struct seg_info *seg_ptr;

	seg_ptr = (struct seg_info *)seg_head;
	while (seg_ptr != NULL) {
		DPRINTF(MC_LIST_DEBUG, ("seg_match: base %lu,given base %llu\n",
		    seg_ptr->base, base));
		if (seg_ptr->base == base)
			break;
		seg_ptr = (struct seg_info *)seg_ptr->seg_node.next;
	}
	return (seg_ptr);
}

/*
 * mc_dlist is a double linking list, including unique id, and pointers to
 * next, and previous nodes. seg_info, bank_info, dgrp_info, device_info,
 * and mctrl_info has it at the top to share the operations, add, del, and get.
 *
 * The new node is added at the tail and is not sorted.
 *
 * Input: The pointer of node to be added, head and tail of the list
 */

static void
mc_node_add(mc_dlist_t *node, mc_dlist_t **head, mc_dlist_t **tail)
{
	DPRINTF(MC_LIST_DEBUG, ("mc_node_add: node->id %d head %p tail %p\n",
	    node->id, *head, *tail));

	if (*head != NULL) {
		node->prev = *tail;
		node->next = (*tail)->next;
		(*tail)->next = node;
		*tail = node;
	} else {
		node->next = node->prev = NULL;
		*head = *tail = node;
	}
}

/*
 * Input: The pointer of node to be deleted, head and tail of the list
 *
 * Deleted node will be at the following positions
 * 1. At the tail of the list
 * 2. At the head of the list
 * 3. At the head and tail of the list, i.e. only one left.
 * 4. At the middle of the list
 */

static void
mc_node_del(mc_dlist_t *node, mc_dlist_t **head, mc_dlist_t **tail)
{
	if (node->next == NULL) {
		/* deleted node is at the tail of list */
		*tail = node->prev;
	} else {
		node->next->prev = node->prev;
	}

	if (node->prev == NULL) {
		/* deleted node is at the head of list */
		*head = node->next;
	} else {
		node->prev->next = node->next;
	}
}

/*
 * Search the list from the head of the list to match the given id
 * Input: id and the head of the list
 * Return: pointer of found node
 */
static mc_dlist_t *
mc_node_get(int id, mc_dlist_t *head)
{
	mc_dlist_t *node;

	node = head;
	while (node != NULL) {
		DPRINTF(MC_LIST_DEBUG, ("mc_node_get: id %d, given id %d\n",
		    node->id, id));
		if (node->id == id)
			break;
		node = node->next;
	}
	return (node);
}

/*
 * mc-us3 driver allows a platform to add extra label
 * information to the unum string. If a platform implements a
 * kernel function called plat_add_mem_unum_label() it will be
 * executed. This would typically be implemented in the platmod.
 */
static void
mc_add_mem_unum_label(char *buf, int mcid, int bank, int dimm)
{
	if (&plat_add_mem_unum_label)
		plat_add_mem_unum_label(buf, mcid, bank, dimm);
}

static int
mc_get_sid_cache_index(int mcid)
{
	int	i;

	for (i = 0; i < max_entries; i++) {
		if (mcid == mc_dimm_sids[i].mcid)
			return (i);
	}

	return (-1);
}

static void
mc_update_bank(struct bank_info *bank)
{
	int i, j;
	int bankid, mcid, dgrp_no;

	/*
	 * Mark the MC if DIMM sids are not available.
	 * Mark which segment the DIMMs belong to.  Allocate
	 * space to store DIMM serial ids which are later
	 * provided by the platform layer, and update the bank_info
	 * structure with pointers to its serial ids.
	 */
	bankid = bank->bank_node.id;
	mcid = bankid / NBANKS;
	i = mc_get_sid_cache_index(mcid);
	if (mc_dimm_sids[i].state == MC_DIMM_SIDS_INVALID)
		mc_dimm_sids[i].state = MC_DIMM_SIDS_REQUESTED;

	mc_dimm_sids[i].seg_id = bank->seg_id;

	if (mc_dimm_sids[i].sids == NULL) {
		mc_dimm_sids[i].sids = (dimm_sid_t *)kmem_zalloc(
		    sizeof (dimm_sid_t) * (NDGRPS * NDIMMS), KM_SLEEP);
	}

	dgrp_no = bank->devgrp_id % NDGRPS;

	for (j = 0; j < NDIMMS; j++) {
		bank->dimmsidp[j] =
		    &mc_dimm_sids[i].sids[j + (NDIMMS * dgrp_no)];
	}
}

static int
mc_populate_sid_cache(void)
{
	struct bank_info	*bank;

	if (&plat_populate_sid_cache == 0)
		return (ENOTSUP);

	ASSERT(RW_WRITE_HELD(&mcdimmsids_rw));

	bank = (struct bank_info *)bank_head;
	while (bank != NULL) {
		if (!bank->valid) {
			bank = (struct bank_info *)bank->bank_node.next;
			continue;
		}

		mc_update_bank(bank);

		bank = (struct bank_info *)bank->bank_node.next;
	}


	/*
	 * Call to the platform layer to populate the cache
	 * with DIMM serial ids.
	 */
	return (plat_populate_sid_cache(mc_dimm_sids, max_entries));
}

static void
mc_init_sid_cache_thr(void)
{
	ASSERT(mc_dimm_sids == NULL);

	mutex_enter(&mcdatamutex);
	rw_enter(&mcdimmsids_rw, RW_WRITER);

	mc_dimm_sids = plat_alloc_sid_cache(&max_entries);
	(void) mc_populate_sid_cache();

	rw_exit(&mcdimmsids_rw);
	mutex_exit(&mcdatamutex);
}

static int
mc_init_sid_cache(void)
{
	if (&plat_alloc_sid_cache) {
		(void) thread_create(NULL, 0, mc_init_sid_cache_thr, NULL, 0,
		    &p0, TS_RUN, minclsyspri);
		return (0);
	} else
		return (ENOTSUP);
}

static int
mc_get_mem_sid(int mcid, int dimm, char *buf, int buflen, int *lenp)
{
	int	i;

	if (buflen < DIMM_SERIAL_ID_LEN)
		return (ENOSPC);

	/*
	 * If DIMM serial ids have not been cached yet, tell the
	 * caller to try again.
	 */
	if (!rw_tryenter(&mcdimmsids_rw, RW_READER))
		return (EAGAIN);

	if (mc_dimm_sids == NULL) {
		rw_exit(&mcdimmsids_rw);
		return (EAGAIN);
	}

	/*
	 * Find dimm serial id using mcid and dimm #
	 */
	for (i = 0; i < max_entries; i++) {
		if (mc_dimm_sids[i].mcid == mcid)
			break;
	}
	if ((i == max_entries) || (!mc_dimm_sids[i].sids)) {
		rw_exit(&mcdimmsids_rw);
		return (ENOENT);
	}

	(void) strlcpy(buf, mc_dimm_sids[i].sids[dimm],
	    DIMM_SERIAL_ID_LEN);
	*lenp = strlen(buf);

	rw_exit(&mcdimmsids_rw);
	return (0);
}

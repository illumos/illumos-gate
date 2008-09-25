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
#include <sys/mc-us3i.h>
#include <sys/note.h>
#include <sys/cpu_module.h>

/*
 * pm-hardware-state value
 */
#define	NO_SUSPEND_RESUME	"no-suspend-resume"

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
	ddi_no_info,			/* getinfo */
	nulldev,			/* identify */
	nulldev,			/* probe */
	mc_attach,			/* attach */
	mc_detach,			/* detach */
	nulldev,			/* reset */
	&mc_cb_ops,			/* cb_ops */
	(struct bus_ops *)0,		/* bus_ops */
	nulldev,			/* power */
	ddi_quiesce_not_needed,			/* quiesce */
};

/*
 * Driver globals
 */
static void *mcp;
static int nmcs = 0;
static int seg_id;
static int nsegments;
static uint64_t	memsize;

static uint_t	mc_debug = 0;

static int getreg;
static int nregs;
struct memory_reg_info *reg_info;

static mc_dlist_t *seg_head, *seg_tail, *bank_head, *bank_tail;
static mc_dlist_t *mctrl_head, *mctrl_tail, *dgrp_head, *dgrp_tail;
static mc_dlist_t *device_head, *device_tail;

static kmutex_t	mcmutex;
static kmutex_t	mcdatamutex;

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,			/* module type, this one is a driver */
	"Memory-controller",		/* module name */
	&mc_ops,			/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,		/* rev */
	(void *)&modldrv,
	NULL
};

static int mc_get_memory_reg_info(struct mc_soft_state *softsp);
static void mc_construct(struct mc_soft_state *softsp);
static void mc_delete(int mc_id);
static void mc_node_add(mc_dlist_t *node, mc_dlist_t **head, mc_dlist_t **tail);
static void mc_node_del(mc_dlist_t *node, mc_dlist_t **head, mc_dlist_t **tail);
static void *mc_node_get(int id, mc_dlist_t *head);
static void mc_add_mem_unum_label(char *unum, int mcid, int bank, int dimm);
static int mc_get_mem_unum(int synd_code, uint64_t paddr, char *buf,
    int buflen, int *lenp);
static int mc_get_mem_info(int synd_code, uint64_t paddr,
    uint64_t *mem_sizep, uint64_t *seg_sizep, uint64_t *bank_sizep,
    int *segsp, int *banksp, int *mcidp);

#pragma weak p2get_mem_unum
#pragma weak p2get_mem_info
#pragma weak plat_add_mem_unum_label

/* For testing only */
struct test_unum {
	int		synd_code;
	uint64_t	paddr;
	char 		unum[UNUM_NAMLEN];
	int		len;
};

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
	int mcreg1_len;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(devi);

	if (ddi_soft_state_zalloc(mcp, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);

	softsp = ddi_get_soft_state(mcp, instance);

	/* Set the dip in the soft state */
	softsp->dip = devi;

	if ((softsp->portid = (int)ddi_getprop(DDI_DEV_T_ANY, softsp->dip,
	    DDI_PROP_DONTPASS, "portid", -1)) == -1) {
		DPRINTF(MC_ATTACH_DEBUG, ("mc%d: unable to get %s property\n",
		    instance, "portid"));
		goto bad;
	}

	DPRINTF(MC_ATTACH_DEBUG, ("mc_attach: mc %d portid %d, cpuid %d\n",
	    instance, softsp->portid, CPU->cpu_id));

	/* Get the content of Memory Control Register I from obp */
	mcreg1_len = sizeof (uint64_t);
	if ((ddi_getlongprop_buf(DDI_DEV_T_ANY, softsp->dip, DDI_PROP_DONTPASS,
	    "memory-control-register-1", (caddr_t)&(softsp->mcreg1),
	    &mcreg1_len) == DDI_PROP_SUCCESS) &&
	    (mcreg1_len == sizeof (uint64_t))) {
		softsp->mcr_read_ok = 1;
		DPRINTF(MC_ATTACH_DEBUG, ("mc%d from obp: Reg1: 0x%lx\n",
		    instance, softsp->mcreg1));
	}

	/* attach fails if mcreg1 cannot be accessed */
	if (!softsp->mcr_read_ok) {
		DPRINTF(MC_ATTACH_DEBUG, ("mc%d: unable to get mcreg1\n",
		    instance));
		goto bad;
	}

	/* nothing to suspend/resume here */
	(void) ddi_prop_create(DDI_DEV_T_NONE, devi, DDI_PROP_CANSLEEP,
	    "pm-hardware-state", NO_SUSPEND_RESUME,
	    sizeof (NO_SUSPEND_RESUME));

	/*
	 * Get the label of dimms and pin routing information from the
	 * memory-layout property of the memory controller.
	 */
	err = ddi_getlongprop(DDI_DEV_T_ANY, softsp->dip, DDI_PROP_DONTPASS,
	    "memory-layout", (caddr_t)&dimminfop, &len);
	if (err == DDI_PROP_SUCCESS && dimminfop->table_width == 1) {
		/* Set the pointer and size of property in the soft state */
		softsp->memlayoutp = dimminfop;
		softsp->memlayoutlen = len;
	} else {
		/*
		 * memory-layout property was not found or some other
		 * error occured, plat_get_mem_unum() will not work
		 * for this mc.
		 */
		softsp->memlayoutp = NULL;
		softsp->memlayoutlen = 0;
		DPRINTF(MC_ATTACH_DEBUG,
		    ("mc %d: missing or unsupported memory-layout property\n",
		    instance));
	}

	mutex_enter(&mcmutex);

	/* Get the physical segments from memory/reg, just once for all MC */
	if (!getreg) {
		if (mc_get_memory_reg_info(softsp) != 0) {
			goto bad1;
		}
		getreg = 1;
	}

	/* Construct the physical and logical layout of the MC */
	mc_construct(softsp);

	if (nmcs == 1) {
		if (&p2get_mem_unum)
			p2get_mem_unum = mc_get_mem_unum;
		if (&p2get_mem_info)
			p2get_mem_info = mc_get_mem_info;
	}

	if (ddi_create_minor_node(devi, "mc-us3i", S_IFCHR, instance,
	    "ddi_mem_ctrl", 0) != DDI_SUCCESS) {
		DPRINTF(MC_ATTACH_DEBUG, ("mc_attach: create_minor_node"
		    " failed \n"));
		goto bad1;
	}
	mutex_exit(&mcmutex);

	ddi_report_dev(devi);
	return (DDI_SUCCESS);

bad1:
	/* release all allocated data struture for this MC */
	mc_delete(softsp->portid);
	mutex_exit(&mcmutex);
	if (softsp->memlayoutp != NULL)
		kmem_free(softsp->memlayoutp, softsp->memlayoutlen);

bad:
	cmn_err(CE_WARN, "mc-us3i: attach failed for instance %d\n", instance);
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

	DPRINTF(MC_DETACH_DEBUG, ("mc %d DETACH: portid %d\n", instance,
	    softsp->portid));

	mutex_enter(&mcmutex);

	/* release all allocated data struture for this MC */
	mc_delete(softsp->portid);

	if (softsp->memlayoutp != NULL)
		kmem_free(softsp->memlayoutp, softsp->memlayoutlen);

	if (nmcs == 0) {
		if (&p2get_mem_unum)
			p2get_mem_unum = NULL;
		if (&p2get_mem_info)
			p2get_mem_info = NULL;
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
	int status = 0;

	/* verify that otyp is appropriate */
	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	mutex_enter(&mcmutex);
	/* At least one attached? */
	if (nmcs == 0) {
		status = ENXIO;
	}
	mutex_exit(&mcmutex);

	return (status);
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
		mcmconf.nbanks = NLOGBANKS_PER_SEG;
		mcmconf.ndevgrps = NDGRPS_PER_MC;
		mcmconf.ndevs = NDIMMS_PER_DGRP;
		mcmconf.len_dev = MAX_DEVLEN;
		mcmconf.xfer_size = TRANSFER_SIZE;

		mutex_exit(&mcdatamutex);

		if (copyout(&mcmconf, (void *)arg, sizeof (mcmconf)))
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
		if (copyin((void *)arg, &mcmem_in, sizeof (mcmem_in)) != 0)
			return (EFAULT);

		mutex_enter(&mcdatamutex);
		if (mcmem_in.nsegments < nsegments) {
			mcmem_in.nsegments = nsegments;
			mutex_exit(&mcdatamutex);
			if (copyout(&mcmem_in, (void *)arg, sizeof (mcmem_in)))
				status = EFAULT;
			else
				status = EINVAL;

			return (status);
		}

		size = sizeof (*mcmem) + (nsegments - 1) *
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

		if (copyin((void *)arg, &mcseg_in, sizeof (mcseg_in)) != 0)
			return (EFAULT);

		mutex_enter(&mcdatamutex);
		if ((seg = mc_node_get(mcseg_in.id, seg_head)) == NULL) {
			DPRINTF(MC_CMD_DEBUG, ("MCIOC_SEG: seg not match, "
			    "id %d\n", mcseg_in.id));
			mutex_exit(&mcdatamutex);
			return (EFAULT);
		}

		if (mcseg_in.nbanks < seg->nbanks) {
			mcseg_in.nbanks = seg->nbanks;
			mutex_exit(&mcdatamutex);
			if (copyout(&mcseg_in, (void *)arg, sizeof (mcseg_in)))
				status = EFAULT;
			else
				status = EINVAL;

			return (status);
		}

		size = sizeof (*mcseg) + (seg->nbanks - 1) *
		    sizeof (mcseg->bankids[0]);
		mcseg = kmem_zalloc(size, KM_SLEEP);

		mcseg->id = seg->seg_node.id;
		mcseg->ifactor = seg->ifactor;
		mcseg->base = seg->base;
		mcseg->size = seg->size;
		mcseg->nbanks = seg->nbanks;

		bank = seg->head;

		DPRINTF(MC_CMD_DEBUG, ("MCIOC_SEG:nbanks %d seg %p bank %p\n",
		    seg->nbanks, (void *) seg, (void *) bank));

		i = 0;
		while (bank != NULL) {
			DPRINTF(MC_CMD_DEBUG, ("MCIOC_SEG:idx %d bank_id %d\n",
			    i, bank->bank_node.id));
			mcseg->bankids[i].globalid = bank->bank_node.id;
			mcseg->bankids[i++].localid = bank->local_id;
			bank = bank->next;
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
		if (copyin((void *)arg, &mcbank, sizeof (mcbank)) != 0)
			return (EFAULT);

		DPRINTF(MC_CMD_DEBUG, ("MCIOC_BANK: bank id %d\n", mcbank.id));

		mutex_enter(&mcdatamutex);

		if ((bank = mc_node_get(mcbank.id, bank_head)) == NULL) {
			mutex_exit(&mcdatamutex);
			return (EINVAL);
		}

		mcbank.mask = bank->mask;
		mcbank.match = bank->match;
		mcbank.size = bank->size;
		mcbank.devgrpid.globalid = bank->devgrp_id;
		mcbank.devgrpid.localid =
		    bank->bank_node.id % NLOGBANKS_PER_SEG;

		mutex_exit(&mcdatamutex);

		if (copyout(&mcbank, (void *)arg, sizeof (mcbank)))
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

		if (copyin((void *)arg, &mcdevgrp, sizeof (mcdevgrp)) != 0)
			return (EFAULT);

		mutex_enter(&mcdatamutex);
		if ((dgrp = mc_node_get(mcdevgrp.id, dgrp_head)) == NULL) {
			DPRINTF(MC_CMD_DEBUG, ("MCIOC_DEVGRP: not match, id "
			    "%d\n", mcdevgrp.id));
			mutex_exit(&mcdatamutex);
			return (EINVAL);
		}

		mcdevgrp.ndevices = dgrp->ndevices;
		mcdevgrp.size = dgrp->size;

		mutex_exit(&mcdatamutex);

		if (copyout(&mcdevgrp, (void *)arg, sizeof (mcdevgrp)))
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
		    sizeof (mcctrlconf_in)) != 0)
			return (EFAULT);

		mutex_enter(&mcdatamutex);
		if (mcctrlconf_in.nmcs < nmcs) {
			mcctrlconf_in.nmcs = nmcs;
			mutex_exit(&mcdatamutex);
			if (copyout(&mcctrlconf_in, (void *)arg,
			    sizeof (mcctrlconf_in)))
				status = EFAULT;
			else
				status = EINVAL;

			return (status);
		}

		/*
		 * Cannot just use the size of the struct because of the various
		 * length struct
		 */
		size = sizeof (*mcctrlconf) + ((nmcs - 1) *
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
		    sizeof (mccontrol_in)) != 0)
			return (EFAULT);

		mutex_enter(&mcdatamutex);
		if ((mcport = mc_node_get(mccontrol_in.id,
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
			mutex_exit(&mcdatamutex);
			if (copyout(&mccontrol_in, (void *)arg,
			    sizeof (mccontrol_in)))
				status = EFAULT;
			else if (mcport->ndevgrps != 0)
				status = EINVAL;

			return (status);
		}

		size = sizeof (*mccontrol) + (mcport->ndevgrps - 1) *
		    sizeof (mccontrol->devgrpids[0]);
		mccontrol = kmem_zalloc(size, KM_SLEEP);

		mccontrol->id = mcport->mctrl_node.id;
		mccontrol->ndevgrps = mcport->ndevgrps;
		for (i = 0; i < mcport->ndevgrps; i++) {
			mccontrol->devgrpids[i].globalid = mcport->devgrpids[i];
			mccontrol->devgrpids[i].localid =
			    mcport->devgrpids[i] % NDGRPS_PER_MC;
			DPRINTF(MC_CMD_DEBUG, ("MCIOC_CONTROL: devgrp id %d\n",
			    i));
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
 * Gets the reg property from the memory node. This provides the various
 * memory segments, at bank-boundries, dimm-pair boundries, in the form
 * of [base, size] pairs. Continuous segments, spanning boundries are
 * merged into one.
 * Returns 0 for success and -1 for failure.
 */
static int
mc_get_memory_reg_info(struct mc_soft_state *softsp)
{
	dev_info_t *devi;
	int len;
	int i;
	struct memory_reg_info *mregi;

	_NOTE(ARGUNUSED(softsp))

	if ((devi = ddi_find_devinfo("memory", -1, 0)) == NULL) {
		DPRINTF(MC_REG_DEBUG,
		    ("mc-us3i: cannot find memory node under root\n"));
		return (-1);
	}

	if (ddi_getlongprop(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
	    "reg", (caddr_t)&reg_info, &len) != DDI_PROP_SUCCESS) {
		DPRINTF(MC_REG_DEBUG,
		    ("mc-us3i: reg undefined under memory\n"));
		return (-1);
	}

	nregs = len/sizeof (*mregi);

	DPRINTF(MC_REG_DEBUG, ("mc_get_memory_reg_info: nregs %d"
	    "reg_info %p\n", nregs, (void *) reg_info));

	mregi = reg_info;

	/* debug printfs  */
	for (i = 0; i < nregs; i++) {
		DPRINTF(MC_REG_DEBUG, (" [0x%lx, 0x%lx] ",
		    mregi->base, mregi->size));
		mregi++;
	}

	return (0);
}

/*
 * Initialize a logical bank
 */
static struct bank_info *
mc_add_bank(int bankid, uint64_t mask, uint64_t match, uint64_t size,
    int dgrpid)
{
	struct bank_info *banki;

	if ((banki = mc_node_get(bankid, bank_head)) != NULL) {
		DPRINTF(MC_CNSTRC_DEBUG, ("mc_add_bank: bank %d exists\n",
		    bankid));
		return (banki);
	}

	banki = kmem_zalloc(sizeof (*banki), KM_SLEEP);

	banki->bank_node.id = bankid;
	banki->devgrp_id = dgrpid;
	banki->mask = mask;
	banki->match = match;
	banki->base = match;
	banki->size = size;

	mc_node_add((mc_dlist_t *)banki, &bank_head, &bank_tail);

	DPRINTF(MC_CNSTRC_DEBUG, ("mc_add_bank: id %d mask 0x%lx match 0x%lx"
	    " base 0x%lx size 0x%lx\n", bankid, mask, match,
	    banki->base, banki->size));

	return (banki);
}

/*
 * Use the bank's base address to find out whether to initialize a new segment,
 * or weave the bank into an existing segment. If the tail bank of a previous
 * segment is not continuous with the new bank, the new bank goes into a new
 * segment.
 */
static void
mc_add_segment(struct bank_info *banki)
{
	struct seg_info *segi;
	struct bank_info *tb;

	/* does this bank start a new segment? */
	if ((segi = mc_node_get(seg_id, seg_head)) == NULL) {
		/* this should happen for the first segment only */
		goto new_seg;
	}

	tb = segi->tail;
	/* discontiguous banks go into a new segment, increment the seg_id */
	if (banki->base > (tb->base + tb->size)) {
		seg_id++;
		goto new_seg;
	}

	/* weave the bank into the segment */
	segi->nbanks++;
	tb->next = banki;

	banki->seg_id = segi->seg_node.id;
	banki->local_id = tb->local_id + 1;

	/* contiguous or interleaved? */
	if (banki->base != (tb->base + tb->size))
		segi->ifactor++;

	segi->size += banki->size;
	segi->tail = banki;

	memsize += banki->size;

	DPRINTF(MC_CNSTRC_DEBUG, ("mc_add_segment: id %d add bank: id %d"
	    "size 0x%lx\n", segi->seg_node.id, banki->bank_node.id,
	    banki->size));

	return;

new_seg:
	segi = kmem_zalloc(sizeof (*segi), KM_SLEEP);

	segi->seg_node.id = seg_id;
	segi->nbanks = 1;
	segi->ifactor = 1;
	segi->base = banki->base;
	segi->size = banki->size;
	segi->head = banki;
	segi->tail = banki;

	banki->seg_id = segi->seg_node.id;
	banki->local_id = 0;

	mc_node_add((mc_dlist_t *)segi, &seg_head, &seg_tail);
	nsegments++;

	memsize += banki->size;

	DPRINTF(MC_CNSTRC_DEBUG, ("mc_add_segment: id %d new bank: id %d"
	    "size 0x%lx\n", segi->seg_node.id, banki->bank_node.id,
	    banki->size));
}

/*
 * Returns the address bit number (row index) that controls the logical/external
 * bank assignment in interleave of kind internal-external same dimm-pair,
 * internal-external both dimm-pair. This is done by using the dimm-densities
 * and part-type.
 */
static int
get_row_shift(int row_index, struct dgrp_info *dgrp)
{
	int shift;

	switch (dgrp->base_device) {
	case BASE_DEVICE_128Mb:
	case BASE_DEVICE_256Mb:
		/* 128Mb and 256Mb devices have same bank select mask */
		shift = ADDR_GEN_128Mb_X8_ROW_0;
		break;
	case BASE_DEVICE_512Mb:
	case BASE_DEVICE_1Gb:
		/* 512 and 1Gb devices have same bank select mask */
		shift = ADDR_GEN_512Mb_X8_ROW_0;
		break;
	}

	if (dgrp->part_type == PART_TYPE_X4)
		shift += 1;

	shift += row_index;

	return (shift);
}


static void
get_device_select(int interleave, struct dgrp_info *dgrp,
    int *ds_shift, int *bs_shift)
{

	switch (interleave) {
	case INTERLEAVE_DISABLE:
	/* Fall Through */
	case INTERLEAVE_INTERNAL:
		/* Bit 33 selects the dimm group/pair */
		*ds_shift = DIMM_PAIR_SELECT_SHIFT;
		if (dgrp->nlogbanks == 2) {
			/* Bit 32 selects the logical bank */
			*bs_shift = LOG_BANK_SELECT_SHIFT;
		}
		break;
	case INTERLEAVE_INTEXT_SAME_DIMM_PAIR:
		/* Bit 33 selects the dimm group/pair */
		*ds_shift =  DIMM_PAIR_SELECT_SHIFT;
		if (dgrp->nlogbanks == 2) {
			/* Row[2] selects the logical bank */
			*bs_shift = get_row_shift(2, dgrp);
		}
		break;
	case INTERLEAVE_INTEXT_BOTH_DIMM_PAIR:
		if (dgrp->nlogbanks == 2) {
			/* Row[3] selects the dimm group/pair */
			*ds_shift = get_row_shift(3, dgrp);

			/* Row[2] selects the logical bank */
			*bs_shift = get_row_shift(2, dgrp);
		} else {
			/* Row[2] selects the dimm group/pair */
			*ds_shift = get_row_shift(2, dgrp);
		}
		break;
	}
}

static void
mc_add_xor_banks(struct mctrl_info *mctrl,
    uint64_t mask, uint64_t match, int interleave)
{
	int i, j, nbits, nbanks;
	int bankid;
	int dselect[4];
	int ds_shift = -1, bs_shift = -1;
	uint64_t id, size, xmatch;
	struct bank_info *banki;
	struct dgrp_info *dgrp;

	/* xor mode - assume 2 identical dimm-pairs */
	if ((dgrp = mc_node_get(mctrl->devgrpids[0], dgrp_head)) == NULL) {
		return;
	}

	get_device_select(interleave, dgrp, &ds_shift, &bs_shift);

	mask |= (ds_shift == -1 ? 0 : (1ULL << ds_shift));
	mask |= (bs_shift == -1 ? 0 : (1ULL << bs_shift));

	/* xor enable means, bit 21 is used for dimm-pair select */
	mask |= XOR_DEVICE_SELECT_MASK;
	if (dgrp->nlogbanks == NLOGBANKS_PER_DGRP) {
		/* bit 20 is used for logbank select */
		mask |= XOR_BANK_SELECT_MASK;
	}

	/* find out the bits set to 1 in mask, nbits can be 2 or 4 */
	nbits = 0;
	for (i = 0; i <= DIMM_PAIR_SELECT_SHIFT; i++) {
		if ((((mask >> i) & 1) == 1) && (nbits < 4)) {
			dselect[nbits] = i;
			nbits++;
		}
	}

	/* number or banks can be 4 or 16 */
	nbanks = 1 << nbits;

	size = (dgrp->size * 2)/nbanks;

	bankid = mctrl->mctrl_node.id * NLOGBANKS_PER_MC;

	/* each bit position of the mask decides the match & base for bank */
	for (i = 0; i < nbanks; i++) {
		xmatch = 0;
		for (j = 0; j < nbits; j++) {
			xmatch |= (i & (1ULL << j)) << (dselect[j] - j);
		}
		/* xor ds bits to get the dimm-pair */
		id = ((xmatch & (1ULL << ds_shift)) >> ds_shift) ^
		    ((xmatch & (1ULL << XOR_DEVICE_SELECT_SHIFT)) >>
		    XOR_DEVICE_SELECT_SHIFT);
		banki = mc_add_bank(bankid, mask, match | xmatch, size,
		    mctrl->devgrpids[id]);
		mc_add_segment(banki);
		bankid++;
	}
}

/*
 * Based on interleave, dimm-densities, part-type determine the mask
 * and match per bank, construct the logical layout by adding segments
 * and banks
 */
static int
mc_add_dgrp_banks(uint64_t bankid, uint64_t dgrpid,
    uint64_t mask, uint64_t match, int interleave)
{
	int nbanks = 0;
	struct bank_info *banki;
	struct dgrp_info *dgrp;
	int ds_shift = -1, bs_shift = -1;
	uint64_t size;
	uint64_t match_save;

	if ((dgrp = mc_node_get(dgrpid, dgrp_head)) == NULL) {
		return (0);
	}

	get_device_select(interleave, dgrp, &ds_shift, &bs_shift);

	mask |= (ds_shift == -1 ? 0 : (1ULL << ds_shift));
	mask |= (bs_shift == -1 ? 0 : (1ULL << bs_shift));
	match |= (ds_shift == -1 ? 0 : ((dgrpid & 1) << ds_shift));
	match_save = match;
	size = dgrp->size/dgrp->nlogbanks;

	/* for bankid 0, 2, 4 .. */
	match |= (bs_shift == -1 ? 0 : ((bankid & 1) << bs_shift));
	DPRINTF(MC_CNSTRC_DEBUG, ("mc_add_segments: interleave %d"
	    " mask 0x%lx bs_shift %d match 0x%lx\n",
	    interleave, mask, bs_shift, match));
	banki = mc_add_bank(bankid, mask, match, size, dgrpid);
	nbanks++;
	mc_add_segment(banki);

	if (dgrp->nlogbanks == 2) {
		/*
		 * Set match value to original before adding second
		 * logical bank interleaving information.
		 */
		match = match_save;
		bankid++;
		match |= (bs_shift == -1 ? 0 : ((bankid & 1) << bs_shift));
		DPRINTF(MC_CNSTRC_DEBUG, ("mc_add_segments: interleave %d"
		    " mask 0x%lx shift %d match 0x%lx\n",
		    interleave, mask, bs_shift, match));
		banki = mc_add_bank(bankid, mask, match, size, dgrpid);
		nbanks++;
		mc_add_segment(banki);
	}

	return (nbanks);
}

/*
 * Construct the logical layout
 */
static void
mc_logical_layout(struct mctrl_info *mctrl, struct mc_soft_state *softsp)
{
	int i;
	uint64_t mcid, bankid, interleave, mask, match;

	if (mctrl->ndevgrps == 0)
		return;

	mcid = mctrl->mctrl_node.id;
	mask = MC_SELECT_MASK;
	match = mcid << MC_SELECT_SHIFT;

	interleave = (softsp->mcreg1 & MCREG1_INTERLEAVE_MASK) >>
	    MCREG1_INTERLEAVE_SHIFT;

	/* Two dimm pairs and xor bit set */
	if (mctrl->ndevgrps == NDGRPS_PER_MC &&
	    (softsp->mcreg1 & MCREG1_XOR_ENABLE)) {
		mc_add_xor_banks(mctrl, mask, match, interleave);
		return;
	}

	/*
	 * For xor bit unset or only one dimm pair.
	 * In one dimm pair case, even if xor bit is set, xor
	 * interleaving is only taking place in dimm's internal
	 * banks. Dimm and external bank select bits are the
	 * same as those without xor bit set.
	 */
	bankid = mcid * NLOGBANKS_PER_MC;
	for (i = 0; i < mctrl->ndevgrps; i++) {
		bankid += mc_add_dgrp_banks(bankid, mctrl->devgrpids[i],
		    mask, match, interleave);
	}
}

/*
 * Get the dimm-pair's size from the reg_info
 */
static uint64_t
get_devgrp_size(uint64_t start)
{
	int i;
	uint64_t size;
	uint64_t end, reg_start, reg_end;
	struct memory_reg_info *regi;

	/* dgrp end address */
	end = start + DGRP_SIZE_MAX - 1;

	regi = reg_info;
	size = 0;
	for (i = 0; i < nregs; i++) {
		reg_start = regi->base;
		reg_end = regi->base + regi->size - 1;

		/* completely outside */
		if ((reg_end < start) || (reg_start > end)) {
			regi++;
			continue;
		}

		/* completely inside */
		if ((reg_start <= start) && (reg_end >= end)) {
			return (DGRP_SIZE_MAX);
		}

		/* start is inside, but not the end, get the remainder */
		if (reg_start < start) {
			size = regi->size - (start - reg_start);
			regi++;
			continue;
		}

		/* add up size for all within range */
		size += regi->size;
		regi++;
	}

	return (size);
}

/*
 * Each device group is a pair (dimm-pair) of identical single/dual dimms.
 * Determine the dimm-pair's dimm-densities and part-type using the MCR-I.
 */
static void
mc_add_devgrp(int dgrpid, struct mc_soft_state *softsp)
{
	int i, mcid, devid, dgrpoffset;
	struct dgrp_info *dgrp;
	struct device_info *dev;
	struct dimm_info *dimmp = (struct dimm_info *)softsp->memlayoutp;

	mcid = softsp->portid;

	/* add the entry on dgrp_info list */
	if ((dgrp = mc_node_get(dgrpid, dgrp_head)) != NULL) {
		DPRINTF(MC_CNSTRC_DEBUG, ("mc_add_devgrp: devgrp %d exists\n",
		    dgrpid));
		return;
	}

	dgrp = kmem_zalloc(sizeof (*dgrp), KM_SLEEP);

	dgrp->dgrp_node.id = dgrpid;

	/* a devgrp has identical (type & size) pair */
	if ((dgrpid & 1) == 0) {
		/* dimm-pair 0, 2, 4, 6 */
		if (softsp->mcreg1 & MCREG1_DIMM1_BANK1)
			dgrp->nlogbanks = 2;
		else
			dgrp->nlogbanks = 1;
		dgrp->base_device = (softsp->mcreg1 & MCREG1_ADDRGEN1_MASK) >>
		    MCREG1_ADDRGEN1_SHIFT;
		dgrp->part_type = (softsp->mcreg1 & MCREG1_X4DIMM1_MASK) >>
		    MCREG1_X4DIMM1_SHIFT;
	} else {
		/* dimm-pair 1, 3, 5, 7 */
		if (softsp->mcreg1 & MCREG1_DIMM2_BANK3)
			dgrp->nlogbanks = 2;
		else
			dgrp->nlogbanks = 1;
		dgrp->base_device = (softsp->mcreg1 & MCREG1_ADDRGEN2_MASK) >>
		    MCREG1_ADDRGEN2_SHIFT;
		dgrp->part_type = (softsp->mcreg1 & MCREG1_X4DIMM2_MASK) >>
		    MCREG1_X4DIMM2_SHIFT;
	}

	dgrp->base = MC_BASE(mcid) + DGRP_BASE(dgrpid);
	dgrp->size = get_devgrp_size(dgrp->base);

	DPRINTF(MC_CNSTRC_DEBUG, ("mc_add_devgrp: id %d size %ld logbanks %d"
	    " base_device %d part_type %d\n", dgrpid, dgrp->size,
	    dgrp->nlogbanks, dgrp->base_device, dgrp->part_type));

	dgrpoffset = dgrpid % NDGRPS_PER_MC;
	dgrp->ndevices = NDIMMS_PER_DGRP;
	/* add the entry for the (identical) pair of dimms/device */
	for (i = 0; i < NDIMMS_PER_DGRP; i++) {
		devid = dgrpid * NDIMMS_PER_DGRP + i;
		dgrp->deviceids[i] = devid;

		if ((dev = mc_node_get(devid, device_head)) != NULL) {
			DPRINTF(MC_CNSTRC_DEBUG, ("mc_add_devgrp: device %d "
			    "exists\n", devid));
			continue;
		}

		dev = kmem_zalloc(sizeof (*dev), KM_SLEEP);

		dev->dev_node.id = devid;

		dev->size = dgrp->size/2;

		if (dimmp) {
			(void) strncpy(dev->label, (char *)dimmp->label[
			    i + NDIMMS_PER_DGRP * dgrpoffset],
			    MAX_DEVLEN);

			DPRINTF(MC_CNSTRC_DEBUG, ("mc_add_devgrp: dimm %d %s\n",
			    dev->dev_node.id, dev->label));
		}

		mc_node_add((mc_dlist_t *)dev, &device_head, &device_tail);
	}

	mc_node_add((mc_dlist_t *)dgrp, &dgrp_head, &dgrp_tail);
}

/*
 * Construct the physical and logical layout
 */
static void
mc_construct(struct mc_soft_state *softsp)
{
	int i, mcid, dgrpid;
	struct mctrl_info *mctrl;

	mcid = softsp->portid;

	DPRINTF(MC_CNSTRC_DEBUG, ("mc_construct: mcid %d, mcreg1 0x%lx\n",
	    mcid, softsp->mcreg1));

	/*
	 * Construct the Physical & Logical Layout
	 */
	mutex_enter(&mcdatamutex);

	/* allocate for mctrl_info */
	if ((mctrl = mc_node_get(mcid, mctrl_head)) != NULL) {
		DPRINTF(MC_CNSTRC_DEBUG, ("mc_construct: mctrl %d exists\n",
		    mcid));
		mutex_exit(&mcdatamutex);
		return;
	}

	mctrl = kmem_zalloc(sizeof (*mctrl), KM_SLEEP);

	mctrl->mctrl_node.id = mcid;

	i = 0;
	dgrpid = mcid * NDGRPS_PER_MC;
	if (softsp->mcreg1 & MCREG1_DIMM1_BANK0) {
		mc_add_devgrp(dgrpid, softsp);
		mctrl->devgrpids[i] = dgrpid;
		mctrl->ndevgrps++;
		i++;
	}

	if (softsp->mcreg1 & MCREG1_DIMM2_BANK2) {
		dgrpid++;
		mc_add_devgrp(dgrpid, softsp);
		mctrl->devgrpids[i] = dgrpid;
		mctrl->ndevgrps++;
	}

	mc_logical_layout(mctrl, softsp);

	mctrl->dimminfop = (struct dimm_info *)softsp->memlayoutp;

	nmcs++;
	mc_node_add((mc_dlist_t *)mctrl, &mctrl_head, &mctrl_tail);

	mutex_exit(&mcdatamutex);

	DPRINTF(MC_CNSTRC_DEBUG, ("mc_construct: nmcs %d memsize %ld"
	    "nsegments %d\n", nmcs, memsize, nsegments));
}

/*
 * Delete nodes related to the given MC on mc, device group, device,
 * and bank lists. Moreover, delete corresponding segment if its connected
 * banks are all removed.
 */
static void
mc_delete(int mc_id)
{
	int i, j, dgrpid, devid, bankid;
	struct mctrl_info *mctrl;
	struct dgrp_info *dgrp;
	struct device_info *devp;
	struct seg_info *segi;
	struct bank_info *banki;

	mutex_enter(&mcdatamutex);

	/* delete mctrl_info */
	if ((mctrl = mc_node_get(mc_id, mctrl_head)) != NULL) {
		mc_node_del((mc_dlist_t *)mctrl, &mctrl_head, &mctrl_tail);
		kmem_free(mctrl, sizeof (*mctrl));
		nmcs--;
	} else
		DPRINTF(MC_DESTRC_DEBUG, ("mc_delete: mctrl is not found\n"));

	/* delete device groups and devices of the detached MC */
	for (i = 0; i < NDGRPS_PER_MC; i++) {
		dgrpid = mc_id * NDGRPS_PER_MC + i;
		if (!(dgrp = mc_node_get(dgrpid, dgrp_head))) {
			continue;
		}

		for (j = 0; j < NDIMMS_PER_DGRP; j++) {
			devid = dgrpid * NDIMMS_PER_DGRP + j;
			if (devp = mc_node_get(devid, device_head)) {
				mc_node_del((mc_dlist_t *)devp,
				    &device_head, &device_tail);
				kmem_free(devp, sizeof (*devp));
			} else
				DPRINTF(MC_DESTRC_DEBUG,
				    ("mc_delete: no dev %d\n", devid));
		}

		mc_node_del((mc_dlist_t *)dgrp, &dgrp_head, &dgrp_tail);
		kmem_free(dgrp, sizeof (*dgrp));
	}

	/* delete all banks and associated segments */
	for (i = 0; i < NLOGBANKS_PER_MC; i++) {
		bankid = mc_id * NLOGBANKS_PER_MC + i;
		if (!(banki = mc_node_get(bankid, bank_head))) {
			continue;
		}

		/* bank and segments go together */
		if ((segi = mc_node_get(banki->seg_id, seg_head)) != NULL) {
			mc_node_del((mc_dlist_t *)segi, &seg_head, &seg_tail);
			kmem_free(segi, sizeof (*segi));
			nsegments--;
		}

		mc_node_del((mc_dlist_t *)banki, &bank_head, &bank_tail);
		kmem_free(banki, sizeof (*banki));
	}

	mutex_exit(&mcdatamutex);
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
	    node->id, (void *) *head, (void *) *tail));

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
static void *
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
 * Memory subsystem provides 144 bits (128 Data bits, 9 ECC bits and 7
 * unused bits) interface via a pair of DIMMs. Mapping of Data/ECC bits
 * to a specific DIMM pin is described by the memory-layout property
 * via two tables: dimm table and pin table.
 *
 * Memory-layout property arranges data/ecc bits in the following order:
 *
 *   Bit#  143                          16 15       7 6           0
 *        |      Data[127:0]              | ECC[8:0] | Unused[6:0] |
 *
 * dimm table: 1 bit is used to store DIMM number (2 possible DIMMs) for
 *	each Data/ECC bit. Thus, it needs 18 bytes (144/8) to represent
 *	all Data/ECC bits in this table. Information is stored in big
 *	endian order, i.e. dimm_table[0] represents information for
 *	logical bit# 143 to 136.
 *
 * pin table: 1 byte is used to store pin position for each Data/ECC bit.
 *	Thus, this table is 144 bytes long. Information is stored in little
 *	endian order, i.e, pin_table[0] represents pin number of logical
 *	bit 0 and pin_table[143] contains pin number for logical bit 143
 *	(i.e. data bit# 127).
 *
 * qwordmap table below is used to map mc_get_mem_unum "synd_code" value into
 * logical bit position assigned above by the memory-layout property.
 */

#define	QWORD_SIZE	144
static uint8_t qwordmap[QWORD_SIZE] =
{
16,   17,  18,  19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,  30,  31,
32,   33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,
48,   49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  62,  63,
64,   65,  66,  67,  68,  69,  70,  71,  72,  73,  74,  75,  76,  77,  78,  79,
80,   81,  82,  83,  84,  85,  86,  87,  88,  89,  90,  91,  92,  93,  94,  95,
96,   97,  98,  99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127,
128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
7,    8,   9,  10,  11,  12,  13,  14,  15,   4,   5,   6,   0,   1,   2,   3
};


/* ARGSUSED */
static int
mc_get_mem_unum(int synd_code, uint64_t paddr, char *buf, int buflen, int *lenp)
{
	int i;
	int pos_cacheline, position, index, idx4dimm;
	int qwlayout = synd_code;
	short offset, data;
	char unum[UNUM_NAMLEN];
	struct dimm_info *dimmp;
	struct pin_info *pinp;
	struct bank_info *bank;
	struct mctrl_info *mctrl;

	/*
	 * Enforce old Openboot requirement for synd code, either a single-bit
	 * code from 0..QWORD_SIZE-1 or -1 (multi-bit error).
	 */
	if (qwlayout < -1 || qwlayout >= QWORD_SIZE)
		return (EINVAL);

	unum[0] = '\0';

	DPRINTF(MC_GUNUM_DEBUG, ("mc_get_mem_unum:qwlayout %d phyaddr 0x%lx\n",
	    qwlayout, paddr));

	/*
	 * Scan all logical banks to get one responding to the physical
	 * address. Then compute the index to look up dimm and pin tables
	 * to generate the unmuber.
	 */
	mutex_enter(&mcdatamutex);
	bank = (struct bank_info *)bank_head;
	while (bank != NULL) {
		int mcid, mcdgrpid, dimmoffset;

		/*
		 * Physical Address is in a bank if (Addr & Mask) == Match
		 */
		if ((paddr & bank->mask) != bank->match) {
			bank = (struct bank_info *)bank->bank_node.next;
			continue;
		}

		mcid = bank->bank_node.id / NLOGBANKS_PER_MC;
		mctrl = mc_node_get(mcid, mctrl_head);
		ASSERT(mctrl != NULL);

		DPRINTF(MC_GUNUM_DEBUG, ("mc_get_mem_unum:mc %d bank %d "
		    "dgrp %d\n", mcid, bank->bank_node.id, bank->devgrp_id));

		mcdgrpid = bank->devgrp_id % NDGRPS_PER_MC;
		dimmoffset = mcdgrpid * NDIMMS_PER_DGRP;

		dimmp = (struct dimm_info *)mctrl->dimminfop;
		if (dimmp == NULL) {
			mutex_exit(&mcdatamutex);
			return (ENXIO);
		}

		if ((qwlayout >= 0) && (qwlayout < QWORD_SIZE)) {
			/*
			 * single-bit error handling, we can identify specific
			 * DIMM.
			 */

			pinp = (struct pin_info *)&dimmp->data[0];

			pos_cacheline = qwordmap[qwlayout];
			position = 143 - pos_cacheline;
			index = position / 8;
			offset = 7 - (position % 8);

			DPRINTF(MC_GUNUM_DEBUG, ("mc_get_mem_unum:position "
			    "%d\n", position));
			/*
			 * Trade-off: We cound't add pin number to
			 * unumber string because statistic number
			 * pumps up at the corresponding dimm not pin.
			 * (void) sprintf(unum, "Pin %1u ", (uint_t)
			 * pinp->pintable[pos_cacheline]);
			 */
			DPRINTF(MC_GUNUM_DEBUG, ("mc_get_mem_unum:pin number "
			    "%1u\n", (uint_t)pinp->pintable[pos_cacheline]));
			data = pinp->dimmtable[index];
			idx4dimm = (data >> offset) & 1;

			(void) strncpy(unum,
			    (char *)dimmp->label[dimmoffset + idx4dimm],
			    UNUM_NAMLEN);

			DPRINTF(MC_GUNUM_DEBUG,
			    ("mc_get_mem_unum:unum %s\n", unum));

			/*
			 * platform hook for adding label information to unum.
			 */
			mc_add_mem_unum_label(unum, mcid, mcdgrpid, idx4dimm);
		} else {
			char *p = unum;
			size_t res = UNUM_NAMLEN;

			/*
			 * multi-bit error handling, we can only identify
			 * bank of DIMMs.
			 */

			for (i = 0; (i < NDIMMS_PER_DGRP) && (res > 0); i++) {
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
			mc_add_mem_unum_label(unum, mcid, mcdgrpid, -1);
		}
		mutex_exit(&mcdatamutex);
		if ((strlen(unum) >= UNUM_NAMLEN) ||
		    (strlen(unum) >= buflen)) {
			return (ENAMETOOLONG);
		} else {
			(void) strncpy(buf, unum, UNUM_NAMLEN);
			*lenp = strlen(buf);
			return (0);
		}
	}	/* end of while loop for logic bank list */

	mutex_exit(&mcdatamutex);
	return (ENXIO);
}

static int
mc_get_mem_info(int synd_code, uint64_t paddr,
    uint64_t *mem_sizep, uint64_t *seg_sizep, uint64_t *bank_sizep,
    int *segsp, int *banksp, int *mcidp)
{
	struct bank_info *bankp;

	if (synd_code < -1 || synd_code >= QWORD_SIZE)
		return (EINVAL);

	/*
	 * Scan all logical banks to get one responding to the physical
	 * address. Then compute the index to look up dimm and pin tables
	 * to generate the unmuber.
	 */
	mutex_enter(&mcdatamutex);
	bankp = (struct bank_info *)bank_head;
	while (bankp != NULL) {
		struct seg_info *segp;
		int mcid;

		/*
		 * Physical Address is in a bank if (Addr & Mask) == Match
		 */
		if ((paddr & bankp->mask) != bankp->match) {
			bankp = (struct bank_info *)bankp->bank_node.next;
			continue;
		}

		mcid = bankp->bank_node.id / NLOGBANKS_PER_MC;

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

	}	/* end of while loop for logic bank list */

	mutex_exit(&mcdatamutex);
	return (ENXIO);
}
/*
 * mc-us3i driver allows a platform to add extra label
 * information to the unum string. If a platform implements a
 * kernel function called plat_add_mem_unum_label() it will be
 * executed. This would typically be implemented in the platmod.
 */
static void
mc_add_mem_unum_label(char *unum, int mcid, int bank, int dimm)
{
	if (&plat_add_mem_unum_label)
		plat_add_mem_unum_label(unum, mcid, bank, dimm);
}

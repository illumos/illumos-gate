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
 * sun4 root nexus driver
 */

#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/ddi_subrdefs.h>
#include <sys/sunndi.h>
#include <sys/vmsystm.h>
#include <sys/async.h>
#include <sys/intr.h>
#include <sys/ndifm.h>
#include <vm/seg_dev.h>
#include <vm/seg_kmem.h>
#include <sys/ontrap.h>

/* Useful debugging Stuff */
#include <sys/nexusdebug.h>
#define	ROOTNEX_MAP_DEBUG		0x1
#define	ROOTNEX_INTR_DEBUG		0x2

/*
 * config information
 */

static int
rootnex_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
    off_t offset, off_t len, caddr_t *vaddrp);

static int
rootnex_intr_ops(dev_info_t *, dev_info_t *, ddi_intr_op_t,
    ddi_intr_handle_impl_t *, void *);

static int
rootnex_map_fault(dev_info_t *dip, dev_info_t *rdip,
    struct hat *hat, struct seg *seg, caddr_t addr,
    struct devpage *dp, pfn_t pfn, uint_t prot, uint_t lock);

static int
rootnex_ctlops(dev_info_t *, dev_info_t *, ddi_ctl_enum_t, void *, void *);

static int
rootnex_busop_fminit(dev_info_t *dip, dev_info_t *tdip, int tcap,
    ddi_iblock_cookie_t *ibc);

static void
rootnex_fm_init(dev_info_t *);

static int
rootnex_ctlops_peekpoke(ddi_ctl_enum_t, peekpoke_ctlops_t *, void *result);

/*
 * Defined in $KARCH/io/mach_rootnex.c
 */
int rootnex_add_intr_impl(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp);
#pragma weak rootnex_add_intr_impl

int rootnex_remove_intr_impl(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp);
#pragma weak rootnex_remove_intr_impl

int rootnex_get_intr_pri(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp);
#pragma weak rootnex_get_intr_pri

int rootnex_name_child_impl(dev_info_t *child, char *name, int namelen);
#pragma weak rootnex_name_child_impl

int rootnex_ctl_initchild_impl(dev_info_t *dip);
#pragma weak rootnex_initchild_impl

void rootnex_ctl_uninitchild_impl(dev_info_t *dip);
#pragma weak rootnex_uninitchild_impl

int rootnex_ctl_reportdev_impl(dev_info_t *dev);
#pragma weak rootnex_reportdev_impl

static struct cb_ops rootnex_cb_ops = {
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
	nochpoll,	/* chpoll */
	ddi_prop_op,	/* cb_prop_op */
	NULL,		/* struct streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* compatibility flags */
	CB_REV,		/* Rev */
	nodev,		/* cb_aread */
	nodev		/* cb_awrite */
};

static struct bus_ops rootnex_bus_ops = {
	BUSO_REV,
	rootnex_map,
	NULL,
	NULL,
	NULL,
	rootnex_map_fault,
	ddi_no_dma_map,		/* no rootnex_dma_map- now in sysio nexus */
	ddi_no_dma_allochdl,
	ddi_no_dma_freehdl,
	ddi_no_dma_bindhdl,
	ddi_no_dma_unbindhdl,
	ddi_no_dma_flush,
	ddi_no_dma_win,
	ddi_no_dma_mctl,	/* no rootnex_dma_mctl- now in sysio nexus */
	rootnex_ctlops,
	ddi_bus_prop_op,
	i_ddi_rootnex_get_eventcookie,
	i_ddi_rootnex_add_eventcall,
	i_ddi_rootnex_remove_eventcall,
	i_ddi_rootnex_post_event,
	NULL,			/* bus_intr_ctl */
	NULL,			/* bus_config */
	NULL,			/* bus_unconfig */
	rootnex_busop_fminit,	/* bus_fm_init */
	NULL,			/* bus_fm_fini */
	NULL,			/* bus_fm_access_enter */
	NULL,			/* bus_fm_access_fini */
	NULL,			/* bus_power */
	rootnex_intr_ops	/* bus_intr_op */
};

static int rootnex_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);
static int rootnex_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);

static struct dev_ops rootnex_ops = {
	DEVO_REV,
	0,			/* refcnt */
	ddi_no_info,		/* info */
	nulldev,
	nulldev,		/* probe */
	rootnex_attach,
	rootnex_detach,
	nodev,			/* reset */
	&rootnex_cb_ops,
	&rootnex_bus_ops,
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};


extern uint_t	root_phys_addr_lo_mask;
extern uint_t	root_phys_addr_hi_mask;
extern struct mod_ops mod_driverops;
extern struct dev_ops rootnex_ops;
extern struct cpu cpu0;
extern ddi_iblock_cookie_t rootnex_err_ibc;


/*
 * Add statically defined root properties to this list...
 */
static const int pagesize = PAGESIZE;
static const int mmu_pagesize = MMU_PAGESIZE;
static const int mmu_pageoffset = MMU_PAGEOFFSET;

struct prop_def {
	char *prop_name;
	caddr_t prop_value;
};

static struct prop_def root_props[] = {
	{ "PAGESIZE",		(caddr_t)&pagesize },
	{ "MMU_PAGESIZE",	(caddr_t)&mmu_pagesize},
	{ "MMU_PAGEOFFSET",	(caddr_t)&mmu_pageoffset},
};

static vmem_t	*rootnex_regspec_arena;

#define	NROOT_PROPS	(sizeof (root_props) / sizeof (struct prop_def))



/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops,	/* Type of module.  This one is a nexus driver */
	"sun4 root nexus",
	&rootnex_ops,	/* Driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
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

/*
 * rootnex_attach:
 *
 *	attach the root nexus.
 */
static void add_root_props(dev_info_t *);

/*ARGSUSED*/
static int
rootnex_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int length;
	char *valuep = NULL;

	/*
	 * Only do these functions when the driver is acting as the
	 * root nexus, not when it is driving a memory controller.
	 */
	if (ddi_root_node() == devi) {
		rootnex_fm_init(devi);
		add_root_props(devi);
		i_ddi_rootnex_init_events(devi);
		rootnex_regspec_arena = vmem_create("regspec",
		    (void *)PIOMAPBASE, PIOMAPSIZE, MMU_PAGESIZE, NULL, NULL,
		    NULL, 0, VM_SLEEP);
	}

	if (ddi_prop_op(DDI_DEV_T_ANY, devi, PROP_LEN_AND_VAL_ALLOC,
	    DDI_PROP_DONTPASS, "banner-name", (caddr_t)&valuep,
	    &length) == DDI_PROP_SUCCESS) {
		cmn_err(CE_CONT, "?root nexus = %s\n", valuep);
		kmem_free(valuep, length);
	}
	/*
	 * Add a no-suspend-resume property so that NDI
	 * does not attempt to suspend/resume the rootnex
	 * (or any of its aliases) node.
	 */
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, devi,
	    "pm-hardware-state", "no-suspend-resume");

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
rootnex_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	return (DDI_SUCCESS);
}

static void
add_root_props(dev_info_t *devi)
{
	int i;
	struct prop_def *rpp;

	/*
	 * Note that this for loop works because all of the
	 * properties in root_prop are integers
	 */
	for (i = 0, rpp = root_props; i < NROOT_PROPS; ++i, ++rpp) {
		(void) e_ddi_prop_update_int(DDI_DEV_T_NONE, devi,
		    rpp->prop_name, *((int *)rpp->prop_value));
	}

	/*
	 * Create the root node "boolean" property
	 * corresponding to addressing type supported in the root node:
	 *
	 * Choices are:
	 *	"relative-addressing" (OBP PROMS)
	 *	"generic-addressing"  (SunMon -- pseudo OBP/DDI)
	 */

	(void) e_ddi_prop_update_int(DDI_DEV_T_NONE, devi,
	    DDI_RELATIVE_ADDRESSING, 1);

	/*
	 * Create fault management capability property
	 */
	(void) e_ddi_prop_update_int(DDI_DEV_T_NONE, devi, "fm-capable",
	    ddi_fm_capable(devi));
}

static int
rootnex_map_regspec(ddi_map_req_t *mp, caddr_t *vaddrp, uint_t mapping_attr)
{
	uint64_t base;
	caddr_t kaddr;
	pgcnt_t npages;
	pfn_t 	pfn;
	uint_t 	pgoffset;
	struct regspec *rp = mp->map_obj.rp;
	ddi_acc_hdl_t *hp;

	base = (uint64_t)rp->regspec_addr & (~MMU_PAGEOFFSET); /* base addr */

	/*
	 * Take the bustype and addr and convert it to a
	 * page frame number.
	 */
	pfn =  mmu_btop(((uint64_t)(rp->regspec_bustype &
	    root_phys_addr_hi_mask) << 32) | base);

	/*
	 * Do a quick sanity check to make sure we are in I/O space.
	 */
	if (pf_is_memory(pfn))
		return (DDI_ME_INVAL);

	if (rp->regspec_size == 0) {
		DPRINTF(ROOTNEX_MAP_DEBUG, ("rootnex_map_regspec: zero "
		    "regspec_size\n"));
		return (DDI_ME_INVAL);
	}

	if (mp->map_flags & DDI_MF_DEVICE_MAPPING)
		*vaddrp = (caddr_t)pfn;
	else {
		pgoffset = (ulong_t)rp->regspec_addr & MMU_PAGEOFFSET;
		npages = mmu_btopr(rp->regspec_size + pgoffset);

		DPRINTF(ROOTNEX_MAP_DEBUG, ("rootnex_map_regspec: Mapping "
		    "%lu pages physical %x.%lx ", npages, rp->regspec_bustype,
		    base));

		if ((kaddr = vmem_alloc(rootnex_regspec_arena,
		    ptob(npages), VM_NOSLEEP)) == NULL)
			return (DDI_ME_NORESOURCES);

		/*
		 * Now map in the pages we've allocated...
		 */
		hat_devload(kas.a_hat, kaddr, ptob(npages), pfn,
		    mp->map_prot | mapping_attr, HAT_LOAD_LOCK);

		*vaddrp = kaddr + pgoffset;

		hp = mp->map_handlep;
		if (hp) {
			hp->ah_pfn = pfn;
			hp->ah_pnum = npages;
		}
	}

	DPRINTF(ROOTNEX_MAP_DEBUG, ("at virtual 0x%p\n", (void *)*vaddrp));
	return (0);
}

static int
rootnex_unmap_regspec(ddi_map_req_t *mp, caddr_t *vaddrp)
{
	caddr_t addr = *vaddrp;
	pgcnt_t npages;
	uint_t  pgoffset;
	caddr_t base;
	struct regspec *rp;

	if (mp->map_flags & DDI_MF_DEVICE_MAPPING)
		return (0);

	rp = mp->map_obj.rp;
	pgoffset = (uintptr_t)addr & MMU_PAGEOFFSET;

	if (rp->regspec_size == 0) {
		DPRINTF(ROOTNEX_MAP_DEBUG, ("rootnex_unmap_regspec: "
		    "zero regspec_size\n"));
		return (DDI_ME_INVAL);
	}

	base = addr - pgoffset;
	npages = mmu_btopr(rp->regspec_size + pgoffset);
	hat_unload(kas.a_hat, base, ptob(npages), HAT_UNLOAD_UNLOCK);
	vmem_free(rootnex_regspec_arena, base, ptob(npages));

	/*
	 * Destroy the pointer - the mapping has logically gone
	 */
	*vaddrp = (caddr_t)0;

	return (0);
}

static int
rootnex_map_handle(ddi_map_req_t *mp)
{
	ddi_acc_hdl_t *hp;
	uint_t hat_flags;
	register struct regspec *rp;

	/*
	 * Set up the hat_flags for the mapping.
	 */
	hp = mp->map_handlep;

	switch (hp->ah_acc.devacc_attr_endian_flags) {
	case DDI_NEVERSWAP_ACC:
		hat_flags = HAT_NEVERSWAP | HAT_STRICTORDER;
		break;
	case DDI_STRUCTURE_BE_ACC:
		hat_flags = HAT_STRUCTURE_BE;
		break;
	case DDI_STRUCTURE_LE_ACC:
		hat_flags = HAT_STRUCTURE_LE;
		break;
	default:
		return (DDI_REGS_ACC_CONFLICT);
	}

	switch (hp->ah_acc.devacc_attr_dataorder) {
	case DDI_STRICTORDER_ACC:
		break;
	case DDI_UNORDERED_OK_ACC:
		hat_flags |= HAT_UNORDERED_OK;
		break;
	case DDI_MERGING_OK_ACC:
		hat_flags |= HAT_MERGING_OK;
		break;
	case DDI_LOADCACHING_OK_ACC:
		hat_flags |= HAT_LOADCACHING_OK;
		break;
	case DDI_STORECACHING_OK_ACC:
		hat_flags |= HAT_STORECACHING_OK;
		break;
	default:
		return (DDI_FAILURE);
	}

	rp = mp->map_obj.rp;
	if (rp->regspec_size == 0)
		return (DDI_ME_INVAL);

	hp->ah_hat_flags = hat_flags;
	hp->ah_pfn = mmu_btop((ulong_t)rp->regspec_addr & (~MMU_PAGEOFFSET));
	hp->ah_pnum = mmu_btopr(rp->regspec_size +
	    (ulong_t)rp->regspec_addr & MMU_PAGEOFFSET);
	return (DDI_SUCCESS);
}

static int
rootnex_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
    off_t offset, off_t len, caddr_t *vaddrp)
{
	struct regspec *rp, tmp_reg;
	ddi_map_req_t mr = *mp;		/* Get private copy of request */
	int error;
	uint_t mapping_attr;
	ddi_acc_hdl_t *hp = NULL;

	mp = &mr;

	switch (mp->map_op)  {
	case DDI_MO_MAP_LOCKED:
	case DDI_MO_UNMAP:
	case DDI_MO_MAP_HANDLE:
		break;
	default:
		DPRINTF(ROOTNEX_MAP_DEBUG, ("rootnex_map: unimplemented map "
		    "op %d.", mp->map_op));
		return (DDI_ME_UNIMPLEMENTED);
	}

	if (mp->map_flags & DDI_MF_USER_MAPPING)  {
		DPRINTF(ROOTNEX_MAP_DEBUG, ("rootnex_map: unimplemented map "
		    "type: user."));
		return (DDI_ME_UNIMPLEMENTED);
	}

	/*
	 * First, if given an rnumber, convert it to a regspec...
	 * (Presumably, this is on behalf of a child of the root node?)
	 */

	if (mp->map_type == DDI_MT_RNUMBER)  {

		int rnumber = mp->map_obj.rnumber;

		rp = i_ddi_rnumber_to_regspec(rdip, rnumber);
		if (rp == (struct regspec *)0)  {
			DPRINTF(ROOTNEX_MAP_DEBUG, ("rootnex_map: Out of "
			    "range rnumber <%d>, device <%s>", rnumber,
			    ddi_get_name(rdip)));
			return (DDI_ME_RNUMBER_RANGE);
		}

		/*
		 * Convert the given ddi_map_req_t from rnumber to regspec...
		 */

		mp->map_type = DDI_MT_REGSPEC;
		mp->map_obj.rp = rp;
	}

	/*
	 * Adjust offset and length corresponding to called values...
	 * XXX: A non-zero length means override the one in the regspec
	 * XXX: regardless of what's in the parent's range?.
	 */

	tmp_reg = *(mp->map_obj.rp);		/* Preserve underlying data */
	rp = mp->map_obj.rp = &tmp_reg;		/* Use tmp_reg in request */

	rp->regspec_addr += (uint_t)offset;
	if (len != 0)
		rp->regspec_size = (uint_t)len;

	/*
	 * Apply any parent ranges at this level, if applicable.
	 * (This is where nexus specific regspec translation takes place.
	 * Use of this function is implicit agreement that translation is
	 * provided via ddi_apply_range.)
	 */

	DPRINTF(ROOTNEX_MAP_DEBUG, ("rootnex_map: applying range of parent "
	    "<%s> to child <%s>...\n", ddi_get_name(dip), ddi_get_name(rdip)));

	if ((error = i_ddi_apply_range(dip, rdip, mp->map_obj.rp)) != 0)
		return (error);

	switch (mp->map_op)  {
	case DDI_MO_MAP_LOCKED:

		/*
		 * Set up the locked down kernel mapping to the regspec...
		 */

		/*
		 * If we were passed an access handle we need to determine
		 * the "endian-ness" of the mapping and fill in the handle.
		 */
		if (mp->map_handlep) {
			hp = mp->map_handlep;
			switch (hp->ah_acc.devacc_attr_endian_flags) {
			case DDI_NEVERSWAP_ACC:
				mapping_attr = HAT_NEVERSWAP | HAT_STRICTORDER;
				break;
			case DDI_STRUCTURE_BE_ACC:
				mapping_attr = HAT_STRUCTURE_BE;
				break;
			case DDI_STRUCTURE_LE_ACC:
				mapping_attr = HAT_STRUCTURE_LE;
				break;
			default:
				return (DDI_REGS_ACC_CONFLICT);
			}

			switch (hp->ah_acc.devacc_attr_dataorder) {
			case DDI_STRICTORDER_ACC:
				break;
			case DDI_UNORDERED_OK_ACC:
				mapping_attr |= HAT_UNORDERED_OK;
				break;
			case DDI_MERGING_OK_ACC:
				mapping_attr |= HAT_MERGING_OK;
				break;
			case DDI_LOADCACHING_OK_ACC:
				mapping_attr |= HAT_LOADCACHING_OK;
				break;
			case DDI_STORECACHING_OK_ACC:
				mapping_attr |= HAT_STORECACHING_OK;
				break;
			default:
				return (DDI_REGS_ACC_CONFLICT);
			}
		} else {
			mapping_attr = HAT_NEVERSWAP | HAT_STRICTORDER;
		}

		/*
		 * Set up the mapping.
		 */
		error = rootnex_map_regspec(mp, vaddrp, mapping_attr);

		/*
		 * Fill in the access handle if needed.
		 */
		if (hp) {
			hp->ah_addr = *vaddrp;
			hp->ah_hat_flags = mapping_attr;
			if (error == 0)
				impl_acc_hdl_init(hp);
		}
		return (error);

	case DDI_MO_UNMAP:

		/*
		 * Release mapping...
		 */

		return (rootnex_unmap_regspec(mp, vaddrp));

	case DDI_MO_MAP_HANDLE:
		return (rootnex_map_handle(mp));

	}

	return (DDI_ME_UNIMPLEMENTED);
}

static int
rootnex_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	int	ret = DDI_SUCCESS;

	DPRINTF(ROOTNEX_INTR_DEBUG, ("rootnex_intr_ops: rdip=%s%d "
	    "intr_op 0x%x hdlp 0x%p\n", ddi_driver_name(rdip),
	    ddi_get_instance(rdip), intr_op, (void *)hdlp));

	switch (intr_op) {
	case DDI_INTROP_GETCAP:
		*(int *)result = DDI_INTR_FLAG_LEVEL;
		break;
	case DDI_INTROP_SETCAP:
		ret = DDI_ENOTSUP;
		break;
	case DDI_INTROP_ALLOC:
		*(int *)result = hdlp->ih_scratch1;
		break;
	case DDI_INTROP_FREE:
		break;
	case DDI_INTROP_GETPRI:
		*(int *)result = rootnex_get_intr_pri(dip, rdip, hdlp);
		break;
	case DDI_INTROP_SETPRI:
		break;
	case DDI_INTROP_ADDISR:
		ret = rootnex_add_intr_impl(dip, rdip, hdlp);
		break;
	case DDI_INTROP_REMISR:
		ret = rootnex_remove_intr_impl(dip, rdip, hdlp);
		break;
	case DDI_INTROP_ENABLE:
	case DDI_INTROP_DISABLE:
		break;
	case DDI_INTROP_NINTRS:
	case DDI_INTROP_NAVAIL:
		*(int *)result = i_ddi_get_intx_nintrs(rdip);
		break;
	case DDI_INTROP_SUPPORTED_TYPES:
		/* Root nexus driver supports only fixed interrupts */
		*(int *)result = i_ddi_get_intx_nintrs(rdip) ?
		    DDI_INTR_TYPE_FIXED : 0;
		break;
	default:
		ret = DDI_ENOTSUP;
		break;
	}

	return (ret);
}


/*
 * Shorthand defines
 */

#define	DMAOBJ_PP_PP	dmao_obj.pp_obj.pp_pp
#define	DMAOBJ_PP_OFF	dmao_ogj.pp_obj.pp_offset
#define	ALO		dma_lim->dlim_addr_lo
#define	AHI		dma_lim->dlim_addr_hi
#define	OBJSIZE		dmareq->dmar_object.dmao_size
#define	ORIGVADDR	dmareq->dmar_object.dmao_obj.virt_obj.v_addr
#define	RED		((mp->dmai_rflags & DDI_DMA_REDZONE)? 1 : 0)
#define	DIRECTION	(mp->dmai_rflags & DDI_DMA_RDWR)

/*
 * rootnex_map_fault:
 *
 *	fault in mappings for requestors
 */

/*ARGSUSED*/
static int
rootnex_map_fault(dev_info_t *dip, dev_info_t *rdip,
    struct hat *hat, struct seg *seg, caddr_t addr,
    struct devpage *dp, pfn_t pfn, uint_t prot, uint_t lock)
{
	extern struct seg_ops segdev_ops;

	DPRINTF(ROOTNEX_MAP_DEBUG, ("rootnex_map_fault: address <%p> "
	    "pfn <%lx>", (void *)addr, pfn));
	DPRINTF(ROOTNEX_MAP_DEBUG, (" Seg <%s>\n",
	    seg->s_ops == &segdev_ops ? "segdev" :
	    seg == &kvseg ? "segkmem" : "NONE!"));

	/*
	 * This is all terribly broken, but it is a start
	 *
	 * XXX	Note that this test means that segdev_ops
	 *	must be exported from seg_dev.c.
	 * XXX	What about devices with their own segment drivers?
	 */
	if (seg->s_ops == &segdev_ops) {
		register struct segdev_data *sdp =
		    (struct segdev_data *)seg->s_data;

		if (hat == NULL) {
			/*
			 * This is one plausible interpretation of
			 * a null hat i.e. use the first hat on the
			 * address space hat list which by convention is
			 * the hat of the system MMU.  At alternative
			 * would be to panic .. this might well be better ..
			 */
			ASSERT(AS_READ_HELD(seg->s_as));
			hat = seg->s_as->a_hat;
			cmn_err(CE_NOTE, "rootnex_map_fault: nil hat");
		}
		hat_devload(hat, addr, MMU_PAGESIZE, pfn, prot | sdp->hat_attr,
		    (lock ? HAT_LOAD_LOCK : HAT_LOAD));
	} else if (seg == &kvseg && dp == (struct devpage *)0) {
		hat_devload(kas.a_hat, addr, MMU_PAGESIZE, pfn, prot,
		    HAT_LOAD_LOCK);
	} else
		return (DDI_FAILURE);
	return (DDI_SUCCESS);
}

/*
 * Name a child of rootnex
 *
 * This may be called multiple times, independent of initchild calls.
 */
int
rootnex_name_child(dev_info_t *child, char *name, int namelen)
{
	return (rootnex_name_child_impl(child, name, namelen));
}


static int
rootnex_ctl_initchild(dev_info_t *dip)
{
	return (rootnex_ctl_initchild_impl(dip));
}


int
rootnex_ctl_uninitchild(dev_info_t *dip)
{
	extern void impl_free_ddi_ppd(dev_info_t *);

	rootnex_ctl_uninitchild_impl(dip);

	/*
	 * strip properties and convert node to prototype form
	 */
	impl_free_ddi_ppd(dip);
	ddi_set_name_addr(dip, NULL);
	impl_rem_dev_props(dip);
	return (DDI_SUCCESS);
}


static int
rootnex_ctl_reportdev(dev_info_t *dev)
{
	return (rootnex_ctl_reportdev_impl(dev));
}


static int
rootnex_ctlops_peekpoke(ddi_ctl_enum_t cmd, peekpoke_ctlops_t *in_args,
    void *result)
{
	int err = DDI_SUCCESS;
	on_trap_data_t otd;

	/* No safe access except for peek/poke is supported. */
	if (in_args->handle != NULL)
		return (DDI_FAILURE);

	/* Set up protected environment. */
	if (!on_trap(&otd, OT_DATA_ACCESS)) {
		uintptr_t tramp = otd.ot_trampoline;

		if (cmd == DDI_CTLOPS_POKE) {
			otd.ot_trampoline = (uintptr_t)&poke_fault;
			err = do_poke(in_args->size, (void *)in_args->dev_addr,
			    (void *)in_args->host_addr);
		} else {
			otd.ot_trampoline = (uintptr_t)&peek_fault;
			err = do_peek(in_args->size, (void *)in_args->dev_addr,
			    (void *)in_args->host_addr);
			result = (void *)in_args->host_addr;
		}
		otd.ot_trampoline = tramp;
	} else
		err = DDI_FAILURE;

	/* Take down protected environment. */
	no_trap();

	return (err);
}

/*ARGSUSED*/
static int
rootnex_ctlops(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t ctlop, void *arg, void *result)
{
	register int n, *ptr;
	register struct ddi_parent_private_data *pdp;

	static boolean_t reserved_msg_printed = B_FALSE;

	switch (ctlop) {
	case DDI_CTLOPS_DMAPMAPC:
		return (DDI_FAILURE);

	case DDI_CTLOPS_BTOP:
		/*
		 * Convert byte count input to physical page units.
		 * (byte counts that are not a page-size multiple
		 * are rounded down)
		 */
		*(ulong_t *)result = btop(*(ulong_t *)arg);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_PTOB:
		/*
		 * Convert size in physical pages to bytes
		 */
		*(ulong_t *)result = ptob(*(ulong_t *)arg);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_BTOPR:
		/*
		 * Convert byte count input to physical page units
		 * (byte counts that are not a page-size multiple
		 * are rounded up)
		 */
		*(ulong_t *)result = btopr(*(ulong_t *)arg);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_INITCHILD:
		return (rootnex_ctl_initchild((dev_info_t *)arg));

	case DDI_CTLOPS_UNINITCHILD:
		return (rootnex_ctl_uninitchild((dev_info_t *)arg));

	case DDI_CTLOPS_REPORTDEV:
		return (rootnex_ctl_reportdev(rdip));

	case DDI_CTLOPS_IOMIN:
		/*
		 * Nothing to do here but reflect back..
		 */
		return (DDI_SUCCESS);

	case DDI_CTLOPS_REGSIZE:
	case DDI_CTLOPS_NREGS:
		break;

	case DDI_CTLOPS_SIDDEV:
		if (ndi_dev_is_prom_node(rdip))
			return (DDI_SUCCESS);
		if (ndi_dev_is_persistent_node(rdip))
			return (DDI_SUCCESS);
		return (DDI_FAILURE);

	case DDI_CTLOPS_POWER: {
		return ((*pm_platform_power)((power_req_t *)arg));
	}

	case DDI_CTLOPS_RESERVED0: /* Was DDI_CTLOPS_NINTRS, obsolete */
	case DDI_CTLOPS_RESERVED1: /* Was DDI_CTLOPS_POKE_INIT, obsolete */
	case DDI_CTLOPS_RESERVED2: /* Was DDI_CTLOPS_POKE_FLUSH, obsolete */
	case DDI_CTLOPS_RESERVED3: /* Was DDI_CTLOPS_POKE_FINI, obsolete */
	case DDI_CTLOPS_RESERVED4: /* Was DDI_CTLOPS_INTR_HILEVEL, obsolete */
	case DDI_CTLOPS_RESERVED5: /* Was DDI_CTLOPS_XLATE_INTRS, obsolete */
		if (!reserved_msg_printed) {
			reserved_msg_printed = B_TRUE;
			cmn_err(CE_WARN, "Failing ddi_ctlops call(s) for "
			    "1 or more reserved/obsolete operations.");
		}
		return (DDI_FAILURE);

	case DDI_CTLOPS_POKE:
	case DDI_CTLOPS_PEEK:
		return (rootnex_ctlops_peekpoke(ctlop, (peekpoke_ctlops_t *)arg,
		    result));

	default:
		return (DDI_FAILURE);
	}

	/*
	 * The rest are for "hardware" properties
	 */
	if ((pdp = ddi_get_parent_data(rdip)) == NULL)
		return (DDI_FAILURE);

	if (ctlop == DDI_CTLOPS_NREGS) {
		ptr = (int *)result;
		*ptr = pdp->par_nreg;
	} else {	/* ctlop == DDI_CTLOPS_REGSIZE */
		off_t *size = (off_t *)result;

		ptr = (int *)arg;
		n = *ptr;
		if (n >= pdp->par_nreg) {
			return (DDI_FAILURE);
		}
		*size = (off_t)pdp->par_reg[n].regspec_size;
	}
	return (DDI_SUCCESS);
}

/* ARGSUSED */
int
rootnex_busop_fminit(dev_info_t *dip, dev_info_t *tdip, int cap,
    ddi_iblock_cookie_t *ibc)
{
	*ibc = rootnex_err_ibc;
	return (ddi_system_fmcap | DDI_FM_ACCCHK_CAPABLE |
	    DDI_FM_DMACHK_CAPABLE);
}

static void
rootnex_fm_init(dev_info_t *dip)
{
	int fmcap;

	/* Minimum fm capability level for sun4u platforms */
	ddi_system_fmcap = DDI_FM_EREPORT_CAPABLE | DDI_FM_ERRCB_CAPABLE;

	fmcap = ddi_system_fmcap;

	/*
	 * Initialize ECC error handling
	 */
	rootnex_err_ibc = (ddi_iblock_cookie_t)PIL_15;
	ddi_fm_init(dip, &fmcap, &rootnex_err_ibc);
}

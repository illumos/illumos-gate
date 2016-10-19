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
 *
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/modctl.h>
#include <sys/ddi_impldefs.h>
#include <vm/seg_kmem.h>
#include <sys/vmsystm.h>
#include <sys/sysmacros.h>
#include <sys/ddidevmap.h>
#include <sys/avl.h>
#ifdef __xpv
#include <sys/hypervisor.h>
#endif

#include <sys/xsvc.h>

/* total max memory which can be alloced with ioctl interface */
uint64_t xsvc_max_memory = 10 * 1024 * 1024;

extern void i86_va_map(caddr_t vaddr, struct as *asp, caddr_t kaddr);


static int xsvc_open(dev_t *devp, int flag, int otyp, cred_t *cred);
static int xsvc_close(dev_t devp, int flag, int otyp, cred_t *cred);
static int xsvc_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred,
    int *rval);
static int xsvc_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off, size_t len,
    size_t *maplen, uint_t model);
static int xsvc_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);
static int xsvc_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);
static int xsvc_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **result);

static 	struct cb_ops xsvc_cb_ops = {
	xsvc_open,		/* cb_open */
	xsvc_close,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	xsvc_ioctl,		/* cb_ioctl */
	xsvc_devmap,		/* cb_devmap */
	NULL,			/* cb_mmap */
	NULL,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_stream */
	D_NEW | D_MP | D_64BIT | D_DEVMAP,	/* cb_flag */
	CB_REV
};

static struct dev_ops xsvc_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	xsvc_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	xsvc_attach,		/* devo_attach */
	xsvc_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&xsvc_cb_ops,		/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv xsvc_modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"xsvc driver",		/* Name of the module. */
	&xsvc_dev_ops,		/* driver ops */
};

static struct modlinkage xsvc_modlinkage = {
	MODREV_1,
	(void *) &xsvc_modldrv,
	NULL
};


static int xsvc_ioctl_alloc_memory(xsvc_state_t *state, void *arg, int mode);
static int xsvc_ioctl_flush_memory(xsvc_state_t *state, void *arg, int mode);
static int xsvc_ioctl_free_memory(xsvc_state_t *state, void *arg, int mode);
static int xsvc_mem_alloc(xsvc_state_t *state, uint64_t key,
    xsvc_mem_t **mp);
static void xsvc_mem_free(xsvc_state_t *state, xsvc_mem_t *mp);
static xsvc_mem_t *xsvc_mem_lookup(xsvc_state_t *state,
    uint64_t key);
static int xsvc_mnode_key_compare(const void *q, const void *e);
static int xsvc_umem_cookie_alloc(caddr_t kva, size_t size, int flags,
    ddi_umem_cookie_t *cookiep);
static void xsvc_umem_cookie_free(ddi_umem_cookie_t *cookiep);


void *xsvc_statep;

static ddi_device_acc_attr_t xsvc_device_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

static int xsvc_devmap_map(devmap_cookie_t dhp, dev_t dev, uint_t flags,
    offset_t off, size_t len, void **pvtp);
static int xsvc_devmap_dup(devmap_cookie_t dhp, void *pvtp,
    devmap_cookie_t new_dhp, void **new_pvtp);
static void xsvc_devmap_unmap(devmap_cookie_t dhp, void *pvtp, offset_t off,
    size_t len, devmap_cookie_t new_dhp1, void **new_pvtp1,
    devmap_cookie_t new_dhp2, void **new_pvtp2);


static struct devmap_callback_ctl xsvc_callbk = {
	DEVMAP_OPS_REV,
	xsvc_devmap_map,
	NULL,
	xsvc_devmap_dup,
	xsvc_devmap_unmap
};


/*
 * _init()
 *
 */
int
_init(void)
{
	int err;

	err = ddi_soft_state_init(&xsvc_statep, sizeof (xsvc_state_t), 1);
	if (err != 0) {
		return (err);
	}

	err = mod_install(&xsvc_modlinkage);
	if (err != 0) {
		ddi_soft_state_fini(&xsvc_statep);
		return (err);
	}

	return (0);
}

/*
 * _info()
 *
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&xsvc_modlinkage, modinfop));
}

/*
 * _fini()
 *
 */
int
_fini(void)
{
	int err;

	err = mod_remove(&xsvc_modlinkage);
	if (err != 0) {
		return (err);
	}

	ddi_soft_state_fini(&xsvc_statep);

	return (0);
}

/*
 * xsvc_attach()
 *
 */
static int
xsvc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	xsvc_state_t *state;
	int maxallocmem;
	int instance;
	int err;


	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);
	err = ddi_soft_state_zalloc(xsvc_statep, instance);
	if (err != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	state = ddi_get_soft_state(xsvc_statep, instance);
	if (state == NULL) {
		goto attachfail_get_soft_state;
	}

	state->xs_dip = dip;
	state->xs_instance = instance;

	/* Initialize allocation count */
	mutex_init(&state->xs_mutex, NULL, MUTEX_DRIVER, NULL);
	state->xs_currently_alloced = 0;

	mutex_init(&state->xs_cookie_mutex, NULL, MUTEX_DRIVER, NULL);

	/* create the minor node (for the ioctl) */
	err = ddi_create_minor_node(dip, "xsvc", S_IFCHR, instance, DDI_PSEUDO,
	    0);
	if (err != DDI_SUCCESS) {
		goto attachfail_minor_node;
	}

	/*
	 * the maxallocmem property will override the default (xsvc_max_memory).
	 * This is the maximum total memory the ioctl will allow to be alloced.
	 */
	maxallocmem = ddi_prop_get_int(DDI_DEV_T_ANY, state->xs_dip,
	    DDI_PROP_DONTPASS, "maxallocmem", -1);
	if (maxallocmem >= 0) {
		xsvc_max_memory = maxallocmem * 1024;
	}

	/* Initialize list of memory allocs */
	mutex_init(&state->xs_mlist.ml_mutex, NULL, MUTEX_DRIVER, NULL);
	avl_create(&state->xs_mlist.ml_avl, xsvc_mnode_key_compare,
	    sizeof (xsvc_mnode_t), offsetof(xsvc_mnode_t, mn_link));

	/* Report that driver was loaded */
	ddi_report_dev(dip);

	return (DDI_SUCCESS);

attachfail_minor_node:
	mutex_destroy(&state->xs_cookie_mutex);
	mutex_destroy(&state->xs_mutex);
attachfail_get_soft_state:
	(void) ddi_soft_state_free(xsvc_statep, instance);

	return (err);
}

/*
 * xsvc_detach()
 *
 */
static int
xsvc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	xsvc_state_t *state;
	xsvc_mnode_t *mnode;
	xsvc_mem_t *mp;
	int instance;


	instance = ddi_get_instance(dip);
	state = ddi_get_soft_state(xsvc_statep, instance);
	if (state == NULL) {
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	ddi_remove_minor_node(dip, NULL);

	/* Free any memory on list */
	while ((mnode = avl_first(&state->xs_mlist.ml_avl)) != NULL) {
		mp = mnode->mn_home;
		xsvc_mem_free(state, mp);
	}

	/* remove list */
	avl_destroy(&state->xs_mlist.ml_avl);
	mutex_destroy(&state->xs_mlist.ml_mutex);

	mutex_destroy(&state->xs_cookie_mutex);
	mutex_destroy(&state->xs_mutex);
	(void) ddi_soft_state_free(xsvc_statep, state->xs_instance);
	return (DDI_SUCCESS);
}

/*
 * xsvc_getinfo()
 *
 */
/*ARGSUSED*/
static int
xsvc_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	xsvc_state_t *state;
	int instance;
	dev_t dev;
	int err;


	dev = (dev_t)arg;
	instance = getminor(dev);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		state = ddi_get_soft_state(xsvc_statep, instance);
		if (state == NULL) {
			return (DDI_FAILURE);
		}
		*result = (void *)state->xs_dip;
		err = DDI_SUCCESS;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		err = DDI_SUCCESS;
		break;

	default:
		err = DDI_FAILURE;
		break;
	}

	return (err);
}


/*
 * xsvc_open()
 *
 */
/*ARGSUSED*/
static int
xsvc_open(dev_t *devp, int flag, int otyp, cred_t *cred)
{
	xsvc_state_t *state;
	int instance;

	instance = getminor(*devp);
	state = ddi_get_soft_state(xsvc_statep, instance);
	if (state == NULL) {
		return (ENXIO);
	}

	return (0);
}

/*
 * xsvc_close()
 *
 */
/*ARGSUSED*/
static int
xsvc_close(dev_t devp, int flag, int otyp, cred_t *cred)
{
	return (0);
}

/*
 * xsvc_ioctl()
 *
 */
/*ARGSUSED*/
static int
xsvc_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred, int *rval)
{
	xsvc_state_t *state;
	int instance;
	int err;


	err = drv_priv(cred);
	if (err != 0) {
		return (EPERM);
	}
	instance = getminor(dev);
	if (instance == -1) {
		return (EBADF);
	}
	state = ddi_get_soft_state(xsvc_statep, instance);
	if (state == NULL) {
		return (EBADF);
	}

	switch (cmd) {
	case XSVC_ALLOC_MEM:
		err = xsvc_ioctl_alloc_memory(state, (void *)arg, mode);
		break;

	case XSVC_FREE_MEM:
		err = xsvc_ioctl_free_memory(state, (void *)arg, mode);
		break;

	case XSVC_FLUSH_MEM:
		err = xsvc_ioctl_flush_memory(state, (void *)arg, mode);
		break;

	default:
		err = ENXIO;
	}

	return (err);
}

/*
 * xsvc_ioctl_alloc_memory()
 *
 */
static int
xsvc_ioctl_alloc_memory(xsvc_state_t *state, void *arg, int mode)
{
	xsvc_mem_req_32 params32;
	xsvc_mloc_32 *usgl32;
	xsvc_mem_req params;
	xsvc_mloc_32 sgl32;
	xsvc_mloc *usgl;
	xsvc_mem_t *mp;
	xsvc_mloc sgl;
	uint64_t key;
	size_t size;
	int err;
	int i;


	/* Copy in the params, then get the size and key */
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		err = ddi_copyin(arg, &params32, sizeof (xsvc_mem_req_32),
		    mode);
		if (err != 0) {
			return (EFAULT);
		}

		key = (uint64_t)params32.xsvc_mem_reqid;
		size = P2ROUNDUP((size_t)params32.xsvc_mem_size, PAGESIZE);
	} else {
		err = ddi_copyin(arg, &params, sizeof (xsvc_mem_req), mode);
		if (err != 0) {
			return (EFAULT);
		}
		key = (uint64_t)params.xsvc_mem_reqid;
		size = P2ROUNDUP(params.xsvc_mem_size, PAGESIZE);
	}

	/*
	 * make sure this doesn't put us over the maximum allowed to be
	 * allocated
	 */
	mutex_enter(&state->xs_mutex);
	if ((state->xs_currently_alloced + size) > xsvc_max_memory) {
		mutex_exit(&state->xs_mutex);
		return (EAGAIN);
	}
	state->xs_currently_alloced += size;
	mutex_exit(&state->xs_mutex);

	/* get state to track this memory */
	err = xsvc_mem_alloc(state, key, &mp);
	if (err != 0) {
		return (err);
	}
	mp->xm_size = size;

	/* allocate and bind the memory */
	mp->xm_dma_attr.dma_attr_version = DMA_ATTR_V0;
	mp->xm_dma_attr.dma_attr_count_max = (uint64_t)0xFFFFFFFF;
	mp->xm_dma_attr.dma_attr_burstsizes = 1;
	mp->xm_dma_attr.dma_attr_minxfer = 1;
	mp->xm_dma_attr.dma_attr_maxxfer = (uint64_t)0xFFFFFFFF;
	mp->xm_dma_attr.dma_attr_seg = (uint64_t)0xFFFFFFFF;
	mp->xm_dma_attr.dma_attr_granular = 1;
	mp->xm_dma_attr.dma_attr_flags = 0;

	/* Finish converting params */
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		mp->xm_dma_attr.dma_attr_addr_lo = params32.xsvc_mem_addr_lo;
		mp->xm_dma_attr.dma_attr_addr_hi = params32.xsvc_mem_addr_hi;
		mp->xm_dma_attr.dma_attr_sgllen = params32.xsvc_mem_sgllen;
		usgl32 = (xsvc_mloc_32 *)(uintptr_t)params32.xsvc_sg_list;
		mp->xm_dma_attr.dma_attr_align = P2ROUNDUP(
		    params32.xsvc_mem_align, PAGESIZE);
	} else {
		mp->xm_dma_attr.dma_attr_addr_lo = params.xsvc_mem_addr_lo;
		mp->xm_dma_attr.dma_attr_addr_hi = params.xsvc_mem_addr_hi;
		mp->xm_dma_attr.dma_attr_sgllen = params.xsvc_mem_sgllen;
		usgl = (xsvc_mloc *)(uintptr_t)params.xsvc_sg_list;
		mp->xm_dma_attr.dma_attr_align = P2ROUNDUP(
		    params.xsvc_mem_align, PAGESIZE);
	}

	mp->xm_device_attr = xsvc_device_attr;

	err = ddi_dma_alloc_handle(state->xs_dip, &mp->xm_dma_attr,
	    DDI_DMA_SLEEP, NULL, &mp->xm_dma_handle);
	if (err != DDI_SUCCESS) {
		err = EINVAL;
		goto allocfail_alloc_handle;
	}

	/* don't sleep here so we don't get stuck in contig alloc */
	err = ddi_dma_mem_alloc(mp->xm_dma_handle, mp->xm_size,
	    &mp->xm_device_attr, DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, NULL,
	    &mp->xm_addr, &mp->xm_real_length, &mp->xm_mem_handle);
	if (err != DDI_SUCCESS) {
		err = EINVAL;
		goto allocfail_alloc_mem;
	}

	err = ddi_dma_addr_bind_handle(mp->xm_dma_handle, NULL, mp->xm_addr,
	    mp->xm_size, DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP,
	    NULL, &mp->xm_cookie, &mp->xm_cookie_count);
	if (err != DDI_DMA_MAPPED) {
		err = EFAULT;
		goto allocfail_bind;
	}

	/* return sgl */
	for (i = 0; i < mp->xm_cookie_count; i++) {
		if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
			sgl32.mloc_addr = mp->xm_cookie.dmac_laddress;
			sgl32.mloc_size = mp->xm_cookie.dmac_size;
			err = ddi_copyout(&sgl32, &usgl32[i],
			    sizeof (xsvc_mloc_32), mode);
			if (err != 0) {
				err = EFAULT;
				goto allocfail_copyout;
			}
		} else {
			sgl.mloc_addr = mp->xm_cookie.dmac_laddress;
			sgl.mloc_size = mp->xm_cookie.dmac_size;
			err = ddi_copyout(&sgl, &usgl[i], sizeof (xsvc_mloc),
			    mode);
			if (err != 0) {
				err = EFAULT;
				goto allocfail_copyout;
			}
		}
		ddi_dma_nextcookie(mp->xm_dma_handle, &mp->xm_cookie);
	}

	/* set the last sgl entry to 0 to indicate cookie count */
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		sgl32.mloc_addr = 0;
		sgl32.mloc_size = 0;
		err = ddi_copyout(&sgl32, &usgl32[i], sizeof (xsvc_mloc_32),
		    mode);
		if (err != 0) {
			err = EFAULT;
			goto allocfail_copyout;
		}
	} else {
		sgl.mloc_addr = 0;
		sgl.mloc_size = 0;
		err = ddi_copyout(&sgl, &usgl[i], sizeof (xsvc_mloc), mode);
		if (err != 0) {
			err = EFAULT;
			goto allocfail_copyout;
		}
	}

	return (0);

allocfail_copyout:
	(void) ddi_dma_unbind_handle(mp->xm_dma_handle);
allocfail_bind:
	ddi_dma_mem_free(&mp->xm_mem_handle);
allocfail_alloc_mem:
	ddi_dma_free_handle(&mp->xm_dma_handle);
allocfail_alloc_handle:
	mp->xm_dma_handle = NULL;
	xsvc_mem_free(state, mp);

	mutex_enter(&state->xs_mutex);
	state->xs_currently_alloced = state->xs_currently_alloced - size;
	mutex_exit(&state->xs_mutex);

	return (err);
}

/*
 * xsvc_ioctl_flush_memory()
 *
 */
static int
xsvc_ioctl_flush_memory(xsvc_state_t *state, void *arg, int mode)
{
	xsvc_mem_req_32 params32;
	xsvc_mem_req params;
	xsvc_mem_t *mp;
	uint64_t key;
	int err;


	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		err = ddi_copyin(arg, &params32, sizeof (xsvc_mem_req_32),
		    mode);
		if (err != 0) {
			return (EFAULT);
		}
		key = (uint64_t)params32.xsvc_mem_reqid;
	} else {
		err = ddi_copyin(arg, &params, sizeof (xsvc_mem_req), mode);
		if (err != 0) {
			return (EFAULT);
		}
		key = (uint64_t)params.xsvc_mem_reqid;
	}

	/* find the memory */
	mp = xsvc_mem_lookup(state, key);
	if (mp == NULL) {
		return (EINVAL);
	}

	(void) ddi_dma_sync(mp->xm_dma_handle, 0, 0, DDI_DMA_SYNC_FORCPU);

	return (0);
}


/*
 * xsvc_ioctl_free_memory()
 *
 */
static int
xsvc_ioctl_free_memory(xsvc_state_t *state, void *arg, int mode)
{
	xsvc_mem_req_32 params32;
	xsvc_mem_req params;
	xsvc_mem_t *mp;
	uint64_t key;
	int err;


	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		err = ddi_copyin(arg, &params32, sizeof (xsvc_mem_req_32),
		    mode);
		if (err != 0) {
			return (EFAULT);
		}
		key = (uint64_t)params32.xsvc_mem_reqid;
	} else {
		err = ddi_copyin(arg, &params, sizeof (xsvc_mem_req), mode);
		if (err != 0) {
			return (EFAULT);
		}
		key = (uint64_t)params.xsvc_mem_reqid;
	}

	/* find the memory */
	mp = xsvc_mem_lookup(state, key);
	if (mp == NULL) {
		return (EINVAL);
	}

	xsvc_mem_free(state, mp);

	return (0);
}

/*
 * xsvc_mem_alloc()
 *
 */
static int
xsvc_mem_alloc(xsvc_state_t *state, uint64_t key, xsvc_mem_t **mp)
{
	xsvc_mem_t *mem;

	mem = xsvc_mem_lookup(state, key);
	if (mem != NULL) {
		xsvc_mem_free(state, mem);
	}

	*mp = kmem_alloc(sizeof (xsvc_mem_t), KM_SLEEP);
	(*mp)->xm_mnode.mn_home = *mp;
	(*mp)->xm_mnode.mn_key = key;

	mutex_enter(&state->xs_mlist.ml_mutex);
	avl_add(&state->xs_mlist.ml_avl, &(*mp)->xm_mnode);
	mutex_exit(&state->xs_mlist.ml_mutex);

	return (0);
}

/*
 * xsvc_mem_free()
 *
 */
static void
xsvc_mem_free(xsvc_state_t *state, xsvc_mem_t *mp)
{
	if (mp->xm_dma_handle != NULL) {
		(void) ddi_dma_unbind_handle(mp->xm_dma_handle);
		ddi_dma_mem_free(&mp->xm_mem_handle);
		ddi_dma_free_handle(&mp->xm_dma_handle);

		mutex_enter(&state->xs_mutex);
		state->xs_currently_alloced = state->xs_currently_alloced -
		    mp->xm_size;
		mutex_exit(&state->xs_mutex);
	}

	mutex_enter(&state->xs_mlist.ml_mutex);
	avl_remove(&state->xs_mlist.ml_avl, &mp->xm_mnode);
	mutex_exit(&state->xs_mlist.ml_mutex);

	kmem_free(mp, sizeof (*mp));
}

/*
 * xsvc_mem_lookup()
 *
 */
static xsvc_mem_t *
xsvc_mem_lookup(xsvc_state_t *state, uint64_t key)
{
	xsvc_mnode_t mnode;
	xsvc_mnode_t *mnp;
	avl_index_t where;
	xsvc_mem_t *mp;

	mnode.mn_key = key;
	mutex_enter(&state->xs_mlist.ml_mutex);
	mnp = avl_find(&state->xs_mlist.ml_avl, &mnode, &where);
	mutex_exit(&state->xs_mlist.ml_mutex);

	if (mnp != NULL) {
		mp = mnp->mn_home;
	} else {
		mp = NULL;
	}

	return (mp);
}

/*
 * xsvc_mnode_key_compare()
 *
 */
static int
xsvc_mnode_key_compare(const void *q, const void *e)
{
	xsvc_mnode_t *n1;
	xsvc_mnode_t *n2;

	n1 = (xsvc_mnode_t *)q;
	n2 = (xsvc_mnode_t *)e;

	if (n1->mn_key < n2->mn_key) {
		return (-1);
	} else if (n1->mn_key > n2->mn_key) {
		return (1);
	} else {
		return (0);
	}
}

/*
 * xsvc_devmap()
 *
 */
/*ARGSUSED*/
static int
xsvc_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off, size_t len,
    size_t *maplen, uint_t model)
{
	ddi_umem_cookie_t cookie;
	xsvc_state_t *state;
	offset_t off_align;
	size_t npages;
	caddr_t kvai;
	size_t psize;
	int instance;
	caddr_t kva;
	pfn_t pfn;
	int err;
	int i;


	instance = getminor(dev);
	state = ddi_get_soft_state(xsvc_statep, instance);
	if (state == NULL) {
		return (ENXIO);
	}

	/*
	 * On 64-bit kernels, if we have a 32-bit application doing a mmap(),
	 * smmap32 will sign extend the offset. We need to undo that since
	 * we are passed a physical address in off, not a offset.
	 */
#if defined(__amd64)
	if (((model & DDI_MODEL_MASK) == DDI_MODEL_ILP32) &&
	    ((off & ~0xFFFFFFFFll) == ~0xFFFFFFFFll)) {
		off = off & 0xFFFFFFFF;
	}
#endif

#ifdef __xpv
	/*
	 * we won't allow guest OSes to devmap mfn/pfns. Maybe we'll relax
	 * this some later when there is a good reason.
	 */
	if (!DOMAIN_IS_INITDOMAIN(xen_info)) {
		return (-1);
	}

	/* we will always treat this as a foreign MFN */
	pfn = xen_assign_pfn(btop(off));
#else
	pfn = btop(off);
#endif
	/* always work with whole pages */

	off_align = P2ALIGN(off, PAGESIZE);
	psize = P2ROUNDUP(off + len, PAGESIZE) - off_align;

	/*
	 * if this is memory we're trying to map into user space, we first
	 * need to map the PFNs into KVA, then build up a umem cookie, and
	 * finally do a umem_setup to map it in.
	 */
	if (pf_is_memory(pfn)) {
		npages = btop(psize);

		kva = vmem_alloc(heap_arena, psize, VM_SLEEP);
		if (kva == NULL) {
			return (-1);
		}

		kvai = kva;
		for (i = 0; i < npages; i++) {
			page_t *pp = page_numtopp_nolock(pfn);

			/*
			 * Preemptively check for panic conditions from
			 * hat_devload and error out instead.
			 */
			if (pp != NULL && (PP_ISFREE(pp) ||
			    (!PAGE_LOCKED(pp) && !PP_ISNORELOC(pp)))) {
				err = DDI_FAILURE;
				npages = i;
				goto devmapfail_cookie_alloc;
			}

			hat_devload(kas.a_hat, kvai, PAGESIZE, pfn,
			    PROT_READ | PROT_WRITE, HAT_LOAD_LOCK);
			pfn++;
			kvai = (caddr_t)((uintptr_t)kvai + PAGESIZE);
		}

		err = xsvc_umem_cookie_alloc(kva, psize, KM_SLEEP, &cookie);
		if (err != 0) {
			goto devmapfail_cookie_alloc;
		}

		if ((err = devmap_umem_setup(dhp, state->xs_dip, &xsvc_callbk,
		    cookie, 0, psize, PROT_ALL, 0, &xsvc_device_attr)) < 0) {
			goto devmapfail_umem_setup;
		}
		*maplen = psize;

	/*
	 * If this is not memory (or a foreign MFN in i86xpv), go through
	 * devmem_setup.
	 */
	} else {
		if ((err = devmap_devmem_setup(dhp, state->xs_dip, NULL, 0,
		    off_align, psize, PROT_ALL, 0, &xsvc_device_attr)) < 0) {
			return (err);
		}
		*maplen = psize;
	}

	return (0);

devmapfail_umem_setup:
	xsvc_umem_cookie_free(&cookie);

devmapfail_cookie_alloc:
	kvai = kva;
	for (i = 0; i < npages; i++) {
		hat_unload(kas.a_hat, kvai, PAGESIZE,
		    HAT_UNLOAD_UNLOCK);
		kvai = (caddr_t)((uintptr_t)kvai + PAGESIZE);
	}
	vmem_free(heap_arena, kva, psize);

	return (err);
}

/*
 * xsvc_umem_cookie_alloc()
 *
 *   allocate a umem cookie to be used in devmap_umem_setup using KVA already
 *   allocated.
 */
int
xsvc_umem_cookie_alloc(caddr_t kva, size_t size, int flags,
    ddi_umem_cookie_t *cookiep)
{
	struct ddi_umem_cookie *umem_cookiep;

	umem_cookiep = kmem_zalloc(sizeof (struct ddi_umem_cookie), flags);
	if (umem_cookiep == NULL) {
		*cookiep = NULL;
		return (-1);
	}

	umem_cookiep->cvaddr = kva;
	umem_cookiep->type = KMEM_NON_PAGEABLE;
	umem_cookiep->size = size;
	*cookiep = (ddi_umem_cookie_t *)umem_cookiep;

	return (0);
}

/*
 * xsvc_umem_cookie_free()
 *
 */
static void
xsvc_umem_cookie_free(ddi_umem_cookie_t *cookiep)
{
	kmem_free(*cookiep, sizeof (struct ddi_umem_cookie));
	*cookiep = NULL;
}


/*
 * xsvc_devmap_map()
 *
 */
/*ARGSUSED*/
static int
xsvc_devmap_map(devmap_cookie_t dhc, dev_t dev, uint_t flags, offset_t off,
    size_t len, void **pvtp)
{
	struct ddi_umem_cookie *cp;
	devmap_handle_t *dhp;
	xsvc_state_t *state;
	int instance;


	instance = getminor(dev);
	state = ddi_get_soft_state(xsvc_statep, instance);
	if (state == NULL) {
		return (ENXIO);
	}

	dhp = (devmap_handle_t *)dhc;
	/* This driver only supports MAP_SHARED, not MAP_PRIVATE */
	if (flags & MAP_PRIVATE) {
		cmn_err(CE_WARN, "!xsvc driver doesn't support MAP_PRIVATE");
		return (EINVAL);
	}

	cp = (struct ddi_umem_cookie *)dhp->dh_cookie;
	cp->cook_refcnt = 1;

	*pvtp = state;
	return (0);
}


/*
 * xsvc_devmap_dup()
 *
 *   keep a reference count for forks so we don't unmap if we have multiple
 *   mappings.
 */
/*ARGSUSED*/
static int
xsvc_devmap_dup(devmap_cookie_t dhc, void *pvtp, devmap_cookie_t new_dhp,
    void **new_pvtp)
{
	struct ddi_umem_cookie *cp;
	devmap_handle_t *dhp;
	xsvc_state_t *state;


	state = (xsvc_state_t *)pvtp;
	dhp = (devmap_handle_t *)dhc;

	mutex_enter(&state->xs_cookie_mutex);
	cp = (struct ddi_umem_cookie *)dhp->dh_cookie;
	if (cp == NULL) {
		mutex_exit(&state->xs_cookie_mutex);
		return (ENOMEM);
	}

	cp->cook_refcnt++;
	mutex_exit(&state->xs_cookie_mutex);

	*new_pvtp = state;
	return (0);
}


/*
 * xsvc_devmap_unmap()
 *
 *   This routine is only call if we were mapping in memory in xsvc_devmap().
 *   i.e. we only pass in xsvc_callbk to devmap_umem_setup if pf_is_memory()
 *   was true. It would have been nice if devmap_callback_ctl had an args param.
 *   We wouldn't have had to look into the devmap_handle and into the umem
 *   cookie.
 */
/*ARGSUSED*/
static void
xsvc_devmap_unmap(devmap_cookie_t dhc, void *pvtp, offset_t off, size_t len,
    devmap_cookie_t new_dhp1, void **new_pvtp1, devmap_cookie_t new_dhp2,
    void **new_pvtp2)
{
	struct ddi_umem_cookie *ncp;
	struct ddi_umem_cookie *cp;
	devmap_handle_t *ndhp;
	devmap_handle_t *dhp;
	xsvc_state_t *state;
	size_t npages;
	caddr_t kvai;
	caddr_t kva;
	size_t size;
	int i;


	state = (xsvc_state_t *)pvtp;
	mutex_enter(&state->xs_cookie_mutex);

	/* peek into the umem cookie to figure out what we need to free up */
	dhp = (devmap_handle_t *)dhc;
	cp = (struct ddi_umem_cookie *)dhp->dh_cookie;
	ASSERT(cp != NULL);

	if (new_dhp1 != NULL) {
		ndhp = (devmap_handle_t *)new_dhp1;
		ncp = (struct ddi_umem_cookie *)ndhp->dh_cookie;
		ncp->cook_refcnt++;
		*new_pvtp1 = state;
	}
	if (new_dhp2 != NULL) {
		ndhp = (devmap_handle_t *)new_dhp2;
		ncp = (struct ddi_umem_cookie *)ndhp->dh_cookie;
		ncp->cook_refcnt++;
		*new_pvtp2 = state;
	}

	cp->cook_refcnt--;
	if (cp->cook_refcnt == 0) {
		kva = cp->cvaddr;
		size = cp->size;

		/*
		 * free up the umem cookie, then unmap all the pages what we
		 * mapped in during devmap, then free up the kva space.
		 */
		npages = btop(size);
		xsvc_umem_cookie_free(&dhp->dh_cookie);
		kvai = kva;
		for (i = 0; i < npages; i++) {
			hat_unload(kas.a_hat, kvai, PAGESIZE,
			    HAT_UNLOAD_UNLOCK);
			kvai = (caddr_t)((uintptr_t)kvai + PAGESIZE);
		}
		vmem_free(heap_arena, kva, size);
	}

	mutex_exit(&state->xs_cookie_mutex);
}

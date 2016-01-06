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
#include <sys/sysmacros.h>
#include <sys/ddidevmap.h>
#include <sys/policy.h>

#include <sys/vmsystm.h>
#include <vm/hat_i86.h>
#include <vm/hat_pte.h>
#include <vm/seg_kmem.h>
#include <vm/seg_mf.h>

#include <xen/io/blkif_impl.h>
#include <xen/io/blk_common.h>
#include <xen/io/xpvtap.h>


static int xpvtap_open(dev_t *devp, int flag, int otyp, cred_t *cred);
static int xpvtap_close(dev_t devp, int flag, int otyp, cred_t *cred);
static int xpvtap_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *cred, int *rval);
static int xpvtap_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off,
    size_t len, size_t *maplen, uint_t model);
static int xpvtap_segmap(dev_t dev, off_t off, struct as *asp, caddr_t *addrp,
    off_t len, unsigned int prot, unsigned int maxprot, unsigned int flags,
    cred_t *cred_p);
static int xpvtap_chpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp);

static 	struct cb_ops xpvtap_cb_ops = {
	xpvtap_open,		/* cb_open */
	xpvtap_close,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	xpvtap_ioctl,		/* cb_ioctl */
	xpvtap_devmap,		/* cb_devmap */
	nodev,			/* cb_mmap */
	xpvtap_segmap,		/* cb_segmap */
	xpvtap_chpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_stream */
	D_NEW | D_MP | D_64BIT | D_DEVMAP,	/* cb_flag */
	CB_REV
};

static int xpvtap_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **result);
static int xpvtap_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);
static int xpvtap_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);

static struct dev_ops xpvtap_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	xpvtap_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	xpvtap_attach,		/* devo_attach */
	xpvtap_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&xpvtap_cb_ops,		/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL			/* power */
};


static struct modldrv xpvtap_modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"xpvtap driver",	/* Name of the module. */
	&xpvtap_dev_ops,	/* driver ops */
};

static struct modlinkage xpvtap_modlinkage = {
	MODREV_1,
	(void *) &xpvtap_modldrv,
	NULL
};


void *xpvtap_statep;


static xpvtap_state_t *xpvtap_drv_init(int instance);
static void xpvtap_drv_fini(xpvtap_state_t *state);
static uint_t xpvtap_intr(caddr_t arg);

typedef void (*xpvtap_rs_cleanup_t)(xpvtap_state_t *state, uint_t rs);
static void xpvtap_rs_init(uint_t min_val, uint_t max_val,
    xpvtap_rs_hdl_t *handle);
static void xpvtap_rs_fini(xpvtap_rs_hdl_t *handle);
static int xpvtap_rs_alloc(xpvtap_rs_hdl_t handle, uint_t *rs);
static void xpvtap_rs_free(xpvtap_rs_hdl_t handle, uint_t rs);
static void xpvtap_rs_flush(xpvtap_rs_hdl_t handle,
    xpvtap_rs_cleanup_t callback, void *arg);

static int xpvtap_segmf_register(xpvtap_state_t *state);
static void xpvtap_segmf_unregister(struct as *as, void *arg, uint_t event);

static int xpvtap_user_init(xpvtap_state_t *state);
static void xpvtap_user_fini(xpvtap_state_t *state);
static int xpvtap_user_ring_init(xpvtap_state_t *state);
static void xpvtap_user_ring_fini(xpvtap_state_t *state);
static int xpvtap_user_thread_init(xpvtap_state_t *state);
static void xpvtap_user_thread_fini(xpvtap_state_t *state);
static void xpvtap_user_thread_start(caddr_t arg);
static void xpvtap_user_thread_stop(xpvtap_state_t *state);
static void xpvtap_user_thread(void *arg);

static void xpvtap_user_app_stop(caddr_t arg);

static int xpvtap_user_request_map(xpvtap_state_t *state, blkif_request_t *req,
    uint_t *uid);
static int xpvtap_user_request_push(xpvtap_state_t *state,
    blkif_request_t *req, uint_t uid);
static int xpvtap_user_response_get(xpvtap_state_t *state,
    blkif_response_t *resp, uint_t *uid);
static void xpvtap_user_request_unmap(xpvtap_state_t *state, uint_t uid);


/*
 * _init()
 */
int
_init(void)
{
	int e;

	e = ddi_soft_state_init(&xpvtap_statep, sizeof (xpvtap_state_t), 1);
	if (e != 0) {
		return (e);
	}

	e = mod_install(&xpvtap_modlinkage);
	if (e != 0) {
		ddi_soft_state_fini(&xpvtap_statep);
		return (e);
	}

	return (0);
}


/*
 * _info()
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&xpvtap_modlinkage, modinfop));
}


/*
 * _fini()
 */
int
_fini(void)
{
	int e;

	e = mod_remove(&xpvtap_modlinkage);
	if (e != 0) {
		return (e);
	}

	ddi_soft_state_fini(&xpvtap_statep);

	return (0);
}


/*
 * xpvtap_attach()
 */
static int
xpvtap_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	blk_ringinit_args_t args;
	xpvtap_state_t *state;
	int instance;
	int e;


	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	/* initialize our state info */
	instance = ddi_get_instance(dip);
	state = xpvtap_drv_init(instance);
	if (state == NULL) {
		return (DDI_FAILURE);
	}
	state->bt_dip = dip;

	/* Initialize the guest ring */
	args.ar_dip = state->bt_dip;
	args.ar_intr = xpvtap_intr;
	args.ar_intr_arg = (caddr_t)state;
	args.ar_ringup = xpvtap_user_thread_start;
	args.ar_ringup_arg = (caddr_t)state;
	args.ar_ringdown = xpvtap_user_app_stop;
	args.ar_ringdown_arg = (caddr_t)state;
	e = blk_ring_init(&args, &state->bt_guest_ring);
	if (e != DDI_SUCCESS) {
		goto attachfail_ringinit;
	}

	/* create the minor node (for ioctl/mmap) */
	e = ddi_create_minor_node(dip, "xpvtap", S_IFCHR, instance,
	    DDI_PSEUDO, 0);
	if (e != DDI_SUCCESS) {
		goto attachfail_minor_node;
	}

	/* Report that driver was loaded */
	ddi_report_dev(dip);

	return (DDI_SUCCESS);

attachfail_minor_node:
	blk_ring_fini(&state->bt_guest_ring);
attachfail_ringinit:
	xpvtap_drv_fini(state);
	return (DDI_FAILURE);
}


/*
 * xpvtap_detach()
 */
static int
xpvtap_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	xpvtap_state_t *state;
	int instance;


	instance = ddi_get_instance(dip);
	state = ddi_get_soft_state(xpvtap_statep, instance);
	if (state == NULL) {
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
	default:
		return (DDI_FAILURE);
	}

	xpvtap_user_thread_stop(state);
	blk_ring_fini(&state->bt_guest_ring);
	xpvtap_drv_fini(state);
	ddi_remove_minor_node(dip, NULL);

	return (DDI_SUCCESS);
}


/*
 * xpvtap_getinfo()
 */
/*ARGSUSED*/
static int
xpvtap_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	xpvtap_state_t *state;
	int instance;
	dev_t dev;
	int e;


	dev = (dev_t)arg;
	instance = getminor(dev);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		state = ddi_get_soft_state(xpvtap_statep, instance);
		if (state == NULL) {
			return (DDI_FAILURE);
		}
		*result = (void *)state->bt_dip;
		e = DDI_SUCCESS;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		e = DDI_SUCCESS;
		break;

	default:
		e = DDI_FAILURE;
		break;
	}

	return (e);
}


/*
 * xpvtap_open()
 */
/*ARGSUSED*/
static int
xpvtap_open(dev_t *devp, int flag, int otyp, cred_t *cred)
{
	xpvtap_state_t *state;
	int instance;


	if (secpolicy_xvm_control(cred)) {
		return (EPERM);
	}

	instance = getminor(*devp);
	state = ddi_get_soft_state(xpvtap_statep, instance);
	if (state == NULL) {
		return (ENXIO);
	}

	/* we should only be opened once */
	mutex_enter(&state->bt_open.bo_mutex);
	if (state->bt_open.bo_opened) {
		mutex_exit(&state->bt_open.bo_mutex);
		return (EBUSY);
	}
	state->bt_open.bo_opened = B_TRUE;
	mutex_exit(&state->bt_open.bo_mutex);

	/*
	 * save the apps address space. need it for mapping/unmapping grefs
	 * since will be doing it in a separate kernel thread.
	 */
	state->bt_map.um_as = curproc->p_as;

	return (0);
}


/*
 * xpvtap_close()
 */
/*ARGSUSED*/
static int
xpvtap_close(dev_t devp, int flag, int otyp, cred_t *cred)
{
	xpvtap_state_t *state;
	int instance;


	instance = getminor(devp);
	state = ddi_get_soft_state(xpvtap_statep, instance);
	if (state == NULL) {
		return (ENXIO);
	}

	/*
	 * wake thread so it can cleanup and wait for it to exit so we can
	 * be sure it's not in the middle of processing a request/response.
	 */
	mutex_enter(&state->bt_thread.ut_mutex);
	state->bt_thread.ut_wake = B_TRUE;
	state->bt_thread.ut_exit = B_TRUE;
	cv_signal(&state->bt_thread.ut_wake_cv);
	if (!state->bt_thread.ut_exit_done) {
		cv_wait(&state->bt_thread.ut_exit_done_cv,
		    &state->bt_thread.ut_mutex);
	}
	ASSERT(state->bt_thread.ut_exit_done);
	mutex_exit(&state->bt_thread.ut_mutex);

	state->bt_map.um_as = NULL;
	state->bt_map.um_guest_pages = NULL;

	/*
	 * when the ring is brought down, a userland hotplug script is run
	 * which tries to bring the userland app down. We'll wait for a bit
	 * for the user app to exit. Notify the thread waiting that the app
	 * has closed the driver.
	 */
	mutex_enter(&state->bt_open.bo_mutex);
	ASSERT(state->bt_open.bo_opened);
	state->bt_open.bo_opened = B_FALSE;
	cv_signal(&state->bt_open.bo_exit_cv);
	mutex_exit(&state->bt_open.bo_mutex);

	return (0);
}


/*
 * xpvtap_ioctl()
 */
/*ARGSUSED*/
static int
xpvtap_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred,
    int *rval)
{
	xpvtap_state_t *state;
	int instance;


	if (secpolicy_xvm_control(cred)) {
		return (EPERM);
	}

	instance = getminor(dev);
	if (instance == -1) {
		return (EBADF);
	}

	state = ddi_get_soft_state(xpvtap_statep, instance);
	if (state == NULL) {
		return (EBADF);
	}

	switch (cmd) {
	case XPVTAP_IOCTL_RESP_PUSH:
		/*
		 * wake thread, thread handles guest requests and user app
		 * responses.
		 */
		mutex_enter(&state->bt_thread.ut_mutex);
		state->bt_thread.ut_wake = B_TRUE;
		cv_signal(&state->bt_thread.ut_wake_cv);
		mutex_exit(&state->bt_thread.ut_mutex);
		break;

	default:
		cmn_err(CE_WARN, "ioctl(%d) not supported\n", cmd);
		return (ENXIO);
	}

	return (0);
}


/*
 * xpvtap_segmap()
 */
/*ARGSUSED*/
static int
xpvtap_segmap(dev_t dev, off_t off, struct as *asp, caddr_t *addrp,
    off_t len, unsigned int prot, unsigned int maxprot, unsigned int flags,
    cred_t *cred_p)
{
	struct segmf_crargs a;
	xpvtap_state_t *state;
	int instance;
	int e;


	if (secpolicy_xvm_control(cred_p)) {
		return (EPERM);
	}

	instance = getminor(dev);
	state = ddi_get_soft_state(xpvtap_statep, instance);
	if (state == NULL) {
		return (EBADF);
	}

	/* the user app should be doing a MAP_SHARED mapping */
	if ((flags & MAP_TYPE) != MAP_SHARED) {
		return (EINVAL);
	}

	/*
	 * if this is the user ring (offset = 0), devmap it (which ends up in
	 * xpvtap_devmap). devmap will alloc and map the ring into the
	 * app's VA space.
	 */
	if (off == 0) {
		e = devmap_setup(dev, (offset_t)off, asp, addrp, (size_t)len,
		    prot, maxprot, flags, cred_p);
		return (e);
	}

	/* this should be the mmap for the gref pages (offset = PAGESIZE) */
	if (off != PAGESIZE) {
		return (EINVAL);
	}

	/* make sure we get the size we're expecting */
	if (len != XPVTAP_GREF_BUFSIZE) {
		return (EINVAL);
	}

	/*
	 * reserve user app VA space for the gref pages and use segmf to
	 * manage the backing store for the physical memory. segmf will
	 * map in/out the grefs and fault them in/out.
	 */
	ASSERT(asp == state->bt_map.um_as);
	as_rangelock(asp);
	if ((flags & MAP_FIXED) == 0) {
		map_addr(addrp, len, 0, 0, flags);
		if (*addrp == NULL) {
			as_rangeunlock(asp);
			return (ENOMEM);
		}
	} else {
		/* User specified address */
		(void) as_unmap(asp, *addrp, len);
	}
	a.dev = dev;
	a.prot = (uchar_t)prot;
	a.maxprot = (uchar_t)maxprot;
	e = as_map(asp, *addrp, len, segmf_create, &a);
	if (e != 0) {
		as_rangeunlock(asp);
		return (e);
	}
	as_rangeunlock(asp);

	/*
	 * Stash user base address, and compute address where the request
	 * array will end up.
	 */
	state->bt_map.um_guest_pages = (caddr_t)*addrp;
	state->bt_map.um_guest_size = (size_t)len;

	/* register an as callback so we can cleanup when the app goes away */
	e = as_add_callback(asp, xpvtap_segmf_unregister, state,
	    AS_UNMAP_EVENT, *addrp, len, KM_SLEEP);
	if (e != 0) {
		(void) as_unmap(asp, *addrp, len);
		return (EINVAL);
	}

	/* wake thread to see if there are requests already queued up */
	mutex_enter(&state->bt_thread.ut_mutex);
	state->bt_thread.ut_wake = B_TRUE;
	cv_signal(&state->bt_thread.ut_wake_cv);
	mutex_exit(&state->bt_thread.ut_mutex);

	return (0);
}


/*
 * xpvtap_devmap()
 */
/*ARGSUSED*/
static int
xpvtap_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off, size_t len,
    size_t *maplen, uint_t model)
{
	xpvtap_user_ring_t *usring;
	xpvtap_state_t *state;
	int instance;
	int e;


	instance = getminor(dev);
	state = ddi_get_soft_state(xpvtap_statep, instance);
	if (state == NULL) {
		return (EBADF);
	}

	/* we should only get here if the offset was == 0 */
	if (off != 0) {
		return (EINVAL);
	}

	/* we should only be mapping in one page */
	if (len != PAGESIZE) {
		return (EINVAL);
	}

	/*
	 * we already allocated the user ring during driver attach, all we
	 * need to do is map it into the user app's VA.
	 */
	usring = &state->bt_user_ring;
	e = devmap_umem_setup(dhp, state->bt_dip, NULL, usring->ur_cookie, 0,
	    PAGESIZE, PROT_ALL, DEVMAP_DEFAULTS, NULL);
	if (e < 0) {
		return (e);
	}

	/* return the size to compete the devmap */
	*maplen = PAGESIZE;

	return (0);
}


/*
 * xpvtap_chpoll()
 */
static int
xpvtap_chpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	xpvtap_user_ring_t *usring;
	xpvtap_state_t *state;
	int instance;


	instance = getminor(dev);
	if (instance == -1) {
		return (EBADF);
	}
	state = ddi_get_soft_state(xpvtap_statep, instance);
	if (state == NULL) {
		return (EBADF);
	}

	if (((events & (POLLIN | POLLRDNORM)) == 0) && !anyyet) {
		*reventsp = 0;
		return (EINVAL);
	}

	/*
	 * if we pushed requests on the user ring since the last poll, wakeup
	 * the user app
	 */
	usring = &state->bt_user_ring;
	if (usring->ur_prod_polled != usring->ur_ring.req_prod_pvt) {

		/*
		 * XXX - is this faster here or xpvtap_user_request_push??
		 * prelim data says here.  Because less membars or because
		 * user thread will spin in poll requests before getting to
		 * responses?
		 */
		RING_PUSH_REQUESTS(&usring->ur_ring);

		usring->ur_prod_polled = usring->ur_ring.sring->req_prod;
		*reventsp =  POLLIN | POLLRDNORM;

	/* no new requests */
	} else {
		*reventsp = 0;
		if (!anyyet) {
			*phpp = &state->bt_pollhead;
		}
	}

	return (0);
}


/*
 * xpvtap_drv_init()
 */
static xpvtap_state_t *
xpvtap_drv_init(int instance)
{
	xpvtap_state_t *state;
	int e;


	e = ddi_soft_state_zalloc(xpvtap_statep, instance);
	if (e != DDI_SUCCESS) {
		return (NULL);
	}
	state = ddi_get_soft_state(xpvtap_statep, instance);
	if (state == NULL) {
		goto drvinitfail_get_soft_state;
	}

	state->bt_instance = instance;
	mutex_init(&state->bt_open.bo_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&state->bt_open.bo_exit_cv, NULL, CV_DRIVER, NULL);
	state->bt_open.bo_opened = B_FALSE;
	state->bt_map.um_registered = B_FALSE;

	/* initialize user ring, thread, mapping state */
	e = xpvtap_user_init(state);
	if (e != DDI_SUCCESS) {
		goto drvinitfail_userinit;
	}

	return (state);

drvinitfail_userinit:
	cv_destroy(&state->bt_open.bo_exit_cv);
	mutex_destroy(&state->bt_open.bo_mutex);
drvinitfail_get_soft_state:
	(void) ddi_soft_state_free(xpvtap_statep, instance);
	return (NULL);
}


/*
 * xpvtap_drv_fini()
 */
static void
xpvtap_drv_fini(xpvtap_state_t *state)
{
	xpvtap_user_fini(state);
	cv_destroy(&state->bt_open.bo_exit_cv);
	mutex_destroy(&state->bt_open.bo_mutex);
	(void) ddi_soft_state_free(xpvtap_statep, state->bt_instance);
}


/*
 * xpvtap_intr()
 *    this routine will be called when we have a request on the guest ring.
 */
static uint_t
xpvtap_intr(caddr_t arg)
{
	xpvtap_state_t *state;


	state = (xpvtap_state_t *)arg;

	/* wake thread, thread handles guest requests and user app responses */
	mutex_enter(&state->bt_thread.ut_mutex);
	state->bt_thread.ut_wake = B_TRUE;
	cv_signal(&state->bt_thread.ut_wake_cv);
	mutex_exit(&state->bt_thread.ut_mutex);

	return (DDI_INTR_CLAIMED);
}


/*
 * xpvtap_segmf_register()
 */
static int
xpvtap_segmf_register(xpvtap_state_t *state)
{
	struct seg *seg;
	uint64_t pte_ma;
	struct as *as;
	caddr_t uaddr;
	uint_t pgcnt;
	int i;


	as = state->bt_map.um_as;
	pgcnt = btopr(state->bt_map.um_guest_size);
	uaddr = state->bt_map.um_guest_pages;

	if (pgcnt == 0) {
		return (DDI_FAILURE);
	}

	AS_LOCK_ENTER(as, RW_READER);

	seg = as_findseg(as, state->bt_map.um_guest_pages, 0);
	if ((seg == NULL) || ((uaddr + state->bt_map.um_guest_size) >
	    (seg->s_base + seg->s_size))) {
		AS_LOCK_EXIT(as);
		return (DDI_FAILURE);
	}

	/*
	 * lock down the htables so the HAT can't steal them. Register the
	 * PTE MA's for each gref page with seg_mf so we can do user space
	 * gref mappings.
	 */
	for (i = 0; i < pgcnt; i++) {
		hat_prepare_mapping(as->a_hat, uaddr, &pte_ma);
		hat_devload(as->a_hat, uaddr, PAGESIZE, (pfn_t)0,
		    PROT_READ | PROT_WRITE | PROT_USER | HAT_UNORDERED_OK,
		    HAT_LOAD_NOCONSIST | HAT_LOAD_LOCK);
		hat_release_mapping(as->a_hat, uaddr);
		segmf_add_gref_pte(seg, uaddr, pte_ma);
		uaddr += PAGESIZE;
	}

	state->bt_map.um_registered = B_TRUE;

	AS_LOCK_EXIT(as);

	return (DDI_SUCCESS);
}


/*
 * xpvtap_segmf_unregister()
 *    as_callback routine
 */
/*ARGSUSED*/
static void
xpvtap_segmf_unregister(struct as *as, void *arg, uint_t event)
{
	xpvtap_state_t *state;
	caddr_t uaddr;
	uint_t pgcnt;
	int i;


	state = (xpvtap_state_t *)arg;
	if (!state->bt_map.um_registered) {
		/* remove the callback (which is this routine) */
		(void) as_delete_callback(as, arg);
		return;
	}

	pgcnt = btopr(state->bt_map.um_guest_size);
	uaddr = state->bt_map.um_guest_pages;

	/* unmap any outstanding req's grefs */
	xpvtap_rs_flush(state->bt_map.um_rs, xpvtap_user_request_unmap, state);

	/* Unlock the gref pages */
	for (i = 0; i < pgcnt; i++) {
		AS_LOCK_ENTER(as, RW_WRITER);
		hat_prepare_mapping(as->a_hat, uaddr, NULL);
		hat_unload(as->a_hat, uaddr, PAGESIZE, HAT_UNLOAD_UNLOCK);
		hat_release_mapping(as->a_hat, uaddr);
		AS_LOCK_EXIT(as);
		uaddr += PAGESIZE;
	}

	/* remove the callback (which is this routine) */
	(void) as_delete_callback(as, arg);

	state->bt_map.um_registered = B_FALSE;
}


/*
 * xpvtap_user_init()
 */
static int
xpvtap_user_init(xpvtap_state_t *state)
{
	xpvtap_user_map_t *map;
	int e;


	map = &state->bt_map;

	/* Setup the ring between the driver and user app */
	e = xpvtap_user_ring_init(state);
	if (e != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * the user ring can handle BLKIF_RING_SIZE outstanding requests. This
	 * is the same number of requests as the guest ring. Initialize the
	 * state we use to track request IDs to the user app. These IDs will
	 * also identify which group of gref pages correspond with the
	 * request.
	 */
	xpvtap_rs_init(0, (BLKIF_RING_SIZE - 1), &map->um_rs);

	/*
	 * allocate the space to store a copy of each outstanding requests. We
	 * will need to reference the ID and the number of segments when we
	 * get the response from the user app.
	 */
	map->um_outstanding_reqs = kmem_zalloc(
	    sizeof (*map->um_outstanding_reqs) * BLKIF_RING_SIZE,
	    KM_SLEEP);

	/*
	 * initialize the thread we use to process guest requests and user
	 * responses.
	 */
	e = xpvtap_user_thread_init(state);
	if (e != DDI_SUCCESS) {
		goto userinitfail_user_thread_init;
	}

	return (DDI_SUCCESS);

userinitfail_user_thread_init:
	xpvtap_rs_fini(&map->um_rs);
	kmem_free(map->um_outstanding_reqs,
	    sizeof (*map->um_outstanding_reqs) * BLKIF_RING_SIZE);
	xpvtap_user_ring_fini(state);
	return (DDI_FAILURE);
}


/*
 * xpvtap_user_ring_init()
 */
static int
xpvtap_user_ring_init(xpvtap_state_t *state)
{
	xpvtap_user_ring_t *usring;


	usring = &state->bt_user_ring;

	/* alocate and initialize the page for the shared user ring */
	usring->ur_sring = (blkif_sring_t *)ddi_umem_alloc(PAGESIZE,
	    DDI_UMEM_SLEEP, &usring->ur_cookie);
	SHARED_RING_INIT(usring->ur_sring);
	FRONT_RING_INIT(&usring->ur_ring, usring->ur_sring, PAGESIZE);
	usring->ur_prod_polled = 0;

	return (DDI_SUCCESS);
}


/*
 * xpvtap_user_thread_init()
 */
static int
xpvtap_user_thread_init(xpvtap_state_t *state)
{
	xpvtap_user_thread_t *thread;
	char taskqname[32];


	thread = &state->bt_thread;

	mutex_init(&thread->ut_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&thread->ut_wake_cv, NULL, CV_DRIVER, NULL);
	cv_init(&thread->ut_exit_done_cv, NULL, CV_DRIVER, NULL);
	thread->ut_wake = B_FALSE;
	thread->ut_exit = B_FALSE;
	thread->ut_exit_done = B_TRUE;

	/* create but don't start the user thread */
	(void) sprintf(taskqname, "xvptap_%d", state->bt_instance);
	thread->ut_taskq = ddi_taskq_create(state->bt_dip, taskqname, 1,
	    TASKQ_DEFAULTPRI, 0);
	if (thread->ut_taskq == NULL) {
		goto userinitthrfail_taskq_create;
	}

	return (DDI_SUCCESS);

userinitthrfail_taskq_dispatch:
	ddi_taskq_destroy(thread->ut_taskq);
userinitthrfail_taskq_create:
	cv_destroy(&thread->ut_exit_done_cv);
	cv_destroy(&thread->ut_wake_cv);
	mutex_destroy(&thread->ut_mutex);

	return (DDI_FAILURE);
}


/*
 * xpvtap_user_thread_start()
 */
static void
xpvtap_user_thread_start(caddr_t arg)
{
	xpvtap_user_thread_t *thread;
	xpvtap_state_t *state;
	int e;


	state = (xpvtap_state_t *)arg;
	thread = &state->bt_thread;

	/* start the user thread */
	thread->ut_exit_done = B_FALSE;
	e = ddi_taskq_dispatch(thread->ut_taskq, xpvtap_user_thread, state,
	    DDI_SLEEP);
	if (e != DDI_SUCCESS) {
		thread->ut_exit_done = B_TRUE;
		cmn_err(CE_WARN, "Unable to start user thread\n");
	}
}


/*
 * xpvtap_user_thread_stop()
 */
static void
xpvtap_user_thread_stop(xpvtap_state_t *state)
{
	/* wake thread so it can exit */
	mutex_enter(&state->bt_thread.ut_mutex);
	state->bt_thread.ut_wake = B_TRUE;
	state->bt_thread.ut_exit = B_TRUE;
	cv_signal(&state->bt_thread.ut_wake_cv);
	if (!state->bt_thread.ut_exit_done) {
		cv_wait(&state->bt_thread.ut_exit_done_cv,
		    &state->bt_thread.ut_mutex);
	}
	mutex_exit(&state->bt_thread.ut_mutex);
	ASSERT(state->bt_thread.ut_exit_done);
}


/*
 * xpvtap_user_fini()
 */
static void
xpvtap_user_fini(xpvtap_state_t *state)
{
	xpvtap_user_map_t *map;


	map = &state->bt_map;

	xpvtap_user_thread_fini(state);
	xpvtap_rs_fini(&map->um_rs);
	kmem_free(map->um_outstanding_reqs,
	    sizeof (*map->um_outstanding_reqs) * BLKIF_RING_SIZE);
	xpvtap_user_ring_fini(state);
}


/*
 * xpvtap_user_ring_fini()
 */
static void
xpvtap_user_ring_fini(xpvtap_state_t *state)
{
	ddi_umem_free(state->bt_user_ring.ur_cookie);
}


/*
 * xpvtap_user_thread_fini()
 */
static void
xpvtap_user_thread_fini(xpvtap_state_t *state)
{
	ddi_taskq_destroy(state->bt_thread.ut_taskq);
	cv_destroy(&state->bt_thread.ut_exit_done_cv);
	cv_destroy(&state->bt_thread.ut_wake_cv);
	mutex_destroy(&state->bt_thread.ut_mutex);
}


/*
 * xpvtap_user_thread()
 */
static void
xpvtap_user_thread(void *arg)
{
	xpvtap_user_thread_t *thread;
	blkif_response_t resp;
	xpvtap_state_t *state;
	blkif_request_t req;
	boolean_t b;
	uint_t uid;
	int e;


	state = (xpvtap_state_t *)arg;
	thread = &state->bt_thread;

xpvtap_thread_start:
	/* See if we are supposed to exit */
	mutex_enter(&thread->ut_mutex);
	if (thread->ut_exit) {
		thread->ut_exit_done = B_TRUE;
		cv_signal(&state->bt_thread.ut_exit_done_cv);
		mutex_exit(&thread->ut_mutex);
		return;
	}

	/*
	 * if we aren't supposed to be awake, wait until someone wakes us.
	 * when we wake up, check for a kill or someone telling us to exit.
	 */
	if (!thread->ut_wake) {
		e = cv_wait_sig(&thread->ut_wake_cv, &thread->ut_mutex);
		if ((e == 0) || (thread->ut_exit)) {
			thread->ut_exit = B_TRUE;
			mutex_exit(&thread->ut_mutex);
			goto xpvtap_thread_start;
		}
	}

	/* if someone didn't wake us, go back to the start of the thread */
	if (!thread->ut_wake) {
		mutex_exit(&thread->ut_mutex);
		goto xpvtap_thread_start;
	}

	/* we are awake */
	thread->ut_wake = B_FALSE;
	mutex_exit(&thread->ut_mutex);

	/* process requests from the guest */
	do {
		/*
		 * check for requests from the guest. if we don't have any,
		 * break out of the loop.
		 */
		e = blk_ring_request_get(state->bt_guest_ring, &req);
		if (e == B_FALSE) {
			break;
		}

		/* we got a request, map the grefs into the user app's VA */
		e = xpvtap_user_request_map(state, &req, &uid);
		if (e != DDI_SUCCESS) {
			/*
			 * If we couldn't map the request (e.g. user app hasn't
			 * opened the device yet), requeue it and try again
			 * later
			 */
			blk_ring_request_requeue(state->bt_guest_ring);
			break;
		}

		/* push the request to the user app */
		e = xpvtap_user_request_push(state, &req, uid);
		if (e != DDI_SUCCESS) {
			resp.id = req.id;
			resp.operation = req.operation;
			resp.status = BLKIF_RSP_ERROR;
			blk_ring_response_put(state->bt_guest_ring, &resp);
		}
	} while (!thread->ut_exit);

	/* process reponses from the user app */
	do {
		/*
		 * check for responses from the user app. if we don't have any,
		 * break out of the loop.
		 */
		b = xpvtap_user_response_get(state, &resp, &uid);
		if (b != B_TRUE) {
			break;
		}

		/*
		 * if we got a response, unmap the grefs from the matching
		 * request.
		 */
		xpvtap_user_request_unmap(state, uid);

		/* push the response to the guest */
		blk_ring_response_put(state->bt_guest_ring, &resp);
	} while (!thread->ut_exit);

	goto xpvtap_thread_start;
}


/*
 * xpvtap_user_request_map()
 */
static int
xpvtap_user_request_map(xpvtap_state_t *state, blkif_request_t *req,
    uint_t *uid)
{
	grant_ref_t gref[BLKIF_MAX_SEGMENTS_PER_REQUEST];
	struct seg *seg;
	struct as *as;
	domid_t domid;
	caddr_t uaddr;
	uint_t flags;
	int i;
	int e;


	domid = xvdi_get_oeid(state->bt_dip);

	as = state->bt_map.um_as;
	if ((as == NULL) || (state->bt_map.um_guest_pages == NULL)) {
		return (DDI_FAILURE);
	}

	/* has to happen after segmap returns */
	if (!state->bt_map.um_registered) {
		/* register the pte's with segmf */
		e = xpvtap_segmf_register(state);
		if (e != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
	}

	/* alloc an ID for the user ring */
	e = xpvtap_rs_alloc(state->bt_map.um_rs, uid);
	if (e != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/* if we don't have any segments to map, we're done */
	if ((req->operation == BLKIF_OP_WRITE_BARRIER) ||
	    (req->operation == BLKIF_OP_FLUSH_DISKCACHE) ||
	    (req->nr_segments == 0)) {
		return (DDI_SUCCESS);
	}

	/* get the apps gref address */
	uaddr = XPVTAP_GREF_REQADDR(state->bt_map.um_guest_pages, *uid);

	AS_LOCK_ENTER(as, RW_READER);
	seg = as_findseg(as, state->bt_map.um_guest_pages, 0);
	if ((seg == NULL) || ((uaddr + mmu_ptob(req->nr_segments)) >
	    (seg->s_base + seg->s_size))) {
		AS_LOCK_EXIT(as);
		return (DDI_FAILURE);
	}

	/* if we are reading from disk, we are writing into memory */
	flags = 0;
	if (req->operation == BLKIF_OP_READ) {
		flags |= SEGMF_GREF_WR;
	}

	/* Load the grefs into seg_mf */
	for (i = 0; i < req->nr_segments; i++) {
		gref[i] = req->seg[i].gref;
	}
	(void) segmf_add_grefs(seg, uaddr, flags, gref, req->nr_segments,
	    domid);

	AS_LOCK_EXIT(as);

	return (DDI_SUCCESS);
}


/*
 * xpvtap_user_request_push()
 */
static int
xpvtap_user_request_push(xpvtap_state_t *state, blkif_request_t *req,
    uint_t uid)
{
	blkif_request_t *outstanding_req;
	blkif_front_ring_t *uring;
	blkif_request_t *target;
	xpvtap_user_map_t *map;


	uring = &state->bt_user_ring.ur_ring;
	map = &state->bt_map;

	target = RING_GET_REQUEST(uring, uring->req_prod_pvt);

	/*
	 * Save request from the frontend. used for ID mapping and unmap
	 * on response/cleanup
	 */
	outstanding_req = &map->um_outstanding_reqs[uid];
	bcopy(req, outstanding_req, sizeof (*outstanding_req));

	/* put the request on the user ring */
	bcopy(req, target, sizeof (*req));
	target->id = (uint64_t)uid;
	uring->req_prod_pvt++;

	pollwakeup(&state->bt_pollhead, POLLIN | POLLRDNORM);

	return (DDI_SUCCESS);
}


static void
xpvtap_user_request_unmap(xpvtap_state_t *state, uint_t uid)
{
	blkif_request_t *req;
	struct seg *seg;
	struct as *as;
	caddr_t uaddr;
	int e;


	as = state->bt_map.um_as;
	if (as == NULL) {
		return;
	}

	/* get a copy of the original request */
	req = &state->bt_map.um_outstanding_reqs[uid];

	/* unmap the grefs for this request */
	if ((req->operation != BLKIF_OP_WRITE_BARRIER) &&
	    (req->operation != BLKIF_OP_FLUSH_DISKCACHE) &&
	    (req->nr_segments != 0)) {
		uaddr = XPVTAP_GREF_REQADDR(state->bt_map.um_guest_pages, uid);
		AS_LOCK_ENTER(as, RW_READER);
		seg = as_findseg(as, state->bt_map.um_guest_pages, 0);
		if ((seg == NULL) || ((uaddr + mmu_ptob(req->nr_segments)) >
		    (seg->s_base + seg->s_size))) {
			AS_LOCK_EXIT(as);
			xpvtap_rs_free(state->bt_map.um_rs, uid);
			return;
		}

		e = segmf_release_grefs(seg, uaddr, req->nr_segments);
		if (e != 0) {
			cmn_err(CE_WARN, "unable to release grefs");
		}

		AS_LOCK_EXIT(as);
	}

	/* free up the user ring id */
	xpvtap_rs_free(state->bt_map.um_rs, uid);
}


static int
xpvtap_user_response_get(xpvtap_state_t *state, blkif_response_t *resp,
    uint_t *uid)
{
	blkif_front_ring_t *uring;
	blkif_response_t *target;


	uring = &state->bt_user_ring.ur_ring;

	if (!RING_HAS_UNCONSUMED_RESPONSES(uring)) {
		return (B_FALSE);
	}

	target = NULL;
	target = RING_GET_RESPONSE(uring, uring->rsp_cons);
	if (target == NULL) {
		return (B_FALSE);
	}

	/* copy out the user app response */
	bcopy(target, resp, sizeof (*resp));
	uring->rsp_cons++;

	/* restore the quests id from the original request */
	*uid = (uint_t)resp->id;
	resp->id = state->bt_map.um_outstanding_reqs[*uid].id;

	return (B_TRUE);
}


/*
 * xpvtap_user_app_stop()
 */
static void xpvtap_user_app_stop(caddr_t arg)
{
	xpvtap_state_t *state;
	clock_t rc;

	state = (xpvtap_state_t *)arg;

	/*
	 * Give the app 10 secs to exit. If it doesn't exit, it's not a serious
	 * problem, we just won't auto-detach the driver.
	 */
	mutex_enter(&state->bt_open.bo_mutex);
	if (state->bt_open.bo_opened) {
		rc = cv_reltimedwait(&state->bt_open.bo_exit_cv,
		    &state->bt_open.bo_mutex, drv_usectohz(10000000),
		    TR_CLOCK_TICK);
		if (rc <= 0) {
			cmn_err(CE_NOTE, "!user process still has driver open, "
			    "deferring detach\n");
		}
	}
	mutex_exit(&state->bt_open.bo_mutex);
}


/*
 * xpvtap_rs_init()
 *    Initialize the resource structure. init() returns a handle to be used
 *    for the rest of the resource functions. This code is written assuming
 *    that min_val will be close to 0. Therefore, we will allocate the free
 *    buffer only taking max_val into account.
 */
static void
xpvtap_rs_init(uint_t min_val, uint_t max_val, xpvtap_rs_hdl_t *handle)
{
	xpvtap_rs_t *rstruct;
	uint_t array_size;
	uint_t index;


	ASSERT(handle != NULL);
	ASSERT(min_val < max_val);

	/* alloc space for resource structure */
	rstruct = kmem_alloc(sizeof (xpvtap_rs_t), KM_SLEEP);

	/*
	 * Test to see if the max value is 64-bit aligned. If so, we don't need
	 * to allocate an extra 64-bit word. alloc space for free buffer
	 * (8 bytes per uint64_t).
	 */
	if ((max_val & 0x3F) == 0) {
		rstruct->rs_free_size = (max_val >> 6) * 8;
	} else {
		rstruct->rs_free_size = ((max_val >> 6) + 1) * 8;
	}
	rstruct->rs_free = kmem_alloc(rstruct->rs_free_size, KM_SLEEP);

	/* Initialize resource structure */
	rstruct->rs_min = min_val;
	rstruct->rs_last = min_val;
	rstruct->rs_max = max_val;
	mutex_init(&rstruct->rs_mutex, NULL, MUTEX_DRIVER, NULL);
	rstruct->rs_flushing = B_FALSE;

	/* Mark all resources as free */
	array_size = rstruct->rs_free_size >> 3;
	for (index = 0; index < array_size; index++) {
		rstruct->rs_free[index] = (uint64_t)0xFFFFFFFFFFFFFFFF;
	}

	/* setup handle which is returned from this function */
	*handle = rstruct;
}


/*
 * xpvtap_rs_fini()
 *    Frees up the space allocated in init().  Notice that a pointer to the
 *    handle is used for the parameter.  fini() will set the handle to NULL
 *    before returning.
 */
static void
xpvtap_rs_fini(xpvtap_rs_hdl_t *handle)
{
	xpvtap_rs_t *rstruct;


	ASSERT(handle != NULL);

	rstruct = (xpvtap_rs_t *)*handle;

	mutex_destroy(&rstruct->rs_mutex);
	kmem_free(rstruct->rs_free, rstruct->rs_free_size);
	kmem_free(rstruct, sizeof (xpvtap_rs_t));

	/* set handle to null.  This helps catch bugs. */
	*handle = NULL;
}


/*
 * xpvtap_rs_alloc()
 *    alloc a resource. If alloc fails, we are out of resources.
 */
static int
xpvtap_rs_alloc(xpvtap_rs_hdl_t handle, uint_t *resource)
{
	xpvtap_rs_t *rstruct;
	uint_t array_idx;
	uint64_t free;
	uint_t index;
	uint_t last;
	uint_t min;
	uint_t max;


	ASSERT(handle != NULL);
	ASSERT(resource != NULL);

	rstruct = (xpvtap_rs_t *)handle;

	mutex_enter(&rstruct->rs_mutex);
	min = rstruct->rs_min;
	max = rstruct->rs_max;

	/*
	 * Find a free resource. This will return out of the loop once it finds
	 * a free resource. There are a total of 'max'-'min'+1 resources.
	 * Performs a round robin allocation.
	 */
	for (index = min; index <= max; index++) {

		array_idx = rstruct->rs_last >> 6;
		free = rstruct->rs_free[array_idx];
		last = rstruct->rs_last & 0x3F;

		/* if the next resource to check is free */
		if ((free & ((uint64_t)1 << last)) != 0) {
			/* we are using this resource */
			*resource = rstruct->rs_last;

			/* take it out of the free list */
			rstruct->rs_free[array_idx] &= ~((uint64_t)1 << last);

			/*
			 * increment the last count so we start checking the
			 * next resource on the next alloc().  Note the rollover
			 * at 'max'+1.
			 */
			rstruct->rs_last++;
			if (rstruct->rs_last > max) {
				rstruct->rs_last = rstruct->rs_min;
			}

			/* unlock the resource structure */
			mutex_exit(&rstruct->rs_mutex);

			return (DDI_SUCCESS);
		}

		/*
		 * This resource is not free, lets go to the next one. Note the
		 * rollover at 'max'.
		 */
		rstruct->rs_last++;
		if (rstruct->rs_last > max) {
			rstruct->rs_last = rstruct->rs_min;
		}
	}

	mutex_exit(&rstruct->rs_mutex);

	return (DDI_FAILURE);
}


/*
 * xpvtap_rs_free()
 *    Free the previously alloc'd resource.  Once a resource has been free'd,
 *    it can be used again when alloc is called.
 */
static void
xpvtap_rs_free(xpvtap_rs_hdl_t handle, uint_t resource)
{
	xpvtap_rs_t *rstruct;
	uint_t array_idx;
	uint_t offset;


	ASSERT(handle != NULL);

	rstruct = (xpvtap_rs_t *)handle;
	ASSERT(resource >= rstruct->rs_min);
	ASSERT(resource <= rstruct->rs_max);

	if (!rstruct->rs_flushing) {
		mutex_enter(&rstruct->rs_mutex);
	}

	/* Put the resource back in the free list */
	array_idx = resource >> 6;
	offset = resource & 0x3F;
	rstruct->rs_free[array_idx] |= ((uint64_t)1 << offset);

	if (!rstruct->rs_flushing) {
		mutex_exit(&rstruct->rs_mutex);
	}
}


/*
 * xpvtap_rs_flush()
 */
static void
xpvtap_rs_flush(xpvtap_rs_hdl_t handle, xpvtap_rs_cleanup_t callback,
    void *arg)
{
	xpvtap_rs_t *rstruct;
	uint_t array_idx;
	uint64_t free;
	uint_t index;
	uint_t last;
	uint_t min;
	uint_t max;


	ASSERT(handle != NULL);

	rstruct = (xpvtap_rs_t *)handle;

	mutex_enter(&rstruct->rs_mutex);
	min = rstruct->rs_min;
	max = rstruct->rs_max;

	rstruct->rs_flushing = B_TRUE;

	/*
	 * for all resources not free, call the callback routine to clean it
	 * up.
	 */
	for (index = min; index <= max; index++) {

		array_idx = rstruct->rs_last >> 6;
		free = rstruct->rs_free[array_idx];
		last = rstruct->rs_last & 0x3F;

		/* if the next resource to check is not free */
		if ((free & ((uint64_t)1 << last)) == 0) {
			/* call the callback to cleanup */
			(*callback)(arg, rstruct->rs_last);

			/* put it back in the free list */
			rstruct->rs_free[array_idx] |= ((uint64_t)1 << last);
		}

		/* go to the next one. Note the rollover at 'max' */
		rstruct->rs_last++;
		if (rstruct->rs_last > max) {
			rstruct->rs_last = rstruct->rs_min;
		}
	}

	mutex_exit(&rstruct->rs_mutex);
}

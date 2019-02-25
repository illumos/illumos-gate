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
#include <sys/sysmacros.h>
#include <sys/buf.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/kmem.h>
#include <sys/proc.h>
#include <sys/cpuvar.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/io/ddi.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/debug.h>
#include <sys/bofi.h>
#include <sys/dvma.h>
#include <sys/bofi_impl.h>

/*
 * Testing the resilience of a hardened device driver requires a suitably wide
 * range of different types of "typical" hardware faults to be injected,
 * preferably in a controlled and repeatable fashion. This is not in general
 * possible via hardware, so the "fault injection test harness" is provided.
 * This works by intercepting calls from the driver to various DDI routines,
 * and then corrupting the result of those DDI routine calls as if the
 * hardware had caused the corruption.
 *
 * Conceptually, the bofi driver consists of two parts:
 *
 * A driver interface that supports a number of ioctls which allow error
 * definitions ("errdefs") to be defined and subsequently managed. The
 * driver is a clone driver, so each open will create a separate
 * invocation. Any errdefs created by using ioctls to that invocation
 * will automatically be deleted when that invocation is closed.
 *
 * Intercept routines: When the bofi driver is attached, it edits the
 * bus_ops structure of the bus nexus specified by the "bofi-nexus"
 * field in the "bofi.conf" file, thus allowing the
 * bofi driver to intercept various ddi functions. These intercept
 * routines primarily carry out fault injections based on the errdefs
 * created for that device.
 *
 * Faults can be injected into:
 *
 * DMA (corrupting data for DMA to/from memory areas defined by
 * ddi_dma_setup(), ddi_dma_bind_handle(), etc)
 *
 * Physical IO (corrupting data sent/received via ddi_get8(), ddi_put8(),
 * etc),
 *
 * Interrupts (generating spurious interrupts, losing interrupts,
 * delaying interrupts).
 *
 * By default, ddi routines called from all drivers will be intercepted
 * and faults potentially injected. However, the "bofi-to-test" field in
 * the "bofi.conf" file can be set to a space-separated list of drivers to
 * test (or by preceding each driver name in the list with an "!", a list
 * of drivers not to test).
 *
 * In addition to fault injection, the bofi driver does a number of static
 * checks which are controlled by properties in the "bofi.conf" file.
 *
 * "bofi-ddi-check" - if set will validate that there are no PIO access
 * other than those using the DDI routines (ddi_get8(), ddi_put8(), etc).
 *
 * "bofi-range-check" - if set to values 1 (warning) or 2 (panic), will
 * validate that calls to ddi_get8(), ddi_put8(), etc are not made
 * specifying addresses outside the range of the access_handle.
 *
 * "bofi-sync-check" - if set will validate that calls to ddi_dma_sync()
 * are being made correctly.
 */

extern void *bp_mapin_common(struct buf *, int);

static int bofi_ddi_check;
static int bofi_sync_check;
static int bofi_range_check;

static struct bofi_link bofi_link_array[BOFI_NLINKS], *bofi_link_freelist;

#define	LLSZMASK (sizeof (uint64_t)-1)

#define	HDL_HASH_TBL_SIZE 64
static struct bofi_shadow hhash_table[HDL_HASH_TBL_SIZE];
static struct bofi_shadow dhash_table[HDL_HASH_TBL_SIZE];
#define	HDL_DHASH(x) \
	(&dhash_table[((uintptr_t)(x) >> 3) & (HDL_HASH_TBL_SIZE-1)])
#define	HDL_HHASH(x) \
	(&hhash_table[((uintptr_t)(x) >> 5) & (HDL_HASH_TBL_SIZE-1)])

static struct bofi_shadow shadow_list;
static struct bofi_errent *errent_listp;

static char driver_list[NAMESIZE];
static int driver_list_size;
static int driver_list_neg;
static char nexus_name[NAMESIZE];

static int initialized = 0;

#define	NCLONES 2560
static int clone_tab[NCLONES];

static dev_info_t *our_dip;

static kmutex_t bofi_mutex;
static kmutex_t clone_tab_mutex;
static kmutex_t bofi_low_mutex;
static ddi_iblock_cookie_t bofi_low_cookie;
static uint_t	bofi_signal(caddr_t arg);
static int	bofi_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int	bofi_attach(dev_info_t *, ddi_attach_cmd_t);
static int	bofi_detach(dev_info_t *, ddi_detach_cmd_t);
static int	bofi_open(dev_t *, int, int, cred_t *);
static int	bofi_close(dev_t, int, int, cred_t *);
static int	bofi_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int	bofi_errdef_alloc(struct bofi_errdef *, char *,
		    struct bofi_errent *);
static int	bofi_errdef_free(struct bofi_errent *);
static void	bofi_start(struct bofi_errctl *, char *);
static void	bofi_stop(struct bofi_errctl *, char *);
static void	bofi_broadcast(struct bofi_errctl *, char *);
static void	bofi_clear_acc_chk(struct bofi_errctl *, char *);
static void	bofi_clear_errors(struct bofi_errctl *, char *);
static void	bofi_clear_errdefs(struct bofi_errctl *, char *);
static int	bofi_errdef_check(struct bofi_errstate *,
		    struct acc_log_elem **);
static int	bofi_errdef_check_w(struct bofi_errstate *,
		    struct acc_log_elem **);
static int	bofi_map(dev_info_t *, dev_info_t *, ddi_map_req_t *,
		    off_t, off_t, caddr_t *);
static int	bofi_dma_allochdl(dev_info_t *, dev_info_t *,
		    ddi_dma_attr_t *, int (*)(caddr_t), caddr_t,
		    ddi_dma_handle_t *);
static int	bofi_dma_freehdl(dev_info_t *, dev_info_t *,
		    ddi_dma_handle_t);
static int	bofi_dma_bindhdl(dev_info_t *, dev_info_t *,
		    ddi_dma_handle_t, struct ddi_dma_req *, ddi_dma_cookie_t *,
		    uint_t *);
static int	bofi_dma_unbindhdl(dev_info_t *, dev_info_t *,
		    ddi_dma_handle_t);
static int	bofi_dma_flush(dev_info_t *, dev_info_t *, ddi_dma_handle_t,
		    off_t, size_t, uint_t);
static int	bofi_dma_ctl(dev_info_t *, dev_info_t *, ddi_dma_handle_t,
		    enum ddi_dma_ctlops, off_t *, size_t *, caddr_t *, uint_t);
static int	bofi_dma_win(dev_info_t *, dev_info_t *, ddi_dma_handle_t,
		    uint_t, off_t *, size_t *, ddi_dma_cookie_t *, uint_t *);
static int	bofi_intr_ops(dev_info_t *dip, dev_info_t *rdip,
		    ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp,
		    void *result);
static int	bofi_fm_ereport_callback(sysevent_t *ev, void *cookie);

evchan_t *bofi_error_chan;

#define	FM_SIMULATED_DMA "simulated.dma"
#define	FM_SIMULATED_PIO "simulated.pio"

#if defined(__sparc)
static void	bofi_dvma_kaddr_load(ddi_dma_handle_t, caddr_t, uint_t,
		    uint_t, ddi_dma_cookie_t *);
static void	bofi_dvma_unload(ddi_dma_handle_t, uint_t, uint_t);
static void	bofi_dvma_sync(ddi_dma_handle_t, uint_t, uint_t);
static void	bofi_dvma_reserve(dev_info_t *, ddi_dma_handle_t);
#endif
static int	driver_under_test(dev_info_t *);
static int	bofi_check_acc_hdl(ddi_acc_impl_t *);
static int	bofi_check_dma_hdl(ddi_dma_impl_t *);
static int	bofi_post_event(dev_info_t *dip, dev_info_t *rdip,
		    ddi_eventcookie_t eventhdl, void *impl_data);

static struct bus_ops bofi_bus_ops = {
	BUSO_REV,
	bofi_map,
	NULL,
	NULL,
	NULL,
	i_ddi_map_fault,
	NULL,
	bofi_dma_allochdl,
	bofi_dma_freehdl,
	bofi_dma_bindhdl,
	bofi_dma_unbindhdl,
	bofi_dma_flush,
	bofi_dma_win,
	bofi_dma_ctl,
	NULL,
	ddi_bus_prop_op,
	ndi_busop_get_eventcookie,
	ndi_busop_add_eventcall,
	ndi_busop_remove_eventcall,
	bofi_post_event,
	NULL,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	bofi_intr_ops
};

static struct cb_ops bofi_cb_ops = {
	bofi_open,		/* open */
	bofi_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	bofi_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* chpoll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* for STREAMS drivers */
	D_MP,			/* driver compatibility flag */
	CB_REV,			/* cb_ops revision */
	nodev,			/* aread */
	nodev			/* awrite */
};

static struct dev_ops bofi_ops = {
	DEVO_REV,		/* driver build version */
	0,			/* device reference count */
	bofi_getinfo,
	nulldev,
	nulldev,		/* probe */
	bofi_attach,
	bofi_detach,
	nulldev,		/* reset */
	&bofi_cb_ops,
	(struct bus_ops *)NULL,
	nulldev,		/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

/* module configuration stuff */
static void    *statep;

static struct modldrv modldrv = {
	&mod_driverops,
	"bofi driver",
	&bofi_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	0
};

static struct bus_ops save_bus_ops;

#if defined(__sparc)
static struct dvma_ops bofi_dvma_ops = {
	DVMAO_REV,
	bofi_dvma_kaddr_load,
	bofi_dvma_unload,
	bofi_dvma_sync
};
#endif

/*
 * support routine - map user page into kernel virtual
 */
static caddr_t
dmareq_mapin(offset_t len, caddr_t addr, struct as *as, int flag)
{
	struct buf buf;
	struct proc proc;

	/*
	 * mock up a buf structure so we can call bp_mapin_common()
	 */
	buf.b_flags = B_PHYS;
	buf.b_un.b_addr = (caddr_t)addr;
	buf.b_bcount = (size_t)len;
	proc.p_as = as;
	buf.b_proc = &proc;
	return (bp_mapin_common(&buf, flag));
}


/*
 * support routine - map page chain into kernel virtual
 */
static caddr_t
dmareq_pp_mapin(offset_t len, uint_t offset, page_t *pp, int flag)
{
	struct buf buf;

	/*
	 * mock up a buf structure so we can call bp_mapin_common()
	 */
	buf.b_flags = B_PAGEIO;
	buf.b_un.b_addr = (caddr_t)(uintptr_t)offset;
	buf.b_bcount = (size_t)len;
	buf.b_pages = pp;
	return (bp_mapin_common(&buf, flag));
}


/*
 * support routine - map page array into kernel virtual
 */
static caddr_t
dmareq_pplist_mapin(uint_t len, caddr_t addr, page_t **pplist, struct as *as,
    int flag)
{
	struct buf buf;
	struct proc proc;

	/*
	 * mock up a buf structure so we can call bp_mapin_common()
	 */
	buf.b_flags = B_PHYS|B_SHADOW;
	buf.b_un.b_addr = addr;
	buf.b_bcount = len;
	buf.b_shadow = pplist;
	proc.p_as = as;
	buf.b_proc = &proc;
	return (bp_mapin_common(&buf, flag));
}


/*
 * support routine - map dmareq into kernel virtual if not already
 * fills in *lenp with length
 * *mapaddr will be new kernel virtual address - or null if no mapping needed
 */
static caddr_t
ddi_dmareq_mapin(struct ddi_dma_req *dmareqp, caddr_t *mapaddrp,
    offset_t *lenp)
{
	int sleep = (dmareqp->dmar_fp == DDI_DMA_SLEEP) ? VM_SLEEP: VM_NOSLEEP;

	*lenp = dmareqp->dmar_object.dmao_size;
	if (dmareqp->dmar_object.dmao_type == DMA_OTYP_PAGES) {
		*mapaddrp = dmareq_pp_mapin(dmareqp->dmar_object.dmao_size,
		    dmareqp->dmar_object.dmao_obj.pp_obj.pp_offset,
		    dmareqp->dmar_object.dmao_obj.pp_obj.pp_pp, sleep);
		return (*mapaddrp);
	} else if (dmareqp->dmar_object.dmao_obj.virt_obj.v_priv != NULL) {
		*mapaddrp = dmareq_pplist_mapin(dmareqp->dmar_object.dmao_size,
		    dmareqp->dmar_object.dmao_obj.virt_obj.v_addr,
		    dmareqp->dmar_object.dmao_obj.virt_obj.v_priv,
		    dmareqp->dmar_object.dmao_obj.virt_obj.v_as, sleep);
		return (*mapaddrp);
	} else if (dmareqp->dmar_object.dmao_obj.virt_obj.v_as == &kas) {
		*mapaddrp = NULL;
		return (dmareqp->dmar_object.dmao_obj.virt_obj.v_addr);
	} else if (dmareqp->dmar_object.dmao_obj.virt_obj.v_as == NULL) {
		*mapaddrp = NULL;
		return (dmareqp->dmar_object.dmao_obj.virt_obj.v_addr);
	} else {
		*mapaddrp = dmareq_mapin(dmareqp->dmar_object.dmao_size,
		    dmareqp->dmar_object.dmao_obj.virt_obj.v_addr,
		    dmareqp->dmar_object.dmao_obj.virt_obj.v_as, sleep);
		return (*mapaddrp);
	}
}


/*
 * support routine - free off kernel virtual mapping as allocated by
 * ddi_dmareq_mapin()
 */
static void
ddi_dmareq_mapout(caddr_t addr, offset_t len, int map_flags, page_t *pp,
    page_t **pplist)
{
	struct buf buf;

	if (addr == NULL)
		return;
	/*
	 * mock up a buf structure
	 */
	buf.b_flags = B_REMAPPED | map_flags;
	buf.b_un.b_addr = addr;
	buf.b_bcount = (size_t)len;
	buf.b_pages = pp;
	buf.b_shadow = pplist;
	bp_mapout(&buf);
}

static time_t
bofi_gettime()
{
	timestruc_t ts;

	gethrestime(&ts);
	return (ts.tv_sec);
}

/*
 * reset the bus_ops structure of the specified nexus to point to
 * the original values in the save_bus_ops structure.
 *
 * Note that both this routine and modify_bus_ops() rely on the current
 * behavior of the framework in that nexus drivers are not unloadable
 *
 */

static int
reset_bus_ops(char *name, struct bus_ops *bop)
{
	struct modctl *modp;
	struct modldrv *mp;
	struct bus_ops *bp;
	struct dev_ops *ops;

	mutex_enter(&mod_lock);
	/*
	 * find specified module
	 */
	modp = &modules;
	do {
		if (strcmp(name, modp->mod_modname) == 0) {
			if (!modp->mod_linkage) {
				mutex_exit(&mod_lock);
				return (0);
			}
			mp = modp->mod_linkage->ml_linkage[0];
			if (!mp || !mp->drv_dev_ops) {
				mutex_exit(&mod_lock);
				return (0);
			}
			ops = mp->drv_dev_ops;
			bp = ops->devo_bus_ops;
			if (!bp) {
				mutex_exit(&mod_lock);
				return (0);
			}
			if (ops->devo_refcnt > 0) {
				/*
				 * As long as devices are active with modified
				 * bus ops bofi must not go away. There may be
				 * drivers with modified access or dma handles.
				 */
				mutex_exit(&mod_lock);
				return (0);
			}
			cmn_err(CE_NOTE, "bofi reset bus_ops for %s",
			    mp->drv_linkinfo);
			bp->bus_intr_op = bop->bus_intr_op;
			bp->bus_post_event = bop->bus_post_event;
			bp->bus_map = bop->bus_map;
			bp->bus_dma_map = bop->bus_dma_map;
			bp->bus_dma_allochdl = bop->bus_dma_allochdl;
			bp->bus_dma_freehdl = bop->bus_dma_freehdl;
			bp->bus_dma_bindhdl = bop->bus_dma_bindhdl;
			bp->bus_dma_unbindhdl = bop->bus_dma_unbindhdl;
			bp->bus_dma_flush = bop->bus_dma_flush;
			bp->bus_dma_win = bop->bus_dma_win;
			bp->bus_dma_ctl = bop->bus_dma_ctl;
			mutex_exit(&mod_lock);
			return (1);
		}
	} while ((modp = modp->mod_next) != &modules);
	mutex_exit(&mod_lock);
	return (0);
}

/*
 * modify the bus_ops structure of the specified nexus to point to bofi
 * routines, saving the original values in the save_bus_ops structure
 */

static int
modify_bus_ops(char *name, struct bus_ops *bop)
{
	struct modctl *modp;
	struct modldrv *mp;
	struct bus_ops *bp;
	struct dev_ops *ops;

	if (ddi_name_to_major(name) == -1)
		return (0);

	mutex_enter(&mod_lock);
	/*
	 * find specified module
	 */
	modp = &modules;
	do {
		if (strcmp(name, modp->mod_modname) == 0) {
			if (!modp->mod_linkage) {
				mutex_exit(&mod_lock);
				return (0);
			}
			mp = modp->mod_linkage->ml_linkage[0];
			if (!mp || !mp->drv_dev_ops) {
				mutex_exit(&mod_lock);
				return (0);
			}
			ops = mp->drv_dev_ops;
			bp = ops->devo_bus_ops;
			if (!bp) {
				mutex_exit(&mod_lock);
				return (0);
			}
			if (ops->devo_refcnt == 0) {
				/*
				 * If there is no device active for this
				 * module then there is nothing to do for bofi.
				 */
				mutex_exit(&mod_lock);
				return (0);
			}
			cmn_err(CE_NOTE, "bofi modify bus_ops for %s",
			    mp->drv_linkinfo);
			save_bus_ops = *bp;
			bp->bus_intr_op = bop->bus_intr_op;
			bp->bus_post_event = bop->bus_post_event;
			bp->bus_map = bop->bus_map;
			bp->bus_dma_map = bop->bus_dma_map;
			bp->bus_dma_allochdl = bop->bus_dma_allochdl;
			bp->bus_dma_freehdl = bop->bus_dma_freehdl;
			bp->bus_dma_bindhdl = bop->bus_dma_bindhdl;
			bp->bus_dma_unbindhdl = bop->bus_dma_unbindhdl;
			bp->bus_dma_flush = bop->bus_dma_flush;
			bp->bus_dma_win = bop->bus_dma_win;
			bp->bus_dma_ctl = bop->bus_dma_ctl;
			mutex_exit(&mod_lock);
			return (1);
		}
	} while ((modp = modp->mod_next) != &modules);
	mutex_exit(&mod_lock);
	return (0);
}


int
_init(void)
{
	int    e;

	e = ddi_soft_state_init(&statep, sizeof (struct bofi_errent), 1);
	if (e != 0)
		return (e);
	if ((e = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&statep);
	return (e);
}


int
_fini(void)
{
	int e;

	if ((e = mod_remove(&modlinkage)) != 0)
		return (e);
	ddi_soft_state_fini(&statep);
	return (e);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


static int
bofi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	char *name;
	char buf[80];
	int i;
	int s, ss;
	int size = NAMESIZE;
	int new_string;
	char *ptr;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);
	/*
	 * only one instance - but we clone using the open routine
	 */
	if (ddi_get_instance(dip) > 0)
		return (DDI_FAILURE);

	if (!initialized) {
		if ((name = ddi_get_name(dip)) == NULL)
			return (DDI_FAILURE);
		(void) snprintf(buf, sizeof (buf), "%s,ctl", name);
		if (ddi_create_minor_node(dip, buf, S_IFCHR, 0,
		    DDI_PSEUDO, 0) == DDI_FAILURE)
			return (DDI_FAILURE);

		if (ddi_get_soft_iblock_cookie(dip, DDI_SOFTINT_MED,
		    &bofi_low_cookie) != DDI_SUCCESS) {
			ddi_remove_minor_node(dip, buf);
			return (DDI_FAILURE); /* fail attach */
		}
		/*
		 * get nexus name (from conf file)
		 */
		if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN_AND_VAL_BUF, 0,
		    "bofi-nexus", nexus_name, &size) != DDI_PROP_SUCCESS) {
			ddi_remove_minor_node(dip, buf);
			return (DDI_FAILURE);
		}
		/*
		 * get whether to do dma map kmem private checking
		 */
		if ((bofi_range_check = ddi_prop_lookup_string(DDI_DEV_T_ANY,
		    dip, 0, "bofi-range-check", &ptr)) != DDI_PROP_SUCCESS)
			bofi_range_check = 0;
		else if (strcmp(ptr, "panic") == 0)
			bofi_range_check = 2;
		else if (strcmp(ptr, "warn") == 0)
			bofi_range_check = 1;
		else
			bofi_range_check = 0;
		ddi_prop_free(ptr);

		/*
		 * get whether to prevent direct access to register
		 */
		if ((bofi_ddi_check = ddi_prop_lookup_string(DDI_DEV_T_ANY,
		    dip, 0, "bofi-ddi-check", &ptr)) != DDI_PROP_SUCCESS)
			bofi_ddi_check = 0;
		else if (strcmp(ptr, "on") == 0)
			bofi_ddi_check = 1;
		else
			bofi_ddi_check = 0;
		ddi_prop_free(ptr);

		/*
		 * get whether to do copy on ddi_dma_sync
		 */
		if ((bofi_sync_check = ddi_prop_lookup_string(DDI_DEV_T_ANY,
		    dip, 0, "bofi-sync-check", &ptr)) != DDI_PROP_SUCCESS)
			bofi_sync_check = 0;
		else if (strcmp(ptr, "on") == 0)
			bofi_sync_check = 1;
		else
			bofi_sync_check = 0;
		ddi_prop_free(ptr);

		/*
		 * get driver-under-test names (from conf file)
		 */
		size = NAMESIZE;
		if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN_AND_VAL_BUF, 0,
		    "bofi-to-test", driver_list, &size) != DDI_PROP_SUCCESS)
			driver_list[0] = 0;
		/*
		 * and convert into a sequence of strings
		 */
		driver_list_neg = 1;
		new_string = 1;
		driver_list_size = strlen(driver_list);
		for (i = 0; i < driver_list_size; i++) {
			if (driver_list[i] == ' ') {
				driver_list[i] = '\0';
				new_string = 1;
			} else if (new_string) {
				if (driver_list[i] != '!')
					driver_list_neg = 0;
				new_string = 0;
			}
		}
		/*
		 * initialize mutex, lists
		 */
		mutex_init(&clone_tab_mutex, NULL, MUTEX_DRIVER,
		    NULL);
		/*
		 * fake up iblock cookie - need to protect outselves
		 * against drivers that use hilevel interrupts
		 */
		ss = spl8();
		s = spl8();
		splx(ss);
		mutex_init(&bofi_mutex, NULL, MUTEX_SPIN, (void *)(uintptr_t)s);
		mutex_init(&bofi_low_mutex, NULL, MUTEX_DRIVER,
		    (void *)bofi_low_cookie);
		shadow_list.next = &shadow_list;
		shadow_list.prev = &shadow_list;
		for (i = 0; i < HDL_HASH_TBL_SIZE; i++) {
			hhash_table[i].hnext = &hhash_table[i];
			hhash_table[i].hprev = &hhash_table[i];
			dhash_table[i].dnext = &dhash_table[i];
			dhash_table[i].dprev = &dhash_table[i];
		}
		for (i = 1; i < BOFI_NLINKS; i++)
			bofi_link_array[i].link = &bofi_link_array[i-1];
		bofi_link_freelist = &bofi_link_array[BOFI_NLINKS - 1];
		/*
		 * overlay bus_ops structure
		 */
		if (modify_bus_ops(nexus_name, &bofi_bus_ops) == 0) {
			ddi_remove_minor_node(dip, buf);
			mutex_destroy(&clone_tab_mutex);
			mutex_destroy(&bofi_mutex);
			mutex_destroy(&bofi_low_mutex);
			return (DDI_FAILURE);
		}
		if (sysevent_evc_bind(FM_ERROR_CHAN, &bofi_error_chan, 0) == 0)
			(void) sysevent_evc_subscribe(bofi_error_chan, "bofi",
			    EC_FM, bofi_fm_ereport_callback, NULL, 0);

		/*
		 * save dip for getinfo
		 */
		our_dip = dip;
		ddi_report_dev(dip);
		initialized = 1;
	}
	return (DDI_SUCCESS);
}


static int
bofi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	char *name;
	char buf[80];

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);
	if (ddi_get_instance(dip) > 0)
		return (DDI_FAILURE);
	if ((name = ddi_get_name(dip)) == NULL)
		return (DDI_FAILURE);
	(void) snprintf(buf, sizeof (buf), "%s,ctl", name);
	mutex_enter(&bofi_low_mutex);
	mutex_enter(&bofi_mutex);
	/*
	 * make sure test bofi is no longer in use
	 */
	if (shadow_list.next != &shadow_list || errent_listp != NULL) {
		mutex_exit(&bofi_mutex);
		mutex_exit(&bofi_low_mutex);
		return (DDI_FAILURE);
	}
	mutex_exit(&bofi_mutex);
	mutex_exit(&bofi_low_mutex);

	/*
	 * restore bus_ops structure
	 */
	if (reset_bus_ops(nexus_name, &save_bus_ops) == 0)
		return (DDI_FAILURE);

	(void) sysevent_evc_unbind(bofi_error_chan);

	mutex_destroy(&clone_tab_mutex);
	mutex_destroy(&bofi_mutex);
	mutex_destroy(&bofi_low_mutex);
	ddi_remove_minor_node(dip, buf);
	our_dip = NULL;
	initialized = 0;
	return (DDI_SUCCESS);
}


/* ARGSUSED */
static int
bofi_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	dev_t	dev = (dev_t)arg;
	int	minor = (int)getminor(dev);
	int	retval;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (minor != 0 || our_dip == NULL) {
			*result = (void *)NULL;
			retval = DDI_FAILURE;
		} else {
			*result = (void *)our_dip;
			retval = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		retval = DDI_SUCCESS;
		break;
	default:
		retval = DDI_FAILURE;
	}
	return (retval);
}


/* ARGSUSED */
static int
bofi_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	int	minor = (int)getminor(*devp);
	struct bofi_errent *softc;

	/*
	 * only allow open on minor=0 - the clone device
	 */
	if (minor != 0)
		return (ENXIO);
	/*
	 * fail if not attached
	 */
	if (!initialized)
		return (ENXIO);
	/*
	 * find a free slot and grab it
	 */
	mutex_enter(&clone_tab_mutex);
	for (minor = 1; minor < NCLONES; minor++) {
		if (clone_tab[minor] == 0) {
			clone_tab[minor] = 1;
			break;
		}
	}
	mutex_exit(&clone_tab_mutex);
	if (minor == NCLONES)
		return (EAGAIN);
	/*
	 * soft state structure for this clone is used to maintain a list
	 * of allocated errdefs so they can be freed on close
	 */
	if (ddi_soft_state_zalloc(statep, minor) != DDI_SUCCESS) {
		mutex_enter(&clone_tab_mutex);
		clone_tab[minor] = 0;
		mutex_exit(&clone_tab_mutex);
		return (EAGAIN);
	}
	softc = ddi_get_soft_state(statep, minor);
	softc->cnext = softc;
	softc->cprev = softc;

	*devp = makedevice(getmajor(*devp), minor);
	return (0);
}


/* ARGSUSED */
static int
bofi_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	int	minor = (int)getminor(dev);
	struct bofi_errent *softc;
	struct bofi_errent *ep, *next_ep;

	softc = ddi_get_soft_state(statep, minor);
	if (softc == NULL)
		return (ENXIO);
	/*
	 * find list of errdefs and free them off
	 */
	for (ep = softc->cnext; ep != softc; ) {
		next_ep = ep->cnext;
		(void) bofi_errdef_free(ep);
		ep = next_ep;
	}
	/*
	 * free clone tab slot
	 */
	mutex_enter(&clone_tab_mutex);
	clone_tab[minor] = 0;
	mutex_exit(&clone_tab_mutex);

	ddi_soft_state_free(statep, minor);
	return (0);
}


/* ARGSUSED */
static int
bofi_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	struct bofi_errent *softc;
	int	minor = (int)getminor(dev);
	struct bofi_errdef errdef;
	struct bofi_errctl errctl;
	struct bofi_errstate errstate;
	void *ed_handle;
	struct bofi_get_handles get_handles;
	struct bofi_get_hdl_info hdl_info;
	struct handle_info *hdlip;
	struct handle_info *hib;

	char *buffer;
	char *bufptr;
	char *endbuf;
	int req_count, count, err;
	char *namep;
	struct bofi_shadow *hp;
	int retval;
	struct bofi_shadow *hhashp;
	int i;

	switch (cmd) {
	case BOFI_ADD_DEF:
		/*
		 * add a new error definition
		 */
#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32:
		{
			/*
			 * For use when a 32 bit app makes a call into a
			 * 64 bit ioctl
			 */
			struct bofi_errdef32	errdef_32;

			if (ddi_copyin((void *)arg, &errdef_32,
			    sizeof (struct bofi_errdef32), mode)) {
				return (EFAULT);
			}
			errdef.namesize = errdef_32.namesize;
			(void) strncpy(errdef.name, errdef_32.name, NAMESIZE);
			errdef.instance = errdef_32.instance;
			errdef.rnumber = errdef_32.rnumber;
			errdef.offset = errdef_32.offset;
			errdef.len = errdef_32.len;
			errdef.access_type = errdef_32.access_type;
			errdef.access_count = errdef_32.access_count;
			errdef.fail_count = errdef_32.fail_count;
			errdef.acc_chk = errdef_32.acc_chk;
			errdef.optype = errdef_32.optype;
			errdef.operand = errdef_32.operand;
			errdef.log.logsize = errdef_32.log.logsize;
			errdef.log.entries = errdef_32.log.entries;
			errdef.log.flags = errdef_32.log.flags;
			errdef.log.wrapcnt = errdef_32.log.wrapcnt;
			errdef.log.start_time = errdef_32.log.start_time;
			errdef.log.stop_time = errdef_32.log.stop_time;
			errdef.log.logbase =
			    (caddr_t)(uintptr_t)errdef_32.log.logbase;
			errdef.errdef_handle = errdef_32.errdef_handle;
			break;
		}
		case DDI_MODEL_NONE:
			if (ddi_copyin((void *)arg, &errdef,
			    sizeof (struct bofi_errdef), mode))
				return (EFAULT);
			break;
		}
#else /* ! _MULTI_DATAMODEL */
		if (ddi_copyin((void *)arg, &errdef,
		    sizeof (struct bofi_errdef), mode) != 0)
			return (EFAULT);
#endif /* _MULTI_DATAMODEL */
		/*
		 * do some validation
		 */
		if (errdef.fail_count == 0)
			errdef.optype = 0;
		if (errdef.optype != 0) {
			if (errdef.access_type & BOFI_INTR &&
			    errdef.optype != BOFI_DELAY_INTR &&
			    errdef.optype != BOFI_LOSE_INTR &&
			    errdef.optype != BOFI_EXTRA_INTR)
				return (EINVAL);
			if ((errdef.access_type & (BOFI_DMA_RW|BOFI_PIO_R)) &&
			    errdef.optype == BOFI_NO_TRANSFER)
				return (EINVAL);
			if ((errdef.access_type & (BOFI_PIO_RW)) &&
			    errdef.optype != BOFI_EQUAL &&
			    errdef.optype != BOFI_OR &&
			    errdef.optype != BOFI_XOR &&
			    errdef.optype != BOFI_AND &&
			    errdef.optype != BOFI_NO_TRANSFER)
				return (EINVAL);
		}
		/*
		 * find softstate for this clone, so we can tag
		 * new errdef on to it
		 */
		softc = ddi_get_soft_state(statep, minor);
		if (softc == NULL)
			return (ENXIO);
		/*
		 * read in name
		 */
		if (errdef.namesize > NAMESIZE)
			return (EINVAL);
		namep = kmem_zalloc(errdef.namesize+1, KM_SLEEP);
		(void) strncpy(namep, errdef.name, errdef.namesize);

		if (bofi_errdef_alloc(&errdef, namep, softc) != DDI_SUCCESS) {
			(void) bofi_errdef_free((struct bofi_errent *)
			    (uintptr_t)errdef.errdef_handle);
			kmem_free(namep, errdef.namesize+1);
			return (EINVAL);
		}
		/*
		 * copy out errdef again, including filled in errdef_handle
		 */
#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32:
		{
			/*
			 * For use when a 32 bit app makes a call into a
			 * 64 bit ioctl
			 */
			struct bofi_errdef32	errdef_32;

			errdef_32.namesize = errdef.namesize;
			(void) strncpy(errdef_32.name, errdef.name, NAMESIZE);
			errdef_32.instance = errdef.instance;
			errdef_32.rnumber = errdef.rnumber;
			errdef_32.offset = errdef.offset;
			errdef_32.len = errdef.len;
			errdef_32.access_type = errdef.access_type;
			errdef_32.access_count = errdef.access_count;
			errdef_32.fail_count = errdef.fail_count;
			errdef_32.acc_chk = errdef.acc_chk;
			errdef_32.optype = errdef.optype;
			errdef_32.operand = errdef.operand;
			errdef_32.log.logsize = errdef.log.logsize;
			errdef_32.log.entries = errdef.log.entries;
			errdef_32.log.flags = errdef.log.flags;
			errdef_32.log.wrapcnt = errdef.log.wrapcnt;
			errdef_32.log.start_time = errdef.log.start_time;
			errdef_32.log.stop_time = errdef.log.stop_time;
			errdef_32.log.logbase =
			    (caddr32_t)(uintptr_t)errdef.log.logbase;
			errdef_32.errdef_handle = errdef.errdef_handle;
			if (ddi_copyout(&errdef_32, (void *)arg,
			    sizeof (struct bofi_errdef32), mode) != 0) {
				(void) bofi_errdef_free((struct bofi_errent *)
				    errdef.errdef_handle);
				kmem_free(namep, errdef.namesize+1);
				return (EFAULT);
			}
			break;
		}
		case DDI_MODEL_NONE:
			if (ddi_copyout(&errdef, (void *)arg,
			    sizeof (struct bofi_errdef), mode) != 0) {
				(void) bofi_errdef_free((struct bofi_errent *)
				    errdef.errdef_handle);
				kmem_free(namep, errdef.namesize+1);
				return (EFAULT);
			}
			break;
		}
#else /* ! _MULTI_DATAMODEL */
		if (ddi_copyout(&errdef, (void *)arg,
		    sizeof (struct bofi_errdef), mode) != 0) {
			(void) bofi_errdef_free((struct bofi_errent *)
			    (uintptr_t)errdef.errdef_handle);
			kmem_free(namep, errdef.namesize+1);
			return (EFAULT);
		}
#endif /* _MULTI_DATAMODEL */
		return (0);
	case BOFI_DEL_DEF:
		/*
		 * delete existing errdef
		 */
		if (ddi_copyin((void *)arg, &ed_handle,
		    sizeof (void *), mode) != 0)
			return (EFAULT);
		return (bofi_errdef_free((struct bofi_errent *)ed_handle));
	case BOFI_START:
		/*
		 * start all errdefs corresponding to
		 * this name and instance
		 */
		if (ddi_copyin((void *)arg, &errctl,
		    sizeof (struct bofi_errctl), mode) != 0)
			return (EFAULT);
		/*
		 * copy in name
		 */
		if (errctl.namesize > NAMESIZE)
			return (EINVAL);
		namep = kmem_zalloc(errctl.namesize+1, KM_SLEEP);
		(void) strncpy(namep, errctl.name, errctl.namesize);
		bofi_start(&errctl, namep);
		kmem_free(namep, errctl.namesize+1);
		return (0);
	case BOFI_STOP:
		/*
		 * stop all errdefs corresponding to
		 * this name and instance
		 */
		if (ddi_copyin((void *)arg, &errctl,
		    sizeof (struct bofi_errctl), mode) != 0)
			return (EFAULT);
		/*
		 * copy in name
		 */
		if (errctl.namesize > NAMESIZE)
			return (EINVAL);
		namep = kmem_zalloc(errctl.namesize+1, KM_SLEEP);
		(void) strncpy(namep, errctl.name, errctl.namesize);
		bofi_stop(&errctl, namep);
		kmem_free(namep, errctl.namesize+1);
		return (0);
	case BOFI_BROADCAST:
		/*
		 * wakeup all errdefs corresponding to
		 * this name and instance
		 */
		if (ddi_copyin((void *)arg, &errctl,
		    sizeof (struct bofi_errctl), mode) != 0)
			return (EFAULT);
		/*
		 * copy in name
		 */
		if (errctl.namesize > NAMESIZE)
			return (EINVAL);
		namep = kmem_zalloc(errctl.namesize+1, KM_SLEEP);
		(void) strncpy(namep, errctl.name, errctl.namesize);
		bofi_broadcast(&errctl, namep);
		kmem_free(namep, errctl.namesize+1);
		return (0);
	case BOFI_CLEAR_ACC_CHK:
		/*
		 * clear "acc_chk" for all errdefs corresponding to
		 * this name and instance
		 */
		if (ddi_copyin((void *)arg, &errctl,
		    sizeof (struct bofi_errctl), mode) != 0)
			return (EFAULT);
		/*
		 * copy in name
		 */
		if (errctl.namesize > NAMESIZE)
			return (EINVAL);
		namep = kmem_zalloc(errctl.namesize+1, KM_SLEEP);
		(void) strncpy(namep, errctl.name, errctl.namesize);
		bofi_clear_acc_chk(&errctl, namep);
		kmem_free(namep, errctl.namesize+1);
		return (0);
	case BOFI_CLEAR_ERRORS:
		/*
		 * set "fail_count" to 0 for all errdefs corresponding to
		 * this name and instance whose "access_count"
		 * has expired.
		 */
		if (ddi_copyin((void *)arg, &errctl,
		    sizeof (struct bofi_errctl), mode) != 0)
			return (EFAULT);
		/*
		 * copy in name
		 */
		if (errctl.namesize > NAMESIZE)
			return (EINVAL);
		namep = kmem_zalloc(errctl.namesize+1, KM_SLEEP);
		(void) strncpy(namep, errctl.name, errctl.namesize);
		bofi_clear_errors(&errctl, namep);
		kmem_free(namep, errctl.namesize+1);
		return (0);
	case BOFI_CLEAR_ERRDEFS:
		/*
		 * set "access_count" and "fail_count" to 0 for all errdefs
		 * corresponding to this name and instance
		 */
		if (ddi_copyin((void *)arg, &errctl,
		    sizeof (struct bofi_errctl), mode) != 0)
			return (EFAULT);
		/*
		 * copy in name
		 */
		if (errctl.namesize > NAMESIZE)
			return (EINVAL);
		namep = kmem_zalloc(errctl.namesize+1, KM_SLEEP);
		(void) strncpy(namep, errctl.name, errctl.namesize);
		bofi_clear_errdefs(&errctl, namep);
		kmem_free(namep, errctl.namesize+1);
		return (0);
	case BOFI_CHK_STATE:
	{
		struct acc_log_elem *klg;
		size_t uls;
		/*
		 * get state for this errdef - read in dummy errstate
		 * with just the errdef_handle filled in
		 */
#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32:
		{
			/*
			 * For use when a 32 bit app makes a call into a
			 * 64 bit ioctl
			 */
			struct bofi_errstate32	errstate_32;

			if (ddi_copyin((void *)arg, &errstate_32,
			    sizeof (struct bofi_errstate32), mode) != 0) {
				return (EFAULT);
			}
			errstate.fail_time = errstate_32.fail_time;
			errstate.msg_time = errstate_32.msg_time;
			errstate.access_count = errstate_32.access_count;
			errstate.fail_count = errstate_32.fail_count;
			errstate.acc_chk = errstate_32.acc_chk;
			errstate.errmsg_count = errstate_32.errmsg_count;
			(void) strncpy(errstate.buffer, errstate_32.buffer,
			    ERRMSGSIZE);
			errstate.severity = errstate_32.severity;
			errstate.log.logsize = errstate_32.log.logsize;
			errstate.log.entries = errstate_32.log.entries;
			errstate.log.flags = errstate_32.log.flags;
			errstate.log.wrapcnt = errstate_32.log.wrapcnt;
			errstate.log.start_time = errstate_32.log.start_time;
			errstate.log.stop_time = errstate_32.log.stop_time;
			errstate.log.logbase =
			    (caddr_t)(uintptr_t)errstate_32.log.logbase;
			errstate.errdef_handle = errstate_32.errdef_handle;
			break;
		}
		case DDI_MODEL_NONE:
			if (ddi_copyin((void *)arg, &errstate,
			    sizeof (struct bofi_errstate), mode) != 0)
				return (EFAULT);
			break;
		}
#else /* ! _MULTI_DATAMODEL */
		if (ddi_copyin((void *)arg, &errstate,
		    sizeof (struct bofi_errstate), mode) != 0)
			return (EFAULT);
#endif /* _MULTI_DATAMODEL */
		if ((retval = bofi_errdef_check(&errstate, &klg)) == EINVAL)
			return (EINVAL);
		/*
		 * copy out real errstate structure
		 */
		uls = errstate.log.logsize;
		if (errstate.log.entries > uls && uls)
			/* insufficient user memory */
			errstate.log.entries = uls;
		/* always pass back a time */
		if (errstate.log.stop_time == 0ul)
			(void) drv_getparm(TIME, &(errstate.log.stop_time));

#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32:
		{
			/*
			 * For use when a 32 bit app makes a call into a
			 * 64 bit ioctl
			 */
			struct bofi_errstate32	errstate_32;

			errstate_32.fail_time = errstate.fail_time;
			errstate_32.msg_time = errstate.msg_time;
			errstate_32.access_count = errstate.access_count;
			errstate_32.fail_count = errstate.fail_count;
			errstate_32.acc_chk = errstate.acc_chk;
			errstate_32.errmsg_count = errstate.errmsg_count;
			(void) strncpy(errstate_32.buffer, errstate.buffer,
			    ERRMSGSIZE);
			errstate_32.severity = errstate.severity;
			errstate_32.log.logsize = errstate.log.logsize;
			errstate_32.log.entries = errstate.log.entries;
			errstate_32.log.flags = errstate.log.flags;
			errstate_32.log.wrapcnt = errstate.log.wrapcnt;
			errstate_32.log.start_time = errstate.log.start_time;
			errstate_32.log.stop_time = errstate.log.stop_time;
			errstate_32.log.logbase =
			    (caddr32_t)(uintptr_t)errstate.log.logbase;
			errstate_32.errdef_handle = errstate.errdef_handle;
			if (ddi_copyout(&errstate_32, (void *)arg,
			    sizeof (struct bofi_errstate32), mode) != 0)
				return (EFAULT);
			break;
		}
		case DDI_MODEL_NONE:
			if (ddi_copyout(&errstate, (void *)arg,
			    sizeof (struct bofi_errstate), mode) != 0)
				return (EFAULT);
			break;
		}
#else /* ! _MULTI_DATAMODEL */
		if (ddi_copyout(&errstate, (void *)arg,
		    sizeof (struct bofi_errstate), mode) != 0)
			return (EFAULT);
#endif /* _MULTI_DATAMODEL */
		if (uls && errstate.log.entries &&
		    ddi_copyout(klg, errstate.log.logbase,
		    errstate.log.entries * sizeof (struct acc_log_elem),
		    mode) != 0) {
			return (EFAULT);
		}
		return (retval);
	}
	case BOFI_CHK_STATE_W:
	{
		struct acc_log_elem *klg;
		size_t uls;
		/*
		 * get state for this errdef - read in dummy errstate
		 * with just the errdef_handle filled in. Then wait for
		 * a ddi_report_fault message to come back
		 */
#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32:
		{
			/*
			 * For use when a 32 bit app makes a call into a
			 * 64 bit ioctl
			 */
			struct bofi_errstate32	errstate_32;

			if (ddi_copyin((void *)arg, &errstate_32,
			    sizeof (struct bofi_errstate32), mode) != 0) {
				return (EFAULT);
			}
			errstate.fail_time = errstate_32.fail_time;
			errstate.msg_time = errstate_32.msg_time;
			errstate.access_count = errstate_32.access_count;
			errstate.fail_count = errstate_32.fail_count;
			errstate.acc_chk = errstate_32.acc_chk;
			errstate.errmsg_count = errstate_32.errmsg_count;
			(void) strncpy(errstate.buffer, errstate_32.buffer,
			    ERRMSGSIZE);
			errstate.severity = errstate_32.severity;
			errstate.log.logsize = errstate_32.log.logsize;
			errstate.log.entries = errstate_32.log.entries;
			errstate.log.flags = errstate_32.log.flags;
			errstate.log.wrapcnt = errstate_32.log.wrapcnt;
			errstate.log.start_time = errstate_32.log.start_time;
			errstate.log.stop_time = errstate_32.log.stop_time;
			errstate.log.logbase =
			    (caddr_t)(uintptr_t)errstate_32.log.logbase;
			errstate.errdef_handle = errstate_32.errdef_handle;
			break;
		}
		case DDI_MODEL_NONE:
			if (ddi_copyin((void *)arg, &errstate,
			    sizeof (struct bofi_errstate), mode) != 0)
				return (EFAULT);
			break;
		}
#else /* ! _MULTI_DATAMODEL */
		if (ddi_copyin((void *)arg, &errstate,
		    sizeof (struct bofi_errstate), mode) != 0)
			return (EFAULT);
#endif /* _MULTI_DATAMODEL */
		if ((retval = bofi_errdef_check_w(&errstate, &klg)) == EINVAL)
			return (EINVAL);
		/*
		 * copy out real errstate structure
		 */
		uls = errstate.log.logsize;
		uls = errstate.log.logsize;
		if (errstate.log.entries > uls && uls)
			/* insufficient user memory */
			errstate.log.entries = uls;
		/* always pass back a time */
		if (errstate.log.stop_time == 0ul)
			(void) drv_getparm(TIME, &(errstate.log.stop_time));

#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32:
		{
			/*
			 * For use when a 32 bit app makes a call into a
			 * 64 bit ioctl
			 */
			struct bofi_errstate32	errstate_32;

			errstate_32.fail_time = errstate.fail_time;
			errstate_32.msg_time = errstate.msg_time;
			errstate_32.access_count = errstate.access_count;
			errstate_32.fail_count = errstate.fail_count;
			errstate_32.acc_chk = errstate.acc_chk;
			errstate_32.errmsg_count = errstate.errmsg_count;
			(void) strncpy(errstate_32.buffer, errstate.buffer,
			    ERRMSGSIZE);
			errstate_32.severity = errstate.severity;
			errstate_32.log.logsize = errstate.log.logsize;
			errstate_32.log.entries = errstate.log.entries;
			errstate_32.log.flags = errstate.log.flags;
			errstate_32.log.wrapcnt = errstate.log.wrapcnt;
			errstate_32.log.start_time = errstate.log.start_time;
			errstate_32.log.stop_time = errstate.log.stop_time;
			errstate_32.log.logbase =
			    (caddr32_t)(uintptr_t)errstate.log.logbase;
			errstate_32.errdef_handle = errstate.errdef_handle;
			if (ddi_copyout(&errstate_32, (void *)arg,
			    sizeof (struct bofi_errstate32), mode) != 0)
				return (EFAULT);
			break;
		}
		case DDI_MODEL_NONE:
			if (ddi_copyout(&errstate, (void *)arg,
			    sizeof (struct bofi_errstate), mode) != 0)
				return (EFAULT);
			break;
		}
#else /* ! _MULTI_DATAMODEL */
		if (ddi_copyout(&errstate, (void *)arg,
		    sizeof (struct bofi_errstate), mode) != 0)
			return (EFAULT);
#endif /* _MULTI_DATAMODEL */

		if (uls && errstate.log.entries &&
		    ddi_copyout(klg, errstate.log.logbase,
		    errstate.log.entries * sizeof (struct acc_log_elem),
		    mode) != 0) {
			return (EFAULT);
		}
		return (retval);
	}
	case BOFI_GET_HANDLES:
		/*
		 * display existing handles
		 */
#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32:
		{
			/*
			 * For use when a 32 bit app makes a call into a
			 * 64 bit ioctl
			 */
			struct bofi_get_handles32	get_handles_32;

			if (ddi_copyin((void *)arg, &get_handles_32,
			    sizeof (get_handles_32), mode) != 0) {
				return (EFAULT);
			}
			get_handles.namesize = get_handles_32.namesize;
			(void) strncpy(get_handles.name, get_handles_32.name,
			    NAMESIZE);
			get_handles.instance = get_handles_32.instance;
			get_handles.count = get_handles_32.count;
			get_handles.buffer =
			    (caddr_t)(uintptr_t)get_handles_32.buffer;
			break;
		}
		case DDI_MODEL_NONE:
			if (ddi_copyin((void *)arg, &get_handles,
			    sizeof (get_handles), mode) != 0)
				return (EFAULT);
			break;
		}
#else /* ! _MULTI_DATAMODEL */
		if (ddi_copyin((void *)arg, &get_handles,
		    sizeof (get_handles), mode) != 0)
			return (EFAULT);
#endif /* _MULTI_DATAMODEL */
		/*
		 * read in name
		 */
		if (get_handles.namesize > NAMESIZE)
			return (EINVAL);
		namep = kmem_zalloc(get_handles.namesize+1, KM_SLEEP);
		(void) strncpy(namep, get_handles.name, get_handles.namesize);
		req_count = get_handles.count;
		bufptr = buffer = kmem_zalloc(req_count, KM_SLEEP);
		endbuf = bufptr + req_count;
		/*
		 * display existing handles
		 */
		mutex_enter(&bofi_low_mutex);
		mutex_enter(&bofi_mutex);
		for (i = 0; i < HDL_HASH_TBL_SIZE; i++) {
			hhashp = &hhash_table[i];
			for (hp = hhashp->hnext; hp != hhashp; hp = hp->hnext) {
				if (!driver_under_test(hp->dip))
					continue;
				if (ddi_name_to_major(ddi_get_name(hp->dip)) !=
				    ddi_name_to_major(namep))
					continue;
				if (hp->instance != get_handles.instance)
					continue;
				/*
				 * print information per handle - note that
				 * DMA* means an unbound DMA handle
				 */
				(void) snprintf(bufptr, (size_t)(endbuf-bufptr),
				    "  %s %d %s ", hp->name, hp->instance,
				    (hp->type == BOFI_INT_HDL) ? "INTR" :
				    (hp->type == BOFI_ACC_HDL) ? "PIO" :
				    (hp->type == BOFI_DMA_HDL) ? "DMA" :
				    (hp->hparrayp != NULL) ? "DVMA" : "DMA*");
				bufptr += strlen(bufptr);
				if (hp->type == BOFI_ACC_HDL) {
					if (hp->len == INT_MAX - hp->offset)
						(void) snprintf(bufptr,
						    (size_t)(endbuf-bufptr),
						    "reg set %d off 0x%llx\n",
						    hp->rnumber, hp->offset);
					else
						(void) snprintf(bufptr,
						    (size_t)(endbuf-bufptr),
						    "reg set %d off 0x%llx"
						    " len 0x%llx\n",
						    hp->rnumber, hp->offset,
						    hp->len);
				} else if (hp->type == BOFI_DMA_HDL)
					(void) snprintf(bufptr,
					    (size_t)(endbuf-bufptr),
					    "handle no %d len 0x%llx"
					    " addr 0x%p\n", hp->rnumber,
					    hp->len, (void *)hp->addr);
				else if (hp->type == BOFI_NULL &&
				    hp->hparrayp == NULL)
					(void) snprintf(bufptr,
					    (size_t)(endbuf-bufptr),
					    "handle no %d\n", hp->rnumber);
				else
					(void) snprintf(bufptr,
					    (size_t)(endbuf-bufptr), "\n");
				bufptr += strlen(bufptr);
			}
		}
		mutex_exit(&bofi_mutex);
		mutex_exit(&bofi_low_mutex);
		err = ddi_copyout(buffer, get_handles.buffer, req_count, mode);
		kmem_free(namep, get_handles.namesize+1);
		kmem_free(buffer, req_count);
		if (err != 0)
			return (EFAULT);
		else
			return (0);
	case BOFI_GET_HANDLE_INFO:
		/*
		 * display existing handles
		 */
#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32:
		{
			/*
			 * For use when a 32 bit app makes a call into a
			 * 64 bit ioctl
			 */
			struct bofi_get_hdl_info32	hdl_info_32;

			if (ddi_copyin((void *)arg, &hdl_info_32,
			    sizeof (hdl_info_32), mode)) {
				return (EFAULT);
			}
			hdl_info.namesize = hdl_info_32.namesize;
			(void) strncpy(hdl_info.name, hdl_info_32.name,
			    NAMESIZE);
			hdl_info.count = hdl_info_32.count;
			hdl_info.hdli = (caddr_t)(uintptr_t)hdl_info_32.hdli;
			break;
		}
		case DDI_MODEL_NONE:
			if (ddi_copyin((void *)arg, &hdl_info,
			    sizeof (hdl_info), mode))
				return (EFAULT);
			break;
		}
#else /* ! _MULTI_DATAMODEL */
		if (ddi_copyin((void *)arg, &hdl_info,
		    sizeof (hdl_info), mode))
			return (EFAULT);
#endif /* _MULTI_DATAMODEL */
		if (hdl_info.namesize > NAMESIZE)
			return (EINVAL);
		namep = kmem_zalloc(hdl_info.namesize + 1, KM_SLEEP);
		(void) strncpy(namep, hdl_info.name, hdl_info.namesize);
		req_count = hdl_info.count;
		count = hdl_info.count = 0; /* the actual no of handles */
		if (req_count > 0) {
			hib = hdlip =
			    kmem_zalloc(req_count * sizeof (struct handle_info),
			    KM_SLEEP);
		} else {
			hib = hdlip = 0;
			req_count = hdl_info.count = 0;
		}

		/*
		 * display existing handles
		 */
		mutex_enter(&bofi_low_mutex);
		mutex_enter(&bofi_mutex);
		for (i = 0; i < HDL_HASH_TBL_SIZE; i++) {
			hhashp = &hhash_table[i];
			for (hp = hhashp->hnext; hp != hhashp; hp = hp->hnext) {
				if (!driver_under_test(hp->dip) ||
				    ddi_name_to_major(ddi_get_name(hp->dip)) !=
				    ddi_name_to_major(namep) ||
				    ++(hdl_info.count) > req_count ||
				    count == req_count)
					continue;

				hdlip->instance = hp->instance;
				hdlip->rnumber = hp->rnumber;
				switch (hp->type) {
				case BOFI_ACC_HDL:
					hdlip->access_type = BOFI_PIO_RW;
					hdlip->offset = hp->offset;
					hdlip->len = hp->len;
					break;
				case BOFI_DMA_HDL:
					hdlip->access_type = 0;
					if (hp->flags & DDI_DMA_WRITE)
						hdlip->access_type |=
						    BOFI_DMA_W;
					if (hp->flags & DDI_DMA_READ)
						hdlip->access_type |=
						    BOFI_DMA_R;
					hdlip->len = hp->len;
					hdlip->addr_cookie =
					    (uint64_t)(uintptr_t)hp->addr;
					break;
				case BOFI_INT_HDL:
					hdlip->access_type = BOFI_INTR;
					break;
				default:
					hdlip->access_type = 0;
					break;
				}
				hdlip++;
				count++;
			}
		}
		mutex_exit(&bofi_mutex);
		mutex_exit(&bofi_low_mutex);
		err = 0;
#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32:
		{
			/*
			 * For use when a 32 bit app makes a call into a
			 * 64 bit ioctl
			 */
			struct bofi_get_hdl_info32	hdl_info_32;

			hdl_info_32.namesize = hdl_info.namesize;
			(void) strncpy(hdl_info_32.name, hdl_info.name,
			    NAMESIZE);
			hdl_info_32.count = hdl_info.count;
			hdl_info_32.hdli = (caddr32_t)(uintptr_t)hdl_info.hdli;
			if (ddi_copyout(&hdl_info_32, (void *)arg,
			    sizeof (hdl_info_32), mode) != 0) {
				kmem_free(namep, hdl_info.namesize+1);
				if (req_count > 0)
					kmem_free(hib,
					    req_count * sizeof (*hib));
				return (EFAULT);
			}
			break;
		}
		case DDI_MODEL_NONE:
			if (ddi_copyout(&hdl_info, (void *)arg,
			    sizeof (hdl_info), mode) != 0) {
				kmem_free(namep, hdl_info.namesize+1);
				if (req_count > 0)
					kmem_free(hib,
					    req_count * sizeof (*hib));
				return (EFAULT);
			}
			break;
		}
#else /* ! _MULTI_DATAMODEL */
		if (ddi_copyout(&hdl_info, (void *)arg,
		    sizeof (hdl_info), mode) != 0) {
			kmem_free(namep, hdl_info.namesize+1);
			if (req_count > 0)
				kmem_free(hib, req_count * sizeof (*hib));
			return (EFAULT);
		}
#endif /* ! _MULTI_DATAMODEL */
		if (count > 0) {
			if (ddi_copyout(hib, hdl_info.hdli,
			    count * sizeof (*hib), mode) != 0) {
				kmem_free(namep, hdl_info.namesize+1);
				if (req_count > 0)
					kmem_free(hib,
					    req_count * sizeof (*hib));
				return (EFAULT);
			}
		}
		kmem_free(namep, hdl_info.namesize+1);
		if (req_count > 0)
			kmem_free(hib, req_count * sizeof (*hib));
		return (err);
	default:
		return (ENOTTY);
	}
}


/*
 * add a new error definition
 */
static int
bofi_errdef_alloc(struct bofi_errdef *errdefp, char *namep,
    struct bofi_errent *softc)
{
	struct bofi_errent *ep;
	struct bofi_shadow *hp;
	struct bofi_link   *lp;

	/*
	 * allocate errdef structure and put on in-use list
	 */
	ep = kmem_zalloc(sizeof (struct bofi_errent), KM_SLEEP);
	ep->errdef = *errdefp;
	ep->name = namep;
	ep->errdef.errdef_handle = (uint64_t)(uintptr_t)ep;
	ep->errstate.severity = DDI_SERVICE_RESTORED;
	ep->errstate.errdef_handle = (uint64_t)(uintptr_t)ep;
	cv_init(&ep->cv, NULL, CV_DRIVER, NULL);
	/*
	 * allocate space for logging
	 */
	ep->errdef.log.entries = 0;
	ep->errdef.log.wrapcnt = 0;
	if (ep->errdef.access_type & BOFI_LOG)
		ep->logbase = kmem_alloc(sizeof (struct acc_log_elem) *
		    ep->errdef.log.logsize, KM_SLEEP);
	else
		ep->logbase = NULL;
	/*
	 * put on in-use list
	 */
	mutex_enter(&bofi_low_mutex);
	mutex_enter(&bofi_mutex);
	ep->next = errent_listp;
	errent_listp = ep;
	/*
	 * and add it to the per-clone list
	 */
	ep->cnext = softc->cnext;
	softc->cnext->cprev = ep;
	ep->cprev = softc;
	softc->cnext = ep;

	/*
	 * look for corresponding shadow handle structures and if we find any
	 * tag this errdef structure on to their link lists.
	 */
	for (hp = shadow_list.next; hp != &shadow_list; hp = hp->next) {
		if (ddi_name_to_major(hp->name) == ddi_name_to_major(namep) &&
		    hp->instance == errdefp->instance &&
		    (((errdefp->access_type & BOFI_DMA_RW) &&
		    (ep->errdef.rnumber == -1 ||
		    hp->rnumber == ep->errdef.rnumber) &&
		    hp->type == BOFI_DMA_HDL &&
		    (((uintptr_t)(hp->addr + ep->errdef.offset +
		    ep->errdef.len) & ~LLSZMASK) >
		    ((uintptr_t)((hp->addr + ep->errdef.offset) +
		    LLSZMASK) & ~LLSZMASK))) ||
		    ((errdefp->access_type & BOFI_INTR) &&
		    hp->type == BOFI_INT_HDL) ||
		    ((errdefp->access_type & BOFI_PIO_RW) &&
		    hp->type == BOFI_ACC_HDL &&
		    (errdefp->rnumber == -1 ||
		    hp->rnumber == errdefp->rnumber) &&
		    (errdefp->len == 0 ||
		    hp->offset < errdefp->offset + errdefp->len) &&
		    hp->offset + hp->len > errdefp->offset))) {
			lp = bofi_link_freelist;
			if (lp != NULL) {
				bofi_link_freelist = lp->link;
				lp->errentp = ep;
				lp->link = hp->link;
				hp->link = lp;
			}
		}
	}
	errdefp->errdef_handle = (uint64_t)(uintptr_t)ep;
	mutex_exit(&bofi_mutex);
	mutex_exit(&bofi_low_mutex);
	ep->softintr_id = NULL;
	return (ddi_add_softintr(our_dip, DDI_SOFTINT_MED, &ep->softintr_id,
	    NULL, NULL, bofi_signal, (caddr_t)&ep->errdef));
}


/*
 * delete existing errdef
 */
static int
bofi_errdef_free(struct bofi_errent *ep)
{
	struct bofi_errent *hep, *prev_hep;
	struct bofi_link *lp, *prev_lp, *next_lp;
	struct bofi_shadow *hp;

	mutex_enter(&bofi_low_mutex);
	mutex_enter(&bofi_mutex);
	/*
	 * don't just assume its a valid ep - check that its on the
	 * in-use list
	 */
	prev_hep = NULL;
	for (hep = errent_listp; hep != NULL; ) {
		if (hep == ep)
			break;
		prev_hep = hep;
		hep = hep->next;
	}
	if (hep == NULL) {
		mutex_exit(&bofi_mutex);
		mutex_exit(&bofi_low_mutex);
		return (EINVAL);
	}
	/*
	 * found it - delete from in-use list
	 */

	if (prev_hep)
		prev_hep->next = hep->next;
	else
		errent_listp = hep->next;
	/*
	 * and take it off the per-clone list
	 */
	hep->cnext->cprev = hep->cprev;
	hep->cprev->cnext = hep->cnext;
	/*
	 * see if we are on any shadow handle link lists - and if we
	 * are then take us off
	 */
	for (hp = shadow_list.next; hp != &shadow_list; hp = hp->next) {
		prev_lp = NULL;
		for (lp = hp->link; lp != NULL; ) {
			if (lp->errentp == ep) {
				if (prev_lp)
					prev_lp->link = lp->link;
				else
					hp->link = lp->link;
				next_lp = lp->link;
				lp->link = bofi_link_freelist;
				bofi_link_freelist = lp;
				lp = next_lp;
			} else {
				prev_lp = lp;
				lp = lp->link;
			}
		}
	}
	mutex_exit(&bofi_mutex);
	mutex_exit(&bofi_low_mutex);

	cv_destroy(&ep->cv);
	kmem_free(ep->name, ep->errdef.namesize+1);
	if ((ep->errdef.access_type & BOFI_LOG) &&
	    ep->errdef.log.logsize && ep->logbase) /* double check */
		kmem_free(ep->logbase,
		    sizeof (struct acc_log_elem) * ep->errdef.log.logsize);

	if (ep->softintr_id)
		ddi_remove_softintr(ep->softintr_id);
	kmem_free(ep, sizeof (struct bofi_errent));
	return (0);
}


/*
 * start all errdefs corresponding to this name and instance
 */
static void
bofi_start(struct bofi_errctl *errctlp, char *namep)
{
	struct bofi_errent *ep;

	/*
	 * look for any errdefs with matching name and instance
	 */
	mutex_enter(&bofi_low_mutex);
	for (ep = errent_listp; ep != NULL; ep = ep->next)
		if (strncmp(namep, ep->name, NAMESIZE) == 0 &&
		    errctlp->instance == ep->errdef.instance) {
			ep->state |= BOFI_DEV_ACTIVE;
			(void) drv_getparm(TIME, &(ep->errdef.log.start_time));
			ep->errdef.log.stop_time = 0ul;
		}
	mutex_exit(&bofi_low_mutex);
}


/*
 * stop all errdefs corresponding to this name and instance
 */
static void
bofi_stop(struct bofi_errctl *errctlp, char *namep)
{
	struct bofi_errent *ep;

	/*
	 * look for any errdefs with matching name and instance
	 */
	mutex_enter(&bofi_low_mutex);
	for (ep = errent_listp; ep != NULL; ep = ep->next)
		if (strncmp(namep, ep->name, NAMESIZE) == 0 &&
		    errctlp->instance == ep->errdef.instance) {
			ep->state &= ~BOFI_DEV_ACTIVE;
			if (ep->errdef.log.stop_time == 0ul)
				(void) drv_getparm(TIME,
				    &(ep->errdef.log.stop_time));
		}
	mutex_exit(&bofi_low_mutex);
}


/*
 * wake up any thread waiting on this errdefs
 */
static uint_t
bofi_signal(caddr_t arg)
{
	struct bofi_errdef *edp = (struct bofi_errdef *)arg;
	struct bofi_errent *hep;
	struct bofi_errent *ep =
	    (struct bofi_errent *)(uintptr_t)edp->errdef_handle;

	mutex_enter(&bofi_low_mutex);
	for (hep = errent_listp; hep != NULL; ) {
		if (hep == ep)
			break;
		hep = hep->next;
	}
	if (hep == NULL) {
		mutex_exit(&bofi_low_mutex);
		return (DDI_INTR_UNCLAIMED);
	}
	if ((ep->errdef.access_type & BOFI_LOG) &&
	    (edp->log.flags & BOFI_LOG_FULL)) {
		edp->log.stop_time = bofi_gettime();
		ep->state |= BOFI_NEW_MESSAGE;
		if (ep->state & BOFI_MESSAGE_WAIT)
			cv_broadcast(&ep->cv);
		ep->state &= ~BOFI_MESSAGE_WAIT;
	}
	if (ep->errstate.msg_time != 0) {
		ep->state |= BOFI_NEW_MESSAGE;
		if (ep->state & BOFI_MESSAGE_WAIT)
			cv_broadcast(&ep->cv);
		ep->state &= ~BOFI_MESSAGE_WAIT;
	}
	mutex_exit(&bofi_low_mutex);
	return (DDI_INTR_CLAIMED);
}


/*
 * wake up all errdefs corresponding to this name and instance
 */
static void
bofi_broadcast(struct bofi_errctl *errctlp, char *namep)
{
	struct bofi_errent *ep;

	/*
	 * look for any errdefs with matching name and instance
	 */
	mutex_enter(&bofi_low_mutex);
	for (ep = errent_listp; ep != NULL; ep = ep->next)
		if (strncmp(namep, ep->name, NAMESIZE) == 0 &&
		    errctlp->instance == ep->errdef.instance) {
			/*
			 * wake up sleepers
			 */
			ep->state |= BOFI_NEW_MESSAGE;
			if (ep->state & BOFI_MESSAGE_WAIT)
				cv_broadcast(&ep->cv);
			ep->state &= ~BOFI_MESSAGE_WAIT;
		}
	mutex_exit(&bofi_low_mutex);
}


/*
 * clear "acc_chk" for all errdefs corresponding to this name and instance
 * and wake them up.
 */
static void
bofi_clear_acc_chk(struct bofi_errctl *errctlp, char *namep)
{
	struct bofi_errent *ep;

	/*
	 * look for any errdefs with matching name and instance
	 */
	mutex_enter(&bofi_low_mutex);
	for (ep = errent_listp; ep != NULL; ep = ep->next)
		if (strncmp(namep, ep->name, NAMESIZE) == 0 &&
		    errctlp->instance == ep->errdef.instance) {
			mutex_enter(&bofi_mutex);
			if (ep->errdef.access_count == 0 &&
			    ep->errdef.fail_count == 0)
				ep->errdef.acc_chk = 0;
			mutex_exit(&bofi_mutex);
			/*
			 * wake up sleepers
			 */
			ep->state |= BOFI_NEW_MESSAGE;
			if (ep->state & BOFI_MESSAGE_WAIT)
				cv_broadcast(&ep->cv);
			ep->state &= ~BOFI_MESSAGE_WAIT;
		}
	mutex_exit(&bofi_low_mutex);
}


/*
 * set "fail_count" to 0 for all errdefs corresponding to this name and instance
 * whose "access_count" has expired, set "acc_chk" to 0 and wake them up.
 */
static void
bofi_clear_errors(struct bofi_errctl *errctlp, char *namep)
{
	struct bofi_errent *ep;

	/*
	 * look for any errdefs with matching name and instance
	 */
	mutex_enter(&bofi_low_mutex);
	for (ep = errent_listp; ep != NULL; ep = ep->next)
		if (strncmp(namep, ep->name, NAMESIZE) == 0 &&
		    errctlp->instance == ep->errdef.instance) {
			mutex_enter(&bofi_mutex);
			if (ep->errdef.access_count == 0) {
				ep->errdef.acc_chk = 0;
				ep->errdef.fail_count = 0;
				mutex_exit(&bofi_mutex);
				if (ep->errdef.log.stop_time == 0ul)
					(void) drv_getparm(TIME,
					    &(ep->errdef.log.stop_time));
			} else
				mutex_exit(&bofi_mutex);
			/*
			 * wake up sleepers
			 */
			ep->state |= BOFI_NEW_MESSAGE;
			if (ep->state & BOFI_MESSAGE_WAIT)
				cv_broadcast(&ep->cv);
			ep->state &= ~BOFI_MESSAGE_WAIT;
		}
	mutex_exit(&bofi_low_mutex);
}


/*
 * set "access_count" and "fail_count" to 0 for all errdefs corresponding to
 * this name and instance, set "acc_chk" to 0, and wake them up.
 */
static void
bofi_clear_errdefs(struct bofi_errctl *errctlp, char *namep)
{
	struct bofi_errent *ep;

	/*
	 * look for any errdefs with matching name and instance
	 */
	mutex_enter(&bofi_low_mutex);
	for (ep = errent_listp; ep != NULL; ep = ep->next)
		if (strncmp(namep, ep->name, NAMESIZE) == 0 &&
		    errctlp->instance == ep->errdef.instance) {
			mutex_enter(&bofi_mutex);
			ep->errdef.acc_chk = 0;
			ep->errdef.access_count = 0;
			ep->errdef.fail_count = 0;
			mutex_exit(&bofi_mutex);
			if (ep->errdef.log.stop_time == 0ul)
				(void) drv_getparm(TIME,
				    &(ep->errdef.log.stop_time));
			/*
			 * wake up sleepers
			 */
			ep->state |= BOFI_NEW_MESSAGE;
			if (ep->state & BOFI_MESSAGE_WAIT)
				cv_broadcast(&ep->cv);
			ep->state &= ~BOFI_MESSAGE_WAIT;
		}
	mutex_exit(&bofi_low_mutex);
}


/*
 * get state for this errdef
 */
static int
bofi_errdef_check(struct bofi_errstate *errstatep, struct acc_log_elem **logpp)
{
	struct bofi_errent *hep;
	struct bofi_errent *ep;

	ep = (struct bofi_errent *)(uintptr_t)errstatep->errdef_handle;
	mutex_enter(&bofi_low_mutex);
	/*
	 * don't just assume its a valid ep - check that its on the
	 * in-use list
	 */
	for (hep = errent_listp; hep != NULL; hep = hep->next)
		if (hep == ep)
			break;
	if (hep == NULL) {
		mutex_exit(&bofi_low_mutex);
		return (EINVAL);
	}
	mutex_enter(&bofi_mutex);
	ep->errstate.access_count = ep->errdef.access_count;
	ep->errstate.fail_count = ep->errdef.fail_count;
	ep->errstate.acc_chk = ep->errdef.acc_chk;
	ep->errstate.log = ep->errdef.log;
	*logpp = ep->logbase;
	*errstatep = ep->errstate;
	mutex_exit(&bofi_mutex);
	mutex_exit(&bofi_low_mutex);
	return (0);
}


/*
 * Wait for a ddi_report_fault message to come back for this errdef
 * Then return state for this errdef.
 * fault report is intercepted by bofi_post_event, which triggers
 * bofi_signal via a softint, which will wake up this routine if
 * we are waiting
 */
static int
bofi_errdef_check_w(struct bofi_errstate *errstatep,
    struct acc_log_elem **logpp)
{
	struct bofi_errent *hep;
	struct bofi_errent *ep;
	int rval = 0;

	ep = (struct bofi_errent *)(uintptr_t)errstatep->errdef_handle;
	mutex_enter(&bofi_low_mutex);
retry:
	/*
	 * don't just assume its a valid ep - check that its on the
	 * in-use list
	 */
	for (hep = errent_listp; hep != NULL; hep = hep->next)
		if (hep == ep)
			break;
	if (hep == NULL) {
		mutex_exit(&bofi_low_mutex);
		return (EINVAL);
	}
	/*
	 * wait for ddi_report_fault for the devinfo corresponding
	 * to this errdef
	 */
	if (rval == 0 && !(ep->state & BOFI_NEW_MESSAGE)) {
		ep->state |= BOFI_MESSAGE_WAIT;
		if (cv_wait_sig(&ep->cv, &bofi_low_mutex) == 0) {
			if (!(ep->state & BOFI_NEW_MESSAGE))
				rval = EINTR;
		}
		goto retry;
	}
	ep->state &= ~BOFI_NEW_MESSAGE;
	/*
	 * we either didn't need to sleep, we've been woken up or we've been
	 * signaled - either way return state now
	 */
	mutex_enter(&bofi_mutex);
	ep->errstate.access_count = ep->errdef.access_count;
	ep->errstate.fail_count = ep->errdef.fail_count;
	ep->errstate.acc_chk = ep->errdef.acc_chk;
	ep->errstate.log = ep->errdef.log;
	*logpp = ep->logbase;
	*errstatep = ep->errstate;
	mutex_exit(&bofi_mutex);
	mutex_exit(&bofi_low_mutex);
	return (rval);
}


/*
 * support routine - check if requested driver is defined as under test in the
 * conf file.
 */
static int
driver_under_test(dev_info_t *rdip)
{
	int i;
	char	*rname;
	major_t rmaj;

	rname = ddi_get_name(rdip);
	rmaj = ddi_name_to_major(rname);

	/*
	 * Enforce the user to specifically request the following drivers.
	 */
	for (i = 0; i < driver_list_size; i += (1 + strlen(&driver_list[i]))) {
		if (driver_list_neg == 0) {
			if (rmaj == ddi_name_to_major(&driver_list[i]))
				return (1);
		} else {
			if (rmaj == ddi_name_to_major(&driver_list[i+1]))
				return (0);
		}
	}
	if (driver_list_neg == 0)
		return (0);
	else
		return (1);

}


static void
log_acc_event(struct bofi_errent *ep, uint_t at, offset_t offset, off_t len,
    size_t repcount, uint64_t *valuep)
{
	struct bofi_errdef *edp = &(ep->errdef);
	struct acc_log *log = &edp->log;

	ASSERT(log != NULL);
	ASSERT(MUTEX_HELD(&bofi_mutex));

	if (log->flags & BOFI_LOG_REPIO)
		repcount = 1;
	else if (repcount == 0 && edp->access_count > 0 &&
	    (log->flags & BOFI_LOG_FULL) == 0)
		edp->access_count += 1;

	if (repcount && log->entries < log->logsize) {
		struct acc_log_elem *elem = ep->logbase + log->entries;

		if (log->flags & BOFI_LOG_TIMESTAMP)
			elem->access_time = bofi_gettime();
		elem->access_type = at;
		elem->offset = offset;
		elem->value = valuep ? *valuep : 0ll;
		elem->size = len;
		elem->repcount = repcount;
		++log->entries;
		if (log->entries == log->logsize) {
			log->flags |= BOFI_LOG_FULL;
			ddi_trigger_softintr(((struct bofi_errent *)
			    (uintptr_t)edp->errdef_handle)->softintr_id);
		}
	}
	if ((log->flags & BOFI_LOG_WRAP) && edp->access_count <= 1) {
		log->wrapcnt++;
		edp->access_count = log->logsize;
		log->entries = 0;	/* wrap back to the start */
	}
}


/*
 * got a condition match on dma read/write - check counts and corrupt
 * data if necessary
 *
 * bofi_mutex always held when this is called.
 */
static void
do_dma_corrupt(struct bofi_shadow *hp, struct bofi_errent *ep,
    uint_t synctype, off_t off, off_t length)
{
	uint64_t operand;
	int i;
	off_t len;
	caddr_t logaddr;
	uint64_t *addr;
	uint64_t *endaddr;
	ddi_dma_impl_t *hdlp;
	ndi_err_t *errp;

	ASSERT(MUTEX_HELD(&bofi_mutex));
	if ((ep->errdef.access_count ||
	    ep->errdef.fail_count) &&
	    (ep->errdef.access_type & BOFI_LOG)) {
		uint_t atype;

		if (synctype == DDI_DMA_SYNC_FORDEV)
			atype = BOFI_DMA_W;
		else if (synctype == DDI_DMA_SYNC_FORCPU ||
		    synctype == DDI_DMA_SYNC_FORKERNEL)
			atype = BOFI_DMA_R;
		else
			atype = 0;
		if ((off <= ep->errdef.offset &&
		    off + length > ep->errdef.offset) ||
		    (off > ep->errdef.offset &&
		    off < ep->errdef.offset + ep->errdef.len)) {
			logaddr = (caddr_t)((uintptr_t)(hp->addr +
			    off + LLSZMASK) & ~LLSZMASK);

			log_acc_event(ep, atype, logaddr - hp->addr,
			    length, 1, 0);
		}
	}
	if (ep->errdef.access_count > 1) {
		ep->errdef.access_count--;
	} else if (ep->errdef.fail_count > 0) {
		ep->errdef.fail_count--;
		ep->errdef.access_count = 0;
		/*
		 * OK do the corruption
		 */
		if (ep->errstate.fail_time == 0)
			ep->errstate.fail_time = bofi_gettime();
		/*
		 * work out how much to corrupt
		 *
		 * Make sure endaddr isn't greater than hp->addr + hp->len.
		 * If endaddr becomes less than addr len becomes negative
		 * and the following loop isn't entered.
		 */
		addr = (uint64_t *)((uintptr_t)((hp->addr +
		    ep->errdef.offset) + LLSZMASK) & ~LLSZMASK);
		endaddr = (uint64_t *)((uintptr_t)(hp->addr + min(hp->len,
		    ep->errdef.offset + ep->errdef.len)) & ~LLSZMASK);
		len = endaddr - addr;
		operand = ep->errdef.operand;
		hdlp = (ddi_dma_impl_t *)(hp->hdl.dma_handle);
		errp = &hdlp->dmai_error;
		if (ep->errdef.acc_chk & 2) {
			uint64_t ena;
			char buf[FM_MAX_CLASS];

			errp->err_status = DDI_FM_NONFATAL;
			(void) snprintf(buf, FM_MAX_CLASS, FM_SIMULATED_DMA);
			ena = fm_ena_generate(0, FM_ENA_FMT1);
			ddi_fm_ereport_post(hp->dip, buf, ena,
			    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8,
			    FM_EREPORT_VERS0, NULL);
		}
		switch (ep->errdef.optype) {
		case BOFI_EQUAL :
			for (i = 0; i < len; i++)
				*(addr + i) = operand;
			break;
		case BOFI_AND :
			for (i = 0; i < len; i++)
				*(addr + i) &= operand;
			break;
		case BOFI_OR :
			for (i = 0; i < len; i++)
				*(addr + i) |= operand;
			break;
		case BOFI_XOR :
			for (i = 0; i < len; i++)
				*(addr + i) ^= operand;
			break;
		default:
			/* do nothing */
			break;
		}
	}
}


static uint64_t do_bofi_rd8(struct bofi_shadow *, caddr_t);
static uint64_t do_bofi_rd16(struct bofi_shadow *, caddr_t);
static uint64_t do_bofi_rd32(struct bofi_shadow *, caddr_t);
static uint64_t do_bofi_rd64(struct bofi_shadow *, caddr_t);


/*
 * check all errdefs linked to this shadow handle. If we've got a condition
 * match check counts and corrupt data if necessary
 *
 * bofi_mutex always held when this is called.
 *
 * because of possibility of BOFI_NO_TRANSFER, we couldn't get data
 * from io-space before calling this, so we pass in the func to do the
 * transfer as a parameter.
 */
static uint64_t
do_pior_corrupt(struct bofi_shadow *hp, caddr_t addr,
    uint64_t (*func)(), size_t repcount, size_t accsize)
{
	struct bofi_errent *ep;
	struct bofi_link   *lp;
	uint64_t operand;
	uintptr_t minlen;
	intptr_t base;
	int done_get = 0;
	uint64_t get_val, gv;
	ddi_acc_impl_t *hdlp;
	ndi_err_t *errp;

	ASSERT(MUTEX_HELD(&bofi_mutex));
	/*
	 * check through all errdefs associated with this shadow handle
	 */
	for (lp = hp->link; lp != NULL; lp = lp->link) {
		ep = lp->errentp;
		if (ep->errdef.len == 0)
			minlen = hp->len;
		else
			minlen = min(hp->len, ep->errdef.len);
		base = addr - hp->addr - ep->errdef.offset + hp->offset;
		if ((ep->errdef.access_type & BOFI_PIO_R) &&
		    (ep->state & BOFI_DEV_ACTIVE) &&
		    base >= 0 && base < minlen) {
			/*
			 * condition match for pio read
			 */
			if (ep->errdef.access_count > 1) {
				ep->errdef.access_count--;
				if (done_get == 0) {
					done_get = 1;
					gv = get_val = func(hp, addr);
				}
				if (ep->errdef.access_type & BOFI_LOG) {
					log_acc_event(ep, BOFI_PIO_R,
					    addr - hp->addr,
					    accsize, repcount, &gv);
				}
			} else if (ep->errdef.fail_count > 0) {
				ep->errdef.fail_count--;
				ep->errdef.access_count = 0;
				/*
				 * OK do corruption
				 */
				if (ep->errstate.fail_time == 0)
					ep->errstate.fail_time = bofi_gettime();
				operand = ep->errdef.operand;
				if (done_get == 0) {
					if (ep->errdef.optype ==
					    BOFI_NO_TRANSFER)
						/*
						 * no transfer - bomb out
						 */
						return (operand);
					done_get = 1;
					gv = get_val = func(hp, addr);

				}
				if (ep->errdef.access_type & BOFI_LOG) {
					log_acc_event(ep, BOFI_PIO_R,
					    addr - hp->addr,
					    accsize, repcount, &gv);
				}
				hdlp = (ddi_acc_impl_t *)(hp->hdl.acc_handle);
				errp = hdlp->ahi_err;
				if (ep->errdef.acc_chk & 1) {
					uint64_t ena;
					char buf[FM_MAX_CLASS];

					errp->err_status = DDI_FM_NONFATAL;
					(void) snprintf(buf, FM_MAX_CLASS,
					    FM_SIMULATED_PIO);
					ena = fm_ena_generate(0, FM_ENA_FMT1);
					ddi_fm_ereport_post(hp->dip, buf, ena,
					    DDI_NOSLEEP, FM_VERSION,
					    DATA_TYPE_UINT8, FM_EREPORT_VERS0,
					    NULL);
				}
				switch (ep->errdef.optype) {
				case BOFI_EQUAL :
					get_val = operand;
					break;
				case BOFI_AND :
					get_val &= operand;
					break;
				case BOFI_OR :
					get_val |= operand;
					break;
				case BOFI_XOR :
					get_val ^= operand;
					break;
				default:
					/* do nothing */
					break;
				}
			}
		}
	}
	if (done_get == 0)
		return (func(hp, addr));
	else
		return (get_val);
}


/*
 * check all errdefs linked to this shadow handle. If we've got a condition
 * match check counts and corrupt data if necessary
 *
 * bofi_mutex always held when this is called.
 *
 * because of possibility of BOFI_NO_TRANSFER, we return 0 if no data
 * is to be written out to io-space, 1 otherwise
 */
static int
do_piow_corrupt(struct bofi_shadow *hp, caddr_t addr, uint64_t *valuep,
    size_t size, size_t repcount)
{
	struct bofi_errent *ep;
	struct bofi_link   *lp;
	uintptr_t minlen;
	intptr_t base;
	uint64_t v = *valuep;
	ddi_acc_impl_t *hdlp;
	ndi_err_t *errp;

	ASSERT(MUTEX_HELD(&bofi_mutex));
	/*
	 * check through all errdefs associated with this shadow handle
	 */
	for (lp = hp->link; lp != NULL; lp = lp->link) {
		ep = lp->errentp;
		if (ep->errdef.len == 0)
			minlen = hp->len;
		else
			minlen = min(hp->len, ep->errdef.len);
		base = (caddr_t)addr - hp->addr - ep->errdef.offset +hp->offset;
		if ((ep->errdef.access_type & BOFI_PIO_W) &&
		    (ep->state & BOFI_DEV_ACTIVE) &&
		    base >= 0 && base < minlen) {
			/*
			 * condition match for pio write
			 */

			if (ep->errdef.access_count > 1) {
				ep->errdef.access_count--;
				if (ep->errdef.access_type & BOFI_LOG)
					log_acc_event(ep, BOFI_PIO_W,
					    addr - hp->addr, size,
					    repcount, &v);
			} else if (ep->errdef.fail_count > 0) {
				ep->errdef.fail_count--;
				ep->errdef.access_count = 0;
				if (ep->errdef.access_type & BOFI_LOG)
					log_acc_event(ep, BOFI_PIO_W,
					    addr - hp->addr, size,
					    repcount, &v);
				/*
				 * OK do corruption
				 */
				if (ep->errstate.fail_time == 0)
					ep->errstate.fail_time = bofi_gettime();
				hdlp = (ddi_acc_impl_t *)(hp->hdl.acc_handle);
				errp = hdlp->ahi_err;
				if (ep->errdef.acc_chk & 1) {
					uint64_t ena;
					char buf[FM_MAX_CLASS];

					errp->err_status = DDI_FM_NONFATAL;
					(void) snprintf(buf, FM_MAX_CLASS,
					    FM_SIMULATED_PIO);
					ena = fm_ena_generate(0, FM_ENA_FMT1);
					ddi_fm_ereport_post(hp->dip, buf, ena,
					    DDI_NOSLEEP, FM_VERSION,
					    DATA_TYPE_UINT8, FM_EREPORT_VERS0,
					    NULL);
				}
				switch (ep->errdef.optype) {
				case BOFI_EQUAL :
					*valuep = ep->errdef.operand;
					break;
				case BOFI_AND :
					*valuep &= ep->errdef.operand;
					break;
				case BOFI_OR :
					*valuep |= ep->errdef.operand;
					break;
				case BOFI_XOR :
					*valuep ^= ep->errdef.operand;
					break;
				case BOFI_NO_TRANSFER :
					/*
					 * no transfer - bomb out
					 */
					return (0);
				default:
					/* do nothing */
					break;
				}
			}
		}
	}
	return (1);
}


static uint64_t
do_bofi_rd8(struct bofi_shadow *hp, caddr_t addr)
{
	return (hp->save.acc.ahi_get8(&hp->save.acc, (uint8_t *)addr));
}

#define	BOFI_READ_CHECKS(type) \
	if (bofi_ddi_check) \
		addr = (type *)((uintptr_t)addr - 64 + hp->addr); \
	if (bofi_range_check && ((caddr_t)addr < hp->addr || \
	    (caddr_t)addr - hp->addr >= hp->len)) { \
		cmn_err((bofi_range_check == 2) ? CE_PANIC : CE_WARN, \
		    "ddi_get() out of range addr %p not in %p/%llx", \
		    (void *)addr, (void *)hp->addr, hp->len); \
		return (0); \
	}

/*
 * our getb() routine - use tryenter
 */
static uint8_t
bofi_rd8(ddi_acc_impl_t *handle, uint8_t *addr)
{
	struct bofi_shadow *hp;
	uint8_t retval;

	hp = handle->ahi_common.ah_bus_private;
	BOFI_READ_CHECKS(uint8_t)
	if (!hp->link || !mutex_tryenter(&bofi_mutex))
		return (hp->save.acc.ahi_get8(&hp->save.acc, addr));
	retval = (uint8_t)do_pior_corrupt(hp, (caddr_t)addr, do_bofi_rd8, 1,
	    1);
	mutex_exit(&bofi_mutex);
	return (retval);
}


static uint64_t
do_bofi_rd16(struct bofi_shadow *hp, caddr_t addr)
{
	return (hp->save.acc.ahi_get16(&hp->save.acc, (uint16_t *)addr));
}


/*
 * our getw() routine - use tryenter
 */
static uint16_t
bofi_rd16(ddi_acc_impl_t *handle, uint16_t *addr)
{
	struct bofi_shadow *hp;
	uint16_t retval;

	hp = handle->ahi_common.ah_bus_private;
	BOFI_READ_CHECKS(uint16_t)
	if (!hp->link || !mutex_tryenter(&bofi_mutex))
		return (hp->save.acc.ahi_get16(&hp->save.acc, addr));
	retval = (uint16_t)do_pior_corrupt(hp, (caddr_t)addr, do_bofi_rd16, 1,
	    2);
	mutex_exit(&bofi_mutex);
	return (retval);
}


static uint64_t
do_bofi_rd32(struct bofi_shadow *hp, caddr_t addr)
{
	return (hp->save.acc.ahi_get32(&hp->save.acc, (uint32_t *)addr));
}


/*
 * our getl() routine - use tryenter
 */
static uint32_t
bofi_rd32(ddi_acc_impl_t *handle, uint32_t *addr)
{
	struct bofi_shadow *hp;
	uint32_t retval;

	hp = handle->ahi_common.ah_bus_private;
	BOFI_READ_CHECKS(uint32_t)
	if (!hp->link || !mutex_tryenter(&bofi_mutex))
		return (hp->save.acc.ahi_get32(&hp->save.acc, addr));
	retval = (uint32_t)do_pior_corrupt(hp, (caddr_t)addr, do_bofi_rd32, 1,
	    4);
	mutex_exit(&bofi_mutex);
	return (retval);
}


static uint64_t
do_bofi_rd64(struct bofi_shadow *hp, caddr_t addr)
{
	return (hp->save.acc.ahi_get64(&hp->save.acc, (uint64_t *)addr));
}


/*
 * our getll() routine - use tryenter
 */
static uint64_t
bofi_rd64(ddi_acc_impl_t *handle, uint64_t *addr)
{
	struct bofi_shadow *hp;
	uint64_t retval;

	hp = handle->ahi_common.ah_bus_private;
	BOFI_READ_CHECKS(uint64_t)
	if (!hp->link || !mutex_tryenter(&bofi_mutex))
		return (hp->save.acc.ahi_get64(&hp->save.acc, addr));
	retval = (uint64_t)do_pior_corrupt(hp, (caddr_t)addr, do_bofi_rd64, 1,
	    8);
	mutex_exit(&bofi_mutex);
	return (retval);
}

#define	BOFI_WRITE_TESTS(type) \
	if (bofi_ddi_check) \
		addr = (type *)((uintptr_t)addr - 64 + hp->addr); \
	if (bofi_range_check && ((caddr_t)addr < hp->addr || \
	    (caddr_t)addr - hp->addr >= hp->len)) { \
		cmn_err((bofi_range_check == 2) ? CE_PANIC : CE_WARN, \
		    "ddi_put() out of range addr %p not in %p/%llx\n", \
		    (void *)addr, (void *)hp->addr, hp->len); \
		return; \
	}

/*
 * our putb() routine - use tryenter
 */
static void
bofi_wr8(ddi_acc_impl_t *handle, uint8_t *addr, uint8_t value)
{
	struct bofi_shadow *hp;
	uint64_t llvalue = value;

	hp = handle->ahi_common.ah_bus_private;
	BOFI_WRITE_TESTS(uint8_t)
	if (!hp->link || !mutex_tryenter(&bofi_mutex)) {
		hp->save.acc.ahi_put8(&hp->save.acc, addr, (uint8_t)llvalue);
		return;
	}
	if (do_piow_corrupt(hp, (caddr_t)addr, &llvalue, 1, 1))
		hp->save.acc.ahi_put8(&hp->save.acc, addr, (uint8_t)llvalue);
	mutex_exit(&bofi_mutex);
}


/*
 * our putw() routine - use tryenter
 */
static void
bofi_wr16(ddi_acc_impl_t *handle, uint16_t *addr, uint16_t value)
{
	struct bofi_shadow *hp;
	uint64_t llvalue = value;

	hp = handle->ahi_common.ah_bus_private;
	BOFI_WRITE_TESTS(uint16_t)
	if (!hp->link || !mutex_tryenter(&bofi_mutex)) {
		hp->save.acc.ahi_put16(&hp->save.acc, addr, (uint16_t)llvalue);
		return;
	}
	if (do_piow_corrupt(hp, (caddr_t)addr, &llvalue, 2, 1))
		hp->save.acc.ahi_put16(&hp->save.acc, addr, (uint16_t)llvalue);
	mutex_exit(&bofi_mutex);
}


/*
 * our putl() routine - use tryenter
 */
static void
bofi_wr32(ddi_acc_impl_t *handle, uint32_t *addr, uint32_t value)
{
	struct bofi_shadow *hp;
	uint64_t llvalue = value;

	hp = handle->ahi_common.ah_bus_private;
	BOFI_WRITE_TESTS(uint32_t)
	if (!hp->link || !mutex_tryenter(&bofi_mutex)) {
		hp->save.acc.ahi_put32(&hp->save.acc, addr, (uint32_t)llvalue);
		return;
	}
	if (do_piow_corrupt(hp, (caddr_t)addr, &llvalue, 4, 1))
		hp->save.acc.ahi_put32(&hp->save.acc, addr, (uint32_t)llvalue);
	mutex_exit(&bofi_mutex);
}


/*
 * our putll() routine - use tryenter
 */
static void
bofi_wr64(ddi_acc_impl_t *handle, uint64_t *addr, uint64_t value)
{
	struct bofi_shadow *hp;
	uint64_t llvalue = value;

	hp = handle->ahi_common.ah_bus_private;
	BOFI_WRITE_TESTS(uint64_t)
	if (!hp->link || !mutex_tryenter(&bofi_mutex)) {
		hp->save.acc.ahi_put64(&hp->save.acc, addr, (uint64_t)llvalue);
		return;
	}
	if (do_piow_corrupt(hp, (caddr_t)addr, &llvalue, 8, 1))
		hp->save.acc.ahi_put64(&hp->save.acc, addr, (uint64_t)llvalue);
	mutex_exit(&bofi_mutex);
}

#define	BOFI_REP_READ_TESTS(type) \
	if (bofi_ddi_check) \
		dev_addr = (type *)((uintptr_t)dev_addr - 64 + hp->addr); \
	if (bofi_range_check && ((caddr_t)dev_addr < hp->addr || \
	    (caddr_t)(dev_addr + repcount) - hp->addr > hp->len)) { \
		cmn_err((bofi_range_check == 2) ? CE_PANIC : CE_WARN, \
		    "ddi_rep_get() out of range addr %p not in %p/%llx\n", \
		    (void *)dev_addr, (void *)hp->addr, hp->len); \
		if ((caddr_t)dev_addr < hp->addr || \
		    (caddr_t)dev_addr - hp->addr >= hp->len) \
			return; \
		repcount = (type *)(hp->addr + hp->len) - dev_addr; \
	}

/*
 * our rep_getb() routine - use tryenter
 */
static void
bofi_rep_rd8(ddi_acc_impl_t *handle, uint8_t *host_addr, uint8_t *dev_addr,
    size_t repcount, uint_t flags)
{
	struct bofi_shadow *hp;
	int i;
	uint8_t *addr;

	hp = handle->ahi_common.ah_bus_private;
	BOFI_REP_READ_TESTS(uint8_t)
	if (!hp->link || !mutex_tryenter(&bofi_mutex)) {
		hp->save.acc.ahi_rep_get8(&hp->save.acc, host_addr, dev_addr,
		    repcount, flags);
		return;
	}
	for (i = 0; i < repcount; i++) {
		addr = dev_addr + ((flags == DDI_DEV_AUTOINCR) ? i : 0);
		*(host_addr + i) = (uint8_t)do_pior_corrupt(hp, (caddr_t)addr,
		    do_bofi_rd8, i ? 0 : repcount, 1);
	}
	mutex_exit(&bofi_mutex);
}


/*
 * our rep_getw() routine - use tryenter
 */
static void
bofi_rep_rd16(ddi_acc_impl_t *handle, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	struct bofi_shadow *hp;
	int i;
	uint16_t *addr;

	hp = handle->ahi_common.ah_bus_private;
	BOFI_REP_READ_TESTS(uint16_t)
	if (!hp->link || !mutex_tryenter(&bofi_mutex)) {
		hp->save.acc.ahi_rep_get16(&hp->save.acc, host_addr, dev_addr,
		    repcount, flags);
		return;
	}
	for (i = 0; i < repcount; i++) {
		addr = dev_addr + ((flags == DDI_DEV_AUTOINCR) ? i : 0);
		*(host_addr + i) = (uint16_t)do_pior_corrupt(hp, (caddr_t)addr,
		    do_bofi_rd16, i ? 0 : repcount, 2);
	}
	mutex_exit(&bofi_mutex);
}


/*
 * our rep_getl() routine - use tryenter
 */
static void
bofi_rep_rd32(ddi_acc_impl_t *handle, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	struct bofi_shadow *hp;
	int i;
	uint32_t *addr;

	hp = handle->ahi_common.ah_bus_private;
	BOFI_REP_READ_TESTS(uint32_t)
	if (!hp->link || !mutex_tryenter(&bofi_mutex)) {
		hp->save.acc.ahi_rep_get32(&hp->save.acc, host_addr, dev_addr,
		    repcount, flags);
		return;
	}
	for (i = 0; i < repcount; i++) {
		addr = dev_addr + ((flags == DDI_DEV_AUTOINCR) ? i : 0);
		*(host_addr + i) = (uint32_t)do_pior_corrupt(hp, (caddr_t)addr,
		    do_bofi_rd32, i ? 0 : repcount, 4);
	}
	mutex_exit(&bofi_mutex);
}


/*
 * our rep_getll() routine - use tryenter
 */
static void
bofi_rep_rd64(ddi_acc_impl_t *handle, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	struct bofi_shadow *hp;
	int i;
	uint64_t *addr;

	hp = handle->ahi_common.ah_bus_private;
	BOFI_REP_READ_TESTS(uint64_t)
	if (!hp->link || !mutex_tryenter(&bofi_mutex)) {
		hp->save.acc.ahi_rep_get64(&hp->save.acc, host_addr, dev_addr,
		    repcount, flags);
		return;
	}
	for (i = 0; i < repcount; i++) {
		addr = dev_addr + ((flags == DDI_DEV_AUTOINCR) ? i : 0);
		*(host_addr + i) = (uint64_t)do_pior_corrupt(hp, (caddr_t)addr,
		    do_bofi_rd64, i ? 0 : repcount, 8);
	}
	mutex_exit(&bofi_mutex);
}

#define	BOFI_REP_WRITE_TESTS(type) \
	if (bofi_ddi_check) \
		dev_addr = (type *)((uintptr_t)dev_addr - 64 + hp->addr); \
	if (bofi_range_check && ((caddr_t)dev_addr < hp->addr || \
	    (caddr_t)(dev_addr + repcount) - hp->addr > hp->len)) { \
		cmn_err((bofi_range_check == 2) ? CE_PANIC : CE_WARN, \
		    "ddi_rep_put() out of range addr %p not in %p/%llx\n", \
		    (void *)dev_addr, (void *)hp->addr, hp->len); \
		if ((caddr_t)dev_addr < hp->addr || \
		    (caddr_t)dev_addr - hp->addr >= hp->len) \
			return; \
		repcount = (type *)(hp->addr + hp->len) - dev_addr; \
	}

/*
 * our rep_putb() routine - use tryenter
 */
static void
bofi_rep_wr8(ddi_acc_impl_t *handle, uint8_t *host_addr, uint8_t *dev_addr,
    size_t repcount, uint_t flags)
{
	struct bofi_shadow *hp;
	int i;
	uint64_t llvalue;
	uint8_t *addr;

	hp = handle->ahi_common.ah_bus_private;
	BOFI_REP_WRITE_TESTS(uint8_t)
	if (!hp->link || !mutex_tryenter(&bofi_mutex)) {
		hp->save.acc.ahi_rep_put8(&hp->save.acc, host_addr, dev_addr,
		    repcount, flags);
		return;
	}
	for (i = 0; i < repcount; i++) {
		llvalue = *(host_addr + i);
		addr = dev_addr + ((flags == DDI_DEV_AUTOINCR) ? i : 0);
		if (do_piow_corrupt(hp, (caddr_t)addr, &llvalue, 1, i ? 0 :
		    repcount))
			hp->save.acc.ahi_put8(&hp->save.acc, addr,
			    (uint8_t)llvalue);
	}
	mutex_exit(&bofi_mutex);
}


/*
 * our rep_putw() routine - use tryenter
 */
static void
bofi_rep_wr16(ddi_acc_impl_t *handle, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	struct bofi_shadow *hp;
	int i;
	uint64_t llvalue;
	uint16_t *addr;

	hp = handle->ahi_common.ah_bus_private;
	BOFI_REP_WRITE_TESTS(uint16_t)
	if (!hp->link || !mutex_tryenter(&bofi_mutex)) {
		hp->save.acc.ahi_rep_put16(&hp->save.acc, host_addr, dev_addr,
		    repcount, flags);
		return;
	}
	for (i = 0; i < repcount; i++) {
		llvalue = *(host_addr + i);
		addr = dev_addr + ((flags == DDI_DEV_AUTOINCR) ? i : 0);
		if (do_piow_corrupt(hp, (caddr_t)addr, &llvalue, 2, i ? 0 :
		    repcount))
			hp->save.acc.ahi_put16(&hp->save.acc, addr,
			    (uint16_t)llvalue);
	}
	mutex_exit(&bofi_mutex);
}


/*
 * our rep_putl() routine - use tryenter
 */
static void
bofi_rep_wr32(ddi_acc_impl_t *handle, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	struct bofi_shadow *hp;
	int i;
	uint64_t llvalue;
	uint32_t *addr;

	hp = handle->ahi_common.ah_bus_private;
	BOFI_REP_WRITE_TESTS(uint32_t)
	if (!hp->link || !mutex_tryenter(&bofi_mutex)) {
		hp->save.acc.ahi_rep_put32(&hp->save.acc, host_addr, dev_addr,
		    repcount, flags);
		return;
	}
	for (i = 0; i < repcount; i++) {
		llvalue = *(host_addr + i);
		addr = dev_addr + ((flags == DDI_DEV_AUTOINCR) ? i : 0);
		if (do_piow_corrupt(hp, (caddr_t)addr, &llvalue, 4, i ? 0 :
		    repcount))
			hp->save.acc.ahi_put32(&hp->save.acc, addr,
			    (uint32_t)llvalue);
	}
	mutex_exit(&bofi_mutex);
}


/*
 * our rep_putll() routine - use tryenter
 */
static void
bofi_rep_wr64(ddi_acc_impl_t *handle, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	struct bofi_shadow *hp;
	int i;
	uint64_t llvalue;
	uint64_t *addr;

	hp = handle->ahi_common.ah_bus_private;
	BOFI_REP_WRITE_TESTS(uint64_t)
	if (!hp->link || !mutex_tryenter(&bofi_mutex)) {
		hp->save.acc.ahi_rep_put64(&hp->save.acc, host_addr, dev_addr,
		    repcount, flags);
		return;
	}
	for (i = 0; i < repcount; i++) {
		llvalue = *(host_addr + i);
		addr = dev_addr + ((flags == DDI_DEV_AUTOINCR) ? i : 0);
		if (do_piow_corrupt(hp, (caddr_t)addr, &llvalue, 8, i ? 0 :
		    repcount))
			hp->save.acc.ahi_put64(&hp->save.acc, addr,
			    (uint64_t)llvalue);
	}
	mutex_exit(&bofi_mutex);
}


/*
 * our ddi_map routine
 */
static int
bofi_map(dev_info_t *dip, dev_info_t *rdip,
    ddi_map_req_t *reqp, off_t offset, off_t len, caddr_t *vaddrp)
{
	ddi_acc_impl_t *ap;
	struct bofi_shadow *hp;
	struct bofi_errent *ep;
	struct bofi_link   *lp, *next_lp;
	int retval;
	struct bofi_shadow *dhashp;
	struct bofi_shadow *hhashp;

	switch (reqp->map_op) {
	case DDI_MO_MAP_LOCKED:
		/*
		 * for this case get nexus to do real work first
		 */
		retval = save_bus_ops.bus_map(dip, rdip, reqp, offset, len,
		    vaddrp);
		if (retval != DDI_SUCCESS)
			return (retval);

		ap = (ddi_acc_impl_t *)reqp->map_handlep;
		if (ap == NULL)
			return (DDI_SUCCESS);
		/*
		 * if driver_list is set, only intercept those drivers
		 */
		if (!driver_under_test(ap->ahi_common.ah_dip))
			return (DDI_SUCCESS);

		/*
		 * support for ddi_regs_map_setup()
		 * - allocate shadow handle structure and fill it in
		 */
		hp = kmem_zalloc(sizeof (struct bofi_shadow), KM_SLEEP);
		(void) strncpy(hp->name, ddi_get_name(ap->ahi_common.ah_dip),
		    NAMESIZE);
		hp->instance = ddi_get_instance(ap->ahi_common.ah_dip);
		hp->dip = ap->ahi_common.ah_dip;
		hp->addr = *vaddrp;
		/*
		 * return spurious value to catch direct access to registers
		 */
		if (bofi_ddi_check)
			*vaddrp = (caddr_t)64;
		hp->rnumber = ((ddi_acc_hdl_t *)ap)->ah_rnumber;
		hp->offset = offset;
		if (len == 0)
			hp->len = INT_MAX - offset;
		else
			hp->len = min(len, INT_MAX - offset);
		hp->hdl.acc_handle = (ddi_acc_handle_t)ap;
		hp->link = NULL;
		hp->type = BOFI_ACC_HDL;
		/*
		 * save existing function pointers and plug in our own
		 */
		hp->save.acc = *ap;
		ap->ahi_get8 = bofi_rd8;
		ap->ahi_get16 = bofi_rd16;
		ap->ahi_get32 = bofi_rd32;
		ap->ahi_get64 = bofi_rd64;
		ap->ahi_put8 = bofi_wr8;
		ap->ahi_put16 = bofi_wr16;
		ap->ahi_put32 = bofi_wr32;
		ap->ahi_put64 = bofi_wr64;
		ap->ahi_rep_get8 = bofi_rep_rd8;
		ap->ahi_rep_get16 = bofi_rep_rd16;
		ap->ahi_rep_get32 = bofi_rep_rd32;
		ap->ahi_rep_get64 = bofi_rep_rd64;
		ap->ahi_rep_put8 = bofi_rep_wr8;
		ap->ahi_rep_put16 = bofi_rep_wr16;
		ap->ahi_rep_put32 = bofi_rep_wr32;
		ap->ahi_rep_put64 = bofi_rep_wr64;
		ap->ahi_fault_check = bofi_check_acc_hdl;
#if defined(__sparc)
#else
		ap->ahi_acc_attr &= ~DDI_ACCATTR_DIRECT;
#endif
		/*
		 * stick in a pointer to our shadow handle
		 */
		ap->ahi_common.ah_bus_private = hp;
		/*
		 * add to dhash, hhash and inuse lists
		 */
		mutex_enter(&bofi_low_mutex);
		mutex_enter(&bofi_mutex);
		hp->next = shadow_list.next;
		shadow_list.next->prev = hp;
		hp->prev = &shadow_list;
		shadow_list.next = hp;
		hhashp = HDL_HHASH(ap);
		hp->hnext = hhashp->hnext;
		hhashp->hnext->hprev = hp;
		hp->hprev = hhashp;
		hhashp->hnext = hp;
		dhashp = HDL_DHASH(hp->dip);
		hp->dnext = dhashp->dnext;
		dhashp->dnext->dprev = hp;
		hp->dprev = dhashp;
		dhashp->dnext = hp;
		/*
		 * chain on any pre-existing errdefs that apply to this
		 * acc_handle
		 */
		for (ep = errent_listp; ep != NULL; ep = ep->next) {
			if (ddi_name_to_major(hp->name) ==
			    ddi_name_to_major(ep->name) &&
			    hp->instance == ep->errdef.instance &&
			    (ep->errdef.access_type & BOFI_PIO_RW) &&
			    (ep->errdef.rnumber == -1 ||
			    hp->rnumber == ep->errdef.rnumber) &&
			    (ep->errdef.len == 0 ||
			    offset < ep->errdef.offset + ep->errdef.len) &&
			    offset + hp->len > ep->errdef.offset) {
				lp = bofi_link_freelist;
				if (lp != NULL) {
					bofi_link_freelist = lp->link;
					lp->errentp = ep;
					lp->link = hp->link;
					hp->link = lp;
				}
			}
		}
		mutex_exit(&bofi_mutex);
		mutex_exit(&bofi_low_mutex);
		return (DDI_SUCCESS);
	case DDI_MO_UNMAP:

		ap = (ddi_acc_impl_t *)reqp->map_handlep;
		if (ap == NULL)
			break;
		/*
		 * support for ddi_regs_map_free()
		 * - check we really have a shadow handle for this one
		 */
		mutex_enter(&bofi_low_mutex);
		mutex_enter(&bofi_mutex);
		hhashp = HDL_HHASH(ap);
		for (hp = hhashp->hnext; hp != hhashp; hp = hp->hnext)
			if (hp->hdl.acc_handle == (ddi_acc_handle_t)ap)
				break;
		if (hp == hhashp) {
			mutex_exit(&bofi_mutex);
			mutex_exit(&bofi_low_mutex);
			break;
		}
		/*
		 * got a shadow handle - restore original pointers
		 */
		*ap = hp->save.acc;
		*vaddrp = hp->addr;
		/*
		 * remove from dhash, hhash and inuse lists
		 */
		hp->hnext->hprev = hp->hprev;
		hp->hprev->hnext = hp->hnext;
		hp->dnext->dprev = hp->dprev;
		hp->dprev->dnext = hp->dnext;
		hp->next->prev = hp->prev;
		hp->prev->next = hp->next;
		/*
		 * free any errdef link structures tagged onto the shadow handle
		 */
		for (lp = hp->link; lp != NULL; ) {
			next_lp = lp->link;
			lp->link = bofi_link_freelist;
			bofi_link_freelist = lp;
			lp = next_lp;
		}
		hp->link = NULL;
		mutex_exit(&bofi_mutex);
		mutex_exit(&bofi_low_mutex);
		/*
		 * finally delete shadow handle
		 */
		kmem_free(hp, sizeof (struct bofi_shadow));
		break;
	default:
		break;
	}
	return (save_bus_ops.bus_map(dip, rdip, reqp, offset, len, vaddrp));
}


/*
 * chain any pre-existing errdefs on to newly created dma handle
 * if required call do_dma_corrupt() to corrupt data
 */
static void
chain_on_errdefs(struct bofi_shadow *hp)
{
	struct bofi_errent *ep;
	struct bofi_link   *lp;

	ASSERT(MUTEX_HELD(&bofi_mutex));
	/*
	 * chain on any pre-existing errdefs that apply to this dma_handle
	 */
	for (ep = errent_listp; ep != NULL; ep = ep->next) {
		if (ddi_name_to_major(hp->name) ==
		    ddi_name_to_major(ep->name) &&
		    hp->instance == ep->errdef.instance &&
		    (ep->errdef.rnumber == -1 ||
		    hp->rnumber == ep->errdef.rnumber) &&
		    ((ep->errdef.access_type & BOFI_DMA_RW) &&
		    (((uintptr_t)(hp->addr + ep->errdef.offset +
		    ep->errdef.len) & ~LLSZMASK) >
		    ((uintptr_t)((hp->addr + ep->errdef.offset) +
		    LLSZMASK) & ~LLSZMASK)))) {
			/*
			 * got a match - link it on
			 */
			lp = bofi_link_freelist;
			if (lp != NULL) {
				bofi_link_freelist = lp->link;
				lp->errentp = ep;
				lp->link = hp->link;
				hp->link = lp;
				if ((ep->errdef.access_type & BOFI_DMA_W) &&
				    (hp->flags & DDI_DMA_WRITE) &&
				    (ep->state & BOFI_DEV_ACTIVE)) {
					do_dma_corrupt(hp, ep,
					    DDI_DMA_SYNC_FORDEV,
					    0, hp->len);
				}
			}
		}
	}
}


/*
 * need to do copy byte-by-byte in case one of pages is little-endian
 */
static void
xbcopy(void *from, void *to, u_longlong_t len)
{
	uchar_t *f = from;
	uchar_t *t = to;

	while (len--)
		*t++ = *f++;
}


/*
 * our ddi_dma_allochdl routine
 */
static int
bofi_dma_allochdl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_attr_t *attrp,
    int (*waitfp)(caddr_t), caddr_t arg, ddi_dma_handle_t *handlep)
{
	int retval = DDI_DMA_NORESOURCES;
	struct bofi_shadow *hp, *xhp;
	int maxrnumber = 0;
	struct bofi_shadow *dhashp;
	struct bofi_shadow *hhashp;
	ddi_dma_impl_t *mp;

	/*
	 * if driver_list is set, only intercept those drivers
	 */
	if (!driver_under_test(rdip))
		return (save_bus_ops.bus_dma_allochdl(dip, rdip, attrp,
		    waitfp, arg, handlep));

	/*
	 * allocate shadow handle structure and fill it in
	 */
	hp = kmem_zalloc(sizeof (struct bofi_shadow),
	    ((waitfp == DDI_DMA_SLEEP) ? KM_SLEEP : KM_NOSLEEP));
	if (hp == NULL) {
		/*
		 * what to do here? Wait a bit and try again
		 */
		if (waitfp != DDI_DMA_DONTWAIT)
			(void) timeout((void (*)())(uintptr_t)waitfp, arg, 10);
		return (retval);
	}
	(void) strncpy(hp->name, ddi_get_name(rdip), NAMESIZE);
	hp->instance = ddi_get_instance(rdip);
	hp->dip = rdip;
	hp->link = NULL;
	hp->type = BOFI_NULL;
	/*
	 * call nexus to do the real work
	 */
	retval = save_bus_ops.bus_dma_allochdl(dip, rdip, attrp, waitfp, arg,
	    handlep);
	if (retval != DDI_SUCCESS) {
		kmem_free(hp, sizeof (struct bofi_shadow));
		return (retval);
	}
	/*
	 * now point set dma_handle to point to real handle
	 */
	hp->hdl.dma_handle = *handlep;
	mp = (ddi_dma_impl_t *)*handlep;
	mp->dmai_fault_check = bofi_check_dma_hdl;
	/*
	 * bind and unbind are cached in devinfo - must overwrite them
	 * - note that our bind and unbind are quite happy dealing with
	 * any handles for this devinfo that were previously allocated
	 */
	if (save_bus_ops.bus_dma_bindhdl == DEVI(rdip)->devi_bus_dma_bindfunc)
		DEVI(rdip)->devi_bus_dma_bindfunc = bofi_dma_bindhdl;
	if (save_bus_ops.bus_dma_unbindhdl ==
	    DEVI(rdip)->devi_bus_dma_unbindfunc)
		DEVI(rdip)->devi_bus_dma_unbindfunc = bofi_dma_unbindhdl;
	mutex_enter(&bofi_low_mutex);
	mutex_enter(&bofi_mutex);
	/*
	 * get an "rnumber" for this handle - really just seeking to
	 * get a unique number - generally only care for early allocated
	 * handles - so we get as far as INT_MAX, just stay there
	 */
	dhashp = HDL_DHASH(hp->dip);
	for (xhp = dhashp->dnext; xhp != dhashp; xhp = xhp->dnext)
		if (ddi_name_to_major(xhp->name) ==
		    ddi_name_to_major(hp->name) &&
		    xhp->instance == hp->instance &&
		    (xhp->type == BOFI_DMA_HDL ||
		    xhp->type == BOFI_NULL))
			if (xhp->rnumber >= maxrnumber) {
				if (xhp->rnumber == INT_MAX)
					maxrnumber = INT_MAX;
				else
					maxrnumber = xhp->rnumber + 1;
			}
	hp->rnumber = maxrnumber;
	/*
	 * add to dhash, hhash and inuse lists
	 */
	hp->next = shadow_list.next;
	shadow_list.next->prev = hp;
	hp->prev = &shadow_list;
	shadow_list.next = hp;
	hhashp = HDL_HHASH(*handlep);
	hp->hnext = hhashp->hnext;
	hhashp->hnext->hprev = hp;
	hp->hprev = hhashp;
	hhashp->hnext = hp;
	dhashp = HDL_DHASH(hp->dip);
	hp->dnext = dhashp->dnext;
	dhashp->dnext->dprev = hp;
	hp->dprev = dhashp;
	dhashp->dnext = hp;
	mutex_exit(&bofi_mutex);
	mutex_exit(&bofi_low_mutex);
	return (retval);
}


/*
 * our ddi_dma_freehdl routine
 */
static int
bofi_dma_freehdl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t handle)
{
	int retval;
	struct bofi_shadow *hp;
	struct bofi_shadow *hhashp;

	/*
	 * find shadow for this handle
	 */
	mutex_enter(&bofi_low_mutex);
	mutex_enter(&bofi_mutex);
	hhashp = HDL_HHASH(handle);
	for (hp = hhashp->hnext; hp != hhashp; hp = hp->hnext)
		if (hp->hdl.dma_handle == handle)
			break;
	mutex_exit(&bofi_mutex);
	mutex_exit(&bofi_low_mutex);
	/*
	 * call nexus to do the real work
	 */
	retval = save_bus_ops.bus_dma_freehdl(dip, rdip, handle);
	if (retval != DDI_SUCCESS) {
		return (retval);
	}
	/*
	 * did we really have a shadow for this handle
	 */
	if (hp == hhashp)
		return (retval);
	/*
	 * yes we have - see if it's still bound
	 */
	mutex_enter(&bofi_low_mutex);
	mutex_enter(&bofi_mutex);
	if (hp->type != BOFI_NULL)
		panic("driver freeing bound dma_handle");
	/*
	 * remove from dhash, hhash and inuse lists
	 */
	hp->hnext->hprev = hp->hprev;
	hp->hprev->hnext = hp->hnext;
	hp->dnext->dprev = hp->dprev;
	hp->dprev->dnext = hp->dnext;
	hp->next->prev = hp->prev;
	hp->prev->next = hp->next;
	mutex_exit(&bofi_mutex);
	mutex_exit(&bofi_low_mutex);

	kmem_free(hp, sizeof (struct bofi_shadow));
	return (retval);
}


/*
 * our ddi_dma_bindhdl routine
 */
static int
bofi_dma_bindhdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, struct ddi_dma_req *dmareqp,
    ddi_dma_cookie_t *cookiep, uint_t *ccountp)
{
	int retval = DDI_DMA_NORESOURCES;
	auto struct ddi_dma_req dmareq;
	struct bofi_shadow *hp;
	struct bofi_shadow *hhashp;
	ddi_dma_impl_t *mp;
	unsigned long pagemask = ddi_ptob(rdip, 1) - 1;

	/*
	 * check we really have a shadow for this handle
	 */
	mutex_enter(&bofi_low_mutex);
	mutex_enter(&bofi_mutex);
	hhashp = HDL_HHASH(handle);
	for (hp = hhashp->hnext; hp != hhashp; hp = hp->hnext)
		if (hp->hdl.dma_handle == handle)
			break;
	mutex_exit(&bofi_mutex);
	mutex_exit(&bofi_low_mutex);
	if (hp == hhashp) {
		/*
		 * no we don't - just call nexus to do the real work
		 */
		return save_bus_ops.bus_dma_bindhdl(dip, rdip, handle, dmareqp,
		    cookiep, ccountp);
	}
	/*
	 * yes we have - see if it's already bound
	 */
	if (hp->type != BOFI_NULL)
		return (DDI_DMA_INUSE);

	hp->flags = dmareqp->dmar_flags;
	if (dmareqp->dmar_object.dmao_type == DMA_OTYP_PAGES) {
		hp->map_flags = B_PAGEIO;
		hp->map_pp = dmareqp->dmar_object.dmao_obj.pp_obj.pp_pp;
	} else if (dmareqp->dmar_object.dmao_obj.virt_obj.v_priv != NULL) {
		hp->map_flags = B_SHADOW;
		hp->map_pplist = dmareqp->dmar_object.dmao_obj.virt_obj.v_priv;
	} else {
		hp->map_flags = 0;
	}
	/*
	 * get a kernel virtual mapping
	 */
	hp->addr = ddi_dmareq_mapin(dmareqp, &hp->mapaddr, &hp->len);
	if (hp->addr == NULL)
		goto error;
	if (bofi_sync_check) {
		/*
		 * Take a copy and pass pointers to this up to nexus instead.
		 * Data will be copied from the original on explicit
		 * and implicit ddi_dma_sync()
		 *
		 * - maintain page alignment because some devices assume it.
		 */
		hp->origaddr = hp->addr;
		hp->allocaddr = ddi_umem_alloc(
		    ((uintptr_t)hp->addr & pagemask) + hp->len,
		    (dmareqp->dmar_fp == DDI_DMA_SLEEP) ? KM_SLEEP : KM_NOSLEEP,
		    &hp->umem_cookie);
		if (hp->allocaddr == NULL)
			goto error;
		hp->addr = hp->allocaddr + ((uintptr_t)hp->addr & pagemask);
		if (dmareqp->dmar_flags & DDI_DMA_WRITE)
			xbcopy(hp->origaddr, hp->addr, hp->len);
		dmareq = *dmareqp;
		dmareq.dmar_object.dmao_size = hp->len;
		dmareq.dmar_object.dmao_type = DMA_OTYP_VADDR;
		dmareq.dmar_object.dmao_obj.virt_obj.v_as = &kas;
		dmareq.dmar_object.dmao_obj.virt_obj.v_addr = hp->addr;
		dmareq.dmar_object.dmao_obj.virt_obj.v_priv = NULL;
		dmareqp = &dmareq;
	}
	/*
	 * call nexus to do the real work
	 */
	retval = save_bus_ops.bus_dma_bindhdl(dip, rdip, handle, dmareqp,
	    cookiep, ccountp);
	if (retval != DDI_SUCCESS)
		goto error2;
	/*
	 * unset DMP_NOSYNC
	 */
	mp = (ddi_dma_impl_t *)handle;
	mp->dmai_rflags &= ~DMP_NOSYNC;
	/*
	 * chain on any pre-existing errdefs that apply to this
	 * acc_handle and corrupt if required (as there is an implicit
	 * ddi_dma_sync() in this call)
	 */
	mutex_enter(&bofi_low_mutex);
	mutex_enter(&bofi_mutex);
	hp->type = BOFI_DMA_HDL;
	chain_on_errdefs(hp);
	mutex_exit(&bofi_mutex);
	mutex_exit(&bofi_low_mutex);
	return (retval);

error:
	if (dmareqp->dmar_fp != DDI_DMA_DONTWAIT) {
		/*
		 * what to do here? Wait a bit and try again
		 */
		(void) timeout((void (*)())(uintptr_t)dmareqp->dmar_fp,
		    dmareqp->dmar_arg, 10);
	}
error2:
	if (hp) {
		ddi_dmareq_mapout(hp->mapaddr, hp->len, hp->map_flags,
		    hp->map_pp, hp->map_pplist);
		if (bofi_sync_check && hp->allocaddr)
			ddi_umem_free(hp->umem_cookie);
		hp->mapaddr = NULL;
		hp->allocaddr = NULL;
		hp->origaddr = NULL;
	}
	return (retval);
}


/*
 * our ddi_dma_unbindhdl routine
 */
static int
bofi_dma_unbindhdl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t handle)
{
	struct bofi_link *lp, *next_lp;
	struct bofi_errent *ep;
	int retval;
	struct bofi_shadow *hp;
	struct bofi_shadow *hhashp;

	/*
	 * call nexus to do the real work
	 */
	retval = save_bus_ops.bus_dma_unbindhdl(dip, rdip, handle);
	if (retval != DDI_SUCCESS)
		return (retval);
	/*
	 * check we really have a shadow for this handle
	 */
	mutex_enter(&bofi_low_mutex);
	mutex_enter(&bofi_mutex);
	hhashp = HDL_HHASH(handle);
	for (hp = hhashp->hnext; hp != hhashp; hp = hp->hnext)
		if (hp->hdl.dma_handle == handle)
			break;
	if (hp == hhashp) {
		mutex_exit(&bofi_mutex);
		mutex_exit(&bofi_low_mutex);
		return (retval);
	}
	/*
	 * yes we have - see if it's already unbound
	 */
	if (hp->type == BOFI_NULL)
		panic("driver unbinding unbound dma_handle");
	/*
	 * free any errdef link structures tagged on to this
	 * shadow handle
	 */
	for (lp = hp->link; lp != NULL; ) {
		next_lp = lp->link;
		/*
		 * there is an implicit sync_for_cpu on free -
		 * may need to corrupt
		 */
		ep = lp->errentp;
		if ((ep->errdef.access_type & BOFI_DMA_R) &&
		    (hp->flags & DDI_DMA_READ) &&
		    (ep->state & BOFI_DEV_ACTIVE)) {
			do_dma_corrupt(hp, ep, DDI_DMA_SYNC_FORCPU, 0, hp->len);
		}
		lp->link = bofi_link_freelist;
		bofi_link_freelist = lp;
		lp = next_lp;
	}
	hp->link = NULL;
	hp->type = BOFI_NULL;
	mutex_exit(&bofi_mutex);
	mutex_exit(&bofi_low_mutex);

	if (bofi_sync_check && (hp->flags & DDI_DMA_READ))
		/*
		 * implicit sync_for_cpu - copy data back
		 */
		if (hp->allocaddr)
			xbcopy(hp->addr, hp->origaddr, hp->len);
	ddi_dmareq_mapout(hp->mapaddr, hp->len, hp->map_flags,
	    hp->map_pp, hp->map_pplist);
	if (bofi_sync_check && hp->allocaddr)
		ddi_umem_free(hp->umem_cookie);
	hp->mapaddr = NULL;
	hp->allocaddr = NULL;
	hp->origaddr = NULL;
	return (retval);
}


/*
 * our ddi_dma_sync routine
 */
static int
bofi_dma_flush(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, off_t off, size_t len, uint_t flags)
{
	struct bofi_link *lp;
	struct bofi_errent *ep;
	struct bofi_shadow *hp;
	struct bofi_shadow *hhashp;
	int retval;

	if (flags == DDI_DMA_SYNC_FORCPU || flags == DDI_DMA_SYNC_FORKERNEL) {
		/*
		 * in this case get nexus driver to do sync first
		 */
		retval = save_bus_ops.bus_dma_flush(dip, rdip, handle, off,
		    len, flags);
		if (retval != DDI_SUCCESS)
			return (retval);
	}
	/*
	 * check we really have a shadow for this handle
	 */
	mutex_enter(&bofi_low_mutex);
	mutex_enter(&bofi_mutex);
	hhashp = HDL_HHASH(handle);
	for (hp = hhashp->hnext; hp != hhashp; hp = hp->hnext)
		if (hp->hdl.dma_handle == handle &&
		    hp->type == BOFI_DMA_HDL)
			break;
	mutex_exit(&bofi_mutex);
	mutex_exit(&bofi_low_mutex);
	if (hp != hhashp) {
		/*
		 * yes - do we need to copy data from original
		 */
		if (bofi_sync_check && flags == DDI_DMA_SYNC_FORDEV)
			if (hp->allocaddr)
				xbcopy(hp->origaddr+off, hp->addr+off,
				    len ? len : (hp->len - off));
		/*
		 * yes - check if we need to corrupt the data
		 */
		mutex_enter(&bofi_low_mutex);
		mutex_enter(&bofi_mutex);
		for (lp = hp->link; lp != NULL; lp = lp->link) {
			ep = lp->errentp;
			if ((((ep->errdef.access_type & BOFI_DMA_R) &&
			    (flags == DDI_DMA_SYNC_FORCPU ||
			    flags == DDI_DMA_SYNC_FORKERNEL)) ||
			    ((ep->errdef.access_type & BOFI_DMA_W) &&
			    (flags == DDI_DMA_SYNC_FORDEV))) &&
			    (ep->state & BOFI_DEV_ACTIVE)) {
				do_dma_corrupt(hp, ep, flags, off,
				    len ? len : (hp->len - off));
			}
		}
		mutex_exit(&bofi_mutex);
		mutex_exit(&bofi_low_mutex);
		/*
		 *  do we need to copy data to original
		 */
		if (bofi_sync_check && (flags == DDI_DMA_SYNC_FORCPU ||
		    flags == DDI_DMA_SYNC_FORKERNEL))
			if (hp->allocaddr)
				xbcopy(hp->addr+off, hp->origaddr+off,
				    len ? len : (hp->len - off));
	}
	if (flags == DDI_DMA_SYNC_FORDEV)
		/*
		 * in this case get nexus driver to do sync last
		 */
		retval = save_bus_ops.bus_dma_flush(dip, rdip, handle, off,
		    len, flags);
	return (retval);
}


/*
 * our dma_win routine
 */
static int
bofi_dma_win(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, uint_t win, off_t *offp,
    size_t *lenp, ddi_dma_cookie_t *cookiep, uint_t *ccountp)
{
	struct bofi_shadow *hp;
	struct bofi_shadow *hhashp;
	int retval;
	ddi_dma_impl_t *mp;

	/*
	 * call nexus to do the real work
	 */
	retval = save_bus_ops.bus_dma_win(dip, rdip, handle, win, offp, lenp,
	    cookiep, ccountp);
	if (retval != DDI_SUCCESS)
		return (retval);
	/*
	 * check we really have a shadow for this handle
	 */
	mutex_enter(&bofi_low_mutex);
	mutex_enter(&bofi_mutex);
	hhashp = HDL_HHASH(handle);
	for (hp = hhashp->hnext; hp != hhashp; hp = hp->hnext)
		if (hp->hdl.dma_handle == handle)
			break;
	if (hp != hhashp) {
		/*
		 * yes - make sure DMP_NOSYNC is unset
		 */
		mp = (ddi_dma_impl_t *)handle;
		mp->dmai_rflags &= ~DMP_NOSYNC;
	}
	mutex_exit(&bofi_mutex);
	mutex_exit(&bofi_low_mutex);
	return (retval);
}


/*
 * our dma_ctl routine
 */
static int
bofi_dma_ctl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, enum ddi_dma_ctlops request,
    off_t *offp, size_t *lenp, caddr_t *objp, uint_t flags)
{
	struct bofi_shadow *hp;
	struct bofi_shadow *hhashp;
	int retval;
	int i;
	struct bofi_shadow *dummyhp;

	/*
	 * get nexus to do real work
	 */
	retval = save_bus_ops.bus_dma_ctl(dip, rdip, handle, request, offp,
	    lenp, objp, flags);
	if (retval != DDI_SUCCESS)
		return (retval);
	/*
	 * if driver_list is set, only intercept those drivers
	 */
	if (!driver_under_test(rdip))
		return (DDI_SUCCESS);

#if defined(__sparc)
	/*
	 * check if this is a dvma_reserve - that one's like a
	 * dma_allochdl and needs to be handled separately
	 */
	if (request == DDI_DMA_RESERVE) {
		bofi_dvma_reserve(rdip, *(ddi_dma_handle_t *)objp);
		return (DDI_SUCCESS);
	}
#endif
	/*
	 * check we really have a shadow for this handle
	 */
	mutex_enter(&bofi_low_mutex);
	mutex_enter(&bofi_mutex);
	hhashp = HDL_HHASH(handle);
	for (hp = hhashp->hnext; hp != hhashp; hp = hp->hnext)
		if (hp->hdl.dma_handle == handle)
			break;
	if (hp == hhashp) {
		mutex_exit(&bofi_mutex);
		mutex_exit(&bofi_low_mutex);
		return (retval);
	}
	/*
	 * yes we have - see what kind of command this is
	 */
	switch (request) {
	case DDI_DMA_RELEASE:
		/*
		 * dvma release - release dummy handle and all the index handles
		 */
		dummyhp = hp;
		dummyhp->hnext->hprev = dummyhp->hprev;
		dummyhp->hprev->hnext = dummyhp->hnext;
		mutex_exit(&bofi_mutex);
		mutex_exit(&bofi_low_mutex);
		for (i = 0; i < dummyhp->len; i++) {
			hp = dummyhp->hparrayp[i];
			/*
			 * chek none of the index handles were still loaded
			 */
			if (hp->type != BOFI_NULL)
				panic("driver releasing loaded dvma");
			/*
			 * remove from dhash and inuse lists
			 */
			mutex_enter(&bofi_low_mutex);
			mutex_enter(&bofi_mutex);
			hp->dnext->dprev = hp->dprev;
			hp->dprev->dnext = hp->dnext;
			hp->next->prev = hp->prev;
			hp->prev->next = hp->next;
			mutex_exit(&bofi_mutex);
			mutex_exit(&bofi_low_mutex);

			if (bofi_sync_check && hp->allocaddr)
				ddi_umem_free(hp->umem_cookie);
			kmem_free(hp, sizeof (struct bofi_shadow));
		}
		kmem_free(dummyhp->hparrayp, dummyhp->len *
		    sizeof (struct bofi_shadow *));
		kmem_free(dummyhp, sizeof (struct bofi_shadow));
		return (retval);
	default:
		break;
	}
	mutex_exit(&bofi_mutex);
	mutex_exit(&bofi_low_mutex);
	return (retval);
}

#if defined(__sparc)
/*
 * dvma reserve case from bofi_dma_ctl()
 */
static void
bofi_dvma_reserve(dev_info_t *rdip, ddi_dma_handle_t handle)
{
	struct bofi_shadow *hp;
	struct bofi_shadow *dummyhp;
	struct bofi_shadow *dhashp;
	struct bofi_shadow *hhashp;
	ddi_dma_impl_t *mp;
	struct fast_dvma *nexus_private;
	int i, count;

	mp = (ddi_dma_impl_t *)handle;
	count = mp->dmai_ndvmapages;
	/*
	 * allocate dummy shadow handle structure
	 */
	dummyhp = kmem_zalloc(sizeof (*dummyhp), KM_SLEEP);
	if (mp->dmai_rflags & DMP_BYPASSNEXUS) {
		/*
		 * overlay our routines over the nexus's dvma routines
		 */
		nexus_private = (struct fast_dvma *)mp->dmai_nexus_private;
		dummyhp->save.dvma_ops = *(nexus_private->ops);
		nexus_private->ops = &bofi_dvma_ops;
	}
	/*
	 * now fill in the dummy handle. This just gets put on hhash queue
	 * so our dvma routines can find and index off to the handle they
	 * really want.
	 */
	(void) strncpy(dummyhp->name, ddi_get_name(rdip), NAMESIZE);
	dummyhp->instance = ddi_get_instance(rdip);
	dummyhp->rnumber = -1;
	dummyhp->dip = rdip;
	dummyhp->len = count;
	dummyhp->hdl.dma_handle = handle;
	dummyhp->link = NULL;
	dummyhp->type = BOFI_NULL;
	/*
	 * allocate space for real handles
	 */
	dummyhp->hparrayp = kmem_alloc(count *
	    sizeof (struct bofi_shadow *), KM_SLEEP);
	for (i = 0; i < count; i++) {
		/*
		 * allocate shadow handle structures and fill them in
		 */
		hp = kmem_zalloc(sizeof (*hp), KM_SLEEP);
		(void) strncpy(hp->name, ddi_get_name(rdip), NAMESIZE);
		hp->instance = ddi_get_instance(rdip);
		hp->rnumber = -1;
		hp->dip = rdip;
		hp->hdl.dma_handle = 0;
		hp->link = NULL;
		hp->type = BOFI_NULL;
		if (bofi_sync_check) {
			unsigned long pagemask = ddi_ptob(rdip, 1) - 1;
			/*
			 * Take a copy and set this to be hp->addr
			 * Data will be copied to and from the original on
			 * explicit and implicit ddi_dma_sync()
			 *
			 * - maintain page alignment because some devices
			 * assume it.
			 */
			hp->allocaddr = ddi_umem_alloc(
			    ((int)(uintptr_t)hp->addr & pagemask)
			    + pagemask + 1,
			    KM_SLEEP, &hp->umem_cookie);
			hp->addr = hp->allocaddr +
			    ((int)(uintptr_t)hp->addr & pagemask);
		}
		/*
		 * add to dhash and inuse lists.
		 * these don't go on hhash queue.
		 */
		mutex_enter(&bofi_low_mutex);
		mutex_enter(&bofi_mutex);
		hp->next = shadow_list.next;
		shadow_list.next->prev = hp;
		hp->prev = &shadow_list;
		shadow_list.next = hp;
		dhashp = HDL_DHASH(hp->dip);
		hp->dnext = dhashp->dnext;
		dhashp->dnext->dprev = hp;
		hp->dprev = dhashp;
		dhashp->dnext = hp;
		dummyhp->hparrayp[i] = hp;
		mutex_exit(&bofi_mutex);
		mutex_exit(&bofi_low_mutex);
	}
	/*
	 * add dummy handle to hhash list only
	 */
	mutex_enter(&bofi_low_mutex);
	mutex_enter(&bofi_mutex);
	hhashp = HDL_HHASH(handle);
	dummyhp->hnext = hhashp->hnext;
	hhashp->hnext->hprev = dummyhp;
	dummyhp->hprev = hhashp;
	hhashp->hnext = dummyhp;
	mutex_exit(&bofi_mutex);
	mutex_exit(&bofi_low_mutex);
}

/*
 * our dvma_kaddr_load()
 */
static void
bofi_dvma_kaddr_load(ddi_dma_handle_t h, caddr_t a, uint_t len, uint_t index,
    ddi_dma_cookie_t *cp)
{
	struct bofi_shadow *dummyhp;
	struct bofi_shadow *hp;
	struct bofi_shadow *hhashp;
	struct bofi_errent *ep;
	struct bofi_link   *lp;

	/*
	 * check we really have a dummy shadow for this handle
	 */
	mutex_enter(&bofi_low_mutex);
	mutex_enter(&bofi_mutex);
	hhashp = HDL_HHASH(h);
	for (dummyhp = hhashp->hnext; dummyhp != hhashp;
	    dummyhp = dummyhp->hnext)
		if (dummyhp->hdl.dma_handle == h)
			break;
	mutex_exit(&bofi_mutex);
	mutex_exit(&bofi_low_mutex);
	if (dummyhp == hhashp) {
		/*
		 * no dummy shadow - panic
		 */
		panic("driver dvma_kaddr_load with no reserve");
	}

	/*
	 * find real hp
	 */
	hp = dummyhp->hparrayp[index];
	/*
	 * check its not already loaded
	 */
	if (hp->type != BOFI_NULL)
		panic("driver loading loaded dvma");
	/*
	 * if were doing copying, just need to change origaddr and get
	 * nexus to map hp->addr again
	 * if not, set hp->addr to new address.
	 * - note these are always kernel virtual addresses - no need to map
	 */
	if (bofi_sync_check && hp->allocaddr) {
		hp->origaddr = a;
		a = hp->addr;
	} else
		hp->addr = a;
	hp->len = len;
	/*
	 * get nexus to do the real work
	 */
	dummyhp->save.dvma_ops.dvma_kaddr_load(h, a, len, index, cp);
	/*
	 * chain on any pre-existing errdefs that apply to this dma_handle
	 * no need to corrupt - there's no implicit dma_sync on this one
	 */
	mutex_enter(&bofi_low_mutex);
	mutex_enter(&bofi_mutex);
	hp->type = BOFI_DMA_HDL;
	for (ep = errent_listp; ep != NULL; ep = ep->next) {
		if (ddi_name_to_major(hp->name) ==
		    ddi_name_to_major(ep->name) &&
		    hp->instance == ep->errdef.instance &&
		    (ep->errdef.rnumber == -1 ||
		    hp->rnumber == ep->errdef.rnumber) &&
		    ((ep->errdef.access_type & BOFI_DMA_RW) &&
		    (((uintptr_t)(hp->addr + ep->errdef.offset +
		    ep->errdef.len) & ~LLSZMASK) >
		    ((uintptr_t)((hp->addr + ep->errdef.offset) +
		    LLSZMASK) & ~LLSZMASK)))) {
			lp = bofi_link_freelist;
			if (lp != NULL) {
				bofi_link_freelist = lp->link;
				lp->errentp = ep;
				lp->link = hp->link;
				hp->link = lp;
			}
		}
	}
	mutex_exit(&bofi_mutex);
	mutex_exit(&bofi_low_mutex);
}

/*
 * our dvma_unload()
 */
static void
bofi_dvma_unload(ddi_dma_handle_t h, uint_t index, uint_t view)
{
	struct bofi_link *lp, *next_lp;
	struct bofi_errent *ep;
	struct bofi_shadow *dummyhp;
	struct bofi_shadow *hp;
	struct bofi_shadow *hhashp;

	/*
	 * check we really have a dummy shadow for this handle
	 */
	mutex_enter(&bofi_low_mutex);
	mutex_enter(&bofi_mutex);
	hhashp = HDL_HHASH(h);
	for (dummyhp = hhashp->hnext; dummyhp != hhashp;
	    dummyhp = dummyhp->hnext)
		if (dummyhp->hdl.dma_handle == h)
			break;
	mutex_exit(&bofi_mutex);
	mutex_exit(&bofi_low_mutex);
	if (dummyhp == hhashp) {
		/*
		 * no dummy shadow - panic
		 */
		panic("driver dvma_unload with no reserve");
	}
	dummyhp->save.dvma_ops.dvma_unload(h, index, view);
	/*
	 * find real hp
	 */
	hp = dummyhp->hparrayp[index];
	/*
	 * check its not already unloaded
	 */
	if (hp->type == BOFI_NULL)
		panic("driver unloading unloaded dvma");
	/*
	 * free any errdef link structures tagged on to this
	 * shadow handle - do corruption if necessary
	 */
	mutex_enter(&bofi_low_mutex);
	mutex_enter(&bofi_mutex);
	for (lp = hp->link; lp != NULL; ) {
		next_lp = lp->link;
		ep = lp->errentp;
		if ((ep->errdef.access_type & BOFI_DMA_R) &&
		    (view == DDI_DMA_SYNC_FORCPU ||
		    view == DDI_DMA_SYNC_FORKERNEL) &&
		    (ep->state & BOFI_DEV_ACTIVE)) {
			do_dma_corrupt(hp, ep, view, 0, hp->len);
		}
		lp->link = bofi_link_freelist;
		bofi_link_freelist = lp;
		lp = next_lp;
	}
	hp->link = NULL;
	hp->type = BOFI_NULL;
	mutex_exit(&bofi_mutex);
	mutex_exit(&bofi_low_mutex);
	/*
	 * if there is an explicit sync_for_cpu, then do copy to original
	 */
	if (bofi_sync_check &&
	    (view == DDI_DMA_SYNC_FORCPU || view == DDI_DMA_SYNC_FORKERNEL))
		if (hp->allocaddr)
			xbcopy(hp->addr, hp->origaddr, hp->len);
}

/*
 * our dvma_unload()
 */
static void
bofi_dvma_sync(ddi_dma_handle_t h, uint_t index, uint_t view)
{
	struct bofi_link *lp;
	struct bofi_errent *ep;
	struct bofi_shadow *hp;
	struct bofi_shadow *dummyhp;
	struct bofi_shadow *hhashp;

	/*
	 * check we really have a dummy shadow for this handle
	 */
	mutex_enter(&bofi_low_mutex);
	mutex_enter(&bofi_mutex);
	hhashp = HDL_HHASH(h);
	for (dummyhp = hhashp->hnext; dummyhp != hhashp;
	    dummyhp = dummyhp->hnext)
		if (dummyhp->hdl.dma_handle == h)
			break;
	mutex_exit(&bofi_mutex);
	mutex_exit(&bofi_low_mutex);
	if (dummyhp == hhashp) {
		/*
		 * no dummy shadow - panic
		 */
		panic("driver dvma_sync with no reserve");
	}
	/*
	 * find real hp
	 */
	hp = dummyhp->hparrayp[index];
	/*
	 * check its already loaded
	 */
	if (hp->type == BOFI_NULL)
		panic("driver syncing unloaded dvma");
	if (view == DDI_DMA_SYNC_FORCPU || view == DDI_DMA_SYNC_FORKERNEL)
		/*
		 * in this case do sync first
		 */
		dummyhp->save.dvma_ops.dvma_sync(h, index, view);
	/*
	 * if there is an explicit sync_for_dev, then do copy from original
	 */
	if (bofi_sync_check && view == DDI_DMA_SYNC_FORDEV) {
		if (hp->allocaddr)
			xbcopy(hp->origaddr, hp->addr, hp->len);
	}
	/*
	 * do corruption if necessary
	 */
	mutex_enter(&bofi_low_mutex);
	mutex_enter(&bofi_mutex);
	for (lp = hp->link; lp != NULL; lp = lp->link) {
		ep = lp->errentp;
		if ((((ep->errdef.access_type & BOFI_DMA_R) &&
		    (view == DDI_DMA_SYNC_FORCPU ||
		    view == DDI_DMA_SYNC_FORKERNEL)) ||
		    ((ep->errdef.access_type & BOFI_DMA_W) &&
		    (view == DDI_DMA_SYNC_FORDEV))) &&
		    (ep->state & BOFI_DEV_ACTIVE)) {
			do_dma_corrupt(hp, ep, view, 0, hp->len);
		}
	}
	mutex_exit(&bofi_mutex);
	mutex_exit(&bofi_low_mutex);
	/*
	 * if there is an explicit sync_for_cpu, then do copy to original
	 */
	if (bofi_sync_check &&
	    (view == DDI_DMA_SYNC_FORCPU || view == DDI_DMA_SYNC_FORKERNEL)) {
		if (hp->allocaddr)
			xbcopy(hp->addr, hp->origaddr, hp->len);
	}
	if (view == DDI_DMA_SYNC_FORDEV)
		/*
		 * in this case do sync last
		 */
		dummyhp->save.dvma_ops.dvma_sync(h, index, view);
}
#endif

/*
 * bofi intercept routine - gets called instead of users interrupt routine
 */
static uint_t
bofi_intercept_intr(caddr_t xp, caddr_t arg2)
{
	struct bofi_errent *ep;
	struct bofi_link   *lp;
	struct bofi_shadow *hp;
	int intr_count = 1;
	int i;
	uint_t retval = DDI_INTR_UNCLAIMED;
	uint_t result;
	int unclaimed_counter = 0;
	int jabber_detected = 0;

	hp = (struct bofi_shadow *)xp;
	/*
	 * check if nothing to do
	 */
	if (hp->link == NULL)
		return (hp->save.intr.int_handler
		    (hp->save.intr.int_handler_arg1, arg2));
	mutex_enter(&bofi_mutex);
	/*
	 * look for any errdefs
	 */
	for (lp = hp->link; lp != NULL; lp = lp->link) {
		ep = lp->errentp;
		if (ep->state & BOFI_DEV_ACTIVE) {
			/*
			 * got one
			 */
			if ((ep->errdef.access_count ||
			    ep->errdef.fail_count) &&
			    (ep->errdef.access_type & BOFI_LOG))
				log_acc_event(ep, BOFI_INTR, 0, 0, 1, 0);
			if (ep->errdef.access_count > 1) {
				ep->errdef.access_count--;
			} else if (ep->errdef.fail_count > 0) {
				ep->errdef.fail_count--;
				ep->errdef.access_count = 0;
				/*
				 * OK do "corruption"
				 */
				if (ep->errstate.fail_time == 0)
					ep->errstate.fail_time = bofi_gettime();
				switch (ep->errdef.optype) {
				case BOFI_DELAY_INTR:
					if (!hp->hilevel) {
						drv_usecwait
						    (ep->errdef.operand);
					}
					break;
				case BOFI_LOSE_INTR:
					intr_count = 0;
					break;
				case BOFI_EXTRA_INTR:
					intr_count += ep->errdef.operand;
					break;
				default:
					break;
				}
			}
		}
	}
	mutex_exit(&bofi_mutex);
	/*
	 * send extra or fewer interrupts as requested
	 */
	for (i = 0; i < intr_count; i++) {
		result = hp->save.intr.int_handler
		    (hp->save.intr.int_handler_arg1, arg2);
		if (result == DDI_INTR_CLAIMED)
			unclaimed_counter >>= 1;
		else if (++unclaimed_counter >= 20)
			jabber_detected = 1;
		if (i == 0)
			retval = result;
	}
	/*
	 * if more than 1000 spurious interrupts requested and
	 * jabber not detected - give warning
	 */
	if (intr_count > 1000 && !jabber_detected)
		panic("undetected interrupt jabber: %s%d",
		    hp->name, hp->instance);
	/*
	 * return first response - or "unclaimed" if none
	 */
	return (retval);
}


/*
 * our ddi_check_acc_hdl
 */
/* ARGSUSED */
static int
bofi_check_acc_hdl(ddi_acc_impl_t *handle)
{
	struct bofi_shadow *hp;
	struct bofi_link   *lp;
	uint_t result = 0;

	hp = handle->ahi_common.ah_bus_private;
	if (!hp->link || !mutex_tryenter(&bofi_mutex)) {
		return (0);
	}
	for (lp = hp->link; lp != NULL; lp = lp->link) {
		/*
		 * OR in error state from all associated
		 * errdef structures
		 */
		if (lp->errentp->errdef.access_count == 0 &&
		    (lp->errentp->state & BOFI_DEV_ACTIVE)) {
			result = (lp->errentp->errdef.acc_chk & 1);
		}
	}
	mutex_exit(&bofi_mutex);
	return (result);
}

/*
 * our ddi_check_dma_hdl
 */
/* ARGSUSED */
static int
bofi_check_dma_hdl(ddi_dma_impl_t *handle)
{
	struct bofi_shadow *hp;
	struct bofi_link   *lp;
	struct bofi_shadow *hhashp;
	uint_t result = 0;

	if (!mutex_tryenter(&bofi_mutex)) {
		return (0);
	}
	hhashp = HDL_HHASH(handle);
	for (hp = hhashp->hnext; hp != hhashp; hp = hp->hnext)
		if (hp->hdl.dma_handle == (ddi_dma_handle_t)handle)
			break;
	if (hp == hhashp) {
		mutex_exit(&bofi_mutex);
		return (0);
	}
	if (!hp->link) {
		mutex_exit(&bofi_mutex);
		return (0);
	}
	for (lp = hp->link; lp != NULL; lp = lp->link) {
		/*
		 * OR in error state from all associated
		 * errdef structures
		 */
		if (lp->errentp->errdef.access_count == 0 &&
		    (lp->errentp->state & BOFI_DEV_ACTIVE)) {
			result = ((lp->errentp->errdef.acc_chk & 2) ? 1 : 0);
		}
	}
	mutex_exit(&bofi_mutex);
	return (result);
}


/* ARGSUSED */
static int
bofi_post_event(dev_info_t *dip, dev_info_t *rdip,
    ddi_eventcookie_t eventhdl, void *impl_data)
{
	ddi_eventcookie_t ec;
	struct ddi_fault_event_data *arg;
	struct bofi_errent *ep;
	struct bofi_shadow *hp;
	struct bofi_shadow *dhashp;
	struct bofi_link   *lp;

	ASSERT(eventhdl);
	if (ddi_get_eventcookie(dip, DDI_DEVI_FAULT_EVENT, &ec) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (ec != eventhdl)
		return (save_bus_ops.bus_post_event(dip, rdip, eventhdl,
		    impl_data));

	arg = (struct ddi_fault_event_data *)impl_data;
	mutex_enter(&bofi_mutex);
	/*
	 * find shadow handles with appropriate dev_infos
	 * and set error reported on all associated errdef structures
	 */
	dhashp = HDL_DHASH(arg->f_dip);
	for (hp = dhashp->dnext; hp != dhashp; hp = hp->dnext) {
		if (hp->dip == arg->f_dip) {
			for (lp = hp->link; lp != NULL; lp = lp->link) {
				ep = lp->errentp;
				ep->errstate.errmsg_count++;
				if ((ep->errstate.msg_time == 0 ||
				    ep->errstate.severity > arg->f_impact) &&
				    (ep->state & BOFI_DEV_ACTIVE)) {
					ep->errstate.msg_time = bofi_gettime();
					ep->errstate.severity = arg->f_impact;
					(void) strncpy(ep->errstate.buffer,
					    arg->f_message, ERRMSGSIZE);
					ddi_trigger_softintr(ep->softintr_id);
				}
			}
		}
	}
	mutex_exit(&bofi_mutex);
	return (save_bus_ops.bus_post_event(dip, rdip, eventhdl, impl_data));
}

/*ARGSUSED*/
static int
bofi_fm_ereport_callback(sysevent_t *ev, void *cookie)
{
	char *class = "";
	char *path = "";
	char *ptr;
	nvlist_t *nvlist;
	nvlist_t *detector;
	ddi_fault_impact_t impact;
	struct bofi_errent *ep;
	struct bofi_shadow *hp;
	struct bofi_link   *lp;
	char service_class[FM_MAX_CLASS];
	char hppath[MAXPATHLEN];
	int service_ereport = 0;

	(void) sysevent_get_attr_list(ev, &nvlist);
	(void) nvlist_lookup_string(nvlist, FM_CLASS, &class);
	if (nvlist_lookup_nvlist(nvlist, FM_EREPORT_DETECTOR, &detector) == 0)
		(void) nvlist_lookup_string(detector, FM_FMRI_DEV_PATH, &path);

	(void) snprintf(service_class, FM_MAX_CLASS, "%s.%s.%s.",
	    FM_EREPORT_CLASS, DDI_IO_CLASS, DDI_FM_SERVICE_IMPACT);
	if (strncmp(class, service_class, strlen(service_class) - 1) == 0)
		service_ereport = 1;

	mutex_enter(&bofi_mutex);
	/*
	 * find shadow handles with appropriate dev_infos
	 * and set error reported on all associated errdef structures
	 */
	for (hp = shadow_list.next; hp != &shadow_list; hp = hp->next) {
		(void) ddi_pathname(hp->dip, hppath);
		if (strcmp(path, hppath) != 0)
			continue;
		for (lp = hp->link; lp != NULL; lp = lp->link) {
			ep = lp->errentp;
			ep->errstate.errmsg_count++;
			if (!(ep->state & BOFI_DEV_ACTIVE))
				continue;
			if (ep->errstate.msg_time != 0)
				continue;
			if (service_ereport) {
				ptr = class + strlen(service_class);
				if (strcmp(ptr, DDI_FM_SERVICE_LOST) == 0)
					impact = DDI_SERVICE_LOST;
				else if (strcmp(ptr,
				    DDI_FM_SERVICE_DEGRADED) == 0)
					impact = DDI_SERVICE_DEGRADED;
				else if (strcmp(ptr,
				    DDI_FM_SERVICE_RESTORED) == 0)
					impact = DDI_SERVICE_RESTORED;
				else
					impact = DDI_SERVICE_UNAFFECTED;
				if (ep->errstate.severity > impact)
					ep->errstate.severity = impact;
			} else if (ep->errstate.buffer[0] == '\0') {
				(void) strncpy(ep->errstate.buffer, class,
				    ERRMSGSIZE);
			}
			if (ep->errstate.buffer[0] != '\0' &&
			    ep->errstate.severity < DDI_SERVICE_RESTORED) {
				ep->errstate.msg_time = bofi_gettime();
				ddi_trigger_softintr(ep->softintr_id);
			}
		}
	}
	nvlist_free(nvlist);
	mutex_exit(&bofi_mutex);
	return (0);
}

/*
 * our intr_ops routine
 */
static int
bofi_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	int retval;
	struct bofi_shadow *hp;
	struct bofi_shadow *dhashp;
	struct bofi_shadow *hhashp;
	struct bofi_errent *ep;
	struct bofi_link   *lp, *next_lp;

	switch (intr_op) {
	case DDI_INTROP_ADDISR:
		/*
		 * if driver_list is set, only intercept those drivers
		 */
		if (!driver_under_test(rdip))
			return (save_bus_ops.bus_intr_op(dip, rdip,
			    intr_op, hdlp, result));
		/*
		 * allocate shadow handle structure and fill in
		 */
		hp = kmem_zalloc(sizeof (struct bofi_shadow), KM_SLEEP);
		(void) strncpy(hp->name, ddi_get_name(rdip), NAMESIZE);
		hp->instance = ddi_get_instance(rdip);
		hp->save.intr.int_handler = hdlp->ih_cb_func;
		hp->save.intr.int_handler_arg1 = hdlp->ih_cb_arg1;
		hdlp->ih_cb_func = (ddi_intr_handler_t *)bofi_intercept_intr;
		hdlp->ih_cb_arg1 = (caddr_t)hp;
		hp->bofi_inum = hdlp->ih_inum;
		hp->dip = rdip;
		hp->link = NULL;
		hp->type = BOFI_INT_HDL;
		/*
		 * save whether hilevel or not
		 */

		if (hdlp->ih_pri >= ddi_intr_get_hilevel_pri())
			hp->hilevel = 1;
		else
			hp->hilevel = 0;

		/*
		 * call nexus to do real work, but specifying our handler, and
		 * our shadow handle as argument
		 */
		retval = save_bus_ops.bus_intr_op(dip, rdip,
		    intr_op, hdlp, result);
		if (retval != DDI_SUCCESS) {
			kmem_free(hp, sizeof (struct bofi_shadow));
			return (retval);
		}
		/*
		 * add to dhash, hhash and inuse lists
		 */
		mutex_enter(&bofi_low_mutex);
		mutex_enter(&bofi_mutex);
		hp->next = shadow_list.next;
		shadow_list.next->prev = hp;
		hp->prev = &shadow_list;
		shadow_list.next = hp;
		hhashp = HDL_HHASH(hdlp->ih_inum);
		hp->hnext = hhashp->hnext;
		hhashp->hnext->hprev = hp;
		hp->hprev = hhashp;
		hhashp->hnext = hp;
		dhashp = HDL_DHASH(hp->dip);
		hp->dnext = dhashp->dnext;
		dhashp->dnext->dprev = hp;
		hp->dprev = dhashp;
		dhashp->dnext = hp;
		/*
		 * chain on any pre-existing errdefs that apply to this
		 * acc_handle
		 */
		for (ep = errent_listp; ep != NULL; ep = ep->next) {
			if (ddi_name_to_major(hp->name) ==
			    ddi_name_to_major(ep->name) &&
			    hp->instance == ep->errdef.instance &&
			    (ep->errdef.access_type & BOFI_INTR)) {
				lp = bofi_link_freelist;
				if (lp != NULL) {
					bofi_link_freelist = lp->link;
					lp->errentp = ep;
					lp->link = hp->link;
					hp->link = lp;
				}
			}
		}
		mutex_exit(&bofi_mutex);
		mutex_exit(&bofi_low_mutex);
		return (retval);
	case DDI_INTROP_REMISR:
		/*
		 * call nexus routine first
		 */
		retval = save_bus_ops.bus_intr_op(dip, rdip,
		    intr_op, hdlp, result);
		/*
		 * find shadow handle
		 */
		mutex_enter(&bofi_low_mutex);
		mutex_enter(&bofi_mutex);
		hhashp = HDL_HHASH(hdlp->ih_inum);
		for (hp = hhashp->hnext; hp != hhashp; hp = hp->hnext) {
			if (hp->dip == rdip &&
			    hp->type == BOFI_INT_HDL &&
			    hp->bofi_inum == hdlp->ih_inum) {
				break;
			}
		}
		if (hp == hhashp) {
			mutex_exit(&bofi_mutex);
			mutex_exit(&bofi_low_mutex);
			return (retval);
		}
		/*
		 * found one - remove from dhash, hhash and inuse lists
		 */
		hp->hnext->hprev = hp->hprev;
		hp->hprev->hnext = hp->hnext;
		hp->dnext->dprev = hp->dprev;
		hp->dprev->dnext = hp->dnext;
		hp->next->prev = hp->prev;
		hp->prev->next = hp->next;
		/*
		 * free any errdef link structures
		 * tagged on to this shadow handle
		 */
		for (lp = hp->link; lp != NULL; ) {
			next_lp = lp->link;
			lp->link = bofi_link_freelist;
			bofi_link_freelist = lp;
			lp = next_lp;
		}
		hp->link = NULL;
		mutex_exit(&bofi_mutex);
		mutex_exit(&bofi_low_mutex);
		kmem_free(hp, sizeof (struct bofi_shadow));
		return (retval);
	default:
		return (save_bus_ops.bus_intr_op(dip, rdip,
		    intr_op, hdlp, result));
	}
}

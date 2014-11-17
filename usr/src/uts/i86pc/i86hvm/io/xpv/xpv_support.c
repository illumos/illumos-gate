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

#include <sys/modctl.h>
#include <sys/types.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/sunndi.h>
#include <sys/sunddi.h>
#include <sys/ddi_subrdefs.h>
#include <sys/xpv_support.h>
#include <sys/xen_errno.h>
#include <sys/hypervisor.h>
#include <sys/gnttab.h>
#include <sys/xenbus_comms.h>
#include <sys/xenbus_impl.h>
#include <xen/sys/xendev.h>
#include <sys/sysmacros.h>
#include <sys/x86_archext.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/pc_mmu.h>
#include <sys/cmn_err.h>
#include <sys/cpr.h>
#include <sys/ddi.h>
#include <vm/seg_kmem.h>
#include <vm/as.h>
#include <vm/hat_pte.h>
#include <vm/hat_i86.h>

#define	XPV_MINOR 0
#define	XPV_BUFSIZE 128

/* virtual addr for the store_mfn page */
caddr_t xb_addr;

dev_info_t *xpv_dip;
static dev_info_t *xpvd_dip;

#ifdef DEBUG
int xen_suspend_debug;

#define	SUSPEND_DEBUG if (xen_suspend_debug) xen_printf
#else
#define	SUSPEND_DEBUG(...)
#endif

/*
 * Forward declarations
 */
static int xpv_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int xpv_attach(dev_info_t *, ddi_attach_cmd_t);
static int xpv_detach(dev_info_t *, ddi_detach_cmd_t);
static int xpv_open(dev_t *, int, int, cred_t *);
static int xpv_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static struct cb_ops xpv_cb_ops = {
	xpv_open,
	nulldev,	/* close */
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	xpv_ioctl,	/* ioctl */
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* poll */
	ddi_prop_op,
	NULL,
	D_MP,
	CB_REV,
	NULL,
	NULL
};

static struct dev_ops xpv_dv_ops = {
	DEVO_REV,
	0,
	xpv_getinfo,
	nulldev,	/* identify */
	nulldev,	/* probe */
	xpv_attach,
	xpv_detach,
	nodev,		/* reset */
	&xpv_cb_ops,
	NULL,		/* struct bus_ops */
	NULL,		/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"xpv driver",
	&xpv_dv_ops
};

static struct modlinkage modl = {
	MODREV_1,
	{
		(void *)&modldrv,
		NULL		/* null termination */
	}
};

static ddi_dma_attr_t xpv_dma_attr = {
	DMA_ATTR_V0,		/* version of this structure */
	0,			/* lowest usable address */
	0xffffffffffffffffULL,	/* highest usable address */
	0x7fffffff,		/* maximum DMAable byte count */
	MMU_PAGESIZE,		/* alignment in bytes */
	0x7ff,			/* bitmap of burst sizes */
	1,			/* minimum transfer */
	0xffffffffU,		/* maximum transfer */
	0x7fffffffULL,		/* maximum segment length */
	1,			/* maximum number of segments */
	1,			/* granularity */
	0,			/* flags (reserved) */
};

static ddi_device_acc_attr_t xpv_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

#define	MAX_ALLOCATIONS 10
static ddi_dma_handle_t xpv_dma_handle[MAX_ALLOCATIONS];
static ddi_acc_handle_t xpv_dma_acchandle[MAX_ALLOCATIONS];
static int xen_alloc_cnt = 0;

void *
xen_alloc_pages(pgcnt_t cnt)
{
	size_t len;
	int a = xen_alloc_cnt++;
	caddr_t addr;

	ASSERT(xen_alloc_cnt < MAX_ALLOCATIONS);
	if (ddi_dma_alloc_handle(xpv_dip, &xpv_dma_attr, DDI_DMA_SLEEP, 0,
	    &xpv_dma_handle[a]) != DDI_SUCCESS)
		return (NULL);

	if (ddi_dma_mem_alloc(xpv_dma_handle[a], MMU_PAGESIZE * cnt,
	    &xpv_accattr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, 0,
	    &addr, &len, &xpv_dma_acchandle[a]) != DDI_SUCCESS) {
		ddi_dma_free_handle(&xpv_dma_handle[a]);
		cmn_err(CE_WARN, "Couldn't allocate memory for xpv devices");
		return (NULL);
	}
	return (addr);
}

/*
 * This function is invoked twice, first time with reprogram=0 to set up
 * the xpvd portion of the device tree. The second time it is ignored.
 */
static void
xpv_enumerate(int reprogram)
{
	dev_info_t *dip;

	if (reprogram != 0)
		return;

	ndi_devi_alloc_sleep(ddi_root_node(), "xpvd",
	    (pnode_t)DEVI_SID_NODEID, &dip);

	(void) ndi_devi_bind_driver(dip, 0);

	/*
	 * Too early to enumerate split device drivers in domU
	 * since we need to create taskq thread during enumeration.
	 * So, we only enumerate softdevs and console here.
	 */
	xendev_enum_all(dip, B_TRUE);
}

/*
 * Translate a hypervisor errcode to a Solaris error code.
 */
int
xen_xlate_errcode(int error)
{
#define	CASE(num)	case X_##num: error = num; break

	switch (-error) {
		CASE(EPERM);    CASE(ENOENT);   CASE(ESRCH);
		CASE(EINTR);	CASE(EIO);	CASE(ENXIO);
		CASE(E2BIG);    CASE(ENOMEM);   CASE(EACCES);
		CASE(EFAULT);   CASE(EBUSY);    CASE(EEXIST);
		CASE(ENODEV);   CASE(EISDIR);   CASE(EINVAL);
		CASE(ENOSPC);   CASE(ESPIPE);   CASE(EROFS);
		CASE(ENOSYS);   CASE(ENOTEMPTY); CASE(EISCONN);
		CASE(ENODATA);
		default:
		panic("xen_xlate_errcode: unknown error %d", error);
	}
	return (error);
#undef CASE
}

/*PRINTFLIKE1*/
void
xen_printf(const char *fmt, ...)
{
	va_list adx;

	va_start(adx, fmt);
	printf(fmt, adx);
	va_end(adx);
}

/*
 * Stub functions to get the FE drivers to build, and to catch drivers that
 * misbehave in HVM domains.
 */
/*ARGSUSED*/
void
xen_release_pfn(pfn_t pfn)
{
	panic("xen_release_pfn() is not supported in HVM domains");
}

/*ARGSUSED*/
void
reassign_pfn(pfn_t pfn, mfn_t mfn)
{
	panic("reassign_pfn() is not supported in HVM domains");
}

/*ARGSUSED*/
long
balloon_free_pages(uint_t page_cnt, mfn_t *mfns, caddr_t kva, pfn_t *pfns)
{
	panic("balloon_free_pages() is not supported in HVM domains");
	return (0);
}

/*ARGSUSED*/
void
balloon_drv_added(int64_t delta)
{
	panic("balloon_drv_added() is not supported in HVM domains");
}

/*
 * Add a mapping for the machine page at the given virtual address.
 */
void
kbm_map_ma(maddr_t ma, uintptr_t va, uint_t level)
{
	ASSERT(level == 0);

	hat_devload(kas.a_hat, (caddr_t)va, MMU_PAGESIZE,
	    mmu_btop(ma), PROT_READ | PROT_WRITE, HAT_LOAD);
}

/*ARGSUSED*/
int
xen_map_gref(uint_t cmd, gnttab_map_grant_ref_t *mapop, uint_t count,
    boolean_t uvaddr)
{
	long rc;

	ASSERT(cmd == GNTTABOP_map_grant_ref);
	rc = HYPERVISOR_grant_table_op(cmd, mapop, count);

	return (rc);
}

static struct xenbus_watch shutdown_watch;
taskq_t *xen_shutdown_tq;

#define	SHUTDOWN_INVALID	-1
#define	SHUTDOWN_POWEROFF	0
#define	SHUTDOWN_REBOOT		1
#define	SHUTDOWN_SUSPEND	2
#define	SHUTDOWN_HALT		3
#define	SHUTDOWN_MAX		4

#define	SHUTDOWN_TIMEOUT_SECS (60 * 5)

int
xen_suspend_devices(dev_info_t *dip)
{
	int error;
	char buf[XPV_BUFSIZE];

	SUSPEND_DEBUG("xen_suspend_devices\n");

	for (; dip != NULL; dip = ddi_get_next_sibling(dip)) {
		if (xen_suspend_devices(ddi_get_child(dip)))
			return (ENXIO);
		if (ddi_get_driver(dip) == NULL)
			continue;
		SUSPEND_DEBUG("Suspending device %s\n", ddi_deviname(dip, buf));
		ASSERT((DEVI(dip)->devi_cpr_flags & DCF_CPR_SUSPENDED) == 0);


		if (!i_ddi_devi_attached(dip)) {
			error = DDI_FAILURE;
		} else {
			error = devi_detach(dip, DDI_SUSPEND);
		}

		if (error == DDI_SUCCESS) {
			DEVI(dip)->devi_cpr_flags |= DCF_CPR_SUSPENDED;
		} else {
			SUSPEND_DEBUG("WARNING: Unable to suspend device %s\n",
			    ddi_deviname(dip, buf));
			cmn_err(CE_WARN, "Unable to suspend device %s.",
			    ddi_deviname(dip, buf));
			cmn_err(CE_WARN, "Device is busy or does not "
			    "support suspend/resume.");
				return (ENXIO);
		}
	}
	return (0);
}

int
xen_resume_devices(dev_info_t *start, int resume_failed)
{
	dev_info_t *dip, *next, *last = NULL;
	int did_suspend;
	int error = resume_failed;
	char buf[XPV_BUFSIZE];

	SUSPEND_DEBUG("xen_resume_devices\n");

	while (last != start) {
		dip = start;
		next = ddi_get_next_sibling(dip);
		while (next != last) {
			dip = next;
			next = ddi_get_next_sibling(dip);
		}

		/*
		 * cpr is the only one that uses this field and the device
		 * itself hasn't resumed yet, there is no need to use a
		 * lock, even though kernel threads are active by now.
		 */
		did_suspend = DEVI(dip)->devi_cpr_flags & DCF_CPR_SUSPENDED;
		if (did_suspend)
			DEVI(dip)->devi_cpr_flags &= ~DCF_CPR_SUSPENDED;

		/*
		 * There may be background attaches happening on devices
		 * that were not originally suspended by cpr, so resume
		 * only devices that were suspended by cpr. Also, stop
		 * resuming after the first resume failure, but traverse
		 * the entire tree to clear the suspend flag.
		 */
		if (did_suspend && !error) {
			SUSPEND_DEBUG("Resuming device %s\n",
			    ddi_deviname(dip, buf));
			/*
			 * If a device suspended by cpr gets detached during
			 * the resume process (for example, due to hotplugging)
			 * before cpr gets around to issuing it a DDI_RESUME,
			 * we'll have problems.
			 */
			if (!i_ddi_devi_attached(dip)) {
				cmn_err(CE_WARN, "Skipping %s, device "
				    "not ready for resume",
				    ddi_deviname(dip, buf));
			} else {
				if (devi_attach(dip, DDI_RESUME) !=
				    DDI_SUCCESS) {
					error = ENXIO;
				}
			}
		}

		if (error == ENXIO) {
			cmn_err(CE_WARN, "Unable to resume device %s",
			    ddi_deviname(dip, buf));
		}

		error = xen_resume_devices(ddi_get_child(dip), error);
		last = dip;
	}

	return (error);
}

/*ARGSUSED*/
static int
check_xpvd(dev_info_t *dip, void *arg)
{
	char *name;

	name = ddi_node_name(dip);
	if (name == NULL || strcmp(name, "xpvd")) {
		return (DDI_WALK_CONTINUE);
	} else {
		xpvd_dip = dip;
		return (DDI_WALK_TERMINATE);
	}
}

/*
 * Top level routine to direct suspend/resume of a domain.
 */
void
xen_suspend_domain(void)
{
	extern void rtcsync(void);
	extern void ec_resume(void);
	extern kmutex_t ec_lock;
	struct xen_add_to_physmap xatp;
	ulong_t flags;
	int err;

	cmn_err(CE_NOTE, "Domain suspending for save/migrate");

	SUSPEND_DEBUG("xen_suspend_domain\n");

	/*
	 * We only want to suspend the PV devices, since the emulated devices
	 * are suspended by saving the emulated device state.  The PV devices
	 * are all children of the xpvd nexus device.  So we search the
	 * device tree for the xpvd node to use as the root of the tree to
	 * be suspended.
	 */
	if (xpvd_dip == NULL)
		ddi_walk_devs(ddi_root_node(), check_xpvd, NULL);

	/*
	 * suspend interrupts and devices
	 */
	if (xpvd_dip != NULL)
		(void) xen_suspend_devices(ddi_get_child(xpvd_dip));
	else
		cmn_err(CE_WARN, "No PV devices found to suspend");
	SUSPEND_DEBUG("xenbus_suspend\n");
	xenbus_suspend();

	mutex_enter(&cpu_lock);

	/*
	 * Suspend on vcpu 0
	 */
	thread_affinity_set(curthread, 0);
	kpreempt_disable();

	if (ncpus > 1)
		pause_cpus(NULL, NULL);
	/*
	 * We can grab the ec_lock as it's a spinlock with a high SPL. Hence
	 * any holder would have dropped it to get through pause_cpus().
	 */
	mutex_enter(&ec_lock);

	/*
	 * From here on in, we can't take locks.
	 */

	flags = intr_clear();

	SUSPEND_DEBUG("HYPERVISOR_suspend\n");
	/*
	 * At this point we suspend and sometime later resume.
	 * Note that this call may return with an indication of a cancelled
	 * for now no matter ehat the return we do a full resume of all
	 * suspended drivers, etc.
	 */
	(void) HYPERVISOR_shutdown(SHUTDOWN_suspend);

	/*
	 * Point HYPERVISOR_shared_info to the proper place.
	 */
	xatp.domid = DOMID_SELF;
	xatp.idx = 0;
	xatp.space = XENMAPSPACE_shared_info;
	xatp.gpfn = xen_shared_info_frame;
	if ((err = HYPERVISOR_memory_op(XENMEM_add_to_physmap, &xatp)) != 0)
		panic("Could not set shared_info page. error: %d", err);

	SUSPEND_DEBUG("gnttab_resume\n");
	gnttab_resume();

	SUSPEND_DEBUG("ec_resume\n");
	ec_resume();

	intr_restore(flags);

	if (ncpus > 1)
		start_cpus();

	mutex_exit(&ec_lock);
	mutex_exit(&cpu_lock);

	/*
	 * Now we can take locks again.
	 */

	rtcsync();

	SUSPEND_DEBUG("xenbus_resume\n");
	xenbus_resume();
	SUSPEND_DEBUG("xen_resume_devices\n");
	if (xpvd_dip != NULL)
		(void) xen_resume_devices(ddi_get_child(xpvd_dip), 0);

	thread_affinity_clear(curthread);
	kpreempt_enable();

	SUSPEND_DEBUG("finished xen_suspend_domain\n");

	cmn_err(CE_NOTE, "domain restore/migrate completed");
}

static void
xen_dirty_shutdown(void *arg)
{
	int cmd = (uintptr_t)arg;

	cmn_err(CE_WARN, "Externally requested shutdown failed or "
	    "timed out.\nShutting down.\n");

	switch (cmd) {
	case SHUTDOWN_HALT:
	case SHUTDOWN_POWEROFF:
		(void) kadmin(A_SHUTDOWN, AD_POWEROFF, NULL, kcred);
		break;
	case SHUTDOWN_REBOOT:
		(void) kadmin(A_REBOOT, AD_BOOT, NULL, kcred);
		break;
	}
}

static void
xen_shutdown(void *arg)
{
	int cmd = (uintptr_t)arg;
	proc_t *initpp;

	ASSERT(cmd > SHUTDOWN_INVALID && cmd < SHUTDOWN_MAX);

	if (cmd == SHUTDOWN_SUSPEND) {
		xen_suspend_domain();
		return;
	}

	switch (cmd) {
	case SHUTDOWN_POWEROFF:
		force_shutdown_method = AD_POWEROFF;
		break;
	case SHUTDOWN_HALT:
		force_shutdown_method = AD_HALT;
		break;
	case SHUTDOWN_REBOOT:
		force_shutdown_method = AD_BOOT;
		break;
	}


	/*
	 * If we're still booting and init(1) isn't set up yet, simply halt.
	 */
	mutex_enter(&pidlock);
	initpp = prfind(P_INITPID);
	mutex_exit(&pidlock);
	if (initpp == NULL) {
		extern void halt(char *);
		halt("Power off the System");   /* just in case */
	}

	/*
	 * else, graceful shutdown with inittab and all getting involved
	 */
	psignal(initpp, SIGPWR);

	(void) timeout(xen_dirty_shutdown, arg,
	    SHUTDOWN_TIMEOUT_SECS * drv_usectohz(MICROSEC));
}

/*ARGSUSED*/
static void
xen_shutdown_handler(struct xenbus_watch *watch, const char **vec,
	unsigned int len)
{
	char *str;
	xenbus_transaction_t xbt;
	int err, shutdown_code = SHUTDOWN_INVALID;
	unsigned int slen;

again:
	err = xenbus_transaction_start(&xbt);
	if (err)
		return;
	if (xenbus_read(xbt, "control", "shutdown", (void *)&str, &slen)) {
		(void) xenbus_transaction_end(xbt, 1);
		return;
	}

	SUSPEND_DEBUG("%d: xen_shutdown_handler: \"%s\"\n", CPU->cpu_id, str);

	/*
	 * If this is a watch fired from our write below, check out early to
	 * avoid an infinite loop.
	 */
	if (strcmp(str, "") == 0) {
		(void) xenbus_transaction_end(xbt, 0);
		kmem_free(str, slen);
		return;
	} else if (strcmp(str, "poweroff") == 0) {
		shutdown_code = SHUTDOWN_POWEROFF;
	} else if (strcmp(str, "reboot") == 0) {
		shutdown_code = SHUTDOWN_REBOOT;
	} else if (strcmp(str, "suspend") == 0) {
		shutdown_code = SHUTDOWN_SUSPEND;
	} else if (strcmp(str, "halt") == 0) {
		shutdown_code = SHUTDOWN_HALT;
	} else {
		printf("Ignoring shutdown request: %s\n", str);
	}

	(void) xenbus_write(xbt, "control", "shutdown", "");
	err = xenbus_transaction_end(xbt, 0);
	if (err == EAGAIN) {
		SUSPEND_DEBUG("%d: trying again\n", CPU->cpu_id);
		kmem_free(str, slen);
		goto again;
	}

	kmem_free(str, slen);
	if (shutdown_code != SHUTDOWN_INVALID) {
		(void) taskq_dispatch(xen_shutdown_tq, xen_shutdown,
		    (void *)(intptr_t)shutdown_code, 0);
	}
}

static int
xpv_drv_init(void)
{
	if (xpv_feature(XPVF_HYPERCALLS) < 0 ||
	    xpv_feature(XPVF_SHARED_INFO) < 0)
		return (-1);

	/* Set up the grant tables.  */
	gnttab_init();

	/* Set up event channel support */
	if (ec_init() != 0)
		return (-1);

	/* Set up xenbus */
	xb_addr = vmem_alloc(heap_arena, MMU_PAGESIZE, VM_SLEEP);
	xs_early_init();
	xs_domu_init();

	/* Set up for suspend/resume/migrate */
	xen_shutdown_tq = taskq_create("shutdown_taskq", 1,
	    maxclsyspri - 1, 1, 1, TASKQ_PREPOPULATE);
	shutdown_watch.node = "control/shutdown";
	shutdown_watch.callback = xen_shutdown_handler;
	if (register_xenbus_watch(&shutdown_watch))
		cmn_err(CE_WARN, "Failed to set shutdown watcher");

	return (0);
}

static void
xen_pv_fini()
{
	ec_fini();
}

/*ARGSUSED*/
static int
xpv_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	if (getminor((dev_t)arg) != XPV_MINOR)
		return (DDI_FAILURE);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = xpv_dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = 0;
		break;
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
xpv_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(dip, ddi_get_name(dip), S_IFCHR,
	    ddi_get_instance(dip), DDI_PSEUDO, 0) != DDI_SUCCESS)
		return (DDI_FAILURE);

	xpv_dip = dip;

	if (xpv_drv_init() != 0)
		return (DDI_FAILURE);

	ddi_report_dev(dip);

	/*
	 * If the memscrubber attempts to scrub the pages we hand to Xen,
	 * the domain will panic.
	 */
	memscrub_disable();

	/*
	 * Report our version to dom0.
	 */
	if (xenbus_printf(XBT_NULL, "guest/xpv", "version", "%d",
	    HVMPV_XPV_VERS))
		cmn_err(CE_WARN, "xpv: couldn't write version\n");

	return (DDI_SUCCESS);
}

/*
 * Attempts to reload the PV driver plumbing hang on Intel platforms, so
 * we don't want to unload the framework by accident.
 */
int xpv_allow_detach = 0;

static int
xpv_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH || xpv_allow_detach == 0)
		return (DDI_FAILURE);

	if (xpv_dip != NULL) {
		xen_pv_fini();
		ddi_remove_minor_node(dip, NULL);
		xpv_dip = NULL;
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED1*/
static int
xpv_open(dev_t *dev, int flag, int otyp, cred_t *cr)
{
	return (getminor(*dev) == XPV_MINOR ? 0 : ENXIO);
}

/*ARGSUSED*/
static int
xpv_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cr,
    int *rval_p)
{
	return (EINVAL);
}

int
_init(void)
{
	int err;

	if ((err = mod_install(&modl)) != 0)
		return (err);

	impl_bus_add_probe(xpv_enumerate);
	return (0);
}

int
_fini(void)
{
	int err;

	if ((err = mod_remove(&modl)) != 0)
		return (err);

	impl_bus_delete_probe(xpv_enumerate);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modl, modinfop));
}

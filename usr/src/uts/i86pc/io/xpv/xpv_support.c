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
#include <vm/seg_kmem.h>
#include <vm/as.h>
#include <vm/hat_pte.h>
#include <vm/hat_i86.h>

#define	XPV_MINOR 0

/*
 * This structure is ordinarily constructed by Xen. In the HVM world, we
 * manually fill in the few fields the PV drivers need.
 */
start_info_t *xen_info = NULL;

/* Xen version number. */
int xen_major, xen_minor;

/* Metadata page shared between domain and Xen */
shared_info_t *HYPERVISOR_shared_info = NULL;

/* Page containing code to issue hypercalls.  */
extern caddr_t hypercall_page;

/* Is the hypervisor 64-bit? */
int xen_is_64bit = -1;

/* virtual addr for the store_mfn page */
caddr_t xb_addr;

dev_info_t *xpv_dip;

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
	NULL		/* power */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"xpv driver %I%",
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
xen_release_pfn(pfn_t pfn, caddr_t va)
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

static uint64_t
hvm_get_param(int param_id)
{
	struct xen_hvm_param xhp;

	xhp.domid = DOMID_SELF;
	xhp.index = param_id;
	if ((HYPERVISOR_hvm_op(HVMOP_get_param, &xhp) < 0))
		return (-1);
	return (xhp.value);
}

static int
xen_pv_init(dev_info_t *xpv_dip)
{
	struct cpuid_regs cp;
	uint32_t xen_signature[4];
	char *xen_str;
	struct xen_add_to_physmap xatp;
	xen_capabilities_info_t caps;
	pfn_t pfn;
	uint64_t msrval;
	int err;

	/*
	 * Xen's pseudo-cpuid function 0x40000000 returns a string
	 * representing the Xen signature in %ebx, %ecx, and %edx.
	 * %eax contains the maximum supported cpuid function.
	 */
	cp.cp_eax = 0x40000000;
	(void) __cpuid_insn(&cp);
	xen_signature[0] = cp.cp_ebx;
	xen_signature[1] = cp.cp_ecx;
	xen_signature[2] = cp.cp_edx;
	xen_signature[3] = 0;
	xen_str = (char *)xen_signature;
	if (strcmp("XenVMMXenVMM", xen_str) != 0 ||
	    cp.cp_eax < 0x40000002) {
		cmn_err(CE_WARN,
		    "Attempting to load Xen drivers on non-Xen system");
		return (-1);
	}

	/*
	 * cpuid function 0x40000001 returns the Xen version in %eax.  The
	 * top 16 bits are the major version, the bottom 16 are the minor
	 * version.
	 */
	cp.cp_eax = 0x40000001;
	(void) __cpuid_insn(&cp);
	xen_major = cp.cp_eax >> 16;
	xen_minor = cp.cp_eax & 0xffff;

	/*
	 * The xpv driver is incompatible with xen versions older than 3.1. This
	 * is due to the changes in the vcpu_info and shared_info structs used
	 * to communicate with the hypervisor (the event channels in particular)
	 * that were introduced with 3.1.
	 */
	if (xen_major < 3 || (xen_major == 3 && xen_minor < 1)) {
		cmn_err(CE_WARN, "Xen version %d.%d is not supported",
		    xen_major, xen_minor);
		return (-1);
	}

	/*
	 * cpuid function 0x40000002 returns information about the
	 * hypercall page.  %eax nominally contains the number of pages
	 * with hypercall code, but according to the Xen guys, "I'll
	 * guarantee that remains one forever more, so you can just
	 * allocate a single page and get quite upset if you ever see CPUID
	 * return more than one page."  %ebx contains an MSR we use to ask
	 * Xen to remap each page at a specific pfn.
	 */
	cp.cp_eax = 0x40000002;
	(void) __cpuid_insn(&cp);

	/*
	 * Let Xen know where we want the hypercall page mapped.  We
	 * already have a page allocated in the .text section to simplify
	 * the wrapper code.
	 */
	pfn = hat_getpfnum(kas.a_hat, (caddr_t)&hypercall_page);
	msrval = mmu_ptob(pfn);
	wrmsr(cp.cp_ebx, msrval);

	/* Fill in the xen_info data */
	xen_info = kmem_zalloc(sizeof (start_info_t), KM_SLEEP);
	(void) sprintf(xen_info->magic, "xen-%d.%d", xen_major, xen_minor);
	xen_info->store_mfn = (mfn_t)hvm_get_param(HVM_PARAM_STORE_PFN);
	xen_info->store_evtchn = (int)hvm_get_param(HVM_PARAM_STORE_EVTCHN);

	/* Figure out whether the hypervisor is 32-bit or 64-bit.  */
	if ((HYPERVISOR_xen_version(XENVER_capabilities, &caps) == 0)) {
		((char *)(caps))[sizeof (caps) - 1] = '\0';
		if (strstr(caps, "x86_64") != NULL)
			xen_is_64bit = 1;
		else if (strstr(caps, "x86_32") != NULL)
			xen_is_64bit = 0;
	}
	if (xen_is_64bit < 0) {
		cmn_err(CE_WARN, "Couldn't get capability info from Xen.");
		return (-1);
	}
#ifdef __amd64
	ASSERT(xen_is_64bit == 1);
#endif

	/*
	 * Allocate space for the shared_info page and tell Xen where it
	 * is.
	 */
	HYPERVISOR_shared_info = xen_alloc_pages(1);
	xatp.domid = DOMID_SELF;
	xatp.idx = 0;
	xatp.space = XENMAPSPACE_shared_info;
	xatp.gpfn = hat_getpfnum(kas.a_hat, (caddr_t)HYPERVISOR_shared_info);
	if ((err = HYPERVISOR_memory_op(XENMEM_add_to_physmap, &xatp)) != 0) {
		cmn_err(CE_WARN, "Could not get shared_info page from Xen."
		    "  error: %d", err);
		return (-1);
	}

	/* Set up the grant tables.  */
	gnttab_init();

	/* Set up event channel support */
	if (ec_init(xpv_dip) != 0)
		return (-1);

	/* Set up xenbus */
	xb_addr = vmem_alloc(heap_arena, MMU_PAGESIZE, VM_SLEEP);
	xs_early_init();
	xs_domu_init();

	return (0);
}

static void
xen_pv_fini()
{
	if (xen_info != NULL)
		kmem_free(xen_info, sizeof (start_info_t));
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

	if (xen_pv_init(dip) != 0)
		return (DDI_FAILURE);

	ddi_report_dev(dip);

	/*
	 * If the memscrubber attempts to scrub the pages we hand to Xen,
	 * the domain will panic.
	 */
	memscrub_disable();

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

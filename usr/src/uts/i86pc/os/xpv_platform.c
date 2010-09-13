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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

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

static int xen_hvm_inited;

/*
 * This structure is ordinarily constructed by Xen. In the HVM world, we
 * manually fill in the few fields the PV drivers need.
 */
static start_info_t __xen_info;
start_info_t *xen_info = NULL;

static int xen_bits = -1;
static int xen_major = -1, xen_minor = -1;

/*
 * Feature bits; more bits will be added, like direct I/O, etc.
 */
#define	XEN_HVM_HYPERCALLS	0x0001
#define	XEN_HVM_TLBFLUSH	0x0002
static uint64_t xen_hvm_features;

/* Metadata page shared between domain and Xen */
shared_info_t *HYPERVISOR_shared_info = NULL;
pfn_t xen_shared_info_frame;

/* Page containing code to issue hypercalls.  */
extern caddr_t hypercall_page;
extern caddr_t hypercall_shared_info_page;

static int
hvm_get_param(int param_id, uint64_t *val)
{
	struct xen_hvm_param xhp;

	xhp.domid = DOMID_SELF;
	xhp.index = param_id;
	if ((HYPERVISOR_hvm_op(HVMOP_get_param, &xhp) < 0))
		return (-1);
	*val = xhp.value;
	return (0);
}

void
xen_hvm_init(void)
{
	struct cpuid_regs cp;
	uint32_t xen_signature[4], base;
	char *xen_str;
	struct xen_add_to_physmap xatp;
	xen_capabilities_info_t caps;
	pfn_t pfn;
	uint64_t msrval, val;

	if (xen_hvm_inited != 0)
		return;

	xen_hvm_inited = 1;

	/*
	 * Xen's pseudo-cpuid function returns a string representing
	 * the Xen signature in %ebx, %ecx, and %edx.
	 * Loop over the base values, since it may be different if
	 * the hypervisor has hyper-v emulation switched on.
	 *
	 * %eax contains the maximum supported cpuid function.
	 */
	for (base = 0x40000000; base < 0x40010000; base += 0x100) {
		cp.cp_eax = base;
		(void) __cpuid_insn(&cp);
		xen_signature[0] = cp.cp_ebx;
		xen_signature[1] = cp.cp_ecx;
		xen_signature[2] = cp.cp_edx;
		xen_signature[3] = 0;
		xen_str = (char *)xen_signature;
		if (strcmp("XenVMMXenVMM", xen_str)  == 0 &&
		    cp.cp_eax >= (base + 2))
			break;
	}
	if (base >= 0x40010000)
		return;

	/*
	 * cpuid function at base + 1 returns the Xen version in %eax.  The
	 * top 16 bits are the major version, the bottom 16 are the minor
	 * version.
	 */
	cp.cp_eax = base + 1;
	(void) __cpuid_insn(&cp);
	xen_major = cp.cp_eax >> 16;
	xen_minor = cp.cp_eax & 0xffff;

	/*
	 * Below version 3.1 we can't do anything special as a HVM domain;
	 * the PV drivers don't work, many hypercalls are not available,
	 * etc.
	 */
	if (xen_major < 3 || (xen_major == 3 && xen_minor < 1))
		return;

	/*
	 * cpuid function at base + 2 returns information about the
	 * hypercall page.  %eax nominally contains the number of pages
	 * with hypercall code, but according to the Xen guys, "I'll
	 * guarantee that remains one forever more, so you can just
	 * allocate a single page and get quite upset if you ever see CPUID
	 * return more than one page."  %ebx contains an MSR we use to ask
	 * Xen to remap each page at a specific pfn.
	 */
	cp.cp_eax = base + 2;
	(void) __cpuid_insn(&cp);

	/*
	 * Let Xen know where we want the hypercall page mapped.  We
	 * already have a page allocated in the .text section to simplify
	 * the wrapper code.
	 */
	pfn = va_to_pfn(&hypercall_page);
	msrval = mmu_ptob(pfn);
	wrmsr(cp.cp_ebx, msrval);

	/* Fill in the xen_info data */
	xen_info = &__xen_info;
	(void) sprintf(xen_info->magic, "xen-%d.%d", xen_major, xen_minor);

	if (hvm_get_param(HVM_PARAM_STORE_PFN, &val) < 0)
		return;
	/*
	 * The first hypercall worked, so mark hypercalls as working.
	 */
	xen_hvm_features |= XEN_HVM_HYPERCALLS;

	xen_info->store_mfn = (mfn_t)val;
	if (hvm_get_param(HVM_PARAM_STORE_EVTCHN, &val) < 0)
		return;
	xen_info->store_evtchn = (mfn_t)val;

	/* Figure out whether the hypervisor is 32-bit or 64-bit.  */
	if ((HYPERVISOR_xen_version(XENVER_capabilities, &caps) == 0)) {
		((char *)(caps))[sizeof (caps) - 1] = '\0';
		if (strstr(caps, "x86_64") != NULL)
			xen_bits = 64;
		else if (strstr(caps, "x86_32") != NULL)
			xen_bits = 32;
	}

	if (xen_bits < 0)
		return;
#ifdef __amd64
	ASSERT(xen_bits == 64);
#endif

	/*
	 * Allocate space for the shared_info page and tell Xen where it
	 * is.
	 */
	xen_shared_info_frame = va_to_pfn(&hypercall_shared_info_page);
	xatp.domid = DOMID_SELF;
	xatp.idx = 0;
	xatp.space = XENMAPSPACE_shared_info;
	xatp.gpfn = xen_shared_info_frame;
	if (HYPERVISOR_memory_op(XENMEM_add_to_physmap, &xatp) != 0)
		return;

	HYPERVISOR_shared_info = (void *)&hypercall_shared_info_page;

	/*
	 * A working HVM tlb flush hypercall was introduced in Xen 3.3.
	 */
	if (xen_major > 3 || (xen_major == 3 && xen_minor >= 3))
		xen_hvm_features |= XEN_HVM_TLBFLUSH;
}

/*
 * Returns:
 *          -1 if a feature is not available
 *          1 if a boolean feature is available
 *          > 0 if numeric feature is available
 */
int
xpv_feature(int which)
{
	switch (which) {
	case XPVF_BITS:
		return (xen_bits);
	case XPVF_VERSION_MAJOR:
		return (xen_major);
	case XPVF_VERSION_MINOR:
		return (xen_minor);
	case XPVF_HYPERCALLS:
		if (xen_hvm_features & XEN_HVM_HYPERCALLS)
			return (1);
		break;
	case XPVF_SHARED_INFO:
		if (HYPERVISOR_shared_info != NULL)
			return (1);
		break;
	case XPVF_TLB_FLUSH:
		if (xen_hvm_features & XEN_HVM_TLBFLUSH)
			return (1);
		break;
	default:
		break;
	}

	return (-1);
}

/*
 * Copyright (c) 2009-2012,2016 Microsoft Corp.
 * Copyright (c) 2012 NetApp Inc.
 * Copyright (c) 2012 Citrix Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2017, 2019 by Delphix. All rights reserved.
 */

/*
 * Implements low-level interactions with Hypver-V/Azure
 */

#include <sys/param.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/types.h>
#include <sys/inttypes.h>
#include <sys/cmn_err.h>
#include <sys/x86_archext.h>

#include <sys/hyperv_illumos.h>
#include <sys/hyperv_busdma.h>
#include <vmbus/hyperv_machdep.h>

#include "hyperv_reg.h"
#include "hyperv_var.h"
#include <sys/hyperv.h>

#define	HYPERV_ILLUMOS_BUILD		0ULL
#define	HYPERV_ILLUMOS_VERSION		511ULL
#define	HYPERV_ILLUMOS_OSID		0ULL

#define	MSR_HV_GUESTID_BUILD_ILLUMOS	\
	(HYPERV_ILLUMOS_BUILD & MSR_HV_GUESTID_BUILD_MASK)
#define	MSR_HV_GUESTID_VERSION_ILLUMOS	\
	((HYPERV_ILLUMOS_VERSION << MSR_HV_GUESTID_VERSION_SHIFT) & \
	MSR_HV_GUESTID_VERSION_MASK)
#define	MSR_HV_GUESTID_OSID_ILLUMOS	\
	((HYPERV_ILLUMOS_OSID << MSR_HV_GUESTID_OSID_SHIFT) & \
	MSR_HV_GUESTID_OSID_MASK)

#define	MSR_HV_GUESTID_ILLUMOS		\
	(MSR_HV_GUESTID_BUILD_ILLUMOS |	\
	MSR_HV_GUESTID_VERSION_ILLUMOS | \
	MSR_HV_GUESTID_OSID_ILLUMOS |	\
	MSR_HV_GUESTID_OSTYPE_ILLUMOS)

#ifdef	DEBUG
#define	hyperv_log(level, fmt...)	\
	cmn_err(level, fmt);

#define	HYPERCALL_LOG_STATUS(status)				\
{								\
	switch (status) {					\
	case HYPERCALL_STATUS_SUCCESS:				\
		break;						\
	case HYPERCALL_STATUS_INVALID_HYPERCALL_INPUT:		\
		hyperv_log(CE_WARN,				\
		    "%s: Invalid hypercall input", __func__);	\
		break;						\
	case HYPERCALL_STATUS_INVALID_ALIGNMENT:		\
		hyperv_log(CE_WARN,				\
		    "%s: Invalid alignment", __func__);		\
		break;						\
	case HYPERCALL_STATUS_INSUFFICIENT_BUFFERS:		\
		hyperv_log(CE_WARN,				\
		    "%s: Insufficient buffers", __func__);	\
		break;						\
	case HYPERCALL_STATUS_INSUFFICIENT_MEMORY:		\
		hyperv_log(CE_WARN,				\
		    "%s: Insufficient memory", __func__);	\
		break;						\
	case HYPERCALL_STATUS_INVALID_CONNECTION_ID:		\
		hyperv_log(CE_WARN,				\
		    "%s: Invalid connection id", __func__);	\
		break;						\
	case HYPERCALL_STATUS_INVALID_HYPERCALL_CODE:		\
		hyperv_log(CE_WARN,				\
		    "%s: Invalid hypercall code", __func__);	\
		break;						\
	default:						\
		hyperv_log(CE_WARN, "%s: Unknown status: %d",	\
		    __func__, status);				\
		break;						\
	}							\
}
#else
#define	hyperv_log(level, fmt...)
#define	HYPERCALL_LOG_STATUS(status)
#endif

struct hypercall_ctx {
	caddr_t		hc_addr;
	hv_dma_t	hc_dma;
};
static struct hypercall_ctx	hypercall_context;

uint_t		hyperv_recommends;

/*
 * Hyper-V Feature identification obtained by
 * reading the CPUID_LEAF_HV_FEATURES cpuid.
 * Results are in the following registers:
 * hyperv_features (EAX):
 *   This indicates which features are available to this partition
 *   based upon current partition privileges.
 * hyperv_features1 (EBX):
 *   This indicates which flags were specified at partition creation.
 * hyperv_pm_features (ECX):
 *   This contains power management related information.
 * hyperv_features3 (EDX):
 *   This indicates which miscellaneous features are available to the partition.
 */
uint_t			hyperv_features;
static uint_t		hyperv_features1;
static uint_t		hyperv_pm_features;
static uint_t		hyperv_features3;

static boolean_t		hyperv_identify(void);
static void			hypercall_memfree(void);

hv_status_t
hypercall_post_message(paddr_t msg_paddr)
{
	hv_status_t status;
	status = hypercall_md(hypercall_context.hc_addr,
	    HYPERCALL_POST_MESSAGE, msg_paddr, 0) & HYPERCALL_STATUS_MASK;
	HYPERCALL_LOG_STATUS(status);
	return (status);
}

hv_status_t
hypercall_signal_event(paddr_t monprm_paddr)
{
	hv_status_t status;
	status = hypercall_md(hypercall_context.hc_addr,
	    HYPERCALL_SIGNAL_EVENT, monprm_paddr, 0) & HYPERCALL_STATUS_MASK;
	HYPERCALL_LOG_STATUS(status);
	return (status);
}

/* Get my partition id */
hv_status_t
hv_vmbus_get_partitionid(uint64_t part_paddr)
{
	hv_status_t status;
	status = hypercall_md(hypercall_context.hc_addr,
	    HV_CALL_GET_PARTITIONID, 0, part_paddr) & HYPERCALL_STATUS_MASK;
	HYPERCALL_LOG_STATUS(status);
	return (status);
}

int
hyperv_guid2str(const struct hyperv_guid *guid, char *buf, size_t sz)
{
	const uint8_t *d = guid->hv_guid;

	return snprintf(buf, sz, "%02x%02x%02x%02x-"
	    "%02x%02x-%02x%02x-%02x%02x-"
	    "%02x%02x%02x%02x%02x%02x",
	    d[3], d[2], d[1], d[0],
	    d[5], d[4], d[7], d[6], d[8], d[9],
	    d[10], d[11], d[12], d[13], d[14], d[15]);
}

void
do_cpuid(uint32_t eax, uint32_t *regs)
{
	struct cpuid_regs cp;
	cp.cp_eax = eax;
	(void) __cpuid_insn(&cp);
	regs[0] = cp.cp_eax;
	regs[1] = cp.cp_ebx;
	regs[2] = cp.cp_ecx;
	regs[3] = cp.cp_edx;
	cmn_err(CE_CONT,
	    "?do_cpuid: cpuid leaf=0x%08x, eax=0x%08x, ebx=0x%08x, "
	    "ecx=0x%08x, edx=0x%08x\n", eax, regs[0], regs[1],
	    regs[2], regs[3]);
}

/*
 * Check if Hyper-V supported in currently booted environment
 * And if so what features are available.
 */
static boolean_t
hyperv_identify(void)
{
	uint32_t regs[4];
	unsigned int maxleaf;

	if ((get_hwenv() & HW_MICROSOFT) == 0) {
		cmn_err(CE_WARN,
		    "hyperv_identify: NOT Hyper-V environment: 0x%x",
		    get_hwenv());
		return (B_FALSE);
	}

	cmn_err(CE_CONT, "?hyperv_identify: Checking Hyper-V features...\n");
	do_cpuid(CPUID_LEAF_HV_MAXLEAF, regs);
	maxleaf = regs[0];
	if (maxleaf < CPUID_LEAF_HV_LIMITS) {
		cmn_err(CE_WARN,
		    "hyperv_identify: max leaves mismatch, maxleaf=0x%08x",
		    maxleaf);
		return (B_FALSE);
	}

	do_cpuid(CPUID_LEAF_HV_INTERFACE, regs);
	if (regs[0] != CPUID_HV_IFACE_HYPERV) {
		cmn_err(CE_WARN,
		    "hyperv_identify: Hyper-V signature mismatch=0x%08x",
		    regs[0]);
		return (B_FALSE);
	}

	do_cpuid(CPUID_LEAF_HV_FEATURES, regs);
	if ((regs[0] & CPUID_HV_MSR_HYPERCALL) == 0) {
		/*
		 * Hyper-V w/o Hypercall is impossible; someone
		 * is faking Hyper-V.
		 */
		cmn_err(CE_WARN,
		    "hyperv_identify: Hypercall Interface not supported, "
		    "please contact your system administrator!");
		return (B_FALSE);
	}

	hyperv_features = regs[0]; /* EAX */
	hyperv_features1 = regs[1]; /* EBX */
	hyperv_pm_features = regs[2]; /* ECX */
	hyperv_features3 = regs[3]; /* EDX */

	do_cpuid(CPUID_LEAF_HV_IDENTITY, regs);
	printf("Hyper-V Version: %d.%d.%d [SP%d]\n",
	    regs[1] >> 16, regs[1] & 0xffff, regs[0], regs[2]);
	/*
	 * Hyper-V version numbering is based on Linux source code, in
	 * function ms_hyperv_init_platform().
	 */
	cmn_err(CE_CONT, "?Hyper-V Host Build: %d-%d.%d-%d-%d.%d\n",
	    regs[0], regs[1] >> 16, regs[1] & 0xffff, regs[2],
	    regs[3] >> 24, regs[3] & 0xffffff);

	printf("  Features=0x%b\n", hyperv_features,
	    "\020"
	    "\001VPRUNTIME"	/* MSR_HV_VP_RUNTIME */
	    "\002TMREFCNT"	/* MSR_HV_TIME_REF_COUNT */
	    "\003SYNIC"		/* MSRs for SynIC */
	    "\004SYNTM"		/* MSRs for SynTimer */
	    "\005APIC"		/* MSR_HV_{EOI,ICR,TPR} */
	    "\006HYPERCALL"	/* MSR_HV_{GUEST_OS_ID,HYPERCALL} */
	    "\007VPINDEX"	/* MSR_HV_VP_INDEX */
	    "\010RESET"		/* MSR_HV_RESET */
	    "\011STATS"		/* MSR_HV_STATS_ */
	    "\012REFTSC"	/* MSR_HV_REFERENCE_TSC */
	    "\013IDLE"		/* MSR_HV_GUEST_IDLE */
	    "\014TMFREQ"	/* MSR_HV_{TSC,APIC}_FREQUENCY */
	    "\015DEBUG");	/* MSR_HV_SYNTH_DEBUG_ */
	printf("  Features1=0x%b\n", hyperv_features1,
	    "\020"
	    "\001CreatePartitions"
	    "\002AccessPartitionId"
	    "\003AccessMemoryPool"
	    "\004AdjustMessageBuffers"
	    "\005PostMessages"
	    "\006SignalEvents"
	    "\007CreatePort"
	    "\008ConnectPort"
	    "\009AccessStats"
	    "\012Debugging"
	    "\013CpuManagement"
	    "\014ConfigureProfiler"
	    "\015EnableExpandedStackwalking");
	printf("  Features2(PM)=0x%b [C%u]\n",
	    (hyperv_pm_features & ~CPUPM_HV_CSTATE_MASK),
	    "\020"
	    "\005C3HPET",	/* HPET is required for C3 state */
	    CPUPM_HV_CSTATE(hyperv_pm_features));
	printf("  Features3=0x%b\n", hyperv_features3,
	    "\020"
	    "\001MWAIT"		/* MWAIT */
	    "\002DEBUG"		/* guest debug support */
	    "\003PERFMON"	/* performance monitor */
	    "\004PCPUDPE"	/* physical CPU dynamic partition event */
	    "\005XMMHC"		/* hypercall input through XMM regs */
	    "\006IDLE"		/* guest idle support */
	    "\007SLEEP"		/* hypervisor sleep support */
	    "\010NUMA"		/* NUMA distance query support */
	    "\011TMFREQ"	/* timer frequency query (TSC, LAPIC) */
	    "\012SYNCMC"	/* inject synthetic machine checks */
	    "\013CRASH"		/* MSRs for guest crash */
	    "\014DEBUGMSR"	/* MSRs for guest debug */
	    "\015NPIEP"		/* NPIEP */
	    "\016HVDIS");	/* disabling hypervisor */

	do_cpuid(CPUID_LEAF_HV_RECOMMENDS, regs);
	hyperv_recommends = regs[0];
	cmn_err(CE_CONT,
	    "?hyperv_identify:  Recommends: %08x %08x\n", regs[0], regs[1]);

	do_cpuid(CPUID_LEAF_HV_LIMITS, regs);
	cmn_err(CE_CONT,
	    "?hyperv_identify:  Limits: Vcpu:%d Lcpu:%d Int:%d\n",
	    regs[0], regs[1], regs[2]);

	if (maxleaf >= CPUID_LEAF_HV_HWFEATURES) {
		do_cpuid(CPUID_LEAF_HV_HWFEATURES, regs);
		cmn_err(CE_CONT,
		    "?hyperv_identify:  HW Features: %08x, AMD: %08x\n",
		    regs[0], regs[3]);
	}

	return (B_TRUE);
}

static int
hyperv_init(void)
{
	cmn_err(CE_CONT, "?hyperv_init: Checking Hyper-V support...\n");
	if (!hyperv_identify()) {
		cmn_err(CE_WARN,
		    "hyperv_init: Hyper-V not supported on this environment");
		return (-1);
	}

	/* Set guest id */
	wrmsr(MSR_HV_GUEST_OS_ID, MSR_HV_GUESTID_ILLUMOS);
	return (0);
}

static void
hypercall_memfree(void)
{
	hyperv_dmamem_free(&hypercall_context.hc_dma);
	hypercall_context.hc_addr = NULL;
}


/*
 * Enable Hypercall interface
 *
 * All hypercalls are invoked using special opcode.
 * Since this opcode can vary among hyper-v implementations,
 * this is done through a special "Hypercall Page", used by
 * the hypervisor to abstract the differences.
 *
 * We enable Hypercall interface by:
 * - Creating a "Hypercall Page" in guest memory
 * - Programming the Hypercall MSR (MSR_HV_HYPERCALL)
 *   with the GPA (guest physical address) of the above page.
 */
int
hypercall_create(dev_info_t *dip)
{
	uint64_t hc, hc_orig;

	if (dip == NULL || (get_hwenv() & HW_MICROSOFT) == 0)
		return (DDI_FAILURE);

	dev_err(dip, CE_CONT, "?hypercall_create: Enabling Hypercall "
	    "interface...\n");

	/* Get the 'reserved' bits, which requires preservation. */
	hc_orig = rdmsr(MSR_HV_HYPERCALL);
	dev_err(dip, CE_CONT,
	    "?hypercall_create: Current Hypercall MSR: 0x%"PRId64"\n", hc_orig);

	/* Create a hypercall page */
	hypercall_context.hc_addr = hyperv_dmamem_alloc(dip,
	    PAGE_SIZE, 0, PAGE_SIZE, &hypercall_context.hc_dma, DDI_DMA_RDWR);
	if (hypercall_context.hc_addr == NULL) {
		dev_err(dip, CE_WARN,
		    "hypercall_create: Hypercall Page allocation failed");
		goto fail;
	}

	dev_err(dip, CE_CONT,
	    "?hypercall_create: Hypercall Page allocation done: 0x%p\n",
	    (void *)hypercall_context.hc_addr);

	/*
	 * Setup the Hypercall page.
	 *
	 * NOTE: 'reserved' bits (11:1) MUST be preserved.
	 * And bit 0 must be set to 1 to indicate enable Hypercall Page.
	 */
	hc = ((hypercall_context.hc_dma.hv_paddr >> PAGE_SHIFT) <<
	    MSR_HV_HYPERCALL_PGSHIFT) |
	    (hc_orig & MSR_HV_HYPERCALL_RSVD_MASK) |
	    MSR_HV_HYPERCALL_ENABLE;

	dev_err(dip, CE_CONT,
	    "?hypercall_create: Programming Hypercall MSR: 0x%"PRId64"\n", hc);

	wrmsr(MSR_HV_HYPERCALL, hc);

	/*
	 * Confirm that Hypercall page did get setup.
	 */
	hc = rdmsr(MSR_HV_HYPERCALL);

	if ((hc & MSR_HV_HYPERCALL_ENABLE) == 0) {
		dev_err(dip, CE_CONT,
		    "?hypercall_create: Verify Hypercall MSR: 0x%"PRId64
		    "failed\n", hc);
		hypercall_memfree();
		goto fail;
	}

	dev_err(dip, CE_CONT,
	    "?hypercall_create: Verified Hypercall MSR: 0x%"PRId64"\n", hc);
	dev_err(dip, CE_CONT,
	    "?hypercall_create: Enabling Hypercall interface - SUCCESS !\n");
	return (DDI_SUCCESS);
fail:
	dev_err(dip, CE_WARN,
	    "hypercall_create: Enabling Hypercall interface - FAILED.");
	return (DDI_FAILURE);
}

/*
 * Disable Hypercall interface
 */
void
hypercall_destroy()
{
	uint64_t hc;

	if (hypercall_context.hc_addr == NULL)
		return;

	cmn_err(CE_NOTE,
	    "hypercall_destroy: Disabling Hypercall interface...");

	/* Disable Hypercall */
	hc = rdmsr(MSR_HV_HYPERCALL);
	wrmsr(MSR_HV_HYPERCALL, (hc & MSR_HV_HYPERCALL_RSVD_MASK));
	hypercall_memfree();

	cmn_err(CE_NOTE,
	    "hypercall_destroy: Disabling Hypercall interface - done.");
}

static struct modldrv hyperv_modldrv = {
	&mod_miscops,
	"Hyper-V Driver"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&hyperv_modldrv,
	NULL
};

int
_init(void)
{
	if (hyperv_init() != 0)
		return (ENOTSUP);

	int error = mod_install(&modlinkage);
	return (error);
}

int
_fini(void)
{
	int error;

	error = mod_remove(&modlinkage);
	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

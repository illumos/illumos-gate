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
 * Copyright 2023 Toomas Soome <tsoome@me.com>
 * Copyright 2026 Oxide Computer Company
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include "codes.h"

#if defined(__x86)

/* vmm_dev.h is expecting to have the types below. */
typedef uint64_t vm_paddr_t;
typedef int64_t vm_ooffset_t;
#include <sys/vmm_dev.h>
#include <sys/viona_io.h>

/* VMM ioctls */
const struct ioc vmmctl_ioc[] = {
	{ (uint_t)VMM_CREATE_VM,		"VMM_CREATE_VM", NULL },
	{ (uint_t)VMM_DESTROY_VM,		"VMM_DESTROY_VM", NULL },
	{ (uint_t)VMM_VM_SUPPORTED,		"VMM_VM_SUPPORTED", NULL },

	{ (uint_t)VMM_RESV_QUERY,		"VMM_RESV_QUERY", NULL },
	{ (uint_t)VMM_RESV_SET_TARGET,		"VMM_RESV_SET_TARGET", NULL }
};

const struct ioc vmm_cpu_ioc[] = {
	{ (uint_t)VM_RUN,			"VM_RUN", NULL },
	{ (uint_t)VM_SET_REGISTER,		"VM_SET_REGISTER", NULL },
	{ (uint_t)VM_GET_REGISTER,		"VM_GET_REGISTER", NULL },
	{ (uint_t)VM_SET_SEGMENT_DESCRIPTOR,	"VM_SET_SEGMENT_DESCRIPTOR",
		NULL },
	{ (uint_t)VM_GET_SEGMENT_DESCRIPTOR,	"VM_GET_SEGMENT_DESCRIPTOR",
		NULL },
	{ (uint_t)VM_SET_REGISTER_SET,		"VM_SET_REGISTER_SET", NULL },
	{ (uint_t)VM_GET_REGISTER_SET,		"VM_GET_REGISTER_SET", NULL },
	{ (uint_t)VM_INJECT_EXCEPTION,		"VM_INJECT_EXCEPTION", NULL },
	{ (uint_t)VM_SET_CAPABILITY,		"VM_SET_CAPABILITY", NULL },
	{ (uint_t)VM_GET_CAPABILITY,		"VM_GET_CAPABILITY", NULL },
	{ (uint_t)VM_PPTDEV_MSI,		"VM_PPTDEV_MSI", NULL },
	{ (uint_t)VM_PPTDEV_MSIX,		"VM_PPTDEV_MSIX", NULL },
	{ (uint_t)VM_SET_X2APIC_STATE,		"VM_SET_X2APIC_STATE", NULL },
	{ (uint_t)VM_GLA2GPA,			"VM_GLA2GPA", NULL },
	{ (uint_t)VM_GLA2GPA_NOFAULT,		"VM_GLA2GPA_NOFAULT", NULL },
	{ (uint_t)VM_ACTIVATE_CPU,		"VM_ACTIVATE_CPU", NULL },
	{ (uint_t)VM_SET_INTINFO,		"VM_SET_INTINFO", NULL },
	{ (uint_t)VM_GET_INTINFO,		"VM_GET_INTINFO", NULL },
	{ (uint_t)VM_RESTART_INSTRUCTION,	"VM_RESTART_INSTRUCTION",
		NULL },
	{ (uint_t)VM_SET_KERNEMU_DEV,		"VM_SET_KERNEMU_DEV", NULL },
	{ (uint_t)VM_GET_KERNEMU_DEV,		"VM_GET_KERNEMU_DEV", NULL },
	{ (uint_t)VM_RESET_CPU,			"VM_RESET_CPU", NULL },
	{ (uint_t)VM_GET_RUN_STATE,		"VM_GET_RUN_STATE", NULL },
	{ (uint_t)VM_SET_RUN_STATE,		"VM_SET_RUN_STATE", NULL },
	{ (uint_t)VM_GET_FPU,			"VM_GET_FPU", NULL },
	{ (uint_t)VM_SET_FPU,			"VM_SET_FPU", NULL },
	{ (uint_t)VM_GET_CPUID,			"VM_GET_CPUID", NULL },
	{ (uint_t)VM_SET_CPUID,			"VM_SET_CPUID", NULL },
	{ (uint_t)VM_LEGACY_CPUID,		"VM_LEGACY_CPUID", NULL }
};

const struct ioc vmm_lock_ioc[] = {
	{ (uint_t)VM_REINIT,			"VM_REINIT", NULL },
	{ (uint_t)VM_BIND_PPTDEV,		"VM_BIND_PPTDEV", NULL },
	{ (uint_t)VM_UNBIND_PPTDEV,		"VM_UNBIND_PPTDEV", NULL },
	{ (uint_t)VM_MAP_PPTDEV_MMIO,		"VM_MAP_PPTDEV_MMIO", NULL },
	{ (uint_t)VM_ALLOC_MEMSEG,		"VM_ALLOC_MEMSEG", NULL },
	{ (uint_t)VM_MMAP_MEMSEG,		"VM_MMAP_MEMSEG", NULL },
	{ (uint_t)VM_PMTMR_LOCATE,		"VM_PMTMR_LOCATE", NULL },
	{ (uint_t)VM_MUNMAP_MEMSEG,		"VM_MUNMAP_MEMSEG", NULL },
	{ (uint_t)VM_UNMAP_PPTDEV_MMIO,		"VM_UNMAP_PPTDEV_MMIO", NULL },
	{ (uint_t)VM_PAUSE,			"VM_PAUSE", NULL },
	{ (uint_t)VM_RESUME,			"VM_RESUME", NULL },

	{ (uint_t)VM_WRLOCK_CYCLE,		"VM_WRLOCK_CYCLE", NULL }
};

const struct ioc vmm_ioc[] = {
	{ (uint_t)VM_GET_GPA_PMAP,		"VM_GET_GPA_PMAP", NULL },
	{ (uint_t)VM_GET_MEMSEG,		"VM_GET_MEMSEG", NULL },
	{ (uint_t)VM_MMAP_GETNEXT,		"VM_MMAP_GETNEXT", NULL },

	{ (uint_t)VM_LAPIC_IRQ,			"VM_LAPIC_IRQ", NULL },
	{ (uint_t)VM_LAPIC_LOCAL_IRQ,		"VM_LAPIC_LOCAL_IRQ", NULL },
	{ (uint_t)VM_LAPIC_MSI,			"VM_LAPIC_MSI", NULL },

	{ (uint_t)VM_IOAPIC_ASSERT_IRQ,		"VM_IOAPIC_ASSERT_IRQ", NULL },
	{ (uint_t)VM_IOAPIC_DEASSERT_IRQ,	"VM_IOAPIC_DEASSERT_IRQ",
		NULL },
	{ (uint_t)VM_IOAPIC_PULSE_IRQ,		"VM_IOAPIC_PULSE_IRQ", NULL },

	{ (uint_t)VM_ISA_ASSERT_IRQ,		"VM_ISA_ASSERT_IRQ", NULL },
	{ (uint_t)VM_ISA_DEASSERT_IRQ,		"VM_ISA_DEASSERT_IRQ", NULL },
	{ (uint_t)VM_ISA_PULSE_IRQ,		"VM_ISA_PULSE_IRQ", NULL },
	{ (uint_t)VM_ISA_SET_IRQ_TRIGGER,	"VM_ISA_SET_IRQ_TRIGGER",
		NULL },

	{ (uint_t)VM_RTC_WRITE,			"VM_RTC_WRITE", NULL },
	{ (uint_t)VM_RTC_READ,			"VM_RTC_READ", NULL },
	{ (uint_t)VM_RTC_SETTIME,		"VM_RTC_SETTIME", NULL },
	{ (uint_t)VM_RTC_GETTIME,		"VM_RTC_GETTIME", NULL },

	{ (uint_t)VM_SUSPEND,			"VM_SUSPEND", NULL },

	{ (uint_t)VM_IOAPIC_PINCOUNT,		"VM_IOAPIC_PINCOUNT", NULL },
	{ (uint_t)VM_GET_PPTDEV_LIMITS,		"VM_GET_PPTDEV_LIMITS", NULL },
	{ (uint_t)VM_GET_HPET_CAPABILITIES,	"VM_GET_HPET_CAPABILITIES",
		NULL },

	{ (uint_t)VM_STATS_IOC,			"VM_STATS_IOC", NULL },
	{ (uint_t)VM_STAT_DESC,			"VM_STAT_DESC", NULL },

	{ (uint_t)VM_INJECT_NMI,		"VM_INJECT_NMI", NULL },
	{ (uint_t)VM_GET_X2APIC_STATE,		"VM_GET_X2APIC_STATE", NULL },
	{ (uint_t)VM_SET_TOPOLOGY,		"VM_SET_TOPOLOGY", NULL },
	{ (uint_t)VM_GET_TOPOLOGY,		"VM_GET_TOPOLOGY", NULL },
	{ (uint_t)VM_GET_CPUS,			"VM_GET_CPUS", NULL },
	{ (uint_t)VM_SUSPEND_CPU,		"VM_SUSPEND_CPU", NULL },
	{ (uint_t)VM_RESUME_CPU,		"VM_RESUME_CPU", NULL },

	{ (uint_t)VM_PPTDEV_DISABLE_MSIX,	"VM_PPTDEV_DISABLE_MSIX",
		NULL },

	{ (uint_t)VM_TRACK_DIRTY_PAGES,		"VM_TRACK_DIRTY_PAGES", NULL },
	{ (uint_t)VM_DESC_FPU_AREA,		"VM_DESC_FPU_AREA", NULL },

	{ (uint_t)VM_DATA_READ,			"VM_DATA_READ", NULL },
	{ (uint_t)VM_DATA_WRITE,		"VM_DATA_WRITE", NULL },

	{ (uint_t)VM_SET_AUTODESTRUCT,		"VM_SET_AUTODESTRUCT", NULL },
	{ (uint_t)VM_DESTROY_SELF,		"VM_DESTROY_SELF", NULL },
	{ (uint_t)VM_DESTROY_PENDING,		"VM_DESTROY_PENDING", NULL },

	{ (uint_t)VM_VCPU_BARRIER,		"VM_VCPU_BARRIER", NULL },

	{ (uint_t)VM_DEVMEM_GETOFFSET,		"VM_DEVMEM_GETOFFSET", NULL }
};

/* viona ioctls */
const struct ioc viona_ioc[] = {
	{ (uint_t)VNA_IOC_CREATE,		"VNA_IOC_CREATE", NULL },
	{ (uint_t)VNA_IOC_DELETE,		"VNA_IOC_DELETE", NULL },
	{ (uint_t)VNA_IOC_VERSION,		"VNA_IOC_VERSION", NULL },
	{ (uint_t)VNA_IOC_DEFAULT_PARAMS,	"VNA_IOC_DEFAULT_PARAMS",
		NULL },

	{ (uint_t)VNA_IOC_RING_INIT,		"VNA_IOC_RING_INIT", NULL },
	{ (uint_t)VNA_IOC_RING_RESET,		"VNA_IOC_RING_RESET", NULL },
	{ (uint_t)VNA_IOC_RING_KICK,		"VNA_IOC_RING_KICK", NULL },
	{ (uint_t)VNA_IOC_RING_SET_MSI,		"VNA_IOC_RING_SET_MSI", NULL },
	{ (uint_t)VNA_IOC_RING_INTR_CLR,	"VNA_IOC_RING_INTR_CLR", NULL },
	{ (uint_t)VNA_IOC_RING_SET_STATE,	"VNA_IOC_RING_SET_STATE",
		NULL },
	{ (uint_t)VNA_IOC_RING_GET_STATE,	"VNA_IOC_RING_GET_STATE",
		NULL },
	{ (uint_t)VNA_IOC_RING_PAUSE,		"VNA_IOC_RING_PAUSE", NULL },
	{ (uint_t)VNA_IOC_RING_INIT_MODERN,	"VNA_IOC_RING_INIT_MODERN",
		NULL },

	{ (uint_t)VNA_IOC_INTR_POLL,		"VNA_IOC_INTR_POLL", NULL },
	{ (uint_t)VNA_IOC_SET_FEATURES,		"VNA_IOC_SET_FEATURES", NULL },
	{ (uint_t)VNA_IOC_GET_FEATURES,		"VNA_IOC_GET_FEATURES", NULL },
	{ (uint_t)VNA_IOC_SET_NOTIFY_IOP,	"VNA_IOC_SET_NOTIFY_IOP",
		NULL },
	{ (uint_t)VNA_IOC_SET_PROMISC,		"VNA_IOC_SET_PROMISC", NULL },
	{ (uint_t)VNA_IOC_GET_PARAMS,		"VNA_IOC_GET_PARAMS", NULL },
	{ (uint_t)VNA_IOC_SET_PARAMS,		"VNA_IOC_SET_PARAMS", NULL },
	{ (uint_t)VNA_IOC_GET_MTU,		"VNA_IOC_GET_MTU", NULL },
	{ (uint_t)VNA_IOC_SET_MTU,		"VNA_IOC_SET_MTU", NULL },
	{ (uint_t)VNA_IOC_SET_NOTIFY_MMIO,	"VNA_IOC_SET_NOTIFY_MMIO",
		NULL },
	{ (uint_t)VNA_IOC_INTR_POLL_MQ,		"VNA_IOC_INTR_POLL_MQ", NULL },
	{ (uint_t)VNA_IOC_SET_MAC_FILTERS,	"VNA_IOC_SET_MAC_FILTERS",
		NULL },
	{ (uint_t)VNA_IOC_GET_MAC_FILTERS,	"VNA_IOC_GET_MAC_FILTERS",
		NULL },
	{ (uint_t)VNA_IOC_SET_MAC_ADDR,		"VNA_IOC_SET_MAC_ADDR", NULL },
	{ (uint_t)VNA_IOC_GET_MAC_ADDR,		"VNA_IOC_GET_MAC_ADDR", NULL },

	{ (uint_t)VNA_IOC_GET_PAIRS,		"VNA_IOC_GET_PAIRS", NULL },
	{ (uint_t)VNA_IOC_SET_PAIRS,		"VNA_IOC_SET_PAIRS", NULL },
	{ (uint_t)VNA_IOC_GET_USEPAIRS,		"VNA_IOC_GET_USEPAIRS", NULL },
	{ (uint_t)VNA_IOC_SET_USEPAIRS,		"VNA_IOC_SET_USEPAIRS", NULL }
};

const struct iocs vmm_iocs[] = {
	{ .nitems = ARRAY_SIZE(vmmctl_ioc), .data = vmmctl_ioc },
	{ .nitems = ARRAY_SIZE(vmm_cpu_ioc), .data = vmm_cpu_ioc },
	{ .nitems = ARRAY_SIZE(vmm_lock_ioc), .data = vmm_lock_ioc },
	{ .nitems = ARRAY_SIZE(vmm_ioc), .data = vmm_ioc },
	{ .nitems = ARRAY_SIZE(viona_ioc), .data = viona_ioc },
	{ .nitems = 0, .data = NULL }
};
#else
const struct iocs vmm_iocs[] = {
	{ .nitems = 0, .data = NULL }
};
#endif /* __x86 */

/******************************************************************************
 * arch-x86/xen-mca.h
 * 
 * Contributed by Advanced Micro Devices, Inc.
 * Author: Christoph Egger <Christoph.Egger@amd.com>
 *
 * Guest OS machine check interface to x86 Xen.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/* Full MCA functionality has the following Usecases from the guest side:
 *
 * Must have's:
 * 1. Dom0 and DomU register machine check trap callback handlers
 *    (already done via "set_trap_table" hypercall)
 * 2. Dom0 registers machine check event callback handler
 *    (doable via EVTCHNOP_bind_virq)
 * 3. Dom0 and DomU fetches machine check data
 * 4. Dom0 wants Xen to notify a DomU
 * 5. Dom0 gets DomU ID from physical address
 * 6. Dom0 wants Xen to kill DomU (already done for "xm destroy")
 *
 * Nice to have's:
 * 7. Dom0 wants Xen to deactivate a physical CPU
 *    This is better done as separate task, physical CPU hotplugging,
 *    and hypercall(s) should be sysctl's
 * 8. Page migration proposed from Xen NUMA work, where Dom0 can tell Xen to
 *    move a DomU (or Dom0 itself) away from a malicious page
 *    producing correctable errors.
 * 9. offlining physical page:
 *    Xen free's and never re-uses a certain physical page.
 * 10. Testfacility: Allow Dom0 to write values into machine check MSR's
 *     and tell Xen to trigger a machine check
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef __XEN_PUBLIC_ARCH_X86_MCA_H__
#define __XEN_PUBLIC_ARCH_X86_MCA_H__

/* Hypercall */
#define __HYPERVISOR_mca __HYPERVISOR_arch_0

#define	XEN_MC_HCALL_SUCCESS	0

/*
 * The xen-unstable repo has interface version 0x03000001; out interface
 * is incompatible with that and any future minor revisions, so we
 * choose a different version number range that is numerically less
 * than that used in xen-unstable.
 */
#define XEN_MCA_INTERFACE_VERSION 0x01ecc001

/* IN: Dom0 calls hypercall to retrieve nonurgent telemetry */
#define XEN_MC_F_NONURGENT	0x0001
/* IN: Dom0 calls hypercall to retrieve urgent telemetry */
#define XEN_MC_F_URGENT		0x0002
/* IN: Dom0 acknowledges previosly-fetched telemetry */
#define	XEN_MC_F_ACK		0x0004

/* OUT: All is ok - all flags bits clear */
#define XEN_MC_F_OK           0x0
/* OUT: Domain could not fetch data. */
#define XEN_MC_F_FETCHFAILED  0x0001
/* OUT: There was no machine check data to fetch. */
#define XEN_MC_F_NODATA       0x0002
/* OUT: Between notification time and this hypercall an other
 *  (most likely) correctable error happened. The fetched data,
 *  does not match the original machine check data. */
#define XEN_MC_F_NOMATCH      0x0004

/* OUT: DomU did not register MC NMI handler. Try something else. */
#define XEN_MC_F_CANNOTHANDLE 0x0008
/* OUT: Notifying DomU failed. Retry later or try something else. */
#define XEN_MC_F_NOTDELIVERED 0x0010
/* Note, XEN_MC_F_CANNOTHANDLE and XEN_MC_F_NOTDELIVERED are mutually exclusive. */

#ifndef __ASSEMBLY__

#define VIRQ_MCA VIRQ_ARCH_0 /* G. (DOM0) Machine Check Architecture */

/*
 * Machine Check Architecure:
 * structs are read-only and used to report all kinds of
 * correctable and uncorrectable errors detected by the HW.
 * Dom0 and DomU: register a handler to get notified.
 * Dom0 only: Correctable errors are reported via VIRQ_MCA
 * Dom0 and DomU: Uncorrectable errors are reported via nmi handlers
 */
#define MC_TYPE_GLOBAL          0
#define MC_TYPE_BANK            1
#define MC_TYPE_EXTENDED        2

struct mcinfo_common {
    uint16_t type;      /* structure type - one of MC_TYPE_* above */
    uint16_t size;      /* size of this struct in bytes */
};

#define MC_FLAG_CORRECTABLE     0x00000001
#define MC_FLAG_UNCORRECTABLE   0x00000002
#define	MC_FLAG_MCE		0x00000004
#define	MC_FLAG_POLLED		0x00000008

/* contains global x86 mc information */
struct mcinfo_global {
    struct mcinfo_common common;

    /* running domain at the time in error (most likely the impacted one) */
    uint16_t mc_domid;
    uint32_t mc_socketid; /* physical socket of the physical core */
    uint16_t mc_coreid; /* physical impacted core */
    uint16_t mc_core_threadid; /* core thread of physical core */
    uint8_t  mc_apicid;	/* APIC id of physical core */
    uint16_t mc_vcpuid; /* virtual cpu scheduled for mc_domid */
    uint32_t mc_pad0;
    uint64_t mc_gstatus; /* global status */
    uint32_t mc_flags; /* see MC_FLAG_* above */
};

/* contains bank local x86 mc information */
struct mcinfo_bank {
    struct mcinfo_common common;

    uint16_t mc_bank; /* bank nr */
    uint16_t mc_domid; /* Usecase 5: domain referenced by mc_addr on dom0
                        * and if mc_addr is valid. Never valid on DomU. */
    uint64_t mc_status; /* bank status */
    uint64_t mc_addr;   /* bank address, only valid
                         * if addr bit is set in mc_status */
    uint64_t mc_misc;
};


struct mcinfo_msr {
    uint64_t reg;   /* MSR */
    uint64_t value; /* MSR value */
};

/* contains mc information from other
 * or additional mc MSRs */ 
struct mcinfo_extended {
    struct mcinfo_common common;

    /* You can fill up to five registers.
     * If you need more, then use this structure
     * multiple times. */

    uint32_t mc_msrs; /* Number of msr with valid values. */
    struct mcinfo_msr mc_msr[12];
};

#define MCINFO_MAXSIZE		768

typedef struct mc_info {
    /* Number of mcinfo_* entries in mi_data */
    uint32_t mi_nentries;

    uint8_t mi_data[MCINFO_MAXSIZE - sizeof(uint32_t)];
} mc_info_t;
DEFINE_XEN_GUEST_HANDLE(mc_info_t);

#define __MC_MSR_ARRAYSIZE 8
#define __MC_NMSRS 1
#define MC_NCAPS	7	/* 7 CPU feature flag words */
#define MC_CAPS_STD_EDX	0	/* cpuid level 0x00000001 (%edx) */
#define MC_CAPS_AMD_EDX	1	/* cpuid level 0x80000001 (%edx) */
#define MC_CAPS_TM	2	/* cpuid level 0x80860001 (TransMeta) */
#define MC_CAPS_LINUX	3	/* Linux-defined */
#define MC_CAPS_STD_ECX	4	/* cpuid level 0x00000001 (%ecx) */
#define MC_CAPS_VIA	5	/* cpuid level 0xc0000001 */
#define MC_CAPS_AMD_ECX	6	/* cpuid level 0x80000001 (%ecx) */

typedef struct mcinfo_logical_cpu {
    unsigned int mc_cpunr;          
    uint32_t mc_chipid; 
    uint16_t mc_coreid;
    uint16_t mc_threadid;
    uint8_t mc_apicid;
    unsigned int mc_ncores;
    unsigned int mc_ncores_active;
    unsigned int mc_nthreads;
    int mc_cpuid_level;
    unsigned int mc_family;
    unsigned int mc_vendor;
    unsigned int mc_model;
    unsigned int mc_step;
    char mc_vendorid[16];
    char mc_brandid[64];
    uint32_t mc_cpu_caps[MC_NCAPS];
    unsigned int mc_cache_size;
    unsigned int mc_cache_alignment;
    unsigned int mc_nmsrvals;
    struct mcinfo_msr mc_msrvalues[__MC_MSR_ARRAYSIZE];
} xen_mc_logical_cpu_t;
DEFINE_XEN_GUEST_HANDLE(xen_mc_logical_cpu_t);

/* 
 * OS's should use these instead of writing their own lookup function
 * each with its own bugs and drawbacks.
 * We use macros instead of static inline functions to allow guests
 * to include this header in assembly files (*.S).
 */
/* Prototype:
 *    uint32_t x86_mcinfo_nentries(struct mc_info *mi);
 */
#define x86_mcinfo_nentries(_mi)    \
    (_mi)->mi_nentries
/* Prototype:
 *    struct mcinfo_common *x86_mcinfo_first(struct mc_info *mi);
 */
#define x86_mcinfo_first(_mi)       \
    (struct mcinfo_common *)((_mi)->mi_data)
/* Prototype:
 *    struct mcinfo_common *x86_mcinfo_next(struct mcinfo_common *mic);
 */
#define x86_mcinfo_next(_mic)       \
    (struct mcinfo_common *)((uint8_t *)(_mic) + (_mic)->size)

/* Prototype:
 *    void x86_mcinfo_lookup(void *ret, struct mc_info *mi, uint16_t type);
 */
#define x86_mcinfo_lookup(_ret, _mi, _type)    \
    do {                                                        \
        uint32_t found, i;                                      \
        struct mcinfo_common *_mic;                             \
                                                                \
        found = 0;                                              \
	(_ret) = NULL;						\
	if (_mi == NULL) break;					\
        _mic = x86_mcinfo_first(_mi);                           \
        for (i = 0; i < x86_mcinfo_nentries(_mi); i++) {        \
            if (_mic->type == (_type)) {                        \
                found = 1;                                      \
                break;                                          \
            }                                                   \
            _mic = x86_mcinfo_next(_mic);                       \
        }                                                       \
        (_ret) = found ? _mic : NULL;                           \
    } while (0)


/* Usecase 1
 * Register machine check trap callback handler
 *    (already done via "set_trap_table" hypercall)
 */

/* Usecase 2
 * Dom0 registers machine check event callback handler
 * done by EVTCHNOP_bind_virq
 */

/* Usecase 3
 * Fetch machine check data from hypervisor.
 * Note, this hypercall is special, because both Dom0 and DomU must use this.
 */
#define XEN_MC_CMD_fetch            1
struct xen_mc_fetch {
    /* IN/OUT */
    uint32_t flags;	/*  IN: XEN_MC_F_NONURGENT or XEN_MC_F_URGENT, 
			 *      XEN_MC_F_ACK if ack'ing an earlier fetch
			 * OUT: XEN_MC_F_OK, XEN_MC_F_FETCHFAILED,
			 *      XEN_MC_F_NODATA, XEN_MC_F_NOMATCH */
    uint32_t data_sz;	/* IN: size of data area */
    uint64_t fetch_id;	/* OUT: id for ack; IN: id we are ack'ing */


    /* OUT */
    XEN_GUEST_HANDLE(mc_info_t) data;
};
typedef struct xen_mc_fetch xen_mc_fetch_t;
DEFINE_XEN_GUEST_HANDLE(xen_mc_fetch_t);


/* Usecase 4
 * This tells the hypervisor to notify a DomU about the machine check error
 */
#define XEN_MC_CMD_notifydomain     2
struct xen_mc_notifydomain {
    /* IN variables. */
    uint16_t mc_domid;	/* The unprivileged domain to notify. */
    uint16_t mc_vcpuid;	/* The vcpu in mc_domid to notify.
                       	 * Usually echo'd value from the fetch hypercall. */

    /* IN/OUT variables. */
    uint32_t flags;	/*  IN: XEN_MC_F_URGENT, XEN_MC_F_TRAP
			 * OUT: XEN_MC_F_OK, XEN_MC_F_CANNOTHANDLE,
			 * XEN_MC_NOTDELIVERED, XEN_MC_NOMATCH */
};
typedef struct xen_mc_notifydomain xen_mc_notifydomain_t;
DEFINE_XEN_GUEST_HANDLE(xen_mc_notifydomain_t);

#define XEN_MC_CMD_physcpuinfo	3
struct xen_mc_physcpuinfo {
	/* IN/OUT */
	uint32_t ncpus;
	uint32_t pad0;
	/* OUT */
	XEN_GUEST_HANDLE(xen_mc_logical_cpu_t) info;
};

#define	XEN_MC_CMD_msrinject	4
#define	MC_MSRINJ_MAXMSRS	8
struct xen_mc_msrinject {
	/* IN */
	unsigned int mcinj_cpunr;	/* target processor id */
	uint32_t mcinj_flags;		/* see MC_MSRINJ_F_* below */
	uint32_t mcinj_count;		/* 0 .. count-1 in array are valid */
	uint32_t mcinj_pad0;
	struct mcinfo_msr mcinj_msr[MC_MSRINJ_MAXMSRS];
};

/* Flags for mcinj_flags above; bits 16-31 are reserved */
#define	MC_MSRINJ_F_INTERPOSE	0x1

#define	XEN_MC_CMD_mceinject	5
struct xen_mc_mceinject {
	unsigned int mceinj_cpunr;	/* target processor id */
};

#define XEN_MC_CMD_offlinecpu 6
struct xen_mc_offline {
	/* IN */
	unsigned int mco_cpu;
	/* IN / OUT */
	int mco_flag;		/* MC_CPU_P_* */
};

#define	MC_CPU_P_STATUS		0x0000
#define	MC_CPU_P_ONLINE		0x0001
#define	MC_CPU_P_OFFLINE	0x0002
#define	MC_CPU_P_FAULTED	0x0004
#define	MC_CPU_P_SPARE		0x0008
#define	MC_CPU_P_POWEROFF	0x0010

typedef union {
        struct xen_mc_fetch        mc_fetch;
        struct xen_mc_notifydomain mc_notifydomain;
        struct xen_mc_physcpuinfo  mc_physcpuinfo;
	struct xen_mc_msrinject	   mc_msrinject;
	struct xen_mc_mceinject	   mc_mceinject;
	struct xen_mc_offline      mc_offline;
} xen_mc_arg_t;

struct xen_mc {
    uint32_t cmd;
    uint32_t interface_version; /* XEN_MCA_INTERFACE_VERSION */
    xen_mc_arg_t u;
};
typedef struct xen_mc xen_mc_t;
DEFINE_XEN_GUEST_HANDLE(xen_mc_t);

#endif /* __ASSEMBLY__ */

#endif /* __XEN_PUBLIC_ARCH_X86_MCA_H__ */

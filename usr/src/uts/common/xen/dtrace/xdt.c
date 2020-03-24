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
 * Xen event provider for DTrace
 *
 * NOTE: This provider is PRIVATE. It is intended as a short-term solution and
 * may disappear or be re-implemented at anytime.
 *
 * This provider isn't suitable as a general-purpose solution for a number of
 * reasons. First and foremost, we rely on the Xen tracing mechanism and don't
 * have any way to gather data other than that collected by the Xen trace
 * buffers. Further, it does not fit into the DTrace model (see "Interacting
 * with DTrace" below.)
 *
 *
 * Tracing in Xen
 * --------------
 *
 * Xen implements a tracing facility for generating and collecting execution
 * event traces from the hypervisor. When tracing is enabled, compiled in
 * probes record events in contiguous per-CPU trace buffers.
 *
 *               +---------+
 * +------+      |         |
 * | CPUn |----> | BUFFERn |
 * +------+      |         |
 *               +---------+- tbuf.va + (tbuf.size * n)
 *               :         :
 *               +---------+
 * +------+      |         |
 * | CPU1 |----> | BUFFER1 |
 * +------+      |         |
 *               +---------+- tbuf.va + tbuf.size
 * +------+      |         |
 * | CPU0 |----> | BUFFER0 |
 * +------+      |         |
 *               +---------+- tbuf.va
 *
 * Each CPU buffer consists of a metadata header followed by the trace records.
 * The metadata consists of a producer/consumer pair of pointers into the buffer
 * that point to the next record to be written and the next record to be read
 * respectively.
 *
 * A trace record can be in one of two forms, depending on if the TSC is
 * included. The record header indicates whether or not the TSC field is
 * present.
 *
 * 1. Trace record without TSC:
 * +------------------------------------------------------------+
 * | HEADER(uint32_t) |            DATA FIELDS                  |
 * +------------------------------------------------------------+
 *
 * 2. Trace record with TSC:
 * +--------------------------------------------------------------------------+
 * | HEADER(uint32_t) | TSC(uint64_t) |              DATA FIELDS              |
 * +--------------------------------------------------------------------------+
 *
 * Where,
 *
 * HEADER bit field:
 * +--------------------------------------------------------------------------+
 * | C |  NDATA  |                        EVENT                               |
 * +--------------------------------------------------------------------------+
 *  31  30     28 27                                                         0
 *
 * EVENT: Event ID.
 * NDATA: Number of populated data fields.
 *     C: TSC included.
 *
 * DATA FIELDS:
 * +--------------------------------------------------------------------------+
 * | D1(uint32_t) | D2(uint32_t) | D3(uint32_t) |     . . .    | D7(uint32_t) |
 * +--------------------------------------------------------------------------+
 *
 *
 * Interacting with DTrace
 * -----------------------
 *
 * Every xdt_poll_nsec nano-seconds we poll the trace buffers for data and feed
 * each entry into dtrace_probe() with the corresponding probe ID for the event.
 * As a result of this periodic collection implementation probe firings are
 * asynchronous. This is the only sensible way to implement this form of
 * provider, but because of its asynchronous nature asking things like
 * "current CPU" and, more importantly, arbitrary questions about the context
 * surrounding the probe firing are not meaningful. So, consumers should not
 * attempt to infer anything beyond what is supplied via the probe arguments.
 */

#include <sys/xpv_user.h>

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <sys/ddi.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/stat.h>
#include <sys/cmn_err.h>
#include <sys/dtrace.h>
#include <sys/sdt.h>
#include <sys/cyclic.h>
#include <vm/seg_kmem.h>
#include <vm/hat_i86.h>

#include <sys/hypervisor.h>
#include <xen/public/trace.h>
#include <xen/public/sched.h>

#define	XDT_POLL_DEFAULT	100000000	/* default poll interval (ns) */
#define	XDT_POLL_MIN		10000000	/* min poll interval (ns) */
#define	XDT_TBUF_RETRY		50		/* tbuf disable retry count */

/*
 * The domid must match IDLE_DOMAIN_ID in xen.hg/xen/include/xen/sched.h
 * in the xVM gate.
 */
#define	IS_IDLE_DOM(domid)	(domid == 0x7FFFU)

/* Macros to extract the domid and cpuid from a HVM trace data field */
#define	HVM_DOMID(d)		(d >> 16)
#define	HVM_VCPUID(d)		(d & 0xFFFF)

/* Flags for shadow page table events */
#define	SH_GUEST_32	0x000
#define	SH_GUEST_PAE	0x100
#define	SH_GUEST_64	0x200

#define	XDT_PROBE5(event, arg0, arg1, arg2, arg3, arg4) {		\
	dtrace_id_t id = xdt_probemap[event];				\
	if (id)								\
		dtrace_probe(id, arg0, arg1, arg2, arg3, arg4);		\
}									\

#define	XDT_PROBE4(event, arg0, arg1, arg2, arg3) \
	XDT_PROBE5(event, arg0, arg1, arg2, arg3, 0)

#define	XDT_PROBE3(event, arg0, arg1, arg2) \
	XDT_PROBE5(event, arg0, arg1, arg2, 0, 0)

#define	XDT_PROBE2(event, arg0, arg1) \
	XDT_PROBE5(event, arg0, arg1, 0, 0, 0)

#define	XDT_PROBE1(event, arg0) \
	XDT_PROBE5(event, arg0, 0, 0, 0, 0)

#define	XDT_PROBE0(event) \
	XDT_PROBE5(event, 0, 0, 0, 0, 0)

/* Probe classes */
#define	XDT_SCHED			0
#define	XDT_MEM				1
#define	XDT_HVM				2
#define	XDT_GEN				3
#define	XDT_PV				4
#define	XDT_SHADOW			5
#define	XDT_PM				6
#define	XDT_NCLASSES			7

/* Probe events */
#define	XDT_EVT_INVALID			(-(int)1)
#define	XDT_SCHED_OFF_CPU		0
#define	XDT_SCHED_ON_CPU		1
#define	XDT_SCHED_IDLE_OFF_CPU		2
#define	XDT_SCHED_IDLE_ON_CPU		3
#define	XDT_SCHED_BLOCK			4
#define	XDT_SCHED_SLEEP			5
#define	XDT_SCHED_WAKE			6
#define	XDT_SCHED_YIELD			7
#define	XDT_SCHED_SHUTDOWN_POWEROFF	8
#define	XDT_SCHED_SHUTDOWN_REBOOT	9
#define	XDT_SCHED_SHUTDOWN_SUSPEND	10
#define	XDT_SCHED_SHUTDOWN_CRASH	11
#define	XDT_MEM_PAGE_GRANT_MAP		12
#define	XDT_MEM_PAGE_GRANT_UNMAP	13
#define	XDT_MEM_PAGE_GRANT_TRANSFER	14
#define	XDT_HVM_VMENTRY			15
#define	XDT_HVM_VMEXIT			16
#define	XDT_TRC_LOST_RECORDS		17
#define	XDT_SCHED_ADD_VCPU		18
#define	XDT_SCHED_REM_VCPU		19	/* unused */
#define	XDT_SCHED_CTL			20	/* unused */
#define	XDT_SCHED_ADJDOM		21
#define	XDT_SCHED_S_TIMER_FN		22	/* unused */
#define	XDT_SCHED_T_TIMER_FN		23	/* unused */
#define	XDT_SCHED_DOM_TIMER_FN		24	/* unused */
#define	XDT_PV_HYPERCALL		25
#define	XDT_PV_TRAP			26
#define	XDT_PV_PAGE_FAULT		27
#define	XDT_PV_FORCED_INVALID_OP	28
#define	XDT_PV_EMULATE_PRIVOP		29
#define	XDT_PV_EMULATE_4GB		30	/* unused (32-bit HV only ) */
#define	XDT_PV_MATH_STATE_RESTORE	31
#define	XDT_PV_PAGING_FIXUP		32
#define	XDT_PV_DT_MAPPING_FAULT		33
#define	XDT_PV_PTWR_EMULATION		34
#define	XDT_HVM_PF_XEN			35
#define	XDT_HVM_PF_INJECT		36
#define	XDT_HVM_EXC_INJECT		37
#define	XDT_HVM_VIRQ_INJECT		38
#define	XDT_HVM_VIRQ_REINJECT		39
#define	XDT_HVM_IO_READ			40	/* unused */
#define	XDT_HVM_IO_WRITE		41	/* unused */
#define	XDT_HVM_CR_READ			42
#define	XDT_HVM_CR_WRITE		43
#define	XDT_HVM_DR_READ			44	/* unused */
#define	XDT_HVM_DR_WRITE		45	/* unused */
#define	XDT_HVM_MSR_READ		46
#define	XDT_HVM_MSR_WRITE		47
#define	XDT_HVM_CPUID			48
#define	XDT_HVM_INTR			49
#define	XDT_HVM_INTR_WINDOW		50
#define	XDT_HVM_NMI			51
#define	XDT_HVM_SMI			52
#define	XDT_HVM_VMMCALL			53
#define	XDT_HVM_HLT			54
#define	XDT_HVM_INVLPG			55
#define	XDT_HVM_MCE			56
#define	XDT_HVM_IOPORT_READ		57
#define	XDT_HVM_IOPORT_WRITE		58
#define	XDT_HVM_CLTS			59
#define	XDT_HVM_LMSW			60
#define	XDT_HVM_IOMEM_READ		61
#define	XDT_HVM_IOMEM_WRITE		62
#define	XDT_SHADOW_NOT_SHADOW			63
#define	XDT_SHADOW_FAST_PROPAGATE		64
#define	XDT_SHADOW_FAST_MMIO			65
#define	XDT_SHADOW_FALSE_FAST_PATH		66
#define	XDT_SHADOW_MMIO				67
#define	XDT_SHADOW_FIXUP			68
#define	XDT_SHADOW_DOMF_DYING			69
#define	XDT_SHADOW_EMULATE			70
#define	XDT_SHADOW_EMULATE_UNSHADOW_USER	71
#define	XDT_SHADOW_EMULATE_UNSHADOW_EVTINJ	72
#define	XDT_SHADOW_EMULATE_UNSHADOW_UNHANDLED	73
#define	XDT_SHADOW_WRMAP_BF			74
#define	XDT_SHADOW_PREALLOC_UNPIN		75
#define	XDT_SHADOW_RESYNC_FULL			76
#define	XDT_SHADOW_RESYNC_ONLY			77
#define	XDT_PM_FREQ_CHANGE		78
#define	XDT_PM_IDLE_ENTRY		79
#define	XDT_PM_IDLE_EXIT		80
#define	XDT_SCHED_RUNSTATE_CHANGE	81
#define	XDT_SCHED_CONTINUE_RUNNING	82
#define	XDT_NEVENTS			83

typedef struct {
	const char	*pr_mod;	/* probe module */
	const char	*pr_name;	/* probe name */
	int		evt_id;		/* event id */
	uint_t		class;		/* probe class */
} xdt_probe_t;

typedef struct {
	uint32_t	trc_mask;	/* trace mask */
	uint32_t	cnt;		/* num enabled probes in class */
} xdt_classinfo_t;

typedef struct {
	ulong_t prev_domid;		/* previous dom executed */
	ulong_t prev_vcpuid;		/* previous vcpu executed */
	ulong_t prev_ctime;		/* time spent on cpu */
	ulong_t next_domid;		/* next dom to be scheduled */
	ulong_t next_vcpuid;		/* next vcpu to be scheduled */
	ulong_t next_wtime;		/* time spent waiting to get on cpu */
	ulong_t next_ts;		/* allocated time slice */
	ulong_t cur_domid;		/* current dom */
	ulong_t cur_vcpuid;		/* current vcpuid */
	int curinfo_valid;		/* info is valid */
} xdt_schedinfo_t;

static struct {
	uint_t cnt;			/* total num of trace buffers */
	size_t size;			/* size of each cpu buffer */
	mfn_t start_mfn;		/* starting mfn of buffers */
	caddr_t va;			/* va buffers are mapped into */

	/* per-cpu buffers */
	struct t_buf **meta;		/* buffer metadata */
	struct t_rec **data;		/* buffer data records */

	/* statistics */
	uint64_t stat_dropped_recs;	/* records dropped */
	uint64_t stat_spurious_cpu;	/* recs with garbage cpuids */
	uint64_t stat_spurious_switch;	/* inconsistent vcpu switches */
	uint64_t stat_unknown_shutdown;	/* unknown shutdown code */
	uint64_t stat_unknown_recs;	/* unknown records */
} tbuf;

static size_t tbuf_data_size;

static char *xdt_stats[] = {
	"dropped_recs",
};

/*
 * Tunable variables
 *
 * The following may be tuned by adding a line to /etc/system that
 * includes both the name of the module ("xdt") and the name of the variable.
 * For example:
 *     set xdt:xdt_tbuf_pages = 40
 */
uint_t xdt_tbuf_pages = 20;			/* pages to alloc per-cpu buf */

/*
 * The following may be tuned by adding a line to
 * /platform/i86xpv/kernel/drv/xdt.conf.
 * For example:
 *     xdt_poll_nsec = 200000000;
 */
static hrtime_t xdt_poll_nsec;			/* trace buffer poll interval */

/*
 * Another tunable variable: the maximum number of records to process
 * in one scan. If it is 0 (e.g. not set in /etc/system), it will
 * be set to ncpu * (bufsize / max_rec_size).
 *
 * Having an upper limit avoids a situation where the scan would loop
 * endlessly in case the hypervisor adds records quicker than we
 * can process them. It's better to drop records than to loop, obviously.
 */
uint_t xdt_max_recs = 0;

/*
 * Internal variables
 */
static dev_info_t *xdt_devi;
static dtrace_provider_id_t xdt_id;
static uint_t xdt_ncpus;			/* total number of phys CPUs */
static uint32_t cur_trace_mask;			/* current trace mask */
static xdt_schedinfo_t *xdt_cpu_schedinfo;	/* per-cpu sched info */
dtrace_id_t xdt_probemap[XDT_NEVENTS];		/* map of enabled probes */
dtrace_id_t xdt_prid[XDT_NEVENTS];		/* IDs of registered events */
static cyclic_id_t xdt_cyclic = CYCLIC_NONE;
static kstat_t *xdt_kstats;
static xdt_classinfo_t xdt_classinfo[XDT_NCLASSES];

/*
 * These provide context when probes fire. They can be accessed
 * from xdt dtrace probe (as `xdt_curdom, etc). It's ok for these
 * to be global, and not per-cpu, as probes are run strictly in sequence
 * as the trace buffers are
 */
uint_t xdt_curdom, xdt_curvcpu, xdt_curpcpu;
uint64_t xdt_timestamp;

static xdt_probe_t xdt_probe[] = {
	/* Sched probes */
	{ "sched", "off-cpu", XDT_SCHED_OFF_CPU, XDT_SCHED },
	{ "sched", "on-cpu", XDT_SCHED_ON_CPU, XDT_SCHED },
	{ "sched", "idle-off-cpu", XDT_SCHED_IDLE_OFF_CPU, XDT_SCHED },
	{ "sched", "idle-on-cpu", XDT_SCHED_IDLE_ON_CPU, XDT_SCHED },
	{ "sched", "block", XDT_SCHED_BLOCK, XDT_SCHED },
	{ "sched", "sleep", XDT_SCHED_SLEEP, XDT_SCHED },
	{ "sched", "wake", XDT_SCHED_WAKE, XDT_SCHED },
	{ "sched", "yield", XDT_SCHED_YIELD, XDT_SCHED },
	{ "sched", "shutdown-poweroff", XDT_SCHED_SHUTDOWN_POWEROFF,
		XDT_SCHED },
	{ "sched", "shutdown-reboot", XDT_SCHED_SHUTDOWN_REBOOT, XDT_SCHED },
	{ "sched", "shutdown-suspend", XDT_SCHED_SHUTDOWN_SUSPEND, XDT_SCHED },
	{ "sched", "shutdown-crash", XDT_SCHED_SHUTDOWN_CRASH, XDT_SCHED },
	{ "sched", "add", XDT_SCHED_ADD_VCPU, XDT_SCHED },
	{ "sched", "runstate-change", XDT_SCHED_RUNSTATE_CHANGE, XDT_SCHED },
	{ "sched", "continue-running", XDT_SCHED_CONTINUE_RUNNING, XDT_SCHED },

	/* Memory probes */
	{ "mem", "page-grant-map", XDT_MEM_PAGE_GRANT_MAP, XDT_MEM },
	{ "mem", "page-grant-unmap", XDT_MEM_PAGE_GRANT_UNMAP, XDT_MEM },
	{ "mem", "page-grant-transfer", XDT_MEM_PAGE_GRANT_TRANSFER, XDT_MEM },

	{"pv", "hypercall", XDT_PV_HYPERCALL, XDT_PV },
	{"pv", "trap", XDT_PV_TRAP, XDT_PV },
	{"pv", "page-fault", XDT_PV_PAGE_FAULT, XDT_PV },
	{"pv", "forced-invalid-op", XDT_PV_FORCED_INVALID_OP, XDT_PV },
	{"pv", "emulate-priv-op", XDT_PV_EMULATE_PRIVOP, XDT_PV },
	{"pv", "math-state-restore", XDT_PV_MATH_STATE_RESTORE, XDT_PV },
	{"pv", "paging-fixup", XDT_PV_PAGING_FIXUP, XDT_PV },
	{"pv", "dt-mapping-fault", XDT_PV_DT_MAPPING_FAULT, XDT_PV },
	{"pv", "pte-write-emul", XDT_PV_PTWR_EMULATION, XDT_PV },

	/* HVM probes */
	{ "hvm", "vmentry", XDT_HVM_VMENTRY, XDT_HVM },
	{ "hvm", "vmexit", XDT_HVM_VMEXIT, XDT_HVM },
	{ "hvm", "pagefault-xen", XDT_HVM_PF_XEN, XDT_HVM },
	{ "hvm", "pagefault-inject", XDT_HVM_PF_INJECT, XDT_HVM },
	{ "hvm", "exception-inject", XDT_HVM_EXC_INJECT, XDT_HVM },
	{ "hvm", "virq-inject", XDT_HVM_VIRQ_INJECT, XDT_HVM },
	{ "hvm", "cr-read", XDT_HVM_CR_READ, XDT_HVM },
	{ "hvm", "cr-write", XDT_HVM_CR_WRITE, XDT_HVM },
	{ "hvm", "msr-read", XDT_HVM_MSR_READ, XDT_HVM },
	{ "hvm", "msr-write", XDT_HVM_MSR_WRITE, XDT_HVM },
	{ "hvm", "cpuid", XDT_HVM_CPUID, XDT_HVM },
	{ "hvm", "intr", XDT_HVM_INTR, XDT_HVM },
	{ "hvm", "intr-window", XDT_HVM_INTR_WINDOW, XDT_HVM },
	{ "hvm", "nmi", XDT_HVM_NMI, XDT_HVM },
	{ "hvm", "smi", XDT_HVM_SMI, XDT_HVM },
	{ "hvm", "vmmcall", XDT_HVM_VMMCALL, XDT_HVM },
	{ "hvm", "hlt", XDT_HVM_HLT, XDT_HVM },
	{ "hvm", "invlpg", XDT_HVM_INVLPG, XDT_HVM },
	{ "hvm", "mce", XDT_HVM_MCE, XDT_HVM },
	{ "hvm", "pio-read", XDT_HVM_IOPORT_READ, XDT_HVM },
	{ "hvm", "pio-write", XDT_HVM_IOPORT_WRITE, XDT_HVM },
	{ "hvm", "mmio-read", XDT_HVM_IOMEM_READ, XDT_HVM },
	{ "hvm", "mmio-write", XDT_HVM_IOMEM_WRITE, XDT_HVM },
	{ "hvm", "clts", XDT_HVM_CLTS, XDT_HVM },
	{ "hvm", "lmsw", XDT_HVM_LMSW, XDT_HVM },

	{ "shadow", "fault-not-shadow", XDT_SHADOW_NOT_SHADOW, XDT_SHADOW },
	{ "shadow", "fast-propagate", XDT_SHADOW_FAST_PROPAGATE, XDT_SHADOW },
	{ "shadow", "fast-mmio", XDT_SHADOW_FAST_MMIO, XDT_SHADOW },
	{ "shadow", "false-fast-path", XDT_SHADOW_FALSE_FAST_PATH,
	    XDT_SHADOW },
	{ "shadow", "mmio", XDT_SHADOW_MMIO, XDT_SHADOW },
	{ "shadow", "fixup", XDT_SHADOW_FIXUP, XDT_SHADOW },
	{ "shadow", "domf-dying", XDT_SHADOW_DOMF_DYING, XDT_SHADOW },
	{ "shadow", "emulate", XDT_SHADOW_EMULATE, XDT_SHADOW },
	{ "shadow", "emulate-unshadow-user", XDT_SHADOW_EMULATE_UNSHADOW_USER,
	    XDT_SHADOW },
	{ "shadow", "emulate-unshadow-evtinj",
	    XDT_SHADOW_EMULATE_UNSHADOW_EVTINJ, XDT_SHADOW },
	{ "shadow", "emulate-unshadow-unhandled",
	    XDT_SHADOW_EMULATE_UNSHADOW_UNHANDLED, XDT_SHADOW },
	{ "shadow", "wrmap-bf", XDT_SHADOW_WRMAP_BF, XDT_SHADOW },
	{ "shadow", "prealloc-unpin", XDT_SHADOW_PREALLOC_UNPIN, XDT_SHADOW },
	{ "shadow", "resync-full", XDT_SHADOW_RESYNC_FULL, XDT_SHADOW },
	{ "shadow", "resync-only", XDT_SHADOW_RESYNC_ONLY, XDT_SHADOW },

	{ "pm", "freq-change", XDT_PM_FREQ_CHANGE, XDT_PM },
	{ "pm", "idle-entry", XDT_PM_IDLE_ENTRY, XDT_PM },
	{ "pm", "idle-exit", XDT_PM_IDLE_EXIT, XDT_PM },

	/* Trace buffer related probes */
	{ "trace", "records-lost", XDT_TRC_LOST_RECORDS, XDT_GEN },

	{ NULL }
};

static inline uint32_t
xdt_nr_active_probes()
{
	int i;
	uint32_t tot = 0;

	for (i = 0; i < XDT_NCLASSES; i++)
		tot += xdt_classinfo[i].cnt;

	return (tot);
}

static void
xdt_init_trace_masks(void)
{
	xdt_classinfo[XDT_SCHED].trc_mask = TRC_SCHED;
	xdt_classinfo[XDT_MEM].trc_mask = TRC_MEM;
	xdt_classinfo[XDT_HVM].trc_mask = TRC_HVM;
	xdt_classinfo[XDT_GEN].trc_mask = TRC_GEN;
	xdt_classinfo[XDT_PV].trc_mask = TRC_PV;
	xdt_classinfo[XDT_SHADOW].trc_mask = TRC_SHADOW;
	xdt_classinfo[XDT_PM].trc_mask = TRC_PM;
}

static int
xdt_kstat_update(kstat_t *ksp, int flag)
{
	kstat_named_t *knp;

	if (flag != KSTAT_READ)
		return (EACCES);

	knp = ksp->ks_data;

	/*
	 * Assignment order should match that of the names in
	 * xdt_stats.
	 */
	(knp++)->value.ui64 = tbuf.stat_dropped_recs;

	return (0);
}

static void
xdt_kstat_init(void)
{
	int nstats = sizeof (xdt_stats) / sizeof (xdt_stats[0]);
	char **cp = xdt_stats;
	kstat_named_t *knp;

	if ((xdt_kstats = kstat_create("xdt", 0, "trace_statistics", "misc",
	    KSTAT_TYPE_NAMED, nstats, 0)) == NULL)
		return;

	xdt_kstats->ks_update = xdt_kstat_update;

	knp = xdt_kstats->ks_data;
	while (nstats > 0) {
		kstat_named_init(knp, *cp, KSTAT_DATA_UINT64);
		knp++;
		cp++;
		nstats--;
	}

	kstat_install(xdt_kstats);
}

static int
xdt_sysctl_tbuf(xen_sysctl_tbuf_op_t *tbuf_op)
{
	xen_sysctl_t op;
	int xerr;

	op.cmd = XEN_SYSCTL_tbuf_op;
	op.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
	op.u.tbuf_op = *tbuf_op;

	if ((xerr = HYPERVISOR_sysctl(&op)) != 0)
		return (xen_xlate_errcode(xerr));

	*tbuf_op = op.u.tbuf_op;
	return (0);
}

static int
xdt_map_trace_buffers(mfn_t mfn, caddr_t va, size_t len)
{
	x86pte_t pte;
	caddr_t const sva = va;
	caddr_t const eva = va + len;
	int xerr;

	ASSERT(mfn != MFN_INVALID);
	ASSERT(va != NULL);
	ASSERT(IS_PAGEALIGNED(len));

	for (; va < eva; va += MMU_PAGESIZE) {
		/*
		 * Ask the HAT to load a throwaway mapping to page zero, then
		 * overwrite it with the hypervisor mapping. It gets removed
		 * later via hat_unload().
		 */
		hat_devload(kas.a_hat, va, MMU_PAGESIZE, (pfn_t)0,
		    PROT_READ | HAT_UNORDERED_OK,
		    HAT_LOAD_NOCONSIST | HAT_LOAD);

		pte = mmu_ptob((x86pte_t)mfn) | PT_VALID | PT_USER
		    | PT_FOREIGN | PT_WRITABLE;

		xerr = HYPERVISOR_update_va_mapping_otherdomain((ulong_t)va,
		    pte, UVMF_INVLPG | UVMF_LOCAL, DOMID_XEN);

		if (xerr != 0) {
			/* unmap pages loaded so far */
			size_t ulen = (uintptr_t)(va + MMU_PAGESIZE) -
			    (uintptr_t)sva;
			hat_unload(kas.a_hat, sva, ulen, HAT_UNLOAD_UNMAP);
			return (xen_xlate_errcode(xerr));
		}

		mfn++;
	}

	return (0);
}

static int
xdt_attach_trace_buffers(void)
{
	xen_sysctl_tbuf_op_t tbuf_op;
	size_t len;
	int err;
	uint_t i;

	/*
	 * Xen does not support trace buffer re-sizing. If the buffers
	 * have already been allocated we just use them as is.
	 */
	tbuf_op.cmd  = XEN_SYSCTL_TBUFOP_get_info;
	if ((err = xdt_sysctl_tbuf(&tbuf_op)) != 0)
		return (err);

	if (tbuf_op.size == 0) {
		/* set trace buffer size */
		tbuf_op.cmd  = XEN_SYSCTL_TBUFOP_set_size;
		tbuf_op.size = xdt_tbuf_pages;
		(void) xdt_sysctl_tbuf(&tbuf_op);

		/* get trace buffer info */
		tbuf_op.cmd  = XEN_SYSCTL_TBUFOP_get_info;
		if ((err = xdt_sysctl_tbuf(&tbuf_op)) != 0)
			return (err);

		if (tbuf_op.size == 0) {
			cmn_err(CE_NOTE, "Couldn't allocate trace buffers.");
			return (ENOBUFS);
		}
	}

	tbuf.size = tbuf_op.size;
	tbuf.start_mfn = (mfn_t)tbuf_op.buffer_mfn;
	tbuf.cnt = xdt_ncpus;

	ASSERT(tbuf.start_mfn != MFN_INVALID);
	ASSERT(tbuf.cnt > 0);

	len = tbuf.size * tbuf.cnt;
	tbuf.va = vmem_alloc(heap_arena, len, VM_SLEEP);

	if ((err = xdt_map_trace_buffers(tbuf.start_mfn, tbuf.va, len)) != 0) {
		vmem_free(heap_arena, tbuf.va, len);
		tbuf.va = NULL;
		return (err);
	}

	tbuf.meta = (struct t_buf **)kmem_alloc(tbuf.cnt * sizeof (*tbuf.meta),
	    KM_SLEEP);
	tbuf.data = (struct t_rec **)kmem_alloc(tbuf.cnt * sizeof (*tbuf.data),
	    KM_SLEEP);

	for (i = 0; i < tbuf.cnt; i++) {
		void *cpu_buf = (void *)(tbuf.va + (tbuf.size * i));
		tbuf.meta[i] = cpu_buf;
		tbuf.data[i] = (struct t_rec *)((uintptr_t)cpu_buf +
		    sizeof (struct t_buf));

		/* throw away stale trace records */
		tbuf.meta[i]->cons = tbuf.meta[i]->prod;
	}

	tbuf_data_size = tbuf.size - sizeof (struct t_buf);
	if (xdt_max_recs == 0)
		xdt_max_recs = (xdt_ncpus * tbuf_data_size)
		    / sizeof (struct t_rec);

	return (0);
}

static void
xdt_detach_trace_buffers(void)
{
	size_t len = tbuf.size * tbuf.cnt;

	ASSERT(tbuf.va != NULL);

	hat_unload(kas.a_hat, tbuf.va, len,
	    HAT_UNLOAD_UNMAP | HAT_UNLOAD_UNLOCK);
	vmem_free(heap_arena, tbuf.va, len);
	kmem_free(tbuf.meta, tbuf.cnt * sizeof (*tbuf.meta));
	kmem_free(tbuf.data, tbuf.cnt * sizeof (*tbuf.data));
}

static void
xdt_update_sched_context(uint_t cpuid, uint_t dom, uint_t vcpu)
{
	xdt_schedinfo_t *sp = &xdt_cpu_schedinfo[cpuid];

	sp->cur_domid = dom;
	sp->cur_vcpuid = vcpu;
	sp->curinfo_valid = 1;
}

static void
xdt_update_domain_context(uint_t dom, uint_t vcpu)
{
	xdt_curdom = dom;
	xdt_curvcpu = vcpu;
}

static size_t
xdt_process_rec(uint_t cpuid, struct t_rec *rec)
{
	xdt_schedinfo_t *sp = &xdt_cpu_schedinfo[cpuid];
	uint_t dom, vcpu;
	int eid;
	uint32_t *data;
	uint64_t tsc, addr64, rip64, val64, pte64;
	size_t rec_size;

	ASSERT(rec != NULL);
	ASSERT(xdt_ncpus == xpv_nr_phys_cpus());

	eid = 0;
	if (cpuid >= xdt_ncpus) {
		tbuf.stat_spurious_cpu++;
		goto done;
	}

	/*
	 * If our current state isn't valid, and if this is not
	 * an event that will update our state, skip it.
	 */

	if (!sp->curinfo_valid &&
	    rec->event != TRC_SCHED_SWITCH &&
	    rec->event != TRC_LOST_RECORDS)
		goto done;

	if (rec->cycles_included) {
		data = rec->u.cycles.extra_u32;
		tsc = (((uint64_t)rec->u.cycles.cycles_hi) << 32)
		    | rec->u.cycles.cycles_lo;
	} else {
		data = rec->u.nocycles.extra_u32;
		tsc = 0;
	}

	xdt_timestamp = tsc;

	switch (rec->event) {
	/*
	 * Sched probes
	 */
	case TRC_SCHED_SWITCH_INFPREV:
		/*
		 * Info on vCPU being de-scheduled
		 *
		 * data[0] = prev domid
		 * data[1] = time spent on pcpu
		 */
		sp->prev_domid = data[0];
		sp->prev_ctime = data[1];
		break;

	case TRC_SCHED_SWITCH_INFNEXT:
		/*
		 * Info on next vCPU to be scheduled
		 *
		 * data[0] = next domid
		 * data[1] = time spent waiting to get on cpu
		 * data[2] = time slice
		 */
		sp->next_domid = data[0];
		sp->next_wtime = data[1];
		sp->next_ts = data[2];
		break;

	case TRC_SCHED_SWITCH:
		/*
		 * vCPU switch
		 *
		 * data[0] = prev domid
		 * data[1] = prev vcpuid
		 * data[2] = next domid
		 * data[3] = next vcpuid
		 */

		/*
		 * Provide valid context for this probe if there
		 * wasn't one.
		 */
		if (!sp->curinfo_valid)
			xdt_update_domain_context(data[0], data[1]);

		xdt_update_sched_context(cpuid, data[0], data[1]);

		if (data[0] != sp->prev_domid &&
		    data[2] != sp->next_domid) {
			/* prev and next info don't match doms being sched'd */
			tbuf.stat_spurious_switch++;
			goto switchdone;
		}

		sp->prev_vcpuid = data[1];
		sp->next_vcpuid = data[3];

		XDT_PROBE3(IS_IDLE_DOM(sp->prev_domid)?
		    XDT_SCHED_IDLE_OFF_CPU:XDT_SCHED_OFF_CPU,
		    sp->prev_domid, sp->prev_vcpuid, sp->prev_ctime);

		XDT_PROBE4(IS_IDLE_DOM(sp->next_domid)?
		    XDT_SCHED_IDLE_ON_CPU:XDT_SCHED_ON_CPU,
		    sp->next_domid, sp->next_vcpuid, sp->next_wtime,
		    sp->next_ts);
switchdone:
		xdt_update_sched_context(cpuid, data[2], data[3]);
		xdt_update_domain_context(data[2], data[3]);

		break;

	case TRC_SCHED_BLOCK:
		/*
		 * vCPU blocked
		 *
		 * data[0] = domid
		 * data[1] = vcpuid
		 */
		XDT_PROBE2(XDT_SCHED_BLOCK, data[0], data[1]);
		break;

	case TRC_SCHED_SLEEP:
		/*
		 * Put vCPU to sleep
		 *
		 * data[0] = domid
		 * data[1] = vcpuid
		 */
		XDT_PROBE2(XDT_SCHED_SLEEP, data[0], data[1]);
		break;

	case TRC_SCHED_WAKE:
		/*
		 * Wake up vCPU
		 *
		 * data[0] = domid
		 * data[1] = vcpuid
		 */
		XDT_PROBE2(XDT_SCHED_WAKE, data[0], data[1]);
		break;

	case TRC_SCHED_YIELD:
		/*
		 * vCPU yielded
		 *
		 * data[0] = domid
		 * data[1] = vcpuid
		 */
		XDT_PROBE2(XDT_SCHED_YIELD, data[0], data[1]);
		break;

	case TRC_SCHED_SHUTDOWN:
		/*
		 * Guest shutting down
		 *
		 * data[0] = domid
		 * data[1] = initiating vcpu
		 * data[2] = shutdown code
		 */
		switch (data[2]) {
		case SHUTDOWN_poweroff:
			eid = XDT_SCHED_SHUTDOWN_POWEROFF;
			break;
		case SHUTDOWN_reboot:
			eid = XDT_SCHED_SHUTDOWN_REBOOT;
			break;
		case SHUTDOWN_suspend:
			eid = XDT_SCHED_SHUTDOWN_SUSPEND;
			break;
		case SHUTDOWN_crash:
			eid = XDT_SCHED_SHUTDOWN_CRASH;
			break;
		default:
			tbuf.stat_unknown_shutdown++;
			goto done;
		}

		XDT_PROBE2(eid, data[0], data[1]);
		break;

	case TRC_SCHED_DOM_REM:
	case TRC_SCHED_CTL:
	case TRC_SCHED_S_TIMER_FN:
	case TRC_SCHED_T_TIMER_FN:
	case TRC_SCHED_DOM_TIMER_FN:
		/* unused */
		break;
	case TRC_SCHED_DOM_ADD:
		/*
		 * Add vcpu to a guest.
		 *
		 * data[0] = domid
		 * data[1] = vcpu
		 */
		XDT_PROBE2(XDT_SCHED_ADD_VCPU, data[0], data[1]);
		break;
	case TRC_SCHED_ADJDOM:
		/*
		 * Scheduling parameters for a guest
		 * were modified.
		 *
		 * data[0] = domid;
		 */
		XDT_PROBE1(XDT_SCHED_ADJDOM, data[1]);
		break;
	case TRC_SCHED_RUNSTATE_CHANGE:
		/*
		 * Runstate change for a VCPU.
		 *
		 * data[0] = (domain << 16) | vcpu;
		 * data[1] = oldstate;
		 * data[2] = newstate;
		 */
		XDT_PROBE4(XDT_SCHED_RUNSTATE_CHANGE, data[0] >> 16,
		    data[0] & 0xffff, data[1], data[2]);
		break;
	case TRC_SCHED_CONTINUE_RUNNING:
		/*
		 * VCPU is back on a physical CPU that it previously
		 * was also running this VCPU.
		 *
		 * data[0] = (domain << 16) | vcpu;
		 */
		XDT_PROBE2(XDT_SCHED_CONTINUE_RUNNING, data[0] >> 16,
		    data[0] & 0xffff);
		break;
	/*
	 * Mem probes
	 */
	case TRC_MEM_PAGE_GRANT_MAP:
		/*
		 * Guest mapped page grant
		 *
		 * data[0] = target domid
		 */
		XDT_PROBE1(XDT_MEM_PAGE_GRANT_MAP, data[0]);
		break;

	case TRC_MEM_PAGE_GRANT_UNMAP:
		/*
		 * Guest unmapped page grant
		 *
		 * data[0] = target domid
		 */
		XDT_PROBE1(XDT_MEM_PAGE_GRANT_UNMAP, data[0]);
		break;

	case TRC_MEM_PAGE_GRANT_TRANSFER:
		/*
		 * Page grant is being transferred
		 *
		 * data[0] = target domid
		 */
		XDT_PROBE1(XDT_MEM_PAGE_GRANT_TRANSFER, data[0]);
		break;

	/*
	 * Probes for PV domains.
	 */
	case TRC_PV_HYPERCALL:
		/*
		 * Hypercall from a 32-bit PV domain.
		 *
		 * data[0] = eip
		 * data[1] = eax
		 */
		XDT_PROBE2(XDT_PV_HYPERCALL, data[0], data[1]);
		break;
	case TRC_PV_HYPERCALL | TRC_64_FLAG:
		/*
		 * Hypercall from a 64-bit PV domain.
		 *
		 * data[0] = rip(0:31)
		 * data[1] = rip(32:63)
		 * data[2] = eax;
		 */
		rip64 = (((uint64_t)data[1]) << 32) | data[0];
		XDT_PROBE2(XDT_PV_HYPERCALL, rip64, data[2]);
		break;
	case TRC_PV_TRAP:
		/*
		 * Trap in a 32-bit PV domain.
		 *
		 * data[0] = eip
		 * data[1] = trapnr | (error_code_valid << 15)
		 *	| (error_code << 16);
		 */
		XDT_PROBE4(XDT_PV_TRAP, data[0], data[1] & 0x7fff,
		    (data[1] >> 15) & 1, data[1] >> 16);
		break;
	case TRC_PV_TRAP | TRC_64_FLAG:
		/*
		 * Trap in a 64-bit PV domain.
		 *
		 * data[0] = rip(0:31)
		 * data[1] = rip(32:63)
		 * data[2] = trapnr | (error_code_valid << 15)
		 *	| (error_code << 16);
		 */
		rip64 = (((uint64_t)data[1]) << 32) | data[2];
		XDT_PROBE4(XDT_PV_TRAP, rip64, data[2] & 0x7fff,
		    (data[2] >> 15) & 1, data[2] >> 16);
		break;
	case TRC_PV_PAGE_FAULT:
		/*
		 * Page fault in a 32-bit PV domain.
		 *
		 * data[0] = eip
		 * data[1] = vaddr
		 * data[2] = error code
		 */
		XDT_PROBE3(XDT_PV_PAGE_FAULT, data[0], data[1], data[2]);
		break;
	case TRC_PV_PAGE_FAULT | TRC_64_FLAG:
		/*
		 * Page fault in a 32-bit PV domain.
		 *
		 * data[0] = rip(0:31)
		 * data[1] = rip(31:63)
		 * data[2] = vaddr(0:31)
		 * data[3] = vaddr(31:63)
		 * data[4] = error code
		 */
		rip64 = (((uint64_t)data[1]) << 32) | data[0];
		addr64 = (((uint64_t)data[3]) << 32) | data[2];
		XDT_PROBE3(XDT_PV_PAGE_FAULT, rip64, addr64, data[4]);
		break;
	case TRC_PV_FORCED_INVALID_OP:
		/*
		 * Hypervisor emulated a forced invalid op (ud2)
		 * in a 32-bit PV domain.
		 *
		 * data[1] = eip
		 */
		XDT_PROBE1(XDT_PV_FORCED_INVALID_OP, data[1]);
		break;
	case TRC_PV_FORCED_INVALID_OP | TRC_64_FLAG:
		/*
		 * Hypervisor emulated a forced invalid op (ud2)
		 * in a 64-bit PV domain.
		 *
		 * data[1] = rip(0:31)
		 * data[2] = rip(31:63)
		 *
		 */
		rip64 = (((uint64_t)data[2]) << 32) | data[1];
		XDT_PROBE1(XDT_PV_FORCED_INVALID_OP, rip64);
		break;
	case TRC_PV_EMULATE_PRIVOP:
		/*
		 * Hypervisor emulated a privileged operation
		 * in a 32-bit PV domain.
		 *
		 * data[0] = eip
		 */
		XDT_PROBE1(XDT_PV_EMULATE_PRIVOP, data[0]);
		break;
	case TRC_PV_EMULATE_PRIVOP | TRC_64_FLAG:
		/*
		 * Hypervisor emulated a privileged operation
		 * in a 64-bit PV domain.
		 *
		 * data[0] = rip(0:31)
		 * data[1] = rip(31:63)
		 */
		rip64 = (((uint64_t)data[1]) << 32) | data[0];
		XDT_PROBE1(XDT_PV_EMULATE_PRIVOP, rip64);
		break;
	case TRC_PV_EMULATE_4GB:
		/* unused, 32-bit hypervisor only */
		break;
	case TRC_PV_MATH_STATE_RESTORE:
		/*
		 * Hypervisor restores math state after FP DNA trap.
		 *
		 * No arguments.
		 */
		XDT_PROBE0(XDT_PV_MATH_STATE_RESTORE);
		break;
	case TRC_PV_PAGING_FIXUP:
		/*
		 * Hypervisor fixed up a page fault (e.g. it was
		 * a side-effect of hypervisor guest page table
		 * bookkeeping, and not propagated to the guest).
		 *
		 * data[0] = eip
		 * data[1] = vaddr
		 */
		XDT_PROBE2(XDT_PV_PAGING_FIXUP, data[0], data[2]);
		break;
	case TRC_PV_PAGING_FIXUP | TRC_64_FLAG:
		/*
		 * Hypervisor fixed up a page fault (e.g. it was
		 * a side-effect of hypervisor guest page table
		 * bookkeeping, and not propagated to the guest).
		 *
		 * data[0] = eip(0:31)
		 * data[1] = eip(31:63)
		 * data[2] = vaddr(0:31)
		 * data[3] = vaddr(31:63)
		 */
		rip64 = (((uint64_t)data[1]) << 32) | data[0];
		addr64 = (((uint64_t)data[3]) << 32) | data[2];
		XDT_PROBE2(XDT_PV_PAGING_FIXUP, rip64, addr64);
		break;
	case TRC_PV_GDT_LDT_MAPPING_FAULT:
		/*
		 * Descriptor table mapping fault in a 32-bit PV domain.
		 * data[0] = eip
		 * data[1] = offset
		 */
		XDT_PROBE2(XDT_PV_DT_MAPPING_FAULT, data[0], data[1]);
		break;
	case TRC_PV_GDT_LDT_MAPPING_FAULT | TRC_64_FLAG:
		/*
		 * Descriptor table mapping fault in a 64-bit PV domain.
		 *
		 * data[0] = eip(0:31)
		 * data[1] = eip(31:63)
		 * data[2] = offset(0:31)
		 * data[3] = offset(31:63)
		 */
		rip64 = (((uint64_t)data[1]) << 32) | data[0];
		val64 = (((uint64_t)data[3]) << 32) | data[2];
		XDT_PROBE2(XDT_PV_DT_MAPPING_FAULT, rip64, val64);
		break;
	case TRC_PV_PTWR_EMULATION:
	case TRC_PV_PTWR_EMULATION_PAE | TRC_64_FLAG:
		/*
		 * Should only happen on 32-bit hypervisor; unused.
		 */
		break;
	case TRC_PV_PTWR_EMULATION_PAE:
		/*
		 * PTE write emulation for a 32-bit PV domain.
		 *
		 * data[0] = pte
		 * data[1] = addr
		 * data[2] = eip
		 */
		XDT_PROBE3(XDT_PV_PTWR_EMULATION, data[0], data[1], data[2]);
		break;
	case TRC_PV_PTWR_EMULATION | TRC_64_FLAG:
		/*
		 * PTE write emulation for a 64-bit PV domain.
		 *
		 * data[0] = pte(0:31)
		 * data[1] = pte(32:63)
		 * data[2] = addr(0:31)
		 * data[3] = addr(32:63)
		 * data[4] = rip(0:31)
		 * data[5] = rip(32:63)
		 */
		pte64 = (((uint64_t)data[1]) << 32) | data[0];
		addr64 = (((uint64_t)data[3]) << 32) | data[2];
		rip64 = (((uint64_t)data[5]) << 32) | data[4];
		XDT_PROBE3(XDT_PV_PTWR_EMULATION, pte64, addr64, rip64);
		break;

	/*
	 * HVM probes
	 */
	case TRC_HVM_VMENTRY:
		/*
		 * Return to guest via vmx_launch/vmrun
		 *
		 */
		XDT_PROBE0(XDT_HVM_VMENTRY);
		break;

	case TRC_HVM_VMEXIT:
		/*
		 * Entry into VMEXIT handler from 32-bit HVM domain
		 *
		 * data[0] = cpu vendor specific exit code
		 * data[1] = guest eip
		 */
		XDT_PROBE2(XDT_HVM_VMEXIT, data[0], data[1]);
		break;
	case TRC_HVM_VMEXIT64:
		/*
		 * Entry into VMEXIT handler from 64-bit HVM domain
		 *
		 * data[0] = cpu vendor specific exit code
		 * data[1] = guest rip(0:31)
		 * data[2] = guest rip(32:64)
		 */
		rip64 = (((uint64_t)data[2]) << 32) | data[1];
		XDT_PROBE2(XDT_HVM_VMEXIT, data[0], rip64);
		break;

	case TRC_HVM_PF_XEN64:
		/*
		 * Pagefault in a guest that is a Xen (e.g. shadow)
		 * artifact, and is not injected back into the guest.
		 *
		 * data[0] = error code
		 * data[1] = guest VA(0:31)
		 * data[2] = guest VA(32:64)
		 */
		addr64 = (((uint64_t)data[2]) << 32) | data[1];
		XDT_PROBE2(XDT_HVM_PF_XEN, data[0], addr64);
		break;

	case TRC_HVM_PF_XEN:
		/*
		 * Same as above, but for a 32-bit HVM domain.
		 *
		 * data[0] = error code
		 * data[1] = guest VA
		 */
		XDT_PROBE2(XDT_HVM_PF_XEN, data[0], data[1]);
		break;

	case TRC_HVM_PF_INJECT:
		/*
		 * 32-bit Xen only.
		 */
		break;
	case TRC_HVM_PF_INJECT64:
		/*
		 * Pagefault injected back into a guest (e.g. the shadow
		 * code found no mapping).
		 *
		 * data[0] = error code
		 * data[1] = guest VA(0:31)
		 * data[2] = guest VA(32:64)
		 */
		addr64 = (((uint64_t)data[2]) << 32) | data[1];
		XDT_PROBE2(XDT_HVM_PF_INJECT, data[0], addr64);
		break;

	case TRC_HVM_INJ_EXC:
		/*
		 * Exception injected into an HVM guest.
		 *
		 * data[0] = trap
		 * data[1] = error code
		 */
		XDT_PROBE2(XDT_HVM_EXC_INJECT, data[0], data[1]);
		break;
	case TRC_HVM_INJ_VIRQ:
		/*
		 * Interrupt inject into an HVM guest.
		 *
		 * data[0] = vector
		 */
		XDT_PROBE1(XDT_HVM_VIRQ_INJECT, data[0]);
		break;
	case TRC_HVM_REINJ_VIRQ:
	case TRC_HVM_IO_READ:
	case TRC_HVM_IO_WRITE:
		/* unused */
		break;
	case TRC_HVM_CR_READ64:
		/*
		 * Control register read. Intel VMX only.
		 *
		 * data[0] = control register #
		 * data[1] = value(0:31)
		 * data[2] = value(32:63)
		 */
		val64 = (((uint64_t)data[2]) << 32) | data[1];
		XDT_PROBE2(XDT_HVM_CR_READ, data[0], val64);
		break;
	case TRC_HVM_CR_READ:
		/*
		 * unused (32-bit Xen only)
		 */
		break;
	case TRC_HVM_CR_WRITE64:
		/*
		 * Control register write. Intel VMX only.
		 *
		 * data[0] = control register #
		 * data[1] = value(0:31)
		 * data[2] = value(32:63)
		 */
		val64 = (((uint64_t)data[2]) << 32) | data[1];
		XDT_PROBE2(XDT_HVM_CR_READ, data[0], val64);
		break;
	case TRC_HVM_CR_WRITE:
		/*
		 * unused (32-bit Xen only)
		 */
		break;
	case TRC_HVM_DR_READ:
		/*
		 * unused.
		 *
		 * data[0] = (domid<<16 + vcpuid)
		 */
		break;
	case TRC_HVM_DR_WRITE:
		/*
		 * Debug register write. Not too useful; no values,
		 * so we ignore this.
		 *
		 * data[0] = (domid<<16 + vcpuid)
		 */
		break;
	case TRC_HVM_MSR_READ:
		/*
		 * MSR read.
		 *
		 * data[0] = MSR
		 * data[1] = value(0:31)
		 * data[2] = value(32:63)
		 */
		val64 = (((uint64_t)data[3]) << 32) | data[2];
		XDT_PROBE2(XDT_HVM_MSR_READ, data[0], val64);
		break;
	case TRC_HVM_MSR_WRITE:
		/*
		 * MSR write.
		 *
		 * data[0] = MSR;
		 * data[1] = value(0:31)
		 * data[2] = value(32:63)
		 */
		val64 = (((uint64_t)data[2]) << 32) | data[1];
		XDT_PROBE2(XDT_HVM_MSR_WRITE, data[0], val64);
		break;
	case TRC_HVM_CPUID:
		/*
		 * CPUID insn.
		 *
		 * data[0] = %eax (input)
		 * data[1] = %eax
		 * data[2] = %ebx
		 * data[3] = %ecx
		 * data[4] = %edx
		 */
		XDT_PROBE5(XDT_HVM_CPUID, data[0], data[1], data[2], data[3],
		    data[4]);
		break;
	case TRC_HVM_INTR:
		/*
		 * VMEXIT because of an interrupt.
		 */
		XDT_PROBE0(XDT_HVM_INTR);
		break;
	case TRC_HVM_INTR_WINDOW:
		/*
		 * VMEXIT because of an interrupt window (an interrupt
		 * can't be delivered immediately to a HVM guest and must
		 * be delayed).
		 *
		 * data[0] = vector
		 * data[1] = source
		 * data[2] = info
		 */
		XDT_PROBE3(XDT_HVM_INTR_WINDOW, data[0], data[1], data[2]);
		break;
	case TRC_HVM_NMI:
		/*
		 * VMEXIT because of an NMI.
		 */
		XDT_PROBE0(XDT_HVM_NMI);
		break;
	case TRC_HVM_SMI:
		/*
		 * VMEXIT because of an SMI
		 */
		XDT_PROBE0(XDT_HVM_SMI);
		break;
	case TRC_HVM_VMMCALL:
		/*
		 * VMMCALL insn.
		 *
		 * data[0] = %eax
		 */
		XDT_PROBE1(XDT_HVM_VMMCALL, data[0]);
		break;
	case TRC_HVM_HLT:
		/*
		 * HLT insn.
		 *
		 * data[0] = 1 if VCPU runnable, 0 if not
		 */
		XDT_PROBE1(XDT_HVM_HLT, data[0]);
		break;
	case TRC_HVM_INVLPG64:
		/*
		 *
		 * data[0] = INVLPGA ? 1 : 0
		 * data[1] = vaddr(0:31)
		 * data[2] = vaddr(32:63)
		 */
		addr64 = (((uint64_t)data[2]) << 32) | data[1];
		XDT_PROBE2(XDT_HVM_INVLPG, data[0], addr64);
		break;
	case TRC_HVM_INVLPG:
		/*
		 * unused (32-bit Xen only)
		 *
		 * data[0] = (domid<<16 + vcpuid)
		 */
		break;
	case TRC_HVM_MCE:
		/*
		 * #MCE VMEXIT
		 *
		 */
		XDT_PROBE0(XDT_HVM_MCE);
		break;
	case TRC_HVM_IOPORT_READ:
	case TRC_HVM_IOPORT_WRITE:
	case TRC_HVM_IOMEM_READ:
	case TRC_HVM_IOMEM_WRITE:
		/*
		 * data[0] = addr(0:31)
		 * data[1] = addr(32:63)
		 * data[2] = count
		 * data[3] = size
		 */
		switch (rec->event) {
		case TRC_HVM_IOPORT_READ:
			eid = XDT_HVM_IOPORT_READ;
			break;
		case TRC_HVM_IOPORT_WRITE:
			eid = XDT_HVM_IOPORT_WRITE;
			break;
		case TRC_HVM_IOMEM_READ:
			eid = XDT_HVM_IOMEM_READ;
			break;
		case TRC_HVM_IOMEM_WRITE:
			eid = XDT_HVM_IOMEM_WRITE;
			break;
		}
		addr64 = (((uint64_t)data[1]) << 32) | data[0];
		XDT_PROBE3(eid, addr64, data[2], data[3]);
		break;
	case TRC_HVM_CLTS:
		/*
		 * CLTS insn (Intel VMX only)
		 */
		XDT_PROBE0(XDT_HVM_CLTS);
		break;
	case TRC_HVM_LMSW64:
		/*
		 * LMSW insn.
		 *
		 * data[0] = value(0:31)
		 * data[1] = value(32:63)
		 */
		val64 = (((uint64_t)data[1]) << 32) | data[0];
		XDT_PROBE1(XDT_HVM_LMSW, val64);
		break;
	case TRC_HVM_LMSW:
		/*
		 * unused (32-bit Xen only)
		 */
		break;

	/*
	 * Shadow page table probes (mainly used for HVM domains
	 * without hardware paging support).
	 */
	case TRC_SHADOW_NOT_SHADOW | SH_GUEST_32:
		/*
		 * data[0] = pte(0:31)
		 * data[1] = pte(32:63)
		 * data[2] = va
		 * data[3] = flags
		 */
		pte64 = ((uint64_t)data[1] << 32) | data[0];
		XDT_PROBE3(XDT_SHADOW_NOT_SHADOW, pte64, data[2], data[3]);
		break;
	case TRC_SHADOW_NOT_SHADOW | SH_GUEST_PAE:
	case TRC_SHADOW_NOT_SHADOW | SH_GUEST_64:
		/*
		 * data[0] = pte(0:31)
		 * data[1] = pte(32:63)
		 * data[2] = va(0:31)
		 * data[3] = va(32:63)
		 * data[4] = flags
		 */
		addr64 = ((uint64_t)data[2] << 32) | data[3];
		pte64 = ((uint64_t)data[1] << 32) | data[0];
		XDT_PROBE3(XDT_SHADOW_NOT_SHADOW, pte64, addr64, data[4]);
		break;
	case TRC_SHADOW_FAST_PROPAGATE | SH_GUEST_32:
		/*
		 * data[0] = va
		 */
		XDT_PROBE1(XDT_SHADOW_FAST_PROPAGATE, data[0]);
		break;
	case TRC_SHADOW_FAST_PROPAGATE | SH_GUEST_PAE:
	case TRC_SHADOW_FAST_PROPAGATE | SH_GUEST_64:
		/*
		 * data[0] = va(0:31)
		 * data[1] = va(32:63)
		 */
		addr64 = ((uint64_t)data[1] << 32) | data[0];
		XDT_PROBE1(XDT_SHADOW_FAST_PROPAGATE, addr64);
		break;
	case TRC_SHADOW_FAST_MMIO | SH_GUEST_32:
		/*
		 * data[0] = va
		 */
		XDT_PROBE1(XDT_SHADOW_FAST_MMIO, data[0]);
		break;
	case TRC_SHADOW_FAST_MMIO | SH_GUEST_PAE:
	case TRC_SHADOW_FAST_MMIO | SH_GUEST_64:
		/*
		 * data[0] = va(0:31)
		 * data[1] = va(32:63)
		 */
		addr64 = ((uint64_t)data[1] << 32) | data[0];
		XDT_PROBE1(XDT_SHADOW_FAST_MMIO, addr64);
		break;
	case TRC_SHADOW_FALSE_FAST_PATH | SH_GUEST_32:
		/*
		 * data[0] = va
		 */
		XDT_PROBE1(XDT_SHADOW_FALSE_FAST_PATH, data[0]);
		break;
	case TRC_SHADOW_FALSE_FAST_PATH | SH_GUEST_PAE:
	case TRC_SHADOW_FALSE_FAST_PATH | SH_GUEST_64:
		/*
		 * data[0] = va(0:31)
		 * data[1] = va(32:63)
		 */
		addr64 = ((uint64_t)data[1] << 32) | data[0];
		XDT_PROBE1(XDT_SHADOW_FALSE_FAST_PATH, addr64);
		break;
	case TRC_SHADOW_MMIO | SH_GUEST_32:
		/*
		 * data[0] = va
		 */
		XDT_PROBE1(XDT_SHADOW_MMIO, data[0]);
		break;
	case TRC_SHADOW_MMIO | SH_GUEST_PAE:
	case TRC_SHADOW_MMIO | SH_GUEST_64:
		/*
		 * data[0] = va(0:31)
		 * data[1] = va(32:63)
		 */
		addr64 = ((uint64_t)data[1] << 32) | data[0];
		XDT_PROBE1(XDT_SHADOW_MMIO, addr64);
		break;
	case TRC_SHADOW_FIXUP | SH_GUEST_32:
		/*
		 * data[0] = pte(0:31)
		 * data[1] = pte(32:63)
		 * data[2] = va
		 * data[3] = flags
		 */
		pte64 = ((uint64_t)data[1] << 32) | data[0];
		XDT_PROBE3(XDT_SHADOW_FIXUP, pte64, data[2], data[3]);
		break;
	case TRC_SHADOW_FIXUP | SH_GUEST_64:
	case TRC_SHADOW_FIXUP | SH_GUEST_PAE:
		/*
		 * data[0] = pte(0:31)
		 * data[1] = pte(32:63)
		 * data[2] = va(0:31)
		 * data[3] = va(32:63)
		 * data[4] = flags
		 */
		addr64 = ((uint64_t)data[2] << 32) | data[3];
		pte64 = ((uint64_t)data[1] << 32) | data[0];
		XDT_PROBE3(XDT_SHADOW_FIXUP, pte64, addr64, data[4]);
		break;
	case TRC_SHADOW_DOMF_DYING | SH_GUEST_32:
		/*
		 * data[0] = va
		 */
		XDT_PROBE1(XDT_SHADOW_DOMF_DYING, data[0]);
		break;
	case TRC_SHADOW_DOMF_DYING | SH_GUEST_PAE:
	case TRC_SHADOW_DOMF_DYING | SH_GUEST_64:
		/*
		 * data[0] = va(0:31)
		 * data[1] = va(32:63)
		 */
		addr64 = ((uint64_t)data[1] << 32) | data[0];
		XDT_PROBE1(XDT_SHADOW_DOMF_DYING, addr64);
		break;
	case TRC_SHADOW_EMULATE | SH_GUEST_32:
		/*
		 * data[0] = pte(0:31)
		 * data[1] = pte(32:63)
		 * data[2] = val(0:31)
		 * data[3] = val(32:63)
		 * data[4] = addr
		 * data[5] = flags
		 */
		pte64 = ((uint64_t)data[1] << 32) | data[0];
		val64 = ((uint64_t)data[3] << 32) | data[2];
		XDT_PROBE5(XDT_SHADOW_EMULATE, pte64, val64, data[4],
		    data[5] & 0x7fffffff, data[5] >> 29);
		break;
	case TRC_SHADOW_EMULATE | SH_GUEST_PAE:
	case TRC_SHADOW_EMULATE | SH_GUEST_64:
		/*
		 * data[0] = pte(0:31)
		 * data[1] = pte(32:63)
		 * data[2] = val(0:31)
		 * data[3] = val(32:63)
		 * data[4] = addr(0:31)
		 * data[5] = addr(32:63)
		 * data[6] = flags
		 */
		pte64 = ((uint64_t)data[1] << 32) | data[0];
		val64 = ((uint64_t)data[3] << 32) | data[2];
		addr64 = ((uint64_t)data[5] << 32) | data[4];
		XDT_PROBE5(XDT_SHADOW_EMULATE, pte64, val64, data[4],
		    data[6] & 0x7fffffff, data[6] >> 29);
		break;
	case TRC_SHADOW_EMULATE_UNSHADOW_USER | SH_GUEST_32:
		/*
		 * data[0] = gfn
		 * data[1] = vaddr
		 */
		XDT_PROBE2(XDT_SHADOW_EMULATE_UNSHADOW_USER, data[0], data[1]);
		break;
	case TRC_SHADOW_EMULATE_UNSHADOW_USER | SH_GUEST_PAE:
	case TRC_SHADOW_EMULATE_UNSHADOW_USER | SH_GUEST_64:
		/*
		 * data[0] = gfn(0:31)
		 * data[1] = gfn(32:63)
		 * data[2] = vaddr(0:31)
		 * data[3] = vaddr(32:63)
		 */
		val64 = ((uint64_t)data[1] << 32) | data[0];
		addr64 = ((uint64_t)data[3] << 32) | data[2];
		XDT_PROBE2(XDT_SHADOW_EMULATE_UNSHADOW_USER, val64, addr64);
		break;
	case TRC_SHADOW_EMULATE_UNSHADOW_EVTINJ | SH_GUEST_32:
		/*
		 * data[0] = gfn
		 * data[1] = vaddr
		 */
		XDT_PROBE2(XDT_SHADOW_EMULATE_UNSHADOW_EVTINJ, data[0],
		    data[1]);
		break;
	case TRC_SHADOW_EMULATE_UNSHADOW_EVTINJ | SH_GUEST_PAE:
	case TRC_SHADOW_EMULATE_UNSHADOW_EVTINJ | SH_GUEST_64:
		/*
		 * data[0] = gfn(0:31)
		 * data[1] = gfn(32:63)
		 * data[2] = vaddr(0:31)
		 * data[3] = vaddr(32:63)
		 */
		val64 = ((uint64_t)data[1] << 32) | data[0];
		addr64 = ((uint64_t)data[3] << 32) | data[2];
		XDT_PROBE2(XDT_SHADOW_EMULATE_UNSHADOW_EVTINJ, val64, addr64);
		break;
	case TRC_SHADOW_EMULATE_UNSHADOW_UNHANDLED | SH_GUEST_32:
		/*
		 * data[0] = gfn
		 * data[1] = vaddr
		 */
		XDT_PROBE2(XDT_SHADOW_EMULATE_UNSHADOW_UNHANDLED, data[0],
		    data[1]);
		break;
	case TRC_SHADOW_EMULATE_UNSHADOW_UNHANDLED | SH_GUEST_PAE:
	case TRC_SHADOW_EMULATE_UNSHADOW_UNHANDLED | SH_GUEST_64:
		/*
		 * data[0] = gfn(0:31)
		 * data[1] = gfn(32:63)
		 * data[2] = vaddr(0:31)
		 * data[3] = vaddr(32:63)
		 */
		val64 = ((uint64_t)data[1] << 32) | data[0];
		addr64 = ((uint64_t)data[3] << 32) | data[2];
		XDT_PROBE2(XDT_SHADOW_EMULATE_UNSHADOW_UNHANDLED, val64,
		    addr64);
		break;
	case TRC_SHADOW_WRMAP_BF:
		/*
		 * data[0] = gfn(0:31)
		 * data[1] = gfn(32:63)
		 */
		val64 = ((uint64_t)data[1] << 32) | data[0];
		XDT_PROBE1(XDT_SHADOW_WRMAP_BF, val64);
		break;
	case TRC_SHADOW_PREALLOC_UNPIN:
		/*
		 * data[0] = gfn(0:31)
		 * data[1] = gfn(32:63)
		 */
		val64 = ((uint64_t)data[1] << 32) | data[0];
		XDT_PROBE1(XDT_SHADOW_PREALLOC_UNPIN, val64);
		break;
	case TRC_SHADOW_RESYNC_FULL:
		/*
		 * data[0] = gmfn(0:31)
		 * data[1] = gmfn(32:63)
		 */
		val64 = ((uint64_t)data[1] << 32) | data[0];
		XDT_PROBE1(XDT_SHADOW_RESYNC_FULL, val64);
		break;
	case TRC_SHADOW_RESYNC_ONLY:
		/*
		 * data[0] = gmfn(0:31)
		 * data[1] = gmfn(32:63)
		 */
		val64 = ((uint64_t)data[1] << 32) | data[0];
		XDT_PROBE1(XDT_SHADOW_RESYNC_ONLY, val64);
		break;

	/*
	 * Power management probes.
	 */
	case TRC_PM_FREQ_CHANGE:
		/*
		 * data[0] = old freq
		 * data[1] = new freq
		 */
		XDT_PROBE2(XDT_PM_FREQ_CHANGE, data[0], data[1]);
		break;
	case TRC_PM_IDLE_ENTRY:
		/*
		 * data[0] = C-state
		 * data[1] = time
		 */
		XDT_PROBE2(XDT_PM_IDLE_ENTRY, data[0], data[1]);
		break;
	case TRC_PM_IDLE_EXIT:
		/*
		 * data[0] = C-state
		 * data[1] = time
		 */
		XDT_PROBE2(XDT_PM_IDLE_EXIT, data[0], data[1]);
		break;
	case TRC_LOST_RECORDS:
		vcpu = data[1] >> 16;
		dom = data[1] & 0xffff;
		xdt_update_sched_context(cpuid, dom, vcpu);
		xdt_update_domain_context(dom, vcpu);
		XDT_PROBE1(XDT_TRC_LOST_RECORDS, cpuid);
		tbuf.stat_dropped_recs++;
		break;

	default:
		tbuf.stat_unknown_recs++;
		break;
	}

done:
	rec_size = 4 + (rec->cycles_included ? 8 : 0) + (rec->extra_u32 * 4);
	return (rec_size);
}

/*
 * Scan all CPU buffers for the record with the lowest timestamp so
 * that the probes will fire in order.
 */
static int
xdt_get_first_rec(uint_t *cpuidp, struct t_rec **recp, uint32_t *consp)
{
	uint_t cpuid;
	uint32_t prod, cons, offset;
	struct t_rec *rec;
	uint64_t minstamp = ~0ULL, stamp;
	uintptr_t data;

	for (cpuid = 0; cpuid < tbuf.cnt; cpuid++) {
		cons = tbuf.meta[cpuid]->cons;
		prod = tbuf.meta[cpuid]->prod;
		membar_consumer();
		if (prod == cons)
			continue;

		offset = cons % tbuf_data_size;
		data = (uintptr_t)tbuf.data[cpuid] + offset;
		rec = (struct t_rec *)data;
		ASSERT((caddr_t)rec < tbuf.va + (tbuf.size * (cpuid + 1)));

		/*
		 * All records that we know about have time cycles included.
		 * If this record doesn't have them, assume it's a type
		 * that we don't handle. Use a 0 time value, which will make
		 * it get handled first (it will be thrown away).
		 */
		if (rec->cycles_included)
			stamp = (((uint64_t)rec->u.cycles.cycles_hi) << 32)
			    | rec->u.cycles.cycles_lo;
		else
			stamp = 0;

		if (stamp < minstamp) {
			minstamp = stamp;
			*cpuidp = cpuid;
			*recp = rec;
			*consp = cons;
		}
	}

	if (minstamp != ~0ULL)
		return (1);

	return (0);
}

/*ARGSUSED*/
static void
xdt_tbuf_scan(void *arg)
{
	uint32_t bytes_done, cons;
	struct t_rec *rec;
	xdt_schedinfo_t *sp;
	uint_t nrecs, cpuid;

	for (nrecs = 0;
	    nrecs < xdt_max_recs && xdt_get_first_rec(&cpuid, &rec, &cons) > 0;
	    nrecs++) {
		xdt_curpcpu = cpuid;
		sp = &xdt_cpu_schedinfo[cpuid];
		if (sp->curinfo_valid)
			xdt_update_domain_context(sp->cur_domid,
			    sp->cur_vcpuid);

		bytes_done = xdt_process_rec(cpuid, rec);
		cons += bytes_done;
		/*
		 * cons and prod are incremented modulo (2 * tbuf_data_size).
		 * See <xen/public/trace.h>.
		 */
		if (cons >= 2 * tbuf_data_size)
			cons -= 2 * tbuf_data_size;
		membar_exit();
		tbuf.meta[cpuid]->cons = cons;
	}
}

static void
xdt_cyclic_enable(void)
{
	cyc_handler_t hdlr;
	cyc_time_t when;

	ASSERT(MUTEX_HELD(&cpu_lock));

	hdlr.cyh_func = xdt_tbuf_scan;
	hdlr.cyh_arg = NULL;
	hdlr.cyh_level = CY_LOW_LEVEL;

	when.cyt_interval = xdt_poll_nsec;
	when.cyt_when = dtrace_gethrtime() + when.cyt_interval;

	xdt_cyclic = cyclic_add(&hdlr, &when);
}

static void
xdt_probe_create(xdt_probe_t *p)
{
	ASSERT(p != NULL && p->pr_mod != NULL);

	if (dtrace_probe_lookup(xdt_id, p->pr_mod, NULL, p->pr_name) != 0)
		return;

	xdt_prid[p->evt_id] = dtrace_probe_create(xdt_id, p->pr_mod, NULL,
	    p->pr_name, dtrace_mach_aframes(), p);
}

/*ARGSUSED*/
static void
xdt_provide(void *arg, const dtrace_probedesc_t *desc)
{
	const char *mod, *name;
	int i;

	if (desc == NULL) {
		for (i = 0; xdt_probe[i].pr_mod != NULL; i++) {
			xdt_probe_create(&xdt_probe[i]);
		}
	} else {
		mod = desc->dtpd_mod;
		name = desc->dtpd_name;
		for (i = 0; xdt_probe[i].pr_mod != NULL; i++) {
			int l1 = strlen(xdt_probe[i].pr_name);
			int l2 = strlen(xdt_probe[i].pr_mod);
			if (strncmp(name, xdt_probe[i].pr_name, l1) == 0 &&
			    strncmp(mod, xdt_probe[i].pr_mod, l2) == 0)
				break;
		}

		if (xdt_probe[i].pr_mod == NULL)
			return;
		xdt_probe_create(&xdt_probe[i]);
	}

}

/*ARGSUSED*/
static void
xdt_destroy(void *arg, dtrace_id_t id, void *parg)
{
	xdt_probe_t *p = parg;
	xdt_prid[p->evt_id] = 0;
}

static void
xdt_set_trace_mask(uint32_t mask)
{
	xen_sysctl_tbuf_op_t tbuf_op;

	/* Always need to trace scheduling, for context */
	if (mask != 0)
		mask |= TRC_SCHED;
	tbuf_op.evt_mask = mask;
	tbuf_op.cmd  = XEN_SYSCTL_TBUFOP_set_evt_mask;
	(void) xdt_sysctl_tbuf(&tbuf_op);
}

/*ARGSUSED*/
static int
xdt_enable(void *arg, dtrace_id_t id, void *parg)
{
	xdt_probe_t *p = parg;
	xen_sysctl_tbuf_op_t tbuf_op;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(xdt_prid[p->evt_id] != 0);

	xdt_probemap[p->evt_id] = xdt_prid[p->evt_id];
	xdt_classinfo[p->class].cnt++;

	if (xdt_classinfo[p->class].cnt == 1) {
		/* set the trace mask for this class */
		cur_trace_mask |= xdt_classinfo[p->class].trc_mask;
		xdt_set_trace_mask(cur_trace_mask);
	}

	if (xdt_cyclic == CYCLIC_NONE) {
		tbuf_op.cmd = XEN_SYSCTL_TBUFOP_enable;
		if (xdt_sysctl_tbuf(&tbuf_op) != 0) {
			cmn_err(CE_NOTE, "Couldn't enable hypervisor tracing.");
			return (-1);
		}

		xdt_cyclic_enable();
	}
	return (0);
}

/*ARGSUSED*/
static void
xdt_disable(void *arg, dtrace_id_t id, void *parg)
{
	xdt_probe_t *p = parg;
	xen_sysctl_tbuf_op_t tbuf_op;
	int i, err;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(xdt_probemap[p->evt_id] != 0);
	ASSERT(xdt_probemap[p->evt_id] == xdt_prid[p->evt_id]);
	ASSERT(xdt_classinfo[p->class].cnt > 0);

	/*
	 * We could be here in the slight window between the cyclic firing and
	 * a call to dtrace_probe() occurring. We need to be careful if we tear
	 * down any shared state.
	 */

	xdt_probemap[p->evt_id] = 0;
	xdt_classinfo[p->class].cnt--;

	if (xdt_nr_active_probes() == 0) {
		cur_trace_mask = 0;

		if (xdt_cyclic == CYCLIC_NONE)
			return;

		for (i = 0; i < xdt_ncpus; i++)
			xdt_cpu_schedinfo[i].curinfo_valid = 0;

		/*
		 * We will try to disable the trace buffers. If we fail for some
		 * reason we will try again, up to a count of XDT_TBUF_RETRY.
		 * If we still aren't successful we try to set the trace mask
		 * to 0 in order to prevent trace records from being written.
		 */
		tbuf_op.cmd = XEN_SYSCTL_TBUFOP_disable;
		i = 0;
		do {
			err = xdt_sysctl_tbuf(&tbuf_op);
		} while ((err != 0) && (++i < XDT_TBUF_RETRY));

		if (err != 0) {
			cmn_err(CE_NOTE,
			    "Couldn't disable hypervisor tracing.");
			xdt_set_trace_mask(0);
		} else {
			cyclic_remove(xdt_cyclic);
			xdt_cyclic = CYCLIC_NONE;
			/*
			 * We don't bother making the hypercall to set
			 * the trace mask, since it will be reset when
			 * tracing is re-enabled.
			 */
		}
	} else if (xdt_classinfo[p->class].cnt == 0) {
		cur_trace_mask ^= xdt_classinfo[p->class].trc_mask;
		/* other probes are enabled, so add the sub-class mask back */
		cur_trace_mask |= 0xF000;
		xdt_set_trace_mask(cur_trace_mask);
	}
}

static dtrace_pattr_t xdt_attr = {
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_PLATFORM },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_PLATFORM },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_PLATFORM },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_PLATFORM },
};

static dtrace_pops_t xdt_pops = {
	xdt_provide,		/* dtps_provide() */
	NULL,			/* dtps_provide_module() */
	xdt_enable,		/* dtps_enable() */
	xdt_disable,		/* dtps_disable() */
	NULL,			/* dtps_suspend() */
	NULL,			/* dtps_resume() */
	NULL,			/* dtps_getargdesc() */
	NULL,			/* dtps_getargval() */
	NULL,			/* dtps_usermode() */
	xdt_destroy		/* dtps_destroy() */
};

static int
xdt_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int val;

	if (!DOMAIN_IS_INITDOMAIN(xen_info))
		return (DDI_FAILURE);

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		/*
		 * We might support proper suspend/resume in the future, so,
		 * return DDI_FAILURE for now.
		 */
		return (DDI_FAILURE);

	default:
		return (DDI_FAILURE);
	}

	xdt_ncpus = xpv_nr_phys_cpus();
	ASSERT(xdt_ncpus > 0);

	if (ddi_create_minor_node(devi, "xdt", S_IFCHR, 0, DDI_PSEUDO, 0) ==
	    DDI_FAILURE || xdt_attach_trace_buffers() != 0 ||
	    dtrace_register("xdt", &xdt_attr, DTRACE_PRIV_KERNEL, NULL,
	    &xdt_pops, NULL, &xdt_id) != 0) {
		if (tbuf.va != NULL)
			xdt_detach_trace_buffers();
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}

	val = ddi_getprop(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
	    "xdt_poll_nsec", XDT_POLL_DEFAULT);
	xdt_poll_nsec = MAX(val, XDT_POLL_MIN);

	xdt_cpu_schedinfo = (xdt_schedinfo_t *)kmem_zalloc(xdt_ncpus *
	    sizeof (xdt_schedinfo_t), KM_SLEEP);
	xdt_init_trace_masks();
	xdt_kstat_init();

	xdt_devi = devi;
	ddi_report_dev(devi);
	return (DDI_SUCCESS);
}

static int
xdt_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		/*
		 * We might support proper suspend/resume in the future. So
		 * return DDI_FAILURE for now.
		 */
		return (DDI_FAILURE);

	default:
		return (DDI_FAILURE);
	}

	if (dtrace_unregister(xdt_id) != 0)
		return (DDI_FAILURE);

	xdt_detach_trace_buffers();
	kmem_free(xdt_cpu_schedinfo, xdt_ncpus * sizeof (xdt_schedinfo_t));
	if (xdt_cyclic != CYCLIC_NONE)
		cyclic_remove(xdt_cyclic);
	if (xdt_kstats != NULL)
		kstat_delete(xdt_kstats);
	xdt_devi = (void *)0;
	ddi_remove_minor_node(devi, NULL);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
xdt_info(dev_info_t *devi, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = xdt_devi;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

static struct cb_ops xdt_cb_ops = {
	nulldev,		/* open(9E) */
	nodev,			/* close(9E) */
	nodev,			/* strategy(9E) */
	nodev,			/* print(9E) */
	nodev,			/* dump(9E) */
	nodev,			/* read(9E) */
	nodev,			/* write(9E) */
	nodev,			/* ioctl(9E) */
	nodev,			/* devmap(9E) */
	nodev,			/* mmap(9E) */
	nodev,			/* segmap(9E) */
	nochpoll,		/* chpoll(9E) */
	ddi_prop_op,		/* prop_op(9E) */
	NULL,			/* streamtab(9S) */
	D_MP | D_64BIT | D_NEW	/* cb_flag */
};

static struct dev_ops xdt_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	xdt_info,		/* getinfo(9E) */
	nulldev,		/* identify(9E) */
	nulldev,		/* probe(9E) */
	xdt_attach,		/* attach(9E) */
	xdt_detach,		/* detach(9E) */
	nulldev,		/* devo_reset */
	&xdt_cb_ops,		/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* power(9E) */
	ddi_quiesce_not_needed,	/* devo_quiesce */
};


static struct modldrv modldrv = {
	&mod_driverops,
	"Hypervisor event tracing",
	&xdt_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

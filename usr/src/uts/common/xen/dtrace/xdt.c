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
 * respectively. The trace record format is as follows:
 *
 * +--------------------------------------------------------------------------+
 * | CPUID(uint_t) | TSC(uint64_t) | EVENTID(uint32_t) |     DATA FIELDS      |
 * +--------------------------------------------------------------------------+
 *
 * DATA FIELDS:
 * +--------------------------------------------------------------------------+
 * | D1(uint32_t) | D2(uint32_t) | D3(uint32_t) | D4(uint32_t) | D5(uint32_t) |
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

#define	XDT_PROBE4(event, cpuid, arg0, arg1, arg2, arg3) {		\
	dtrace_id_t id = xdt_probemap[event];				\
	if (id)								\
		dtrace_probe(id, cpuid, arg0, arg1, arg2, arg3);	\
}									\

#define	XDT_PROBE3(event, cpuid, arg0, arg1, arg2) \
	XDT_PROBE4(event, cpuid, arg0, arg1, arg2, 0)

#define	XDT_PROBE2(event, cpuid, arg0, arg1) \
	XDT_PROBE4(event, cpuid, arg0, arg1, 0, 0)

#define	XDT_PROBE1(event, cpuid, arg0) \
	XDT_PROBE4(event, cpuid, arg0, 0, 0, 0)

#define	XDT_PROBE0(event, cpuid) \
	XDT_PROBE4(event, cpuid, 0, 0, 0, 0)

/* Probe classes */
#define	XDT_SCHED			0
#define	XDT_MEM				1
#define	XDT_HVM				2
#define	XDT_NCLASSES			3

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
#define	XDT_NEVENTS			17

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

	/* Memory probes */
	{ "mem", "page-grant-map", XDT_MEM_PAGE_GRANT_MAP, XDT_MEM },
	{ "mem", "page-grant-unmap", XDT_MEM_PAGE_GRANT_UNMAP, XDT_MEM },
	{ "mem", "page-grant-transfer", XDT_MEM_PAGE_GRANT_TRANSFER, XDT_MEM },

	/* HVM probes */
	{ "hvm", "vmentry", XDT_HVM_VMENTRY, XDT_HVM },
	{ "hvm", "vmexit", XDT_HVM_VMEXIT, XDT_HVM },

	{ NULL }
};

extern uint_t xen_get_nphyscpus(void);

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

	/* set trace buffer size */
	tbuf_op.cmd  = XEN_SYSCTL_TBUFOP_set_size;
	tbuf_op.size = xdt_tbuf_pages;
	(void) xdt_sysctl_tbuf(&tbuf_op);

	/* get trace buffer info */
	tbuf_op.cmd  = XEN_SYSCTL_TBUFOP_get_info;
	if ((err = xdt_sysctl_tbuf(&tbuf_op)) != 0)
		return (err);

	tbuf.size = tbuf_op.size;
	tbuf.start_mfn = (mfn_t)tbuf_op.buffer_mfn;
	tbuf.cnt = xdt_ncpus;

	if (tbuf.size == 0) {
		cmn_err(CE_NOTE, "No trace buffers allocated!");
		return (ENOBUFS);
	}

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

static inline void
xdt_process_rec(uint_t cpuid, struct t_rec *rec)
{
	xdt_schedinfo_t *sp = &xdt_cpu_schedinfo[cpuid];
	int eid;

	ASSERT(rec != NULL);
	ASSERT(xdt_ncpus == xen_get_nphyscpus());

	if (cpuid >= xdt_ncpus) {
		tbuf.stat_spurious_cpu++;
		return;
	}

	switch (rec->event) {

	/*
	 * Sched probes
	 */
	case TRC_SCHED_SWITCH_INFPREV:
		/*
		 * Info on vCPU being de-scheduled
		 *
		 * rec->data[0] = prev domid
		 * rec->data[1] = time spent on pcpu
		 */
		sp->prev_domid = rec->data[0];
		sp->prev_ctime = rec->data[1];
		break;

	case TRC_SCHED_SWITCH_INFNEXT:
		/*
		 * Info on next vCPU to be scheduled
		 *
		 * rec->data[0] = next domid
		 * rec->data[1] = time spent waiting to get on cpu
		 * rec->data[2] = time slice
		 */
		sp->next_domid = rec->data[0];
		sp->next_wtime = rec->data[1];
		sp->next_ts = rec->data[2];
		break;

	case TRC_SCHED_SWITCH:
		/*
		 * vCPU switch
		 *
		 * rec->data[0] = prev domid
		 * rec->data[1] = prev vcpuid
		 * rec->data[2] = next domid
		 * rec->data[3] = next vcpuid
		 */
		if (rec->data[0] != sp->prev_domid &&
		    rec->data[2] != sp->next_domid) {
			/* prev and next info don't match doms being sched'd */
			tbuf.stat_spurious_switch++;
			return;
		}

		sp->prev_vcpuid = rec->data[1];
		sp->next_vcpuid = rec->data[3];

		XDT_PROBE3(IS_IDLE_DOM(sp->prev_domid)?
		    XDT_SCHED_IDLE_OFF_CPU:XDT_SCHED_OFF_CPU,
		    cpuid, sp->prev_domid, sp->prev_vcpuid, sp->prev_ctime);

		XDT_PROBE4(IS_IDLE_DOM(sp->next_domid)?
		    XDT_SCHED_IDLE_ON_CPU:XDT_SCHED_ON_CPU,
		    cpuid, sp->next_domid, sp->next_vcpuid, sp->next_wtime,
		    sp->next_ts);
		break;

	case TRC_SCHED_BLOCK:
		/*
		 * vCPU blocked
		 *
		 * rec->data[0] = domid
		 * rec->data[1] = vcpuid
		 */
		XDT_PROBE2(XDT_SCHED_BLOCK, cpuid, rec->data[0], rec->data[1]);
		break;

	case TRC_SCHED_SLEEP:
		/*
		 * Put vCPU to sleep
		 *
		 * rec->data[0] = domid
		 * rec->data[1] = vcpuid
		 */
		XDT_PROBE2(XDT_SCHED_SLEEP, cpuid, rec->data[0], rec->data[1]);
		break;

	case TRC_SCHED_WAKE:
		/*
		 * Wake up vCPU
		 *
		 * rec->data[0] = domid
		 * rec->data[1] = vcpuid
		 */
		XDT_PROBE2(XDT_SCHED_WAKE, cpuid, rec->data[0], rec->data[1]);
		break;

	case TRC_SCHED_YIELD:
		/*
		 * vCPU yielded
		 *
		 * rec->data[0] = domid
		 * rec->data[1] = vcpuid
		 */
		XDT_PROBE2(XDT_SCHED_YIELD, cpuid, rec->data[0], rec->data[1]);
		break;

	case TRC_SCHED_SHUTDOWN:
		/*
		 * Guest shutting down
		 *
		 * rec->data[0] = domid
		 * rec->data[1] = initiating vcpu
		 * rec->data[2] = shutdown code
		 */
		switch (rec->data[2]) {
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
			return;
		}

		XDT_PROBE1(eid, cpuid, rec->data[0]);
		break;

	/*
	 * Mem probes
	 */
	case TRC_MEM_PAGE_GRANT_MAP:
		/*
		 * Guest mapped page grant
		 *
		 * rec->data[0] = domid
		 */
		XDT_PROBE1(XDT_MEM_PAGE_GRANT_MAP, cpuid, rec->data[0]);
		break;

	case TRC_MEM_PAGE_GRANT_UNMAP:
		/*
		 * Guest unmapped page grant
		 *
		 * rec->data[0] = domid
		 */
		XDT_PROBE1(XDT_MEM_PAGE_GRANT_UNMAP, cpuid, rec->data[0]);
		break;

	case TRC_MEM_PAGE_GRANT_TRANSFER:
		/*
		 * Page grant is being transferred
		 *
		 * rec->data[0] = target domid
		 */
		XDT_PROBE1(XDT_MEM_PAGE_GRANT_TRANSFER, cpuid, rec->data[0]);
		break;

	/*
	 * HVM probes
	 */
	case TRC_HVM_VMENTRY:
		/*
		 * Return to guest via vmx_launch/vmrun
		 *
		 * rec->data[0] = (domid<<16 + vcpuid)
		 */
		XDT_PROBE2(XDT_HVM_VMENTRY, cpuid, HVM_DOMID(rec->data[0]),
		    HVM_VCPUID(rec->data[0]));
		break;

	case TRC_HVM_VMEXIT:
		/*
		 * Entry into VMEXIT handler
		 *
		 * rec->data[0] = (domid<<16 + vcpuid)
		 * rec->data[1] = guest rip
		 * rec->data[2] = cpu vendor specific exit code
		 */
		XDT_PROBE4(XDT_HVM_VMEXIT, cpuid, HVM_DOMID(rec->data[0]),
		    HVM_VCPUID(rec->data[0]), rec->data[1], rec->data[2]);
		break;

	case TRC_LOST_RECORDS:
		tbuf.stat_dropped_recs++;
		break;

	default:
		tbuf.stat_unknown_recs++;
		break;
	}
}

/*ARGSUSED*/
static void
xdt_tbuf_scan(void *arg)
{
	uint_t cpuid;
	size_t nrecs;
	struct t_rec *rec;
	uint32_t prod;

	nrecs = (tbuf.size - sizeof (struct t_buf)) / sizeof (struct t_rec);

	/* scan all cpu buffers for new records */
	for (cpuid = 0; cpuid < tbuf.cnt; cpuid++) {
		prod = tbuf.meta[cpuid]->prod;
		membar_consumer(); /* read prod /then/ data */
		while (tbuf.meta[cpuid]->cons != prod) {
			rec = tbuf.data[cpuid] + tbuf.meta[cpuid]->cons % nrecs;
			xdt_process_rec(cpuid, rec);
			membar_exit(); /* read data /then/ update cons */
			tbuf.meta[cpuid]->cons++;
		}
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

	tbuf_op.cmd  = XEN_SYSCTL_TBUFOP_set_evt_mask;
	tbuf_op.evt_mask = mask;
	(void) xdt_sysctl_tbuf(&tbuf_op);
}

/*ARGSUSED*/
static void
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
		/*
		 * DTrace doesn't have the notion of failing an enabling. It
		 * works on the premise that, if you have advertised a probe
		 * via the pops->dtps_provide() function, you can enable it.
		 * Failure is not an option. In the case where we can't enable
		 * Xen tracing the consumer will carry on regardless and
		 * think all is OK except the probes will never fire.
		 */
		tbuf_op.cmd = XEN_SYSCTL_TBUFOP_enable;
		if (xdt_sysctl_tbuf(&tbuf_op) != 0) {
			cmn_err(CE_NOTE, "Couldn't enable hypervisor tracing.");
			return;
		}

		xdt_cyclic_enable();
	}
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

	xdt_ncpus = xen_get_nphyscpus();
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

	xdt_cpu_schedinfo = (xdt_schedinfo_t *)kmem_alloc(xdt_ncpus *
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
	NULL			/* power(9E) */
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

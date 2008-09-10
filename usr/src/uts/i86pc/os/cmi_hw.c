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

/*
 * CPU Module Interface - hardware abstraction.
 */

#include <sys/types.h>
#include <sys/cpu_module.h>
#include <sys/kmem.h>
#include <sys/x86_archext.h>
#include <sys/cpuvar.h>
#include <sys/ksynch.h>
#include <sys/x_call.h>
#include <sys/pghw.h>
#include <sys/pci_cfgspace.h>
#include <sys/archsystm.h>
#include <sys/ontrap.h>
#include <sys/controlregs.h>
#include <sys/sunddi.h>
#include <sys/trap.h>
#include <sys/mca_x86.h>
#include <sys/processor.h>

#ifdef __xpv
#include <sys/hypervisor.h>
#endif

/*
 * Outside of this file consumers use the opaque cmi_hdl_t.  This
 * definition is duplicated in the generic_cpu mdb module, so keep
 * them in-sync when making changes.
 */
typedef struct cmi_hdl_impl {
	enum cmi_hdl_class cmih_class;		/* Handle nature */
	const struct cmi_hdl_ops *cmih_ops;	/* Operations vector */
	uint_t cmih_chipid;			/* Chipid of cpu resource */
	uint_t cmih_coreid;			/* Core within die */
	uint_t cmih_strandid;			/* Thread within core */
	boolean_t cmih_mstrand;			/* cores are multithreaded */
	volatile uint32_t *cmih_refcntp;	/* Reference count pointer */
	uint64_t cmih_msrsrc;			/* MSR data source flags */
	void *cmih_hdlpriv;			/* cmi_hw.c private data */
	void *cmih_spec;			/* cmi_hdl_{set,get}_specific */
	void *cmih_cmi;				/* cpu mod control structure */
	void *cmih_cmidata;			/* cpu mod private data */
	const struct cmi_mc_ops *cmih_mcops;	/* Memory-controller ops */
	void *cmih_mcdata;			/* Memory-controller data */
	uint64_t cmih_flags;			/* See CMIH_F_* below */
} cmi_hdl_impl_t;

#define	IMPLHDL(ophdl)	((cmi_hdl_impl_t *)ophdl)
#define	HDLOPS(hdl)	((hdl)->cmih_ops)

#define	CMIH_F_INJACTV		0x1ULL

/*
 * Ops structure for handle operations.
 */
struct cmi_hdl_ops {
	/*
	 * These ops are required in an implementation.
	 */
	uint_t (*cmio_vendor)(cmi_hdl_impl_t *);
	const char *(*cmio_vendorstr)(cmi_hdl_impl_t *);
	uint_t (*cmio_family)(cmi_hdl_impl_t *);
	uint_t (*cmio_model)(cmi_hdl_impl_t *);
	uint_t (*cmio_stepping)(cmi_hdl_impl_t *);
	uint_t (*cmio_chipid)(cmi_hdl_impl_t *);
	uint_t (*cmio_coreid)(cmi_hdl_impl_t *);
	uint_t (*cmio_strandid)(cmi_hdl_impl_t *);
	uint32_t (*cmio_chiprev)(cmi_hdl_impl_t *);
	const char *(*cmio_chiprevstr)(cmi_hdl_impl_t *);
	uint32_t (*cmio_getsockettype)(cmi_hdl_impl_t *);
	id_t (*cmio_logical_id)(cmi_hdl_impl_t *);
	/*
	 * These ops are optional in an implementation.
	 */
	ulong_t (*cmio_getcr4)(cmi_hdl_impl_t *);
	void (*cmio_setcr4)(cmi_hdl_impl_t *, ulong_t);
	cmi_errno_t (*cmio_rdmsr)(cmi_hdl_impl_t *, uint_t, uint64_t *);
	cmi_errno_t (*cmio_wrmsr)(cmi_hdl_impl_t *, uint_t, uint64_t);
	cmi_errno_t (*cmio_msrinterpose)(cmi_hdl_impl_t *, uint_t, uint64_t);
	void (*cmio_int)(cmi_hdl_impl_t *, int);
	int (*cmio_online)(cmi_hdl_impl_t *, int, int *);
};

static const struct cmi_hdl_ops cmi_hdl_ops;

/*
 * Handles are looked up from contexts such as polling, injection etc
 * where the context is reasonably well defined (although a poller could
 * interrupt any old thread holding any old lock).  They are also looked
 * up by machine check handlers, which may strike at inconvenient times
 * such as during handle initialization or destruction or during handle
 * lookup (which the #MC handler itself will also have to perform).
 *
 * So keeping handles in a linked list makes locking difficult when we
 * consider #MC handlers.  Our solution is to have an array indexed
 * by that which uniquely identifies a handle - chip/core/strand id -
 * with each array member a structure including a pointer to a handle
 * structure for the resource, and a reference count for the handle.
 * Reference counts are modified atomically.  The public cmi_hdl_hold
 * always succeeds because this can only be used after handle creation
 * and before the call to destruct, so the hold count is already at least one.
 * In other functions that lookup a handle (cmi_hdl_lookup, cmi_hdl_any)
 * we must be certain that the count has not already decrmented to zero
 * before applying our hold.
 *
 * This array is allocated when first we want to populate an entry.
 * When allocated it is maximal - ideally we should scale to the
 * actual number of chips, cores per chip and strand per core but
 * that info is not readily available if we are virtualized so
 * for now we stick with the dumb approach.
 */
#define	CMI_MAX_CHIPS_NBITS		4	/* 16 chips packages max */
#define	CMI_MAX_CORES_PER_CHIP_NBITS	3	/* 8 cores per chip max */
#define	CMI_MAX_STRANDS_PER_CORE_NBITS	1	/* 2 strands per core max */

#define	CMI_MAX_CHIPS			(1 << CMI_MAX_CHIPS_NBITS)
#define	CMI_MAX_CORES_PER_CHIP		(1 << CMI_MAX_CORES_PER_CHIP_NBITS)
#define	CMI_MAX_STRANDS_PER_CORE	(1 << CMI_MAX_STRANDS_PER_CORE_NBITS)

/*
 * Handle array indexing.
 *	[7:4] = Chip package.
 *	[3:1] = Core in package,
 *	[0:0] = Strand in core,
 */
#define	CMI_HDL_ARR_IDX_CHIP(chipid) \
	(((chipid) & (CMI_MAX_CHIPS - 1)) << \
	(CMI_MAX_STRANDS_PER_CORE_NBITS + CMI_MAX_CORES_PER_CHIP_NBITS))

#define	CMI_HDL_ARR_IDX_CORE(coreid) \
	(((coreid) & (CMI_MAX_CORES_PER_CHIP - 1)) << \
	CMI_MAX_STRANDS_PER_CORE_NBITS)

#define	CMI_HDL_ARR_IDX_STRAND(strandid) \
	(((strandid) & (CMI_MAX_STRANDS_PER_CORE - 1)))

#define	CMI_HDL_ARR_IDX(chipid, coreid, strandid) \
	(CMI_HDL_ARR_IDX_CHIP(chipid) | CMI_HDL_ARR_IDX_CORE(coreid) | \
	CMI_HDL_ARR_IDX_STRAND(strandid))

#define	CMI_HDL_ARR_SZ (CMI_MAX_CHIPS * CMI_MAX_CORES_PER_CHIP * \
    CMI_MAX_STRANDS_PER_CORE)

struct cmi_hdl_arr_ent {
	volatile uint32_t cmae_refcnt;
	cmi_hdl_impl_t *cmae_hdlp;
};

static struct cmi_hdl_arr_ent *cmi_hdl_arr;

/*
 * Controls where we will source PCI config space data.
 */
#define	CMI_PCICFG_FLAG_RD_HWOK		0x0001
#define	CMI_PCICFG_FLAG_RD_INTERPOSEOK	0X0002
#define	CMI_PCICFG_FLAG_WR_HWOK		0x0004
#define	CMI_PCICFG_FLAG_WR_INTERPOSEOK	0X0008

static uint64_t cmi_pcicfg_flags =
    CMI_PCICFG_FLAG_RD_HWOK | CMI_PCICFG_FLAG_RD_INTERPOSEOK |
    CMI_PCICFG_FLAG_WR_HWOK | CMI_PCICFG_FLAG_WR_INTERPOSEOK;

/*
 * The flags for individual cpus are kept in their per-cpu handle cmih_msrsrc
 */
#define	CMI_MSR_FLAG_RD_HWOK		0x0001
#define	CMI_MSR_FLAG_RD_INTERPOSEOK	0x0002
#define	CMI_MSR_FLAG_WR_HWOK		0x0004
#define	CMI_MSR_FLAG_WR_INTERPOSEOK	0x0008

int cmi_call_func_ntv_tries = 3;

static cmi_errno_t
call_func_ntv(int cpuid, xc_func_t func, xc_arg_t arg1, xc_arg_t arg2)
{
	cmi_errno_t rc = -1;
	int i;

	kpreempt_disable();

	if (CPU->cpu_id == cpuid) {
		(*func)(arg1, arg2, (xc_arg_t)&rc);
	} else {
		/*
		 * This should not happen for a #MC trap or a poll, so
		 * this is likely an error injection or similar.
		 * We will try to cross call with xc_trycall - we
		 * can't guarantee success with xc_call because
		 * the interrupt code in the case of a #MC may
		 * already hold the xc mutex.
		 */
		for (i = 0; i < cmi_call_func_ntv_tries; i++) {
			cpuset_t cpus;

			CPUSET_ONLY(cpus, cpuid);
			xc_trycall(arg1, arg2, (xc_arg_t)&rc, cpus, func);
			if (rc != -1)
				break;

			DELAY(1);
		}
	}

	kpreempt_enable();

	return (rc != -1 ? rc : CMIERR_DEADLOCK);
}

static uint64_t injcnt;

void
cmi_hdl_inj_begin(cmi_hdl_t ophdl)
{
	cmi_hdl_impl_t *hdl = IMPLHDL(ophdl);

	if (hdl != NULL)
		hdl->cmih_flags |= CMIH_F_INJACTV;
	if (injcnt++ == 0) {
		cmn_err(CE_NOTE, "Hardware error injection/simulation "
		    "activity noted");
	}
}

void
cmi_hdl_inj_end(cmi_hdl_t ophdl)
{
	cmi_hdl_impl_t *hdl = IMPLHDL(ophdl);

	ASSERT(hdl == NULL || hdl->cmih_flags & CMIH_F_INJACTV);
	if (hdl != NULL)
		hdl->cmih_flags &= ~CMIH_F_INJACTV;
}

boolean_t
cmi_inj_tainted(void)
{
	return (injcnt != 0 ? B_TRUE : B_FALSE);
}

/*
 *	 =======================================================
 *	|	MSR Interposition				|
 *	|	-----------------				|
 *	|							|
 *	 -------------------------------------------------------
 */

#define	CMI_MSRI_HASHSZ		16
#define	CMI_MSRI_HASHIDX(hdl, msr) \
	(((uintptr_t)(hdl) >> 3 + (msr)) % (CMI_MSRI_HASHSZ - 1))

struct cmi_msri_bkt {
	kmutex_t msrib_lock;
	struct cmi_msri_hashent *msrib_head;
};

struct cmi_msri_hashent {
	struct cmi_msri_hashent *msrie_next;
	struct cmi_msri_hashent *msrie_prev;
	cmi_hdl_impl_t *msrie_hdl;
	uint_t msrie_msrnum;
	uint64_t msrie_msrval;
};

#define	CMI_MSRI_MATCH(ent, hdl, req_msr) \
	((ent)->msrie_hdl == (hdl) && (ent)->msrie_msrnum == (req_msr))

static struct cmi_msri_bkt msrihash[CMI_MSRI_HASHSZ];

static void
msri_addent(cmi_hdl_impl_t *hdl, uint_t msr, uint64_t val)
{
	int idx = CMI_MSRI_HASHIDX(hdl, msr);
	struct cmi_msri_bkt *hbp = &msrihash[idx];
	struct cmi_msri_hashent *hep;

	mutex_enter(&hbp->msrib_lock);

	for (hep = hbp->msrib_head; hep != NULL; hep = hep->msrie_next) {
		if (CMI_MSRI_MATCH(hep, hdl, msr))
			break;
	}

	if (hep != NULL) {
		hep->msrie_msrval = val;
	} else {
		hep = kmem_alloc(sizeof (*hep), KM_SLEEP);
		hep->msrie_hdl = hdl;
		hep->msrie_msrnum = msr;
		hep->msrie_msrval = val;

		if (hbp->msrib_head != NULL)
			hbp->msrib_head->msrie_prev = hep;
		hep->msrie_next = hbp->msrib_head;
		hep->msrie_prev = NULL;
		hbp->msrib_head = hep;
	}

	mutex_exit(&hbp->msrib_lock);
}

/*
 * Look for a match for the given hanlde and msr.  Return 1 with valp
 * filled if a match is found, otherwise return 0 with valp untouched.
 */
static int
msri_lookup(cmi_hdl_impl_t *hdl, uint_t msr, uint64_t *valp)
{
	int idx = CMI_MSRI_HASHIDX(hdl, msr);
	struct cmi_msri_bkt *hbp = &msrihash[idx];
	struct cmi_msri_hashent *hep;

	/*
	 * This function is called during #MC trap handling, so we should
	 * consider the possibility that the hash mutex is held by the
	 * interrupted thread.  This should not happen because interposition
	 * is an artificial injection mechanism and the #MC is requested
	 * after adding entries, but just in case of a real #MC at an
	 * unlucky moment we'll use mutex_tryenter here.
	 */
	if (!mutex_tryenter(&hbp->msrib_lock))
		return (0);

	for (hep = hbp->msrib_head; hep != NULL; hep = hep->msrie_next) {
		if (CMI_MSRI_MATCH(hep, hdl, msr)) {
			*valp = hep->msrie_msrval;
			break;
		}
	}

	mutex_exit(&hbp->msrib_lock);

	return (hep != NULL);
}

/*
 * Remove any interposed value that matches.
 */
static void
msri_rment(cmi_hdl_impl_t *hdl, uint_t msr)
{

	int idx = CMI_MSRI_HASHIDX(hdl, msr);
	struct cmi_msri_bkt *hbp = &msrihash[idx];
	struct cmi_msri_hashent *hep;

	if (!mutex_tryenter(&hbp->msrib_lock))
		return;

	for (hep = hbp->msrib_head; hep != NULL; hep = hep->msrie_next) {
		if (CMI_MSRI_MATCH(hep, hdl, msr)) {
			if (hep->msrie_prev != NULL)
				hep->msrie_prev->msrie_next = hep->msrie_next;

			if (hep->msrie_next != NULL)
				hep->msrie_next->msrie_prev = hep->msrie_prev;

			if (hbp->msrib_head == hep)
				hbp->msrib_head = hep->msrie_next;

			kmem_free(hep, sizeof (*hep));
			break;
		}
	}

	mutex_exit(&hbp->msrib_lock);
}

/*
 *	 =======================================================
 *	|	PCI Config Space Interposition			|
 *	|	------------------------------			|
 *	|							|
 *	 -------------------------------------------------------
 */

/*
 * Hash for interposed PCI config space values.  We lookup on bus/dev/fun/offset
 * and then record whether the value stashed was made with a byte, word or
 * doubleword access;  we will only return a hit for an access of the
 * same size.  If you access say a 32-bit register using byte accesses
 * and then attempt to read the full 32-bit value back you will not obtain
 * any sort of merged result - you get a lookup miss.
 */

#define	CMI_PCII_HASHSZ		16
#define	CMI_PCII_HASHIDX(b, d, f, o) \
	(((b) + (d) + (f) + (o)) % (CMI_PCII_HASHSZ - 1))

struct cmi_pcii_bkt {
	kmutex_t pciib_lock;
	struct cmi_pcii_hashent *pciib_head;
};

struct cmi_pcii_hashent {
	struct cmi_pcii_hashent *pcii_next;
	struct cmi_pcii_hashent *pcii_prev;
	int pcii_bus;
	int pcii_dev;
	int pcii_func;
	int pcii_reg;
	int pcii_asize;
	uint32_t pcii_val;
};

#define	CMI_PCII_MATCH(ent, b, d, f, r, asz) \
	((ent)->pcii_bus == (b) && (ent)->pcii_dev == (d) && \
	(ent)->pcii_func == (f) && (ent)->pcii_reg == (r) && \
	(ent)->pcii_asize == (asz))

static struct cmi_pcii_bkt pciihash[CMI_PCII_HASHSZ];


/*
 * Add a new entry to the PCI interpose hash, overwriting any existing
 * entry that is found.
 */
static void
pcii_addent(int bus, int dev, int func, int reg, uint32_t val, int asz)
{
	int idx = CMI_PCII_HASHIDX(bus, dev, func, reg);
	struct cmi_pcii_bkt *hbp = &pciihash[idx];
	struct cmi_pcii_hashent *hep;

	cmi_hdl_inj_begin(NULL);

	mutex_enter(&hbp->pciib_lock);

	for (hep = hbp->pciib_head; hep != NULL; hep = hep->pcii_next) {
		if (CMI_PCII_MATCH(hep, bus, dev, func, reg, asz))
			break;
	}

	if (hep != NULL) {
		hep->pcii_val = val;
	} else {
		hep = kmem_alloc(sizeof (*hep), KM_SLEEP);
		hep->pcii_bus = bus;
		hep->pcii_dev = dev;
		hep->pcii_func = func;
		hep->pcii_reg = reg;
		hep->pcii_asize = asz;
		hep->pcii_val = val;

		if (hbp->pciib_head != NULL)
			hbp->pciib_head->pcii_prev = hep;
		hep->pcii_next = hbp->pciib_head;
		hep->pcii_prev = NULL;
		hbp->pciib_head = hep;
	}

	mutex_exit(&hbp->pciib_lock);

	cmi_hdl_inj_end(NULL);
}

/*
 * Look for a match for the given bus/dev/func/reg; return 1 with valp
 * filled if a match is found, otherwise return 0 with valp untouched.
 */
static int
pcii_lookup(int bus, int dev, int func, int reg, int asz, uint32_t *valp)
{
	int idx = CMI_PCII_HASHIDX(bus, dev, func, reg);
	struct cmi_pcii_bkt *hbp = &pciihash[idx];
	struct cmi_pcii_hashent *hep;

	if (!mutex_tryenter(&hbp->pciib_lock))
		return (0);

	for (hep = hbp->pciib_head; hep != NULL; hep = hep->pcii_next) {
		if (CMI_PCII_MATCH(hep, bus, dev, func, reg, asz)) {
			*valp = hep->pcii_val;
			break;
		}
	}

	mutex_exit(&hbp->pciib_lock);

	return (hep != NULL);
}

static void
pcii_rment(int bus, int dev, int func, int reg, int asz)
{
	int idx = CMI_PCII_HASHIDX(bus, dev, func, reg);
	struct cmi_pcii_bkt *hbp = &pciihash[idx];
	struct cmi_pcii_hashent *hep;

	mutex_enter(&hbp->pciib_lock);

	for (hep = hbp->pciib_head; hep != NULL; hep = hep->pcii_next) {
		if (CMI_PCII_MATCH(hep, bus, dev, func, reg, asz)) {
			if (hep->pcii_prev != NULL)
				hep->pcii_prev->pcii_next = hep->pcii_next;

			if (hep->pcii_next != NULL)
				hep->pcii_next->pcii_prev = hep->pcii_prev;

			if (hbp->pciib_head == hep)
				hbp->pciib_head = hep->pcii_next;

			kmem_free(hep, sizeof (*hep));
			break;
		}
	}

	mutex_exit(&hbp->pciib_lock);
}

#ifndef __xpv

/*
 *	 =======================================================
 *	|	Native methods					|
 *	|	--------------					|
 *	|							|
 *	| These are used when we are running native on bare-	|
 *	| metal, or simply don't know any better.		|
 *	---------------------------------------------------------
 */

#define	HDLPRIV(hdl)	((cpu_t *)(hdl)->cmih_hdlpriv)

static uint_t
ntv_vendor(cmi_hdl_impl_t *hdl)
{
	return (cpuid_getvendor(HDLPRIV(hdl)));
}

static const char *
ntv_vendorstr(cmi_hdl_impl_t *hdl)
{
	return (cpuid_getvendorstr(HDLPRIV(hdl)));
}

static uint_t
ntv_family(cmi_hdl_impl_t *hdl)
{
	return (cpuid_getfamily(HDLPRIV(hdl)));
}

static uint_t
ntv_model(cmi_hdl_impl_t *hdl)
{
	return (cpuid_getmodel(HDLPRIV(hdl)));
}

static uint_t
ntv_stepping(cmi_hdl_impl_t *hdl)
{
	return (cpuid_getstep(HDLPRIV(hdl)));
}

static uint_t
ntv_chipid(cmi_hdl_impl_t *hdl)
{
	return (hdl->cmih_chipid);

}

static uint_t
ntv_coreid(cmi_hdl_impl_t *hdl)
{
	return (hdl->cmih_coreid);
}

static uint_t
ntv_strandid(cmi_hdl_impl_t *hdl)
{
	return (hdl->cmih_strandid);
}

static uint32_t
ntv_chiprev(cmi_hdl_impl_t *hdl)
{
	return (cpuid_getchiprev(HDLPRIV(hdl)));
}

static const char *
ntv_chiprevstr(cmi_hdl_impl_t *hdl)
{
	return (cpuid_getchiprevstr(HDLPRIV(hdl)));
}

static uint32_t
ntv_getsockettype(cmi_hdl_impl_t *hdl)
{
	return (cpuid_getsockettype(HDLPRIV(hdl)));
}

static id_t
ntv_logical_id(cmi_hdl_impl_t *hdl)
{
	return (HDLPRIV(hdl)->cpu_id);
}

/*ARGSUSED*/
static int
ntv_getcr4_xc(xc_arg_t arg1, xc_arg_t arg2, xc_arg_t arg3)
{
	ulong_t *dest = (ulong_t *)arg1;
	cmi_errno_t *rcp = (cmi_errno_t *)arg3;

	*dest = getcr4();
	*rcp = CMI_SUCCESS;

	return (0);
}

static ulong_t
ntv_getcr4(cmi_hdl_impl_t *hdl)
{
	cpu_t *cp = HDLPRIV(hdl);
	ulong_t val;

	(void) call_func_ntv(cp->cpu_id, ntv_getcr4_xc, (xc_arg_t)&val, NULL);

	return (val);
}

/*ARGSUSED*/
static int
ntv_setcr4_xc(xc_arg_t arg1, xc_arg_t arg2, xc_arg_t arg3)
{
	ulong_t val = (ulong_t)arg1;
	cmi_errno_t *rcp = (cmi_errno_t *)arg3;

	setcr4(val);
	*rcp = CMI_SUCCESS;

	return (0);
}

static void
ntv_setcr4(cmi_hdl_impl_t *hdl, ulong_t val)
{
	cpu_t *cp = HDLPRIV(hdl);

	(void) call_func_ntv(cp->cpu_id, ntv_setcr4_xc, (xc_arg_t)val, NULL);
}

volatile uint32_t cmi_trapped_rdmsr;

/*ARGSUSED*/
static int
ntv_rdmsr_xc(xc_arg_t arg1, xc_arg_t arg2, xc_arg_t arg3)
{
	uint_t msr = (uint_t)arg1;
	uint64_t *valp = (uint64_t *)arg2;
	cmi_errno_t *rcp = (cmi_errno_t *)arg3;

	on_trap_data_t otd;

	if (on_trap(&otd, OT_DATA_ACCESS) == 0) {
		if (checked_rdmsr(msr, valp) == 0)
			*rcp = CMI_SUCCESS;
		else
			*rcp = CMIERR_NOTSUP;
	} else {
		*rcp = CMIERR_MSRGPF;
		atomic_inc_32(&cmi_trapped_rdmsr);
	}
	no_trap();

	return (0);
}

static cmi_errno_t
ntv_rdmsr(cmi_hdl_impl_t *hdl, uint_t msr, uint64_t *valp)
{
	cpu_t *cp = HDLPRIV(hdl);

	if (!(hdl->cmih_msrsrc & CMI_MSR_FLAG_RD_HWOK))
		return (CMIERR_INTERPOSE);

	return (call_func_ntv(cp->cpu_id, ntv_rdmsr_xc,
	    (xc_arg_t)msr, (xc_arg_t)valp));
}

volatile uint32_t cmi_trapped_wrmsr;

/*ARGSUSED*/
static int
ntv_wrmsr_xc(xc_arg_t arg1, xc_arg_t arg2, xc_arg_t arg3)
{
	uint_t msr = (uint_t)arg1;
	uint64_t val = *((uint64_t *)arg2);
	cmi_errno_t *rcp = (cmi_errno_t *)arg3;
	on_trap_data_t otd;

	if (on_trap(&otd, OT_DATA_ACCESS) == 0) {
		if (checked_wrmsr(msr, val) == 0)
			*rcp = CMI_SUCCESS;
		else
			*rcp = CMIERR_NOTSUP;
	} else {
		*rcp = CMIERR_MSRGPF;
		atomic_inc_32(&cmi_trapped_wrmsr);
	}
	no_trap();

	return (0);

}

static cmi_errno_t
ntv_wrmsr(cmi_hdl_impl_t *hdl, uint_t msr, uint64_t val)
{
	cpu_t *cp = HDLPRIV(hdl);

	if (!(hdl->cmih_msrsrc & CMI_MSR_FLAG_WR_HWOK))
		return (CMI_SUCCESS);

	return (call_func_ntv(cp->cpu_id, ntv_wrmsr_xc,
	    (xc_arg_t)msr, (xc_arg_t)&val));
}

static cmi_errno_t
ntv_msrinterpose(cmi_hdl_impl_t *hdl, uint_t msr, uint64_t val)
{
	msri_addent(hdl, msr, val);
	return (CMI_SUCCESS);
}

/*ARGSUSED*/
static int
ntv_int_xc(xc_arg_t arg1, xc_arg_t arg2, xc_arg_t arg3)
{
	cmi_errno_t *rcp = (cmi_errno_t *)arg3;
	int int_no = (int)arg1;

	if (int_no == T_MCE)
		int18();
	else
		int_cmci();
	*rcp = CMI_SUCCESS;

	return (0);
}

static void
ntv_int(cmi_hdl_impl_t *hdl, int int_no)
{
	cpu_t *cp = HDLPRIV(hdl);

	(void) call_func_ntv(cp->cpu_id, ntv_int_xc, (xc_arg_t)int_no, NULL);
}

static int
ntv_online(cmi_hdl_impl_t *hdl, int new_status, int *old_status)
{
	processorid_t cpuid = HDLPRIV(hdl)->cpu_id;

	return (p_online_internal(cpuid, new_status, old_status));
}

#else	/* __xpv */

/*
 *	 =======================================================
 *	|	xVM dom0 methods				|
 *	|	----------------				|
 *	|							|
 *	| These are used when we are running as dom0 in		|
 *	| a Solaris xVM context.				|
 *	---------------------------------------------------------
 */

#define	HDLPRIV(hdl)	((xen_mc_lcpu_cookie_t)(hdl)->cmih_hdlpriv)

extern uint_t _cpuid_vendorstr_to_vendorcode(char *);


static uint_t
xpv_vendor(cmi_hdl_impl_t *hdl)
{
	return (_cpuid_vendorstr_to_vendorcode((char *)xen_physcpu_vendorstr(
	    HDLPRIV(hdl))));
}

static const char *
xpv_vendorstr(cmi_hdl_impl_t *hdl)
{
	return (xen_physcpu_vendorstr(HDLPRIV(hdl)));
}

static uint_t
xpv_family(cmi_hdl_impl_t *hdl)
{
	return (xen_physcpu_family(HDLPRIV(hdl)));
}

static uint_t
xpv_model(cmi_hdl_impl_t *hdl)
{
	return (xen_physcpu_model(HDLPRIV(hdl)));
}

static uint_t
xpv_stepping(cmi_hdl_impl_t *hdl)
{
	return (xen_physcpu_stepping(HDLPRIV(hdl)));
}

static uint_t
xpv_chipid(cmi_hdl_impl_t *hdl)
{
	return (hdl->cmih_chipid);
}

static uint_t
xpv_coreid(cmi_hdl_impl_t *hdl)
{
	return (hdl->cmih_coreid);
}

static uint_t
xpv_strandid(cmi_hdl_impl_t *hdl)
{
	return (hdl->cmih_strandid);
}

extern uint32_t _cpuid_chiprev(uint_t, uint_t, uint_t, uint_t);

static uint32_t
xpv_chiprev(cmi_hdl_impl_t *hdl)
{
	return (_cpuid_chiprev(xpv_vendor(hdl), xpv_family(hdl),
	    xpv_model(hdl), xpv_stepping(hdl)));
}

extern const char *_cpuid_chiprevstr(uint_t, uint_t, uint_t, uint_t);

static const char *
xpv_chiprevstr(cmi_hdl_impl_t *hdl)
{
	return (_cpuid_chiprevstr(xpv_vendor(hdl), xpv_family(hdl),
	    xpv_model(hdl), xpv_stepping(hdl)));
}

extern uint32_t _cpuid_skt(uint_t, uint_t, uint_t, uint_t);

static uint32_t
xpv_getsockettype(cmi_hdl_impl_t *hdl)
{
	return (_cpuid_skt(xpv_vendor(hdl), xpv_family(hdl),
	    xpv_model(hdl), xpv_stepping(hdl)));
}

static id_t
xpv_logical_id(cmi_hdl_impl_t *hdl)
{
	return (xen_physcpu_logical_id(HDLPRIV(hdl)));
}

static cmi_errno_t
xpv_rdmsr(cmi_hdl_impl_t *hdl, uint_t msr, uint64_t *valp)
{
	switch (msr) {
	case IA32_MSR_MCG_CAP:
		*valp = xen_physcpu_mcg_cap(HDLPRIV(hdl));
		break;

	default:
		return (CMIERR_NOTSUP);
	}

	return (CMI_SUCCESS);
}

/*
 * Request the hypervisor to write an MSR for us.  The hypervisor
 * will only accept MCA-related MSRs, as this is for MCA error
 * simulation purposes alone.  We will pre-screen MSRs for injection
 * so we don't bother the HV with bogus requests.  We will permit
 * injection to any MCA bank register, and to MCG_STATUS.
 */

#define	IS_MCA_INJ_MSR(msr) \
	(((msr) >= IA32_MSR_MC(0, CTL) && (msr) <= IA32_MSR_MC(10, MISC)) || \
	(msr) == IA32_MSR_MCG_STATUS)

static cmi_errno_t
xpv_wrmsr_cmn(cmi_hdl_impl_t *hdl, uint_t msr, uint64_t val, boolean_t intpose)
{
	struct xen_mc_msrinject mci;

	if (!(hdl->cmih_flags & CMIH_F_INJACTV))
		return (CMIERR_NOTSUP);		/* for injection use only! */

	if (!IS_MCA_INJ_MSR(msr))
		return (CMIERR_API);

	if (panicstr)
		return (CMIERR_DEADLOCK);

	mci.mcinj_cpunr = xen_physcpu_logical_id(HDLPRIV(hdl));
	mci.mcinj_flags = intpose ? MC_MSRINJ_F_INTERPOSE : 0;
	mci.mcinj_count = 1;	/* learn to batch sometime */
	mci.mcinj_msr[0].reg = msr;
	mci.mcinj_msr[0].value = val;

	return (HYPERVISOR_mca(XEN_MC_CMD_msrinject, (xen_mc_arg_t *)&mci) ==
	    XEN_MC_HCALL_SUCCESS ?  CMI_SUCCESS : CMIERR_NOTSUP);
}

static cmi_errno_t
xpv_wrmsr(cmi_hdl_impl_t *hdl, uint_t msr, uint64_t val)
{
	return (xpv_wrmsr_cmn(hdl, msr, val, B_FALSE));
}


static cmi_errno_t
xpv_msrinterpose(cmi_hdl_impl_t *hdl, uint_t msr, uint64_t val)
{
	return (xpv_wrmsr_cmn(hdl, msr, val, B_TRUE));
}

static void
xpv_int(cmi_hdl_impl_t *hdl, int int_no)
{
	struct xen_mc_mceinject mce;

	if (!(hdl->cmih_flags & CMIH_F_INJACTV))
		return;

	if (int_no != T_MCE) {
		cmn_err(CE_WARN, "xpv_int: int_no %d unimplemented\n",
		    int_no);
	}

	mce.mceinj_cpunr = xen_physcpu_logical_id(HDLPRIV(hdl));

	(void) HYPERVISOR_mca(XEN_MC_CMD_mceinject, (xen_mc_arg_t *)&mce);
}

#define	CSM_XLATE_SUNOS2XEN	1
#define	CSM_XLATE_XEN2SUNOS	2

#define	CSM_MAPENT(suffix)	{ P_##suffix, MC_CPU_P_##suffix }

static int
cpu_status_xlate(int in, int direction, int *outp)
{
	struct cpu_status_map {
		int csm_val[2];
	} map[] = {
		CSM_MAPENT(STATUS),
		CSM_MAPENT(ONLINE),
		CSM_MAPENT(OFFLINE),
		CSM_MAPENT(FAULTED),
		CSM_MAPENT(SPARE),
		CSM_MAPENT(POWEROFF)
	};

	int cmpidx = (direction == CSM_XLATE_XEN2SUNOS);
	int i;

	for (i = 0; i < sizeof (map) / sizeof (struct cpu_status_map); i++) {
		if (map[i].csm_val[cmpidx] == in) {
			*outp = map[i].csm_val[!cmpidx];
			return (1);
		}
	}

	return (0);
}

static int
xpv_online(cmi_hdl_impl_t *hdl, int new_status, int *old_status)
{
	struct xen_mc_offline mco;
	int flag, rc;

	new_status &= ~P_FORCED;

	if (!cpu_status_xlate(new_status, CSM_XLATE_SUNOS2XEN, &flag))
		return (ENOSYS);

	mco.mco_cpu = xen_physcpu_logical_id(HDLPRIV(hdl));
	mco.mco_flag = flag;

	if ((rc = HYPERVISOR_mca(XEN_MC_CMD_offlinecpu,
	    (xen_mc_arg_t *)&mco)) == XEN_MC_HCALL_SUCCESS) {
		flag = mco.mco_flag;
		if (!cpu_status_xlate(flag, CSM_XLATE_XEN2SUNOS, old_status))
			cmn_err(CE_NOTE, "xpv_online: unknown status %d.",
			    flag);
	}

	return (-rc);
}

#endif

/*ARGSUSED*/
static void *
cpu_search(enum cmi_hdl_class class, uint_t chipid, uint_t coreid,
    uint_t strandid)
{
#ifdef __xpv
	xen_mc_lcpu_cookie_t cpi;

	for (cpi = xen_physcpu_next(NULL); cpi != NULL;
	    cpi = xen_physcpu_next(cpi)) {
		if (xen_physcpu_chipid(cpi) == chipid &&
		    xen_physcpu_coreid(cpi) == coreid &&
		    xen_physcpu_strandid(cpi) == strandid)
			return ((void *)cpi);
	}
	return (NULL);

#else	/* __xpv */

	cpu_t *cp, *startcp;

	kpreempt_disable();
	cp = startcp = CPU;
	do {
		if (cmi_ntv_hwchipid(cp) == chipid &&
		    cmi_ntv_hwcoreid(cp) == coreid &&
		    cmi_ntv_hwstrandid(cp) == strandid) {
			kpreempt_enable();
			return ((void *)cp);
		}

		cp = cp->cpu_next;
	} while (cp != startcp);
	kpreempt_enable();
	return (NULL);
#endif	/* __ xpv */
}

static boolean_t
cpu_is_cmt(void *priv)
{
#ifdef __xpv
	return (xen_physcpu_is_cmt((xen_mc_lcpu_cookie_t)priv));
#else /* __xpv */
	cpu_t *cp = (cpu_t *)priv;

	int strands_per_core = cpuid_get_ncpu_per_chip(cp) /
	    cpuid_get_ncore_per_chip(cp);

	return (strands_per_core > 1);
#endif /* __xpv */
}

cmi_hdl_t
cmi_hdl_create(enum cmi_hdl_class class, uint_t chipid, uint_t coreid,
    uint_t strandid)
{
	cmi_hdl_impl_t *hdl;
	void *priv;
	int idx;

#ifdef __xpv
	ASSERT(class == CMI_HDL_SOLARIS_xVM_MCA);
#else
	ASSERT(class == CMI_HDL_NATIVE);
#endif

	if (chipid > CMI_MAX_CHIPS - 1 || coreid > CMI_MAX_CORES_PER_CHIP - 1 ||
	    strandid > CMI_MAX_STRANDS_PER_CORE - 1)
		return (NULL);

	if ((priv = cpu_search(class, chipid, coreid, strandid)) == NULL)
		return (NULL);

	hdl = kmem_zalloc(sizeof (*hdl), KM_SLEEP);

	hdl->cmih_class = class;
	HDLOPS(hdl) = &cmi_hdl_ops;
	hdl->cmih_chipid = chipid;
	hdl->cmih_coreid = coreid;
	hdl->cmih_strandid = strandid;
	hdl->cmih_mstrand = cpu_is_cmt(priv);
	hdl->cmih_hdlpriv = priv;
#ifdef __xpv
	hdl->cmih_msrsrc = CMI_MSR_FLAG_RD_INTERPOSEOK |
	    CMI_MSR_FLAG_WR_INTERPOSEOK;
#else	/* __xpv */
	hdl->cmih_msrsrc = CMI_MSR_FLAG_RD_HWOK | CMI_MSR_FLAG_RD_INTERPOSEOK |
	    CMI_MSR_FLAG_WR_HWOK | CMI_MSR_FLAG_WR_INTERPOSEOK;
#endif

	if (cmi_hdl_arr == NULL) {
		size_t sz = CMI_HDL_ARR_SZ * sizeof (struct cmi_hdl_arr_ent);
		void *arr = kmem_zalloc(sz, KM_SLEEP);

		if (atomic_cas_ptr(&cmi_hdl_arr, NULL, arr) != NULL)
			kmem_free(arr, sz); /* someone beat us */
	}

	idx = CMI_HDL_ARR_IDX(chipid, coreid, strandid);
	if (cmi_hdl_arr[idx].cmae_refcnt != 0 ||
	    cmi_hdl_arr[idx].cmae_hdlp != NULL) {
		/*
		 * Somehow this (chipid, coreid, strandid) id tuple has
		 * already been assigned!  This indicates that the
		 * callers logic in determining these values is busted,
		 * or perhaps undermined by bad BIOS setup.  Complain,
		 * and refuse to initialize this tuple again as bad things
		 * will happen.
		 */
		cmn_err(CE_NOTE, "cmi_hdl_create: chipid %d coreid %d "
		    "strandid %d handle already allocated!",
		    chipid, coreid, strandid);
		kmem_free(hdl, sizeof (*hdl));
		return (NULL);
	}

	/*
	 * Once we store a nonzero reference count others can find this
	 * handle via cmi_hdl_lookup etc.  This initial hold on the handle
	 * is to be dropped only if some other part of cmi initialization
	 * fails or, if it succeeds, at later cpu deconfigure.  Note the
	 * the module private data we hold in cmih_cmi and cmih_cmidata
	 * is still NULL at this point (the caller will fill it with
	 * cmi_hdl_setcmi if it initializes) so consumers of handles
	 * should always be ready for that possibility.
	 */
	cmi_hdl_arr[idx].cmae_hdlp = hdl;
	hdl->cmih_refcntp = &cmi_hdl_arr[idx].cmae_refcnt;
	cmi_hdl_arr[idx].cmae_refcnt = 1;

	return ((cmi_hdl_t)hdl);
}

void
cmi_hdl_hold(cmi_hdl_t ophdl)
{
	cmi_hdl_impl_t *hdl = IMPLHDL(ophdl);

	ASSERT(*hdl->cmih_refcntp != 0); /* must not be the initial hold */

	atomic_inc_32(hdl->cmih_refcntp);
}

static int
cmi_hdl_canref(int arridx)
{
	volatile uint32_t *refcntp;
	uint32_t refcnt;

	if (cmi_hdl_arr == NULL)
		return (0);

	refcntp = &cmi_hdl_arr[arridx].cmae_refcnt;
	refcnt = *refcntp;

	if (refcnt == 0) {
		/*
		 * Associated object never existed, is being destroyed,
		 * or has been destroyed.
		 */
		return (0);
	}

	/*
	 * We cannot use atomic increment here because once the reference
	 * count reaches zero it must never be bumped up again.
	 */
	while (refcnt != 0) {
		if (atomic_cas_32(refcntp, refcnt, refcnt + 1) == refcnt)
			return (1);
		refcnt = *refcntp;
	}

	/*
	 * Somebody dropped the reference count to 0 after our initial
	 * check.
	 */
	return (0);
}


void
cmi_hdl_rele(cmi_hdl_t ophdl)
{
	cmi_hdl_impl_t *hdl = IMPLHDL(ophdl);
	int idx;

	ASSERT(*hdl->cmih_refcntp > 0);

	if (atomic_dec_32_nv(hdl->cmih_refcntp) > 0)
		return;

	idx = CMI_HDL_ARR_IDX(hdl->cmih_chipid, hdl->cmih_coreid,
	    hdl->cmih_strandid);
	cmi_hdl_arr[idx].cmae_hdlp = NULL;

	kmem_free(hdl, sizeof (*hdl));
}

void
cmi_hdl_setspecific(cmi_hdl_t ophdl, void *arg)
{
	IMPLHDL(ophdl)->cmih_spec = arg;
}

void *
cmi_hdl_getspecific(cmi_hdl_t ophdl)
{
	return (IMPLHDL(ophdl)->cmih_spec);
}

void
cmi_hdl_setmc(cmi_hdl_t ophdl, const struct cmi_mc_ops *mcops, void *mcdata)
{
	cmi_hdl_impl_t *hdl = IMPLHDL(ophdl);

	ASSERT(hdl->cmih_mcops == NULL && hdl->cmih_mcdata == NULL);
	hdl->cmih_mcops = mcops;
	hdl->cmih_mcdata = mcdata;
}

const struct cmi_mc_ops *
cmi_hdl_getmcops(cmi_hdl_t ophdl)
{
	return (IMPLHDL(ophdl)->cmih_mcops);
}

void *
cmi_hdl_getmcdata(cmi_hdl_t ophdl)
{
	return (IMPLHDL(ophdl)->cmih_mcdata);
}

cmi_hdl_t
cmi_hdl_lookup(enum cmi_hdl_class class, uint_t chipid, uint_t coreid,
    uint_t strandid)
{
	int idx;

	if (chipid > CMI_MAX_CHIPS - 1 || coreid > CMI_MAX_CORES_PER_CHIP - 1 ||
	    strandid > CMI_MAX_STRANDS_PER_CORE - 1)
		return (NULL);

	idx = CMI_HDL_ARR_IDX(chipid, coreid, strandid);

	if (class == CMI_HDL_NEUTRAL)
#ifdef __xpv
		class = CMI_HDL_SOLARIS_xVM_MCA;
#else
		class = CMI_HDL_NATIVE;
#endif

	if (!cmi_hdl_canref(idx))
		return (NULL);

	if (cmi_hdl_arr[idx].cmae_hdlp->cmih_class != class) {
		cmi_hdl_rele((cmi_hdl_t)cmi_hdl_arr[idx].cmae_hdlp);
		return (NULL);
	}

	return ((cmi_hdl_t)cmi_hdl_arr[idx].cmae_hdlp);
}

cmi_hdl_t
cmi_hdl_any(void)
{
	int i;

	for (i = 0; i < CMI_HDL_ARR_SZ; i++) {
		if (cmi_hdl_canref(i))
			return ((cmi_hdl_t)cmi_hdl_arr[i].cmae_hdlp);
	}

	return (NULL);
}

void
cmi_hdl_walk(int (*cbfunc)(cmi_hdl_t, void *, void *, void *),
    void *arg1, void *arg2, void *arg3)
{
	int i;

	for (i = 0; i < CMI_HDL_ARR_SZ; i++) {
		if (cmi_hdl_canref(i)) {
			cmi_hdl_impl_t *hdl = cmi_hdl_arr[i].cmae_hdlp;

			if ((*cbfunc)((cmi_hdl_t)hdl, arg1, arg2, arg3) ==
			    CMI_HDL_WALK_DONE) {
				cmi_hdl_rele((cmi_hdl_t)hdl);
				break;
			}
			cmi_hdl_rele((cmi_hdl_t)hdl);
		}
	}
}

void
cmi_hdl_setcmi(cmi_hdl_t ophdl, void *cmi, void *cmidata)
{
	IMPLHDL(ophdl)->cmih_cmidata = cmidata;
	IMPLHDL(ophdl)->cmih_cmi = cmi;
}

void *
cmi_hdl_getcmi(cmi_hdl_t ophdl)
{
	return (IMPLHDL(ophdl)->cmih_cmi);
}

void *
cmi_hdl_getcmidata(cmi_hdl_t ophdl)
{
	return (IMPLHDL(ophdl)->cmih_cmidata);
}

enum cmi_hdl_class
cmi_hdl_class(cmi_hdl_t ophdl)
{
	return (IMPLHDL(ophdl)->cmih_class);
}

#define	CMI_HDL_OPFUNC(what, type)				\
	type							\
	cmi_hdl_##what(cmi_hdl_t ophdl)				\
	{							\
		return (HDLOPS(IMPLHDL(ophdl))->		\
		    cmio_##what(IMPLHDL(ophdl)));		\
	}

CMI_HDL_OPFUNC(vendor, uint_t)
CMI_HDL_OPFUNC(vendorstr, const char *)
CMI_HDL_OPFUNC(family, uint_t)
CMI_HDL_OPFUNC(model, uint_t)
CMI_HDL_OPFUNC(stepping, uint_t)
CMI_HDL_OPFUNC(chipid, uint_t)
CMI_HDL_OPFUNC(coreid, uint_t)
CMI_HDL_OPFUNC(strandid, uint_t)
CMI_HDL_OPFUNC(chiprev, uint32_t)
CMI_HDL_OPFUNC(chiprevstr, const char *)
CMI_HDL_OPFUNC(getsockettype, uint32_t)
CMI_HDL_OPFUNC(logical_id, id_t)

boolean_t
cmi_hdl_is_cmt(cmi_hdl_t ophdl)
{
	return (IMPLHDL(ophdl)->cmih_mstrand);
}

void
cmi_hdl_int(cmi_hdl_t ophdl, int num)
{
	if (HDLOPS(IMPLHDL(ophdl))->cmio_int == NULL)
		return;

	cmi_hdl_inj_begin(ophdl);
	HDLOPS(IMPLHDL(ophdl))->cmio_int(IMPLHDL(ophdl), num);
	cmi_hdl_inj_end(NULL);
}

int
cmi_hdl_online(cmi_hdl_t ophdl, int new_status, int *old_status)
{
	return (HDLOPS(IMPLHDL(ophdl))->cmio_online(IMPLHDL(ophdl),
	    new_status, old_status));
}

#ifndef	__xpv
/*
 * Return hardware chip instance; cpuid_get_chipid provides this directly.
 */
uint_t
cmi_ntv_hwchipid(cpu_t *cp)
{
	return (cpuid_get_chipid(cp));
}

/*
 * Return core instance within a single chip.
 */
uint_t
cmi_ntv_hwcoreid(cpu_t *cp)
{
	return (cpuid_get_pkgcoreid(cp));
}

/*
 * Return strand number within a single core.  cpuid_get_clogid numbers
 * all execution units (strands, or cores in unstranded models) sequentially
 * within a single chip.
 */
uint_t
cmi_ntv_hwstrandid(cpu_t *cp)
{
	int strands_per_core = cpuid_get_ncpu_per_chip(cp) /
	    cpuid_get_ncore_per_chip(cp);

	return (cpuid_get_clogid(cp) % strands_per_core);
}
#endif	/* __xpv */

void
cmi_hdlconf_rdmsr_nohw(cmi_hdl_t ophdl)
{
	cmi_hdl_impl_t *hdl = IMPLHDL(ophdl);

	hdl->cmih_msrsrc &= ~CMI_MSR_FLAG_RD_HWOK;
}

void
cmi_hdlconf_wrmsr_nohw(cmi_hdl_t ophdl)
{
	cmi_hdl_impl_t *hdl = IMPLHDL(ophdl);

	hdl->cmih_msrsrc &= ~CMI_MSR_FLAG_WR_HWOK;
}

cmi_errno_t
cmi_hdl_rdmsr(cmi_hdl_t ophdl, uint_t msr, uint64_t *valp)
{
	cmi_hdl_impl_t *hdl = IMPLHDL(ophdl);

	/*
	 * Regardless of the handle class, we first check for am
	 * interposed value.  In the xVM case you probably want to
	 * place interposed values within the hypervisor itself, but
	 * we still allow interposing them in dom0 for test and bringup
	 * purposes.
	 */
	if ((hdl->cmih_msrsrc & CMI_MSR_FLAG_RD_INTERPOSEOK) &&
	    msri_lookup(hdl, msr, valp))
		return (CMI_SUCCESS);

	if (HDLOPS(hdl)->cmio_rdmsr == NULL)
		return (CMIERR_NOTSUP);

	return (HDLOPS(hdl)->cmio_rdmsr(hdl, msr, valp));
}

cmi_errno_t
cmi_hdl_wrmsr(cmi_hdl_t ophdl, uint_t msr, uint64_t val)
{
	cmi_hdl_impl_t *hdl = IMPLHDL(ophdl);

	/* Invalidate any interposed value */
	msri_rment(hdl, msr);

	if (HDLOPS(hdl)->cmio_wrmsr == NULL)
		return (CMI_SUCCESS);	/* pretend all is ok */

	return (HDLOPS(hdl)->cmio_wrmsr(hdl, msr, val));
}

void
cmi_hdl_enable_mce(cmi_hdl_t ophdl)
{
	cmi_hdl_impl_t *hdl = IMPLHDL(ophdl);
	ulong_t cr4;

	if (HDLOPS(hdl)->cmio_getcr4 == NULL ||
	    HDLOPS(hdl)->cmio_setcr4 == NULL)
		return;

	cr4 = HDLOPS(hdl)->cmio_getcr4(hdl);

	HDLOPS(hdl)->cmio_setcr4(hdl, cr4 | CR4_MCE);
}

void
cmi_hdl_msrinterpose(cmi_hdl_t ophdl, cmi_mca_regs_t *regs, uint_t nregs)
{
	cmi_hdl_impl_t *hdl = IMPLHDL(ophdl);
	int i;

	if (HDLOPS(hdl)->cmio_msrinterpose == NULL)
		return;

	cmi_hdl_inj_begin(ophdl);

	for (i = 0; i < nregs; i++, regs++)
		HDLOPS(hdl)->cmio_msrinterpose(hdl, regs->cmr_msrnum,
		    regs->cmr_msrval);

	cmi_hdl_inj_end(ophdl);
}

/*ARGSUSED*/
void
cmi_hdl_msrforward(cmi_hdl_t ophdl, cmi_mca_regs_t *regs, uint_t nregs)
{
#ifdef __xpv
	cmi_hdl_impl_t *hdl = IMPLHDL(ophdl);
	int i;

	for (i = 0; i < nregs; i++, regs++)
		msri_addent(hdl, regs->cmr_msrnum, regs->cmr_msrval);
#endif
}


void
cmi_pcird_nohw(void)
{
	cmi_pcicfg_flags &= ~CMI_PCICFG_FLAG_RD_HWOK;
}

void
cmi_pciwr_nohw(void)
{
	cmi_pcicfg_flags &= ~CMI_PCICFG_FLAG_WR_HWOK;
}

static uint32_t
cmi_pci_get_cmn(int bus, int dev, int func, int reg, int asz,
    int *interpose, ddi_acc_handle_t hdl)
{
	uint32_t val;

	if (cmi_pcicfg_flags & CMI_PCICFG_FLAG_RD_INTERPOSEOK &&
	    pcii_lookup(bus, dev, func, reg, asz, &val)) {
		if (interpose)
			*interpose = 1;
		return (val);
	}
	if (interpose)
		*interpose = 0;

	if (!(cmi_pcicfg_flags & CMI_PCICFG_FLAG_RD_HWOK))
		return (0);

	switch (asz) {
	case 1:
		if (hdl)
			val = pci_config_get8(hdl, (off_t)reg);
		else
			val = (*pci_getb_func)(bus, dev, func, reg);
		break;
	case 2:
		if (hdl)
			val = pci_config_get16(hdl, (off_t)reg);
		else
			val = (*pci_getw_func)(bus, dev, func, reg);
		break;
	case 4:
		if (hdl)
			val = pci_config_get32(hdl, (off_t)reg);
		else
			val = (*pci_getl_func)(bus, dev, func, reg);
		break;
	default:
		val = 0;
	}
	return (val);
}

uint8_t
cmi_pci_getb(int bus, int dev, int func, int reg, int *interpose,
    ddi_acc_handle_t hdl)
{
	return ((uint8_t)cmi_pci_get_cmn(bus, dev, func, reg, 1, interpose,
	    hdl));
}

uint16_t
cmi_pci_getw(int bus, int dev, int func, int reg, int *interpose,
    ddi_acc_handle_t hdl)
{
	return ((uint16_t)cmi_pci_get_cmn(bus, dev, func, reg, 2, interpose,
	    hdl));
}

uint32_t
cmi_pci_getl(int bus, int dev, int func, int reg, int *interpose,
    ddi_acc_handle_t hdl)
{
	return (cmi_pci_get_cmn(bus, dev, func, reg, 4, interpose, hdl));
}

void
cmi_pci_interposeb(int bus, int dev, int func, int reg, uint8_t val)
{
	pcii_addent(bus, dev, func, reg, val, 1);
}

void
cmi_pci_interposew(int bus, int dev, int func, int reg, uint16_t val)
{
	pcii_addent(bus, dev, func, reg, val, 2);
}

void
cmi_pci_interposel(int bus, int dev, int func, int reg, uint32_t val)
{
	pcii_addent(bus, dev, func, reg, val, 4);
}

static void
cmi_pci_put_cmn(int bus, int dev, int func, int reg, int asz,
    ddi_acc_handle_t hdl, uint32_t val)
{
	/*
	 * If there is an interposed value for this register invalidate it.
	 */
	pcii_rment(bus, dev, func, reg, asz);

	if (!(cmi_pcicfg_flags & CMI_PCICFG_FLAG_WR_HWOK))
		return;

	switch (asz) {
	case 1:
		if (hdl)
			pci_config_put8(hdl, (off_t)reg, (uint8_t)val);
		else
			(*pci_putb_func)(bus, dev, func, reg, (uint8_t)val);
		break;

	case 2:
		if (hdl)
			pci_config_put16(hdl, (off_t)reg, (uint16_t)val);
		else
			(*pci_putw_func)(bus, dev, func, reg, (uint16_t)val);
		break;

	case 4:
		if (hdl)
			pci_config_put32(hdl, (off_t)reg, val);
		else
			(*pci_putl_func)(bus, dev, func, reg, val);
		break;

	default:
		break;
	}
}

void
cmi_pci_putb(int bus, int dev, int func, int reg, ddi_acc_handle_t hdl,
    uint8_t val)
{
	cmi_pci_put_cmn(bus, dev, func, reg, 1, hdl, val);
}

void
cmi_pci_putw(int bus, int dev, int func, int reg, ddi_acc_handle_t hdl,
    uint16_t val)
{
	cmi_pci_put_cmn(bus, dev, func, reg, 2, hdl, val);
}

void
cmi_pci_putl(int bus, int dev, int func, int reg, ddi_acc_handle_t hdl,
    uint32_t val)
{
	cmi_pci_put_cmn(bus, dev, func, reg, 4, hdl, val);
}

static const struct cmi_hdl_ops cmi_hdl_ops = {
#ifdef __xpv
	/*
	 * CMI_HDL_SOLARIS_xVM_MCA - ops when we are an xVM dom0
	 */
	xpv_vendor,		/* cmio_vendor */
	xpv_vendorstr,		/* cmio_vendorstr */
	xpv_family,		/* cmio_family */
	xpv_model,		/* cmio_model */
	xpv_stepping,		/* cmio_stepping */
	xpv_chipid,		/* cmio_chipid */
	xpv_coreid,		/* cmio_coreid */
	xpv_strandid,		/* cmio_strandid */
	xpv_chiprev,		/* cmio_chiprev */
	xpv_chiprevstr,		/* cmio_chiprevstr */
	xpv_getsockettype,	/* cmio_getsockettype */
	xpv_logical_id,		/* cmio_logical_id */
	NULL,			/* cmio_getcr4 */
	NULL,			/* cmio_setcr4 */
	xpv_rdmsr,		/* cmio_rdmsr */
	xpv_wrmsr,		/* cmio_wrmsr */
	xpv_msrinterpose,	/* cmio_msrinterpose */
	xpv_int,		/* cmio_int */
	xpv_online		/* cmio_online */

#else	/* __xpv */

	/*
	 * CMI_HDL_NATIVE - ops when apparently running on bare-metal
	 */
	ntv_vendor,		/* cmio_vendor */
	ntv_vendorstr,		/* cmio_vendorstr */
	ntv_family,		/* cmio_family */
	ntv_model,		/* cmio_model */
	ntv_stepping,		/* cmio_stepping */
	ntv_chipid,		/* cmio_chipid */
	ntv_coreid,		/* cmio_coreid */
	ntv_strandid,		/* cmio_strandid */
	ntv_chiprev,		/* cmio_chiprev */
	ntv_chiprevstr,		/* cmio_chiprevstr */
	ntv_getsockettype,	/* cmio_getsockettype */
	ntv_logical_id,		/* cmio_logical_id */
	ntv_getcr4,		/* cmio_getcr4 */
	ntv_setcr4,		/* cmio_setcr4 */
	ntv_rdmsr,		/* cmio_rdmsr */
	ntv_wrmsr,		/* cmio_wrmsr */
	ntv_msrinterpose,	/* cmio_msrinterpose */
	ntv_int,		/* cmio_int */
	ntv_online		/* cmio_online */
#endif
};

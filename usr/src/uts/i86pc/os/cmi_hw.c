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

/*
 * Outside of this file consumers use the opaque cmi_hdl_t.  This
 * definition is duplicated in the generic_cpu mdb module, so keep
 * them in-sync when making changes.
 */
typedef struct cmi_hdl_impl {
	enum cmi_hdl_class cmih_class;		/* Handle nature */
	struct cmi_hdl_ops *cmih_ops;		/* Operations vector */
	uint_t cmih_chipid;			/* Chipid of cpu resource */
	uint_t cmih_coreid;			/* Core within die */
	uint_t cmih_strandid;			/* Thread within core */
	volatile uint32_t *cmih_refcntp;	/* Reference count pointer */
	uint64_t cmih_msrsrc;			/* MSR data source flags */
	void *cmih_hdlpriv;			/* cmi_hw.c private data */
	void *cmih_spec;			/* cmi_hdl_{set,get}_specific */
	void *cmih_cmi;				/* cpu mod control structure */
	void *cmih_cmidata;			/* cpu mod private data */
	const struct cmi_mc_ops *cmih_mcops;	/* Memory-controller ops */
	void *cmih_mcdata;			/* Memory-controller data */
} cmi_hdl_impl_t;

#define	IMPLHDL(ophdl)	((cmi_hdl_impl_t *)ophdl)

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
 * and before the call to destruct, so the hold count it already at least one.
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
#define	CMI_MAX_CHIPS			16
#define	CMI_MAX_CORES_PER_CHIP		8
#define	CMI_MAX_STRANDS_PER_CORE	2
#define	CMI_HDL_HASHSZ (CMI_MAX_CHIPS * CMI_MAX_CORES_PER_CHIP * \
    CMI_MAX_STRANDS_PER_CORE)

struct cmi_hdl_hashent {
	volatile uint32_t cmhe_refcnt;
	cmi_hdl_impl_t *cmhe_hdlp;
};

static struct cmi_hdl_hashent *cmi_hdl_hash;

#define	CMI_HDL_HASHIDX(chipid, coreid, strandid) \
	((chipid) * CMI_MAX_CHIPS + (coreid) * CMI_MAX_CORES_PER_CHIP + \
	(strandid))

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
msri_addent(cmi_hdl_impl_t *hdl, cmi_mca_regs_t *regp)
{
	int idx = CMI_MSRI_HASHIDX(hdl, regp->cmr_msrnum);
	struct cmi_msri_bkt *hbp = &msrihash[idx];
	struct cmi_msri_hashent *hep;

	mutex_enter(&hbp->msrib_lock);

	for (hep = hbp->msrib_head; hep != NULL; hep = hep->msrie_next) {
		if (CMI_MSRI_MATCH(hep, hdl, regp->cmr_msrnum))
			break;
	}

	if (hep != NULL) {
		hep->msrie_msrval = regp->cmr_msrval;
	} else {
		hep = kmem_alloc(sizeof (*hep), KM_SLEEP);
		hep->msrie_hdl = hdl;
		hep->msrie_msrnum = regp->cmr_msrnum;
		hep->msrie_msrval = regp->cmr_msrval;

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

/*
 *	 =======================================================
 *	|	Native methods					|
 *	|	--------------					|
 *	|							|
 *	| These are used when we are running native on bare-	|
 *	| metal, or simply don't know any better.		|
 *	---------------------------------------------------------
 */

static uint_t
ntv_vendor(cmi_hdl_impl_t *hdl)
{
	return (cpuid_getvendor((cpu_t *)hdl->cmih_hdlpriv));
}

static const char *
ntv_vendorstr(cmi_hdl_impl_t *hdl)
{
	return (cpuid_getvendorstr((cpu_t *)hdl->cmih_hdlpriv));
}

static uint_t
ntv_family(cmi_hdl_impl_t *hdl)
{
	return (cpuid_getfamily((cpu_t *)hdl->cmih_hdlpriv));
}

static uint_t
ntv_model(cmi_hdl_impl_t *hdl)
{
	return (cpuid_getmodel((cpu_t *)hdl->cmih_hdlpriv));
}

static uint_t
ntv_stepping(cmi_hdl_impl_t *hdl)
{
	return (cpuid_getstep((cpu_t *)hdl->cmih_hdlpriv));
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
	return (cpuid_getchiprev((cpu_t *)hdl->cmih_hdlpriv));
}

static const char *
ntv_chiprevstr(cmi_hdl_impl_t *hdl)
{
	return (cpuid_getchiprevstr((cpu_t *)hdl->cmih_hdlpriv));
}

static uint32_t
ntv_getsockettype(cmi_hdl_impl_t *hdl)
{
	return (cpuid_getsockettype((cpu_t *)hdl->cmih_hdlpriv));
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
	cpu_t *cp = (cpu_t *)hdl->cmih_hdlpriv;
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
	cpu_t *cp = (cpu_t *)hdl->cmih_hdlpriv;

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
	cpu_t *cp = (cpu_t *)hdl->cmih_hdlpriv;

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
	cpu_t *cp = (cpu_t *)hdl->cmih_hdlpriv;

	return (call_func_ntv(cp->cpu_id, ntv_wrmsr_xc,
	    (xc_arg_t)msr, (xc_arg_t)&val));
}

/*ARGSUSED*/
static int
ntv_mcheck_xc(xc_arg_t arg1, xc_arg_t arg2, xc_arg_t arg3)
{
	cmi_errno_t *rcp = (cmi_errno_t *)arg3;

	int18();
	*rcp = CMI_SUCCESS;

	return (0);
}

static void
ntv_mcheck(cmi_hdl_impl_t *hdl)
{
	cpu_t *cp = (cpu_t *)hdl->cmih_hdlpriv;

	(void) call_func_ntv(cp->cpu_id, ntv_mcheck_xc, NULL, NULL);
}

/*
 * Ops structure for handle operations.
 */
struct cmi_hdl_ops {
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
	ulong_t (*cmio_getcr4)(cmi_hdl_impl_t *);
	void (*cmio_setcr4)(cmi_hdl_impl_t *, ulong_t);
	cmi_errno_t (*cmio_rdmsr)(cmi_hdl_impl_t *, uint_t, uint64_t *);
	cmi_errno_t (*cmio_wrmsr)(cmi_hdl_impl_t *, uint_t, uint64_t);
	void (*cmio_mcheck)(cmi_hdl_impl_t *);
} cmi_hdl_ops[] = {
	/*
	 * CMI_HDL_NATIVE - ops when apparently running on bare-metal
	 */
	{
		ntv_vendor,
		ntv_vendorstr,
		ntv_family,
		ntv_model,
		ntv_stepping,
		ntv_chipid,
		ntv_coreid,
		ntv_strandid,
		ntv_chiprev,
		ntv_chiprevstr,
		ntv_getsockettype,
		ntv_getcr4,
		ntv_setcr4,
		ntv_rdmsr,
		ntv_wrmsr,
		ntv_mcheck
	},
};

#ifndef __xpv
static void *
cpu_search(enum cmi_hdl_class class, uint_t chipid, uint_t coreid,
    uint_t strandid)
{
	switch (class) {
	case CMI_HDL_NATIVE: {
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
	}

	default:
		return (NULL);
	}
}
#endif

cmi_hdl_t
cmi_hdl_create(enum cmi_hdl_class class, uint_t chipid, uint_t coreid,
    uint_t strandid)
{
	cmi_hdl_impl_t *hdl;
	void *priv = NULL;
	int idx;

	if (chipid > CMI_MAX_CHIPS - 1 || coreid > CMI_MAX_CORES_PER_CHIP - 1 ||
	    strandid > CMI_MAX_STRANDS_PER_CORE - 1)
		return (NULL);

#ifndef __xpv
	if ((priv = cpu_search(class, chipid, coreid, strandid)) == NULL)
		return (NULL);
#endif

	hdl = kmem_zalloc(sizeof (*hdl), KM_SLEEP);

	hdl->cmih_class = class;
	hdl->cmih_ops = &cmi_hdl_ops[class];
	hdl->cmih_chipid = chipid;
	hdl->cmih_coreid = coreid;
	hdl->cmih_strandid = strandid;
	hdl->cmih_hdlpriv = priv;
	hdl->cmih_msrsrc = CMI_MSR_FLAG_RD_HWOK | CMI_MSR_FLAG_RD_INTERPOSEOK |
	    CMI_MSR_FLAG_WR_HWOK | CMI_MSR_FLAG_WR_INTERPOSEOK;

	if (cmi_hdl_hash == NULL) {
		size_t sz = CMI_HDL_HASHSZ * sizeof (struct cmi_hdl_hashent);
		void *hash = kmem_zalloc(sz, KM_SLEEP);

		if (atomic_cas_ptr(&cmi_hdl_hash, NULL, hash) != NULL)
			kmem_free(hash, sz); /* someone beat us */
	}

	idx = CMI_HDL_HASHIDX(chipid, coreid, strandid);
	if (cmi_hdl_hash[idx].cmhe_refcnt != 0 ||
	    cmi_hdl_hash[idx].cmhe_hdlp != NULL) {
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
	cmi_hdl_hash[idx].cmhe_hdlp = hdl;
	hdl->cmih_refcntp = &cmi_hdl_hash[idx].cmhe_refcnt;
	cmi_hdl_hash[idx].cmhe_refcnt = 1;

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
cmi_hdl_canref(int hashidx)
{
	volatile uint32_t *refcntp;
	uint32_t refcnt;

	if (cmi_hdl_hash == NULL)
		return (0);

	refcntp = &cmi_hdl_hash[hashidx].cmhe_refcnt;
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

	idx = CMI_HDL_HASHIDX(hdl->cmih_chipid, hdl->cmih_coreid,
	    hdl->cmih_strandid);
	cmi_hdl_hash[idx].cmhe_hdlp = NULL;

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
	int idx = CMI_HDL_HASHIDX(chipid, coreid, strandid);

	if (!cmi_hdl_canref(idx))
		return (NULL);

	if (cmi_hdl_hash[idx].cmhe_hdlp->cmih_class != class) {
		cmi_hdl_rele((cmi_hdl_t)cmi_hdl_hash[idx].cmhe_hdlp);
		return (NULL);
	}

	return ((cmi_hdl_t)cmi_hdl_hash[idx].cmhe_hdlp);
}

cmi_hdl_t
cmi_hdl_any(void)
{
	int i;

	for (i = 0; i < CMI_HDL_HASHSZ; i++) {
		if (cmi_hdl_canref(i))
			return ((cmi_hdl_t)cmi_hdl_hash[i].cmhe_hdlp);
	}

	return (NULL);
}

void
cmi_hdl_walk(int (*cbfunc)(cmi_hdl_t, void *, void *, void *),
    void *arg1, void *arg2, void *arg3)
{
	int i;

	for (i = 0; i < CMI_HDL_HASHSZ; i++) {
		if (cmi_hdl_canref(i)) {
			cmi_hdl_impl_t *hdl = cmi_hdl_hash[i].cmhe_hdlp;

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
		return (IMPLHDL(ophdl)->cmih_ops->		\
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

void
cmi_hdl_mcheck(cmi_hdl_t ophdl)
{
	IMPLHDL(ophdl)->cmih_ops->cmio_mcheck(IMPLHDL(ophdl));
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

	if (!(hdl->cmih_msrsrc & CMI_MSR_FLAG_RD_HWOK))
		return (CMIERR_INTERPOSE);

	return (hdl->cmih_ops->cmio_rdmsr(hdl, msr, valp));
}

cmi_errno_t
cmi_hdl_wrmsr(cmi_hdl_t ophdl, uint_t msr, uint64_t val)
{
	cmi_hdl_impl_t *hdl = IMPLHDL(ophdl);

	/* Invalidate any interposed value */
	msri_rment(hdl, msr);

	if (!(hdl->cmih_msrsrc & CMI_MSR_FLAG_WR_HWOK))
		return (CMI_SUCCESS);

	return (hdl->cmih_ops->cmio_wrmsr(hdl, msr, val));
}

void
cmi_hdl_enable_mce(cmi_hdl_t ophdl)
{
	cmi_hdl_impl_t *hdl = IMPLHDL(ophdl);
	ulong_t cr4 = hdl->cmih_ops->cmio_getcr4(hdl);

	hdl->cmih_ops->cmio_setcr4(hdl, cr4 | CR4_MCE);
}

void
cmi_hdl_msrinterpose(cmi_hdl_t ophdl, cmi_mca_regs_t *regs, uint_t nregs)
{
	cmi_hdl_impl_t *hdl = IMPLHDL(ophdl);
	int i;

	for (i = 0; i < nregs; i++)
		msri_addent(hdl, regs++);
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

extern void
cmi_pci_putb(int bus, int dev, int func, int reg, ddi_acc_handle_t hdl,
    uint8_t val)
{
	cmi_pci_put_cmn(bus, dev, func, reg, 1, hdl, val);
}

extern void
cmi_pci_putw(int bus, int dev, int func, int reg, ddi_acc_handle_t hdl,
    uint16_t val)
{
	cmi_pci_put_cmn(bus, dev, func, reg, 2, hdl, val);
}

extern void
cmi_pci_putl(int bus, int dev, int func, int reg, ddi_acc_handle_t hdl,
    uint32_t val)
{
	cmi_pci_put_cmn(bus, dev, func, reg, 4, hdl, val);
}

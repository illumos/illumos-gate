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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Platform specific implementation code
 */

#define	SUNDDI_IMPL

#include <sys/types.h>
#include <sys/promif.h>
#include <sys/prom_isa.h>
#include <sys/prom_plat.h>
#include <sys/mmu.h>
#include <vm/hat_sfmmu.h>
#include <sys/iommu.h>
#include <sys/scb.h>
#include <sys/cpuvar.h>
#include <sys/intreg.h>
#include <sys/pte.h>
#include <vm/hat.h>
#include <vm/page.h>
#include <vm/as.h>
#include <sys/cpr.h>
#include <sys/kmem.h>
#include <sys/clock.h>
#include <sys/kmem.h>
#include <sys/panic.h>
#include <vm/seg_kmem.h>
#include <sys/cpu_module.h>
#include <sys/callb.h>
#include <sys/machsystm.h>
#include <sys/vmsystm.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/stack.h>
#include <sys/fs/ufs_fs.h>
#include <sys/memlist.h>
#include <sys/bootconf.h>
#include <sys/thread.h>
#include <vm/vm_dep.h>

extern	void cpr_clear_bitmaps(void);
extern	int cpr_setbit(pfn_t ppn, int mapflag);
extern	int cpr_clrbit(pfn_t ppn, int mapflag);
extern	pgcnt_t cpr_scan_kvseg(int mapflag, bitfunc_t bitfunc, struct seg *seg);
extern	pgcnt_t cpr_count_seg_pages(int mapflag, bitfunc_t bitfunc);
extern	void dtlb_wr_entry(uint_t, tte_t *, uint64_t *);
extern	void itlb_wr_entry(uint_t, tte_t *, uint64_t *);

static	int i_cpr_storage_desc_alloc(csd_t **, pgcnt_t *, csd_t **, int);
static	void i_cpr_storage_desc_init(csd_t *, pgcnt_t, csd_t *);
static	caddr_t i_cpr_storage_data_alloc(pgcnt_t, pgcnt_t *, int);
static	int cpr_dump_sensitive(vnode_t *, csd_t *);
static	void i_cpr_clear_entries(uint64_t, uint64_t);
static	void i_cpr_xcall(xcfunc_t);

void	i_cpr_storage_free(void);

extern void *i_cpr_data_page;
extern int cpr_test_mode;
extern int cpr_nbitmaps;
extern char cpr_default_path[];
extern caddr_t textva, datava;

static struct cpr_map_info cpr_prom_retain[CPR_PROM_RETAIN_CNT];
caddr_t cpr_vaddr = NULL;

static	uint_t sensitive_pages_saved;
static	uint_t sensitive_size_saved;

caddr_t	i_cpr_storage_data_base;
caddr_t	i_cpr_storage_data_end;
csd_t *i_cpr_storage_desc_base;
csd_t *i_cpr_storage_desc_end;		/* one byte beyond last used descp */
csd_t *i_cpr_storage_desc_last_used;	/* last used descriptor */
caddr_t sensitive_write_ptr;		/* position for next storage write */

size_t	i_cpr_sensitive_bytes_dumped;
pgcnt_t	i_cpr_sensitive_pgs_dumped;
pgcnt_t	i_cpr_storage_data_sz;		/* in pages */
pgcnt_t	i_cpr_storage_desc_pgcnt;	/* in pages */

ushort_t cpr_mach_type = CPR_MACHTYPE_4U;
static	csu_md_t m_info;


#define	MAX_STORAGE_RETRY	3
#define	MAX_STORAGE_ALLOC_RETRY	3
#define	INITIAL_ALLOC_PCNT	40	/* starting allocation percentage */
#define	INTEGRAL		100	/* to get 1% precision */

#define	EXTRA_RATE		2	/* add EXTRA_RATE% extra space */
#define	EXTRA_DESCS		10

#define	CPR_NO_STORAGE_DESC	1
#define	CPR_NO_STORAGE_DATA	2

#define	CIF_SPLICE		0
#define	CIF_UNLINK		1


/*
 * CPR miscellaneous support routines
 */
#define	cpr_open(path, mode,  vpp)	(vn_open(path, UIO_SYSSPACE, \
		mode, 0600, vpp, CRCREAT, 0))
#define	cpr_rdwr(rw, vp, basep, cnt)	(vn_rdwr(rw, vp,  (caddr_t)(basep), \
		cnt, 0LL, UIO_SYSSPACE, 0, (rlim64_t)MAXOFF_T, CRED(), \
		(ssize_t *)NULL))

/*
 * definitions for saving/restoring prom pages
 */
static void	*ppage_buf;
static pgcnt_t	ppage_count;
static pfn_t	*pphys_list;
static size_t	pphys_list_size;

typedef void (*tlb_rw_t)(uint_t, tte_t *, uint64_t *);
typedef void (*tlb_filter_t)(int, tte_t *, uint64_t, void *);

/*
 * private struct for tlb handling
 */
struct cpr_trans_info {
	sutlb_t		*dst;
	sutlb_t		*tail;
	tlb_rw_t	reader;
	tlb_rw_t	writer;
	tlb_filter_t	filter;
	int		index;
	uint64_t	skip;		/* assumes TLB <= 64 locked entries */
};
typedef struct cpr_trans_info cti_t;


/*
 * special handling for tlb info
 */
#define	WITHIN_OFW(va) \
	(((va) > (uint64_t)OFW_START_ADDR) && ((va) < (uint64_t)OFW_END_ADDR))

#define	WITHIN_NUCLEUS(va, base) \
	(((va) >= (base)) && \
	(((va) + MMU_PAGESIZE) <= ((base) + MMU_PAGESIZE4M)))

#define	IS_BIGKTSB(va) \
	(enable_bigktsb && \
	((va) >= (uint64_t)ktsb_base) && \
	((va) < (uint64_t)(ktsb_base + ktsb_sz)))


/*
 * WARNING:
 * the text from this file is linked to follow cpr_resume_setup.o;
 * only add text between here and i_cpr_end_jumpback when it needs
 * to be called during resume before we switch back to the kernel
 * trap table.  all the text in this range must fit within a page.
 */


/*
 * each time a machine is reset, the prom uses an inconsistent set of phys
 * pages and the cif cookie may differ as well.  so prior to restoring the
 * original prom, we have to use to use the new/tmp prom's translations
 * when requesting prom services.
 *
 * cif_handler starts out as the original prom cookie, and that gets used
 * by client_handler() to jump into the prom.  here we splice-in a wrapper
 * routine by writing cif_handler; client_handler() will now jump to the
 * wrapper which switches the %tba to the new/tmp prom's trap table then
 * jumps to the new cookie.
 */
void
i_cpr_cif_setup(int action)
{
	extern void *i_cpr_orig_cif, *cif_handler;
	extern int i_cpr_cif_wrapper(void *);

	/*
	 * save the original cookie and change the current cookie to the
	 * wrapper routine.  later we just restore the original cookie.
	 */
	if (action == CIF_SPLICE) {
		i_cpr_orig_cif = cif_handler;
		cif_handler = (void *)i_cpr_cif_wrapper;
	} else if (action == CIF_UNLINK)
		cif_handler = i_cpr_orig_cif;
}


/*
 * launch slave cpus into kernel text, pause them,
 * and restore the original prom pages
 */
void
i_cpr_mp_setup(void)
{
	extern void restart_other_cpu(int);
	cpu_t *cp;

	uint64_t kctx = kcontextreg;

	/*
	 * Do not allow setting page size codes in MMU primary context
	 * register while using cif wrapper. This is needed to work
	 * around OBP incorrect handling of this MMU register.
	 */
	kcontextreg = 0;

	/*
	 * reset cpu_ready_set so x_calls work properly
	 */
	CPUSET_ZERO(cpu_ready_set);
	CPUSET_ADD(cpu_ready_set, getprocessorid());

	/*
	 * setup cif to use the cookie from the new/tmp prom
	 * and setup tmp handling for calling prom services.
	 */
	i_cpr_cif_setup(CIF_SPLICE);

	/*
	 * at this point, only the nucleus and a few cpr pages are
	 * mapped in.  once we switch to the kernel trap table,
	 * we can access the rest of kernel space.
	 */
	prom_set_traptable(&trap_table);

	if (ncpus > 1) {
		sfmmu_init_tsbs();

		mutex_enter(&cpu_lock);
		/*
		 * All of the slave cpus are not ready at this time,
		 * yet the cpu structures have various cpu_flags set;
		 * clear cpu_flags and mutex_ready.
		 * Since we are coming up from a CPU suspend, the slave cpus
		 * are frozen.
		 */
		for (cp = CPU->cpu_next; cp != CPU; cp = cp->cpu_next) {
			cp->cpu_flags = CPU_FROZEN;
			cp->cpu_m.mutex_ready = 0;
		}

		for (cp = CPU->cpu_next; cp != CPU; cp = cp->cpu_next)
			restart_other_cpu(cp->cpu_id);

		pause_cpus(NULL, NULL);
		mutex_exit(&cpu_lock);

		i_cpr_xcall(i_cpr_clear_entries);
	} else
		i_cpr_clear_entries(0, 0);

	/*
	 * now unlink the cif wrapper;  WARNING: do not call any
	 * prom_xxx() routines until after prom pages are restored.
	 */
	i_cpr_cif_setup(CIF_UNLINK);

	(void) i_cpr_prom_pages(CPR_PROM_RESTORE);

	/* allow setting page size codes in MMU primary context register */
	kcontextreg = kctx;
}


/*
 * end marker for jumpback page;
 * this symbol is used to check the size of i_cpr_resume_setup()
 * and the above text.  For simplicity, the Makefile needs to
 * link i_cpr_resume_setup.o and cpr_impl.o consecutively.
 */
void
i_cpr_end_jumpback(void)
{
}


/*
 * scan tlb entries with reader; when valid entries are found,
 * the filter routine will selectively save/clear them
 */
static void
i_cpr_scan_tlb(cti_t *ctip)
{
	uint64_t va_tag;
	int tlb_index;
	tte_t tte;

	for (tlb_index = ctip->index; tlb_index >= 0; tlb_index--) {
		(*ctip->reader)((uint_t)tlb_index, &tte, &va_tag);
		if (va_tag && TTE_IS_VALID(&tte))
			(*ctip->filter)(tlb_index, &tte, va_tag, ctip);
	}
}


/*
 * filter for locked tlb entries that reference the text/data nucleus
 * and any bigktsb's; these will be reinstalled by cprboot on all cpus
 */
/* ARGSUSED */
static void
i_cpr_lnb(int index, tte_t *ttep, uint64_t va_tag, void *ctrans)
{
	cti_t *ctip;

	/*
	 * record tlb data at ctip->dst; the target tlb index starts
	 * at the highest tlb offset and moves towards 0.  the prom
	 * reserves both dtlb and itlb index 0.  any selected entry
	 * also gets marked to prevent being flushed during resume
	 */
	if (TTE_IS_LOCKED(ttep) && (va_tag == (uint64_t)textva ||
	    va_tag == (uint64_t)datava || IS_BIGKTSB(va_tag))) {
		ctip = ctrans;
		while ((1 << ctip->index) & ctip->skip)
			ctip->index--;
		ASSERT(ctip->index > 0);
		ASSERT(ctip->dst < ctip->tail);
		ctip->dst->tte.ll = ttep->ll;
		ctip->dst->va_tag = va_tag;
		ctip->dst->index = ctip->index--;
		ctip->dst->tmp = 0;
		ctip->dst++;
	}
}


/*
 * some tlb entries are stale, filter for unlocked entries
 * within the prom virt range and clear them
 */
static void
i_cpr_ufw(int index, tte_t *ttep, uint64_t va_tag, void *ctrans)
{
	sutlb_t clr;
	cti_t *ctip;

	if (!TTE_IS_LOCKED(ttep) && WITHIN_OFW(va_tag)) {
		ctip = ctrans;
		bzero(&clr, sizeof (clr));
		(*ctip->writer)((uint_t)index, &clr.tte, &clr.va_tag);
	}
}


/*
 * some of the entries installed by cprboot are needed only on a
 * short-term basis and need to be flushed to avoid clogging the tlbs.
 * scan the dtte/itte arrays for items marked as temporary and clear
 * dtlb/itlb entries using wrfunc.
 */
static void
i_cpr_clear_tmp(sutlb_t *listp, int max, tlb_rw_t wrfunc)
{
	sutlb_t clr, *tail;

	bzero(&clr, sizeof (clr));
	for (tail = listp + max; listp < tail && listp->va_tag; listp++) {
		if (listp->tmp)
			(*wrfunc)((uint_t)listp->index, &clr.tte, &clr.va_tag);
	}
}


/* ARGSUSED */
static void
i_cpr_clear_entries(uint64_t arg1, uint64_t arg2)
{
	extern void demap_all(void);
	cti_t cti;

	i_cpr_clear_tmp(m_info.dtte, CPR_MAX_TLB, dtlb_wr_entry);
	i_cpr_clear_tmp(m_info.itte, CPR_MAX_TLB, itlb_wr_entry);

	/*
	 * for newer cpus that implement DEMAP_ALL_TYPE, demap_all is
	 * a second label for vtag_flushall.  the call is made using
	 * vtag_flushall() instead of demap_all() due to runtime and
	 * krtld results with both older and newer cpu modules.
	 */
	if (&demap_all != 0) {
		vtag_flushall();
		return;
	}

	/*
	 * for older V9 cpus, scan tlbs and clear stale entries
	 */
	bzero(&cti, sizeof (cti));
	cti.filter = i_cpr_ufw;

	cti.index = cpunodes[CPU->cpu_id].dtlb_size - 1;
	cti.reader = dtlb_rd_entry;
	cti.writer = dtlb_wr_entry;
	i_cpr_scan_tlb(&cti);

	cti.index = cpunodes[CPU->cpu_id].itlb_size - 1;
	cti.reader = itlb_rd_entry;
	cti.writer = itlb_wr_entry;
	i_cpr_scan_tlb(&cti);
}


/*
 * craft tlb info for tmp use during resume; this data gets used by
 * cprboot to install tlb entries.  we also mark each struct as tmp
 * so those tlb entries will get flushed after switching to the kernel
 * trap table.  no data needs to be recorded for vaddr when it falls
 * within the nucleus since we've already recorded nucleus ttes and
 * a 8K tte would conflict with a 4MB tte.  eg: the cpr module
 * text/data may have been loaded into the text/data nucleus.
 */
static void
i_cpr_make_tte(cti_t *ctip, void *vaddr, caddr_t nbase)
{
	pfn_t ppn;
	uint_t rw;

	if (WITHIN_NUCLEUS((caddr_t)vaddr, nbase))
		return;

	while ((1 << ctip->index) & ctip->skip)
		ctip->index--;
	ASSERT(ctip->index > 0);
	ASSERT(ctip->dst < ctip->tail);

	/*
	 * without any global service available to lookup
	 * a tte by vaddr, we craft our own here:
	 */
	ppn = va_to_pfn(vaddr);
	rw = (nbase == datava) ? TTE_HWWR_INT : 0;
	ctip->dst->tte.tte_inthi = TTE_VALID_INT | TTE_PFN_INTHI(ppn);
	ctip->dst->tte.tte_intlo = TTE_PFN_INTLO(ppn) | TTE_LCK_INT |
	    TTE_CP_INT | TTE_PRIV_INT | rw;
	ctip->dst->va_tag = ((uintptr_t)vaddr & MMU_PAGEMASK);
	ctip->dst->index = ctip->index--;
	ctip->dst->tmp = 1;
	ctip->dst++;
}


static void
i_cpr_xcall(xcfunc_t func)
{
	uint_t pil, reset_pil;

	pil = getpil();
	if (pil < XCALL_PIL)
		reset_pil = 0;
	else {
		reset_pil = 1;
		setpil(XCALL_PIL - 1);
	}
	xc_some(cpu_ready_set, func, 0, 0);
	if (reset_pil)
		setpil(pil);
}


/*
 * restart paused slave cpus
 */
void
i_cpr_machdep_setup(void)
{
	if (ncpus > 1) {
		CPR_DEBUG(CPR_DEBUG1, "MP restarted...\n");
		mutex_enter(&cpu_lock);
		start_cpus();
		mutex_exit(&cpu_lock);
	}
}


/*
 * Stop all interrupt activities in the system
 */
void
i_cpr_stop_intr(void)
{
	(void) spl7();
}

/*
 * Set machine up to take interrupts
 */
void
i_cpr_enable_intr(void)
{
	(void) spl0();
}


/*
 * record cpu nodes and ids
 */
static void
i_cpr_save_cpu_info(void)
{
	struct sun4u_cpu_info *scip;
	cpu_t *cp;

	scip = m_info.sci;
	cp = CPU;
	do {
		ASSERT(scip < &m_info.sci[NCPU]);
		scip->cpu_id = cp->cpu_id;
		scip->node = cpunodes[cp->cpu_id].nodeid;
		scip++;
	} while ((cp = cp->cpu_next) != CPU);
}


/*
 * Write necessary machine dependent information to cpr state file,
 * eg. sun4u mmu ctx secondary for the current running process (cpr) ...
 */
int
i_cpr_write_machdep(vnode_t *vp)
{
	extern uint_t getpstate(), getwstate();
	extern uint_t i_cpr_tstack_size;
	const char ustr[] = ": unix-tte 2drop false ;";
	uintptr_t tinfo;
	label_t *ltp;
	cmd_t cmach;
	char *fmt;
	int rc;

	/*
	 * ustr[] is used as temporary forth words during
	 * slave startup sequence, see sfmmu_mp_startup()
	 */

	cmach.md_magic = (uint_t)CPR_MACHDEP_MAGIC;
	cmach.md_size = sizeof (m_info) + sizeof (ustr);

	if (rc = cpr_write(vp, (caddr_t)&cmach, sizeof (cmach))) {
		cpr_err(CE_WARN, "Failed to write descriptor.");
		return (rc);
	}

	/*
	 * m_info is now cleared in i_cpr_dump_setup()
	 */
	m_info.ksb = (uint32_t)STACK_BIAS;
	m_info.kpstate = (uint16_t)getpstate();
	m_info.kwstate = (uint16_t)getwstate();
	CPR_DEBUG(CPR_DEBUG1, "stack bias 0x%x, pstate 0x%x, wstate 0x%x\n",
	    m_info.ksb, m_info.kpstate, m_info.kwstate);

	ltp = &ttolwp(curthread)->lwp_qsav;
	m_info.qsav_pc = (cpr_ext)ltp->val[0];
	m_info.qsav_sp = (cpr_ext)ltp->val[1];

	/*
	 * Set secondary context to INVALID_CONTEXT to force the HAT
	 * to re-setup the MMU registers and locked TTEs it needs for
	 * TLB miss handling.
	 */
	m_info.mmu_ctx_sec = INVALID_CONTEXT;
	m_info.mmu_ctx_pri = KCONTEXT;

	tinfo = (uintptr_t)curthread;
	m_info.thrp = (cpr_ptr)tinfo;

	tinfo = (uintptr_t)i_cpr_resume_setup;
	m_info.func = (cpr_ptr)tinfo;

	/*
	 * i_cpr_data_page is comprised of a 4K stack area and a few
	 * trailing data symbols; the page is shared by the prom and
	 * kernel during resume.  the stack size is recorded here
	 * and used by cprboot to set %sp
	 */
	tinfo = (uintptr_t)&i_cpr_data_page;
	m_info.tmp_stack = (cpr_ptr)tinfo;
	m_info.tmp_stacksize = i_cpr_tstack_size;

	m_info.test_mode = cpr_test_mode;

	i_cpr_save_cpu_info();

	if (rc = cpr_write(vp, (caddr_t)&m_info, sizeof (m_info))) {
		cpr_err(CE_WARN, "Failed to write machdep info.");
		return (rc);
	}

	fmt = "error writing %s forth info";
	if (rc = cpr_write(vp, (caddr_t)ustr, sizeof (ustr)))
		cpr_err(CE_WARN, fmt, "unix-tte");

	return (rc);
}


/*
 * Save miscellaneous information which needs to be written to the
 * state file.  This information is required to re-initialize
 * kernel/prom handshaking.
 */
void
i_cpr_save_machdep_info(void)
{
	CPR_DEBUG(CPR_DEBUG5, "jumpback size = 0x%lx\n",
	    (uintptr_t)&i_cpr_end_jumpback -
	    (uintptr_t)i_cpr_resume_setup);

	/*
	 * Verify the jumpback code all falls in one page.
	 */
	if (((uintptr_t)&i_cpr_end_jumpback & MMU_PAGEMASK) !=
	    ((uintptr_t)i_cpr_resume_setup & MMU_PAGEMASK))
		cpr_err(CE_PANIC, "jumpback code exceeds one page.");
}


/*
 * cpu0 should contain bootcpu info
 */
cpu_t *
i_cpr_bootcpu(void)
{
	return (&cpu0);
}

processorid_t
i_cpr_bootcpuid(void)
{
	return (0);
}

/*
 * Return the virtual address of the mapping area
 */
caddr_t
i_cpr_map_setup(void)
{
	/*
	 * Allocate a virtual memory range spanned by an hmeblk.
	 * This would be 8 hments or 64k bytes.  Starting VA
	 * must be 64k (8-page) aligned.
	 */
	cpr_vaddr = vmem_xalloc(heap_arena,
	    mmu_ptob(NHMENTS), mmu_ptob(NHMENTS),
	    0, 0, NULL, NULL, VM_NOSLEEP);
	return (cpr_vaddr);
}

/*
 * create tmp locked tlb entries for a group of phys pages;
 *
 * i_cpr_mapin/i_cpr_mapout should always be called in pairs,
 * otherwise would fill up a tlb with locked entries
 */
void
i_cpr_mapin(caddr_t vaddr, uint_t pages, pfn_t ppn)
{
	tte_t tte;
	extern pfn_t curthreadpfn;
	extern int curthreadremapped;

	curthreadremapped = (ppn <= curthreadpfn && curthreadpfn < ppn + pages);

	for (; pages--; ppn++, vaddr += MMU_PAGESIZE) {
		tte.tte_inthi = TTE_VALID_INT | TTE_PFN_INTHI(ppn);
		tte.tte_intlo = TTE_PFN_INTLO(ppn) | TTE_LCK_INT |
		    TTE_CP_INT | TTE_PRIV_INT | TTE_HWWR_INT;
		sfmmu_dtlb_ld_kva(vaddr, &tte);
	}
}

void
i_cpr_mapout(caddr_t vaddr, uint_t pages)
{
	extern int curthreadremapped;

	if (curthreadremapped && vaddr <= (caddr_t)curthread &&
	    (caddr_t)curthread < vaddr + pages * MMU_PAGESIZE)
		curthreadremapped = 0;

	for (; pages--; vaddr += MMU_PAGESIZE)
		vtag_flushpage(vaddr, (uint64_t)ksfmmup);
}

/*
 * We're done using the mapping area; release virtual space
 */
void
i_cpr_map_destroy(void)
{
	vmem_free(heap_arena, cpr_vaddr, mmu_ptob(NHMENTS));
	cpr_vaddr = NULL;
}

/* ARGSUSED */
void
i_cpr_handle_xc(int flag)
{
}


/*
 * This function takes care of pages which are not in kas or need to be
 * taken care of in a special way.  For example, panicbuf pages are not
 * in kas and their pages are allocated via prom_retain().
 */
pgcnt_t
i_cpr_count_special_kpages(int mapflag, bitfunc_t bitfunc)
{
	struct cpr_map_info *pri, *tail;
	pgcnt_t pages, total = 0;
	pfn_t pfn;

	/*
	 * Save information about prom retained panicbuf pages
	 */
	if (bitfunc == cpr_setbit) {
		pri = &cpr_prom_retain[CPR_PANICBUF];
		pri->virt = (cpr_ptr)panicbuf;
		pri->phys = va_to_pa(panicbuf);
		pri->size = sizeof (panicbuf);
	}

	/*
	 * Go through the prom_retain array to tag those pages.
	 */
	tail = &cpr_prom_retain[CPR_PROM_RETAIN_CNT];
	for (pri = cpr_prom_retain; pri < tail; pri++) {
		pages = mmu_btopr(pri->size);
		for (pfn = ADDR_TO_PN(pri->phys); pages--; pfn++) {
			if (pf_is_memory(pfn)) {
				if (bitfunc == cpr_setbit) {
					if ((*bitfunc)(pfn, mapflag) == 0)
						total++;
				} else
					total++;
			}
		}
	}

	return (total);
}


/*
 * Free up memory-related resources here.  We start by freeing buffers
 * allocated during suspend initialization.  Also, free up the mapping
 * resources allocated in cpr_init().
 */
void
i_cpr_free_memory_resources(void)
{
	(void) i_cpr_prom_pages(CPR_PROM_FREE);
	i_cpr_map_destroy();
	i_cpr_storage_free();
}


/*
 * Derived from cpr_write_statefile().
 * Save the sensitive pages to the storage area and do bookkeeping
 * using the sensitive descriptors. Each descriptor will contain no more
 * than CPR_MAXCONTIG amount of contiguous pages to match the max amount
 * of pages that statefile gets written to disk at each write.
 * XXX The CPR_MAXCONTIG can be changed to the size of the compression
 * scratch area.
 */
static int
i_cpr_save_to_storage(void)
{
	sensitive_size_saved = 0;
	sensitive_pages_saved = 0;
	sensitive_write_ptr = i_cpr_storage_data_base;
	return (cpr_contig_pages(NULL, SAVE_TO_STORAGE));
}


/*
 * This routine allocates space to save the sensitive kernel pages,
 * i.e. kernel data nucleus, kvalloc and kvseg segments.
 * It's assumed that those segments are the only areas that can be
 * contaminated by memory allocations during statefile dumping.
 * The space allocated here contains:
 * 	A list of descriptors describing the saved sensitive pages.
 * 	The storage area for saving the compressed sensitive kernel pages.
 * Since storage pages are allocated from segkmem, they need to be
 * excluded when saving.
 */
int
i_cpr_save_sensitive_kpages(void)
{
	static const char pages_fmt[] = "\n%s %s allocs\n"
	    "	spages %ld, vpages %ld, diff %ld\n";
	int retry_cnt;
	int error = 0;
	pgcnt_t pages, spages, vpages;
	caddr_t	addr;
	char *str;

	/*
	 * Tag sensitive kpages. Allocate space for storage descriptors
	 * and storage data area based on the resulting bitmaps.
	 * Note: The storage space will be part of the sensitive
	 * segment, so we need to tag kpages here before the storage
	 * is actually allocated just so their space won't be accounted
	 * for. They will not be part of the statefile although those
	 * pages will be claimed by cprboot.
	 */
	cpr_clear_bitmaps();

	spages = i_cpr_count_sensitive_kpages(REGULAR_BITMAP, cpr_setbit);
	vpages = cpr_count_volatile_pages(REGULAR_BITMAP, cpr_clrbit);
	pages = spages - vpages;

	str = "i_cpr_save_sensitive_kpages:";
	CPR_DEBUG(CPR_DEBUG7, pages_fmt, "before", str, spages, vpages, pages);

	/*
	 * Allocate space to save the clean sensitive kpages
	 */
	for (retry_cnt = 0; retry_cnt < MAX_STORAGE_ALLOC_RETRY; retry_cnt++) {
		/*
		 * Alloc on first pass or realloc if we are retrying because
		 * of insufficient storage for sensitive pages
		 */
		if (retry_cnt == 0 || error == ENOMEM) {
			if (i_cpr_storage_data_base) {
				kmem_free(i_cpr_storage_data_base,
				    mmu_ptob(i_cpr_storage_data_sz));
				i_cpr_storage_data_base = NULL;
				i_cpr_storage_data_sz = 0;
			}
			addr = i_cpr_storage_data_alloc(pages,
			    &i_cpr_storage_data_sz, retry_cnt);
			if (addr == NULL) {
				CPR_DEBUG(CPR_DEBUG7,
				    "\n%s can't allocate data storage space!\n",
				    str);
				return (ENOMEM);
			}
			i_cpr_storage_data_base = addr;
			i_cpr_storage_data_end =
			    addr + mmu_ptob(i_cpr_storage_data_sz);
		}

		/*
		 * Allocate on first pass, only realloc if retry is because of
		 * insufficient descriptors, but reset contents on each pass
		 * (desc_alloc resets contents as well)
		 */
		if (retry_cnt == 0 || error == -1) {
			error = i_cpr_storage_desc_alloc(
			    &i_cpr_storage_desc_base, &i_cpr_storage_desc_pgcnt,
			    &i_cpr_storage_desc_end, retry_cnt);
			if (error != 0)
				return (error);
		} else {
			i_cpr_storage_desc_init(i_cpr_storage_desc_base,
			    i_cpr_storage_desc_pgcnt, i_cpr_storage_desc_end);
		}

		/*
		 * We are ready to save the sensitive kpages to storage.
		 * We cannot trust what's tagged in the bitmaps anymore
		 * after storage allocations.  Clear up the bitmaps and
		 * retag the sensitive kpages again.  The storage pages
		 * should be untagged.
		 */
		cpr_clear_bitmaps();

		spages =
		    i_cpr_count_sensitive_kpages(REGULAR_BITMAP, cpr_setbit);
		vpages = cpr_count_volatile_pages(REGULAR_BITMAP, cpr_clrbit);

		CPR_DEBUG(CPR_DEBUG7, pages_fmt, "after ", str,
		    spages, vpages, spages - vpages);

		/*
		 * Returns 0 on success, -1 if too few descriptors, and
		 * ENOMEM if not enough space to save sensitive pages
		 */
		CPR_DEBUG(CPR_DEBUG1, "compressing pages to storage...\n");
		error = i_cpr_save_to_storage();
		if (error == 0) {
			/* Saving to storage succeeded */
			CPR_DEBUG(CPR_DEBUG1, "compressed %d pages\n",
			    sensitive_pages_saved);
			break;
		} else if (error == -1)
			CPR_DEBUG(CPR_DEBUG1, "%s too few descriptors\n", str);
	}
	if (error == -1)
		error = ENOMEM;
	return (error);
}


/*
 * Estimate how much memory we will need to save
 * the sensitive pages with compression.
 */
static caddr_t
i_cpr_storage_data_alloc(pgcnt_t pages, pgcnt_t *alloc_pages, int retry_cnt)
{
	pgcnt_t alloc_pcnt, last_pcnt;
	caddr_t addr;
	char *str;

	str = "i_cpr_storage_data_alloc:";
	if (retry_cnt == 0) {
		/*
		 * common compression ratio is about 3:1
		 * initial storage allocation is estimated at 40%
		 * to cover the majority of cases
		 */
		alloc_pcnt = INITIAL_ALLOC_PCNT;
		*alloc_pages = (pages * alloc_pcnt) / INTEGRAL;
		CPR_DEBUG(CPR_DEBUG7, "%s sensitive pages: %ld\n", str, pages);
		CPR_DEBUG(CPR_DEBUG7,
		    "%s initial est pages: %ld, alloc %ld%%\n",
		    str, *alloc_pages, alloc_pcnt);
	} else {
		/*
		 * calculate the prior compression percentage (x100)
		 * from the last attempt to save sensitive pages
		 */
		ASSERT(sensitive_pages_saved != 0);
		last_pcnt = (mmu_btopr(sensitive_size_saved) * INTEGRAL) /
		    sensitive_pages_saved;
		CPR_DEBUG(CPR_DEBUG7, "%s last ratio %ld%%\n", str, last_pcnt);

		/*
		 * new estimated storage size is based on
		 * the larger ratio + 5% for each retry:
		 * pages * (last + [5%, 10%])
		 */
		alloc_pcnt = MAX(last_pcnt, INITIAL_ALLOC_PCNT) +
		    (retry_cnt * 5);
		*alloc_pages = (pages * alloc_pcnt) / INTEGRAL;
		CPR_DEBUG(CPR_DEBUG7, "%s Retry est pages: %ld, alloc %ld%%\n",
		    str, *alloc_pages, alloc_pcnt);
	}

	addr = kmem_alloc(mmu_ptob(*alloc_pages), KM_NOSLEEP);
	CPR_DEBUG(CPR_DEBUG7, "%s alloc %ld pages\n", str, *alloc_pages);
	return (addr);
}


void
i_cpr_storage_free(void)
{
	/* Free descriptors */
	if (i_cpr_storage_desc_base) {
		kmem_free(i_cpr_storage_desc_base,
		    mmu_ptob(i_cpr_storage_desc_pgcnt));
		i_cpr_storage_desc_base = NULL;
		i_cpr_storage_desc_pgcnt = 0;
	}


	/* Data storage */
	if (i_cpr_storage_data_base) {
		kmem_free(i_cpr_storage_data_base,
		    mmu_ptob(i_cpr_storage_data_sz));
		i_cpr_storage_data_base = NULL;
		i_cpr_storage_data_sz = 0;
	}
}


/*
 * This routine is derived from cpr_compress_and_write().
 * 1. Do bookkeeping in the descriptor for the contiguous sensitive chunk.
 * 2. Compress and save the clean sensitive pages into the storage area.
 */
int
i_cpr_compress_and_save(int chunks, pfn_t spfn, pgcnt_t pages)
{
	extern char *cpr_compress_pages(cpd_t *, pgcnt_t, int);
	extern caddr_t i_cpr_storage_data_end;
	uint_t remaining, datalen;
	uint32_t test_usum;
	char *datap;
	csd_t *descp;
	cpd_t cpd;
	int error;

	/*
	 * Fill next empty storage descriptor
	 */
	descp = i_cpr_storage_desc_base + chunks - 1;
	if (descp >= i_cpr_storage_desc_end) {
		CPR_DEBUG(CPR_DEBUG1, "ran out of descriptors, base 0x%p, "
		    "chunks %d, end 0x%p, descp 0x%p\n",
		    (void *)i_cpr_storage_desc_base, chunks,
		    (void *)i_cpr_storage_desc_end, (void *)descp);
		return (-1);
	}
	ASSERT(descp->csd_dirty_spfn == (uint_t)-1);
	i_cpr_storage_desc_last_used = descp;

	descp->csd_dirty_spfn = spfn;
	descp->csd_dirty_npages = pages;

	i_cpr_mapin(CPR->c_mapping_area, pages, spfn);

	/*
	 * try compressing pages and copy cpd fields
	 * pfn is copied for debug use
	 */
	cpd.cpd_pfn = spfn;
	datap = cpr_compress_pages(&cpd, pages, C_COMPRESSING);
	datalen = cpd.cpd_length;
	descp->csd_clean_compressed = (cpd.cpd_flag & CPD_COMPRESS);
#ifdef DEBUG
	descp->csd_usum = cpd.cpd_usum;
	descp->csd_csum = cpd.cpd_csum;
#endif

	error = 0;

	/*
	 * Save the raw or compressed data to the storage area pointed to by
	 * sensitive_write_ptr. Make sure the storage space is big enough to
	 * hold the result. Otherwise roll back to increase the storage space.
	 */
	descp->csd_clean_sva = (cpr_ptr)sensitive_write_ptr;
	descp->csd_clean_sz = datalen;
	if ((sensitive_write_ptr + datalen) < i_cpr_storage_data_end) {
		extern	void cprbcopy(void *, void *, size_t);

		cprbcopy(datap, sensitive_write_ptr, datalen);
		sensitive_size_saved += datalen;
		sensitive_pages_saved += descp->csd_dirty_npages;
		sensitive_write_ptr += datalen;
	} else {
		remaining = (i_cpr_storage_data_end - sensitive_write_ptr);
		CPR_DEBUG(CPR_DEBUG1, "i_cpr_compress_and_save: The storage "
		    "space is too small!\ngot %d, want %d\n\n",
		    remaining, (remaining + datalen));
#ifdef	DEBUG
		/*
		 * Check to see if the content of the sensitive pages that we
		 * just copied have changed during this small time window.
		 */
		test_usum = checksum32(CPR->c_mapping_area, mmu_ptob(pages));
		descp->csd_usum = cpd.cpd_usum;
		if (test_usum != descp->csd_usum) {
			CPR_DEBUG(CPR_DEBUG1, "\nWARNING: "
			    "i_cpr_compress_and_save: "
			    "Data in the range of pfn 0x%lx to pfn "
			    "0x%lx has changed after they are saved "
			    "into storage.", spfn, (spfn + pages - 1));
		}
#endif
		error = ENOMEM;
	}

	i_cpr_mapout(CPR->c_mapping_area, pages);
	return (error);
}


/*
 * This routine is derived from cpr_count_kpages().
 * It goes through kernel data nucleus and segkmem segments to select
 * pages in use and mark them in the corresponding bitmap.
 */
pgcnt_t
i_cpr_count_sensitive_kpages(int mapflag, bitfunc_t bitfunc)
{
	pgcnt_t kdata_cnt = 0, segkmem_cnt = 0;
	extern caddr_t e_moddata;
	extern struct seg kvalloc;
	extern struct seg kmem64;
	size_t size;

	/*
	 * Kernel data nucleus pages
	 */
	size = e_moddata - s_data;
	kdata_cnt += cpr_count_pages(s_data, size,
	    mapflag, bitfunc, DBG_SHOWRANGE);

	/*
	 * kvseg and kvalloc pages
	 */
	segkmem_cnt += cpr_scan_kvseg(mapflag, bitfunc, &kvseg);
	segkmem_cnt += cpr_count_pages(kvalloc.s_base, kvalloc.s_size,
	    mapflag, bitfunc, DBG_SHOWRANGE);

	/* segment to support kernel memory usage above 32-bit space (4GB) */
	if (kmem64.s_base)
		segkmem_cnt += cpr_count_pages(kmem64.s_base, kmem64.s_size,
		    mapflag, bitfunc, DBG_SHOWRANGE);

	CPR_DEBUG(CPR_DEBUG7, "\ni_cpr_count_sensitive_kpages:\n"
	    "\tkdata_cnt %ld + segkmem_cnt %ld = %ld pages\n",
	    kdata_cnt, segkmem_cnt, kdata_cnt + segkmem_cnt);

	return (kdata_cnt + segkmem_cnt);
}


pgcnt_t
i_cpr_count_storage_pages(int mapflag, bitfunc_t bitfunc)
{
	pgcnt_t count = 0;

	if (i_cpr_storage_desc_base) {
		count += cpr_count_pages((caddr_t)i_cpr_storage_desc_base,
		    (size_t)mmu_ptob(i_cpr_storage_desc_pgcnt),
		    mapflag, bitfunc, DBG_SHOWRANGE);
	}
	if (i_cpr_storage_data_base) {
		count += cpr_count_pages(i_cpr_storage_data_base,
		    (size_t)mmu_ptob(i_cpr_storage_data_sz),
		    mapflag, bitfunc, DBG_SHOWRANGE);
	}
	return (count);
}


/*
 * Derived from cpr_write_statefile().
 * Allocate (or reallocate after exhausting the supply) descriptors for each
 * chunk of contiguous sensitive kpages.
 */
static int
i_cpr_storage_desc_alloc(csd_t **basepp, pgcnt_t *pgsp, csd_t **endpp,
    int retry)
{
	pgcnt_t npages;
	int chunks;
	csd_t	*descp, *end;
	size_t	len;
	char *str = "i_cpr_storage_desc_alloc:";

	/*
	 * On initial allocation, add some extra to cover overhead caused
	 * by the allocation for the storage area later.
	 */
	if (retry == 0) {
		chunks = cpr_contig_pages(NULL, STORAGE_DESC_ALLOC) +
		    EXTRA_DESCS;
		npages = mmu_btopr(sizeof (**basepp) * (pgcnt_t)chunks);
		CPR_DEBUG(CPR_DEBUG7, "%s chunks %d, ", str, chunks);
	} else {
		CPR_DEBUG(CPR_DEBUG7, "%s retry %d: ", str, retry);
		npages = *pgsp + 1;
	}
	/* Free old descriptors, if any */
	if (*basepp)
		kmem_free((caddr_t)*basepp, mmu_ptob(*pgsp));

	descp = *basepp = kmem_alloc(mmu_ptob(npages), KM_NOSLEEP);
	if (descp == NULL) {
		CPR_DEBUG(CPR_DEBUG7, "%s no space for descriptors!\n", str);
		return (ENOMEM);
	}

	*pgsp = npages;
	len = mmu_ptob(npages);
	end = *endpp = descp + (len / (sizeof (**basepp)));
	CPR_DEBUG(CPR_DEBUG7, "npages 0x%lx, len 0x%lx, items 0x%lx\n\t*basepp "
	    "%p, *endpp %p\n", npages, len, (len / (sizeof (**basepp))),
	    (void *)*basepp, (void *)*endpp);
	i_cpr_storage_desc_init(descp, npages, end);
	return (0);
}

static void
i_cpr_storage_desc_init(csd_t *descp, pgcnt_t npages, csd_t *end)
{
	size_t	len = mmu_ptob(npages);

	/* Initialize the descriptors to something impossible. */
	bzero(descp, len);
#ifdef	DEBUG
	/*
	 * This condition is tested by an ASSERT
	 */
	for (; descp < end; descp++)
		descp->csd_dirty_spfn = (uint_t)-1;
#endif
}

int
i_cpr_dump_sensitive_kpages(vnode_t *vp)
{
	int	error = 0;
	uint_t	spin_cnt = 0;
	csd_t	*descp;

	/*
	 * These following two variables need to be reinitialized
	 * for each cpr cycle.
	 */
	i_cpr_sensitive_bytes_dumped = 0;
	i_cpr_sensitive_pgs_dumped = 0;

	if (i_cpr_storage_desc_base) {
		for (descp = i_cpr_storage_desc_base;
		    descp <= i_cpr_storage_desc_last_used; descp++) {
			if (error = cpr_dump_sensitive(vp, descp))
				return (error);
			spin_cnt++;
			if ((spin_cnt & 0x5F) == 1)
				cpr_spinning_bar();
		}
		prom_printf(" \b");
	}

	CPR_DEBUG(CPR_DEBUG7, "\ni_cpr_dump_sensitive_kpages: dumped %ld\n",
	    i_cpr_sensitive_pgs_dumped);
	return (0);
}


/*
 * 1. Fill the cpr page descriptor with the info of the dirty pages
 *    and
 *    write the descriptor out. It will be used at resume.
 * 2. Write the clean data in stead of the dirty data out.
 *    Note: to save space, the clean data is already compressed.
 */
static int
cpr_dump_sensitive(vnode_t *vp, csd_t *descp)
{
	int error = 0;
	caddr_t datap;
	cpd_t cpd;	/* cpr page descriptor */
	pfn_t	dirty_spfn;
	pgcnt_t dirty_npages;
	size_t clean_sz;
	caddr_t	clean_sva;
	int	clean_compressed;
	extern uchar_t cpr_pagecopy[];

	dirty_spfn = descp->csd_dirty_spfn;
	dirty_npages = descp->csd_dirty_npages;
	clean_sva = (caddr_t)descp->csd_clean_sva;
	clean_sz = descp->csd_clean_sz;
	clean_compressed = descp->csd_clean_compressed;

	/* Fill cpr page descriptor. */
	cpd.cpd_magic = (uint_t)CPR_PAGE_MAGIC;
	cpd.cpd_pfn = dirty_spfn;
	cpd.cpd_flag = 0;  /* must init to zero */
	cpd.cpd_pages = dirty_npages;

#ifdef	DEBUG
	if ((cpd.cpd_usum = descp->csd_usum) != 0)
		cpd.cpd_flag |= CPD_USUM;
	if ((cpd.cpd_csum = descp->csd_csum) != 0)
		cpd.cpd_flag |= CPD_CSUM;
#endif

	STAT->cs_dumped_statefsz += mmu_ptob(dirty_npages);

	/*
	 * The sensitive kpages are usually saved with compression
	 * unless compression could not reduce the size of the data.
	 * If user choose not to have the statefile compressed,
	 * we need to decompress the data back before dumping it to disk.
	 */
	if (CPR->c_flags & C_COMPRESSING) {
		cpd.cpd_length = clean_sz;
		datap = clean_sva;
		if (clean_compressed)
			cpd.cpd_flag |= CPD_COMPRESS;
	} else {
		if (clean_compressed) {
			cpd.cpd_length = decompress(clean_sva, cpr_pagecopy,
			    clean_sz, mmu_ptob(dirty_npages));
			datap = (caddr_t)cpr_pagecopy;
			ASSERT(cpd.cpd_length == mmu_ptob(dirty_npages));
		} else {
			cpd.cpd_length = clean_sz;
			datap = clean_sva;
		}
		cpd.cpd_csum = 0;
	}

	/* Write cpr page descriptor */
	error = cpr_write(vp, (caddr_t)&cpd, sizeof (cpd));
	if (error) {
		CPR_DEBUG(CPR_DEBUG7, "descp: %p\n", (void *)descp);
#ifdef DEBUG
		debug_enter("cpr_dump_sensitive: cpr_write() page "
		    "descriptor failed!\n");
#endif
		return (error);
	}

	i_cpr_sensitive_bytes_dumped += sizeof (cpd_t);

	/* Write page data */
	error = cpr_write(vp, (caddr_t)datap, cpd.cpd_length);
	if (error) {
		CPR_DEBUG(CPR_DEBUG7, "error: %x\n", error);
		CPR_DEBUG(CPR_DEBUG7, "descp: %p\n", (void *)descp);
		CPR_DEBUG(CPR_DEBUG7, "cpr_write(%p, %p , %lx)\n",
		    (void *)vp, (void *)datap, cpd.cpd_length);
#ifdef DEBUG
		debug_enter("cpr_dump_sensitive: cpr_write() data failed!\n");
#endif
		return (error);
	}

	i_cpr_sensitive_bytes_dumped += cpd.cpd_length;
	i_cpr_sensitive_pgs_dumped += dirty_npages;

	return (error);
}


/*
 * Sanity check to make sure that we have dumped right amount
 * of pages from different sources to statefile.
 */
int
i_cpr_check_pgs_dumped(uint_t pgs_expected, uint_t regular_pgs_dumped)
{
	uint_t total_pgs_dumped;

	total_pgs_dumped = regular_pgs_dumped + i_cpr_sensitive_pgs_dumped;

	CPR_DEBUG(CPR_DEBUG7, "\ncheck_pgs: reg %d + sens %ld = %d, "
	    "expect %d\n\n", regular_pgs_dumped, i_cpr_sensitive_pgs_dumped,
	    total_pgs_dumped, pgs_expected);

	if (pgs_expected == total_pgs_dumped)
		return (0);

	return (EINVAL);
}


int
i_cpr_reusefini(void)
{
	struct vnode *vp;
	cdef_t *cdef;
	size_t size;
	char *bufp;
	int rc;

	if (cpr_reusable_mode)
		cpr_reusable_mode = 0;

	if (rc = cpr_open_deffile(FREAD|FWRITE, &vp)) {
		if (rc == EROFS) {
			cpr_err(CE_CONT, "uadmin A_FREEZE AD_REUSEFINI "
			    "(uadmin %d %d)\nmust be done with / mounted "
			    "writeable.\n", A_FREEZE, AD_REUSEFINI);
		}
		return (rc);
	}

	cdef = kmem_alloc(sizeof (*cdef), KM_SLEEP);
	rc = cpr_rdwr(UIO_READ, vp, cdef, sizeof (*cdef));

	if (rc) {
		cpr_err(CE_WARN, "Failed reading %s, errno = %d",
		    cpr_default_path, rc);
	} else if (cdef->mini.magic != CPR_DEFAULT_MAGIC) {
		cpr_err(CE_WARN, "bad magic number in %s, cannot restore "
		    "prom values for %s", cpr_default_path,
		    cpr_enumerate_promprops(&bufp, &size));
		kmem_free(bufp, size);
		rc = EINVAL;
	} else {
		/*
		 * clean up prom properties
		 */
		rc = cpr_update_nvram(cdef->props);
		if (rc == 0) {
			/*
			 * invalidate the disk copy and turn off reusable
			 */
			cdef->mini.magic = 0;
			cdef->mini.reusable = 0;
			if (rc = cpr_rdwr(UIO_WRITE, vp,
			    &cdef->mini, sizeof (cdef->mini))) {
				cpr_err(CE_WARN, "Failed writing %s, errno %d",
				    cpr_default_path, rc);
			}
		}
	}

	(void) VOP_CLOSE(vp, FREAD|FWRITE, 1, (offset_t)0, CRED(), NULL);
	VN_RELE(vp);
	kmem_free(cdef, sizeof (*cdef));

	return (rc);
}


int
i_cpr_reuseinit(void)
{
	int rc = 0;

	if (rc = cpr_default_setup(1))
		return (rc);

	/*
	 * We need to validate default file
	 */
	rc = cpr_validate_definfo(1);
	if (rc == 0)
		cpr_reusable_mode = 1;
	else if (rc == EROFS) {
		cpr_err(CE_NOTE, "reuseinit must be performed "
		    "while / is mounted writeable");
	}

	(void) cpr_default_setup(0);

	return (rc);
}


int
i_cpr_check_cprinfo(void)
{
	struct vnode *vp;
	cmini_t mini;
	int rc = 0;

	if (rc = cpr_open_deffile(FREAD, &vp)) {
		if (rc == ENOENT)
			cpr_err(CE_NOTE, "cprinfo file does not "
			    "exist.  You must run 'uadmin %d %d' "
			    "command while / is mounted writeable,\n"
			    "then reboot and run 'uadmin %d %d' "
			    "to create a reusable statefile",
			    A_FREEZE, AD_REUSEINIT, A_FREEZE, AD_REUSABLE);
		return (rc);
	}

	rc = cpr_rdwr(UIO_READ, vp, &mini, sizeof (mini));
	(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED(), NULL);
	VN_RELE(vp);

	if (rc) {
		cpr_err(CE_WARN, "Failed reading %s, errno = %d",
		    cpr_default_path, rc);
	} else if (mini.magic != CPR_DEFAULT_MAGIC) {
		cpr_err(CE_CONT, "bad magic number in cprinfo file.\n"
		    "You must run 'uadmin %d %d' while / is mounted "
		    "writeable, then reboot and run 'uadmin %d %d' "
		    "to create a reusable statefile\n",
		    A_FREEZE, AD_REUSEINIT, A_FREEZE, AD_REUSABLE);
		rc = EINVAL;
	}

	return (rc);
}


int
i_cpr_reusable_supported(void)
{
	return (1);
}


/*
 * find prom phys pages and alloc space for a tmp copy
 */
static int
i_cpr_find_ppages(void)
{
	struct page *pp;
	struct memlist *pmem;
	pgcnt_t npages, pcnt, scnt, vcnt;
	pfn_t ppn, plast, *dst;
	int mapflag;

	cpr_clear_bitmaps();
	mapflag = REGULAR_BITMAP;

	/*
	 * there should be a page_t for each phys page used by the kernel;
	 * set a bit for each phys page not tracked by a page_t
	 */
	pcnt = 0;
	memlist_read_lock();
	for (pmem = phys_install; pmem; pmem = pmem->ml_next) {
		npages = mmu_btop(pmem->ml_size);
		ppn = mmu_btop(pmem->ml_address);
		for (plast = ppn + npages; ppn < plast; ppn++) {
			if (page_numtopp_nolock(ppn))
				continue;
			(void) cpr_setbit(ppn, mapflag);
			pcnt++;
		}
	}
	memlist_read_unlock();

	/*
	 * clear bits for phys pages in each segment
	 */
	scnt = cpr_count_seg_pages(mapflag, cpr_clrbit);

	/*
	 * set bits for phys pages referenced by the promvp vnode;
	 * these pages are mostly comprised of forthdebug words
	 */
	vcnt = 0;
	for (pp = promvp.v_pages; pp; ) {
		if (cpr_setbit(pp->p_offset, mapflag) == 0)
			vcnt++;
		pp = pp->p_vpnext;
		if (pp == promvp.v_pages)
			break;
	}

	/*
	 * total number of prom pages are:
	 * (non-page_t pages - seg pages + vnode pages)
	 */
	ppage_count = pcnt - scnt + vcnt;
	CPR_DEBUG(CPR_DEBUG1,
	    "find_ppages: pcnt %ld - scnt %ld + vcnt %ld = %ld\n",
	    pcnt, scnt, vcnt, ppage_count);

	/*
	 * alloc array of pfn_t to store phys page list
	 */
	pphys_list_size = ppage_count * sizeof (pfn_t);
	pphys_list = kmem_alloc(pphys_list_size, KM_NOSLEEP);
	if (pphys_list == NULL) {
		cpr_err(CE_WARN, "cannot alloc pphys_list");
		return (ENOMEM);
	}

	/*
	 * phys pages referenced in the bitmap should be
	 * those used by the prom; scan bitmap and save
	 * a list of prom phys page numbers
	 */
	dst = pphys_list;
	memlist_read_lock();
	for (pmem = phys_install; pmem; pmem = pmem->ml_next) {
		npages = mmu_btop(pmem->ml_size);
		ppn = mmu_btop(pmem->ml_address);
		for (plast = ppn + npages; ppn < plast; ppn++) {
			if (cpr_isset(ppn, mapflag)) {
				ASSERT(dst < (pphys_list + ppage_count));
				*dst++ = ppn;
			}
		}
	}
	memlist_read_unlock();

	/*
	 * allocate space to store prom pages
	 */
	ppage_buf = kmem_alloc(mmu_ptob(ppage_count), KM_NOSLEEP);
	if (ppage_buf == NULL) {
		kmem_free(pphys_list, pphys_list_size);
		pphys_list = NULL;
		cpr_err(CE_WARN, "cannot alloc ppage_buf");
		return (ENOMEM);
	}

	return (0);
}


/*
 * save prom pages to kmem pages
 */
static void
i_cpr_save_ppages(void)
{
	pfn_t *pphys, *plast;
	caddr_t dst;

	/*
	 * map in each prom page and copy to a kmem page
	 */
	dst = ppage_buf;
	plast = pphys_list + ppage_count;
	for (pphys = pphys_list; pphys < plast; pphys++) {
		i_cpr_mapin(cpr_vaddr, 1, *pphys);
		bcopy(cpr_vaddr, dst, MMU_PAGESIZE);
		i_cpr_mapout(cpr_vaddr, 1);
		dst += MMU_PAGESIZE;
	}

	CPR_DEBUG(CPR_DEBUG1, "saved %ld prom pages\n", ppage_count);
}


/*
 * restore prom pages from kmem pages
 */
static void
i_cpr_restore_ppages(void)
{
	pfn_t *pphys, *plast;
	caddr_t src;

	dcache_flushall();

	/*
	 * map in each prom page and copy from a kmem page
	 */
	src = ppage_buf;
	plast = pphys_list + ppage_count;
	for (pphys = pphys_list; pphys < plast; pphys++) {
		i_cpr_mapin(cpr_vaddr, 1, *pphys);
		bcopy(src, cpr_vaddr, MMU_PAGESIZE);
		i_cpr_mapout(cpr_vaddr, 1);
		src += MMU_PAGESIZE;
	}

	dcache_flushall();

	CPR_DEBUG(CPR_DEBUG1, "restored %ld prom pages\n", ppage_count);
}


/*
 * save/restore prom pages or free related allocs
 */
int
i_cpr_prom_pages(int action)
{
	int error;

	if (action == CPR_PROM_SAVE) {
		if (ppage_buf == NULL) {
			ASSERT(pphys_list == NULL);
			if (error = i_cpr_find_ppages())
				return (error);
			i_cpr_save_ppages();
		}
	} else if (action == CPR_PROM_RESTORE) {
		i_cpr_restore_ppages();
	} else if (action == CPR_PROM_FREE) {
		if (pphys_list) {
			ASSERT(pphys_list_size);
			kmem_free(pphys_list, pphys_list_size);
			pphys_list = NULL;
			pphys_list_size = 0;
		}
		if (ppage_buf) {
			ASSERT(ppage_count);
			kmem_free(ppage_buf, mmu_ptob(ppage_count));
			CPR_DEBUG(CPR_DEBUG1, "freed %ld prom pages\n",
			    ppage_count);
			ppage_buf = NULL;
			ppage_count = 0;
		}
	}
	return (0);
}


/*
 * record tlb data for the nucleus, bigktsb's, and the cpr module;
 * this data is later used by cprboot to install dtlb/itlb entries.
 * when we jump into the cpr module during the resume phase, those
 * mappings are needed until switching to the kernel trap table.
 * to make the dtte/itte info available during resume, we need
 * the info recorded prior to saving sensitive pages, otherwise
 * all the data would appear as NULLs.
 */
static void
i_cpr_save_tlbinfo(void)
{
	cti_t cti = {0};

	/*
	 * during resume - shortly after jumping into the cpr module,
	 * sfmmu_load_mmustate() will overwrite any dtlb entry at any
	 * index used for TSBs; skip is set so that any saved tte will
	 * target other tlb offsets and prevent being lost during
	 * resume.  now scan the dtlb and save locked entries,
	 * then add entries for the tmp stack / data page and the
	 * cpr thread structure.
	 */
	cti.dst = m_info.dtte;
	cti.tail = cti.dst + CPR_MAX_TLB;
	cti.reader = dtlb_rd_entry;
	cti.writer = NULL;
	cti.filter = i_cpr_lnb;
	cti.index = cpunodes[CPU->cpu_id].dtlb_size - 1;

	if (utsb_dtlb_ttenum != -1)
		cti.skip = (1 << utsb_dtlb_ttenum);

	if (utsb4m_dtlb_ttenum != -1)
		cti.skip |= (1 << utsb4m_dtlb_ttenum);

	i_cpr_scan_tlb(&cti);
	i_cpr_make_tte(&cti, &i_cpr_data_page, datava);
	i_cpr_make_tte(&cti, curthread, datava);

	/*
	 * scan itlb and save locked entries; add an entry for
	 * the first text page of the cpr module; cprboot will
	 * jump to that page after restoring kernel pages.
	 */
	cti.dst = m_info.itte;
	cti.tail = cti.dst + CPR_MAX_TLB;
	cti.reader = itlb_rd_entry;
	cti.index = cpunodes[CPU->cpu_id].itlb_size - 1;
	cti.skip = 0;
	i_cpr_scan_tlb(&cti);
	i_cpr_make_tte(&cti, (void *)i_cpr_resume_setup, textva);
}


/* ARGSUSED */
int
i_cpr_dump_setup(vnode_t *vp)
{
	/*
	 * zero out m_info and add info to dtte/itte arrays
	 */
	bzero(&m_info, sizeof (m_info));
	i_cpr_save_tlbinfo();
	return (0);
}


int
i_cpr_is_supported(int sleeptype)
{
	char es_prop[] = "energystar-v2";
	pnode_t node;
	int last;
	extern int cpr_supported_override;
	extern int cpr_platform_enable;

	if (sleeptype != CPR_TODISK)
		return (0);

	/*
	 * The next statement tests if a specific platform has turned off
	 * cpr support.
	 */
	if (cpr_supported_override)
		return (0);

	/*
	 * Do not inspect energystar-v* property if a platform has
	 * specifically turned on cpr support
	 */
	if (cpr_platform_enable)
		return (1);

	node = prom_rootnode();
	if (prom_getproplen(node, es_prop) != -1)
		return (1);
	last = strlen(es_prop) - 1;
	es_prop[last] = '3';
	return (prom_getproplen(node, es_prop) != -1);
}


/*
 * the actual size of the statefile data isn't known until after all the
 * compressed pages are written; even the inode size doesn't reflect the
 * data size since there are usually many extra fs blocks.  for recording
 * the actual data size, the first sector of the statefile is copied to
 * a tmp buf, and the copy is later updated and flushed to disk.
 */
int
i_cpr_blockzero(char *base, char **bufpp, int *blkno, vnode_t *vp)
{
	extern int cpr_flush_write(vnode_t *);
	static char cpr_sector[DEV_BSIZE];
	cpr_ext bytes, *dst;

	/*
	 * this routine is called after cdd_t and csu_md_t are copied
	 * to cpr_buf; mini-hack alert: the save/update method creates
	 * a dependency on the combined struct size being >= one sector
	 * or DEV_BSIZE; since introduction in Sol2.7, csu_md_t size is
	 * over 1K bytes and will probably grow with any changes.
	 *
	 * copy when vp is NULL, flush when non-NULL
	 */
	if (vp == NULL) {
		ASSERT((*bufpp - base) >= DEV_BSIZE);
		bcopy(base, cpr_sector, sizeof (cpr_sector));
		return (0);
	} else {
		bytes = dbtob(*blkno);
		dst = &((cdd_t *)cpr_sector)->cdd_filesize;
		bcopy(&bytes, dst, sizeof (bytes));
		bcopy(cpr_sector, base, sizeof (cpr_sector));
		*bufpp = base + sizeof (cpr_sector);
		*blkno = cpr_statefile_offset();
		CPR_DEBUG(CPR_DEBUG1, "statefile data size: %ld\n\n", bytes);
		return (cpr_flush_write(vp));
	}
}


/*
 * Allocate bitmaps according to the phys_install list.
 */
static int
i_cpr_bitmap_setup(void)
{
	struct memlist *pmem;
	cbd_t *dp, *tail;
	void *space;
	size_t size;

	/*
	 * The number of bitmap descriptors will be the count of
	 * phys_install ranges plus 1 for a trailing NULL struct.
	 */
	cpr_nbitmaps = 1;
	for (pmem = phys_install; pmem; pmem = pmem->ml_next)
		cpr_nbitmaps++;

	if (cpr_nbitmaps > (CPR_MAX_BMDESC - 1)) {
		cpr_err(CE_WARN, "too many physical memory ranges %d, max %d",
		    cpr_nbitmaps, CPR_MAX_BMDESC - 1);
		return (EFBIG);
	}

	/* Alloc an array of bitmap descriptors. */
	dp = kmem_zalloc(cpr_nbitmaps * sizeof (*dp), KM_NOSLEEP);
	if (dp == NULL) {
		cpr_nbitmaps = 0;
		return (ENOMEM);
	}
	tail = dp + cpr_nbitmaps;

	CPR->c_bmda = dp;
	for (pmem = phys_install; pmem; pmem = pmem->ml_next) {
		size = BITMAP_BYTES(pmem->ml_size);
		space = kmem_zalloc(size * 2, KM_NOSLEEP);
		if (space == NULL)
			return (ENOMEM);
		ASSERT(dp < tail);
		dp->cbd_magic = CPR_BITMAP_MAGIC;
		dp->cbd_spfn = mmu_btop(pmem->ml_address);
		dp->cbd_epfn = mmu_btop(pmem->ml_address + pmem->ml_size) - 1;
		dp->cbd_size = size;
		dp->cbd_reg_bitmap = (cpr_ptr)space;
		dp->cbd_vlt_bitmap = (cpr_ptr)((caddr_t)space + size);
		dp++;
	}

	/* set magic for the last descriptor */
	ASSERT(dp == (tail - 1));
	dp->cbd_magic = CPR_BITMAP_MAGIC;

	return (0);
}


void
i_cpr_bitmap_cleanup(void)
{
	cbd_t *dp;

	if (CPR->c_bmda == NULL)
		return;
	for (dp = CPR->c_bmda; dp->cbd_size; dp++)
		kmem_free((void *)dp->cbd_reg_bitmap, dp->cbd_size * 2);
	kmem_free(CPR->c_bmda, cpr_nbitmaps * sizeof (*CPR->c_bmda));
	CPR->c_bmda = NULL;
	cpr_nbitmaps = 0;
}


/*
 * A "regular" and "volatile" bitmap are created for each range of
 * physical memory.  The volatile maps are used to count and track pages
 * susceptible to heap corruption - caused by drivers that allocate mem
 * during VOP_DUMP(); the regular maps are used for all the other non-
 * susceptible pages.  Before writing the bitmaps to the statefile,
 * each bitmap pair gets merged to simplify handling within cprboot.
 */
int
i_cpr_alloc_bitmaps(void)
{
	int err;

	memlist_read_lock();
	err = i_cpr_bitmap_setup();
	memlist_read_unlock();
	if (err)
		i_cpr_bitmap_cleanup();
	return (err);
}



/*
 * Power down the system.
 */
int
i_cpr_power_down(int sleeptype)
{
	int is_defined = 0;
	char *wordexists = "p\" power-off\" find nip swap l! ";
	char *req = "power-off";

	ASSERT(sleeptype == CPR_TODISK);

	/*
	 * is_defined has value -1 when defined
	 */
	prom_interpret(wordexists, (uintptr_t)&is_defined, 0, 0, 0, 0);
	if (is_defined) {
		CPR_DEBUG(CPR_DEBUG1, "\ncpr: %s...\n", req);
		prom_interpret(req, 0, 0, 0, 0, 0);
	}
	/*
	 * Only returns if failed
	 */
	return (EIO);
}

void
i_cpr_stop_other_cpus(void)
{
	stop_other_cpus();
}

/*
 *	Save context for the specified CPU
 */
/* ARGSUSED */
void *
i_cpr_save_context(void *arg)
{
	/*
	 * Not yet
	 */
	ASSERT(0);
	return (NULL);
}

void
i_cpr_pre_resume_cpus(void)
{
	/*
	 * Not yet
	 */
	ASSERT(0);
}

void
i_cpr_post_resume_cpus(void)
{
	/*
	 * Not yet
	 */
	ASSERT(0);
}

/*
 * nothing to do
 */
void
i_cpr_alloc_cpus(void)
{
}

/*
 * nothing to do
 */
void
i_cpr_free_cpus(void)
{
}

/* ARGSUSED */
void
i_cpr_save_configuration(dev_info_t *dip)
{
	/*
	 * this is a no-op on sparc
	 */
}

/* ARGSUSED */
void
i_cpr_restore_configuration(dev_info_t *dip)
{
	/*
	 * this is a no-op on sparc
	 */
}

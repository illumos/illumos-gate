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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc. */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T   */
/*	All Rights Reserved   */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/signal.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/class.h>
#include <sys/proc.h>
#include <sys/procfs.h>
#include <sys/buf.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/archsystm.h>
#include <sys/vmparam.h>
#include <sys/prsystm.h>
#include <sys/reboot.h>
#include <sys/uadmin.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/session.h>
#include <sys/ucontext.h>
#include <sys/dnlc.h>
#include <sys/var.h>
#include <sys/cmn_err.h>
#include <sys/debugreg.h>
#include <sys/thread.h>
#include <sys/vtrace.h>
#include <sys/consdev.h>
#include <sys/psw.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/cpu.h>
#include <sys/stack.h>
#include <sys/swap.h>
#include <vm/hat.h>
#include <vm/anon.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/seg.h>
#include <vm/seg_kmem.h>
#include <vm/seg_map.h>
#include <vm/seg_vn.h>
#include <sys/exec.h>
#include <sys/acct.h>
#include <sys/core.h>
#include <sys/corectl.h>
#include <sys/modctl.h>
#include <sys/tuneable.h>
#include <c2/audit.h>
#include <sys/bootconf.h>
#include <sys/brand.h>
#include <sys/dumphdr.h>
#include <sys/promif.h>
#include <sys/systeminfo.h>
#include <sys/kdi.h>
#include <sys/contract_impl.h>
#include <sys/x86_archext.h>
#include <sys/segments.h>
#include <sys/ontrap.h>
#include <sys/cpu.h>
#ifdef __xpv
#include <sys/hypervisor.h>
#endif

/*
 * Compare the version of boot that boot says it is against
 * the version of boot the kernel expects.
 */
int
check_boot_version(int boots_version)
{
	if (boots_version == BO_VERSION)
		return (0);

	prom_printf("Wrong boot interface - kernel needs v%d found v%d\n",
	    BO_VERSION, boots_version);
	prom_panic("halting");
	/*NOTREACHED*/
}

/*
 * Process the physical installed list for boot.
 * Finds:
 * 1) the pfn of the highest installed physical page,
 * 2) the number of pages installed
 * 3) the number of distinct contiguous regions these pages fall into.
 * 4) the number of contiguous memory ranges
 */
void
installed_top_size_ex(
	struct memlist *list,	/* pointer to start of installed list */
	pfn_t *high_pfn,	/* return ptr for top value */
	pgcnt_t *pgcnt,		/* return ptr for sum of installed pages */
	int	*ranges)	/* return ptr for the count of contig. ranges */
{
	pfn_t top = 0;
	pgcnt_t sumpages = 0;
	pfn_t highp;		/* high page in a chunk */
	int cnt = 0;

	for (; list; list = list->ml_next) {
		++cnt;
		highp = (list->ml_address + list->ml_size - 1) >> PAGESHIFT;
		if (top < highp)
			top = highp;
		sumpages += btop(list->ml_size);
	}

	*high_pfn = top;
	*pgcnt = sumpages;
	*ranges = cnt;
}

void
installed_top_size(
	struct memlist *list,	/* pointer to start of installed list */
	pfn_t *high_pfn,	/* return ptr for top value */
	pgcnt_t *pgcnt)		/* return ptr for sum of installed pages */
{
	int ranges;

	installed_top_size_ex(list, high_pfn, pgcnt, &ranges);
}

void
phys_install_has_changed(void)
{}

/*
 * Copy in a memory list from boot to kernel, with a filter function
 * to remove pages. The filter function can increase the address and/or
 * decrease the size to filter out pages.  It will also align addresses and
 * sizes to PAGESIZE.
 */
void
copy_memlist_filter(
	struct memlist *src,
	struct memlist **dstp,
	void (*filter)(uint64_t *, uint64_t *))
{
	struct memlist *dst, *prev;
	uint64_t addr;
	uint64_t size;
	uint64_t eaddr;

	dst = *dstp;
	prev = dst;

	/*
	 * Move through the memlist applying a filter against
	 * each range of memory. Note that we may apply the
	 * filter multiple times against each memlist entry.
	 */
	for (; src; src = src->ml_next) {
		addr = P2ROUNDUP(src->ml_address, PAGESIZE);
		eaddr = P2ALIGN(src->ml_address + src->ml_size, PAGESIZE);
		while (addr < eaddr) {
			size = eaddr - addr;
			if (filter != NULL)
				filter(&addr, &size);
			if (size == 0)
				break;
			dst->ml_address = addr;
			dst->ml_size = size;
			dst->ml_next = 0;
			if (prev == dst) {
				dst->ml_prev = 0;
				dst++;
			} else {
				dst->ml_prev = prev;
				prev->ml_next = dst;
				dst++;
				prev++;
			}
			addr += size;
		}
	}

	*dstp = dst;
}

/*
 * Kernel setup code, called from startup().
 */
void
kern_setup1(void)
{
	proc_t *pp;

	pp = &p0;

	proc_sched = pp;

	/*
	 * Initialize process 0 data structures
	 */
	pp->p_stat = SRUN;
	pp->p_flag = SSYS;

	pp->p_pidp = &pid0;
	pp->p_pgidp = &pid0;
	pp->p_sessp = &session0;
	pp->p_tlist = &t0;
	pid0.pid_pglink = pp;
	pid0.pid_pgtail = pp;

	/*
	 * XXX - we asssume that the u-area is zeroed out except for
	 * ttolwp(curthread)->lwp_regs.
	 */
	PTOU(curproc)->u_cmask = (mode_t)CMASK;

	thread_init();		/* init thread_free list */
	pid_init();		/* initialize pid (proc) table */
	contract_init();	/* initialize contracts */

	init_pages_pp_maximum();
}

/*
 * Load a procedure into a thread.
 */
void
thread_load(kthread_t *t, void (*start)(), caddr_t arg, size_t len)
{
	caddr_t sp;
	size_t framesz;
	caddr_t argp;
	long *p;
	extern void thread_start();

	/*
	 * Push a "c" call frame onto the stack to represent
	 * the caller of "start".
	 */
	sp = t->t_stk;
	ASSERT(((uintptr_t)t->t_stk & (STACK_ENTRY_ALIGN - 1)) == 0);
	if (len != 0) {
		/*
		 * the object that arg points at is copied into the
		 * caller's frame.
		 */
		framesz = SA(len);
		sp -= framesz;
		ASSERT(sp > t->t_stkbase);
		argp = sp + SA(MINFRAME);
		bcopy(arg, argp, len);
		arg = argp;
	}
	/*
	 * Set up arguments (arg and len) on the caller's stack frame.
	 */
	p = (long *)sp;

	*--p = 0;		/* fake call */
	*--p = 0;		/* null frame pointer terminates stack trace */
	*--p = (long)len;
	*--p = (intptr_t)arg;
	*--p = (intptr_t)start;

	/*
	 * initialize thread to resume at thread_start() which will
	 * turn around and invoke (*start)(arg, len).
	 */
	t->t_pc = (uintptr_t)thread_start;
	t->t_sp = (uintptr_t)p;

	ASSERT((t->t_sp & (STACK_ENTRY_ALIGN - 1)) == 0);
}

/*
 * load user registers into lwp.
 */
/*ARGSUSED2*/
void
lwp_load(klwp_t *lwp, gregset_t grp, uintptr_t thrptr)
{
	struct regs *rp = lwptoregs(lwp);

	setgregs(lwp, grp);
	rp->r_ps = PSL_USER;

	/*
	 * For 64-bit lwps, we allow one magic %fs selector value, and one
	 * magic %gs selector to point anywhere in the address space using
	 * %fsbase and %gsbase behind the scenes.  libc uses %fs to point
	 * at the ulwp_t structure.
	 *
	 * For 32-bit lwps, libc wedges its lwp thread pointer into the
	 * ucontext ESP slot (which is otherwise irrelevant to setting a
	 * ucontext) and LWPGS_SEL value into gregs[REG_GS].  This is so
	 * syslwp_create() can atomically setup %gs.
	 *
	 * See setup_context() in libc.
	 */
#ifdef _SYSCALL32_IMPL
	if (lwp_getdatamodel(lwp) == DATAMODEL_ILP32) {
		if (grp[REG_GS] == LWPGS_SEL)
			(void) lwp_setprivate(lwp, _LWP_GSBASE, thrptr);
	} else {
		/*
		 * See lwp_setprivate in kernel and setup_context in libc.
		 *
		 * Currently libc constructs a ucontext from whole cloth for
		 * every new (not main) lwp created.  For 64 bit processes
		 * %fsbase is directly set to point to current thread pointer.
		 * In the past (solaris 10) %fs was also set LWPFS_SEL to
		 * indicate %fsbase. Now we use the null GDT selector for
		 * this purpose. LWP[FS|GS]_SEL are only intended for 32 bit
		 * processes. To ease transition we support older libcs in
		 * the newer kernel by forcing %fs or %gs selector to null
		 * by calling lwp_setprivate if LWP[FS|GS]_SEL is passed in
		 * the ucontext.  This is should be ripped out at some future
		 * date.  Another fix would be for libc to do a getcontext
		 * and inherit the null %fs/%gs from the current context but
		 * that means an extra system call and could hurt performance.
		 */
		if (grp[REG_FS] == 0x1bb) /* hard code legacy LWPFS_SEL */
			(void) lwp_setprivate(lwp, _LWP_FSBASE,
			    (uintptr_t)grp[REG_FSBASE]);

		if (grp[REG_GS] == 0x1c3) /* hard code legacy LWPGS_SEL */
			(void) lwp_setprivate(lwp, _LWP_GSBASE,
			    (uintptr_t)grp[REG_GSBASE]);
	}
#else
	if (grp[GS] == LWPGS_SEL)
		(void) lwp_setprivate(lwp, _LWP_GSBASE, thrptr);
#endif

	lwp->lwp_eosys = JUSTRETURN;
	lwptot(lwp)->t_post_sys = 1;
}

/*
 * set syscall()'s return values for a lwp.
 */
void
lwp_setrval(klwp_t *lwp, int v1, int v2)
{
	lwptoregs(lwp)->r_ps &= ~PS_C;
	lwptoregs(lwp)->r_r0 = v1;
	lwptoregs(lwp)->r_r1 = v2;
}

/*
 * set syscall()'s return values for a lwp.
 */
void
lwp_setsp(klwp_t *lwp, caddr_t sp)
{
	lwptoregs(lwp)->r_sp = (intptr_t)sp;
}

/*
 * Copy regs from parent to child.
 */
void
lwp_forkregs(klwp_t *lwp, klwp_t *clwp)
{
#if defined(__amd64)
	struct pcb *pcb = &clwp->lwp_pcb;
	struct regs *rp = lwptoregs(lwp);

	if (pcb->pcb_rupdate == 0) {
		pcb->pcb_ds = rp->r_ds;
		pcb->pcb_es = rp->r_es;
		pcb->pcb_fs = rp->r_fs;
		pcb->pcb_gs = rp->r_gs;
		pcb->pcb_rupdate = 1;
		lwptot(clwp)->t_post_sys = 1;
	}
	ASSERT(lwptot(clwp)->t_post_sys);
#endif

	bcopy(lwp->lwp_regs, clwp->lwp_regs, sizeof (struct regs));
}

/*
 * This function is currently unused on x86.
 */
/*ARGSUSED*/
void
lwp_freeregs(klwp_t *lwp, int isexec)
{}

/*
 * This function is currently unused on x86.
 */
void
lwp_pcb_exit(void)
{}

/*
 * Lwp context ops for segment registers.
 */

/*
 * Every time we come into the kernel (syscall, interrupt or trap
 * but not fast-traps) we capture the current values of the user's
 * segment registers into the lwp's reg structure. This includes
 * lcall for i386 generic system call support since it is handled
 * as a segment-not-present trap.
 *
 * Here we save the current values from the lwp regs into the pcb
 * and set pcb->pcb_rupdate to 1 to tell the rest of the kernel
 * that the pcb copy of the segment registers is the current one.
 * This ensures the lwp's next trip to user land via update_sregs.
 * Finally we set t_post_sys to ensure that no system call fast-path's
 * its way out of the kernel via sysret.
 *
 * (This means that we need to have interrupts disabled when we test
 * t->t_post_sys in the syscall handlers; if the test fails, we need
 * to keep interrupts disabled until we return to userland so we can't
 * be switched away.)
 *
 * As a result of all this, we don't really have to do a whole lot if
 * the thread is just mucking about in the kernel, switching on and
 * off the cpu for whatever reason it feels like. And yet we still
 * preserve fast syscalls, cause if we -don't- get descheduled,
 * we never come here either.
 */

#define	VALID_LWP_DESC(udp) ((udp)->usd_type == SDT_MEMRWA && \
	    (udp)->usd_p == 1 && (udp)->usd_dpl == SEL_UPL)

/*ARGSUSED*/
void
lwp_segregs_save(klwp_t *lwp)
{
#if defined(__amd64)
	pcb_t *pcb = &lwp->lwp_pcb;
	struct regs *rp;

	ASSERT(VALID_LWP_DESC(&pcb->pcb_fsdesc));
	ASSERT(VALID_LWP_DESC(&pcb->pcb_gsdesc));

	if (pcb->pcb_rupdate == 0) {
		rp = lwptoregs(lwp);

		/*
		 * If there's no update already pending, capture the current
		 * %ds/%es/%fs/%gs values from lwp's regs in case the user
		 * changed them; %fsbase and %gsbase are privileged so the
		 * kernel versions of these registers in pcb_fsbase and
		 * pcb_gsbase are always up-to-date.
		 */
		pcb->pcb_ds = rp->r_ds;
		pcb->pcb_es = rp->r_es;
		pcb->pcb_fs = rp->r_fs;
		pcb->pcb_gs = rp->r_gs;
		pcb->pcb_rupdate = 1;
		lwp->lwp_thread->t_post_sys = 1;
	}
#endif	/* __amd64 */

#if !defined(__xpv)	/* XXPV not sure if we can re-read gdt? */
	ASSERT(bcmp(&CPU->cpu_gdt[GDT_LWPFS], &lwp->lwp_pcb.pcb_fsdesc,
	    sizeof (lwp->lwp_pcb.pcb_fsdesc)) == 0);
	ASSERT(bcmp(&CPU->cpu_gdt[GDT_LWPGS], &lwp->lwp_pcb.pcb_gsdesc,
	    sizeof (lwp->lwp_pcb.pcb_gsdesc)) == 0);
#endif
}

#if defined(__amd64)

/*
 * Update the segment registers with new values from the pcb.
 *
 * We have to do this carefully, and in the following order,
 * in case any of the selectors points at a bogus descriptor.
 * If they do, we'll catch trap with on_trap and return 1.
 * returns 0 on success.
 *
 * This is particularly tricky for %gs.
 * This routine must be executed under a cli.
 */
int
update_sregs(struct regs *rp,  klwp_t *lwp)
{
	pcb_t *pcb = &lwp->lwp_pcb;
	ulong_t	kgsbase;
	on_trap_data_t	otd;
	int rc = 0;

	if (!on_trap(&otd, OT_SEGMENT_ACCESS)) {

#if defined(__xpv)
		/*
		 * On the hyervisor this is easy. The hypercall below will
		 * swapgs and load %gs with the user selector. If the user
		 * selector is bad the hypervisor will catch the fault and
		 * load %gs with the null selector instead. Either way the
		 * kernel's gsbase is not damaged.
		 */
		kgsbase = (ulong_t)CPU;
		if (HYPERVISOR_set_segment_base(SEGBASE_GS_USER_SEL,
		    pcb->pcb_gs) != 0) {
				no_trap();
				return (1);
		}

		rp->r_gs = pcb->pcb_gs;
		ASSERT((cpu_t *)kgsbase == CPU);

#else	/* __xpv */

		/*
		 * A little more complicated running native.
		 */
		kgsbase = (ulong_t)CPU;
		__set_gs(pcb->pcb_gs);

		/*
		 * If __set_gs fails it's because the new %gs is a bad %gs,
		 * we'll be taking a trap but with the original %gs and %gsbase
		 * undamaged (i.e. pointing at curcpu).
		 *
		 * We've just mucked up the kernel's gsbase.  Oops.  In
		 * particular we can't take any traps at all.  Make the newly
		 * computed gsbase be the hidden gs via __swapgs, and fix
		 * the kernel's gsbase back again. Later, when we return to
		 * userland we'll swapgs again restoring gsbase just loaded
		 * above.
		 */
		__swapgs();
		rp->r_gs = pcb->pcb_gs;

		/*
		 * restore kernel's gsbase
		 */
		wrmsr(MSR_AMD_GSBASE, kgsbase);

#endif	/* __xpv */

		/*
		 * Only override the descriptor base address if
		 * r_gs == LWPGS_SEL or if r_gs == NULL. A note on
		 * NULL descriptors -- 32-bit programs take faults
		 * if they deference NULL descriptors; however,
		 * when 64-bit programs load them into %fs or %gs,
		 * they DONT fault -- only the base address remains
		 * whatever it was from the last load.   Urk.
		 *
		 * XXX - note that lwp_setprivate now sets %fs/%gs to the
		 * null selector for 64 bit processes. Whereas before
		 * %fs/%gs were set to LWP(FS|GS)_SEL regardless of
		 * the process's data model. For now we check for both
		 * values so that the kernel can also support the older
		 * libc. This should be ripped out at some point in the
		 * future.
		 */
		if (pcb->pcb_gs == LWPGS_SEL || pcb->pcb_gs == 0) {
#if defined(__xpv)
			if (HYPERVISOR_set_segment_base(SEGBASE_GS_USER,
			    pcb->pcb_gsbase)) {
				no_trap();
				return (1);
			}
#else
			wrmsr(MSR_AMD_KGSBASE, pcb->pcb_gsbase);
#endif
		}

		__set_ds(pcb->pcb_ds);
		rp->r_ds = pcb->pcb_ds;

		__set_es(pcb->pcb_es);
		rp->r_es = pcb->pcb_es;

		__set_fs(pcb->pcb_fs);
		rp->r_fs = pcb->pcb_fs;

		/*
		 * Same as for %gs
		 */
		if (pcb->pcb_fs == LWPFS_SEL || pcb->pcb_fs == 0) {
#if defined(__xpv)
			if (HYPERVISOR_set_segment_base(SEGBASE_FS,
			    pcb->pcb_fsbase)) {
				no_trap();
				return (1);
			}
#else
			wrmsr(MSR_AMD_FSBASE, pcb->pcb_fsbase);
#endif
		}

	} else {
		cli();
		rc = 1;
	}
	no_trap();
	return (rc);
}

/*
 * Make sure any stale selectors are cleared from the segment registers
 * by putting KDS_SEL (the kernel's default %ds gdt selector) into them.
 * This is necessary because the kernel itself does not use %es, %fs, nor
 * %ds. (%cs and %ss are necessary, and are set up by the kernel - along with
 * %gs - to point to the current cpu struct.) If we enter kmdb while in the
 * kernel and resume with a stale ldt or brandz selector sitting there in a
 * segment register, kmdb will #gp fault if the stale selector points to,
 * for example, an ldt in the context of another process.
 *
 * WARNING: Intel and AMD chips behave differently when storing
 * the null selector into %fs and %gs while in long mode. On AMD
 * chips fsbase and gsbase are not cleared. But on Intel chips, storing
 * a null selector into %fs or %gs has the side effect of clearing
 * fsbase or gsbase. For that reason we use KDS_SEL, which has
 * consistent behavor between AMD and Intel.
 *
 * Caller responsible for preventing cpu migration.
 */
void
reset_sregs(void)
{
	ulong_t kgsbase = (ulong_t)CPU;

	ASSERT(curthread->t_preempt != 0 || getpil() >= DISP_LEVEL);

	cli();
	__set_gs(KGS_SEL);

	/*
	 * restore kernel gsbase
	 */
#if defined(__xpv)
	xen_set_segment_base(SEGBASE_GS_KERNEL, kgsbase);
#else
	wrmsr(MSR_AMD_GSBASE, kgsbase);
#endif

	sti();

	__set_ds(KDS_SEL);
	__set_es(0 | SEL_KPL);	/* selector RPL not ring 0 on hypervisor */
	__set_fs(KFS_SEL);
}

#endif	/* __amd64 */

#ifdef _SYSCALL32_IMPL

/*
 * Make it impossible for a process to change its data model.
 * We do this by toggling the present bits for the 32 and
 * 64-bit user code descriptors. That way if a user lwp attempts
 * to change its data model (by using the wrong code descriptor in
 * %cs) it will fault immediately. This also allows us to simplify
 * assertions and checks in the kernel.
 */

static void
gdt_ucode_model(model_t model)
{
	kpreempt_disable();
	if (model == DATAMODEL_NATIVE) {
		gdt_update_usegd(GDT_UCODE, &ucs_on);
		gdt_update_usegd(GDT_U32CODE, &ucs32_off);
	} else {
		gdt_update_usegd(GDT_U32CODE, &ucs32_on);
		gdt_update_usegd(GDT_UCODE, &ucs_off);
	}
	kpreempt_enable();
}

#endif	/* _SYSCALL32_IMPL */

/*
 * Restore lwp private fs and gs segment descriptors
 * on current cpu's GDT.
 */
static void
lwp_segregs_restore(klwp_t *lwp)
{
	pcb_t *pcb = &lwp->lwp_pcb;

	ASSERT(VALID_LWP_DESC(&pcb->pcb_fsdesc));
	ASSERT(VALID_LWP_DESC(&pcb->pcb_gsdesc));

#ifdef	_SYSCALL32_IMPL
	gdt_ucode_model(DATAMODEL_NATIVE);
#endif

	gdt_update_usegd(GDT_LWPFS, &pcb->pcb_fsdesc);
	gdt_update_usegd(GDT_LWPGS, &pcb->pcb_gsdesc);

}

#ifdef _SYSCALL32_IMPL

static void
lwp_segregs_restore32(klwp_t *lwp)
{
	/*LINTED*/
	cpu_t *cpu = CPU;
	pcb_t *pcb = &lwp->lwp_pcb;

	ASSERT(VALID_LWP_DESC(&lwp->lwp_pcb.pcb_fsdesc));
	ASSERT(VALID_LWP_DESC(&lwp->lwp_pcb.pcb_gsdesc));

	gdt_ucode_model(DATAMODEL_ILP32);
	gdt_update_usegd(GDT_LWPFS, &pcb->pcb_fsdesc);
	gdt_update_usegd(GDT_LWPGS, &pcb->pcb_gsdesc);
}

#endif	/* _SYSCALL32_IMPL */

/*
 * If this is a process in a branded zone, then we want it to use the brand
 * syscall entry points instead of the standard Solaris entry points.  This
 * routine must be called when a new lwp is created within a branded zone
 * or when an existing lwp moves into a branded zone via a zone_enter()
 * operation.
 */
void
lwp_attach_brand_hdlrs(klwp_t *lwp)
{
	kthread_t *t = lwptot(lwp);

	ASSERT(PROC_IS_BRANDED(lwptoproc(lwp)));

	ASSERT(removectx(t, NULL, brand_interpositioning_disable,
	    brand_interpositioning_enable, NULL, NULL,
	    brand_interpositioning_disable, NULL) == 0);
	installctx(t, NULL, brand_interpositioning_disable,
	    brand_interpositioning_enable, NULL, NULL,
	    brand_interpositioning_disable, NULL);

	if (t == curthread) {
		kpreempt_disable();
		brand_interpositioning_enable();
		kpreempt_enable();
	}
}

/*
 * If this is a process in a branded zone, then we want it to disable the
 * brand syscall entry points.  This routine must be called when the last
 * lwp in a process is exiting in proc_exit().
 */
void
lwp_detach_brand_hdlrs(klwp_t *lwp)
{
	kthread_t *t = lwptot(lwp);

	ASSERT(PROC_IS_BRANDED(lwptoproc(lwp)));
	if (t == curthread)
		kpreempt_disable();

	/* Remove the original context handlers */
	VERIFY(removectx(t, NULL, brand_interpositioning_disable,
	    brand_interpositioning_enable, NULL, NULL,
	    brand_interpositioning_disable, NULL) != 0);

	if (t == curthread) {
		/* Cleanup our MSR and IDT entries. */
		brand_interpositioning_disable();
		kpreempt_enable();
	}
}

/*
 * Add any lwp-associated context handlers to the lwp at the beginning
 * of the lwp's useful life.
 *
 * All paths which create lwp's invoke lwp_create(); lwp_create()
 * invokes lwp_stk_init() which initializes the stack, sets up
 * lwp_regs, and invokes this routine.
 *
 * All paths which destroy lwp's invoke lwp_exit() to rip the lwp
 * apart and put it on 'lwp_deathrow'; if the lwp is destroyed it
 * ends up in thread_free() which invokes freectx(t, 0) before
 * invoking lwp_stk_fini().  When the lwp is recycled from death
 * row, lwp_stk_fini() is invoked, then thread_free(), and thus
 * freectx(t, 0) as before.
 *
 * In the case of exec, the surviving lwp is thoroughly scrubbed
 * clean; exec invokes freectx(t, 1) to destroy associated contexts.
 * On the way back to the new image, it invokes setregs() which
 * in turn invokes this routine.
 */
void
lwp_installctx(klwp_t *lwp)
{
	kthread_t *t = lwptot(lwp);
	int thisthread = t == curthread;
#ifdef _SYSCALL32_IMPL
	void (*restop)(klwp_t *) = lwp_getdatamodel(lwp) == DATAMODEL_NATIVE ?
	    lwp_segregs_restore : lwp_segregs_restore32;
#else
	void (*restop)(klwp_t *) = lwp_segregs_restore;
#endif

	/*
	 * Install the basic lwp context handlers on each lwp.
	 *
	 * On the amd64 kernel, the context handlers are responsible for
	 * virtualizing %ds, %es, %fs, and %gs to the lwp.  The register
	 * values are only ever changed via sys_rtt when the
	 * pcb->pcb_rupdate == 1.  Only sys_rtt gets to clear the bit.
	 *
	 * On the i386 kernel, the context handlers are responsible for
	 * virtualizing %gs/%fs to the lwp by updating the per-cpu GDTs
	 */
	ASSERT(removectx(t, lwp, lwp_segregs_save, restop,
	    NULL, NULL, NULL, NULL) == 0);
	if (thisthread)
		kpreempt_disable();
	installctx(t, lwp, lwp_segregs_save, restop,
	    NULL, NULL, NULL, NULL);
	if (thisthread) {
		/*
		 * Since we're the right thread, set the values in the GDT
		 */
		restop(lwp);
		kpreempt_enable();
	}

	/*
	 * If we have sysenter/sysexit instructions enabled, we need
	 * to ensure that the hardware mechanism is kept up-to-date with the
	 * lwp's kernel stack pointer across context switches.
	 *
	 * sep_save zeros the sysenter stack pointer msr; sep_restore sets
	 * it to the lwp's kernel stack pointer (kstktop).
	 */
	if (is_x86_feature(x86_featureset, X86FSET_SEP)) {
#if defined(__amd64)
		caddr_t kstktop = (caddr_t)lwp->lwp_regs;
#elif defined(__i386)
		caddr_t kstktop = ((caddr_t)lwp->lwp_regs - MINFRAME) +
		    SA(sizeof (struct regs) + MINFRAME);
#endif
		ASSERT(removectx(t, kstktop,
		    sep_save, sep_restore, NULL, NULL, NULL, NULL) == 0);

		if (thisthread)
			kpreempt_disable();
		installctx(t, kstktop,
		    sep_save, sep_restore, NULL, NULL, NULL, NULL);
		if (thisthread) {
			/*
			 * We're the right thread, so set the stack pointer
			 * for the first sysenter instruction to use
			 */
			sep_restore(kstktop);
			kpreempt_enable();
		}
	}

	if (PROC_IS_BRANDED(ttoproc(t)))
		lwp_attach_brand_hdlrs(lwp);
}

/*
 * Clear registers on exec(2).
 */
void
setregs(uarg_t *args)
{
	struct regs *rp;
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);
	pcb_t *pcb = &lwp->lwp_pcb;
	greg_t sp;

	/*
	 * Initialize user registers
	 */
	(void) save_syscall_args();	/* copy args from registers first */
	rp = lwptoregs(lwp);
	sp = rp->r_sp;
	bzero(rp, sizeof (*rp));

	rp->r_ss = UDS_SEL;
	rp->r_sp = sp;
	rp->r_pc = args->entry;
	rp->r_ps = PSL_USER;

#if defined(__amd64)

	pcb->pcb_fs = pcb->pcb_gs = 0;
	pcb->pcb_fsbase = pcb->pcb_gsbase = 0;

	if (ttoproc(t)->p_model == DATAMODEL_NATIVE) {

		rp->r_cs = UCS_SEL;

		/*
		 * Only allow 64-bit user code descriptor to be present.
		 */
		gdt_ucode_model(DATAMODEL_NATIVE);

		/*
		 * Arrange that the virtualized %fs and %gs GDT descriptors
		 * have a well-defined initial state (present, ring 3
		 * and of type data).
		 */
		pcb->pcb_fsdesc = pcb->pcb_gsdesc = zero_udesc;

		/*
		 * thrptr is either NULL or a value used by DTrace.
		 * 64-bit processes use %fs as their "thread" register.
		 */
		if (args->thrptr)
			(void) lwp_setprivate(lwp, _LWP_FSBASE, args->thrptr);

	} else {

		rp->r_cs = U32CS_SEL;
		rp->r_ds = rp->r_es = UDS_SEL;

		/*
		 * only allow 32-bit user code selector to be present.
		 */
		gdt_ucode_model(DATAMODEL_ILP32);

		pcb->pcb_fsdesc = pcb->pcb_gsdesc = zero_u32desc;

		/*
		 * thrptr is either NULL or a value used by DTrace.
		 * 32-bit processes use %gs as their "thread" register.
		 */
		if (args->thrptr)
			(void) lwp_setprivate(lwp, _LWP_GSBASE, args->thrptr);

	}

	pcb->pcb_ds = rp->r_ds;
	pcb->pcb_es = rp->r_es;
	pcb->pcb_rupdate = 1;

#elif defined(__i386)

	rp->r_cs = UCS_SEL;
	rp->r_ds = rp->r_es = UDS_SEL;

	/*
	 * Arrange that the virtualized %fs and %gs GDT descriptors
	 * have a well-defined initial state (present, ring 3
	 * and of type data).
	 */
	pcb->pcb_fsdesc = pcb->pcb_gsdesc = zero_udesc;

	/*
	 * For %gs we need to reset LWP_GSBASE in pcb and the
	 * per-cpu GDT descriptor. thrptr is either NULL
	 * or a value used by DTrace.
	 */
	if (args->thrptr)
		(void) lwp_setprivate(lwp, _LWP_GSBASE, args->thrptr);
#endif

	lwp->lwp_eosys = JUSTRETURN;
	t->t_post_sys = 1;

	/*
	 * Here we initialize minimal fpu state.
	 * The rest is done at the first floating
	 * point instruction that a process executes.
	 */
	pcb->pcb_fpu.fpu_flags = 0;

	/*
	 * Add the lwp context handlers that virtualize segment registers,
	 * and/or system call stacks etc.
	 */
	lwp_installctx(lwp);
}

user_desc_t *
cpu_get_gdt(void)
{
	return (CPU->cpu_gdt);
}


#if !defined(lwp_getdatamodel)

/*
 * Return the datamodel of the given lwp.
 */
/*ARGSUSED*/
model_t
lwp_getdatamodel(klwp_t *lwp)
{
	return (lwp->lwp_procp->p_model);
}

#endif	/* !lwp_getdatamodel */

#if !defined(get_udatamodel)

model_t
get_udatamodel(void)
{
	return (curproc->p_model);
}

#endif	/* !get_udatamodel */

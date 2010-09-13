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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/archsystm.h>
#include <sys/contract_impl.h>

#include <sys/reboot.h>
#include <sys/uadmin.h>

#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/session.h>
#include <sys/ucontext.h>

#include <sys/dnlc.h>
#include <sys/var.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/thread.h>
#include <sys/vtrace.h>
#include <sys/consdev.h>
#include <sys/frame.h>
#include <sys/stack.h>
#include <sys/swap.h>
#include <sys/vmparam.h>
#include <sys/cpuvar.h>
#include <sys/cpu.h>

#include <sys/privregs.h>

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
#include <sys/corectl.h>
#include <sys/modctl.h>
#include <sys/tuneable.h>

#include <c2/audit.h>

#include <sys/trap.h>
#include <sys/sunddi.h>
#include <sys/bootconf.h>
#include <sys/memlist.h>
#include <sys/systeminfo.h>
#include <sys/promif.h>

/*
 * Compare the version of boot that boot says it is against
 * the version of boot the kernel expects.
 *
 * XXX	There should be no need to use promif routines here.
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
	 * We assume that the u-area is zeroed out.
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
	struct rwindow *rwin;
	caddr_t sp;
	size_t framesz;
	caddr_t argp;
	extern void thread_start();

	/*
	 * Push a "c" call frame onto the stack to represent
	 * the caller of "start".
	 */
	sp = t->t_stk;
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
	 * store arg and len into the frames input register save area.
	 * these are then transfered to the first 2 output registers by
	 * thread_start() in swtch.s.
	 */
	rwin = (struct rwindow *)sp;
	rwin->rw_in[0] = (intptr_t)arg;
	rwin->rw_in[1] = len;
	rwin->rw_in[6] = 0;
	rwin->rw_in[7] = (intptr_t)start;
	/*
	 * initialize thread to resume at thread_start().
	 */
	t->t_pc = (uintptr_t)thread_start - 8;
	t->t_sp = (uintptr_t)sp - STACK_BIAS;
}

#if !defined(lwp_getdatamodel)

/*
 * Return the datamodel of the given lwp.
 */
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

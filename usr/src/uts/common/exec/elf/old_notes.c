/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/thread.h>
#include <sys/sysmacros.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/errno.h>
#include <sys/vnode.h>
#include <sys/mman.h>
#include <sys/kmem.h>
#include <sys/proc.h>
#include <sys/pathname.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/elf.h>
#include <sys/vmsystm.h>
#include <sys/debug.h>
#include <sys/old_procfs.h>
#include <sys/auxv.h>
#include <sys/exec.h>
#include <sys/prsystm.h>
#include <vm/as.h>
#include <vm/rm.h>
#include <sys/modctl.h>
#include <sys/systeminfo.h>
#include <sys/machelf.h>
#include <sys/zone.h>
#include "elf_impl.h"

extern void oprgetstatus(kthread_t *, prstatus_t *, zone_t *);
extern void oprgetpsinfo(proc_t *, prpsinfo_t *, kthread_t *);

/*
 * Historically the system dumped the xreg note when on SPARC. Because we no
 * longer support SPARC we do not dump the old note form of the xregs for any
 * additional platforms. Please do not add this back unless it's for SPARC's
 * future resurrection.
 */
void
setup_old_note_header(Phdr *v, proc_t *p)
{
	int nlwp = p->p_lwpcnt;

	v[0].p_type = PT_NOTE;
	v[0].p_flags = PF_R;
	v[0].p_filesz = (sizeof (Note) * (3 + nlwp))
	    + roundup(sizeof (prpsinfo_t), sizeof (Word))
	    + roundup(strlen(platform) + 1, sizeof (Word))
	    + roundup(__KERN_NAUXV_IMPL * sizeof (aux_entry_t),
	    sizeof (Word))
	    + nlwp * roundup(sizeof (prstatus_t), sizeof (Word));
	if (prhasfp()) {
		v[0].p_filesz += nlwp * sizeof (Note) +
		    nlwp * roundup(sizeof (prfpregset_t), sizeof (Word));
	}
}

int
write_old_elfnotes(proc_t *p, int sig, vnode_t *vp, offset_t offset,
    rlim64_t rlimit, cred_t *credp)
{
	union {
		prpsinfo_t	psinfo;
		prstatus_t	prstat;
		prfpregset_t	fpregs;
		aux_entry_t	auxv[__KERN_NAUXV_IMPL];
	} *bigwad;
	size_t bigsize = sizeof (*bigwad);
	kthread_t *t;
	klwp_t *lwp;
	user_t *up;
	int i;
	int nlwp;
	int error;

	bigwad = kmem_alloc(bigsize, KM_SLEEP);

	/*
	 * The order of the elfnote entries should be same here and in
	 * the gcore(1) command.  Synchronization is needed between the
	 * kernel and libproc's Pfgcore() function where the meat of
	 * the gcore(1) command lives.
	 */

	mutex_enter(&p->p_lock);
	oprgetpsinfo(p, &bigwad->psinfo, NULL);
	mutex_exit(&p->p_lock);
	error = elfnote(vp, &offset, NT_PRPSINFO, sizeof (bigwad->psinfo),
	    (caddr_t)&bigwad->psinfo, rlimit, credp);
	if (error)
		goto done;

	error = elfnote(vp, &offset, NT_PLATFORM, strlen(platform) + 1,
	    platform, rlimit, credp);
	if (error)
		goto done;

	up = PTOU(p);
	for (i = 0; i < __KERN_NAUXV_IMPL; i++) {
		bigwad->auxv[i].a_type = up->u_auxv[i].a_type;
		bigwad->auxv[i].a_un.a_val = up->u_auxv[i].a_un.a_val;
	}
	error = elfnote(vp, &offset, NT_AUXV, sizeof (bigwad->auxv),
	    (caddr_t)bigwad->auxv, rlimit, credp);
	if (error)
		goto done;

	t = curthread;
	nlwp = p->p_lwpcnt;
	do {
		ASSERT(nlwp != 0);
		nlwp--;
		lwp = ttolwp(t);

		mutex_enter(&p->p_lock);
		if (t == curthread) {
			uchar_t oldsig;

			/*
			 * Modify t_whystop and lwp_cursig so it appears that
			 * the current LWP is stopped after faulting on the
			 * signal that caused the core dump.  As a result,
			 * oprgetstatus() will record that signal, the saved
			 * lwp_siginfo, and its signal handler in the core file
			 * status.  We restore lwp_cursig in case a subsequent
			 * signal was received while dumping core.
			 */
			oldsig = lwp->lwp_cursig;
			lwp->lwp_cursig = (uchar_t)sig;
			t->t_whystop = PR_FAULTED;

			oprgetstatus(t, &bigwad->prstat, p->p_zone);
			bigwad->prstat.pr_why = 0;

			t->t_whystop = 0;
			lwp->lwp_cursig = oldsig;

		} else {
			oprgetstatus(t, &bigwad->prstat, p->p_zone);
		}
		mutex_exit(&p->p_lock);
		error = elfnote(vp, &offset, NT_PRSTATUS,
		    sizeof (bigwad->prstat), (caddr_t)&bigwad->prstat,
		    rlimit, credp);
		if (error)
			goto done;

		if (prhasfp()) {
			prgetprfpregs(lwp, &bigwad->fpregs);
			error = elfnote(vp, &offset, NT_PRFPREG,
			    sizeof (bigwad->fpregs), (caddr_t)&bigwad->fpregs,
			    rlimit, credp);
			if (error)
				goto done;
		}
	} while ((t = t->t_forw) != curthread);
	ASSERT(nlwp == 0);

done:
	kmem_free(bigwad, bigsize);
	return (error);
}

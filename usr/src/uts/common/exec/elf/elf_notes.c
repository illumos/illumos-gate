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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/thread.h>
#include <sys/sysmacros.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/priv.h>
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
#include <sys/procfs.h>
#include <sys/regset.h>
#include <sys/auxv.h>
#include <sys/exec.h>
#include <sys/prsystm.h>
#include <sys/utsname.h>
#include <sys/zone.h>
#include <vm/as.h>
#include <vm/rm.h>
#include <sys/modctl.h>
#include <sys/systeminfo.h>
#include <sys/machelf.h>
#include "elf_impl.h"
#if defined(__i386) || defined(__i386_COMPAT)
#include <sys/sysi86.h>
#endif

void
setup_note_header(Phdr *v, proc_t *p)
{
	int nlwp = p->p_lwpcnt;
	int nzomb = p->p_zombcnt;
	size_t size;
	prcred_t *pcrp;

	v[0].p_type = PT_NOTE;
	v[0].p_flags = PF_R;
	v[0].p_filesz = (sizeof (Note) * (9 + 2 * nlwp + nzomb))
	    + roundup(sizeof (psinfo_t), sizeof (Word))
	    + roundup(sizeof (pstatus_t), sizeof (Word))
	    + roundup(prgetprivsize(), sizeof (Word))
	    + roundup(priv_get_implinfo_size(), sizeof (Word))
	    + roundup(strlen(platform) + 1, sizeof (Word))
	    + roundup(strlen(p->p_zone->zone_name) + 1, sizeof (Word))
	    + roundup(__KERN_NAUXV_IMPL * sizeof (aux_entry_t), sizeof (Word))
	    + roundup(sizeof (utsname), sizeof (Word))
	    + roundup(sizeof (core_content_t), sizeof (Word))
	    + (nlwp + nzomb) * roundup(sizeof (lwpsinfo_t), sizeof (Word))
	    + nlwp * roundup(sizeof (lwpstatus_t), sizeof (Word));

	size = sizeof (prcred_t) + sizeof (gid_t) * (ngroups_max - 1);
	pcrp = kmem_alloc(size, KM_SLEEP);
	prgetcred(p, pcrp);
	if (pcrp->pr_ngroups != 0) {
		v[0].p_filesz += sizeof (Note) + roundup(sizeof (prcred_t) +
		    sizeof (gid_t) * (pcrp->pr_ngroups - 1), sizeof (Word));
	} else {
		v[0].p_filesz += sizeof (Note) +
		    roundup(sizeof (prcred_t), sizeof (Word));
	}
	kmem_free(pcrp, size);

#if defined(__i386) || defined(__i386_COMPAT)
	mutex_enter(&p->p_ldtlock);
	size = prnldt(p) * sizeof (struct ssd);
	mutex_exit(&p->p_ldtlock);
	if (size != 0)
		v[0].p_filesz += sizeof (Note) + roundup(size, sizeof (Word));
#endif	/* __i386 || __i386_COMPAT */

	if ((size = prhasx(p)? prgetprxregsize(p) : 0) != 0)
		v[0].p_filesz += nlwp * sizeof (Note)
		    + nlwp * roundup(size, sizeof (Word));

#if defined(__sparc)
	/*
	 * Figure out the number and sizes of register windows.
	 */
	{
		kthread_t *t = p->p_tlist;
		do {
			if ((size = prnwindows(ttolwp(t))) != 0) {
				size = sizeof (gwindows_t) -
				    (SPARC_MAXREGWINDOW - size) *
				    sizeof (struct rwindow);
				v[0].p_filesz += sizeof (Note) +
				    roundup(size, sizeof (Word));
			}
		} while ((t = t->t_forw) != p->p_tlist);
	}
	/*
	 * Space for the Ancillary State Registers.
	 */
	if (p->p_model == DATAMODEL_LP64)
		v[0].p_filesz += nlwp * sizeof (Note)
		    + nlwp * roundup(sizeof (asrset_t), sizeof (Word));
#endif /* __sparc */
}

int
write_elfnotes(proc_t *p, int sig, vnode_t *vp, offset_t offset,
    rlim64_t rlimit, cred_t *credp, core_content_t content)
{
	union {
		psinfo_t	psinfo;
		pstatus_t	pstatus;
		lwpsinfo_t	lwpsinfo;
		lwpstatus_t	lwpstatus;
#if defined(__sparc)
		gwindows_t	gwindows;
		asrset_t	asrset;
#endif /* __sparc */
		char		xregs[1];
		aux_entry_t	auxv[__KERN_NAUXV_IMPL];
		prcred_t	pcred;
		prpriv_t	ppriv;
		priv_impl_info_t prinfo;
		struct utsname	uts;
	} *bigwad;

	size_t xregsize = prhasx(p)? prgetprxregsize(p) : 0;
	size_t crsize = sizeof (prcred_t) + sizeof (gid_t) * (ngroups_max - 1);
	size_t psize = prgetprivsize();
	size_t bigsize = MAX(psize, MAX(sizeof (*bigwad),
					MAX(xregsize, crsize)));

	priv_impl_info_t *prii;

	lwpdir_t *ldp;
	lwpent_t *lep;
	kthread_t *t;
	klwp_t *lwp;
	user_t *up;
	int i;
	int nlwp;
	int nzomb;
	int error;
	uchar_t oldsig;
#if defined(__i386) || defined(__i386_COMPAT)
	struct ssd *ssd;
	size_t ssdsize;
#endif	/* __i386 || __i386_COMPAT */

	bigsize = MAX(bigsize, priv_get_implinfo_size());

	bigwad = kmem_alloc(bigsize, KM_SLEEP);

	/*
	 * The order of the elfnote entries should be same here
	 * and in the gcore(1) command.  Synchronization is
	 * needed between the kernel and gcore(1).
	 */

	/*
	 * Get the psinfo, and set the wait status to indicate that a core was
	 * dumped.  We have to forge this since p->p_wcode is not set yet.
	 */
	mutex_enter(&p->p_lock);
	prgetpsinfo(p, &bigwad->psinfo);
	mutex_exit(&p->p_lock);
	bigwad->psinfo.pr_wstat = wstat(CLD_DUMPED, sig);

	error = elfnote(vp, &offset, NT_PSINFO, sizeof (bigwad->psinfo),
	    (caddr_t)&bigwad->psinfo, rlimit, credp);
	if (error)
		goto done;

	/*
	 * Modify t_whystop and lwp_cursig so it appears that the current LWP
	 * is stopped after faulting on the signal that caused the core dump.
	 * As a result, prgetstatus() will record that signal, the saved
	 * lwp_siginfo, and its signal handler in the core file status.  We
	 * restore lwp_cursig in case a subsequent signal was received while
	 * dumping core.
	 */
	mutex_enter(&p->p_lock);
	lwp = ttolwp(curthread);

	oldsig = lwp->lwp_cursig;
	lwp->lwp_cursig = (uchar_t)sig;
	curthread->t_whystop = PR_FAULTED;

	prgetstatus(p, &bigwad->pstatus, p->p_zone);
	bigwad->pstatus.pr_lwp.pr_why = 0;

	curthread->t_whystop = 0;
	lwp->lwp_cursig = oldsig;
	mutex_exit(&p->p_lock);

	error = elfnote(vp, &offset, NT_PSTATUS, sizeof (bigwad->pstatus),
	    (caddr_t)&bigwad->pstatus, rlimit, credp);
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

	bcopy(&utsname, &bigwad->uts, sizeof (struct utsname));
	if (!INGLOBALZONE(p)) {
		bcopy(p->p_zone->zone_nodename, &bigwad->uts.nodename,
		    _SYS_NMLN);
	}
	error = elfnote(vp, &offset, NT_UTSNAME, sizeof (struct utsname),
	    (caddr_t)&bigwad->uts, rlimit, credp);
	if (error)
		goto done;

	prgetcred(p, &bigwad->pcred);

	if (bigwad->pcred.pr_ngroups != 0) {
		crsize = sizeof (prcred_t) +
		    sizeof (gid_t) * (bigwad->pcred.pr_ngroups - 1);
	} else
		crsize = sizeof (prcred_t);

	error = elfnote(vp, &offset, NT_PRCRED, crsize,
	    (caddr_t)&bigwad->pcred, rlimit, credp);
	if (error)
		goto done;

	error = elfnote(vp, &offset, NT_CONTENT, sizeof (core_content_t),
	    (caddr_t)&content, rlimit, credp);
	if (error)
		goto done;

	prgetpriv(p, &bigwad->ppriv);

	error = elfnote(vp, &offset, NT_PRPRIV, psize,
	    (caddr_t)&bigwad->ppriv, rlimit, credp);
	if (error)
		goto done;

	prii = priv_hold_implinfo();
	error = elfnote(vp, &offset, NT_PRPRIVINFO, priv_get_implinfo_size(),
	    (caddr_t)prii, rlimit, credp);
	priv_release_implinfo();
	if (error)
		goto done;

	/* zone can't go away as long as process exists */
	error = elfnote(vp, &offset, NT_ZONENAME,
	    strlen(p->p_zone->zone_name) + 1, p->p_zone->zone_name,
	    rlimit, credp);
	if (error)
		goto done;

#if defined(__i386) || defined(__i386_COMPAT)
	mutex_enter(&p->p_ldtlock);
	ssdsize = prnldt(p) * sizeof (struct ssd);
	if (ssdsize != 0) {
		ssd = kmem_alloc(ssdsize, KM_SLEEP);
		prgetldt(p, ssd);
		error = elfnote(vp, &offset, NT_LDT, ssdsize,
		    (caddr_t)ssd, rlimit, credp);
		kmem_free(ssd, ssdsize);
	}
	mutex_exit(&p->p_ldtlock);
	if (error)
		goto done;
#endif	/* __i386 || defined(__i386_COMPAT) */

	nlwp = p->p_lwpcnt;
	nzomb = p->p_zombcnt;
	/* for each entry in the lwp directory ... */
	for (ldp = p->p_lwpdir; nlwp + nzomb != 0; ldp++) {

		if ((lep = ldp->ld_entry) == NULL)	/* empty slot */
			continue;

		if ((t = lep->le_thread) != NULL) {	/* active lwp */
			ASSERT(nlwp != 0);
			nlwp--;
			lwp = ttolwp(t);
			mutex_enter(&p->p_lock);
			prgetlwpsinfo(t, &bigwad->lwpsinfo);
			mutex_exit(&p->p_lock);
		} else {				/* zombie lwp */
			ASSERT(nzomb != 0);
			nzomb--;
			bzero(&bigwad->lwpsinfo, sizeof (bigwad->lwpsinfo));
			bigwad->lwpsinfo.pr_lwpid = lep->le_lwpid;
			bigwad->lwpsinfo.pr_state = SZOMB;
			bigwad->lwpsinfo.pr_sname = 'Z';
			bigwad->lwpsinfo.pr_start.tv_sec = lep->le_start;
		}
		error = elfnote(vp, &offset, NT_LWPSINFO,
		    sizeof (bigwad->lwpsinfo), (caddr_t)&bigwad->lwpsinfo,
		    rlimit, credp);
		if (error)
			goto done;
		if (t == NULL)		/* nothing more to do for a zombie */
			continue;

		mutex_enter(&p->p_lock);
		if (t == curthread) {
			/*
			 * Modify t_whystop and lwp_cursig so it appears that
			 * the current LWP is stopped after faulting on the
			 * signal that caused the core dump.  As a result,
			 * prgetlwpstatus() will record that signal, the saved
			 * lwp_siginfo, and its signal handler in the core file
			 * status.  We restore lwp_cursig in case a subsequent
			 * signal was received while dumping core.
			 */
			oldsig = lwp->lwp_cursig;
			lwp->lwp_cursig = (uchar_t)sig;
			t->t_whystop = PR_FAULTED;

			prgetlwpstatus(t, &bigwad->lwpstatus, p->p_zone);
			bigwad->lwpstatus.pr_why = 0;

			t->t_whystop = 0;
			lwp->lwp_cursig = oldsig;
		} else {
			prgetlwpstatus(t, &bigwad->lwpstatus, p->p_zone);
		}
		mutex_exit(&p->p_lock);
		error = elfnote(vp, &offset, NT_LWPSTATUS,
		    sizeof (bigwad->lwpstatus), (caddr_t)&bigwad->lwpstatus,
		    rlimit, credp);
		if (error)
			goto done;

#if defined(__sparc)
		/*
		 * Unspilled SPARC register windows.
		 */
		{
			size_t size = prnwindows(lwp);

			if (size != 0) {
				size = sizeof (gwindows_t) -
				    (SPARC_MAXREGWINDOW - size) *
				    sizeof (struct rwindow);
				prgetwindows(lwp, &bigwad->gwindows);
				error = elfnote(vp, &offset, NT_GWINDOWS,
				    size, (caddr_t)&bigwad->gwindows,
				    rlimit, credp);
				if (error)
					goto done;
			}
		}
		/*
		 * Ancillary State Registers.
		 */
		if (p->p_model == DATAMODEL_LP64) {
			prgetasregs(lwp, bigwad->asrset);
			error = elfnote(vp, &offset, NT_ASRS,
			    sizeof (asrset_t), (caddr_t)bigwad->asrset,
			    rlimit, credp);
			if (error)
				goto done;
		}
#endif /* __sparc */

		if (xregsize) {
			prgetprxregs(lwp, bigwad->xregs);
			error = elfnote(vp, &offset, NT_PRXREG,
			    xregsize, bigwad->xregs, rlimit, credp);
			if (error)
				goto done;
		}
	}
	ASSERT(nlwp == 0);

done:
	kmem_free(bigwad, bigsize);
	return (error);
}

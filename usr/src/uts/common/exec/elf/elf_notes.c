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

/*
 * Copyright 2012 DEY Storage Systems, Inc.  All rights reserved.
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/thread.h>
#include <sys/sysmacros.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/priv.h>
#include <sys/user.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/vnode.h>
#include <sys/mode.h>
#include <sys/vfs.h>
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
#include <sys/sunddi.h>
#include "elf_impl.h"
#if defined(__i386) || defined(__i386_COMPAT)
#include <sys/sysi86.h>
#endif

void
setup_note_header(Phdr *v, proc_t *p)
{
	int nlwp = p->p_lwpcnt;
	int nzomb = p->p_zombcnt;
	int nfd;
	size_t size;
	prcred_t *pcrp;
	uf_info_t *fip;
	uf_entry_t *ufp;
	int fd;

	fip = P_FINFO(p);
	nfd = 0;
	mutex_enter(&fip->fi_lock);
	for (fd = 0; fd < fip->fi_nfiles; fd++) {
		UF_ENTER(ufp, fip, fd);
		if ((ufp->uf_file != NULL) && (ufp->uf_file->f_count > 0))
			nfd++;
		UF_EXIT(ufp);
	}
	mutex_exit(&fip->fi_lock);

	v[0].p_type = PT_NOTE;
	v[0].p_flags = PF_R;
	v[0].p_filesz = (sizeof (Note) * (9 + 2 * nlwp + nzomb + nfd))
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
	    + nlwp * roundup(sizeof (lwpstatus_t), sizeof (Word))
	    + nfd * roundup(sizeof (prfdinfo_t), sizeof (Word));

	if (curproc->p_agenttp != NULL) {
		v[0].p_filesz += sizeof (Note) +
		    roundup(sizeof (psinfo_t), sizeof (Word));
	}

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
	uf_info_t *fip;
	int fd;
	vnode_t *vroot;

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


	/* open file table */
	vroot = PTOU(p)->u_rdir;
	if (vroot == NULL)
		vroot = rootdir;

	VN_HOLD(vroot);

	fip = P_FINFO(p);

	for (fd = 0; fd < fip->fi_nfiles; fd++) {
		uf_entry_t *ufp;
		vnode_t *fvp;
		struct file *fp;
		vattr_t vattr;
		prfdinfo_t fdinfo;

		bzero(&fdinfo, sizeof (fdinfo));

		mutex_enter(&fip->fi_lock);
		UF_ENTER(ufp, fip, fd);
		if (((fp = ufp->uf_file) == NULL) || (fp->f_count < 1)) {
			UF_EXIT(ufp);
			mutex_exit(&fip->fi_lock);
			continue;
		}

		fdinfo.pr_fd = fd;
		fdinfo.pr_fdflags = ufp->uf_flag;
		fdinfo.pr_fileflags = fp->f_flag2;
		fdinfo.pr_fileflags <<= 16;
		fdinfo.pr_fileflags |= fp->f_flag;
		if ((fdinfo.pr_fileflags & (FSEARCH | FEXEC)) == 0)
			fdinfo.pr_fileflags += FOPEN;
		fdinfo.pr_offset = fp->f_offset;


		fvp = fp->f_vnode;
		VN_HOLD(fvp);
		UF_EXIT(ufp);
		mutex_exit(&fip->fi_lock);

		/*
		 * There are some vnodes that have no corresponding
		 * path.  Its reasonable for this to fail, in which
		 * case the path will remain an empty string.
		 */
		(void) vnodetopath(vroot, fvp, fdinfo.pr_path,
		    sizeof (fdinfo.pr_path), credp);

		error = VOP_GETATTR(fvp, &vattr, 0, credp, NULL);
		if (error != 0) {
			VN_RELE(fvp);
			VN_RELE(vroot);
			goto done;
		}

		if (fvp->v_type == VSOCK)
			fdinfo.pr_fileflags |= sock_getfasync(fvp);

		VN_RELE(fvp);

		/*
		 * This logic mirrors fstat(), which we cannot use
		 * directly, as it calls copyout().
		 */
		fdinfo.pr_major = getmajor(vattr.va_fsid);
		fdinfo.pr_minor = getminor(vattr.va_fsid);
		fdinfo.pr_ino = (ino64_t)vattr.va_nodeid;
		fdinfo.pr_mode = VTTOIF(vattr.va_type) | vattr.va_mode;
		fdinfo.pr_uid = vattr.va_uid;
		fdinfo.pr_gid = vattr.va_gid;
		fdinfo.pr_rmajor = getmajor(vattr.va_rdev);
		fdinfo.pr_rminor = getminor(vattr.va_rdev);
		fdinfo.pr_size = (off64_t)vattr.va_size;

		error = elfnote(vp, &offset, NT_FDINFO,
		    sizeof (fdinfo), &fdinfo, rlimit, credp);
		if (error) {
			VN_RELE(vroot);
			goto done;
		}
	}

	VN_RELE(vroot);

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

		if (t->t_lwp->lwp_spymaster != NULL) {
			void *psaddr = t->t_lwp->lwp_spymaster;
#ifdef _ELF32_COMPAT
			/*
			 * On a 64-bit kernel with 32-bit ELF compatibility,
			 * this file is compiled into two different objects:
			 * one is compiled normally, and the other is compiled
			 * with _ELF32_COMPAT set -- and therefore with a
			 * psinfo_t defined to be a psinfo32_t.  However, the
			 * psinfo_t denoting our spymaster is always of the
			 * native type; if we are in the _ELF32_COMPAT case,
			 * we need to explicitly convert it.
			 */
			if (p->p_model == DATAMODEL_ILP32) {
				psinfo_kto32(psaddr, &bigwad->psinfo);
				psaddr = &bigwad->psinfo;
			}
#endif

			error = elfnote(vp, &offset, NT_SPYMASTER,
			    sizeof (psinfo_t), psaddr, rlimit, credp);
			if (error)
				goto done;
		}
	}
	ASSERT(nlwp == 0);

done:
	kmem_free(bigwad, bigsize);
	return (error);
}

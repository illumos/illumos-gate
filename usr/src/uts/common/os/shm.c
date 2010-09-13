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
 * Copyright (c) 1986, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * Inter-Process Communication Shared Memory Facility.
 *
 * See os/ipc.c for a description of common IPC functionality.
 *
 * Resource controls
 * -----------------
 *
 * Control:      zone.max-shm-ids (rc_zone_shmmni)
 * Description:  Maximum number of shared memory ids allowed a zone.
 *
 *   When shmget() is used to allocate a shared memory segment, one id
 *   is allocated.  If the id allocation doesn't succeed, shmget()
 *   fails and errno is set to ENOSPC.  Upon successful shmctl(,
 *   IPC_RMID) the id is deallocated.
 *
 * Control:      project.max-shm-ids (rc_project_shmmni)
 * Description:  Maximum number of shared memory ids allowed a project.
 *
 *   When shmget() is used to allocate a shared memory segment, one id
 *   is allocated.  If the id allocation doesn't succeed, shmget()
 *   fails and errno is set to ENOSPC.  Upon successful shmctl(,
 *   IPC_RMID) the id is deallocated.
 *
 * Control:      zone.max-shm-memory (rc_zone_shmmax)
 * Description:  Total amount of shared memory allowed a zone.
 *
 *   When shmget() is used to allocate a shared memory segment, the
 *   segment's size is allocated against this limit.  If the space
 *   allocation doesn't succeed, shmget() fails and errno is set to
 *   EINVAL.  The size will be deallocated once the last process has
 *   detached the segment and the segment has been successfully
 *   shmctl(, IPC_RMID)ed.
 *
 * Control:      project.max-shm-memory (rc_project_shmmax)
 * Description:  Total amount of shared memory allowed a project.
 *
 *   When shmget() is used to allocate a shared memory segment, the
 *   segment's size is allocated against this limit.  If the space
 *   allocation doesn't succeed, shmget() fails and errno is set to
 *   EINVAL.  The size will be deallocated once the last process has
 *   detached the segment and the segment has been successfully
 *   shmctl(, IPC_RMID)ed.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/cred.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kmem.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/prsystm.h>
#include <sys/sysmacros.h>
#include <sys/tuneable.h>
#include <sys/vm.h>
#include <sys/mman.h>
#include <sys/swap.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/lwpchan_impl.h>
#include <sys/avl.h>
#include <sys/modctl.h>
#include <sys/syscall.h>
#include <sys/task.h>
#include <sys/project.h>
#include <sys/policy.h>
#include <sys/zone.h>
#include <sys/rctl.h>

#include <sys/ipc.h>
#include <sys/ipc_impl.h>
#include <sys/shm.h>
#include <sys/shm_impl.h>

#include <vm/hat.h>
#include <vm/seg.h>
#include <vm/as.h>
#include <vm/seg_vn.h>
#include <vm/anon.h>
#include <vm/page.h>
#include <vm/vpage.h>
#include <vm/seg_spt.h>

#include <c2/audit.h>

static int shmem_lock(kshmid_t *sp, struct anon_map *amp);
static void shmem_unlock(kshmid_t *sp, struct anon_map *amp);
static void sa_add(struct proc *pp, caddr_t addr, size_t len, ulong_t flags,
	kshmid_t *id);
static void shm_rm_amp(kshmid_t *sp);
static void shm_dtor(kipc_perm_t *);
static void shm_rmid(kipc_perm_t *);
static void shm_remove_zone(zoneid_t, void *);

/*
 * Semantics for share_page_table and ism_off:
 *
 * These are hooks in /etc/system - only for internal testing purpose.
 *
 * Setting share_page_table automatically turns on the SHM_SHARE_MMU (ISM) flag
 * in a call to shmat(2). In other words, with share_page_table set, you always
 * get ISM, even if say, DISM is specified. It should really be called "ism_on".
 *
 * Setting ism_off turns off the SHM_SHARE_MMU flag from the flags passed to
 * shmat(2).
 *
 * If both share_page_table and ism_off are set, share_page_table prevails.
 *
 * Although these tunables should probably be removed, they do have some
 * external exposure; as long as they exist, they should at least work sensibly.
 */

int share_page_table;
int ism_off;

/*
 * The following tunables are obsolete.  Though for compatibility we
 * still read and interpret shminfo_shmmax and shminfo_shmmni (see
 * os/project.c), the preferred mechanism for administrating the IPC
 * Shared Memory facility is through the resource controls described at
 * the top of this file.
 */
size_t	shminfo_shmmax = 0x800000;	/* (obsolete) */
int	shminfo_shmmni = 100;		/* (obsolete) */
size_t	shminfo_shmmin = 1;		/* (obsolete) */
int	shminfo_shmseg = 6;		/* (obsolete) */

extern rctl_hndl_t rc_zone_shmmax;
extern rctl_hndl_t rc_zone_shmmni;
extern rctl_hndl_t rc_project_shmmax;
extern rctl_hndl_t rc_project_shmmni;
static ipc_service_t *shm_svc;
static zone_key_t shm_zone_key;

/*
 * Module linkage information for the kernel.
 */
static uintptr_t shmsys(int, uintptr_t, uintptr_t, uintptr_t);

static struct sysent ipcshm_sysent = {
	4,
#ifdef	_SYSCALL32_IMPL
	SE_ARGC | SE_NOUNLOAD | SE_64RVAL,
#else	/* _SYSCALL32_IMPL */
	SE_ARGC | SE_NOUNLOAD | SE_32RVAL1,
#endif	/* _SYSCALL32_IMPL */
	(int (*)())shmsys
};

#ifdef	_SYSCALL32_IMPL
static struct sysent ipcshm_sysent32 = {
	4,
	SE_ARGC | SE_NOUNLOAD | SE_32RVAL1,
	(int (*)())shmsys
};
#endif	/* _SYSCALL32_IMPL */

static struct modlsys modlsys = {
	&mod_syscallops, "System V shared memory", &ipcshm_sysent
};

#ifdef	_SYSCALL32_IMPL
static struct modlsys modlsys32 = {
	&mod_syscallops32, "32-bit System V shared memory", &ipcshm_sysent32
};
#endif	/* _SYSCALL32_IMPL */

static struct modlinkage modlinkage = {
	MODREV_1,
	&modlsys,
#ifdef	_SYSCALL32_IMPL
	&modlsys32,
#endif
	NULL
};


int
_init(void)
{
	int result;

	shm_svc = ipcs_create("shmids", rc_project_shmmni, rc_zone_shmmni,
	    sizeof (kshmid_t), shm_dtor, shm_rmid, AT_IPC_SHM,
	    offsetof(ipc_rqty_t, ipcq_shmmni));
	zone_key_create(&shm_zone_key, NULL, shm_remove_zone, NULL);

	if ((result = mod_install(&modlinkage)) == 0)
		return (0);

	(void) zone_key_delete(shm_zone_key);
	ipcs_destroy(shm_svc);

	return (result);
}

int
_fini(void)
{
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Shmat (attach shared segment) system call.
 */
static int
shmat(int shmid, caddr_t uaddr, int uflags, uintptr_t *rvp)
{
	kshmid_t *sp;	/* shared memory header ptr */
	size_t	size;
	int	error = 0;
	proc_t *pp = curproc;
	struct as *as = pp->p_as;
	struct segvn_crargs	crargs;	/* segvn create arguments */
	kmutex_t	*lock;
	struct seg 	*segspt = NULL;
	caddr_t		addr = uaddr;
	int		flags = (uflags & SHMAT_VALID_FLAGS_MASK);
	int		useISM;
	uchar_t		prot = PROT_ALL;
	int result;

	if ((lock = ipc_lookup(shm_svc, shmid, (kipc_perm_t **)&sp)) == NULL)
		return (EINVAL);
	if (error = ipcperm_access(&sp->shm_perm, SHM_R, CRED()))
		goto errret;
	if ((flags & SHM_RDONLY) == 0 &&
	    (error = ipcperm_access(&sp->shm_perm, SHM_W, CRED())))
		goto errret;
	if (spt_invalid(flags)) {
		error = EINVAL;
		goto errret;
	}
	if (ism_off)
		flags = flags & ~SHM_SHARE_MMU;
	if (share_page_table) {
		flags = flags & ~SHM_PAGEABLE;
		flags = flags | SHM_SHARE_MMU;
	}
	useISM = (spt_locked(flags) || spt_pageable(flags));
	if (useISM && (error = ipcperm_access(&sp->shm_perm, SHM_W, CRED())))
		goto errret;
	if (useISM && isspt(sp)) {
		uint_t newsptflags = flags | spt_flags(sp->shm_sptseg);
		/*
		 * If trying to change an existing {D}ISM segment from ISM
		 * to DISM or vice versa, return error. Note that this
		 * validation of flags needs to be done after the effect of
		 * tunables such as ism_off and share_page_table, for
		 * semantics that are consistent with the tunables' settings.
		 */
		if (spt_invalid(newsptflags)) {
			error = EINVAL;
			goto errret;
		}
	}
	ANON_LOCK_ENTER(&sp->shm_amp->a_rwlock, RW_WRITER);
	size = sp->shm_amp->size;
	ANON_LOCK_EXIT(&sp->shm_amp->a_rwlock);

	/* somewhere to record spt info for final detach */
	if (sp->shm_sptinfo == NULL)
		sp->shm_sptinfo = kmem_zalloc(sizeof (sptinfo_t), KM_SLEEP);

	as_rangelock(as);

	if (useISM) {
		/*
		 * Handle ISM
		 */
		uint_t	share_szc;
		size_t	share_size;
		struct	shm_data ssd;
		uintptr_t align_hint;

		/*
		 * Pick a share pagesize to use, if (!isspt(sp)).
		 * Otherwise use the already chosen page size.
		 *
		 * For the initial shmat (!isspt(sp)), where sptcreate is
		 * called, map_pgsz is called to recommend a [D]ISM pagesize,
		 * important for systems which offer more than one potential
		 * [D]ISM pagesize.
		 * If the shmat is just to attach to an already created
		 * [D]ISM segment, then use the previously selected page size.
		 */
		if (!isspt(sp)) {
			share_size = map_pgsz(MAPPGSZ_ISM, pp, addr, size, 0);
			if (share_size == 0) {
				as_rangeunlock(as);
				error = EINVAL;
				goto errret;
			}
			share_szc = page_szc(share_size);
		} else {
			share_szc = sp->shm_sptseg->s_szc;
			share_size = page_get_pagesize(share_szc);
		}
		size = P2ROUNDUP(size, share_size);

		align_hint = share_size;
#if defined(__i386) || defined(__amd64)
		/*
		 * For x86, we want to share as much of the page table tree
		 * as possible. We use a large align_hint at first, but
		 * if that fails, then the code below retries with align_hint
		 * set to share_size.
		 *
		 * The explicit extern here is due to the difficulties
		 * of getting to platform dependent includes. When/if the
		 * platform dependent bits of this function are cleaned up,
		 * another way of doing this should found.
		 */
		{
			extern uint_t ptes_per_table;

			while (size >= ptes_per_table * (uint64_t)align_hint)
				align_hint *= ptes_per_table;
		}
#endif /* __i386 || __amd64 */

#if defined(__sparcv9)
		if (addr == 0 &&
		    pp->p_model == DATAMODEL_LP64 && AS_TYPE_64BIT(as)) {
			/*
			 * If no address has been passed in, and this is a
			 * 64-bit process, we'll try to find an address
			 * in the predict-ISM zone.
			 */
			caddr_t predbase = (caddr_t)PREDISM_1T_BASE;
			size_t len = PREDISM_BOUND - PREDISM_1T_BASE;

			as_purge(as);
			if (as_gap(as, size + share_size, &predbase, &len,
			    AH_LO, (caddr_t)NULL) != -1) {
				/*
				 * We found an address which looks like a
				 * candidate.  We want to round it up, and
				 * then check that it's a valid user range.
				 * This assures that we won't fail below.
				 */
				addr = (caddr_t)P2ROUNDUP((uintptr_t)predbase,
				    share_size);

				if (valid_usr_range(addr, size, prot,
				    as, as->a_userlimit) != RANGE_OKAY) {
					addr = 0;
				}
			}
		}
#endif /* __sparcv9 */

		if (addr == 0) {
			for (;;) {
				addr = (caddr_t)align_hint;
				map_addr(&addr, size, 0ll, 1, MAP_ALIGN);
				if (addr != NULL || align_hint == share_size)
					break;
				align_hint = share_size;
			}
			if (addr == NULL) {
				as_rangeunlock(as);
				error = ENOMEM;
				goto errret;
			}
			ASSERT(((uintptr_t)addr & (align_hint - 1)) == 0);
		} else {
			/* Use the user-supplied attach address */
			caddr_t base;
			size_t len;

			/*
			 * Check that the address range
			 *  1) is properly aligned
			 *  2) is correct in unix terms
			 *  3) is within an unmapped address segment
			 */
			base = addr;
			len = size;		/* use spt aligned size */
			/* XXX - in SunOS, is sp->shm_segsz */
			if ((uintptr_t)base & (share_size - 1)) {
				error = EINVAL;
				as_rangeunlock(as);
				goto errret;
			}
			result = valid_usr_range(base, len, prot, as,
			    as->a_userlimit);
			if (result == RANGE_BADPROT) {
				/*
				 * We try to accomodate processors which
				 * may not support execute permissions on
				 * all ISM segments by trying the check
				 * again but without PROT_EXEC.
				 */
				prot &= ~PROT_EXEC;
				result = valid_usr_range(base, len, prot, as,
				    as->a_userlimit);
			}
			as_purge(as);
			if (result != RANGE_OKAY ||
			    as_gap(as, len, &base, &len, AH_LO,
			    (caddr_t)NULL) != 0) {
				error = EINVAL;
				as_rangeunlock(as);
				goto errret;
			}
		}

		if (!isspt(sp)) {
			error = sptcreate(size, &segspt, sp->shm_amp, prot,
			    flags, share_szc);
			if (error) {
				as_rangeunlock(as);
				goto errret;
			}
			sp->shm_sptinfo->sptas = segspt->s_as;
			sp->shm_sptseg = segspt;
			sp->shm_sptprot = prot;
		} else if ((prot & sp->shm_sptprot) != sp->shm_sptprot) {
			/*
			 * Ensure we're attaching to an ISM segment with
			 * fewer or equal permissions than what we're
			 * allowed.  Fail if the segment has more
			 * permissions than what we're allowed.
			 */
			error = EACCES;
			as_rangeunlock(as);
			goto errret;
		}

		ssd.shm_sptseg = sp->shm_sptseg;
		ssd.shm_sptas = sp->shm_sptinfo->sptas;
		ssd.shm_amp = sp->shm_amp;
		error = as_map(as, addr, size, segspt_shmattach, &ssd);
		if (error == 0)
			sp->shm_ismattch++; /* keep count of ISM attaches */
	} else {

		/*
		 * Normal case.
		 */
		if (flags & SHM_RDONLY)
			prot &= ~PROT_WRITE;

		if (addr == 0) {
			/* Let the system pick the attach address */
			map_addr(&addr, size, 0ll, 1, 0);
			if (addr == NULL) {
				as_rangeunlock(as);
				error = ENOMEM;
				goto errret;
			}
		} else {
			/* Use the user-supplied attach address */
			caddr_t base;
			size_t len;

			if (flags & SHM_RND)
				addr = (caddr_t)((uintptr_t)addr &
				    ~(SHMLBA - 1));
			/*
			 * Check that the address range
			 *  1) is properly aligned
			 *  2) is correct in unix terms
			 *  3) is within an unmapped address segment
			 */
			base = addr;
			len = size;		/* use aligned size */
			/* XXX - in SunOS, is sp->shm_segsz */
			if ((uintptr_t)base & PAGEOFFSET) {
				error = EINVAL;
				as_rangeunlock(as);
				goto errret;
			}
			result = valid_usr_range(base, len, prot, as,
			    as->a_userlimit);
			if (result == RANGE_BADPROT) {
				prot &= ~PROT_EXEC;
				result = valid_usr_range(base, len, prot, as,
				    as->a_userlimit);
			}
			as_purge(as);
			if (result != RANGE_OKAY ||
			    as_gap(as, len, &base, &len,
			    AH_LO, (caddr_t)NULL) != 0) {
				error = EINVAL;
				as_rangeunlock(as);
				goto errret;
			}
		}

		/* Initialize the create arguments and map the segment */
		crargs = *(struct segvn_crargs *)zfod_argsp;
		crargs.offset = 0;
		crargs.type = MAP_SHARED;
		crargs.amp = sp->shm_amp;
		crargs.prot = prot;
		crargs.maxprot = crargs.prot;
		crargs.flags = 0;

		error = as_map(as, addr, size, segvn_create, &crargs);
	}

	as_rangeunlock(as);
	if (error)
		goto errret;

	/* record shmem range for the detach */
	sa_add(pp, addr, (size_t)size, useISM ? SHMSA_ISM : 0, sp);
	*rvp = (uintptr_t)addr;

	sp->shm_atime = gethrestime_sec();
	sp->shm_lpid = pp->p_pid;
	ipc_hold(shm_svc, (kipc_perm_t *)sp);

	/*
	 * Tell machine specific code that lwp has mapped shared memory
	 */
	LWP_MMODEL_SHARED_AS(addr, size);

errret:
	mutex_exit(lock);
	return (error);
}

static void
shm_dtor(kipc_perm_t *perm)
{
	kshmid_t *sp = (kshmid_t *)perm;
	uint_t cnt;
	size_t rsize;

	ANON_LOCK_ENTER(&sp->shm_amp->a_rwlock, RW_WRITER);
	anonmap_purge(sp->shm_amp);
	ANON_LOCK_EXIT(&sp->shm_amp->a_rwlock);

	if (sp->shm_sptinfo) {
		if (isspt(sp)) {
			sptdestroy(sp->shm_sptinfo->sptas, sp->shm_amp);
			sp->shm_lkcnt = 0;
		}
		kmem_free(sp->shm_sptinfo, sizeof (sptinfo_t));
	}

	if (sp->shm_lkcnt > 0) {
		shmem_unlock(sp, sp->shm_amp);
		sp->shm_lkcnt = 0;
	}

	ANON_LOCK_ENTER(&sp->shm_amp->a_rwlock, RW_WRITER);
	cnt = --sp->shm_amp->refcnt;
	ANON_LOCK_EXIT(&sp->shm_amp->a_rwlock);
	ASSERT(cnt == 0);
	shm_rm_amp(sp);

	if (sp->shm_perm.ipc_id != IPC_ID_INVAL) {
		rsize = ptob(btopr(sp->shm_segsz));
		ipcs_lock(shm_svc);
		sp->shm_perm.ipc_proj->kpj_data.kpd_shmmax -= rsize;
		sp->shm_perm.ipc_zone_ref.zref_zone->zone_shmmax -= rsize;
		ipcs_unlock(shm_svc);
	}
}

/* ARGSUSED */
static void
shm_rmid(kipc_perm_t *perm)
{
	/* nothing to do */
}

/*
 * Shmctl system call.
 */
/* ARGSUSED */
static int
shmctl(int shmid, int cmd, void *arg)
{
	kshmid_t		*sp;	/* shared memory header ptr */
	STRUCT_DECL(shmid_ds, ds);	/* for SVR4 IPC_SET */
	int			error = 0;
	struct cred 		*cr = CRED();
	kmutex_t		*lock;
	model_t			mdl = get_udatamodel();
	struct shmid_ds64	ds64;
	shmatt_t		nattch;

	STRUCT_INIT(ds, mdl);

	/*
	 * Perform pre- or non-lookup actions (e.g. copyins, RMID).
	 */
	switch (cmd) {
	case IPC_SET:
		if (copyin(arg, STRUCT_BUF(ds), STRUCT_SIZE(ds)))
			return (EFAULT);
		break;

	case IPC_SET64:
		if (copyin(arg, &ds64, sizeof (struct shmid_ds64)))
			return (EFAULT);
		break;

	case IPC_RMID:
		return (ipc_rmid(shm_svc, shmid, cr));
	}

	if ((lock = ipc_lookup(shm_svc, shmid, (kipc_perm_t **)&sp)) == NULL)
		return (EINVAL);

	switch (cmd) {
	/* Set ownership and permissions. */
	case IPC_SET:
		if (error = ipcperm_set(shm_svc, cr, &sp->shm_perm,
		    &STRUCT_BUF(ds)->shm_perm, mdl))
				break;
		sp->shm_ctime = gethrestime_sec();
		break;

	case IPC_STAT:
		if (error = ipcperm_access(&sp->shm_perm, SHM_R, cr))
			break;

		nattch = sp->shm_perm.ipc_ref - 1;

		ipcperm_stat(&STRUCT_BUF(ds)->shm_perm, &sp->shm_perm, mdl);
		STRUCT_FSET(ds, shm_segsz, sp->shm_segsz);
		STRUCT_FSETP(ds, shm_amp, NULL);	/* kernel addr */
		STRUCT_FSET(ds, shm_lkcnt, sp->shm_lkcnt);
		STRUCT_FSET(ds, shm_lpid, sp->shm_lpid);
		STRUCT_FSET(ds, shm_cpid, sp->shm_cpid);
		STRUCT_FSET(ds, shm_nattch, nattch);
		STRUCT_FSET(ds, shm_cnattch, sp->shm_ismattch);
		STRUCT_FSET(ds, shm_atime, sp->shm_atime);
		STRUCT_FSET(ds, shm_dtime, sp->shm_dtime);
		STRUCT_FSET(ds, shm_ctime, sp->shm_ctime);

		mutex_exit(lock);
		if (copyout(STRUCT_BUF(ds), arg, STRUCT_SIZE(ds)))
			return (EFAULT);

		return (0);

	case IPC_SET64:
		if (error = ipcperm_set64(shm_svc, cr,
		    &sp->shm_perm, &ds64.shmx_perm))
			break;
		sp->shm_ctime = gethrestime_sec();
		break;

	case IPC_STAT64:
		nattch = sp->shm_perm.ipc_ref - 1;

		ipcperm_stat64(&ds64.shmx_perm, &sp->shm_perm);
		ds64.shmx_segsz = sp->shm_segsz;
		ds64.shmx_lkcnt = sp->shm_lkcnt;
		ds64.shmx_lpid = sp->shm_lpid;
		ds64.shmx_cpid = sp->shm_cpid;
		ds64.shmx_nattch = nattch;
		ds64.shmx_cnattch = sp->shm_ismattch;
		ds64.shmx_atime = sp->shm_atime;
		ds64.shmx_dtime = sp->shm_dtime;
		ds64.shmx_ctime = sp->shm_ctime;

		mutex_exit(lock);
		if (copyout(&ds64, arg, sizeof (struct shmid_ds64)))
			return (EFAULT);

		return (0);

	/* Lock segment in memory */
	case SHM_LOCK:
		if ((error = secpolicy_lock_memory(cr)) != 0)
			break;

		/* protect against overflow */
		if (sp->shm_lkcnt >= USHRT_MAX) {
			error = ENOMEM;
			break;
		}
		if (!isspt(sp) && (sp->shm_lkcnt++ == 0)) {
			if (error = shmem_lock(sp, sp->shm_amp)) {
				ANON_LOCK_ENTER(&sp->shm_amp->a_rwlock,
				    RW_WRITER);
				cmn_err(CE_NOTE, "shmctl - couldn't lock %ld"
				    " pages into memory", sp->shm_amp->size);
				ANON_LOCK_EXIT(&sp->shm_amp->a_rwlock);
				error = ENOMEM;
				sp->shm_lkcnt--;
			}
		}
		break;

	/* Unlock segment */
	case SHM_UNLOCK:
		if ((error = secpolicy_lock_memory(cr)) != 0)
			break;

		if (sp->shm_lkcnt && (--sp->shm_lkcnt == 0)) {
			shmem_unlock(sp, sp->shm_amp);
		}
		break;

	default:
		error = EINVAL;
		break;
	}
	mutex_exit(lock);
	return (error);
}

static void
shm_detach(proc_t *pp, segacct_t *sap)
{
	kshmid_t	*sp = sap->sa_id;
	size_t		len = sap->sa_len;
	caddr_t		addr = sap->sa_addr;

	/*
	 * Discard lwpchan mappings.
	 */
	if (pp->p_lcp != NULL)
		lwpchan_delete_mapping(pp, addr, addr + len);
	(void) as_unmap(pp->p_as, addr, len);

	/*
	 * Perform some detach-time accounting.
	 */
	(void) ipc_lock(shm_svc, sp->shm_perm.ipc_id);
	if (sap->sa_flags & SHMSA_ISM)
		sp->shm_ismattch--;
	sp->shm_dtime = gethrestime_sec();
	sp->shm_lpid = pp->p_pid;
	ipc_rele(shm_svc, (kipc_perm_t *)sp);	/* Drops lock */

	kmem_free(sap, sizeof (segacct_t));
}

static int
shmdt(caddr_t addr)
{
	proc_t *pp = curproc;
	segacct_t *sap, template;

	mutex_enter(&pp->p_lock);
	prbarrier(pp);			/* block /proc.  See shmgetid(). */

	template.sa_addr = addr;
	template.sa_len = 0;
	if ((pp->p_segacct == NULL) ||
	    ((sap = avl_find(pp->p_segacct, &template, NULL)) == NULL)) {
		mutex_exit(&pp->p_lock);
		return (EINVAL);
	}
	if (sap->sa_addr != addr) {
		mutex_exit(&pp->p_lock);
		return (EINVAL);
	}
	avl_remove(pp->p_segacct, sap);
	mutex_exit(&pp->p_lock);

	shm_detach(pp, sap);

	return (0);
}

/*
 * Remove all shared memory segments associated with a given zone.
 * Called by zone_shutdown when the zone is halted.
 */
/*ARGSUSED1*/
static void
shm_remove_zone(zoneid_t zoneid, void *arg)
{
	ipc_remove_zone(shm_svc, zoneid);
}

/*
 * Shmget (create new shmem) system call.
 */
static int
shmget(key_t key, size_t size, int shmflg, uintptr_t *rvp)
{
	proc_t		*pp = curproc;
	kshmid_t	*sp;
	kmutex_t	*lock;
	int		error;

top:
	if (error = ipc_get(shm_svc, key, shmflg, (kipc_perm_t **)&sp, &lock))
		return (error);

	if (!IPC_FREE(&sp->shm_perm)) {
		/*
		 * A segment with the requested key exists.
		 */
		if (size > sp->shm_segsz) {
			mutex_exit(lock);
			return (EINVAL);
		}
	} else {
		/*
		 * A new segment should be created.
		 */
		size_t npages = btopr(size);
		size_t rsize = ptob(npages);

		/*
		 * Check rsize and the per-project and per-zone limit on
		 * shared memory.  Checking rsize handles both the size == 0
		 * case and the size < ULONG_MAX & PAGEMASK case (i.e.
		 * rounding up wraps a size_t).
		 */
		if (rsize == 0 ||
		    (rctl_test(rc_project_shmmax,
		    pp->p_task->tk_proj->kpj_rctls, pp, rsize,
		    RCA_SAFE) & RCT_DENY) ||
		    (rctl_test(rc_zone_shmmax,
		    pp->p_zone->zone_rctls, pp, rsize,
		    RCA_SAFE) & RCT_DENY)) {

			mutex_exit(&pp->p_lock);
			mutex_exit(lock);
			ipc_cleanup(shm_svc, (kipc_perm_t *)sp);
			return (EINVAL);
		}
		mutex_exit(&pp->p_lock);
		mutex_exit(lock);

		if (anon_resv(rsize) == 0) {
			ipc_cleanup(shm_svc, (kipc_perm_t *)sp);
			return (ENOMEM);
		}

		/*
		 * If any new failure points are introduced between the
		 * the above anon_resv() and the below ipc_commit_begin(),
		 * these failure points will need to unreserve the anon
		 * reserved using anon_unresv().
		 *
		 * Once ipc_commit_begin() is called, the anon reserved
		 * above will be automatically unreserved by future calls to
		 * ipcs_cleanup() -> shm_dtor() -> shm_rm_amp().  If
		 * ipc_commit_begin() fails, it internally calls shm_dtor(),
		 * unreserving the above anon, and freeing the below amp.
		 */

		sp->shm_amp = anonmap_alloc(rsize, rsize, ANON_SLEEP);
		sp->shm_amp->a_sp = sp;
		/*
		 * Store the original user's requested size, in bytes,
		 * rather than the page-aligned size.  The former is
		 * used for IPC_STAT and shmget() lookups.  The latter
		 * is saved in the anon_map structure and is used for
		 * calls to the vm layer.
		 */
		sp->shm_segsz = size;
		sp->shm_atime = sp->shm_dtime = 0;
		sp->shm_ctime = gethrestime_sec();
		sp->shm_lpid = (pid_t)0;
		sp->shm_cpid = curproc->p_pid;
		sp->shm_ismattch = 0;
		sp->shm_sptinfo = NULL;
		/*
		 * Check limits one last time, push id into global
		 * visibility, and update resource usage counts.
		 */
		if (error = ipc_commit_begin(shm_svc, key, shmflg,
		    (kipc_perm_t *)sp)) {
			if (error == EAGAIN)
				goto top;
			return (error);
		}

		if ((rctl_test(rc_project_shmmax,
		    sp->shm_perm.ipc_proj->kpj_rctls, pp, rsize,
		    RCA_SAFE) & RCT_DENY) ||
		    (rctl_test(rc_zone_shmmax,
		    sp->shm_perm.ipc_zone_ref.zref_zone->zone_rctls, pp, rsize,
		    RCA_SAFE) & RCT_DENY)) {
			ipc_cleanup(shm_svc, (kipc_perm_t *)sp);
			return (EINVAL);
		}
		sp->shm_perm.ipc_proj->kpj_data.kpd_shmmax += rsize;
		sp->shm_perm.ipc_zone_ref.zref_zone->zone_shmmax += rsize;

		lock = ipc_commit_end(shm_svc, &sp->shm_perm);
	}

	if (AU_AUDITING())
		audit_ipcget(AT_IPC_SHM, (void *)sp);

	*rvp = (uintptr_t)(sp->shm_perm.ipc_id);

	mutex_exit(lock);
	return (0);
}

/*
 * shmids system call.
 */
static int
shmids(int *buf, uint_t nids, uint_t *pnids)
{
	return (ipc_ids(shm_svc, buf, nids, pnids));
}

/*
 * System entry point for shmat, shmctl, shmdt, and shmget system calls.
 */
static uintptr_t
shmsys(int opcode, uintptr_t a0, uintptr_t a1, uintptr_t a2)
{
	int	error;
	uintptr_t r_val = 0;

	switch (opcode) {
	case SHMAT:
		error = shmat((int)a0, (caddr_t)a1, (int)a2, &r_val);
		break;
	case SHMCTL:
		error = shmctl((int)a0, (int)a1, (void *)a2);
		break;
	case SHMDT:
		error = shmdt((caddr_t)a0);
		break;
	case SHMGET:
		error = shmget((key_t)a0, (size_t)a1, (int)a2, &r_val);
		break;
	case SHMIDS:
		error = shmids((int *)a0, (uint_t)a1, (uint_t *)a2);
		break;
	default:
		error = EINVAL;
		break;
	}

	if (error)
		return ((uintptr_t)set_errno(error));

	return (r_val);
}

/*
 * segacct_t comparator
 * This works as expected, with one minor change: the first of two real
 * segments with equal addresses is considered to be 'greater than' the
 * second.  We only return equal when searching using a template, in
 * which case we explicitly set the template segment's length to 0
 * (which is invalid for a real segment).
 */
static int
shm_sacompar(const void *x, const void *y)
{
	segacct_t *sa1 = (segacct_t *)x;
	segacct_t *sa2 = (segacct_t *)y;

	if (sa1->sa_addr < sa2->sa_addr) {
		return (-1);
	} else if (sa2->sa_len != 0) {
		if (sa1->sa_addr >= sa2->sa_addr + sa2->sa_len) {
			return (1);
		} else if (sa1->sa_len != 0) {
			return (1);
		} else {
			return (0);
		}
	} else if (sa1->sa_addr > sa2->sa_addr) {
		return (1);
	} else {
		return (0);
	}
}

/*
 * add this record to the segacct list.
 */
static void
sa_add(struct proc *pp, caddr_t addr, size_t len, ulong_t flags, kshmid_t *id)
{
	segacct_t *nsap;
	avl_tree_t *tree = NULL;
	avl_index_t where;

	nsap = kmem_alloc(sizeof (segacct_t), KM_SLEEP);
	nsap->sa_addr = addr;
	nsap->sa_len  = len;
	nsap->sa_flags = flags;
	nsap->sa_id = id;

	if (pp->p_segacct == NULL)
		tree = kmem_alloc(sizeof (avl_tree_t), KM_SLEEP);

	mutex_enter(&pp->p_lock);
	prbarrier(pp);			/* block /proc.  See shmgetid(). */

	if (pp->p_segacct == NULL) {
		avl_create(tree, shm_sacompar, sizeof (segacct_t),
		    offsetof(segacct_t, sa_tree));
		pp->p_segacct = tree;
	} else if (tree) {
		kmem_free(tree, sizeof (avl_tree_t));
	}

	/*
	 * We can ignore the result of avl_find, as the comparator will
	 * never return equal for segments with non-zero length.  This
	 * is a necessary hack to get around the fact that we do, in
	 * fact, have duplicate keys.
	 */
	(void) avl_find(pp->p_segacct, nsap, &where);
	avl_insert(pp->p_segacct, nsap, where);

	mutex_exit(&pp->p_lock);
}

/*
 * Duplicate parent's segacct records in child.
 */
void
shmfork(struct proc *ppp, struct proc *cpp)
{
	segacct_t *sap;
	kshmid_t *sp;
	kmutex_t *mp;

	ASSERT(ppp->p_segacct != NULL);

	/*
	 * We are the only lwp running in the parent so nobody can
	 * mess with our p_segacct list.  Thus it is safe to traverse
	 * the list without holding p_lock.  This is essential because
	 * we can't hold p_lock during a KM_SLEEP allocation.
	 */
	for (sap = (segacct_t *)avl_first(ppp->p_segacct); sap != NULL;
	    sap = (segacct_t *)AVL_NEXT(ppp->p_segacct, sap)) {
		sa_add(cpp, sap->sa_addr, sap->sa_len, sap->sa_flags,
		    sap->sa_id);
		sp = sap->sa_id;
		mp = ipc_lock(shm_svc, sp->shm_perm.ipc_id);
		if (sap->sa_flags & SHMSA_ISM)
			sp->shm_ismattch++;
		ipc_hold(shm_svc, (kipc_perm_t *)sp);
		mutex_exit(mp);
	}
}

/*
 * Detach shared memory segments from exiting process.
 */
void
shmexit(struct proc *pp)
{
	segacct_t *sap;
	avl_tree_t *tree;
	void *cookie = NULL;

	ASSERT(pp->p_segacct != NULL);

	mutex_enter(&pp->p_lock);
	prbarrier(pp);
	tree = pp->p_segacct;
	pp->p_segacct = NULL;
	mutex_exit(&pp->p_lock);

	while ((sap = avl_destroy_nodes(tree, &cookie)) != NULL)
		(void) shm_detach(pp, sap);

	avl_destroy(tree);
	kmem_free(tree, sizeof (avl_tree_t));
}

/*
 * At this time pages should be in memory, so just lock them.
 */
static void
lock_again(size_t npages, kshmid_t *sp, struct anon_map *amp)
{
	struct anon *ap;
	struct page *pp;
	struct vnode *vp;
	u_offset_t off;
	ulong_t anon_idx;
	anon_sync_obj_t cookie;

	mutex_enter(&sp->shm_mlock);
	ANON_LOCK_ENTER(&amp->a_rwlock, RW_READER);
	for (anon_idx = 0; npages != 0; anon_idx++, npages--) {

		anon_array_enter(amp, anon_idx, &cookie);
		ap = anon_get_ptr(amp->ahp, anon_idx);
		ASSERT(ap != NULL);
		swap_xlate(ap, &vp, &off);
		anon_array_exit(&cookie);

		pp = page_lookup(vp, off, SE_SHARED);
		if (pp == NULL) {
			panic("lock_again: page not in the system");
			/*NOTREACHED*/
		}
		/* page should already be locked by caller */
		ASSERT(pp->p_lckcnt > 0);
		(void) page_pp_lock(pp, 0, 0);
		page_unlock(pp);
	}
	ANON_LOCK_EXIT(&amp->a_rwlock);
	mutex_exit(&sp->shm_mlock);
}

/*
 * Attach the shared memory segment to the process
 * address space and lock the pages.
 */
static int
shmem_lock(kshmid_t *sp, struct anon_map *amp)
{
	size_t npages = btopr(amp->size);
	struct as *as;
	struct segvn_crargs crargs;
	uint_t error;

	/*
	 * A later ISM/DISM attach may increase the size of the amp, so
	 * cache the number of pages locked for the future shmem_unlock()
	 */
	sp->shm_lkpages = npages;

	as = as_alloc();
	/* Initialize the create arguments and map the segment */
	crargs = *(struct segvn_crargs *)zfod_argsp;	/* structure copy */
	crargs.offset = (u_offset_t)0;
	crargs.type = MAP_SHARED;
	crargs.amp = amp;
	crargs.prot = PROT_ALL;
	crargs.maxprot = crargs.prot;
	crargs.flags = 0;
	error = as_map(as, 0x0, amp->size, segvn_create, &crargs);
	if (!error) {
		if ((error = as_ctl(as, 0x0, amp->size, MC_LOCK, 0, 0,
		    NULL, 0)) == 0) {
			lock_again(npages, sp, amp);
		}
		(void) as_unmap(as, 0x0, amp->size);
	}
	as_free(as);
	return (error);
}


/*
 * Unlock shared memory
 */
static void
shmem_unlock(kshmid_t *sp, struct anon_map *amp)
{
	struct anon *ap;
	pgcnt_t npages = sp->shm_lkpages;
	struct vnode *vp;
	struct page *pp;
	u_offset_t off;
	ulong_t anon_idx;
	size_t unlocked_bytes = 0;
	kproject_t	*proj;
	anon_sync_obj_t cookie;

	proj = sp->shm_perm.ipc_proj;
	mutex_enter(&sp->shm_mlock);
	ANON_LOCK_ENTER(&amp->a_rwlock, RW_READER);
	for (anon_idx = 0; anon_idx < npages; anon_idx++) {

		anon_array_enter(amp, anon_idx, &cookie);
		if ((ap = anon_get_ptr(amp->ahp, anon_idx)) == NULL) {
			panic("shmem_unlock: null app");
			/*NOTREACHED*/
		}
		swap_xlate(ap, &vp, &off);
		anon_array_exit(&cookie);
		pp = page_lookup(vp, off, SE_SHARED);
		if (pp == NULL) {
			panic("shmem_unlock: page not in the system");
			/*NOTREACHED*/
		}
		/*
		 * Page should at least have once lock from previous
		 * shmem_lock
		 */
		ASSERT(pp->p_lckcnt > 0);
		page_pp_unlock(pp, 0, 0);
		if (pp->p_lckcnt == 0)
			unlocked_bytes += PAGESIZE;

		page_unlock(pp);
	}

	if (unlocked_bytes > 0) {
		rctl_decr_locked_mem(NULL, proj, unlocked_bytes, 0);
	}

	ANON_LOCK_EXIT(&amp->a_rwlock);
	mutex_exit(&sp->shm_mlock);
}

/*
 * We call this routine when we have removed all references to this
 * amp.  This means all shmdt()s and the IPC_RMID have been done.
 */
static void
shm_rm_amp(kshmid_t *sp)
{
	struct anon_map *amp = sp->shm_amp;
	zone_t *zone;

	zone = sp->shm_perm.ipc_zone_ref.zref_zone;
	ASSERT(zone != NULL);
	/*
	 * Free up the anon_map.
	 */
	lgrp_shm_policy_fini(amp, NULL);
	ANON_LOCK_ENTER(&amp->a_rwlock, RW_WRITER);
	if (amp->a_szc != 0) {
		anon_shmap_free_pages(amp, 0, amp->size);
	} else {
		anon_free(amp->ahp, 0, amp->size);
	}
	ANON_LOCK_EXIT(&amp->a_rwlock);
	anon_unresv_zone(amp->swresv, zone);
	anonmap_free(amp);
}

/*
 * Return the shared memory id for the process's virtual address.
 * Return SHMID_NONE if addr is not within a SysV shared memory segment.
 * Return SHMID_FREE if addr's SysV shared memory segment's id has been freed.
 *
 * shmgetid() is called from code in /proc with the process locked but
 * with pp->p_lock not held.  The address space lock is held, so we
 * cannot grab pp->p_lock here due to lock-ordering constraints.
 * Because of all this, modifications to the p_segacct list must only
 * be made after calling prbarrier() to ensure the process is not locked.
 * See shmdt() and sa_add(), above. shmgetid() may also be called on a
 * thread's own process without the process locked.
 */
int
shmgetid(proc_t *pp, caddr_t addr)
{
	segacct_t *sap, template;

	ASSERT(MUTEX_NOT_HELD(&pp->p_lock));
	ASSERT((pp->p_proc_flag & P_PR_LOCK) || pp == curproc);

	if (pp->p_segacct == NULL)
		return (SHMID_NONE);

	template.sa_addr = addr;
	template.sa_len = 0;
	if ((sap = avl_find(pp->p_segacct, &template, NULL)) == NULL)
		return (SHMID_NONE);

	if (IPC_FREE(&sap->sa_id->shm_perm))
		return (SHMID_FREE);

	return (sap->sa_id->shm_perm.ipc_id);
}

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
 * Copyright 2016 Joyent, Inc.  All rights reserved.
 */

/*
 * lxprsubr.c: Various functions for the /lxproc vnodeops.
 */

#include <sys/varargs.h>

#include <sys/cpuvar.h>
#include <sys/mman.h>
#include <sys/vmsystm.h>
#include <sys/prsystm.h>
#include <sys/zfs_ioctl.h>
#include <sys/brand.h>
#include <sys/lx_brand.h>

#include "lx_proc.h"

#define	LXPRCACHE_NAME "lxbpr_cache"

static int lxpr_node_constructor(void *, void *, int);
static void lxpr_node_destructor(void *, void *);

static kmem_cache_t *lxpr_node_cache;

int lx_pr_bufsize = 4000;

struct lxpr_zfs_ds {
	list_node_t	ds_link;
	char		ds_name[MAXPATHLEN];
	uint64_t	ds_cookie;
};

struct lxpr_uiobuf *
lxpr_uiobuf_new(uio_t *uiop)
{
	/* Allocate memory for both lxpr_uiobuf and output buffer */
	int bufsize = lx_pr_bufsize;
	struct lxpr_uiobuf *uiobuf =
	    kmem_alloc(sizeof (struct lxpr_uiobuf) + bufsize, KM_SLEEP);

	uiobuf->uiop = uiop;
	uiobuf->buffer = (char *)&uiobuf[1];
	uiobuf->buffsize = bufsize;
	uiobuf->pos = uiobuf->buffer;
	uiobuf->beg = 0;
	uiobuf->error = 0;

	return (uiobuf);
}

void
lxpr_uiobuf_free(struct lxpr_uiobuf *uiobuf)
{
	ASSERT(uiobuf != NULL);
	ASSERT(uiobuf->pos == uiobuf->buffer);

	kmem_free(uiobuf, sizeof (struct lxpr_uiobuf) + uiobuf->buffsize);
}

void
lxpr_uiobuf_seek(struct lxpr_uiobuf *uiobuf, offset_t offset)
{
	uiobuf->uiop->uio_offset = (off_t)offset;
}

boolean_t
lxpr_uiobuf_nonblock(struct lxpr_uiobuf *uiobuf)
{
	if ((uiobuf->uiop->uio_fmode & FNONBLOCK) != 0)
		return (B_TRUE);
	return (B_FALSE);
}

void
lxpr_uiobuf_seterr(struct lxpr_uiobuf *uiobuf, int err)
{
	ASSERT(uiobuf->error == 0);

	uiobuf->error = err;
}

int
lxpr_uiobuf_flush(struct lxpr_uiobuf *uiobuf)
{
	off_t off = uiobuf->uiop->uio_offset;
	caddr_t uaddr = uiobuf->buffer;
	size_t beg = uiobuf->beg;
	size_t size = (uintptr_t)uiobuf->pos - (uintptr_t)uaddr;

	if (uiobuf->error == 0 && uiobuf->uiop->uio_resid != 0) {
		ASSERT(off >= beg);

		if (beg + size > off && off >= 0)
			uiobuf->error =
			    uiomove(uaddr + (off - beg), size - (off - beg),
			    UIO_READ, uiobuf->uiop);

		uiobuf->beg += size;
	}

	uiobuf->pos = uaddr;

	return (uiobuf->error);
}

void
lxpr_uiobuf_write(struct lxpr_uiobuf *uiobuf, const char *buf, size_t size)
{
	/* While we can still carry on */
	while (uiobuf->error == 0 && uiobuf->uiop->uio_resid != 0) {
		uintptr_t remain = (uintptr_t)uiobuf->buffsize -
		    ((uintptr_t)uiobuf->pos - (uintptr_t)uiobuf->buffer);

		/* Enough space in buffer? */
		if (remain >= size) {
			bcopy(buf, uiobuf->pos, size);
			uiobuf->pos += size;
			return;
		}

		/* Not enough space, so copy all we can and try again */
		bcopy(buf, uiobuf->pos, remain);
		uiobuf->pos += remain;
		(void) lxpr_uiobuf_flush(uiobuf);
		buf += remain;
		size -= remain;
	}
}

#define	TYPBUFFSIZE 256

void
lxpr_uiobuf_printf(struct lxpr_uiobuf *uiobuf, const char *fmt, ...)
{
	va_list args;
	char buff[TYPBUFFSIZE];
	int len;
	char *buffer;

	/* Can we still do any output */
	if (uiobuf->error != 0 || uiobuf->uiop->uio_resid == 0)
		return;

	va_start(args, fmt);

	/* Try using stack allocated buffer */
	len = vsnprintf(buff, TYPBUFFSIZE, fmt, args);
	if (len < TYPBUFFSIZE) {
		va_end(args);
		lxpr_uiobuf_write(uiobuf, buff, len);
		return;
	}

	/* Not enough space in pre-allocated buffer */
	buffer = kmem_alloc(len + 1, KM_SLEEP);

	/*
	 * We know we allocated the correct amount of space
	 * so no check on the return value
	 */
	(void) vsnprintf(buffer, len+1, fmt, args);
	lxpr_uiobuf_write(uiobuf, buffer, len);
	va_end(args);
	kmem_free(buffer, len+1);
}

/*
 * Lookup process, potentially constrained by pid associated with lxpr_node and
 * return with p_lock and P_PR_LOCK held.
 */
proc_t *
lxpr_lock_pid(lxpr_node_t *lxpnp, pid_t pid, zombok_t zombie_ok,
    kthread_t **tp)
{
	zone_t *zone = LXPTOZ(lxpnp);
	proc_t *p;
	kthread_t *t;

	ASSERT(!MUTEX_HELD(&pidlock));

retry:
	if (pid == 0) {
		/*
		 * Present zsched as pid 0 for the zone.  There is no worry
		 * about zsched disappearing during sprlock_proc() since the
		 * zone (and zsched) will persist until all zone filesystems,
		 * include this one, are unmounted.
		 */
		p = zone->zone_zsched;
		mutex_enter(&p->p_lock);
		sprlock_proc(p);
	} else {
		if (lx_lpid_lock(pid, zone, PRLOCK, &p, &t) != 0) {
			return (NULL);
		}
	}

	/*
	 * Make sure that thread lookups (where non-main LX threads are
	 * assigned a pid not equal to the encompassing parent) match the pid
	 * of the encompasing directory.  This must be performed carefully for
	 * the Linux pid 1 as it will not equal the native pid despite the
	 * process matching.
	 *
	 * This is necessary to constrain paths such as /proc/<pid>/task/<tid>.
	 */
	if (lxpnp->lxpr_pid != 0 && lxpnp->lxpr_pid != pid &&
	    !(pid == 1 && lxpnp->lxpr_pid == zone->zone_proc_initpid)) {
		klwp_t *lwp;
		lx_lwp_data_t *lwpd;

		/*
		 * Only LWPs of branded processes will be accessible this way.
		 * The threads of native processes lack pid assignments which
		 * LX uses to emulate Linux's weird thread/process model.
		 */
		if ((lwp = ttolwp(t)) == NULL ||
		    (lwpd = lwptolxlwp(lwp)) == NULL ||
		    lwpd->br_pid != pid) {
			sprunlock(p);
			return (NULL);
		}
	}

	if (zombie_ok == NO_ZOMB &&
	    ((p->p_flag & SEXITING) || p->p_stat == SZOMB)) {
		sprunlock(p);
		return (NULL);
	}

	/*
	 * Accessing a process which is undergoing exec(2) is somewhat risky.
	 * In particular, the p_exec field is updated outside p_lock.  To avoid
	 * this mess, access is denied when P_PR_EXEC set unless the caller
	 * happens to be the process itself.  This allows actions such as
	 * re-exec()-ing /proc/<pid>/exe to make forward progress.
	 *
	 * All other callers must block until the flag is cleared.
	 */
	if ((p->p_proc_flag & P_PR_EXEC) != 0) {
		if (p != curproc) {
			kmutex_t *mp;

			/*
			 * Drop PR_LOCK and wait for the exec() to ping the CV
			 * once it has completed.  Afterward, the pid is looked
			 * up again in case the process exited for some reason.
			 */
			mp = &p->p_lock;
			sprunprlock(p);
			cv_wait(&pr_pid_cv[p->p_slot], mp);
			mutex_exit(mp);
			goto retry;
		}
	}

	if (tp != NULL) {
		*tp = t;
	}
	return (p);
}


/*
 * Lookup process from pid associated with lxpr_node and return with p_lock and
 * P_PR_LOCK held.
 */
proc_t *
lxpr_lock(lxpr_node_t *lxpnp, zombok_t zombie_ok)
{
	return (lxpr_lock_pid(lxpnp, lxpnp->lxpr_pid, zombie_ok, NULL));
}

void
lxpr_fixpid(zone_t *zone, proc_t *p, pid_t *pidp, pid_t *ppidp)
{
	pid_t pid = p->p_pid;
	pid_t ppid = p->p_ppid;

	ASSERT(p != NULL);
	ASSERT(pidp != NULL);
	ASSERT(zone->zone_brand == &lx_brand);

	if (pid == zone->zone_proc_initpid) {
		pid = 1;
		ppid = 0;	/* parent pid for init is 0 */
	} else if (pid == zone->zone_zsched->p_pid) {
		pid = 0;	/* zsched is pid 0 */
		ppid = 0;	/* parent pid for zsched is itself */
	} else {
		/*
		 * Make sure not to reference parent PIDs that reside outside
		 * the zone
		 */
		if ((p->p_flag & SZONETOP) != 0) {
			ppid = 0;
		}

		/*
		 * Convert ppid to the Linux default of 1 if our parent is the
		 * zone's init process
		 */
		if (ppid == zone->zone_proc_initpid) {
			ppid = 1;
		}
	}

	*pidp = pid;
	if (ppidp != NULL) {
		*ppidp = ppid;
	}
}

/*
 * lxpr_unlock()
 *
 * Unlock locked process
 */
void
lxpr_unlock(proc_t *p)
{
	ASSERT(p->p_proc_flag & P_PR_LOCK);
	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(!MUTEX_HELD(&pidlock));

	cv_signal(&pr_pid_cv[p->p_slot]);
	p->p_proc_flag &= ~P_PR_LOCK;
	mutex_exit(&p->p_lock);
	THREAD_KPRI_RELEASE();
}

void
lxpr_initnodecache()
{
	lxpr_node_cache = kmem_cache_create(LXPRCACHE_NAME,
	    sizeof (lxpr_node_t), 0,
	    lxpr_node_constructor, lxpr_node_destructor, NULL, NULL, NULL, 0);
}

void
lxpr_fininodecache()
{
	kmem_cache_destroy(lxpr_node_cache);
}

/* ARGSUSED */
static int
lxpr_node_constructor(void *buf, void *un, int kmflags)
{
	lxpr_node_t	*lxpnp = buf;
	vnode_t		*vp;

	vp = lxpnp->lxpr_vnode = vn_alloc(kmflags);
	if (vp == NULL)
		return (-1);

	(void) vn_setops(vp, lxpr_vnodeops);
	vp->v_data = lxpnp;

	return (0);
}

/* ARGSUSED */
static void
lxpr_node_destructor(void *buf, void *un)
{
	lxpr_node_t	*lxpnp = buf;

	vn_free(LXPTOV(lxpnp));
}

/*
 * Calculate an inode number
 *
 * This takes various bits of info and munges them
 * to give the inode number for an lxproc node
 */
ino_t
lxpr_inode(lxpr_nodetype_t type, pid_t pid, int desc)
{
	switch (type) {
	case LXPR_PIDDIR:
		return (maxpid + pid + 1);
	case LXPR_PID_TASK_IDDIR:
		return (maxpid + (desc * 10));
	case LXPR_PROCDIR:
		return (maxpid + 2);
	case LXPR_PID_FD_FD:
		return (maxpid + 2 +
		    (pid * (LXPR_FD_PERPROC + LXPR_NFILES)) +
		    LXPR_NFILES + desc);
	default:
		return (maxpid + 2 +
		    (pid * (LXPR_FD_PERPROC + LXPR_NFILES)) +
		    type);
	}
}

/*
 * Return inode number of parent (directory)
 */
ino_t
lxpr_parentinode(lxpr_node_t *lxpnp)
{
	/*
	 * If the input node is the root then the parent inode
	 * is the mounted on inode so just return our inode number
	 */
	if (lxpnp->lxpr_type != LXPR_PROCDIR)
		return (VTOLXP(lxpnp->lxpr_parent)->lxpr_ino);
	else
		return (lxpnp->lxpr_ino);
}

/*
 * Allocate a new lxproc node
 *
 * This also allocates the vnode associated with it
 */
lxpr_node_t *
lxpr_getnode(vnode_t *dp, lxpr_nodetype_t type, proc_t *p, int desc)
{
	lxpr_node_t *lxpnp;
	vnode_t *vp;
	user_t *up;
	timestruc_t now;

	/*
	 * Allocate a new node. It is deallocated in vop_inactive
	 */
	lxpnp = kmem_cache_alloc(lxpr_node_cache, KM_SLEEP);

	/*
	 * Set defaults (may be overridden below)
	 */
	gethrestime(&now);
	lxpnp->lxpr_type = type;
	lxpnp->lxpr_realvp = NULL;
	lxpnp->lxpr_parent = dp;
	lxpnp->lxpr_desc = desc;
	VN_HOLD(dp);
	if (p != NULL) {
		lxpr_node_t *dlxpnp = VTOLXP(dp);

		lxpnp->lxpr_pid = p->p_pid;
		/* Propagate the tid whenever possible. */
		if (desc == 0 && dlxpnp->lxpr_desc != 0) {
			lxpnp->lxpr_desc = dlxpnp->lxpr_desc;
		}
		lxpnp->lxpr_time = PTOU(p)->u_start;
		lxpnp->lxpr_uid = crgetruid(p->p_cred);
		lxpnp->lxpr_gid = crgetrgid(p->p_cred);
		lxpnp->lxpr_ino = lxpr_inode(type, p->p_pid, desc);
	} else {
		/* Pretend files without a proc belong to sched */
		lxpnp->lxpr_pid = 0;
		lxpnp->lxpr_time = now;
		lxpnp->lxpr_uid = lxpnp->lxpr_gid = 0;
		lxpnp->lxpr_ino = lxpr_inode(type, 0, 0);
	}

	/* initialize the vnode data */
	vp = lxpnp->lxpr_vnode;
	vn_reinit(vp);
	vp->v_flag = VNOCACHE|VNOMAP|VNOSWAP|VNOMOUNT;
	vp->v_vfsp = dp->v_vfsp;

	/*
	 * Do node specific stuff
	 */
	if (lxpr_is_writable(type)) {
		/* These two have different modes; handled later. */
		if (type != LXPR_PID_FD_FD && type != LXPR_PID_TID_FD_FD) {
			vp->v_type = VREG;
			lxpnp->lxpr_mode = 0644;
			return (lxpnp);
		}
	}

	switch (type) {
	case LXPR_PROCDIR:
		vp->v_flag |= VROOT;
		vp->v_type = VDIR;
		lxpnp->lxpr_mode = 0555;	/* read-search by everyone */
		break;

	case LXPR_PID_CURDIR:
		ASSERT(p != NULL);

		/*
		 * Zombie check.  p_stat is officially protected by pidlock,
		 * but we can't grab pidlock here because we already hold
		 * p_lock.  Luckily if we look at the process exit code
		 * we see that p_stat only transisions from SRUN to SZOMB
		 * while p_lock is held.  Aside from this, the only other
		 * p_stat transition that we need to be aware about is
		 * SIDL to SRUN, but that's not a problem since lxpr_lock()
		 * ignores nodes in the SIDL state so we'll never get a node
		 * that isn't already in the SRUN state.
		 */
		if (p->p_stat == SZOMB) {
			lxpnp->lxpr_realvp = NULL;
		} else {
			up = PTOU(p);
			lxpnp->lxpr_realvp = up->u_cdir;
			ASSERT(lxpnp->lxpr_realvp != NULL);
			VN_HOLD(lxpnp->lxpr_realvp);
		}
		vp->v_type = VLNK;
		lxpnp->lxpr_mode = 0777;	/* anyone does anything ! */
		break;

	case LXPR_PID_ROOTDIR:
		ASSERT(p != NULL);
		/* Zombie check.  see locking comment above */
		if (p->p_stat == SZOMB) {
			lxpnp->lxpr_realvp = NULL;
		} else {
			up = PTOU(p);
			lxpnp->lxpr_realvp =
			    up->u_rdir != NULL ? up->u_rdir : rootdir;
			ASSERT(lxpnp->lxpr_realvp != NULL);
			VN_HOLD(lxpnp->lxpr_realvp);
		}
		vp->v_type = VLNK;
		lxpnp->lxpr_mode = 0777;	/* anyone does anything ! */
		break;

	case LXPR_PID_EXE:
		ASSERT(p != NULL);
		lxpnp->lxpr_realvp = p->p_exec;
		if (lxpnp->lxpr_realvp != NULL) {
			VN_HOLD(lxpnp->lxpr_realvp);
		}
		vp->v_type = VLNK;
		lxpnp->lxpr_mode = 0777;
		break;

	case LXPR_SELF:
		vp->v_type = VLNK;
		lxpnp->lxpr_mode = 0777;	/* anyone does anything ! */
		break;

	case LXPR_PID_TASKDIR:
		ASSERT(p != NULL);
		vp->v_type = VDIR;
		lxpnp->lxpr_mode = 0555;	/* read-search by everyone */
		break;

	case LXPR_PID_TASK_IDDIR:
		ASSERT(p != NULL);
		vp->v_type = VDIR;
		lxpnp->lxpr_mode = 0555;	/* read-search by everyone */
		break;

	case LXPR_PID_FD_FD:
	case LXPR_PID_TID_FD_FD:
		ASSERT(p != NULL);
		/* lxpr_realvp is set after we return */
		lxpnp->lxpr_mode = 0700;	/* read-write-exe owner only */
		vp->v_type = VLNK;
		break;

	case LXPR_PID_FDDIR:
	case LXPR_PID_TID_FDDIR:
		ASSERT(p != NULL);
		vp->v_type = VDIR;
		lxpnp->lxpr_mode = 0500;	/* read-search by owner only */
		break;

	case LXPR_PIDDIR:
		ASSERT(p != NULL);
		vp->v_type = VDIR;
		lxpnp->lxpr_mode = 0511;
		break;

	case LXPR_NETDIR:
	case LXPR_SYSDIR:
	case LXPR_SYS_FSDIR:
	case LXPR_SYS_FS_INOTIFYDIR:
	case LXPR_SYS_KERNELDIR:
	case LXPR_SYS_KERNEL_RANDDIR:
	case LXPR_SYS_NETDIR:
	case LXPR_SYS_NET_COREDIR:
	case LXPR_SYS_NET_IPV4DIR:
	case LXPR_SYS_VMDIR:
		vp->v_type = VDIR;
		lxpnp->lxpr_mode = 0555;	/* read-search by all */
		break;

	case LXPR_PID_ENV:
	case LXPR_PID_MEM:
		ASSERT(p != NULL);
		/*FALLTHRU*/
	case LXPR_KCORE:
		vp->v_type = VREG;
		lxpnp->lxpr_mode = 0400;	/* read-only by owner only */
		break;

	default:
		vp->v_type = VREG;
		lxpnp->lxpr_mode = 0444;	/* read-only by all */
		break;
	}

	return (lxpnp);
}


/*
 * Free the storage obtained from lxpr_getnode().
 */
void
lxpr_freenode(lxpr_node_t *lxpnp)
{
	ASSERT(lxpnp != NULL);
	ASSERT(LXPTOV(lxpnp) != NULL);

	/*
	 * delete any association with realvp
	 */
	if (lxpnp->lxpr_realvp != NULL)
		VN_RELE(lxpnp->lxpr_realvp);

	/*
	 * delete any association with parent vp
	 */
	if (lxpnp->lxpr_parent != NULL)
		VN_RELE(lxpnp->lxpr_parent);

	/*
	 * Release the lxprnode.
	 */
	kmem_cache_free(lxpr_node_cache, lxpnp);
}

/*
 * Attempt to locate vnode for /proc/<pid>/fd/<#>.
 */
vnode_t *
lxpr_lookup_fdnode(vnode_t *dvp, const char *name)
{
	lxpr_node_t *lxdp = VTOLXP(dvp);
	lxpr_node_t *lxfp;
	char *endptr = NULL;
	long num;
	int fd;
	proc_t *p;
	vnode_t *vp = NULL;
	file_t *fp;
	uf_entry_t *ufp;
	uf_info_t *fip;

	ASSERT(lxdp->lxpr_type == LXPR_PID_FDDIR ||
	    lxdp->lxpr_type == LXPR_PID_TID_FDDIR);

	if (ddi_strtol(name, &endptr, 10, &num) != 0) {
		return (NULL);
	} else if (name[0] < '0' || name[0] > '9' || *endptr != '\0') {
		/*
		 * ddi_strtol allows leading spaces and trailing garbage
		 * We do not tolerate such foolishness.
		 */
		return (NULL);
	} else if ((fd = (int)num) < 0) {
		return (NULL);
	}

	/* Lock the owner process */
	if ((p = lxpr_lock(lxdp, NO_ZOMB)) == NULL) {
		return (NULL);
	}

	/* Not applicable to processes which are system-owned. */
	if (p->p_as == &kas) {
		lxpr_unlock(p);
		return (NULL);
	}

	lxfp = lxpr_getnode(dvp, LXPR_PID_FD_FD, p, fd);

	/*
	 * Drop p_lock, but keep the process P_PR_LOCK'd to prevent it from
	 * going away while we dereference into fi_list.
	 */
	fip = P_FINFO(p);
	mutex_exit(&p->p_lock);
	mutex_enter(&fip->fi_lock);
	if (fd < fip->fi_nfiles) {
		UF_ENTER(ufp, fip, fd);
		if ((fp = ufp->uf_file) != NULL) {
			vp = fp->f_vnode;
			VN_HOLD(vp);
		}
		UF_EXIT(ufp);
	}
	mutex_exit(&fip->fi_lock);

	if (vp == NULL) {
		mutex_enter(&p->p_lock);
		lxpr_unlock(p);
		lxpr_freenode(lxfp);
		return (NULL);
	} else {
		/*
		 * Fill in the lxpr_node so future references will be able to
		 * find the underlying vnode. The vnode is held on the realvp.
		 */
		lxfp->lxpr_realvp = vp;

		/*
		 * For certain entries (sockets, pipes, etc), Linux expects a
		 * bogus-named symlink.  If that's the case, report the type as
		 * VNON to bypass link-following elsewhere in the vfs system.
		 *
		 * See lxpr_readlink for more details.
		 */
		if (lxpr_readlink_fdnode(lxfp, NULL, 0) == 0)
			LXPTOV(lxfp)->v_type = VNON;
	}

	mutex_enter(&p->p_lock);
	lxpr_unlock(p);
	ASSERT(LXPTOV(lxfp) != NULL);
	return (LXPTOV(lxfp));
}

/*
 * Attempt to create Linux-proc-style fake symlinks contents for supported
 * /proc/<pid>/fd/<#> entries.
 */
int
lxpr_readlink_fdnode(lxpr_node_t *lxpnp, char *bp, size_t len)
{
	const char *format;
	vnode_t *rvp = lxpnp->lxpr_realvp;
	vattr_t attr;

	switch (rvp->v_type) {
	case VSOCK:
		format = "socket:[%lu]";
		break;
	case VFIFO:
		format = "pipe:[%lu]";
		break;
	default:
		return (-1);
	}

	/* Fetch the inode of the underlying vnode */
	if (VOP_GETATTR(rvp, &attr, 0, CRED(), NULL) != 0)
		return (-1);

	if (bp != NULL)
		(void) snprintf(bp, len, format, (ino_t)attr.va_nodeid);
	return (0);
}

/*
 * Translate a Linux core_pattern path to a native Illumos one, by replacing
 * the appropriate % escape sequences.
 *
 * Any % escape sequences that are not recognised are double-escaped so that
 * they will be inserted literally into the path (to mimic Linux).
 */
int
lxpr_core_path_l2s(const char *inp, char *outp, size_t outsz)
{
	int i = 0, j = 0;
	char x;

	while (j < outsz - 1) {
		x = inp[i++];
		if (x == '\0')
			break;
		if (x != '%') {
			outp[j++] = x;
			continue;
		}

		x = inp[i++];
		if (x == '\0')
			break;

		/* Make sure we have enough space in the output buffer. */
		if (j + 2 >= outsz - 1)
			return (EINVAL);

		switch (x) {
		case 'E':
			if (j + 4 >= outsz - 1)
				return (EINVAL);
			outp[j++] = '%';
			outp[j++] = 'd';
			outp[j++] = '%';
			outp[j++] = 'f';
			break;
		case 'e':
			outp[j++] = '%';
			outp[j++] = 'f';
			break;
		case 'p':
		case 'g':
		case 'u':
		case 't':
		case '%':
			outp[j++] = '%';
			outp[j++] = x;
			break;
		case 'h':
			outp[j++] = '%';
			outp[j++] = 'n';
			break;
		default:
			/* No translation, make it literal. */
			if (j + 3 >= outsz - 1)
				return (EINVAL);
			outp[j++] = '%';
			outp[j++] = '%';
			outp[j++] = x;
			break;
		}
	}

	outp[j] = '\0';
	return (0);
}

/*
 * Translate an Illumos core pattern path back to Linux format.
 */
int
lxpr_core_path_s2l(const char *inp, char *outp, size_t outsz)
{
	int i = 0, j = 0;
	char x;

	while (j < outsz - 1) {
		x = inp[i++];
		if (x == '\0')
			break;
		if (x != '%') {
			outp[j++] = x;
			continue;
		}

		x = inp[i++];
		if (x == '\0')
			break;

		/* Make sure we have enough space in the output buffer. */
		if (j + 2 >= outsz - 1)
			return (EINVAL);

		switch (x) {
		case 'd':
			/* No Linux equivalent unless it's %d%f. */
			if (inp[i] == '%' && inp[i + 1] == 'f') {
				i += 2;
				outp[j++] = '%';
				outp[j++] = 'E';
			}
			break;
		case 'f':
			outp[j++] = '%';
			outp[j++] = 'e';
			break;
		case 'p':
		case 'P':
		case 'g':
		case 'u':
		case 't':
		case '%':
			outp[j++] = '%';
			outp[j++] = (x == 'P' ? 'p' : x);
			break;
		case 'n':
			outp[j++] = '%';
			outp[j++] = 'h';
			break;
		default:
			/* No translation. */
			break;
		}
	}

	outp[j] = '\0';
	return (0);
}

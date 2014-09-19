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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * lxprsubr.c: Various functions for the /lxproc vnodeops.
 */

#include <sys/varargs.h>

#include <sys/cpuvar.h>
#include <sys/mman.h>
#include <sys/vmsystm.h>
#include <sys/prsystm.h>

#include "lx_proc.h"

#define	LXPRCACHE_NAME "lxbpr_cache"

static int lxpr_node_constructor(void *, void *, int);
static void lxpr_node_destructor(void *, void *);

static kmem_cache_t *lxpr_node_cache;

struct lxpr_uiobuf {
	uio_t *uiop;
	char *buffer;
	uint32_t buffsize;
	char *pos;
	size_t beg;
	int error;
};

int lx_pr_bufsize = 4000;

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
 * lxpr_lock():
 *
 * Lookup process from pid and return with p_plock and P_PR_LOCK held.
 */
proc_t *
lxpr_lock(pid_t pid)
{
	proc_t *p;
	kmutex_t *mp;

	ASSERT(!MUTEX_HELD(&pidlock));

	for (;;) {
		mutex_enter(&pidlock);

		/*
		 * If the pid is 1, we really want the zone's init process
		 */
		p = prfind((pid == 1) ?
		    curproc->p_zone->zone_proc_initpid : pid);

		if (p == NULL || p->p_stat == SIDL) {
			mutex_exit(&pidlock);
			return (NULL);
		}

		/*
		 * p_lock is persistent, but p itself is not -- it could
		 * vanish during cv_wait().  Load p->p_lock now so we can
		 * drop it after cv_wait() without referencing p.
		 */
		mp = &p->p_lock;
		mutex_enter(mp);

		mutex_exit(&pidlock);

		if (p->p_flag & SEXITING) {
			/*
			 * This process is exiting -- let it go.
			 */
			mutex_exit(mp);
			return (NULL);
		}

		if (!(p->p_proc_flag & P_PR_LOCK))
			break;

		cv_wait(&pr_pid_cv[p->p_slot], mp);
		mutex_exit(mp);
	}

	p->p_proc_flag |= P_PR_LOCK;
	THREAD_KPRI_REQUEST();
	return (p);
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
lxpr_inode(lxpr_nodetype_t type, pid_t pid, int fd)
{
	if (pid == 1)
		pid = curproc->p_zone->zone_proc_initpid;

	switch (type) {
	case LXPR_PIDDIR:
		return (pid + 1);
	case LXPR_PROCDIR:
		return (maxpid + 2);
	case LXPR_PID_FD_FD:
		return (maxpid + 2 +
		    (pid * (LXPR_FD_PERPROC + LXPR_NFILES)) +
		    LXPR_NFILES + fd);
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
lxpr_getnode(vnode_t *dp, lxpr_nodetype_t type, proc_t *p, int fd)
{
	lxpr_node_t *lxpnp;
	vnode_t *vp;
	user_t *up;
	timestruc_t now;

	/*
	 * Allocate a new node. It is deallocated in vop_innactive
	 */
	lxpnp = kmem_cache_alloc(lxpr_node_cache, KM_SLEEP);

	/*
	 * Set defaults (may be overridden below)
	 */
	gethrestime(&now);
	lxpnp->lxpr_type = type;
	lxpnp->lxpr_realvp = NULL;
	lxpnp->lxpr_parent = dp;
	VN_HOLD(dp);
	if (p != NULL) {
		lxpnp->lxpr_pid = ((p->p_pid ==
		    curproc->p_zone->zone_proc_initpid) ? 1 : p->p_pid);

		lxpnp->lxpr_time = PTOU(p)->u_start;
		lxpnp->lxpr_uid = crgetruid(p->p_cred);
		lxpnp->lxpr_gid = crgetrgid(p->p_cred);
		lxpnp->lxpr_ino = lxpr_inode(type, p->p_pid, fd);
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

	case LXPR_PID_FD_FD:
		ASSERT(p != NULL);
		/* lxpr_realvp is set after we return */
		vp->v_type = VLNK;
		lxpnp->lxpr_mode = 0700;	/* read-write-exe owner only */
		break;

	case LXPR_PID_FDDIR:
		ASSERT(p != NULL);
		vp->v_type = VDIR;
		lxpnp->lxpr_mode = 0500;	/* read-search by owner only */
		break;

	case LXPR_PIDDIR:
		ASSERT(p != NULL);
		vp->v_type = VDIR;
		lxpnp->lxpr_mode = 0511;
		break;

	case LXPR_SYSDIR:
	case LXPR_SYS_FSDIR:
	case LXPR_SYS_FS_INOTIFYDIR:
	case LXPR_SYS_KERNELDIR:
	case LXPR_NETDIR:
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

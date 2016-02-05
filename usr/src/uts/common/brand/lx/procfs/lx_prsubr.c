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

#include "lx_proc.h"

#define	LXPRCACHE_NAME "lxbpr_cache"

static int lxpr_node_constructor(void *, void *, int);
static void lxpr_node_destructor(void *, void *);

static kmem_cache_t *lxpr_node_cache;

static ddi_modhandle_t	lxpr_zfs_mod = NULL;
static int (*lxpr_zvol_name2minor_fp)(char *, minor_t *) = NULL;
static int (*lxpr_zvol_create_minor_fp)(char *) = NULL;

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
 * lxpr_lock():
 *
 * Lookup process from pid and return with p_plock and P_PR_LOCK held.
 */
proc_t *
lxpr_lock(pid_t pid)
{
	proc_t *p;
	kmutex_t *mp;
	pid_t find_pid;

	ASSERT(!MUTEX_HELD(&pidlock));

	for (;;) {
		mutex_enter(&pidlock);

		/*
		 * If the pid is 1, we really want the zone's init process;
		 * if 0 we want zsched.
		 */
		if (pid == 1) {
			find_pid = curproc->p_zone->zone_proc_initpid;
		} else if (pid == 0) {
			find_pid = curproc->p_zone->zone_zsched->p_pid;
		} else {
			find_pid = pid;
		}
		p = prfind(find_pid);

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
lxpr_inode(lxpr_nodetype_t type, pid_t pid, int desc)
{
	if (pid == 1) {
		pid = curproc->p_zone->zone_proc_initpid;
	} else if (pid == 0) {
		pid = curproc->p_zone->zone_zsched->p_pid;
	}

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
	lxpnp->lxpr_desc = desc;
	VN_HOLD(dp);
	if (p != NULL) {
		if (p->p_pid == curproc->p_zone->zone_proc_initpid) {
			lxpnp->lxpr_pid = 1;
		} else if (p->p_pid == curproc->p_zone->zone_zsched->p_pid) {
			lxpnp->lxpr_pid = 0;
		} else {
			lxpnp->lxpr_pid = p->p_pid;
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

	case LXPR_PID_OOM_SCR_ADJ:
	case LXPR_PID_TID_OOM_SCR_ADJ:
	case LXPR_SYS_KERNEL_COREPATT:
	case LXPR_SYS_KERNEL_SHMALL:
	case LXPR_SYS_KERNEL_SHMMAX:
	case LXPR_SYS_NET_CORE_SOMAXCON:
	case LXPR_SYS_VM_OVERCOMMIT_MEM:
	case LXPR_SYS_VM_SWAPPINESS:
		vp->v_type = VREG;
		lxpnp->lxpr_mode = 0644;
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
	p = lxpr_lock(lxdp->lxpr_pid);
	if ((p == NULL))
		return (NULL);
	if ((p->p_stat == SZOMB) || (p->p_flag & SSYS) || (p->p_as == &kas)) {
		/* Not applicable to kernel or system processes */
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
	mutex_enter(&p->p_lock);

	if (vp == NULL) {
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

/*
 * Utility functions for using an LDI handle over /dev/zfs to
 * examine ZFS datasets. These are used for /proc/partitions.
 */

/*
 * Get the major/minor numbers for a zvol device.
 *
 * If no number has been allocated yet, this will ask for one to
 * be allocated, then return it.
 */
int
lxpr_zvol_dev(lxpr_mnt_t *m, char *dsname, major_t *major, minor_t *minor)
{
	int	rc;

	if (m->lxprm_zfs_isopen == B_FALSE)
		return (-1);

	VERIFY(lxpr_zfs_mod != NULL);
	ASSERT(lxpr_zvol_name2minor_fp != NULL);
	ASSERT(lxpr_zvol_create_minor_fp != NULL);

	if (lxpr_zvol_name2minor_fp(dsname, minor) != 0) {
		rc = lxpr_zvol_create_minor_fp(dsname);
		if (rc != 0 && rc != EEXIST)
			return (rc);
		if ((rc = lxpr_zvol_name2minor_fp(dsname, minor)) != 0)
			return (rc);
	}
	*major = m->lxprm_zfs_major;

	return (0);
}

void
lxpr_zfs_init(void)
{
	int	rc = 0;

	ASSERT(lxpr_zfs_mod == NULL);
	ASSERT(lxpr_zvol_name2minor_fp == NULL);
	ASSERT(lxpr_zvol_create_minor_fp == NULL);

	lxpr_zfs_mod = ddi_modopen("fs/zfs", KRTLD_MODE_FIRST, &rc);
	if (rc != 0 || lxpr_zfs_mod == NULL)
		return;

	/*
	 * If these symbols have changed names, we should just
	 * panic, as none of this code will do anything useful.
	 */
	lxpr_zvol_name2minor_fp = (int(*)(char *, minor_t *))
	    ddi_modsym(lxpr_zfs_mod, "zvol_name2minor", &rc);
	VERIFY(rc == 0);
	ASSERT(lxpr_zvol_name2minor_fp != NULL);

	lxpr_zvol_create_minor_fp = (int(*)(char *))
	    ddi_modsym(lxpr_zfs_mod, "zvol_create_minor", &rc);
	VERIFY(rc == 0);
	ASSERT(lxpr_zvol_create_minor_fp != NULL);
}

void
lxpr_zfs_fini(void)
{
	lxpr_zvol_name2minor_fp = NULL;
	lxpr_zvol_create_minor_fp = NULL;
	if (lxpr_zfs_mod != NULL)
		ddi_modclose(lxpr_zfs_mod);
	lxpr_zfs_mod = NULL;
}

/*
 * Call an ioctl on the zfs LDI handle, dealing with allocation of memory
 * for the output nvlist and returning its size.
 *
 * If a NULL dst_alloc_size is given, will discard the allocated dst nvlist.
 */
static int
lxpr_zfs_ioctl(lxpr_mnt_t *m, int cmd, zfs_cmd_t *zc, size_t *dst_alloc_size)
{
	uint64_t	cookie;
	size_t		dstsize = 8192;
	int		rc, unused;

	VERIFY(m->lxprm_zfs_isopen == B_TRUE);

	cookie = zc->zc_cookie;

again:
	zc->zc_nvlist_dst = (uint64_t)(intptr_t)kmem_alloc(dstsize, KM_SLEEP);
	zc->zc_nvlist_dst_size = dstsize;

	rc = ldi_ioctl(m->lxprm_zfs_lh, cmd, (intptr_t)zc, FKIOCTL, kcred,
	    &unused);

	if (rc == ENOMEM) {
		/*
		 * Our nvlist_dst buffer was too small, retry with a bigger
		 * buffer. ZFS will tell us the exact needed size.
		 */
		size_t newsize = zc->zc_nvlist_dst_size;
		ASSERT(newsize > dstsize);

		kmem_free((void *)(uintptr_t)zc->zc_nvlist_dst, dstsize);
		dstsize = newsize;
		zc->zc_cookie = cookie;

		goto again;
	}

	if (dst_alloc_size != NULL) {
		*dst_alloc_size = dstsize;
	} else {
		/* Caller didn't want the nvlist_dst anyway */
		kmem_free((void *)(uintptr_t)zc->zc_nvlist_dst, dstsize);
		zc->zc_nvlist_dst = NULL;
	}

	return (rc);
}

/*
 * Gives an nvlist with all the zpools on the system.
 *
 * Caller is responsible for calling nvlist_free on nv -- it should be set
 * to NULL at call time (this function will allocate it).
 */
int
lxpr_zfs_list_pools(lxpr_mnt_t *m, zfs_cmd_t *zc, nvlist_t **nv)
{
	int	rc;
	size_t	size;

	bzero(zc, sizeof (zfs_cmd_t));

	rc = lxpr_zfs_ioctl(m, ZFS_IOC_POOL_CONFIGS, zc, &size);
	if (rc != 0)
		goto out;

	ASSERT(zc->zc_cookie > 0);

	*nv = NULL;
	rc = nvlist_unpack((char *)(uintptr_t)zc->zc_nvlist_dst,
	    zc->zc_nvlist_dst_size, nv, 0);

out:
	kmem_free((void *)(uintptr_t)zc->zc_nvlist_dst, size);
	zc->zc_nvlist_dst = NULL;
	zc->zc_nvlist_dst_size = 0;
	return (rc);
}

/*
 * Frees the linked list held by an lxpr_zfs_iter_t.
 */
void
lxpr_zfs_end_iter(lxpr_zfs_iter_t *i)
{
	lxpr_zfs_ds_t *ds;
	while ((ds = list_remove_head(&i->it_list)) != NULL)
		kmem_free(ds, sizeof (lxpr_zfs_ds_t));
	list_destroy(&i->it_list);
	i->it_ds = NULL;
}

/*
 * Used to iterate over all the zvols under a given dataset, recursively.
 *
 * Upon success, zc->zc_name contains the full name of the next zvol.
 *
 * If you do not keep calling this function until a non-zero return value
 * is returned, you should call lxpr_zfs_end_iter before freeing the
 * lxpr_zfs_iter.
 */
int
lxpr_zfs_next_zvol(lxpr_mnt_t *m, char *dsname, zfs_cmd_t *zc,
    lxpr_zfs_iter_t *i)
{
	int		rc = (-1);
	lxpr_zfs_ds_t	*ds, *nds;

	ds = i->it_ds;
	/* If this is the first iteration, set up the iter list. */
	if (ds == NULL) {
		ds = kmem_zalloc(sizeof (lxpr_zfs_ds_t), KM_SLEEP);

		list_create(&i->it_list, sizeof (lxpr_zfs_ds_t),
		    offsetof(lxpr_zfs_ds_t, ds_link));
		(void) strcpy(ds->ds_name, dsname);

		list_insert_head(&i->it_list, ds);
		i->it_ds = ds;
	}

	/*
	 * We do depth-first enumeration of all datasets visible to us,
	 * exiting this function whenever we encounter a zvol.
	 *
	 * The caller then calls us again after doing something with that
	 * zvol, re-entering this loop.
	 */
	while (ds != NULL) {
		bzero(zc, sizeof (zfs_cmd_t));
		zc->zc_cookie = ds->ds_cookie;
		(void) strcpy(zc->zc_name, ds->ds_name);

		rc = lxpr_zfs_ioctl(m, ZFS_IOC_DATASET_LIST_NEXT, zc,
		    NULL);

		/*
		 * We get ESRCH if there is nothing left under this
		 * part of the tree.
		 */
		if (rc == ESRCH) {
			list_remove(&i->it_list, ds);
			kmem_free(ds, sizeof (lxpr_zfs_ds_t));
			ds = list_tail(&i->it_list);
			continue;
		} else if (rc != 0) {
			/* Something went really wrong. */
			goto out;
		}

		/* Update the cookie before we skip or return. */
		ds->ds_cookie = zc->zc_cookie;

		/* Reserved internal names, skip over these. */
		if (strchr(zc->zc_name, '$') != NULL ||
		    strchr(zc->zc_name, '%') != NULL)
			continue;

		if (zc->zc_objset_stats.dds_type == DMU_OST_ZVOL) {
			i->it_ds = ds;
			return (0);
		}

		/* Create a new ds_t for the child. */
		nds = kmem_zalloc(sizeof (lxpr_zfs_ds_t), KM_SLEEP);
		(void) strcpy(nds->ds_name, zc->zc_name);
		list_insert_after(&i->it_list, ds, nds);
		/*
		 * Depth-first, so we move straight to the one we
		 * just created.
		 */
		ds = nds;
	}

out:
	lxpr_zfs_end_iter(i);
	return (rc);
}

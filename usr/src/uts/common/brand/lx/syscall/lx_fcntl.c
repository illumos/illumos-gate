/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2018 Joyent, Inc.
 */

#include <sys/systm.h>
#include <sys/zone.h>
#include <sys/types.h>
#include <sys/filio.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/cmn_err.h>
#include <sys/pathname.h>
#include <sys/policy.h>
#include <sys/lx_impl.h>
#include <sys/lx_brand.h>
#include <sys/lx_fcntl.h>
#include <sys/lx_misc.h>
#include <sys/lx_socket.h>
#include <sys/brand.h>
#include <sys/fs/fifonode.h>
#include <sys/strsubr.h>
#include <sys/stream.h>
#include <sys/flock.h>

extern int fcntl(int, int, intptr_t);
extern int flock_check(vnode_t *, flock64_t *, offset_t, offset_t);
extern int lx_pipe_setsz(stdata_t *, uint_t, boolean_t);


int
lx_vp_at(int fd, char *upath, vnode_t **vpp, int flag)
{
	vnode_t *startvp;
	int error;

	if (fd == LX_AT_FDCWD) {
		fd = AT_FDCWD;
	}

	if ((error = fgetstartvp(fd, upath, &startvp)) != 0) {
		return (error);
	}

	if (upath != NULL) {
		uio_seg_t seg = UIO_USERSPACE;

		error = lookupnameat(upath, seg,
		    (flag == AT_SYMLINK_NOFOLLOW) ?  NO_FOLLOW : FOLLOW,
		    NULLVPP, vpp, startvp);
		if (startvp != NULL) {
			VN_RELE(startvp);
		}
		return (error);
	} else {
		/* VN_HOLD was established in fgetstartvp */
		*vpp = startvp;
		VERIFY(*vpp);
		return (0);
	}
}

#define	LTOS_FLOCK(l, s)						\
{									\
	s->l_type = ltos_type(l->l_type);				\
	s->l_whence = l->l_whence;					\
	s->l_start = l->l_start;					\
	s->l_len = l->l_len;						\
	s->l_sysid = 0;			/* not defined in linux */	\
	s->l_pid = (pid_t)l->l_pid;					\
}

#define	STOL_FLOCK(s, l)						\
{									\
	l->l_type = stol_type(s->l_type);				\
	l->l_whence = s->l_whence;					\
	l->l_start = s->l_start;					\
	l->l_len = s->l_len;						\
	l->l_pid = (int)s->l_pid;					\
}

static short
ltos_type(short l_type)
{
	switch (l_type) {
	case LX_F_RDLCK:
		return (F_RDLCK);
	case LX_F_WRLCK:
		return (F_WRLCK);
	case LX_F_UNLCK:
		return (F_UNLCK);
	default:
		return (-1);
	}
}

static short
stol_type(short l_type)
{
	switch (l_type) {
	case F_RDLCK:
		return (LX_F_RDLCK);
	case F_WRLCK:
		return (LX_F_WRLCK);
	case F_UNLCK:
		return (LX_F_UNLCK);
	default:
		/* can't ever happen */
		return (0);
	}
}

static void
ltos_flock(struct lx_flock *l, struct flock64 *s)
{
	LTOS_FLOCK(l, s)
}

static void
stol_flock(struct flock64 *s, struct lx_flock *l)
{
	STOL_FLOCK(s, l)
}

static void
ltos_flock64(struct lx_flock64_32 *l, struct flock64 *s)
{
	LTOS_FLOCK(l, s)
}

static void
stol_flock64(struct flock64 *s, struct lx_flock64_32 *l)
{
	STOL_FLOCK(s, l)
}

static int
lx_fcntl_getfl(int fd)
{
	int retval;
	int rc;

	retval = fcntl(fd, F_GETFL, 0);
	if (ttolwp(curthread)->lwp_errno != 0)
		return (ttolwp(curthread)->lwp_errno);

	if ((retval & O_ACCMODE) == O_RDONLY)
		rc = LX_O_RDONLY;
	else if ((retval & O_ACCMODE) == O_WRONLY)
		rc = LX_O_WRONLY;
	else
		rc = LX_O_RDWR;
	/* O_NDELAY != O_NONBLOCK, so we need to check for both */
	if (retval & O_NDELAY)
		rc |= LX_O_NDELAY;
	if (retval & O_NONBLOCK)
		rc |= LX_O_NONBLOCK;
	if (retval & O_APPEND)
		rc |= LX_O_APPEND;
	if (retval & O_SYNC)
		rc |= LX_O_SYNC;
	if (retval & O_LARGEFILE)
		rc |= LX_O_LARGEFILE;
	if (retval & FASYNC)
		rc |= LX_O_ASYNC;

	return (rc);
}

#define	LX_SETFL_MASK	(O_NONBLOCK | O_APPEND | O_SYNC |  FASYNC);

static int
lx_fcntl_setfl(int fd, ulong_t arg)
{
	int flags;

	/*
	 * When performing fcntl(F_SETFL), only certain flags are
	 * allowed to be manipulated. A mask is used to preserve
	 * other flags, such as those which are specified during
	 * open(2). The mask on Linux excludes O_LARGEFILE from
	 * being manipulated, whereas illumos expects the flag to
	 * be set. In order to properly preserve the O_LARGEFILE
	 * (FOFFMAX) state, we must first query for it via
	 * fcntl(F_GETFL) so that the value can be carried
	 * through.
	 */
	flags = fcntl(fd, F_GETFL, 0);
	if (ttolwp(curthread)->lwp_errno != 0)
		return (ttolwp(curthread)->lwp_errno);

	flags &= ~LX_SETFL_MASK;

	/* LX_O_NDELAY == LX_O_NONBLOCK, so we only check for one */
	if (arg & LX_O_NDELAY)
		flags |= O_NONBLOCK;
	if (arg & LX_O_APPEND)
		flags |= O_APPEND;
	if (arg & LX_O_SYNC)
		flags |= O_SYNC;
	if (arg & LX_O_ASYNC)
		flags |= FASYNC;

	return (fcntl(fd, F_SETFL, flags));
}


static int
lx_fcntl_pipesz(int fd, int cmd, ulong_t arg)
{
	file_t *fp;
	vnode_t *vp;
	stdata_t *str;
	int err = 0, res = 0;

	if ((fp = getf(fd)) == NULL) {
		return (set_errno(EBADF));
	}
	vp = fp->f_vnode;
	if (vp->v_type != VFIFO || vp->v_op != fifo_vnodeops) {
		err = EBADF;
		goto out;
	}
	VERIFY((str = vp->v_stream) != NULL);

	if (cmd == LX_F_SETPIPE_SZ) {
		err = lx_pipe_setsz(str, (uint_t)arg, B_FALSE);
	} else if (cmd == LX_F_GETPIPE_SZ) {
		size_t val;

		err = strqget(RD(str->sd_wrq), QHIWAT, 0, &val);
		res = val;
	} else {
		/* NOTREACHED */
		ASSERT(0);
	}

out:
	releasef(fd);
	if (err != 0) {
		return (set_errno(err));
	}
	return (res);
}

static int
lx_fcntl_common(int fd, int cmd, ulong_t arg)
{
	int		rc = 0;
	pid_t		pid;
	int		error;
	int		rv;
	int32_t		flag;
	file_t		*fp;

	/*
	 * We depend on the call to fcntl to set the errno if necessary.
	 */
	ttolwp(curthread)->lwp_errno = 0;

	switch (cmd) {
	case LX_F_SETSIG:
	case LX_F_GETSIG:
	case LX_F_SETLEASE:
	case LX_F_GETLEASE:
	case LX_F_NOTIFY:
	case LX_F_CANCELLK:
		{
			char buf[80];

			(void) snprintf(buf, sizeof (buf),
			    "unsupported fcntl command: %d", cmd);
			lx_unsupported(buf);
		}
		return (set_errno(ENOTSUP));

	case LX_F_DUPFD:
		rc = fcntl(fd, F_DUPFD, arg);
		break;

	case LX_F_DUPFD_CLOEXEC:
		rc = fcntl(fd, F_DUPFD_CLOEXEC, arg);
		break;

	case LX_F_GETFD:
		rc = fcntl(fd, F_GETFD, 0);
		break;

	case LX_F_SETFD:
		rc = fcntl(fd, F_SETFD, arg);
		break;

	case LX_F_GETFL:
		rc = lx_fcntl_getfl(fd);
		break;

	case LX_F_SETFL:
		rc = lx_fcntl_setfl(fd, arg);
		break;

	case LX_F_SETOWN:
		pid = (pid_t)arg;
		if (pid == 1) {
			/* Setown for the init process uses the real pid. */
			pid = curzone->zone_proc_initpid;
		}

		if ((fp = getf(fd)) == NULL)
			return (set_errno(EBADF));

		rv = 0;

		flag = fp->f_flag | get_udatamodel() | FKIOCTL;
		error = VOP_IOCTL(fp->f_vnode, FIOSETOWN, (intptr_t)&pid,
		    flag, CRED(), &rv, NULL);
		releasef(fd);
		if (error != 0) {
			/*
			 * On illumos F_SETOWN is only defined for sockets, but
			 * some apps hardcode to do this fcntl on other devices
			 * (e.g. /dev/tty) to setup signal handling. If the
			 * app is only setting itself to be the signal
			 * handler, we pretend to succeed.
			 */
			if (error != EINVAL ||
			    curthread->t_procp->p_pid != pid) {
				return (set_errno(error));
			}
		}

		rc = 0;
		break;

	case LX_F_GETOWN:
		if ((fp = getf(fd)) == NULL)
			return (set_errno(EBADF));

		rv = 0;

		flag = fp->f_flag | get_udatamodel() | FKIOCTL;
		error = VOP_IOCTL(fp->f_vnode, FIOGETOWN, (intptr_t)&pid,
		    flag, CRED(), &rv, NULL);
		releasef(fd);
		if (error != 0)
			return (set_errno(error));

		if (pid == curzone->zone_proc_initpid) {
			/* Getown for the init process returns 1. */
			pid = 1;
		}

		rc = pid;
		break;

	case LX_F_SETPIPE_SZ:
	case LX_F_GETPIPE_SZ:
		rc = lx_fcntl_pipesz(fd, cmd, arg);
		break;

	default:
		return (set_errno(EINVAL));
	}

	return (rc);
}

static int
lx_fcntl_lock_cmd_to_s(int lx_cmd)
{
	switch (lx_cmd) {
	case LX_F_GETLK:
		return (F_GETLK);
	case LX_F_SETLK:
		return (F_SETLK);
	case LX_F_SETLKW:
		return (F_SETLKW);
	case LX_F_GETLK64:
		return (F_GETLK64);
	case LX_F_SETLK64:
		return (F_SETLK64);
	case LX_F_SETLKW64:
		return (F_SETLKW64);
	default:
		VERIFY(0);
		/*NOTREACHED*/
		return (0);
	}
}

/*
 * This is a pain but we can't re-use the fcntl code for locking since it does
 * its own copyin/copyout for the flock struct. Since we have to convert the
 * struct we have to do our own copyin/out. Thus we replicate the fcntl code for
 * these 3 cmds. Luckily it's not much.
 */
static int
lx_fcntl_lock(int fd, int lx_cmd, void *arg)
{
	int cmd;
	int error = 0;
	file_t *fp;
	vnode_t *vp;
	int flag;
	offset_t maxoffset;
	u_offset_t offset;
	model_t datamodel;
	lx_flock_t lxflk;
	lx_flock64_32_t lxflk64;
	struct flock64 bf;

	if ((fp = getf(fd)) == NULL)
		return (set_errno(EBADF));

	maxoffset = MAXOFF_T;
	datamodel = DATAMODEL_NATIVE;
#if defined(_SYSCALL32_IMPL)
	if ((datamodel = get_udatamodel()) == DATAMODEL_ILP32)
		maxoffset = MAXOFF32_T;
#endif
	vp = fp->f_vnode;
	flag = fp->f_flag;
	offset = fp->f_offset;

	cmd = lx_fcntl_lock_cmd_to_s(lx_cmd);

	switch (cmd) {
	case F_GETLK:
	case F_SETLK:
	case F_SETLKW:
		if (datamodel == DATAMODEL_NATIVE) {
			if (copyin(arg, &lxflk, sizeof (lx_flock_t)) != 0) {
				error = EFAULT;
				break;
			}
		}
#if defined(_SYSCALL32_IMPL)
		else {
			lx_flock32_t lxflk32;

			if (copyin(arg, &lxflk32, sizeof (lxflk32)) != 0) {
				error = EFAULT;
				break;
			}

			lxflk.l_type = lxflk32.l_type;
			lxflk.l_whence = lxflk32.l_whence;
			lxflk.l_start = (off64_t)lxflk32.l_start;
			lxflk.l_len = (off64_t)lxflk32.l_len;
			lxflk.l_pid = lxflk32.l_pid;
		}
#endif /* _SYSCALL32_IMPL */

		ltos_flock(&lxflk, &bf);

		if ((error = flock_check(vp, &bf, offset, maxoffset)) != 0)
			break;

		if ((error = VOP_FRLOCK(vp, cmd, &bf, flag, offset, NULL,
		    fp->f_cred, NULL)) != 0) {
			if (cmd == F_SETLKW && error == EINTR) {
				ttolxlwp(curthread)->br_syscall_restart =
				    B_TRUE;
			}
			break;
		}

		if (cmd != F_GETLK)
			break;

		/*
		 * The command is GETLK, return result.
		 */
		stol_flock(&bf, &lxflk);

		/*
		 * If no lock is found, only the type field is changed.
		 */
		if (lxflk.l_type == LX_F_UNLCK) {
			/* l_type always first entry, always a short */
			if (copyout(&lxflk.l_type, &((lx_flock_t *)arg)->l_type,
			    sizeof (lxflk.l_type)))
				error = EFAULT;
			break;
		}

		if (bf.l_start > maxoffset || bf.l_len > maxoffset) {
			error = EOVERFLOW;
			break;
		}

		if (datamodel == DATAMODEL_NATIVE) {
			if (copyout(&lxflk, arg, sizeof (lxflk)) != 0) {
				error = EFAULT;
				break;
			}
		}
#if defined(_SYSCALL32_IMPL)
		else {
			lx_flock32_t lxflk32;

			if (bf.l_start > MAXOFF32_T || bf.l_len > MAXOFF32_T) {
				error = EOVERFLOW;
				break;
			}

			lxflk32.l_type = lxflk.l_type;
			lxflk32.l_whence = lxflk.l_whence;
			lxflk32.l_start = lxflk.l_start;
			lxflk32.l_len = lxflk.l_len;
			lxflk32.l_pid = lxflk.l_pid;

			if (copyout(&lxflk32, arg, sizeof (lxflk32)) != 0) {
				error = EFAULT;
				break;
			}
		}
#endif /* _SYSCALL32_IMPL */
		break;

	case F_GETLK64:
	case F_SETLK64:
	case F_SETLKW64:
		/*
		 * Large File support is only used for ILP32 apps.
		 */
		if (datamodel != DATAMODEL_ILP32) {
			error = EINVAL;
			break;
		}

		if (cmd == F_GETLK64)
			cmd = F_GETLK;
		else if (cmd == F_SETLK64)
			cmd = F_SETLK;
		else if (cmd == F_SETLKW64)
			cmd = F_SETLKW;

		if (copyin(arg, &lxflk64, sizeof (lxflk64)) != 0) {
			error = EFAULT;
			break;
		}

		ltos_flock64(&lxflk64, &bf);

		if ((error = flock_check(vp, &bf, offset, MAXOFFSET_T)) != 0)
			break;

		if ((error = VOP_FRLOCK(vp, cmd, &bf, flag, offset, NULL,
		    fp->f_cred, NULL)) != 0)
			break;

		if (cmd != F_GETLK)
			break;

		/*
		 * The command is GETLK, return result.
		 */
		stol_flock64(&bf, &lxflk64);

		/*
		 * If no lock is found, only the type field is changed.
		 */
		if (lxflk64.l_type == LX_F_UNLCK) {
			/* l_type always first entry, always a short */
			if (copyout(&lxflk64.l_type,
			    &((lx_flock64_t *)arg)->l_type,
			    sizeof (lxflk64.l_type)))
				error = EFAULT;
			break;
		}

		if (bf.l_start > maxoffset || bf.l_len > maxoffset) {
			error = EOVERFLOW;
			break;
		}

		if (copyout(&lxflk64, arg, sizeof (lxflk64)) != 0) {
			error = EFAULT;
			break;
		}
		break;
	}

	releasef(fd);
	if (error)
		return (set_errno(error));

	return (0);
}

long
lx_fcntl(int fd, int cmd, intptr_t arg)
{
	switch (cmd) {
	case LX_F_GETLK64:
	case LX_F_SETLK64:
	case LX_F_SETLKW64:
		/* The 64-bit fcntl commands must go through fcntl64(). */
		return (set_errno(EINVAL));

	case LX_F_GETLK:
	case LX_F_SETLK:
	case LX_F_SETLKW:
		return (lx_fcntl_lock(fd, cmd, (void *)arg));

	default:
		return (lx_fcntl_common(fd, cmd, arg));
	}
}

long
lx_fcntl64(int fd, int cmd, intptr_t arg)
{
	switch (cmd) {
	case LX_F_GETLK:
	case LX_F_SETLK:
	case LX_F_SETLKW:
	case LX_F_GETLK64:
	case LX_F_SETLKW64:
	case LX_F_SETLK64:
		return (lx_fcntl_lock(fd, cmd, (void *)arg));

	default:
		return (lx_fcntl_common(fd, cmd, (ulong_t)arg));
	}
}

/*
 * Apply or remove an advisory lock on the entire file. F_FLOCK and F_FLOCKW
 * are OFD-style locks. For more information, see the comment on ofdlock().
 */
long
lx_flock(int fd, int op)
{
	int cmd;
	int error;
	flock64_t bf;
	file_t *fp;

	if (op & LX_LOCK_NB) {
		cmd = F_FLOCK;
		op &= ~LX_LOCK_NB;
	} else {
		cmd = F_FLOCKW;
	}

	switch (op) {
	case LX_LOCK_UN:
		bf.l_type = F_UNLCK;
		break;
	case LX_LOCK_SH:
		bf.l_type = F_RDLCK;
		break;
	case LX_LOCK_EX:
		bf.l_type = F_WRLCK;
		break;
	default:
		return (set_errno(EINVAL));
	}

	bf.l_whence = 0;
	bf.l_start = 0;
	bf.l_len = 0;
	bf.l_sysid = 0;
	bf.l_pid = 0;

	if ((fp = getf(fd)) == NULL)
		return (set_errno(EBADF));

	/*
	 * See the locking comment in fcntl.c. In summary, the *_frlock
	 * functions in the various file systems basically do some validation,
	 * then funnel everything through the fs_frlock function. For OFD-style
	 * locks, fs_frlock will do nothing. Once control returns here, we call
	 * the ofdlock function to do the actual locking.
	 */
	error = VOP_FRLOCK(fp->f_vnode, cmd, &bf, fp->f_flag, fp->f_offset,
	    NULL, fp->f_cred, NULL);
	if (error != 0) {
		releasef(fd);
		return (set_errno(error));
	}
	error = ofdlock(fp, cmd, &bf, fp->f_flag, fp->f_offset);
	if (error != 0) {
		if (cmd == F_FLOCKW && error == EINTR)
			ttolxlwp(curthread)->br_syscall_restart = B_TRUE;
		(void) set_errno(error);
	}
	releasef(fd);
	return (error);
}

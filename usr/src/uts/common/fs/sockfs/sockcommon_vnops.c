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
 */
/*
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bitmap.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/strsubr.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/filio.h>
#include <sys/flock.h>
#include <sys/stat.h>
#include <sys/share.h>

#include <sys/vfs.h>
#include <sys/vfs_opreg.h>

#include <sys/sockio.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/strsun.h>

#include <fs/sockfs/sockcommon.h>
#include <fs/sockfs/socktpi.h>

/*
 * Generic vnode ops
 */
static int	socket_vop_open(struct vnode **, int, struct cred *,
		    caller_context_t *);
static int	socket_vop_close(struct vnode *, int, int, offset_t,
		    struct cred *, caller_context_t *);
static int	socket_vop_read(struct vnode *, struct uio *, int,
		    struct cred *, caller_context_t *);
static int	socket_vop_write(struct vnode *, struct uio *, int,
		    struct cred *, caller_context_t *);
static int	socket_vop_ioctl(struct vnode *, int, intptr_t, int,
		    struct cred *, int32_t *, caller_context_t *);
static int	socket_vop_setfl(struct vnode *, int, int, cred_t *,
		    caller_context_t *);
static int 	socket_vop_getattr(struct vnode *, struct vattr *, int,
		    struct cred *, caller_context_t *);
static int 	socket_vop_setattr(struct vnode *, struct vattr *, int,
		    struct cred *, caller_context_t *);
static int 	socket_vop_access(struct vnode *, int, int, struct cred *,
		    caller_context_t *);
static int 	socket_vop_fsync(struct vnode *, int, struct cred *,
		    caller_context_t *);
static void	socket_vop_inactive(struct vnode *, struct cred *,
		    caller_context_t *);
static int 	socket_vop_fid(struct vnode *, struct fid *,
		    caller_context_t *);
static int 	socket_vop_seek(struct vnode *, offset_t, offset_t *,
		    caller_context_t *);
static int	socket_vop_poll(struct vnode *, short, int, short *,
		    struct pollhead **, caller_context_t *);

extern int	socket_close_internal(struct sonode *, int, cred_t *);
extern void	socket_destroy_internal(struct sonode *, cred_t *);

struct vnodeops *socket_vnodeops;
const fs_operation_def_t socket_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = socket_vop_open },
	VOPNAME_CLOSE,		{ .vop_close = socket_vop_close },
	VOPNAME_READ,		{ .vop_read = socket_vop_read },
	VOPNAME_WRITE,		{ .vop_write = socket_vop_write },
	VOPNAME_IOCTL,		{ .vop_ioctl = socket_vop_ioctl },
	VOPNAME_SETFL,		{ .vop_setfl = socket_vop_setfl },
	VOPNAME_GETATTR,	{ .vop_getattr = socket_vop_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = socket_vop_setattr },
	VOPNAME_ACCESS,		{ .vop_access = socket_vop_access },
	VOPNAME_FSYNC,		{ .vop_fsync = socket_vop_fsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = socket_vop_inactive },
	VOPNAME_FID,		{ .vop_fid = socket_vop_fid },
	VOPNAME_SEEK,		{ .vop_seek = socket_vop_seek },
	VOPNAME_POLL,		{ .vop_poll = socket_vop_poll },
	VOPNAME_DISPOSE,	{ .error = fs_error },
	NULL,			NULL
};


/*
 * generic vnode ops
 */

/*ARGSUSED*/
static int
socket_vop_open(struct vnode **vpp, int flag, struct cred *cr,
    caller_context_t *ct)
{
	struct vnode *vp = *vpp;
	struct sonode *so = VTOSO(vp);

	flag &= ~FCREAT;		/* paranoia */
	mutex_enter(&so->so_lock);
	so->so_count++;
	mutex_exit(&so->so_lock);

	ASSERT(so->so_count != 0);	/* wraparound */
	ASSERT(vp->v_type == VSOCK);

	return (0);
}

/*ARGSUSED*/
static int
socket_vop_close(struct vnode *vp, int flag, int count, offset_t offset,
    struct cred *cr, caller_context_t *ct)
{
	struct sonode *so;
	int error = 0;

	so = VTOSO(vp);
	ASSERT(vp->v_type == VSOCK);

	cleanlocks(vp, ttoproc(curthread)->p_pid, 0);
	cleanshares(vp, ttoproc(curthread)->p_pid);

	if (vp->v_stream)
		strclean(vp);

	if (count > 1) {
		dprint(2, ("socket_vop_close: count %d\n", count));
		return (0);
	}

	mutex_enter(&so->so_lock);
	if (--so->so_count == 0) {
		/*
		 * Initiate connection shutdown.
		 */
		mutex_exit(&so->so_lock);
		error = socket_close_internal(so, flag, cr);
	} else {
		mutex_exit(&so->so_lock);
	}

	return (error);
}

/*ARGSUSED2*/
static int
socket_vop_read(struct vnode *vp, struct uio *uiop, int ioflag, struct cred *cr,
    caller_context_t *ct)
{
	struct sonode *so = VTOSO(vp);
	struct nmsghdr lmsg;

	ASSERT(vp->v_type == VSOCK);
	bzero((void *)&lmsg, sizeof (lmsg));

	return (socket_recvmsg(so, &lmsg, uiop, cr));
}

/*ARGSUSED2*/
static int
socket_vop_write(struct vnode *vp, struct uio *uiop, int ioflag,
    struct cred *cr, caller_context_t *ct)
{
	struct sonode *so = VTOSO(vp);
	struct nmsghdr lmsg;

	ASSERT(vp->v_type == VSOCK);
	bzero((void *)&lmsg, sizeof (lmsg));

	if (!(so->so_mode & SM_BYTESTREAM)) {
		/*
		 * If the socket is not byte stream set MSG_EOR
		 */
		lmsg.msg_flags = MSG_EOR;
	}

	return (socket_sendmsg(so, &lmsg, uiop, cr));
}

/*ARGSUSED4*/
static int
socket_vop_ioctl(struct vnode *vp, int cmd, intptr_t arg, int mode,
    struct cred *cr, int32_t *rvalp, caller_context_t *ct)
{
	struct sonode *so = VTOSO(vp);

	ASSERT(vp->v_type == VSOCK);

	return (socket_ioctl(so, cmd, arg, mode, cr, rvalp));
}

/*
 * Allow any flags. Record FNDELAY and FNONBLOCK so that they can be inherited
 * from listener to acceptor.
 */
/* ARGSUSED */
static int
socket_vop_setfl(vnode_t *vp, int oflags, int nflags, cred_t *cr,
    caller_context_t *ct)
{
	struct sonode *so = VTOSO(vp);
	int error = 0;

	ASSERT(vp->v_type == VSOCK);

	mutex_enter(&so->so_lock);
	if (nflags & FNDELAY)
		so->so_state |= SS_NDELAY;
	else
		so->so_state &= ~SS_NDELAY;
	if (nflags & FNONBLOCK)
		so->so_state |= SS_NONBLOCK;
	else
		so->so_state &= ~SS_NONBLOCK;
	mutex_exit(&so->so_lock);

	if (so->so_state & SS_ASYNC)
		oflags |= FASYNC;
	/*
	 * Sets/clears the SS_ASYNC flag based on the presence/absence
	 * of the FASYNC flag passed to fcntl(F_SETFL).
	 * This exists solely for BSD fcntl() FASYNC compatibility.
	 */
	if ((oflags ^ nflags) & FASYNC && so->so_version != SOV_STREAM) {
		int async = nflags & FASYNC;
		int32_t rv;

		/*
		 * For non-TPI sockets all we have to do is set/remove the
		 * SS_ASYNC bit, but for TPI it is more involved. For that
		 * reason we delegate the job to the protocol's ioctl handler.
		 */
		error = socket_ioctl(so, FIOASYNC, (intptr_t)&async, FKIOCTL,
		    cr, &rv);
	}
	return (error);
}


/*
 * Get the made up attributes for the vnode.
 * 4.3BSD returns the current time for all the timestamps.
 * 4.4BSD returns 0 for all the timestamps.
 * Here we use the access and modified times recorded in the sonode.
 *
 * Just like in BSD there is not effect on the underlying file system node
 * bound to an AF_UNIX pathname.
 *
 * When sockmod has been popped this will act just like a stream. Since
 * a socket is always a clone there is no need to inspect the attributes
 * of the "realvp".
 */
/* ARGSUSED */
int
socket_vop_getattr(struct vnode *vp, struct vattr *vap, int flags,
    struct cred *cr, caller_context_t *ct)
{
	dev_t		fsid;
	struct sonode 	*so;
	static int	sonode_shift = 0;

	/*
	 * Calculate the amount of bitshift to a sonode pointer which will
	 * still keep it unique.  See below.
	 */
	if (sonode_shift == 0)
		sonode_shift = highbit(sizeof (struct sonode));
	ASSERT(sonode_shift > 0);

	so = VTOSO(vp);
	fsid = sockdev;

	if (so->so_version == SOV_STREAM) {
		/*
		 * The imaginary "sockmod" has been popped - act
		 * as a stream
		 */
		vap->va_type = VCHR;
		vap->va_mode = 0;
	} else {
		vap->va_type = vp->v_type;
		vap->va_mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|
		    S_IROTH|S_IWOTH;
	}
	vap->va_uid = vap->va_gid = 0;
	vap->va_fsid = fsid;
	/*
	 * If the va_nodeid is > MAX_USHORT, then i386 stats might fail.
	 * So we shift down the sonode pointer to try and get the most
	 * uniqueness into 16-bits.
	 */
	vap->va_nodeid = ((ino_t)so >> sonode_shift) & 0xFFFF;
	vap->va_nlink = 0;
	vap->va_size = 0;

	/*
	 * We need to zero out the va_rdev to avoid some fstats getting
	 * EOVERFLOW.  This also mimics SunOS 4.x and BSD behavior.
	 */
	vap->va_rdev = (dev_t)0;
	vap->va_blksize = MAXBSIZE;
	vap->va_nblocks = btod(vap->va_size);

	if (!SOCK_IS_NONSTR(so)) {
		sotpi_info_t *sti = SOTOTPI(so);

		mutex_enter(&so->so_lock);
		vap->va_atime.tv_sec = sti->sti_atime;
		vap->va_mtime.tv_sec = sti->sti_mtime;
		vap->va_ctime.tv_sec = sti->sti_ctime;
		mutex_exit(&so->so_lock);
	} else {
		vap->va_atime.tv_sec = 0;
		vap->va_mtime.tv_sec = 0;
		vap->va_ctime.tv_sec = 0;
	}

	vap->va_atime.tv_nsec = 0;
	vap->va_mtime.tv_nsec = 0;
	vap->va_ctime.tv_nsec = 0;
	vap->va_seq = 0;

	return (0);
}

/*
 * Set attributes.
 * Just like in BSD there is not effect on the underlying file system node
 * bound to an AF_UNIX pathname.
 *
 * When sockmod has been popped this will act just like a stream. Since
 * a socket is always a clone there is no need to modify the attributes
 * of the "realvp".
 */
/* ARGSUSED */
int
socket_vop_setattr(struct vnode *vp, struct vattr *vap, int flags,
    struct cred *cr, caller_context_t *ct)
{
	struct sonode *so = VTOSO(vp);

	/*
	 * If times were changed, and we have a STREAMS socket, then update
	 * the sonode.
	 */
	if (!SOCK_IS_NONSTR(so)) {
		sotpi_info_t *sti = SOTOTPI(so);

		mutex_enter(&so->so_lock);
		if (vap->va_mask & AT_ATIME)
			sti->sti_atime = vap->va_atime.tv_sec;
		if (vap->va_mask & AT_MTIME) {
			sti->sti_mtime = vap->va_mtime.tv_sec;
			sti->sti_ctime = gethrestime_sec();
		}
		mutex_exit(&so->so_lock);
	}

	return (0);
}

/*
 * Check if user is allowed to access vp. For non-STREAMS based sockets,
 * there might not be a device attached to the file system. So for those
 * types of sockets there are no permissions to check.
 *
 * XXX Should there be some other mechanism to check access rights?
 */
/*ARGSUSED*/
int
socket_vop_access(struct vnode *vp, int mode, int flags, struct cred *cr,
    caller_context_t *ct)
{
	struct sonode *so = VTOSO(vp);

	if (!SOCK_IS_NONSTR(so)) {
		ASSERT(so->so_sockparams->sp_sdev_info.sd_vnode != NULL);
		return (VOP_ACCESS(so->so_sockparams->sp_sdev_info.sd_vnode,
		    mode, flags, cr, NULL));
	}
	return (0);
}

/*
 * 4.3BSD and 4.4BSD fail a fsync on a socket with EINVAL.
 * This code does the same to be compatible and also to not give an
 * application the impression that the data has actually been "synced"
 * to the other end of the connection.
 */
/* ARGSUSED */
int
socket_vop_fsync(struct vnode *vp, int syncflag, struct cred *cr,
    caller_context_t *ct)
{
	return (EINVAL);
}

/*ARGSUSED*/
static void
socket_vop_inactive(struct vnode *vp, struct cred *cr, caller_context_t *ct)
{
	struct sonode *so = VTOSO(vp);

	ASSERT(vp->v_type == VSOCK);

	mutex_enter(&vp->v_lock);
	/*
	 * If no one has reclaimed the vnode, remove from the
	 * cache now.
	 */
	if (vp->v_count < 1)
		cmn_err(CE_PANIC, "socket_inactive: Bad v_count");

	VN_RELE_LOCKED(vp);
	if (vp->v_count != 0) {
		mutex_exit(&vp->v_lock);
		return;
	}
	mutex_exit(&vp->v_lock);


	ASSERT(!vn_has_cached_data(vp));

	/* socket specfic clean-up */
	socket_destroy_internal(so, cr);
}

/* ARGSUSED */
int
socket_vop_fid(struct vnode *vp, struct fid *fidp, caller_context_t *ct)
{
	return (EINVAL);
}

/*
 * Sockets are not seekable.
 * (and there is a bug to fix STREAMS to make them fail this as well).
 */
/*ARGSUSED*/
int
socket_vop_seek(struct vnode *vp, offset_t ooff, offset_t *noffp,
    caller_context_t *ct)
{
	return (ESPIPE);
}

/*ARGSUSED*/
static int
socket_vop_poll(struct vnode *vp, short events, int anyyet, short *reventsp,
    struct pollhead **phpp, caller_context_t *ct)
{
	struct sonode *so = VTOSO(vp);

	ASSERT(vp->v_type == VSOCK);

	return (socket_poll(so, events, anyyet, reventsp, phpp));
}

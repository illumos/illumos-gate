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
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/user.h>
#include <sys/termios.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/flock.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/vmsystm.h>

#include <sys/socket.h>
#include <sys/socketvar.h>
#include <fs/sockfs/sockcommon.h>
#include <fs/sockfs/socktpi.h>

#include <netinet/in.h>
#include <sys/sendfile.h>
#include <sys/un.h>
#include <sys/tihdr.h>
#include <sys/atomic.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/tcp.h>

extern int sosendfile64(file_t *, file_t *, const struct ksendfilevec64 *,
		ssize32_t *);
extern int nl7c_sendfilev(struct sonode *, u_offset_t *, struct sendfilevec *,
		int, ssize_t *);
extern int snf_segmap(file_t *, vnode_t *, u_offset_t, u_offset_t, ssize_t *,
		boolean_t);
extern sotpi_info_t *sotpi_sototpi(struct sonode *);

#define	SEND_MAX_CHUNK	16

#if defined(_SYSCALL32_IMPL) || defined(_ILP32)
/*
 * 64 bit offsets for 32 bit applications only running either on
 * 64 bit kernel or 32 bit kernel. For 32 bit apps, we can't transfer
 * more than 2GB of data.
 */
static int
sendvec_chunk64(file_t *fp, u_offset_t *fileoff, struct ksendfilevec64 *sfv,
    int copy_cnt, ssize32_t *count)
{
	struct vnode *vp;
	ushort_t fflag;
	int ioflag;
	size32_t cnt;
	ssize32_t sfv_len;
	ssize32_t tmpcount;
	u_offset_t sfv_off;
	struct uio auio;
	struct iovec aiov;
	int i, error;

	fflag = fp->f_flag;
	vp = fp->f_vnode;
	for (i = 0; i < copy_cnt; i++) {

		if (ISSIG(curthread, JUSTLOOKING))
			return (EINTR);

		/*
		 * Do similar checks as "write" as we are writing
		 * sfv_len bytes into "vp".
		 */
		sfv_len = (ssize32_t)sfv->sfv_len;

		if (sfv_len == 0) {
			sfv++;
			continue;
		}

		if (sfv_len < 0)
			return (EINVAL);

		if (vp->v_type == VREG) {
			if (*fileoff >= curproc->p_fsz_ctl) {
				mutex_enter(&curproc->p_lock);
				(void) rctl_action(
				    rctlproc_legacy[RLIMIT_FSIZE],
				    curproc->p_rctls, curproc, RCA_SAFE);
				mutex_exit(&curproc->p_lock);
				return (EFBIG);
			}

			if (*fileoff >= OFFSET_MAX(fp))
				return (EFBIG);

			if (*fileoff + sfv_len > OFFSET_MAX(fp))
				return (EINVAL);
		}

		tmpcount = *count + sfv_len;
		if (tmpcount < 0)
			return (EINVAL);

		sfv_off = sfv->sfv_off;

		auio.uio_extflg = UIO_COPY_DEFAULT;
		if (sfv->sfv_fd == SFV_FD_SELF) {
			aiov.iov_len = sfv_len;
			aiov.iov_base = (caddr_t)(uintptr_t)sfv_off;
			auio.uio_loffset = *fileoff;
			auio.uio_iovcnt = 1;
			auio.uio_resid = sfv_len;
			auio.uio_iov = &aiov;
			auio.uio_segflg = UIO_USERSPACE;
			auio.uio_llimit = curproc->p_fsz_ctl;
			auio.uio_fmode = fflag;
			ioflag = auio.uio_fmode & (FAPPEND|FSYNC|FDSYNC|FRSYNC);
			while (sfv_len > 0) {
				error = VOP_WRITE(vp, &auio, ioflag,
				    fp->f_cred, NULL);
				cnt = sfv_len - auio.uio_resid;
				sfv_len -= cnt;
				ttolwp(curthread)->lwp_ru.ioch += (ulong_t)cnt;
				if (vp->v_type == VREG)
					*fileoff += cnt;
				*count += cnt;
				if (error != 0)
					return (error);
			}
		} else {
			file_t	*ffp;
			vnode_t	*readvp;
			size_t	size;
			caddr_t	ptr;

			if ((ffp = getf(sfv->sfv_fd)) == NULL)
				return (EBADF);

			if ((ffp->f_flag & FREAD) == 0) {
				releasef(sfv->sfv_fd);
				return (EBADF);
			}

			readvp = ffp->f_vnode;
			if (readvp->v_type != VREG) {
				releasef(sfv->sfv_fd);
				return (EINVAL);
			}

			/*
			 * No point reading and writing to same vp,
			 * as long as both are regular files. readvp is not
			 * locked; but since we got it from an open file the
			 * contents will be valid during the time of access.
			 */
			if (vn_compare(vp, readvp)) {
				releasef(sfv->sfv_fd);
				return (EINVAL);
			}

			/*
			 * Optimize the regular file over
			 * the socket case.
			 */
			if (vp->v_type == VSOCK) {
				error = sosendfile64(fp, ffp, sfv,
				    (ssize32_t *)&cnt);
				*count += cnt;
				if (error)
					return (error);
				sfv++;
				continue;
			}

			/*
			 * Note: we assume readvp != vp. "vp" is already
			 * locked, and "readvp" must not be.
			 */
			if (readvp < vp) {
				VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);
				(void) VOP_RWLOCK(readvp, V_WRITELOCK_FALSE,
				    NULL);
				(void) VOP_RWLOCK(vp, V_WRITELOCK_TRUE, NULL);
			} else {
				(void) VOP_RWLOCK(readvp, V_WRITELOCK_FALSE,
				    NULL);
			}

			/*
			 * Same checks as in pread64.
			 */
			if (sfv_off > MAXOFFSET_T) {
				VOP_RWUNLOCK(readvp, V_WRITELOCK_FALSE, NULL);
				releasef(sfv->sfv_fd);
				return (EINVAL);
			}

			if (sfv_off + sfv_len > MAXOFFSET_T)
				sfv_len = (ssize32_t)(MAXOFFSET_T - sfv_off);

			/* Find the native blocksize to transfer data */
			size = MIN(vp->v_vfsp->vfs_bsize,
			    readvp->v_vfsp->vfs_bsize);
			size = sfv_len < size ? sfv_len : size;
			ptr = kmem_alloc(size, KM_NOSLEEP);
			if (ptr == NULL) {
				VOP_RWUNLOCK(readvp, V_WRITELOCK_FALSE, NULL);
				releasef(sfv->sfv_fd);
				return (ENOMEM);
			}

			while (sfv_len > 0) {
				size_t	iov_len;

				iov_len = MIN(size, sfv_len);
				aiov.iov_base = ptr;
				aiov.iov_len = iov_len;
				auio.uio_loffset = sfv_off;
				auio.uio_iov = &aiov;
				auio.uio_iovcnt = 1;
				auio.uio_resid = iov_len;
				auio.uio_segflg = UIO_SYSSPACE;
				auio.uio_llimit = MAXOFFSET_T;
				auio.uio_fmode = ffp->f_flag;
				ioflag = auio.uio_fmode &
				    (FAPPEND|FSYNC|FDSYNC|FRSYNC);

				/*
				 * If read sync is not asked for,
				 * filter sync flags
				 */
				if ((ioflag & FRSYNC) == 0)
					ioflag &= ~(FSYNC|FDSYNC);
				error = VOP_READ(readvp, &auio, ioflag,
				    fp->f_cred, NULL);
				if (error) {
					kmem_free(ptr, size);
					VOP_RWUNLOCK(readvp, V_WRITELOCK_FALSE,
					    NULL);
					releasef(sfv->sfv_fd);
					return (error);
				}

				/*
				 * Check how must data was really read.
				 * Decrement the 'len' and increment the
				 * 'off' appropriately.
				 */
				cnt = iov_len - auio.uio_resid;
				if (cnt == 0) {
					/*
					 * If we were reading a pipe (currently
					 * not implemented), we may now lose
					 * data.
					 */
					kmem_free(ptr, size);
					VOP_RWUNLOCK(readvp, V_WRITELOCK_FALSE,
					    NULL);
					releasef(sfv->sfv_fd);
					return (EINVAL);
				}
				sfv_len -= cnt;
				sfv_off += cnt;

				aiov.iov_base = ptr;
				aiov.iov_len = cnt;
				auio.uio_loffset = *fileoff;
				auio.uio_iov = &aiov;
				auio.uio_iovcnt = 1;
				auio.uio_resid = cnt;
				auio.uio_segflg = UIO_SYSSPACE;
				auio.uio_llimit = curproc->p_fsz_ctl;
				auio.uio_fmode = fflag;
				ioflag = auio.uio_fmode &
				    (FAPPEND|FSYNC|FDSYNC|FRSYNC);
				error = VOP_WRITE(vp, &auio, ioflag,
				    fp->f_cred, NULL);

				/*
				 * Check how much data was written. Increment
				 * the 'len' and decrement the 'off' if all
				 * the data was not written.
				 */
				cnt -= auio.uio_resid;
				sfv_len += auio.uio_resid;
				sfv_off -= auio.uio_resid;
				ttolwp(curthread)->lwp_ru.ioch += (ulong_t)cnt;
				if (vp->v_type == VREG)
					*fileoff += cnt;
				*count += cnt;
				if (error != 0) {
					kmem_free(ptr, size);
					VOP_RWUNLOCK(readvp, V_WRITELOCK_FALSE,
					    NULL);
					releasef(sfv->sfv_fd);
					return (error);
				}
			}
			VOP_RWUNLOCK(readvp, V_WRITELOCK_FALSE, NULL);
			releasef(sfv->sfv_fd);
			kmem_free(ptr, size);
		}
		sfv++;
	}
	return (0);
}

static ssize32_t
sendvec64(file_t *fp, const struct ksendfilevec64 *vec, int sfvcnt,
	size32_t *xferred, int fildes)
{
	u_offset_t		fileoff;
	int			copy_cnt;
	const struct ksendfilevec64 *copy_vec;
	struct ksendfilevec64 sfv[SEND_MAX_CHUNK];
	struct vnode *vp;
	int error;
	ssize32_t count = 0;

	vp = fp->f_vnode;
	(void) VOP_RWLOCK(vp, V_WRITELOCK_TRUE, NULL);

	copy_vec = vec;
	fileoff = fp->f_offset;

	do {
		copy_cnt = MIN(sfvcnt, SEND_MAX_CHUNK);
		if (copyin(copy_vec, sfv, copy_cnt *
		    sizeof (struct ksendfilevec64))) {
			error = EFAULT;
			break;
		}

		error = sendvec_chunk64(fp, &fileoff, sfv, copy_cnt, &count);
		if (error != 0)
			break;

		copy_vec += copy_cnt;
		sfvcnt -= copy_cnt;
	} while (sfvcnt > 0);

	if (vp->v_type == VREG)
		fp->f_offset += count;

	VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);
	if (copyout(&count, xferred, sizeof (count)))
		error = EFAULT;
	releasef(fildes);
	if (error != 0)
		return (set_errno(error));
	return (count);
}
#endif

static int
sendvec_small_chunk(file_t *fp, u_offset_t *fileoff, struct sendfilevec *sfv,
    int copy_cnt, ssize_t total_size, int maxblk, ssize_t *count)
{
	struct vnode *vp;
	struct uio auio;
	struct iovec aiov;
	ushort_t fflag;
	int ioflag;
	int i, error;
	size_t cnt;
	ssize_t sfv_len;
	u_offset_t sfv_off;
#ifdef _SYSCALL32_IMPL
	model_t model = get_udatamodel();
	u_offset_t maxoff = (model == DATAMODEL_ILP32) ?
	    MAXOFF32_T : MAXOFFSET_T;
#else
	const u_offset_t maxoff = MAXOFF32_T;
#endif
	mblk_t *dmp = NULL;
	int wroff;
	int buf_left = 0;
	size_t	iov_len;
	mblk_t  *head, *tmp;
	size_t  size = total_size;
	size_t  extra;
	int tail_len;
	struct nmsghdr msg;

	fflag = fp->f_flag;
	vp = fp->f_vnode;

	ASSERT(vp->v_type == VSOCK);
	ASSERT(maxblk > 0);

	/* If nothing to send, return */
	if (total_size == 0)
		return (0);

	if (vp->v_stream != NULL) {
		wroff = (int)vp->v_stream->sd_wroff;
		tail_len = (int)vp->v_stream->sd_tail;
	} else {
		struct sonode *so;

		so = VTOSO(vp);
		wroff = so->so_proto_props.sopp_wroff;
		tail_len = so->so_proto_props.sopp_tail;
	}

	extra = wroff + tail_len;

	buf_left = MIN(total_size, maxblk);
	head = dmp = allocb(buf_left + extra, BPRI_HI);
	if (head == NULL)
		return (ENOMEM);
	head->b_wptr = head->b_rptr = head->b_rptr + wroff;
	bzero(&msg, sizeof (msg));

	auio.uio_extflg = UIO_COPY_DEFAULT;
	for (i = 0; i < copy_cnt; i++) {
		if (ISSIG(curthread, JUSTLOOKING)) {
			freemsg(head);
			return (EINTR);
		}

		/*
		 * Do similar checks as "write" as we are writing
		 * sfv_len bytes into "vp".
		 */
		sfv_len = (ssize_t)sfv->sfv_len;

		if (sfv_len == 0) {
			sfv++;
			continue;
		}

		/* Check for overflow */
#ifdef _SYSCALL32_IMPL
		if (model == DATAMODEL_ILP32) {
			if (((ssize32_t)(*count + sfv_len)) < 0) {
				freemsg(head);
				return (EINVAL);
			}
		} else
#endif
		if ((*count + sfv_len) < 0) {
			freemsg(head);
			return (EINVAL);
		}

		sfv_off = (u_offset_t)(ulong_t)sfv->sfv_off;

		if (sfv->sfv_fd == SFV_FD_SELF) {
			while (sfv_len > 0) {
				if (buf_left == 0) {
					tmp = dmp;
					buf_left = MIN(total_size, maxblk);
					iov_len = MIN(buf_left, sfv_len);
					dmp = allocb(buf_left + extra, BPRI_HI);
					if (dmp == NULL) {
						freemsg(head);
						return (ENOMEM);
					}
					dmp->b_wptr = dmp->b_rptr =
					    dmp->b_rptr + wroff;
					tmp->b_cont = dmp;
				} else {
					iov_len = MIN(buf_left, sfv_len);
				}

				aiov.iov_len = iov_len;
				aiov.iov_base = (caddr_t)(uintptr_t)sfv_off;
				auio.uio_loffset = *fileoff;
				auio.uio_iovcnt = 1;
				auio.uio_resid = iov_len;
				auio.uio_iov = &aiov;
				auio.uio_segflg = UIO_USERSPACE;
				auio.uio_llimit = curproc->p_fsz_ctl;
				auio.uio_fmode = fflag;

				buf_left -= iov_len;
				total_size -= iov_len;
				sfv_len -= iov_len;
				sfv_off += iov_len;

				error = uiomove((caddr_t)dmp->b_wptr,
				    iov_len, UIO_WRITE, &auio);
				if (error != 0) {
					freemsg(head);
					return (error);
				}
				dmp->b_wptr += iov_len;
			}
		} else {
			file_t	*ffp;
			vnode_t	*readvp;

			if ((ffp = getf(sfv->sfv_fd)) == NULL) {
				freemsg(head);
				return (EBADF);
			}

			if ((ffp->f_flag & FREAD) == 0) {
				releasef(sfv->sfv_fd);
				freemsg(head);
				return (EACCES);
			}

			readvp = ffp->f_vnode;
			if (readvp->v_type != VREG) {
				releasef(sfv->sfv_fd);
				freemsg(head);
				return (EINVAL);
			}

			/*
			 * No point reading and writing to same vp,
			 * as long as both are regular files. readvp is not
			 * locked; but since we got it from an open file the
			 * contents will be valid during the time of access.
			 */

			if (vn_compare(vp, readvp)) {
				releasef(sfv->sfv_fd);
				freemsg(head);
				return (EINVAL);
			}

			/*
			 * Note: we assume readvp != vp. "vp" is already
			 * locked, and "readvp" must not be.
			 */

			if (readvp < vp) {
				VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);
				(void) VOP_RWLOCK(readvp, V_WRITELOCK_FALSE,
				    NULL);
				(void) VOP_RWLOCK(vp, V_WRITELOCK_TRUE, NULL);
			} else {
				(void) VOP_RWLOCK(readvp, V_WRITELOCK_FALSE,
				    NULL);
			}

			/* Same checks as in pread */
			if (sfv_off > maxoff) {
				VOP_RWUNLOCK(readvp, V_WRITELOCK_FALSE, NULL);
				releasef(sfv->sfv_fd);
				freemsg(head);
				return (EINVAL);
			}
			if (sfv_off + sfv_len > maxoff) {
				total_size -= (sfv_off + sfv_len - maxoff);
				sfv_len = (ssize_t)((offset_t)maxoff -
				    sfv_off);
			}

			while (sfv_len > 0) {
				if (buf_left == 0) {
					tmp = dmp;
					buf_left = MIN(total_size, maxblk);
					iov_len = MIN(buf_left, sfv_len);
					dmp = allocb(buf_left + extra, BPRI_HI);
					if (dmp == NULL) {
						VOP_RWUNLOCK(readvp,
						    V_WRITELOCK_FALSE, NULL);
						releasef(sfv->sfv_fd);
						freemsg(head);
						return (ENOMEM);
					}
					dmp->b_wptr = dmp->b_rptr =
					    dmp->b_rptr + wroff;
					tmp->b_cont = dmp;
				} else {
					iov_len = MIN(buf_left, sfv_len);
				}
				aiov.iov_base = (caddr_t)dmp->b_wptr;
				aiov.iov_len = iov_len;
				auio.uio_loffset = sfv_off;
				auio.uio_iov = &aiov;
				auio.uio_iovcnt = 1;
				auio.uio_resid = iov_len;
				auio.uio_segflg = UIO_SYSSPACE;
				auio.uio_llimit = MAXOFFSET_T;
				auio.uio_fmode = ffp->f_flag;
				ioflag = auio.uio_fmode &
				    (FAPPEND|FSYNC|FDSYNC|FRSYNC);

				/*
				 * If read sync is not asked for,
				 * filter sync flags
				 */
				if ((ioflag & FRSYNC) == 0)
					ioflag &= ~(FSYNC|FDSYNC);
				error = VOP_READ(readvp, &auio, ioflag,
				    fp->f_cred, NULL);
				if (error != 0) {
					/*
					 * If we were reading a pipe (currently
					 * not implemented), we may now loose
					 * data.
					 */
					VOP_RWUNLOCK(readvp, V_WRITELOCK_FALSE,
					    NULL);
					releasef(sfv->sfv_fd);
					freemsg(head);
					return (error);
				}

				/*
				 * Check how much data was really read.
				 * Decrement the 'len' and increment the
				 * 'off' appropriately.
				 */
				cnt = iov_len - auio.uio_resid;
				if (cnt == 0) {
					VOP_RWUNLOCK(readvp, V_WRITELOCK_FALSE,
					    NULL);
					releasef(sfv->sfv_fd);
					freemsg(head);
					return (EINVAL);
				}
				sfv_len -= cnt;
				sfv_off += cnt;
				total_size -= cnt;
				buf_left -= cnt;

				dmp->b_wptr += cnt;
			}
			VOP_RWUNLOCK(readvp, V_WRITELOCK_FALSE, NULL);
			releasef(sfv->sfv_fd);
		}
		sfv++;
	}

	ASSERT(total_size == 0);
	error = socket_sendmblk(VTOSO(vp), &msg, fflag, CRED(), &head);
	if (error != 0) {
		if (head != NULL)
			freemsg(head);
		return (error);
	}
	ttolwp(curthread)->lwp_ru.ioch += (ulong_t)size;
	*count += size;

	return (0);
}


static int
sendvec_chunk(file_t *fp, u_offset_t *fileoff, struct sendfilevec *sfv,
    int copy_cnt, ssize_t *count)
{
	struct vnode *vp;
	struct uio auio;
	struct iovec aiov;
	ushort_t fflag;
	int ioflag;
	int i, error;
	size_t cnt;
	ssize_t sfv_len;
	u_offset_t sfv_off;
#ifdef _SYSCALL32_IMPL
	model_t model = get_udatamodel();
	u_offset_t maxoff = (model == DATAMODEL_ILP32) ?
	    MAXOFF32_T : MAXOFFSET_T;
#else
	const u_offset_t maxoff = MAXOFF32_T;
#endif
	mblk_t	*dmp = NULL;
	char	*buf = NULL;
	size_t  extra;
	int maxblk, wroff, tail_len;
	struct sonode *so;
	stdata_t *stp;
	struct nmsghdr msg;

	fflag = fp->f_flag;
	vp = fp->f_vnode;

	if (vp->v_type == VSOCK) {
		so = VTOSO(vp);
		if (vp->v_stream != NULL) {
			stp = vp->v_stream;
			wroff = (int)stp->sd_wroff;
			tail_len = (int)stp->sd_tail;
			maxblk = (int)stp->sd_maxblk;
		} else {
			stp = NULL;
			wroff = so->so_proto_props.sopp_wroff;
			tail_len = so->so_proto_props.sopp_tail;
			maxblk = so->so_proto_props.sopp_maxblk;
		}
		extra = wroff + tail_len;
	}

	bzero(&msg, sizeof (msg));
	auio.uio_extflg = UIO_COPY_DEFAULT;
	for (i = 0; i < copy_cnt; i++) {
		if (ISSIG(curthread, JUSTLOOKING))
			return (EINTR);

		/*
		 * Do similar checks as "write" as we are writing
		 * sfv_len bytes into "vp".
		 */
		sfv_len = (ssize_t)sfv->sfv_len;

		if (sfv_len == 0) {
			sfv++;
			continue;
		}

		if (vp->v_type == VREG) {
			if (*fileoff >= curproc->p_fsz_ctl) {
				mutex_enter(&curproc->p_lock);
				(void) rctl_action(
				    rctlproc_legacy[RLIMIT_FSIZE],
				    curproc->p_rctls, curproc, RCA_SAFE);
				mutex_exit(&curproc->p_lock);

				return (EFBIG);
			}

			if (*fileoff >= maxoff)
				return (EFBIG);

			if (*fileoff + sfv_len > maxoff)
				return (EINVAL);
		}

		/* Check for overflow */
#ifdef _SYSCALL32_IMPL
		if (model == DATAMODEL_ILP32) {
			if (((ssize32_t)(*count + sfv_len)) < 0)
				return (EINVAL);
		} else
#endif
		if ((*count + sfv_len) < 0)
			return (EINVAL);

		sfv_off = (u_offset_t)(ulong_t)sfv->sfv_off;

		if (sfv->sfv_fd == SFV_FD_SELF) {
			if (vp->v_type == VSOCK) {
				while (sfv_len > 0) {
					size_t iov_len;

					iov_len = sfv_len;
					/*
					 * Socket filters can limit the mblk
					 * size, so limit reads to maxblk if
					 * there are filters present.
					 */
					if (so->so_filter_active > 0 &&
					    maxblk != INFPSZ)
						iov_len = MIN(iov_len, maxblk);

					aiov.iov_len = iov_len;
					aiov.iov_base =
					    (caddr_t)(uintptr_t)sfv_off;

					auio.uio_iov = &aiov;
					auio.uio_iovcnt = 1;
					auio.uio_loffset = *fileoff;
					auio.uio_segflg = UIO_USERSPACE;
					auio.uio_fmode = fflag;
					auio.uio_llimit = curproc->p_fsz_ctl;
					auio.uio_resid = iov_len;

					dmp = allocb(iov_len + extra, BPRI_HI);
					if (dmp == NULL)
						return (ENOMEM);
					dmp->b_wptr = dmp->b_rptr =
					    dmp->b_rptr + wroff;
					error = uiomove((caddr_t)dmp->b_wptr,
					    iov_len, UIO_WRITE, &auio);
					if (error != 0) {
						freeb(dmp);
						return (error);
					}
					dmp->b_wptr += iov_len;
					error = socket_sendmblk(VTOSO(vp),
					    &msg, fflag, CRED(), &dmp);

					if (error != 0) {
						if (dmp != NULL)
							freeb(dmp);
						return (error);
					}
					ttolwp(curthread)->lwp_ru.ioch +=
					    (ulong_t)iov_len;
					*count += iov_len;
					sfv_len -= iov_len;
					sfv_off += iov_len;
				}
			} else {
				aiov.iov_len = sfv_len;
				aiov.iov_base = (caddr_t)(uintptr_t)sfv_off;

				auio.uio_iov = &aiov;
				auio.uio_iovcnt = 1;
				auio.uio_loffset = *fileoff;
				auio.uio_segflg = UIO_USERSPACE;
				auio.uio_fmode = fflag;
				auio.uio_llimit = curproc->p_fsz_ctl;
				auio.uio_resid = sfv_len;

				ioflag = auio.uio_fmode &
				    (FAPPEND|FSYNC|FDSYNC|FRSYNC);
				while (sfv_len > 0) {
					error = VOP_WRITE(vp, &auio, ioflag,
					    fp->f_cred, NULL);
					cnt = sfv_len - auio.uio_resid;
					sfv_len -= cnt;
					ttolwp(curthread)->lwp_ru.ioch +=
					    (ulong_t)cnt;
					*fileoff += cnt;
					*count += cnt;
					if (error != 0)
						return (error);
				}
			}
		} else {
			int segmapit = 0;
			file_t	*ffp;
			vnode_t	*readvp;
			struct vnode *realvp;
			size_t	size;
			caddr_t	ptr;

			if ((ffp = getf(sfv->sfv_fd)) == NULL)
				return (EBADF);

			if ((ffp->f_flag & FREAD) == 0) {
				releasef(sfv->sfv_fd);
				return (EBADF);
			}

			readvp = ffp->f_vnode;
			if (VOP_REALVP(readvp, &realvp, NULL) == 0)
				readvp = realvp;
			if (readvp->v_type != VREG) {
				releasef(sfv->sfv_fd);
				return (EINVAL);
			}

			/*
			 * No point reading and writing to same vp,
			 * as long as both are regular files. readvp is not
			 * locked; but since we got it from an open file the
			 * contents will be valid during the time of access.
			 */
			if (vn_compare(vp, readvp)) {
				releasef(sfv->sfv_fd);
				return (EINVAL);
			}

			/*
			 * Note: we assume readvp != vp. "vp" is already
			 * locked, and "readvp" must not be.
			 */
			if (readvp < vp) {
				VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);
				(void) VOP_RWLOCK(readvp, V_WRITELOCK_FALSE,
				    NULL);
				(void) VOP_RWLOCK(vp, V_WRITELOCK_TRUE, NULL);
			} else {
				(void) VOP_RWLOCK(readvp, V_WRITELOCK_FALSE,
				    NULL);
			}

			/* Same checks as in pread */
			if (sfv_off > maxoff) {
				VOP_RWUNLOCK(readvp, V_WRITELOCK_FALSE, NULL);
				releasef(sfv->sfv_fd);
				return (EINVAL);
			}
			if (sfv_off + sfv_len > maxoff) {
				sfv_len = (ssize_t)((offset_t)maxoff -
				    sfv_off);
			}
			/* Find the native blocksize to transfer data */
			size = MIN(vp->v_vfsp->vfs_bsize,
			    readvp->v_vfsp->vfs_bsize);
			size = sfv_len < size ? sfv_len : size;

			if (vp->v_type != VSOCK) {
				segmapit = 0;
				buf = kmem_alloc(size, KM_NOSLEEP);
				if (buf == NULL) {
					VOP_RWUNLOCK(readvp, V_WRITELOCK_FALSE,
					    NULL);
					releasef(sfv->sfv_fd);
					return (ENOMEM);
				}
			} else {
				uint_t	copyflag;

				copyflag = stp != NULL ? stp->sd_copyflag :
				    so->so_proto_props.sopp_zcopyflag;

				/*
				 * Socket filters can limit the mblk size,
				 * so limit reads to maxblk if there are
				 * filters present.
				 */
				if (so->so_filter_active > 0 &&
				    maxblk != INFPSZ)
					size = MIN(size, maxblk);

				if (vn_has_flocks(readvp) ||
				    readvp->v_flag & VNOMAP ||
				    copyflag & STZCVMUNSAFE) {
					segmapit = 0;
				} else if (copyflag & STZCVMSAFE) {
					segmapit = 1;
				} else {
					int on = 1;
					if (socket_setsockopt(VTOSO(vp),
					    SOL_SOCKET, SO_SND_COPYAVOID,
					    &on, sizeof (on), CRED()) == 0)
					segmapit = 1;
				}
			}

			if (segmapit) {
				boolean_t nowait;

				nowait = (sfv->sfv_flag & SFV_NOWAIT) != 0;
				error = snf_segmap(fp, readvp, sfv_off,
				    (u_offset_t)sfv_len, (ssize_t *)&cnt,
				    nowait);
				releasef(sfv->sfv_fd);
				*count += cnt;
				if (error)
					return (error);
				sfv++;
				continue;
			}

			while (sfv_len > 0) {
				size_t	iov_len;

				iov_len = MIN(size, sfv_len);

				if (vp->v_type == VSOCK) {
					dmp = allocb(iov_len + extra, BPRI_HI);
					if (dmp == NULL) {
						VOP_RWUNLOCK(readvp,
						    V_WRITELOCK_FALSE, NULL);
						releasef(sfv->sfv_fd);
						return (ENOMEM);
					}
					dmp->b_wptr = dmp->b_rptr =
					    dmp->b_rptr + wroff;
					ptr = (caddr_t)dmp->b_rptr;
				} else {
					ptr = buf;
				}

				aiov.iov_base = ptr;
				aiov.iov_len = iov_len;
				auio.uio_loffset = sfv_off;
				auio.uio_iov = &aiov;
				auio.uio_iovcnt = 1;
				auio.uio_resid = iov_len;
				auio.uio_segflg = UIO_SYSSPACE;
				auio.uio_llimit = MAXOFFSET_T;
				auio.uio_fmode = ffp->f_flag;
				ioflag = auio.uio_fmode &
				    (FAPPEND|FSYNC|FDSYNC|FRSYNC);

				/*
				 * If read sync is not asked for,
				 * filter sync flags
				 */
				if ((ioflag & FRSYNC) == 0)
					ioflag &= ~(FSYNC|FDSYNC);
				error = VOP_READ(readvp, &auio, ioflag,
				    fp->f_cred, NULL);
				if (error != 0) {
					/*
					 * If we were reading a pipe (currently
					 * not implemented), we may now lose
					 * data.
					 */
					if (vp->v_type == VSOCK)
						freeb(dmp);
					else
						kmem_free(buf, size);
					VOP_RWUNLOCK(readvp, V_WRITELOCK_FALSE,
					    NULL);
					releasef(sfv->sfv_fd);
					return (error);
				}

				/*
				 * Check how much data was really read.
				 * Decrement the 'len' and increment the
				 * 'off' appropriately.
				 */
				cnt = iov_len - auio.uio_resid;
				if (cnt == 0) {
					if (vp->v_type == VSOCK)
						freeb(dmp);
					else
						kmem_free(buf, size);
					VOP_RWUNLOCK(readvp, V_WRITELOCK_FALSE,
					    NULL);
					releasef(sfv->sfv_fd);
					return (EINVAL);
				}
				sfv_len -= cnt;
				sfv_off += cnt;

				if (vp->v_type == VSOCK) {
					dmp->b_wptr = dmp->b_rptr + cnt;

					error = socket_sendmblk(VTOSO(vp),
					    &msg, fflag, CRED(), &dmp);

					if (error != 0) {
						if (dmp != NULL)
							freeb(dmp);
						VOP_RWUNLOCK(readvp,
						    V_WRITELOCK_FALSE, NULL);
						releasef(sfv->sfv_fd);
						return (error);
					}

					ttolwp(curthread)->lwp_ru.ioch +=
					    (ulong_t)cnt;
					*count += cnt;
				} else {

					aiov.iov_base = ptr;
					aiov.iov_len = cnt;
					auio.uio_loffset = *fileoff;
					auio.uio_resid = cnt;
					auio.uio_iov = &aiov;
					auio.uio_iovcnt = 1;
					auio.uio_segflg = UIO_SYSSPACE;
					auio.uio_llimit = curproc->p_fsz_ctl;
					auio.uio_fmode = fflag;
					ioflag = auio.uio_fmode &
					    (FAPPEND|FSYNC|FDSYNC|FRSYNC);
					error = VOP_WRITE(vp, &auio, ioflag,
					    fp->f_cred, NULL);

					/*
					 * Check how much data was written.
					 * Increment the 'len' and decrement the
					 * 'off' if all the data was not
					 * written.
					 */
					cnt -= auio.uio_resid;
					sfv_len += auio.uio_resid;
					sfv_off -= auio.uio_resid;
					ttolwp(curthread)->lwp_ru.ioch +=
					    (ulong_t)cnt;
					*fileoff += cnt;
					*count += cnt;
					if (error != 0) {
						kmem_free(buf, size);
						VOP_RWUNLOCK(readvp,
						    V_WRITELOCK_FALSE, NULL);
						releasef(sfv->sfv_fd);
						return (error);
					}
				}
			}
			if (buf) {
				kmem_free(buf, size);
				buf = NULL;
			}
			VOP_RWUNLOCK(readvp, V_WRITELOCK_FALSE, NULL);
			releasef(sfv->sfv_fd);
		}
		sfv++;
	}
	return (0);
}

ssize_t
sendfilev(int opcode, int fildes, const struct sendfilevec *vec, int sfvcnt,
    size_t *xferred)
{
	int error = 0;
	int first_vector_error = 0;
	file_t *fp;
	struct vnode *vp;
	struct sonode *so;
	u_offset_t fileoff;
	int copy_cnt;
	const struct sendfilevec *copy_vec;
	struct sendfilevec sfv[SEND_MAX_CHUNK];
	ssize_t count = 0;
#ifdef _SYSCALL32_IMPL
	struct ksendfilevec32 sfv32[SEND_MAX_CHUNK];
#endif
	ssize_t total_size;
	int i;
	boolean_t is_sock = B_FALSE;
	int maxblk = 0;

	if (sfvcnt <= 0)
		return (set_errno(EINVAL));

	if ((fp = getf(fildes)) == NULL)
		return (set_errno(EBADF));

	if (((fp->f_flag) & FWRITE) == 0) {
		error = EBADF;
		goto err;
	}

	fileoff = fp->f_offset;
	vp = fp->f_vnode;

	switch (vp->v_type) {
	case VSOCK:
		so = VTOSO(vp);
		is_sock = B_TRUE;
		if (SOCK_IS_NONSTR(so)) {
			maxblk = so->so_proto_props.sopp_maxblk;
		} else {
			maxblk = (int)vp->v_stream->sd_maxblk;
		}

		/*
		 * We need to make sure that the socket that we're sending on
		 * supports sendfile behavior. sockfs doesn't know that the APIs
		 * we want to use are coming from sendfile, so we can't rely on
		 * it to check for us.
		 */
		if ((so->so_mode & SM_SENDFILESUPP) == 0) {
			error = EOPNOTSUPP;
			goto err;
		}
		break;
	case VREG:
		break;
	default:
		error = EINVAL;
		goto err;
	}

	switch (opcode) {
	case SENDFILEV :
		break;
#if defined(_SYSCALL32_IMPL) || defined(_ILP32)
	case SENDFILEV64 :
		return (sendvec64(fp, (struct ksendfilevec64 *)vec, sfvcnt,
		    (size32_t *)xferred, fildes));
#endif
	default :
		error = ENOSYS;
		break;
	}

	(void) VOP_RWLOCK(vp, V_WRITELOCK_TRUE, NULL);
	copy_vec = vec;

	do {
		total_size = 0;
		copy_cnt = MIN(sfvcnt, SEND_MAX_CHUNK);
#ifdef _SYSCALL32_IMPL
		/* 32-bit callers need to have their iovec expanded. */
		if (get_udatamodel() == DATAMODEL_ILP32) {
			if (copyin(copy_vec, sfv32,
			    copy_cnt * sizeof (ksendfilevec32_t))) {
				error = EFAULT;
				break;
			}

			for (i = 0; i < copy_cnt; i++) {
				sfv[i].sfv_fd = sfv32[i].sfv_fd;
				sfv[i].sfv_off =
				    (off_t)(uint32_t)sfv32[i].sfv_off;
				sfv[i].sfv_len = (size_t)sfv32[i].sfv_len;
				total_size += sfv[i].sfv_len;
				sfv[i].sfv_flag = sfv32[i].sfv_flag;
				/*
				 * Individual elements of the vector must not
				 * wrap or overflow, as later math is signed.
				 * Equally total_size needs to be checked after
				 * each vector is added in, to be sure that
				 * rogue values haven't overflowed the counter.
				 */
				if (((ssize32_t)sfv[i].sfv_len < 0) ||
				    ((ssize32_t)total_size < 0)) {
					/*
					 * Truncate the vector to send data
					 * described by elements before the
					 * error.
					 */
					copy_cnt = i;
					first_vector_error = EINVAL;
					/* total_size can't be trusted */
					if ((ssize32_t)total_size < 0)
						error = EINVAL;
					break;
				}
			}
			/* Nothing to do, process errors */
			if (copy_cnt == 0)
				break;

		} else {
#endif
			if (copyin(copy_vec, sfv,
			    copy_cnt * sizeof (sendfilevec_t))) {
				error = EFAULT;
				break;
			}

			for (i = 0; i < copy_cnt; i++) {
				total_size += sfv[i].sfv_len;
				/*
				 * Individual elements of the vector must not
				 * wrap or overflow, as later math is signed.
				 * Equally total_size needs to be checked after
				 * each vector is added in, to be sure that
				 * rogue values haven't overflowed the counter.
				 */
				if (((ssize_t)sfv[i].sfv_len < 0) ||
				    (total_size < 0)) {
					/*
					 * Truncate the vector to send data
					 * described by elements before the
					 * error.
					 */
					copy_cnt = i;
					first_vector_error = EINVAL;
					/* total_size can't be trusted */
					if (total_size < 0)
						error = EINVAL;
					break;
				}
			}
			/* Nothing to do, process errors */
			if (copy_cnt == 0)
				break;
#ifdef _SYSCALL32_IMPL
		}
#endif

		/*
		 * The task between deciding to use sendvec_small_chunk
		 * and sendvec_chunk is dependant on multiple things:
		 *
		 * i) latency is important for smaller files. So if the
		 * data is smaller than 'tcp_slow_start_initial' times
		 * maxblk, then use sendvec_small_chunk which creates
		 * maxblk size mblks and chains them together and sends
		 * them to TCP in one shot. It also leaves 'wroff' size
		 * space for the headers in each mblk.
		 *
		 * ii) for total size bigger than 'tcp_slow_start_initial'
		 * time maxblk, its probably real file data which is
		 * dominating. So its better to use sendvec_chunk because
		 * performance goes to dog if we don't do pagesize reads.
		 * sendvec_chunk will do pagesize reads and write them
		 * in pagesize mblks to TCP.
		 *
		 * Side Notes: A write to file has not been optimized.
		 * Future zero copy code will plugin into sendvec_chunk
		 * only because doing zero copy for files smaller then
		 * pagesize is useless.
		 *
		 * Note, if socket has NL7C enabled then call NL7C's
		 * senfilev() function to consume the sfv[].
		 */
		if (is_sock) {
			if (!SOCK_IS_NONSTR(so) &&
			    _SOTOTPI(so)->sti_nl7c_flags != 0) {
				error = nl7c_sendfilev(so, &fileoff,
				    sfv, copy_cnt, &count);
			} else if ((total_size <= (4 * maxblk)) &&
			    error == 0) {
				error = sendvec_small_chunk(fp,
				    &fileoff, sfv, copy_cnt,
				    total_size, maxblk, &count);
			} else {
				error = sendvec_chunk(fp, &fileoff,
				    sfv, copy_cnt, &count);
			}
		} else {
			ASSERT(vp->v_type == VREG);
			error = sendvec_chunk(fp, &fileoff, sfv, copy_cnt,
			    &count);
		}


#ifdef _SYSCALL32_IMPL
	if (get_udatamodel() == DATAMODEL_ILP32)
		copy_vec = (const struct sendfilevec *)((char *)copy_vec +
		    (copy_cnt * sizeof (ksendfilevec32_t)));
	else
#endif
		copy_vec += copy_cnt;
		sfvcnt -= copy_cnt;

	/* Process all vector members up to first error */
	} while ((sfvcnt > 0) && first_vector_error == 0 && error == 0);

	if (vp->v_type == VREG)
		fp->f_offset += count;

	VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);

#ifdef _SYSCALL32_IMPL
	if (get_udatamodel() == DATAMODEL_ILP32) {
		ssize32_t count32 = (ssize32_t)count;
		if (copyout(&count32, xferred, sizeof (count32)))
			error = EFAULT;
		releasef(fildes);
		if (error != 0)
			return (set_errno(error));
		if (first_vector_error != 0)
			return (set_errno(first_vector_error));
		return (count32);
	}
#endif
	if (copyout(&count, xferred, sizeof (count)))
		error = EFAULT;
	releasef(fildes);
	if (error != 0)
		return (set_errno(error));
	if (first_vector_error != 0)
		return (set_errno(first_vector_error));
	return (count);
err:
	ASSERT(error != 0);
	releasef(fildes);
	return (set_errno(error));
}

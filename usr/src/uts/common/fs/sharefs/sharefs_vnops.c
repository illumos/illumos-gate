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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <fs/fs_subr.h>

#include <sys/errno.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/kobj.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/atomic.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>

#include <sharefs/sharefs.h>

/*
 * sharefs_snap_create: create a large character buffer with
 * the shares enumerated.
 */
static int
sharefs_snap_create(shnode_t *sft)
{
	sharetab_t		*sht;
	share_t			*sh;
	size_t			sWritten = 0;
	int			iCount = 0;
	char			*buf;

	rw_enter(&sharefs_lock, RW_WRITER);
	rw_enter(&sharetab_lock, RW_READER);

	if (sft->sharefs_snap) {
		/*
		 * Nothing has changed, so no need to grab a new copy!
		 */
		if (sft->sharefs_generation == sharetab_generation) {
			rw_exit(&sharetab_lock);
			rw_exit(&sharefs_lock);
			return (0);
		}

		ASSERT(sft->sharefs_size != 0);
		kmem_free(sft->sharefs_snap, sft->sharefs_size + 1);
		sft->sharefs_snap = NULL;
	}

	sft->sharefs_size = sharetab_size;
	sft->sharefs_count = sharetab_count;

	if (sft->sharefs_size == 0) {
		rw_exit(&sharetab_lock);
		rw_exit(&sharefs_lock);
		return (0);
	}

	sft->sharefs_snap = kmem_zalloc(sft->sharefs_size + 1, KM_SLEEP);

	buf = sft->sharefs_snap;

	/*
	 * Walk the Sharetab, dumping each entry.
	 */
	for (sht = sharefs_sharetab; sht != NULL; sht = sht->s_next) {
		int	i;

		for (i = 0; i < SHARETAB_HASHES; i++) {
			for (sh = sht->s_buckets[i].ssh_sh;
			    sh != NULL;
			    sh = sh->sh_next) {
				int	n;

				if ((sWritten + sh->sh_size) >
				    sft->sharefs_size) {
					goto error_fault;
				}

				/*
				 * Note that sh->sh_size accounts
				 * for the field seperators.
				 * We need to add one for the EOL
				 * marker. And we should note that
				 * the space is accounted for in
				 * each share by the EOS marker.
				 */
				n = snprintf(&buf[sWritten],
				    sh->sh_size + 1,
				    "%s\t%s\t%s\t%s\t%s\n",
				    sh->sh_path,
				    sh->sh_res,
				    sh->sh_fstype,
				    sh->sh_opts,
				    sh->sh_descr);

				if (n != sh->sh_size) {
					goto error_fault;
				}

				sWritten += n;
				iCount++;
			}
		}
	}

	/*
	 * We want to record the generation number and
	 * mtime inside this snapshot.
	 */
	gethrestime(&sharetab_snap_time);
	sft->sharefs_snap_time = sharetab_snap_time;
	sft->sharefs_generation = sharetab_generation;

	ASSERT(iCount == sft->sharefs_count);

	rw_exit(&sharetab_lock);
	rw_exit(&sharefs_lock);
	return (0);

error_fault:

	kmem_free(sft->sharefs_snap, sft->sharefs_size + 1);
	sft->sharefs_size = 0;
	sft->sharefs_count = 0;
	sft->sharefs_snap = NULL;
	rw_exit(&sharetab_lock);
	rw_exit(&sharefs_lock);

	return (EFAULT);
}

/* ARGSUSED */
static int
sharefs_getattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr,
    caller_context_t *ct)
{
	timestruc_t	now;
	shnode_t	*sft = VTOSH(vp);

	vap->va_type = VREG;
	vap->va_mode = S_IRUSR | S_IRGRP | S_IROTH;
	vap->va_nodeid = SHAREFS_INO_FILE;
	vap->va_nlink = 1;

	rw_enter(&sharefs_lock, RW_READER);

	/*
	 * If we get asked about a snapped vnode, then
	 * we must report the data in that vnode.
	 *
	 * Else we report what is currently in the
	 * sharetab.
	 */
	if (sft->sharefs_real_vp) {
		rw_enter(&sharetab_lock, RW_READER);
		vap->va_size = sharetab_size;
		vap->va_mtime = sharetab_mtime;
		rw_exit(&sharetab_lock);
	} else {
		vap->va_size = sft->sharefs_size;
		vap->va_mtime = sft->sharefs_snap_time;
	}
	rw_exit(&sharefs_lock);

	gethrestime(&now);
	vap->va_atime = vap->va_ctime = now;

	vap->va_uid = 0;
	vap->va_gid = 0;
	vap->va_rdev = 0;
	vap->va_blksize = DEV_BSIZE;
	vap->va_nblocks = howmany(vap->va_size, vap->va_blksize);
	vap->va_seq = 0;
	vap->va_fsid = vp->v_vfsp->vfs_dev;

	return (0);
}

/* ARGSUSED */
static int
sharefs_access(vnode_t *vp, int mode, int flags, cred_t *cr,
    caller_context_t *ct)
{
	if (mode & (VWRITE|VEXEC))
		return (EROFS);

	return (0);
}

/* ARGSUSED */
int
sharefs_open(vnode_t **vpp, int flag, cred_t *cr, caller_context_t *ct)
{
	vnode_t		*vp;
	vnode_t		*ovp = *vpp;
	shnode_t	*sft;
	int		error = 0;

	if (flag & FWRITE)
		return (EINVAL);

	/*
	 * Create a new sharefs vnode for each operation. In order to
	 * avoid locks, we create a snapshot which can not change during
	 * reads.
	 */
	vp = gfs_file_create(sizeof (shnode_t), NULL, sharefs_ops_data);

	((gfs_file_t *)vp->v_data)->gfs_ino = SHAREFS_INO_FILE;

	/*
	 * Hold the parent!
	 */
	VFS_HOLD(ovp->v_vfsp);

	VN_SET_VFS_TYPE_DEV(vp, ovp->v_vfsp, VREG, 0);

	vp->v_flag |= VROOT | VNOCACHE | VNOMAP | VNOSWAP | VNOMOUNT;

	*vpp = vp;
	VN_RELE(ovp);

	sft = VTOSH(vp);

	/*
	 * No need for the lock, no other thread can be accessing
	 * this data structure.
	 */
	atomic_inc_32(&sft->sharefs_refs);
	sft->sharefs_real_vp = 0;

	/*
	 * Since the sharetab could easily change on us whilst we
	 * are dumping an extremely huge sharetab, we make a copy
	 * of it here and use it to dump instead.
	 */
	error = sharefs_snap_create(sft);

	return (error);
}

/* ARGSUSED */
int
sharefs_close(vnode_t *vp, int flag, int count,
    offset_t off, cred_t *cr, caller_context_t *ct)
{
	shnode_t	*sft = VTOSH(vp);

	if (count > 1)
		return (0);

	rw_enter(&sharefs_lock, RW_WRITER);
	if (vp->v_count == 1) {
		if (sft->sharefs_snap != NULL) {
			kmem_free(sft->sharefs_snap, sft->sharefs_size + 1);
			sft->sharefs_size = 0;
			sft->sharefs_snap = NULL;
			sft->sharefs_generation = 0;
		}
	}
	atomic_dec_32(&sft->sharefs_refs);
	rw_exit(&sharefs_lock);

	return (0);
}

/* ARGSUSED */
static int
sharefs_read(vnode_t *vp, uio_t *uio, int ioflag, cred_t *cr,
			caller_context_t *ct)
{
	shnode_t	*sft = VTOSH(vp);
	off_t		off = uio->uio_offset;
	size_t		len = uio->uio_resid;
	int		error = 0;

	rw_enter(&sharefs_lock, RW_READER);

	/*
	 * First check to see if we need to grab a new snapshot.
	 */
	if (off == (off_t)0) {
		rw_exit(&sharefs_lock);
		error = sharefs_snap_create(sft);
		if (error) {
			return (EFAULT);
		}
		rw_enter(&sharefs_lock, RW_READER);
	}

	/* LINTED */
	if (len <= 0 || off >= sft->sharefs_size) {
		rw_exit(&sharefs_lock);
		return (error);
	}

	if ((size_t)(off + len) > sft->sharefs_size)
		len = sft->sharefs_size - off;

	if (off < 0 || len > sft->sharefs_size) {
		rw_exit(&sharefs_lock);
		return (EFAULT);
	}

	if (len != 0) {
		error = uiomove(sft->sharefs_snap + off,
		    len, UIO_READ, uio);
	}

	rw_exit(&sharefs_lock);
	return (error);
}

/* ARGSUSED */
static void
sharefs_inactive(vnode_t *vp, cred_t *cr, caller_context_t *tx)
{
	gfs_file_t	*fp = vp->v_data;
	shnode_t	*sft;

	sft = (shnode_t *)gfs_file_inactive(vp);
	if (sft) {
		rw_enter(&sharefs_lock, RW_WRITER);
		if (sft->sharefs_snap != NULL) {
			kmem_free(sft->sharefs_snap, sft->sharefs_size + 1);
		}

		kmem_free(sft, fp->gfs_size);
		rw_exit(&sharefs_lock);
	}
}

vnode_t *
sharefs_create_root_file(vfs_t *vfsp)
{
	vnode_t		*vp;
	shnode_t	*sft;

	vp = gfs_root_create_file(sizeof (shnode_t),
	    vfsp, sharefs_ops_data, SHAREFS_INO_FILE);

	sft = VTOSH(vp);

	sft->sharefs_real_vp = 1;

	return (vp);
}

const fs_operation_def_t sharefs_tops_data[] = {
	{ VOPNAME_OPEN,		{ .vop_open = sharefs_open } },
	{ VOPNAME_CLOSE,	{ .vop_close = sharefs_close } },
	{ VOPNAME_IOCTL,	{ .error = fs_inval } },
	{ VOPNAME_GETATTR,	{ .vop_getattr = sharefs_getattr } },
	{ VOPNAME_ACCESS,	{ .vop_access = sharefs_access } },
	{ VOPNAME_INACTIVE,	{ .vop_inactive = sharefs_inactive } },
	{ VOPNAME_READ,		{ .vop_read = sharefs_read } },
	{ VOPNAME_SEEK,		{ .vop_seek = fs_seek } },
	{ NULL }
};

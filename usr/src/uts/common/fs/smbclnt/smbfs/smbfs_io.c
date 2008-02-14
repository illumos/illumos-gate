/*
 * Copyright (c) 2000-2001, Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: smbfs_io.c,v 1.41.38.1 2005/05/27 02:35:28 lindak Exp $
 *
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/fcntl.h>
#include <sys/mount.h>
#include <sys/dirent.h>
#include <sys/syslog.h>
#include <sys/file.h>

#ifdef APPLE
#include <sys/smb_apple.h>
#else
#include <netsmb/smb_osdep.h>
#endif

#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>

#include <smbfs/smbfs.h>
#include <smbfs/smbfs_node.h>
#include <smbfs/smbfs_subr.h>

/* XXX: This file should go away, after more work in _vnops.c */

int
smbfs_readvnode(vnode_t *vp, uio_t *uiop, cred_t *cr,
		struct vattr *vap)
{
	smbmntinfo_t *smp = VTOSMI(vp);
	struct smbnode *np = VTOSMB(vp);
	struct smb_cred scred;
	int error;
	int requestsize;
	size_t remainder;

	/* shared lock for n_fid use in smb_rwuio */
	ASSERT(smbfs_rw_lock_held(&np->r_lkserlock, RW_READER));

	if (vp->v_type != VREG) {
		SMBVDEBUG("only VREG supported\n");
		return (EIO);
	}
	if (uiop->uio_resid == 0)
		return (0);
	if (uiop->uio_loffset < 0)
		return (EINVAL);
#ifdef NOT_YET
	if ((uiop->uio_loffset + uiop->uio_resid) > smp->nm_maxfilesize)
		return (EFBIG);
#endif

	smb_credinit(&scred, curproc, cr);

	/* XXX: Update n_size maybe? */
	(void) smbfs_smb_flush(np, &scred);

	if (uiop->uio_loffset >= vap->va_size) {
		/* if offset is beyond EOF, read nothing */
		error = 0;
		goto out;
	}

	/* pin requestsize to EOF */
	requestsize = min(uiop->uio_resid,
	    (vap->va_size - uiop->uio_loffset));

	/* subtract requestSize from uio_resid and save remainder */
	remainder = uiop->uio_resid - requestsize;

	/* adjust size of read */
	uiop->uio_resid = requestsize;

	error = smb_rwuio(smp->smi_share, np->n_fid, UIO_READ, uiop,
	    &scred, smb_timo_read);

	/* set remaining uio_resid */
	uiop->uio_resid = uiop->uio_resid + remainder;

out:
	smb_credrele(&scred);

	return (error);
}

int
smbfs_writevnode(vnode_t *vp, uio_t *uiop,
	cred_t *cr, int ioflag, int timo)
{
	smbmntinfo_t *smp = VTOSMI(vp);
	struct smbnode *np = VTOSMB(vp);
	struct smb_cred scred;
	int error = 0;

	/* shared lock for n_fid use in smb_rwuio */
	ASSERT(smbfs_rw_lock_held(&np->r_lkserlock, RW_READER));

	if (vp->v_type != VREG) {
		SMBVDEBUG("only VREG supported\n");
		return (EIO);
	}
	SMBVDEBUG("ofs=%lld,resid=%d\n", uiop->uio_loffset,
	    (int)uiop->uio_resid);
	if (uiop->uio_loffset < 0)
		return (EINVAL);
#ifdef NOT_YET
	if (uiop->uio_loffset + uiop->uio_resid > smp->nm_maxfilesize)
		return (EFBIG);
#endif
	if (ioflag & (FAPPEND | FSYNC)) {
		if (np->n_flag & NMODIFIED) {
			smbfs_attr_cacheremove(np);
			/* XXX: smbfs_vinvalbuf? */
		}
		if (ioflag & FAPPEND) {
			struct vattr vattr;
			/*
			 * File size can be changed by another client
			 */
			error = smbfsgetattr(vp, &vattr, cr);
			if (error)
				return (error);
			mutex_enter(&np->r_statelock);
			uiop->uio_loffset = np->n_size;
			mutex_exit(&np->r_statelock);
		}
	}
	if (uiop->uio_resid == 0)
		return (0);

	smb_credinit(&scred, curproc, cr);

	/*
	 * Darwin had code here to zero-extend using
	 * smb_write requests.  Not needed.
	 *
	 * Use a longer timeout when appending.
	 * This ignores the passed-in timo value,
	 * but that was just a constant anyway.
	 * XXX: remove passed in timo arg later.
	 */
	timo = smb_timo_write;
	if ((uiop->uio_loffset + uiop->uio_resid) > np->n_size)
		timo = smb_timo_append;
	error = smb_rwuio(smp->smi_share, np->n_fid, UIO_WRITE, uiop,
	    &scred, timo);

	mutex_enter(&np->r_statelock);
	np->n_flag |= (NFLUSHWIRE | NATTRCHANGED);
	mutex_exit(&np->r_statelock);

	smb_credrele(&scred);

	SMBVDEBUG("after: ofs=%lld,resid=%d\n", uiop->uio_loffset,
	    (int)uiop->uio_resid);
	if (!error) {
		mutex_enter(&np->r_statelock);
		if (uiop->uio_loffset > (offset_t)np->n_size)
			np->n_size = (len_t)uiop->uio_loffset;
		mutex_exit(&np->r_statelock);
	}
	return (error);
}

/*
 * Copyright (c) 2000-2001 Boris Popov
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
 * $Id: smbfs_vnops.c,v 1.128.36.1 2005/05/27 02:35:28 lindak Exp $
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Vnode operations
 *
 * This file is similar to nfs3_vnops.c
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/filio.h>
#include <sys/uio.h>
#include <sys/dirent.h>
#include <sys/errno.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/vfs_opreg.h>
#include <sys/policy.h>
#include <sys/sdt.h>
#include <sys/zone.h>
#include <sys/vmsystm.h>

#include <vm/hat.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/seg_kpm.h>
#include <vm/seg_vn.h>

#include <netsmb/smb_osdep.h>
#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>

#include <smbfs/smbfs.h>
#include <smbfs/smbfs_node.h>
#include <smbfs/smbfs_subr.h>

#include <sys/fs/smbfs_ioctl.h>
#include <fs/fs_subr.h>

/*
 * We assign directory offsets like the NFS client, where the
 * offset increments by _one_ after each directory entry.
 * Further, the entries "." and ".." are always at offsets
 * zero and one (respectively) and the "real" entries from
 * the server appear at offsets starting with two.  This
 * macro is used to initialize the n_dirofs field after
 * setting n_dirseq with a _findopen call.
 */
#define	FIRST_DIROFS	2

/*
 * These characters are illegal in NTFS file names.
 * ref: http://support.microsoft.com/kb/147438
 *
 * Careful!  The check in the XATTR case skips the
 * first character to allow colon in XATTR names.
 */
static const char illegal_chars[] = {
	':',	/* colon - keep this first! */
	'\\',	/* back slash */
	'/',	/* slash */
	'*',	/* asterisk */
	'?',	/* question mark */
	'"',	/* double quote */
	'<',	/* less than sign */
	'>',	/* greater than sign */
	'|',	/* vertical bar */
	0
};

/*
 * Turning this on causes nodes to be created in the cache
 * during directory listings, normally avoiding a second
 * OtW attribute fetch just after a readdir.
 */
int smbfs_fastlookup = 1;

struct vnodeops *smbfs_vnodeops = NULL;

/* local static function defines */

static int	smbfslookup_cache(vnode_t *, char *, int, vnode_t **,
			cred_t *);
static int	smbfslookup(vnode_t *dvp, char *nm, vnode_t **vpp, cred_t *cr,
			int cache_ok, caller_context_t *);
static int	smbfsremove(vnode_t *dvp, vnode_t *vp, struct smb_cred *scred,
			int flags);
static int	smbfsrename(vnode_t *odvp, vnode_t *ovp, vnode_t *ndvp,
			char *nnm, struct smb_cred *scred, int flags);
static int	smbfssetattr(vnode_t *, struct vattr *, int, cred_t *);
static int	smbfs_accessx(void *, int, cred_t *);
static int	smbfs_readvdir(vnode_t *vp, uio_t *uio, cred_t *cr, int *eofp,
			caller_context_t *);
static void	smbfs_rele_fid(smbnode_t *, struct smb_cred *);
static uint32_t xvattr_to_dosattr(smbnode_t *, struct vattr *);

static int	smbfs_rdwrlbn(vnode_t *, page_t *, u_offset_t, size_t, int,
			cred_t *);
static int	smbfs_bio(struct buf *, int, cred_t *);
static int	smbfs_writenp(smbnode_t *np, caddr_t base, int tcount,
			struct uio *uiop, int pgcreated);

static int	smbfs_fsync(vnode_t *, int, cred_t *, caller_context_t *);
static int	smbfs_putpage(vnode_t *, offset_t, size_t, int, cred_t *,
			caller_context_t *);
static int	smbfs_getapage(vnode_t *, u_offset_t, size_t, uint_t *,
			page_t *[], size_t, struct seg *, caddr_t,
			enum seg_rw, cred_t *);
static int	smbfs_putapage(vnode_t *, page_t *, u_offset_t *, size_t *,
			int, cred_t *);
static void	smbfs_delmap_callback(struct as *, void *, uint_t);

/*
 * Error flags used to pass information about certain special errors
 * which need to be handled specially.
 */
#define	SMBFS_EOF			-98

/* When implementing OtW locks, make this a real function. */
#define	smbfs_lm_has_sleep(vp) 0

/*
 * These are the vnode ops routines which implement the vnode interface to
 * the networked file system.  These routines just take their parameters,
 * make them look networkish by putting the right info into interface structs,
 * and then calling the appropriate remote routine(s) to do the work.
 *
 * Note on directory name lookup cacheing:  If we detect a stale fhandle,
 * we purge the directory cache relative to that vnode.  This way, the
 * user won't get burned by the cache repeatedly.  See <smbfs/smbnode.h> for
 * more details on smbnode locking.
 */


/*
 * XXX
 * When new and relevant functionality is enabled, we should be
 * calling vfs_set_feature() to inform callers that pieces of
 * functionality are available, per PSARC 2007/227.
 */
/* ARGSUSED */
static int
smbfs_open(vnode_t **vpp, int flag, cred_t *cr, caller_context_t *ct)
{
	smbnode_t	*np;
	vnode_t		*vp;
	smbfattr_t	fa;
	u_int32_t	rights, rightsrcvd;
	u_int16_t	fid, oldfid;
	int		oldgenid;
	struct smb_cred scred;
	smbmntinfo_t	*smi;
	smb_share_t	*ssp;
	cred_t		*oldcr;
	int		tmperror;
	int		error = 0;

	vp = *vpp;
	np = VTOSMB(vp);
	smi = VTOSMI(vp);
	ssp = smi->smi_share;

	if (curproc->p_zone != smi->smi_zone_ref.zref_zone)
		return (EIO);

	if (smi->smi_flags & SMI_DEAD || vp->v_vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	if (vp->v_type != VREG && vp->v_type != VDIR) { /* XXX VLNK? */
		SMBVDEBUG("open eacces vtype=%d\n", vp->v_type);
		return (EACCES);
	}

	/*
	 * Get exclusive access to n_fid and related stuff.
	 * No returns after this until out.
	 */
	if (smbfs_rw_enter_sig(&np->r_lkserlock, RW_WRITER, SMBINTR(vp)))
		return (EINTR);
	smb_credinit(&scred, cr);

	/*
	 * Keep track of the vnode type at first open.
	 * It may change later, and we need close to do
	 * cleanup for the type we opened.  Also deny
	 * open of new types until old type is closed.
	 */
	if (np->n_ovtype == VNON) {
		ASSERT(np->n_dirrefs == 0);
		ASSERT(np->n_fidrefs == 0);
	} else if (np->n_ovtype != vp->v_type) {
		SMBVDEBUG("open n_ovtype=%d v_type=%d\n",
		    np->n_ovtype, vp->v_type);
		error = EACCES;
		goto out;
	}

	/*
	 * Directory open.  See smbfs_readvdir()
	 */
	if (vp->v_type == VDIR) {
		if (np->n_dirseq == NULL) {
			/* first open */
			error = smbfs_smb_findopen(np, "*", 1,
			    SMB_FA_SYSTEM | SMB_FA_HIDDEN | SMB_FA_DIR,
			    &scred, &np->n_dirseq);
			if (error != 0)
				goto out;
		}
		np->n_dirofs = FIRST_DIROFS;
		np->n_dirrefs++;
		goto have_fid;
	}

	/*
	 * If caller specified O_TRUNC/FTRUNC, then be sure to set
	 * FWRITE (to drive successful setattr(size=0) after open)
	 */
	if (flag & FTRUNC)
		flag |= FWRITE;

	/*
	 * If we already have it open, and the FID is still valid,
	 * check whether the rights are sufficient for FID reuse.
	 */
	if (np->n_fidrefs > 0 &&
	    np->n_vcgenid == ssp->ss_vcgenid) {
		int upgrade = 0;

		if ((flag & FWRITE) &&
		    !(np->n_rights & SA_RIGHT_FILE_WRITE_DATA))
			upgrade = 1;
		if ((flag & FREAD) &&
		    !(np->n_rights & SA_RIGHT_FILE_READ_DATA))
			upgrade = 1;
		if (!upgrade) {
			/*
			 *  the existing open is good enough
			 */
			np->n_fidrefs++;
			goto have_fid;
		}
	}
	rights = np->n_fidrefs ? np->n_rights : 0;

	/*
	 * we always ask for READ_CONTROL so we can always get the
	 * owner/group IDs to satisfy a stat.  Ditto attributes.
	 */
	rights |= (STD_RIGHT_READ_CONTROL_ACCESS |
	    SA_RIGHT_FILE_READ_ATTRIBUTES);
	if ((flag & FREAD))
		rights |= SA_RIGHT_FILE_READ_DATA;
	if ((flag & FWRITE))
		rights |= SA_RIGHT_FILE_WRITE_DATA |
		    SA_RIGHT_FILE_APPEND_DATA |
		    SA_RIGHT_FILE_WRITE_ATTRIBUTES;

	bzero(&fa, sizeof (fa));
	error = smbfs_smb_open(np,
	    NULL, 0, 0, /* name nmlen xattr */
	    rights, &scred,
	    &fid, &rightsrcvd, &fa);
	if (error)
		goto out;
	smbfs_attrcache_fa(vp, &fa);

	/*
	 * We have a new FID and access rights.
	 */
	oldfid = np->n_fid;
	oldgenid = np->n_vcgenid;
	np->n_fid = fid;
	np->n_vcgenid = ssp->ss_vcgenid;
	np->n_rights = rightsrcvd;
	np->n_fidrefs++;
	if (np->n_fidrefs > 1 &&
	    oldgenid == ssp->ss_vcgenid) {
		/*
		 * We already had it open (presumably because
		 * it was open with insufficient rights.)
		 * Close old wire-open.
		 */
		tmperror = smbfs_smb_close(ssp,
		    oldfid, NULL, &scred);
		if (tmperror)
			SMBVDEBUG("error %d closing %s\n",
			    tmperror, np->n_rpath);
	}

	/*
	 * This thread did the open.
	 * Save our credentials too.
	 */
	mutex_enter(&np->r_statelock);
	oldcr = np->r_cred;
	np->r_cred = cr;
	crhold(cr);
	if (oldcr)
		crfree(oldcr);
	mutex_exit(&np->r_statelock);

have_fid:
	/*
	 * Keep track of the vnode type at first open.
	 * (see comments above)
	 */
	if (np->n_ovtype == VNON)
		np->n_ovtype = vp->v_type;

out:
	smb_credrele(&scred);
	smbfs_rw_exit(&np->r_lkserlock);
	return (error);
}

/*ARGSUSED*/
static int
smbfs_close(vnode_t *vp, int flag, int count, offset_t offset, cred_t *cr,
	caller_context_t *ct)
{
	smbnode_t	*np;
	smbmntinfo_t	*smi;
	struct smb_cred scred;
	int error = 0;

	np = VTOSMB(vp);
	smi = VTOSMI(vp);

	/*
	 * Don't "bail out" for VFS_UNMOUNTED here,
	 * as we want to do cleanup, etc.
	 */

	/*
	 * zone_enter(2) prevents processes from changing zones with SMBFS files
	 * open; if we happen to get here from the wrong zone we can't do
	 * anything over the wire.
	 */
	if (smi->smi_zone_ref.zref_zone != curproc->p_zone) {
		/*
		 * We could attempt to clean up locks, except we're sure
		 * that the current process didn't acquire any locks on
		 * the file: any attempt to lock a file belong to another zone
		 * will fail, and one can't lock an SMBFS file and then change
		 * zones, as that fails too.
		 *
		 * Returning an error here is the sane thing to do.  A
		 * subsequent call to VN_RELE() which translates to a
		 * smbfs_inactive() will clean up state: if the zone of the
		 * vnode's origin is still alive and kicking, an async worker
		 * thread will handle the request (from the correct zone), and
		 * everything (minus the final smbfs_getattr_otw() call) should
		 * be OK. If the zone is going away smbfs_async_inactive() will
		 * throw away cached pages inline.
		 */
		return (EIO);
	}

	/*
	 * If we are using local locking for this filesystem, then
	 * release all of the SYSV style record locks.  Otherwise,
	 * we are doing network locking and we need to release all
	 * of the network locks.  All of the locks held by this
	 * process on this file are released no matter what the
	 * incoming reference count is.
	 */
	if (smi->smi_flags & SMI_LLOCK) {
		pid_t pid = ddi_get_pid();
		cleanlocks(vp, pid, 0);
		cleanshares(vp, pid);
	}
	/*
	 * else doing OtW locking.  SMB servers drop all locks
	 * on the file ID we close here, so no _lockrelease()
	 */

	/*
	 * This (passed in) count is the ref. count from the
	 * user's file_t before the closef call (fio.c).
	 * The rest happens only on last close.
	 */
	if (count > 1)
		return (0);

	/* NFS has DNLC purge here. */

	/*
	 * If the file was open for write and there are pages,
	 * then make sure dirty pages written back.
	 *
	 * NFS does this async when "close-to-open" is off
	 * (MI_NOCTO flag is set) to avoid blocking the caller.
	 * For now, always do this synchronously (no B_ASYNC).
	 */
	if ((flag & FWRITE) && vn_has_cached_data(vp)) {
		error = smbfs_putpage(vp, (offset_t)0, 0, 0, cr, ct);
		if (error == EAGAIN)
			error = 0;
	}
	if (error == 0) {
		mutex_enter(&np->r_statelock);
		np->r_flags &= ~RSTALE;
		np->r_error = 0;
		mutex_exit(&np->r_statelock);
	}

	/*
	 * Decrement the reference count for the FID
	 * and possibly do the OtW close.
	 *
	 * Exclusive lock for modifying n_fid stuff.
	 * Don't want this one ever interruptible.
	 */
	(void) smbfs_rw_enter_sig(&np->r_lkserlock, RW_WRITER, 0);
	smb_credinit(&scred, cr);

	smbfs_rele_fid(np, &scred);

	smb_credrele(&scred);
	smbfs_rw_exit(&np->r_lkserlock);

	return (0);
}

/*
 * Helper for smbfs_close.  Decrement the reference count
 * for an SMB-level file or directory ID, and when the last
 * reference for the fid goes away, do the OtW close.
 * Also called in smbfs_inactive (defensive cleanup).
 */
static void
smbfs_rele_fid(smbnode_t *np, struct smb_cred *scred)
{
	smb_share_t	*ssp;
	cred_t		*oldcr;
	struct smbfs_fctx *fctx;
	int		error;
	uint16_t ofid;

	ssp = np->n_mount->smi_share;
	error = 0;

	/* Make sure we serialize for n_dirseq use. */
	ASSERT(smbfs_rw_lock_held(&np->r_lkserlock, RW_WRITER));

	/*
	 * Note that vp->v_type may change if a remote node
	 * is deleted and recreated as a different type, and
	 * our getattr may change v_type accordingly.
	 * Now use n_ovtype to keep track of the v_type
	 * we had during open (see comments above).
	 */
	switch (np->n_ovtype) {
	case VDIR:
		ASSERT(np->n_dirrefs > 0);
		if (--np->n_dirrefs)
			return;
		if ((fctx = np->n_dirseq) != NULL) {
			np->n_dirseq = NULL;
			np->n_dirofs = 0;
			error = smbfs_smb_findclose(fctx, scred);
		}
		break;

	case VREG:
		ASSERT(np->n_fidrefs > 0);
		if (--np->n_fidrefs)
			return;
		if ((ofid = np->n_fid) != SMB_FID_UNUSED) {
			np->n_fid = SMB_FID_UNUSED;
			/* After reconnect, n_fid is invalid */
			if (np->n_vcgenid == ssp->ss_vcgenid) {
				error = smbfs_smb_close(
				    ssp, ofid, NULL, scred);
			}
		}
		break;

	default:
		SMBVDEBUG("bad n_ovtype %d\n", np->n_ovtype);
		break;
	}
	if (error) {
		SMBVDEBUG("error %d closing %s\n",
		    error, np->n_rpath);
	}

	/* Allow next open to use any v_type. */
	np->n_ovtype = VNON;

	/*
	 * Other "last close" stuff.
	 */
	mutex_enter(&np->r_statelock);
	if (np->n_flag & NATTRCHANGED)
		smbfs_attrcache_rm_locked(np);
	oldcr = np->r_cred;
	np->r_cred = NULL;
	mutex_exit(&np->r_statelock);
	if (oldcr != NULL)
		crfree(oldcr);
}

/* ARGSUSED */
static int
smbfs_read(vnode_t *vp, struct uio *uiop, int ioflag, cred_t *cr,
	caller_context_t *ct)
{
	struct smb_cred scred;
	struct vattr	va;
	smbnode_t	*np;
	smbmntinfo_t	*smi;
	smb_share_t	*ssp;
	offset_t	endoff;
	ssize_t		past_eof;
	int		error;

	caddr_t		base;
	u_offset_t	off;
	size_t		n;
	int		on;
	uint_t		flags;

	np = VTOSMB(vp);
	smi = VTOSMI(vp);
	ssp = smi->smi_share;

	if (curproc->p_zone != smi->smi_zone_ref.zref_zone)
		return (EIO);

	if (smi->smi_flags & SMI_DEAD || vp->v_vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	ASSERT(smbfs_rw_lock_held(&np->r_rwlock, RW_READER));

	if (vp->v_type != VREG)
		return (EISDIR);

	if (uiop->uio_resid == 0)
		return (0);

	/*
	 * Like NFS3, just check for 63-bit overflow.
	 * Our SMB layer takes care to return EFBIG
	 * when it has to fallback to a 32-bit call.
	 */
	endoff = uiop->uio_loffset + uiop->uio_resid;
	if (uiop->uio_loffset < 0 || endoff < 0)
		return (EINVAL);

	/* get vnode attributes from server */
	va.va_mask = AT_SIZE | AT_MTIME;
	if (error = smbfsgetattr(vp, &va, cr))
		return (error);

	/* Update mtime with mtime from server here? */

	/* if offset is beyond EOF, read nothing */
	if (uiop->uio_loffset >= va.va_size)
		return (0);

	/*
	 * Limit the read to the remaining file size.
	 * Do this by temporarily reducing uio_resid
	 * by the amount the lies beyoned the EOF.
	 */
	if (endoff > va.va_size) {
		past_eof = (ssize_t)(endoff - va.va_size);
		uiop->uio_resid -= past_eof;
	} else
		past_eof = 0;

	/*
	 * Bypass VM if caching has been disabled (e.g., locking) or if
	 * using client-side direct I/O and the file is not mmap'd and
	 * there are no cached pages.
	 */
	if ((vp->v_flag & VNOCACHE) ||
	    (((np->r_flags & RDIRECTIO) || (smi->smi_flags & SMI_DIRECTIO)) &&
	    np->r_mapcnt == 0 && np->r_inmap == 0 &&
	    !vn_has_cached_data(vp))) {

		/* Shared lock for n_fid use in smb_rwuio */
		if (smbfs_rw_enter_sig(&np->r_lkserlock, RW_READER, SMBINTR(vp)))
			return (EINTR);
		smb_credinit(&scred, cr);

		/* After reconnect, n_fid is invalid */
		if (np->n_vcgenid != ssp->ss_vcgenid)
			error = ESTALE;
		else
			error = smb_rwuio(ssp, np->n_fid, UIO_READ,
			    uiop, &scred, smb_timo_read);

		smb_credrele(&scred);
		smbfs_rw_exit(&np->r_lkserlock);

		/* undo adjustment of resid */
		uiop->uio_resid += past_eof;

		return (error);
	}

	/* (else) Do I/O through segmap. */
	do {
		off = uiop->uio_loffset & MAXBMASK; /* mapping offset */
		on = uiop->uio_loffset & MAXBOFFSET; /* Relative offset */
		n = MIN(MAXBSIZE - on, uiop->uio_resid);

		error = smbfs_validate_caches(vp, cr);
		if (error)
			break;

		/* NFS waits for RINCACHEPURGE here. */

		if (vpm_enable) {
			/*
			 * Copy data.
			 */
			error = vpm_data_copy(vp, off + on, n, uiop,
			    1, NULL, 0, S_READ);
		} else {
			base = segmap_getmapflt(segkmap, vp, off + on, n, 1,
			    S_READ);

			error = uiomove(base + on, n, UIO_READ, uiop);
		}

		if (!error) {
			/*
			 * If read a whole block or read to eof,
			 * won't need this buffer again soon.
			 */
			mutex_enter(&np->r_statelock);
			if (n + on == MAXBSIZE ||
			    uiop->uio_loffset == np->r_size)
				flags = SM_DONTNEED;
			else
				flags = 0;
			mutex_exit(&np->r_statelock);
			if (vpm_enable) {
				error = vpm_sync_pages(vp, off, n, flags);
			} else {
				error = segmap_release(segkmap, base, flags);
			}
		} else {
			if (vpm_enable) {
				(void) vpm_sync_pages(vp, off, n, 0);
			} else {
				(void) segmap_release(segkmap, base, 0);
			}
		}
	} while (!error && uiop->uio_resid > 0);

	/* undo adjustment of resid */
	uiop->uio_resid += past_eof;

	return (error);
}


/* ARGSUSED */
static int
smbfs_write(vnode_t *vp, struct uio *uiop, int ioflag, cred_t *cr,
	caller_context_t *ct)
{
	struct smb_cred scred;
	struct vattr    va;
	smbnode_t	*np;
	smbmntinfo_t	*smi;
	smb_share_t	*ssp;
	offset_t	endoff, limit;
	ssize_t		past_limit;
	int		error, timo;
	caddr_t		base;
	u_offset_t	off;
	size_t		n;
	int		on;
	uint_t		flags;
	u_offset_t	last_off;
	size_t		last_resid;
	uint_t		bsize;

	np = VTOSMB(vp);
	smi = VTOSMI(vp);
	ssp = smi->smi_share;

	if (curproc->p_zone != smi->smi_zone_ref.zref_zone)
		return (EIO);

	if (smi->smi_flags & SMI_DEAD || vp->v_vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	ASSERT(smbfs_rw_lock_held(&np->r_rwlock, RW_WRITER));

	if (vp->v_type != VREG)
		return (EISDIR);

	if (uiop->uio_resid == 0)
		return (0);

	/*
	 * Handle ioflag bits: (FAPPEND|FSYNC|FDSYNC)
	 */
	if (ioflag & (FAPPEND | FSYNC)) {
		if (np->n_flag & NMODIFIED) {
			smbfs_attrcache_remove(np);
		}
	}
	if (ioflag & FAPPEND) {
		/*
		 * File size can be changed by another client
		 *
		 * Todo: Consider redesigning this to use a
		 * handle opened for append instead.
		 */
		va.va_mask = AT_SIZE;
		if (error = smbfsgetattr(vp, &va, cr))
			return (error);
		uiop->uio_loffset = va.va_size;
	}

	/*
	 * Like NFS3, just check for 63-bit overflow.
	 */
	endoff = uiop->uio_loffset + uiop->uio_resid;
	if (uiop->uio_loffset < 0 || endoff < 0)
		return (EINVAL);

	/*
	 * Check to make sure that the process will not exceed
	 * its limit on file size.  It is okay to write up to
	 * the limit, but not beyond.  Thus, the write which
	 * reaches the limit will be short and the next write
	 * will return an error.
	 *
	 * So if we're starting at or beyond the limit, EFBIG.
	 * Otherwise, temporarily reduce resid to the amount
	 * that is after the limit.
	 */
	limit = uiop->uio_llimit;
	if (limit == RLIM64_INFINITY || limit > MAXOFFSET_T)
		limit = MAXOFFSET_T;
	if (uiop->uio_loffset >= limit) {
		proc_t *p = ttoproc(curthread);

		mutex_enter(&p->p_lock);
		(void) rctl_action(rctlproc_legacy[RLIMIT_FSIZE],
		    p->p_rctls, p, RCA_UNSAFE_SIGINFO);
		mutex_exit(&p->p_lock);
		return (EFBIG);
	}
	if (endoff > limit) {
		past_limit = (ssize_t)(endoff - limit);
		uiop->uio_resid -= past_limit;
	} else
		past_limit = 0;

	/*
	 * Bypass VM if caching has been disabled (e.g., locking) or if
	 * using client-side direct I/O and the file is not mmap'd and
	 * there are no cached pages.
	 */
	if ((vp->v_flag & VNOCACHE) ||
	    (((np->r_flags & RDIRECTIO) || (smi->smi_flags & SMI_DIRECTIO)) &&
	    np->r_mapcnt == 0 && np->r_inmap == 0 &&
	    !vn_has_cached_data(vp))) {

smbfs_fwrite:
		if (np->r_flags & RSTALE) {
			last_resid = uiop->uio_resid;
			last_off = uiop->uio_loffset;
			error = np->r_error;
			/*
			 * A close may have cleared r_error, if so,
			 * propagate ESTALE error return properly
			 */
			if (error == 0)
				error = ESTALE;
			goto bottom;
		}

		/* Timeout: longer for append. */
		timo = smb_timo_write;
		if (endoff > np->r_size)
			timo = smb_timo_append;

		/* Shared lock for n_fid use in smb_rwuio */
		if (smbfs_rw_enter_sig(&np->r_lkserlock, RW_READER, SMBINTR(vp)))
			return (EINTR);
		smb_credinit(&scred, cr);

		/* After reconnect, n_fid is invalid */
		if (np->n_vcgenid != ssp->ss_vcgenid)
			error = ESTALE;
		else
			error = smb_rwuio(ssp, np->n_fid, UIO_WRITE,
			    uiop, &scred, timo);

		if (error == 0) {
			mutex_enter(&np->r_statelock);
			np->n_flag |= (NFLUSHWIRE | NATTRCHANGED);
			if (uiop->uio_loffset > (offset_t)np->r_size)
				np->r_size = (len_t)uiop->uio_loffset;
			mutex_exit(&np->r_statelock);
			if (ioflag & (FSYNC | FDSYNC)) {
				/* Don't error the I/O if this fails. */
				(void) smbfs_smb_flush(np, &scred);
			}
		}

		smb_credrele(&scred);
		smbfs_rw_exit(&np->r_lkserlock);

		/* undo adjustment of resid */
		uiop->uio_resid += past_limit;

		return (error);
	}

	/* (else) Do I/O through segmap. */
	bsize = vp->v_vfsp->vfs_bsize;

	do {
		off = uiop->uio_loffset & MAXBMASK; /* mapping offset */
		on = uiop->uio_loffset & MAXBOFFSET; /* Relative offset */
		n = MIN(MAXBSIZE - on, uiop->uio_resid);

		last_resid = uiop->uio_resid;
		last_off = uiop->uio_loffset;

		if (np->r_flags & RSTALE) {
			error = np->r_error;
			/*
			 * A close may have cleared r_error, if so,
			 * propagate ESTALE error return properly
			 */
			if (error == 0)
				error = ESTALE;
			break;
		}

		/*
		 * From NFS: Don't create dirty pages faster than they
		 * can be cleaned.
		 *
		 * Here NFS also checks for async writes (np->r_awcount)
		 */
		mutex_enter(&np->r_statelock);
		while (np->r_gcount > 0) {
			if (SMBINTR(vp)) {
				klwp_t *lwp = ttolwp(curthread);

				if (lwp != NULL)
					lwp->lwp_nostop++;
				if (!cv_wait_sig(&np->r_cv, &np->r_statelock)) {
					mutex_exit(&np->r_statelock);
					if (lwp != NULL)
						lwp->lwp_nostop--;
					error = EINTR;
					goto bottom;
				}
				if (lwp != NULL)
					lwp->lwp_nostop--;
			} else
				cv_wait(&np->r_cv, &np->r_statelock);
		}
		mutex_exit(&np->r_statelock);

		/*
		 * Touch the page and fault it in if it is not in core
		 * before segmap_getmapflt or vpm_data_copy can lock it.
		 * This is to avoid the deadlock if the buffer is mapped
		 * to the same file through mmap which we want to write.
		 */
		uio_prefaultpages((long)n, uiop);

		if (vpm_enable) {
			/*
			 * It will use kpm mappings, so no need to
			 * pass an address.
			 */
			error = smbfs_writenp(np, NULL, n, uiop, 0);
		} else {
			if (segmap_kpm) {
				int pon = uiop->uio_loffset & PAGEOFFSET;
				size_t pn = MIN(PAGESIZE - pon,
				    uiop->uio_resid);
				int pagecreate;

				mutex_enter(&np->r_statelock);
				pagecreate = (pon == 0) && (pn == PAGESIZE ||
				    uiop->uio_loffset + pn >= np->r_size);
				mutex_exit(&np->r_statelock);

				base = segmap_getmapflt(segkmap, vp, off + on,
				    pn, !pagecreate, S_WRITE);

				error = smbfs_writenp(np, base + pon, n, uiop,
				    pagecreate);

			} else {
				base = segmap_getmapflt(segkmap, vp, off + on,
				    n, 0, S_READ);
				error = smbfs_writenp(np, base + on, n, uiop, 0);
			}
		}

		if (!error) {
			if (smi->smi_flags & SMI_NOAC)
				flags = SM_WRITE;
			else if ((uiop->uio_loffset % bsize) == 0 ||
			    IS_SWAPVP(vp)) {
				/*
				 * Have written a whole block.
				 * Start an asynchronous write
				 * and mark the buffer to
				 * indicate that it won't be
				 * needed again soon.
				 */
				flags = SM_WRITE | SM_ASYNC | SM_DONTNEED;
			} else
				flags = 0;
			if ((ioflag & (FSYNC|FDSYNC)) ||
			    (np->r_flags & ROUTOFSPACE)) {
				flags &= ~SM_ASYNC;
				flags |= SM_WRITE;
			}
			if (vpm_enable) {
				error = vpm_sync_pages(vp, off, n, flags);
			} else {
				error = segmap_release(segkmap, base, flags);
			}
		} else {
			if (vpm_enable) {
				(void) vpm_sync_pages(vp, off, n, 0);
			} else {
				(void) segmap_release(segkmap, base, 0);
			}
			/*
			 * In the event that we got an access error while
			 * faulting in a page for a write-only file just
			 * force a write.
			 */
			if (error == EACCES)
				goto smbfs_fwrite;
		}
	} while (!error && uiop->uio_resid > 0);

bottom:
	/* undo adjustment of resid */
	if (error) {
		uiop->uio_resid = last_resid + past_limit;
		uiop->uio_loffset = last_off;
	} else {
		uiop->uio_resid += past_limit;
	}

	return (error);
}

/*
 * Like nfs_client.c: writerp()
 *
 * Write by creating pages and uiomove data onto them.
 */

int
smbfs_writenp(smbnode_t *np, caddr_t base, int tcount, struct uio *uio,
    int pgcreated)
{
	int		pagecreate;
	int		n;
	int		saved_n;
	caddr_t		saved_base;
	u_offset_t	offset;
	int		error;
	int		sm_error;
	vnode_t		*vp = SMBTOV(np);

	ASSERT(tcount <= MAXBSIZE && tcount <= uio->uio_resid);
	ASSERT(smbfs_rw_lock_held(&np->r_rwlock, RW_WRITER));
	if (!vpm_enable) {
		ASSERT(((uintptr_t)base & MAXBOFFSET) + tcount <= MAXBSIZE);
	}

	/*
	 * Move bytes in at most PAGESIZE chunks. We must avoid
	 * spanning pages in uiomove() because page faults may cause
	 * the cache to be invalidated out from under us. The r_size is not
	 * updated until after the uiomove. If we push the last page of a
	 * file before r_size is correct, we will lose the data written past
	 * the current (and invalid) r_size.
	 */
	do {
		offset = uio->uio_loffset;
		pagecreate = 0;

		/*
		 * n is the number of bytes required to satisfy the request
		 *   or the number of bytes to fill out the page.
		 */
		n = (int)MIN((PAGESIZE - (offset & PAGEOFFSET)), tcount);

		/*
		 * Check to see if we can skip reading in the page
		 * and just allocate the memory.  We can do this
		 * if we are going to rewrite the entire mapping
		 * or if we are going to write to or beyond the current
		 * end of file from the beginning of the mapping.
		 *
		 * The read of r_size is now protected by r_statelock.
		 */
		mutex_enter(&np->r_statelock);
		/*
		 * When pgcreated is nonzero the caller has already done
		 * a segmap_getmapflt with forcefault 0 and S_WRITE. With
		 * segkpm this means we already have at least one page
		 * created and mapped at base.
		 */
		pagecreate = pgcreated ||
		    ((offset & PAGEOFFSET) == 0 &&
		    (n == PAGESIZE || ((offset + n) >= np->r_size)));

		mutex_exit(&np->r_statelock);
		if (!vpm_enable && pagecreate) {
			/*
			 * The last argument tells segmap_pagecreate() to
			 * always lock the page, as opposed to sometimes
			 * returning with the page locked. This way we avoid a
			 * fault on the ensuing uiomove(), but also
			 * more importantly (to fix bug 1094402) we can
			 * call segmap_fault() to unlock the page in all
			 * cases. An alternative would be to modify
			 * segmap_pagecreate() to tell us when it is
			 * locking a page, but that's a fairly major
			 * interface change.
			 */
			if (pgcreated == 0)
				(void) segmap_pagecreate(segkmap, base,
				    (uint_t)n, 1);
			saved_base = base;
			saved_n = n;
		}

		/*
		 * The number of bytes of data in the last page can not
		 * be accurately be determined while page is being
		 * uiomove'd to and the size of the file being updated.
		 * Thus, inform threads which need to know accurately
		 * how much data is in the last page of the file.  They
		 * will not do the i/o immediately, but will arrange for
		 * the i/o to happen later when this modify operation
		 * will have finished.
		 */
		ASSERT(!(np->r_flags & RMODINPROGRESS));
		mutex_enter(&np->r_statelock);
		np->r_flags |= RMODINPROGRESS;
		np->r_modaddr = (offset & MAXBMASK);
		mutex_exit(&np->r_statelock);

		if (vpm_enable) {
			/*
			 * Copy data. If new pages are created, part of
			 * the page that is not written will be initizliazed
			 * with zeros.
			 */
			error = vpm_data_copy(vp, offset, n, uio,
			    !pagecreate, NULL, 0, S_WRITE);
		} else {
			error = uiomove(base, n, UIO_WRITE, uio);
		}

		/*
		 * r_size is the maximum number of
		 * bytes known to be in the file.
		 * Make sure it is at least as high as the
		 * first unwritten byte pointed to by uio_loffset.
		 */
		mutex_enter(&np->r_statelock);
		if (np->r_size < uio->uio_loffset)
			np->r_size = uio->uio_loffset;
		np->r_flags &= ~RMODINPROGRESS;
		np->r_flags |= RDIRTY;
		mutex_exit(&np->r_statelock);

		/* n = # of bytes written */
		n = (int)(uio->uio_loffset - offset);

		if (!vpm_enable) {
			base += n;
		}
		tcount -= n;
		/*
		 * If we created pages w/o initializing them completely,
		 * we need to zero the part that wasn't set up.
		 * This happens on a most EOF write cases and if
		 * we had some sort of error during the uiomove.
		 */
		if (!vpm_enable && pagecreate) {
			if ((uio->uio_loffset & PAGEOFFSET) || n == 0)
				(void) kzero(base, PAGESIZE - n);

			if (pgcreated) {
				/*
				 * Caller is responsible for this page,
				 * it was not created in this loop.
				 */
				pgcreated = 0;
			} else {
				/*
				 * For bug 1094402: segmap_pagecreate locks
				 * page. Unlock it. This also unlocks the
				 * pages allocated by page_create_va() in
				 * segmap_pagecreate().
				 */
				sm_error = segmap_fault(kas.a_hat, segkmap,
				    saved_base, saved_n,
				    F_SOFTUNLOCK, S_WRITE);
				if (error == 0)
					error = sm_error;
			}
		}
	} while (tcount > 0 && error == 0);

	return (error);
}

/*
 * Flags are composed of {B_ASYNC, B_INVAL, B_FREE, B_DONTNEED}
 * Like nfs3_rdwrlbn()
 */
static int
smbfs_rdwrlbn(vnode_t *vp, page_t *pp, u_offset_t off, size_t len,
	int flags, cred_t *cr)
{
	smbmntinfo_t	*smi = VTOSMI(vp);
	struct buf *bp;
	int error;
	int sync;

	if (curproc->p_zone != smi->smi_zone_ref.zref_zone)
		return (EIO);

	if (smi->smi_flags & SMI_DEAD || vp->v_vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	bp = pageio_setup(pp, len, vp, flags);
	ASSERT(bp != NULL);

	/*
	 * pageio_setup should have set b_addr to 0.  This
	 * is correct since we want to do I/O on a page
	 * boundary.  bp_mapin will use this addr to calculate
	 * an offset, and then set b_addr to the kernel virtual
	 * address it allocated for us.
	 */
	ASSERT(bp->b_un.b_addr == 0);

	bp->b_edev = 0;
	bp->b_dev = 0;
	bp->b_lblkno = lbtodb(off);
	bp->b_file = vp;
	bp->b_offset = (offset_t)off;
	bp_mapin(bp);

	/*
	 * Calculate the desired level of stability to write data.
	 */
	if ((flags & (B_WRITE|B_ASYNC)) == (B_WRITE|B_ASYNC) &&
	    freemem > desfree) {
		sync = 0;
	} else {
		sync = 1;
	}

	error = smbfs_bio(bp, sync, cr);

	bp_mapout(bp);
	pageio_done(bp);

	return (error);
}


/*
 * Corresponds to nfs3_vnopc.c : nfs3_bio(), though the NFS code
 * uses nfs3read()/nfs3write() where we use smb_rwuio().  Also,
 * NFS has this later in the file.  Move it up here closer to
 * the one call site just above.
 */

static int
smbfs_bio(struct buf *bp, int sync, cred_t *cr)
{
	struct iovec aiov[1];
	struct uio  auio;
	struct smb_cred scred;
	smbnode_t *np = VTOSMB(bp->b_vp);
	smbmntinfo_t *smi = np->n_mount;
	smb_share_t *ssp = smi->smi_share;
	offset_t offset;
	offset_t endoff;
	size_t count;
	size_t past_eof;
	int error;

	ASSERT(curproc->p_zone == smi->smi_zone_ref.zref_zone);

	offset = ldbtob(bp->b_lblkno);
	count = bp->b_bcount;
	endoff = offset + count;
	if (offset < 0 || endoff < 0)
		return (EINVAL);

	/*
	 * Limit file I/O to the remaining file size, but see
	 * the notes in smbfs_getpage about SMBFS_EOF.
	 */
	mutex_enter(&np->r_statelock);
	if (offset >= np->r_size) {
		mutex_exit(&np->r_statelock);
		if (bp->b_flags & B_READ) {
			return (SMBFS_EOF);
		} else {
			return (EINVAL);
		}
	}
	if (endoff > np->r_size) {
		past_eof = (size_t)(endoff - np->r_size);
		count -= past_eof;
	} else
		past_eof = 0;
	mutex_exit(&np->r_statelock);
	ASSERT(count > 0);

	/* Caller did bpmapin().  Mapped address is... */
	aiov[0].iov_base = bp->b_un.b_addr;
	aiov[0].iov_len = count;
	auio.uio_iov = aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = offset;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_fmode = 0;
	auio.uio_resid = count;

	/* Shared lock for n_fid use in smb_rwuio */
	if (smbfs_rw_enter_sig(&np->r_lkserlock, RW_READER,
	    smi->smi_flags & SMI_INT))
		return (EINTR);
	smb_credinit(&scred, cr);

	DTRACE_IO1(start, struct buf *, bp);

	if (bp->b_flags & B_READ) {

		/* After reconnect, n_fid is invalid */
		if (np->n_vcgenid != ssp->ss_vcgenid)
			error = ESTALE;
		else
			error = smb_rwuio(ssp, np->n_fid, UIO_READ,
			    &auio, &scred, smb_timo_read);

		/* Like NFS, only set b_error here. */
		bp->b_error = error;
		bp->b_resid = auio.uio_resid;

		if (!error && auio.uio_resid != 0)
			error = EIO;
		if (!error && past_eof != 0) {
			/* Zero the memory beyond EOF. */
			bzero(bp->b_un.b_addr + count, past_eof);
		}
	} else {

		/* After reconnect, n_fid is invalid */
		if (np->n_vcgenid != ssp->ss_vcgenid)
			error = ESTALE;
		else
			error = smb_rwuio(ssp, np->n_fid, UIO_WRITE,
			    &auio, &scred, smb_timo_write);

		/* Like NFS, only set b_error here. */
		bp->b_error = error;
		bp->b_resid = auio.uio_resid;

		if (!error && auio.uio_resid != 0)
			error = EIO;
		if (!error && sync) {
			(void) smbfs_smb_flush(np, &scred);
		}
	}

	/*
	 * This comes from nfs3_commit()
	 */
	if (error != 0) {
		mutex_enter(&np->r_statelock);
		if (error == ESTALE)
			np->r_flags |= RSTALE;
		if (!np->r_error)
			np->r_error = error;
		mutex_exit(&np->r_statelock);
		bp->b_flags |= B_ERROR;
	}

	DTRACE_IO1(done, struct buf *, bp);

	smb_credrele(&scred);
	smbfs_rw_exit(&np->r_lkserlock);

	if (error == ESTALE)
		smbfs_attrcache_remove(np);

	return (error);
}

/*
 * Here NFS has: nfs3write, nfs3read
 * We use smb_rwuio instead.
 */

/* ARGSUSED */
static int
smbfs_ioctl(vnode_t *vp, int cmd, intptr_t arg, int flag,
	cred_t *cr, int *rvalp,	caller_context_t *ct)
{
	int		error;
	smbmntinfo_t	*smi;

	smi = VTOSMI(vp);

	if (curproc->p_zone != smi->smi_zone_ref.zref_zone)
		return (EIO);

	if (smi->smi_flags & SMI_DEAD || vp->v_vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	switch (cmd) {

	case _FIOFFS:
		error = smbfs_fsync(vp, 0, cr, ct);
		break;

		/*
		 * The following two ioctls are used by bfu.
		 * Silently ignore to avoid bfu errors.
		 */
	case _FIOGDIO:
	case _FIOSDIO:
		error = 0;
		break;

#if 0	/* Todo - SMB ioctl query regions */
	case _FIO_SEEK_DATA:
	case _FIO_SEEK_HOLE:
#endif

	case _FIODIRECTIO:
		error = smbfs_directio(vp, (int)arg, cr);
		break;

		/*
		 * Allow get/set with "raw" security descriptor (SD) data.
		 * Useful for testing, diagnosing idmap problems, etc.
		 */
	case SMBFSIO_GETSD:
		error = smbfs_acl_iocget(vp, arg, flag, cr);
		break;

	case SMBFSIO_SETSD:
		error = smbfs_acl_iocset(vp, arg, flag, cr);
		break;

	default:
		error = ENOTTY;
		break;
	}

	return (error);
}


/*
 * Return either cached or remote attributes. If get remote attr
 * use them to check and invalidate caches, then cache the new attributes.
 */
/* ARGSUSED */
static int
smbfs_getattr(vnode_t *vp, struct vattr *vap, int flags, cred_t *cr,
	caller_context_t *ct)
{
	smbnode_t *np;
	smbmntinfo_t *smi;
	int error;

	smi = VTOSMI(vp);

	if (curproc->p_zone != smi->smi_zone_ref.zref_zone)
		return (EIO);

	if (smi->smi_flags & SMI_DEAD || vp->v_vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	/*
	 * If it has been specified that the return value will
	 * just be used as a hint, and we are only being asked
	 * for size, fsid or rdevid, then return the client's
	 * notion of these values without checking to make sure
	 * that the attribute cache is up to date.
	 * The whole point is to avoid an over the wire GETATTR
	 * call.
	 */
	np = VTOSMB(vp);
	if (flags & ATTR_HINT) {
		if (vap->va_mask ==
		    (vap->va_mask & (AT_SIZE | AT_FSID | AT_RDEV))) {
			mutex_enter(&np->r_statelock);
			if (vap->va_mask | AT_SIZE)
				vap->va_size = np->r_size;
			if (vap->va_mask | AT_FSID)
				vap->va_fsid = vp->v_vfsp->vfs_dev;
			if (vap->va_mask | AT_RDEV)
				vap->va_rdev = vp->v_rdev;
			mutex_exit(&np->r_statelock);
			return (0);
		}
	}

	/*
	 * Only need to flush pages if asking for the mtime
	 * and if there any dirty pages.
	 *
	 * Here NFS also checks for async writes (np->r_awcount)
	 */
	if (vap->va_mask & AT_MTIME) {
		if (vn_has_cached_data(vp) &&
		    ((np->r_flags & RDIRTY) != 0)) {
			mutex_enter(&np->r_statelock);
			np->r_gcount++;
			mutex_exit(&np->r_statelock);
			error = smbfs_putpage(vp, (offset_t)0, 0, 0, cr, ct);
			mutex_enter(&np->r_statelock);
			if (error && (error == ENOSPC || error == EDQUOT)) {
				if (!np->r_error)
					np->r_error = error;
			}
			if (--np->r_gcount == 0)
				cv_broadcast(&np->r_cv);
			mutex_exit(&np->r_statelock);
		}
	}

	return (smbfsgetattr(vp, vap, cr));
}

/* smbfsgetattr() in smbfs_client.c */

/*ARGSUSED4*/
static int
smbfs_setattr(vnode_t *vp, struct vattr *vap, int flags, cred_t *cr,
		caller_context_t *ct)
{
	vfs_t		*vfsp;
	smbmntinfo_t	*smi;
	int		error;
	uint_t		mask;
	struct vattr	oldva;

	vfsp = vp->v_vfsp;
	smi = VFTOSMI(vfsp);

	if (curproc->p_zone != smi->smi_zone_ref.zref_zone)
		return (EIO);

	if (smi->smi_flags & SMI_DEAD || vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	mask = vap->va_mask;
	if (mask & AT_NOSET)
		return (EINVAL);

	if (vfsp->vfs_flag & VFS_RDONLY)
		return (EROFS);

	/*
	 * This is a _local_ access check so that only the owner of
	 * this mount can set attributes.  With ACLs enabled, the
	 * file owner can be different from the mount owner, and we
	 * need to check the _mount_ owner here.  See _access_rwx
	 */
	bzero(&oldva, sizeof (oldva));
	oldva.va_mask = AT_TYPE | AT_MODE;
	error = smbfsgetattr(vp, &oldva, cr);
	if (error)
		return (error);
	oldva.va_mask |= AT_UID | AT_GID;
	oldva.va_uid = smi->smi_uid;
	oldva.va_gid = smi->smi_gid;

	error = secpolicy_vnode_setattr(cr, vp, vap, &oldva, flags,
	    smbfs_accessx, vp);
	if (error)
		return (error);

	if (mask & (AT_UID | AT_GID)) {
		if (smi->smi_flags & SMI_ACL)
			error = smbfs_acl_setids(vp, vap, cr);
		else
			error = ENOSYS;
		if (error != 0) {
			SMBVDEBUG("error %d seting UID/GID on %s",
			    error, VTOSMB(vp)->n_rpath);
			/*
			 * It might be more correct to return the
			 * error here, but that causes complaints
			 * when root extracts a cpio archive, etc.
			 * So ignore this error, and go ahead with
			 * the rest of the setattr work.
			 */
		}
	}

	error = smbfssetattr(vp, vap, flags, cr);

#ifdef	SMBFS_VNEVENT
	if (error == 0 && (vap->va_mask & AT_SIZE) && vap->va_size == 0)
		vnevent_truncate(vp, ct);
#endif

	return (error);
}

/*
 * Mostly from Darwin smbfs_setattr()
 * but then modified a lot.
 */
/* ARGSUSED */
static int
smbfssetattr(vnode_t *vp, struct vattr *vap, int flags, cred_t *cr)
{
	int		error = 0;
	smbnode_t	*np = VTOSMB(vp);
	uint_t		mask = vap->va_mask;
	struct timespec	*mtime, *atime;
	struct smb_cred	scred;
	int		cerror, modified = 0;
	unsigned short	fid;
	int have_fid = 0;
	uint32_t rights = 0;
	uint32_t dosattr = 0;

	ASSERT(curproc->p_zone == VTOSMI(vp)->smi_zone_ref.zref_zone);

	/*
	 * There are no settable attributes on the XATTR dir,
	 * so just silently ignore these.  On XATTR files,
	 * you can set the size but nothing else.
	 */
	if (vp->v_flag & V_XATTRDIR)
		return (0);
	if (np->n_flag & N_XATTR) {
		if (mask & AT_TIMES)
			SMBVDEBUG("ignore set time on xattr\n");
		mask &= AT_SIZE;
	}

	/*
	 * Only need to flush pages if there are any pages and
	 * if the file is marked as dirty in some fashion.  The
	 * file must be flushed so that we can accurately
	 * determine the size of the file and the cached data
	 * after the SETATTR returns.  A file is considered to
	 * be dirty if it is either marked with RDIRTY, has
	 * outstanding i/o's active, or is mmap'd.  In this
	 * last case, we can't tell whether there are dirty
	 * pages, so we flush just to be sure.
	 */
	if (vn_has_cached_data(vp) &&
	    ((np->r_flags & RDIRTY) ||
	    np->r_count > 0 ||
	    np->r_mapcnt > 0)) {
		ASSERT(vp->v_type != VCHR);
		error = smbfs_putpage(vp, (offset_t)0, 0, 0, cr, NULL);
		if (error && (error == ENOSPC || error == EDQUOT)) {
			mutex_enter(&np->r_statelock);
			if (!np->r_error)
				np->r_error = error;
			mutex_exit(&np->r_statelock);
		}
	}

	/*
	 * If our caller is trying to set multiple attributes, they
	 * can make no assumption about what order they are done in.
	 * Here we try to do them in order of decreasing likelihood
	 * of failure, just to minimize the chance we'll wind up
	 * with a partially complete request.
	 */

	/* Shared lock for (possible) n_fid use. */
	if (smbfs_rw_enter_sig(&np->r_lkserlock, RW_READER, SMBINTR(vp)))
		return (EINTR);
	smb_credinit(&scred, cr);

	/*
	 * If the caller has provided extensible attributes,
	 * map those into DOS attributes supported by SMB.
	 * Note: zero means "no change".
	 */
	if (mask & AT_XVATTR)
		dosattr = xvattr_to_dosattr(np, vap);

	/*
	 * Will we need an open handle for this setattr?
	 * If so, what rights will we need?
	 */
	if (dosattr || (mask & (AT_ATIME | AT_MTIME))) {
		rights |=
		    SA_RIGHT_FILE_WRITE_ATTRIBUTES;
	}
	if (mask & AT_SIZE) {
		rights |=
		    SA_RIGHT_FILE_WRITE_DATA |
		    SA_RIGHT_FILE_APPEND_DATA;
	}

	/*
	 * Only SIZE really requires a handle, but it's
	 * simpler and more reliable to set via a handle.
	 * Some servers like NT4 won't set times by path.
	 * Also, we're usually setting everything anyway.
	 */
	if (rights != 0) {
		error = smbfs_smb_tmpopen(np, rights, &scred, &fid);
		if (error) {
			SMBVDEBUG("error %d opening %s\n",
			    error, np->n_rpath);
			goto out;
		}
		have_fid = 1;
	}

	/*
	 * If the server supports the UNIX extensions, right here is where
	 * we'd support changes to uid, gid, mode, and possibly va_flags.
	 * For now we claim to have made any such changes.
	 */

	if (mask & AT_SIZE) {
		/*
		 * If the new file size is less than what the client sees as
		 * the file size, then just change the size and invalidate
		 * the pages.
		 */

		/*
		 * Set the file size to vap->va_size.
		 */
		ASSERT(have_fid);
		error = smbfs_smb_setfsize(np, fid, vap->va_size, &scred);
		if (error) {
			SMBVDEBUG("setsize error %d file %s\n",
			    error, np->n_rpath);
		} else {
			/*
			 * Darwin had code here to zero-extend.
			 * Tests indicate the server will zero-fill,
			 * so looks like we don't need to do that.
			 */
			mutex_enter(&np->r_statelock);
			np->r_size = vap->va_size;
			mutex_exit(&np->r_statelock);
			modified = 1;
		}
	}

	/*
	 * Todo: Implement setting create_time (which is
	 * different from ctime).
	 */
	mtime = ((mask & AT_MTIME) ? &vap->va_mtime : 0);
	atime = ((mask & AT_ATIME) ? &vap->va_atime : 0);

	if (dosattr || mtime || atime) {
		/*
		 * Always use the handle-based set attr call now.
		 */
		ASSERT(have_fid);
		error = smbfs_smb_setfattr(np, fid,
		    dosattr, mtime, atime, &scred);
		if (error) {
			SMBVDEBUG("set times error %d file %s\n",
			    error, np->n_rpath);
		} else {
			modified = 1;
		}
	}

out:
	if (have_fid) {
		cerror = smbfs_smb_tmpclose(np, fid, &scred);
		if (cerror)
			SMBVDEBUG("error %d closing %s\n",
			    cerror, np->n_rpath);
	}

	smb_credrele(&scred);
	smbfs_rw_exit(&np->r_lkserlock);

	if (modified) {
		/*
		 * Invalidate attribute cache in case the server
		 * doesn't set exactly the attributes we asked.
		 */
		smbfs_attrcache_remove(np);

		/*
		 * If changing the size of the file, invalidate
		 * any local cached data which is no longer part
		 * of the file.  We also possibly invalidate the
		 * last page in the file.  We could use
		 * pvn_vpzero(), but this would mark the page as
		 * modified and require it to be written back to
		 * the server for no particularly good reason.
		 * This way, if we access it, then we bring it
		 * back in.  A read should be cheaper than a
		 * write.
		 */
		if (mask & AT_SIZE) {
			smbfs_invalidate_pages(vp,
			    (vap->va_size & PAGEMASK), cr);
		}
	}

	return (error);
}

/*
 * Helper function for extensible system attributes (PSARC 2007/315)
 * Compute the DOS attribute word to pass to _setfattr (see above).
 * This returns zero IFF no change is being made to attributes.
 * Otherwise return the new attributes or SMB_EFA_NORMAL.
 */
static uint32_t
xvattr_to_dosattr(smbnode_t *np, struct vattr *vap)
{
	xvattr_t *xvap = (xvattr_t *)vap;
	xoptattr_t *xoap = NULL;
	uint32_t attr = np->r_attr.fa_attr;
	boolean_t anyset = B_FALSE;

	if ((xoap = xva_getxoptattr(xvap)) == NULL)
		return (0);

	if (XVA_ISSET_REQ(xvap, XAT_ARCHIVE)) {
		if (xoap->xoa_archive)
			attr |= SMB_FA_ARCHIVE;
		else
			attr &= ~SMB_FA_ARCHIVE;
		XVA_SET_RTN(xvap, XAT_ARCHIVE);
		anyset = B_TRUE;
	}
	if (XVA_ISSET_REQ(xvap, XAT_SYSTEM)) {
		if (xoap->xoa_system)
			attr |= SMB_FA_SYSTEM;
		else
			attr &= ~SMB_FA_SYSTEM;
		XVA_SET_RTN(xvap, XAT_SYSTEM);
		anyset = B_TRUE;
	}
	if (XVA_ISSET_REQ(xvap, XAT_READONLY)) {
		if (xoap->xoa_readonly)
			attr |= SMB_FA_RDONLY;
		else
			attr &= ~SMB_FA_RDONLY;
		XVA_SET_RTN(xvap, XAT_READONLY);
		anyset = B_TRUE;
	}
	if (XVA_ISSET_REQ(xvap, XAT_HIDDEN)) {
		if (xoap->xoa_hidden)
			attr |= SMB_FA_HIDDEN;
		else
			attr &= ~SMB_FA_HIDDEN;
		XVA_SET_RTN(xvap, XAT_HIDDEN);
		anyset = B_TRUE;
	}

	if (anyset == B_FALSE)
		return (0);	/* no change */
	if (attr == 0)
		attr = SMB_EFA_NORMAL;

	return (attr);
}

/*
 * smbfs_access_rwx()
 * Common function for smbfs_access, etc.
 *
 * The security model implemented by the FS is unusual
 * due to the current "single user mounts" restriction:
 * All access under a given mount point uses the CIFS
 * credentials established by the owner of the mount.
 *
 * Most access checking is handled by the CIFS server,
 * but we need sufficient Unix access checks here to
 * prevent other local Unix users from having access
 * to objects under this mount that the uid/gid/mode
 * settings in the mount would not allow.
 *
 * With this model, there is a case where we need the
 * ability to do an access check before we have the
 * vnode for an object.  This function takes advantage
 * of the fact that the uid/gid/mode is per mount, and
 * avoids the need for a vnode.
 *
 * We still (sort of) need a vnode when we call
 * secpolicy_vnode_access, but that only uses
 * the vtype field, so we can use a pair of fake
 * vnodes that have only v_type filled in.
 */
static int
smbfs_access_rwx(vfs_t *vfsp, int vtype, int mode, cred_t *cr)
{
	/* See the secpolicy call below. */
	static const vnode_t tmpl_vdir = { .v_type = VDIR };
	static const vnode_t tmpl_vreg = { .v_type = VREG };
	vattr_t		va;
	vnode_t		*tvp;
	struct smbmntinfo *smi = VFTOSMI(vfsp);
	int shift = 0;

	/*
	 * Build our (fabricated) vnode attributes.
	 */
	bzero(&va, sizeof (va));
	va.va_mask = AT_TYPE | AT_MODE | AT_UID | AT_GID;
	va.va_type = vtype;
	va.va_mode = (vtype == VDIR) ?
	    smi->smi_dmode : smi->smi_fmode;
	va.va_uid = smi->smi_uid;
	va.va_gid = smi->smi_gid;

	/*
	 * Disallow write attempts on read-only file systems,
	 * unless the file is a device or fifo node.  Note:
	 * Inline vn_is_readonly and IS_DEVVP here because
	 * we may not have a vnode ptr.  Original expr. was:
	 * (mode & VWRITE) && vn_is_readonly(vp) && !IS_DEVVP(vp))
	 */
	if ((mode & VWRITE) &&
	    (vfsp->vfs_flag & VFS_RDONLY) &&
	    !(vtype == VCHR || vtype == VBLK || vtype == VFIFO))
		return (EROFS);

	/*
	 * Disallow attempts to access mandatory lock files.
	 * Similarly, expand MANDLOCK here.
	 */
	if ((mode & (VWRITE | VREAD | VEXEC)) &&
	    va.va_type == VREG && MANDMODE(va.va_mode))
		return (EACCES);

	/*
	 * Access check is based on only
	 * one of owner, group, public.
	 * If not owner, then check group.
	 * If not a member of the group,
	 * then check public access.
	 */
	if (crgetuid(cr) != va.va_uid) {
		shift += 3;
		if (!groupmember(va.va_gid, cr))
			shift += 3;
	}

	/*
	 * We need a vnode for secpolicy_vnode_access,
	 * but the only thing it looks at is v_type,
	 * so pass one of the templates above.
	 */
	tvp = (va.va_type == VDIR) ?
	    (vnode_t *)&tmpl_vdir :
	    (vnode_t *)&tmpl_vreg;

	return (secpolicy_vnode_access2(cr, tvp, va.va_uid,
	    va.va_mode << shift, mode));
}

/*
 * See smbfs_setattr
 */
static int
smbfs_accessx(void *arg, int mode, cred_t *cr)
{
	vnode_t *vp = arg;
	/*
	 * Note: The caller has checked the current zone,
	 * the SMI_DEAD and VFS_UNMOUNTED flags, etc.
	 */
	return (smbfs_access_rwx(vp->v_vfsp, vp->v_type, mode, cr));
}

/*
 * XXX
 * This op should support PSARC 2007/403, Modified Access Checks for CIFS
 */
/* ARGSUSED */
static int
smbfs_access(vnode_t *vp, int mode, int flags, cred_t *cr, caller_context_t *ct)
{
	vfs_t		*vfsp;
	smbmntinfo_t	*smi;

	vfsp = vp->v_vfsp;
	smi = VFTOSMI(vfsp);

	if (curproc->p_zone != smi->smi_zone_ref.zref_zone)
		return (EIO);

	if (smi->smi_flags & SMI_DEAD || vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	return (smbfs_access_rwx(vfsp, vp->v_type, mode, cr));
}


/* ARGSUSED */
static int
smbfs_readlink(vnode_t *vp, struct uio *uiop, cred_t *cr, caller_context_t *ct)
{
	/* Not yet... */
	return (ENOSYS);
}


/*
 * Flush local dirty pages to stable storage on the server.
 *
 * If FNODSYNC is specified, then there is nothing to do because
 * metadata changes are not cached on the client before being
 * sent to the server.
 */
/* ARGSUSED */
static int
smbfs_fsync(vnode_t *vp, int syncflag, cred_t *cr, caller_context_t *ct)
{
	int		error = 0;
	smbmntinfo_t	*smi;
	smbnode_t	*np;
	struct smb_cred scred;

	np = VTOSMB(vp);
	smi = VTOSMI(vp);

	if (curproc->p_zone != smi->smi_zone_ref.zref_zone)
		return (EIO);

	if (smi->smi_flags & SMI_DEAD || vp->v_vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	if ((syncflag & FNODSYNC) || IS_SWAPVP(vp))
		return (0);

	if ((syncflag & (FSYNC|FDSYNC)) == 0)
		return (0);

	error = smbfs_putpage(vp, (offset_t)0, 0, 0, cr, ct);
	if (error)
		return (error);

	/* Shared lock for n_fid use in _flush */
	if (smbfs_rw_enter_sig(&np->r_lkserlock, RW_READER, SMBINTR(vp)))
		return (EINTR);
	smb_credinit(&scred, cr);

	error = smbfs_smb_flush(np, &scred);

	smb_credrele(&scred);
	smbfs_rw_exit(&np->r_lkserlock);

	return (error);
}

/*
 * Last reference to vnode went away.
 */
/* ARGSUSED */
static void
smbfs_inactive(vnode_t *vp, cred_t *cr, caller_context_t *ct)
{
	struct smb_cred scred;
	smbnode_t	*np = VTOSMB(vp);
	int error;

	/*
	 * Don't "bail out" for VFS_UNMOUNTED here,
	 * as we want to do cleanup, etc.
	 * See also pcfs_inactive
	 */

	/*
	 * If this is coming from the wrong zone, we let someone in the right
	 * zone take care of it asynchronously.  We can get here due to
	 * VN_RELE() being called from pageout() or fsflush().  This call may
	 * potentially turn into an expensive no-op if, for instance, v_count
	 * gets incremented in the meantime, but it's still correct.
	 */

	/*
	 * From NFS:rinactive()
	 *
	 * Before freeing anything, wait until all asynchronous
	 * activity is done on this rnode.  This will allow all
	 * asynchronous read ahead and write behind i/o's to
	 * finish.
	 */
	mutex_enter(&np->r_statelock);
	while (np->r_count > 0)
		cv_wait(&np->r_cv, &np->r_statelock);
	mutex_exit(&np->r_statelock);

	/*
	 * Flush and invalidate all pages associated with the vnode.
	 */
	if (vn_has_cached_data(vp)) {
		if ((np->r_flags & RDIRTY) && !np->r_error) {
			error = smbfs_putpage(vp, (u_offset_t)0, 0, 0, cr, ct);
			if (error && (error == ENOSPC || error == EDQUOT)) {
				mutex_enter(&np->r_statelock);
				if (!np->r_error)
					np->r_error = error;
				mutex_exit(&np->r_statelock);
			}
		}
		smbfs_invalidate_pages(vp, (u_offset_t)0, cr);
	}
	/*
	 * This vnode should have lost all cached data.
	 */
	ASSERT(vn_has_cached_data(vp) == 0);

	/*
	 * Defend against the possibility that higher-level callers
	 * might not correctly balance open and close calls.  If we
	 * get here with open references remaining, it means there
	 * was a missing VOP_CLOSE somewhere.  If that happens, do
	 * the close here so we don't "leak" FIDs on the server.
	 *
	 * Exclusive lock for modifying n_fid stuff.
	 * Don't want this one ever interruptible.
	 */
	(void) smbfs_rw_enter_sig(&np->r_lkserlock, RW_WRITER, 0);
	smb_credinit(&scred, cr);

	switch (np->n_ovtype) {
	case VNON:
		/* not open (OK) */
		break;

	case VDIR:
		if (np->n_dirrefs == 0)
			break;
		SMBVDEBUG("open dir: refs %d path %s\n",
		    np->n_dirrefs, np->n_rpath);
		/* Force last close. */
		np->n_dirrefs = 1;
		smbfs_rele_fid(np, &scred);
		break;

	case VREG:
		if (np->n_fidrefs == 0)
			break;
		SMBVDEBUG("open file: refs %d id 0x%x path %s\n",
		    np->n_fidrefs, np->n_fid, np->n_rpath);
		/* Force last close. */
		np->n_fidrefs = 1;
		smbfs_rele_fid(np, &scred);
		break;

	default:
		SMBVDEBUG("bad n_ovtype %d\n", np->n_ovtype);
		np->n_ovtype = VNON;
		break;
	}

	smb_credrele(&scred);
	smbfs_rw_exit(&np->r_lkserlock);

	/*
	 * XATTR directories (and the files under them) have
	 * little value for reclaim, so just remove them from
	 * the "hash" (AVL) as soon as they go inactive.
	 * Note that the node may already have been removed
	 * from the hash by smbfsremove.
	 */
	if ((np->n_flag & N_XATTR) != 0 &&
	    (np->r_flags & RHASHED) != 0)
		smbfs_rmhash(np);

	smbfs_addfree(np);
}

/*
 * Remote file system operations having to do with directory manipulation.
 */
/* ARGSUSED */
static int
smbfs_lookup(vnode_t *dvp, char *nm, vnode_t **vpp, struct pathname *pnp,
	int flags, vnode_t *rdir, cred_t *cr, caller_context_t *ct,
	int *direntflags, pathname_t *realpnp)
{
	vfs_t		*vfs;
	smbmntinfo_t	*smi;
	smbnode_t	*dnp;
	int		error;

	vfs = dvp->v_vfsp;
	smi = VFTOSMI(vfs);

	if (curproc->p_zone != smi->smi_zone_ref.zref_zone)
		return (EPERM);

	if (smi->smi_flags & SMI_DEAD || vfs->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	dnp = VTOSMB(dvp);

	/*
	 * Are we looking up extended attributes?  If so, "dvp" is
	 * the file or directory for which we want attributes, and
	 * we need a lookup of the (faked up) attribute directory
	 * before we lookup the rest of the path.
	 */
	if (flags & LOOKUP_XATTR) {
		/*
		 * Require the xattr mount option.
		 */
		if ((vfs->vfs_flag & VFS_XATTR) == 0)
			return (EINVAL);

		error = smbfs_get_xattrdir(dvp, vpp, cr, flags);
		return (error);
	}

	if (smbfs_rw_enter_sig(&dnp->r_rwlock, RW_READER, SMBINTR(dvp)))
		return (EINTR);

	error = smbfslookup(dvp, nm, vpp, cr, 1, ct);

	smbfs_rw_exit(&dnp->r_rwlock);

	return (error);
}

/* ARGSUSED */
static int
smbfslookup(vnode_t *dvp, char *nm, vnode_t **vpp, cred_t *cr,
	int cache_ok, caller_context_t *ct)
{
	int		error;
	int		supplen; /* supported length */
	vnode_t		*vp;
	smbnode_t	*np;
	smbnode_t	*dnp;
	smbmntinfo_t	*smi;
	/* struct smb_vc	*vcp; */
	const char	*ill;
	const char	*name = (const char *)nm;
	int		nmlen = strlen(nm);
	int		rplen;
	struct smb_cred scred;
	struct smbfattr fa;

	smi = VTOSMI(dvp);
	dnp = VTOSMB(dvp);

	ASSERT(curproc->p_zone == smi->smi_zone_ref.zref_zone);

#ifdef NOT_YET
	vcp = SSTOVC(smi->smi_share);

	/* XXX: Should compute this once and store it in smbmntinfo_t */
	supplen = (SMB_DIALECT(vcp) >= SMB_DIALECT_LANMAN2_0) ? 255 : 12;
#else
	supplen = 255;
#endif

	/*
	 * RWlock must be held, either reader or writer.
	 */
	ASSERT(dnp->r_rwlock.count != 0);

	/*
	 * If lookup is for "", just return dvp.
	 * No need to perform any access checks.
	 */
	if (nmlen == 0) {
		VN_HOLD(dvp);
		*vpp = dvp;
		return (0);
	}

	/*
	 * Can't do lookups in non-directories.
	 */
	if (dvp->v_type != VDIR)
		return (ENOTDIR);

	/*
	 * Need search permission in the directory.
	 */
	error = smbfs_access(dvp, VEXEC, 0, cr, ct);
	if (error)
		return (error);

	/*
	 * If lookup is for ".", just return dvp.
	 * Access check was done above.
	 */
	if (nmlen == 1 && name[0] == '.') {
		VN_HOLD(dvp);
		*vpp = dvp;
		return (0);
	}

	/*
	 * Now some sanity checks on the name.
	 * First check the length.
	 */
	if (nmlen > supplen)
		return (ENAMETOOLONG);

	/*
	 * Avoid surprises with characters that are
	 * illegal in Windows file names.
	 * Todo: CATIA mappings?
	 */
	ill = illegal_chars;
	if (dnp->n_flag & N_XATTR)
		ill++; /* allow colon */
	if (strpbrk(nm, ill))
		return (EINVAL);

	/*
	 * Special handling for lookup of ".."
	 *
	 * We keep full pathnames (as seen on the server)
	 * so we can just trim off the last component to
	 * get the full pathname of the parent.  Note:
	 * We don't actually copy and modify, but just
	 * compute the trimmed length and pass that with
	 * the current dir path (not null terminated).
	 *
	 * We don't go over-the-wire to get attributes
	 * for ".." because we know it's a directory,
	 * and we can just leave the rest "stale"
	 * until someone does a getattr.
	 */
	if (nmlen == 2 && name[0] == '.' && name[1] == '.') {
		if (dvp->v_flag & VROOT) {
			/*
			 * Already at the root.  This can happen
			 * with directory listings at the root,
			 * which lookup "." and ".." to get the
			 * inode numbers.  Let ".." be the same
			 * as "." in the FS root.
			 */
			VN_HOLD(dvp);
			*vpp = dvp;
			return (0);
		}

		/*
		 * Special case for XATTR directory
		 */
		if (dvp->v_flag & V_XATTRDIR) {
			error = smbfs_xa_parent(dvp, vpp);
			return (error);
		}

		/*
		 * Find the parent path length.
		 */
		rplen = dnp->n_rplen;
		ASSERT(rplen > 0);
		while (--rplen >= 0) {
			if (dnp->n_rpath[rplen] == '\\')
				break;
		}
		if (rplen <= 0) {
			/* Found our way to the root. */
			vp = SMBTOV(smi->smi_root);
			VN_HOLD(vp);
			*vpp = vp;
			return (0);
		}
		np = smbfs_node_findcreate(smi,
		    dnp->n_rpath, rplen, NULL, 0, 0,
		    &smbfs_fattr0); /* force create */
		ASSERT(np != NULL);
		vp = SMBTOV(np);
		vp->v_type = VDIR;

		/* Success! */
		*vpp = vp;
		return (0);
	}

	/*
	 * Normal lookup of a name under this directory.
	 * Note we handled "", ".", ".." above.
	 */
	if (cache_ok) {
		/*
		 * The caller indicated that it's OK to use a
		 * cached result for this lookup, so try to
		 * reclaim a node from the smbfs node cache.
		 */
		error = smbfslookup_cache(dvp, nm, nmlen, &vp, cr);
		if (error)
			return (error);
		if (vp != NULL) {
			/* hold taken in lookup_cache */
			*vpp = vp;
			return (0);
		}
	}

	/*
	 * OK, go over-the-wire to get the attributes,
	 * then create the node.
	 */
	smb_credinit(&scred, cr);
	/* Note: this can allocate a new "name" */
	error = smbfs_smb_lookup(dnp, &name, &nmlen, &fa, &scred);
	smb_credrele(&scred);
	if (error == ENOTDIR) {
		/*
		 * Lookup failed because this directory was
		 * removed or renamed by another client.
		 * Remove any cached attributes under it.
		 */
		smbfs_attrcache_remove(dnp);
		smbfs_attrcache_prune(dnp);
	}
	if (error)
		goto out;

	error = smbfs_nget(dvp, name, nmlen, &fa, &vp);
	if (error)
		goto out;

	/* Success! */
	*vpp = vp;

out:
	/* smbfs_smb_lookup may have allocated name. */
	if (name != nm)
		smbfs_name_free(name, nmlen);

	return (error);
}

/*
 * smbfslookup_cache
 *
 * Try to reclaim a node from the smbfs node cache.
 * Some statistics for DEBUG.
 *
 * This mechanism lets us avoid many of the five (or more)
 * OtW lookup calls per file seen with "ls -l" if we search
 * the smbfs node cache for recently inactive(ated) nodes.
 */
#ifdef DEBUG
int smbfs_lookup_cache_calls = 0;
int smbfs_lookup_cache_error = 0;
int smbfs_lookup_cache_miss = 0;
int smbfs_lookup_cache_stale = 0;
int smbfs_lookup_cache_hits = 0;
#endif /* DEBUG */

/* ARGSUSED */
static int
smbfslookup_cache(vnode_t *dvp, char *nm, int nmlen,
	vnode_t **vpp, cred_t *cr)
{
	struct vattr va;
	smbnode_t *dnp;
	smbnode_t *np;
	vnode_t *vp;
	int error;
	char sep;

	dnp = VTOSMB(dvp);
	*vpp = NULL;

#ifdef DEBUG
	smbfs_lookup_cache_calls++;
#endif

	/*
	 * First make sure we can get attributes for the
	 * directory.  Cached attributes are OK here.
	 * If we removed or renamed the directory, this
	 * will return ENOENT.  If someone else removed
	 * this directory or file, we'll find out when we
	 * try to open or get attributes.
	 */
	va.va_mask = AT_TYPE | AT_MODE;
	error = smbfsgetattr(dvp, &va, cr);
	if (error) {
#ifdef DEBUG
		smbfs_lookup_cache_error++;
#endif
		return (error);
	}

	/*
	 * Passing NULL smbfattr here so we will
	 * just look, not create.
	 */
	sep = SMBFS_DNP_SEP(dnp);
	np = smbfs_node_findcreate(dnp->n_mount,
	    dnp->n_rpath, dnp->n_rplen,
	    nm, nmlen, sep, NULL);
	if (np == NULL) {
#ifdef DEBUG
		smbfs_lookup_cache_miss++;
#endif
		return (0);
	}

	/*
	 * Found it.  Attributes still valid?
	 */
	vp = SMBTOV(np);
	if (np->r_attrtime <= gethrtime()) {
		/* stale */
#ifdef DEBUG
		smbfs_lookup_cache_stale++;
#endif
		VN_RELE(vp);
		return (0);
	}

	/*
	 * Success!
	 * Caller gets hold from smbfs_node_findcreate
	 */
#ifdef DEBUG
	smbfs_lookup_cache_hits++;
#endif
	*vpp = vp;
	return (0);
}


/*
 * XXX
 * vsecattr_t is new to build 77, and we need to eventually support
 * it in order to create an ACL when an object is created.
 *
 * This op should support the new FIGNORECASE flag for case-insensitive
 * lookups, per PSARC 2007/244.
 */
/* ARGSUSED */
static int
smbfs_create(vnode_t *dvp, char *nm, struct vattr *va, enum vcexcl exclusive,
	int mode, vnode_t **vpp, cred_t *cr, int lfaware, caller_context_t *ct,
	vsecattr_t *vsecp)
{
	int		error;
	int		cerror;
	vfs_t		*vfsp;
	vnode_t		*vp;
	smbnode_t	*np;
	smbnode_t	*dnp;
	smbmntinfo_t	*smi;
	struct vattr	vattr;
	struct smbfattr	fattr;
	struct smb_cred	scred;
	const char *name = (const char *)nm;
	int		nmlen = strlen(nm);
	uint32_t	disp;
	uint16_t	fid;
	int		xattr;

	vfsp = dvp->v_vfsp;
	smi = VFTOSMI(vfsp);
	dnp = VTOSMB(dvp);
	vp = NULL;

	if (curproc->p_zone != smi->smi_zone_ref.zref_zone)
		return (EPERM);

	if (smi->smi_flags & SMI_DEAD || vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	/*
	 * Note: this may break mknod(2) calls to create a directory,
	 * but that's obscure use.  Some other filesystems do this.
	 * Todo: redirect VDIR type here to _mkdir.
	 */
	if (va->va_type != VREG)
		return (EINVAL);

	/*
	 * If the pathname is "", just use dvp, no checks.
	 * Do this outside of the rwlock (like zfs).
	 */
	if (nmlen == 0) {
		VN_HOLD(dvp);
		*vpp = dvp;
		return (0);
	}

	/* Don't allow "." or ".." through here. */
	if ((nmlen == 1 && name[0] == '.') ||
	    (nmlen == 2 && name[0] == '.' && name[1] == '.'))
		return (EISDIR);

	/*
	 * We make a copy of the attributes because the caller does not
	 * expect us to change what va points to.
	 */
	vattr = *va;

	if (smbfs_rw_enter_sig(&dnp->r_rwlock, RW_WRITER, SMBINTR(dvp)))
		return (EINTR);
	smb_credinit(&scred, cr);

	/*
	 * NFS needs to go over the wire, just to be sure whether the
	 * file exists or not.  Using a cached result is dangerous in
	 * this case when making a decision regarding existence.
	 *
	 * The SMB protocol does NOT really need to go OTW here
	 * thanks to the expressive NTCREATE disposition values.
	 * Unfortunately, to do Unix access checks correctly,
	 * we need to know if the object already exists.
	 * When the object does not exist, we need VWRITE on
	 * the directory.  Note: smbfslookup() checks VEXEC.
	 */
	error = smbfslookup(dvp, nm, &vp, cr, 0, ct);
	if (error == 0) {
		/*
		 * The file already exists.  Error?
		 * NB: have a hold from smbfslookup
		 */
		if (exclusive == EXCL) {
			error = EEXIST;
			VN_RELE(vp);
			goto out;
		}
		/*
		 * Verify requested access.
		 */
		error = smbfs_access(vp, mode, 0, cr, ct);
		if (error) {
			VN_RELE(vp);
			goto out;
		}

		/*
		 * Truncate (if requested).
		 */
		if ((vattr.va_mask & AT_SIZE) && vp->v_type == VREG) {
			np = VTOSMB(vp);
			/*
			 * Check here for large file truncation by
			 * LF-unaware process, like ufs_create().
			 */
			if (!(lfaware & FOFFMAX)) {
				mutex_enter(&np->r_statelock);
				if (np->r_size > MAXOFF32_T)
					error = EOVERFLOW;
				mutex_exit(&np->r_statelock);
			}
			if (error) {
				VN_RELE(vp);
				goto out;
			}
			vattr.va_mask = AT_SIZE;
			error = smbfssetattr(vp, &vattr, 0, cr);
			if (error) {
				VN_RELE(vp);
				goto out;
			}
#ifdef	SMBFS_VNEVENT
			/* Existing file was truncated */
			vnevent_create(vp, ct);
#endif
			/* invalidate pages done in smbfssetattr() */
		}
		/* Success! */
		*vpp = vp;
		goto out;
	}

	/*
	 * The file did not exist.  Need VWRITE in the directory.
	 */
	error = smbfs_access(dvp, VWRITE, 0, cr, ct);
	if (error)
		goto out;

	/*
	 * Now things get tricky.  We also need to check the
	 * requested open mode against the file we may create.
	 * See comments at smbfs_access_rwx
	 */
	error = smbfs_access_rwx(vfsp, VREG, mode, cr);
	if (error)
		goto out;

	/*
	 * Now the code derived from Darwin,
	 * but with greater use of NT_CREATE
	 * disposition options.  Much changed.
	 *
	 * Create (or open) a new child node.
	 * Note we handled "." and ".." above.
	 */

	if (exclusive == EXCL)
		disp = NTCREATEX_DISP_CREATE;
	else {
		/* Truncate regular files if requested. */
		if ((va->va_type == VREG) &&
		    (va->va_mask & AT_SIZE) &&
		    (va->va_size == 0))
			disp = NTCREATEX_DISP_OVERWRITE_IF;
		else
			disp = NTCREATEX_DISP_OPEN_IF;
	}
	xattr = (dnp->n_flag & N_XATTR) ? 1 : 0;
	error = smbfs_smb_create(dnp,
	    name, nmlen, xattr,
	    disp, &scred, &fid);
	if (error)
		goto out;

	/*
	 * Should use the fid to get/set the size
	 * while we have it opened here.  See above.
	 */

	cerror = smbfs_smb_close(smi->smi_share, fid, NULL, &scred);
	if (cerror)
		SMBVDEBUG("error %d closing %s\\%s\n",
		    cerror, dnp->n_rpath, name);

	/*
	 * In the open case, the name may differ a little
	 * from what we passed to create (case, etc.)
	 * so call lookup to get the (opened) name.
	 *
	 * XXX: Could avoid this extra lookup if the
	 * "createact" result from NT_CREATE says we
	 * created the object.
	 */
	error = smbfs_smb_lookup(dnp, &name, &nmlen, &fattr, &scred);
	if (error)
		goto out;

	/* update attr and directory cache */
	smbfs_attr_touchdir(dnp);

	error = smbfs_nget(dvp, name, nmlen, &fattr, &vp);
	if (error)
		goto out;

	/* Success! */
	*vpp = vp;
	error = 0;

out:
	smb_credrele(&scred);
	smbfs_rw_exit(&dnp->r_rwlock);
	if (name != nm)
		smbfs_name_free(name, nmlen);
	return (error);
}

/*
 * XXX
 * This op should support the new FIGNORECASE flag for case-insensitive
 * lookups, per PSARC 2007/244.
 */
/* ARGSUSED */
static int
smbfs_remove(vnode_t *dvp, char *nm, cred_t *cr, caller_context_t *ct,
	int flags)
{
	struct smb_cred	scred;
	vnode_t		*vp = NULL;
	smbnode_t	*dnp = VTOSMB(dvp);
	smbmntinfo_t	*smi = VTOSMI(dvp);
	int		error;

	if (curproc->p_zone != smi->smi_zone_ref.zref_zone)
		return (EPERM);

	if (smi->smi_flags & SMI_DEAD || dvp->v_vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	/*
	 * Verify access to the dirctory.
	 */
	error = smbfs_access(dvp, VWRITE|VEXEC, 0, cr, ct);
	if (error)
		return (error);

	if (smbfs_rw_enter_sig(&dnp->r_rwlock, RW_WRITER, SMBINTR(dvp)))
		return (EINTR);
	smb_credinit(&scred, cr);

	/* Lookup the file to remove. */
	error = smbfslookup(dvp, nm, &vp, cr, 0, ct);
	if (error == 0) {
		/*
		 * Do the real remove work
		 */
		error = smbfsremove(dvp, vp, &scred, flags);
		VN_RELE(vp);
	}

	smb_credrele(&scred);
	smbfs_rw_exit(&dnp->r_rwlock);

	return (error);
}

/*
 * smbfsremove does the real work of removing in SMBFS
 * Caller has done dir access checks etc.
 *
 * The normal way to delete a file over SMB is open it (with DELETE access),
 * set the "delete-on-close" flag, and close the file.  The problem for Unix
 * applications is that they expect the file name to be gone once the unlink
 * completes, and the SMB server does not actually delete the file until ALL
 * opens of that file are closed.  We can't assume our open handles are the
 * only open handles on a file we're deleting, so to be safe we'll try to
 * rename the file to a temporary name and then set delete-on-close.  If we
 * fail to set delete-on-close (i.e. because other opens prevent it) then
 * undo the changes we made and give up with EBUSY.  Note that we might have
 * permission to delete a file but lack permission to rename, so we want to
 * continue in cases where rename fails.  As an optimization, only do the
 * rename when we have the file open.
 *
 * This is similar to what NFS does when deleting a file that has local opens,
 * but thanks to SMB delete-on-close, we don't need to keep track of when the
 * last local open goes away and send a delete.  The server does that for us.
 */
/* ARGSUSED */
static int
smbfsremove(vnode_t *dvp, vnode_t *vp, struct smb_cred *scred,
    int flags)
{
	smbnode_t	*dnp = VTOSMB(dvp);
	smbnode_t	*np = VTOSMB(vp);
	char		*tmpname = NULL;
	int		tnlen;
	int		error;
	unsigned short	fid;
	boolean_t	have_fid = B_FALSE;
	boolean_t	renamed = B_FALSE;

	/*
	 * The dvp RWlock must be held as writer.
	 */
	ASSERT(dnp->r_rwlock.owner == curthread);

	/* Never allow link/unlink directories on SMB. */
	if (vp->v_type == VDIR)
		return (EPERM);

	/*
	 * We need to flush any dirty pages which happen to
	 * be hanging around before removing the file.  This
	 * shouldn't happen very often and mostly on file
	 * systems mounted "nocto".
	 */
	if (vn_has_cached_data(vp) &&
	    ((np->r_flags & RDIRTY) || np->r_count > 0)) {
		error = smbfs_putpage(vp, (offset_t)0, 0, 0,
		    scred->scr_cred, NULL);
		if (error && (error == ENOSPC || error == EDQUOT)) {
			mutex_enter(&np->r_statelock);
			if (!np->r_error)
				np->r_error = error;
			mutex_exit(&np->r_statelock);
		}
	}

	/* Shared lock for n_fid use in smbfs_smb_setdisp etc. */
	if (smbfs_rw_enter_sig(&np->r_lkserlock, RW_READER, SMBINTR(vp)))
		return (EINTR);

	/*
	 * Get a file handle with delete access.
	 * Close this FID before return.
	 */
	error = smbfs_smb_tmpopen(np, STD_RIGHT_DELETE_ACCESS,
	    scred, &fid);
	if (error) {
		SMBVDEBUG("error %d opening %s\n",
		    error, np->n_rpath);
		goto out;
	}
	have_fid = B_TRUE;

	/*
	 * If we have the file open, try to rename it to a temporary name.
	 * If we can't rename, continue on and try setting DoC anyway.
	 */
	if ((vp->v_count > 1) && (np->n_fidrefs > 0)) {
		tmpname = kmem_alloc(MAXNAMELEN, KM_SLEEP);
		tnlen = smbfs_newname(tmpname, MAXNAMELEN);
		error = smbfs_smb_t2rename(np, tmpname, tnlen, scred, fid, 0);
		if (error != 0) {
			SMBVDEBUG("error %d renaming %s -> %s\n",
			    error, np->n_rpath, tmpname);
			/* Keep going without the rename. */
		} else {
			renamed = B_TRUE;
		}
	}

	/*
	 * Mark the file as delete-on-close.  If we can't,
	 * undo what we did and err out.
	 */
	error = smbfs_smb_setdisp(np, fid, 1, scred);
	if (error != 0) {
		SMBVDEBUG("error %d setting DoC on %s\n",
		    error, np->n_rpath);
		/*
		 * Failed to set DoC. If we renamed, undo that.
		 * Need np->n_rpath relative to parent (dnp).
		 * Use parent path name length plus one for
		 * the separator ('/' or ':')
		 */
		if (renamed) {
			char *oldname;
			int oldnlen;
			int err2;

			oldname = np->n_rpath + (dnp->n_rplen + 1);
			oldnlen = np->n_rplen - (dnp->n_rplen + 1);
			err2 = smbfs_smb_t2rename(np, oldname, oldnlen,
			    scred, fid, 0);
			SMBVDEBUG("error %d un-renaming %s -> %s\n",
			    err2, tmpname, np->n_rpath);
		}
		error = EBUSY;
		goto out;
	}
	/* Done! */
	smbfs_attrcache_prune(np);

#ifdef	SMBFS_VNEVENT
	vnevent_remove(vp, dvp, nm, ct);
#endif

out:
	if (tmpname != NULL)
		kmem_free(tmpname, MAXNAMELEN);

	if (have_fid)
		(void) smbfs_smb_tmpclose(np, fid, scred);
	smbfs_rw_exit(&np->r_lkserlock);

	if (error == 0) {
		/* Keep lookup from finding this node anymore. */
		smbfs_rmhash(np);
	}

	return (error);
}


/* ARGSUSED */
static int
smbfs_link(vnode_t *tdvp, vnode_t *svp, char *tnm, cred_t *cr,
	caller_context_t *ct, int flags)
{
	/* Not yet... */
	return (ENOSYS);
}


/*
 * XXX
 * This op should support the new FIGNORECASE flag for case-insensitive
 * lookups, per PSARC 2007/244.
 */
/* ARGSUSED */
static int
smbfs_rename(vnode_t *odvp, char *onm, vnode_t *ndvp, char *nnm, cred_t *cr,
	caller_context_t *ct, int flags)
{
	struct smb_cred	scred;
	smbnode_t	*odnp = VTOSMB(odvp);
	smbnode_t	*ndnp = VTOSMB(ndvp);
	vnode_t		*ovp;
	int error;

	if (curproc->p_zone != VTOSMI(odvp)->smi_zone_ref.zref_zone ||
	    curproc->p_zone != VTOSMI(ndvp)->smi_zone_ref.zref_zone)
		return (EPERM);

	if (VTOSMI(odvp)->smi_flags & SMI_DEAD ||
	    VTOSMI(ndvp)->smi_flags & SMI_DEAD ||
	    odvp->v_vfsp->vfs_flag & VFS_UNMOUNTED ||
	    ndvp->v_vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	if (strcmp(onm, ".") == 0 || strcmp(onm, "..") == 0 ||
	    strcmp(nnm, ".") == 0 || strcmp(nnm, "..") == 0)
		return (EINVAL);

	/*
	 * Check that everything is on the same filesystem.
	 * vn_rename checks the fsid's, but in case we don't
	 * fill those in correctly, check here too.
	 */
	if (odvp->v_vfsp != ndvp->v_vfsp)
		return (EXDEV);

	/*
	 * Need write access on source and target.
	 * Server takes care of most checks.
	 */
	error = smbfs_access(odvp, VWRITE|VEXEC, 0, cr, ct);
	if (error)
		return (error);
	if (odvp != ndvp) {
		error = smbfs_access(ndvp, VWRITE, 0, cr, ct);
		if (error)
			return (error);
	}

	/*
	 * Need to lock both old/new dirs as writer.
	 *
	 * Avoid deadlock here on old vs new directory nodes
	 * by always taking the locks in order of address.
	 * The order is arbitrary, but must be consistent.
	 */
	if (odnp < ndnp) {
		if (smbfs_rw_enter_sig(&odnp->r_rwlock, RW_WRITER,
		    SMBINTR(odvp)))
			return (EINTR);
		if (smbfs_rw_enter_sig(&ndnp->r_rwlock, RW_WRITER,
		    SMBINTR(ndvp))) {
			smbfs_rw_exit(&odnp->r_rwlock);
			return (EINTR);
		}
	} else {
		if (smbfs_rw_enter_sig(&ndnp->r_rwlock, RW_WRITER,
		    SMBINTR(ndvp)))
			return (EINTR);
		if (smbfs_rw_enter_sig(&odnp->r_rwlock, RW_WRITER,
		    SMBINTR(odvp))) {
			smbfs_rw_exit(&ndnp->r_rwlock);
			return (EINTR);
		}
	}
	smb_credinit(&scred, cr);

	/* Lookup the "old" name */
	error = smbfslookup(odvp, onm, &ovp, cr, 0, ct);
	if (error == 0) {
		/*
		 * Do the real rename work
		 */
		error = smbfsrename(odvp, ovp, ndvp, nnm, &scred, flags);
		VN_RELE(ovp);
	}

	smb_credrele(&scred);
	smbfs_rw_exit(&odnp->r_rwlock);
	smbfs_rw_exit(&ndnp->r_rwlock);

	return (error);
}

/*
 * smbfsrename does the real work of renaming in SMBFS
 * Caller has done dir access checks etc.
 */
/* ARGSUSED */
static int
smbfsrename(vnode_t *odvp, vnode_t *ovp, vnode_t *ndvp, char *nnm,
    struct smb_cred *scred, int flags)
{
	smbnode_t	*odnp = VTOSMB(odvp);
	smbnode_t	*onp = VTOSMB(ovp);
	smbnode_t	*ndnp = VTOSMB(ndvp);
	vnode_t		*nvp = NULL;
	int		error;
	int		nvp_locked = 0;

	/* Things our caller should have checked. */
	ASSERT(curproc->p_zone == VTOSMI(odvp)->smi_zone_ref.zref_zone);
	ASSERT(odvp->v_vfsp == ndvp->v_vfsp);
	ASSERT(odnp->r_rwlock.owner == curthread);
	ASSERT(ndnp->r_rwlock.owner == curthread);

	/*
	 * Lookup the target file.  If it exists, it needs to be
	 * checked to see whether it is a mount point and whether
	 * it is active (open).
	 */
	error = smbfslookup(ndvp, nnm, &nvp, scred->scr_cred, 0, NULL);
	if (!error) {
		/*
		 * Target (nvp) already exists.  Check that it
		 * has the same type as the source.  The server
		 * will check this also, (and more reliably) but
		 * this lets us return the correct error codes.
		 */
		if (ovp->v_type == VDIR) {
			if (nvp->v_type != VDIR) {
				error = ENOTDIR;
				goto out;
			}
		} else {
			if (nvp->v_type == VDIR) {
				error = EISDIR;
				goto out;
			}
		}

		/*
		 * POSIX dictates that when the source and target
		 * entries refer to the same file object, rename
		 * must do nothing and exit without error.
		 */
		if (ovp == nvp) {
			error = 0;
			goto out;
		}

		/*
		 * Also must ensure the target is not a mount point,
		 * and keep mount/umount away until we're done.
		 */
		if (vn_vfsrlock(nvp)) {
			error = EBUSY;
			goto out;
		}
		nvp_locked = 1;
		if (vn_mountedvfs(nvp) != NULL) {
			error = EBUSY;
			goto out;
		}

		/*
		 * CIFS may give a SHARING_VIOLATION error when
		 * trying to rename onto an exising object,
		 * so try to remove the target first.
		 * (Only for files, not directories.)
		 */
		if (nvp->v_type == VDIR) {
			error = EEXIST;
			goto out;
		}
		error = smbfsremove(ndvp, nvp, scred, flags);
		if (error != 0)
			goto out;

		/*
		 * OK, removed the target file.  Continue as if
		 * lookup target had failed (nvp == NULL).
		 */
		vn_vfsunlock(nvp);
		nvp_locked = 0;
		VN_RELE(nvp);
		nvp = NULL;
	} /* nvp */

	smbfs_attrcache_remove(onp);
	error = smbfs_smb_rename(onp, ndnp, nnm, strlen(nnm), scred);

	/*
	 * If the old name should no longer exist,
	 * discard any cached attributes under it.
	 */
	if (error == 0) {
		smbfs_attrcache_prune(onp);
		/* SMBFS_VNEVENT... */
	}

out:
	if (nvp) {
		if (nvp_locked)
			vn_vfsunlock(nvp);
		VN_RELE(nvp);
	}

	return (error);
}

/*
 * XXX
 * vsecattr_t is new to build 77, and we need to eventually support
 * it in order to create an ACL when an object is created.
 *
 * This op should support the new FIGNORECASE flag for case-insensitive
 * lookups, per PSARC 2007/244.
 */
/* ARGSUSED */
static int
smbfs_mkdir(vnode_t *dvp, char *nm, struct vattr *va, vnode_t **vpp,
	cred_t *cr, caller_context_t *ct, int flags, vsecattr_t *vsecp)
{
	vnode_t		*vp;
	struct smbnode	*dnp = VTOSMB(dvp);
	struct smbmntinfo *smi = VTOSMI(dvp);
	struct smb_cred	scred;
	struct smbfattr	fattr;
	const char		*name = (const char *) nm;
	int		nmlen = strlen(name);
	int		error, hiderr;

	if (curproc->p_zone != smi->smi_zone_ref.zref_zone)
		return (EPERM);

	if (smi->smi_flags & SMI_DEAD || dvp->v_vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	if ((nmlen == 1 && name[0] == '.') ||
	    (nmlen == 2 && name[0] == '.' && name[1] == '.'))
		return (EEXIST);

	/* Only plain files are allowed in V_XATTRDIR. */
	if (dvp->v_flag & V_XATTRDIR)
		return (EINVAL);

	if (smbfs_rw_enter_sig(&dnp->r_rwlock, RW_WRITER, SMBINTR(dvp)))
		return (EINTR);
	smb_credinit(&scred, cr);

	/*
	 * Require write access in the containing directory.
	 */
	error = smbfs_access(dvp, VWRITE, 0, cr, ct);
	if (error)
		goto out;

	error = smbfs_smb_mkdir(dnp, name, nmlen, &scred);
	if (error)
		goto out;

	error = smbfs_smb_lookup(dnp, &name, &nmlen, &fattr, &scred);
	if (error)
		goto out;

	smbfs_attr_touchdir(dnp);

	error = smbfs_nget(dvp, name, nmlen, &fattr, &vp);
	if (error)
		goto out;

	if (name[0] == '.')
		if ((hiderr = smbfs_smb_hideit(VTOSMB(vp), NULL, 0, &scred)))
			SMBVDEBUG("hide failure %d\n", hiderr);

	/* Success! */
	*vpp = vp;
	error = 0;
out:
	smb_credrele(&scred);
	smbfs_rw_exit(&dnp->r_rwlock);

	if (name != nm)
		smbfs_name_free(name, nmlen);

	return (error);
}

/*
 * XXX
 * This op should support the new FIGNORECASE flag for case-insensitive
 * lookups, per PSARC 2007/244.
 */
/* ARGSUSED */
static int
smbfs_rmdir(vnode_t *dvp, char *nm, vnode_t *cdir, cred_t *cr,
	caller_context_t *ct, int flags)
{
	vnode_t		*vp = NULL;
	int		vp_locked = 0;
	struct smbmntinfo *smi = VTOSMI(dvp);
	struct smbnode	*dnp = VTOSMB(dvp);
	struct smbnode	*np;
	struct smb_cred	scred;
	int		error;

	if (curproc->p_zone != smi->smi_zone_ref.zref_zone)
		return (EPERM);

	if (smi->smi_flags & SMI_DEAD || dvp->v_vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	if (smbfs_rw_enter_sig(&dnp->r_rwlock, RW_WRITER, SMBINTR(dvp)))
		return (EINTR);
	smb_credinit(&scred, cr);

	/*
	 * Require w/x access in the containing directory.
	 * Server handles all other access checks.
	 */
	error = smbfs_access(dvp, VEXEC|VWRITE, 0, cr, ct);
	if (error)
		goto out;

	/*
	 * First lookup the entry to be removed.
	 */
	error = smbfslookup(dvp, nm, &vp, cr, 0, ct);
	if (error)
		goto out;
	np = VTOSMB(vp);

	/*
	 * Disallow rmdir of "." or current dir, or the FS root.
	 * Also make sure it's a directory, not a mount point,
	 * and lock to keep mount/umount away until we're done.
	 */
	if ((vp == dvp) || (vp == cdir) || (vp->v_flag & VROOT)) {
		error = EINVAL;
		goto out;
	}
	if (vp->v_type != VDIR) {
		error = ENOTDIR;
		goto out;
	}
	if (vn_vfsrlock(vp)) {
		error = EBUSY;
		goto out;
	}
	vp_locked = 1;
	if (vn_mountedvfs(vp) != NULL) {
		error = EBUSY;
		goto out;
	}

	smbfs_attrcache_remove(np);
	error = smbfs_smb_rmdir(np, &scred);

	/*
	 * Similar to smbfs_remove
	 */
	switch (error) {
	case 0:
	case ENOENT:
	case ENOTDIR:
		smbfs_attrcache_prune(np);
		break;
	}

	if (error)
		goto out;

	mutex_enter(&np->r_statelock);
	dnp->n_flag |= NMODIFIED;
	mutex_exit(&np->r_statelock);
	smbfs_attr_touchdir(dnp);
	smbfs_rmhash(np);

out:
	if (vp) {
		if (vp_locked)
			vn_vfsunlock(vp);
		VN_RELE(vp);
	}
	smb_credrele(&scred);
	smbfs_rw_exit(&dnp->r_rwlock);

	return (error);
}


/* ARGSUSED */
static int
smbfs_symlink(vnode_t *dvp, char *lnm, struct vattr *tva, char *tnm, cred_t *cr,
	caller_context_t *ct, int flags)
{
	/* Not yet... */
	return (ENOSYS);
}


/* ARGSUSED */
static int
smbfs_readdir(vnode_t *vp, struct uio *uiop, cred_t *cr, int *eofp,
	caller_context_t *ct, int flags)
{
	struct smbnode	*np = VTOSMB(vp);
	int		error = 0;
	smbmntinfo_t	*smi;

	smi = VTOSMI(vp);

	if (curproc->p_zone != smi->smi_zone_ref.zref_zone)
		return (EIO);

	if (smi->smi_flags & SMI_DEAD || vp->v_vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	/*
	 * Require read access in the directory.
	 */
	error = smbfs_access(vp, VREAD, 0, cr, ct);
	if (error)
		return (error);

	ASSERT(smbfs_rw_lock_held(&np->r_rwlock, RW_READER));

	/*
	 * Todo readdir cache here
	 *
	 * I am serializing the entire readdir opreation
	 * now since we have not yet implemented readdir
	 * cache. This fix needs to be revisited once
	 * we implement readdir cache.
	 */
	if (smbfs_rw_enter_sig(&np->r_lkserlock, RW_WRITER, SMBINTR(vp)))
		return (EINTR);

	error = smbfs_readvdir(vp, uiop, cr, eofp, ct);

	smbfs_rw_exit(&np->r_lkserlock);

	return (error);
}

/* ARGSUSED */
static int
smbfs_readvdir(vnode_t *vp, uio_t *uio, cred_t *cr, int *eofp,
	caller_context_t *ct)
{
	/*
	 * Note: "limit" tells the SMB-level FindFirst/FindNext
	 * functions how many directory entries to request in
	 * each OtW call.  It needs to be large enough so that
	 * we don't make lots of tiny OtW requests, but there's
	 * no point making it larger than the maximum number of
	 * OtW entries that would fit in a maximum sized trans2
	 * response (64k / 48).  Beyond that, it's just tuning.
	 * WinNT used 512, Win2k used 1366.  We use 1000.
	 */
	static const int limit = 1000;
	/* Largest possible dirent size. */
	static const size_t dbufsiz = DIRENT64_RECLEN(SMB_MAXFNAMELEN);
	struct smb_cred scred;
	vnode_t		*newvp;
	struct smbnode	*np = VTOSMB(vp);
	struct smbfs_fctx *ctx;
	struct dirent64 *dp;
	ssize_t		save_resid;
	offset_t	save_offset; /* 64 bits */
	int		offset; /* yes, 32 bits */
	int		nmlen, error;
	ushort_t	reclen;

	ASSERT(curproc->p_zone == VTOSMI(vp)->smi_zone_ref.zref_zone);

	/* Make sure we serialize for n_dirseq use. */
	ASSERT(smbfs_rw_lock_held(&np->r_lkserlock, RW_WRITER));

	/*
	 * Make sure smbfs_open filled in n_dirseq
	 */
	if (np->n_dirseq == NULL)
		return (EBADF);

	/* Check for overflow of (32-bit) directory offset. */
	if (uio->uio_loffset < 0 || uio->uio_loffset > INT32_MAX ||
	    (uio->uio_loffset + uio->uio_resid) > INT32_MAX)
		return (EINVAL);

	/* Require space for at least one dirent. */
	if (uio->uio_resid < dbufsiz)
		return (EINVAL);

	SMBVDEBUG("dirname='%s'\n", np->n_rpath);
	smb_credinit(&scred, cr);
	dp = kmem_alloc(dbufsiz, KM_SLEEP);

	save_resid = uio->uio_resid;
	save_offset = uio->uio_loffset;
	offset = uio->uio_offset;
	SMBVDEBUG("in: offset=%d, resid=%d\n",
	    (int)uio->uio_offset, (int)uio->uio_resid);
	error = 0;

	/*
	 * Generate the "." and ".." entries here so we can
	 * (1) make sure they appear (but only once), and
	 * (2) deal with getting their I numbers which the
	 * findnext below does only for normal names.
	 */
	while (offset < FIRST_DIROFS) {
		/*
		 * Tricky bit filling in the first two:
		 * offset 0 is ".", offset 1 is ".."
		 * so strlen of these is offset+1.
		 */
		reclen = DIRENT64_RECLEN(offset + 1);
		if (uio->uio_resid < reclen)
			goto out;
		bzero(dp, reclen);
		dp->d_reclen = reclen;
		dp->d_name[0] = '.';
		dp->d_name[1] = '.';
		dp->d_name[offset + 1] = '\0';
		/*
		 * Want the real I-numbers for the "." and ".."
		 * entries.  For these two names, we know that
		 * smbfslookup can get the nodes efficiently.
		 */
		error = smbfslookup(vp, dp->d_name, &newvp, cr, 1, ct);
		if (error) {
			dp->d_ino = np->n_ino + offset; /* fiction */
		} else {
			dp->d_ino = VTOSMB(newvp)->n_ino;
			VN_RELE(newvp);
		}
		/*
		 * Note: d_off is the offset that a user-level program
		 * should seek to for reading the NEXT directory entry.
		 * See libc: readdir, telldir, seekdir
		 */
		dp->d_off = offset + 1;
		error = uiomove(dp, reclen, UIO_READ, uio);
		if (error)
			goto out;
		/*
		 * Note: uiomove updates uio->uio_offset,
		 * but we want it to be our "cookie" value,
		 * which just counts dirents ignoring size.
		 */
		uio->uio_offset = ++offset;
	}

	/*
	 * If there was a backward seek, we have to reopen.
	 */
	if (offset < np->n_dirofs) {
		SMBVDEBUG("Reopening search %d:%d\n",
		    offset, np->n_dirofs);
		error = smbfs_smb_findopen(np, "*", 1,
		    SMB_FA_SYSTEM | SMB_FA_HIDDEN | SMB_FA_DIR,
		    &scred, &ctx);
		if (error) {
			SMBVDEBUG("can not open search, error = %d", error);
			goto out;
		}
		/* free the old one */
		(void) smbfs_smb_findclose(np->n_dirseq, &scred);
		/* save the new one */
		np->n_dirseq = ctx;
		np->n_dirofs = FIRST_DIROFS;
	} else {
		ctx = np->n_dirseq;
	}

	/*
	 * Skip entries before the requested offset.
	 */
	while (np->n_dirofs < offset) {
		error = smbfs_smb_findnext(ctx, limit, &scred);
		if (error != 0)
			goto out;
		np->n_dirofs++;
	}

	/*
	 * While there's room in the caller's buffer:
	 *	get a directory entry from SMB,
	 *	convert to a dirent, copyout.
	 * We stop when there is no longer room for a
	 * maximum sized dirent because we must decide
	 * before we know anything about the next entry.
	 */
	while (uio->uio_resid >= dbufsiz) {
		error = smbfs_smb_findnext(ctx, limit, &scred);
		if (error != 0)
			goto out;
		np->n_dirofs++;

		/* Sanity check the name length. */
		nmlen = ctx->f_nmlen;
		if (nmlen > SMB_MAXFNAMELEN) {
			nmlen = SMB_MAXFNAMELEN;
			SMBVDEBUG("Truncating name: %s\n", ctx->f_name);
		}
		if (smbfs_fastlookup) {
			/* See comment at smbfs_fastlookup above. */
			if (smbfs_nget(vp, ctx->f_name, nmlen,
			    &ctx->f_attr, &newvp) == 0)
				VN_RELE(newvp);
		}

		reclen = DIRENT64_RECLEN(nmlen);
		bzero(dp, reclen);
		dp->d_reclen = reclen;
		bcopy(ctx->f_name, dp->d_name, nmlen);
		dp->d_name[nmlen] = '\0';
		dp->d_ino = ctx->f_inum;
		dp->d_off = offset + 1;	/* See d_off comment above */
		error = uiomove(dp, reclen, UIO_READ, uio);
		if (error)
			goto out;
		/* See comment re. uio_offset above. */
		uio->uio_offset = ++offset;
	}

out:
	/*
	 * When we come to the end of a directory, the
	 * SMB-level functions return ENOENT, but the
	 * caller is not expecting an error return.
	 *
	 * Also note that we must delay the call to
	 * smbfs_smb_findclose(np->n_dirseq, ...)
	 * until smbfs_close so that all reads at the
	 * end of the directory will return no data.
	 */
	if (error == ENOENT) {
		error = 0;
		if (eofp)
			*eofp = 1;
	}
	/*
	 * If we encountered an error (i.e. "access denied")
	 * from the FindFirst call, we will have copied out
	 * the "." and ".." entries leaving offset == 2.
	 * In that case, restore the original offset/resid
	 * so the caller gets no data with the error.
	 */
	if (error != 0 && offset == FIRST_DIROFS) {
		uio->uio_loffset = save_offset;
		uio->uio_resid = save_resid;
	}
	SMBVDEBUG("out: offset=%d, resid=%d\n",
	    (int)uio->uio_offset, (int)uio->uio_resid);

	kmem_free(dp, dbufsiz);
	smb_credrele(&scred);
	return (error);
}

/*
 * Here NFS has: nfs3_bio
 * See smbfs_bio above.
 */

/* ARGSUSED */
static int
smbfs_fid(vnode_t *vp, fid_t *fidp, caller_context_t *ct)
{
	return (ENOSYS);
}


/*
 * The pair of functions VOP_RWLOCK, VOP_RWUNLOCK
 * are optional functions that are called by:
 *    getdents, before/after VOP_READDIR
 *    pread, before/after ... VOP_READ
 *    pwrite, before/after ... VOP_WRITE
 *    (other places)
 *
 * Careful here: None of the above check for any
 * error returns from VOP_RWLOCK / VOP_RWUNLOCK!
 * In fact, the return value from _rwlock is NOT
 * an error code, but V_WRITELOCK_TRUE / _FALSE.
 *
 * Therefore, it's up to _this_ code to make sure
 * the lock state remains balanced, which means
 * we can't "bail out" on interrupts, etc.
 */

/* ARGSUSED2 */
static int
smbfs_rwlock(vnode_t *vp, int write_lock, caller_context_t *ctp)
{
	smbnode_t	*np = VTOSMB(vp);

	if (!write_lock) {
		(void) smbfs_rw_enter_sig(&np->r_rwlock, RW_READER, FALSE);
		return (V_WRITELOCK_FALSE);
	}


	(void) smbfs_rw_enter_sig(&np->r_rwlock, RW_WRITER, FALSE);
	return (V_WRITELOCK_TRUE);
}

/* ARGSUSED */
static void
smbfs_rwunlock(vnode_t *vp, int write_lock, caller_context_t *ctp)
{
	smbnode_t	*np = VTOSMB(vp);

	smbfs_rw_exit(&np->r_rwlock);
}


/* ARGSUSED */
static int
smbfs_seek(vnode_t *vp, offset_t ooff, offset_t *noffp, caller_context_t *ct)
{
	smbmntinfo_t	*smi;

	smi = VTOSMI(vp);

	if (curproc->p_zone != smi->smi_zone_ref.zref_zone)
		return (EPERM);

	if (smi->smi_flags & SMI_DEAD || vp->v_vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	/*
	 * Because we stuff the readdir cookie into the offset field
	 * someone may attempt to do an lseek with the cookie which
	 * we want to succeed.
	 */
	if (vp->v_type == VDIR)
		return (0);

	/* Like NFS3, just check for 63-bit overflow. */
	if (*noffp < 0)
		return (EINVAL);

	return (0);
}

/* mmap support ******************************************************** */

#ifdef DEBUG
static int smbfs_lostpage = 0;	/* number of times we lost original page */
#endif

/*
 * Return all the pages from [off..off+len) in file
 * Like nfs3_getpage
 */
/* ARGSUSED */
static int
smbfs_getpage(vnode_t *vp, offset_t off, size_t len, uint_t *protp,
	page_t *pl[], size_t plsz, struct seg *seg, caddr_t addr,
	enum seg_rw rw, cred_t *cr, caller_context_t *ct)
{
	smbnode_t	*np;
	smbmntinfo_t	*smi;
	int		error;

	np = VTOSMB(vp);
	smi = VTOSMI(vp);

	if (curproc->p_zone != smi->smi_zone_ref.zref_zone)
		return (EIO);

	if (smi->smi_flags & SMI_DEAD || vp->v_vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	if (protp != NULL)
		*protp = PROT_ALL;

	/*
	 * Now valididate that the caches are up to date.
	 */
	error = smbfs_validate_caches(vp, cr);
	if (error)
		return (error);

retry:
	mutex_enter(&np->r_statelock);

	/*
	 * Don't create dirty pages faster than they
	 * can be cleaned ... (etc. see nfs)
	 *
	 * Here NFS also tests:
	 *  (mi->mi_max_threads != 0 &&
	 *  rp->r_awcount > 2 * mi->mi_max_threads)
	 */
	if (rw == S_CREATE) {
		while (np->r_gcount > 0)
			cv_wait(&np->r_cv, &np->r_statelock);
	}

	/*
	 * If we are getting called as a side effect of a write
	 * operation the local file size might not be extended yet.
	 * In this case we want to be able to return pages of zeroes.
	 */
	if (off + len > np->r_size + PAGEOFFSET && seg != segkmap) {
		mutex_exit(&np->r_statelock);
		return (EFAULT);		/* beyond EOF */
	}

	mutex_exit(&np->r_statelock);

	error = pvn_getpages(smbfs_getapage, vp, off, len, protp,
	    pl, plsz, seg, addr, rw, cr);

	switch (error) {
	case SMBFS_EOF:
		smbfs_purge_caches(vp, cr);
		goto retry;
	case ESTALE:
		/*
		 * Here NFS has: PURGE_STALE_FH(error, vp, cr);
		 * In-line here as we only use it once.
		 */
		mutex_enter(&np->r_statelock);
		np->r_flags |= RSTALE;
		if (!np->r_error)
			np->r_error = (error);
		mutex_exit(&np->r_statelock);
		if (vn_has_cached_data(vp))
			smbfs_invalidate_pages(vp, (u_offset_t)0, cr);
		smbfs_purge_caches(vp, cr);
		break;
	default:
		break;
	}

	return (error);
}

/*
 * Called from pvn_getpages to get a particular page.
 * Like nfs3_getapage
 */
/* ARGSUSED */
static int
smbfs_getapage(vnode_t *vp, u_offset_t off, size_t len, uint_t *protp,
	page_t *pl[], size_t plsz, struct seg *seg, caddr_t addr,
	enum seg_rw rw, cred_t *cr)
{
	smbnode_t	*np;
	smbmntinfo_t   *smi;

	uint_t		bsize;
	struct buf	*bp;
	page_t		*pp;
	u_offset_t	lbn;
	u_offset_t	io_off;
	u_offset_t	blkoff;
	size_t		io_len;
	uint_t blksize;
	int error;
	/* int readahead; */
	int readahead_issued = 0;
	/* int ra_window; * readahead window */
	page_t *pagefound;

	np = VTOSMB(vp);
	smi = VTOSMI(vp);

	if (curproc->p_zone != smi->smi_zone_ref.zref_zone)
		return (EIO);

	if (smi->smi_flags & SMI_DEAD || vp->v_vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	bsize = MAX(vp->v_vfsp->vfs_bsize, PAGESIZE);

reread:
	bp = NULL;
	pp = NULL;
	pagefound = NULL;

	if (pl != NULL)
		pl[0] = NULL;

	error = 0;
	lbn = off / bsize;
	blkoff = lbn * bsize;

	/*
	 * NFS queues up readahead work here.
	 */

again:
	if ((pagefound = page_exists(vp, off)) == NULL) {
		if (pl == NULL) {
			(void) 0; /* Todo: smbfs_async_readahead(); */
		} else if (rw == S_CREATE) {
			/*
			 * Block for this page is not allocated, or the offset
			 * is beyond the current allocation size, or we're
			 * allocating a swap slot and the page was not found,
			 * so allocate it and return a zero page.
			 */
			if ((pp = page_create_va(vp, off,
			    PAGESIZE, PG_WAIT, seg, addr)) == NULL)
				cmn_err(CE_PANIC, "smbfs_getapage: page_create");
			io_len = PAGESIZE;
			mutex_enter(&np->r_statelock);
			np->r_nextr = off + PAGESIZE;
			mutex_exit(&np->r_statelock);
		} else {
			/*
			 * Need to go to server to get a BLOCK, exception to
			 * that being while reading at offset = 0 or doing
			 * random i/o, in that case read only a PAGE.
			 */
			mutex_enter(&np->r_statelock);
			if (blkoff < np->r_size &&
			    blkoff + bsize >= np->r_size) {
				/*
				 * If only a block or less is left in
				 * the file, read all that is remaining.
				 */
				if (np->r_size <= off) {
					/*
					 * Trying to access beyond EOF,
					 * set up to get at least one page.
					 */
					blksize = off + PAGESIZE - blkoff;
				} else
					blksize = np->r_size - blkoff;
			} else if ((off == 0) ||
			    (off != np->r_nextr && !readahead_issued)) {
				blksize = PAGESIZE;
				blkoff = off; /* block = page here */
			} else
				blksize = bsize;
			mutex_exit(&np->r_statelock);

			pp = pvn_read_kluster(vp, off, seg, addr, &io_off,
			    &io_len, blkoff, blksize, 0);

			/*
			 * Some other thread has entered the page,
			 * so just use it.
			 */
			if (pp == NULL)
				goto again;

			/*
			 * Now round the request size up to page boundaries.
			 * This ensures that the entire page will be
			 * initialized to zeroes if EOF is encountered.
			 */
			io_len = ptob(btopr(io_len));

			bp = pageio_setup(pp, io_len, vp, B_READ);
			ASSERT(bp != NULL);

			/*
			 * pageio_setup should have set b_addr to 0.  This
			 * is correct since we want to do I/O on a page
			 * boundary.  bp_mapin will use this addr to calculate
			 * an offset, and then set b_addr to the kernel virtual
			 * address it allocated for us.
			 */
			ASSERT(bp->b_un.b_addr == 0);

			bp->b_edev = 0;
			bp->b_dev = 0;
			bp->b_lblkno = lbtodb(io_off);
			bp->b_file = vp;
			bp->b_offset = (offset_t)off;
			bp_mapin(bp);

			/*
			 * If doing a write beyond what we believe is EOF,
			 * don't bother trying to read the pages from the
			 * server, we'll just zero the pages here.  We
			 * don't check that the rw flag is S_WRITE here
			 * because some implementations may attempt a
			 * read access to the buffer before copying data.
			 */
			mutex_enter(&np->r_statelock);
			if (io_off >= np->r_size && seg == segkmap) {
				mutex_exit(&np->r_statelock);
				bzero(bp->b_un.b_addr, io_len);
			} else {
				mutex_exit(&np->r_statelock);
				error = smbfs_bio(bp, 0, cr);
			}

			/*
			 * Unmap the buffer before freeing it.
			 */
			bp_mapout(bp);
			pageio_done(bp);

			/* Here NFS3 updates all pp->p_fsdata */

			if (error == SMBFS_EOF) {
				/*
				 * If doing a write system call just return
				 * zeroed pages, else user tried to get pages
				 * beyond EOF, return error.  We don't check
				 * that the rw flag is S_WRITE here because
				 * some implementations may attempt a read
				 * access to the buffer before copying data.
				 */
				if (seg == segkmap)
					error = 0;
				else
					error = EFAULT;
			}

			if (!readahead_issued && !error) {
				mutex_enter(&np->r_statelock);
				np->r_nextr = io_off + io_len;
				mutex_exit(&np->r_statelock);
			}
		}
	}

	if (pl == NULL)
		return (error);

	if (error) {
		if (pp != NULL)
			pvn_read_done(pp, B_ERROR);
		return (error);
	}

	if (pagefound) {
		se_t se = (rw == S_CREATE ? SE_EXCL : SE_SHARED);

		/*
		 * Page exists in the cache, acquire the appropriate lock.
		 * If this fails, start all over again.
		 */
		if ((pp = page_lookup(vp, off, se)) == NULL) {
#ifdef DEBUG
			smbfs_lostpage++;
#endif
			goto reread;
		}
		pl[0] = pp;
		pl[1] = NULL;
		return (0);
	}

	if (pp != NULL)
		pvn_plist_init(pp, pl, plsz, off, io_len, rw);

	return (error);
}

/*
 * Here NFS has: nfs3_readahead
 * No read-ahead in smbfs yet.
 */

/*
 * Flags are composed of {B_INVAL, B_FREE, B_DONTNEED, B_FORCE}
 * If len == 0, do from off to EOF.
 *
 * The normal cases should be len == 0 && off == 0 (entire vp list),
 * len == MAXBSIZE (from segmap_release actions), and len == PAGESIZE
 * (from pageout).
 *
 * Like nfs3_putpage + nfs_putpages
 */
/* ARGSUSED */
static int
smbfs_putpage(vnode_t *vp, offset_t off, size_t len, int flags, cred_t *cr,
	caller_context_t *ct)
{
	smbnode_t *np;
	smbmntinfo_t *smi;
	page_t *pp;
	u_offset_t eoff;
	u_offset_t io_off;
	size_t io_len;
	int error;
	int rdirty;
	int err;

	np = VTOSMB(vp);
	smi = VTOSMI(vp);

	if (curproc->p_zone != smi->smi_zone_ref.zref_zone)
		return (EIO);

	if (smi->smi_flags & SMI_DEAD || vp->v_vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	/* Here NFS does rp->r_count (++/--) stuff. */

	/* Beginning of code from nfs_putpages. */

	if (!vn_has_cached_data(vp))
		return (0);

	/*
	 * If ROUTOFSPACE is set, then all writes turn into B_INVAL
	 * writes.  B_FORCE is set to force the VM system to actually
	 * invalidate the pages, even if the i/o failed.  The pages
	 * need to get invalidated because they can't be written out
	 * because there isn't any space left on either the server's
	 * file system or in the user's disk quota.  The B_FREE bit
	 * is cleared to avoid confusion as to whether this is a
	 * request to place the page on the freelist or to destroy
	 * it.
	 */
	if ((np->r_flags & ROUTOFSPACE) ||
	    (vp->v_vfsp->vfs_flag & VFS_UNMOUNTED))
		flags = (flags & ~B_FREE) | B_INVAL | B_FORCE;

	if (len == 0) {
		/*
		 * If doing a full file synchronous operation, then clear
		 * the RDIRTY bit.  If a page gets dirtied while the flush
		 * is happening, then RDIRTY will get set again.  The
		 * RDIRTY bit must get cleared before the flush so that
		 * we don't lose this information.
		 *
		 * NFS has B_ASYNC vs sync stuff here.
		 */
		if (off == (u_offset_t)0 &&
		    (np->r_flags & RDIRTY)) {
			mutex_enter(&np->r_statelock);
			rdirty = (np->r_flags & RDIRTY);
			np->r_flags &= ~RDIRTY;
			mutex_exit(&np->r_statelock);
		} else
			rdirty = 0;

		/*
		 * Search the entire vp list for pages >= off, and flush
		 * the dirty pages.
		 */
		error = pvn_vplist_dirty(vp, off, smbfs_putapage,
		    flags, cr);

		/*
		 * If an error occurred and the file was marked as dirty
		 * before and we aren't forcibly invalidating pages, then
		 * reset the RDIRTY flag.
		 */
		if (error && rdirty &&
		    (flags & (B_INVAL | B_FORCE)) != (B_INVAL | B_FORCE)) {
			mutex_enter(&np->r_statelock);
			np->r_flags |= RDIRTY;
			mutex_exit(&np->r_statelock);
		}
	} else {
		/*
		 * Do a range from [off...off + len) looking for pages
		 * to deal with.
		 */
		error = 0;
		io_len = 1; /* quiet warnings */
		eoff = off + len;

		for (io_off = off; io_off < eoff; io_off += io_len) {
			mutex_enter(&np->r_statelock);
			if (io_off >= np->r_size) {
				mutex_exit(&np->r_statelock);
				break;
			}
			mutex_exit(&np->r_statelock);
			/*
			 * If we are not invalidating, synchronously
			 * freeing or writing pages use the routine
			 * page_lookup_nowait() to prevent reclaiming
			 * them from the free list.
			 */
			if ((flags & B_INVAL) || !(flags & B_ASYNC)) {
				pp = page_lookup(vp, io_off,
				    (flags & (B_INVAL | B_FREE)) ?
				    SE_EXCL : SE_SHARED);
			} else {
				pp = page_lookup_nowait(vp, io_off,
				    (flags & B_FREE) ? SE_EXCL : SE_SHARED);
			}

			if (pp == NULL || !pvn_getdirty(pp, flags))
				io_len = PAGESIZE;
			else {
				err = smbfs_putapage(vp, pp, &io_off,
				    &io_len, flags, cr);
				if (!error)
					error = err;
				/*
				 * "io_off" and "io_len" are returned as
				 * the range of pages we actually wrote.
				 * This allows us to skip ahead more quickly
				 * since several pages may've been dealt
				 * with by this iteration of the loop.
				 */
			}
		}
	}

	return (error);
}

/*
 * Write out a single page, possibly klustering adjacent dirty pages.
 *
 * Like nfs3_putapage / nfs3_sync_putapage
 */
static int
smbfs_putapage(vnode_t *vp, page_t *pp, u_offset_t *offp, size_t *lenp,
	int flags, cred_t *cr)
{
	smbnode_t *np;
	u_offset_t io_off;
	u_offset_t lbn_off;
	u_offset_t lbn;
	size_t io_len;
	uint_t bsize;
	int error;

	np = VTOSMB(vp);

	ASSERT(!vn_is_readonly(vp));

	bsize = MAX(vp->v_vfsp->vfs_bsize, PAGESIZE);
	lbn = pp->p_offset / bsize;
	lbn_off = lbn * bsize;

	/*
	 * Find a kluster that fits in one block, or in
	 * one page if pages are bigger than blocks.  If
	 * there is less file space allocated than a whole
	 * page, we'll shorten the i/o request below.
	 */
	pp = pvn_write_kluster(vp, pp, &io_off, &io_len, lbn_off,
	    roundup(bsize, PAGESIZE), flags);

	/*
	 * pvn_write_kluster shouldn't have returned a page with offset
	 * behind the original page we were given.  Verify that.
	 */
	ASSERT((pp->p_offset / bsize) >= lbn);

	/*
	 * Now pp will have the list of kept dirty pages marked for
	 * write back.  It will also handle invalidation and freeing
	 * of pages that are not dirty.  Check for page length rounding
	 * problems.
	 */
	if (io_off + io_len > lbn_off + bsize) {
		ASSERT((io_off + io_len) - (lbn_off + bsize) < PAGESIZE);
		io_len = lbn_off + bsize - io_off;
	}
	/*
	 * The RMODINPROGRESS flag makes sure that smbfs_bio() sees a
	 * consistent value of r_size. RMODINPROGRESS is set in writerp().
	 * When RMODINPROGRESS is set it indicates that a uiomove() is in
	 * progress and the r_size has not been made consistent with the
	 * new size of the file. When the uiomove() completes the r_size is
	 * updated and the RMODINPROGRESS flag is cleared.
	 *
	 * The RMODINPROGRESS flag makes sure that smbfs_bio() sees a
	 * consistent value of r_size. Without this handshaking, it is
	 * possible that smbfs_bio() picks  up the old value of r_size
	 * before the uiomove() in writerp() completes. This will result
	 * in the write through smbfs_bio() being dropped.
	 *
	 * More precisely, there is a window between the time the uiomove()
	 * completes and the time the r_size is updated. If a VOP_PUTPAGE()
	 * operation intervenes in this window, the page will be picked up,
	 * because it is dirty (it will be unlocked, unless it was
	 * pagecreate'd). When the page is picked up as dirty, the dirty
	 * bit is reset (pvn_getdirty()). In smbfs_write(), r_size is
	 * checked. This will still be the old size. Therefore the page will
	 * not be written out. When segmap_release() calls VOP_PUTPAGE(),
	 * the page will be found to be clean and the write will be dropped.
	 */
	if (np->r_flags & RMODINPROGRESS) {
		mutex_enter(&np->r_statelock);
		if ((np->r_flags & RMODINPROGRESS) &&
		    np->r_modaddr + MAXBSIZE > io_off &&
		    np->r_modaddr < io_off + io_len) {
			page_t *plist;
			/*
			 * A write is in progress for this region of the file.
			 * If we did not detect RMODINPROGRESS here then this
			 * path through smbfs_putapage() would eventually go to
			 * smbfs_bio() and may not write out all of the data
			 * in the pages. We end up losing data. So we decide
			 * to set the modified bit on each page in the page
			 * list and mark the rnode with RDIRTY. This write
			 * will be restarted at some later time.
			 */
			plist = pp;
			while (plist != NULL) {
				pp = plist;
				page_sub(&plist, pp);
				hat_setmod(pp);
				page_io_unlock(pp);
				page_unlock(pp);
			}
			np->r_flags |= RDIRTY;
			mutex_exit(&np->r_statelock);
			if (offp)
				*offp = io_off;
			if (lenp)
				*lenp = io_len;
			return (0);
		}
		mutex_exit(&np->r_statelock);
	}

	/*
	 * NFS handles (flags & B_ASYNC) here...
	 * (See nfs_async_putapage())
	 *
	 * This code section from: nfs3_sync_putapage()
	 */

	flags |= B_WRITE;

	error = smbfs_rdwrlbn(vp, pp, io_off, io_len, flags, cr);

	if ((error == ENOSPC || error == EDQUOT || error == EFBIG ||
	    error == EACCES) &&
	    (flags & (B_INVAL|B_FORCE)) != (B_INVAL|B_FORCE)) {
		if (!(np->r_flags & ROUTOFSPACE)) {
			mutex_enter(&np->r_statelock);
			np->r_flags |= ROUTOFSPACE;
			mutex_exit(&np->r_statelock);
		}
		flags |= B_ERROR;
		pvn_write_done(pp, flags);
		/*
		 * If this was not an async thread, then try again to
		 * write out the pages, but this time, also destroy
		 * them whether or not the write is successful.  This
		 * will prevent memory from filling up with these
		 * pages and destroying them is the only alternative
		 * if they can't be written out.
		 *
		 * Don't do this if this is an async thread because
		 * when the pages are unlocked in pvn_write_done,
		 * some other thread could have come along, locked
		 * them, and queued for an async thread.  It would be
		 * possible for all of the async threads to be tied
		 * up waiting to lock the pages again and they would
		 * all already be locked and waiting for an async
		 * thread to handle them.  Deadlock.
		 */
		if (!(flags & B_ASYNC)) {
			error = smbfs_putpage(vp, io_off, io_len,
			    B_INVAL | B_FORCE, cr, NULL);
		}
	} else {
		if (error)
			flags |= B_ERROR;
		else if (np->r_flags & ROUTOFSPACE) {
			mutex_enter(&np->r_statelock);
			np->r_flags &= ~ROUTOFSPACE;
			mutex_exit(&np->r_statelock);
		}
		pvn_write_done(pp, flags);
	}

	/* Now more code from: nfs3_putapage */

	if (offp)
		*offp = io_off;
	if (lenp)
		*lenp = io_len;

	return (error);
}

/*
 * NFS has this in nfs_client.c (shared by v2,v3,...)
 * We have it here so smbfs_putapage can be file scope.
 */
void
smbfs_invalidate_pages(vnode_t *vp, u_offset_t off, cred_t *cr)
{
	smbnode_t *np;

	np = VTOSMB(vp);

	mutex_enter(&np->r_statelock);
	while (np->r_flags & RTRUNCATE)
		cv_wait(&np->r_cv, &np->r_statelock);
	np->r_flags |= RTRUNCATE;

	if (off == (u_offset_t)0) {
		np->r_flags &= ~RDIRTY;
		if (!(np->r_flags & RSTALE))
			np->r_error = 0;
	}
	/* Here NFSv3 has np->r_truncaddr = off; */
	mutex_exit(&np->r_statelock);

	(void) pvn_vplist_dirty(vp, off, smbfs_putapage,
	    B_INVAL | B_TRUNC, cr);

	mutex_enter(&np->r_statelock);
	np->r_flags &= ~RTRUNCATE;
	cv_broadcast(&np->r_cv);
	mutex_exit(&np->r_statelock);
}

/* Like nfs3_map */

/* ARGSUSED */
static int
smbfs_map(vnode_t *vp, offset_t off, struct as *as, caddr_t *addrp,
	size_t len, uchar_t prot, uchar_t maxprot, uint_t flags,
	cred_t *cr, caller_context_t *ct)
{
	segvn_crargs_t	vn_a;
	struct vattr	va;
	smbnode_t	*np;
	smbmntinfo_t	*smi;
	int		error;

	np = VTOSMB(vp);
	smi = VTOSMI(vp);

	if (curproc->p_zone != smi->smi_zone_ref.zref_zone)
		return (EIO);

	if (smi->smi_flags & SMI_DEAD || vp->v_vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	if (off < 0 || off + (ssize_t)len < 0)
		return (ENXIO);

	if (vp->v_type != VREG)
		return (ENODEV);

	/*
	 * NFS does close-to-open consistency stuff here.
	 * Just get (possibly cached) attributes.
	 */
	va.va_mask = AT_ALL;
	if ((error = smbfsgetattr(vp, &va, cr)) != 0)
		return (error);

	/*
	 * Check to see if the vnode is currently marked as not cachable.
	 * This means portions of the file are locked (through VOP_FRLOCK).
	 * In this case the map request must be refused.  We use
	 * rp->r_lkserlock to avoid a race with concurrent lock requests.
	 */
	/*
	 * Atomically increment r_inmap after acquiring r_rwlock. The
	 * idea here is to acquire r_rwlock to block read/write and
	 * not to protect r_inmap. r_inmap will inform smbfs_read/write()
	 * that we are in smbfs_map(). Now, r_rwlock is acquired in order
	 * and we can prevent the deadlock that would have occurred
	 * when smbfs_addmap() would have acquired it out of order.
	 *
	 * Since we are not protecting r_inmap by any lock, we do not
	 * hold any lock when we decrement it. We atomically decrement
	 * r_inmap after we release r_lkserlock.  Note that rwlock is
	 * re-entered as writer in smbfs_addmap (called via as_map).
	 */

	if (smbfs_rw_enter_sig(&np->r_rwlock, RW_WRITER, SMBINTR(vp)))
		return (EINTR);
	atomic_inc_uint(&np->r_inmap);
	smbfs_rw_exit(&np->r_rwlock);

	if (smbfs_rw_enter_sig(&np->r_lkserlock, RW_WRITER, SMBINTR(vp))) {
		atomic_dec_uint(&np->r_inmap);
		return (EINTR);
	}

	if (vp->v_flag & VNOCACHE) {
		error = EAGAIN;
		goto done;
	}

	/*
	 * Don't allow concurrent locks and mapping if mandatory locking is
	 * enabled.
	 */
	if ((flk_has_remote_locks(vp) || smbfs_lm_has_sleep(vp)) &&
	    MANDLOCK(vp, va.va_mode)) {
		error = EAGAIN;
		goto done;
	}

	as_rangelock(as);
	error = choose_addr(as, addrp, len, off, ADDR_VACALIGN, flags);
	if (error != 0) {
		as_rangeunlock(as);
		goto done;
	}

	vn_a.vp = vp;
	vn_a.offset = off;
	vn_a.type = (flags & MAP_TYPE);
	vn_a.prot = (uchar_t)prot;
	vn_a.maxprot = (uchar_t)maxprot;
	vn_a.flags = (flags & ~MAP_TYPE);
	vn_a.cred = cr;
	vn_a.amp = NULL;
	vn_a.szc = 0;
	vn_a.lgrp_mem_policy_flags = 0;

	error = as_map(as, *addrp, len, segvn_create, &vn_a);
	as_rangeunlock(as);

done:
	smbfs_rw_exit(&np->r_lkserlock);
	atomic_dec_uint(&np->r_inmap);
	return (error);
}

/* ARGSUSED */
static int
smbfs_addmap(vnode_t *vp, offset_t off, struct as *as, caddr_t addr,
	size_t len, uchar_t prot, uchar_t maxprot, uint_t flags,
	cred_t *cr, caller_context_t *ct)
{
	smbnode_t *np = VTOSMB(vp);
	boolean_t inc_fidrefs = B_FALSE;

	/*
	 * When r_mapcnt goes from zero to non-zero,
	 * increment n_fidrefs
	 */
	mutex_enter(&np->r_statelock);
	if (np->r_mapcnt == 0)
		inc_fidrefs = B_TRUE;
	np->r_mapcnt += btopr(len);
	mutex_exit(&np->r_statelock);

	if (inc_fidrefs) {
		(void) smbfs_rw_enter_sig(&np->r_lkserlock, RW_WRITER, 0);
		np->n_fidrefs++;
		smbfs_rw_exit(&np->r_lkserlock);
	}

	return (0);
}

/*
 * Use an address space callback to flush pages dirty pages after unmap,
 * which we can't do directly in smbfs_delmap due to locking issues.
 */
typedef struct smbfs_delmap_args {
	vnode_t			*vp;
	cred_t			*cr;
	offset_t		off;
	caddr_t			addr;
	size_t			len;
	uint_t			prot;
	uint_t			maxprot;
	uint_t			flags;
	boolean_t		dec_fidrefs;
} smbfs_delmap_args_t;

/* ARGSUSED */
static int
smbfs_delmap(vnode_t *vp, offset_t off, struct as *as, caddr_t addr,
	size_t len, uint_t prot, uint_t maxprot, uint_t flags,
	cred_t *cr, caller_context_t *ct)
{
	smbnode_t *np = VTOSMB(vp);
	smbfs_delmap_args_t	*dmapp;
	int error;

	dmapp = kmem_zalloc(sizeof (*dmapp), KM_SLEEP);

	dmapp->vp = vp;
	dmapp->off = off;
	dmapp->addr = addr;
	dmapp->len = len;
	dmapp->prot = prot;
	dmapp->maxprot = maxprot;
	dmapp->flags = flags;
	dmapp->cr = cr;
	dmapp->dec_fidrefs = B_FALSE;

	/*
	 * When r_mapcnt returns to zero, arrange for the
	 * callback to decrement n_fidrefs
	 */
	mutex_enter(&np->r_statelock);
	np->r_mapcnt -= btopr(len);
	ASSERT(np->r_mapcnt >= 0);
	if (np->r_mapcnt == 0)
		dmapp->dec_fidrefs = B_TRUE;
	mutex_exit(&np->r_statelock);

	error = as_add_callback(as, smbfs_delmap_callback, dmapp,
	    AS_UNMAP_EVENT, addr, len, KM_SLEEP);
	if (error != 0) {
		/*
		 * So sad, no callback is coming. Can't flush pages
		 * in delmap (as locks).  Just handle n_fidrefs.
		 */
		cmn_err(CE_NOTE, "smbfs_delmap(%p) "
		    "as_add_callback err=%d",
		    (void *)vp, error);

		if (dmapp->dec_fidrefs) {
			struct smb_cred scred;

			(void) smbfs_rw_enter_sig(&np->r_lkserlock,
			    RW_WRITER, 0);
			smb_credinit(&scred, dmapp->cr);

			smbfs_rele_fid(np, &scred);

			smb_credrele(&scred);
			smbfs_rw_exit(&np->r_lkserlock);
		}
		kmem_free(dmapp, sizeof (*dmapp));
	}

	return (0);
}

/*
 * Remove some pages from an mmap'd vnode.  Flush any
 * dirty pages in the unmapped range.
 */
/* ARGSUSED */
static void
smbfs_delmap_callback(struct as *as, void *arg, uint_t event)
{
	vnode_t			*vp;
	smbnode_t		*np;
	smbmntinfo_t		*smi;
	smbfs_delmap_args_t	*dmapp = arg;

	vp = dmapp->vp;
	np = VTOSMB(vp);
	smi = VTOSMI(vp);

	/* Decremented r_mapcnt in smbfs_delmap */

	/*
	 * Initiate a page flush and potential commit if there are
	 * pages, the file system was not mounted readonly, the segment
	 * was mapped shared, and the pages themselves were writeable.
	 *
	 * mark RDIRTY here, will be used to check if a file is dirty when
	 * unmount smbfs
	 */
	if (vn_has_cached_data(vp) && !vn_is_readonly(vp) &&
	    dmapp->flags == MAP_SHARED && (dmapp->maxprot & PROT_WRITE)) {
		mutex_enter(&np->r_statelock);
		np->r_flags |= RDIRTY;
		mutex_exit(&np->r_statelock);

		/*
		 * Need to finish the putpage before we
		 * close the OtW FID needed for I/O.
		 */
		(void) smbfs_putpage(vp, dmapp->off, dmapp->len, 0,
		    dmapp->cr, NULL);
	}

	if ((np->r_flags & RDIRECTIO) || (smi->smi_flags & SMI_DIRECTIO))
		(void) smbfs_putpage(vp, dmapp->off, dmapp->len,
		    B_INVAL, dmapp->cr, NULL);

	/*
	 * If r_mapcnt went to zero, drop our FID ref now.
	 * On the last fidref, this does an OtW close.
	 */
	if (dmapp->dec_fidrefs) {
		struct smb_cred scred;

		(void) smbfs_rw_enter_sig(&np->r_lkserlock, RW_WRITER, 0);
		smb_credinit(&scred, dmapp->cr);

		smbfs_rele_fid(np, &scred);

		smb_credrele(&scred);
		smbfs_rw_exit(&np->r_lkserlock);
	}

	(void) as_delete_callback(as, arg);
	kmem_free(dmapp, sizeof (*dmapp));
}

/* No smbfs_pageio() or smbfs_dispose() ops. */

/* misc. ******************************************************** */


/*
 * XXX
 * This op may need to support PSARC 2007/440, nbmand changes for CIFS Service.
 */
static int
smbfs_frlock(vnode_t *vp, int cmd, struct flock64 *bfp, int flag,
	offset_t offset, struct flk_callback *flk_cbp, cred_t *cr,
	caller_context_t *ct)
{
	if (curproc->p_zone != VTOSMI(vp)->smi_zone_ref.zref_zone)
		return (EIO);

	if (VTOSMI(vp)->smi_flags & SMI_LLOCK)
		return (fs_frlock(vp, cmd, bfp, flag, offset, flk_cbp, cr, ct));
	else
		return (ENOSYS);
}

/*
 * Free storage space associated with the specified vnode.  The portion
 * to be freed is specified by bfp->l_start and bfp->l_len (already
 * normalized to a "whence" of 0).
 *
 * Called by fcntl(fd, F_FREESP, lkp) for libc:ftruncate, etc.
 */
/* ARGSUSED */
static int
smbfs_space(vnode_t *vp, int cmd, struct flock64 *bfp, int flag,
	offset_t offset, cred_t *cr, caller_context_t *ct)
{
	int		error;
	smbmntinfo_t	*smi;

	smi = VTOSMI(vp);

	if (curproc->p_zone != smi->smi_zone_ref.zref_zone)
		return (EIO);

	if (smi->smi_flags & SMI_DEAD || vp->v_vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	/* Caller (fcntl) has checked v_type */
	ASSERT(vp->v_type == VREG);
	if (cmd != F_FREESP)
		return (EINVAL);

	/*
	 * Like NFS3, no 32-bit offset checks here.
	 * Our SMB layer takes care to return EFBIG
	 * when it has to fallback to a 32-bit call.
	 */

	error = convoff(vp, bfp, 0, offset);
	if (!error) {
		ASSERT(bfp->l_start >= 0);
		if (bfp->l_len == 0) {
			struct vattr va;

			/*
			 * ftruncate should not change the ctime and
			 * mtime if we truncate the file to its
			 * previous size.
			 */
			va.va_mask = AT_SIZE;
			error = smbfsgetattr(vp, &va, cr);
			if (error || va.va_size == bfp->l_start)
				return (error);
			va.va_mask = AT_SIZE;
			va.va_size = bfp->l_start;
			error = smbfssetattr(vp, &va, 0, cr);
			/* SMBFS_VNEVENT... */
		} else
			error = EINVAL;
	}

	return (error);
}


/* ARGSUSED */
static int
smbfs_realvp(vnode_t *vp, vnode_t **vpp, caller_context_t *ct)
{

	return (ENOSYS);
}


/* ARGSUSED */
static int
smbfs_pathconf(vnode_t *vp, int cmd, ulong_t *valp, cred_t *cr,
	caller_context_t *ct)
{
	vfs_t *vfs;
	smbmntinfo_t *smi;
	struct smb_share *ssp;

	vfs = vp->v_vfsp;
	smi = VFTOSMI(vfs);

	if (curproc->p_zone != smi->smi_zone_ref.zref_zone)
		return (EIO);

	if (smi->smi_flags & SMI_DEAD || vp->v_vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	switch (cmd) {
	case _PC_FILESIZEBITS:
		ssp = smi->smi_share;
		if (SSTOVC(ssp)->vc_sopt.sv_caps & SMB_CAP_LARGE_FILES)
			*valp = 64;
		else
			*valp = 32;
		break;

	case _PC_LINK_MAX:
		/* We only ever report one link to an object */
		*valp = 1;
		break;

	case _PC_ACL_ENABLED:
		/*
		 * Always indicate that ACLs are enabled and
		 * that we support ACE_T format, otherwise
		 * libsec will ask for ACLENT_T format data
		 * which we don't support.
		 */
		*valp = _ACL_ACE_ENABLED;
		break;

	case _PC_SYMLINK_MAX:	/* No symlinks until we do Unix extensions */
		*valp = 0;
		break;

	case _PC_XATTR_EXISTS:
		if (vfs->vfs_flag & VFS_XATTR) {
			*valp = smbfs_xa_exists(vp, cr);
			break;
		}
		return (EINVAL);

	case _PC_SATTR_ENABLED:
	case _PC_SATTR_EXISTS:
		*valp = 1;
		break;

	case _PC_TIMESTAMP_RESOLUTION:
		/*
		 * Windows times are tenths of microseconds
		 * (multiples of 100 nanoseconds).
		 */
		*valp = 100L;
		break;

	default:
		return (fs_pathconf(vp, cmd, valp, cr, ct));
	}
	return (0);
}

/* ARGSUSED */
static int
smbfs_getsecattr(vnode_t *vp, vsecattr_t *vsa, int flag, cred_t *cr,
	caller_context_t *ct)
{
	vfs_t *vfsp;
	smbmntinfo_t *smi;
	int	error;
	uint_t	mask;

	vfsp = vp->v_vfsp;
	smi = VFTOSMI(vfsp);

	if (curproc->p_zone != smi->smi_zone_ref.zref_zone)
		return (EIO);

	if (smi->smi_flags & SMI_DEAD || vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	/*
	 * Our _pathconf indicates _ACL_ACE_ENABLED,
	 * so we should only see VSA_ACE, etc here.
	 * Note: vn_create asks for VSA_DFACLCNT,
	 * and it expects ENOSYS and empty data.
	 */
	mask = vsa->vsa_mask & (VSA_ACE | VSA_ACECNT |
	    VSA_ACE_ACLFLAGS | VSA_ACE_ALLTYPES);
	if (mask == 0)
		return (ENOSYS);

	if (smi->smi_flags & SMI_ACL)
		error = smbfs_acl_getvsa(vp, vsa, flag, cr);
	else
		error = ENOSYS;

	if (error == ENOSYS)
		error = fs_fab_acl(vp, vsa, flag, cr, ct);

	return (error);
}

/* ARGSUSED */
static int
smbfs_setsecattr(vnode_t *vp, vsecattr_t *vsa, int flag, cred_t *cr,
	caller_context_t *ct)
{
	vfs_t *vfsp;
	smbmntinfo_t *smi;
	int	error;
	uint_t	mask;

	vfsp = vp->v_vfsp;
	smi = VFTOSMI(vfsp);

	if (curproc->p_zone != smi->smi_zone_ref.zref_zone)
		return (EIO);

	if (smi->smi_flags & SMI_DEAD || vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	/*
	 * Our _pathconf indicates _ACL_ACE_ENABLED,
	 * so we should only see VSA_ACE, etc here.
	 */
	mask = vsa->vsa_mask & (VSA_ACE | VSA_ACECNT);
	if (mask == 0)
		return (ENOSYS);

	if (vfsp->vfs_flag & VFS_RDONLY)
		return (EROFS);

	/*
	 * Allow only the mount owner to do this.
	 * See comments at smbfs_access_rwx.
	 */
	error = secpolicy_vnode_setdac(cr, smi->smi_uid);
	if (error != 0)
		return (error);

	if (smi->smi_flags & SMI_ACL)
		error = smbfs_acl_setvsa(vp, vsa, flag, cr);
	else
		error = ENOSYS;

	return (error);
}


/*
 * XXX
 * This op should eventually support PSARC 2007/268.
 */
static int
smbfs_shrlock(vnode_t *vp, int cmd, struct shrlock *shr, int flag, cred_t *cr,
	caller_context_t *ct)
{
	if (curproc->p_zone != VTOSMI(vp)->smi_zone_ref.zref_zone)
		return (EIO);

	if (VTOSMI(vp)->smi_flags & SMI_LLOCK)
		return (fs_shrlock(vp, cmd, shr, flag, cr, ct));
	else
		return (ENOSYS);
}


/*
 * Most unimplemented ops will return ENOSYS because of fs_nosys().
 * The only ops where that won't work are ACCESS (due to open(2)
 * failures) and ... (anything else left?)
 */
const fs_operation_def_t smbfs_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = smbfs_open },
	VOPNAME_CLOSE,		{ .vop_close = smbfs_close },
	VOPNAME_READ,		{ .vop_read = smbfs_read },
	VOPNAME_WRITE,		{ .vop_write = smbfs_write },
	VOPNAME_IOCTL,		{ .vop_ioctl = smbfs_ioctl },
	VOPNAME_GETATTR,	{ .vop_getattr = smbfs_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = smbfs_setattr },
	VOPNAME_ACCESS,		{ .vop_access = smbfs_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = smbfs_lookup },
	VOPNAME_CREATE,		{ .vop_create = smbfs_create },
	VOPNAME_REMOVE,		{ .vop_remove = smbfs_remove },
	VOPNAME_LINK,		{ .vop_link = smbfs_link },
	VOPNAME_RENAME,		{ .vop_rename = smbfs_rename },
	VOPNAME_MKDIR,		{ .vop_mkdir = smbfs_mkdir },
	VOPNAME_RMDIR,		{ .vop_rmdir = smbfs_rmdir },
	VOPNAME_READDIR,	{ .vop_readdir = smbfs_readdir },
	VOPNAME_SYMLINK,	{ .vop_symlink = smbfs_symlink },
	VOPNAME_READLINK,	{ .vop_readlink = smbfs_readlink },
	VOPNAME_FSYNC,		{ .vop_fsync = smbfs_fsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = smbfs_inactive },
	VOPNAME_FID,		{ .vop_fid = smbfs_fid },
	VOPNAME_RWLOCK,		{ .vop_rwlock = smbfs_rwlock },
	VOPNAME_RWUNLOCK,	{ .vop_rwunlock = smbfs_rwunlock },
	VOPNAME_SEEK,		{ .vop_seek = smbfs_seek },
	VOPNAME_FRLOCK,		{ .vop_frlock = smbfs_frlock },
	VOPNAME_SPACE,		{ .vop_space = smbfs_space },
	VOPNAME_REALVP,		{ .vop_realvp = smbfs_realvp },
	VOPNAME_GETPAGE,	{ .vop_getpage = smbfs_getpage },
	VOPNAME_PUTPAGE,	{ .vop_putpage = smbfs_putpage },
	VOPNAME_MAP,		{ .vop_map = smbfs_map },
	VOPNAME_ADDMAP,		{ .vop_addmap = smbfs_addmap },
	VOPNAME_DELMAP,		{ .vop_delmap = smbfs_delmap },
	VOPNAME_PATHCONF,	{ .vop_pathconf = smbfs_pathconf },
	VOPNAME_SETSECATTR,	{ .vop_setsecattr = smbfs_setsecattr },
	VOPNAME_GETSECATTR,	{ .vop_getsecattr = smbfs_getsecattr },
	VOPNAME_SHRLOCK,	{ .vop_shrlock = smbfs_shrlock },
#ifdef	SMBFS_VNEVENT
	VOPNAME_VNEVENT,	{ .vop_vnevent = fs_vnevent_support },
#endif
	{ NULL, NULL }
};

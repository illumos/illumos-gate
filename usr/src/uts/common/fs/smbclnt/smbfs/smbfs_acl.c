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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ACL support for smbfs
 */

#include <sys/systm.h>	/* bcopy, ... */
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/acl.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/byteorder.h>

#include <netsmb/smb_osdep.h>
#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>
#include <netsmb/mchain.h>

#include <smbfs/smbfs.h>
#include <smbfs/smbfs_node.h>
#include <smbfs/smbfs_subr.h>

#include <sys/fs/smbfs_ioctl.h>
#include <fs/fs_subr.h>

/* Sanity check SD sizes */
#define	MAX_RAW_SD_SIZE	32768
#define	SMALL_SD_SIZE	1024

#undef	ACL_SUPPORT	/* not yet */


/*
 * smbfs_getsd(), smbfs_setsd() are common functions used by
 * both ioctl get/set ACL and VOP_GETSECATTR, VOP_SETSECATTR.
 * Handles required rights, tmpopen/tmpclose.
 *
 * Note: smbfs_getsd allocates and returns an mblk chain,
 * which the caller must free.
 */
int
smbfs_getsd(vnode_t *vp, uint32_t selector, mblk_t **mp, cred_t *cr)
{
	struct smb_cred scred;
	int error, cerror;
	smbmntinfo_t *smi;
	smbnode_t	*np;
	u_int16_t	fid = SMB_FID_UNUSED;
	uint32_t	sdlen = SMALL_SD_SIZE;
	uint32_t	rights = STD_RIGHT_READ_CONTROL_ACCESS;

	if (selector & SACL_SECURITY_INFORMATION)
		rights |= SEC_RIGHT_SYSTEM_SECURITY;

	np = VTOSMB(vp);
	smi = VTOSMI(vp);

	/* Shared lock for (possible) n_fid use. */
	if (smbfs_rw_enter_sig(&np->r_lkserlock, RW_READER, SMBINTR(vp)))
		return (EINTR);
	smb_credinit(&scred, curproc, cr);

	error = smbfs_smb_tmpopen(np, rights, &scred, &fid);
	if (error)
		goto out;

again:
	/*
	 * This does the OTW Get
	 */
	error = smbfs_smb_getsec_m(smi->smi_share, fid,
	    &scred, selector, mp, &sdlen);
	/*
	 * Server may give us an error indicating that we
	 * need a larger data buffer to receive the SD,
	 * and the size we'll need.  Use the given size,
	 * but only after a sanity check.
	 *
	 * Let's check for specific error values here.
	 * The NT error is: STATUS_BUFFER_TOO_SMALL,
	 * or with old error codes, one of these:
	 * ERRSRV/ERRnoroom, ERRDOS/122, ERRDOS/111
	 * Those are mapped to: EMOREDATA, which is
	 * later converted to E2BIG.
	 */
	if (error == E2BIG &&
	    sdlen > SMALL_SD_SIZE &&
	    sdlen <= MAX_RAW_SD_SIZE)
		goto again;

	cerror = smbfs_smb_tmpclose(np, fid, &scred);
	if (cerror)
		SMBERROR("error %d closing file %s\n",
		    cerror, np->n_rpath);

out:
	smb_credrele(&scred);
	smbfs_rw_exit(&np->r_lkserlock);

	return (error);
}

int
smbfs_setsd(vnode_t *vp, uint32_t selector, mblk_t **mp, cred_t *cr)
{
	struct smb_cred scred;
	int error, cerror;
	smbmntinfo_t *smi;
	smbnode_t	*np;
	uint32_t	rights;
	u_int16_t	fid = SMB_FID_UNUSED;

	np = VTOSMB(vp);
	smi = VTOSMI(vp);

	/*
	 * Which parts of the SD are we setting?
	 * What rights do we need for that?
	 */
	if (selector == 0)
		return (0);
	rights = 0;
	if (selector & (OWNER_SECURITY_INFORMATION |
	    GROUP_SECURITY_INFORMATION))
		rights |= STD_RIGHT_WRITE_OWNER_ACCESS;
	if (selector & DACL_SECURITY_INFORMATION)
		rights |= STD_RIGHT_WRITE_DAC_ACCESS;
	if (selector & SACL_SECURITY_INFORMATION)
		rights |= SEC_RIGHT_SYSTEM_SECURITY;

	/* Shared lock for (possible) n_fid use. */
	if (smbfs_rw_enter_sig(&np->r_lkserlock, RW_READER, SMBINTR(vp)))
		return (EINTR);
	smb_credinit(&scred, curproc, cr);

	error = smbfs_smb_tmpopen(np, rights, &scred, &fid);
	if (error)
		goto out;

	/*
	 * This does the OTW Set
	 */
	error = smbfs_smb_setsec_m(smi->smi_share, fid,
	    &scred, selector, mp);

	cerror = smbfs_smb_tmpclose(np, fid, &scred);
	if (cerror)
		SMBERROR("error %d closing file %s\n",
		    cerror, np->n_rpath);

out:
	smb_credrele(&scred);
	smbfs_rw_exit(&np->r_lkserlock);

	return (error);
}

/*
 * Entry points from VOP_IOCTL
 */
int
smbfs_ioc_getsd(vnode_t *vp, intptr_t arg, int flag, cred_t *cr)
{
	ioc_sdbuf_t iocb;
	mdchain_t *mdp, md_store;
	mblk_t *m;
	void *ubuf;
	int error;

	/*
	 * Get the buffer information
	 */
	if (ddi_copyin((void *)arg, &iocb, sizeof (iocb), flag))
		return (EFAULT);

	/*
	 * This does the OTW Get (and maybe open, close)
	 * Allocates and returns an mblk in &m.
	 */
	error = smbfs_getsd(vp, iocb.selector, &m, cr);
	if (error)
		return (error);

	/*
	 * Have m.  Must free it before return.
	 */
	mdp = &md_store;
	md_initm(mdp, m);
	iocb.used = m_fixhdr(m);

	/*
	 * Always copyout the buffer information,
	 * so the user can realloc and try again
	 * after an EOVERFLOW return.
	 */
	if (ddi_copyout(&iocb, (void *)arg, sizeof (iocb), flag)) {
		error = EFAULT;
		goto out;
	}

	if (iocb.used > iocb.alloc) {
		error = EOVERFLOW;
		goto out;
	}

	/*
	 * Copyout the buffer contents (SD)
	 */
	ubuf = (void *)(uintptr_t)iocb.addr;
	error = md_get_mem(mdp, ubuf, iocb.used, MB_MUSER);

out:
	/* Note: m_freem(m) is done by... */
	md_done(mdp);

	return (error);
}

int
smbfs_ioc_setsd(vnode_t *vp, intptr_t arg, int flag, cred_t *cr)
{
	ioc_sdbuf_t iocb;
	mbchain_t *mbp, mb_store;
	void *ubuf;
	int error;

	/*
	 * Get the buffer information
	 */
	if (ddi_copyin((void *)arg, &iocb, sizeof (iocb), flag))
		return (EFAULT);

	if (iocb.used < sizeof (ntsecdesc_t) ||
	    iocb.used >= MAX_RAW_SD_SIZE)
		return (EINVAL);

	/*
	 * Get the buffer contents (security descriptor data)
	 */
	mbp = &mb_store;
	mb_init(mbp);
	ubuf = (void *)(uintptr_t)iocb.addr;
	error = mb_put_mem(mbp, ubuf, iocb.used, MB_MUSER);
	if (error)
		goto out;

	/*
	 * This does the OTW Set (and maybe open, close)
	 * It clears mb_top when consuming the message.
	 */
	error = smbfs_setsd(vp, iocb.selector, &mbp->mb_top, cr);

out:
	mb_done(mbp);
	return (error);

}

#ifdef	ACL_SUPPORT
/*
 * Conversion functions for VOP_GETSECATTR, VOP_SETSECATTR
 *
 * XXX: We may or may not add conversion code here, or we
 * may add that to usr/src/common (TBD).  For now all the
 * ACL conversion code is in libsmbfs.
 */

/*
 * Convert a Windows SD (in the mdchain mdp) into a
 * ZFS-style vsecattr_t and possibly uid, gid.
 */
/* ARGSUSED */
static int
smb_ntsd2vsec(mdchain_t *mdp, vsecattr_t *vsa,
	int *uidp, int *gidp, cred_t *cr)
{
	/* XXX NOT_YET */
	return (ENOSYS);
}

/*
 * Convert a ZFS-style vsecattr_t (and possibly uid, gid)
 * into a Windows SD (built in the mbchain mbp).
 */
/* ARGSUSED */
static int
smb_vsec2ntsd(vsecattr_t *vsa, int uid, int gid,
	mbchain_t *mbp, cred_t *cr)
{
	/* XXX NOT_YET */
	return (ENOSYS);
}
#endif	/* ACL_SUPPORT */

/*
 * Entry points from VOP_GETSECATTR, VOP_SETSECATTR
 *
 * Disabled the real _getacl functionality for now,
 * because we have no way to return the owner and
 * primary group until we replace our fake uid/gid
 * in getattr with something derived from _getsd.
 */

/* ARGSUSED */
int
smbfs_getacl(vnode_t *vp, vsecattr_t *vsa,
	int *uidp, int *gidp, int flag, cred_t *cr)
{
#ifdef	ACL_SUPPORT
	mdchain_t *mdp, md_store;
	mblk_t *m;
	uint32_t	selector;
	int		error;

	/*
	 * Which parts of the SD we request.
	 * XXX: We need a way to let the caller specify
	 * what parts she wants - i.e. the SACL?
	 * XXX: selector |= SACL_SECURITY_INFORMATION;
	 * Or maybe: if we get access denied, try the
	 * open/fetch again without the SACL bit.
	 */
	selector = 0;
	if (vsa)
		selector |= DACL_SECURITY_INFORMATION;
	if (uidp)
		selector |= OWNER_SECURITY_INFORMATION;
	if (gidp)
		selector |= GROUP_SECURITY_INFORMATION;
	if (selector == 0)
		return (0);

	/*
	 * This does the OTW Get (and maybe open, close)
	 * Allocates and returns an mblk in &m.
	 */
	error = smbfs_getsd(vp, selector, &m, cr);
	if (error)
		return (error);

	/*
	 * Have m.  Must free it before return.
	 */
	mdp = &md_store;
	md_initm(mdp, m);

	/*
	 * Convert the Windows security descriptor to a
	 * ZFS ACL (and owner ID, primary group ID).
	 * This is the difficult part. (todo)
	 */
	error = smb_ntsd2vsec(mdp, vsa, uidp, gidp, cr);

	/* Note: m_freem(m) is done by... */
	md_done(mdp);

	return (error);
#else	/* ACL_SUPPORT */
	return (ENOSYS);
#endif	/* ACL_SUPPORT */
}


/* ARGSUSED */
int
smbfs_setacl(vnode_t *vp, vsecattr_t *vsa,
	int uid, int gid, int flag, cred_t *cr)
{
#ifdef	ACL_SUPPORT
	mbchain_t *mbp, mb_store;
	uint32_t	selector;
	int		error;

	/*
	 * Which parts of the SD we'll modify.
	 * Ditto comments above re. SACL
	 */
	selector = 0;
	if (vsa)
		selector |= DACL_SECURITY_INFORMATION;
	if (uid != -1)
		selector |= OWNER_SECURITY_INFORMATION;
	if (gid != -1)
		selector |= GROUP_SECURITY_INFORMATION;
	if (selector == 0)
		return (0);

	/*
	 * Setup buffer for SD data.
	 */
	mbp = &mb_store;
	mb_init(mbp);

	/*
	 * Convert a ZFS ACL (and owner ID, group ID)
	 * to a Windows security descriptor.
	 * This is the difficult part. (todo)
	 */
	error = smb_vsec2ntsd(vsa, uid, gid, mbp, cr);
	if (error)
		goto out;

	/*
	 * This does the OTW Set (and maybe open, close)
	 * It clears mb_top when consuming the message.
	 */
	error = smbfs_setsd(vp, selector, &mbp->mb_top, cr);

out:
	mb_done(mbp);
	return (error);
#else	/* ACL_SUPPORT */
	return (ENOSYS);
#endif	/* ACL_SUPPORT */
}

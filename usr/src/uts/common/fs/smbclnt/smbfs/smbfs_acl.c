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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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

#include <netsmb/mchain.h>
#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_osdep.h>
#include <netsmb/smb_subr.h>

#include <smbfs/smbfs.h>
#include <smbfs/smbfs_node.h>
#include <smbfs/smbfs_subr.h>

#include <sys/fs/smbfs_ioctl.h>
#include <fs/fs_subr.h>
#include "smbfs_ntacl.h"

/* Sanity check SD sizes */
#define	MAX_RAW_SD_SIZE	32768
#define	SMALL_SD_SIZE	1024

/*
 * smbfs_getsd() is a common function used by both
 * smbfs_ioctl SMBFSIO_GETSD and VOP_GETSECATTR.
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
	smb_credinit(&scred, cr);

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
		SMBVDEBUG("error %d closing file %s\n",
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
	smb_credinit(&scred, cr);

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
		SMBVDEBUG("error %d closing file %s\n",
		    cerror, np->n_rpath);

out:
	smb_credrele(&scred);
	smbfs_rw_exit(&np->r_lkserlock);

	return (error);
}

/*
 * Helper for VOP_IOCTL: SMBFSIO_GETSD
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

/*
 * Helper for VOP_IOCTL: SMBFSIO_SETSD
 */
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


/*
 * Helper for VOP_GETSECATTR
 * Call smbfs_getsd, convert NT to ZFS form.
 */

/* ARGSUSED */
int
smbfs_getacl(vnode_t *vp, vsecattr_t *vsa,
	uid_t *uidp, gid_t *gidp, int flag, cred_t *cr)
{
	mdchain_t *mdp, md_store;
	mblk_t *m = NULL;
	i_ntsd_t *sd = NULL;
	uint32_t	selector;
	int		error;

	bzero(&md_store, sizeof (md_store));
	mdp = &md_store;

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
		goto out;
	/* Note: allocated *m */
	md_initm(mdp, m);

	/*
	 * Parse the OtW security descriptor,
	 * storing in our internal form.
	 */
	error = md_get_ntsd(mdp, &sd);
	if (error)
		goto out;

	/*
	 * Convert the Windows security descriptor to a
	 * ZFS ACL (and owner ID, primary group ID).
	 */
	error = smbfs_acl_sd2zfs(sd, vsa, uidp, gidp);

out:
	if (sd != NULL)
		smbfs_acl_free_sd(sd);
	/* Note: m_freem(m) is done by... */
	md_done(mdp);

	return (error);
}

/*
 * Helper for VOP_SETSECATTR
 * Convert ZFS to NT form, call smbfs_setsd.
 */

/* ARGSUSED */
int
smbfs_setacl(vnode_t *vp, vsecattr_t *vsa,
	uid_t uid, gid_t gid, int flag, cred_t *cr)
{
	mbchain_t *mbp, mb_store;
	i_ntsd_t *sd = NULL;
	uint32_t	selector;
	int		error;

	bzero(&mb_store, sizeof (mb_store));
	mbp = &mb_store;

	/*
	 * Which parts of the SD we'll modify.
	 * Ditto comments above re. SACL
	 */
	selector = 0;
	if (vsa)
		selector |= DACL_SECURITY_INFORMATION;
	if (uid != (uid_t)-1)
		selector |= OWNER_SECURITY_INFORMATION;
	if (gid != (gid_t)-1)
		selector |= GROUP_SECURITY_INFORMATION;
	if (selector == 0)
		return (0);

	/*
	 * Convert a ZFS ACL (and owner ID, group ID)
	 * into an NT SD, internal form.
	 */
	error = smbfs_acl_zfs2sd(vsa, uid, gid, &sd);
	if (error)
		goto out;

	/*
	 * Marshall the internal form SD into an
	 * OtW security descriptor.
	 */
	mb_init(mbp);
	error = mb_put_ntsd(mbp, sd);
	if (error)
		goto out;

	/*
	 * This does the OTW Set (and maybe open, close)
	 * It clears mb_top when consuming the message.
	 */
	error = smbfs_setsd(vp, selector, &mbp->mb_top, cr);

out:
	if (sd != NULL)
		smbfs_acl_free_sd(sd);
	mb_done(mbp);
	return (error);
}

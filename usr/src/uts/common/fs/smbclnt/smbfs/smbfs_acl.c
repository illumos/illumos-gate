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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
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
static int
smbfs_getsd(vnode_t *vp, uint32_t selector, mblk_t **mp, cred_t *cr)
{
	struct smb_cred scred;
	smbmntinfo_t *smi;
	smbnode_t	*np;
	smb_fh_t	*fid = NULL;
	uint32_t	sdlen = SMALL_SD_SIZE;
	uint32_t	rights = STD_RIGHT_READ_CONTROL_ACCESS;
	int error;

	if (selector & SACL_SECURITY_INFORMATION)
		rights |= SEC_RIGHT_SYSTEM_SECURITY;

	np = VTOSMB(vp);
	smi = VTOSMI(vp);

	smb_credinit(&scred, cr);

	error = smbfs_smb_tmpopen(np, rights, &scred, &fid);
	if (error)
		goto out;

again:
	/*
	 * This does the OTW Get
	 */
	error = smbfs_smb_getsec(smi->smi_share, fid,
	    selector, mp, &sdlen, &scred);
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

	smbfs_smb_tmpclose(np, fid);

out:
	smb_credrele(&scred);

	return (error);
}

/*
 * smbfs_setsd() is a common function used by both
 * smbfs_ioctl SMBFSIO_SETSD and VOP_SETSECATTR.
 * Handles required rights, tmpopen/tmpclose.
 *
 * Note: smbfs_setsd _consumes_ the passed *mp and
 * clears the pointer (so the caller won't free it)
 */
static int
smbfs_setsd(vnode_t *vp, uint32_t selector, mblk_t **mp, cred_t *cr)
{
	struct smb_cred scred;
	smbmntinfo_t *smi;
	smbnode_t	*np;
	uint32_t	rights;
	smb_fh_t	*fid = NULL;
	int error;

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

	smb_credinit(&scred, cr);

	error = smbfs_smb_tmpopen(np, rights, &scred, &fid);
	if (error)
		goto out;

	/*
	 * We're setting the remote ACL now, so
	 * invalidate our cached ACL just in case
	 * the server doesn't do exactly as we ask.
	 */
	mutex_enter(&np->r_statelock);
	np->r_sectime = gethrtime();
	mutex_exit(&np->r_statelock);

	/*
	 * This does the OTW Set
	 */
	error = smbfs_smb_setsec(smi->smi_share, fid,
	    selector, mp, &scred);

	smbfs_smb_tmpclose(np, fid);

out:
	smb_credrele(&scred);

	return (error);
}

/*
 * Helper for VOP_IOCTL: SMBFSIO_GETSD
 */
int
smbfs_acl_iocget(vnode_t *vp, intptr_t arg, int flag, cred_t *cr)
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
smbfs_acl_iocset(vnode_t *vp, intptr_t arg, int flag, cred_t *cr)
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
	(void) mb_init(mbp);
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
 * Refresh our cached copy of the security attributes
 */
static int
smbfs_acl_refresh(vnode_t *vp, cred_t *cr)
{
	smbnode_t *np;
	smbmntinfo_t *smi;
	mdchain_t *mdp, md_store;
	mblk_t *m = NULL;
	i_ntsd_t *sd = NULL;
	vsecattr_t vsa, ovsa;
	uint32_t selector;
	uid_t uid;
	gid_t gid;
	int error;

	np = VTOSMB(vp);
	smi = VTOSMI(vp);

	bzero(&md_store, sizeof (md_store));
	mdp = &md_store;

	/*
	 * Which parts of the SD we request.
	 * Not getting the SACL for now.
	 */
	selector = DACL_SECURITY_INFORMATION |
	    OWNER_SECURITY_INFORMATION |
	    GROUP_SECURITY_INFORMATION;

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
	bzero(&vsa, sizeof (vsa));
	vsa.vsa_mask = VSA_ACE | VSA_ACECNT;
	error = smbfs_acl_sd2zfs(sd, &vsa, &uid, &gid);
	if (error)
		goto out;

	ASSERT(vsa.vsa_aclentp != NULL);
	SMBVDEBUG("uid=%u, gid=%u", uid, gid);

	/*
	 * Store the results in r_secattr, n_uid, n_gid
	 */
	mutex_enter(&np->r_statelock);
	ovsa = np->r_secattr;
	np->r_secattr = vsa;
	np->n_uid = uid;
	np->n_gid = gid;
	/*
	 * ACLs don't change frequently, so cache these
	 * for a relatively long time (ac dir max).
	 */
	np->r_sectime = gethrtime() + smi->smi_acdirmax;
	mutex_exit(&np->r_statelock);

	/* Allocated in: smbfs_acl_sd2zfs */
	if (ovsa.vsa_aclentp != NULL)
		kmem_free(ovsa.vsa_aclentp, ovsa.vsa_aclentsz);

out:
	if (sd != NULL)
		smbfs_acl_free_sd(sd);
	/* Note: m_freem(m) is done by... */
	md_done(mdp);

	return (error);
}

/*
 * Helper for smbfsgetattr()
 *
 * Just refresh the ACL cache if needed,
 * which updates n_uid/n_gid
 */
int
smbfs_acl_getids(vnode_t *vp, cred_t *cr)
{
	smbnode_t *np;
	int error;

	np = VTOSMB(vp);

	/*
	 * NB: extended attribute files and directories
	 * do not have ACLs separate from the parent.
	 * Let the caller do ACL fabrication.
	 */
	if (np->n_flag & N_XATTR)
		return (ENOSYS);

	mutex_enter(&np->r_statelock);
	if (gethrtime() >= np->r_sectime) {
		/* Need to update r_secattr */
		mutex_exit(&np->r_statelock);
		error = smbfs_acl_refresh(vp, cr);
		return (error);
	}
	mutex_exit(&np->r_statelock);

	return (0);
}

/*
 * Helper for VOP_GETSECATTR
 *
 * Refresh the ACL cache if needed, then
 * duplicate the requested parts of the vsecattr.
 */
/* ARGSUSED */
int
smbfs_acl_getvsa(vnode_t *vp, vsecattr_t *vsa,
	int flag, cred_t *cr)
{
	smbnode_t *np;
	int error;

	np = VTOSMB(vp);

	/*
	 * NB: extended attribute files and directories
	 * do not have ACLs separate from the parent.
	 * Let the caller do ACL fabrication.
	 */
	if (np->n_flag & N_XATTR)
		return (ENOSYS);

	mutex_enter(&np->r_statelock);

	if (np->r_secattr.vsa_aclentp == NULL ||
	    gethrtime() >= np->r_sectime) {
		/* Need to update r_secattr */
		mutex_exit(&np->r_statelock);

		error = smbfs_acl_refresh(vp, cr);
		if (error)
			return (error);

		mutex_enter(&np->r_statelock);
	}
	ASSERT(np->r_secattr.vsa_aclentp != NULL);

	/*
	 * Duplicate requested parts of r_secattr
	 */

	if (vsa->vsa_mask & VSA_ACECNT)
		vsa->vsa_aclcnt = np->r_secattr.vsa_aclcnt;

	if (vsa->vsa_mask & VSA_ACE) {
		vsa->vsa_aclentsz = np->r_secattr.vsa_aclentsz;
		vsa->vsa_aclentp = kmem_alloc(vsa->vsa_aclentsz, KM_SLEEP);
		bcopy(np->r_secattr.vsa_aclentp, vsa->vsa_aclentp,
		    vsa->vsa_aclentsz);
	}

	mutex_exit(&np->r_statelock);
	return (0);
}

/*
 * Helper for smbfs_acl_setids, smbfs_acl_setvsa
 */
static int
smbfs_acl_store(vnode_t *vp, vsecattr_t *vsa, uid_t uid, gid_t gid,
	uint32_t selector, cred_t *cr)
{
	mbchain_t *mbp, mb_store;
	i_ntsd_t *sd;
	int error;

	ASSERT(selector != 0);

	sd = NULL;
	bzero(&mb_store, sizeof (mb_store));
	mbp = &mb_store;

	/*
	 * Convert a ZFS ACL (and owner ID, group ID)
	 * into an NT SD, internal form.
	 */
	error = smbfs_acl_zfs2sd(vsa, uid, gid, selector, &sd);
	if (error)
		goto out;

	/*
	 * Marshall the internal form SD into an
	 * OtW security descriptor.
	 */
	(void) mb_init(mbp);
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

/*
 * Helper for smbfs_setattr()
 *
 * Set the passed UID/GID as indicated by va_mask.
 */
int
smbfs_acl_setids(vnode_t *vp, vattr_t *vap, cred_t *cr)
{
	uid_t uid = (uid_t)-1;
	gid_t gid = (uid_t)-1;
	uint32_t selector = 0;
	int error;

	if (vap->va_mask & AT_UID) {
		selector |= OWNER_SECURITY_INFORMATION;
		uid = vap->va_uid;
	}

	if (vap->va_mask & AT_GID) {
		selector |= GROUP_SECURITY_INFORMATION;
		gid = vap->va_gid;
	}

	if (selector == 0)
		return (0);

	error = smbfs_acl_store(vp, NULL, uid, gid, selector, cr);
	return (error);
}

/*
 * Helper for VOP_SETSECATTR
 * Convert ZFS to NT form, call smbfs_setsd.
 */
/* ARGSUSED */
int
smbfs_acl_setvsa(vnode_t *vp, vsecattr_t *vsa,
	int flag, cred_t *cr)
{
	uint32_t selector = DACL_SECURITY_INFORMATION;
	smbnode_t *np = VTOSMB(vp);
	int error;

	/*
	 * NB: extended attribute files and directories
	 * do not have ACLs separate from the parent.
	 */
	if (np->n_flag & N_XATTR)
		return (ENOSYS);

	/*
	 * When handling ACE_OWNER or ACE_GROUP entries,
	 * we need the current owner and group.
	 */
	error = smbfs_acl_getids(vp, cr);
	if (error)
		return (error);

	error = smbfs_acl_store(vp, vsa, np->n_uid, np->n_gid, selector, cr);
	return (error);
}

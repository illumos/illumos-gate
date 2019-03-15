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
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * ACL API for smbfs
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/acl.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/byteorder.h>

#include <errno.h>
#include <stdio.h>
#include <strings.h>
#include <unistd.h>

#include <umem.h>
#include <idmap.h>

#include <sys/fs/smbfs_ioctl.h>

#include <netsmb/smb.h>
#include <netsmb/smb_lib.h>
#include <netsmb/smbfs_acl.h>

#include "smbfs_ntacl.h"
#include "private.h"

/* Sanity check SD sizes */
#define	MAX_RAW_SD_SIZE	32768

/* XXX: acl_common.h */
acl_t *acl_alloc(enum acl_type);
void acl_free(acl_t *);


/*
 * Get/set a Windows security descriptor (SD)
 * using the (private) smbfs ioctl mechanism.
 * Note: Get allocates mbp->mb_top
 */

/* ARGSUSED */
int
smbfs_acl_iocget(int fd, uint32_t selector, mbdata_t *mbp)
{
	ioc_sdbuf_t	iocb;
	struct mbuf	*m;
	int		error;

	error = mb_init_sz(mbp, MAX_RAW_SD_SIZE);
	if (error)
		return (error);

	m = mbp->mb_top;
	bzero(&iocb, sizeof (iocb));
	iocb.addr = mtod(m, uintptr_t);
	iocb.alloc = m->m_maxlen;
	iocb.used = 0;
	iocb.selector = selector;

	/*
	 * This does the OTW Get.
	 */
	if (nsmb_ioctl(fd, SMBFSIO_GETSD, &iocb) < 0) {
		error = errno;
		goto errout;
	}

	m->m_len = iocb.used;
	return (0);

errout:
	mb_done(mbp);
	return (error);
}

/* ARGSUSED */
int
smbfs_acl_iocset(int fd, uint32_t selector, mbdata_t *mbp)
{
	ioc_sdbuf_t	iocb;
	struct mbuf	*m;
	int		error;

	/* Make the data contiguous. */
	error = m_lineup(mbp->mb_top, &m);
	if (error)
		return (error);

	if (mbp->mb_top != m)
		mb_initm(mbp, m);

	bzero(&iocb, sizeof (iocb));
	iocb.addr = mtod(m, uintptr_t);
	iocb.alloc = m->m_maxlen;
	iocb.used  = m->m_len;
	iocb.selector = selector;

	/*
	 * This does the OTW Set.
	 */
	if (nsmb_ioctl(fd, SMBFSIO_SETSD, &iocb) < 0)
		error = errno;

	return (error);
}

/*
 * Get an NT SD from the open file via ioctl.
 */
int
smbfs_acl_getsd(int fd, uint32_t selector, i_ntsd_t **sdp)
{
	mbdata_t *mbp, mb_store;
	int error;

	mbp = &mb_store;
	bzero(mbp, sizeof (*mbp));

	/*
	 * Get the raw Windows SD via ioctl.
	 * Returns allocated mbchain in mbp.
	 */
	error = smbfs_acl_iocget(fd, selector, mbp);
	if (error == 0) {
		/*
		 * Import the raw SD into "internal" form.
		 * (like "absolute" form per. NT docs)
		 * Returns allocated data in sdp
		 */
		error = md_get_ntsd(mbp, sdp);
	}

	mb_done(mbp);
	return (error);
}

/*
 * Set an NT SD onto the open file via ioctl.
 */
int
smbfs_acl_setsd(int fd, uint32_t selector, i_ntsd_t *sd)
{
	mbdata_t *mbp, mb_store;
	int error;

	mbp = &mb_store;
	error = mb_init_sz(mbp, MAX_RAW_SD_SIZE);
	if (error)
		return (error);

	/*
	 * Export the "internal" SD into an mb chain.
	 * (a.k.a "self-relative" form per. NT docs)
	 * Returns allocated mbchain in mbp.
	 */
	error = mb_put_ntsd(mbp, sd);
	if (error == 0) {
		/*
		 * Set the raw Windows SD via ioctl.
		 */
		error = smbfs_acl_iocset(fd, selector, mbp);
	}

	mb_done(mbp);

	return (error);
}



/*
 * Convenience function to Get security using a
 * ZFS-style ACL (libsec acl, type=ACE_T)
 * Intentionally similar to: facl_get(3SEC)
 */
int
smbfs_acl_get(int fd, acl_t **aclp, uid_t *uidp, gid_t *gidp)
{
	i_ntsd_t *sd = NULL;
	acl_t *acl = NULL;
	uint32_t selector;
	int error;

	/*
	 * Which parts of the SD are being requested?
	 * XXX: Should we request the SACL too?  If so,
	 * might that cause this access to be denied?
	 * Or maybe: if we get access denied, try the
	 * open/fetch again without the SACL bit.
	 */
	selector = 0;
	if (aclp)
		selector |= DACL_SECURITY_INFORMATION;
	if (uidp)
		selector |= OWNER_SECURITY_INFORMATION;
	if (gidp)
		selector |= GROUP_SECURITY_INFORMATION;

	if (selector == 0)
		return (0);

	/*
	 * Get the Windows SD via ioctl, in
	 * "internal" (absolute) form.
	 */
	error = smbfs_acl_getsd(fd, selector, &sd);
	if (error)
		return (error);
	/* Note: sd now holds allocated data. */

	/*
	 * Convert the internal SD to a ZFS ACL.
	 * Get uid/gid too if pointers != NULL.
	 */
	if (aclp) {
		acl = acl_alloc(ACE_T);
		if (acl == NULL) {
			error = ENOMEM;
			goto out;
		}
	}
	error = smbfs_acl_sd2zfs(sd, acl, uidp, gidp);
	if (error)
		goto out;

	/* Success! */
	if (aclp) {
		*aclp = acl;
		acl = NULL;
	}

out:
	if (acl)
		acl_free(acl);
	smbfs_acl_free_sd(sd);
	return (error);
}

/*
 * Convenience function to Set security using a
 * ZFS-style ACL (libsec acl, type=ACE_T)
 * Intentionally similar to: facl_set(3SEC)
 */
int
smbfs_acl_set(int fd, acl_t *acl, uid_t uid, gid_t gid)
{
	struct stat st;
	i_ntsd_t *sd = NULL;
	uint32_t selector;
	int error;

	if (acl && acl->acl_type != ACE_T)
		return (EINVAL);

	/*
	 * Which parts of the SD are being modified?
	 * XXX: Ditto comments above re. SACL.
	 */
	selector = 0;
	if (acl)
		selector |= DACL_SECURITY_INFORMATION;
	if (uid != (uid_t)-1)
		selector |= OWNER_SECURITY_INFORMATION;
	if (gid != (gid_t)-1)
		selector |= GROUP_SECURITY_INFORMATION;
	if (selector == 0)
		return (0);

	if (uid == (uid_t)-1 || gid == (gid_t)-1) {
		/*
		 * If not setting owner or group, we need the
		 * current owner and group for translating
		 * references via owner@ or group@ ACEs.
		 */
		if (fstat(fd, &st) != 0)
			return (errno);
		if (uid == (uid_t)-1)
			uid = st.st_uid;
		if (gid == (gid_t)-1)
			gid = st.st_gid;
	}

	/*
	 * Convert the ZFS ACL to an internal SD.
	 * Returns allocated data in sd
	 */
	error = smbfs_acl_zfs2sd(acl, uid, gid, selector, &sd);
	if (error == 0)
		error = smbfs_acl_setsd(fd, selector, sd);

	smbfs_acl_free_sd(sd);

	return (error);
}

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

#pragma ident	"@(#)smb_vfs.c	1.3	08/08/07 SMI"

#include <sys/types.h>
#include <sys/fsid.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <smbsrv/smb_ktypes.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/string.h>

static smb_vfs_t *smb_vfs_lookup(smb_server_t *, vnode_t *);

/*
 * smb_vfs_hold
 *
 * Increments the reference count of the fs passed in. If no smb_vfs_t structure
 * has been created yet for the fs passed in it is created.
 */
boolean_t
smb_vfs_hold(smb_server_t *sv, vfs_t *vfsp)
{
	smb_vfs_t	*smb_vfs;
	vnode_t 	*rootvp;

	if ((vfsp == NULL) || VFS_ROOT(vfsp, &rootvp))
		return (B_FALSE);

	smb_llist_enter(&sv->sv_vfs_list, RW_WRITER);
	smb_vfs = smb_vfs_lookup(sv, rootvp);
	if (smb_vfs) {
		DTRACE_PROBE1(smb_vfs_hold_hit, smb_vfs_t *, smb_vfs);
		smb_llist_exit(&sv->sv_vfs_list);
		VN_RELE(rootvp);
		return (B_TRUE);
	}
	smb_vfs = kmem_cache_alloc(sv->si_cache_vfs, KM_SLEEP);

	bzero(smb_vfs, sizeof (smb_vfs_t));

	smb_vfs->sv_magic = SMB_VFS_MAGIC;
	smb_vfs->sv_refcnt = 1;
	smb_vfs->sv_vfsp = vfsp;
	/*
	 * We have a hold on the root vnode of the file system
	 * from the VFS_ROOT call above.
	 */
	smb_vfs->sv_rootvp = rootvp;
	smb_llist_insert_head(&sv->sv_vfs_list, smb_vfs);
	DTRACE_PROBE1(smb_vfs_hold_miss, smb_vfs_t *, smb_vfs);
	smb_llist_exit(&sv->sv_vfs_list);
	return (B_TRUE);
}

/*
 * smb_vfs_rele
 *
 * Decrements the reference count of the fs passed in. If the reference count
 * drops to zero the smb_vfs_t structure associated with the fs is freed.
 */
void
smb_vfs_rele(smb_server_t *sv, vfs_t *vfsp)
{
	smb_vfs_t	*smb_vfs;
	vnode_t		*rootvp;

	ASSERT(vfsp);

	if (VFS_ROOT(vfsp, &rootvp))
		return;

	smb_llist_enter(&sv->sv_vfs_list, RW_WRITER);
	smb_vfs = smb_vfs_lookup(sv, rootvp);
	DTRACE_PROBE2(smb_vfs_release, smb_vfs_t *, smb_vfs, vnode_t *, rootvp);
	VN_RELE(rootvp);
	if (smb_vfs) {
		--smb_vfs->sv_refcnt;
		ASSERT(smb_vfs->sv_refcnt);
		if (--smb_vfs->sv_refcnt == 0) {
			smb_llist_remove(&sv->sv_vfs_list, smb_vfs);
			smb_llist_exit(&sv->sv_vfs_list);
			ASSERT(rootvp == smb_vfs->sv_rootvp);
			VN_RELE(smb_vfs->sv_rootvp);
			smb_vfs->sv_magic = (uint32_t)~SMB_VFS_MAGIC;
			kmem_cache_free(sv->si_cache_vfs, smb_vfs);
			return;
		}
	}
	smb_llist_exit(&sv->sv_vfs_list);
}

/*
 * smb_vfs_rele_all()
 *
 * Release all holds on root vnodes of file systems which were taken
 * due to the existence of at least one enabled share on the file system.
 * Called at driver close time.
 */
void
smb_vfs_rele_all(smb_server_t *sv)
{
	smb_vfs_t	*smb_vfs;

	smb_llist_enter(&sv->sv_vfs_list, RW_WRITER);
	while ((smb_vfs = smb_llist_head(&sv->sv_vfs_list)) != NULL) {

		ASSERT(smb_vfs->sv_magic == SMB_VFS_MAGIC);
		DTRACE_PROBE1(smb_vfs_rele_all_hit, smb_vfs_t *, smb_vfs);
		smb_llist_remove(&sv->sv_vfs_list, smb_vfs);
		VN_RELE(smb_vfs->sv_rootvp);
		kmem_cache_free(sv->si_cache_vfs, smb_vfs);
	}
	smb_llist_exit(&sv->sv_vfs_list);
}

/*
 * smb_vfs_lookup
 *
 * Goes through the list of smb_vfs_t structure and returns the one matching
 * the vnode passed in. If no match is found a NULL pointer is returned.
 *
 * The list of smb_vfs_t structures has to have been entered prior calling
 * this function.
 */
static smb_vfs_t *
smb_vfs_lookup(smb_server_t *sv, vnode_t *rootvp)
{
	smb_vfs_t	*smb_vfs;

	smb_vfs = smb_llist_head(&sv->sv_vfs_list);
	while (smb_vfs) {
		ASSERT(smb_vfs->sv_magic == SMB_VFS_MAGIC);
		if (smb_vfs->sv_rootvp == rootvp) {
			smb_vfs->sv_refcnt++;
			ASSERT(smb_vfs->sv_refcnt);
			return (smb_vfs);
		}
		smb_vfs = smb_llist_next(&sv->sv_vfs_list, smb_vfs);
	}
	return (NULL);
}

/*
 * Returns true if both VFS pointers represent the same mounted
 * file system.  Otherwise returns false.
 */
boolean_t
smb_vfs_cmp(vfs_t *vfsp1, vfs_t *vfsp2)
{
	fsid_t *fsid1 = &vfsp1->vfs_fsid;
	fsid_t *fsid2 = &vfsp2->vfs_fsid;
	boolean_t result = B_FALSE;

	if ((vfsp1 = getvfs(fsid1)) == NULL)
		return (B_FALSE);

	if ((vfsp2 = getvfs(fsid2)) == NULL) {
		VFS_RELE(vfsp1);
		return (B_FALSE);
	}

	if ((fsid1->val[0] == fsid2->val[0]) &&
	    (fsid1->val[1] == fsid2->val[1])) {
		result = B_TRUE;
	}

	VFS_RELE(vfsp2);
	VFS_RELE(vfsp1);
	return (result);
}

/*
 * Check whether or not a file system is readonly.
 */
boolean_t
smb_vfs_is_readonly(vfs_t *vfsp)
{
	boolean_t result;

	if (getvfs(&vfsp->vfs_fsid) == NULL)
		return (B_FALSE);

	result = (vfsp->vfs_flag & VFS_RDONLY);
	VFS_RELE(vfsp);
	return (result);
}

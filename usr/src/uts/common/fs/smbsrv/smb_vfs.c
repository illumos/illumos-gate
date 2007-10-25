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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>
#include <sys/vfs.h>

static smb_vfs_t *smb_vfs_lookup(vnode_t *);

/*
 * smb_vfs_hold
 *
 * Increments the reference count of the fs passed in. If no smb_vfs_t structure
 * has been created yet for the fs passed in it is created.
 */
boolean_t
smb_vfs_hold(vfs_t *vfsp)
{
	smb_vfs_t	*smb_vfs;
	vnode_t 	*rootvp;

	if ((vfsp == NULL) || VFS_ROOT(vfsp, &rootvp))
		return (B_FALSE);

	smb_llist_enter(&smb_info.si_vfs_list, RW_WRITER);
	smb_vfs = smb_vfs_lookup(rootvp);
	if (smb_vfs) {
		DTRACE_PROBE1(smb_vfs_hold_hit, smb_vfs_t *, smb_vfs);
		smb_llist_exit(&smb_info.si_vfs_list);
		VN_RELE(rootvp);
		return (B_TRUE);
	}
	smb_vfs = kmem_cache_alloc(smb_info.si_cache_vfs, KM_SLEEP);

	bzero(smb_vfs, sizeof (smb_vfs_t));

	smb_vfs->sv_magic = SMB_VFS_MAGIC;
	smb_vfs->sv_refcnt = 1;
	smb_vfs->sv_vfsp = vfsp;
	/*
	 * We have a hold on the root vnode of the file system
	 * from the VFS_ROOT call above.
	 */
	smb_vfs->sv_rootvp = rootvp;
	smb_llist_insert_head(&smb_info.si_vfs_list, smb_vfs);
	DTRACE_PROBE1(smb_vfs_hold_miss, smb_vfs_t *, smb_vfs);
	smb_llist_exit(&smb_info.si_vfs_list);
	return (B_TRUE);
}

/*
 * smb_vfs_rele
 *
 * Decrements the reference count of the fs passed in. If the reference count
 * drops to zero the smb_vfs_t structure associated with the fs is freed.
 */
void
smb_vfs_rele(vfs_t *vfsp)
{
	smb_vfs_t	*smb_vfs;
	vnode_t		*rootvp;

	ASSERT(vfsp);

	if (VFS_ROOT(vfsp, &rootvp))
		return;

	smb_llist_enter(&smb_info.si_vfs_list, RW_WRITER);
	smb_vfs = smb_vfs_lookup(rootvp);
	DTRACE_PROBE2(smb_vfs_release, smb_vfs_t *, smb_vfs, vnode_t *, rootvp);
	VN_RELE(rootvp);
	if (smb_vfs) {
		--smb_vfs->sv_refcnt;
		ASSERT(smb_vfs->sv_refcnt);
		if (--smb_vfs->sv_refcnt == 0) {
			smb_llist_remove(&smb_info.si_vfs_list, smb_vfs);
			smb_llist_exit(&smb_info.si_vfs_list);
			ASSERT(rootvp == smb_vfs->sv_rootvp);
			VN_RELE(smb_vfs->sv_rootvp);
			smb_vfs->sv_magic = (uint32_t)~SMB_VFS_MAGIC;
			kmem_cache_free(smb_info.si_cache_vfs, smb_vfs);
			return;
		}
	}
	smb_llist_exit(&smb_info.si_vfs_list);
}

/*
 * smb_vfs_rele_all()
 *
 * Release all holds on root vnodes of file systems which were taken
 * due to the existence of at least one enabled share on the file system.
 * Called at driver close time.
 */
void
smb_vfs_rele_all()
{
	smb_vfs_t	*smb_vfs;

	smb_llist_enter(&smb_info.si_vfs_list, RW_WRITER);
	while ((smb_vfs = smb_llist_head(&smb_info.si_vfs_list)) != NULL) {

		ASSERT(smb_vfs->sv_magic == SMB_VFS_MAGIC);
		DTRACE_PROBE1(smb_vfs_rele_all_hit, smb_vfs_t *, smb_vfs);
		smb_llist_remove(&smb_info.si_vfs_list, smb_vfs);
		VN_RELE(smb_vfs->sv_rootvp);
		kmem_cache_free(smb_info.si_cache_vfs, smb_vfs);
	}
	smb_llist_exit(&smb_info.si_vfs_list);
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
smb_vfs_lookup(vnode_t *rootvp)
{
	smb_vfs_t	*smb_vfs;

	smb_vfs = smb_llist_head(&smb_info.si_vfs_list);
	while (smb_vfs) {
		ASSERT(smb_vfs->sv_magic == SMB_VFS_MAGIC);
		if (smb_vfs->sv_rootvp == rootvp) {
			smb_vfs->sv_refcnt++;
			ASSERT(smb_vfs->sv_refcnt);
			return (smb_vfs);
		}
		smb_vfs = smb_llist_next(&smb_info.si_vfs_list, smb_vfs);
	}
	return (NULL);
}

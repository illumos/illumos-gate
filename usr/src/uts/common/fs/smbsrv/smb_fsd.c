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

#include <sys/types.h>
#include <sys/feature_tests.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/sdt.h>
#include <smbsrv/string.h>
#include <smbsrv/smb_vops.h>

fs_desc_t null_fsd = {0, 0};
extern vfs_t *rootvfs;

static void fsd_getname(vfs_t *vfsp, fsvol_attr_t *vol_attr);
static void fsd_getflags(vfs_t *vfsp, unsigned *flags);
static void fsd_getseq(vfs_t *vfsp, uint32_t *fs_sequence);
static void fsd_name_from_mntpoint(char *, const char *, size_t);

/*
 * The "pathname" parameter may be either a path name or a volume name.
 * Kernel caller must call fsd_rele(vfsp).
 * User space caller will not have a hold on the fs.
 */

void *
fsd_lookup(char *name, unsigned flags, fs_desc_t *fsd)
{
	int (*func)(const char *, const char *);
	struct vfs *vfsp, *vfs_found = NULL;
	refstr_t *vfs_mntpoint;
	char vfs_volname[VOL_NAME_MAX];
	char volname[VOL_NAME_MAX];

	if (fsd)
		*fsd = null_fsd;

	vfs_list_read_lock();
	vfsp = rootvfs;

	func = (flags & FSOLF_CASE_INSENSITIVE) ? utf8_strcasecmp : strcmp;

	fsd_name_from_mntpoint(volname, name, VOL_NAME_MAX);

	do {
		vfs_mntpoint = vfsp->vfs_mntpt;
		refstr_hold(vfs_mntpoint);

		fsd_name_from_mntpoint(vfs_volname, vfs_mntpoint->rs_string,
		    VOL_NAME_MAX);

		if (func(volname, vfs_volname) == 0) {
			VFS_HOLD(vfsp);
			vfs_found = vfsp;

			if (fsd) {
				*fsd = vfsp->vfs_fsid;
			}
			refstr_rele(vfs_mntpoint);
			break;
		} else {
			refstr_rele(vfs_mntpoint);
		}
		vfsp = vfsp->vfs_next;

	} while (vfsp != rootvfs);

	vfs_list_unlock();
	return (vfs_found);
}

/*
 * Compare two volume descriptors to determine whether or not they
 * refer to the same volume. Returns 0 if the descriptors refer to
 * the same volume. Otherwise returns 1.
 */

int
fsd_cmp(fs_desc_t *fsd1, fs_desc_t *fsd2)
{
	if ((fsd1->val[0] == fsd2->val[0]) && (fsd1->val[1] == fsd2->val[1])) {
		return (0);
	}
	return (1);
}

/*
 * fsd_getattr
 *
 * Obtain volume attributes. If the volume is mounted, the attributes
 * are copied to vol_attr.  Otherwise, vol_attr is zero'd.
 *
 * Returns 0 on success. Otherwise an errno is returned to indicate
 * the error.
 */

int
fsd_getattr(fs_desc_t *fsd, fsvol_attr_t *vol_attr)
{
	vfs_t *vfsp;

	ASSERT(fsd);
	ASSERT(vol_attr);

	if ((vfsp = getvfs(fsd)) == NULL)
		return (ESTALE);

	bzero(vol_attr, sizeof (fsvol_attr_t));
	fsd_getname(vfsp, vol_attr);
	fsd_getflags(vfsp, &vol_attr->flags);
	fsd_getseq(vfsp, &vol_attr->fs_sequence);

	VFS_RELE(vfsp);
	return (0);
}

/*
 * Check whether or not a file system supports the features identified
 * by flags. Flags can be any combination of the FSOLF flags.
 * Returns 1 if all of the features are supported. Otherwise returns 0.
 * Exception: Returns -1 if stale fsd.
 */

int
fsd_chkcap(fs_desc_t *fsd, unsigned flags)
{
	vfs_t *vfsp = getvfs(fsd);
	unsigned getflags = 0;

	if (!vfsp) {
		return (-1);
	}

	fsd_getflags(vfsp, &getflags);

	VFS_RELE(vfsp);

	if ((flags != 0) && (getflags & flags) == flags) {
		return (1);
	}

	return (0);
}

void *
fsd_hold(fs_desc_t *fsd)
{
	void *vfsp = getvfs(fsd);

	return (vfsp);
}

void
fsd_rele(void *vfsp)
{
	ASSERT(vfsp);

	VFS_RELE((vfs_t *)vfsp);
}

/*
 * Returns volume name.
 * Also fills in vol_attr->fs_typename (needed for fsd_getattr()).
 *
 * File system types are hardcoded in uts/common/os/vfs_conf.c .
 */

static void
fsd_getname(vfs_t *vfsp, fsvol_attr_t *vol_attr)
{
	refstr_t *vfs_mntpoint;

	(void) strlcpy(vol_attr->fs_typename,
	    vfssw[vfsp->vfs_fstype].vsw_name, VOL_NAME_MAX);

	vfs_mntpoint = vfs_getmntpoint(vfsp);
	fsd_name_from_mntpoint(vol_attr->name, vfs_mntpoint->rs_string,
	    VOL_NAME_MAX);

	refstr_rele(vfs_mntpoint);
}

/*
 * Always set supports ACLs because the VFS will fake ACLs
 * for file systems that don't support them.
 */
static void
fsd_getflags(vfs_t *vfsp, uint_t *flags_ret)
{
	char *fsname = vfssw[vfsp->vfs_fstype].vsw_name;
	uint_t flags = FSOLF_SUPPORTS_ACLS;

	if (vfsp->vfs_flag & VFS_RDONLY)
		flags |= FSOLF_READONLY;

	if (vfsp->vfs_flag & VFS_XATTR)
		flags |= FSOLF_STREAMS;

	if (vfs_optionisset(vfsp, MNTOPT_NOATIME, NULL))
		flags |= FSOLF_NO_ATIME;

	if (strcmp(fsname, "tmpfs") == 0)
		flags |= FSOLF_NOEXPORT;

	if (vfs_has_feature(vfsp, VFSFT_XVATTR))
		flags |= FSOLF_XVATTR;

	if (vfs_has_feature(vfsp, VFSFT_CASEINSENSITIVE))
		flags |= FSOLF_CASE_INSENSITIVE;

	if (vfs_has_feature(vfsp, VFSFT_NOCASESENSITIVE))
		flags |= FSOLF_NO_CASE_SENSITIVE;

	if (vfs_has_feature(vfsp, VFSFT_DIRENTFLAGS))
		flags |= FSOLF_DIRENTFLAGS;

	DTRACE_PROBE1(smb__vfs__getflags, uint_t, flags);
	*flags_ret = flags;
}


/* ARGSUSED */
static void
fsd_getseq(vfs_t *vfsp, uint32_t *fs_sequence)
{
	/*
	 * This function is more complicated if there is
	 * DAVE support, but we have excised that code for
	 * the moment.
	 */
	*fs_sequence = 0;
}

/*
 * This function parses out the first conponent of a mount path,
 * used elsewhere as the volume name.
 *
 * For "/", the volume name is "" (i.e. ROOTVOL).
 */

static void
fsd_name_from_mntpoint(char *name, const char *mntpnt, size_t name_sz)
{
	const char *s = mntpnt;
	char *tmp = name;

	s += strspn(s, "/");
	(void) strlcpy(name, s, name_sz);
	(void) strsep((char **)&tmp, "/");

	DTRACE_PROBE2(smb__vfs__volume, char *, mntpnt, char *, name);
}

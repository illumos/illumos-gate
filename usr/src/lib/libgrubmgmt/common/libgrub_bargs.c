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
 * This file contains functions for constructing boot arguments
 * from GRUB menu for Fast Reboot.
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/elf.h>

#include "libgrub_impl.h"

#if defined(__sparc)
#define	CUR_ELFDATA	ELFDATA2MSB
#elif defined(__i386)
#define	CUR_ELFDATA	ELFDATA2LSB
#endif /* __i386 */

/*
 * Open the kernel file.
 * Return zero on sucess or error code otherwise.
 * On success the kernel file descriptor is returned in fdp.
 */
static int
get_kernel_fd(const char *path, int *fdp)
{
	const char	*bname;
	int		fd = -1, class, format;
	char		ident[EI_NIDENT];

	/* kernel basename must be unix */
	if ((bname = strrchr(path, '/')) == NULL)
		bname = path;
	else
		bname++;

	if (strcmp(bname, "unix") != 0) {
		if (strcmp(bname, "xen.gz") == 0)
			return (EG_XVMNOTSUP);
		return (EG_NOTUNIX);
	}

	if ((fd = open64(path, O_RDONLY)) >= 0 &&
	    (pread64(fd, ident, sizeof (ident), 0) == sizeof (ident))) {

		class = ident[EI_CLASS];
		format = ident[EI_DATA];

		if ((class == ELFCLASS32 || class == ELFCLASS64) &&
		    (memcmp(&ident[EI_MAG0], ELFMAG, 4) == 0) &&
		    format == CUR_ELFDATA) {
			*fdp = fd;
			return (0);
		}
	}

	if (fd >= 0)
		(void) close(fd);
	return (EG_OPENKERNFILE);
}

/*
 * Construct boot arguments for Fast Reboot from the ge_barg field of
 * a GRUB menu entry.
 * Return 0 on success, errno on failure.
 */
static int
barg2bootargs(const grub_barg_t *barg, grub_boot_args_t *fbarg)
{
	int	rc = 0;
	char	path[BOOTARGS_MAX];
	char	rpath[BOOTARGS_MAX];
	const grub_fsdesc_t	*fsd;

	assert(fbarg);
	bzero(fbarg, sizeof (*fbarg));
	fbarg->gba_kernel_fd = -1;

	if (!IS_BARG_VALID(barg))
		return (EINVAL);
	if ((fsd = grub_get_rootfsd(&barg->gb_root)) == NULL)
		return (EG_UNKNOWNFS);

	bcopy(fsd, &fbarg->gba_fsd, sizeof (fbarg->gba_fsd));
	bcopy(barg->gb_kernel, fbarg->gba_kernel, sizeof (fbarg->gba_kernel));
	bcopy(barg->gb_module, fbarg->gba_module, sizeof (fbarg->gba_module));

	if (fbarg->gba_fsd.gfs_mountp[0] == 0 &&
	    (rc = grub_fsd_mount_tmp(&fbarg->gba_fsd,
	    barg->gb_root.gr_fstyp)) != 0)
		return (rc);

	if (snprintf(path, sizeof (path), "%s%s", fbarg->gba_fsd.gfs_mountp,
	    fbarg->gba_kernel) >= sizeof (path)) {
		rc = E2BIG;
		goto err_out;
	}
	(void) strtok(path, " \t");
	(void) clean_path(path);

	/*
	 * GRUB requires absolute path, no symlinks, so do we
	 */
	if ((rc = resolvepath(path, rpath, sizeof (rpath))) == -1)
		rc = errno;
	else {
		rpath[rc] = 0;
		if (strcmp(rpath, path) != 0)
			rc = EG_NOTABSPATH;
		else
			rc = get_kernel_fd(rpath, &fbarg->gba_kernel_fd);
	}

	/* construct bootargs command-line */
	if (rc == 0 && snprintf(fbarg->gba_bootargs,
	    sizeof (fbarg->gba_bootargs), "%s %s", fbarg->gba_fsd.gfs_mountp,
	    fbarg->gba_kernel) >= sizeof (fbarg->gba_bootargs))
		rc = E2BIG;

err_out:
	if (rc != 0)
		grub_cleanup_boot_args(fbarg);

	return (rc);
}

/*
 * Construct boot arguments for Fast Reboot from grub_menu_t.
 * Return 0 on success, errno on failure.
 */
static int
grub_entry_get_boot_args(grub_entry_t *ent, grub_boot_args_t *fbarg)
{
	int rc = EG_INVALIDENT;

	if (IS_ENTRY_VALID(ent) && (rc = grub_entry_construct_barg(ent)) == 0)
		return (barg2bootargs(&ent->ge_barg, fbarg));
	else
		return (rc);
}

/*
 * Construct boot arguments for Fast Reboot from grub_menu_t and the
 * entry number.
 * Return 0 on success, errno on failure.
 */
static int
grub_menu_get_boot_args(const grub_menu_t *mp, int num,
    grub_boot_args_t *fbarg)
{
	grub_entry_t *ent;

	assert(mp);
	assert(fbarg);

	if ((ent = grub_menu_get_entry(mp, num)) == NULL)
		return (EG_NOENTRY);

	return (grub_entry_get_boot_args(ent, fbarg));
}

/*
 * Construct boot arguments from the specified GRUB menu entry.
 * Caller must allocate space for fbarg, and call grub_cleanup_boot_args()
 * when it's done with fbarg to clean up.
 *
 * Return 0 on success, errno on failure.
 */
int
grub_get_boot_args(grub_boot_args_t *fbarg, const char *menupath, int num)
{
	int rc;
	grub_menu_t *mp;

	assert(fbarg);
	if ((rc = grub_menu_init(menupath, &mp)) == 0) {
		rc = grub_menu_get_boot_args(mp, num, fbarg);
		grub_menu_fini(mp);
	}
	return (rc);
}

/*
 * Clean up when done with fbarg: close file handle, unmount file
 * systems.  Must be safe to call even if not all the fields are
 * set up.
 */
void
grub_cleanup_boot_args(grub_boot_args_t *fbarg)
{
	if (fbarg == NULL)
		return;

	(void) close(fbarg->gba_kernel_fd);
	grub_fsd_umount_tmp(&fbarg->gba_fsd);
}

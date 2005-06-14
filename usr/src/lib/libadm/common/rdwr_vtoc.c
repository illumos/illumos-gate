/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 1991-1997,2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/


#include <stdio.h>
#include <errno.h>
#include <memory.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>

/*
 * Read VTOC - return partition number.
 */
int
read_vtoc(int fd, struct vtoc *vtoc)
{
	struct dk_cinfo		dki_info;

	/*
	 * Read the vtoc.
	 */
	if (ioctl(fd, DKIOCGVTOC, (caddr_t)vtoc) == -1) {
		switch (errno) {
		case EIO:
			return (VT_EIO);
		case EINVAL:
			return (VT_EINVAL);
		/* for disks > 1TB */
		case ENOTSUP:
			return (VT_ENOTSUP);
		default:
			return (VT_ERROR);
		}
	}

	/*
	 * Sanity-check the vtoc.
	 */
	if (vtoc->v_sanity != VTOC_SANE) {
		return (VT_EINVAL);
	}

	/*
	 * Convert older-style vtoc's.
	 */
	switch (vtoc->v_version) {
	case 0:
		/*
		 * No vtoc information.  Install default
		 * nparts/sectorsz and version.  We are
		 * assuming that the driver returns the
		 * current partition information correctly.
		 */

		vtoc->v_version = V_VERSION;
		if (vtoc->v_nparts == 0)
			vtoc->v_nparts = V_NUMPAR;
		if (vtoc->v_sectorsz == 0)
			vtoc->v_sectorsz = DEV_BSIZE;

		break;

	case V_VERSION:
		break;

	default:
		return (VT_EINVAL);
	}

	/*
	 * Return partition number for this file descriptor.
	 */
	if (ioctl(fd, DKIOCINFO, (caddr_t)&dki_info) == -1) {
		switch (errno) {
		case EIO:
			return (VT_EIO);
		case EINVAL:
			return (VT_EINVAL);
		default:
			return (VT_ERROR);
		}
	}
	if (dki_info.dki_partition > V_NUMPAR) {
		return (VT_EINVAL);
	}
	return ((int)dki_info.dki_partition);
}

/*
 * Write VTOC
 */
int
write_vtoc(int fd, struct vtoc *vtoc)
{
	int i;
	/*
	 * Sanity-check the vtoc
	 */
	if (vtoc->v_sanity != VTOC_SANE || vtoc->v_nparts > V_NUMPAR) {
		return (-1);
	}

	/*
	 * since many drivers won't allow opening a device make sure
	 * all partitions aren't being set to zero. If all are zero then
	 * we have no way to set them to something else
	 */

	for (i = 0; i < (int)vtoc->v_nparts; i++)
		if (vtoc->v_part[i].p_size > 0)
			break;
	if (i == (int)vtoc->v_nparts)
		return (-1);

	/*
	 * Write the vtoc
	 */
	if (ioctl(fd, DKIOCSVTOC, (caddr_t)vtoc) == -1) {
		switch (errno) {
		case EIO:
			return (VT_EIO);
		case EINVAL:
			return (VT_EINVAL);
		/* for disks > 1TB */
		case ENOTSUP:
			return (VT_ENOTSUP);
		default:
			return (VT_ERROR);
		}
	}
	return (0);
}

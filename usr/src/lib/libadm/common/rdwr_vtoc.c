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

/*LINTLIBRARY*/


#include <stdio.h>
#include <errno.h>
#include <memory.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <strings.h>
#include <limits.h>

/*
 * To copy each field of vtoc individually for copying extvtoc
 * to 32 bit vtoc and vs.
 * Currently bootinfo and timestamp are not really supported.
 */

#define	libadm_vtoc_copy(vs, vd) \
	{							\
	int i;							\
	vd->v_bootinfo[0]	= (unsigned)vs->v_bootinfo[0];	\
	vd->v_bootinfo[1]	= (unsigned)vs->v_bootinfo[1];	\
	vd->v_bootinfo[2]	= (unsigned)vs->v_bootinfo[2];	\
	vd->v_sanity		= (unsigned)vs->v_sanity;	\
	vd->v_version		= (unsigned)vs->v_version;	\
	bcopy(vs->v_volume, vd->v_volume, LEN_DKL_VVOL);	\
	vd->v_sectorsz		= vs->v_sectorsz;		\
	vd->v_nparts		= vs->v_nparts;			\
	vd->v_version		= (unsigned)vs->v_version;	\
	for (i = 0; i < 10; i++)				\
		vd->v_reserved[i] = (unsigned)vs->v_reserved[i];\
	for (i = 0; i < V_NUMPAR; i++) {			\
		vd->v_part[i].p_tag = vs->v_part[i].p_tag;	\
		vd->v_part[i].p_flag = vs->v_part[i].p_flag;	\
		vd->v_part[i].p_start = (unsigned)vs->v_part[i].p_start;\
		vd->v_part[i].p_size = (unsigned)vs->v_part[i].p_size;	\
	}								\
	for (i = 0; i < V_NUMPAR; i++)					\
		if ((sizeof (vd->timestamp[i]) != sizeof (vs->timestamp[i])) &&\
		    (vs->timestamp[i] > INT32_MAX))			\
			vd->timestamp[i] = INT32_MAX;			\
		else							\
			vd->timestamp[i] = (unsigned)vs->timestamp[i];	\
	bcopy(vs->v_asciilabel, vd->v_asciilabel, LEN_DKL_ASCII);	\
	}


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
		case ENOTSUP:
			/* GPT labeled or disk > 1TB with no extvtoc support */
			return (VT_ENOTSUP);
		case EOVERFLOW:
			return (VT_EOVERFLOW);
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
		case ENOTSUP:
			/* GPT labeled or disk > 1TB with no extvtoc support */
			return (VT_ENOTSUP);
		case EOVERFLOW:
			return (VT_EOVERFLOW);
		default:
			return (VT_ERROR);
		}
	}
	return (0);
}

int
read_extvtoc(int fd, struct extvtoc *extvtoc)
{
	struct dk_cinfo		dki_info;
	struct vtoc	oldvtoc;
	struct vtoc *oldvtocp = &oldvtoc;
	int ret;

	/*
	 * Read the vtoc.
	 */
	if (ioctl(fd, DKIOCGEXTVTOC, (caddr_t)extvtoc) == -1) {
		switch (errno) {
		case EIO:
			return (VT_EIO);
		case EINVAL:
			return (VT_EINVAL);
		/* for disks > 1TB */
		case ENOTSUP:
			return (VT_ENOTSUP);
		case EOVERFLOW:
			return (VT_EOVERFLOW);
		case ENOTTY:

			if ((ret = read_vtoc(fd, oldvtocp)) < 0)
				return (ret);

#ifdef _LP64
			/*
			 * 64-bit vtoc and extvtoc have the same field sizes
			 * and offsets.
			 */
			bcopy(oldvtocp, extvtoc, sizeof (struct extvtoc));
#else
			bzero(extvtoc, sizeof (struct extvtoc));
			libadm_vtoc_copy(oldvtocp, extvtoc);
#endif
			return (ret);


		default:
			return (VT_ERROR);
		}
	}

	/*
	 * Sanity-check the vtoc.
	 */
	if (extvtoc->v_sanity != VTOC_SANE) {
		return (VT_EINVAL);
	}

	switch (extvtoc->v_version) {
	case 0:
		/*
		 * For pre-version 1 vtoc keep same functionality
		 * as read_vtoc.
		 */

		extvtoc->v_version = V_VERSION;
		if (extvtoc->v_nparts == 0)
			extvtoc->v_nparts = V_NUMPAR;
		if (extvtoc->v_sectorsz == 0)
			extvtoc->v_sectorsz = DEV_BSIZE;

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
 * Write ext VTOC.
 */
int
write_extvtoc(int fd, struct extvtoc *extvtoc)
{
	int i;
	struct vtoc	oldvtoc;
	struct vtoc	*oldvtocp = &oldvtoc;
	/*
	 * Sanity-check the vtoc
	 */
	if (extvtoc->v_sanity != VTOC_SANE || extvtoc->v_nparts > V_NUMPAR) {
		return (-1);
	}

	/*
	 * since many drivers won't allow opening a device make sure
	 * all partitions aren't being set to zero. If all are zero then
	 * we have no way to set them to something else
	 */

	for (i = 0; i < (int)extvtoc->v_nparts; i++)
		if (extvtoc->v_part[i].p_size > 0)
			break;
	if (i == (int)extvtoc->v_nparts)
		return (-1);

	/*
	 * Write the extvtoc
	 */
	if (ioctl(fd, DKIOCSEXTVTOC, (caddr_t)extvtoc) == -1) {
		switch (errno) {
		case EIO:
			return (VT_EIO);
		case EINVAL:
			return (VT_EINVAL);
		/* for disks > 1TB */
		case ENOTSUP:
			return (VT_ENOTSUP);
		case EOVERFLOW:
			return (VT_EOVERFLOW);
		case ENOTTY:
#ifdef _LP64
			/*
			 * 64-bit vtoc and extvtoc have the same field sizes
			 * and offsets.
			 */
			bcopy(extvtoc, oldvtocp, sizeof (struct vtoc));
#else
			bzero(oldvtocp, sizeof (struct vtoc));
			libadm_vtoc_copy(extvtoc, oldvtocp);

#endif
			return (write_vtoc(fd, &oldvtoc));

		default:
			return (VT_ERROR);
		}
	}

	return (0);
}

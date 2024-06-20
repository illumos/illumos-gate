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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2024 Oxide Computer Company
 */

#include "lint.h"
#include <sys/types.h>
#include <sys/mkdev.h>
#include <errno.h>

/*
 * Create a formatted device number
 */
dev_t
__makedev(const int version, const major_t majdev, const minor_t mindev)
{
	dev_t devnum;
	switch (version) {
	case OLDDEV:
		if (majdev > OMAXMAJ || mindev > OMAXMIN) {
			errno = EINVAL;
			return ((o_dev_t)NODEV);
		}
		devnum = ((majdev << ONBITSMINOR) | mindev);
		break;

	case NEWDEV:
#if MAXMAJ != 0xfffffffful	/* assumes major_t == uint32_t */
		if (majdev > MAXMAJ) {
			errno = EINVAL;
			return (NODEV);
		}
#endif
#if MAXMIN != 0xfffffffful	/* assumes minor_t == uint32_t */
		if (mindev > MAXMIN) {
			errno = EINVAL;
			return (NODEV);
		}
#endif
		if ((devnum = (((dev_t)majdev << NBITSMINOR) |
		    mindev)) == NODEV) {
			errno = EINVAL;
			return (NODEV);
		}
		break;
	case COMPATDEV:
		if (majdev > MAXMAJ32 || mindev > MAXMIN32) {
			errno = EINVAL;
			return (NODEV);
		}

		if ((devnum = (((dev_t)majdev << NBITSMINOR32) |
		    mindev)) == NODEV) {
			errno = EINVAL;
			return (NODEV);
		}
		break;
	default:
		errno = EINVAL;
		return (NODEV);
	}

	return (devnum);
}

/*
 * Return major number part of formatted device number
 */
major_t
__major(const int version, const dev_t devnum)
{
	major_t maj;

	switch (version) {
	case OLDDEV:
		maj = (devnum >> ONBITSMINOR);
		if (devnum == NODEV || maj > OMAXMAJ) {
			errno = EINVAL;
			return ((major_t)NODEV);
		}
		break;

	case NEWDEV:
		maj = (devnum >> NBITSMINOR);
		if (devnum == NODEV) {
			errno = EINVAL;
			return ((major_t)NODEV);
		}
#if MAXMAJ != 0xfffffffful	/* assumes major_t == uint32_t */
		if (maj > MAXMAJ) {
			errno = EINVAL;
			return ((major_t)NODEV);
		}
#endif
		break;

	case COMPATDEV:
		maj = devnum >> NBITSMAJOR32;
		if (devnum == NODEV || maj > MAXMAJ32) {
			errno = EINVAL;
			return ((major_t)NODEV);
		}
		break;

	default:
		errno = EINVAL;
		return ((major_t)NODEV);
	}

	return (maj);
}


/*
 * Return minor number part of formatted device number
 */
minor_t
__minor(const int version, const dev_t devnum)
{
	if (devnum == NODEV) {
		errno = EINVAL;
		return ((minor_t)NODEV);
	}

	switch (version) {
	case OLDDEV:
		return (devnum & OMAXMIN);
	case NEWDEV:
		return (devnum & MAXMIN);
	case COMPATDEV:
		return (devnum & MAXMIN32);
	default:
		errno = EINVAL;
		return ((minor_t)NODEV);
	}
}

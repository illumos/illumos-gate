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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * UNIX Device Driver Interface functions
 * (excerpts)
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/ddi.h>
#include <sys/mkdev.h>
#include <sys/debug.h>

#ifndef NODEV32
#define	NODEV32	(dev32_t)(-1)
#endif	/* NODEV32 */

/*
 * return internal major number corresponding to device
 * number (new format) argument
 */
major_t
getmajor(dev_t dev)
{
#ifdef _LP64
	return ((major_t)((dev >> NBITSMINOR64) & MAXMAJ64));
#else
	return ((major_t)((dev >> NBITSMINOR) & MAXMAJ));
#endif
}

/*
 * return internal minor number corresponding to device
 * number (new format) argument
 */
minor_t
getminor(dev_t dev)
{
#ifdef _LP64
	return ((minor_t)(dev & MAXMIN64));
#else
	return ((minor_t)(dev & MAXMIN));
#endif
}

/*
 * encode external major and minor number arguments into a
 * new format device number
 */
dev_t
makedevice(major_t maj, minor_t minor)
{
#ifdef _LP64
	return (((dev_t)maj << NBITSMINOR64) | (minor & MAXMIN64));
#else
	return (((dev_t)maj << NBITSMINOR) | (minor & MAXMIN));
#endif
}

/*
 * Compress 'long' device number encoding to 32-bit device number
 * encoding.  If it won't fit, we return failure, but set the
 * device number to 32-bit NODEV for the sake of our callers.
 */
int
cmpldev(dev32_t *dst, dev_t dev)
{
#if defined(_LP64)
	if (dev == NODEV) {
		*dst = NODEV32;
	} else {
		major_t major = dev >> L_BITSMINOR;
		minor_t minor = dev & L_MAXMIN;

		if (major > L_MAXMAJ32 || minor > L_MAXMIN32) {
			*dst = NODEV32;
			return (0);
		}

		*dst = (dev32_t)((major << L_BITSMINOR32) | minor);
	}
#else
	*dst = (dev32_t)dev;
#endif
	return (1);
}

/*
 * Expand 32-bit dev_t's to long dev_t's.  Expansion always "fits"
 * into the return type, but we're careful to expand NODEV explicitly.
 */
dev_t
expldev(dev32_t dev32)
{
#ifdef _LP64
	if (dev32 == NODEV32)
		return (NODEV);
	return (makedevice((dev32 >> L_BITSMINOR32) & L_MAXMAJ32,
	    dev32 & L_MAXMIN32));
#else
	return ((dev_t)dev32);
#endif
}

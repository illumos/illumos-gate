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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef _SYS_MKDEV_H
#define	_SYS_MKDEV_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * SVR3/Pre-EFT device number constants.
 */
#define	ONBITSMAJOR	7	/* # of SVR3 major device bits */
#define	ONBITSMINOR	8	/* # of SVR3 minor device bits */
#define	OMAXMAJ		0x7f	/* SVR3 max major value */
#define	OMAXMIN		0xff	/* SVR3 max major value */

/*
 * 32-bit Solaris device major/minor sizes.
 */
#define	NBITSMAJOR32	14
#define	NBITSMINOR32	18
#define	MAXMAJ32	0x3ffful	/* SVR4 max major value */
#define	MAXMIN32	0x3fffful	/* SVR4 max minor value */

#define	NBITSMAJOR64	32	/* # of major device bits in 64-bit Solaris */
#define	NBITSMINOR64	32	/* # of minor device bits in 64-bit Solaris */

#ifdef _LP64

#define	MAXMAJ64	0xfffffffful	/* max major value */
#define	MAXMIN64	0xfffffffful	/* max minor value */

#define	NBITSMAJOR	NBITSMAJOR64
#define	NBITSMINOR	NBITSMINOR64
#define	MAXMAJ		MAXMAJ64
#define	MAXMIN		MAXMIN64

#else /* !_LP64 */

#define	NBITSMAJOR	NBITSMAJOR32
#define	NBITSMINOR	NBITSMINOR32
#define	MAXMAJ		MAXMAJ32
#define	MAXMIN		MAXMIN32

#endif /* !_LP64 */

#if !defined(_KERNEL)

/*
 * Undefine sysmacros.h device macros.
 */
#undef makedev
#undef major
#undef minor

extern dev_t makedev(const major_t, const minor_t);
extern major_t major(const dev_t);
extern minor_t minor(const dev_t);
extern dev_t __makedev(const int, const major_t, const minor_t);
extern major_t __major(const int, const dev_t);
extern minor_t __minor(const int, const dev_t);

#define	OLDDEV 0	/* old device format */
#define	NEWDEV 1	/* new device format */

#define	makedev(maj, min)	(__makedev(NEWDEV, maj, min))
#define	major(dev)		(__major(NEWDEV, dev))
#define	minor(dev)		(__minor(NEWDEV, dev))

#endif	/* !defined(_KERNEL) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MKDEV_H */

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
 * Copyright 2015 Nexenta Systems, Inc. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#ifndef _SYS_FILIO_H
#define	_SYS_FILIO_H

/*
 * General file ioctl definitions.
 */

#include <sys/ioccom.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	FIOCLEX		_IO('f', 1)		/* set exclusive use on fd */
#define	FIONCLEX	_IO('f', 2)		/* remove exclusive use */
/* another local */
#define	FIONREAD	_IOR('f', 127, int)	/* get # bytes to read */
#define	FIONBIO		_IOW('f', 126, int)	/* set/clear non-blocking i/o */
#define	FIOASYNC	_IOW('f', 125, int)	/* set/clear async i/o */
#define	FIOSETOWN	_IOW('f', 124, int)	/* set owner */
#define	FIOGETOWN	_IOR('f', 123, int)	/* get owner */

/*
 * ioctl's for Online: DiskSuite.
 * WARNING - the support for these ioctls may be withdrawn
 * in future OS releases.
 */
#define	_FIOLFS		_IO('f', 64)		/* file system lock */
#define	_FIOLFSS	_IO('f', 65)		/* file system lock status */
#define	_FIOFFS		_IO('f', 66)		/* file system flush */
#define	_FIOAI		_FIOOBSOLETE67		/* get allocation info is */
#define	_FIOOBSOLETE67	_IO('f', 67)		/* obsolete and unsupported */
#define	_FIOSATIME	_IO('f', 68)		/* set atime */
#define	_FIOSDIO	_IO('f', 69)		/* set delayed io */
#define	_FIOGDIO	_IO('f', 70)		/* get delayed io */
#define	_FIOIO		_IO('f', 71)		/* inode open */
#define	_FIOISLOG	_IO('f', 72)		/* disksuite/ufs protocol */
#define	_FIOISLOGOK	_IO('f', 73)		/* disksuite/ufs protocol */
#define	_FIOLOGRESET	_IO('f', 74)		/* disksuite/ufs protocol */

/*
 * Contract-private ioctl()
 */
#define	_FIOISBUSY	_IO('f', 75)		/* networker/ufs protocol */
#define	_FIODIRECTIO	_IO('f', 76)		/* directio */
#define	_FIOTUNE	_IO('f', 77)		/* tuning */

/*
 * Internal Logging UFS
 */
#define	_FIOLOGENABLE	_IO('f', 87)		/* logging/ufs protocol */
#define	_FIOLOGDISABLE	_IO('f', 88)		/* logging/ufs protocol */

/*
 * File system snapshot ioctls (see sys/fs/ufs_snap.h)
 * (there is another snapshot ioctl, _FIOSNAPSHOTCREATE_MULTI,
 * defined farther down in this file.)
 */
#define	_FIOSNAPSHOTCREATE	_IO('f', 89)	/* create a snapshot */
#define	_FIOSNAPSHOTDELETE	_IO('f', 90)	/* delete a snapshot */

/*
 * Return the current superblock of size SBSIZE
 */
#define	_FIOGETSUPERBLOCK	_IO('f', 91)

/*
 * Contract private ioctl
 */
#define	_FIOGETMAXPHYS		_IO('f', 92)

/*
 * TSufs support
 */
#define	_FIO_SET_LUFS_DEBUG	_IO('f', 93) /* set lufs_debug */
#define	_FIO_SET_LUFS_ERROR	_IO('f', 94) /* set a lufs error */
#define	_FIO_GET_TOP_STATS	_IO('f', 95) /* get lufs tranaction stats */

/*
 * create a snapshot with multiple backing files
 */
#define	_FIOSNAPSHOTCREATE_MULTI	_IO('f', 96)

/*
 * handle lseek SEEK_DATA and SEEK_HOLE for holey file knowledge
 */
#define	_FIO_SEEK_DATA		_IO('f', 97) /* SEEK_DATA */
#define	_FIO_SEEK_HOLE		_IO('f', 98) /* SEEK_HOLE */

/*
 * boot archive compression
 */
#define	_FIO_COMPRESSED		_IO('f', 99) /* mark file as compressed */

/*
 * Expose fill information through ioctl
 */
#define	_FIO_COUNT_FILLED	_IO('f', 100)	/* count holes in a file */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FILIO_H */

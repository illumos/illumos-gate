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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _CPIO_H
#define	_CPIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The following are values used by c_mode field of the cpio archive.
 */

#define	C_IRUSR		0000400
#define	C_IWUSR		0000200
#define	C_IXUSR		0000100
#define	C_IRGRP		0000040
#define	C_IWGRP		0000020
#define	C_IXGRP		0000010
#define	C_IROTH		0000004
#define	C_IWOTH		0000002
#define	C_IXOTH		0000001
#define	C_ISUID		0004000
#define	C_ISGID		0002000
#define	C_ISVTX		0001000
#define	C_ISDIR		0040000
#define	C_ISFIFO	0010000
#define	C_ISREG		0100000
#define	C_ISBLK		0060000
#define	C_ISCHR		0020000
#define	C_ISCTG		0110000
#define	C_ISLNK		0120000
#define	C_ISSOCK	0140000

#define	MAGIC		"070707"

#ifdef	__cplusplus
}
#endif

#endif	/* _CPIO_H */

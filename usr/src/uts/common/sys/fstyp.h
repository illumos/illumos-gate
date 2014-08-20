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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _SYS_FSTYP_H
#define	_SYS_FSTYP_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	FSTYPSZ
#define	FSTYPSZ		16	/* max size of fs identifier */
#endif

/*
 * Opcodes for the sysfs() system call.
 */
#define	GETFSIND	1	/* translate fs identifier to fstype index */
#define	GETFSTYP	2	/* translate fstype index to fs identifier */
#define	GETNFSTYP	3	/* return the number of fstypes */

#if !defined(_KERNEL)
int sysfs(int, ...);
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FSTYP_H */

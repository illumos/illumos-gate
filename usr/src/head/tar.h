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


#ifndef _TAR_H
#define	_TAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2	*/

#ifdef	__cplusplus
extern "C" {
#endif

#define	TMAGIC		"ustar"
#define	TMAGLEN		6
#define	TVERSION	"00"
#define	TVERSLEN	2

/*
 * Typeflag field definitions.
 */

#define	REGTYPE		'0'
#define	AREGTYPE	'\0'
#define	LNKTYPE		'1'
#define	SYMTYPE		'2'
#define	CHRTYPE		'3'
#define	BLKTYPE		'4'
#define	DIRTYPE		'5'
#define	FIFOTYPE	'6'
#define	CONTTYPE	'7'

/*
 * Mode fild bit definitions.
 */

#define	TSUID		04000
#define	TSGID		02000
#define	TSVTX		01000
#define	TUREAD		00400
#define	TUWRITE		00200
#define	TUEXEC		00100
#define	TGREAD		00040
#define	TGWRITE		00020
#define	TGEXEC		00010
#define	TOREAD		00004
#define	TOWRITE		00002
#define	TOEXEC		00001

#ifdef	__cplusplus
}
#endif

#endif	/* _TAR_H */

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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef _TAR_H
#define	_TAR_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/feature_tests.h>

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

#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
/*
 *      Types used in ancillary files
 */
#define	ACL_HDR		'A'	/* Access Control List */
#define	LBL_TYPE	'L'	/* Trusted Extensions file label */
#define	DIR_TYPE	'D'	/* Trusted Extensions directory label */
/*
 * Attribute types used in Trusted Solaris ancillary files
 * that are interpreted for backward compatibility
 */
#define	SLD_TYPE	'S'	/* single-level directory component */
#define	PATH_TYPE	'P'	/* Path component */
#define	MLD_TYPE	'M'	/* multi-level directory component */
#define	FILE_TYPE	'F'	/* Have to handle files differently */
#define	APRIV_TYPE	'P'	/* allowed privileges data type in file */
#define	FPRIV_TYPE	'p'	/* forced privileges data type in file */
#define	COMP_TYPE	'C'	/* path components, use for MLD */
#define	ATTR_FLAG_TYPE	'F'	/* file attribute flag bytes data type */
#define	LK_COMP_TYPE	'K'	/* link data path component */
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _TAR_H */

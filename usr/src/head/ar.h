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


#ifndef _AR_H
#define	_AR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 2.12	*/

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *		COMMON ARCHIVE FORMAT
 *
 *	ARCHIVE File Organization:
 *	_________________________________________________
 *	|__________ARCHIVE_MAGIC_STRING_________________|
 *	|__________ARCHIVE_FILE_MEMBER_1________________|
 *	|						|
 *	|	Archive File Header "ar_hdr"		|
 *	|...............................................|
 *	|	Member Contents				|
 *	|		1. External symbol directory	|
 *	|		2. Text file			|
 *	|_______________________________________________|
 *	|________ARCHIVE_FILE_MEMBER_2__________________|
 *	|		"ar_hdr"			|
 *	|...............................................|
 *	|	Member Contents (.o or text file)	|
 *	|_______________________________________________|
 *	|	.		.		.	|
 *	|	.		.		.	|
 *	|	.		.		.	|
 *	|_______________________________________________|
 *	|________ARCHIVE_FILE_MEMBER_n__________________|
 *	|		"ar_hdr"			|
 *	|...............................................|
 *	|		Member Contents			|
 *	|_______________________________________________|
 *
 */

#define	ARMAG	"!<arch>\n"
#define	SARMAG	8
#define	ARFMAG	"`\n"

struct ar_hdr		/* archive file member header - printable ascii */
{
	char	ar_name[16];	/* file member name - `/' terminated */
	char	ar_date[12];	/* file member date - decimal */
	char	ar_uid[6];	/* file member user id - decimal */
	char	ar_gid[6];	/* file member group id - decimal */
	char	ar_mode[8];	/* file member mode - octal */
	char	ar_size[10];	/* file member size - decimal */
	char	ar_fmag[2];	/* ARFMAG - string to end header */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _AR_H */

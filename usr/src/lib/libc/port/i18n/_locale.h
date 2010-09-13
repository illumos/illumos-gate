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
 * Copyright (c) 1996 by Sun Microsystems, Inc.
 * All Rights Reserved
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3	*/

/* maximum part name length (inc. \0) */
#define	LC_NAMELEN	255

#define	LC_ANS		(255 * 6)

/* is* and to{upp,low}er tables */
#define	SZ_CTYPE	(257 + 257)

/* bytes for codeset information */
#define	SZ_CODESET	7

/* bytes for numeric editing */
#define	SZ_NUMERIC	2

#define	SZ_TOTAL	(SZ_CTYPE + SZ_CODESET)

/* index of decimal point character */
#define	NM_UNITS	0

/* index of thousand's sep. character */
#define	NM_THOUS	1

extern unsigned char _ctype[SZ_TOTAL];
extern unsigned char _numeric[SZ_NUMERIC];

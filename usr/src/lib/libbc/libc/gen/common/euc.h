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
/*	Copyright (c) 1984 AT&T	*/
/*	  All Rights Reserved  	*/


/*	This module is created for NLS on Jan.07.87	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* static  char *sccsid = "%Z%%M%	%I%	%E% SMI";	*/

#define	SS2	0x008e
#define	SS3	0x008f

typedef struct {
	short int _eucw1, _eucw2, _eucw3;	/*	EUC width	*/
} eucwidth_t;

#define csetno(c) (((c)&0x80)?((c)==SS2)?2:(((c)==SS3)?3:1):0)
	/* Returns code set number for the first byte of an EUC char. */

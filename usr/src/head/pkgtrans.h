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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef	_PKGTRANS_H
#define	_PKGTRANS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2.1.1 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	PT_OVERWRITE	0x01
#define	PT_INFO_ONLY	0x02
#define	PT_RENAME	0x04
#define	PT_DEBUG	0x08
#define	PT_SILENT	0x10
#define	PT_ODTSTREAM	0x40

#ifdef	__cplusplus
}
#endif

#endif	/* _PKGTRANS_H */

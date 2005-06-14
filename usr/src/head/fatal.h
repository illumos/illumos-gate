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


#ifndef	_FATAL_H
#define	_FATAL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.4.1.1 */

#ifdef	__cplusplus
extern "C" {
#endif

extern	int	Fflags;
extern	char	*Ffile;
extern	int	Fvalue;
extern	int	(*Ffunc)();
extern	int	Fjmp[10];

#define	FTLMSG		0100000
#define	FTLCLN		0040000
#define	FTLFUNC		0020000
#define	FTLACT		0000077
#define	FTLJMP		0000002
#define	FTLEXIT		0000001
#define	FTLRET		0000000

#define	FSAVE(val)	SAVE(Fflags, old_Fflags); Fflags = val;
#define	FRSTR()	RSTR(Fflags, old_Fflags);

#ifdef	__cplusplus
}
#endif

#endif	/* _FATAL_H */

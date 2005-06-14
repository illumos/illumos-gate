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


#ifndef _ETI_H
#define	_ETI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3	*/

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAX_COMMAND	(KEY_MAX + 512)

typedef int		OPTIONS;

typedef char *		(*	PTF_charP) ();
typedef void		(*	PTF_void) ();
typedef int		(*	PTF_int) ();

#define	E_OK			  0
#define	E_SYSTEM_ERROR		 -1
#define	E_BAD_ARGUMENT		 -2
#define	E_POSTED		 -3
#define	E_CONNECTED		 -4
#define	E_BAD_STATE		 -5
#define	E_NO_ROOM		 -6
#define	E_NOT_POSTED		 -7
#define	E_UNKNOWN_COMMAND	 -8
#define	E_NO_MATCH		 -9
#define	E_NOT_SELECTABLE	-10
#define	E_NOT_CONNECTED		-11
#define	E_REQUEST_DENIED	-12
#define	E_INVALID_FIELD		-13
#define	E_CURRENT		-14

#ifdef	__cplusplus
}
#endif

#endif	/* _ETI_H */

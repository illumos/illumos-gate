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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef	_USERDISP_H
#define	_USERDISP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* Flag values for dispusrdefs() */
#define	D_GROUP		0x0001
#define	D_BASEDIR	0x0002
#define	D_RID		0x0004
#define	D_SKEL		0x0008
#define	D_SHELL		0x0010
#define	D_INACT		0x0020
#define	D_EXPIRE	0x0040
#define	D_AUTH		0x0080
#define	D_PROF		0x0100
#define	D_ROLE		0x0200
#define	D_PROJ		0x0400
#define	D_LPRIV		0x0800
#define	D_DPRIV		0x1000
#define	D_LOCK		0x2000

#define	D_ALL	(D_GROUP | D_BASEDIR | D_RID | D_SKEL | D_SHELL \
	| D_INACT | D_EXPIRE | D_AUTH | D_PROF | D_ROLE | D_PROJ | \
	D_LPRIV | D_DPRIV | D_LOCK)

#ifdef	__cplusplus
}
#endif

#endif	/* _USERDISP_H */

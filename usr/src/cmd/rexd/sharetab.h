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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * Note: <sharefs/share.h> must be included before this file.
 */

#ifndef	_SHARETAB_H
#define	_SHARETAB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/* generic options */
#define	SHOPT_RO	"ro"
#define	SHOPT_RW	"rw"

/* options for nfs */
#define	SHOPT_ROOT	"root"
#define	SHOPT_ANON	"anon"
#define	SHOPT_SECURE	"secure"
#define	SHOPT_WINDOW	"window"

int		getshare();
char		*getshareopt();

#ifdef __cplusplus
}
#endif

#endif /* !_SHARETAB_H */

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
/*	Copyright (c) 1996,  by Sun Microsystems, Inc.	*/
/*	All rights reserved.				*/

#ifndef	_NETDEBUG_H
#define	_NETDEBUG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	MALLOC_ERR	"aborting netpr: malloc returns NULL"
#define	REALLOC_ERR	"aborting netpr: realloc returns NULL"

#define	ASSERT(expr, str)	\
{	\
	if (!expr) {	\
		(void) fprintf(stderr,	\
		"%s: line %d %s\n", __FILE__, __LINE__, str);	\
		panic();	\
		exit(E_RETRY);	\
		}	\
};

#ifdef	__cplusplus
}
#endif

#endif /* _NETDEBUG_H */

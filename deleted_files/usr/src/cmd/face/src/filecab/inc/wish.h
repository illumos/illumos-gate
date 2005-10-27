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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3	*/

#include	<malloc.h>

#define MALLOC

/* miked: shut up line
char *calloc();
*/

#ifndef TRUE
#define TRUE	(1)
#define FALSE	(0)
#endif

#ifndef bool
#define bool	int
#endif

#define FAIL	-1
#define SUCCESS	0
#define PATHSIZ	128

#define new(X)		((X *) ((_tmp_ptr = calloc(sizeof(X), 1)) == NULL ? (char *) fatal(NOMEM, nil) : _tmp_ptr))
#define _debug0		(!(_Debug & 1)) ? 0 : fprintf
#define _debug1		(!(_Debug & 2)) ? 0 : fprintf
#define _debug2		(!(_Debug & 4)) ? 0 : fprintf
#define _debug3		(!(_Debug & 8)) ? 0 : fprintf
#define _debug4		(!(_Debug & 16)) ? 0 : fprintf
#define _debug5		(!(_Debug & 32)) ? 0 : fprintf
#define _debug		_debug5
#define max(A, B)	((A) > (B) ? (A) : (B))
#define min(A, B)	((A) < (B) ? (A) : (B))

extern int	_Debug;
extern char	nil[];
extern char	*_tmp_ptr;

typedef int	vt_id;
typedef int	menu_id;
typedef int	form_id;

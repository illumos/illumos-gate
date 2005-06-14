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


/*
 *	VPATH assumptions:
 *		VPATH is the environment variable containing the view path
 *		where each path name is followed by ':', '\n', or '\0'.
 *		Embedded blanks are considered part of the path.
 */

/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <limits.h>

#define	MAXPATH	PATH_MAX	/* max length for entire name */

extern char	**vpdirs;	/* directories (including current) in */
				/* view path */
extern	int	vpndirs;	/* number of directories in view path */

extern void vpinit(char *);
extern int vpaccess(char *path, mode_t amode);

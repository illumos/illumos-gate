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


/*
 * Copyright  (c) 1985 AT&T
 *	All Rights Reserved
 */
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.2 */

#ifndef _CURSES_H
    extern int COLS;
#endif
#define RESERVED_LINES  (3)	/* banner + message + command lines     */
#define FIXED_TITLE	(6)	/* max overhead for frame no. + border  */
#define FIXED_COLS	(4)	/* overhead for frame border + margin   */
#define MAX_TITLE	(COLS - FIXED_TITLE) /* longest frame title     */
#define MESS_COLS	(COLS - 1) /* longest message line              */
#define FILE_NAME_SIZ	(256)	/* length +1 of longest file name       */
#define PATHSIZ		(1024)	/* length +1 of longest UNIX path name  */
#define MAX_WIDTH	(256)	/* the widest screen possibly supported *
				 * used for allocating string buffers   *
				 * that are then limited by the real    *
				 * screen width or other constraints.   */
#define TRUNCATE_STR	("...")	/* str to indicate desc. was truncated  */
#define LEN_TRUNC_STR	(3)	/* length of above string, TRUNCATE_STR */

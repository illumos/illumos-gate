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
 *
 */

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.3 */

extern char	nil[];

#define warn(what, name)	_terror(0, what, name, __FILE__, __LINE__, FALSE)
#define error(what, name)	_terror(TERR_LOG, what, name, __FILE__, __LINE__, FALSE)
#define child_error(what, name)	_terror(TERR_LOG, what, name, __FILE__, __LINE__, TRUE)
#define fatal(what, name)	_terror(TERR_LOG | TERR_EXIT, what, name, __FILE__, __LINE__, FALSE)
#define child_fatal(what, name)	_terror(TERR_LOG | TERR_EXIT, what, name, __FILE__, __LINE__, TRUE)

#define TERR_CONT	0
#define TERR_LOG	1
#define TERR_EXIT	2

#define TERRLOG		"/tmp/TERRLOG"

/*
 * These values are indices into the What array in terrmess.c
 * If you want to add a new error, the procedure is as follows:
 *  add the message for it to the end of the What array.
 *  add a define for it to this group of defines.
 *  add one to the value of TS_NERRS in this file.
 */
#define NONE		0
#define NOFORK		0
#define NOMEM		0
#define NOPEN		1
#define BADARGS		2
#define MUNGED		3
#define MISSING		4
#define SWERR		5
#define NOEXEC		6
#define LINK		7
#define VALID		8
#define NOT_UPDATED     9
#define FRAME_NOPEN    10

#define TS_NERRS       11

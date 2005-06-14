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

#define MAX_PROCS	5
#define MAX_ARGS	10

#ifndef NOPID			/* EFT abs k16 */
#define NOPID	(pid_t)(-1)	/* EFT abs k16 */
#endif
#define ST_RUNNING	0
#define ST_DEAD		1
#define ST_SUSPENDED	2

struct proc_rec {
	char *name;
	char *argv[MAX_ARGS+2];
	int status;			/* running, dead, or suspended */
	int flags;			/* prompt at end */
	pid_t pid;			/* actual process id.    EFT k16 */
	pid_t respid;			/* process id to resume  EFT k16 */
	struct actrec *ar;	/* activation record proc is in */
};

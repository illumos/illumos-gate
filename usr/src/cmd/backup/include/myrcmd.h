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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Internal definitions for the myrcmd.c rcmd(3) replacement module.
 */

#ifndef _MYRCMD_H
#define	_MYRCMD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* Failure return values */
#define	MYRCMD_EBAD		-1
#define	MYRCMD_NOHOST		-2
#define	MYRCMD_ENOPORT		-3
#define	MYRCMD_ENOSOCK		-4
#define	MYRCMD_ENOCONNECT	-5

/*
 * On a failure, the output that would have normally gone to stderr is
 * now placed in the global string "myrcmd_stderr".  Callers should check
 * to see if there is anything in the string before trying to print it.
 */
extern char myrcmd_stderr[];

#ifdef __STDC__
extern int myrcmd(char **ahost, unsigned short rport, char *locuser,
	char *remuser, char *cmd);
#else
extern int myrcmd();
#endif /* __STDC__ */

#ifdef	__cplusplus
}
#endif

#endif /* _MYRCMD_H */

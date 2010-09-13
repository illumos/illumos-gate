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
 *      Copyright (c) 2001 by Sun Microsystems, Inc.
 *      All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 *  NAME
 *	legal - check existence of file
 *
 *  SYNOPSIS
 *	int legal(char *file)
 *
 *  DESCRIPTION
 *	legal() checks to see if "file" is a writable file name.
 *
 *	Returns:
 *		0	-> file or directory exists, but is unwriteable
 *		1	-> file exists writeable
 *		2	-> file does not exist, but can be created
 */

#include "mail.h"
int
legal(file)
register char *file;
{
	register char *sp;
	char dfile[MAXFILENAME];

	/*
	 *	If file does not exist then try "." if file name has
	 *	no "/". For file names that have a "/", try check
	 *	for existence of previous directory.
	 */
	if (access(file, A_EXIST) == A_OK) {
		if (access(file, A_WRITE) == A_OK)
			return (1);
		else return (0);
	} else {
		if ((sp = strrchr(file, '/')) == NULL) {
			strcpy(dfile, ".");
		} else if (sp == file) {
			strcpy(dfile, "/");
		} else {
			if ((sp - file + 1) > MAXFILENAME)
				return (0);
			strncpy(dfile, file, sp - file);
			dfile[sp - file] = '\0';
		}
		if (access(dfile, A_WRITE) == CERROR)
			return (0);
		return (2);
	}
}

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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * format a password file entry
 */

#include "lint.h"
#include <sys/types.h>
#include <stdio.h>
#include <pwd.h>

int
putpwent(const struct passwd *p, FILE *f)
{
	int black_magic;

	(void) fprintf(f, "%s:%s", p->pw_name,
	    p->pw_passwd ? p->pw_passwd : "");
	if (((p->pw_age) != NULL) && ((*p->pw_age) != '\0'))
		(void) fprintf(f, ",%s", p->pw_age); /* fatal "," */
	black_magic = (*p->pw_name == '+' || *p->pw_name == '-');
	/* leading "+/-"  taken from getpwnam_r.c */
	if (black_magic) {
		(void) fprintf(f, ":::%s:%s:%s",
		    p->pw_gecos ? p->pw_gecos : "",
		    p->pw_dir ? p->pw_dir : "",
		    p->pw_shell ? p->pw_shell : "");
	} else { /* "normal case" */
		(void) fprintf(f, ":%d:%d:%s:%s:%s",
		    p->pw_uid,
		    p->pw_gid,
		    p->pw_gecos,
		    p->pw_dir,
		    p->pw_shell);
	}
	(void) putc('\n', f);
	(void) fflush(f);
	return (ferror(f));
}

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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ident	"%Z%%M%	%I%	%E% SMI"	/* from SVR4 bnu:mailst.c 2.7 */

#include "uucp.h"

extern int xfappend();

/*
 * fork and execute a mail command sending
 * string (str) to user (user).
 * If file is non-null, the file is also sent.
 * (this is used for mail returned to sender.)
 *	user	 -> user to send mail to
 *	subj	 -> subject for the mail
 *	str	 -> string mailed to user
 *	infile	 -> optional stdin mailed to user
 *	errfile	 -> optional stderr mailed to user
 */
void
mailst(user, subj, str, infile, errfile)
char *user, *subj, *str, *infile, *errfile;
{
	register FILE *fp, *fi;
	char cmd[BUFSIZ];
	char subject[BUFSIZ];
	char *c;

	/* get rid of some stuff that could be dangerous */
	if ( (c = strpbrk(user, Shchar)) != NULL) {
		*c = NULLCHAR;
	}

	/* limit subject to one line */
	if ((c = strchr(subj, '\n')) != NULL) {
		strncpy(subject, subj, c-subj);
		subject[c-subj] = NULLCHAR;
		subj = subject;
	}

	(void) snprintf(cmd, sizeof (cmd), "%s %s '%s'", PATH, MAIL, user);
	if ((fp = popen(cmd, "w")) == NULL)
		return;
	(void) fprintf(fp, "To: %s\nSubject: %s\n\n%s\n", user, subj, str);

	/* copy back stderr */
	if (*errfile != '\0' && NOTEMPTY(errfile) && (fi = fopen(errfile, "r")) != NULL) {
		fputs(gettext("\n\t===== stderr was =====\n"), fp);
		if (xfappend(fi, fp) != SUCCESS)
			fputs(gettext("\n\t===== well, i tried =====\n"), fp);
		(void) fclose(fi);
		fputc('\n', fp);
	}

	/* copy back stdin */
 	if (*infile) {
 		if (!NOTEMPTY(infile))
 			fputs(gettext("\n\t===== stdin was empty =====\n"), fp);
 		else if (chkpth(infile, CK_READ) == FAIL) {
 			fputs(gettext( "\n\t===== stdin was"
			    " denied read permission =====\n"), fp);
			snprintf(cmd, sizeof (cmd),
				"user %s, stdin %s", user, infile);
			logent(cmd, "DENIED");
		}
 		else if ((fi = fopen(infile, "r")) == NULL) {
 			fputs(gettext(
			    "\n\t===== stdin was unreadable =====\n"), fp);
			snprintf(cmd, sizeof (cmd),
				"user %s, stdin %s", user, infile);
			logent(cmd, "UNREADABLE");
		}
 		else {
 			fputs(gettext("\n\t===== stdin was =====\n"), fp);
 			if (xfappend(fi, fp) != SUCCESS)
 				fputs(gettext(
				    "\n\t===== well, i tried =====\n"), fp);
 			(void) fclose(fi);
 		}
		fputc('\n', fp);
	}

	(void) pclose(fp);
	return;
}
#ifndef	V7
static char un[2*NAMESIZE];
void
setuucp(p)
char *p;
{
   char **envp;

    envp = Env;
    for ( ; *envp; envp++) {
	if(PREFIX("LOGNAME", *envp)) {
	    (void) snprintf(un, sizeof (un), "LOGNAME=%s",p);
	    envp[0] = &un[0];
	}
    }
   return;
}
#else
/*ARGSUSED*/
void
setuucp(p) char	*p; {}
#endif

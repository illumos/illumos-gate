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
 * Copyright (c) 1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*LINTLIBRARY*/
#pragma	ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <grp.h>
#include <sys/types.h>
#include "libadm.h"
#include <stdlib.h>
#include <limits.h>

#define	PROMPT	"Enter the name of an existing group"
#define	MESG	"Please enter the name of an existing group."
#define	ALTMESG	"Please enter one of the following group names:\\n\\t"
#define	MALSIZ	64

#define	DELIM1 '/'
#define	BLANK ' '

static char *
setmsg(int disp)
{
	struct group
		*grpptr;
	int	count;
	size_t	n, m;
	char	*msg;

	if (disp == 0)
		return (MESG);

	m = MALSIZ;
	n = sizeof (ALTMESG);
	msg = calloc(m, sizeof (char));
	(void) strcpy(msg, ALTMESG);

	setgrent();
	count = 0;
	while ((grpptr = getgrent()) != NULL) {
		n += strlen(grpptr->gr_name) + 2;
		while (n >= m) {
			m += MALSIZ;
			msg = realloc(msg, m*sizeof (char));
		}
		if (count++)
			(void) strcat(msg, ", ");
		(void) strcat(msg, grpptr->gr_name);
	}
	endgrent();
	return (msg);
}

int
ckgid_dsp(void)
{
	struct group *grpptr;

	/* if display flag is set, then list out group file */
	if (ckgrpfile() == 1)
		return (1);
	setgrent();
	while (grpptr = getgrent())
		(void) printf("%s\n", grpptr->gr_name);
	endgrent();
	return (0);
}

int
ckgid_val(char *grpnm)
{
	int	valid;

	setgrent();
	valid = (getgrnam(grpnm) ? 0 : 1);
	endgrent();
	return (valid);
}

int
ckgrpfile(void) /* check to see if group file there */
{
	struct group *grpptr;

	setgrent();
	grpptr = getgrent();
	if (!grpptr) {
		endgrent();
		return (1);
	}
	endgrent();
	return (0);
}

void
ckgid_err(int disp, char *error)
{
	char	*msg;

	msg = setmsg(disp);
	puterror(stdout, msg, error);
	if (disp)
		free(msg);
}

void
ckgid_hlp(int disp, char *help)
{
	char	*msg;

	msg = setmsg(disp);
	puthelp(stdout, msg, help);
	if (disp)
		free(msg);
}

int
ckgid(char *gid, short disp, char *defstr, char *error, char *help,
    char *prompt)
{
	char	*defmesg,
		input[MAX_INPUT];

	defmesg = NULL;
	if (!prompt)
		prompt = PROMPT;

start:
	putprmpt(stderr, prompt, NULL, defstr);
	if (getinput(input)) {
		if (disp && defmesg)
			free(defmesg);
		return (1);
	}

	if (!strlen(input)) {
		if (defstr) {
			if (disp && defmesg)
				free(defmesg);
			(void) strcpy(gid, defstr);
			return (0);
		}
		if (!defmesg)
			defmesg = setmsg(disp);
		puterror(stderr, defmesg, error);
		goto start;
	} else if (strcmp(input, "?") == 0) {
		if (!defmesg)
			defmesg = setmsg(disp);
		puthelp(stderr, defmesg, help);
		goto start;
	} else if (ckquit && (strcmp(input, "q") == 0)) {
		if (disp && defmesg)
			free(defmesg);
		return (3);
	} else if (ckgid_val(input)) {
		if (!defmesg)
			defmesg = setmsg(disp);
		puterror(stderr, defmesg, error);
		goto start;
	}
	(void) strcpy(gid, input);
	if (disp && defmesg)
		free(defmesg);
	return (0);
}

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

#pragma	ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2 */
/*LINTLIBRARY*/

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <pwd.h>
#include <stdlib.h>
#include <limits.h>
#include "libadm.h"

#define	PROMPT	"Enter the login name of an existing user"
#define	MESG	"Please enter the login name of an existing user."
#define	ALTMESG	"Please enter one of the following login names:\\n\\t"
#define	MALSIZ	64

#define	DELIM1 '/'
#define	BLANK ' '

static char *
setmsg(int disp)
{
	struct passwd
		*pwdptr;
	int	count;
	size_t	n, m;
	char	*msg;

	if (disp == 0)
		return (MESG);

	m = MALSIZ;
	n = sizeof (ALTMESG);
	msg = (char *) calloc(m, sizeof (char));
	(void) strcpy(msg, ALTMESG);

	setpwent();
	count = 0;
	while (pwdptr = getpwent()) {
		n += strlen(pwdptr->pw_name) + 2;
		while (n >= m) {
			m += MALSIZ;
			msg = (char *) realloc(msg, m*sizeof (char));
		}
		if (count++)
			(void) strcat(msg, ", ");
		(void) strcat(msg, pwdptr->pw_name);
	}
	endpwent();
	return (msg);
}

int
ckuid_dsp(void)
{
	struct passwd *pwdptr;

	/* if display flag is set, then list out passwd file */
	if (ckpwdfile() == 1)
		return (1);
	setpwent();
	while (pwdptr = getpwent())
		(void) printf("%s\n", pwdptr->pw_name);
	endpwent();
	return (0);
}

int
ckuid_val(char *usrnm)
{
	int	valid;

	setpwent();
	valid = (getpwnam(usrnm) ? 0 : 1);
	endpwent();
	return (valid);
}

int
ckpwdfile(void) /* check to see if passwd file there */
{
	struct passwd *pwdptr;

	setpwent();
	pwdptr = getpwent();
	if (!pwdptr) {
		endpwent();
		return (1);
	}
	endpwent();
	return (0);
}

void
ckuid_err(short disp, char *error)
{
	char	*msg;

	msg = setmsg(disp);
	puterror(stdout, msg, error);
	if (disp)
		free(msg);
}

void
ckuid_hlp(int disp, char *help)
{
	char	*msg;

	msg = setmsg(disp);
	puthelp(stdout, msg, help);
	if (disp)
		free(msg);
}

int
ckuid(char *uid, short disp, char *defstr, char *error, char *help,
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
			(void) strcpy(uid, defstr);
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
	} else if (ckuid_val(input)) {
		if (!defmesg)
			defmesg = setmsg(disp);
		puterror(stderr, defmesg, error);
		goto start;
	}
	(void) strcpy(uid, input);
	if (disp && defmesg)
		free(defmesg);
	return (0);
}

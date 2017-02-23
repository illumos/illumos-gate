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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.17	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "stdio.h"
#include "string.h"
#include "errno.h"
#include "limits.h"
#include "unistd.h"

#include "lp.h"

extern char		**environ;

static void		envlist(int, char **);

/*
 * We recognize the following key phrases in the alert prototype
 * file, and replace them with appropriate values.
 */
#define NALRT_KEYS	7
# define ALRT_ENV		0
# define ALRT_PWD		1
# define ALRT_ULIMIT		2
# define ALRT_UMASK		3
# define ALRT_INTERVAL		4
# define ALRT_CMD		5
# define ALRT_USER		6

static struct {
	char			*v;
	short			len;
}			shell_keys[NALRT_KEYS] = {
#define	ENTRY(X)	X, sizeof(X)-1
	ENTRY("-ENVIRONMENT-"),
	ENTRY("-PWD-"),
	ENTRY("-ULIMIT-"),
	ENTRY("-UMASK-"),
	ENTRY("-INTERVAL-"),
	ENTRY("-CMD-"),
	ENTRY("-USER-"),
};

/*
 * These are used to bracket the administrator's command, so that
 * we can find it easily. We're out of luck if the administrator
 * includes an identical phrase in their command.
 */
#define ALRT_CMDSTART "## YOUR COMMAND STARTS HERE -- DON'T TOUCH ABOVE!!"
#define ALRT_CMDEND   "## YOUR COMMAND ENDS HERE -- DON'T TOUCH BELOW!!"

/**
 ** putalert() - WRITE ALERT TO FILES
 **/

int
putalert(char *parent, char *name, FALERT *alertp)
{
	char			*path,
				cur_dir[PATH_MAX + 1],
				buf[BUFSIZ];

	int			cur_umask;

	int fdout, fdin;


	if (!parent || !*parent || !name || !*name) {
		errno = EINVAL;
		return (-1);
	}

	if (!alertp->shcmd) {
		errno = EINVAL;
		return (-1);
	}

	if (STREQU(alertp->shcmd, NAME_NONE))
		return (delalert(parent, name));

	/*
	 * See if the form/printer/print-wheel exists.
	 */

	if (!(path = makepath(parent, name, (char *)0)))
		return (-1);

	if (Access(path, F_OK) == -1) {
		if (errno == ENOENT)
			errno = ENOTDIR; /* not quite, but what else? */
		Free (path);
		return (-1);
	}
	Free (path);

	/*
	 * First, the shell command file.
	 */

	if (!(path = makepath(parent, name, ALERTSHFILE, (char *)0)))
		return (-1);

	if ((fdout = open_locked(path, "w", MODE_NOEXEC)) < 0) {
		Free (path);
		return (-1);
	}
	Free (path);

	/*
	 * We use a prototype file to build the shell command,
	 * so that the alerts are easily customized. The shell
	 * is expected to handle repeat alerts and failed alerts,
	 * because the Spooler doesn't. Also, the Spooler runs
	 * each alert with the UID and GID of the administrator
	 * who defined the alert. Otherwise, anything goes.
	 */

	if (!Lp_Bin) {
		getpaths ();
		if (!Lp_Bin)
			return (-1);
	}
	if (!(path = makepath(Lp_Bin, ALERTPROTOFILE, (char *)0)))
		return (-1);

	if ((fdin = open_locked(path, "r", 0)) < 0) {
		Free (path);
		return (-1);
	}
	Free (path);

	errno = 0;
	while (fdgets(buf, BUFSIZ, fdin)) {
		int			key;
		char			*cp,
					*dash;

		cp = buf;
		while ((dash = strchr(cp, '-'))) {

		    *dash = 0;
		    fdputs (cp, fdout);
		    *(cp = dash) = '-';

		    for (key = 0; key < NALRT_KEYS; key++)
			if (STRNEQU(
				cp,
				shell_keys[key].v,
				shell_keys[key].len
			)) {
				register char	*newline =
						(cp != buf)? "\n" : "";

				cp += shell_keys[key].len;

				switch (key) {

				case ALRT_ENV:
					fdprintf(fdout, newline);
					envlist(fdout, environ);
					break;

				case ALRT_PWD:
					getcwd (cur_dir, PATH_MAX);
					fdprintf (fdout, "%s", cur_dir);
					break;

				case ALRT_ULIMIT:
					fdprintf (fdout, "%ld", ulimit(1, (long)0));
					break;

				case ALRT_UMASK:
					umask (cur_umask = umask(0));
					fdprintf (fdout, "%03o", cur_umask);
					break;

				case ALRT_INTERVAL:
					fdprintf(fdout, "%ld", (long)alertp->W);
					break;

				case ALRT_CMD:
					fdprintf(fdout, newline);
					fdprintf(fdout, "%s\n", ALRT_CMDSTART);
					fdprintf(fdout, "%s\n", alertp->shcmd);
					fdprintf(fdout, "%s\n", ALRT_CMDEND);
					break;

				case ALRT_USER:
					fdprintf(fdout, "%s", getname());
					break;

				}

				break;
			}
		    if (key >= NALRT_KEYS)
			fdputc(*cp++, fdout);

		}
		fdputs(cp, fdout);

	}
	if (errno != 0) {
		int			save_errno = errno;

		close(fdin);
		close(fdout);
		errno = save_errno;
		return (-1);
	}
	close(fdin);
	close(fdout);

	/*
	 * Next, the variables file.
	 */

	if (!(path = makepath(parent, name, ALERTVARSFILE, (char *)0)))
		return (-1);

	if ((fdout = open_locked(path, "w", MODE_NOREAD)) < 0) {
		Free (path);
		return (-1);
	}
	Free (path);

	fdprintf(fdout, "%d\n", alertp->Q > 0? alertp->Q : 1);
	fdprintf(fdout, "%d\n", alertp->W >= 0? alertp->W : 0);

	close(fdout);

	return (0);
}

/**
 ** getalert() - EXTRACT ALERT FROM FILES
 **/

FALERT *
getalert(char *parent, char *name)
{
	int fd;
	char *tmp;
	static FALERT		alert;
	register char		*path;
	char			buf[BUFSIZ];
	int			len;

	if (!parent || !*parent || !name || !*name) {
		errno = EINVAL;
		return (0);
	}

	/*
	 * See if the form/printer/print-wheel exists.
	 */

	if (!(path = makepath(parent, name, (char *)0)))
		return (0);

	if (Access(path, F_OK) == -1) {
		if (errno == ENOENT)
			errno = ENOTDIR; /* not quite, but what else? */
		Free (path);
		return (0);
	}
	Free (path);

	/*
	 * First, the shell command file.
	 */

	if (!(path = makepath(parent, name, ALERTSHFILE, (char *)0)))
		return (0);

	if ((fd = open_locked(path, "r", 0)) < 0) {
		Free (path);
		return (0);
	}
	Free (path);

	/*
	 * Skip over environment setting stuff, while loop, etc.,
	 * to find the beginning of the command.
	 */
	errno = 0;
	while ((tmp =  fdgets(buf, BUFSIZ, fd)) &&
		!STRNEQU(buf, ALRT_CMDSTART, sizeof(ALRT_CMDSTART)-1))
		;
	if ((tmp == NULL) || (errno != 0)) {
		int			save_errno = errno;

		close(fd);
		errno = save_errno;
		return (0);
	}

	alert.shcmd = sop_up_rest(fd, ALRT_CMDEND);

	close(fd);

	if (!alert.shcmd)
		return (0);

	/*
	 * Drop terminating newline.
	 */
	if (alert.shcmd[(len = strlen(alert.shcmd)) - 1] == '\n')
		alert.shcmd[len - 1] = 0;


	/*
	 * Next, the variables file.
	 */

	if (!(path = makepath(parent, name, ALERTVARSFILE, (char *)0)))
		return (0);

	if ((fd = open_locked(path, "r", 0)) < 0) {
		Free (path);
		return (0);
	}
	Free (path);

	errno = 0;
	(void)fdgets (buf, BUFSIZ, fd);
	if (errno != 0) {
		int			save_errno = errno;

		close(fd);
		errno = save_errno;
		return (0);
	}
	alert.Q = atoi(buf);

	(void)fdgets (buf, BUFSIZ, fd);
	if (errno != 0) {
		int			save_errno = errno;

		close(fd);
		errno = save_errno;
		return (0);
	}
	alert.W = atoi(buf);

	close(fd);

	return (&alert);
}

/**
 ** delalert() - DELETE ALERT FILES
 **/

int
delalert(char *parent, char *name)
{
	char			*path;


	if (!parent || !*parent || !name || !*name) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * See if the form/printer/print-wheel exists.
	 */

	if (!(path = makepath(parent, name, (char *)0)))
		return (-1);

	if (Access(path, F_OK) == -1) {
		if (errno == ENOENT)
			errno = ENOTDIR; /* not quite, but what else? */
		Free (path);
		return (-1);
	}
	Free (path);

	/*
	 * Remove the two files.
	 */

	if (!(path = makepath(parent, name, ALERTSHFILE, (char *)0)))
		return (-1);
	if (rmfile(path) == -1) {
		Free (path);
		return (-1);
	}
	Free (path);

	if (!(path = makepath(parent, name, ALERTVARSFILE, (char *)0)))
		return (-1);
	if (rmfile(path) == -1) {
		Free (path);
		return (-1);
	}
	Free (path);

	return (0);
}

/**
 ** envlist() - PRINT OUT ENVIRONMENT LIST SAFELY
 **/

static void
envlist(int fd, char **list)
{
	register char		*env,
				*value;

	if (!list || !*list)
		return;

	while ((env = *list++)) {
		if (!(value = strchr(env, '=')))
			continue;
		*value++ = 0;
		if (!strchr(value, '\''))
			fdprintf(fd, (char *)gettext("export %s; %s='%s'\n"),
				env, env, value);
		*--value = '=';
	}
}

/*
 * printalert() - PRINT ALERT DESCRIPTION
 *
 * This is not used in the scheduler, so we don't need to switch to using
 * file descriptors for scalability.
 */

void
printalert(FILE *fp, FALERT *alertp, int isfault)
{
	if (!alertp->shcmd) {
		if (isfault)
			(void)fprintf (fp, (char *)gettext("On fault: no alert\n"));
		else
			(void)fprintf (fp, (char *)gettext("No alert\n"));

	} else {
		register char	*copy = Strdup(alertp->shcmd),
				*cp;

		if (isfault)
			(void)fprintf (fp, (char *)gettext("On fault: "));
		else
			if (alertp->Q > 1)
				(void)fprintf (
					fp,
					(char *)gettext("When %d are queued: "),
					alertp->Q
				);
			else
				(void)fprintf (fp, (char *)gettext("Upon any being queued: "));

		if (copy && (cp = strchr(copy, ' ')))
			while (*cp == ' ')
				*cp++ = 0;

		if (
			copy
		     && syn_name(cp)
		     && (
				STREQU(copy, NAME_WRITE)
			     || STREQU(copy, NAME_MAIL)
			)
		)
			(void)fprintf (fp, "%s to %s ", copy, cp);
		else
			(void)fprintf (fp, (char *)gettext("alert with \"%s\" "), alertp->shcmd);

		if (alertp->W > 0)
			(void)fprintf (fp, (char *)gettext("every %d minutes\n"), alertp->W);
		else
			(void)fprintf (fp, (char *)gettext("once\n"));

		Free (copy);
	}
	return;
}

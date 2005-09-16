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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<stdlib.h>
#include	<signal.h>
#include	<fcntl.h>
#include	<errno.h>
#include	<sys/types.h>	/* abs k16 */
#include	"wish.h"
#include	"retcodes.h"
#include	"var_arrays.h"
#include	"terror.h"
#include	"moremacros.h"

#define	LCKPREFIX	".L"

/*
 * globals used throughout the Telesystem
 */
extern char	**Remove;

static void putdec(pid_t n, int fd);
static int getdec(int fd);

/*
 * make an entry in the Remove table and return its index
 */
static int
makentry(path)
char	path[];
{

	if (path == NULL)
		return (-1);
	if (Remove == NULL)
		Remove = (char **)array_create(sizeof (char *), 10);
	Remove = (char **)array_append(Remove, &path);
	return (array_len(Remove) - 1);
}

/*
 * Remove an entry from the Remove table (presumably because
 * the file could not be created)
 */
static void
rmentry(ent)
int	ent;
{
	register char	*ptr;

	ptr = Remove[ent];
	Remove = (char **)array_delete(Remove, ent);
	free(ptr);
}

/*
 * create a lockfile and return success
 */
bool
lockfile(path)
char	path[];
{
	register char	*save;
	register int	ent;
	register int	fd;
	register bool	success;
	char	*prefix();

	if ((save = prefix(path, LCKPREFIX)) == NULL)
		fatal(NOMEM, path);
	if ((ent = makentry(save)) < 0) {
		free(save);
		return (FALSE);
	}
	/* assume we will be successful */
	success = TRUE;
	if ((fd = open(save, O_RDONLY)) >= 0) {
		register pid_t	pid;    /* EFT abs k16 */

		if ((pid = getdec(fd)) < 0 || (kill(pid, 0) && errno == ESRCH))
			unlink(save);
		else
			/*
			 * if there's another process active, we won't be
			 * (unless it's us)
			 */
			if (pid == getpid()) {
				close(fd);
				return (TRUE);
			}
			else
				success = FALSE;
		close(fd);
	}
	errno = 0;
	/* if we still think we'll be successful, try it for real */
	if (success)
		success = ((fd = open(save, O_EXCL | O_CREAT | O_WRONLY,
		    0444)) >= 0);
	if (success) {
		chmod(save, 0444);
		putdec(getpid(), fd);
		close(fd);
	}
	else
		rmentry(ent);
	errno = 0;	/* reset */
	return (success);
}

static void
putdec(pid_t n, int fd)
{
	char	buf[16];

	sprintf(buf, "%d\n", n);
	write(fd, buf, strlen(buf));
}

static int
getdec(int fd)
{
	char	buf[16];
	register int	n;
	register pid_t	pid;	/* EFT abs k16 */

	n = read(fd, buf, sizeof (buf));
	if (n > 1 && buf[n - 1] == '\n' &&
	    (pid = (pid_t)strtol(buf, (char **)NULL, 0)) > 1)  /* EFT abs k16 */
		return (pid);
	else
		return (-1);
}

/*
 * Remove lockfile created by "lockfile()"
 */
void
unlock(path)
char	*path;
{
	register char	*save;
	register int	n;
	char	*prefix();
	int	lcv;

	if ((save = prefix(path, LCKPREFIX)) == NULL)
		return;
	unlink(save);
	lcv = array_len(Remove);
	for (n = 0; n < lcv; n++)
		if (strcmp(save, Remove[n]) == 0) {
			rmentry(n);
			break;
		}
	free(save);
}

/*
 * eopen performs an fopen/fdopen with some good things added for temp files
 * If the mode starts with "t" the file will be unlinked immediately
 * after creation.  If the mode starts with "T", the file will be
 * removed when the program exits - normally or from the receipt
 * of signal 1, 2, 3, or 15.
 * SIDE EFFECT: for temp files, calls "mkstemp(3)" on "path"
 */
FILE *
eopen(path, mode)
char	path[];
char	mode[];
{
	register int	ent;
	register FILE	*fp;
	int		tmpfd = -1;

	switch (mode[0]) {
	case 'T':
	case 't':
		if ((tmpfd = mkstemp(path)) == -1)
			return (NULL);
		(void) close(tmpfd);
		if ((ent = makentry(strsave(path))) < 0)
			return (NULL);
		fp = fopen(path, mode + 1);
		if (mode[0] == 't' && unlink(path) == 0)
			rmentry(ent);
		break;
	default:
		fp = fopen(path, mode);
		break;
	}
	return (fp);
}

/*
 * for compatibility's sake
 */
void
eclose(fp)
FILE	*fp;
{
	fclose(fp);
}

/*
 * make a tempfile using "eopen()"
 * if the path is null, one is provided
 * if the mode starts with neither "t" nor "T"
 * it defaults to "t"
 */
FILE *
tempfile(path, mode)
char	path[];
char	mode[];
{
	char	newmode[8];
	char	save[20];	/* based on length of string below */

	if (path == NULL) {
		path = save;
		strcpy(path, "/tmp/wishXXXXXX");
	}
	if (mode[0] != 't' && mode[0] != 'T') {
		newmode[0] = 't';
		strncpy(newmode + 1, mode, sizeof (mode) - 2);
		newmode[sizeof (mode) - 1] = '\0';
		mode = newmode;
	}
	return (eopen(path, mode));
}

char *
prefx(path, prfx)
char	*path;
char	*prfx;
{
	register int	len;
	char	*filename();
	register char	*p, *q;

	p = filename(path);
	len = strlen(prfx);
	for (q = path + strlen(path) + len; q >= p; q--)
		*q = *(q - len);
	strncpy(p, prfx, len);
	return (path);
}
char *
prefix(path, prfx)
char	*path;
char	*prfx;
{
	register char	*ret;

	if ((ret = malloc(strlen(path) + strlen(prfx) + 1)) != NULL) {
		strcpy(ret, path);
		return (prefx(ret, prfx));
	}
	return (ret);
}

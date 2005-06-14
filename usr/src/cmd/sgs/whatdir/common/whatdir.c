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
 * Copyright (c) 1991 by Sun Microsystems, Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* This tools finds the run directory of for the argument
 * supplied, returning 0 and printing the directory if successful
 * else returning 1 and printing an error message to stderr
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>

static int resolve(char *,char* ,char *, char **);
static int check_if_exec(char *);
int find_run_directory(char *, char *, char *, char **, char *);


/* resolve - check for specified file in specified directory
 *	sets up dir, following symlinks.
 *	returns zero for success, or
 *	-1 for error (with errno set properly)
 *   *indir;	search directory 
 *   *cmd;	search for name 
 *   *dir;	directory buffer 
 *  **run;	resultion name ptr ptr 
 *
 */
static int
resolve (char *indir, char *cmd, char *dir, char **run)
{
    char               *p;
    int                 rv = -1;
    int                 sll;
    char                symlink[MAXPATHLEN + 1];

    do {
	errno = ENAMETOOLONG;
	if ((size_t) strlen (indir) + (size_t) strlen (cmd) + 2 > MAXPATHLEN)
	    break;

	(void) sprintf(dir, "%s/%s", indir, cmd);
	if (check_if_exec(dir) != 0)  /* check if dir is an executable */
	{
		break;		/* Not an executable program */
	}

	while ((sll = readlink (dir, symlink, MAXPATHLEN)) >= 0) {
	    symlink[sll] = 0;
	    if (*symlink == '/')
		strcpy (dir, symlink);
	    else
		(void) sprintf (strrchr (dir, '/'), "/%s", symlink);
	}
	if (errno != EINVAL)
	    break;

	p = strrchr (dir, '/');
	*p++ = 0;
	if (run)		/* user wants resolution name */
	    *run = p;
	rv = 0;			/* complete, with success! */

    /* CONSTCOND */
    } while (0);

    return rv;
}

/* This routine checks to see if a given filename is an executable or not.
   Logically similar to the csh statement : if  ( -x $i && ! -d $i )
 */
static int
check_if_exec(char *file)
{
        struct stat stb;
        if (stat(file, &stb) < 0) {
                return ( -1);
        }
        if (S_ISDIR(stb.st_mode)) {
                return (-1);
        }
        if (!(stb.st_mode & S_IEXEC)) {
                return ( -1);
        }
        return (0);
}

/* find_run_directory - find executable file in PATH
 * PARAMETERS:
 *	cmd	filename as typed by user
 *	cwd	where to return working directory
 *	dir	where to return program's directory
 *	run	where to return final resolution name
 *	path	user's path from environment
 * RETURNS:
 *	returns zero for success,
 *	-1 for error (with errno set properly).
 * BUGS:
 *	Under the Bourne shell, the input parameters may be
 *	insufficient since the shell maintains its own path variable.
 *	See BugId 1069862.
 */
int
find_run_directory (char *cmd, char *cwd, char *dir, char **run, char *path)
{
    int                 rv = 0;
    char 		*f, *s;
    char		*tmp_path;

    if (!cmd || !*cmd || !cwd || !dir) {
	errno = EINVAL;		/* stupid arguments! */
	return -1;
    }
    if (!path || !*path)	/* missing or null path */
	path = ".";		/* assume sanity */

    tmp_path = (char *) malloc(strlen(path)+1);
    if (tmp_path == NULL) {
	errno = EINVAL;
        return -1;
    }

    if (*cwd != '/')
	if (!(getcwd (cwd, MAXPATHLEN)))
	    return -1;		/* cant get working directory */

    f = strrchr (cmd, '/');

    if (dir) {			/* user wants program directory */
	rv = -1;
	if (*cmd == '/')	/* absname given */
	    rv = resolve ("", cmd + 1, dir, run);
	else if (f)		/* relname given */
	    rv = resolve (cwd, cmd, dir, run);
	else {	/* from searchpath */
	    strcpy(tmp_path,path);
	    f = tmp_path;
	    rv = -1;
	    errno = ENOENT;	/* errno gets this if path empty */
	    while (*f && (rv < 0)) {
		s = f;
		while (*f && (*f != ':'))
		    ++f;
		if (*f)
		    *f++ = 0;
		if (*s == '/')
		    rv = resolve (s, cmd, dir, run);
		else {
		    char                abuf[MAXPATHLEN];

		    (void) sprintf (abuf, "%s/%s", cwd, s);
		    rv = resolve (abuf, cmd, dir, run);
		}
	    }
	}
    }
    free(tmp_path);
    return rv;
}


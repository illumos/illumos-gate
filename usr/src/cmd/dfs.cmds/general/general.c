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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	generic interface to dfs commands.
 *
 *	usage:	cmd [-F fstype] [-o fs_options] [ args ]
 *
 *	exec's /usr/lib/fs/<fstype>/<cmd>
 *	<cmd> is the basename of the command.
 *
 *	if -F is missing, fstype is the first entry in /etc/dfs/fstypes
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>

#define	DFSTYPES	"/etc/dfs/fstypes"		/* dfs list */
#define	FSCMD		"/usr/lib/fs/%s/%s"

#define	ARGVPAD		4	/* non-[arg...] elements in new argv list: */
				/* cmd name, -o, opts, (char *)0 terminator */

static char *getfs();
static int invalid();
void perror();

int
main(argc, argv)
int argc;
char **argv;
{
	extern char *optarg;
	extern int optind;
	FILE *dfp;		/* fp for dfs list */
	int c, err = 0;
	char subcmd[BUFSIZ];	/* fs specific command */
	char *cmd;		/* basename of this command */
	char *fsname = NULL;	/* file system name */
	char *opts = NULL;	/* -o options */
	char **nargv;		/* new argv list */
	int nargc = 0;		/* new argc */
	static char usage[] =
		"usage: %s [-F fstype] [-o fs_options ] [arg ...]\n";

	cmd = strrchr(argv[0], '/');	/* find the basename */
	if (cmd)
		++cmd;
	else
		cmd = argv[0];

	while ((c = getopt(argc, argv, "F:o:")) != -1)
		switch (c) {
		case 'F':
			err |= (fsname != NULL);	/* at most one -F */
			fsname = optarg;
			break;
		case 'o':			/* fs specific options */
			err |= (opts != NULL);		/* at most one -o */
			opts = optarg;
			break;
		case '?':
			err = 1;
			break;
		}
	if (err) {
		(void) fprintf(stderr, usage, cmd);
		exit(1);
	}

	if ((dfp = fopen(DFSTYPES, "r")) == NULL) {
		(void) fprintf(stderr, "%s: cannot open %s\n",
			cmd, DFSTYPES);
		exit(1);
	}

	if (fsname) {		/* generate fs specific command name */
		if (invalid(fsname, dfp)) {	/* valid ? */
			(void) fprintf(stderr,
			    "%s: invalid file system name\n", cmd);
			(void) fprintf(stderr, usage, cmd);
			exit(1);
		} else {
			(void) snprintf(subcmd, sizeof (subcmd),
			    FSCMD, fsname, cmd);
		}
	} else if (fsname = getfs(dfp)) {	/* use 1st line in dfstypes */
		(void) snprintf(subcmd, sizeof (subcmd), FSCMD, fsname, cmd);
	} else {
		(void) fprintf(stderr,
		    "%s: no file systems in %s\n", cmd, DFSTYPES);
		(void) fprintf(stderr, usage, cmd);
		exit(1);
	}

	/* allocate a block for the new argv list */
	if (!(nargv = (char **)malloc(sizeof (char *)*(argc-optind+ARGVPAD)))) {
		(void) fprintf(stderr, "%s: malloc failed.\n", cmd);
		exit(1);
		/*NOTREACHED*/
	}
	nargv[nargc++] = cmd;
	if (opts) {
		nargv[nargc++] = "-o";
		nargv[nargc++] = opts;
	}
	for (; optind <= argc; ++optind)	/* this copies the last NULL */
		nargv[nargc++] = argv[optind];

	(void) execvp(subcmd, nargv);
	perror(subcmd);
	return (1);
}


/*
 *	invalid(name, f)  -  return non-zero if name is not in
 *			     the list of fs names in file f
 */

static int
invalid(name, f)
char *name;		/* file system name */
FILE *f;		/* file of list of systems */
{
	char *s;

	while (s = getfs(f))	/* while there's still hope ... */
		if (strcmp(s, name) == 0)
			return (0);	/* we got it! */
	return (1);
}


/*
 *	getfs(fp) - get the next file system name from fp
 *		ignoring lines starting with a #.
 *		All leading whitespace is discarded.
 */

static char buf[BUFSIZ];

static char *
getfs(fp)
FILE *fp;
{
	char *s;

	while (s = fgets(buf, BUFSIZ, fp)) {
		while (isspace(*s))	/* leading whitespace doesn't count */
			++s;
		if (*s != '#') {	/* not a comment */
			char *t = s;

			while (!isspace(*t))	/* get the token */
				++t;
			*t = '\0';		/* ignore rest of line */
			return (s);
		}
	}
	return (NULL);	/* that's all, folks! */
}

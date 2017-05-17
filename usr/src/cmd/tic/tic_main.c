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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/* 
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 * 
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
*************************************************************************
*			COPYRIGHT NOTICE				*
*************************************************************************
*	This software is copyright(C) 1982 by Pavel Curtis		*
*									*
*	Permission is granted to reproduce and distribute		*
*	this file by any means so long as no fee is charged		*
*	above a nominal handling fee and so long as this		*
*	notice is always included in the copies.			*
*									*
*	Other rights are reserved except as explicitly granted		*
*	by written permission of the author.				*
*		Pavel Curtis						*
*		Computer Science Dept.					*
*		405 Upson Halli						*
*		Cornell Universityi					*
*		Ithaca, NY 14853					*
*									*
*		Ph- (607) 256-4934					*
*									*
*		Pavel.Cornell@Udel-Relay(ARPAnet)			*
*		decvax!cornell!pavel(UUCPnet)				*
*********************************************************************** */

/*
 *	comp_main.c --- Main program for terminfo compiler
 *
 *  $Log:	RCS/comp_main.v $
 * Revision 2.1  82/10/25  14:45:37  pavel
 * Added Copyright Notice
 *
 * Revision 2.0  82/10/24  15:16:37  pavel
 * Beta-one Test Release
 *
 * Revision 1.3  82/08/23  22:29:36  pavel
 * The REAL Alpha-one Release Version
 *
 * Revision 1.2  82/08/19  19:09:49  pavel
 * Alpha Test Release One
 *
 * Revision 1.1  82/08/12  18:36:55  pavel
 * Initial revision
 *
 *
 */


#define	EXTERN		/* EXTERN=extern in other .c files */
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include "compiler.h"

char	*source_file = "./terminfo.src";
char	*destination = SRCDIR;
char	*usage_string = "[-v[n]] [-c] source-file\n";
char	check_only = 0;
char	*progname;

extern void make_hash_table();	/* should be in a header file :-( */
extern void compile();		/* should be in a header file :-( */
extern void syserr_abort();		/* should be in a header file :-( */
static void init();

int
main(int argc, char *argv[])
{
	int	i;
	int	argflag = FALSE;

	debug_level = 0;
	progname = argv[0];

	umask(022);

	for (i = 1; i < argc; i++) {
	    if (argv[i][0] == '-') {
		switch (argv[i][1]) {
		    case 'c':
			check_only = 1;
			break;

		    case 'v':
			debug_level = argv[i][2]  ?  atoi(&argv[i][2])  :  1;
			break;

		    default:
			fprintf(stderr,
			    "%s: Unknown option. Usage is:\n\t%s: %s\n",
			    argv[0], progname, usage_string);
				exit(1);
		}
	    } else if (argflag) {
		fprintf(stderr, "%s: Too many file names.  Usage is:\n\t%s\n",
		    argv[0], usage_string);
			exit(1);
	    } else {
		argflag = TRUE;
		source_file = argv[i];
	    }
	}

	init();
	make_hash_table();
	compile();

	exit(0);

	return(0);
}

/*
 *	init()
 *
 *	Miscellaneous initializations
 *
 *	Open source file as standard input
 *	Change directory to working terminfo directory.
 *
 */

static void
init()
{
	char		*env = getenv("TERMINFO");

	start_time = time((time_t *) 0);

	curr_line = 0;

	if (freopen(source_file, "r", stdin) == NULL) {
	    fprintf(stderr, "%s: Can't open %s\n", progname, source_file);
	    exit(1);
	}

	if (env && *env)
	    destination = env;

	if (check_only) {
		DEBUG(1, "Would be working in %s\n", destination);
	} else {
		DEBUG(1, "Working in %s\n", destination);
	}

	if (access(destination, 7) < 0) {
		fprintf(stderr, "%s: %s nonexistent or permission denied\n",
		    progname, destination);
		exit(1);
	}

	if (chdir(destination) < 0) {
		fprintf(stderr, "%s: %s is not a directory\n",
		    progname, destination);
		exit(1);
	}

}

/*
 *
 *	check_dir(dirletter)
 *
 *	Check for access rights to the destination directory.
 *	Create any directories which don't exist.
 *
 */

void
check_dir(char dirletter)
{
	struct stat64	statbuf;
	static char	dirnames[128];
	static char	dir[2] = " ";

	if (dirnames[dirletter] == 0) {
	    dir[0] = dirletter;
	    if (stat64(dir, &statbuf) < 0) {
		if (mkdir(dir, 0755) < 0)
			syserr_abort("mkdir %s returned bad status", dir);
		dirnames[dirletter] = 1;
	    } else if (access(dir, 7) < 0) {
			fprintf(stderr, "%s: %s/%s: Permission denied\n",
			    progname, destination, dir);
			perror(dir);
			exit(1);
	    } else if ((statbuf.st_mode & S_IFMT) != S_IFDIR) {
			fprintf(stderr, "%s: %s/%s: Not a directory\n",
			    progname, destination, dir);
			perror(dir);
			exit(1);
	    }
	}
	return;
}

#include <curses.h>
#if (defined(SYSV) || defined(USG)) && !defined(SIGPOLL)
/*
 *	mkdir(dirname, mode)
 *
 *	forks and execs the mkdir program to create the given directory
 *
 */

mkdir(dirname, mode)
#ifdef __STDC__
const
#endif
char	*dirname;
int mode;
{
    int	fork_rtn;
    int	status;

    fork_rtn = fork();

    switch (fork_rtn) {
	case 0:		/* Child */
		(void) execl("/bin/mkdir", "mkdir", dirname, (char *)0);
		_exit(1);

	case -1:	/* Error */
		fprintf(stderr, "%s: SYSTEM ERROR!! Fork failed!!!\n",
		    progname);
		exit(1);

	default:
		(void) wait(&status);
		if ((status != 0) || (chmod(dirname, mode) == -1))
			return (-1);
		return (0);
	}
}
#endif

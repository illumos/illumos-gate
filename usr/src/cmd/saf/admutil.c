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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <signal.h>
#include <sac.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "misc.h"
#include "structs.h"
#include "extern.h"


/*
 * error - print out an error message and die
 *
 *	args:	msg - message to be printed, Saferrno previously set
 */

void
error(msg)
char *msg;
{
	(void) fprintf(stderr, "%s\n", msg);
	quit();
}


/*
 * quit - exit the program with the status in Saferrno
 */

void
quit()
{
	exit(Saferrno);
}


/*
 * make_tempname - generate a temp name to be used for updating files.
 *		Names will be of the form HOME/xxx/.name, where HOME
 *		is from misc.h
 *
 *	args:	bname - the basename of the file.  For example foo/_config
 *		        will generate a tempname of HOME/foo/._config
 */


char *
make_tempname(bname)
char *bname;
{
	static char buf[SIZE];	/* this is where we put the new name */
	char *p;			/* work pointer */

	p = strrchr(bname, '/');
	if (p == NULL)
		(void) sprintf(buf, "%s/.%s", HOME, bname);
	else {
		(void) strcpy(buf, HOME);
		/* this zaps the trailing slash so the '.' can be stuck in */
		*p = '\0';
		(void) strcat(buf, "/");
		(void) strcat(buf, bname);
		(void) strcat(buf, "/.");
		(void) strcat(buf, (p + 1));
		*p = '/';
	}
	return(buf);
}


/*
 * open_temp - open up a temp file
 *
 *	args:	tname - temp file name
 */



FILE *
open_temp(tname)
char *tname;
{
	FILE *fp;			/* fp associated with tname */
	struct sigaction sigact;	/* for signal handling */

	sigact.sa_flags = 0;
	sigact.sa_handler = SIG_IGN;
	(void) sigemptyset(&sigact.sa_mask);
	(void) sigaddset(&sigact.sa_mask, SIGHUP);
	(void) sigaddset(&sigact.sa_mask, SIGINT);
	(void) sigaddset(&sigact.sa_mask, SIGQUIT);
	(void) sigaction(SIGHUP, &sigact, NULL);
	(void) sigaction(SIGINT, &sigact, NULL);
	(void) sigaction(SIGQUIT, &sigact, NULL);
	(void) umask(0333);
	if (access(tname, 0) != -1) {
		Saferrno = E_SAFERR;
		error("tempfile busy; try again later");
	}
	fp = fopen(tname, "w");
	if (fp == NULL) {
		Saferrno = E_SYSERR;
		error("cannot create tempfile");
	}
	return(fp);
}


/*
 * replace - replace one file with another, only returns on success
 *
 *	args:	fname - name of target file
 *		tname - name of source file
 */


void
replace(fname, tname)
char *fname;
char *tname;
{
	char buf[SIZE];	/* scratch buffer */

	(void) sprintf(buf, "%s/%s", HOME, fname);
	(void) unlink(buf);
	if (rename(tname, buf) < 0) {
		Saferrno = E_SYSERR;
		(void) unlink(tname);
		quit();
	}
}


/*
 * copy_file - copy information from one file to another, return 0 on
 *	success, -1 on failure
 *
 *	args:	fp - source file's file pointer
 *		tfp - destination file's file pointer
 *		start - starting line number
 *		finish - ending line number (-1 indicates entire file)
 */

int
copy_file(FILE *fp, FILE *tfp, int start, int finish)
{
	int i;		/* loop variable */
	char dummy[SIZE];	/* scratch buffer */

/*
 * always start from the beginning because line numbers are absolute
 */

	rewind(fp);

/*
 * get to the starting point of interest
 */

	if (start != 1) {
		for (i = 1; i < start; i++)
			if (!fgets(dummy, SIZE, fp))
				return(-1);
	}

/*
 * copy as much as was requested
 */

	if (finish != -1) {
		for (i = start; i <= finish; i++) {
			if (!fgets(dummy, SIZE, fp))
				return(-1);
			if (fputs(dummy, tfp) == EOF)
				return(-1);
		}
	}
	else {
		for (;;) {
			if (fgets(dummy, SIZE, fp) == NULL) {
				if (feof(fp))
					break;
				else
					return(-1);
			}
			if (fputs(dummy, tfp) == EOF)
				return(-1);
		}
	}
	return(0);
}


/*
 * find_pm - find an entry in _sactab for a particular port monitor
 *
 *	args:	fp - file pointer for _sactab
 *		pmtag - tag of port monitor we're looking for
 */

int
find_pm(FILE *fp, char *pmtag)
{
	char *p;		/* working pointer */
	int line = 0;		/* line number we found entry on */
	struct sactab stab;	/* place to hold parsed info */
	char buf[SIZE];	/* scratch buffer */

	while (fgets(buf, SIZE, fp)) {
		line++;
		p = trim(buf);
		if (*p == '\0')
			continue;
		parse(p, &stab);
		if (!(strcmp(stab.sc_tag, pmtag)))
			return(line);
	}
	if (!feof(fp)) {
		Saferrno = E_SYSERR;
		error("error reading _sactab");
		/* NOTREACHED */
		return (0);
	}
	else
		return(0);
}


/*
 * do_config - take a config script and put it where it belongs or
 *		output an existing one.  Saferrno is set if any errors
 *		are encountered.  Calling routine may choose to quit or
 *		continue, in which case Saferrno will stay set, but may
 *		change value if another error is encountered.
 *
 *	args:	script - name of file containing script (if NULL, means output
 *			 existing one instead)
 *		basename - name of script (relative to HOME (from misc.h))
 */

int
do_config(char *script, char *basename)
{
	FILE *ifp;		/* file pointer for source file */
	FILE *ofp;		/* file pointer for target file */
	struct stat statbuf;	/* file status info */
	char *tname;		/* name of tempfile */
	char buf[SIZE];		/* scratch buffer */

	if (script) {
		/* we're installing a new configuration script */
		if (access(script, 0) == 0) {
			if (stat(script, &statbuf) < 0) {
				Saferrno = E_SYSERR;
				(void) fprintf(stderr, "Could not stat <%s>\n", script);
				return(1);
			}
			if ((statbuf.st_mode & S_IFMT) != S_IFREG) {
				(void) fprintf(stderr, "warning - %s not a regular file - ignored\n", script);
				return(1);
			}
		}
		else {
			Saferrno = E_NOEXIST;
			(void) fprintf(stderr, "Invalid request, %s does not exist\n", script);
			return(1);
		}
		ifp = fopen(script, "r");
		if (ifp == NULL) {
			(void) fprintf(stderr, "Invalid request, can not open %s\n", script);
			Saferrno = E_SYSERR;
			return(1);
		}
		tname = make_tempname(basename);
		/* note - open_temp only returns if successful */
		ofp = open_temp(tname);
		while(fgets(buf, SIZE, ifp)) {
			if (fputs(buf, ofp) == EOF) {
				(void) unlink(tname);
				Saferrno = E_SYSERR;
				error("error in writing tempfile");
			}
		}
		(void) fclose(ifp);
		if (fclose(ofp) == EOF) {
			(void) unlink(tname);
			Saferrno = E_SYSERR;
			error("error closing tempfile");
		}
		/* note - replace only returns if successful */
		replace(basename, tname);
		return(0);
	}
	else {
		/* we're outputting a configuration script */
		(void) sprintf(buf, "%s/%s", HOME, basename);
		if (access(buf, 0) < 0) {
			(void) fprintf(stderr, "Invalid request, script does not exist\n");
			Saferrno = E_NOEXIST;
			return(1);
		}
		ifp = fopen(buf, "r");
		if (ifp == NULL) {
			(void) fprintf(stderr, "Invalid request, can not open script\n");
			Saferrno = E_SYSERR;
			return(1);
		}
		while (fgets(buf, SIZE, ifp))
			(void) fputs(buf, stdout);
		(void) fclose(ifp);
		return(0);
	}
}

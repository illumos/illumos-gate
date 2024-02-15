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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
	This module contains routines that find C. files
	in a system spool directory, return the next C. file
	to process, and break up the C. line into arguments
	for processing.
*/

#include "uucp.h"

#define BOOKMARK_PRE	'A'
#define CLEAN_RETURN(fp) {\
	if (fp != NULL) \
		(void) fclose(fp); \
	fp = NULL; \
	return(0); \
	/* NOTREACHED */ \
}

/* C.princetN0026 - ('C' + '.') - "princet" */
#define SUFSIZE	(MAXBASENAME - 2 - SYSNSIZE)
#define LLEN 50
#define MAXRQST 250

static void insert();
static int  anlwrk(), bldflst();
extern int  iswrk(), gtwvec(), gnamef();

static char  Filent[LLEN][NAMESIZE]; /* array of C. file names (text)        */
static char *Fptr[LLEN];	     /* pointers to names in Filent          */
static short Nnext;		     /* index of next C. file in Fptr list   */
static short Nfiles = 0;	     /* Number of files in Filent	     */

/*
 * read a line from the workfile (C.file)
 *	file	-> work file  (Input/Output)  made '\0' after work completion
 *	wvec	-> address of array to return arguments (Output)
 *	wcount	-> maximum # of arguments to return in wvec
 *		NOTE: wvec should be large enough to accept wcount + 1 pointers
 *		since NULL is inserted after last item.
 * returns:
 *	0	   ->  no more work in this file
 *	positive # -> number of arguments
 */
static int
anlwrk(char *file, char **wvec, int wcount)
{
	int i;
	FILE *p_bookmark;    /* pointer to afile */
	static   FILE *fp = NULL;    /* currently opened C. file pointer    */
	static char afile[NAMESIZE]; /* file with line count for book marks */
	static char str[MAXRQST];    /* the string which  wvec points to    */
	static short acount;
	struct stat stbuf;
	int	nargs;		/* return value == # args in the line */

	if (file[0] == '\0') {
		if (fp != NULL)
			errent("anlwrk",
			   "attempt made to use old workfile was thwarted", 0,
			   __FILE__, __LINE__);
		CLEAN_RETURN(fp);
		/* NOTREACHED */
	}
	if (fp == NULL) {
		fp = fopen(file, "r");

		if (fp == NULL){ /* can't open C. file! */
			errent(Ct_OPEN,file,errno, __FILE__, __LINE__);
			/* this may not work, but we'll try it */
			/* It will fail if the C. name is more than */
			/* the standard 14 characters - if this is the */
			/* tocorrupt will exit with ASSERT */
			toCorrupt(file);
			return(0);
		}
		(void) fstat(fileno(fp), &stbuf);
		Nstat.t_qtime = stbuf.st_mtime;

		(void) strncpy(afile, BASENAME(file, '/'), NAMESIZE);
		afile[NAMESIZE-1] = NULLCHAR;
		*afile = BOOKMARK_PRE; /* make up name by replacing C with A */
		acount = 0;
		p_bookmark = fopen(afile, "r");
		if (p_bookmark != NULL) {
			/* get count of already completed work */
			i = fscanf(p_bookmark, "%hd", &acount);
			(void) fclose(p_bookmark);
			if (i <= 0)
				acount = 0;

			/* skip lines which have already been processed */
			for (i = 0; i < acount; i++) {
				if (fgets(str, MAXRQST, fp) == NULL)
					break;
			}
		}

	}

	if (fgets(str, MAXRQST, fp) == NULL) {
		ASSERT(unlink(file) == 0, Ct_UNLINK, file, errno);
		(void) unlink(afile);
		DEBUG(4,"Finished Processing file: %s\n",file);
		*file = '\0';
		CLEAN_RETURN(fp);
		/*NOTREACHED*/
	}

	nargs = getargs(str, wvec, wcount);

	/* sanity checks for C. file */
	if ((str[0] != 'R' && str[0] != 'S')	/* legal wrktypes are R and S */
	 || (str[0] == 'R' && nargs < 6)	/* R lines need >= 6 entries */
	 || (str[0] == 'S' && nargs < 7)) {	/* S lines need >= 7 entries */
		/* bad C. file - stash it */
		toCorrupt(file);
		(void) unlink(afile);
		*file = '\0';
		CLEAN_RETURN(fp);
		/*NOTREACHED*/
	}

	p_bookmark = fopen(afile, "w"); /* update bookmark file */
	if (p_bookmark == NULL)
	    errent(Ct_OPEN, afile, errno, __FILE__, __LINE__);
	else {
	    chmod(afile, CFILEMODE);
	    (void) fprintf(p_bookmark, "%d", acount);
	    (void) fclose(p_bookmark);
	}
	acount++;
	return(nargs);
}

/*
 * Check the list of work files (C.sys).
 * If it is empty or the present work is exhausted, it
 * will call bldflst to generate a new list.
 *
 * If there are no more jobs in the current job grade,
 * it will call findgrade to get the new job grade to process.
 *
 *	file	-> address of array to return full pathname in
 * returns:
 *	0	-> no more work (or some error)
 *	1	-> there is work
 */
extern int
iswrk(file)
char *file;
{
	char newspool[MAXFULLNAME];
	char lockname[MAXFULLNAME];
	char gradedir[2*MAXBASENAME];

	if (Nfiles == 0) {
		/* If Role is MASTER and JobGrade is null, then
		 * there is no work for the remote.
		 *
		 * In the case of uucico slave, the job grade
		 * to process should be determined before building
		 * the work list.
		 */
		if (Role == MASTER) {
		    if (*JobGrade == NULLCHAR)
			return(0);

		    if (bldflst() != 0) {
			(void) sprintf(file, "%s/%s", RemSpool, Fptr[Nnext]);
			Nfiles--;
			Nnext++;
			return(1);
		    }
		    (void) sprintf(lockname, "%.*s.%s", SYSNSIZE, Rmtname, JobGrade);
		    delock(LOCKPRE, lockname);
		} else {
		    (void) sprintf(lockname, "%ld", (long) getpid());
		    delock(LOCKPRE, lockname);
		}

		(void) sprintf(newspool, "%s/%s", SPOOL, Rmtname);
		ASSERT(chdir(newspool) == 0, Ct_CHDIR, newspool, errno);

		findgrade(newspool, JobGrade);
		DEBUG(4, "Job grade to process - %s\n", JobGrade);
		if (*JobGrade == NULLCHAR)
		    return(0);

		(void) sprintf(lockname, "%.*s.%s", SYSNSIZE, Rmtname, JobGrade);
		(void) umlock(LOCKPRE, lockname);

		/* Make the new job grade directory the working directory
		 * and set RemSpool.
		 */
		(void) sprintf(gradedir, "%s/%s", Rmtname, JobGrade);
		chremdir(gradedir);
		bldflst();
	}

	(void) sprintf(file, "%s/%s", RemSpool, Fptr[Nnext]);
	Nfiles--;
	Nnext++;
	return(1);
}


/*
 * build list of work files for given system using an insertion sort
 * Nfiles, Nnext, RemSpool and Rmtname are global
 *
 * return:
 *	number of C. files in list - (Nfiles)
 */
static int
bldflst()
{
	DIR *pdir;
	char filename[NAMESIZE];
	char prefix[SYSNSIZE+3];

	Nnext = Nfiles = 0;
	if ((pdir = opendir(RemSpool)) == NULL)
		return(0);

	(void) sprintf(prefix, "C.%.*s", SYSNSIZE, Rmtname);
	while (gnamef(pdir, filename) ) {
		if (!PREFIX(prefix, filename))
		    	continue;
		if ((strlen(filename)-strlen(prefix)) != SUFSIZE) {
			errent("bldflst: Funny filename", filename, 0,
			   __FILE__, __LINE__);
			continue;
		}
		insert(filename);
	}
	closedir(pdir);
	return(Nfiles);
}

/*
 * get work return
 *	file	-> place to deposit file name
 *	wrkvec	-> array to return arguments
 *	wcount	-> max number of args for wrkvec
 * returns:
 *	nargs  	->  number of arguments
 *	0 	->  no arguments - fail
 */
extern int
gtwvec(char *file, char **wrkvec, int wcount)
{
	int nargs;

	DEBUG(7, "gtwvec: dir %s\n", RemSpool);
	while ((nargs = anlwrk(file, wrkvec, wcount)) == 0) {
		if (!iswrk(file))
			return(0);
	}
	DEBUG(7, "        return - %d\n", nargs);
	return(nargs);
}


/*
 * insert - insert file name in sorted list
 * return - none
 */
static void
insert(file)
char *file;
{
	int i, j;
	char *p;

	DEBUG(7, "insert(%s)  ", file);
	for (i = Nfiles; i>0; i--) {
	    if (strcmp(file, Fptr[i-1]) > 0)
		break;
	}
	if (i == LLEN) /* if this is off the end get out */
	    return;

	/* get p (pointer) to where the text of name will go */
	if (Nfiles == LLEN)	/* last possible entry */
	    /* put in text of last and decrement Nfiles for make hole */
	    p = strcpy(Fptr[--Nfiles], file);
	else
	    p = strcpy(Filent[Nfiles], file);	/* copy to next free  */

	/* make a hole for new entry */
	for (j = Nfiles; j >i; j--)
	    Fptr[j] = Fptr[j-1];

	DEBUG(7, "insert %s ", p);
	DEBUG(7, "at %d\n", i);
	Fptr[i] = p;
	Nfiles++;
	return;
}

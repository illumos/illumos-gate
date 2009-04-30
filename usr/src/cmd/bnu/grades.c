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

#include "uucp.h"
#include <grp.h>

#define G_EXT	0
#define	G_INT	1
#define	G_RES	2
#define	G_ACT	3
#define	G_IDF	4
#define	G_MAX	512	/* max number of fields in the Grades file line */
#define	SMBUF	128

#define	TYPE	0
#define FILE1	1
#define	FILE2	2
#define	USER	3
#define	OPTS	4
#define	FILE3	5

extern int rdfulline(), jsize(), gdirf(), gnamef();
extern void wfcommit();

static void	mailAdmin();		/* Send mail to administrator. */

/*
 * chkgrp - checks to see the group has permission
 *		to use a service grade queue.
 *
 * returns
 *
 *	SUCCESS - if the group has permissions
 *	FAIL - if group does not
 *
 */

static int
chkgrp(carray,na)
char **carray;
int na;
{
	struct group *grp;
	int i;
	gid_t gid;

	gid = getgid();
	grp = getgrgid(gid);

	for (i = G_IDF; i < na; i++)
			if (EQUALS(carray[i], grp->gr_name))
				return(SUCCESS);

	return(FAIL);
}

/*
 * chkusr - checks the permission fields of the Grades file
 *	    to determine if the user can queue to a particular service grade.
 *
 * returns
 *
 *	SUCCESS - if the user can queue to the service grade.
 *	FAIL - if the user can not queue to this service grade.
 *
 */

static int
chkusr(carray, na)
char **carray;
int na;
{
	int i;

	/*
	 * start at the point where the users are supposed to be in the
	 * Grades file. Loop thru until the end of the user list is
	 * found or the user name is found. If the user name is found then
	 * return TRUE. If the end of the list is found, return FAIL.
	 */

	DEBUG(9, "User (%s)\n", User);

	/* check for any user and return if so */

	if (EQUALS(carray[G_IDF], "Any"))
		return(SUCCESS);

	DEBUG(9, "Members of administrator defined service grade (%s)\n", carray[G_EXT]);

	for (i = G_IDF; i < na; i++) {
		DEBUG(9, "%s\n", carray[i]);
		if (EQUALS(User, carray[i]))
			return(SUCCESS);
	}

	return(FAIL);
}

/*
 *	fgrade - finds the appropiate queue to queue a job into
 *
 *	returns
 *		SUCCESS	-> found a queue
 *		FAIL	-> can't find a queue
 */

int
fgrade(scfile)
struct cs_struct *scfile;
{
	char fdgrade();
	FILE *cfd;
	char line[BUFSIZ];
	char *carray[G_MAX];
	long climit;

	/* Check for the default service grade first */

	if (strcmp(scfile->sgrade, "default") == 0) {
		scfile->grade = fdgrade();
		return(SUCCESS);
	}

	/* open grades file to begin a linear for the grade requested */

	cfd = fopen(GRADES, "r");

	/* loop until the file is empty or we find the grade we want */

	while (rdfulline(cfd, line, BUFSIZ) != 0) {
		(void) getargs(line, carray, G_MAX);

		/* check to see if this is the grade we want */

		if (!EQUALS(scfile->sgrade, carray[G_EXT]))
			continue;

		if (jsize(scfile, carray[G_RES], &climit) != FAIL) {
			(void) fclose(cfd);
			scfile->grade = *carray[G_INT];
			return(SUCCESS);
		}
	}

	(void) fclose(cfd);

	(void) fprintf(stderr, gettext("Job size (%ld bytes)"
	    " exceeds maximum number of bytes (%ld bytes)"
	    " allowed into this service grade (%s).\n"
	    "Job queued to default grade.\n"),
	    scfile->jsize, climit, scfile->sgrade);

	scfile->grade = fdgrade();
	return(SUCCESS);
}

/*
 *	fdgrade - finds the default queue for this system
 *
 *	returns
 *		a one char name for the default queue
 *
 */

char
fdgrade()
{
	FILE *cfd;
	char line[BUFSIZ];
	char *carray[G_MAX];

	/* Check for the default grade first */

		cfd = fopen(GRADES, "r");

		/* loop until the end of the file is read */

		for (; rdfulline(cfd, line, BUFSIZ) != 0;) {

			/* parse the fields of this line */

			(void) getargs(line, carray, G_MAX);

			/* check to see if the administrator has defined
			 * a default grade for the machine.
			 */

			if (strcmp(carray[G_EXT], "default") != 0)
				continue;

			/* default must be defined in the file
			 *  close the file, get the queue name, and return.
			 */

			(void) fclose(cfd);
			return(*carray[G_INT]);
		}

		/* no default defined in this file. close file.
		 * get our default queue and return.
		 */

		(void) fclose(cfd);
		return(D_QUEUE);
}

/*
 * job_size - determines the size of a job
 *
 * returns
 *
 *	SUCCESS - if the size of the job can be determined
 *	FAIL	- otherwise
 */

int
job_size(scfile)
struct cs_struct *scfile;
{
	extern int Dfileused;
	struct stat s;
	FILE *fp;
	char line[BUFSIZ];
	char *carray[G_MAX];
	int na;
	int nodfile = FALSE;
	int ret;

	scfile->jsize = 0;

	fp = fopen(scfile->file, "r");

	if (fp == NULL) {
		toCorrupt(scfile->file);
		errent(Ct_OPEN, scfile->file, errno, __FILE__,  __LINE__);
	}

	while (fgets(line, BUFSIZ, fp) != NULL) {
		na = getargs(line, carray, G_MAX);

		if (na < 6) {
			(void) fclose(fp);
			toCorrupt(scfile->file);
			errent("BAD NUMBER OF ARGUMENTS", scfile->file, 0,
				__FILE__, __LINE__);
		}

		/* if the type of a transfer is not a push
		 * then don't try to determine the size of
		 * the data file, because you can't.
		 */

		if (*carray[TYPE] == 'R')
			continue;

		/* find the data dile that is to be transferred */

		if ((ret = stat(carray[FILE3], &s)) != 0) {
			if (errno == ENOENT) {
				nodfile = TRUE;
				ret = stat(carray[FILE1], &s);
			}
		}
		else
			Dfileused = TRUE;

		/*
		 * check to see if the return code from stat was 0
		 * if return code was not 0, write message to error
		 * log and quit. Otherwise, add size of file to job
		 * size and continue looping.
		 */

		if (ret != 0) {
			(void) fclose(fp);
			errent(Ct_STAT, nodfile ?
				carray[FILE1] : carray[FILE3], errno,
				__FILE__, __LINE__);
		}

		nodfile = FALSE;
		scfile->jsize += s.st_size;
	}
	(void) fclose(fp);
	return(SUCCESS);
}

static void lcase();

/*
 * jsize - determines whether if a job is small enough to
 * 	   be placed in the appropiate queue.
 *
 * returns
 *
 *	SUCCESS - if the size of the job is less than or
 *		  equal to the number of bytes in the restriction
 *		  of the GRADES file.
 *
 *	FAIL	- otherwise
 */

int
jsize(scfile, climit, nlimit)
struct cs_struct *scfile;
char *climit;
long *nlimit;
{
#define ONE_K (1024)
#define ONE_MEG ((1024)*(1024))

	char rest[SMBUF];
	char msg[BUFSIZ], *p;

	if (EQUALS(climit, "Any"))
		return(SUCCESS);

	lcase(climit, rest, SMBUF);

	if (!(p = strchr(rest, 'k')) && (!(p = strchr(rest, 'm')))) {

		for(p = climit; *p; ++p) {
			if (isdigit(*p))
				continue;

			/* corrupt restriction field in the Grades file.
			 * report it to the uucp administrator.
			 */

			snprintf(msg, sizeof (msg),
			    gettext("Error encountered in the"
			    " restrictions field of the Grades file."
			    "  Field contents (%s)."), climit);
			mailAdmin(msg);
			return(SUCCESS);
		}

		*nlimit = atol(climit);
	}
	else if (*p == 'k') {
		*p = '\0';
		*nlimit = (long) (atof(rest) * ONE_K);
	}
	else {
		*p = '\0';
		*nlimit = (long) (atof(rest) * ONE_MEG);
	}

	if (scfile->jsize <= *nlimit)
		return(SUCCESS);
	else
		return(FAIL);
}

static void
lcase(s, t, lim)
char s[], t[];
int lim;
{
	char *p;
	int i;


	p = s;

	for (i = 0; i < lim-1 && *p; i++)
		if (isupper(*p))
			t[i] = tolower(*p++);
		else
			t[i] = *p++;

	t[i] = '\0';
	return;
}

/*
 * mailAdmin - mail a message to the uucp administrator.
 *
 * returns:
 *
 *	nothing
 */

static void
mailAdmin (msg)

char *	msg;

{
	char	cmd[BUFSIZ];		/* Place to build mail command. */
	FILE *	mail;			/* Channel to write mail on. */

	(void) sprintf(cmd, "%s %s %s", PATH, MAIL, "uucp");
	if ((mail = popen(cmd, "w")) != (FILE *) NULL)
	{
		(void) fprintf(mail, "To: uucp\nSubject: %s\n\n%s\n",
		    gettext("Grades file problem"), msg);
		(void) pclose(mail);
	}

	/*
	 * Ignore popen failure.  There is not much that we can do if
	 * it fails, since we are already trying to notify the administrator
	 * of a problem.
	 */
	return;
}

/*
 * putdfiles - moves any and all of the D. to the spool directory for
 * 	       a C. file.
 *
 * returns
 *
 *	nothing
 */

void
putdfiles(scfile)
struct cs_struct scfile;
{
	FILE *fp;
	char line[BUFSIZ];
	char *carray[G_MAX];
	int na;
	struct stat s;

	fp = fopen(scfile.file, "r");

	if (fp == NULL) {
		toCorrupt(scfile.file);
		errent(Ct_OPEN, scfile.file, errno, __FILE__, __LINE__);
	}

	while (fgets(line, BUFSIZ, fp) != NULL) {

		na = getargs(line, carray, G_MAX);
		if (na < 6) {
			(void) fclose(fp);
			toCorrupt(scfile.file);
			errent("BAD NUMBER OF ARGUMENTS", scfile.file, 0,
				__FILE__, __LINE__);
		}

		if (*carray[TYPE] == 'R')
			continue;

	    	/* move D. file to the spool area */

		if (stat(carray[FILE3], &s) != -1)
			wfcommit(carray[FILE3], carray[FILE3], scfile.sys);
	}

	(void) fclose(fp);
	return;
}

/*
 * reads a line from a file and takes care of comment lines
 * and continuations (\) in last column.
 *
 * return:
 *	the number of chars that are placed in line.
 */

int
rdfulline(fd, line, lim)
FILE *fd;
char *line;
int lim;
{
	register char *p, *c;
	char buf[BUFSIZ];
	size_t blr, btox;

	p = line;
	for (;fgets(buf, BUFSIZ, fd) != NULL;) {
		/* check to see if it is a comment */

		if (buf[0] == '#')
			continue;

		/* remove trailing white space */
		c = &buf[strlen(buf)-1];
		while (c>=buf && (*c == '\n' || *c == '\t' || *c == ' ') )
			*c-- = NULLCHAR;

		if (buf[0] == '\n' || buf[0] == NULLCHAR)
			continue;

		blr = lim - 1 - (p - line);
		btox = blr < strlen(buf) ? blr : strlen(buf);

		if (btox <= 0)
			break;

		(void) strncpy(p, buf, btox);
		p += btox - 1;

		if ( *(p-1) == '\\')
			p--;
		else
			break;
	}

	*++p = '\0';
	return(p-line-1);
}

/*	upermit - checks to determine if the user has permissions
 *	to use administrator defined service grade.
 *
 *	returns
 *		SUCCESS -> if the user can queue to this service grade.
 *		FAIL -> if the user cannot queue to this service grade.
 */

int
upermit(carray, na)
char **carray;
int na;
{
#define G_USR "user"
#define G_NUSR "non-user"
#define G_GRP "group"
#define G_NGRP "non-group"

	char actn[SMBUF];
	char ufld[SMBUF];
	char msg[BUFSIZ];

	(void) strcpy(actn, carray[G_ACT]);

	lcase(actn, ufld, SMBUF);

	if (EQUALS(ufld, G_USR))
		return(chkusr(carray,na));

	if (EQUALS(ufld, G_NUSR))
		return((chkusr(carray, na) != SUCCESS) ? SUCCESS : FAIL);

	if (EQUALS(ufld, G_GRP))
		return(chkgrp(carray, na));

	if (EQUALS(ufld, G_NGRP))
		return((chkgrp(carray, na) != SUCCESS) ? SUCCESS : FAIL);

	(void) snprintf(msg, sizeof (msg),
	    gettext("Error encountered in action field of"
	    " the Grades file. Field contents (%s)."), carray[G_ACT]);
	mailAdmin(msg);
	return(FAIL);
}

/*
 *	vergrd - verify if the grade name is a valid administrator
 *		 defined service grade name and if the user has the
 *		 appropiate permission to use this grade.
 *
 *	returns
 *		SUCCESS	-> grade is valid and user is
 *			   permitted to use this grade.
 *		FAIL	-> otherwise
 *
 */

int
vergrd(grade)
char *grade;
{
	FILE *cfd;
	char line[BUFSIZ];
	char *carray[G_MAX];
	int na;

	/* Check for the default grade first */

	if (EQUALS(grade, "default"))
		return(SUCCESS);

	/* open grades file to begin a linear for the grade requested */

	cfd = fopen(GRADES, "r");

	/* loop until the file is empty or we find the grade we want */

	while (rdfulline(cfd, line, BUFSIZ) != 0) {
		na = getargs(line, carray, G_MAX);

		/* check to see if this is the grade we want */

		if (!EQUALS(grade, carray[G_EXT]))
			continue;

		/* check for the permission on this grade */

		if (upermit(carray, na) != FAIL) {
			(void) fclose(cfd);
			return(SUCCESS);
		}
		else {
			(void) fclose(cfd);
			(void) fprintf(stderr, gettext("User does not have"
			    " permission to use this service grade (%s).\n"
			    "Job has not been queued.\n"
			    "Use (uuglist) to find which service grades"
			    " you can queue to.\n"), grade);
			return(FAIL);
		}
	}

	(void) fclose(cfd);

	(void) fprintf(stderr, gettext(
	    "Service grade (%s) does not exist on this machine."
	    "  Job not queued.\n"
	    "Use (uuglist) to find which service grades are available on"
	    " this machine.\n"), grade);
	return(FAIL);
}

/*
 * wfremove - removes a C. file from the Workspace directory and all of its
 * D. files.
 */

void
wfremove(file)
char *file;
{
	FILE *fp;
	char line[BUFSIZ];
	char *carray[G_MAX];
	int na;
	struct stat s;

	fp = fopen(file, "r");

	if (fp == NULL) {
		toCorrupt(file);
		errent(Ct_OPEN, file, errno, __FILE__, __LINE__);
	}

	while (fgets(line, BUFSIZ, fp) != NULL) {
		na = getargs(line, carray, G_MAX);

		if (na < 6) {
			(void) fclose(fp);
			toCorrupt(file);
			errent("BAD NUMBER OF ARGUMENTS", file, 0,
				__FILE__, __LINE__);
		}

		if (*carray[TYPE] == 'R')
			continue;

	    	/* remove D. file */

	    	DEBUG(4, "Removing data file (%s)\n", carray[FILE3]);

		if ((stat(carray[FILE3], &s) != -1) && (unlink(carray[FILE3]) != 0)) {
			(void) fclose(fp);
			toCorrupt(file);
			toCorrupt(carray[FILE3]);
			errent(Ct_UNLINK, carray[FILE3], errno, __FILE__,
				__LINE__);
		}
	}

	(void) fclose(fp);

	DEBUG(4, "Removing work file (%s)\n", file);

	if (unlink(file) != 0) {
		toCorrupt(file);
		errent(Ct_UNLINK, file, errno, __FILE__, __LINE__);
	}
	return;
}

/*
 * findgrade - finds the highest priority job grade that is not locked
 * and that has jobs.
 *
 * job grade name is null, if no job grade is found.
 */

void
findgrade(dir, jobgrade)
char *dir, *jobgrade;
{
	char prevgrade[MAXBASENAME+1], curgrade[MAXBASENAME+1],
	     gradedir[MAXBASENAME+1];
	char lockname[MAXFULLNAME];
	char Cfile[MAXBASENAME+1];
	DIR *p, *q;

	*prevgrade = NULLCHAR;
	p = opendir(dir);
	ASSERT(p != NULL, Ct_OPEN, dir, errno);

	while (gdirf(p, gradedir, dir) == TRUE) {
		(void) sprintf(lockname, "%s.%.*s.%s", LOCKPRE, SYSNSIZE,
		    Rmtname, gradedir);
		if (cklock(lockname) == FAIL)
			continue;
		q = opendir(gradedir);
		ASSERT(q != NULL, Ct_OPEN, gradedir, errno);
		while (gnamef(q, Cfile) == TRUE) {
			if (Cfile[0] == CMDPRE) {
				if (*prevgrade == NULLCHAR) {
					(void) strcpy(prevgrade, gradedir);
					break;
				}
				(void) strcpy(curgrade, gradedir);
				if (strcmp(curgrade, prevgrade) < 0)
					(void) strcpy(prevgrade, curgrade);
			}
		}
		closedir(q);
	}
	closedir(p);
	(void) strncpy(jobgrade, prevgrade, MAXBASENAME);
	jobgrade[MAXBASENAME] = NULLCHAR;
	return;
}

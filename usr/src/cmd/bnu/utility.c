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

#include "uucp.h"

static void logError();
extern int cuantos(), gnamef();

#define TY_ASSERT	1
#define TY_ERROR	2

/*
 *	produce an assert error message
 * input:
 *	s1 - string 1
 *	s2 - string 2
 *	i1 - integer 1 (usually errno)
 *	file - __FILE of calling module
 *	line - __LINE__ of calling module
 */
void
assert(char *s1, char *s2, int i1, char *file, int line)
{
	logError(s1, s2, i1, TY_ASSERT, file, line);
	return;
}


/*
 *	produce an assert error message
 * input: -- same as assert
 */
void
errent(char *s1, char *s2, int i1, char *file, int line)
{
	logError(s1, s2, i1, TY_ERROR, file, line);
	return;
}

#define EFORMAT	"%sERROR (%.9s)  pid: %ld (%s) %s %s (%d) [FILE: %s, LINE: %d]\n"

static void
logError(char *s1, char *s2, int i1, int type, char *file, int line)
{
	FILE *errlog;
	char text[BUFSIZ];
	pid_t pid;

	if (Debug)
		errlog = stderr;
	else {
		errlog = fopen(ERRLOG, "a");
		(void) chmod(ERRLOG, PUB_FILEMODE);
	}
	if (errlog == NULL)
		return;

	pid = getpid();

	(void) fprintf(errlog, EFORMAT, type == TY_ASSERT ? "ASSERT " : " ",
	    Progname, (long) pid, timeStamp(), s1, s2, i1, file, line);

	if (!Debug)
		(void) fclose(errlog);

	(void) sprintf(text, " %sERROR %.100s %.100s (%.9s)",
	    type == TY_ASSERT ? "ASSERT " : " ",
	    s1, s2, Progname);
	if (type == TY_ASSERT)
	    systat(Rmtname, SS_ASSERT_ERROR, text, Retrytime);
	return;
}


/* timeStamp - create standard time string
 * return
 *	pointer to time string
 */

char *
timeStamp()
{
	register struct tm *tp;
	time_t clock;
	static char str[20];

	(void) time(&clock);
	tp = localtime(&clock);
	(void) sprintf(str, "%d/%d-%d:%2.2d:%2.2d", tp->tm_mon + 1,
	    tp->tm_mday, tp->tm_hour, tp->tm_min, tp->tm_sec);
	return(str);
}


/*
* Function:	countProcs - Count Process to Stay Within Limits
*
* There are a number of cases in BNU when we want to limit the number
* of processes of a certain type that are running at a given time.  This
* process is used to check the number of existing processes, to determine
* if a new one is allowed.
*
* The strategy is that all processes of a given type will place a lock
* file with a specific prefix in a single directory, usually
* /var/spool/locks.  The caller of this function must provide a full
* path prefix, and countProcs will count the number of files that begin
* with the prefix and compare the count to the allowable maximum.
*
* Parameters:
*
*	prefix -	A full path prefix for lock files that identify
*			processes that are to be counted.
*	maxCount -	Maximum number of allowable processes.
*
* Returns:
*
*	TRUE is returned if this process is allowed to continue, and
*	FALSE is returned if the maximum is exceeded.
*/

int
countProcs (prefix, maxCount)

char *	prefix;
int	maxCount;

{
	register char *	namePrefix;		/* Points to file name part */

	char		directory[MAXNAMESIZE];
	register int	processes;		/* Count of processes. */

	/* Separate prefix into directory part and file name part. */

	strncpy(directory, prefix, MAXNAMESIZE);
	directory[MAXNAMESIZE-1] = NULLCHAR;
	namePrefix = strrchr(directory, '/');
	ASSERT(namePrefix  != NULL, "No file name in", prefix, 0);
	*namePrefix++ = NULLCHAR;		/* Terminate directory part */

	/* Check to see if we can continue. */

	processes = cuantos(namePrefix, directory);
	if (processes <= maxCount)
		return TRUE;
	else
		return FALSE;
}


/*
 * return the number of files in directory <dir> who's names
 * begin with <prefix>
 * This is used to count the number of processes of a certain
 * type that are currently running.
 *
 */
int
cuantos(prefix, dir)
char *prefix, *dir;
{
	int i = 0;
	DIR	*pdir;
	char fullname[MAXNAMESIZE], file[MAXNAMESIZE];

	pdir = opendir(dir);
	ASSERT(pdir != NULL, Ct_OPEN, dir, errno);

	while (gnamef(pdir, file) == TRUE)
		if (PREFIX(prefix, file)) {
		    (void) sprintf(fullname, "%s/%s", dir, file);
		    if (cklock(fullname))
			i++;
		}
	closedir(pdir);
	return(i);
}

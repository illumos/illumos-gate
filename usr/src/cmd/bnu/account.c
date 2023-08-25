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


#ident	"%Z%%M%	%I%	%E% SMI"	/* from SVR4 bnu:account.c 1.3 */
/*
*/

#include	"uucp.h"
#include	"log.h"
#include <pwd.h>

/*
*		SYMBOL DEFINITIONS
*/

#define	FS		' '	/* Field seperator for output records. */
#define	STD		'S'	/* standard service. */
#define LOGCHECK	{ if (Collecting == FALSE) return; }

/*
*		STRUCTURE DEFINITIONS
*/

struct acData			/* Data for construction of account record. */
		{
			char	uid[MODSTR]; /* user id */
			char	jobID[MODSTR]; /* C. file */
			off_t	jobsize;	/* Bytes transferred in a job.*/
			char	status; /* transaction status */
			char	service; /* service grade */
			char	jobgrade[MODSTR]; /* job grade */
			char	time[MODSTR]; /* date and time the job execed */
			char	origSystem[MODSTR]; /* originating system's 							   name */
			char	origUser[MODSTR]; /* originator's login
							   name */
			char	rmtSystem[MODSTR]; /* system's name of
							   first hop */
			char	rmtUser[MODSTR]; /* user's name of first
							   hop */
			char	device[MODSTR]; /* network medium */
			char	netid[MODSTR]; /* Network ID in use */
			char	type[MODSTR]; /* type of transaction */
			char	path[BUFSIZ]; /* path of the rest of the hops */

		};

/*
*		LOCAL DATA
*/

static int		Collecting = FALSE; /* True if we are collecting
					     *   data. */
static int		LogFile = CLOSED; /* Log file file destriptor. */
static char		LogName[] = ACCOUNT; /* Name of our log file. */
static char		Record[LOGSIZE]; /* Place to build log records. */

static struct acData	Acct;	/* Accounting data. */

/*
*		LOCAL FUNCTIONS
*/

/* Declarations of functions: */

STATIC_FUNC void	reportJob();

/*
* Local Function:	reportJob - Write Job accounting information to Log
*
* This function writes accounting information about the current job to the log
* file.
*
* Parameters:
*
*	none.
*/

STATIC_FUNC void
reportJob ()

{
	static char	format[] = "%s%c%s%c%ld%c%c%c%c%c%s%c%s%c%s%c(%s)%c%s%c%s%c%s%c%s%c%s%c%s%c";

	register struct acData *	acptr;

	acptr = &Acct;			/* Point to Acct data. */
	sprintf(Record, format,
		acptr->uid, FS,
		acptr->jobID, FS,
		acptr->jobsize, FS,
		acptr->status, FS,
		acptr->service, FS,
		acptr->jobgrade, FS,
		acptr->origSystem, FS,
		acptr->origUser, FS,
		acptr->time, FS,
		acptr->rmtSystem, FS,
  		acptr->rmtUser, FS,
		acptr->device, FS,
		acptr->netid, FS,
		acptr->type, FS,
		acptr->path, FS);

	/* Terminate the record and write it out. */

	(void) strcat(Record, EOR);
	writeLog(Record,&LogFile,LogName,&Collecting);
}


/*
*		EXTERNAL FUNCTIONS
*/

/*
* Function:	acConnected - Report Connection Completion
*
* Parameters:
*
*	remote -	name of the remote system.
*
*	device -	the type of device being used for communicaitons.
*/

void
acConnected (remote, device)

char *	remote;
char *	device;

{
	register struct acData *	acptr = &Acct;

	LOGCHECK;
	copyText(acptr->rmtSystem, sizeof(acptr->rmtSystem), remote);
	copyText(acptr->device, sizeof(acptr->device), device);
	acptr->service = 'S'; /* default to standard service */
}

/* Function:	acDojob - Found Another Job
*
* acDojob  is called when a new job has been found.
*
* Parameters:
*
*	jobid -		The name of the job that was found.
*
*	system -	Originating system's name.
*
*	user -		Originator's login name.
*/

void
acDojob(jobid, system, user)

char *	jobid;
char *	system;
char *	user;

{
	register struct acData *	acptr = &Acct;

struct passwd *passent;
	LOGCHECK;
	if (strcmp(acptr->jobID,jobid) == 0)
		return;
	if ((*acptr->jobID != NULLCHAR) && (acptr->jobsize != 0)){
		reportJob();
	}
	copyText(acptr->jobID, sizeof(acptr->jobID), jobid);
	copyText(acptr->origSystem, sizeof(acptr->origSystem), system);
	copyText(acptr->origUser, sizeof(acptr->origUser), user);
	copyText(acptr->time, sizeof(acptr->time), timeStamp());
	acptr->jobgrade[0] = jobid[strlen(jobid)-5];
	acptr->jobgrade[1] = NULLCHAR;/* get job grade from jobid */
	acptr->jobsize = 0;
	while ((passent = getpwent()) != NULL){
	  if (strcmp(passent->pw_name,user) == 0){
		sprintf(acptr->uid,"%ld",(long) passent->pw_uid);
		break;
	  }
	}
}

/* End recording the accounting log */

void
acEnd(status)
char status;
{
	register struct acData *	acptr = &Acct;

	LOGCHECK;
	if (((*acptr->jobID != NULLCHAR) && (acptr->jobsize != 0))
			|| (status == PARTIAL)){
		acptr->status = status;
		reportJob();
	}

}

/* increment job size */

void
acInc()
{
	register struct acData *	acptr = &Acct;

	LOGCHECK;
	acptr->jobsize += getfilesize();
}

/*
* Function:	acInit - Initialize Accounting Package
*
* This function allows the accounting package to initialize its internal
* data structures.  It should be called when uucico starts running on master
* or changes the role from slave to master, or uuxqt is invoked.
*
* Parameters:
*
*	type: file transfer or remote exec.
*/

void
acInit (type)
char * type;

{
	register struct acData *	acptr = &Acct;

	/*
	* Attempt to open the log file.  If we can't do it, then we
	* won't collect statistics.
	*/

	if (openLog(&LogFile,LogName) == SUCCESS){
		Collecting = TRUE;
		acptr->service = STD; /* default to standard service */
		acptr->status = COMPLETE; /* default to completed transfer */
		copyText(acptr->jobgrade, sizeof(acptr->jobgrade), NOTAVAIL);
		copyText(acptr->uid, sizeof(acptr->uid), NOTAVAIL);
		copyText(acptr->origSystem, sizeof(acptr->origSystem), NOTAVAIL);
		copyText(acptr->origUser, sizeof(acptr->origUser), NOTAVAIL);
		copyText(acptr->rmtSystem, sizeof(acptr->rmtSystem), NOTAVAIL);
		copyText(acptr->rmtUser, sizeof(acptr->rmtUser), NOTAVAIL);
		copyText(acptr->device, sizeof(acptr->device), NOTAVAIL);
		copyText(acptr->netid, sizeof(acptr->netid), NOTAVAIL);
		copyText(acptr->path, sizeof(acptr->path), NOTAVAIL);
		copyText(acptr->type, sizeof(acptr->type), type);
	}
	else
		Collecting = FALSE;
}

/*
* It is called when uuxqt is running
*
*	jobid - jobid after X. prefix
*	origsys - Originating system's name.
*	origuser - Originator's login name.
*	connsys - local system
*	connuser - login user
*	cmd - command to be execed by uuxqt
*/
void
acRexe(jobid,origsys,origuser,connsys,connuser,cmd)
char * jobid;
char * origsys;
char * origuser;
char * connsys;
char * connuser;
char * cmd;
{
	register struct acData *	acptr = &Acct;

	LOGCHECK;
	copyText(acptr->jobID, sizeof(acptr->jobID), jobid);
	copyText(acptr->origSystem, sizeof(acptr->origSystem), origsys);
	copyText(acptr->origUser, sizeof(acptr->origUser), origuser);
	copyText(acptr->rmtSystem, sizeof(acptr->rmtSystem), connsys);
	copyText(acptr->rmtUser, sizeof(acptr->rmtUser), connuser);
	copyText(acptr->path, sizeof(acptr->path), cmd);
	copyText(acptr->time, sizeof(acptr->time), timeStamp());
}
/*
* It is called when the command to be execed is finished
*
*	cpucycle: cpu time the command is consumed
*/
void
acEndexe(cycle,status)
time_t	cycle;
char status;
{

	register struct acData *	acptr = &Acct;

	LOGCHECK;
	acptr->jobsize = cycle;
 	acptr->status = status;
 	reportJob();
}
/*
 *	cpucycle()
 *
 *	return cputime(utime+stime) since last time called
 */
time_t
cpucycle()
{
	struct tms	tbuf;
 	time_t	rval;
 	static time_t	utime,stime;	/* guaranteed 0 first time called */

 	times(&tbuf);
 	rval = ((tbuf.tms_utime-utime) + (tbuf.tms_stime-stime))*1000/HZ;
 	utime = tbuf.tms_utime;
 	stime = tbuf.tms_stime;
 	return(rval);
}

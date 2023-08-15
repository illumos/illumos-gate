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


#ident	"%Z%%M%	%I%	%E% SMI"	/* from SVR4 bnu:security.c 1.3 */
/*
 */

#include	"uucp.h"
#include	"log.h"

extern int guinfo();

/*
 *		SYMBOL DEFINITIONS
 */

#define	FS		' '	/* Field seperator for output records. */
#define LOGCHECK	{ if (Collecting == FALSE) return; }
#define LOGCHECKC	{ if (Collecting == FALSE) return(NOTAVAIL); }

/*
 *		STRUCTURE DEFINITIONS
 */

struct secXfer			/* Data for construction of security record. */
		{
			char	reqSystem[MODSTR]; /* requester system name */
			char	reqUser[MODSTR]; /* requester login name */
			char	desSystem[MODSTR]; /* destination system name */
			char	desUser[MODSTR]; /* destination login name */
			char	desFile[MODSTR]; /* destination file name */
			char	srcSystem[MODSTR]; /* source system name */
			char	srcOwner[MODSTR]; /* source file owner */
			char	srcFile[MODSTR]; /* source file name */
			char	srcSize[MODSTR];/* source file size in Bytes .*/
			char	srcMtime[MODSTR]; /* modification date and time of
						source file */
			char	stime[MODSTR]; /* date and time that transfer
 							started */
			char	etime[MODSTR]; /* date and time that transfer
 							completed */
		};

struct secRexe			/* Data for construction of security record. */
		{
			char	cliSystem[MODSTR]; /* client system name */
			char	cliUser[MODSTR]; /* client login name */
			char	serUser[MODSTR]; /* server login name */
			char	time[MODSTR]; /* date and time that command was
						 issued*/
			char	command[BUFSIZ]; /* command name and options */
		};
/*
 *		LOCAL DATA
 */

static int		Collecting = TRUE; /* ok to collect security inf.*/
static int		LogFile = CLOSED; /* Log file file destriptor. */
static char		LogName[] = SECURITY; /* Name of our log file. */
static char		Record[LOGSIZE]; /* Place to build log records. */
static char		Type[MODSTR]; /* record type */

static struct secXfer	Xfer;	/* security transfer data. */
static struct secRexe	Rexe;	/* security remote execution data. */

/*
 *		LOCAL FUNCTIONS
 */


/*
 * Local Function:	newRec - Initialize new record
 */

STATIC_FUNC void
newRec(type)
char * type;
{
	register struct secXfer *	scptr = &Xfer;
	register struct secRexe *	reptr = &Rexe;

	if EQUALS(type,"xfer"){
	   copyText(scptr->reqUser, sizeof(scptr->reqUser), NOTAVAIL);
	   copyText(scptr->desSystem, sizeof(scptr->desSystem), NOTAVAIL);
	   copyText(scptr->desUser, sizeof(scptr->desUser), NOTAVAIL);
	   copyText(scptr->desFile, sizeof(scptr->desFile), NOTAVAIL);
	   copyText(scptr->srcSystem, sizeof(scptr->srcSystem), NOTAVAIL);
	   copyText(scptr->srcOwner, sizeof(scptr->srcOwner), NOTAVAIL);
	   copyText(scptr->srcFile, sizeof(scptr->srcFile), NOTAVAIL);
	   copyText(scptr->srcMtime, sizeof(scptr->srcMtime), NOTAVAIL);
	   copyText(scptr->stime, sizeof(scptr->stime), NOTAVAIL);
	   copyText(scptr->etime, sizeof(scptr->etime), NOTAVAIL);
	}
	else {
	   copyText(reptr->cliSystem, sizeof(reptr->cliSystem), NOTAVAIL);
	   copyText(reptr->cliUser, sizeof(reptr->cliUser), NOTAVAIL);
	   copyText(reptr->serUser, sizeof(reptr->serUser), NOTAVAIL);
	   copyText(reptr->time, sizeof(reptr->time), NOTAVAIL);
	   copyText(reptr->command, sizeof(reptr->command), NOTAVAIL);
	}
	return;
}

/*
 *		EXTERNAL FUNCTIONS
 */


/*
 * Function:	scInit - Initialize Security Package
 *
 * This function allows the security package to initialize its internal
 * data structures.  It should be called when uucico starts running on master
 * or slave, or uuxqt is invoked.
 *
 * Parameters:
 *
 *	type: file transfer or remote exec.
 */

void
scInit (type)
char * type;

{

	if (LogFile == CLOSED) {
		errno = 0;
		LogFile = open(LogName, O_WRONLY | O_APPEND);
		if (errno == ENOENT) {
			LogFile = creat(LogName, LOGFILEMODE);
			(void) chmod(LogName, LOGFILEMODE);
		}
		if (LogFile < 0){
			Collecting = FALSE;
			return;
		}
	}
	copyText(Type, sizeof(Type), type);
	newRec(Type);
	return;
}

/*
 * Function:	scWrite - write an entry to the log
 *			  initialize the next entry
 */

void
scWrite()

{
	static char	format[] = "%s%c%s%c%s%c%s%c%s%c%s%c%s%c%s%c%s%c%s%c(%s)%c(%s)%c(%s)";

	register struct secXfer *	scptr;

	LOGCHECK;
	scptr = &Xfer;			/* Point to security transfer data. */
	sprintf(Record, format,
		Type, FS,
		scptr->reqSystem, FS,
		scptr->reqUser, FS,
		scptr->desSystem, FS,
		scptr->desUser, FS,
		scptr->desFile, FS,
		scptr->srcSystem, FS,
		scptr->srcOwner, FS,
		scptr->srcFile, FS,
		scptr->srcSize, FS,
		scptr->srcMtime, FS,
		scptr->stime, FS,
		scptr->etime
	       );

	/* Terminate the record and write it out. */

	(void) strcat(Record, EOR);
	writeLog(Record,&LogFile,LogName,&Collecting);
	newRec(Type);
	return;
}

/*
 * Function:	scReqsys - log requestor system name
 *
 * Parameters:
 *	reqsys: master machine name
 */

void
scReqsys(reqsys)
char * reqsys;

{
	register struct secXfer *	scptr = &Xfer;

	LOGCHECK;
	copyText(scptr->reqSystem, sizeof(scptr->reqSystem), reqsys);
	return;
}

/*
 * Function:	scRequser - log requestor user name
 *
 * Parameters:
 *	requser: one who issued the command
 */

void
scRequser(requser)
char * requser;

{
	register struct secXfer *	scptr = &Xfer;

	LOGCHECK;
	copyText(scptr->reqUser, sizeof(scptr->reqUser), requser);
	return;
}

/*
 * Function:	scStime - log start transfer time
 *
 */

void
scStime()

{
	register struct secXfer *	scptr = &Xfer;

	LOGCHECK;
	copyText(scptr->stime, sizeof(scptr->stime), timeStamp());
	return;
}

/*
 * Function:	scEtime - log end transfer time
 *
 */

void
scEtime()

{
	register struct secXfer *	scptr = &Xfer;

	LOGCHECK;
	copyText(scptr->etime, sizeof(scptr->etime), timeStamp());
	return;
}

/*
 * Function:	scDest - log destination node, user and file name
 *
 * Parameters:
 *	destsys: system where the dest file is sent to
 *	destuser: user where the dest file is sent to
 *	destfile: name of the dest file
 *
 */

void
scDest(destsys, destuser, destfile)
char * destsys;
char * destuser;
char * destfile;

{
	register struct secXfer *	scptr = &Xfer;

	LOGCHECK;
	copyText(scptr->desSystem, sizeof(scptr->desSystem), destsys);
	copyText(scptr->desUser, sizeof(scptr->desUser), destuser);
	copyText(scptr->desFile, sizeof(scptr->desFile), destfile);
	return;
}

/*
 * Function:	scSrc - log source node, file owner, file name
 *			modification time and size
 *
 * Parameters:
 *	srcsys: system where the source file is recieved from
 *	srcowner: owner of the source file
 *	srcfile: name of the source file
 *	srcmtime: modification date and time of source file
 *	srcsize: size of the source file
 *
 */

void
scSrc(srcsys, srcowner, srcfile, srcmtime, srcsize)
char * srcsys;
char * srcowner;
char * srcfile;
char * srcmtime;
char * srcsize;

{
	register struct secXfer *	scptr = &Xfer;

	LOGCHECK;
	copyText(scptr->srcSystem, sizeof(scptr->srcSystem), srcsys);
	copyText(scptr->srcOwner, sizeof(scptr->srcOwner), srcowner );
	copyText(scptr->srcFile, sizeof(scptr->srcFile), srcfile);
	copyText(scptr->srcMtime, sizeof(scptr->srcMtime), srcmtime );
	copyText(scptr->srcSize, sizeof(scptr->srcSize), srcsize);
	return;
}

/*
 * Function:	scSize - get size of source file
 *
 * parameter	srcfile: name of the source file
 *
 */

char *
scSize(srcfile)
char * srcfile;

{
	struct stat stbuf;
	static char size[MODSTR];

	LOGCHECKC;
	if (stat(srcfile, &stbuf))
    		return(NOTAVAIL);/* fail, set it ""  */
	sprintf(size,"%ld",stbuf.st_size);
	return(size);
}

/*
 * Function:	scOwn - get owner of source file
 *
 * parameter	srcfile: name of the source file
 *
 */

char *
scOwn(srcfile)
char * srcfile;

{
	struct stat stbuf;
	static char user[MODSTR];

	LOGCHECKC;
	if (stat(srcfile, &stbuf))
		return(NOTAVAIL);
	(void) guinfo(stbuf.st_uid,user);
	return(user);
}

/*
 * Function:	scMtime - get modification date and time of source file
 *
 * parameter	srcfile: name of the source file
 *
 */

char *
scMtime(srcfile)
char * srcfile;

{
	struct stat stbuf;
	static char mtime[MODSTR];
	register struct tm *tp;

	LOGCHECKC;
	if (stat(srcfile, &stbuf))
		return(NOTAVAIL);
	tp = localtime(&stbuf.st_mtime);
	(void) sprintf(mtime, "%d/%d-%d:%2.2d", tp->tm_mon + 1,
	    tp->tm_mday, tp->tm_hour, tp->tm_min);
	return(mtime);
}

/*
 * Function - scRexe: It is called when uuxqt is running
 *
 * Parameter:
 *	clientsys - Client node name.
 *	clientusr - Client user ID.
 *	serverusr - Server user ID.
 *	cmd - command to be execed by uuxqt
 */

void
scRexe(clientsys,clientusr,serverusr,cmd)
char * clientsys;
char * clientusr;
char * serverusr;
char * cmd;
{
	register struct secRexe *	scptr = &Rexe;


	LOGCHECK;
	copyText(scptr->cliSystem, sizeof(scptr->cliSystem), clientsys);
	copyText(scptr->cliUser, sizeof(scptr->cliUser), clientusr);
	copyText(scptr->serUser, sizeof(scptr->serUser), serverusr);
	copyText(scptr->time, sizeof(scptr->time), timeStamp());
	copyText(scptr->command, sizeof(scptr->command), cmd);
	return;
}

/*
 * Function - scWlog: It is called when the violation is occurred
 *
 */

void
scWlog()
{
	static char	format[] = "%s%c%s%c%s%c%s%c(%s)%c%s";

	register struct secRexe *	scptr;

	LOGCHECK;
	scptr = &Rexe;			/* Point to security remote exec data. */
	sprintf(Record, format,
		Type, FS,
		scptr->cliSystem, FS,
		scptr->cliUser, FS,
		scptr->serUser, FS,
		scptr->time, FS,
		scptr->command
	       );

	/* Terminate the record and write it out. */

	(void) strcat(Record, EOR);
	writeLog(Record,&LogFile,LogName,&Collecting);
	newRec(Type);
	return;
}

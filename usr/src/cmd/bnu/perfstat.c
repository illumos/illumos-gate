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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
* This module is intended to collect performance statistics about the
* operation of uucico.  All instances of uucico will write their log
* entries to the files who's path is defined by PERFLOG.  Statistics
* will only be collected if PERFLOG exists when uucico starts, it will
* not be created automatically.  This gives the SA an easy way to turn
* statistics collection on or off at run time.  Three types
* of records will be written to the file, and each record will be
* identified by a mnemonic type at the begining of the record.  The record
* types are as follows:
*
*	conn -		Contains statistics about the establishment of
*			a connection.
*
*	xfer -		Contains statistics about a file transfer.
*
* The intention is to use grep to select the conn and xfer records and put
* them in two Unity data bases.  No attempt will be made to process the
* error records with Unity.
*
* Both the conn and the xfer records will contain a time stamp field.
* This field will be written in case there is a desire to do time of
* day traffic studies.  The time that will be written will be GMT
* to avoid the vagaries of time zone setting for uucico.  The time
* stamp will contain 12 digits of the form YYMMDDhhmmss.  This allows
* proper sorting by time, and the fixed length field type of Unity
* can be used to pick it apart if necessary.  The time stamp is the
* time that the record is written.
*
* Statistics will be collected on the wall clock (real) time to perform
* an action and CPU consumption to perform an action.  These times will
* be written in seconds and fractions of a second to two decimal places.
*
* The conn and xfer records will be written so that they can be processed
* with the following Unity schema (D files).  For those not familiar with
* Unity, the columns are:
*
*	column 1 -	field name
*	column 2 -	field type (t=variable width) and field separator.
*	column 3 -	number of columns to use when printing the field
*			with uprint.
*	column 4 -	a user friendly field name.
*
* Conn:
*
*	type	t|	4	record type (always conn)
*	ts	t|	12	time stamp
*	procid	t|	5	uucico's process id
*	myname	t|	6	name of the machine where the record is written
*	role	t|	1	M = master, S = slave
*	remote	t|	6	name of remote system
*	device	t|	6	name of device used for connection
*	protocol t|	1	the protocal that is used for communication
*	netid	t|	6	physical network ID
*	real	t|	6	real time to connect
*	user	t|	6	user time to connect
*	sys	t\n	6	system (kernal) time to connect
*
* The timer for connection processing starts immediately after the
* command line processing is complete, and it is stopped after the
* protocol has been selected.
*
* Xfer:
*
*	type	t|	4	record type (always xfer)
*	jobgrade t|	1	job grade ID
*	ts	t|	12	time stamp
*	procid	t|	5	uucico's process id
*	myname	t|	6	name of the machine where the record is written
*	role	t|	1	M = master, S = slave
*	remote	t|	6	name of remote system
*	device	t|	6	name of device used for connection
*	protocol t|	1	the protocal that is used for communication
*	netid	t|	6	physical network ID
*	job	t|	7	name of the job.  (Master only).
*	inqueue	t|	6	time in seconds that file was in queue (Master
*					only).
*	tat	t|	6	turn around time in sec.  (Master only).
*	bytes	t|	6	size of the file that was transferred
*	flags	t|	3	m = mail to requester on completion,
*				n = notify remote user, s = write status
*				file.  (Master only).
*	streal	t|	6	real time to start up transfer (master only).
*	stuser	t|	6
*	stsys	t|	6
*	xfrreal	t|	6	real time to transfer file
*	xfruser	t|	6
*	xfrsys	t|	6
*	trmreal	t|	6	real time to terminate the transfer
*	trmuser	t|	6
*	trmsys	t|	6
*	text	t|	12	"PARTIAL FILE" if the data is being transmitted
*				before breaking the transmission; blank if the 
*				partial file after the breakpoint or the whole
*				file is being transmitted completely.
*
* Start up time includes the time for the master to search the queues
* for the next file, for the master and slave to exchange work vectors,
* and time to open files.  It is only recorded on the master.
* Xfer times is the time to transfer the data, close the file, and
* exchange confirmation messages.  Termination time is the time to send
* mail notifications and write status files.  Turn around time is the
* difference between the time that the file was queued and the time that
* the final notification was sent.
*/

#include	"uucp.h"
#include	"log.h"

/*
*		SYMBOL DEFINITIONS
*/

#define	FS		'|'	/* Field seperator for output records. */
#define LOGCHECK	{if ((Initialized == FALSE) || \
				(Collecting == FALSE)) return; }

/* Subscripts for connection time marks: */

#define	CT_START	0	/* Start connection establishment. */
#define	CT_CONNECTED	1	/* Connection completed. */
#define	CT_SIZE		2	/* Number of elements in array. */

/* Subscripts for xfer time marks: */

#define	XT_LOOK		0	/* Start looking for a file (master only). */
#define	XT_FOUND	1	/* File found (master only). */
#define	XT_BEGXFER	2	/* Start of xfer of data. */
#define	XT_ENDXFER	3	/* Data xfer complete. */
#define	XT_ENDFILE	4	/* Done mailing and notifying. */
#define	XT_SIZE		5	/* Number of elements in array. */

/*
*		STRUCTURE DEFINITIONS
*/

typedef struct timeUsed		/* Time consummed between events. */
		{
			float	tu_real;	/* Real time used. */
			float	tu_user;	/* User time used. */
			float	tu_sys;		/* System time used. */
		} TUSED;

typedef struct timeMark		/* Holds times for an event. */
		{
			int	tm_valid;	/* True if data present. */
			long	tm_real;	/* Relative wall clock. */
			struct tms tm_cycles;	/* CPU consumption. */
		} TMARK;

struct connData			/* Data for construction of conn record. */
		{
			char	cn_role;	/* Master/slave indicator. */
			TMARK	cn_times[CT_SIZE]; /* Event data. */
		};

struct xferData			/* Data for construction of xfer record. */
		{
			char	xf_role;	/* Master/slave indicator. */
			char	xf_direction;	/* Send/receive indicator. */
			time_t	xf_intoque;	/* Time that file was placed
						 *   in the queue. (master
						 *   only). */
			long	xf_deque;	/* Time that file was
						 *   dequeued. (master only)*/
			long	xf_filedone;	/* Time that file was
						 *   completed. */
			char	xf_jobname[MODSTR]; /* C. file (master only)*/
  			char	xf_jobgrade[MODSTR]; /* job grade id */
			off_t	xf_bytes;	/* Bytes transferred. */
			char	xf_flags[MODSTR]; /* Notification flags. */
			TMARK	xf_times[XT_SIZE]; /* Event data. */
		};

/*
*		LOCAL DATA
*/

static int		Collecting = FALSE; /* True if we are collecting
					     *   data. */
static struct connData	Conn = {0};	/* Connection data. */
static char		Device[MODSTR] = ""; /* Type of communication
					      *    device. */
static int		Initialized = FALSE; /* True if we have been
					      *   initialized. */
static int		LogFile = CLOSED; /* Log file file destriptor. */
static char		LogName[] = PERFLOG; /* Name of our log file. */
static pid_t		Procid = {0};	/* Our processid. */
static char		Record[LOGSIZE]; /* Place to build log records. */
static char		Remote[MODSTR] = ""; /* Name of the remote system. */
static char		myname[MAXBASENAME+1] = ""; /* Name of the source system
							. */
static char 		Protocol[MODSTR]; /* Protocol in use */
static char 		Netid[MODSTR] = NOTAVAIL; /* Network ID in use */
static struct xferData	Xfer = {0};	/* Transfer data. */

/* Messages: */

static char	Msg_badopen[] = "failed to open %s.  Errno=%%d\n";
static char	Msg_opening[] =	"attempting to open %s\n";
static char	Msg_write[] = "error in writing to %s.  Errno=%%d.\n";

/*
*		LOCAL FUNCTIONS
*/

/* Declarations of functions: */

STATIC_FUNC void	grabTimes();
STATIC_FUNC void	pfloat();
STATIC_FUNC void	reportConn();
STATIC_FUNC void	reportFile();
STATIC_FUNC void	reportTimes();
STATIC_FUNC void	subTimes();


/*
* Local Function:	grabTimes - Get Real and CPU Times
*
* This function uses times(2) to obtain the current real time and CPU
* consumption.  The time mark is also marked as valid.
*
* Parameters:
*
*	markptr -	Address of structure to save times.
*
* Return:
*
*	none.
*/

STATIC_FUNC void
grabTimes (markptr)

register TMARK *	markptr;

{
	markptr->tm_real = times(&markptr->tm_cycles);
	if (markptr->tm_real != FAIL)
		markptr->tm_valid = TRUE;
	return;
}


/*
* Local Function:	pfloat - Print a Floating Number
*
* Format a floating point number for output to the Unity data base.
* If the number is NOTIME, "na" will be displayed instead.
*
* Parameters:
*
*	dest -		The result will be concatenated to this string.
*
*	number -	The number to be formated.
*
*	sep -		Field separator character.
*/

STATIC_FUNC void
pfloat (dest, number, sep)

char *		dest;
double		number;		/* float is promoted to double for args. */
char		sep;

{
	static char	rformat[] = "%c%.2f";
	static char	naformat[] = "%c%s";

	register char *	cp;

	cp = dest + strlen(dest);
	if (number == (float) NOTIME)
		sprintf(cp, naformat, sep, NOTAVAIL);
	else
		sprintf(cp, rformat, sep, number);
	return;
}

/*
* Local Function:	reportConn - Write Out Conn Record
*
* This function writes a conn record to the logfile.
*
* Parameters:
*
*	None.
*
* Returns:
*
*	None.
*/

STATIC_FUNC void
reportConn ()

{
	TUSED	contimes;	/* Times to make connection. */
  	static char	format[] = "%s%c%s%c%ld%c%s%c%c%c%s%c%s%c%s%c%s";

	sprintf(Record, format,
		"conn", FS,		/* record type. */
		gmt(), FS,		/* current time. */
		(long) Procid, FS,	/* our process id. */
		myname, FS,		/* name of local system */
		Conn.cn_role, FS,	/* slave or master. */
		Remote, FS,		/* name of remote system. */
		Device, FS,		/* device used for communication. */
  		Protocol, FS,		/* protocol used for comm. */
  		Netid			/* Network ID */
	       );
	subTimes(&contimes, &Conn.cn_times[CT_CONNECTED],
			&Conn.cn_times[CT_START]);
	reportTimes(Record, &contimes, FS);
	strcat(Record, EOR);
	writeLog(Record,&LogFile,LogName,&Collecting);
	return;
}

/*
* Local Function:	reportFile - Write File Statistics to Log
*
* This function writes statistics about the current file to the log
* file.
*
* Parameters:
*
*	none.
*/

STATIC_FUNC void
reportFile (breakmsg)
char * breakmsg;

{
				     /* minuend,	subtrahand */
	static int	drvtab[] = {
					XT_FOUND,	XT_LOOK, /* startup */
					XT_ENDXFER,	XT_BEGXFER, /* xfer */
					XT_ENDFILE,	XT_ENDXFER /* term. */
				   };
  	static char	format1[] = "%s%c%s%c%s%c%ld%c%s%c%c%c%s%c%s%c%s%c%s%c%s";
	static char	format2[] = "%c%ld%c%s"; /* Bytes & flags. */

	register struct xferData *	xdptr;
	register TMARK *		tdptr;
	register int			i;

	TUSED		diff;		/* time difference between events. */
	float		inque;		/* time in queue. */
	int		lastbyte;	/* Offset to last byte in Record. */
	char *		na = NOTAVAIL;	/* String to show data not available*/
	char		role;		/* Current master/slave status. */
	float		tat;		/* Turn around time. */

	xdptr = &Xfer;			/* Point to Xfer data. */
	role = xdptr->xf_role;
	sprintf(Record, format1,
		"xfer", FS,		/* Record type. */
  		(role == MCHAR) ? xdptr->xf_jobgrade : na ,FS, /* job grade */
		gmt(), FS,		/* Current time. */
		(long) Procid, FS,	/* Our process id. */
		myname, FS,		/* name of local system */
		role, FS,		/* master/slave. */
		Remote, FS,		/* remote. */
		Device, FS,		/* communications device. */
		Protocol, FS,		/* protocol used for comm. */
  		Netid, FS,			/* Network ID */
		(role == MCHAR) ? xdptr->xf_jobname : na
	       );

	/* Do time in queue and turn around time. */

	if (role == MCHAR)
	{
		inque = (float) (xdptr->xf_deque - xdptr->xf_intoque);
		tat = (float) (xdptr->xf_filedone - xdptr->xf_intoque);
	} else
	{
		inque = (float) NOTIME;	/* Not app. if not master. */
		tat = (float) NOTIME;
	}
	pfloat(Record, inque, FS);
	pfloat(Record, tat, FS);

	/*
	* Report bytes transferred and notification flags.
	*/

	lastbyte = strlen(Record);
	(void) sprintf(Record+lastbyte, format2,
			FS, getfilesize(),FS,
  			(role == MCHAR) ? xdptr->xf_flags : na
		      );

	/*
	* Report resource consumption for file startup, file transfer,
	* and file termination.  This means reporting the differences
	* between pairs of elements in the xf_times array of Xfer.  This
	* will be controled by drvtab which contains pairs of subscripts
	* to designate the xf_times elements.
	*/

	tdptr = &xdptr->xf_times[0];
	for (i = 0; i < sizeof(drvtab)/(sizeof(int)); i += 2)
	{
		subTimes(&diff, (tdptr + drvtab[i]), (tdptr + drvtab[i+1]));
		reportTimes(Record, &diff, FS);
	}

	/*
	* write file status
	*/

	lastbyte = strlen(Record);
  	(void) sprintf(Record+lastbyte, "%c%s%c",
  			FS, (*breakmsg == NULLCHAR) ? NOTAVAIL : breakmsg, FS);

	/* Terminate the record and write it out. */

	(void) strcat(Record, EOR);
	writeLog(Record,&LogFile,LogName,&Collecting);
	return;
}

/*
* Local Function:	reportTimes - Print Real, User, and Sys Times
*
* This function is used to convert the real, user, and system times from
* a TUSED structure to Ascii strings.  The results are concatenated to
* the dest string.  If any of the times are NOTIME, they will be reported
* as "na".  The fields will be seperated by the sep character and the
* sep character will be the first character concatenated to the buffer.  No
* seperator character will be placed at the end.  Thus, the output string
* will be of the form:
*
*	|real|user|sys
*
* Parameters:
*
*	dest -		String to receive Ascii times.
*
*	diffptr -	Address of the time data.
*
*	sep -		The field seperator character.
*/

STATIC_FUNC void
reportTimes (dest, diffptr, sep)

register char *		dest;
register TUSED *	diffptr;
char			sep;

{
	pfloat(dest, diffptr->tu_real, sep);
	pfloat(dest, diffptr->tu_user, sep);
	pfloat(dest, diffptr->tu_sys, sep);
	return;
}

/*
* Local Function:	subTimes - Subtract Times Between Events
*
* This function takes the output from two calls to times(2) in the form
* of two TMARK structures, and determines the amount of time consummed
* for various categories.  The result is stored in the specified
* TUSED structure.
*
* Parameters:
*
*	diff -		Place to store the result of the subtraction.
*	minuend -	The second time event.
*	subtra -	The subtrahend in the subtraction.  This should
*			be the first of two time events.
*
* On the large scale this function does the following:
*
*	diff = minuend - subtra
*/

STATIC_FUNC void
subTimes (diff, minuend, subtra)

register TUSED *	diff;
register TMARK *	minuend;
register TMARK *	subtra;

{
	register struct tms *	mintms;
	register struct tms *	subtms;

	long	ltemp;		/* Temporary storage for long arith. */
	float	ticks;		/* Clock interrupts per second. */

	if ((minuend->tm_valid != TRUE) || (subtra->tm_valid != TRUE))
	{				/* If data has not been collected. */
		diff->tu_real = NOTIME;
		diff->tu_user = NOTIME;
		diff->tu_sys = NOTIME;
	} else
	{
		ticks = (float) HZ;	/* HZ defined in <sys/param.h>. */
		mintms = &minuend->tm_cycles;
		subtms = &subtra->tm_cycles;

		/* Calculate real time. */

		ltemp = minuend->tm_real - subtra->tm_real;
		diff->tu_real = ((float) ltemp)/ticks;

		/* Calculate user time. */

		ltemp =	  mintms->tms_utime
			- subtms->tms_utime
			+ mintms->tms_cutime
			- subtms->tms_cutime;
		diff->tu_user = ((float) ltemp)/ticks;

		/* Calculate user time. */

		ltemp =	  mintms->tms_stime
			- subtms->tms_stime
			+ mintms->tms_cstime
			- subtms->tms_cstime;
		diff->tu_sys = ((float) ltemp)/ticks;
	}
	return;
}

/*
*		EXTERNAL FUNCTIONS
*/

/*
* Function:	gmt - Generate Current Time String
*
* This function returns the address a string containing the current
* GMT in the form YYMMDDhhmmss.
*
* Parameters:
*
*	none
*
* Return:
*
*	An address of a static character array containing the date.
*/

char *
gmt()

{
	static char	date[] = "YYMMDDhhmmss";

	register struct tm *	td;
	time_t			now;	/* Current time. */

	now = time((time_t *) 0);
	td = gmtime(&now);
	(void) sprintf(date, "%02d%02d%02d%02d%02d%02d",
				(td->tm_year % 100),
				td->tm_mon + 1,
				td->tm_mday,
				td->tm_hour,
				td->tm_min,
				td->tm_sec
		      );
	return date;
}


/*
* Function:	writeLog - Write String to Log File
*
* After insuring that the log file is open, this function will write
* the specified string to the log file.  If a write error occurs,
* statistics collection will be disabled.
*
* Parameters:
*
*	string - Null terminated string to be written out.
*	logfile - file descripter
*	logname - name of log file.
*	collecting - log enable/disable
*/

void
writeLog (string, logfile, logname, collecting)

char *	string;
int *	logfile;
char *	logname;
int *	collecting;

{
	register int	length;		/* Length of the string. */
	register int	rv;		/* Return value from write. */

	char		errmsg[BUFSIZ];	/* Place for error messages. */

	if (openLog(logfile,logname) != SUCCESS){
		*collecting = FALSE;
		return;
	}
	length = strlen(string);
	do
	{
		rv = write(*logfile, string, (unsigned) length);
	} while ((rv < 0) && (errno == EINTR));	/* Retry if interrupted. */
	if (rv < length)
	{				/* Error or incomplete output. */
		(void) sprintf(errmsg, Msg_write, logname);
		DEBUG(DB_IMPORTANT, errmsg, errno);

		/* If we had a write error, lets give up on loggine. */

		closeLog(logfile);
		*collecting = FALSE;
	}
	return;
}

/*
* Function:	closeLog - Close the Log File
*
* This function allows uucico to close the log file in preparation for
* forking.
*
* Parameters:
*
*	log file descriptor
*/

void
closeLog (logfile)
int	*logfile;

{
	if (*logfile != CLOSED)
	{
		(void) close(*logfile);
		*logfile = CLOSED;
	}
	return;
}


/*
* Function: copyText - Copy String to Dynamic Memory
*
* This function copies a string to a buffer.  It insures that there is
* no overflow of the buffer and that the result is null terminated.
*
* Parameters:
*
*	tptr -		address of the buffer where the string is to
*			be stored.
*
*	size -		number of bytes in the buffer.
*
*	string -	string to be saved.
*
* Returns:
*
*	none.
*/

void
copyText (tptr, size, string)

register char *	tptr;
register int	size;
char *		string;

{
	(void) strncpy(tptr, string, size);
	*(tptr + size - 1) = NULLCHAR;
	return;
}

/*
* Function:	pfConnected - Report Connection Completion
*
* Uucico uses pfConnected to tell this performance package that a connection
* has been established with the remote system.
*
* Parameters:
*
*	remote -	name of the remote system.
*
*	device -	the type of device being used for communicaitons.
*/

void
pfConnected (remote, device)

char *	remote;
char *	device;

{
	register int		i;
	register TMARK *	tptr;

	LOGCHECK;
	grabTimes(&Conn.cn_times[CT_CONNECTED]);
	copyText(Remote, sizeof(Remote), remote);
	copyText(Device, sizeof(Device), device);
	reportConn();
	tptr = &Conn.cn_times[0];

	/*
	* Mark connection times as invalid.  This is really unnecessary
	* since there should only be one connection per invocation of uucico.
	* We do it for consistency with use of the transfer data.
	*/

	for (i = 0; i < CT_SIZE; i++, tptr++)
		tptr->tm_valid = FALSE;
	return;
}


/*
* Function:	pfEndFile - Report End of File
*
* Uucico uses pfEndFile to tell our statistics collection package that
* all processing has been finished on the current file.  PfEndfile should
* be called after all notifications have been done and after the status
* file has been written.  PfEndfile writes out a xfer record for the
* file that just completed.
*
* Parameters:
*
*	none
*/

void
pfEndfile (breakmsg)
char * breakmsg;
{
	register int		i;
	register TMARK *	tdptr;
	register struct xferData *	xptr = &Xfer;

	LOGCHECK;
	grabTimes(&Xfer.xf_times[XT_ENDFILE]);
	Xfer.xf_filedone = time((time_t *) 0);
	reportFile(breakmsg);

	/* Now that we have reported them, mark all times as invalid. */

	copyText(xptr->xf_flags, sizeof(xptr->xf_flags), NOTAVAIL);
	tdptr = &Xfer.xf_times[0];
	for (i = 0; i < XT_SIZE; i++, tdptr++)
		tdptr->tm_valid = FALSE;
	return;
}

/*
* Function:	pfEndXfer - File Transfer Complete
*
* Calling pfEndXfer tells the performance package that a file transfer
* has been completed.  It should be called after the destination site
* closes the file and confirms receipt, but before notifications are done.
*
* Parameters:
*
*	none
*/

void
pfEndXfer ()

{
	LOGCHECK;
	grabTimes(&Xfer.xf_times[XT_ENDXFER]);
	return;
}

/*
* Function:	pfFindFile - Looking for Another File
*
* Uucico uses pfFindFile to announce that it is going to explore the
* queues for another file transfer to do.  PfFindFile is only called
* when uucico is in the role of master.
*
* Parameters:
*
*	none
*/

void
pfFindFile ()

{
	LOGCHECK;
	grabTimes(&Xfer.xf_times[XT_LOOK]);
	return;
}

/*
* Function:	pfFound - Found Another File
*
* PfFound is a counterpart of pfFindFile.  It is called when a new file
* has been found.  Like pfFindFile it is called only by a master uucico.
*
* Parameters:
*
*	jobid -		The name of the job that was found.
*
*	flags -		Options flags that were stored in the queue.
*			These flags are originally set by uucp.
*
*	intoQue -	The time that the C. file was placed in the queue.
*/

void
pfFound (jobid, flags, intoQue)

char *	jobid;
char *	flags;
time_t	intoQue;

{
	register struct xferData *	xptr = &Xfer;

	LOGCHECK;
	grabTimes(&xptr->xf_times[XT_FOUND]);
	copyText(xptr->xf_jobname, sizeof(xptr->xf_jobname), jobid);
  	xptr->xf_jobgrade[0] = jobid[strlen(jobid)-5]; 
  	xptr->xf_jobgrade[1] = NULLCHAR;/* get job grade from jobid */
	copyText(xptr->xf_flags, sizeof(xptr->xf_flags), flags);

	/* Save time that file was placed in queue and current time. */

	xptr->xf_intoque = intoQue;
	xptr->xf_deque = time((time_t *) 0);
	return;
}

/*
* Function:	pfInit - Initialize Performance Package
*
* This function allows the performance package to initialize its internal
* data structures.  It should be called one time only when uucico starts
* running.
*
* Parameters:
*
*	none
*/

void
pfInit ()

{
	register struct xferData *	xptr = &Xfer;

	if (Initialized == TRUE)
		return;
	Procid = getpid();
	myName(myname);
	copyText(xptr->xf_flags, sizeof(xptr->xf_flags), NOTAVAIL);

	/*
	* Attempt to open the log file.  If we can't do it, then we
	* won't collect statistics.
	*/

	if (openLog(&LogFile,LogName) == SUCCESS)
		Collecting = TRUE;
	else
		Collecting = FALSE;
	Initialized = TRUE;
	return;
}

/*
* Function:	pfStrtConn - Going to Establish Connection
*
* Uucico uses pfStrtConn to announce that it is going to attempt
* to establish a connection.
*
* Parameters:
*
*	role -		An indication of whether uucico is currently
*			running in master or slave mode.  M = master,
*			S = slave.
*/

void
pfStrtConn (role)

char	role;
{
	LOGCHECK;
	grabTimes(&Conn.cn_times[CT_START]);
	Conn.cn_role = role;
	return;
}

/*
* Function:	pfStrtXfer - Starting File Transfer
*
* This function should be called just as the first byte of data is
* about to be transferred.
*
* Parameters:
*
*	role -		An indication of whether uucico is currently
*			running in master or slave mode.  M = master,
*			S = slave.
*
*	direction -	Direction of file transfer.  S = sending to
*			remote, R = receiving from remote.
*/

void
pfStrtXfer(role, direction)

char	role;
char	direction;

{
	register struct xferData *	xptr = &Xfer;

	LOGCHECK;
	grabTimes(&xptr->xf_times[XT_BEGXFER]);
	xptr->xf_role = role;
	xptr->xf_direction = direction;
	return;
}

/*
	A protocol which both master and slave sides agree on
*/

void
pfPtcl(str)
char 	*str;
{
	strcpy(Protocol,str);
	return;
}

/*
* Function:	openLog	 - Open the Log File
*
* If the log file is already open this function immediately returns
* success.  Otherwise, an attempt is made to open the logfile in append
* mode.
*
* Parameters:
*
*	logfile - file descripter
*	logname - name of log file.
*
* Returns:
*
*	SUCCESS -	The log file is open.
*	FAIL -		Unable to open logfile.
*/

int
openLog (logfile,logname)
int	*logfile;
char	*logname;
{
	register int	fd;		/* File descriptor of log file. */

	int		level;		/* Level for debug message. */
	char		msgbuf[BUFSIZ];

	/* See if file already open. */

	if (*logfile != CLOSED)
		return (SUCCESS);

	/* Attempt to open the file. */

	DEBUG(DB_TRACE, Msg_opening, logname);
	do
	{
		fd = open(logname, O_WRONLY | O_APPEND);
	} while ((fd < 0) && (errno == EINTR)); /* Retry if interrupted. */
	if (fd < 0) {	/* Error on open. */
		(void) sprintf(msgbuf, Msg_badopen, logname);
		if (errno == ENOENT)
			level = DB_DETAIL; /* If the file is not there
					    *   it will usually mean
					    *   that the SA doesn't
					    *   want to collect
					    *   statisitcs. */
		else
			level = DB_IMPORTANT;	/* Unexpected error */
		DEBUG(level, msgbuf, errno); /* No log file. */
		return FAIL;
	} else {
		*logfile = fd;
		return SUCCESS;
	}
}

#ifdef BSD4_2
#include <sys/time.h>
#include <sys/times.h>
#include <sys/resource.h>

static clock_t
scale60(tvp)
	register struct timeval *tvp;
{
	return (tvp->tv_sec * 60 + tvp->tv_usec / 16667);
}

clock_t
times(tmsp)
	register struct tms *tmsp;
{
	struct rusage ru;
	struct timeval now;
	static time_t epoch;

	if (getrusage(RUSAGE_SELF, &ru) < 0)
		return (clock_t)(-1);
	tmsp->tms_utime = scale60(&ru.ru_utime);
	tmsp->tms_stime = scale60(&ru.ru_stime);
	if (getrusage(RUSAGE_CHILDREN, &ru) < 0)
		return (clock_t)(-1);
	tmsp->tms_cutime = scale60(&ru.ru_utime);
	tmsp->tms_cstime = scale60(&ru.ru_stime);
	if (gettimeofday(&now, (struct timezone *)0) < 0)
		return (clock_t)(-1);
	if (epoch == 0)
		epoch = now.tv_sec;
	now.tv_sec -= epoch;
	return (scale60(&now));
}
#endif /* BSD4_2 */

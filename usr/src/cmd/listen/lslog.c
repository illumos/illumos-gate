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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.7.3.1	*/

/*
 * error/logging/cleanup functions for the network listener process.
 */


/* system include files	*/

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <tiuser.h>
#include <sys/utsname.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <values.h>
#include <ctype.h>
#include <time.h>

/* listener include files */

#include "lsparam.h"		/* listener parameters		*/
#include "listen.h"		/* listener */
#include "lsfiles.h"		/* listener files info		*/
#include "lserror.h"		/* listener error codes		*/
#include "lsdbf.h"

extern char Lastmsg[];
extern int NLPS_proc;
extern char *Netspec;
extern FILE *Logfp;
extern FILE *Debugfp;
extern char Mytag[];
 
static char * stamp(char *);

/*
 * error handling and debug routines
 * most routines take two args: code and exit.
 * code is a #define in lserror.h.
 * if EXIT bit in exitflag is non-zero, the routine exits. (see clean_up() )
 * define COREDUMP to do the obvious.
 */


/*
 * error: catastrophic error handler
 */

error(code, exitflag)
int code, exitflag;
{
	char scratch[BUFSIZ];

	if (!(exitflag & NO_MSG)) {
		strcpy(scratch, err_list[code].err_msg);
		clean_up(code, exitflag, scratch);
	}
	clean_up(code, exitflag, NULL);
}

/*
 * tli_error:  Deal (appropriately) with an error in a TLI call
 */

static char *tlirange = "Unknown TLI error (t_errno > t_nerr)";

tli_error(code, exitflag)
int code, exitflag;
{
	void	t_error();
	extern char *sys_errlist[];
	extern int sys_nerr;
	extern char *range_err();
	char	scratch[256];
	const char *p;

	p = ( t_errno < t_nerr ? t_errlist[t_errno] : tlirange );

	sprintf(scratch, "%s: %s", err_list[code].err_msg, p);
	if (t_errno == TSYSERR)  {
		p = (errno < sys_nerr ? sys_errlist[errno] : range_err());
		strcat(scratch, ": ");
		strcat(scratch, p);
	}
	clean_up(code, exitflag, scratch);
}


/*
 * sys_error: error in a system call
 */

sys_error(code, exitflag)
int code, exitflag;
{
	extern int errno;
	extern char *sys_errlist[];
	extern int sys_nerr;
	register char *p;
	char scratch[256];
	extern char *range_err();

	p = (errno < sys_nerr ? sys_errlist[errno] : range_err());

	sprintf(scratch, "%s: %s", err_list[code].err_msg, p);
	clean_up(code, exitflag, scratch);
}


/*
 * clean_up:	if 'flag', and main listener is exiting, clean things
 *		up and exit.  Dumps core if !(flag & NOCORE).
 *		Tries to send a message to someone if the listener
 *		is exiting due to an error. (Inherrently machine dependent.)
 */

clean_up(code, flag, msg)
register code, flag;
char *msg;
{
	extern int Dbf_entries;
	extern void logexit();
	extern NLPS_proc, Nflag;
	int i;
	extern dbf_t Dbfhead;
	dbf_t	*dbp = &Dbfhead;

	if (!(flag & EXIT)) {
		logmessage(msg);
		return;
	}

	if (!(NLPS_proc))  {

		/*
		 * unbind anything that we bound.
		 * Needs more intelligence.
		 */


		for (i=0;i<Dbf_entries;i++) {
			t_unbind(dbp->dbf_fd);
			dbp++;
		} 
	}

#ifdef	COREDUMP
	if (!(flag & NOCORE))
		abort();
#endif	/* COREDUMP */

	logexit(err_list[code].err_code, msg);
}



/*
 * range_err:	returns a string to use when errno > sys_nerr
 */

static char *sysrange = "Unknown system error (errno %d > sys_nerr)";
static char range_buf[128];

char *
range_err()
{
	extern int errno;

	sprintf(range_buf,sysrange,errno);
	return(range_buf);
}


void
logexit(exitcode, msg)
int exitcode;
char *msg;
{
	if (msg) {
		logmessage(msg); /* put it in the log */
	}
	if (!NLPS_proc)
		logmessage("*** listener terminating!!! ***");
	exit(exitcode);

}


#ifdef	DEBUGMODE

/*VARARGS2*/
int
debug(int level, char *format, ...)
{
	char buf[256];
	va_list ap;

	va_start(ap, format);
	(void) vsprintf(buf, format, ap);
	va_end(ap);

	fprintf(Debugfp, stamp(buf));
	fflush(Debugfp);
}

#endif



/*
 * log:		given a message number (code), write a message to the logfile
 * logmessage:	given a string, write a message to the logfile
 */

log(code)
int code;
{
	logmessage(err_list[code].err_msg);
}


static int nlogs;		/* maintains size of logfile	*/

logmessage(s)
char *s;
{
	char log[BUFSIZ];
	char olog[BUFSIZ];
	register err = 0;
	register FILE *nlogfp;
	extern int Logmax;
	extern int Splflag;

	/*
	 * The listener may be maintaining the size of it's logfile.
	 * Nothing in here should make the listener abort.
	 * If it can't save the file, it rewinds the existing log.
	 * Note that the algorithm is not exact, child listener's
	 * messages do not affect the parent's count.
	 */

	if (!Logfp)
		return;
	if (!NLPS_proc && Logmax && ( nlogs >= Logmax ) && !Splflag)  {
		nlogs = 0;
		fprintf(Logfp, stamp("Restarting log file"));
		sprintf(log, "%s/%s/%s", ALTDIR, Mytag, LOGNAME);
		sprintf(olog, "%s/%s/%s", ALTDIR, Mytag, OLOGNAME);
		DEBUG((1, "Logfile exceeds Logmax (%d) lines", Logmax));
		unlink(olog); /* remove stale saved logfile */
		if (rename(log, olog))  {
			++err;
			rewind(Logfp);
			DEBUG((1,"errno %d renaming log to old logfile",errno));
		}
		else  if (nlogfp = fopen(log, "a+"))  { 
			fclose(Logfp);
			Logfp = nlogfp;
			fcntl(fileno(Logfp), F_SETFD, 1); /* reset close-on-exec */
			DEBUG((1, "logmessage: logfile saved successfully"));
		}  else  {
			++err;
			rewind(Logfp);
			DEBUG((1, "Lost the logfile, errno %d", errno));
		}
		if (err)
			fprintf(Logfp, stamp("Trouble saving the logfile"));
	}

	fprintf(Logfp, stamp(s));
	fflush(Logfp);
	++nlogs;
}

extern pid_t Pid;

static char *
stamp(char *msg)
{
	time_t clock;
	struct tm *tm_p;

	(void)time(&clock);
	tm_p = (struct tm *) localtime(&clock);
	tm_p->tm_mon++;	/* since months are 0-11 */
	sprintf(Lastmsg, "%2.2d/%2.2d/%2.2d %2.2d:%2.2d:%2.2d; %ld; %s\n",
		tm_p->tm_mon, tm_p->tm_mday, (tm_p->tm_year % 100), 
		tm_p->tm_hour, tm_p->tm_min, tm_p->tm_sec, Pid, msg);
	return(Lastmsg);
}

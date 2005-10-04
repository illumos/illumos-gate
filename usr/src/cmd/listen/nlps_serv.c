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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* system include files	*/

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/tiuser.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <values.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <sys/poll.h>
#include <sys/stropts.h>
#include <utmpx.h>
#include <sac.h>


/* listener include files */

#include "lsparam.h"		/* listener parameters		*/
#include "lsfiles.h"		/* listener files info		*/
#include "lserror.h"		/* listener error codes		*/
#include "lsnlsmsg.h"		/* NLPS listener protocol	*/
#include "lssmbmsg.h"		/* MS_NET identifier		*/
#include "lsdbf.h"		/* data base file stuff		*/
#include "listen.h"

/* global variables */

FILE *Logfp;		/* file pointer for nlps_server's log file	*/
#ifdef DEBUGMODE
FILE *Debugfp;		/* debugging output				*/
#endif

int Dbf_entries;	/* number of private addresses in dbf file */
dbf_t	*Dbfhead;
dbf_t	*Newdbf;
char	*New_cmd_lines;
char	*Server_cmd_lines;

extern int t_errno;

/* 
 * These global symbols are used for logging.
 * Pid, NLPS_proc, and Lastmsg are significant here; the others aren't used.
 */
int	NLPS_proc = 1;
pid_t	Pid;
char	Lastmsg[BUFSIZ];
char	*Netspec = NULL;
int	Splflag = 0;
int	Logmax = 0;
char	*Mytag = NULL;

char	msgbuf[BUFSIZ];
char	Altbasedir[BUFSIZ];
char	Basedir[BUFSIZ];
extern	char *getenv();

static void nls_reply(int code, char *text);
static void nullfix(void);

int
main(int argc, char **argv)
{
	extern int read_dbf();
	char *provider;

	provider = getenv("PMTAG");
	sprintf(Altbasedir, "%s/%s/", ALTDIR, provider);
	sprintf(Basedir, "%s/%s/", BASEDIR, provider);
	sprintf(msgbuf, "%s/%s", Altbasedir, LOGNAME);
	if (!(Logfp = fopen(msgbuf, "a+")))  {
		(void)exit(1);  
	}

#ifdef DEBUGMODE
	sprintf(msgbuf, "%s/%s", Altbasedir, PDEBUGNAME);
	if (!(Debugfp = fopen(msgbuf, "a")))  {
		logmessage("NLPS: Unable to open DEBUG file");
		(void)exit(1);  
	}
#endif

	/*
	 * re-sync TLI structures after we were exec'ed from listener
	 */

	if (t_sync(0) == -1) {
		DEBUG((9,"t_sync failed, t_errno %d", t_errno));
		logmessage("NLPS: Resynchronization of TLI failed");
		(void)exit(1);
	}

	nlps_server();
	return(0);
}

/*
 *  nlps_server: 
 */

int
nlps_server()
{
	int size;
	char buf[RCVBUFSZ];
	char **argv;
	char *bp = buf;
	dbf_t *dbp;
	dbf_t *getdbfentry();
	extern char **mkdbfargv();

	Pid = getpid();
	DEBUG((9,"in nlps_server (NLPS/SMB message), pid %ld", Pid));

	if ((size = getrequest(bp)) <= 0)  {
		logmessage("NLPS: No/bad service request received");
		return(-1);
	}

	if (size < 0)  {
		DEBUG((7,"nlps_server(): Error returned from getrequest()" ));
		logmessage("NLPS: Error returned from getrequest()");
		return(-1);
	}

	/*
	 * if message is NLPS protocol...
	 */

	if ((!strncmp(bp,NLPSIDSTR,NLPSIDSZ))  && 	/* NLPS request	*/
	    (*(bp + NLPSIDSZ) == NLPSSEPCHAR)) {
		nls_service(bp, size);
		(void)sleep(10);	/* if returned to here, then 
				 * must sleep for a short period of time to
				 * insure that the client received any possible
				 * exit response message from the listener.
					 */

	/*
	 * else if message is for the MS-NET file server...
	 */

	} else if ( (*bp == (char)0xff) && (!strncmp(bp+1,SMBIDSTR,SMBIDSZ)) )  {
		if (dbp = getdbfentry(DBF_SMB_CODE))
		    if (dbp->dbf_flags & DBF_OFF)
			logmessage("NLPS: SMB message, server disabled in data base");
		    else    {
			argv = mkdbfargv(dbp);
			smbservice(bp, size, argv);
		    }
		else
			logmessage("NLPS: SMB message, no data base entry");

	/*
	 * else, message type is unknown...
	 */

	} else  {
		logmessage("NLPS: Unknown service request (ignored)");
		DEBUG((7,"msg size: %d; 1st four chars (hex) %x %x %x %x",
			*bp, *(bp+1), *(bp+2), *(bp+3)));
	}

	/*
	 * the routines that start servers return only if there was an error
	 * and will have logged their own errors.
	 */

	return(-1);
}


/*
 * getrequest:	read in a full message.  Timeout, in case the client died.
 *		returns: -1 = timeout or other error.
 *			 positive number = message size.
 */

int
getrequest(bp)
char *bp;
{
	int size;
	char *tmp = bp;
	int flags;
	extern void timeout();
	short cnt;
	void (*oldhanp)();

	DEBUG((9,"in getrequest"));

	oldhanp = signal(SIGALRM, timeout);
	(void)alarm(ALARMTIME);

	/* read in MINMSGSZ to determine type of msg */
	if ((size = l_rcv(bp, MINMSGSZ, &flags)) != MINMSGSZ) {
		DEBUG((9, "getrequest: l_rcv returned %d", size));
		tli_error(E_RCV_MSG, CONTINUE);
		return(-1);
	}
	tmp += size;

	/*
	 * if message is NLPS protocol...
	 */

	if ((!strncmp(bp,NLPSIDSTR,NLPSIDSZ))  && 	/* NLPS request	*/
	    (*(bp + NLPSIDSZ) == NLPSSEPCHAR)) {

		do {
			if (++size > RCVBUFSZ) {
				logmessage("NLPS: recieve buffer not large enough");
				return(-1);
			}

			if (t_rcv(0, tmp, sizeof(char), &flags) != sizeof(char)) {
				tli_error(E_RCV_MSG, CONTINUE);
				return(-1);
			}

		} while (*tmp++ != '\0');



	/*
	 * else if message is for the MS-NET file server...
	 */

	} else if ( (*bp == (char)0xff) && (!strncmp(bp+1,SMBIDSTR,SMBIDSZ)) )  {

		/* read in 28 more bytes to get count of paramter words */
		if (l_rcv(tmp, 28, &flags) != 28) {
			tli_error(E_RCV_MSG, CONTINUE);
			return(-1);
		}
		tmp += 28;
		size += 28;

		/*
		 * read amount of paramater words plus word for
                 * the number of data bytes to follow (2 bytes/word)
                 */
		cnt = (int)*(tmp - 1) * 2 + 2;

		if ((size += cnt) > RCVBUFSZ) {
			logmessage("NLPS: recieve buffer not large enough");
			return(-1);
		}

		if (l_rcv(tmp, cnt, &flags) != cnt) {
			tli_error(E_RCV_MSG, CONTINUE);
			return(-1);
		}
		tmp += cnt;

		getword(tmp - 2, &cnt);

		if ((size += cnt) > RCVBUFSZ) {
			logmessage("NLPS: recieve buffer not large enough");
			return(-1);
		}

		if (l_rcv(tmp, cnt, &flags) != cnt) {
			tli_error(E_RCV_MSG, CONTINUE);
			return(-1);
		}

		nullfix();

	/*
	 * else, message type is unknown...
	 */

	} else  {
		logmessage("NLPS: Unknown service request (ignored)");
		DEBUG((7,"msg size: %d; 1st four chars (hex) %x %x %x %x",
			*bp, *(bp+1), *(bp+2), *(bp+3)));
		return(-1);
	}

	(void)alarm(0);
	signal(SIGALRM, oldhanp);

	DEBUG((7,"t_rcv returned %d, flags: %x",size,flags));

	return(size);
}


/*
 * The following code is for patching a 6300 side bug.  The original
 * message that comes over may contain 2 null bytes which aren't
 * part of the message, and if left on the stream, will poison the
 * server.  Peek into the stream and snarf up those bytes if they
 * are there.  If anything goes wrong with the I_PEEK, just continue,
 * if the nulls weren't there, it'll work, and if they were, all that
 * will happen is that the server will fail.  Just note what happened
 * in the log file.
 */

static void
nullfix(void)
{
	struct strpeek peek;
	register struct strpeek *peekp;
	char scratch[BUFSIZ];
	char junk[2];
	int flags;
	int ret;

	peekp = &peek;
	peekp->flags = 0;
	/* need to ask for ctl info to avoid bug in I_PEEK code */
	peekp->ctlbuf.maxlen = 1;
	peekp->ctlbuf.buf = junk;
	peekp->databuf.maxlen = 2;
	peekp->databuf.buf = junk;
	ret = ioctl(0, I_PEEK, &peek);
	if (ret == -1) {
		sprintf(scratch, "NLPS: nullfix(): unable to PEEK, errno is %d", errno);
		DEBUG((9, "nullfix(): I_PEEK failed, errno is %d", errno));
		logmessage(scratch);
	}
	else if (ret == 0) {
		DEBUG((9, "nullfix(): no messages on stream to PEEK"));
	}
	else {
		if (peekp->databuf.len == 2) {
			/* Note: junk contains "peeked" data */
			DEBUG((9, "peeked <%x> <%x>", junk[0], junk[1]));
			if ((junk[0] == 0) && (junk[1] == 0)) {
				/* pitch the nulls */
				DEBUG((9, "pitching 2 nulls from first peek"));
				l_rcv(junk, 2, &flags);
			}
		}

		/*
		 * this represents a somewhat pathological case where
		 * the "2 nulls" are broken across message boundaries.
		 * Pitch the first and hope the next one is there
		 */

		else if (peekp->databuf.len == 1) {
			DEBUG((9, "peeked <%x>", junk[0]));
			if (junk[0] == 0) {
				/* pitch the first */
				DEBUG((9, "split nulls, pitching first"));
				l_rcv(junk, 1, &flags);
				peekp->databuf.maxlen = 1;
				ret = ioctl(0, I_PEEK, &peek);
				if (ret == -1) {
					sprintf(scratch, "NLPS: nullfix(): unable to PEEK second time, errno is %d", errno);
					DEBUG((9, "second peek failed, errno %d", errno));
					logmessage(scratch);
				}
				else if (ret == 0) {
					DEBUG((9, "no messages for 2nd peek"));
				}
				else {
					if (peekp->databuf.len == 1) {
						DEBUG((9, "2nd peek <%x>", junk[0]));
						if (junk[0] == 0) {
							/* pitch the second */
							DEBUG((9, "pitching 2nd single null"));
							l_rcv(junk, 1, &flags);
						}
						else {
							/* uh oh, server will most likely fail */
							DEBUG((9, "2nd null not found"));
							logmessage("NLPS: nullfix(): threw away a valid null byte");
						}
					}
				}
			}
		}
	}
}


/*
 * timeout:	SIGALRM signal handler.  Invoked if t_rcv timed out.
 *		See comments about 'exit' in nlps_server().
 */


void
timeout()
{
	DEBUG((9, "TIMEOUT"));
	error(E_RCV_TMO, EXIT | NOCORE);
}



/*
 * nls_service:	Validate and start a server requested via the NLPS protocol
 *
 *		version 0:1 -- expect "NLPS:000:001:service_code".
 *
 *	returns only if there was an error (either msg format, or couldn't exec)
 */

static char *badversion =
	"NLPS: Unknown version of an NLPS service request: %d:%d";
static char *disabledmsg =
	"NLPS: Request for service code <%s> denied, service is disabled";
static char *nlsunknown =
	"NLPS: Request for service code <%s> denied, unknown service code";


/*
 * Nlsversion can be used as a NLPS flag (< 0 == not nls service)
 * and when >= 0, indicates the version of the NLPS protocol used
 */

static int Nlsversion = -1;	/* protocol version	*/

int
nls_service(bp, size)
int  size;
char *bp;
{
	int low, high;
	char svc_buf[64];
	register char *svc_code_p = svc_buf;
	char scratch[256];
	register dbf_t *dbp;
	dbf_t *getdbfentry();
	extern char **mkdbfargv();
	int passfd;
	int i;

	if (nls_chkmsg(bp, size, &low, &high, svc_code_p))  {
		if ((low == 0) || (low == 2))
			Nlsversion = low;
		else  {
			sprintf(scratch, badversion, low, high);
			logmessage(scratch);
			error(E_BAD_VERSION, CONTINUE);
			return(-1);
		}

		DEBUG((9,"nls_service: protocol version %d", Nlsversion));

		/*
		 * common code for protocol version 0 or 2
		 * version 0 allows no answerback message
		 * version 2 allows exactly 1 answerback message
		 */

		if (dbp = getdbfentry(svc_code_p)) {
			if (dbp->dbf_flags & DBF_OFF)  {
				sprintf(scratch, disabledmsg, svc_code_p);
				logmessage(scratch);
				nls_reply(NLSDISABLED, scratch);
			}  
			else {
				if (dbp->dbf_sflags & CFLAG) {
					exec_cmd(dbp, (char **)0);
					/* return is an error	*/
				}
				else {
					sprintf(msgbuf,"NLPS (%s) passfd: %s", 
						dbp->dbf_svc_code, 
						dbp->dbf_cmd_line);
					nls_reply(NLSSTART, msgbuf);
					logmessage(msgbuf);
					/* open pipe to pass fd through */
					if ((passfd = open(dbp->dbf_cmd_line, 
							O_WRONLY)) < 0) {
						sprintf(scratch,"NLPS open failed: %s", dbp->dbf_cmd_line);
						logmessage(scratch);
					}
					DEBUG((9, "pushmod string: %s", dbp->dbf_modules));
					if (pushmod(0, dbp->dbf_modules)) {
						logmessage("NLPS: Can't push server's modules: exit");
						(void)exit(2); /* server, don't log */
					}

					DEBUG((9, "Running doconfig on %s", dbp->dbf_svc_code));

					sprintf(msgbuf,"%s/%s",Basedir,dbp->dbf_svc_code);

					if ((i = doconfig(0, msgbuf, NOASSIGN)) != 0) {
						DEBUG((9, "doconfig exited with code %d", i));
						sprintf(scratch, "doconfig failed on line %d of script %s", 
								i, msgbuf);
						logmessage(scratch);
						(void)exit(2);
					}
					if (ioctl(passfd, I_SENDFD, 0) < 0) {
						sprintf(scratch,"NLPS passfd failed: %s", dbp->dbf_cmd_line);
						logmessage(scratch);
					}
				}
			}
		}
		else  {
			sprintf(scratch, nlsunknown, svc_code_p);
			logmessage(scratch);
			nls_reply(NLSUNKNOWN, scratch);
		}
		exit(2);

	}  else
		error(E_BAD_FORMAT, CONTINUE);

	/* if we're still here, server didn't get exec'ed	*/

	return(-1);
}



/*
 * nls_chkmsg:	validate message and return fields to caller.
 *		returns: TRUE == good format
 *			 FALSE== bad format
 */

int
nls_chkmsg(bp, size, lowp, highp, svc_code_p)
char *bp, *svc_code_p;
int size, *lowp, *highp;
{

	/* first, make sure bp is null terminated */

	if ((*(bp + size - 1)) != (char)0)
		return(0);

	/* scanf returns number of "matched and assigned items"	*/

	return(sscanf(bp, "%*4c:%3d:%3d:%s", lowp, highp, svc_code_p) == 3);

}


/*
 * nls_reply:	send the "service request response message"
 *		when appropriate.  (Valid if running version 2 or greater).
 *		Must use write(2) since unknown modules may be pushed.
 *
 *		Message format:
 *		protocol_verion_# : message_code_# : message_text
 */

static char *srrpprot = "%d:%d:%s";

static void
nls_reply(int code, char *text)
{
	char scratch[256];

	/* Nlsversion = -1 for login service */

	if (Nlsversion >= 2)  {
		DEBUG((7, "nls_reply: sending response message"));
		sprintf(scratch, srrpprot, Nlsversion, code, text);
		t_snd(0, scratch, strlen(scratch)+1, 0);
	}
}


/*
 * common code to  start a server process (for any service)
 * if optional argv is given, info comes from o_argv, else pointer
 * to dbf struct is used.  In either case, first argument in argv is
 * full pathname of server. Before exec-ing the server, the caller's
 * logical address, opt and udata are added to the environment. 
 */

static char homeenv[BUFSIZ];
#define NETFD	0


int
exec_cmd(dbf_t *dbp, char **o_argv)
{
	char *path;
	char **argvp;
	extern char **environ;
	dbf_t *getdbfentry();
	extern char **mkdbfargv();
	struct passwd *pwdp;
	struct group *grpp;
	dbf_t *wdbp = dbp;
	int	i;

	/*
	 * o_argv is set during SMB service setup only, in
	 * which case dbp is NULL.
	 */

	if (o_argv) {
		argvp = o_argv;
		if ((wdbp = getdbfentry(DBF_SMB_CODE)) == NULL) {
			/* this shouldn't happen because at this point we've
			   already found it once */
			logmessage("NLPS: SMB message, missing data base entry");
			(void)exit(2); /* server, don't log */
		}
	}
	else
		argvp = mkdbfargv(dbp);
	path = *argvp;

	sprintf(msgbuf,"NLPS (%s) exec: %s", 
			(dbp)?dbp->dbf_svc_code:DBF_SMB_CODE, path);
	nls_reply(NLSSTART, msgbuf);
	logmessage(msgbuf);

	if (wdbp->dbf_flags & DBF_UTMP) {
		pid_t	tmp;
		struct	stat	sbuf;
		char	*prefix;
		char	device[20];
		struct	utmpx utline;

		/* 
		 * create a utmpx entry.  extra fork makes parent init,
		 * which will clean up the entry.
		 */

		DEBUG((9, "Creating a utmpx entry for this service "));
		if ((tmp = fork()) < 0) {
			logmessage("NLPS: Can't fork to create utmpx entry");
			exit(2);
		}
		if (tmp)
			exit(0);	/* kill parent */

		/* 
		 * child continues processing, creating utmpx and exec'ing
		 * the service
		 */

		setpgrp();
		if (fstat(0, &sbuf) < 0) {
			logmessage("NLPS: Stat failed on fd 0: no line "
			    "field available for utmpx entry");
			*device = '\0';
		}
		else {
			/* 
			 * MPREFIX is added to the environment by the parent
			 * listener process.
			 */
			prefix = getenv("MPREFIX");
			if (minor(sbuf.st_rdev) < 100)
				sprintf(device, "%.9s%02.02d", prefix, minor(sbuf.st_rdev));
			else
				sprintf(device, "%.8s%03.03d", prefix, minor(sbuf.st_rdev));
			DEBUG((9, "Device: %s", device));
		}
		strncpy(utline.ut_user, wdbp->dbf_id,
		    sizeof (utline.ut_user) - 1);
		sprintf(utline.ut_id, "ps%c%c", SC_WILDC, SC_WILDC);
		strncpy(utline.ut_line, device, sizeof (utline.ut_line) - 1);
		utline.ut_pid = getpid();
                utline.ut_type = USER_PROCESS;
		utline.ut_exit.e_termination = 0;
		utline.ut_exit.e_exit = 0;
		utline.ut_xtime = (time_t) time((time_t *)0);
		makeutx(&utline);
	}

	/* after pushmod, tli calls are questionable?		*/

	DEBUG((9, "pushmod string: %s", wdbp->dbf_modules));
	if (dbp && pushmod(NETFD, dbp->dbf_modules)) {
		logmessage("NLPS: Can't push server's modules: exit");
		exit(2); /* server, don't log */
	}

	DEBUG((9, "Running doconfig on %s", wdbp->dbf_svc_code));
	if ((i = doconfig(NETFD, wdbp->dbf_svc_code, 0)) != 0) {
		DEBUG((9, "doconfig exited with code %d", i));
		sprintf(msgbuf, "doconfig failed on line %d of script %s", 
				i, wdbp->dbf_svc_code);
		logmessage(msgbuf);
	}

	if (wdbp == NULL) {
		logmessage("NLPS: No database entry");
		exit(2); /* server, don't log */
	}
	
	if ((pwdp = getpwnam(wdbp->dbf_id)) == NULL)  {
		sprintf(msgbuf, "NLPS: Missing or bad passwd entry for <%s>",wdbp->dbf_id);
		logmessage(msgbuf);
		exit(2); /* server, don't log */
	}		


	if (setgid(pwdp->pw_gid)) {
		if ((grpp = getgrgid(pwdp->pw_gid)) == NULL) {
			sprintf(msgbuf, "NLPS: No group entry for %ld", pwdp->pw_gid);
			logmessage(msgbuf);
			exit(2); /* server, don't log */
		}
		sprintf(msgbuf, "NLPS: Cannot set group id to %s", grpp->gr_name);
		logmessage(msgbuf);
		(void)exit(2); /* server, don't log */
	}

	if (setuid(pwdp->pw_uid)) {
		sprintf(msgbuf, "NLPS: Cannot set user id to %s", wdbp->dbf_id);
		logmessage(msgbuf);
		(void)exit(2); /* server, don't log */
	}

	if (chdir(pwdp->pw_dir)) {
		sprintf(msgbuf, "NLPS: Cannot chdir to %s", pwdp->pw_dir);
		logmessage(msgbuf);
		(void)exit(2); /* server, don't log */
	}

	DEBUG((9, "New uid %ld New gid %ld", getuid(), getgid()));

	sprintf(homeenv, "HOME=%s", pwdp->pw_dir);
	DEBUG((9,"HOME=%s", pwdp->pw_dir));
	putenv(homeenv);
	endpwent();

	fclose(Logfp);
#ifdef DEBUGMODE
	fclose(Debugfp);
#endif
	execve(path, argvp, environ);

	/* exec returns only on failure!		*/

	logmessage("NLPS server: could not exec service");
	sys_error(E_SYS_ERROR, CONTINUE);
	return(-1);
}





/*
 * isdigits:	string version of isdigit.  (See ctype(3))
 */

/* This routine is public here and used in lsdbf.c as an external */
int
isdigits(p)
register char *p;
{
	register int flag = 1;

	if (!strlen(p))
		return(0);

	while (*p)
		if (!isdigit(*p++))
			flag = 0;
	return(flag);
}


int
l_rcv(bufp, bytes, flagp)
char *bufp;
int bytes;
int *flagp;
{
	register int n;
	register int count = bytes;
	register char *bp = bufp;

	DEBUG((9, "in l_rcv"));

	do {
		*flagp = 0;
		n = t_rcv(0, bp, count, flagp);
		DEBUG((9, "l_rcv, after t_rcv call, n =  %d",n));   

		if (n < 0) {
			DEBUG((9, "l_rcv, t_errno is %d", t_errno));   
#ifdef DEBUGMODE
			if (t_errno == TLOOK) {
				DEBUG((9, "l_rcv, t_look returns %d", t_look(0)));
			}
#endif
			return(n);
		}
		count -= n;
		bp += n;
	} while (count > 0);

	return(bp - bufp);
}


/*
 * getdbfentry:	Given a service code, return a pointer to the dbf_t
 *		entry.  Return NULL if the entry doesn't exist.
 *		Reads the data base, one line at a time, into
 *		Dbf_line_buf.
 */

static	char	Dbf_line_buf[DBFLINESZ];
static	dbf_t	Dbf_entry;

dbf_t *
getdbfentry(svc_code_p)
register char *svc_code_p;
{
	FILE	*dbfp;
	char	dbfname[BUFSIZ];

	sprintf(dbfname, "%s/%s", Basedir, DBFNAME);
	if ((dbfp = fopen(dbfname, "r")) == NULL) {
		DEBUG((9, "open of database file %s failed", DBFNAME));
		logmessage("NLPS: Unable to open database file");
		return((dbf_t *)NULL);
	}

	DEBUG((9, "database file opened, looking for %s", svc_code_p));
	while (rd_dbf_line(dbfp, Dbf_line_buf, &Dbf_entry.dbf_svc_code, 
		&Dbf_entry.dbf_flags, &Dbf_entry.dbf_id, &Dbf_entry.dbf_res1,
		&Dbf_entry.dbf_res2, &Dbf_entry.dbf_res3,&Dbf_entry.dbf_prv_adr,
		&Dbf_entry.dbf_prognum, &Dbf_entry.dbf_version, 
		&Dbf_entry.dbf_modules, &Dbf_entry.dbf_sflags, 
		&Dbf_entry.dbf_cmd_line) > 0) {

		/* see if this line is the one we want (svc_code match) */
		if (!strcmp(Dbf_entry.dbf_svc_code, svc_code_p)) {
			fclose(dbfp);
			return(&Dbf_entry);
		}
	}

	DEBUG((9, "No svc code match"));
	fclose(dbfp);
	return((dbf_t *)0);	/* svc code not in database	*/
}

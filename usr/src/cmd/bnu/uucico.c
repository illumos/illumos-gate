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
/*
 * Copyright 2014 Garrett D'Amore
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*

 * uucp file transfer program:
 * to place a call to a remote machine, login, and
 * copy files between the two machines.

*/
/*
 * Added check to limit the total number of uucicos as defined
 * in the Limits file.
 *
 * Added -f flag to "force execution", ignoring the limit on the
 * number of uucicos. This will be used when invoking uucico from
 * Uutry.
*/

#include "uucp.h"
#include "log.h"

#ifndef	V7
#include <sys/mkdev.h>
#endif /* V7 */

#ifdef TLI
#include	<sys/tiuser.h>
#endif /* TLI */

jmp_buf Sjbuf;
extern unsigned msgtime;
char	uuxqtarg[MAXBASENAME] = {'\0'};
int	uuxqtflag = 0;

extern int	(*Setup)(), (*Teardown)();	/* defined in interface.c */

#define USAGE	"Usage: %s [-x NUM] [-r [0|1]] -s SYSTEM -u USERID -d SPOOL -i INTERFACE [-f]\n"
extern void closedem();
void cleanup(), cleanTM();

extern int sysaccess(), guinfo(), eaccess(), countProcs(), interface(),
	savline(), omsg(), restline(), imsg(), callok(), gnxseq(),
	cmtseq(), conn(), startup(), cntrl();
extern void setuucp(), fixline(), gename(), ulkseq(), pfEndfile();

#ifdef	NOSTRANGERS
static void checkrmt();		/* See if we want to talk to remote. */
#endif /* NOSTRANGERS */

extern char *Mytype;

static char *pskip();

int
main(argc, argv, envp)
int argc;
char *argv[];
char **envp;
{

	extern void intrEXIT(), onintr(), timeout();
	extern void setservice();
#ifndef ATTSVR3
	void setTZ();
#endif /* ATTSVR3 */
	int ret, seq, exitcode;
	char file[NAMESIZE];
	char msg[BUFSIZ], *p, *q;
	char xflag[6];	/* -xN N is single digit */
	char *ttyn;
	char *iface;	/* interface name	*/
	char	cb[128];
	time_t	ts, tconv;
	char lockname[MAXFULLNAME];
	struct limits limitval;
	int maxnumb;
	int force = 0;	/* set to force execution, ignoring uucico limit */
	char gradedir[2*NAMESIZE];

	/* Set locale environment variables local definitions */
	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it wasn't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	Ulimit = ulimit(1,0L);
	Uid = getuid();
	Euid = geteuid();	/* this should be UUCPUID */
	if (Uid == 0)
	    setuid(UUCPUID);
	Env = envp;
	Role = SLAVE;
	strcpy(Logfile, LOGCICO);
	*Rmtname = NULLCHAR;
	Ifn = Ofn = -1;		/* must be set before signal handlers */

	closedem();
	time(&Nstat.t_qtime);
	tconv = Nstat.t_start = Nstat.t_qtime;
	strcpy(Progname, "uucico");
	setservice(Progname);
	ret = sysaccess(EACCESS_SYSTEMS);
	ASSERT(ret == 0, Ct_OPEN, "Systems", ret);
	ret = sysaccess(EACCESS_DEVICES);
	ASSERT(ret == 0, Ct_OPEN, "Devices", ret);
	ret = sysaccess(EACCESS_DIALERS);
	ASSERT(ret == 0, Ct_OPEN, "Dialers", ret);
	Pchar = 'C';
	(void) signal(SIGILL, intrEXIT);
	(void) signal(SIGTRAP, intrEXIT);
	(void) signal(SIGIOT, intrEXIT);
	(void) signal(SIGEMT, intrEXIT);
	(void) signal(SIGFPE, intrEXIT);
	(void) signal(SIGBUS, intrEXIT);
	(void) signal(SIGSEGV, intrEXIT);
	(void) signal(SIGSYS, intrEXIT);
	if (signal(SIGPIPE, SIG_IGN) != SIG_IGN)	/* This for sockets */
		(void) signal(SIGPIPE, intrEXIT);
	(void) signal(SIGINT, onintr);
	(void) signal(SIGHUP, onintr);
	(void) signal(SIGQUIT, onintr);
	(void) signal(SIGTERM, onintr);
#ifdef SIGUSR1
	(void) signal(SIGUSR1, SIG_IGN);
#endif
#ifdef SIGUSR2
	(void) signal(SIGUSR2, SIG_IGN);
#endif
#ifdef BSD4_2
	(void) sigsetmask(sigblock(0) & ~(1 << (SIGALRM - 1)));
#endif /*BSD4_2*/

	pfInit();
	scInit("xfer");
	ret = guinfo(Euid, User);
	ASSERT(ret == 0, "BAD UID ", "", ret);
	strncpy(Uucp, User, NAMESIZE);

	setuucp(User);

	*xflag = NULLCHAR;
	iface = "UNIX";

	while ((ret = getopt(argc, argv, "fd:c:r:s:x:u:i:")) != EOF) {
		switch (ret) {
		case 'd':
			if ( eaccess(optarg, 01) != 0 ) {
				(void) fprintf(stderr, gettext("%s: cannot"
				    " access spool directory %s\n"),
					Progname, optarg);
				exit(1);
			}
			Spool = optarg;
			break;
		case 'c':
			Mytype = optarg;
			break;
		case 'f':
			++force;
			break;
		case 'r':
			if ( (Role = atoi(optarg)) != MASTER && Role != SLAVE ) {
				(void) fprintf(stderr, gettext("%s: bad value"
				    " '%s' for -r argument\n" USAGE),
					Progname, optarg, Progname);
				exit(1);
			}
			break;
		case 's':
			strncpy(Rmtname, optarg, MAXFULLNAME-1);
			if (versys(Rmtname)) {
			    (void) fprintf(stderr,
				gettext("%s: %s not in Systems file\n"),
				Progname, optarg);
			    cleanup(101);
			}
			/* set args for possible xuuxqt call */
			strcpy(uuxqtarg, Rmtname);
			/* if versys put a longer name in, truncate it again */
			Rmtname[MAXBASENAME] = '\0';
			break;
		case 'x':
			Debug = atoi(optarg);
			if (Debug <= 0)
				Debug = 1;
			if (Debug > 9)
				Debug = 9;
			(void) sprintf(xflag, "-x%d", Debug);
			break;
		case 'u':
			DEBUG(4, "Loginuser %s specified\n", optarg);
			strncpy(Loginuser, optarg, NAMESIZE);
			Loginuser[NAMESIZE - 1] = NULLCHAR;
			break;
		case 'i':
			/*	interface type		*/
			iface = optarg;
			break;
		default:
			(void) fprintf(stderr, gettext(USAGE), Progname);
			exit(1);
		}
	}

	if (Role == MASTER || *Loginuser == NULLCHAR) {
	    ret = guinfo(Uid, Loginuser);
	    ASSERT(ret == 0, "BAD LOGIN_UID ", "", ret);
	}

	/* limit the total number of uucicos */
	if (force) {
	    DEBUG(4, "force flag set (ignoring uucico limit)\n%s", "");
	} else if (scanlimit("uucico", &limitval) == FAIL) {
	    DEBUG(1, "No limits for uucico in %s\n", LIMITS);
	} else {
	    maxnumb = limitval.totalmax;
	    if (maxnumb < 0) {
		DEBUG(4, "Non-positive limit for uucico in %s\n", LIMITS);
		DEBUG(1, "No limits for uucico\n%s", "");
	    } else {
		DEBUG(4, "Uucico limit %d -- ", maxnumb);
		(void) sprintf(lockname, "%s.", LOCKPRE);
		if (countProcs(lockname, (maxnumb-1)) == FALSE) {
			DEBUG(4, "exiting\n%s", "");
			cleanup(101);
		}
		DEBUG(4, "continuing\n%s", "");
	    }
	}

	pfStrtConn((Role == MASTER) ? 'M' : 'S');
	if (Role == MASTER) {
	    if (*Rmtname == NULLCHAR) {
		DEBUG(5, "No -s specified\n%s" , "");
		cleanup(101);
	    }
	    /* get Myname - it depends on who I'm calling--Rmtname */
	    (void) mchFind(Rmtname);
	    myName(Myname);
	    if (EQUALSN(Rmtname, Myname, MAXBASENAME)) {
		DEBUG(5, "This system specified: -sMyname: %s, ", Myname);
		cleanup(101);
	    }
	    acInit("xfer");
	}

	ASSERT(chdir(Spool) == 0, Ct_CHDIR, Spool, errno);
	strcpy(Wrkdir, Spool);

	scReqsys((Role == MASTER) ? Myname : Rmtname); /* log requestor system */

	if (Role == SLAVE) {

#ifndef ATTSVR3
		setTZ();
#endif /* ATTSVR3 */

		if (freopen(RMTDEBUG, "a", stderr) == 0) {
			errent(Ct_OPEN, RMTDEBUG, errno, __FILE__, __LINE__);
			freopen("/dev/null", "w", stderr);
		}
		if ( interface(iface) ) {
			(void)fprintf(stderr,
			"%s: invalid interface %s\n", Progname, iface);
			cleanup(101);
		}
		/*master setup will be called from processdev()*/
		if ( (*Setup)( Role, &Ifn, &Ofn ) ) {
			DEBUG(5, "SLAVE Setup failed%s", "");
			cleanup(101);
		}

		/*
		 * initial handshake
		 */
		(void) savline();
		fixline(Ifn, 0, D_ACU);
		/* get MyName - use logFind to check PERMISSIONS file */
		(void) logFind(Loginuser, "");
		myName(Myname);

		DEBUG(4,"cico.c: Myname - %s\n",Myname);
		DEBUG(4,"cico.c: Loginuser - %s\n",Loginuser);
		fflush(stderr);
		Nstat.t_scall = times(&Nstat.t_tga);
		(void) sprintf(msg, "here=%s", Myname);
		omsg('S', msg, Ofn);
		(void) signal(SIGALRM, timeout);
		(void) alarm(msgtime); /* give slow machines a second chance */
		if (setjmp(Sjbuf)) {

			/*
			 * timed out
			 */
			(void) restline();
			rmlock(CNULL);
			exit(0);
		}
		for (;;) {
			ret = imsg(msg, Ifn);
			if (ret != 0) {
				(void) alarm(0);
				(void) restline();
				rmlock(CNULL);
				exit(0);
			}
			if (msg[0] == 'S')
				break;
		}
		Nstat.t_ecall = times(&Nstat.t_tga);
		(void) alarm(0);
		q = &msg[1];
		p = pskip(q);
		strncpy(Rmtname, q, MAXBASENAME);
		Rmtname[MAXBASENAME] = '\0';

		seq = 0;
		while (p && *p == '-') {
			q = pskip(p);
			switch(*(++p)) {
			case 'x':
				Debug = atoi(++p);
				if (Debug <= 0)
					Debug = 1;
				(void) sprintf(xflag, "-x%d", Debug);
				break;
			case 'Q':
				seq = atoi(++p);
				if (seq < 0)
					seq = 0;
				break;
#ifdef MAXGRADE
			case 'v':	/* version -- -vname=val or -vname */
				if (strncmp(++p, "grade=", 6) == 0 &&
				    isalnum(p[6]))
					MaxGrade = p[6];
				break;
#endif /* MAXGRADE */
			case 'R':
				Restart++;
				p++;
				break;
			case 'U':
				SizeCheck++;
				RemUlimit = strtol(++p, (char **) NULL,0);
				break;
			default:
				break;
			}
			p = q;
		}
		DEBUG(4, "sys-%s\n", Rmtname);
		if (strpbrk(Rmtname, Shchar) != NULL) {
			DEBUG(4, "Bad remote system name '%s'\n", Rmtname);
			logent(Rmtname, "BAD REMOTE SYSTEM NAME");
			omsg('R', "Bad remote system name", Ofn);
			cleanup(101);
		}
		if (Restart)
		    CDEBUG(1,"Checkpoint Restart enabled\n%s", "");

#ifdef NOSTRANGERS
		checkrmt();	/* Do we know the remote system. */
#else
		(void) versys(Rmtname);	/* in case the real name is longer */
#endif /* NOSTRANGERS */
		
		(void) sprintf(lockname, "%ld", (long) getpid());
		if (umlock(LOCKPRE, lockname)) {
			omsg('R', "LCK", Ofn);
			cleanup(101);
		}

		/* validate login using PERMISSIONS file */
		if (logFind(Loginuser, Rmtname) == FAIL) {
			scWrite(); /* log security violation */
			Uerror = SS_BAD_LOG_MCH;
			logent(UERRORTEXT, "FAILED");
			systat(Rmtname, SS_BAD_LOG_MCH, UERRORTEXT,
			    Retrytime);
			omsg('R', "LOGIN", Ofn);
			cleanup(101);
		}

		ret = callBack();
		DEBUG(4,"return from callcheck: %s",ret ? "TRUE" : "FALSE");
		if (ret==TRUE) {
			(void) signal(SIGINT, SIG_IGN);
			(void) signal(SIGHUP, SIG_IGN);
			omsg('R', "CB", Ofn);
			logent("CALLBACK", "REQUIRED");
			/*
			 * set up for call back
			 */
			chremdir(Rmtname);
			(void) sprintf(file, "%s/%c", Rmtname, D_QUEUE);
			chremdir(file);
			gename(CMDPRE, Rmtname, 'C', file);
			(void) close(creat(file, CFILEMODE));
			if (callok(Rmtname) == SS_CALLBACK_LOOP) {
			    systat(Rmtname, SS_CALLBACK_LOOP, "CALL BACK - LOOP", Retrytime);
			} else {
			    systat(Rmtname, SS_CALLBACK, "CALL BACK", Retrytime);
			    xuucico(Rmtname);
			}
			cleanup(101);
		}

		if (callok(Rmtname) == SS_SEQBAD) {
			Uerror = SS_SEQBAD;
			logent(UERRORTEXT, "PREVIOUS");
			omsg('R', "BADSEQ", Ofn);
			cleanup(101);
		}

		if (gnxseq(Rmtname) == seq) {
			if (Restart) {
			    if (SizeCheck)
				(void) sprintf (msg, "OK -R -U0x%lx %s",
					Ulimit, xflag);
			    else
				(void) sprintf (msg, "OK -R %s", xflag);
			    omsg('R', msg, Ofn);
			} else
			    omsg('R', "OK", Ofn);
			(void) cmtseq();
		} else {
			Uerror = SS_SEQBAD;
			systat(Rmtname, SS_SEQBAD, UERRORTEXT, Retrytime);
			logent(UERRORTEXT, "HANDSHAKE FAILED");
			ulkseq();
			omsg('R', "BADSEQ", Ofn);
			cleanup(101);
		}
		ttyn = ttyname(Ifn);
		if (ttyn != CNULL && *ttyn != NULLCHAR) {
			struct stat ttysbuf;
			if ( fstat(Ifn,&ttysbuf) == 0 )
				Dev_mode = ttysbuf.st_mode;
			else
				Dev_mode = R_DEVICEMODE;
			if ( EQUALSN(ttyn,"/dev/",5) )
			    strcpy(Dc, ttyn+5);
			else
			    strcpy(Dc, ttyn);
			chmod(ttyn, S_DEVICEMODE);
		} else
			strcpy(Dc, "notty");
		/* set args for possible xuuxqt call */
		strcpy(uuxqtarg, Rmtname);
	}

	strcpy(User, Uucp);
/*
 *  Ensure reasonable ulimit (MINULIMIT)
 */

#ifndef	V7
	{
	long 	minulimit;
	minulimit = ulimit(1, (long) 0);
	ASSERT(minulimit >= MINULIMIT, "ULIMIT TOO SMALL",
	    Loginuser, (int) minulimit);
	}
#endif
	if (Role == MASTER && callok(Rmtname) != 0) {
		logent("SYSTEM STATUS", "CAN NOT CALL");
		cleanup(101);
	}

	chremdir(Rmtname);

	(void) strcpy(Wrkdir, RemSpool);
	if (Role == MASTER) {

		/*
		 * master part
		 */
		(void) signal(SIGINT, SIG_IGN);
		(void) signal(SIGHUP, SIG_IGN);
		(void) signal(SIGQUIT, SIG_IGN);
		if (Ifn != -1 && Role == MASTER) {
			(void) (*Write)(Ofn, EOTMSG, strlen(EOTMSG));
			(void) close(Ofn);
			(void) close(Ifn);
			Ifn = Ofn = -1;
			rmlock(CNULL);
			sleep(3);
		}

		/*
		 * Find the highest priority job grade that has
		 * jobs to do. This is needed to form the lock name.
		 */

		findgrade(RemSpool, JobGrade);
		DEBUG(4, "Job grade to process - %s\n", JobGrade);

		/*
		 * Lock the job grade if there is one to process.
		 */

		if (*JobGrade != NULLCHAR) {
			(void) sprintf(gradedir, "%s/%s", Rmtname, JobGrade);
			chremdir(gradedir);

			(void) sprintf(lockname, "%.*s.%s", SYSNSIZE, Rmtname, JobGrade);
			(void) sprintf(msg, "call to %s - process job grade %s ",
			    Rmtname, JobGrade);
			if (umlock(LOCKPRE, lockname) != 0) {
				logent(msg, "LOCKED");
				CDEBUG(1, "Currently Talking With %s\n",
				    Rmtname);
 				cleanup(100);
			}
		} else {
			(void) sprintf(msg, "call to %s - no work", Rmtname);
		}

		Nstat.t_scall = times(&Nstat.t_tga);
		Ofn = Ifn = conn(Rmtname);
		Nstat.t_ecall = times(&Nstat.t_tga);
		if (Ofn < 0) {
			delock(LOCKPRE, lockname);
			logent(UERRORTEXT, "CONN FAILED");
			systat(Rmtname, Uerror, UERRORTEXT, Retrytime);
			cleanup(101);
		} else {
			logent(msg, "SUCCEEDED");
			ttyn = ttyname(Ifn);
			if (ttyn != CNULL && *ttyn != NULLCHAR) {
				struct stat ttysbuf;
				if ( fstat(Ifn,&ttysbuf) == 0 )
					Dev_mode = ttysbuf.st_mode;
				else
					Dev_mode = R_DEVICEMODE;
				chmod(ttyn, M_DEVICEMODE);
			}
		}
	
		if (setjmp(Sjbuf)) {
			delock(LOCKPRE, lockname);
			Uerror = SS_LOGIN_FAILED;
			logent(Rmtname, UERRORTEXT);
			systat(Rmtname, SS_LOGIN_FAILED,
			    UERRORTEXT, Retrytime);
			DEBUG(4, "%s - failed\n", UERRORTEXT);
			cleanup(101);
		}
		(void) signal(SIGALRM, timeout);
		/* give slow guys lots of time to thrash */
		(void) alarm(2 * msgtime);
		for (;;) {
			ret = imsg(msg, Ifn);
			if (ret != 0) {
				continue; /* try again */
			}
			if (msg[0] == 'S')
				break;
		}
		(void) alarm(0);
		if(EQUALSN("here=", &msg[1], 5)){
			/* This may be a problem, we check up to MAXBASENAME
			 * characters now. The old comment was:
			 * this is a problem.  We'd like to compare with an
			 * untruncated Rmtname but we fear incompatability.
			 * So we'll look at most 6 chars (at most).
			 */
			(void) pskip(&msg[6]);
			if (!EQUALSN(&msg[6], Rmtname, MAXBASENAME)) {
				delock(LOCKPRE, lockname);
				Uerror = SS_WRONG_MCH;
				logent(&msg[6], UERRORTEXT);
				systat(Rmtname, SS_WRONG_MCH, UERRORTEXT,
				     Retrytime);
				DEBUG(4, "%s - failed\n", UERRORTEXT);
				cleanup(101);
			}
		}
		CDEBUG(1,"Login Successful: System=%s\n",&msg[6]);
		seq = gnxseq(Rmtname);
		(void) sprintf(msg, "%s -Q%d -R -U0x%lx %s",
			Myname, seq, Ulimit, xflag);
#ifdef MAXGRADE
		if (MaxGrade != NULLCHAR) {
			p = strchr(msg, NULLCHAR);
			sprintf(p, " -vgrade=%c", MaxGrade);
		}
#endif /* MAXGRADE */
		omsg('S', msg, Ofn);
		(void) alarm(msgtime);	/* give slow guys some thrash time */
		for (;;) {
			ret = imsg(msg, Ifn);
			DEBUG(4, "msg-%s\n", msg);
			if (ret != 0) {
				(void) alarm(0);
				delock(LOCKPRE, lockname);
				ulkseq();
				cleanup(101);
			}
			if (msg[0] == 'R')
				break;
		}
		(void) alarm(0);

		/*  check for rejects from remote */
		Uerror = 0;
		if (EQUALS(&msg[1], "LCK")) 
			Uerror = SS_RLOCKED;
		else if (EQUALS(&msg[1], "LOGIN"))
			Uerror = SS_RLOGIN;
		else if (EQUALS(&msg[1], "CB"))
			Uerror = (callBack() ? SS_CALLBACK_LOOP : SS_CALLBACK);
		else if (EQUALS(&msg[1], "You are unknown to me"))
			Uerror = SS_RUNKNOWN;
		else if (EQUALS(&msg[1], "BADSEQ"))
			Uerror = SS_SEQBAD;
		else if (!EQUALSN(&msg[1], "OK", 2))
			Uerror = SS_UNKNOWN_RESPONSE;
		if (Uerror)  {
			delock(LOCKPRE, lockname);
			systat(Rmtname, Uerror, UERRORTEXT, Retrytime);
			logent(UERRORTEXT, "HANDSHAKE FAILED");
			CDEBUG(1, "HANDSHAKE FAILED: %s\n", UERRORTEXT);
			ulkseq();
			cleanup(101);
		}
		(void) cmtseq();

		/*
		 * See if we have any additional parameters on the OK
		 */

		if (strlen(&msg[3])) {
			p = pskip(&msg[3]);
			while (p && *p == '-') {
				q = pskip(p);
				switch(*(++p)) {
				case 'R':
					Restart++;
					p++;
					break;
				case 'U':
					SizeCheck++;
					RemUlimit = strtol(++p, (char **) NULL, 0);
					break;
				case 'x':
					if (!Debug) {
						Debug = atoi(++p);
						if (Debug <= 0)
							Debug = 1;
					}
					break;
				default:
					break;
				}
				p = q;
			}
		}

	}
	DEBUG(4, " Rmtname %s, ", Rmtname);
	DEBUG(4, " Restart %s, ", (Restart ? "YES" : "NO"));
	DEBUG(4, "Role %s,  ", Role ? "MASTER" : "SLAVE");
	DEBUG(4, "Ifn - %d, ", Ifn);
	DEBUG(4, "Loginuser - %s\n", Loginuser);

	/* alarm/setjmp added here due to experience with uucico
	 * hanging for hours in imsg().
	 */
	if (setjmp(Sjbuf)) {
		delock(LOCKPRE, lockname);
		logent("startup", "TIMEOUT");
		DEBUG(4, "%s - timeout\n", "startup");
		cleanup(101);
	}
	(void) alarm(MAXSTART);
	ret = startup();
	(void) alarm(0);

	if (ret != SUCCESS) {
		delock(LOCKPRE, lockname);
		logent("startup", "FAILED");
		Uerror = SS_STARTUP;
		CDEBUG(1, "%s\n", UERRORTEXT);
		systat(Rmtname, Uerror, UERRORTEXT, Retrytime);
		exitcode = 101;
	} else {
		pfConnected(Rmtname, Dc);
		acConnected(Rmtname, Dc);
		logent("startup", "OK");
		systat(Rmtname, SS_INPROGRESS, UTEXT(SS_INPROGRESS),Retrytime);
		Nstat.t_sftp = times(&Nstat.t_tga);

		exitcode = cntrl();
		Nstat.t_eftp = times(&Nstat.t_tga);
		DEBUG(4, "cntrl - %d\n", exitcode);
		(void) signal(SIGINT, SIG_IGN);
		(void) signal(SIGHUP, SIG_IGN);
		(void) signal(SIGALRM, timeout);

		if (exitcode == 0) {
			(void) time(&ts);
			(void) sprintf(cb, "conversation complete %s %ld",
				Dc, ts - tconv);
			logent(cb, "OK");
			systat(Rmtname, SS_OK, UTEXT(SS_OK), Retrytime);

		} else {
			logent("conversation complete", "FAILED");
			systat(Rmtname, SS_CONVERSATION,
			    UTEXT(SS_CONVERSATION), Retrytime);
		}
		(void) alarm(msgtime);	/* give slow guys some thrash time */
		omsg('O', "OOOOO", Ofn);
		CDEBUG(4, "send OO %d,", ret);
		if (!setjmp(Sjbuf)) {
			for (;;) {
				omsg('O', "OOOOO", Ofn);
				ret = imsg(msg, Ifn);
				if (ret != 0)
					break;
				if (msg[0] == 'O')
					break;
			}
		}
		(void) alarm(0);
	}
	cleanup(exitcode);
	/*NOTREACHED*/
	return (0);
}

/*
 * clean and exit with "code" status
 */
void
cleanup(code)
int code;
{
	(void) signal(SIGINT, SIG_IGN);
	(void) signal(SIGHUP, SIG_IGN);
	rmlock(CNULL);
	closedem();
	alarm(msgtime);		/* Start timer in case closes hang. */
	if (setjmp(Sjbuf) == 0)
		(*Teardown)( Role, Ifn, Ofn );
	alarm(0);			/* Turn off timer. */
	DEBUG(4, "exit code %d\n", code);
	CDEBUG(1, "Conversation Complete: Status %s\n\n", 
	    code ? "FAILED" : "SUCCEEDED");

	cleanTM();
	if ((code == 0) && (uuxqtflag == 1))
		xuuxqt(uuxqtarg);
	exit(code);
}

short TM_cnt = 0;
char TM_name[MAXNAMESIZE];

void
cleanTM()
{
	int i;
	char tm_name[MAXNAMESIZE];

	DEBUG(7,"TM_cnt: %d\n",TM_cnt);
	for(i=0; i < TM_cnt; i++) {
		(void) sprintf(tm_name, "%s.%3.3d", TM_name, i);
		DEBUG(7, "tm_name: %s\n", tm_name);
		unlink(tm_name);
	}
	return;
}

void
TMname(file, pnum)
char *file;
pid_t pnum;
{

	(void) sprintf(file, "%s/TM.%.5ld.%.3d", RemSpool, (long) pnum, TM_cnt);
	if (TM_cnt == 0)
	    (void) sprintf(TM_name, "%s/TM.%.5ld", RemSpool, (long) pnum);
	DEBUG(7, "TMname(%s)\n", file);
	TM_cnt++;
	return;
}

/*
 * intrrupt - remove locks and exit
 */
void
onintr(inter)
int inter;
{
	char str[30];
	/* I'm putting a test for zero here because I saw it happen
	 * and don't know how or why, but it seemed to then loop
	 * here for ever?
	 */
	if (inter == 0)
	    exit(99);
	(void) signal(inter, SIG_IGN);
	(void) sprintf(str, "SIGNAL %d", inter);
	logent(str, "CAUGHT");
	pfEndfile("PARTIAL FILE");
	acEnd(PARTIAL); /*stop collecting accounting log */
	cleanup(inter);
}

void
intrEXIT(inter)
int inter;
{
	char	cb[20];

	(void) sprintf(cb, "SIGNAL %d", inter);
	logent("INTREXIT", cb);
	(void) signal(SIGIOT, SIG_DFL);
	(void) signal(SIGILL, SIG_DFL);
	rmlock(CNULL);
	closedem();
	(void) setuid(Uid);
	abort();
}

/*
 * catch SIGALRM routine
 */
void
timeout()
{
	longjmp(Sjbuf, 1);
}

/* skip to next field */
static char *
pskip(p)
char *p;
{
	if ((p = strchr(p, ' ')) != CNULL)
		do
			*p++ = NULLCHAR;
		while (*p == ' ');
	return(p);
}

void
closedem()
{
	int i, maxfiles;

#ifdef ATTSVR3
	maxfiles = ulimit(4,0);
#else /* !ATTSVR3 */
#ifdef BSD4_2
	maxfiles = getdtablesize();
#else /* BSD4_2 */
	maxfiles = _NFILE;
#endif /* BSD4_2 */
#endif /* ATTSVR3 */

	for (  i = 3; i < maxfiles; i++ )
		if ( i != Ifn && i != Ofn && i != fileno(stderr) )
			(void) close(i);
	return;
}

#ifndef ATTSVR3

/*
 *	setTZ()
 *
 *	if login "shell" is uucico (i.e., Role == SLAVE), must set
 *	timezone env variable TZ.  otherwise will default to EST.
 */

#define	LINELEN	81

void
setTZ()
{
	static char	buf[LINELEN], *bp;
	extern char	*fgets();
	FILE		*tzfp;
	extern FILE	*fopen();
	int		i;
	extern int	fclose(), strncmp();

	if ( (tzfp = fopen("/etc/default/init","r")) == (FILE *)NULL )
		return;
	while ( (bp = fgets(buf,LINELEN,tzfp)) != (char *)NULL ) {
		while ( isspace(*bp) )
			++bp;
		if ( strncmp(bp, "TZ=", 3) == 0 ) {
			for ( i = strlen(bp) - 1; i > 0 && isspace(*(bp+i)); --i )
				*(bp+i) = '\0';
			putenv(bp);
			(void)fclose(tzfp);
			return;
		}
	}
	(void)fclose(tzfp);
	return;
}
#endif /* ATTSVR3 */

#ifdef NOSTRANGERS
/*
* Function:	checkrmt
*
* If NOSTRANGERS is defined, see if the remote system is in our systems
* file.  If it is not, execute NOSTRANGERS and then reject the call.
*/

static void
checkrmt ()

{
	char **	eVarPtr;	/* Pointer to environment variable. */
	char	msgbuf[BUFSIZ];	/* Place to build messages. */
	pid_t	procid;		/* ID of Nostranger process. */
	static char * safePath = PATH;
	int	status;		/* Exit status of child. */
	pid_t	waitrv;		/* Return value from wait system call. */

	/* here's the place to look the remote system up in the Systems file.
	 * If the command NOSTRANGERS is executable and 
	 * If they're not in my file then hang up */

	if (versys(Rmtname) && (access(NOSTRANGERS, 1) == 0)) {
		sprintf(msgbuf, "Invoking %s for %%s\n", NOSTRANGERS);
		DEBUG(4, msgbuf, Rmtname);

		/*
		* Ignore hangup in case remote goes away before we can
		* finish logging.
		*/

		(void) signal(SIGHUP, SIG_IGN);
		omsg('R', "You are unknown to me", Ofn);
		scWrite(); /* log unknown remote system */
		procid = fork();
		if ( procid == 0 ) {
			/*
			* Before execing the no strangers program, there is
			* a security aspect to consider.  If NOSTRANGERS is
			* not a full path name, then the PATH environment
			* variable will provide places to look for the file.
			* To be safe, we will set the PATH environment
			* variable before we do the exec.
			*/

			/* Find PATH in current environment and change it. */

			for (eVarPtr = Env; *eVarPtr != CNULL; eVarPtr++) {
				if (PREFIX("PATH=", *eVarPtr))
					*eVarPtr = safePath;
			}
			execlp( NOSTRANGERS, "stranger", Rmtname, (char *) 0);
			sprintf(msgbuf, "Execlp of %s failed with errno=%%d\n",
				NOSTRANGERS);
			DEBUG(4, msgbuf, errno);
			perror(gettext("cico.c: execlp NOSTRANGERS failed"));
			cleanup(errno);
		} else if (procid < 0) {
			perror(gettext("cico.c: execlp NOSTRANGERS failed"));
			cleanup(errno);
		} else {
			while ((waitrv = wait(&status)) != procid)
				if (waitrv == -1 && errno != EINTR)
					cleanup(errno);
			sprintf(msgbuf, "%s exit status was %%#x\n",
				NOSTRANGERS);
			DEBUG(4, msgbuf, status);
		}
		cleanup(101);
	}
}
#endif /* NOSTRANGERS */

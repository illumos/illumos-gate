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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/
/*
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *
 *	ct [-h] [-v] [-w n] [-x n] [-s speed] telno ...
 *
 *	dials the given telephone number, waits for the
 *	modem to answer, and initiates a login process.
 *
 *	ct uses several routines from uucp:
 *	- getto(flds) takes a vector of fields needed to make
 *	  a connection and returns a file descriptor or -1
 *	- rddev( ... ) takes several arguments and returns lines
 *	  from the /etc/uucp/Devices that match the type
 *	  (in ct the type will be ACU)
 *	- fdig(string) takes a string that is zero or more
 *	  alphabetic characters follow by a number (baud rate)
 *	  and returns a pointer to the first digit in the string.
 *	- fn_cklock(dev) takes a device name [/dev/]term/11 and
 *	  checks whether the appropriate lock file exists. It returns
 *	  FAIL if it does.
 *	- rmlock(pointer) removes the lock file.  In ct pointer is
 *	  always CNULL (a null pointer) causing rmlock to remove
 *	  all lock files associated with this execution of ct.
 */

#include "uucp.h"
#include "sysfiles.h"
#include <pwd.h>
#include <utmpx.h>

#ifdef DATAKIT
#include <dk.h>
extern int dkminor();
#endif

#define ROOT	0
#define SYS	3
#define TTYGID	(gid_t) 7		/* group id for terminal */
#define TTYMOD	(mode_t) 0622
#define DEV	"/dev/"
#define TELNOSIZE	32		/* maximum phone # size is 31 */
#define LEGAL	"0123456789-*#="
#define USAGE	"[-h] [-v] [-w n] [-x n] [-s speed] telno ..."
#define LOG	"/var/adm/ctlog"
#define	TTYMON	"/usr/lib/saf/ttymon"
#define TRUE	1
#define FALSE	0

static
int	_Status;		/* exit status of child */

static
pid_t	_Pid = 0;		/* process id of child */

static
char
	_Tty[sizeof DEV+12] = "",  /* /dev/term/xx for connection device */
	*_Dev[D_MAX + 1],	/* Filled in by rddev and used globally */
	_Devbuf[BUFSIZ];	/* buffer for rddev */

static
char
	*_Num,			/* pointer to a phone number */
	*_Flds[7];		/* Filled in as if finds() in uucp did it */

static
time_t	_Log_on,
	_Log_elpsd;

static
FILE	*_Fdl;

extern int  optind;
extern char *optarg, *fdig();
extern  void cleanup();
extern struct passwd  *getpwuid ();

extern int getto(), rddev();
static int gdev(), logproc(), exists();
static void startat(), stopat(), disconnect(), zero();

/*
 * These two dummy routines are needed because the uucp routines
 * used by ct reference them, but they will never be
 * called when executing from ct
 */

/*VARARGS*/
/*ARGSUSED*/
void
assert (s1, s2, i1, s3, i2)
char *s1, *s2, *s3;
int i1, i2;
{ }		/* for ASSERT in gnamef.c */

/*ARGSUSED*/
void
logent (s1, s2)
char *s1, *s2;
{ }		/* so we can load ulockf() */

jmp_buf Sjbuf;			/* used by uucp routines */

int
main (argc, argv)
int argc;
char   *argv[];
{
    int    	c;
    int		found = 0,
		errors = 0,
		first = TRUE;
    int     count,
	    logprocflag,	/* is there a login process on the line */
            hangup = 1,		/* hangup by default */
            minutes = 0;	/* number of minutes to wait for dialer */
    int     fdl;
    struct termio   termio;
    typedef void (*save_sig)();
    save_sig	save_hup,
		save_quit,
		save_int;
    extern void	setservice(), devreset();
    extern int sysaccess();

    save_hup = signal (SIGHUP, cleanup);
    save_quit = signal (SIGQUIT, cleanup);
    save_int = signal (SIGINT, cleanup);
    (void) signal (SIGTERM, cleanup);
    (void) strcpy (Progname, "ct");

    setservice("cu");
    if ( sysaccess(EACCESS_DEVICES) != 0 ) {
	(void) fprintf(stderr, "ct: can't access Devices file\n");
	cleanup(101);
    }

    /* Set up the _Flds vector as if finds() [from uucico] built it */
    _Flds[F_NAME] = "dummy";		/* never used */
    _Flds[F_TIME] = "Any";		/* never used */
    _Flds[F_TYPE] = "ACU";
    _Flds[F_CLASS] = "1200";		/* default at 1200 */
    _Flds[F_PHONE] = "";			/* filled in by arguments */
    _Flds[F_LOGIN] = "";			/* never used */
    _Flds[6] = NULL;

    while ((c = getopt (argc, argv, "hvw:s:x:")) != EOF) {
	switch (c) {
	    case 'h':
		hangup = 0;
		break;

	    case 'v':
		Verbose = 1;
		break;

	    case 'w':
		minutes = atoi (optarg);
		if (minutes < 1) {
		    (void) fprintf(stderr,
			"\tusage: %s %s\n", Progname, USAGE);
		    (void) fprintf(stderr, "(-w %s) Wait time must be > 0\n",
			optarg);
		    cleanup(101);
		}
		break;

	    case 's':
		_Flds[F_CLASS] = optarg;
		break;

	    case 'x':
		Debug = atoi(optarg);
		if (Debug < 0 || Debug > 9) {
		    (void) fprintf(stderr,
			"\tusage: %s %s\n", Progname, USAGE);
		    (void) fprintf(stderr, "(-x %s) value must be 0-9\n",
			optarg);
		    cleanup(101);
		}
		break;

	    case '?':
		(void) fprintf(stderr, "\tusage: %s %s\n", Progname, USAGE);
		cleanup(101);
		/* NOTREACHED */
	}
    }

    if (optind == argc) {
	(void) fprintf(stderr, "\tusage: %s %s\n", Progname, USAGE);
	(void) fprintf(stderr, "No phone numbers specified!\n");
	cleanup(101);
    }

    /* check for valid phone number(s) */
    for (count = argc - 1; count >= optind; --count) {
	_Num = argv[count];
	if (strlen(_Num) >= (size_t)(TELNOSIZE - 1)) {
	    (void) fprintf(stderr, "ct: phone number too long -- %s\n", _Num);
	    ++errors;
	}
	if ((int)strspn(_Num, LEGAL) < (int)strlen(_Num)) {
	    (void) fprintf(stderr, "ct: bad phone number -- %s\n", _Num);
	    ++errors;
	}
    }
    if (errors)
	cleanup(101);

    /************************************************************/
    /*		Begin Loop:  Find an available Dialer		*/
    /************************************************************/
    for (count = 0;; count++) { /* count will be wait time after first
				 * time through the loop.
				 * break will be used exit loop.
				 */
	if ( (found = gdev (_Flds)) > 0) {  /* found a dialer */
	    (void) fprintf(stdout, "Allocated dialer at %s baud\n",
		_Flds[F_CLASS]);
	    break;
	}
	else if (found == 0) {	/* no dialers of that on system */
	    (void) fprintf(stdout, "No %s dialers on this system\n",
		fdig(_Flds[F_CLASS]) );
    	    cleanup(101);
	}

	if (!first) { /* not the first time in loop */
	    VERBOSE("%s busy", (found == -1) ? "Dialer is" : "Dialers are");
	    VERBOSE(" (%d minute(s))\n", count);
	    if (count < minutes) {
	        sleep(60);
	        continue;
	    }
	    /* This is the end of the loop - no time left */
	    break;
	}

	/**************************************************************/
	/* First time through loop - get wait minutes if no -w option */
	/**************************************************************/
	first = FALSE;
	(void) fprintf(stdout, "The (%d) %s dialer%s busy\n", -found,
	    _Flds[F_CLASS], (found == -1 ? " is" : "s are"));
	if (minutes) {	/* -w already set wait minutes */
	    (void) fprintf(stdout, "Waiting for %d minute%s\n", minutes,
		(minutes > 1 ? "s" : "") );
	    sleep(60);
	    continue;
	}

	if (!isatty(0) )  {  /* not a terminal - get out */
	    cleanup(101);
	}

	/* Ask user if they want to wait */
	(void) fputs("Do you want to wait for dialer? (y for yes): ", stdout);
	if ((c = getchar ()) == EOF || tolower (c) != 'y')
	    cleanup(101);
	while ( (c = getchar()) != EOF && c != '\n')
	    ;

	(void) fputs ("Time, in minutes? ", stdout);
	(void) scanf ("%d", &minutes);
	while ( (c = getchar()) != EOF && c != '\n')
	    ;

	if (minutes <= 0)
	    cleanup(101);

	(void) fputs ("Waiting for dialer\n", stdout);
	sleep(60);
	continue;

    }
    /************************************************************/
    /*		End Loop:  Find an available Dialer		*/
    /************************************************************/

    /* check why loop terminated */
    if (found < 0) {	/* no dialer found - get out */
        (void) fputs("*** TIMEOUT ***\n", stdout);
        cleanup(101);
    }

    (void) signal(SIGHUP, SIG_IGN);
    /* found a dialer. now try to call */
    if (!isatty(0))
        hangup = 0;

    if (hangup) {  /* -h option not specified */
	do {
            (void) fputs ("Confirm hang-up? (y/n): ", stdout);
	    switch (c=tolower(getchar())) {
	   case EOF:
	   case 'n':
		    cleanup(101);
		    break;
	   case 'y':
		    break;
	    default:
		    while ( c != EOF && c != '\n' )
			c=getchar();
		    break;
	    }
	} while (c != 'y');

	/* close stderr if it is not redirected */
        if ( isatty(2) ) {
            Verbose = 0;
	    Debug = 0;
            (void) close (2);
	}

	(void) ioctl (0, TCGETA, &termio);
        termio.c_cflag = 0;	/* speed to zero for hangup */
        (void) ioctl (0, TCSETAW, &termio);  /* hang up terminal */
        (void) sleep (5);
    }
    (void) close(0);
    (void) close(1);

    /* Try each phone number until a connection is made, or non work */
    for (count = optind; count < argc; count++) {
	/* call getto routine to make connection */
	_Flds[F_PHONE] = argv[count];
	rmlock(CNULL);	/* remove temporary lock set by gdev */
	devreset();
	fdl = getto(_Flds);
	if (fdl >= 0) {
	    /*
	     * If there is a login process on the line, get rid
	     * of the lock file quickly so that when the process
	     * reads the first character, the lock file will be gone
	     * indicating that the process should handle the data.
	     */
	    if ( (logprocflag = logproc(Dc)) ) /* really an assignment! */
		rmlock(CNULL);

	    _Fdl = fdopen(fdl, "r+");
	    (void) sprintf(_Tty, "%s%s", DEV, Dc);
	    /* NOTE:  Dc is set in the caller routines */
	    break;
	}
    }

    /* check why the loop ended (connected or no more numbers to try) */
    if (count == argc)
	cleanup(101);

    /****** Successfully made connection ******/
    VERBOSE("Connected\n%s", "");

#ifdef	DATAKIT
 	if (!strcmp(_Dev[D_CALLER], "DK")) {
 		strcpy(_Tty, dtnamer(dkminor(fdl)));
 		strcpy(Dc, (strrchr(_Tty, '/')+1));
 		if ((_Fdl = fopen(_Tty, "r+")) == NULL) {
 			(void) fprintf(stderr, "ct: Cannot open %s, errno %d\n",
 				_Tty, errno);
 			cleanup(101);
 		}
 	}
#endif

    /* ignore some signals if they were ignored upon invocation of ct */
    /* or else, have them go to graceful disconnect */
    if (save_hup == SIG_IGN)
	(void) signal (SIGHUP, SIG_IGN);
    else
	(void) signal (SIGHUP, disconnect);

    if (save_quit == SIG_IGN)
	(void) signal (SIGQUIT, SIG_IGN);
    else
	(void) signal (SIGQUIT, disconnect);

    if (save_int == SIG_IGN)
	(void) signal (SIGINT, SIG_IGN);
    else
	(void) signal (SIGINT, disconnect);

    (void) signal (SIGTERM, disconnect);
    (void) signal (SIGALRM, disconnect);

    (void) sleep (2);		/* time for phone line/modem to settle */

    _Log_on = time ((time_t *) 0);

    /*
     * if there is a login process on this line,
     * tell the user to hit a carriage return to make
     * the waiting process get past the inital read,
     * Then exit.
     */
    if (logprocflag) {	/* there is a login process on the line */
	(void) fputs("Hit carriage return ", _Fdl);
	(void) fclose(_Fdl);
	CDEBUG(4, "there is a login process; exit\n%s", "");
	exit(0);
    }

    CDEBUG(4, "start login process (%s ", TTYMON);
    CDEBUG(4, "-g -h -t 60 -l %s)\n", fdig(_Flds[F_CLASS]));
    for (;;) {
	pid_t w_ret;
	switch(_Pid = fork()) {
	case -1:	/* fork failed */
	    if ((!hangup || Verbose))
		(void) fputs ("ct: can't fork for login process\n", stderr);
	    cleanup(101);
	    /*NOTREACHED*/

	case 0:		/* child process */
	    startat ();
	    (void) close(2);
	    /* ttymon will use open fd 0 for connection */
	    if ( fdl != 0 ) {
		(void) close(0);
		dup(fdl);
	    }
	    (void) signal(SIGHUP, SIG_DFL);  /* so child will exit on hangup */
	    (void) execl(TTYMON, "ttymon", "-g", "-h", "-t", "60",
			"-l", fdig(_Flds[F_CLASS]), (char *) 0);
	    /* exec failed */
	    cleanup(101);
	    /*NOTREACHED*/

	default:	/* parent process */
	    break;
	}

	/* Parent process */

	while ((w_ret = wait(&_Status)) != _Pid)
	    if (w_ret == -1 && errno != EINTR) {
		VERBOSE("ct: wait failed errno=%d\n", errno);
		cleanup(101);
	    }
	if ((_Status & 0xff00) < 0) {
	    if (!hangup)
		VERBOSE("ct: can't exec login process\n%s", "");
	    cleanup(101);
	}

	stopat(_Flds[F_PHONE]);

        rewind (_Fdl);	/* flush line */
        (void) fputs ("\nReconnect? ", _Fdl);

        rewind (_Fdl);
        (void) alarm (20);
        c = getc (_Fdl);

        if (c == EOF || tolower (c) == 'n')
	    disconnect (0);	/* normal disconnect */
        while ( (c = getc(_Fdl)) != EOF && c != '\n')
    	    ;
        (void) alarm (0);
    }
}

static void
disconnect (code)
{
    struct termio   termio;

    (void) alarm(0);
    (void) signal (SIGALRM, SIG_IGN);
    (void) signal (SIGINT, SIG_IGN);
    (void) signal (SIGTERM, SIG_IGN);

    _Log_elpsd = time ((time_t *) 0) - _Log_on;

    (void) ioctl (fileno(_Fdl), TCGETA, &termio);
    termio.c_cflag = 0;				/* speed to zero for hangup */
    (void) ioctl (fileno(_Fdl), TCSETAW, &termio);  /* hang up terminal */
    (void) fclose (_Fdl);

    DEBUG(5, "Disconnect(%d)\n", code);
    VERBOSE("Disconnected\n%s", "");

    /* For normal disconnect or timeout on "Reconnect?" message,
       we already cleaned up above */

    if ((code != 0) && (code != SIGALRM))
	stopat(_Flds[F_PHONE]);

    cleanup(code);
}

/*
 * clean and exit with "code" status
 */
void
cleanup (code)
int    code;
{
    CDEBUG(5, "cleanup(%d)\n", code);
    rmlock (CNULL);
    if (*_Tty != '\0') {
	CDEBUG(5, "chmod/chown %s\n", _Tty);
	if (chown(_Tty , UUCPUID, TTYGID) < 0 ) {
	    CDEBUG(5, "Can't chown to uid=%u, ", UUCPUID);
	    CDEBUG(5, "gid=%u\n", TTYGID);
	}
	if (chmod(_Tty , TTYMOD) < 0) {
	    CDEBUG(5, "Can't chmod to %lo\n", (unsigned long) TTYMOD);
	}
    }
    if (_Pid) { /* kill the child process */
	(void) signal(SIGHUP, SIG_IGN);
	(void) signal(SIGQUIT, SIG_IGN);
	(void) kill (_Pid, SIGKILL);
    }
    exit (code);
}

/*	gdev()
 * Find an available line with a dialer on it.
 * Set a temporary lock file for the line.
 * Return:
 *	>0 - got a dialer
 *	<0 - failed - return the number of possible dialers
 *	0 - not dialers of requested class on the system.
 */

static int
gdev (flds)
char   *flds[];
{
    int	count = 0;
    extern void	devreset();

    devreset();
    while (rddev ("ACU", _Dev, _Devbuf, D_MAX) != FAIL) {
	/* check caller type */
	if (!EQUALS (flds[F_TYPE] /* "ACU" */, _Dev[D_TYPE]))
	    continue;
	/* check class, check (and possibly set) speed */
	if (!EQUALS (flds[F_CLASS] /* speed */, _Dev[D_CLASS]))
	    continue;
	count++;

	if (fn_cklock(_Dev[D_LINE]) == FAIL)
	    continue;

	/* found available dialer and set temporary lock */
	return (count);

    }
    return (- count);
}

/*
 * Check if there is a login process active on this line.
 * Return:
 *	0 - there is no login process on this line
 *	1 - found a login process on this line
 */

static int
logproc(line)
char *line;
{
    struct utmpx   *u;

    while ((u = getutxent()) != NULL) {
	if (u->ut_type == LOGIN_PROCESS
	    && EQUALS(u->ut_line, line)
	    && EQUALS(u->ut_user, "LOGIN") ) {
		CDEBUG(7, "ut_line %s, ", u->ut_line);
		CDEBUG(7, "ut_user %s, ", u->ut_user);
		CDEBUG(7, "ut_id %.4s, ", u->ut_id);
		CDEBUG(7, "ut_pid %d\n", u->ut_pid);

		/* see if the process is still active */
		if (kill(u->ut_pid, 0) == 0 || errno == EPERM) {
		    CDEBUG(4, "process still active\n%s", "");
		    return(1);
		}
	}
    }
    return(0);
}

/*
 * Create an entry in utmpx file if one does not already exist.
 */
static void
startat ()
{
    struct utmpx utmpxbuf, *u;
    int fd;

/*	Set up the prototype for the utmpx structure we want to write.	*/

    u = &utmpxbuf;
    zero (&u -> ut_user[0], sizeof (u -> ut_user));
    zero (&u -> ut_line[0], sizeof (u -> ut_line));

/*	Fill in the various fields of the utmpx structure.		*/

    u -> ut_id[0] = 'c';
    u -> ut_id[1] = 't';
    u -> ut_id[2] = _Tty[strlen(_Tty)-2];
    u -> ut_id[3] = _Tty[strlen(_Tty)-1];
    u -> ut_pid = getpid ();

    u -> ut_exit.e_termination = 0;
    u -> ut_exit.e_exit = 0;
    u -> ut_type = INIT_PROCESS;
    time (&u -> ut_xtime);
    setutxent ();		/* Start at beginning of utmpx file. */

/*	For INIT_PROCESSes put in the name of the program in the	*/
/*	"ut_user" field.						*/

    strncpy (&u -> ut_user[0], "ttymon", sizeof (u -> ut_user));
    strncpy (&u -> ut_line[0], Dc, sizeof (u -> ut_line));

/*	Write out the updated entry to utmpx file.			*/
    pututxline (u);

/*	Now attempt to add to the end of the wtmpx file.  Do not create	*/
/*	if it doesn't already exist. Do not overwrite any info already	*/
/*	in file.							*/

    if ((fd = open(WTMPX_FILE, O_WRONLY | O_APPEND)) != -1) {
	(void) write(fd, u, sizeof(*u));
	(void) close(fd);
    }
    endutxent ();
    return;
}

/*
 * Change utmpx file entry to "dead".
 * Make entry in ct log.
 */

static void
stopat (num)
char   *num;
{
    struct utmpx utmpxbuf, *u;
    int fd;
    FILE * fp;

/*	Set up the prototype for the utmpx structure we want to write.	*/

    setutxent();
    u = &utmpxbuf;
    zero (&u -> ut_user[0], sizeof (u -> ut_user));
    zero (&u -> ut_line[0], sizeof (u -> ut_line));

/*	Fill in the various fields of the utmpx structure.		*/

    u -> ut_id[0] = 'c';
    u -> ut_id[1] = 't';
    u -> ut_id[2] = _Tty[strlen(_Tty)-2];
    u -> ut_id[3] = _Tty[strlen(_Tty)-1];
    u -> ut_pid = (pid_t) _Pid;
    u -> ut_type = USER_PROCESS;

/*	Find the old entry in the utmpx file with the user name and	*/
/*	copy it back.							*/

    if (u = getutxid (u)) {
	utmpxbuf = *u;
	u = &utmpxbuf;
    }

    u -> ut_exit.e_termination = _Status & 0xff;
    u -> ut_exit.e_exit = (_Status >> 8) & 0xff;
    u -> ut_type = DEAD_PROCESS;
    time (&u -> ut_xtime);

/*	Write out the updated entry to utmpx file.			*/

    pututxline (u);

/*	Now attempt to add to the end of the wtmpx file.  Do not create	*/
/*	if it doesn't already exist. Do not overwrite any info already	*/
/*	in file.							*/

    if ((fd = open(WTMPX_FILE, O_WRONLY | O_APPEND)) != -1) {
	(void) write(fd, u, sizeof(*u));
	(void) close(fd);
    }
    endutxent ();

/*	Do the log accounting 					*/

    if (exists (LOG) && (fp = fopen (LOG, "a")) != NULL) {
	char   *aptr;
	int     hrs,
	        mins,
	        secs;

 	/* ignore user set TZ for logfile purposes */
	if ( (aptr = getenv ("TZ")) != NULL )
		*aptr = '\0';

	(aptr = ctime (&_Log_on))[16] = '\0';
	hrs = _Log_elpsd / 3600;
	mins = (_Log_elpsd %= 3600) / 60;
	secs = _Log_elpsd % 60;
	(void) fprintf(fp, "%-8s ", getpwuid (getuid ()) -> pw_name);
	(void) fprintf(fp, "(%4s)  %s ", fdig(_Flds[F_CLASS]), aptr);
	if (hrs)
	    (void) fprintf(fp, "%2d:%.2d", hrs, mins);
	else
	    (void) fprintf(fp, "   %2d", mins);
	(void) fprintf(fp, ":%.2d  %s\n", secs, num);
	(void) fclose (fp);
    }
    return;
}

static int
exists (file)
char   *file;
{
    struct stat statb;

    if (stat (file, &statb) == -1 && errno == ENOENT)
	return (0);
    return (1);
}

static void
zero (adr, size)
char  *adr;
int    size;
{
    while (size--)
	*adr++ = '\0';
    return;
}

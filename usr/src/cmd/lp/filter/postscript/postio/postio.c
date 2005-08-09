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

/*
 *
 * postio - RS-232 serial interface for PostScript printers
 *
 * A simple program that manages input and output for PostScript printers. Much
 * has been added and changed from early versions of the program, but the basic
 * philosophy is still the same. Don't send real data until we're certain we've
 * connected to a PostScript printer that's in the idle state and try to hold
 * the connection until the job is completely done. It's more work than you
 * might expect is necessary, but should provide a reasonably reliable spooler
 * interface that can return error indications to the caller via the program's
 * exit status.
 *
 * I've added code that will let you split the program into separate read/write
 * processes. Although it's not the default it should be useful if you have a
 * file that will be returning useful data from the printer. The two process
 * stuff was laid down on top of the single process code and both methods still
 * work. The implementation isn't as good as it could be, but didn't require
 * many changes to the original program (despite the fact that there are now
 * many differences).
 *
 * By default the program still runs as a single process. The -R2 option forces
 * separate read and write processes after the intial connection is made. If you
 * want that as the default initialize splitme (below) to TRUE. In addition the
 * -t option that's used to force stuff not recognized as status reports to
 * stdout also tries to run as two processes (by setting splitme to TRUE). It
 * will only work if the required code (ie. resetline() in ifdef.c) has been
 * implemented for your Unix system. I've only tested the System V code.
 *
 * Code needed to support interactive mode has also been added, although again
 * it's not as efficient as it could be. It depends on the system dependent
 * procedures resetline() and setupstdin() (file ifdef.c) and for now is only
 * guaranteed to work on System V. Can be requested using the -i option.
 *
 * Quiet mode (-q option) is also new, but was needed for some printers
 * connected to RADIAN. If you're running in quiet mode no status requests will
 * be sent to the printer while files are being transmitted (ie. in send()).
 *
 * The program expects to receive printer status lines that look like,
 *
 *	%%[ status: idle; source: serial 25 ]%%
 *	%%[ status: waiting; source: serial 25 ]%%
 *	%%[ status: initializing; source: serial 25 ]%%
 *	%%[ status: busy; source: serial 25 ]%%
 *	%%[ status: printing; source: serial 25 ]%%
 *	%%[ status: PrinterError: out of paper; source: serial 25 ]%%
 *	%%[ status: PrinterError: no paper tray; source: serial 25 ]%%
 *
 * although this list isn't complete. Sending a '\024' (control T) character
 * forces the return of a status report. PostScript errors detected on the
 * printer result in the immediate transmission of special error messages that
 * look like,
 *
 *	%%[ Error: undefined; OffendingCommand: xxx ]%%
 *	%%[ Flushing: rest of job (to end-of-file) will be ignored ]%%
 *
 * although we only use the Error and Flushing keywords. Finally conditions,
 * like being out of paper, result in other messages being sent back from the
 * printer over the communications line. Typical PrinterError messages look
 * like,
 *
 *	%%[ PrinterError: out of paper; source: serial 25 ]%%
 *	%%[ PrinterError: paper jam; source: serial 25 ]%%
 *
 * although we only use the PrinterError keyword rather than trying to recognize
 * all possible printer errors.
 *
 * The implications of using one process and only flow controlling data going to
 * the printer are obvious. Job transmission should be reliable, but there can
 * be data loss in stuff sent back from the printer. Usually that only caused
 * problems with jobs designed to run on the printer and return useful data
 * back over the communications line. If that's the kind of job you're sending
 * call postio with the -t option. That should force the program to split into
 * separate read and write processes and everything not bracketed by "%%[ "
 * and " ]%%" strings goes to stdout. In otherwords the data you're expecting
 * should be separated from the status stuff that goes to the log file (or
 * stderr). The -R2 option does almost the same thing (ie. separate read and
 * write processes), but everything that comes back from the printer goes to
 * the log file (stderr by default) and you'll have to separate your data from
 * any printer messages.
 *
 * A typical command line might be,
 *
 *	postio -l /dev/tty01 -b 9600 -L log file1 file2
 *
 * where -l selects the line, -b sets the baud rate, and -L selects the printer
 * log file. Since there's no default line, at least not right now, you'll
 * always need to use the -l option, and if you don't choose a log file stderr
 * will be used. If you have a program that will be returning data the command
 * line might look like,
 *
 *	postio -t -l/dev/tty01 -b9600 -Llog file >results
 *
 * Status stuff goes to file log while the data you're expecting back from the
 * printer gets put in file results.
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include <sys/ioccom.h>
#include <sys/ioctl.h>
#include <sys/bpp_io.h>
#include <sys/ecppsys.h>

#include "ifdef.h"			/* conditional compilation stuff */
#include "gen.h"			/* general purpose definitions */
#include "postio.h"			/* some special definitions */

static char	**argv;			/* global so everyone can use them */
static int	argc;
static char	*prog_name = "";	/* really just for error messages */
static int	x_stat = 0;		/* program exit status */
static int	debug = OFF;		/* debug flag */
static int	ignore = OFF;		/* what's done for FATAL errors */
static Baud	baudtable[] = BAUDTABLE; /* converts strings to termio values */
static int	quiet = FALSE;		/* no status queries in send if TRUE */
char	*postbegin = POSTBEGIN;	/* preceeds all the input files */
static int	useslowsend = FALSE;	/* not recommended! */
static int	splitme = FALSE;	/* into READ & WRITE procs if TRUE */
static int	whatami = READWRITE;	/* a READ or WRITE process - or both */
static int	otherpid = -1;		/* who gets signals if greater than 1 */
static int	joinsig = SIGTRAP;	/* reader gets when writing is done */
static int	writedone = FALSE;	/* and then sets this to TRUE */
static char	sbuf[MESGSIZE];		/* for parsing the message */
static char	*mesgptr = NULL;	/* printer msg starts here in mesg[] */
static Status	status[] = STATUS;	/* for converting status strings */
static int	nostatus = NOSTATUS;	/* default getstatus() return value */
static int	tostdout = FALSE;	/* non-status stuff goes to stdout? */
static int	currentstate = NOTCONNECTED;	/* START, SEND, or DONE */

char	*line = NULL;			/* printer is on this tty line */
short	baudrate = BAUDRATE;		/* and running at this baud rate */
int	stopbits = 1;			/* number of stop bits */
int	interactive = FALSE;		/* interactive mode */
char	*block = NULL;			/* input file buffer */
int	blocksize = BLOCKSIZE;		/* and its size in bytes */
int	head = 0;			/* block[head] is the next character */
int	tail = 0;			/* one past the last byte in block[] */
int	canread = TRUE;			/* allow reads */
int	canwrite = TRUE;		/* and writes if TRUE */
char	mesg[MESGSIZE];			/* exactly what came back on ttyi */
char	*endmesg = NULL;		/* end for readline() in mesg[] */
int	ttyi = 0;			/* input */
int	ttyo = 2;			/* and output file descriptors */
FILE	*fp_log = stderr;		/* log file for stuff from printer */

static void	init_signals(void);
static void	interrupt(int);
static void	options(void);
static void	initialize(void);
static void	initialize_parallel(void);
static void	start(void);
static void	split(void);
static void	arguments(void);
static void	send(int, char *);
static void	done(void);
static void	cleanup(void);
static void	clearline(void);
void	logit(char *, ...);
static void	quit(int sig);
static void	Rest(int t);
static int	parsemesg(void);
static int	sendsignal(int);
static int	writeblock(void);
static int	Write(int, char *, int);
static short	getbaud(char *);
static char	*find(char *, char *);

void		error(int, char *, ...);
int		getstatus(int);
int		readblock(int);


/*	from parallel.c for parallel interfaces		*/
extern int	is_a_parallel_bpp(int);
extern int	bpp_state(int);
extern int	is_a_prnio(int);
extern int	prnio_state(int);
extern int	parallel_comm(int, int()); /* arg is bpp_state */

/*	from ifdef.c for serial interfaces	*/
extern void	setupline(void);
extern void	setupstdin(int);
extern void	slowsend(int);
extern int	resetline(void);
extern int	readline(void);

/*
 * A simple program that manages input and output for PostScript printers.
 * Can run as a single process or as separate read/write processes. What's
 * done depends on the value assigned to splitme when split() is called.
 */

int nop(int fd) { return(0); }


int
main(int agc, char *agv[])
{
	argc = agc;
	argv = agv;
	prog_name = argv[0];		/* really just for error messages */

	/* is this a serial or parallel port? */

	init_signals();		/* sets up interrupt handling */
	options();		/* get command line options */

	setbuf(stderr, NULL);   /* unbuffer io for stderr */
	

	if (line) {
		close(1);
		open(line, O_RDWR);

	}

	if (is_a_prnio(1)) {
		initialize_parallel();
		x_stat = parallel_comm(1, prnio_state);
	} else if (is_a_parallel_bpp(1) ||
		    (get_ecpp_status(1) == ECPP_CENTRONICS)) {
		initialize_parallel();
		x_stat = parallel_comm(1, bpp_state);
	} else if (isatty(1)) {
		initialize();		/* must be done after options() */
		start();		/* make sure the printer is ready */
		split();		/* into read/write processes - maybe */
		arguments();		/* then send each input file */
		done();			/* wait until the printer is finished */
		cleanup();		/* make sure the write process stops */
	} else {
		initialize_parallel();
		x_stat = parallel_comm(1, nop);
	}
	

	return (x_stat);		/* everything probably went OK */
}


/*
 * Makes sure we handle interrupts. The proper way to kill the program, if
 * necessary, is to do a kill -15. That forces a call to interrupt(), which in
 * turn tries to reset the printer and then exits with a non-zero status. If the
 * program is running as two processes, sending SIGTERM to either the parent or
 * child should clean things up.
 */

static void
init_signals(void)
{
    if (signal(SIGINT, interrupt) == SIG_IGN) {
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
    } else {
	signal(SIGHUP, interrupt);
	signal(SIGQUIT, interrupt);
    }

    signal(SIGTERM, interrupt);

}


/*
 * Reads and processes the command line options. The -R2, -t, and -i options all
 * force separate read and write processes by eventually setting splitme to TRUE
 * (check initialize()). The -S option is not recommended and should only be
 * used as a last resort!
 */

static void
options(void)
{
    int		ch;			/* return value from getopt() */
    char	*optnames = "b:il:qs:tB:L:P:R:SDI";

    extern char	*optarg;		/* used by getopt() */
    extern int	optind;

    while ((ch = getopt(argc, argv, optnames)) != EOF) {

	switch (ch) {

	    case 'b':			/* baud rate string */
		    baudrate = getbaud(optarg);
		    break;

	    case 'i':			/* interactive mode */
		    interactive = TRUE;
		    break;

	    case 'l':			/* printer line */
		    line = optarg;
		    break;

	    case 'q':			/* no status queries - for RADIAN? */
		    quiet = TRUE;
		    break;

	    case 's':			/* use 2 stop bits - for UNISON? */
		    if ((stopbits = atoi(optarg)) < 1 || stopbits > 2)
			stopbits = 1;
		    break;

	    case 't':			/* non-status stuff goes to stdout */
		    tostdout = TRUE;
		    break;

	    case 'B':			/* set the job buffer size */
		    if ((blocksize = atoi(optarg)) <= 0)
			blocksize = BLOCKSIZE;
		    break;

	    case 'L':			/* printer log file */
		    if ((fp_log = fopen(optarg, "w")) == NULL)  {
			fp_log = stderr;
			error(NON_FATAL, "can't open log file %s", optarg);
		    }	/* End if */
		    break;

	    case 'P':			/* initial PostScript code */
		    postbegin = optarg;
		    break;

	    case 'R':			/* run as one or two processes */
		    if (atoi(optarg) == 2)
			splitme = TRUE;
		    else splitme = FALSE;
		    break;

	    case 'S':			/* slow and kludged up vers. of send */
		    useslowsend = TRUE;
		    break;

	    case 'D':			/* debug flag */
		    debug = ON;
		    break;

	    case 'I':			/* ignore FATAL errors */
		    ignore = ON;
		    break;

	    case '?':			/* don't understand the option */
		    error(FATAL, "");
		    break;

	    default:			/* don't know what to do for ch */
		    error(FATAL, "missing case for option %c\n", ch);
		    break;

	}   /* End switch */

    }   /* End while */

    argc -= optind;			/* get ready for non-option args */
    argv += optind;

}


/*
 * Called from options() to convert a baud rate string into an appropriate
 * termio value. *rate is looked up in baudtable[] and if it's found, the
 * corresponding value is returned to the caller.
 */

static short
getbaud(char *rate)			/* string representing the baud rate */
{
    int		i;			/* for looking through baudtable[] */

    for (i = 0; baudtable[i].rate != NULL; i++)
	if (strcmp(rate, baudtable[i].rate) == 0)
	    return (baudtable[i].val);

    error(FATAL, "don't recognize baud rate %s", rate);
    /*NOTREACHED*/
    return (0);

}


/*
 * Initialization, a few checks, and a call to setupline() (file ifdef.c) to
 * open and configure the communications line. Settings for interactive mode
 * always take precedence. The setupstdin() call with an argument of 0 saves
 * the current terminal settings if interactive mode has been requested -
 * otherwise nothing's done. Unbuffering stdout (via the setbuf() call) isn't
 * really needed on System V since it's flushed whenever terminal input is
 * requested. It's more efficient if we buffer the stdout (on System V) but
 * safer (for other versions of Unix) if we include the setbuf() call.
 */

static void
initialize(void)
{
    whatami = READWRITE;		/* always run start() as one process */
    canread = canwrite = TRUE;

    if (line == NULL)			/* kludge for lp - they use -t option */
	tostdout = FALSE;

    if (tostdout == TRUE)		/* force separate read/write procs */
	splitme = TRUE;

    if (interactive == TRUE) {		/* interactive mode settings win */
	quiet = FALSE;
	tostdout = FALSE;
	splitme = TRUE;
	blocksize = 1;
	postbegin = NULL;
	useslowsend = FALSE;
	nostatus = INTERACTIVE;
	setbuf(stdout, NULL);
    }

    if (useslowsend == TRUE) {		/* last resort only - not recommended */
	quiet = FALSE;
	splitme = FALSE;
	if (blocksize > 1024)		/* don't send too much all at once */
	    blocksize = 1024;
    }

    if (line == NULL && (interactive == TRUE || tostdout == TRUE))
	error(FATAL, "a printer line must be supplied - use the -l option");

    if ((block = malloc(blocksize)) == NULL)
	error(FATAL, "no memory");

    endmesg = mesg + sizeof mesg - 2;	/* one byte from last pos. in mesg */

    setupline();			/* configure the communications line */
    setupstdin(0);			/* save current stdin term settings */

}

static void
initialize_parallel(void)
{
	if ((block = malloc(blocksize)) == NULL)
		error(FATAL, "no memory");
}


/*
 * Tries to put the printer in the IDLE state before anything important is sent.
 * Run as a single process no matter what has been assigned to splitme. Separate
 * read and write processes, if requested, will be created after we're done
 * here.
 */

static void
start(void)
{
   int longwait = 0;

    logit("printer startup\n");

    currentstate = START;
    clearline();

    for (;;)
	switch (getstatus(1))  {

	    case IDLE:
	    case INTERACTIVE:
		    if (postbegin != NULL && *postbegin != '\0')
			Write(ttyo, postbegin, strlen(postbegin));
		    clearline();
		    return;

	    case BUSY:
		    Write(ttyo, "\003", 1);
		    Rest(1);
		    break;

	    /* 03/24/95 - bob golden
	     * The HP LJ3 starts in waiting mode and needs the EOF to move
	     * from waiting to idle. To see what would happen, code was added
	     * to send the INTR on waiting and later changed to INTR/EOF.
	     * The INTR by itself had no effect. The INTR/EOF put the
	     * the printer in a busy status loop from which the only
	     * recovery was to reset the printer. Until further testing
	     * testing is done, do not send an INTR to a HPLJ3 in waiting
	     * state. WAITING moved to a separate case to eliminate the
	     * INTR write.
	     */
	    case WAITING:
		    Write(ttyo, "\004", 1);
		    Rest(1);
		    break;

	    /* 03/24/95 - bob golden
	     * The HP LJ3 seems to process INTR at later times. All the
	     * longwaits are increaased to reduce the number of INTRs sent.
	     */
	    case ERROR:
	    case FLUSHING:
		    Write(ttyo, "\004", 1);
		    if (longwait++ == 5) {
		    	Write(ttyo, "\003", 1);
			Rest(5);
			longwait = 0;
		    }
		    Rest(1);
		    break;

	    case PRINTERERROR:
		    Rest(15);
		    break;

	    case DISCONNECT:
		    error(FATAL, "Disconnected - printer may be offline");
		    break;

	    /* 03/24/95 - bob golden
	     * The ENDJOB case has been removed. The HP LJ3 echoes all EOFs
	     * sent so the ENDJOB has no real meaning.
	     */
	    case UNKNOWN:
		    clearline();
		    break;

	    default:
		    Rest(1);
		    break;

	}   /* End switch */

}   /* End of start */


/*
 *
 * If splitme is TRUE we fork a process, make the parent handle reading, and let
 * the child take care of writing. resetline() (file ifdef.c) contains all the
 * system dependent code needed to reset the communications line for separate
 * read and write processes. For now it's expected to return TRUE or FALSE and
 * that value controls whether we try the fork. I've only tested the two process
 * stuff for System V. Other versions of resetline() may just be dummy
 * procedures that always return FALSE. If the fork() failed previous versions
 * continued as a single process, although the implementation wasn't quite
 * right, but I've now decided to quit. The main reason is a Datakit channel
 * may be configured to flow control data in both directions, and if we run
 * postio over that channel as a single process we likely will end up in
 * deadlock.
 */

static void
split(void)
{
	int	pid;

	if (splitme == TRUE)
		if (resetline() == TRUE) {
			pid = getpid();
			signal(joinsig, interrupt);
			if ((otherpid = fork()) == -1)
				error(FATAL, "can't fork");
			else if (otherpid == 0) {
				whatami = WRITE;
				nostatus = WRITEPROCESS;
				otherpid = pid;
				setupstdin(1);
			} else
				whatami = READ;
		} else if (interactive == TRUE || tostdout == TRUE)
			error(FATAL,
				"can't create two process - check resetline()");
		else
			error(NON_FATAL,
			    "running as a single process - check resetline()");

	canread = (whatami & READ) ? TRUE : FALSE;
	canwrite = (whatami & WRITE) ? TRUE : FALSE;
}


/*
 * Makes sure all the non-option command line arguments are processed. If there
 * aren't any arguments left when we get here we'll send stdin. Input files are
 * only read and sent to the printer if canwrite is TRUE. Checking it here means
 * we won't have to do it in send(). If interactive mode is TRUE we'll stay here
 * forever sending stdin when we run out of files - exit with a break. Actually
 * the loop is bogus and used at most once when we're in interactive mode
 * because stdin is in a pseudo raw mode and the read() in readblock() should
 * never see the end of file.
 */

static void
arguments(void)
{
    int		fd_in;			/* next input file */

    if (canwrite == TRUE)
	do				/* loop is for interactive mode */
	    if (argc < 1)
		send(fileno(stdin), "pipe.end");
	    else  {
		while (argc > 0) {
		    if ((fd_in = open(*argv, O_RDONLY)) == -1)
			error(FATAL, "can't open %s", *argv);
		    send(fd_in, *argv);
		    close(fd_in);
		    argc--;
		    argv++;
		}
	    }
	while (interactive == TRUE);
}

/*
 * Sends file *name to the printer. There's nothing left here that depends on
 * sending and receiving status reports, although it can be reassuring to know
 * the printer is responding and processing our job. Only the writer gets here
 * in the two process implementation, and in that case split() has reset
 * nostatus to WRITEPROCESS and that's what getstatus() always returns. For
 * now we accept the IDLE state and ENDOFJOB as legitimate and ignore the
 * INITIALIZING state.
 *
 * fd_in	next input file
 * name		it's pathname
 */

static void
send(int fd_in, char *name)
{
    if (interactive == FALSE)
	logit("sending file %s\n", name);

    currentstate = SEND;

    if (useslowsend == TRUE) {
	slowsend(fd_in);
	return;
    }

    while (readblock(fd_in))

	switch (getstatus(0)) {

	    case IDLE:
	    case BUSY:
	    case WAITING:
	    case PRINTING:
	    case ENDOFJOB:
	    case PRINTERERROR:
	    case UNKNOWN:
	    case NOSTATUS:
	    case WRITEPROCESS:
	    case INTERACTIVE:
		    writeblock();
		    break;

	    case ERROR:
		    fprintf(stderr, "%s", mesg);	/* for csw */
		    error(USER_FATAL, "PostScript Error");
		    break;

	    case FLUSHING:
		    error(USER_FATAL, "Flushing Job");
		    break;

	    case DISCONNECT:
		    error(FATAL, "Disconnected - printer may be offline");
		    break;

	}

}


/*
 * Tries to stay connected to the printer until we're reasonably sure the job is
 * complete. It's the only way we can recover error messages or data generated
 * by the PostScript program and returned over the communication line. Actually
 * doing it correctly for all possible PostScript jobs is more difficult that it
 * might seem. For example if we've sent several jobs, each with their own EOF
 * mark, then waiting for ENDOFJOB won't guarantee all the jobs have completed.
 * Even waiting for IDLE isn't good enough. Checking for the WAITING state after
 * all the files have been sent and then sending an EOF may be the best
 * approach, but even that won't work all the time - we could miss it or might
 * not get there. Even sending our own special PostScript job after all the
 * input files has it's own different set of problems, but probably could work
 * (perhaps by printing a fake status message or just not timing out). Anyway
 * it's probably not worth the trouble so for now we'll quit if writedone is
 * TRUE and we get ENDOFJOB or IDLE.
 *
 * If we're running separate read and write processes the reader gets here after
 * after split() while the writer goes to send() and only gets here after all
 * the input files have been transmitted. When they're both here the writer
 * sends the reader signal joinsig and that forces writedone to TRUE in the
 * reader. At that point the reader can begin looking for an indication of the
 * end of the job.  The writer hangs around until the reader kills it (usually
 * in cleanup()) sending occasional status requests.
 */

static void
done(void)
{
    int		sleeptime = 15;		/* for 'out of paper' etc. */
    int longwait = 0;

    if (canwrite == TRUE)
	logit("waiting for end of job\n");

    currentstate = DONE;
    writedone = (whatami == READWRITE) ? TRUE : FALSE;

    for (;;) {

	switch (getstatus(1)) {
	    case WRITEPROCESS:
		    if (writedone == FALSE) {
			sendsignal(joinsig);
			Write(ttyo, "\004", 1);
			writedone = TRUE;
			sleeptime = 1;
		    }
		    Rest(sleeptime++);
		    break;

	    /* 03/24/95 - bob golden
	     * For the HP LJ3 INTR sent while in the waiting state have
	     * either had no effect or put the printer into a unrecoverable
	     * loop. Further testing may reveal this to not be the case
	     * but for now, remove the send INTR.
	     */
	    case WAITING:
		    Write(ttyo, "\004", 1);
		    Rest(1);
		    sleeptime = 15;
		    break;

	    /* 03/24/95 - bob golden
	     * ENDOFJOB case removed here. The HP LJ 3 echoes all EOFs sent so
	     * the ENDOFJOB case is meaningless.
	     */
	    case IDLE:
		    if (writedone == TRUE) {
			logit("job complete\n");
			return;
		    }
		    break;

	    /* 03/24/95 - bob golden
	     * During print data transmission, the HP LJ3 stays in
	     * status busy. So give it a rest.
	     * 
	     */
	    case BUSY:
	    case PRINTING:
		    Rest(1);
		    sleeptime = 15;
		    break;

	    case INTERACTIVE:
		    Write(ttyo, "\004", 1);
		    sleeptime = 15;
		    break;

	    case PRINTERERROR:
		    Rest(sleeptime++);
		    break;

	    case ERROR:
		    Write(ttyo, "\004", 1);
		    fprintf(stderr, "%s", mesg);	/* for csw */
		    error(USER_FATAL, "PostScript Error");
		    return;

	    case FLUSHING:
		    Write(ttyo, "\004", 1);
		    error(USER_FATAL, "Flushing Job");
		    return;

	    case DISCONNECT:
		    error(FATAL, "Disconnected - printer may be offline");
		    return;

	    /* 03/24/95 - bob golden
	     * These cases are ignored without a EOF being sent
	     */
	    case ENDOFJOB:
	    case NOSTATUS:
		    Rest(1);
		    break;

	    default:
		    Write(ttyo, "\004", 1);
		    Rest(1);
		    break;

	}

	if (sleeptime > 60)
	    sleeptime = 60;

    }

}


/*
 * Only needed if we're running separate read and write processes. Makes sure
 * the write process is killed after the read process has successfully finished
 * with all the jobs. sendsignal() returns a -1 if there's nobody to signal so
 * things work when we're running a single process.
 */

static void
cleanup(void)
{
    int		w;

    while (sendsignal(SIGKILL) != -1 && (w = wait((int *)0)) != otherpid &&
	w != -1);
    if ( currentstate != NOTCONNECTED )
      Write(ttyo, "\004", 1);
}


/*
 * Fills the input buffer with the next block, provided we're all done with the
 * last one. Blocks from fd_in are stored in array block[]. head is the index
 * of the next byte in block[] that's supposed to go to the printer. tail points
 * one past the last byte in the current block. head is adjusted in writeblock()
 * after each successful write, while head and tail are reset here each time
 * a new block is read. Returns the number of bytes left in the current block.
 * Read errors cause the program to abort. The fake status message that's put
 * out in quiet mode is only so you can look at the log file and know
 * something's happening - take it out if you want.
 */

int
readblock(int fd_in)
{
    static long	blocknum = 1;

    if (head >= tail) {		/* done with the last block */
	if ((tail = read(fd_in, block, blocksize)) == -1)
	    error(FATAL, "error reading input file");
	if (quiet == TRUE && tail > 0)	/* put out a fake message? */
	    logit("%%%%[ status: busy; block: %d ]%%%%\n", blocknum++);
	head = 0;
    }

    return (tail - head);

}


/*
 * Called from send() when it's OK to send the next block to the printer. head
 * is adjusted after the write, and the number of bytes that were successfully
 * written is returned to the caller.
 */

static int
writeblock(void)
{
    int		count;			/* bytes successfully written */

    if ((count = write(ttyo, &block[head], tail - head)) == -1)
	error(FATAL, "error writing to %s", line);
    else if (count == 0)
	error(FATAL, "printer appears to be offline");

    head += count;
    return (count);

}


/*
 * Looks for things coming back from the printer on the communications line,
 * parses complete lines retrieved by readline(), and returns an integer
 * representation of the current printer status to the caller. If nothing was
 * available a status request (control T) is sent to the printer and nostatus
 * is returned to the caller (provided quiet isn't TRUE). Interactive mode
 * either never returns from readline() or returns FALSE.
 */

int
getstatus(int t)			/* sleep time after sending '\024' */
{
    int		state = nostatus;	/* the current state */
    static int	laststate = NOSTATUS;	/* last state recognized */


    if (canread == TRUE && readline() == TRUE)  {
	state = parsemesg();
	if (state != laststate || mesgptr != mesg || debug == ON)
	    logit("%s", mesg);

	if (tostdout == TRUE && currentstate != START) {
	    *mesgptr = '\0';
	    fprintf(stdout, "%s", mesg);
	}
	return (laststate = state);
    }

    if ((quiet == FALSE || currentstate != SEND) && interactive == FALSE) {
	if (Write(ttyo, "\024", 1) != 1)
	    error(FATAL, "printer appears to be offline");
	if (t > 0) Rest(t);
    }

    return (nostatus);
}


/*
 *
 * Parsing the lines that readline() stores in mesg[] is messy, and what's done
 * here isn't completely correct nor as fast as it could be. The general format
 * of lines that come back from the printer (assuming no data loss) is:
 *
 *		str%%[ key: val; key: val; key: val ]%%\n
 *
 * where str can be most anything not containing a newline and printer reports
 * (eg. status or error messages) are bracketed by "%%[ " and " ]%%" strings and
 * end with a newline. Usually we'll have the string or printer report but not
 * both. For most jobs the leading string will be empty, but could be anything
 * generated on a printer and returned over the communications line using the
 * PostScript print operator. I'll assume PostScript jobs are well behaved and
 * never bracket their messages with "%%[ " and " ]%%" strings that delimit
 * status or error messages.
 *
 * Printer reports consist of one or more key/val pairs, and what we're
 * interested in (status or error indications) may not be the first pair in the
 * list. In addition we'll sometimes want the value associated with a keyword
 * (eg. when key = status) and other times we'll want the keyword (eg. when
 * key = Error or Flushing). The last pair isn't terminated by a semicolon and
 * a value string often contains many space separated words and it can even
 * include colons in meaningful places. I've also decided to continue
 * converting things to lower case before doing the lookup in status[]. The
 * isupper() test is for Berkeley systems.
 */

static int
parsemesg(void)
{
	char	*e;			/* end of printer message in mesg[] */
	char	*key, *val;		/* keyword/value strings in sbuf[] */
	char	*p;			/* for converting to lower case etc. */
	int	i;			/* where *key was found in status[] */

	if (*(mesgptr = find("%%[ ", mesg)) != '\0' &&
	    *(e = find(" ]%%", mesgptr+4)) != '\0') {

		strcpy(sbuf, mesgptr+4);	/* don't change mesg[] */
		sbuf[e-mesgptr-4] = '\0';	/* ignore the trailing " ]%%" */

		for (key = strtok(sbuf, " :"); key != NULL;
		    key = strtok(NULL, " :")) {
			if ((val = strtok(NULL, ";")) != NULL &&
			    strcmp(key, "status") == 0)
				key = val;

			for (; *key == ' '; key++);	/* skip leading space */
			for (p = key; *p; p++)		/* conv to lower case */
				if (*p == ':' || *p == ',') {
					*p = '\0';
					break;
				} else if (isupper(*p))
					*p = tolower(*p);

			for (i = 0; status[i].state != NULL; i++)
				if (strcmp(status[i].state, key) == 0)
					return (status[i].val);
		}
	} else if (strcmp(mesg, "CONVERSATION ENDED.\n") == 0)
		return (DISCONNECT);

	return (nostatus);
}


/*
 * Looks for *str1 in string *str2. Returns a pointer to the start of the
 * substring if it's found or to the end of string str2 otherwise.
 */

static char *
find(char *str1, char *str2)
{
    char	*s1, *s2;		/* can't change str1 or str2 too fast */

    for (; *str2 != '\0'; str2++) {
	for (s1 = str1, s2 = str2; *s1 != '\0' && *s1 == *s2; s1++, s2++);
	if (*s1 == '\0')
	    break;
    }

    return (str2);

}


/*
 * Reads characters from the input line until nothing's left. Don't do
 * anything if we're currently running separate read and write processes.
 */

static void
clearline(void)
{
    if (whatami == READWRITE)
	while (readline() != FALSE);

}


/*
 * Sends signal sig to the other process if we're running as separate read and
 * write processes. Returns the result of the kill if there's someone else to
 * signal or -1 if we're running alone.
 *
 */

static int
sendsignal(int sig)
{
    if (whatami != READWRITE && otherpid > 1)
	return (kill(otherpid, sig));

    return (-1);
}


/*
 * Caught a signal - all except joinsig cause the program to quit. joinsig is
 * the signal sent by the writer to the reader after all the jobs have been
 * transmitted.  Used to tell the read process when it can start looking for
 * the end of the job.
 */

static void
interrupt(int sig)
{
    signal(sig, SIG_IGN);

    if (sig != joinsig) {
	x_stat |= FATAL;
	if (canread == TRUE)
	    if (interactive == FALSE)
		error(NON_FATAL, "signal %d abort", sig);
	    else error(NON_FATAL, "quitting");
	quit(sig);
    }

    writedone = TRUE;
    signal(joinsig, interrupt);
}


/*
 * Simple routine that's used to write a message to the log file.
 */

void
logit(char *mesg, ...)
{
	va_list	ap;

	va_start(ap, mesg);
	vfprintf(fp_log, mesg, ap);
	va_end(ap);

	fflush(fp_log);

}

/*
 * Called when we've run into some kind of program error. First *mesg is
 * printed.  If kind is FATAL and we're not ignoring errors the program
 * will be terminated. If mesg is NULL or *mesg is the NULL string nothing
 * will be printed.
 */

void
error(int kind, char *mesg, ...)
{
	va_list	ap;

	if (mesg != NULL && *mesg != '\0') {
		fprintf(fp_log, "%s: ", prog_name);

		va_start(ap, mesg);
		vfprintf(fp_log, mesg, ap);
		va_end(ap);

		putc('\n', fp_log);
	}

	x_stat |= kind;

	if (kind != NON_FATAL && ignore == OFF)
		quit(SIGTERM);

}


/*
 *
 * Makes sure everything is properly cleaned up if there's a signal or FATAL
 * error that should cause the program to terminate. The sleep by the write
 * process is to help give the reset sequence a chance to reach the printer
 * before we break the connection - primarily for printers connected to Datakit.
 * There's a very slight chance the reset sequence that's sent to the printer
 * could get us stuck here. Simplest solution is don't bother to send it -
 * everything works without it.  Flushing ttyo would be better, but means yet
 * another system dependent procedure in ifdef.c! I'll leave things be for now.
 */

static void
quit(int sig)
{
    int		w;

    signal(sig, SIG_IGN);
    ignore = ON;

    while (sendsignal(sig) != -1 && (w = wait((int *)0)) != otherpid &&
	w != -1);

    setupstdin(2);

    if (currentstate != NOTCONNECTED)
	Write(ttyo, "\003\004", 2);
    alarm(0);			/* prevents sleep() loop on V9 systems */
    Rest(2);

    exit(x_stat);

}


/*
 * Used to replace sleep() calls. Only needed if we're running the program as
 * a read and write process and don't want to have the read process sleep. Most
 * sleeps are in the code because of the non-blocking read used by the single
 * process implementation. Probably should be a macro.
 */

static void
Rest(int t)
{
    if (t > 0 && canwrite == TRUE)
	sleep(t);

}


/*
 * Used to replace some of the read() calls. Only needed if we're running
 * separate read and write processes. Should only be used to replace read calls
 * on ttyi.  Always returns 0 to the caller if the process doesn't have its
 * READ flag set.  Probably should be a macro.
 */

#ifdef NEVER

static int
Read(int fd, char *buf, int n)
{
    int		count;

    if (canread == TRUE) {
	if ((count = read(fd, buf, n)) == -1 && errno == EINTR)
	    count = 0;
    } else count = 0;

    return (count);

}

#endif	/* NEVER */


/*
 *
 * Used to replace some of the write() calls. Again only needed if we're running
 * separate read and write processes. Should only be used to replace write calls
 * on ttyo. Always returns n to the caller if the process doesn't have its WRITE
 * flag set. Should also probably be a macro.
 *
 */

static int
Write(int fd, char *buf, int n)
{
    int		count;

    if (canwrite == TRUE) {
	if ((count = write(fd, buf, n)) == -1 && errno == EINTR)
	    count = n;
    } else count = n;

    return (count);
}

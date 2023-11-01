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

/*
 * cu [-cdevice] [-sspeed] [-lline] [-bbits] [-h] [-t] [-d] [-n]
 *		[-o|-e] [-L] [-C] telno | systemname [local-cmd]
 *
 *	legal baud rates: 300, 1200, 2400, 4800, 9600, 19200, 38400.
 *
 *	-c is used to specify which device will be used for making the
 *		call.  The device argument is compared to the Type (first)
 *		field in the Devices file, and only those records that
 *		match will be used to make the call.  Either -d or -t
 *		would be more intuitive options designations, but they
 *		are already in use.
 *	-l is for specifying a line unit from the file whose
 *		name is defined in /etc/uucp/Devices.
 *	-b is for forcing the number of bits per character processed on
 *		the connection. Valid values are '7' or '8'.
 *	-h is for half-duplex (local echoing).
 *	-t is for adding CR to LF on output to remote (for terminals).
 *	-d can be used  to get some tracing & diagnostics.
 *	-o or -e is for odd or even parity on transmission to remote.
 *	-n will request the phone number from the user.
 *	-L will cause cu to go through the login chat sequence in the
 *		Systems file.
 *	-C will cause cu to run the local command specified at the end
 *		of the command line, instead of entering interactive mode.
 *	Telno is a telephone number with `=' for secondary dial-tone.
 *	If "-l dev" is used, speed is taken from /etc/uucp/Devices.
 *	Only systemnames that are included in /etc/uucp/Systems may
 *	be used.
 *
 *	Escape with `~' at beginning of line:
 *
 *	~.	quit,
 *
 *	~![cmd]			execute shell (or 'cmd') locally,
 *
 *	~$cmd			execute 'cmd' locally, stdout to remote,
 *
 *	~%break	(alias ~%b)	transmit BREAK to remote,
 *	~%cd [dir]		change directory to $HOME (or 'dir'),
 *	~%debug (alias ~%d)	toggles on/off the program debug trace,
 *	~%divert		allow unsolicited diversions to files,
 *	~%ifc (alias ~%nostop)	toggles on/off the DC3/DC1 input control,
 *	~%ofc (alias ~%noostop)	toggles on/off the DC3/DC1 output control,
 *		(certain remote systems cannot cope with DC3 or DC1).
 *	~%old			recognize old style silent diversions,
 *	~%put from [to]		put file from local to remote,
 *	~%take from [to]	take file from remote to local,
 *
 *	~l			dump communication line ioctl settings,
 *	~t			dump terminal ioctl settings.
 *
 *	Silent diversions are enabled only for use with the ~%take
 *	command by default for security reasons. Unsolicited diversions
 *	may be enabled using the ~%divert toggle. The 'new-style'
 *	diversion syntax is "~[local]>:filename", and is terminaled
 *	by "~[local]>", where 'local' is the nodename of the local
 *	system. This enables ~%take to operate properly when cu
 *	is used over multiple hops. 'old-style' diversion syntax may
 *	be enabled using the ~%old toggle. ('old-style' diversion
 *	should be avoided!)
 *
 *	Cu no longer uses dial.c to reach the remote.  Instead, cu places
 *	a telephone call to a remote system through the uucp conn() routine
 *	when the user picks the systemname option or through altconn()--
 *	which bypasses /etc/uucp/Systems -- if a telno or direct
 *	line is chosen. The line termio attributes are set in fixline(),
 *	before the remote connection is made.  As a device-lockout semaphore
 *	mechanism, uucp creates an entry in /var/spool/locks whose name is
 *	LK.<MAJ>.<maj>.<min> where MAJ is the major device of the
 *	filesystem containing the device, and <maj> and <min> are the
 *	major and minor of the device.
 *	When cu terminates, for whatever reason, cleanup() must be
 *	called to "release" the device, and clean up entries from
 *	the locks directory.  Cu runs with uucp ownership, and thus provides
 *	extra insurance that lock files will not be left around.
 */

#include "uucp.h"
#include <locale.h>
#include <stropts.h>

#define	MID	BUFSIZ/2	/* mnemonic */
#define	RUB	'\177'		/* mnemonic */
#define	XON	'\21'		/* mnemonic */
#define	XOFF	'\23'		/* mnemonic */
#define	TTYIN	0		/* mnemonic */
#define	TTYOUT	1		/* mnemonic */
#define	TTYERR	2		/* mnemonic */
#define	HUNGUP  2
#define	YES	1		/* mnemonic */
#define	NO	0		/* mnemonic */
#define	IOERR	4		/* exit code */
#define	MAXPATH	100
#define	NPL	50

int Sflag=0;
int Cn;				/*fd for remote comm line */
jmp_buf Sjbuf;			/*needed by uucp routines*/

/*	io buffering	*/
/*	Wiobuf contains, in effect, 3 write buffers (to remote, to tty	*/
/*	stdout, and to tty stderr) and Riobuf contains 2 read buffers	*/
/*	(from remote, from tty).  [WR]IOFD decides which one to use.	*/
/*	[RW]iop holds current position in each.				*/
#define	WIOFD(fd)	(fd == TTYOUT ? 0 : (fd == Cn ? 1 : 2))
#define	RIOFD(fd)	(fd == TTYIN ? 0 : 1)
#define	WMASK(fd)	(fd == Cn ? line_mask : term_mask)
#define	RMASK(fd)	(fd == Cn ? line_mask : term_mask)
#define	WRIOBSZ 256
static char Riobuf[2*WRIOBSZ];
static char Wiobuf[3*WRIOBSZ];
static int Riocnt[2] = {0, 0};
static char *Riop[2];
static char *Wiop[3];

extern int optind;		/* variable in getopt() */

extern char
	*optarg;

static struct call Cucall;	/* call structure for altconn()	*/

static int Saved_tty;		/* was TCGETAW of _Tv0 successful?	*/
static int Saved_termios;	/* was TCGETSW of _Tv0 successful?	*/
static struct termio _Tv, _Tv0;	/* for saving, changing TTY atributes */
static struct termios _Tv0s;	/* for saving, changing TTY atributes */
static struct termio _Lv;	/* attributes for the line to remote */
static struct termios _Lvs;	/* attributes for the line to remote */
static char prompt[BUFSIZ]= "[";
static struct utsname utsn;
static int command_line_hups = 0;

static char filename[BUFSIZ] = "/dev/null";

static char
	_Cxc,			/* place into which we do character io*/
	_Tintr,			/* current input INTR */
	_Tquit,			/* current input QUIT */
	_Terase,		/* current input ERASE */
	_Tkill,			/* current input KILL */
	_Teol,			/* current secondary input EOL */
	_Myeof,			/* current input EOF */
	term_mask,		/* mask value for local terminal */
	line_mask;		/* mask value for remote line */
				/* either '0177' or '0377' */

int
	Echoe,			/* save users ECHOE bit */
	Echok,			/* save users ECHOK bit */
	Intrupt=NO,		/* interrupt indicator */
	Ifc=YES,		/* NO means remote can't XON/XOFF */
	Ofc=YES,		/* NO means local can't XON/XOFF */
	Rtn_code=0,		/* default return code */
	Divert=NO,		/* don't allow unsolicited redirection */
	OldStyle=NO,		/* don't handle old '~>:filename' syntax */
				/* this will be mandatory in SVR4.1 */
	Takeflag=NO,		/* indicates a ~%take is in progress */
	Dologin=NO,		/* go through the login chat sequence */
	Docmd=NO;		/* execute command instead of interactive cu */

EXTERN int			/* These are initialized in line.c */
	Terminal,		/* flag; remote is a terminal */
	Oddflag,		/* flag- odd parity option*/
	Evenflag,		/* flag- even parity option*/
	Duplex,			/* Unix= full duplex=YES; half = NO */
	term_8bit,		/* is terminal set for 8 bit processing */
	line_8bit;		/* is line set for 8 bit processing */

EXTERN int clear_hup();

pid_t
	Child,			/* pid for receive process */
	Shell;			/* pid for escape process */

static pid_t
	dofork();		/* fork and return pid */

static int
	r_char(),		/* local io routine */
	w_char(),		/* local io routine */
	wioflsh();

static void
	_onintrpt(),		/* interrupt routines */
	_rcvdead(),
	_quit(),
	_bye();

extern void	cleanup();
extern void	tdmp();
extern int conn(), altconn(), transmit(), tilda();

static void
	recfork(),
	sysname(),
	blckcnt(),
	_flush(),
	_shell(),
	_dopercen(),
	_receive(),
	_mode(),
	_w_str();

extern char *Myline;	/* flag to force the requested line to be used  */
extern char *Mytype;	/* flag to force requested line type to be used
			 * rddev() will compare the string to the D_TYPE
			 * (first) field of the Devices record and skip any
			 * records where they are not equal. Mytype is set
			 * to point to the argument of the -c option from
			 * the command line. */
static char *P_USAGE= "Usage: %s [-dhtnLC] [-c device] [-s speed] [-l line] [-b 7|8]\n\t[-o | -e] telno | systemname [local-cmd]\n";
static char *P_CON_FAILED = "Connect failed: %s\r\n";
static char *P_Ct_OPEN = "Cannot open: %s\r\n";
static char *P_LINE_GONE = "Remote line gone\r\n";
static char *P_Ct_EXSH = "Can't execute shell\r\n";
static char *P_Ct_DIVERT = "Can't divert to %s\r\n";
static char *P_Ct_UNDIVERT = "Can't end diversion to %s\r\n";
static char *P_Bad_DIVERT = "Won't divert to %s. Unsolicited.\r\n";
static char *P_STARTWITH = "Use `~~' to start line with `~'\r\n";
static char *P_CNTAFTER = "File transmission interrupted after %ld bytes.\r\n";
static char *P_CNTLINES = "%d lines/";
static char *P_CNTCHAR = "%ld characters\r\n";
static char *P_FILEINTR = "File transmission interrupted\r\n";
static char *P_Ct_FK = "Can't fork -- try later\r\n";
static char *P_Ct_SPECIAL = "r\nCan't transmit special character `%#o'\r\n";
static char *P_TOOLONG = "\nLine too long\r\n";
static char *P_IOERR = "r\nIO error\r\n";
static char *P_USECMD = "Use `~$'cmd \r\n";
#ifdef forfutureuse
static char *P_USEPLUSCMD ="Use `~+'cmd \r\n";
#endif
#ifdef u3b
static char *P_NOTERMSTAT = "Can't get terminal status\r\n";
static char *P_3BCONSOLE = "Sorry, you can't cu from a 3B console\r\n";
#endif
static char *P_TELLENGTH = "Telno cannot exceed 58 digits!\r\n";

/***************************************************************
 *	main: get command line args, establish connection, and fork.
 *	Child invokes "receive" to read from remote & write to TTY.
 *	Main line invokes "transmit" to read TTY & write to remote.
 ***************************************************************/

int
main(int argc, char *argv[])
{
    extern void setservice();
    extern int sysaccess();
    char s[MAXPH];
    char *string;
    int i;
    int errflag=0;
    int lflag=0;
    int nflag=0;
    int systemname = 0;
    char vdisable;

    /* Set locale environment variables local definitions */
    (void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it wasn't */
#endif
    (void) textdomain(TEXT_DOMAIN);

    Riop[0] = &Riobuf[0];
    Riop[1] = &Riobuf[WRIOBSZ];
    Wiop[0] = &Wiobuf[0];
    Wiop[1] = &Wiobuf[WRIOBSZ];
    Wiop[2] = &Wiobuf[2*WRIOBSZ];

    Verbose = 1;		/*for uucp callers,  dialers feedback*/
    if ((string = strrchr(argv[0], '/')) != NULL)
	string++;
    else
	string = argv[0];
    if (strlcpy(Progname, string, NAMESIZE) >= NAMESIZE) {
	errno = ENAMETOOLONG;
	perror("cu");
	exit(1);
    }
    setservice(Progname);
    if ( sysaccess(EACCESS_SYSTEMS) != 0 ) {
	(void)fprintf(stderr,
	     gettext("%s: Cannot read Systems files\n"), Progname);
	exit(1);
    }
    if ( sysaccess(EACCESS_DEVICES) != 0 ) {
	(void)fprintf(stderr,
	     gettext("%s: Cannot read Devices files\n"), Progname);
	exit(1);
    }
    if ( sysaccess(EACCESS_DIALERS) != 0 ) {
	(void)fprintf(stderr,
	    gettext("%s: Cannot read Dialers files\n"), Progname);
	exit(1);
    }

    Cucall.speed = "Any";	/*default speed*/
    Cucall.line = CNULL;
    Cucall.telno = CNULL;
    Cucall.type = CNULL;

/*Flags for -h, -t, -e, and -o options set here; corresponding line attributes*/
/*are set in fixline() in culine.c before remote connection is made	   */

    while((i = getopt(argc, argv, "dhteons:l:c:b:LCH")) != EOF)
	switch(i) {
	    case 'd':
		Debug = 9; /*turns on uucp debugging-level 9*/
		break;
	    case 'h':
		Duplex  = NO;
		Ifc = NO;
		Ofc = NO;
		break;
	    case 't':
		Terminal = YES;
		break;
	    case 'e':
		if ( Oddflag ) {
		    (void)fprintf(stderr,
			gettext("%s: Cannot have both even and odd parity\n"),
			argv[0]);
		    exit(1);
		}
		Evenflag = 1;
		break;
	    case 'o':
		if ( Evenflag ) {
		    (void)fprintf(stderr,
			gettext("%s: Cannot have both even and odd parity\n"),
			argv[0]);
		    exit(1);
		}
		Oddflag = 1;
		break;
	    case 'n':
		nflag++;
		printf(gettext("Please enter the number: "));
		/* Read line from stdin, remove trailing newline, if any */
		if (fgets(s, sizeof(s), stdin) != NULL &&
			strchr(s, '\n') != NULL)
		   s[strlen(s)-1] = '\0';
		break;
	    case 's':
		Sflag++;
		Cucall.speed = optarg;
		break;
	    case 'l':
		lflag++;
		Cucall.line = optarg;
		break;
	    case 'c':
		Cucall.type = optarg;
		Mytype = optarg;
		break;
	    case 'b':
		line_8bit = ((*optarg=='7') ? NO : ((*optarg=='8') ? YES : -1));
		if ( line_8bit == -1 ) {
		    (void) fprintf(stderr,
			gettext("%s: b option value must be '7' or '8'\n"),
			argv[0]);
		    exit(1);
		}
		break;
	    case 'L':
		Dologin++;
		break;
	    case 'C':
		Docmd++;
		break;
	    case 'H':
		command_line_hups++;
		break;
	    case '?':
		++errflag;
	}

#ifdef  u3b
    {
    struct stat buff;
    if(fstat(TTYIN, &buff) < 0) {
	VERBOSE(gettext(P_NOTERMSTAT),"");
	exit(1);
    } else if ( (buff.st_mode & S_IFMT) == S_IFCHR && buff.st_rdev == 0 ) {
	VERBOSE(gettext(P_3BCONSOLE),"");
	exit(1);
	}
    }
#endif

    if((optind < argc && optind > 0) || (nflag && optind > 0)) {
	if(nflag)
	    string=s;
	else
	    string = strdup(argv[optind++]);
	Cucall.telno = string;
	if ( strlen(string) != strspn(string, "0123456789=-*#") ) {
	    /* if it's not a legitimate telno, then it should be a systemname */
	    if ( nflag ) {
		(void)fprintf(stderr, gettext("%s: Bad phone number %s\n"),
				argv[0], string);
		(void) fprintf(stderr, gettext("Phone numbers may contain "
		    "only the digits 0 through 9 and the special\n"
		    "characters =, -, * and #.\n"));
		exit(1);
	    }
	    systemname++;
	}
    } else
	if(Cucall.line == CNULL)   /*if none of above, must be direct */
	    ++errflag;

    if(errflag) {
	VERBOSE(gettext(P_USAGE), argv[0]);
	exit(1);
    }

    if ((Cucall.telno != CNULL) &&
		(strlen(Cucall.telno) >= (size_t)(MAXPH - 1))) {
	VERBOSE(gettext(P_TELLENGTH),"");
	exit(0);
    }

    /* save initial tty state */
    if (!(Saved_termios = ( ioctl(TTYIN, TCGETS, &_Tv0s) >= 0 ))) {
	Saved_tty = ( ioctl(TTYIN, TCGETA, &_Tv0) == 0 );
	_Tv0s.c_lflag = _Tv0.c_lflag;
	_Tv0s.c_oflag = _Tv0.c_oflag;
	_Tv0s.c_iflag = _Tv0.c_iflag;
	_Tv0s.c_cflag = _Tv0.c_cflag;
	for(i = 0; i < NCC; i++)
		_Tv0s.c_cc[i] = _Tv0.c_cc[i];
    }

    if (Saved_termios || Saved_tty) {
	char *p;

	/*
	 * We consider the terminal to be in 8 bit mode only if cs8 is set,
	 * istrip is not set, and we're not in the "C" locale.  The "C"
	 * locale is by definition 7 bit only.  This provides reasonable
	 * compatibility when running in the "C" locale (currently the default)
	 * and connecting to other systems, which are most often 7 bit systems.
	 */
	term_8bit = ( (_Tv0s.c_cflag & CS8) && !(_Tv0s.c_iflag & ISTRIP) &&
	  ((p = setlocale(LC_CTYPE, NULL)) != NULL) && (strcmp(p, "C") != 0) );
	if ( !Oddflag && !Evenflag )
	    if (_Tv0s.c_cflag & PARENB)
		if (_Tv0s.c_cflag & PARODD)
		    Oddflag = 1;
		else
		    Evenflag = 1;
    }

    if (line_8bit == -1)
	line_8bit = term_8bit;

    term_mask = ( term_8bit ? 0377 : 0177 );
    line_mask = ( line_8bit ? 0377 : 0177 );

    /* if not set, use the POSIX disabled designation */
#ifdef _POSIX_VDISABLE
    vdisable = _POSIX_VDISABLE;
#else
    vdisable = fpathconf(TTYIN, _PC_VDISABLE);
#endif
    _Tintr = _Tv0s.c_cc[VINTR] ? _Tv0s.c_cc[VINTR] : vdisable;
    _Tquit = _Tv0s.c_cc[VQUIT] ? _Tv0s.c_cc[VQUIT] : vdisable;
    _Terase = _Tv0s.c_cc[VERASE] ? _Tv0s.c_cc[VERASE] : vdisable;
    _Tkill = _Tv0s.c_cc[VKILL] ? _Tv0s.c_cc[VKILL] : vdisable;
    _Teol = _Tv0s.c_cc[VEOL] ? _Tv0s.c_cc[VEOL] : vdisable;
    _Myeof = _Tv0s.c_cc[VEOF] ? _Tv0s.c_cc[VEOF] : '\04';
    Echoe = _Tv0s.c_lflag & ECHOE;
    Echok = _Tv0s.c_lflag & ECHOK;

    (void)signal(SIGHUP, cleanup);
    (void)signal(SIGQUIT, cleanup);
    (void)signal(SIGINT, cleanup);

/* place call to system; if "cu systemname", use conn() from uucp
   directly.  Otherwise, use altconn() which dummies in the
   Systems file line.
*/

    if(systemname) {
	if ( lflag )
	    (void)fprintf(stderr,
	        gettext("%s: Warning: -l flag ignored when system name used\n"),
	        argv[0]);
	if ( Sflag )
	    (void)fprintf(stderr,
	        gettext("%s: Warning: -s flag ignored when system name used\n"),
	        argv[0]);
	Cn = conn(string);
	if ( (Cn < 0) && (Cucall.type != CNULL) )
	    Cn = altconn(&Cucall);
    } else
	Cn = altconn(&Cucall);

    if(Cn < 0) {
	VERBOSE(gettext(P_CON_FAILED),UERRORTEXT);
	cleanup(-Cn);
    } else {
	struct stat Cnsbuf;
	if ( fstat(Cn, &Cnsbuf) == 0 )
	    Dev_mode = Cnsbuf.st_mode;
	else
	    Dev_mode = R_DEVICEMODE;
	fchmod(Cn, M_DEVICEMODE);
    }

    if ((Docmd) && (argv[optind] == NULL)) {
        (void) fprintf(stderr,gettext("cu: local cmd is required, -C is ignored.\n"));
        VERBOSE(gettext(P_USAGE), argv[0]);
        Docmd=NO;
    }

    if (!Docmd) {
	Euid = geteuid();
	if((setuid(getuid()) < 0) || (setgid(getgid()) < 0)) {
	    VERBOSE("Unable to setuid/gid\n%s", "");
	    cleanup(101);
	}
    }

    if(Debug)
	tdmp(Cn);

    /* At this point succeeded in getting an open communication line	*/
    /* Conn() takes care of closing the Systems file			*/

    if (!Docmd) {
	(void)signal(SIGINT,_onintrpt);
	_mode(1);			/* put terminal in `raw' mode */
	VERBOSE("Connected\007\r\n%s", "");	/*bell!*/

	/* must catch signals before fork.  if not and if _receive()	*/
	/* fails in just the right (wrong?) way, _rcvdead() can be	*/
	/* called and do "kill(getppid(),SIGUSR1);" before parent	*/
	/* has done calls to signal() after recfork().			*/
	(void)signal(SIGUSR1, _bye);
	(void)signal(SIGHUP, cleanup);
	(void)signal(SIGQUIT, _onintrpt);

	sysname(&prompt[1]);	/* set up system name prompt */
	(void) strcat(prompt, "]");

	recfork();		/* checks for child == 0 */

	if(Child > 0) {
	    /*
	     * Because the child counts hangups for the -H flag,
	     * and because we fork a new child when doing (e.g.)
	     * ~%take, we assume the first child we fork has
	     * processed all the hangups and we reset the count here.
	     * We really should pass the remaining count back from
	     * the child to the parent when we kill the child.
	     */
	    command_line_hups = 0;
	    Rtn_code = transmit();
	    _quit(Rtn_code);
	    /*NOTREACHED*/
	}
    } else {
	/*
	 * Fork a child to run the specified command,
	 * wait for it to finish, and clean up.
	 */
	Child = dofork();
	if (Child == 0) {
	    close(0);
	    close(1);
	    dup(Cn);
	    dup(Cn);
	    close(Cn);
	    setgid(getgid());
	    setuid(getuid());
	    execvp(argv[optind], &argv[optind]);
	    exit(-1);
	    /* NOTREACHED */
	}
	wait(0);
	/* XXX - should return wait status as our exit code */
    }
    cleanup(Cn);
    /*NOTREACHED*/
	return (0);
}

/*
 *	Kill the present child, if it exists, then fork a new one.
 */

static void
recfork(void)
{
    int ret, status;
    if (Child) {
	kill(Child, SIGKILL);
	while ( (ret = wait(&status)) != Child )
	    if (ret == -1 && errno != EINTR)
		break;
    }
    Child = dofork();
    if(Child == 0) {
	(void)signal(SIGUSR1, SIG_DFL);
	(void)signal(SIGHUP, _rcvdead);
	(void)signal(SIGQUIT, SIG_IGN);
	(void)signal(SIGINT, SIG_IGN);

	_receive();	/* This should run until killed */
	/*NOTREACHED*/
    }
    return;
}

/***************************************************************
 *	transmit: copy stdin to remote fd, except:
 *	~.	terminate
 *	~!	local login-style shell
 *	~!cmd	execute cmd locally
 *	~$proc	execute proc locally, send output to line
 *	~%cmd	execute builtin cmd (put, take, or break)
 ****************************************************************/
#ifdef forfutureuse
 /*****************************************************************
  *	~+proc	execute locally, with stdout to and stdin from line.
  ******************************************************************/
#endif

int
transmit(void)
{
    char b[BUFSIZ];
    char *p;
    int escape;
    int id = 0;  /* flag for systemname prompt on tilda escape */

    CDEBUG(4,"transmit started\n\r%s", "");

    /* In main loop, always waiting to read characters from	*/
    /* keyboard; writes characters to remote, or to TTYOUT	*/
    /* on a tilda escape					*/

    for (;;) {
	p = b;
	while(r_char(TTYIN) == YES) {
	    if(p == b)  	/* Escape on leading  ~    */
		escape = (_Cxc == '~');
	    if(p == b+1)   	/* But not on leading ~~   */
		escape &= (_Cxc != '~');
	    if(escape) {
		 if(_Cxc == '\n' || _Cxc == '\r' || _Cxc == _Teol) {
		    *p = '\0';
		    if(tilda(b+1) == YES)
			return(0);
		    id = 0;
		    break;
		}
		if(_Cxc == _Tintr || _Cxc == _Tkill || _Cxc == _Tquit ||
			(Intrupt && _Cxc == '\0')) {
		    if(_Cxc == _Tkill) {
			if(Echok)
			    VERBOSE("\r\n%s", "");
		    } else {
			_Cxc = '\r';
			if( w_char(Cn) == NO) {
			    VERBOSE(gettext(P_LINE_GONE),"");
			    return(IOERR);
			}
			id=0;
		    }
		    break;
		}
		if((p == b+1) && (_Cxc != _Terase) && (!id)) {
		    id = 1;
		    VERBOSE("%s", prompt);
		}
		if(_Cxc == _Terase) {
		    p = (--p < b)? b:p;
		    if(p > b)
			if(Echoe) {
			    VERBOSE("\b \b%s", "");
			} else
			    (void)w_char(TTYOUT);
		} else {
		    (void)w_char(TTYOUT);
		    if(p-b < BUFSIZ)
			*p++ = _Cxc;
		    else {
			VERBOSE(gettext(P_TOOLONG),"");
			break;
		    }
		}
    /*not a tilda escape command*/
	    } else {
		if(Intrupt && _Cxc == '\0') {
		    CDEBUG(4,"got break in transmit\n\r%s", "");
		    Intrupt = NO;
		    (*genbrk)(Cn);
		    _flush();
		    break;
		}
		if(w_char(Cn) == NO) {
		    VERBOSE(gettext(P_LINE_GONE),"");
		    return(IOERR);
		}
		if(Duplex == NO) {
		    if((w_char(TTYERR) == NO) || (wioflsh(TTYERR) == NO))
			return(IOERR);
		}
		if ((_Cxc == _Tintr) || (_Cxc == _Tquit) ||
		     ( (p==b) && (_Cxc == _Myeof) ) ) {
		    CDEBUG(4,"got a tintr\n\r%s", "");
		    _flush();
		    break;
		}
		if(_Cxc == '\n' || _Cxc == '\r' ||
		    _Cxc == _Teol || _Cxc == _Tkill) {
		    id=0;
		    Takeflag = NO;
		    break;
		}
		p = (char*)0;
	    }
	}
    }
}

/***************************************************************
 *	routine to halt input from remote and flush buffers
 ***************************************************************/
static void
_flush(void)
{
    (void)ioctl(TTYOUT, TCXONC, 0);	/* stop tty output */
    (void)ioctl(Cn, TCFLSH, 0);		/* flush remote input */
    (void)ioctl(TTYOUT, TCFLSH, 1);	/* flush tty output */
    (void)ioctl(TTYOUT, TCXONC, 1);	/* restart tty output */
    if(Takeflag == NO) {
	return;		/* didn't interupt file transmission */
    }
    VERBOSE(gettext(P_FILEINTR),"");
    (void)sleep(3);
    _w_str("echo '\n~>\n';mesg y;stty echo\n");
    Takeflag = NO;
    return;
}

/**************************************************************
 *	command interpreter for escape lines
 **************************************************************/
int
tilda(cmd)
char	*cmd;
{

    VERBOSE("\r\n%s", "");
    CDEBUG(4,"call tilda(%s)\r\n", cmd);

    switch(cmd[0]) {
	case CSUSP:
	case CDSUSP:
	    _mode(0);
	    kill(cmd[0] == CDSUSP ? getpid() : (pid_t) 0, SIGTSTP);
	    _mode(1);
	    break;
	case '.':
	    if(Cucall.telno == CNULL)
		if(cmd[1] != '.') {
		    _w_str("\04\04\04\04\04");
		    if (Child)
			kill(Child, SIGKILL);
		    if (ioctl (Cn, TCGETS, &_Lvs) < 0) {
		    	(void) ioctl (Cn, TCGETA, &_Lv);
		    	/* speed to zero for hangup */
		    	_Lv.c_cflag = 0;
		    	(void) ioctl (Cn, TCSETAW, &_Lv);
		    } else {
		    	/* speed to zero for hangup */
			_Lvs.c_cflag &= 0xffff0000;
			cfsetospeed(&_Lvs, B0);
		    	(void) ioctl (Cn, TCSETSW, &_Lvs);
		    }
		    (void) sleep (2);
		}
	    return(YES);
	case '!':
	    _shell(cmd);	/* local shell */
	    VERBOSE("\r%c\r\n", *cmd);
	    VERBOSE("(continue)%s", "");
	    break;
	case '$':
	    if(cmd[1] == '\0') {
		VERBOSE(gettext(P_USECMD),"");
		VERBOSE("(continue)%s", "");
	    } else {
		_shell(cmd);	/*Local shell  */
		VERBOSE("\r%c\r\n", *cmd);
	    }
	    break;

#ifdef forfutureuse
	case '+':
	    if(cmd[1] == '\0') {
		VERBOSE(gettext(P_USEPLUSCMD), "");
		VERBOSE("(continue)%s", "");
	    } else {
		if (*cmd == '+')
			  /* must suspend receive to give*/
			  /*remote out to stdin of cmd */
		    kill(Child, SIGKILL);
		    _shell(cmd);	/* Local shell */
		if (*cmd == '+')
		    recfork();
		VERBOSE("\r%c\r\n", *cmd);
	    }
	    break;
#endif
	case '%':
	    _dopercen(++cmd);
	    break;

	case 't':
	    tdmp(TTYIN);
	    VERBOSE("(continue)%s", "");
	    break;
	case 'l':
	    tdmp(Cn);
	    VERBOSE("(continue)%s", "");
	    break;

	default:
	    VERBOSE(gettext(P_STARTWITH),"");
	    VERBOSE("(continue)%s", "");
	    break;
    }
    return(NO);
}

/***************************************************************
 *	The routine "shell" takes an argument starting with
 *	either "!" or "$", and terminated with '\0'.
 *	If $arg, arg is the name of a local shell file which
 *	is executed and its output is passed to the remote.
 *	If !arg, we escape to a local shell to execute arg
 *	with output to TTY, and if arg is null, escape to
 *	a local shell and blind the remote line.  In either
 *	case, '^D' will kill the escape status.
 **************************************************************/

#ifdef forfutureuse
/***************************************************************
 *	Another argument to the routine "shell" may be +.  If +arg,
 *	arg is the name of a local shell file which is executed with
 *	stdin from and stdout to the remote.
 **************************************************************/
#endif

static void
_shell(char *str)
{
    pid_t	fk, w_ret;
    void	(*xx)(), (*yy)();

    CDEBUG(4,"call _shell(%s)\r\n", str);
    fk = dofork();
    if(fk < 0)
	return;
    Shell = fk;
    _mode(0);	/* restore normal tty attributes */
    xx = signal(SIGINT, SIG_IGN);
    yy = signal(SIGQUIT, SIG_IGN);
    if(fk == 0) {
	char *shell;

	if( (shell = getenv("SHELL")) == NULL)
	    /* use default if user's shell is not set */
	    shell = SHELL;
	(void)close(TTYOUT);

	/***********************************************
	 * Hook-up our "standard output"
	 * to either the tty for '!' or the line
	 * for '$'  as appropriate
	 ***********************************************/
#ifdef forfutureuse

	/************************************************
	 * Or to the line for '+'.
	 **********************************************/
#endif

	(void)fcntl((*str == '!')? TTYERR:Cn,F_DUPFD,TTYOUT);

#ifdef forfutureuse
	/*************************************************
	 * Hook-up "standard input" to the line for '+'.
	 * **********************************************/
	if (*str == '+') {
	    (void)close(TTYIN);
	    (void)fcntl(Cn,F_DUPFD,TTYIN);
	    }
#endif

	/***********************************************
	 * Hook-up our "standard input"
	 * to the tty for '!' and '$'.
	 ***********************************************/

	(void)close(Cn);   	/*parent still has Cn*/
	(void)signal(SIGINT, SIG_DFL);
	(void)signal(SIGHUP, SIG_DFL);
	(void)signal(SIGQUIT, SIG_DFL);
	(void)signal(SIGUSR1, SIG_DFL);
	if(*++str == '\0')
	    (void)execl(shell,shell,(char*) 0,(char*) 0,(char *) 0);
	else
	    (void)execl(shell,"sh","-c",str,(char *) 0);
	VERBOSE(gettext(P_Ct_EXSH),"");
	exit(0);
    }
    while ((w_ret = wait((int*)0)) != fk)
	if (w_ret == -1 && errno != EINTR)
	    break;
    Shell = 0;
    (void)signal(SIGINT, xx);
    (void)signal(SIGQUIT, yy);
    _mode(1);
    return;
}


/***************************************************************
 *	This function implements the 'put', 'take', 'break',
 *	'ifc' (aliased to nostop) and 'ofc' (aliased to noostop)
 *	commands which are internal to cu.
 ***************************************************************/

static void
_dopercen(char *cmd)
{
    char	*arg[5];
    char	*getpath;
    char	mypath[MAXPATH];
    int	narg;

    blckcnt((long)(-1));

    CDEBUG(4,"call _dopercen(\"%s\")\r\n", cmd);

    arg[narg=0] = strtok(cmd, " \t\n");

    /* following loop breaks out the command and args */
    while((arg[++narg] = strtok((char*) NULL, " \t\n")) != NULL) {
	if(narg < 4)
	    continue;
	else
	    break;
    }

    /* ~%take file option */
    if(EQUALS(arg[0], "take")) {
	if(narg < 2 || narg > 3) {
	    VERBOSE("usage: ~%%take from [to]\r\n%s", "");
	    VERBOSE("(continue)%s", "");
	    return;
	}
	if(narg == 2)
	    arg[2] = arg[1];
	(void) strcpy(filename, arg[2]);
	recfork();	/* fork so child (receive) knows filename */

	/*
	 * be sure that the remote file (arg[1]) exists before
	 * you try to take it.   otherwise, the error message from
	 * cat will wind up in the local file (arg[2])
	 *
	 * what we're doing is:
	 *	stty -echo; \
	 *	if test -r arg1
	 *	then (echo '~[local]'>arg2; cat arg1; echo '~[local]'>)
	 *	else echo can't open: arg1
	 *	fi; \
	 *	stty echo
	 *
	 */
	_w_str("stty -echo;if test -r ");
	_w_str(arg[1]);
	_w_str("; then (echo '~");
	_w_str(prompt);
	_w_str(">'");
	_w_str(arg[2]);
	_w_str(";cat ");
	_w_str(arg[1]);
	_w_str(";echo '~");
	_w_str(prompt);
	_w_str(">'); else echo cant\\'t open: ");
	_w_str(arg[1]);
	_w_str("; fi;stty echo\n");
	Takeflag = YES;
	return;
    }
    /* ~%put file option*/
    if(EQUALS(arg[0], "put")) {
	FILE	*file;
	char	ch, buf[BUFSIZ], spec[NCC+1], *b, *p, *q;
	int	i, j, len, tc=0, lines=0;
	long	chars=0L;

	if(narg < 2 || narg > 3) {
	    VERBOSE("usage: ~%%put from [to]\r\n%s", "");
	    VERBOSE("(continue)%s", "");
	    return;
	}
	if(narg == 2)
	    arg[2] = arg[1];

	if((file = fopen(arg[1], "r")) == NULL) {
	    VERBOSE(gettext(P_Ct_OPEN), arg[1]);
	    VERBOSE("(continue)%s", "");
	    return;
	}
	/*
	 * if cannot write into file on remote machine, write into
	 * /dev/null
	 *
	 * what we're doing is:
	 *	stty -echo
	 *	(cat - > arg2) || cat - > /dev/null
	 *	stty echo
	 */
	_w_str("stty -echo;(cat - >");
	_w_str(arg[2]);
	_w_str(")||cat - >/dev/null;stty echo\n");
	Intrupt = NO;
	for(i=0,j=0; i < NCC; ++i)
	    if((ch=_Tv0s.c_cc[i]) != '\0')
		spec[j++] = ch;
	spec[j] = '\0';
	_mode(2);	/*accept interrupts from keyboard*/
	(void)sleep(5);	/*hope that w_str info digested*/

	/* Read characters line by line into buf to write to	*/
	/* remote with character and line count for blckcnt	*/
	while(Intrupt == NO &&
		fgets(b= &buf[MID],MID,file) != NULL) {
	    /* worse case is each char must be escaped*/
	    len = strlen(b);
	    chars += len;		/* character count */
	    p = b;
	    while(q = strpbrk(p, spec)) {
		if(*q == _Tintr || *q == _Tquit || *q == _Teol) {
		    VERBOSE(gettext(P_Ct_SPECIAL), *q);
		    (void)strcpy(q, q+1);
		    Intrupt = YES;
		} else {
		    b = strncpy(b-1, b, q-b);
		    *(q-1) = '\\';
		}
		p = q+1;
	    }
	    if((tc += len) >= MID) {
		(void)sleep(1);
		tc = len;
	    }
	    if(write(Cn, b, (unsigned)strlen(b)) < 0) {
		VERBOSE(gettext(P_IOERR),"");
		Intrupt = YES;
		break;
	    }
	    ++lines;		/* line count */
	    blckcnt((long)chars);
	}
	_mode(1);
	blckcnt((long)(-2));		/* close */
	(void)fclose(file);
	if(Intrupt == YES) {
	    Intrupt = NO;
	    _w_str("\n");
	    VERBOSE(gettext(P_CNTAFTER), ++chars);
	} else {
	    VERBOSE(gettext(P_CNTLINES), lines);
	    VERBOSE(gettext(P_CNTCHAR),chars);
	}
	(void)sleep(3);
	_w_str("\04");
	return;
    }

	/*  ~%b or ~%break  */
    if(EQUALS(arg[0], "b") || EQUALS(arg[0], "break")) {
	(*genbrk)(Cn);
	return;
    }
	/*  ~%d or ~%debug toggle  */
    if(EQUALS(arg[0], "d") || EQUALS(arg[0], "debug")) {
	if(Debug == 0)
	    Debug = 9;
	else
	    Debug = 0;
	VERBOSE("(continue)%s", "");
	return;
    }
	/*  ~%[ifc|nostop]  toggles start/stop input control  */
    if( EQUALS(arg[0], "ifc") || EQUALS(arg[0], "nostop") ) {
	(void)ioctl(Cn, TCGETA, &_Tv);
	Ifc = !Ifc;
	if(Ifc == YES)
	    _Tv.c_iflag |= IXOFF;
	else
	    _Tv.c_iflag &= ~IXOFF;
	(void)ioctl(Cn, TCSETAW, &_Tv);
	_mode(1);
	VERBOSE("(ifc %s)", (Ifc ? "enabled" : "disabled"));
	VERBOSE("(continue)%s", "");
	return;
    }
	/*  ~%[ofc|noostop]  toggles start/stop output control  */
    if( EQUALS(arg[0], "ofc") || EQUALS(arg[0], "noostop") ) {
	(void)ioctl(Cn, TCGETA, &_Tv);
	Ofc = !Ofc;
	if(Ofc == YES)
	    _Tv.c_iflag |= IXON;
	else
	    _Tv.c_iflag &= ~IXON;
	(void)ioctl(Cn, TCSETAW, &_Tv);
	_mode(1);
	VERBOSE("(ofc %s)", (Ofc ? "enabled" : "disabled"));
	VERBOSE("(continue)%s", "");
	return;
    }
	/*  ~%divert toggles unsolicited redirection security */
    if( EQUALS(arg[0], "divert") ) {
	Divert = !Divert;
	recfork();	/* fork a new child so it knows about change */
	VERBOSE("(unsolicited diversion %s)", (Divert ? "enabled" : "disabled"));
	VERBOSE("(continue)%s", "");
	return;
    }
	/*  ~%old toggles recognition of old-style '~>:filename' */
    if( EQUALS(arg[0], "old") ) {
	OldStyle = !OldStyle;
	recfork();	/* fork a new child so it knows about change */
	VERBOSE("(old-style diversion %s)", (OldStyle ? "enabled" : "disabled"));
	VERBOSE("(continue)%s", "");
	return;
    }
	/* Change local current directory */
    if(EQUALS(arg[0], "cd")) {
	if (narg < 2) {
	    getpath = getenv("HOME");
	    strlcpy(mypath, getpath, sizeof (mypath));
	    if(chdir(mypath) < 0) {
		VERBOSE("Cannot change to %s\r\n", mypath);
		VERBOSE("(continue)%s", "");
		return;
	    }
	} else if (chdir(arg[1]) < 0) {
	    VERBOSE("Cannot change to %s\r\n", arg[1]);
	    VERBOSE("(continue)%s", "");
	    return;
	}
	recfork();	/* fork a new child so it knows about change */
	VERBOSE("(continue)%s", "");
	return;
    }

   if (arg[0] == (char *) NULL)
       arg[0] = "";

    VERBOSE("~%%%s unknown to cu\r\n", arg[0]);
    VERBOSE("(continue)%s", "");
    return;
}

/***************************************************************
 *	receive: read from remote line, write to fd=1 (TTYOUT)
 *	catch:
 *	~>[>]:file
 *	.
 *	. stuff for file
 *	.
 *	~>	(ends diversion)
 ***************************************************************/

static void
_receive(void)
{
    int silent = NO, file = -1;
    char *p;
    int	tic;
    int for_me = NO;
    char	b[BUFSIZ];
    char	*b_p;
    long	count;
    int		line_ok = 1, rval;

    CDEBUG(4,"_receive started\r\n%s", "");

    b[0] = '\0';
    b_p = p = b;

    while(line_ok) {
	rval = r_char(Cn);
	if (rval == NO) {
	    line_ok = 0;
	    continue;
	}
	if (rval == HUNGUP) {
	    if (command_line_hups > 0) {
		CDEBUG(4, "Ignoring device hangup\n%s", "");
		command_line_hups--;
		(void) setuid(Euid);	/* reacquire privileges */
		if (clear_hup(Cn) != SUCCESS) {
		    DEBUG(4, "Unable to clear hup on device\n%s", "");
		    line_ok = 0;
		}
		(void) setuid(getuid());  /* relinquish privileges */
	    } else
		line_ok = 0;
	    continue;
	}

	if(silent == NO)    /* ie., if not redirecting from screen */
	    if(w_char(TTYOUT) == NO)
		_rcvdead(IOERR);    /* this will exit */
	/* remove CR's and fill inserted by remote */
	if(_Cxc == '\0' || _Cxc == RUB || _Cxc == '\r')
	    continue;
	*p++ = _Cxc;
	if(_Cxc != '\n' && (p-b) < BUFSIZ)
	    continue;
	/* ****************************************** */
	/* This code deals with ~%take file diversion */
	/* ****************************************** */
	if (b[0] == '~') {
	    int    append;

	    if (EQUALSN(&b[1],prompt,strlen(prompt))) {
		b_p = b + 1 + strlen(prompt);
		for_me = YES;
	    } else {
		b_p = b + 1;
		for_me = NO;
	    }
	    if ( (for_me || OldStyle) && (*b_p == '>') ) {
		/* This is an acceptable '~[uname]>' line */
		b_p++;
		if ( (*b_p == '\n') && (silent == YES) ) {
		    /* end of diversion */
		    *b_p = '\0';
		    (void) strcpy(filename, "/dev/null");
		    if ( file >= 0 && close(file) ) {
			VERBOSE(gettext(P_Ct_UNDIVERT), b_p);
			perror(gettext("cu: close failed"));
			VERBOSE("%s","\r");
		    }
		    silent = NO;
		    blckcnt((long)(-2));
		    VERBOSE("%s\r\n", b);
		    VERBOSE(gettext(P_CNTLINES), tic);
		    VERBOSE(gettext(P_CNTCHAR), count);
		    file = -1;
		    p = b;
		    continue;
		} else if (*b_p != '\n') {
		    if ( *b_p == '>' ) {
			append = 1;
			b_p++;
		    }
		    if ( (for_me || (OldStyle && (*b_p == ':'))) && (silent == NO) ) {
			/* terminate filename string */
			*(p-1) = '\0';
			if ( *b_p == ':' )
			    b_p++;
			if ( !EQUALS(filename, b_p) ) {
			    if ( !Divert  || !EQUALS(filename, "/dev/null") ) {
				VERBOSE(gettext(P_Bad_DIVERT), b_p);
				(void) strcpy(filename, "/dev/null");
				append = 1;
			    } else {
				(void) strcpy(filename, b_p);
			    }
			}
			if ( append && ((file=open(filename,O_WRONLY)) >= 0) )
			    (void)lseek(file, 0L, 2);
			else
			    file = creat(filename, PUB_FILEMODE);
			if (file < 0) {
			    VERBOSE(gettext(P_Ct_DIVERT), filename);
			    perror(gettext("cu: open|creat failed"));
			    VERBOSE("%s","\r");
			    (void)sleep(5); /* 10 seemed too long*/
			}
			silent = YES;
			count = tic = 0;
			p = b;
			continue;
		    }
		}
	    }
	}
	/* Regular data, divert if appropriate */
	if ( silent == YES ) {
	    if ( file >= 0)
		(void)write(file, b, (unsigned)(p-b));
	    count += p-b;	/* tally char count */
	    ++tic;		/* tally lines */
	    blckcnt((long)count);
	}
	p = b;
    }
    /*
     * we used to tell of lost carrier here, but now
     * defer to _bye() so that escape processes are
     * not interrupted.
     */
    _rcvdead(IOERR);
    return;
}

/***************************************************************
 *	change the TTY attributes of the users terminal:
 *	0 means restore attributes to pre-cu status.
 *	1 means set `raw' mode for use during cu session.
 *	2 means like 1 but accept interrupts from the keyboard.
 ***************************************************************/
static void
_mode(int arg)
{
    int i;

    CDEBUG(4,"call _mode(%d)\r\n", arg);
    if(arg == 0) {
	if ( Saved_termios )
		(void)ioctl(TTYIN, TCSETSW, &_Tv0s);
	else if ( Saved_tty ) {
		_Tv0.c_lflag = _Tv0s.c_lflag;
		_Tv0.c_oflag = _Tv0s.c_oflag;
		_Tv0.c_iflag = _Tv0s.c_iflag;
		_Tv0.c_cflag = _Tv0s.c_cflag;
		for(i = 0; i < NCC; i++)
			_Tv0.c_cc[i] = _Tv0s.c_cc[i];
		(void)ioctl(TTYIN, TCSETAW, &_Tv0);
	}
    } else {
	(void)ioctl(TTYIN, TCGETA, &_Tv);
	if(arg == 1) {
	    _Tv.c_iflag &= ~(INLCR | ICRNL | IGNCR | IUCLC);
	    if ( !term_8bit )
		_Tv.c_iflag |= ISTRIP;
	    _Tv.c_oflag |= OPOST;
	    _Tv.c_oflag &= ~(OLCUC | ONLCR | OCRNL | ONOCR | ONLRET);
	    _Tv.c_lflag &= ~(ICANON | ISIG | ECHO);
	    if(Ifc == NO)
		_Tv.c_iflag &= ~IXON;
	    else
		_Tv.c_iflag |= IXON;
	    if(Ofc == NO)
		_Tv.c_iflag &= ~IXOFF;
	    else
		_Tv.c_iflag |= IXOFF;
	    if(Terminal) {
		_Tv.c_oflag |= ONLCR;
		_Tv.c_iflag |= ICRNL;
	    }
	    _Tv.c_cc[VEOF] = '\01';
	    _Tv.c_cc[VEOL] = '\0';
	}
	if(arg == 2) {
	    _Tv.c_iflag |= IXON;
	    _Tv.c_lflag |= ISIG;
	}
	(void)ioctl(TTYIN, TCSETAW, &_Tv);
    }
    return;
}


static pid_t
dofork(void)
{
    int i;
    pid_t x;

    for(i = 0; i < 6; ++i) {
	if((x = fork()) >= 0) {
	    return(x);
	}
    }

    if(Debug) perror("dofork");

    VERBOSE(gettext(P_Ct_FK),"");
    return(x);
}

static int
r_char(int fd)
{
    int rtn = 1, rfd;
    char *riobuf;

    /* find starting pos in correct buffer in Riobuf	*/
    rfd = RIOFD(fd);
    riobuf = &Riobuf[rfd*WRIOBSZ];

    if (Riop[rfd] >= &riobuf[Riocnt[rfd]]) {
	/* empty read buffer - refill it	*/

	/*	flush any waiting output	*/
	if ( (wioflsh(Cn) == NO ) || (wioflsh(TTYOUT) == NO) )
	    return(NO);

	while((rtn = read(fd, riobuf, WRIOBSZ)) < 0){
	    if(errno == EINTR) {
		/* onintrpt() called asynchronously before this line */
		if(Intrupt == YES) {
		    /* got a BREAK */
		    _Cxc = '\0';
		    return(YES);
		} else {
		    /*a signal other than interrupt*/
		    /*received during read*/
		    continue;
		}
	    } else {
		CDEBUG(4,"got read error, not EINTR\n\r%s", "");
		break;			/* something wrong */
	    }
	}
	if (rtn > 0) {
	    /* reset current position in buffer	*/
	    /* and count of available chars		*/
	    Riop[rfd] = riobuf;
	    Riocnt[rfd] = rtn;
	}
    }

    if ( rtn > 0 ) {
	_Cxc = *(Riop[rfd]++) & RMASK(fd);	/* mask off appropriate bits */
	return(YES);
    } else if (rtn == 0) {
	_Cxc = '\0';
	return (HUNGUP);
    } else {
	_Cxc = '\0';
	return(NO);
    }
}

static int
w_char(int fd)
{
    int wfd;
    char *wiobuf;

    /* find starting pos in correct buffer in Wiobuf	*/
    wfd = WIOFD(fd);
    wiobuf = &Wiobuf[wfd*WRIOBSZ];

    if (Wiop[wfd] >= &wiobuf[WRIOBSZ]) {
	/* full output buffer - flush it */
	if ( wioflsh(fd) == NO )
	    return(NO);
    }
    *(Wiop[wfd]++) = _Cxc & WMASK(fd);	/* mask off appropriate bits */
    return(YES);
}

/* wioflsh	flush output buffer	*/
static int
wioflsh(int fd)
{
    int wfd;
    char *wiobuf;

    /* find starting pos in correct buffer in Wiobuf	*/
    wfd = WIOFD(fd);
    wiobuf = &Wiobuf[wfd*WRIOBSZ];

    if (Wiop[wfd] > wiobuf) {
	/* there's something in the buffer */
	while(write(fd, wiobuf, (Wiop[wfd] - wiobuf)) < 0) {
	    if(errno == EINTR) {
		if(Intrupt == YES) {
		    VERBOSE("\ncu: Output blocked\r\n%s", "");
		    _quit(IOERR);
		} else
		    continue;	/* alarm went off */
	    } else {
		Wiop[wfd] = wiobuf;
		return(NO);			/* bad news */
	    }
	}
    }
    Wiop[wfd] = wiobuf;
    return(YES);
}


static void
_w_str(char *string)
{
    int len;

    len = strlen(string);
    if ( write(Cn, string, (unsigned)len) != len )
	VERBOSE(gettext(P_LINE_GONE),"");
    return;
}

static void
_onintrpt(int sig __unused)
{
    (void)signal(SIGINT, _onintrpt);
    (void)signal(SIGQUIT, _onintrpt);
    Intrupt = YES;
    return;
}

static void
_rcvdead(int arg)	/* this is executed only in the receive process */
{
    CDEBUG(4,"call _rcvdead(%d)\r\n", arg);
    (void)kill(getppid(), SIGUSR1);
    exit((arg == SIGHUP)? SIGHUP: arg);
    /*NOTREACHED*/
}

static void
_quit(int arg)	/* this is executed only in the parent process */
{
    CDEBUG(4,"call _quit(%d)\r\n", arg);
    (void)kill(Child, SIGKILL);
    _bye(arg);
    /*NOTREACHED*/
}

static void
_bye(int arg)	/* this is executed only in the parent proccess */
{
    int status;
    pid_t obit;

    if ( Shell > 0 )
	while ((obit = wait(&status)) != Shell) {
	    if (obit == -1 && errno != EINTR)
		break;
	    /* _receive (Child) may have ended - check it out */
	    if (obit == Child)
		Child = 0;
	}

    /* give user customary message after escape command returns */
    if (arg == SIGUSR1)
	VERBOSE("\r\nLost Carrier\r\n%s", "");

    CDEBUG(4,"call _bye(%d)\r\n", arg);

    (void)signal(SIGINT, SIG_IGN);
    (void)signal(SIGQUIT, SIG_IGN);
    /* if _receive() ended already, don't wait for it again */
    if ( Child != 0 )
	while ((obit = wait(&status)) != Child)
	    if (obit == -1 && errno != EINTR)
		break;
    VERBOSE("\r\nDisconnected\007\r\n%s", "");
    cleanup((arg == SIGUSR1)? (status >>= 8): arg);
    /*NOTREACHED*/
}



void
cleanup(int code) 	/*this is executed only in the parent process*/
{

    CDEBUG(4,"call cleanup(%d)\r\n", code);

    if (Docmd) {
	if (Child > 0)
	    (void)kill(Child, SIGTERM);
    } else
	(void) setuid(Euid);
    if(Cn > 0) {
	fchmod(Cn, Dev_mode);
	fd_rmlock(Cn);
	(void)close(Cn);
    }


    rmlock((char*) NULL);	/* remove all lock files for this process */
    if (!Docmd)
	_mode(0);
    exit(code);		/* code=negative for signal causing disconnect*/
}



void
tdmp(int arg)
{

    struct termio xv;
    int i;

    VERBOSE("\rdevice status for fd=%d\r\n", arg);
    VERBOSE("F_GETFL=%o,", fcntl(arg, F_GETFL,1));
    if(ioctl(arg, TCGETA, &xv) < 0) {
	char	buf[100];
	i = errno;
	(void)snprintf(buf, sizeof (buf), gettext("\rtdmp for fd=%d"), arg);
	errno = i;
	perror(buf);
	return;
    }
    VERBOSE("iflag=`%o',", xv.c_iflag);
    VERBOSE("oflag=`%o',", xv.c_oflag);
    VERBOSE("cflag=`%o',", xv.c_cflag);
    VERBOSE("lflag=`%o',", xv.c_lflag);
    VERBOSE("line=`%o'\r\n", xv.c_line);
    VERBOSE("cc[0]=`%o',",  xv.c_cc[0]);
    for(i=1; i<8; ++i) {
	VERBOSE("[%d]=", i);
	VERBOSE("`%o',",xv.c_cc[i]);
    }
    VERBOSE("\r\n%s", "");
    return;
}



static void
sysname(char *name)
{

    char *s;

    if(uname(&utsn) < 0)
	s = "Local";
    else
	s = utsn.nodename;

    strcpy(name, s);
    return;
}


static void
blckcnt(long count)
{
    static long lcharcnt = 0;
    long c1, c2;
    int i;
    char c;

    if(count == (long) (-1)) {	/* initialization call */
	lcharcnt = 0;
	return;
    }
    c1 = lcharcnt/BUFSIZ;
    if(count != (long)(-2)) {	/* regular call */
	c2 = count/BUFSIZ;
	for(i = c1; i++ < c2;) {
	    c = '0' + i%10;
	    write(2, &c, 1);
	    if(i%NPL == 0)
		write(2, "\n\r", 2);
	}
	lcharcnt = count;
    } else {
	c2 = (lcharcnt + BUFSIZ -1)/BUFSIZ;
	if(c1 != c2)
	    write(2, "+\n\r", 3);
	else if(c2%NPL != 0)
	    write(2, "\n\r", 2);
	lcharcnt = 0;
    }
    return;
}

void
assert (char *s1 __unused, char *s2 __unused, int i1 __unused,
    char *s3 __unused, int i2 __unused)
{ 		/* for ASSERT in gnamef.c */
}

void
logent (char *s1 __unused, char *s2 __unused)
{ 		/* so we can load ulockf() */
}

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

#include "uucp.h"
#include "log.h"

/*
 * execute commands set up by a uux command,
 * usually from a remote machine - set by uucp.
 */

#ifndef	V7
#define	LOGNAME	"LOGNAME=uucp"
#else
#define	LOGNAME	"USER=uucp"
#endif

#define	C_COMMAND	1
#define	C_FILE		2
#define	BAD_COMMAND	1
#define	BAD_FILE	2
#define	USAGEPREFIX	"Usage:"
#define	USAGE		"[-x DEBUG] [-s SYSTEM]"

char	_Xfile[MAXFULLNAME];
char	_Cmd[2 * BUFSIZ];	/* build up command buffer */
int	_CargType;		/* argument type of next C argument */

static void retosndr(), uucpst();
static int chkFile();
static int doFileChk();
void cleanup(), xprocess();

int
main(argc, argv, envp)
int argc;
char *argv[];
char *envp[];
{
	DIR	 *fp1;
	struct	limits limitval;
	int	ret, maxnumb;
	char	dirname[MAXFULLNAME], lockname[MAXFULLNAME];
	void	onintr();

	/* Set locale environment variables local definitions */
	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it wasn't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	(void) signal(SIGILL, onintr);
	(void) signal(SIGTRAP, onintr);
	(void) signal(SIGIOT, onintr);
	(void) signal(SIGEMT, onintr);
	(void) signal(SIGFPE, onintr);
	(void) signal(SIGBUS, onintr);
	(void) signal(SIGSEGV, onintr);
	(void) signal(SIGSYS, onintr);
	(void) signal(SIGPIPE, onintr);
	(void) signal(SIGTERM, SIG_IGN);

	/* choose LOGFILE */
	(void) strcpy(Logfile, LOGUUXQT);

	/*
	 * get local system name
	 */
	Env = envp;
	Nstat.t_qtime = time((time_t *)0);
	(void) strcpy(Progname, "uuxqt");
	Pchar = 'Q';
	uucpname(Myname);
	Ofn = 1;
	Ifn = 0;
	dirname[0] = dirname[MAXFULLNAME-1] = NULLCHAR;
	while ((ret = getopt(argc, argv, "s:x:")) != EOF) {
		switch (ret) {

		/*
		 * debugging level
		 */
		case 'x':
			Debug = atoi(optarg);
			if (Debug <= 0)
				Debug = 1;
			break;

		case 's':
			/*
			 * fake out uuxqt and use the argument as if
			 * it were the spool directory for the purpose
			 * of determining what subdirectories to search
			 *  EX:	mkdir /tmp/foo; touch /tmp/foo/[baz, gorp]
			 *	uuxqt -s/tmp/foo
			 * this will cause uuxqt to only run on the sub
			 * baz and gorp in the Spool directory.  Trust me.
			 */
			(void) strlcpy(dirname, optarg,
			    (MAXFULLNAME - sizeof (SEQLOCK)));
			break;

		default:
			(void) fprintf(stderr, "%s %s %s\n",
			    gettext(USAGEPREFIX), Progname, gettext(USAGE));
			exit(1);
		}
	}
	if (argc != optind) {
		(void) fprintf(stderr, "%s %s %s\n",
		    gettext(USAGEPREFIX), Progname, gettext(USAGE));
		exit(1);
	}

	DEBUG(4, "\n\n** START **\n%s", "");
	acInit("rexe");
	scInit("rexe");
	if (scanlimit("uuxqt", &limitval) == FAIL) {
	    DEBUG(1, "No limits for uuxqt in %s\n", LIMITS);
	} else {
	    maxnumb = limitval.totalmax;
	    if (maxnumb < 0) {
		DEBUG(4, "Non-positive limit for uuxqt in %s\n", LIMITS);
		DEBUG(1, "No limits for uuxqt\n%s", "");
	    } else {
		DEBUG(4, "Uuxqt limit %d -- ", maxnumb);
		ret = cuantos(X_LOCKPRE, X_LOCKDIR);
		DEBUG(4, "found %d -- ", ret);
		if (maxnumb >= 0 && ret >= maxnumb) {
		    DEBUG(4, "exiting.%s\n", "");
		    exit(0);
		}
		DEBUG(4, "continuing.%s\n", "");
	    }
	}

	/*
	 * determine user who started uuxqt (in principle)
	 */
	strcpy(User, "uucp");	/* in case all else fails (can't happen) */
	Uid = getuid();
	Euid = geteuid();	/* this should be UUCPUID */
	guinfo(Euid, User);

	if (Uid == 0)
		(void) setuid(UUCPUID);

	setuucp(User);
	DEBUG(4, "User - %s\n", User);
	guinfo(Uid, Loginuser);



	DEBUG(4, "process\n%s", "");

	fp1 = opendir(Spool);
	ASSERT(fp1 != NULL, Ct_OPEN, Spool, errno);
	if (dirname[0] != NULLCHAR) {
		/* look for special characters in remote name */
		if (strpbrk(dirname, Shchar) != NULL) {
		    /* ignore naughty name */
		    DEBUG(4, "Bad remote name '%s'", dirname);
		    errent("BAD REMOTE NAME", dirname, 0, __FILE__, __LINE__);
		    closedir(fp1);
		    cleanup(101);
		}


		(void) snprintf(lockname, sizeof (lockname), "%s.%s",
		    X_LOCK, dirname);
		if (mklock(lockname) == SUCCESS) {
			xprocess(dirname);
			rmlock(CNULL);
		}
	} else {
		while (gdirf(fp1, dirname, Spool) == TRUE) {
			if (strpbrk(dirname, Shchar) != NULL) {
				/* skip naughty names */
				errent("BAD REMOTE NAME", dirname, 0,
				    __FILE__, __LINE__);
				continue;
			}
			(void) snprintf(lockname, sizeof (lockname), "%s.%s",
			    X_LOCK, dirname);
			if (mklock(lockname) != SUCCESS)
				continue;
			xprocess(dirname);
			rmlock(CNULL);
		}
	}

	closedir(fp1);
	cleanup(0);
	/* NOTREACHED */
	return (0);
}

void
cleanup(code)
int	code;
{
	rmlock(CNULL);
	exit(code);
}

/*
 * catch signal then cleanup and exit
 */
void
onintr(inter)
int	inter;
{
	char	str[30];
	(void) signal(inter, SIG_IGN);
	(void) sprintf(str, "QSIGNAL %d", inter);
	logent(str, "QCAUGHT");
	acEndexe(cpucycle(), PARTIAL);	/* stop collecting accounting log */
	cleanup(-inter);
}

#define	XCACHESIZE (4096 / (MAXBASENAME + 1))
static char	xcache[XCACHESIZE][MAXBASENAME + 1];	/* cache for X. files */
static int	xcachesize = 0;			/* how many left? */

/*
 * stash an X. file so we can process them sorted first by grade, then by
 * sequence number
 */
static void
xstash(file)
char	*file;
{
	if (xcachesize < XCACHESIZE) {
		DEBUG(4, "stashing %s\n", file);
		(void) strlcpy(xcache[xcachesize++], file, (MAXBASENAME + 1));
	}
}

/*
 * xcompare
 *	comparison routine for for qsort()
 */
static int
xcompare(f1, f2)
const void	*f1, *f2;
{
	/* assumes file name is X.siteG1234 */
	/* use -strcmp() so that xstash is sorted largest first */
	/* pull files out of the stash from largest index to smallest */

	return (-strcmp((char *)f1 + strlen((char *)f1) - 5,
	    (char *)f2 + strlen((char *)f2) - 5));
}

/*
 * xsort
 *	sort the cached X. files,
 *	largest (last) to smallest (next to be processed)
 */
static void
xsort()
{
	DEBUG(4, "xsort:  first was %s\n", xcache[0]);
	qsort(xcache, xcachesize, MAXBASENAME + 1, xcompare);
	DEBUG(4, "xsort:  first is %s\n", xcache[0]);
}

/*
 * xget
 *	return smallest X. file in cache
 *	(hint:  it's the last one in the array)
 */
static int
xget(file)
char	*file;
{
	if (xcachesize > 0) {
		strlcpy(file, xcache[--xcachesize], (MAXBASENAME + 1));
		DEBUG(4, "xget: returning %s\n", file);
		return (1);
	} else {
		/* avoid horror of xcachesize < 0 (impossible, you say?)! */
		xcachesize = 0;
		return (0);
	}
}


/*
 * get a file to execute
 *	file	-> a read to return filename in
 * returns:
 *	0	-> no file
 *	1	-> file to execute
 */
int
gt_Xfile(file, dir)
char	*file, *dir;
{
	DIR *pdir;

	if (xcachesize == 0) {
		/* open spool directory */
		pdir = opendir(dir);
		/* this was an ASSERT, but it's not so bad as all that */
		if (pdir == NULL)
			return (0);

		/* scan spool directory looking for X. files to stash */
		while (gnamef(pdir, file) == TRUE) {
			DEBUG(4, "gt_Xfile got %s\n", file);
			/* look for x prefix */
			if (file[0] != XQTPRE)
				continue;

			/* check to see if required files have arrived */
			if (gotfiles(file))
				xstash(file);
			if (xcachesize >= XCACHESIZE)
				break;
		}
		closedir(pdir);
		xsort();
	}

	return (xget(file));
}

/*
 * check for needed files
 *	file	-> name of file to check
 * return:
 *	0	-> not ready
 *	1	-> all files ready
 */
int
gotfiles(file)
char	*file;
{
	FILE *fp;
	struct stat stbuf;
	char	buf[BUFSIZ], rqfile[MAXNAMESIZE];

	fp = fopen(file, "r");
	if (fp == NULL)
		return (FALSE);

	while (fgets(buf, BUFSIZ, fp) != NULL) {
		DEBUG(4, "%s\n", buf);

		/*
		 * look at required files
		 */
		if (buf[0] != X_RQDFILE)
			continue;
		(void) sscanf(&buf[1], "%63s", rqfile);

		/*
		 * expand file name
		 */
		expfile(rqfile);

		/*
		 * see if file exists
		 */
		if (stat(rqfile, &stbuf) == -1) {
			fclose(fp);
			return (FALSE);
		}
	}

	fclose(fp);
	return (TRUE);
}

/*
 * remove execute files to x-directory
 *
 * _Xfile is a global
 * return:
 *	none
 */
void
rm_Xfiles()
{
	FILE *fp;
	char	buf[BUFSIZ], file[MAXNAMESIZE], tfile[MAXNAMESIZE];
	char	tfull[MAXFULLNAME];

	if ((fp = fopen(_Xfile, "r")) == NULL) {
		DEBUG(4, "rm_Xfiles: can't read %s\n", _Xfile);
		return;
	}

	/*
	 * (void) unlink each file belonging to job
	 */
	while (fgets(buf, BUFSIZ, fp) != NULL) {
		if (buf[0] != X_RQDFILE)
			continue;
		if (sscanf(&buf[1], "%63s%63s", file, tfile) < 2)
			continue;
		(void) snprintf(tfull, sizeof (tfull), "%s/%s", XQTDIR, tfile);
		(void) unlink(tfull);
	}
	fclose(fp);
}

/*
 * move execute files to x-directory
 *	_Xfile is a global
 * return:
 *	none
 */
void
mv_Xfiles()
{
	FILE *fp;
	char	buf[BUFSIZ], ffile[MAXFULLNAME], tfile[MAXNAMESIZE];
	char	tfull[MAXFULLNAME];

	if ((fp = fopen(_Xfile, "r")) == NULL) {
		DEBUG(4, "mv_Xfiles: can't read %s\n", _Xfile);
		return;
	}

	while (fgets(buf, BUFSIZ, fp) != NULL) {
		if (buf[0] != X_RQDFILE)
			continue;
		if (sscanf(&buf[1], "%63s%63s", ffile, tfile) < 2)
			continue;

		/*
		 * expand file names and move to
		 * execute directory
		 * Make files readable by anyone
		 */
		expfile(ffile);
		(void) snprintf(tfull, sizeof (tfull), "%s/%s", XQTDIR, tfile);

		if (chkpth(ffile, CK_READ) == FAIL)
			continue;	/* execution will fail later */
		if (chkpth(tfull, CK_WRITE) == FAIL) {
			/*
			 * tfull will have been canonicalized. If
			 * it still points to XQTDIR, allow us to
			 * write there.
			 */
			if (!PREFIX(XQTDIR, tfull))
				continue;	/* execution will fail later */
			/* otherwise, keep going */
		}

		ASSERT(xmv(ffile, tfull) == 0, "XMV ERROR", tfull, errno);
		chmod(tfull, PUB_FILEMODE);
	}
	fclose(fp);
}

/*
 * undo what mv_Xfiles did
 *	_Xfile is a global
 * return:
 *	none
 */
void
unmv_Xfiles()
{
	FILE *fp;
	char	buf[BUFSIZ], ffile[MAXNAMESIZE], tfile[MAXNAMESIZE];
	char	tfull[MAXFULLNAME], ffull[MAXFULLNAME], xfull[MAXFULLNAME];

	(void) snprintf(xfull, MAXFULLNAME, "%s/%s", RemSpool, _Xfile);
	if ((fp = fopen(xfull, "r")) == NULL) {
		DEBUG(4, "unmv_Xfiles: can't read %s\n", xfull);
		return;
	}

	while (fgets(buf, BUFSIZ, fp) != NULL) {
		if (buf[0] != X_RQDFILE)
			continue;
		if (sscanf(&buf[1], "%63s%63s", ffile, tfile) < 2)
			continue;

		/*
		 * expand file names and move back to
		 * spool directory
		 * Make files readable by uucp
		 */
		(void) snprintf(ffull, MAXFULLNAME, "%s/%s", RemSpool, ffile);
		/* i know we're in .Xqtdir, but ... */
		(void) snprintf(tfull, MAXFULLNAME, "%s/%s", XQTDIR, tfile);

		if (chkpth(ffull, CK_WRITE) == FAIL ||
		    chkpth(tfull, CK_READ) == FAIL)
			continue;

		ASSERT(xmv(tfull, ffull) == 0, "XMV ERROR", ffull, errno);
		(void) chmod(ffull, (mode_t)0600);
	}
	fclose(fp);
}

/*
 * chkpart - checks the string (ptr points to it) for illegal command or
 *  file permission restriction - called recursively
 *  to check lines that have `string` or (string) form.
 *  _Cmd is the buffer where the command is built up.
 *  _CargType is the type of the next C line argument
 *
 * Return:
 *	BAD_FILE if a non permitted file is found
 *	BAD_COMMAND if non permitted command is found
 *	0 - ok
 */

static int
chkpart(char *ptr)
{
	char	prm[BUFSIZ], whitesp[BUFSIZ], rqtcmd[BUFSIZ], xcmd[BUFSIZ];
	char	savechar[2]; /* one character string with NULL */
	int	ret;

	/* _CargType is the arg type for this iteration (cmd or file) */
	while ((ptr = getprm(ptr, whitesp, prm)) != NULL) {
	    DEBUG(4, "prm='%s'\n", prm);
	    switch (*prm) {

	    /* End of command delimiter */
	    case ';':
	    case '^':
	    case '&':
	    case '|':
		(void) strlcat(_Cmd, whitesp, sizeof (_Cmd));
		(void) strlcat(_Cmd, prm, sizeof (_Cmd));
		_CargType = C_COMMAND;
		continue;

	    /* Other delimiter */
	    case '>':
	    case '<':
		(void) strlcat(_Cmd, whitesp, sizeof (_Cmd));
		(void) strlcat(_Cmd, prm, sizeof (_Cmd));
		continue;

	    case '`':	/* don't allow any ` commands */
	    case '\\':
		return (BAD_COMMAND);

	    /* Some allowable quoted string */
	    case '(':
	    case '"':
	    case '\'':
		/* must recurse */
		savechar[0] = *prm;
		savechar[1] = NULLCHAR;
		/* put leading white space & first char into command */
		(void) strlcat(_Cmd, whitesp, sizeof (_Cmd));
		(void) strlcat(_Cmd, savechar, sizeof (_Cmd));
		savechar[0] = prm[strlen(prm)-1];
		prm[strlen(prm)-1] = NULLCHAR; /* delete last character */

		/* recurse */
		if (ret = chkpart(prm+1)) { /* failed */
			return (ret);
		}
		/* put last char into command */
		(void) strlcat(_Cmd, savechar, sizeof (_Cmd));
		continue;

	    case '2':
		if (*(prm+1) == '>') {
		    (void) strlcat(_Cmd, whitesp, sizeof (_Cmd));
		    (void) strlcat(_Cmd, prm, sizeof (_Cmd));
		    continue;
		}
		/* fall through if not "2>" */

	    default:	/* check for command or file */
		break;
	    }

	    if (_CargType == C_COMMAND) {
		(void) strlcpy(rqtcmd, prm, sizeof (rqtcmd));
		if (*rqtcmd == '~')
		    expfile(rqtcmd);
		if ((cmdOK(rqtcmd, xcmd)) == FALSE)
			return (BAD_COMMAND);
		(void) strlcat(_Cmd, whitesp, sizeof (_Cmd));
		(void) strlcat(_Cmd, xcmd, sizeof (_Cmd));
		_CargType = C_FILE;
		continue;
	    }

	    (void) strlcpy(rqtcmd, prm, sizeof (rqtcmd));
	    if (*rqtcmd == '~')
		expfile(rqtcmd);
	    if (chkFile(rqtcmd)) {
		return (BAD_FILE);
	    } else {
		(void) strlcat(_Cmd, whitesp, sizeof (_Cmd));
		(void) strlcat(_Cmd, rqtcmd, sizeof (_Cmd));
	    }
	}
	if (whitesp[0] != '\0')
		/* restore any trailing white space */
		(void) strlcat(_Cmd, whitesp, sizeof (_Cmd));
	return (0);	/* all ok */
}

/*
 * chkFile - try to find a path name in the prm.
 * 	if found, check it for access permission.
 *
 * check file access permissions
 * if ! in name assume that access on local machine is required
 *
 * Return:
 *	BAD_FILE - not permitted
 *	0 - ok
 */

static int
chkFile(char *prm)
{
	char	*p, buf[BUFSIZ];

	(void) strlcpy(buf, prm, sizeof (buf));
	switch (*prm) {
	case '~':
	case '/':
	    if (doFileChk(buf))
		return (BAD_FILE);
	    else
		return (0);
	    /*NOTREACHED*/

	case '!':
	    return (chkFile(buf+1));
	    /*NOTREACHED*/

	default:
	    break;
	}

	if ((p = strchr(buf, '!')) == NULL) {  /* no "!", look for "/" */
	    if ((p = strchr(buf, '/')) == NULL) {  /* ok */
		return (0);
	    }
	    if (doFileChk(p))
		return (BAD_FILE);
	    else
		return (0);
	}

	/* there is at least one '!' - see if it refers to my system */
	if (PREFIX(Myname, buf))	/*  my system so far, check further */
	    return (chkFile(p+1));	/* recurse with thing after '!' */
	else				/* not my system - not my worry */
	    return (0);
}

/*
 * doFileChk - check file path permission
 * NOTE: file is assumed to be a buffer that expfile an
 *  write into.
 * Return
 *	BAD_FILE - not allowed
 *	0 - ok
 */

static int
doFileChk(char *file)
{
	expfile(file);
	DEBUG(7, "fullname: %s\n", file);
	if (chkpth(file, CK_READ) == FAIL ||
	    chkpth(file, CK_WRITE) == FAIL)
		return (BAD_FILE);
	else
		return (0);
}


/*
 * return stuff to user
 *	user	-> user to notify
 *	rmt	-> system name where user resides
 *	file	-> file to return (generally contains input)
 *	cmd	-> command that was to be executed
 *	buf	-> user friendly face saving uplifting edifying missive
 *	errfile	-> stderr output from cmd xeqn
 * return:
 *	none
 */
static void
retosndr(user, rmt, file, cmd, buf, errfile)
char	*user, *rmt, *file, *cmd, *buf, *errfile;
{
	char	ruser[BUFSIZ], msg[BUFSIZ], subj[BUFSIZ];

	(void) snprintf(msg, sizeof (msg), "%s\t[%s %s (%s)]\n\t%s\n%s\n",
	    gettext("remote execution"), gettext("uucp job"),
	    *Jobid ? Jobid : &_Xfile[2], timeStamp(), cmd, buf);

	DEBUG(5, "retosndr %s, ", msg);

	if (EQUALS(rmt, Myname))
		(void) strlcpy(ruser, user, sizeof (ruser));
	else
		(void) snprintf(ruser, sizeof (ruser), "%s!%s", rmt, user);

	(void) strlcpy(subj, gettext("remote execution status"), sizeof (subj));
	mailst(ruser, subj, msg, file, errfile);
}


/*
 * uucpst - send the status message back using a uucp command
 * NOTE - this would be better if the file could be appended.
 * - suggestion for the future - if rmail would take a file name
 * instead of just person, then that facility would be correct,
 * and this routine would not be needed.
 */

static void
uucpst(rmt, tofile, errfile, cmd, buf)
char	*rmt, *tofile, *errfile, *cmd, *buf;
{
	char	arg[MAXFULLNAME], tmp[NAMESIZE], msg[BUFSIZ];
	pid_t pid, ret;
	int status;
	FILE *fp, *fi;

	(void) snprintf(msg, sizeof (msg), "%s %s (%s) %s\n\t%s\n%s\n",
	    gettext("uucp job"), *Jobid ? Jobid : &_Xfile[2], timeStamp(),
	    gettext("remote execution"), cmd, buf);

	(void) snprintf(tmp, sizeof (tmp), "%s.%ld", rmt, (long)getpid());
	if ((fp = fopen(tmp, "w")) == NULL)
		return;
	(void) fprintf(fp, "%s\n", msg);

	/* copy back stderr */
	if (*errfile != '\0' && NOTEMPTY(errfile) &&
	    (fi = fopen(errfile, "r")) != NULL) {
		fputs("\n\t===== stderr was =====\n", fp);
		if (xfappend(fi, fp) != SUCCESS)
			fputs("\n\t===== well, i tried =====\n", fp);
		(void) fclose(fi);
		fputc('\n', fp);
	}


	(void) fclose(fp);
	(void) snprintf(arg, sizeof (arg), "%s!%s", rmt, tofile);

	/* start uucp */

	if ((pid = vfork()) == 0) {
		(void) close(0);
		(void) close(1);
		(void) close(2);
		(void) open("/dev/null", 2);
		(void) open("/dev/null", 2);
		(void) open("/dev/null", 2);
		(void) signal(SIGINT, SIG_IGN);
		(void) signal(SIGHUP, SIG_IGN);
		(void) signal(SIGQUIT, SIG_IGN);
		ucloselog();

		(void) execle("/usr/bin/uucp", "UUCP",
		    "-C", tmp, arg, (char *)0, Env);
		_exit(100);
	}

	if (pid == -1)
	    return;

	while ((ret = wait(&status)) != pid)
	    if (ret == -1 && errno != EINTR)
		break;

	(void) unlink(tmp);
}

void
xprocess(dirname)
char *dirname;
{
    char 	fdgrade();	/* returns default service grade on system */
    int		return_stdin;	/* return stdin for failed commands */
    int		cmdok, ret, badfiles;
    mode_t	mask;
    int		send_zero;	/* return successful completion status */
    int		send_nonzero;	/* return unsuccessful completion status */
    int		send_nothing;	/* request for no exit status */
    int		store_status;	/* store status of command in local file */
    char	lbuf[BUFSIZ];
    char	dqueue;		/* var to hold the default service grade */
    char	*errname = "";	/* name of local stderr output file */
    char	*p;
    char	sendsys[MAXNAMESIZE];
    char	dfile[MAXFULLNAME], cfile[MAXFULLNAME], incmd[BUFSIZ];
    char	errDfile[BUFSIZ];
    char	fin[MAXFULLNAME];
    char	fout[MAXFULLNAME], sysout[NAMESIZE];
    char	ferr[MAXFULLNAME], syserr[NAMESIZE];
    char	file[MAXFULLNAME], tempname[NAMESIZE];
    char	_Sfile[MAXFULLNAME];	/* name of local file for status */
    FILE	*xfp, *fp;
    struct	stat sb;
    char	buf[BUFSIZ], user[BUFSIZ], retaddr[BUFSIZ], retuser[BUFSIZ],
		msgbuf[BUFSIZ];
    char	origsys[MAXFULLNAME], origuser[MAXFULLNAME];

    (void) strlcpy(Rmtname, dirname, sizeof (Rmtname));
    chremdir(Rmtname);
    (void) mchFind(Rmtname);
    while (gt_Xfile(_Xfile, RemSpool) > 0) {
	DEBUG(4, "_Xfile - %s\n", _Xfile);

	if ((xfp = fopen(_Xfile, "r")) == NULL) {
	    toCorrupt(_Xfile);
	    continue;
	}
	ASSERT(xfp != NULL, Ct_OPEN, _Xfile, errno);

	if (stat(_Xfile, &sb) != -1)
	    Nstat.t_qtime = sb.st_mtime;
	/*
	 * initialize to defaults
	 */
	(void) strlcpy(user, User, sizeof (user));
	(void) strcpy(fin, "/dev/null");
	(void) strcpy(fout, "/dev/null");
	(void) strcpy(ferr, "/dev/null");
	(void) sprintf(sysout, "%.*s", MAXBASENAME, Myname);
	(void) sprintf(syserr, "%.*s", MAXBASENAME, Myname);
	badfiles = 0;
	*incmd = *retaddr = *retuser = *Jobid = NULLCHAR;
	initSeq();
	send_zero = send_nonzero = send_nothing = 0;
	store_status = 0;
	return_stdin = 0;

	while (fgets(buf, BUFSIZ, xfp) != NULL) {
	    /*
	     * interpret JCL card
	     */
	    switch (buf[0]) {
		case X_USER:
			/*
			 * user name
			 * (ignore Rmtname)
			 * The utmpx username field is 32 characters long;
			 * UUCP usage truncates system name to 14 bytes.
			 */
			(void) sscanf(&buf[1], "%32s%14s", user, origsys);
			(void) strlcpy(origuser, user, sizeof (origuser));
			break;

		case X_STDIN:
			/*
			 * standard input
			 */
			(void) sscanf(&buf[1], "%256s", fin);
			expfile(fin);
			if (chkpth(fin, CK_READ)) {
				DEBUG(4, "badfile - in: %s\n", fin);
				badfiles = 1;
			}
			break;

		case X_STDOUT:
			/*
			 * standard output
			 */
			(void) sscanf(&buf[1], "%256s%14s", fout, sysout);
			if ((p = strpbrk(sysout, "!/")) != NULL)
				*p = NULLCHAR;	/* these are dangerous */
			if (*sysout != NULLCHAR && !EQUALS(sysout, Myname))
				break;

			expfile(fout);
			if (chkpth(fout, CK_WRITE)) {
				badfiles = 1;
				DEBUG(4, "badfile - out: %s\n", fout);
			}
			break;

		case X_STDERR:	/* standard error */
			(void) sscanf(&buf[1], "%256s%14s", ferr, syserr);
			if ((p = strpbrk(syserr, "!/")) != NULL)
				*p = NULLCHAR;	/* these are dangerous */
			if (*syserr != NULLCHAR && !EQUALS(syserr, Myname))
				break;

			expfile(ferr);
			if (chkpth(ferr, CK_WRITE)) {
				badfiles = 1;
				DEBUG(4, "badfile - error: %s\n", ferr);
			}
			break;


		case X_CMD:	/* command to execute */
			(void) strlcpy(incmd, &buf[2], sizeof (incmd));
			if (*(incmd + strlen(incmd) - 1) == '\n')
				*(incmd + strlen(incmd) - 1) = NULLCHAR;
			break;

		case X_MAILF:	/* put status in _Sfile */
			store_status = 1;
			(void) sscanf(&buf[1], "%256s", _Sfile);
			break;

		case X_SENDNOTHING:	/* no failure notification */
			send_nothing++;
			break;

		case X_SENDZERO:	/* success notification */
			send_zero++;
			break;

		case X_NONZERO:	/* failure notification */
			send_nonzero++;
			break;

		case X_BRINGBACK:  /* return stdin on command failure */
			return_stdin = 1;
			break;


		case X_RETADDR:
			/*
			 * return address -- is user's name
			 * put "Rmtname!" in front of it so mail
			 * will always get back to remote system.
			 */
			(void) sscanf(&buf[1], "%s", retuser);

			/*
			 * Creates string of Rmtname!Rmtname!user which
			 * confuses rmail.
			 * (void) strcat(strcat(strcpy(retaddr, Rmtname), "!"),
			 *	retuser);
			 */
			break;

		case X_JOBID:
			/*
			 * job id for notification
			 * (should be MAXBASENAME, not 14, but no can do)
			 */
			(void) sscanf(&buf[1], "%14s", Jobid);
			break;

		default:
			break;
	    }
	}

	fclose(xfp);
	DEBUG(4, "fin - %s, ", fin);
	DEBUG(4, "fout - %s, ", fout);
	DEBUG(4, "ferr - %s, ", ferr);
	DEBUG(4, "sysout - %s, ", sysout);
	DEBUG(4, "syserr - %s, ", syserr);
	DEBUG(4, "user - %s\n", user);
	DEBUG(4, "incmd - %s\n", incmd);

	scRexe(origsys, origuser, Loginuser, incmd);

	if (retuser[0] != NULLCHAR)
	    (void) strlcpy(user, retuser, sizeof (user)); /* pick on this guy */

	/* get rid of stuff that can be dangerous */
	if ((p = strpbrk(user, Shchar)) != NULL) {
	    *p = NULLCHAR;
	}

	if (incmd[0] == NULLCHAR) {
	    /* this is a bad X. file - just get rid of it */
	    toCorrupt(_Xfile);
	    continue;
	}

	/*
	 * send_nothing must be explicitly requested to avert failure status
	 * send_zero must be explicitly requested for success notification
	 */
	if (!send_nothing)
		send_nonzero++;

	/*
	 * command execution
	 */

	/*
	 * generate a temporary file (if necessary)
	 * to hold output to be shipped back
	 */
	if (EQUALS(fout, "/dev/null"))
	    (void) strcpy(dfile, "/dev/null");
	else {
	    gename(DATAPRE, sysout, 'O', tempname);
	    (void) snprintf(dfile, sizeof (dfile), "%s/%s", WORKSPACE,
		tempname);
	}

	/*
	 * generate a temporary file (if necessary)
	 * to hold errors to be shipped back
	 */
/*
 * This is what really should be done. However for compatibility
 * for the interim at least, we will always create temp file
 * so we can return error output. If this temp file IS conditionally
 * created, we must remove the unlink() of errDfile at the end
 * because it may REALLY be /dev/null.
 *	if (EQUALS(ferr, "/dev/null"))
 *	    (void) strcpy(errDfile, "/dev/null");
 *	else {
 */
	    gename(DATAPRE, syserr, 'E', tempname);
	    (void) snprintf(errDfile, sizeof (errDfile), "%s/%s",
		WORKSPACE, tempname);
/*
 *	}
 */

	/* initialize command line */
	/* set up two environment variables, remote machine name */
	/* and remote user name if available from R line */
	/*
	 * xcu4 requires that uucp *does* expand wildcards and uux *does not*
	 * expand wild cards... Further restrictions are that uux must work
	 * with every other uucp / uux that initiated a request, so nothing
	 * strange can been done to communicate that it was uucp that sent
	 * the request and not uux,  What we settle on here is looking for
	 * the command name uucp and expanding wildcards in only that case.
	 * It is true that a user can spoof this using uux, but in reality
	 * this would be identical to using the uucp command to start with.
	 */
	if (strncmp(incmd, "uucp ", 5) == 0) {
		(void) snprintf(_Cmd, sizeof (_Cmd),
		    "%s %s UU_MACHINE=%s UU_USER=%s "
		    " export UU_MACHINE UU_USER PATH; ",
		    PATH, LOGNAME, Rmtname, user);
	} else {
		(void) snprintf(_Cmd, sizeof (_Cmd),
		    "%s %s UU_MACHINE=%s UU_USER=%s "
		    " export UU_MACHINE UU_USER PATH; set -f; ",
		    PATH, LOGNAME, Rmtname, user);
	}

	/*
	 * check to see if command can be executed
	 */
	_CargType = C_COMMAND;	/* the first thing is a command */
	cmdok = chkpart(incmd);

	if (badfiles || (cmdok == BAD_COMMAND) || cmdok == BAD_FILE) {
	    if (cmdok == BAD_COMMAND) {
		(void) snprintf(lbuf, sizeof (lbuf), "%s!%s XQT DENIED",
		    Rmtname, user);
		(void) snprintf(msgbuf, sizeof (msgbuf),
		    "execution permission denied to %s!%s", Rmtname, user);
	    } else {
		(void) snprintf(lbuf, sizeof (lbuf),
		    "%s!%s XQT - STDIN/STDOUT/FILE ACCESS DENIED",
		    Rmtname, user);
		(void) snprintf(msgbuf, sizeof (msgbuf),
		    "file access denied to %s!%s", Rmtname, user);
	    }
	    logent(incmd, lbuf);
	    DEBUG(4, "bad command %s\n", incmd);

	    scWlog(); /* log security vialotion */

	    if (send_nonzero)
		retosndr(user, Rmtname, return_stdin ? fin : "",
		    incmd, msgbuf, "");
	    if (store_status)
		    uucpst(Rmtname, _Sfile, "", incmd, msgbuf);
	    goto rmfiles;
	}

	(void) snprintf(lbuf, sizeof (lbuf), "%s!%s XQT", Rmtname, user);
	logent(_Cmd, lbuf);
	DEBUG(4, "cmd %s\n", _Cmd);

	/* move files to execute directory and change to that directory */

	mv_Xfiles();

	ASSERT(chdir(XQTDIR) == 0, Ct_CHDIR, XQTDIR, errno);
	acRexe(&_Xfile[2], origsys, origuser, Myname, Loginuser, incmd);

	/* invoke shell to execute command */

	mask = umask(0);
	DEBUG(7, "full cmd: %s\n", _Cmd);

	cpucycle();
	ret = shio(_Cmd, fin, dfile, errDfile);
	if (ret == 0)
		acEndexe(cpucycle(), COMPLETE);
	else
		acEndexe(cpucycle(), PARTIAL);

	umask(mask);
	if (ret == -1) {	/* -1 means the fork() failed */
		unmv_Xfiles();	/* put things back */
		errent(Ct_FORK, buf, errno, __FILE__, __LINE__);
		cleanup(1);
	}

	if (ret == 0) {				/* exit == signal == 0 */
	    (void) strcpy(msgbuf, "exited normally");
	} else {				/* exit != 0 */
	    int exitcode = (ret >> 8) & 0377;

	    if (exitcode) {
		/* exit != 0 */
		(void) snprintf(msgbuf, sizeof (msgbuf),
		    "exited with status %d", exitcode);
	    } else {
		/* signal != 0 */
		(void) snprintf(msgbuf, sizeof (msgbuf),
		    "terminated by signal %d", ret & 0177);
	    }
	    DEBUG(5, "%s\n", msgbuf);
	    (void) snprintf(lbuf, sizeof (lbuf), "%s - %s", incmd, msgbuf);
	    logent(lbuf, "COMMAND FAIL");
	}

	/* change back to spool directory */

	chremdir(Rmtname);

	/* remove file */

	rm_Xfiles();

	/*
	 * We used to append stderr to stdout. Since stderr can
	 * now be specified separately, never append it to stdout.
	 * It can still be gotten via -s status file option.
	 */

	if (!EQUALS(fout, "/dev/null")) {
	    /*
	     * if output is on this machine copy output
	     * there, otherwise spawn job to send to send
	     * output elsewhere.
	     */

	    if (EQUALS(sysout, Myname)) {
		if ((xmv(dfile, fout)) != 0) {
		    logent("FAILED", "COPY");
		    scWrite();
		    (void) snprintf(msgbuf + strlen(msgbuf),
			(sizeof (msgbuf) - strlen(msgbuf)),
			"\nCould not move stdout to %s,", fout);
		    if (putinpub(fout, dfile, origuser) == 0)
			(void) snprintf(msgbuf + strlen(msgbuf),
			    (sizeof (msgbuf) - strlen(msgbuf)),
			    "\n\tstdout left in %s.", fout);
		    else
			(void) strlcat(msgbuf, " stdout lost.",
			    sizeof (msgbuf));
		}
	    } else {
		char *bname;

		if (eaccess(GRADES, 04) != -1)
			dqueue = fdgrade();
		else
			dqueue = Grade;
		gename(CMDPRE, sysout, dqueue, tempname);
		(void) snprintf(cfile, sizeof (cfile), "%s/%s",
		    WORKSPACE, tempname);
		fp = fdopen(ret = creat(cfile, CFILEMODE), "w");
		ASSERT(ret >= 0 && fp != NULL, Ct_OPEN, cfile, errno);
		bname = BASENAME(dfile, '/');
		(void) fprintf(fp, "S %s %s %s -d %s 0666\n",
		    bname, fout, user, bname);
		fclose(fp);
		(void) snprintf(sendsys, sizeof (sendsys), "%s/%c", sysout,
		    dqueue);
		sendsys[MAXNAMESIZE-1] = '\0';
		wfcommit(dfile, BASENAME(dfile, '/'), sendsys);
		wfcommit(cfile, BASENAME(cfile, '/'), sendsys);
	    }
	}
	if (!EQUALS(ferr, "/dev/null")) {
	    /*
	     * if stderr is on this machine copy output
	     * there, otherwise spawn job to send to send
	     * it elsewhere.
	     */
	    if (EQUALS(syserr, Myname)) {
		errname = ferr;
		if ((xmv(errDfile, ferr)) != 0) {
		    logent("FAILED", "COPY");
		    scWrite();
		    (void) snprintf(msgbuf + strlen(msgbuf),
			(sizeof (msgbuf) - strlen(msgbuf)),
			"\nCould not move stderr to %s,", ferr);
		    if (putinpub(ferr, errDfile, origuser) == 0) {
			(void) snprintf(msgbuf+strlen(msgbuf),
			    (sizeof (msgbuf) - strlen(msgbuf)),
			    "\n\tstderr left in %s", ferr);
		    } else {
			errname = errDfile;
			(void) strlcat(msgbuf, " stderr lost.",
			    sizeof (msgbuf));
		    }
		}
	    } else {
		char *bname;

		if (eaccess(GRADES, 04) != -1)
			dqueue = fdgrade();
		else
			dqueue = Grade;
		gename(CMDPRE, syserr, dqueue, tempname);
		(void) snprintf(cfile, sizeof (cfile), "%s/%s",
		    WORKSPACE, tempname);
		fp = fdopen(ret = creat(cfile, CFILEMODE), "w");
		ASSERT(ret >= 0 && fp != NULL, Ct_OPEN, cfile, errno);
		bname = BASENAME(errDfile, '/');
		(void) fprintf(fp, "S %s %s %s -d %s 0666\n",
		    bname, ferr, user, bname);
		fclose(fp);
		(void) snprintf(sendsys, sizeof (sendsys), "%s/%c",
		    syserr, dqueue);
		sendsys[MAXNAMESIZE-1] = '\0';
		wfcommit(errDfile, BASENAME(errDfile, '/'), sendsys);
		wfcommit(cfile, BASENAME(cfile, '/'), sendsys);
	    }
	} else {
/*
 * If we conditionally create stderr tempfile, we must
 * remove this unlink() since errDfile may REALLY be /dev/null
 */
	    unlink(errDfile);
	}

	if (ret == 0) {
	    if (send_zero)
		retosndr(user, Rmtname, "", incmd, msgbuf, "");
	    if (store_status)
		uucpst(Rmtname, _Sfile, "", incmd, msgbuf);
	} else {
	    if (send_nonzero)
		retosndr(user, Rmtname, return_stdin ? fin : "",
			incmd, msgbuf, errname);
	    if (store_status)
		uucpst(Rmtname, _Sfile, errname, incmd, msgbuf);
	}

rmfiles:

	/* delete job files in spool directory */
	xfp = fopen(_Xfile, "r");
	ASSERT(xfp != NULL, Ct_OPEN, _Xfile, errno);
	while (fgets(buf, BUFSIZ, xfp) != NULL) {
		if (buf[0] != X_RQDFILE)
			continue;
		(void) sscanf(&buf[1], "%63s", file);
		expfile(file);
		if (chkpth(file, CK_WRITE) != FAIL)
			(void) unlink(file);
	}
	(void) unlink(_Xfile);
	fclose(xfp);
    }
}

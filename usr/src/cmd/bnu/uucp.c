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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include "uucp.h"

/*
 * uucp
 * user id
 * make a copy in spool directory
 */
int Copy = 0;
static int _Transfer = 0;
char Nuser[32];
char *Ropt = " ";
char Optns[10];
char Uopts[BUFSIZ];
char Xopts[BUFSIZ];
char Sgrade[NAMESIZE];
int Mail = 0;
int Notify = 0;

void cleanup(), ruux(), usage();
int eaccess(), guinfo(), vergrd(), gwd(), ckexpf(), uidstat(), uidxcp(),
	copy(), gtcfile();
void commitall(), wfabort(), mailst(), gename(), svcfile();

char	Sfile[MAXFULLNAME];

int
main(argc, argv, envp)
int argc;
char *argv[];
char	**envp;
{
	char *jid();
	int	ret;
	int	errors = 0;
	char	*fopt, *sys2p;
	char	sys1[MAXFULLNAME], sys2[MAXFULLNAME];
	char	fwd1[MAXFULLNAME], fwd2[MAXFULLNAME];
	char	file1[MAXFULLNAME], file2[MAXFULLNAME];
	short	jflag = 0;	/* -j flag  Jobid printout */
	extern int	split();


	/* Set locale environment variables local definitions */
	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it wasn't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	/* this fails in some versions, but it doesn't hurt */
	Uid = getuid();
	Euid = geteuid();
	if (Uid == 0)
		(void) setuid(UUCPUID);

	/* choose LOGFILE */
	(void) strcpy(Logfile, LOGUUCP);

	Env = envp;
	fopt = NULL;
	(void) strcpy(Progname, "uucp");
	Pchar = 'U';
	*Uopts = NULLCHAR;
	*Xopts = NULLCHAR;
	*Sgrade = NULLCHAR;

	if (eaccess(GRADES, 0) != -1) {
		Grade = 'A';
		Sgrades = TRUE;
		sprintf(Sgrade, "%s", "default");
	}

	/*
	 * find name of local system
	 */
	uucpname(Myname);
	Optns[0] = '-';
	Optns[1] = 'd';
	Optns[2] = 'c';
	Optns[3] = Nuser[0] = Sfile[0] = NULLCHAR;

	/*
	 * find id of user who spawned command to
	 * determine
	 */
	(void) guinfo(Uid, User);

	/*
	 * create/append command log
	 */
	commandlog(argc,argv);

	while ((ret = getopt(argc, argv, "Ccdfg:jmn:rs:x:")) != EOF) {
		switch (ret) {

		/*
		 * make a copy of the file in the spool
		 * directory.
		 */
		case 'C':
			Copy = 1;
			Optns[2] = 'C';
			break;

		/*
		 * not used (default)
		 */
		case 'c':
			break;

		/*
		 * not used (default)
		 */
		case 'd':
			break;
		case 'f':
			Optns[1] = 'f';
			break;

		/*
		 * set service grade
		 */
		case 'g':
			snprintf(Xopts, sizeof (Xopts), "-g%s", optarg);
			if (!Sgrades) {
				if (strlen(optarg) < (size_t)2 && isalnum(*optarg))
					Grade = *optarg;
				else {
					(void) fprintf(stderr, gettext("No"
					    " administrator defined service"
					    " grades available on this"
					    " machine.\n"));
					(void) fprintf(stderr, gettext("UUCP"
					    " service grades range from"
					    " [A-Z][a-z] only.\n"));
					cleanup(-1);
				}
			}
			else {
				(void) strncpy(Sgrade, optarg, NAMESIZE-1);
				Sgrade[NAMESIZE-1] = NULLCHAR;
				if (vergrd(Sgrade) != SUCCESS)
					cleanup(FAIL);
			}
			break;

		case 'j':	/* job id */
			jflag = 1;
			break;

		/*
		 * send notification to local user
		 */
		case 'm':
			Mail = 1;
			(void) strcat(Optns, "m");
			break;

		/*
		 * send notification to user on remote
		 * if no user specified do not send notification
		 */
		case 'n':
			/*
			 * We should add "n" option to Optns only once,
			 * even if multiple -n option are passed to uucp
			 */
			if (!Notify) {
				(void) strlcat(Optns, "n", sizeof (Optns));
				Notify = 1;
			}
			(void) sprintf(Nuser, "%.8s", optarg);

			/*
			 * We do the copy multiple times when multiple
			 * -n options are specified, but
			 * only the last -n value is used.
	 		 */
			(void) snprintf(Uopts, sizeof (Uopts), "-n%s ", Nuser);

			break;

		/*
		 * create JCL files but do not start uucico
		 */
		case 'r':
			Ropt = "-r";
			break;

		/*
		 * return status file
		 */
		case 's':
			fopt = optarg;
			/* "m" needed for compatability */
			(void) strcat(Optns, "mo");
			break;

		/*
		 * turn on debugging
		 */
		case 'x':
			Debug = atoi(optarg);
			if (Debug <= 0)
				Debug = 1;
#ifdef SMALL
			fprintf(stderr, gettext("WARNING: uucp built with SMALL"
			    " flag defined -- no debug info available\n"));
#endif /* SMALL */
			break;

		default:
			usage();
			break;
		}
	}
	DEBUG(4, "\n\n** %s **\n", "START");
	gwd(Wrkdir);
	if (fopt) {
		if (*fopt != '/')
			(void) snprintf(Sfile, MAXFULLNAME, "%s/%s",
					Wrkdir, fopt);
		else
			(void) snprintf(Sfile, MAXFULLNAME, "%s", fopt);

	}
	else
		if (strlcpy(Sfile, "dummy", sizeof (Sfile)) >= sizeof (Sfile))
			return (2);

	/*
	 * work in WORKSPACE directory
	 */
	ret = chdir(WORKSPACE);
	if (ret != 0) {
		(void) fprintf(stderr, gettext("No work directory - %s -"
		    " get help\n"), WORKSPACE);
		cleanup(-12);
	}

	if (Nuser[0] == NULLCHAR)
		(void) strcpy(Nuser, User);
	(void) strcpy(Loginuser, User);
	DEBUG(4, "UID %ld, ", (long) Uid);
	DEBUG(4, "User %s\n", User);
	if (argc - optind < 2) {
		usage();
	}

	/*
	 * set up "to" system and file names
	 */

	(void) split(argv[argc - 1], sys2, fwd2, file2);
	if (*sys2 != NULLCHAR) {
		(void) strncpy(Rmtname, sys2, MAXBASENAME);
		Rmtname[MAXBASENAME] = NULLCHAR;

		/* get real Myname - it depends on who I'm calling--Rmtname */
		(void) mchFind(Rmtname);
		myName(Myname);

		if (versys(sys2) != 0) {
			(void) fprintf(stderr,
			    gettext("bad system: %s\n"), sys2);
			cleanup(-EX_NOHOST);
		}
	}

	DEBUG(9, "sys2: %s, ", sys2);
	DEBUG(9, "fwd2: %s, ", fwd2);
	DEBUG(9, "file2: %s\n", file2);

	/*
	 * if there are more than 2 argsc, file2 is a directory
	 */
	if (argc - optind > 2)
		(void) strcat(file2, "/");

	/*
	 * do each from argument
	 */

	for ( ; optind < argc - 1; optind++) {
	    (void) split(argv[optind], sys1, fwd1, file1);
	    if (*sys1 != NULLCHAR) {
		if (versys(sys1) != 0) {
			(void) fprintf(stderr,
			    gettext("bad system: %s\n"), sys1);
			cleanup(-EX_NOHOST);
		}
	    }

	    /*  source files can have at most one ! */
	    if (*fwd1 != NULLCHAR) {
		/* syntax error */
	        (void) fprintf(stderr,
		    gettext("illegal  syntax %s\n"), argv[optind]);
	        exit(2);
	    }

	    /*
	     * check for required remote expansion of file names -- generate
	     *	and execute a uux command
	     * e.g.
	     *		uucp   owl!~/dan/..  ~/dan/
	     *
	     * NOTE: The source file part must be full path name.
	     *  If ~ it will be expanded locally - it assumes the remote
	     *  names are the same.
	     */

	    if (*sys1 != NULLCHAR)
		if ((strchr(file1, '*') != NULL
		      || strchr(file1, '?') != NULL
		      || strchr(file1, '[') != NULL)) {
		        /* do a uux command */
		        if (ckexpf(file1) == FAIL)
			    exit(6);
			(void) strncpy(Rmtname, sys1, MAXBASENAME);
			Rmtname[MAXBASENAME] = NULLCHAR;
			/* get real Myname - it depends on who I'm calling--Rmtname */
			(void) mchFind(Rmtname);
			myName(Myname);
			if (*sys2 == NULLCHAR)
			    sys2p = Myname;
		        ruux(sys1, sys1, file1, sys2p, fwd2, file2);
		        continue;
		}

	    /*
	     * check for forwarding -- generate and execute a uux command
	     * e.g.
	     *		uucp uucp.c raven!owl!~/dan/
	     */

	    if (*fwd2 != NULLCHAR) {
	        ruux(sys2, sys1, file1, "", fwd2, file2);
	        continue;
	    }

	    /*
	     * check for both source and destination on other systems --
	     *  generate and execute a uux command
	     */

	    if (*sys1 != NULLCHAR )
		if ( (!EQUALS(Myname, sys1))
	    	  && *sys2 != NULLCHAR
	    	  && (!EQUALS(sys2, Myname)) ) {
		    ruux(sys2, sys1, file1, "", fwd2, file2);
	            continue;
	        }


	    sys2p = sys2;
	    if (*sys1 == NULLCHAR) {
		if (*sys2 == NULLCHAR)
		    sys2p = Myname;
		(void) strcpy(sys1, Myname);
	    } else {
		(void) strncpy(Rmtname, sys1, MAXBASENAME);
		Rmtname[MAXBASENAME] = NULLCHAR;
		/* get real Myname - it depends on who I'm calling--Rmtname */
		(void) mchFind(Rmtname);
		myName(Myname);
		if (*sys2 == NULLCHAR)
		    sys2p = Myname;
	    }

	    DEBUG(4, "sys1 - %s, ", sys1);
	    DEBUG(4, "file1 - %s, ", file1);
	    DEBUG(4, "Rmtname - %s\n", Rmtname);
	    if (copy(sys1, file1, sys2p, file2))
	    	errors++;
	}

	/* move the work files to their proper places */
	commitall();

	/*
	 * Wait for all background uux processes to finish so
	 * that our caller will know that we're done with all
	 * input files and it's safe to remove them.
	 */
	while (wait(NULL) != -1)
		;

	/*
	 * do not spawn daemon if -r option specified
	 */
	if (*Ropt != '-') {
#ifndef	V7
		long	limit;
		char	msg[100];
		limit = ulimit(1, (long) 0);
		if (limit < MINULIMIT)  {
			(void) sprintf(msg,
			    "ULIMIT (%ld) < MINULIMIT (%ld)", limit, MINULIMIT);
			logent(msg, "Low-ULIMIT");
		}
		else
#endif
			xuucico(Rmtname);
	}
	if (jflag) {
		(void) strncpy(Jobid, jid(), NAMESIZE);
		printf("%s\n", Jobid);
	}
	cleanup(errors);
	/*NOTREACHED*/
	return (0);
}

/*
 * cleanup lock files before exiting
 */
void
cleanup(code)
int	code;
{
	static int first = 1;

	if (first) {
		first = 0;
		rmlock(CNULL);
		if (code != 0)
			wfabort();  /* this may be extreme -- abort all work */
	}
	if (code < 0) {
	       (void) fprintf(stderr,
		   gettext("uucp failed completely (%d)\n"), (-code));
		exit(-code);
	}
	else if (code > 0) {
		(void) fprintf(stderr, gettext(
		    "uucp failed partially: %d file(s) sent; %d error(s)\n"),
		 _Transfer, code);
		exit(code);
	}
	exit(code);
}

static FILE *syscfile();
/*
 * generate copy files for s1!f1 -> s2!f2
 *	Note: only one remote machine, other situations
 *	have been taken care of in main.
 * return:
 *	0	-> success
 * Non-zero     -> failure
 */
int
copy(s1, f1, s2, f2)
char *s1, *f1, *s2, *f2;
{
	FILE *cfp;
	struct stat stbuf, stbuf1;
	int type, statret;
	char dfile[NAMESIZE];
	char cfile[NAMESIZE];
	char command[10+(2*MAXFULLNAME)];
	char file1[MAXFULLNAME], file2[MAXFULLNAME];
	char msg[BUFSIZ];

	type = 0;
	(void) strcpy(file1, f1);
	(void) strcpy(file2, f2);
	if (!EQUALS(s1, Myname))
		type = 1;
	if (!EQUALS(s2, Myname))
		type = 2;

	DEBUG(4, "copy: file1=<%s> ", file1);
	DEBUG(4, "file2=<%s>\n", file2);
	switch (type) {
	case 0:

		/*
		 * all work here
		 */
		DEBUG(4, "all work here %d\n", type);

		/*
		 * check access control permissions
		 */
		if (ckexpf(file1))
			 return(-6);
		if (ckexpf(file2))
			 return(-7);

		setuid(Uid);
		if (chkperm(file1, file2, strchr(Optns, 'd')) &&
		    (access(file2, W_OK) == -1)) {
			(void) fprintf(stderr, gettext("permission denied\n"));
			cleanup(1);
		}

		/*
		 * copy file locally
		 *
		 * Changed from uidxcp() to fic file made and owner
		 * being modified for existing files, and local file
		 * name expansion.
		 */
		DEBUG(2, "local copy: %s -> ", file1);
		DEBUG(2, "%s\n", file2);

		sprintf(command, "cp %s %s", file1, file2);
		if ((cfp = popen(command, "r")) == NULL) {
			perror("popen");
			DEBUG(5, "popen failed - errno %d\n", errno);
			setuid(Euid);
			return (FAIL);
		}
		if (pclose(cfp) != 0) {
			DEBUG(5, "Copy failed - errno %d\n", errno);
			return (FAIL);
		}
		setuid(Euid);

		/*
		 * if user specified -m, notify "local" user
		 */
		 if ( Mail ) {
		 	sprintf(msg,
		 	"REQUEST: %s!%s --> %s!%s (%s)\n(SYSTEM %s) copy succeeded\n",
		 	s1, file1, s2, file2, User, s2 );
		 	mailst(User, "copy succeeded", msg, "", "");
		}
		/*
		 * if user specified -n, notify "remote" user
		 */
		if ( Notify ) {
			sprintf(msg, "%s from %s!%s arrived\n",
				file2, s1, User );
			mailst(Nuser, msg, msg, "", "");
		}
		return(0);
	case 1:

		/*
		 * receive file
		 */
		DEBUG(4, "receive file - %d\n", type);

		/*
		 * expand source and destination file names
		 * and check access permissions
		 */
		if (file1[0] != '~')
			if (ckexpf(file1))
				 return(6);
		if (ckexpf(file2))
			 return(7);


		gename(DATAPRE, s2, Grade, dfile);

		/*
		 * insert JCL card in file
		 */
		cfp = syscfile(cfile, s1);
		(void) fprintf(cfp,
	       	"R %s %s %s %s %s %o %s %s\n", file1, file2,
			User, Optns,
			*Sfile ? Sfile : "dummy",
			0777, Nuser, dfile);
		(void) fclose(cfp);
		(void) sprintf(msg, "%s!%s --> %s!%s", Rmtname, file1,
		    Myname, file2);
		logent(msg, "QUEUED");
		break;
	case 2:

		/*
		 * send file
		 */
		if (ckexpf(file1))
			 return(6);
		/* XQTDIR hook enables 3rd party uux requests (cough) */
		DEBUG(4, "Workdir = <%s>\n", Wrkdir);
		if (file2[0] != '~' && !EQUALS(Wrkdir, XQTDIR))
			if (ckexpf(file2))
				 return(7);
		DEBUG(4, "send file - %d\n", type);

		if (uidstat(file1, &stbuf) != 0) {
			(void) fprintf(stderr,
			    gettext("can't get status for file %s\n"), file1);
			return(8);
		}
		if ((stbuf.st_mode & S_IFMT) == S_IFDIR) {
			(void) fprintf(stderr,
			    gettext("directory name illegal - %s\n"), file1);
			return(9);
		}
		/* see if I can read this file as read uid, gid */
		if (access(file1, R_OK) != 0) {
			(void) fprintf(stderr,
			    gettext("uucp can't read (%s) mode (%o)\n"),
			    file1, stbuf.st_mode&0777);
			return(3);
		}

		/*
		 * make a copy of file in spool directory
		 */

		gename(DATAPRE, s2, Grade, dfile);

		if (Copy || !READANY(file1) ) {

			if (uidxcp(file1, dfile))
			    return(5);

			(void) chmod(dfile, DFILEMODE);
		}

		cfp = syscfile(cfile, s2);
		(void) fprintf(cfp, "S %s %s %s %s %s %lo %s %s\n",
		    file1, file2, User, Optns, dfile,
		    (long) stbuf.st_mode & LEGALMODE, Nuser, Sfile);
		(void) fclose(cfp);
		(void) sprintf(msg, "%s!%s --> %s!%s", Myname, file1,
		    Rmtname, file2);
		logent(msg, "QUEUED");
		break;
	}
	_Transfer++;
	return(0);
}


/*
 *	syscfile(file, sys)
 *	char	*file, *sys;
 *
 *	get the cfile for system sys (creat if need be)
 *	return stream pointer
 *
 *	returns
 *		stream pointer to open cfile
 *
 */

static FILE	*
syscfile(file, sys)
char	*file, *sys;
{
	FILE	*cfp;

	if (gtcfile(file, sys) == FAIL) {
		gename(CMDPRE, sys, Grade, file);
		ASSERT(access(file, 0) != 0, Fl_EXISTS, file, errno);
		cfp = fdopen(creat(file, CFILEMODE), "w");
		svcfile(file, sys, Sgrade);
	} else
		cfp = fopen(file, "a");
	ASSERT(cfp != NULL, Ct_OPEN, file, errno);
	return(cfp);
}


/*
 * generate and execute a uux command
 */

void
ruux(rmt, sys1, file1, sys2, fwd2, file2)
char *rmt, *sys1, *file1, *sys2, *fwd2, *file2;
{
    char cmd[BUFSIZ];
    char xcmd[BUFSIZ];
    char * xarg[6];
    int narg = 0;
    int i;

    /* get real Myname - it depends on who I'm calling--rmt */
    (void) mchFind(rmt);
    myName(Myname);

    xarg[narg++] = UUX;
    xarg[narg++] = "-C";
    if (*Xopts != NULLCHAR)
	xarg[narg++] = Xopts;
    if (*Ropt  != ' ')
	xarg[narg++] = Ropt;

    (void) sprintf(cmd, "%s!uucp -C", rmt);

    if (*Uopts != NULLCHAR)
	(void) sprintf(cmd+strlen(cmd), " (%s) ", Uopts);

    if (*sys1 == NULLCHAR || EQUALS(sys1, Myname)) {
        if (ckexpf(file1))
  	    exit(6);
	(void) sprintf(cmd+strlen(cmd), " %s!%s ", sys1, file1);
    }
    else
	if (!EQUALS(rmt, sys1))
	    (void) sprintf(cmd+strlen(cmd), " (%s!%s) ", sys1, file1);
	else
	    (void) sprintf(cmd+strlen(cmd), " (%s) ", file1);

    if (*fwd2 != NULLCHAR) {
	if (*sys2 != NULLCHAR)
	    (void) sprintf(cmd+strlen(cmd),
		" (%s!%s!%s) ", sys2, fwd2, file2);
	else
	    (void) sprintf(cmd+strlen(cmd), " (%s!%s) ", fwd2, file2);
    }
    else {
	if (*sys2 == NULLCHAR || EQUALS(sys2, Myname))
	    if (ckexpf(file2))
		exit(7);
	(void) sprintf(cmd+strlen(cmd), " (%s!%s) ", sys2, file2);
    }

    xarg[narg++] = cmd;
    xarg[narg] = (char *) 0;

    xcmd[0] = NULLCHAR;
    for (i=0; i < narg; i++) {
	strcat(xcmd, xarg[i]);
	strcat(xcmd, " ");
    }
    DEBUG(2, "cmd: %s\n", xcmd);
    logent(xcmd, "QUEUED");

    if (fork() == 0) {
	ASSERT(setuid(getuid()) == 0, "setuid", "failed", 99);
	execv(UUX, xarg);
	exit(0);
    }
    return;
}

void
usage()
{

	(void) fprintf(stderr, gettext(
	"Usage:  %s [-c|-C] [-d|-f] [-g GRADE] [-jm] [-n USER]\\\n"
	"[-r] [-s FILE] [-x DEBUG_LEVEL] source-files destination-file\n"),
	Progname);
	cleanup(-2);
}

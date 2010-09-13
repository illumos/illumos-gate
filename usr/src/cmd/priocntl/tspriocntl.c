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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#include	<stdio.h>
#include	<string.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<sys/types.h>
#include	<sys/procset.h>
#include	<sys/priocntl.h>
#include	<sys/tspriocntl.h>
#include	<libgen.h>
#include	<limits.h>
#include	<errno.h>

#include	"priocntl.h"

/*
 * This file contains the class specific code implementing
 * the time-sharing priocntl sub-command.
 */

#define	ADDKEYVAL(p, k, v) { (p[0]) = (k); (p[1]) = (v); p += 2; }

#define	TS_KEYCNT	2	/* maximal number of (key, value) pairs */

/*
 * control flags
 */
#define	TS_DOUPRILIM	0x01		/* user priority limit */
#define	TS_DOUPRI	0x02		/* user priority */


static void	print_tsinfo(void);
static int	print_tsprocs(void);
static int	ts_priocntl(idtype_t, id_t, int, char *, uintptr_t *);
static int	set_tsprocs(idtype_t, int, char **, uint_t, pri_t, pri_t);
static void	exec_tscmd(char **, uint_t, pri_t, pri_t);


static char usage[] =
"usage:	priocntl -l\n\
	priocntl -d [-d idtype] [idlist]\n\
	priocntl -s [-c TS] [-m tsuprilim] [-p tsupri] [-i idtype] [idlist]\n\
	priocntl -e [-c TS] [-m tsuprilim] [-p tsupri] command [argument(s)]\n";

static char	cmdpath[MAXPATHLEN];
static char	basenm[BASENMSZ];


int
main(int argc, char *argv[])
{
	int		c;
	int		lflag, dflag, sflag, mflag, pflag, eflag, iflag;
	pri_t		tsuprilim;
	pri_t		tsupri;
	char		*idtypnm;
	idtype_t	idtype;
	int		idargc;
	uint_t		cflags;

	(void) strlcpy(cmdpath, argv[0], MAXPATHLEN);
	(void) strlcpy(basenm, basename(argv[0]), BASENMSZ);
	lflag = dflag = sflag = mflag = pflag = eflag = iflag = 0;
	while ((c = getopt(argc, argv, "ldsm:p:ec:i:")) != -1) {
		switch (c) {

		case 'l':
			lflag++;
			break;

		case 'd':
			dflag++;
			break;

		case 's':
			sflag++;
			break;

		case 'm':
			mflag++;
			tsuprilim = (pri_t)str2num(optarg, SHRT_MIN, SHRT_MAX);
			if (errno)
				fatalerr("%s: Specified user priority limit %s"
				    " out of configured range\n",
				    basenm, optarg);
			break;

		case 'p':
			pflag++;
			tsupri = (pri_t)str2num(optarg, SHRT_MIN, SHRT_MAX);
			if (errno)
				fatalerr("%s: Specified user priority %s out of"
				    " configured range\n", basenm, optarg);
			break;

		case 'e':
			eflag++;
			break;

		case 'c':
			if (strcmp(optarg, "TS") != 0)
				fatalerr("error: %s executed for %s class, %s"
				    " is actually sub-command for TS class\n",
				    cmdpath, optarg, cmdpath);
			break;

		case 'i':
			iflag++;
			idtypnm = optarg;
			break;

		case '?':
			fatalerr(usage);

		default:
			break;
		}
	}

	if (lflag) {
		if (dflag || sflag || mflag || pflag || eflag || iflag)
			fatalerr(usage);

		print_tsinfo();

	} else if (dflag) {
		if (lflag || sflag || mflag || pflag || eflag)
			fatalerr(usage);

		return (print_tsprocs());

	} else if (sflag) {
		if (lflag || dflag || eflag)
			fatalerr(usage);

		if (iflag) {
			if (str2idtyp(idtypnm, &idtype) == -1)
				fatalerr("%s: Bad idtype %s\n", basenm,
				    idtypnm);
		} else {
			idtype = P_PID;
		}

		cflags = (pflag ? TS_DOUPRI : 0);

		if (mflag)
			cflags |= TS_DOUPRILIM;

		if (optind < argc)
			idargc = argc - optind;
		else
			idargc = 0;

		return (set_tsprocs(idtype, idargc, &argv[optind], cflags,
		    tsuprilim, tsupri));

	} else if (eflag) {
		if (lflag || dflag || sflag || iflag)
			fatalerr(usage);

		cflags = (pflag ? TS_DOUPRI : 0);

		if (mflag)
			cflags |= TS_DOUPRILIM;

		exec_tscmd(&argv[optind], cflags, tsuprilim, tsupri);

	} else {
		fatalerr(usage);
	}

	return (0);
}


/*
 * Print our class name and the configured user priority range.
 */
static void
print_tsinfo(void)
{
	pcinfo_t	pcinfo;

	(void) strcpy(pcinfo.pc_clname, "TS");

	(void) printf("TS (Time Sharing)\n");

	if (priocntl(0, 0, PC_GETCID, (caddr_t)&pcinfo) == -1)
		fatalerr("\tCan't get configured TS user priority range\n");

	(void) printf("\tConfigured TS User Priority Range: -%d through %d\n",
	    ((tsinfo_t *)pcinfo.pc_clinfo)->ts_maxupri,
	    ((tsinfo_t *)pcinfo.pc_clinfo)->ts_maxupri);
}


/*
 * Read a list of pids from stdin and print the user priority and user
 * priority limit for each of the corresponding processes.
 */
static int
print_tsprocs(void)
{
	pid_t		*pidlist;
	size_t		numread;
	int		i;
	char		clname[PC_CLNMSZ];
	pri_t		ts_uprilim;
	pri_t		ts_upri;
	int		error = 0;

	/*
	 * Read a list of pids from stdin.
	 */
	if ((pidlist = read_pidlist(&numread, stdin)) == NULL)
		fatalerr("%s: Can't read pidlist.\n", basenm);

	(void) printf(
	    "TIME SHARING PROCESSES:\n    PID    TSUPRILIM    TSUPRI\n");

	if (numread == 0)
		fatalerr("%s: No pids on input\n", basenm);

	for (i = 0; i < numread; i++) {
		(void) printf("%7ld", pidlist[i]);
		if (priocntl(P_PID, pidlist[i], PC_GETXPARMS, "TS", TS_KY_UPRI,
		    &ts_upri, TS_KY_UPRILIM, &ts_uprilim, 0) != -1) {
			(void) printf("    %5d       %5d\n",
			    ts_uprilim, ts_upri);
		} else {
			error = 1;

			if (priocntl(P_PID, pidlist[i], PC_GETXPARMS, NULL,
			    PC_KY_CLNAME, clname, 0) != -1 &&
			    strcmp(clname, "TS"))
				/*
				 * Process from some class other than time
				 * sharing. It has probably changed class while
				 * priocntl command was executing (otherwise
				 * we wouldn't have been passed its pid).
				 * Print the little we know about it.
				 */
				(void) printf("\tChanged to class %s while"
				    " priocntl command executing\n", clname);
			else
				(void) printf("\tCan't get TS user priority\n");
		}
	}

	free_pidlist(pidlist);
	return (error);
}


/*
 * Call priocntl() with command codes PC_SETXPARMS or PC_GETXPARMS.
 * The first parameter behind the command code is always the class name.
 * Each parameter is headed by a key, which determines the meaning of the
 * following value. There are maximal TS_KEYCNT = 2 (key, value) pairs.
 */
static int
ts_priocntl(idtype_t idtype, id_t id, int cmd, char *clname, uintptr_t *argsp)
{
	return (priocntl(idtype, id, cmd, clname, argsp[0], argsp[1],
	    argsp[2], argsp[3], 0));
}


/*
 * Set all processes in the set specified by idtype/idargv to time-sharing
 * (if they aren't already time-sharing) and set their user priority limit
 * and user priority to those specified by tsuprilim and tsupri.
 */
static int
set_tsprocs(idtype_t idtype, int idargc, char **idargv, uint_t cflags,
	pri_t tsuprilim, pri_t tsupri)
{
	pcinfo_t	pcinfo;
	uintptr_t	args[2*TS_KEYCNT+1];
	uintptr_t	*argsp = &args[0];
	pri_t		maxupri;
	char		idtypnm[PC_IDTYPNMSZ];
	int		i;
	int		error = 0;
	id_t		id;

	/*
	 * Get the time sharing class ID and max configured user priority.
	 */
	(void) strcpy(pcinfo.pc_clname, "TS");
	if (priocntl(0, 0, PC_GETCID, (caddr_t)&pcinfo) == -1)
		fatalerr("%s: Can't get TS class ID, priocntl system call"
		    " failed with errno %d\n", basenm, errno);
	maxupri = ((tsinfo_t *)pcinfo.pc_clinfo)->ts_maxupri;

	/*
	 * Validate the tsuprilim and tsupri arguments.
	 */
	if ((cflags & TS_DOUPRILIM) != 0) {
		if (tsuprilim > maxupri || tsuprilim < -maxupri)
			fatalerr("%s: Specified user priority limit %d out of"
			    " configured range\n", basenm, tsuprilim);
		ADDKEYVAL(argsp, TS_KY_UPRILIM, tsuprilim);
	}

	if ((cflags & TS_DOUPRI) != 0) {
		if (tsupri > maxupri || tsupri < -maxupri)
			fatalerr("%s: Specified user priority %d out of"
			    " configured range\n", basenm, tsupri);
		ADDKEYVAL(argsp, TS_KY_UPRI, tsupri);
	}
	*argsp = 0;

	if (idtype == P_ALL) {
		if (ts_priocntl(P_ALL, 0, PC_SETXPARMS, "TS", args) == -1) {
			if (errno == EPERM) {
				(void) fprintf(stderr,
				    "Permissions error encountered"
				    " on one or more processes.\n");
				error = 1;
			} else {
				fatalerr("%s: Can't reset time sharing"
				    " parameters\npriocntl system call failed"
				    " with errno %d\n", basenm, errno);
			}
		} else if ((cflags & (TS_DOUPRILIM|TS_DOUPRI)) == TS_DOUPRI) {
			(void) verifyupri(idtype, 0, "TS", TS_KY_UPRILIM,
			    tsupri, basenm);
		}
	} else if (idargc == 0) {
		if (ts_priocntl(idtype, P_MYID, PC_SETXPARMS, "TS",
		    args) == -1) {
			if (errno == EPERM) {
				(void) idtyp2str(idtype, idtypnm);
				(void) fprintf(stderr, "Permissions error"
				    " encountered on current %s.\n", idtypnm);
				error = 1;
			} else {
				fatalerr("%s: Can't reset time sharing"
				    " parameters\npriocntl system call failed"
				    " with errno %d\n", basenm, errno);
			}
		} else if ((cflags & (TS_DOUPRILIM|TS_DOUPRI)) == TS_DOUPRI &&
		    getmyid(idtype, &id) != -1) {
			(void) verifyupri(idtype, id, "TS", TS_KY_UPRILIM,
			    tsupri, basenm);
		}
	} else {
		(void) idtyp2str(idtype, idtypnm);
		for (i = 0; i < idargc; i++) {
			if (idtype == P_CID) {
				(void) strcpy(pcinfo.pc_clname, idargv[i]);
				if (priocntl(0, 0, PC_GETCID,
				    (caddr_t)&pcinfo) == -1)
					fatalerr("%s: Invalid or unconfigured"
					    " class %s, priocntl system call"
					    " failed with errno %d\n",
					    basenm, pcinfo.pc_clname, errno);
				id = pcinfo.pc_cid;
			} else {
				id = (id_t)str2num(idargv[i], INT_MIN, INT_MAX);
				if (errno)
					fatalerr("%s: Invalid id \"%s\"\n",
					    basenm, idargv[i]);
			}

			if (ts_priocntl(idtype, id, PC_SETXPARMS, "TS",
			    args) == -1) {
				if (errno == EPERM) {
					(void) fprintf(stderr,
					    "Permissions error encountered on"
					    " %s %s.\n", idtypnm, idargv[i]);
					error = 1;
				} else {
					fatalerr("%s: Can't reset time sharing"
					    " parameters\npriocntl system call"
					    " failed with errno %d\n",
					    basenm, errno);
				}
			} else if ((cflags & (TS_DOUPRILIM|TS_DOUPRI)) ==
			    TS_DOUPRI) {
				(void) verifyupri(idtype, id, "TS",
				    TS_KY_UPRILIM, tsupri, basenm);
			}
		}
	}

	return (error);
}


/*
 * Execute the command pointed to by cmdargv as a time-sharing process
 * with the user priority limit given by tsuprilim and user priority tsupri.
 */
static void
exec_tscmd(char **cmdargv, uint_t cflags, pri_t tsuprilim, pri_t tsupri)
{
	pcinfo_t	pcinfo;
	uintptr_t	args[2*TS_KEYCNT+1];
	uintptr_t	*argsp = &args[0];
	pri_t		maxupri;
	pri_t		uprilim;

	/*
	 * Get the time sharing class ID and max configured user priority.
	 */
	(void) strcpy(pcinfo.pc_clname, "TS");
	if (priocntl(0, 0, PC_GETCID, (caddr_t)&pcinfo) == -1)
		fatalerr("%s: Can't get TS class ID, priocntl system call"
		    " failed with errno %d\n", basenm, errno);
	maxupri = ((tsinfo_t *)pcinfo.pc_clinfo)->ts_maxupri;

	if ((cflags & TS_DOUPRILIM) != 0) {
		if (tsuprilim > maxupri || tsuprilim < -maxupri)
			fatalerr("%s: Specified user priority limit %d out of"
			    " configured range\n", basenm, tsuprilim);
		ADDKEYVAL(argsp, TS_KY_UPRILIM, tsuprilim);
	}

	if ((cflags & TS_DOUPRI) != 0) {
		if (tsupri > maxupri || tsupri < -maxupri)
			fatalerr("%s: Specified user priority %d out of"
			    " configured range\n", basenm, tsupri);
		ADDKEYVAL(argsp, TS_KY_UPRI, tsupri);
	}
	*argsp = 0;

	if (ts_priocntl(P_PID, P_MYID, PC_SETXPARMS, "TS", args) == -1)
		fatalerr("%s: Can't reset time sharing parameters\n"
		    "priocntl system call failed with errno %d\n",
		    basenm, errno);

	if ((cflags & (TS_DOUPRILIM|TS_DOUPRI)) == TS_DOUPRI) {
		if (priocntl(P_PID, P_MYID, PC_GETXPARMS, "TS",
		    TS_KY_UPRILIM, &uprilim, 0) != -1 && tsupri > uprilim)
			(void) fprintf(stderr,
			    "%s: Specified user priority %d exceeds"
			    " limit %d; set to %d (pid %d)\n",
			    basenm, tsupri, uprilim, uprilim, (int)getpid());
	}

	(void) execvp(cmdargv[0], cmdargv);
	fatalerr("%s: Can't execute %s, exec failed with errno %d\n",
	    basenm, cmdargv[0], errno);
}

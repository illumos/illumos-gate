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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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
#include	<sys/time.h>
#include	<sys/procset.h>
#include	<sys/priocntl.h>
#include	<sys/rtpriocntl.h>
#include	<sys/param.h>
#include	<signal.h>
#include	<libgen.h>
#include	<limits.h>
#include	<errno.h>

#include	"priocntl.h"

/*
 * This file contains the class specific code implementing
 * the real-time priocntl sub-command.
 */

#define	ADDKEYVAL(p, k, v) { (p[0]) = (k); (p[1]) = (v); p += 2; }

#define	RT_KEYCNT	4	/* maximal number of (key, value) pairs */

/*
 * control flags
 */
#define	RT_DOPRI	0x01	/* change priority */
#define	RT_DOTQ		0x02	/* change RT time quantum */
#define	RT_DOSIG	0x10	/* change RT time quantum signal */


static void	print_rtinfo(void);
static int	print_rtprocs(void);
static int	rt_priocntl(idtype_t, id_t, int, char *, uintptr_t *);
static int	set_rtprocs(idtype_t, int, char **, uint_t, pri_t, long,
			long, int);
static void	exec_rtcmd(char **, uint_t, pri_t, long, long, int);


static char usage[] =
"usage: priocntl -l\n"
"       priocntl -d [-i idtype] [idlist]\n"
"       priocntl -s [-c RT] [-p rtpri] [-t tqntm [-r res]] [-q tqsig]\n"
"                   [-i idtype] [idlist]\n"
"       priocntl -e [-c RT] [-p rtpri] [-t tqntm [-r res]] [-q tqsig]\n"
"                   command [argument(s)]\n";

static char	cmdpath[MAXPATHLEN];
static char	basenm[BASENMSZ];


int
main(int argc, char *argv[])
{
	int		c;
	int		lflag, dflag, sflag, pflag;
	int		tflag, rflag, eflag, iflag, qflag;
	pri_t		rtpri;
	long		tqntm;
	long		res;
	int		tqsig;
	char		*idtypnm;
	idtype_t	idtype;
	int		idargc;
	uint_t		cflags;

	(void) strlcpy(cmdpath, argv[0], MAXPATHLEN);
	(void) strlcpy(basenm, basename(argv[0]), BASENMSZ);
	lflag = dflag = sflag = pflag = 0;
	tflag = rflag = eflag = iflag = qflag = 0;
	while ((c = getopt(argc, argv, "ldsp:t:r:q:ec:i:")) != -1) {
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

		case 'p':
			pflag++;
			rtpri = (pri_t)str2num(optarg, SHRT_MIN, SHRT_MAX);
			if (errno)
				fatalerr("%s: Specified real time priority %s"
				    " out of configured range\n",
				    basenm, optarg);
			break;

		case 't':
			tflag++;
			tqntm = str2num(optarg, 1, INT_MAX);
			if (errno)
				fatalerr("%s: Invalid time quantum specified;"
				    " time quantum must be positive\n", basenm);
			break;

		case 'r':
			rflag++;
			res = str2num(optarg, 1, 1000000000);
			if (errno)
				fatalerr("%s: Invalid resolution specified;"
				    " resolution must be between"
				    " 1 and 1,000,000,000\n", basenm);

			break;

		case 'q':
			qflag++;
			if (str2sig(optarg, &tqsig) != 0)
				fatalerr("%s: Invalid real time quantum signal"
				    " specified\n", basenm);
			break;

		case 'e':
			eflag++;
			break;

		case 'c':
			if (strcmp(optarg, "RT") != 0)
				fatalerr("error: %s executed for %s class, %s"
				    " is actually sub-command for RT class\n",
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
		if (dflag || sflag || pflag || tflag || rflag || eflag ||
		    iflag || qflag)
			fatalerr(usage);

		print_rtinfo();

	} else if (dflag) {
		if (lflag || sflag || pflag || tflag || rflag || eflag || qflag)
			fatalerr(usage);

		return (print_rtprocs());

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

		cflags = (pflag ? RT_DOPRI : 0);

		if (tflag)
			cflags |= RT_DOTQ;

		if (rflag == 0)
			res = 1000;

		if (optind < argc)
			idargc = argc - optind;
		else
			idargc = 0;

		if (qflag)
			cflags |= RT_DOSIG;

		return (set_rtprocs(idtype, idargc, &argv[optind], cflags,
		    rtpri, tqntm, res, tqsig));

	} else if (eflag) {
		if (lflag || dflag || sflag || iflag)
			fatalerr(usage);

		cflags = (pflag ? RT_DOPRI : 0);

		if (tflag)
			cflags |= RT_DOTQ;

		if (rflag == 0)
			res = 1000;

		if (qflag)
			cflags |= RT_DOSIG;

		exec_rtcmd(&argv[optind], cflags, rtpri, tqntm, res, tqsig);

	} else {
		fatalerr(usage);
	}

	return (0);
}


/*
 * Print our class name and the configured user priority range.
 */
static void
print_rtinfo(void)
{
	pcinfo_t	pcinfo;

	(void) strcpy(pcinfo.pc_clname, "RT");

	(void) printf("RT (Real Time)\n");

	if (priocntl(0, 0, PC_GETCID, (caddr_t)&pcinfo) == -1)
		fatalerr("\tCan't get maximum configured RT priority\n");

	(void) printf("\tConfigured RT User Priority Range: 0 through %d\n",
	    ((rtinfo_t *)pcinfo.pc_clinfo)->rt_maxpri);
}


/*
 * Read a list of pids from stdin and print the real-time priority and time
 * quantum (in millisecond resolution) for each of the corresponding processes.
 */
static int
print_rtprocs(void)
{
	pid_t		*pidlist;
	size_t		numread;
	int		i;
	char		clname[PC_CLNMSZ];
	pri_t		rt_pri;
	uint_t		rt_tqsecs;
	int		rt_tqnsecs;
	int		rt_tqsig;
	int		error = 0;

	/*
	 * Read a list of pids from stdin.
	 */
	if ((pidlist = read_pidlist(&numread, stdin)) == NULL)
		fatalerr("%s: Can't read pidlist.\n", basenm);

	(void) printf("REAL TIME PROCESSES:\n"
	    "    PID   RTPRI       TQNTM    TQSIG\n");

	if (numread == 0)
		fatalerr("%s: No pids on input\n", basenm);

	for (i = 0; i < numread; i++) {
		(void) printf("%7ld", pidlist[i]);
		if (priocntl(P_PID, pidlist[i], PC_GETXPARMS, "RT",
		    RT_KY_TQSECS, &rt_tqsecs, RT_KY_TQNSECS, &rt_tqnsecs,
		    RT_KY_PRI, &rt_pri, RT_KY_TQSIG, &rt_tqsig, 0) != -1) {
			(void) printf("   %5d", rt_pri);
			if (rt_tqnsecs == RT_TQINF)
				(void) printf("    RT_TQINF");
			else
				(void) printf(" %11lld",
				    (longlong_t)rt_tqsecs * 1000 +
				    rt_tqnsecs / 1000000);

			(void) printf("      %3d\n", rt_tqsig);
		} else {
			error = 1;

			if (priocntl(P_PID, pidlist[i], PC_GETXPARMS, NULL,
			    PC_KY_CLNAME, clname, 0) != -1 &&
			    strcmp(clname, "RT"))
				/*
				 * Process from some class other than real time.
				 * It has probably changed class while priocntl
				 * command was executing (otherwise we wouldn't
				 * have been passed its pid).  Print the little
				 * we know about it.
				 */
				(void) printf("\tChanged to class %s while"
				    " priocntl command executing\n", clname);
			else
				(void) printf("\tCan't get real time"
				    " parameters\n");
		}
	}

	free_pidlist(pidlist);
	return (error);
}


/*
 * Call priocntl() with command codes PC_SETXPARMS or PC_GETXPARMS.
 * The first parameter behind the command code is always the class name.
 * Each parameter is headed by a key, which determines the meaning of the
 * following value. There are maximal RT_KEYCNT = 4 (key, value) pairs.
 */
static int
rt_priocntl(idtype_t idtype, id_t id, int cmd, char *clname, uintptr_t *argsp)
{
	return (priocntl(idtype, id, cmd, clname, argsp[0], argsp[1],
	    argsp[2], argsp[3], argsp[4], argsp[5], argsp[6], argsp[7], 0));
}


/*
 * Set all processes in the set specified by idtype/idargv to real time
 * (if they aren't already real time) and set their real-time priority,
 * real-time quantum and real-time quantum signal to those specified by
 * rtpri, tqntm/res and rtqsig.
 */
static int
set_rtprocs(idtype_t idtype, int idargc, char **idargv, uint_t cflags,
	pri_t rtpri, long tqntm, long res, int rtqsig)
{
	pcinfo_t	pcinfo;
	uintptr_t	args[2*RT_KEYCNT+1];
	uintptr_t	*argsp = &args[0];
	pri_t		maxrtpri;
	hrtimer_t	hrtime;
	char		idtypnm[PC_IDTYPNMSZ];
	int		i;
	id_t		id;
	int		error = 0;


	/*
	 * Get the real time class ID and max configured RT priority.
	 */
	(void) strcpy(pcinfo.pc_clname, "RT");
	if (priocntl(0, 0, PC_GETCID, (caddr_t)&pcinfo) == -1)
		fatalerr("%s: Can't get RT class ID, priocntl system call"
		    " failed with errno %d\n", basenm, errno);
	maxrtpri = ((rtinfo_t *)pcinfo.pc_clinfo)->rt_maxpri;

	/*
	 * Validate the rtpri and res arguments.
	 */
	if ((cflags & RT_DOPRI) != 0) {
		if (rtpri > maxrtpri || rtpri < 0)
			fatalerr("%s: Specified real time priority %d out of"
			    " configured range\n", basenm, rtpri);
		ADDKEYVAL(argsp, RT_KY_PRI, rtpri);
	}

	if ((cflags & RT_DOTQ) != 0) {
		hrtime.hrt_secs = 0;
		hrtime.hrt_rem = tqntm;
		hrtime.hrt_res = res;
		if (_hrtnewres(&hrtime, NANOSEC, HRT_RNDUP) == -1)
			fatalerr("%s: Can't convert resolution.\n", basenm);
		ADDKEYVAL(argsp, RT_KY_TQSECS, hrtime.hrt_secs);
		ADDKEYVAL(argsp, RT_KY_TQNSECS, hrtime.hrt_rem);
	}

	if ((cflags & RT_DOSIG) != 0)
		ADDKEYVAL(argsp, RT_KY_TQSIG, rtqsig);
	*argsp = 0;

	if (idtype == P_ALL) {
		if (rt_priocntl(P_ALL, 0, PC_SETXPARMS, "RT", args) == -1) {
			if (errno == EPERM) {
				(void) fprintf(stderr,
				    "Permissions error encountered"
				    " on one or more processes.\n");
				error = 1;
			} else {
				fatalerr("%s: Can't reset real time parameters"
				    "\npriocntl system call failed with"
				    " errno %d\n", basenm, errno);
			}
		}
	} else if (idargc == 0) {
		if (rt_priocntl(idtype, P_MYID, PC_SETXPARMS, "RT",
		    args) == -1) {
			if (errno == EPERM) {
				(void) idtyp2str(idtype, idtypnm);
				(void) fprintf(stderr, "Permissions error"
				    " encountered on current %s.\n", idtypnm);
				error = 1;
			} else {
				fatalerr("%s: Can't reset real time parameters"
				    "\npriocntl system call failed with"
				    " errno %d\n", basenm, errno);
			}
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

			if (rt_priocntl(idtype, id, PC_SETXPARMS, "RT",
			    args) == -1) {
				if (errno == EPERM) {
					(void) fprintf(stderr,
					    "Permissions error encountered on"
					    " %s %s.\n", idtypnm, idargv[i]);
					error = 1;
				} else {
					fatalerr("%s: Can't reset real time"
					    " parameters\npriocntl system call"
					    " failed with errno %d\n",
					    basenm, errno);
				}
			}
		}
	}

	return (error);
}


/*
 * Execute the command pointed to by cmdargv as a real-time process
 * with real time priority rtpri, quantum tqntm/res and quantum signal rtqsig.
 */
static void
exec_rtcmd(char **cmdargv, uint_t cflags, pri_t rtpri, long tqntm, long res,
	int rtqsig)
{
	pcinfo_t	pcinfo;
	uintptr_t	args[2*RT_KEYCNT+1];
	uintptr_t	*argsp = &args[0];
	pri_t		maxrtpri;
	hrtimer_t	hrtime;

	/*
	 * Get the real time class ID and max configured RT priority.
	 */
	(void) strcpy(pcinfo.pc_clname, "RT");
	if (priocntl(0, 0, PC_GETCID, (caddr_t)&pcinfo) == -1)
		fatalerr("%s: Can't get RT class ID, priocntl system call"
		    " failed with errno %d\n", basenm, errno);
	maxrtpri = ((rtinfo_t *)pcinfo.pc_clinfo)->rt_maxpri;

	if ((cflags & RT_DOPRI) != 0) {
		if (rtpri > maxrtpri || rtpri < 0)
			fatalerr("%s: Specified real time priority %d out of"
			    " configured range\n", basenm, rtpri);
		ADDKEYVAL(argsp, RT_KY_PRI, rtpri);
	}

	if ((cflags & RT_DOTQ) != 0) {
		hrtime.hrt_secs = 0;
		hrtime.hrt_rem = tqntm;
		hrtime.hrt_res = res;
		if (_hrtnewres(&hrtime, NANOSEC, HRT_RNDUP) == -1)
			fatalerr("%s: Can't convert resolution.\n", basenm);
		ADDKEYVAL(argsp, RT_KY_TQSECS, hrtime.hrt_secs);
		ADDKEYVAL(argsp, RT_KY_TQNSECS, hrtime.hrt_rem);
	}

	if ((cflags & RT_DOSIG) != 0)
		ADDKEYVAL(argsp, RT_KY_TQSIG, rtqsig);
	*argsp = 0;

	if (rt_priocntl(P_PID, P_MYID, PC_SETXPARMS, "RT", args) == -1)
		fatalerr("%s: Can't reset real time parameters\n"
		    "priocntl system call failed with errno %d\n",
		    basenm, errno);

	(void) execvp(cmdargv[0], cmdargv);
	fatalerr("%s: Can't execute %s, exec failed with errno %d\n",
	    basenm, cmdargv[0], errno);
}

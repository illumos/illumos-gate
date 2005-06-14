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
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<string.h>
#include	<libgen.h>
#include	<unistd.h>
#include	<sys/types.h>
#include	<sys/procset.h>
#include	<sys/priocntl.h>
#include	<sys/fxpriocntl.h>
#include	<limits.h>
#include	<errno.h>

#include	"priocntl.h"

/*
 * This file contains the class specific code implementing
 * the fixed-priority priocntl sub-command.
 */

#define	ADDKEYVAL(p, k, v) { (p[0]) = (k); (p[1]) = (v); p += 2; }

#define	FX_KEYCNT	4	/* maximal number of (key, value) pairs */

/*
 * control flags
 */
#define	FX_DOUPRILIM	0x01		/* user priority limit */
#define	FX_DOUPRI	0x02		/* user priority */
#define	FX_DOTQ		0x04		/* time quantum */



static void print_fxinfo();
static int print_fxprocs();
static int set_fxprocs(idtype_t, int, char **, uint_t, pri_t, pri_t, long,
		    long);
static void exec_fxcmd(char **, uint_t, pri_t, pri_t, long, long);
static int fx_priocntl(idtype_t, id_t, int, char *, uintptr_t *);

static char usage[] =
"usage:	priocntl -l\n\
	priocntl -d [-d idtype] [idlist]\n\
	priocntl -s [-c FX] [-m fxuprilim] [-p fxupri] [-t tqntm [-r res]] \
[-i idtype] [idlist]\n\
	priocntl -e [-c FX] [-m fxuprilim] [-p fxupri] [-t tqntm [-r res]] \
command [argument(s)]\n";

static char	cmdpath[MAXPATHLEN];
static char	basenm[BASENMSZ];

int
main(int argc, char *argv[])
{
	extern char	*optarg;
	extern int	optind;

	int		c;
	int		lflag, dflag, sflag, mflag, pflag, eflag, iflag, tflag;
	int		rflag;
	pri_t		fxuprilim;
	pri_t		fxupri;
	char		*idtypnm;
	idtype_t	idtype;
	int		idargc;
	long		res;
	long		tqntm;
	uint_t		cflags;

	(void) strlcpy(cmdpath, argv[0], MAXPATHLEN);
	(void) strlcpy(basenm, basename(argv[0]), BASENMSZ);
	lflag = dflag = sflag = mflag = pflag = eflag = iflag = tflag = 0;
	rflag = 0;
	while ((c = getopt(argc, argv, "ldsm:p:ec:i:t:r:")) != -1) {
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
			fxuprilim = (pri_t)str2num(optarg, SHRT_MIN, SHRT_MAX);
			if (errno)
				fatalerr("%s: Specified user priority limit %s"
				    " out of configured range\n",
				    basenm, optarg);
			break;

		case 'p':
			pflag++;
			fxupri = (pri_t)str2num(optarg, SHRT_MIN, SHRT_MAX);
			if (errno)
				fatalerr("%s: Specified user priority %s out of"
				    " configured range\n", basenm, optarg);
			break;

		case 'e':
			eflag++;
			break;

		case 'c':
			if (strcmp(optarg, "FX") != 0)
				fatalerr("error: %s executed for %s class, %s"
				    " is actually sub-command for FX class\n",
				    cmdpath, optarg, cmdpath);
			break;

		case 'i':
			iflag++;
			idtypnm = optarg;
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

		case '?':
			fatalerr(usage);

		default:
			break;
		}
	}

	if (lflag) {
		if (dflag || sflag || mflag || pflag || eflag || iflag ||
		    tflag || rflag)
			fatalerr(usage);

		print_fxinfo();

	} else if (dflag) {
		if (sflag || mflag || pflag || eflag)
			fatalerr(usage);

		return (print_fxprocs());

	} else if (sflag) {
		if (eflag)
			fatalerr(usage);

		if (iflag) {
			if (str2idtyp(idtypnm, &idtype) == -1)
				fatalerr("%s: Bad idtype %s\n", basenm,
				    idtypnm);
		} else
			idtype = P_PID;

		cflags = (pflag ? FX_DOUPRI : 0);

		if (mflag)
			cflags |= FX_DOUPRILIM;

		if (tflag)
			cflags |= FX_DOTQ;

		if (rflag == 0)
			res = 1000;

		if (optind < argc)
			idargc = argc - optind;
		else
			idargc = 0;

		return (set_fxprocs(idtype, idargc, &argv[optind], cflags,
		    fxuprilim, fxupri, tqntm, res));

	} else if (eflag) {
		if (iflag)
			fatalerr(usage);

		cflags = (pflag ? FX_DOUPRI : 0);

		if (mflag)
			cflags |= FX_DOUPRILIM;

		if (tflag)
			cflags |= FX_DOTQ;

		if (rflag == 0)
			res = 1000;

		exec_fxcmd(&argv[optind], cflags, fxuprilim, fxupri, tqntm,
		    res);

	} else {
		fatalerr(usage);
	}
	return (0);
}


/*
 * Print our class name and the configured user priority range.
 */
static void
print_fxinfo()
{
	pcinfo_t	pcinfo;

	(void) strcpy(pcinfo.pc_clname, "FX");

	(void) printf("FX (Fixed priority)\n");

	if (priocntl(0, 0, PC_GETCID, (caddr_t)&pcinfo) == -1)
		fatalerr("\tCan't get configured FX user priority range\n");

	(void) printf("\tConfigured FX User Priority Range: 0 through %d\n",
	    ((fxinfo_t *)pcinfo.pc_clinfo)->fx_maxupri);
}


/*
 * Read a list of pids from stdin and print the user priority and user
 * priority limit for each of the corresponding processes.
 */
static int
print_fxprocs()
{
	pid_t		*pidlist;
	size_t		numread;
	int		i;
	char		clname[PC_CLNMSZ];
	uint_t		fx_tqsecs;
	int		fx_tqnsecs;
	pri_t		fx_uprilim;
	pri_t		fx_upri;
	int 		error = 0;


	/*
	 * Read a list of pids from stdin.
	 */
	if ((pidlist = read_pidlist(&numread, stdin)) == NULL)
		fatalerr("%s: Can't read pidlist.\n", basenm);

	(void) printf("FIXED PRIORITY PROCESSES:\n    PID    FXUPRILIM    "
		"FXUPRI      FXTQNTM\n");

	if (numread == 0)
		fatalerr("%s: No pids on input\n", basenm);


	for (i = 0; i < numread; i++) {
		(void) printf("%7ld", pidlist[i]);
		if (priocntl(P_PID, pidlist[i], PC_GETXPARMS, "FX",
			    FX_KY_UPRI, &fx_upri, FX_KY_UPRILIM, &fx_uprilim,
			    FX_KY_TQSECS, &fx_tqsecs, FX_KY_TQNSECS,
			    &fx_tqnsecs, 0) != -1) {
			(void) printf("    %5d       %5d", fx_uprilim, fx_upri);

			if (fx_tqnsecs == FX_TQINF)
				(void) printf("    FX_TQINF\n");
			else
				(void) printf(" %11lld\n",
				    (longlong_t)fx_tqsecs * 1000 +
				    fx_tqnsecs / 1000000);

		} else {
			error = 1;

			if (priocntl(P_PID, pidlist[i], PC_GETXPARMS, NULL,
				    PC_KY_CLNAME, clname, 0) != -1 &&
			    strcmp(clname, "FX")) {
			/*
			 * Process from some class other than fixed priority.
			 * It has probably changed class while priocntl
			 * command was executing (otherwise we wouldn't
			 * have been passed its pid).  Print the little
			 * we know about it.
			 */
			(void) printf("\tChanged to class %s while priocntl"
			    " command executing\n", clname);
			} else {
				(void) printf("\tCan't get FX user priority\n");
			}
		}
	}

	free_pidlist(pidlist);
	return (error);
}

/*
 * Call priocntl() with command codes PC_SETXPARMS or PC_GETXPARMS.
 * The first parameter behind the command code is always the class name.
 * Each parameter is headed by a key, which determines the meaning of the
 * following value. There are maximal FX_KEYCNT = 4 (key, value) pairs.
 */
static int
fx_priocntl(idtype_t idtype, id_t id, int cmd, char *clname, uintptr_t *argsp)
{
	return (priocntl(idtype, id, cmd, clname, argsp[0], argsp[1],
	    argsp[2], argsp[3], argsp[4], argsp[5], argsp[6], argsp[7], 0));
}

/*
 * Set all processes in the set specified by idtype/idargv to fixed-priority
 * (if they aren't already fixed-priority) and set their user priority limit
 * and user priority to those specified by fxuprilim and fxupri.
 */
static int
set_fxprocs(idtype_t idtype, int idargc, char **idargv, uint_t cflags,
	pri_t fxuprilim, pri_t fxupri, long tqntm, long	res)
{
	pcinfo_t	pcinfo;
	uintptr_t	args[2*FX_KEYCNT+1];
	uintptr_t	*argsp = &args[0];
	pri_t		maxupri;
	char		idtypnm[PC_IDTYPNMSZ];
	int		i;
	id_t		id;
	hrtimer_t	hrtime;
	int 		error = 0;

	/*
	 * Get the fixed priority class ID and max configured user priority.
	 */
	(void) strcpy(pcinfo.pc_clname, "FX");
	if (priocntl(0, 0, PC_GETCID, (caddr_t)&pcinfo) == -1)
		fatalerr("%s: Can't get FX class ID, priocntl system call"
		    " failed with errno %d\n", basenm, errno);
	maxupri = ((fxinfo_t *)pcinfo.pc_clinfo)->fx_maxupri;

	/*
	 * Validate the fxuprilim and fxupri arguments.
	 */
	if ((cflags & FX_DOUPRILIM) != 0) {
		if (fxuprilim > maxupri || fxuprilim < 0) {
			fatalerr("%s: Specified user priority limit %d out of"
			    " configured range\n", basenm, fxuprilim);
		}
		ADDKEYVAL(argsp, FX_KY_UPRILIM, fxuprilim);
	}

	if ((cflags & FX_DOUPRI) != 0) {
		if (fxupri > maxupri || fxupri < 0)
			fatalerr("%s: Specified user priority %d out of "
				"configured range\n", basenm, fxupri);
		ADDKEYVAL(argsp, FX_KY_UPRI, fxupri);

	}

	if (cflags & FX_DOTQ) {
		hrtime.hrt_secs = 0;
		hrtime.hrt_rem = tqntm;
		hrtime.hrt_res = res;
		if (_hrtnewres(&hrtime, NANOSEC, HRT_RNDUP) == -1)
			fatalerr("%s: Can't convert resolution.\n", basenm);
		ADDKEYVAL(argsp, FX_KY_TQSECS, hrtime.hrt_secs);
		ADDKEYVAL(argsp, FX_KY_TQNSECS, hrtime.hrt_rem);
	}

	*argsp = 0;

	if (idtype == P_ALL) {
		if (fx_priocntl(P_ALL, 0, PC_SETXPARMS, "FX", args) == -1) {
			if (errno == EPERM) {
				(void) fprintf(stderr,
					"Permissions error encountered "
					"on one or more processes.\n");
				error = 1;
			} else {
				fatalerr("%s: Can't reset fixed priority"
				    " parameters\npriocntl system call failed "
				    " with errno %d\n", basenm, errno);
			}
		} else if ((cflags & (FX_DOUPRILIM|FX_DOUPRI)) == FX_DOUPRI) {
			(void) verifyupri(idtype, 0, "FX", FX_KY_UPRILIM,
			    fxupri, basenm);
		}
	} else if (idargc == 0) {
		if (fx_priocntl(idtype, P_MYID, PC_SETXPARMS, "FX",
		    args) == -1) {
			if (errno == EPERM) {
				(void) idtyp2str(idtype, idtypnm);
				(void) fprintf(stderr, "Permissions error"
				    " encountered on current %s.\n", idtypnm);
				error = 1;
			} else {
				fatalerr("%s: Can't reset fixed priority"
				    " parameters\npriocntl system call failed"
				    " with errno %d\n", basenm, errno);
			}
		} else if ((cflags & (FX_DOUPRILIM|FX_DOUPRI)) == FX_DOUPRI &&
		    getmyid(idtype, &id) != -1) {
			(void) verifyupri(idtype, id, "FX", FX_KY_UPRILIM,
			    fxupri, basenm);
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
			}

			if (fx_priocntl(idtype, id, PC_SETXPARMS, "FX", args)
									== -1) {
				if (errno == EPERM) {
					(void) fprintf(stderr,
					    "Permissions error encountered on"
					    " %s %s.\n", idtypnm, idargv[i]);
					error = 1;
				} else {
					fatalerr("%s: Can't reset fixed "
					    "priority"
					    " parameters\npriocntl system call"
					    " failed with errno %d\n",
					    basenm, errno);
				}
			} else if ((cflags & (FX_DOUPRILIM|FX_DOUPRI)) ==
			    FX_DOUPRI) {
				(void) verifyupri(idtype, id, "FX",
				    FX_KY_UPRILIM, fxupri, basenm);
			}
		}
	}
	return (error);

}


/*
 * Execute the command pointed to by cmdargv as a fixed-priority process
 * with the user priority limit given by fxuprilim and user priority fxupri.
 */
static void
exec_fxcmd(char **cmdargv, uint_t cflags, pri_t fxuprilim, pri_t fxupri,
	long tqntm, long res)
{
	pcinfo_t	pcinfo;
	uintptr_t	args[2*FX_KEYCNT+1];
	uintptr_t	*argsp = &args[0];

	pri_t		maxupri;
	pri_t		uprilim;
	hrtimer_t	hrtime;

	/*
	 * Get the fixed priority class ID and max configured user priority.
	 */
	(void) strcpy(pcinfo.pc_clname, "FX");
	if (priocntl(0, 0, PC_GETCID, (caddr_t)&pcinfo) == -1)
		fatalerr("%s: Can't get FX class ID, priocntl system call"
		    " failed with errno %d\n", basenm, errno);
	maxupri = ((fxinfo_t *)pcinfo.pc_clinfo)->fx_maxupri;

	if ((cflags & FX_DOUPRILIM) != 0) {
		if (fxuprilim > maxupri || fxuprilim < 0)
			fatalerr("%s: Specified user priority limit %d out of"
			    " configured range\n", basenm, fxuprilim);
		ADDKEYVAL(argsp, FX_KY_UPRILIM, fxuprilim);
	}

	if ((cflags & FX_DOUPRI) != 0) {
		if (fxupri > maxupri || fxupri < 0)
			fatalerr("%s: Specified user priority %d out of"
			    " configured range\n", basenm, fxupri);
		ADDKEYVAL(argsp, FX_KY_UPRI, fxupri);
	}

	if ((cflags & FX_DOTQ) != 0) {
		hrtime.hrt_secs = 0;
		hrtime.hrt_rem = tqntm;
		hrtime.hrt_res = res;
		if (_hrtnewres(&hrtime, NANOSEC, HRT_RNDUP) == -1)
			fatalerr("%s: Can't convert resolution.\n", basenm);
		ADDKEYVAL(argsp, FX_KY_TQSECS, hrtime.hrt_secs);
		ADDKEYVAL(argsp, FX_KY_TQNSECS, hrtime.hrt_rem);

	}
	*argsp = 0;
	if (fx_priocntl(P_PID, P_MYID, PC_SETXPARMS, "FX", args) == -1)
		fatalerr("%s: Can't reset fixed priority parameters\n"
		    " priocntl system call failed with errno %d\n",
		    basenm, errno);

	if ((cflags & (FX_DOUPRILIM|FX_DOUPRI)) == FX_DOUPRI) {
		if (priocntl(P_PID, P_MYID, PC_GETXPARMS, "FX",
		    FX_KY_UPRILIM, &uprilim, 0) != -1 && fxupri > uprilim)
			(void) fprintf(stderr,
			    "%s: Specified user priority %d exceeds"
			    " limit %d; set to %d (pid %d)\n",
			    basenm, fxupri, uprilim, uprilim, (int)getpid());
	}

	(void) execvp(cmdargv[0], cmdargv);
	fatalerr("%s: Can't execute %s, exec failed with errno %d\n",
	    basenm, cmdargv[0], errno);
}

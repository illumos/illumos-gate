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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<unistd.h>
#include	<errno.h>
#include	<sys/types.h>
#include	<sys/priocntl.h>
#include	<sys/tspriocntl.h>
#include	<sys/param.h>
#include	<sys/ts.h>

#include	"dispadmin.h"

/*
 * This file contains the class specific code implementing
 * the time-sharing dispadmin sub-command.
 */

#define	BASENMSZ	16

extern char	*basename();

static void	get_tsdptbl(), set_tsdptbl();

static char usage[] =
"usage:	dispadmin -l\n\
	dispadmin -c TS -g [-r res]\n\
	dispadmin -c TS -s infile\n";

static char	basenm[BASENMSZ];
static char	cmdpath[256];


int
main(int argc, char **argv)
{
	extern char	*optarg;

	int		c;
	int		lflag, gflag, rflag, sflag;
	ulong_t		res;
	char		*infile;

	(void) strcpy(cmdpath, argv[0]);
	(void) strcpy(basenm, basename(argv[0]));
	lflag = gflag = rflag = sflag = 0;
	while ((c = getopt(argc, argv, "lc:gr:s:")) != -1) {
		switch (c) {

		case 'l':
			lflag++;
			break;

		case 'c':
			if (strcmp(optarg, "TS") != 0)
				fatalerr("error: %s executed for %s class, \
%s is actually sub-command for TS class\n", cmdpath, optarg, cmdpath);
			break;

		case 'g':
			gflag++;
			break;

		case 'r':
			rflag++;
			res = strtoul(optarg, (char **)NULL, 10);
			break;

		case 's':
			sflag++;
			infile = optarg;
			break;

		case '?':
			fatalerr(usage);

		default:
			break;
		}
	}

	if (lflag) {
		if (gflag || rflag || sflag)
			fatalerr(usage);

		(void) printf("TS\t(Time Sharing)\n");
		return (0);

	} else if (gflag) {
		if (lflag || sflag)
			fatalerr(usage);

		if (rflag == 0)
			res = 1000;

		get_tsdptbl(res);
		return (0);

	} else if (sflag) {
		if (lflag || gflag || rflag)
			fatalerr(usage);

		set_tsdptbl(infile);
		return (0);

	} else {
		fatalerr(usage);
	}
	return (1);
}


/*
 * Retrieve the current ts_dptbl from memory, convert the time quantum
 * values to the resolution specified by res and write the table to stdout.
 */
static void
get_tsdptbl(ulong_t res)
{
	int		i;
	int		tsdpsz;
	pcinfo_t	pcinfo;
	pcadmin_t	pcadmin;
	tsadmin_t	tsadmin;
	tsdpent_t	*ts_dptbl;
	hrtimer_t	hrtime;

	(void) strcpy(pcinfo.pc_clname, "TS");
	if (priocntl(0, 0, PC_GETCID, (caddr_t)&pcinfo) == -1)
		fatalerr("%s: Can't get TS class ID, priocntl system \
call failed with errno %d\n", basenm, errno);

	pcadmin.pc_cid = pcinfo.pc_cid;
	pcadmin.pc_cladmin = (char *)&tsadmin;
	tsadmin.ts_cmd = TS_GETDPSIZE;

	if (priocntl(0, 0, PC_ADMIN, (caddr_t)&pcadmin) == -1)
		fatalerr("%s: Can't get ts_dptbl size, priocntl system \
call failed with errno %d\n", basenm, errno);

	tsdpsz = tsadmin.ts_ndpents * sizeof (tsdpent_t);
	if ((ts_dptbl = (tsdpent_t *)malloc(tsdpsz)) == NULL)
		fatalerr("%s: Can't allocate memory for ts_dptbl\n", basenm);

	tsadmin.ts_dpents = ts_dptbl;

	tsadmin.ts_cmd = TS_GETDPTBL;
	if (priocntl(0, 0, PC_ADMIN, (caddr_t)&pcadmin) == -1)
		fatalerr("%s: Can't get ts_dptbl, priocntl system call \
call failed with errno %d\n", basenm, errno);

	(void) printf("# Time Sharing Dispatcher Configuration\n");
	(void) printf("RES=%ld\n\n", res);
	(void) printf("# ts_quantum  ts_tqexp  ts_slpret  ts_maxwait ts_lwait  \
PRIORITY LEVEL\n");

	for (i = 0; i < tsadmin.ts_ndpents; i++) {
		if (res != HZ) {
			hrtime.hrt_secs = 0;
			hrtime.hrt_rem = ts_dptbl[i].ts_quantum;
			hrtime.hrt_res = HZ;
			if (_hrtnewres(&hrtime, res, HRT_RNDUP) == -1)
				fatalerr("%s: Can't convert to requested \
resolution\n", basenm);
			if ((ts_dptbl[i].ts_quantum = hrtconvert(&hrtime))
			    == -1)
				fatalerr("%s: Can't express time quantum in "
				    "requested resolution,\n"
				    "try coarser resolution\n", basenm);
		}
		(void) printf("%10d%10d%10d%12d%10d        #   %3d\n",
		    ts_dptbl[i].ts_quantum, ts_dptbl[i].ts_tqexp,
		    ts_dptbl[i].ts_slpret, ts_dptbl[i].ts_maxwait,
		    ts_dptbl[i].ts_lwait, i);
	}
}


/*
 * Read the ts_dptbl values from infile, convert the time quantum values
 * to HZ resolution, do a little sanity checking and overwrite the table
 * in memory with the values from the file.
 */
static void
set_tsdptbl(infile)
char	*infile;
{
	int		i;
	int		ntsdpents;
	char		*tokp;
	pcinfo_t	pcinfo;
	pcadmin_t	pcadmin;
	tsadmin_t	tsadmin;
	tsdpent_t	*ts_dptbl;
	int		linenum;
	ulong_t		res;
	hrtimer_t	hrtime;
	FILE		*fp;
	char		buf[512];
	int		wslength;

	(void) strcpy(pcinfo.pc_clname, "TS");
	if (priocntl(0, 0, PC_GETCID, (caddr_t)&pcinfo) == -1)
		fatalerr("%s: Can't get TS class ID, priocntl system \
call failed with errno %d\n", basenm, errno);

	pcadmin.pc_cid = pcinfo.pc_cid;
	pcadmin.pc_cladmin = (char *)&tsadmin;
	tsadmin.ts_cmd = TS_GETDPSIZE;

	if (priocntl(0, 0, PC_ADMIN, (caddr_t)&pcadmin) == -1)
		fatalerr("%s: Can't get ts_dptbl size, priocntl system \
call failed with errno %d\n", basenm, errno);

	ntsdpents = tsadmin.ts_ndpents;
	if ((ts_dptbl =
	    (tsdpent_t *)malloc(ntsdpents * sizeof (tsdpent_t))) == NULL)
		fatalerr("%s: Can't allocate memory for ts_dptbl\n", basenm);

	if ((fp = fopen(infile, "r")) == NULL)
		fatalerr("%s: Can't open %s for input\n", basenm, infile);

	linenum = 0;

	/*
	 * Find the first non-blank, non-comment line.  A comment line
	 * is any line with '#' as the first non-white-space character.
	 */
	do {
		if (fgets(buf, sizeof (buf), fp) == NULL)
			fatalerr("%s: Too few lines in input table\n", basenm);
		linenum++;
	} while (buf[0] == '#' || buf[0] == '\0' ||
	    (wslength = strspn(buf, " \t\n")) == strlen(buf) ||
	    strchr(buf, '#') == buf + wslength);

	if ((tokp = strtok(buf, " \t")) == NULL)
		fatalerr("%s: Bad RES specification, line %d of input file\n",
		    basenm, linenum);
	if ((int)strlen(tokp) > 4) {
		if (strncmp(tokp, "RES=", 4) != 0)
			fatalerr("%s: Bad RES specification, \
line %d of input file\n", basenm, linenum);
		if (tokp[4] == '-')
			fatalerr("%s: Bad RES specification, \
line %d of input file\n", basenm, linenum);
		res = strtoul(&tokp[4], (char **)NULL, 10);
	} else if (strlen(tokp) == 4) {
		if (strcmp(tokp, "RES=") != 0)
			fatalerr("%s: Bad RES specification, \
line %d of input file\n", basenm, linenum);
		if ((tokp = strtok(NULL, " \t")) == NULL)
			fatalerr("%s: Bad RES specification, \
line %d of input file\n", basenm, linenum);
		if (tokp[0] == '-')
			fatalerr("%s: Bad RES specification, \
line %d of input file\n", basenm, linenum);
		res = strtoul(tokp, (char **)NULL, 10);
	} else if (strlen(tokp) == 3) {
		if (strcmp(tokp, "RES") != 0)
			fatalerr("%s: Bad RES specification, \
line %d of input file\n", basenm, linenum);
		if ((tokp = strtok(NULL, " \t")) == NULL)
			fatalerr("%s: Bad RES specification, \
line %d of input file\n", basenm, linenum);
		if ((int)strlen(tokp) > 1) {
			if (strncmp(tokp, "=", 1) != 0)
				fatalerr("%s: Bad RES specification, \
line %d of input file\n", basenm, linenum);
			if (tokp[1] == '-')
				fatalerr("%s: Bad RES specification, \
line %d of input file\n", basenm, linenum);
			res = strtoul(&tokp[1], (char **)NULL, 10);
		} else if (strlen(tokp) == 1) {
			if ((tokp = strtok(NULL, " \t")) == NULL)
				fatalerr("%s: Bad RES specification, \
line %d of input file\n", basenm, linenum);
			if (tokp[0] == '-')
				fatalerr("%s: Bad RES specification, \
line %d of input file\n", basenm, linenum);
			res = strtoul(tokp, (char **)NULL, 10);
		}
	} else {
		fatalerr("%s: Bad RES specification, line %d of input file\n",
		    basenm, linenum);
	}

	/*
	 * The remainder of the input file should contain exactly enough
	 * non-blank, non-comment lines to fill the table (ts_ndpents lines).
	 * We assume that any non-blank, non-comment line is data for the
	 * table and fail if we find more or less than we need.
	 */
	for (i = 0; i < tsadmin.ts_ndpents; i++) {

		/*
		 * Get the next non-blank, non-comment line.
		 */
		do {
			if (fgets(buf, sizeof (buf), fp) == NULL)
				fatalerr("%s: Too few lines in input table\n",
				    basenm);
			linenum++;
		} while (buf[0] == '#' || buf[0] == '\0' ||
		    (wslength = strspn(buf, " \t\n")) == strlen(buf) ||
		    strchr(buf, '#') == buf + wslength);

		if ((tokp = strtok(buf, " \t")) == NULL)
			fatalerr("%s: Too few values, line %d of input file\n",
			    basenm, linenum);

		if (res != HZ) {
			hrtime.hrt_secs = 0;
			hrtime.hrt_rem = atol(tokp);
			hrtime.hrt_res = res;
			if (_hrtnewres(&hrtime, HZ, HRT_RNDUP) == -1)
				fatalerr("%s: Can't convert specified "
				    "resolution to ticks\n", basenm);
			if ((ts_dptbl[i].ts_quantum = hrtconvert(&hrtime))
			    == -1)
				fatalerr("%s: ts_quantum value out of "
				    "valid range; line %d of input,\n"
				    "table not overwritten\n",
				    basenm, linenum);
		} else {
			ts_dptbl[i].ts_quantum = atol(tokp);
		}
		if (ts_dptbl[i].ts_quantum <= 0)
			fatalerr("%s: ts_quantum value out of valid range; "
			    "line %d of input,\ntable not overwritten\n",
			    basenm, linenum);

		if ((tokp = strtok(NULL, " \t")) == NULL || tokp[0] == '#')
			fatalerr("%s: Too few values, line %d of input file\n",
			    basenm, linenum);
		ts_dptbl[i].ts_tqexp = (short)atoi(tokp);
		if (ts_dptbl[i].ts_tqexp < 0 ||
		    ts_dptbl[i].ts_tqexp > tsadmin.ts_ndpents)
			fatalerr("%s: ts_tqexp value out of valid range; "
			    "line %d of input,\ntable not overwritten\n",
			    basenm, linenum);

		if ((tokp = strtok(NULL, " \t")) == NULL || tokp[0] == '#')
			fatalerr("%s: Too few values, line %d of input file\n",
			    basenm, linenum);
		ts_dptbl[i].ts_slpret = (short)atoi(tokp);
		if (ts_dptbl[i].ts_slpret < 0 ||
		    ts_dptbl[i].ts_slpret > tsadmin.ts_ndpents)
			fatalerr("%s: ts_slpret value out of valid range; "
			    "line %d of input,\ntable not overwritten\n",
			    basenm, linenum);

		if ((tokp = strtok(NULL, " \t")) == NULL || tokp[0] == '#')
			fatalerr("%s: Too few values, line %d of input file\n",
			    basenm, linenum);
		ts_dptbl[i].ts_maxwait = (short)atoi(tokp);
		if (ts_dptbl[i].ts_maxwait < 0)
			fatalerr("%s: ts_maxwait value out of valid range; "
			    "line %d of input,\ntable not overwritten\n",
			    basenm, linenum);

		if ((tokp = strtok(NULL, " \t")) == NULL || tokp[0] == '#')
			fatalerr("%s: Too few values, line %d of input file\n",
			    basenm, linenum);
		ts_dptbl[i].ts_lwait = (short)atoi(tokp);
		if (ts_dptbl[i].ts_lwait < 0 ||
		    ts_dptbl[i].ts_lwait > tsadmin.ts_ndpents)
			fatalerr("%s: ts_lwait value out of valid range; "
			    "line %d of input,\ntable not overwritten\n",
			    basenm, linenum);

		if ((tokp = strtok(NULL, " \t")) != NULL && tokp[0] != '#')
			fatalerr("%s: Too many values, line %d of input file\n",
			    basenm, linenum);
	}

	/*
	 * We've read enough lines to fill the table.  We fail
	 * if the input file contains any more.
	 */
	while (fgets(buf, sizeof (buf), fp) != NULL) {
		if (buf[0] != '#' && buf[0] != '\0' &&
		    (wslength = strspn(buf, " \t\n")) != strlen(buf) &&
		    strchr(buf, '#') != buf + wslength)
			fatalerr("%s: Too many lines in input table\n",
			    basenm);
	}

	tsadmin.ts_dpents = ts_dptbl;
	tsadmin.ts_cmd = TS_SETDPTBL;
	if (priocntl(0, 0, PC_ADMIN, (caddr_t)&pcadmin) == -1)
		fatalerr("%s: Can't set ts_dptbl, priocntl system call \
failed with errno %d\n", basenm, errno);
}

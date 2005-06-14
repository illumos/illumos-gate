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

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<unistd.h>
#include	<sys/types.h>
#include	<sys/priocntl.h>
#include	<sys/fxpriocntl.h>
#include	<sys/param.h>
#include	<errno.h>
#include	<sys/fx.h>

#include	"dispadmin.h"

/*
 * This file contains the class specific code implementing
 * the fixed-priority dispadmin sub-command.
 */

#define	BASENMSZ	16

extern char	*basename();

static void	get_fxdptbl(), set_fxdptbl();

static char usage[] = "usage:	dispadmin -l\n"
			    "dispadmin -c FX -g [-r res]\n"
			    "dispadmin -c FX -s infile\n";

static char	basenm[BASENMSZ];
static char	cmdpath[256];


int
main(int argc, char **argv)
{
	int		c;
	int		lflag, gflag, rflag, sflag;
	ulong_t		res;
	char		*infile;
	char 		*endp;

	(void) strcpy(cmdpath, argv[0]);
	(void) strcpy(basenm, basename(argv[0]));
	lflag = gflag = rflag = sflag = 0;
	while ((c = getopt(argc, argv, "lc:gr:s:")) != -1) {
		switch (c) {

		case 'l':
			lflag++;
			break;

		case 'c':
			if (strcmp(optarg, "FX") != 0)
				fatalerr("error: %s executed for %s class, "
				    "%s is actually sub-command for FX class\n",
				    cmdpath, optarg, cmdpath);
			break;

		case 'g':
			gflag++;
			break;

		case 'r':
			rflag++;
			errno = 0;
			res = strtoul(optarg, &endp, 10);
			if (res == 0 || errno != 0 || *endp != '\0')
				fatalerr("%s: Can't convert to requested "
				    "resolution\n", basenm);
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

		(void) printf("FX\t(Fixed Priority)\n");
		return (0);

	} else if (gflag) {
		if (sflag)
			fatalerr(usage);

		if (rflag == 0)
			res = 1000;

		get_fxdptbl(res);
		return (0);

	} else if (sflag) {
		if (rflag)
			fatalerr(usage);

		set_fxdptbl(infile);
		return (0);

	} else {
		fatalerr(usage);
	}
	return (1);
}


/*
 * Retrieve the current fx_dptbl from memory, convert the time quantum
 * values to the resolution specified by res and write the table to stdout.
 */
static void
get_fxdptbl(ulong_t res)
{
	int		i;
	int		fxdpsz;
	pcinfo_t	pcinfo;
	pcadmin_t	pcadmin;
	fxadmin_t	fxadmin;
	fxdpent_t	*fx_dptbl;
	hrtimer_t	hrtime;

	(void) strcpy(pcinfo.pc_clname, "FX");
	if (priocntl(0, 0, PC_GETCID, (caddr_t)&pcinfo) == -1)
		fatalerr("%s: Can't get FX class ID, priocntl system call "
		    "failed with errno %d\n", basenm, errno);

	pcadmin.pc_cid = pcinfo.pc_cid;
	pcadmin.pc_cladmin = (char *)&fxadmin;
	fxadmin.fx_cmd = FX_GETDPSIZE;

	if (priocntl(0, 0, PC_ADMIN, (caddr_t)&pcadmin) == -1)
		fatalerr("%s: Can't get fx_dptbl size, priocntl system call "
		    "failed with errno %d\n", basenm, errno);

	fxdpsz = fxadmin.fx_ndpents * sizeof (fxdpent_t);
	if ((fx_dptbl = (fxdpent_t *)malloc(fxdpsz)) == NULL)
		fatalerr("%s: Can't allocate memory for fx_dptbl\n", basenm);

	fxadmin.fx_dpents = fx_dptbl;

	fxadmin.fx_cmd = FX_GETDPTBL;
	if (priocntl(0, 0, PC_ADMIN, (caddr_t)&pcadmin) == -1)
		fatalerr("%s: Can't get fx_dptbl, priocntl system call "
		    "failed with errno %d\n", basenm, errno);

	(void) printf("# Fixed Priority Dispatcher Configuration\n");
	(void) printf("RES=%ld\n\n", res);
	(void) printf("# TIME QUANTUM                    PRIORITY\n");
	(void) printf("# (fx_quantum)                      LEVEL\n");

	for (i = 0; i < fxadmin.fx_ndpents; i++) {
		if (res != HZ && fx_dptbl[i].fx_quantum != FX_TQINF) {
			hrtime.hrt_secs = 0;
			hrtime.hrt_rem = fx_dptbl[i].fx_quantum;
			hrtime.hrt_res = HZ;
			if (_hrtnewres(&hrtime, res, HRT_RNDUP) == -1)
				fatalerr("%s: Can't convert to requested "
				    "resolution\n", basenm);
			if ((fx_dptbl[i].fx_quantum = hrtconvert(&hrtime))
									== -1)
				fatalerr("%s: Can't express time quantum in "
				    "requested resolution,\n"
				    "try coarser resolution\n", basenm);
		}
		(void) printf("%10d                    #      %3d\n",
		    fx_dptbl[i].fx_quantum, i);
	}
}


/*
 * Read the fx_dptbl values from infile, convert the time quantum values
 * to HZ resolution, do a little sanity checking and overwrite the table
 * in memory with the values from the file.
 */
static void
set_fxdptbl(char *infile)
{
	int		i;
	int		nfxdpents;
	char		*tokp;
	pcinfo_t	pcinfo;
	pcadmin_t	pcadmin;
	fxadmin_t	fxadmin;
	fxdpent_t	*fx_dptbl;
	int		linenum;
	ulong_t		res;
	hrtimer_t	hrtime;
	FILE		*fp;
	char		buf[512];
	int		wslength;
	char 		*endp;
	char		name[512], value[512];
	int		len;

	(void) strcpy(pcinfo.pc_clname, "FX");
	if (priocntl(0, 0, PC_GETCID, (caddr_t)&pcinfo) == -1)
		fatalerr("%s: Can't get FX class ID, priocntl system call "
		    "failed with errno %d\n", basenm, errno);

	pcadmin.pc_cid = pcinfo.pc_cid;
	pcadmin.pc_cladmin = (char *)&fxadmin;
	fxadmin.fx_cmd = FX_GETDPSIZE;

	if (priocntl(0, 0, PC_ADMIN, (caddr_t)&pcadmin) == -1)
		fatalerr("%s: Can't get fx_dptbl size, priocntl system call "
		    "failed with errno %d\n", basenm, errno);

	nfxdpents = fxadmin.fx_ndpents;
	if ((fx_dptbl =
	    (fxdpent_t *)malloc(nfxdpents * sizeof (fxdpent_t))) == NULL)
		fatalerr("%s: Can't allocate memory for fx_dptbl\n", basenm);

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

	/* LINTED - unbounded string specifier */
	if (sscanf(buf, " %[^=]=%s \n%n", name, value, &len) == 2 &&
	    name[0] != '\0' && value[0] != '\0' && len == strlen(buf)) {

		if (strcmp(name, "RES") == 0) {
			errno = 0;
			i = (int)strtol(value, &endp, 10);
			if (errno != 0 || endp == value ||
			    i < 0 || *endp != '\0')
				fatalerr("%s: Bad RES specification, "
				    "line %d of input file\n", basenm, linenum);
			else
				res = i;
		} else {
			fatalerr("%s: Bad RES specification, "
			    "line %d of input file\n", basenm, linenum);
		}
	}

	/*
	 * The remainder of the input file should contain exactly enough
	 * non-blank, non-comment lines to fill the table (fx_ndpents lines).
	 * We assume that any non-blank, non-comment line is data for the
	 * table and fail if we find more or less than we need.
	 */
	for (i = 0; i < fxadmin.fx_ndpents; i++) {

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

		fx_dptbl[i].fx_quantum = atol(tokp);
		if (fx_dptbl[i].fx_quantum <= 0) {
				fatalerr("%s: fx_quantum value out of "
				    "valid range; line %d of input,\n"
				    "table not overwritten\n", basenm, linenum);
		} else if (res != HZ) {
			hrtime.hrt_secs = 0;
			hrtime.hrt_rem = fx_dptbl[i].fx_quantum;
			hrtime.hrt_res = res;
			if (_hrtnewres(&hrtime, HZ, HRT_RNDUP) == -1)
				fatalerr("%s: Can't convert specified "
				    "resolution to ticks\n", basenm);
			if ((fx_dptbl[i].fx_quantum =
			    hrtconvert(&hrtime)) == -1)
				fatalerr("%s: fx_quantum value out of "
				    "valid range; line %d of input,\n"
				    "table not overwritten\n", basenm, linenum);
		}

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

	fxadmin.fx_dpents = fx_dptbl;
	fxadmin.fx_cmd = FX_SETDPTBL;
	if (priocntl(0, 0, PC_ADMIN, (caddr_t)&pcadmin) == -1)
		fatalerr("%s: Can't set fx_dptbl, priocntl system call failed "
		    "with errno %d\n", basenm, errno);
}

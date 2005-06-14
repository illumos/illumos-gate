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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/fss.h>
#include <sys/priocntl.h>
#include <sys/fsspriocntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "dispadmin.h"

/*
 * This file contains the class specific code implementing the fair-share
 * scheduler dispadmin sub-command.
 */

#define	BASENMSZ	16

extern char *basename();
static void getadmin(), setadmin();

static char usage[] = "usage:	dispadmin -l\n"
	"dispadmin -c FSS -g [-r res]\n"
	"dispadmin -c FSS -s infile\n";

static char basenm[BASENMSZ];
static char cmdpath[256];

int
main(int argc, char **argv)
{
	int c;
	int lflag, gflag, rflag, sflag;
	ulong_t res;
	char *infile;
	char *endp;

	(void) strcpy(cmdpath, argv[0]);
	(void) strcpy(basenm, basename(argv[0]));
	lflag = gflag = rflag = sflag = 0;
	while ((c = getopt(argc, argv, "lc:gr:s:")) != -1) {
		switch (c) {

		case 'l':
			lflag++;
			break;

		case 'c':
			if (strcmp(optarg, "FSS") != 0)
				fatalerr("error: %s executed for %s class, "
				    "%s is actually sub-command for FSS "
				    "class\n", cmdpath, optarg, cmdpath);
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

		(void) printf("FSS\t(Fair Share)\n");
		return (0);

	} else if (gflag) {
		if (lflag || sflag)
			fatalerr(usage);

		if (rflag == 0)
			res = 1000;

		getadmin(res);
		return (0);

	} else if (sflag) {
		if (lflag || gflag || rflag)
			fatalerr(usage);

		setadmin(infile);
		return (0);

	} else {
		fatalerr(usage);
	}
	return (1);
}

/*
 * Retrieve the current settings from kernel, convert the time quantum
 * value to the resolution specified by res and print out the results.
 */
static void
getadmin(ulong_t res)
{
	pcinfo_t pcinfo;
	pcadmin_t pcadmin;
	fssadmin_t fssadmin;
	hrtimer_t hrtime;
	long fss_quantum;

	(void) strcpy(pcinfo.pc_clname, "FSS");
	if (priocntl(0, 0, PC_GETCID, (caddr_t)&pcinfo) == -1)
		fatalerr("%s: Can't get FSS class ID, priocntl system call "
		    "failed (%s)\n", basenm, strerror(errno));

	pcadmin.pc_cid = pcinfo.pc_cid;
	pcadmin.pc_cladmin = (char *)&fssadmin;
	fssadmin.fss_cmd = FSS_GETADMIN;

	if (priocntl(0, 0, PC_ADMIN, (caddr_t)&pcadmin) == -1)
		fatalerr("%s: Can't get scheduler configuration, priocntl "
		    "system call failed (%s)\n", basenm, strerror(errno));

	hrtime.hrt_secs = 0;
	hrtime.hrt_rem = fssadmin.fss_quantum;
	hrtime.hrt_res = HZ;
	if (_hrtnewres(&hrtime, res, HRT_RNDUP) == -1)
		fatalerr("%s: Can't convert to requested resolution\n", basenm);
	if ((fss_quantum = hrtconvert(&hrtime)) == -1)
		fatalerr("%s: Can't express time quantum in "
		    "requested resolution,\n"
		    "try coarser resolution\n", basenm);

	(void) printf("#\n# Fair Share Scheduler Configuration\n#\n");
	(void) printf("RES=%ld\n", res);
	(void) printf("#\n# Time Quantum\n#\n");
	(void) printf("QUANTUM=%ld\n", fss_quantum);
}

/*
 * Read the scheduler settings from infile, convert the time quantum values
 * to HZ resolution, do a little sanity checking and overwrite kernel settings
 * with the values from the file.
 */
static void
setadmin(char *infile)
{
	int i;
	pcinfo_t pcinfo;
	pcadmin_t pcadmin;
	fssadmin_t fssadmin;
	int line;
	ulong_t res;
	long fss_quantum;
	hrtimer_t hrtime;
	FILE *fp;
	char buf[512];
	char *endp;
	int nparams = 0;

	(void) strcpy(pcinfo.pc_clname, "FSS");
	if (priocntl(0, 0, PC_GETCID, (caddr_t)&pcinfo) == -1)
		fatalerr("%s: Can't get FSS class ID, priocntl system call "
		    "failed (%s)\n", basenm, strerror(errno));

	if ((fp = fopen(infile, "r")) == NULL)
		fatalerr("%s: Can't open %s for input\n", basenm, infile);

	for (line = 1; fgets(buf, sizeof (buf), fp) != NULL; line++) {
		char name[512], value[512];
		int len;

		if (buf[0] == '#' || buf[0] == '\n')
			continue;
		/*
		 * Look for "name=value", with optional whitespaces on either
		 * side, terminated by a newline, and consuming the whole line.
		 */
		/* LINTED - unbounded string specifier */
		if (sscanf(buf, " %[^=]=%s \n%n", name, value, &len) == 2 &&
		    name[0] != '\0' && value[0] != '\0' && len == strlen(buf)) {

			if (strcmp(name, "RES") == 0) {
				errno = 0;
				i = (int)strtol(value, &endp, 10);
				if (errno != 0 || endp == value ||
				    i < 0 || *endp != '\0')
					fatalerr("%s, line %d: illegal "
					    "resolution value\n", infile, line);
				else
					res = i;
				nparams++;
			} else if (strcmp(name, "QUANTUM") == 0) {
				errno = 0;
				i = (int)strtol(value, &endp, 10);
				if (errno != 0 || endp == value ||
				    i < 0 || *endp != '\0')
					fatalerr("%s, line %d: illegal time "
					    "quantum value\n", infile, line);
				else
					fss_quantum = i;
				nparams++;
			} else {
				fatalerr("%s, line %d: invalid token\n",
				    infile, line);
			}
		} else {
			fatalerr("%s, line %d: syntax error\n", infile, line);
		}
	}
	if (line == 1 || nparams < 2)
		fatalerr("cannot read settings from %s\n", infile);
	if (res != HZ) {
		hrtime.hrt_secs = 0;
		hrtime.hrt_rem = fss_quantum;
		hrtime.hrt_res = res;
		if (_hrtnewres(&hrtime, HZ, HRT_RNDUP) == -1)
			fatalerr("%s: Can't convert specified "
			    "resolution to ticks\n", basenm);
		if ((fssadmin.fss_quantum = hrtconvert(&hrtime)) == -1)
			fatalerr("%s, line %d: time quantum value out of "
			    "valid range\n", infile, line);
	} else {
		fssadmin.fss_quantum = (short)fss_quantum;
	}

	pcadmin.pc_cid = pcinfo.pc_cid;
	pcadmin.pc_cladmin = (char *)&fssadmin;
	fssadmin.fss_cmd = FSS_SETADMIN;

	if (priocntl(0, 0, PC_ADMIN, (caddr_t)&pcadmin) == -1)
		fatalerr("%s: Can't set scheduler parameters, priocntl "
		    "system call failed (%s)\n", basenm, strerror(errno));
}

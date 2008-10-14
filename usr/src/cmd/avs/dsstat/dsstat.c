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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <locale.h>

#include <kstat.h>

#include "dsstat.h"
#include "multi_stats.h"

/* Globals */
int mode = 0;
int interval = 1;
int iterations = 1;
int zflag = 0;
int linesout = 0;

short hflags = HEADERS_EXL;
short dflags = 0;
short rflags = 0;
vslist_t *vs_top = NULL;

void
errout(char *msg)
{

	(void) fprintf(stderr, msg);
}

void
usage()
{
	errout(gettext(
	    "\ndsstat [-m <mode>[,<mode>]] [-f | -F] [-z] [-s <sets>] "
	    "[-r <flags>] \\\n[-d <flags>] [<interval> [<count>]]\n\n"));
}

void
help()
{
	usage();

	errout(gettext("\t"
	    "-d <flags> Specifies the statistics to be displayed\n\n"));
	errout(gettext("\t"
	    "   For 'cache' mode\n"));
	errout(gettext("\t"
	    "      Valid <flags> are 'rwfsdc', default <flags> are 'sf'\n"));
	errout(gettext("\t"
	    "      r=read, w=write, f=flags, s=summary,\n"));
	errout(gettext("\t"
	    "   only available for cache mode, need to combine with '-m'\n"));
	errout(gettext("\t"
	    "      d=destaged, c=write cancellations\n\n"));
	errout(gettext("\t"
	    "   For 'ii' mode;\n"));
	errout(gettext("\t"
	    "      Valid <flags> are 'rwtfps', default <flags> are 'sf'\n"));
	errout(gettext("\t"
	    "      r=read, w=write, t=timing, f=flags, p=percentages,\n"));
	errout(gettext("\t"
	    "      s=summary\n\n"));
	errout(gettext("\t"
	    "   For 'sndr' mode;\n"));
	errout(gettext("\t"
	    "      Valid <flags> are'rwtfpsq', default <flags> are 'spf'\n"));
	errout(gettext("\t"
	    "      r=read, w=write, t=timing, f=flags, p=percentages,\n"));
	errout(gettext("\t"
	    "      s=summary\n"));
	errout(gettext("\t"
	    "   only available for sndr mode, need to combine with '-m'\n"));
	errout(gettext("\t"
	    "      q=queue\n\n"));
	errout(gettext("\t"
	    "-f  prints field headers once for each iteration\n\n"));
	errout(gettext("\t"
	    "-F  prints field headers once, at the start of reporting\n\n"));
	errout(gettext("\t"
	    "-h  prints detailed usage message\n\n"));
	errout(gettext("\t"
	    "-m <mode>[,<mode>] where mode is, 'cache', 'ii', or 'sndr'\n\n"));
	errout(gettext("\t"
	    "   Multiple modes may be specified as a comma separated list,\n"));
	errout(gettext("\t"
	    "   or multiple -m switches may be used.\n\n"));
	errout(gettext("\t"
	    "-r <flags> specifies components to be reported\n\n"));
	errout(gettext("\t"
	    "   For 'cache' mode, this option is not used.\n\n"));
	errout(gettext("\t"
	    "   For 'ii' mode;\n"));
	errout(gettext("\t"
	    "      Valid <flags> are 'msbo', default <flags> are 'msbo'\n"));
	errout(gettext("\t"
	    "      m=master, s=shadow, b=bitmap, o=overflow\n\n"));
	errout(gettext("\t"
	    "   For 'sndr' mode;\n"));
	errout(gettext("\t"
	    "      Valid <flags> are 'nb', default <flags> are 'nb'\n"));
	errout(gettext("\t"
	    "      n=network, b=bitmap\n\n"));
	errout(gettext("\t"
	    "-s <sets> outputs specified sets\n"));
	errout(gettext("\t"
	    "    Where <sets> is a comma delimited list of set names\n\n"));
	errout(gettext("\t"
	    "-z  suppress reports with zero value (no activity)\n\n"));
	errout(gettext("\t"
	    "<interval> is the number of seconds between reports\n\n"));
	errout(gettext("\t"
	    "<count> is the number of reports to be generated\n\n"));
}

void
fail(int err, char *msg)
{
	errout(gettext("\ndsstat: "));
	errout(msg);

	usage();

	errout(gettext("For detailed usage run \"dsstat -h\"\n"));

	exit(err);
}

int
set_mode(char *user_modes)
{
	char *m;
	int local_mode = 0;

	for (m = strtok(user_modes, ","); m != NULL; m = strtok(NULL, ",")) {
		if (local_mode != 0) {
			local_mode |= MULTI;
		}

		if (strncasecmp("sndr", m, strlen(m)) == 0) {
			local_mode |= SNDR;
			continue;
		}

		if (strncasecmp("ii", m, strlen(m)) == 0) {
			local_mode |= IIMG;
			continue;
		}

		if (strncasecmp("cache", m, strlen(m)) == 0) {
			local_mode |= SDBC;
			continue;
		}

		fail(DSSTAT_EINVAL, gettext("Invalid mode specified"));
	}

	return (local_mode);
}

short
set_dflags(char *flags)
{
	int index;
	short user_dflags = 0;

	for (index = 0; index < strlen(flags); index++) {
		switch (flags[index]) {
			case 'r':
				user_dflags |= READ;
				break;
			case 'w':
				user_dflags |= WRITE;
				break;
			case 't':
				user_dflags |= TIMING;
				break;
			case 'f':
				user_dflags |= FLAGS;
				break;
			case 'p':
				user_dflags |= PCTS;
				break;
			case 's':
				user_dflags |= SUMMARY;
				break;
			case 'd':
				user_dflags |= DESTAGED;
				break;
			case 'c':
				user_dflags |= WRCANCEL;
				break;
			case 'h':
				user_dflags |= RATIO;
				break;
			case 'q':
				user_dflags |= ASYNC_QUEUE;
				break;
			default:
				fail(DSSTAT_EINVAL,
				    gettext("Invalid display-flags set\n"));
		}
	}

	return (user_dflags);
}

short
set_rflags(char *flags)
{
	int index;
	short user_rflags = 0;

	for (index = 0; index < strlen(flags); index++) {
		switch (flags[index]) {
			case 'm':
				user_rflags |= IIMG_MST;
				break;
			case 's':
				user_rflags |= IIMG_SHD;
				break;
			case 'b':
				user_rflags |= IIMG_BMP;
				user_rflags |= SNDR_BMP;
				break;
			case 'o':
				user_rflags |= IIMG_OVR;
				break;
			case 'n':
				user_rflags |= SNDR_NET;
				break;
			default:
				fail(DSSTAT_EINVAL,
				    gettext("Invalid report-flags set\n"));
		}
	}

	return (user_rflags);
}

void
set_vol_list(char *list)
{
	vslist_t *pre;
	vslist_t *newvol;
	vslist_t *vslist;
	char *volume;

	for (volume = strtok(list, ","); volume != NULL;
	    volume = strtok(NULL, ",")) {
		int dup = 0;
		char *vh = NULL;
		char *vn = NULL;

		/* get user-specified set information */
		if ((vn = strchr(volume, ':')) == NULL) {
			vn = volume;
		} else {
			*vn = '\0';
			vn++;
			vh = volume;
		}

		/* check for duplicates */
		dup = 0;

		for (vslist = vs_top; vslist != NULL; vslist = vslist->next) {
			if (vslist->volhost && vh) {
				if (strcmp(vslist->volhost, vh) == 0 &&
				    strcmp(vslist->volname, vn) == 0)
					dup = 1;
			} else {
				if (strcmp(vslist->volname, vn) == 0)
					dup = 1;
			}

			pre = vslist;
		}

		if (dup)
			continue;

		/* initialize new vslist record */
		newvol = (vslist_t *)calloc(1, sizeof (vslist_t));

		newvol->volname = (char *)calloc((strlen(vn) + 1),
			sizeof (char));
		strcpy(newvol->volname, vn);

		if (vh == NULL)
			goto save;

		newvol->volhost = (char *)calloc((strlen(vh) + 1),
			sizeof (char));
		strcpy(newvol->volhost, vh);

save:
		/* save record */
		if (vs_top == NULL) {
			vslist = vs_top = newvol;
			vslist->next = NULL;
			continue;
		}

		if (vslist == NULL) {
			vslist = pre->next = newvol;
			vslist->next = NULL;
			continue;
		}
	}
}

int
main(int argc, char **argv)
{
	extern char *optarg;
	extern int optind;

	int c;
	int error;
	short user_dflags = 0;
	short user_rflags = 0;

	/* Parse command line */
	while ((c = getopt(argc, argv, "d:fFhm:r:s:z")) != EOF) {
		switch (c) {
			case 'd':	/* what to display */
				user_dflags = set_dflags(optarg);
				break;
			case 'f':
				hflags = HEADERS_ATT;
				break;
			case 'F':
				hflags = HEADERS_BOR;
				break;
			case 'h':		/* usage */
				help();
				exit(0);
				break;
			case 'm':		/* Mode */
				mode |= set_mode(optarg);
				break;
			case 'r':		/* what to report on */
				user_rflags = set_rflags(optarg);
				break;
			case 's':
				set_vol_list(optarg);
				break;
			case 'z':
				zflag = 1;
				break;

			default:
				fail(DSSTAT_EINVAL,
				    "Invalid argument specified\n");
		}
	}

	/* Parse additional arguments */
	if (optind < argc) {
		if ((interval = atoi(argv[optind])) <= 0) {
			fail(DSSTAT_EINVAL,
			    gettext("Invalid interval specified.\n"));
		} else {
			iterations = -1;
		}

		optind++;

		if (optind < argc) {
			if ((iterations = atoi(argv[optind])) <= 0) {
				fail(DSSTAT_EINVAL,
				    gettext("Invalid count specified.\n"));
			}
		}

		optind++;
	}

	if (optind < argc) {
		fail(DSSTAT_EINVAL,
		    gettext("Too many parameters specified.\n"));
	}

	if (mode == 0)
		mode |= MULTI | IIMG | SNDR | SDBC;

	/* Select statistics to gather */
	if (mode & SNDR) {
		if (! (mode & MULTI)) {
			if (user_rflags & IIMG_BMP)
				user_rflags ^= IIMG_BMP;

			if ((user_dflags | SNDR_DIS_MASK) != SNDR_DIS_MASK) {
				fail(DSSTAT_EINVAL, gettext("Invalid "
				    "display-flags for RemoteMirror\n"));
			}

			if ((user_rflags | SNDR_REP_MASK) != SNDR_REP_MASK) {
				fail(DSSTAT_EINVAL,
				    gettext("Invalid report-flags for "
					    "Remote Mirror\n"));
			}
		}

		if ((mode & MULTI) && (user_dflags & ASYNC_QUEUE)) {
			fail(DSSTAT_EINVAL, gettext("Remote Mirror async. queue"
			    "statistics can not be displayed with mutiple "
			    "modes."));
		}

		if (user_dflags)
			dflags = user_dflags;
		else
			dflags |= (SUMMARY | PCTS | FLAGS | RATIO);

		if (user_rflags)
			rflags = user_rflags;
		else
			rflags |= (SNDR_NET | SNDR_BMP);
	}

	if (mode & IIMG) {
		if (! (mode & MULTI)) {
			if (user_rflags & SNDR_BMP)
				user_rflags ^= SNDR_BMP;

			if ((user_dflags | IIMG_DIS_MASK) != IIMG_DIS_MASK) {
				fail(DSSTAT_EINVAL,
				    gettext("Invalid display-flags for "
					    "Point-in-Time Copy\n"));
			}

			if ((user_rflags | IIMG_REP_MASK) != IIMG_REP_MASK) {
				fail(DSSTAT_EINVAL,
				    gettext("Invalid report-flags for "
					    "Point-in-Time Copy\n"));
			}
		}

		if (user_dflags)
			dflags = user_dflags;
		else
			dflags |= (SUMMARY | PCTS | FLAGS | RATIO);

		if (user_rflags)
			rflags = user_rflags;
		else
			rflags |= (IIMG_MST | IIMG_SHD | IIMG_BMP | IIMG_OVR);
	}

	if (mode & SDBC) {
		if (! (mode & MULTI)) {
			if ((user_dflags | CACHE_DIS_MASK) != CACHE_DIS_MASK) {
				fail(DSSTAT_EINVAL, gettext("Invalid "
				    "display-flags for CACHE\n"));
			}

			if ((user_rflags | CACHE_REP_MASK) != CACHE_REP_MASK) {
				fail(DSSTAT_EINVAL, gettext("Invalid "
				    "report-flags for CACHE\n"));
			}
		} else {
		    if ((user_dflags & DESTAGED) || (user_dflags & WRCANCEL)) {
			if (user_dflags & DESTAGED)
			    fail(DSSTAT_EINVAL, gettext("Cache, destaged "
				"statistics can not be displayed with mutiple "
				"modes."));
			else
			    fail(DSSTAT_EINVAL, gettext("Cache, write "
				"cancellations "
				"statistics can not be displayed with mutiple "
				"modes."));
		    }
		}

		if (user_dflags)
			dflags = user_dflags;
		else
			if (mode & MULTI)
				dflags |= (SUMMARY);
			else
				dflags |= (SUMMARY | FLAGS);

		if (user_rflags)
			rflags = user_rflags;
		else
			rflags |= user_rflags;
	}

	error = do_stats();

	if (error == EAGAIN) {
		fail(DSSTAT_NOSTAT, gettext("No statistics available for the "
		    "specified mode(s).\n"));
	}

	if (error == EINVAL) {
		fail(DSSTAT_EINVAL,
		    gettext("Invalid kstat format detected.\n"));
	}

	if (error == ENOMEM) {
		fail(DSSTAT_ENOMEM,
		    gettext("Unable to open kstat device for reading.\n"));
	}

	if (error == -1) {
		if (execv("/usr/sbin/dsstat", argv) != 0) {
			fail(DSSTAT_EMAP, gettext("Kstat is invalid.\n"));
		}
	}

	if (error) {
		fail(DSSTAT_EUNKNWN, gettext("An unknown error occured.\n"));
	}

	return (0);
}

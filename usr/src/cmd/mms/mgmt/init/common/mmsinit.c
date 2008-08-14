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

#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <libnvpair.h>
#include <fcntl.h>

#include "mms_trace.h"
#include "mms_mgmt.h"
#include "mgmt_util.h"
#include "mms_cfg.h"

extern char *optarg;
extern int optind, opterr, optopt;


#ifdef	MMS_VAR_CFG
static char *usemsg = 	\
"Usage:  \n\
\tmmsinit [-?|-h]\n\
\tmmsinit -t server -o options [-P passwordfile]\n\
\tmmsinit -t client -M serverhost[:port] [-P passwordfile]\n\
\tmmsinit -u\n";
#else
static char *usemsg = \
"Usage: \n\
\tmmsinit [-h|-?]\n\
\tmmsinit -t server -o options [-P passwordfile]\n";
#endif	/* MMS_VAR_CFG */

#ifdef	MMS_VAR_CFG
static int uflag = 0;
#endif	/* MMS_VAR_CFG */
static int hflag = 0;

static char *mmsinit_opts = ":M:P:t:o:fuv?";

static char *passphrases[2] = {
	"Enter MMS Administrative password: ",
	"Re-enter password: "
};


static struct option mmsinit_long[] = {
	{"mmhost", required_argument, NULL, 'M'},
	{"passfile", required_argument, NULL, 'P'},
	{"type", required_argument, NULL, 't'},
	{"force", no_argument, NULL, 'f'},
	{"options", required_argument, NULL, 'o'},
	{"uninit", no_argument, NULL, 'u'},
	{"verbose", no_argument, NULL, 'v'},
	{"help", no_argument, NULL, '?'},
	{NULL, 0, NULL, 0}
};

static void usage(void);

int
main(int argc, char **argv)
{
	int		st = 0;
	int		mmsind = 0;
	char		c;
	char		*mmtype = "server";
#ifdef	MMS_VAR_CFG
	char		*mmhost = "localhost";
	char		*mmport = "7151";
	char		*bufp;
	boolean_t	force = B_FALSE;
#endif
	char		*pwfile = NULL;
	nvlist_t	*mmnv = NULL;
	nvlist_t	*errlist = NULL;
	char		buf[2048];

	(void) mms_trace_open("/var/log/mms/mmsinit.log", MMS_ID_CLI,
	    MMS_SEV_INFO, 5 * MEGA, 0, 0);

	if (argc < 2) {
		st = 1;
	}

	memset(buf, 0, sizeof (buf));

	st = nvlist_alloc(&mmnv, NV_UNIQUE_NAME, 0);
	if (st != 0) {
		return (st);
	}

	while (st == 0) {
		c = getopt_clip(argc, argv, mmsinit_opts, mmsinit_long,
		    &mmsind);

		/* catch end-of-args */
		if (c == -1) {
			break;
		}

		switch (c) {
			case 0:
				/* flag set by getopt */
				break;
			case 't':
				mmtype = optarg;
#ifdef	MMS_VAR_CFG
				if (*mmtype == 'c') {
					st = nvlist_add_string(mmnv, O_OBJTYPE,
					    "client");
				} else if (*mmtype == 's') {
					st = nvlist_add_string(mmnv, O_OBJTYPE,
					    "server");
				} else {
					st = 1;
					fprintf(stderr, "Invalid type: %s\n",
					    mmtype);
				}
#else
				if (*mmtype != 's') {
					fprintf(stderr,
					    "Type must be 'server'\n");
					st = 1;
				}
#endif	/* MMS_VAR_CFG */
				break;
#ifdef	MMS_VAR_CFG
			case 'f':
				force = B_TRUE;
				break;
			case 'M':
				mmhost = optarg;
				bufp = strchr(mmhost, ':');
				if (bufp == NULL) {
					mmport = MMS_DEF_MMPORT;
				} else {
					*bufp = '\0';
					mmport = ++bufp;
				}

				if (strcmp(mmhost, "localhost") == 0) {
					gethostname(buf, sizeof (buf));

					st = nvlist_add_string(mmnv, O_MMHOST,
					    buf);
				} else {
					st = nvlist_add_string(mmnv, O_MMHOST,
					    mmhost);
				}
				if (st != 0) {
					break;
				}

				st = nvlist_add_string(mmnv, O_MMPORT, mmport);

				break;
#endif	/* MMS_VAR_CFG */
			case 'P':
				pwfile = optarg;
				break;
			case 'o':
				st = mgmt_opt_to_var(optarg, B_FALSE, mmnv);

				break;
#ifdef	MMS_VAR_CFG
			case 'u':
				uflag++;
				break;
#endif	/* MMS_VAR_CFG */
			case '?':
				hflag++;
				break;
			case ':':
				fprintf(stderr,
				    "Option %s requires an operand\n",
				    argv[optind-1]);
				st = 1;
				break;
			default:
				st = 1;
				break;
		}
	}

	if ((st != 0) || hflag) {
		usage();
		goto done;
	}

#ifdef	MMS_VAR_CFG
	if (uflag) {
		char	yesno = 'n';

		/* remove everything except the DB */
		if ((!isatty(STDIN_FILENO)) && !force) {
			fprintf(stderr,
			    "To uninitialize from a script, "
			    "please use the -f option.\n");
			st = 1;
			goto done;
		}
		fprintf(stdout,
		    "Do you really want to stop using MMS services on "
		    "this system? [y|n] ");

		yesno = fgetc(stdin);
		if ((yesno == 'y') || (yesno == 'Y')) {
			st = mms_mgmt_uninitialize();
		} else {
			fprintf(stdout,
			    "Uninitialize will not be performed.\n");
		}
		goto done;
	}

	/* check to see if this host has already been initialized first */
	st = mms_cfg_getvar(MMS_CFG_CONFIG_TYPE, buf);
	if ((st == 0) && (buf[0] != '\0')) {
		st = EALREADY;
		goto done;
	} else {
		st = 0;
	}

	if (!mmtype) {
		fprintf(stdout,
		    "Either -t client or -t server must be specified.\n");
		st = 1;
		goto done;
	}
#endif	/* MMS_VAR_CFG */

	st = nvlist_add_string(mmnv, O_OBJTYPE, mmtype);

	/*  Prompt the user for the MM password or read it from a file */
	st = mms_mgmt_get_pwd(pwfile, O_MMPASS, passphrases, mmnv, errlist);
	if (st != 0) {
		fprintf(stderr, "%s\n", mms_mgmt_get_errstr(st));
		goto done;
	}

#ifdef	MMS_VAR_CFG
	if (*mmtype == 's') {
		/* set mmhost to localhost */
		gethostname(buf, sizeof (buf));
		nvlist_add_string(mmnv, O_MMHOST, buf);
	}
#endif	/* MMS_VAR_CFG */

	if (st != 0) {
		goto done;
	}

	st = mms_mgmt_init_host(mmnv, &errlist);

done:
	if (st != 0) {
		if (st == EOPNOTSUPP) {
			fprintf(stderr,
			    "Cannot change MMS host type.  To change ");
			fprintf(stderr,
			    "this value, first run 'mmsinit -u'.\n");
		} else if (st == EALREADY) {
			fprintf(stderr,
			    "\nMMS already initialized on this system.\nTo ");
			fprintf(stderr,
			    "change options, use the 'mmsadm set' command.\n");
		} else if (errlist) {
			nvpair_t	*nv = nvlist_next_nvpair(errlist, NULL);
			char		*nvo = NULL;
			int		nvl = 0;
			const char	*errmsg = NULL;

			while (nv != NULL) {
				nvo = nvpair_name(nv);
				(void) nvpair_value_int32(nv, &nvl);
				errmsg = mms_mgmt_get_errstr(nvl);
				if (errmsg != NULL) {
					fprintf(stderr, "\t%s\t%s\n", nvo,
					    errmsg);
				} else {
					fprintf(stderr, "\t%s\terrno = %d\n",
					    nvo, nvl);
				}

				nv = nvlist_next_nvpair(errlist, nv);
			}
		}
	}

	if (errlist) {
		nvlist_free(errlist);
	}

	if (mmnv) {
		nvlist_free(mmnv);
	}

	if (st != 0) {
		fprintf(stderr, "mmsinit exiting with error %d\n", st);
	}

	mms_trace_close();

	return (st);
}

static void
usage(void)
{
	printf("%s\n", usemsg);
}

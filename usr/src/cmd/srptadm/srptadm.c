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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <strings.h>
#include <ctype.h>
#include <libnvpair.h>
#include <libintl.h>
#include <libgen.h>
#include <pwd.h>
#include <auth_attr.h>
#include <secdb.h>
#include <libscf.h>
#include <limits.h>
#include <locale.h>
#include <dirent.h>

#include <libstmf.h>
#include <libsrpt.h>

/* SMF service info */
#define	STMF_SVC	"svc:/system/stmf:default"

#define	STMF_STALE(ret) {\
	if (ret == STMF_ERROR_PROV_DATA_STALE) {\
		(void) fprintf(stderr, "%s\n",\
		    gettext("Configuration changed during processing.  "\
		    "Check the configuration, then retry this command "\
		    "if appropriate."));\
	}\
}

#define	SRPTADM_CHKAUTH(sec) {\
	if (!chkauthattr(sec, srptadm_uname)) {\
		(void) fprintf(stderr,\
		    gettext("Error, operation requires authorization %s"),\
		    sec);\
		(void) fprintf(stderr, "\n");\
		return (1);\
	}\
}

#define	PROPS_FORMAT	"    %-20s: "

static struct option srptadm_long[] = {
	{"enable",		no_argument,		NULL, 'e'},
	{"disable",		no_argument,		NULL, 'd'},
	{"reset",		no_argument,		NULL, 'r'},
	{"help",		no_argument,		NULL, '?'},
	{"help",		no_argument,		NULL, 'h'},
	{NULL, 0, NULL, 0}
};

static char m_def[] = "srptadm modify-defaults [-e] [-d]";
static char l_def[] = "srptadm list-defaults";
static char s_tgt[] = "srptadm modify-target [-e] [-d] [-r] <hca>";
static char l_tgt[] = "srptadm list-target [<hca>]";

/* keep the order of this enum in the same order as the 'subcmds' struct */
typedef enum {
	MODIFY_DEFAULT,
	LIST_DEFAULT,
	MODIFY_TARGET,
	LIST_TARGET,
	NULL_SUBCMD	/* must always be last! */
} srptadm_sub_t;

typedef struct {
	char		*name;
	char		*shortopts;
	char		*usemsg;
} srptadm_subcmds_t;

static srptadm_subcmds_t	subcmds[] = {
	{"modify-defaults", "edh?", m_def},
	{"list-defaults", "h?", l_def},
	{"modify-target", "edrh?", s_tgt},
	{"list-target", "h?", l_tgt},
	{NULL, ":h?", NULL},
};

/* used for checking if user is authorized */
static char *srptadm_uname = NULL;

/* prototypes */
static int get_local_hcas(char **hcaArray, int count);
static int print_target_props(char *hca);
static int list_target(char *hca);
static int disable_target(char *hca);
static int reset_target(char *hca);
static int list_defaults(void);
static int enable_target(char *hca);
static int set_default_state(boolean_t enabled);

int
main(int argc, char *argv[])
{
	int		ret = 0;
	int		idx = NULL_SUBCMD;
	char		c;
	int		newargc = argc;
	char		**newargv = NULL;
	char		*objp;
	int		srptind = 0;
	struct passwd	*pwd = NULL;
	char		*smfstate = NULL;
	boolean_t	reset = B_FALSE;
	int		dflag = 0;
	int		eflag = 0;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if (argc < 2) {
		ret = 1;
		goto usage_error;
	}

	for (idx = 0; subcmds[idx].name != NULL; idx++) {
		if (strcmp(argv[1], subcmds[idx].name) == 0) {
			break;
		}
	}

	/* get the caller's user name for subsequent chkauthattr() calls */
	pwd = getpwuid(getuid());
	if (pwd == NULL) {
		(void) fprintf(stderr, "%s\n",
		    gettext("Could not determine callers user name."));
		return (1);
	}

	srptadm_uname = strdup(pwd->pw_name);

	/* increment past command & subcommand */
	newargc--;
	newargv = &(argv[1]);

	while ((ret == 0) && (newargv)) {
		c = getopt_long(newargc, newargv, subcmds[idx].shortopts,
		    srptadm_long, &srptind);
		if (c == -1) {
			break;
		}

		switch (c) {
			case 0:
				/* flag set by getopt */
				break;
			case 'd':
				dflag++;
				break;
			case 'e':
				eflag++;
				break;
			case 'r':
				reset = B_TRUE;
				break;
			case '?':
				/*
				 * '?' is returned for both unrecognized
				 * options and if explicitly provided on
				 * the command line.  The latter should
				 * be handled the same as -h.
				 */
				if (strcmp(newargv[optind-1], "-?") != 0) {
					(void) fprintf(stderr,
					    gettext("Unrecognized option %s"),
					    newargv[optind-1]);
					(void) fprintf(stderr, "\n");
					ret = 1;
				}
				goto usage_error;
			case 'h':
				goto usage_error;
			case ':':
				(void) fprintf(stderr,
				    gettext("Option %s requires an operand."),
				    newargv[optind-1]);
				(void) fprintf(stderr, "\n");

				/* FALLTHROUGH */
			default:
				ret = 1;
				break;
		}
	}

	if (ret != 0) {
		goto usage_error;
	}

	/* after getopt() to allow handling of -h option */
	if ((srptadm_sub_t)idx == NULL_SUBCMD) {
		(void) fprintf(stderr, "%s\n",
		    gettext("Error, no subcommand specified"));
		ret = 1;
		goto usage_error;
	}

	newargc -= optind;
	if (newargc == 0) {
		newargv = NULL;
		objp = NULL;
	} else {
		newargv = &(newargv[optind]);
		objp = newargv[0];
	}

	if (objp == NULL) {
		switch ((srptadm_sub_t)idx) {
		case MODIFY_TARGET:
			/* These subcommands need operands */
			ret = 1;
			goto usage_error;
		default:
			break;
		}
	}

	if (newargc > 1) {
		switch ((srptadm_sub_t)idx) {
		case MODIFY_TARGET:
		case LIST_TARGET:
			/* These subcommands should have at most one operand */
			ret = 1;
			goto usage_error;

		default:
			break;
		}
	}


	/*
	 * Make sure STMF service is enabled before proceeding.
	 */
	smfstate = smf_get_state(STMF_SVC);
	if (!smfstate ||
	    (strcmp(smfstate, SCF_STATE_STRING_ONLINE) != 0)) {
		(void) fprintf(stderr, "%s\n",
		    gettext("The STMF service must be online "
		    "before running this command."));
		(void) fprintf(stderr,
		    gettext("Use 'svcadm enable -r %s'"), STMF_SVC);
		(void) fprintf(stderr, "\n");
		(void) fprintf(stderr, "%s\n",
		    gettext("to enable the service and its prerequisite "
		    "services and/or"));
		(void) fprintf(stderr,
		    gettext("'svcs -x %s' to determine why it is not online."),
		    STMF_SVC);
		(void) fprintf(stderr, "\n");

		return (1);
	}

	switch ((srptadm_sub_t)idx) {
		case MODIFY_DEFAULT:
			if (eflag) {
				ret = set_default_state(B_TRUE);
			} else if (dflag) {
				ret = set_default_state(B_FALSE);
			} else {
				ret = 1;
				goto usage_error;
			}
			break;
		case LIST_DEFAULT:
			ret = list_defaults();
			break;
		case MODIFY_TARGET:
			if (reset) {
				ret = reset_target(objp);
			} else if (eflag) {
				ret = enable_target(objp);
			} else if (dflag) {
				ret = disable_target(objp);
			} else {
				ret = 1;
				goto usage_error;
			}
			break;
		case LIST_TARGET:
			ret = list_target(objp);
			break;
		default:
			ret = 1;
			goto usage_error;
	}

	if (ret != 0) {
		(void) fprintf(stderr,
		    gettext("srptadm %s failed with error %d"),
		    subcmds[idx].name, ret);
		(void) fprintf(stderr, "\n");
	}
	return (ret);

usage_error:
	if (subcmds[idx].name) {
		(void) printf("%s\n", gettext(subcmds[idx].usemsg));
	} else {
		/* overall usage */
		(void) printf("%s\n\n", gettext("srptadm usage:"));
		for (idx = 0; subcmds[idx].name != NULL; idx++) {
			if (!subcmds[idx].usemsg) {
				continue;
			}
			(void) printf("\t%s\n", gettext(subcmds[idx].usemsg));
		}
	}

	return (ret);
}

static int
set_default_state(boolean_t enabled)
{
	int		ret;
	char		*sec = "solaris.smf.modify.stmf";

	SRPTADM_CHKAUTH(sec);

	ret = srpt_SetDefaultState(enabled);

	return (ret);
}

static int
enable_target(char *hca)
{
	int		ret;
	char		*sec = "solaris.smf.modify.stmf";

	SRPTADM_CHKAUTH(sec);

	ret = srpt_SetTargetState(hca, B_TRUE);

	return (ret);
}

static int
disable_target(char *hca)
{
	int		ret;
	char		*sec = "solaris.smf.modify.stmf";

	SRPTADM_CHKAUTH(sec);

	ret = srpt_SetTargetState(hca, B_FALSE);

	return (ret);
}

static int
reset_target(char *hca)
{
	int		ret;
	char		*sec = "solaris.smf.modify.stmf";

	SRPTADM_CHKAUTH(sec);

	ret = srpt_ResetTarget(hca);

	return (ret);
}

static int
list_defaults(void)
{
	int		ret;
	char		*sec = "solaris.smf.read.stmf";
	boolean_t	enabled;

	SRPTADM_CHKAUTH(sec);

	/* only state set as default for now */
	ret = srpt_GetDefaultState(&enabled);

	if (ret == 0) {
		(void) printf("%s:\n\n",
		    gettext("SRP Target Service Default Properties"));

		(void) printf("    %s:\t",
		    gettext("Target creation enabled by default"));

		if (enabled) {
			(void) printf("%s\n", gettext("true"));
		} else {
			(void) printf("%s\n", gettext("false"));
		}
	}

	return (ret);
}

static int
list_target(char *hca)
{
	int		ret;
	char		*sec = "solaris.smf.read.stmf";
	char		*hcaArr[1024];	/* way bigger than we'll ever see */
	int		i;

	SRPTADM_CHKAUTH(sec);

	if (hca != NULL) {
		ret = print_target_props(hca);
		return (ret);
	}

	/* get list of HCAs configured on this system, from /dev/cfg */
	(void) memset(&hcaArr, 0, 1024 * sizeof (char *));

	ret = get_local_hcas(hcaArr, sizeof (hcaArr));
	if (ret == ETOOMANYREFS) {
		(void) fprintf(stderr, "Internal error:  too many HCAs\n");
		goto done;
	} else if (ret != 0) {
		(void) fprintf(stderr, "Error getting list of HCAs: %d\n", ret);
		goto done;
	}

	for (i = 0; i < 1024; i++) {
		if (hcaArr[i] == NULL) {
			break;
		}
		ret = print_target_props(hcaArr[i]);
	}

done:
	for (i = 0; i < 1024; i++) {
		if (hcaArr[i] == NULL) {
			break;
		}
		free(hcaArr[i]);
	}

	return (ret);
}

static int
print_target_props(char *hca)
{
	int		ret;
	boolean_t	enabled;
	char		buf[32];
	char		euibuf[64];
	uint64_t	hcaguid;
	stmfDevid	devid;
	stmfTargetProperties	props;
	char		*state;

	ret = srpt_NormalizeGuid(hca, buf, sizeof (buf), &hcaguid);
	if (ret != 0) {
		(void) fprintf(stderr, "Invalid target HCA: %s\n",
		    hca);
		return (ret);
	}

	/* only property set is enabled */
	ret = srpt_GetTargetState(buf, &enabled);
	if (ret != 0) {
		(void) fprintf(stderr,
		    "Could not get enabled state for %s: %d\n",
		    buf, ret);
		return (ret);
	}

	(void) printf("Target HCA %s:\n", buf);

	(void) printf(PROPS_FORMAT, gettext("Enabled"));

	if (enabled) {
		(void) printf("%s\n", gettext("true"));
	} else {
		(void) printf("%s\n", gettext("false"));
	}

	state = "-";

	(void) snprintf(euibuf, sizeof (euibuf), "eui.%016llX", hcaguid);

	ret = stmfDevidFromIscsiName(euibuf, &devid);
	if (ret == STMF_STATUS_SUCCESS) {
		ret = stmfGetTargetProperties(&devid, &props);
		if (ret == STMF_STATUS_SUCCESS) {
			if (props.status == STMF_TARGET_PORT_ONLINE) {
				state = "online";
			} else {
				state = "offline";
			}
		}
	}

	(void) printf(PROPS_FORMAT, gettext("SRP Target Name"));
	(void) printf("%s\n", euibuf);
	(void) printf(PROPS_FORMAT, gettext("Operational Status"));
	(void) printf("%s\n", state);

	(void) printf("\n");

	return (0);
}


static int
get_local_hcas(char **hcaArray, int count)
{
	int		ret = 0;
	char		*cfgdir = "/dev/cfg";
	DIR		*dirp = NULL;
	struct dirent	*entry;
	int		idx = 0;
	char		*bufp;

	if ((hcaArray == NULL) || (count == 0)) {
		return (EINVAL);
	}

	dirp = opendir(cfgdir);

	if (dirp == NULL) {
		ret = errno;
		(void) fprintf(stderr, "Could not open %s: errno %d\n",
		    cfgdir, ret);
		return (ret);
	}

	while ((entry = readdir(dirp)) != NULL) {
		bufp = &entry->d_name[0];

		if (strncmp(bufp, "hca:", 4) != 0) {
			continue;
		}

		bufp += 4;

		hcaArray[idx] = strdup(bufp);
		if (hcaArray[idx] == NULL) {
			ret = ENOMEM;
			break;
		}
		idx++;

		if (idx >= count) {
			ret = ETOOMANYREFS;
			break;
		}
	}

	return (ret);
}

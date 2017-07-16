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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
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

#include <libstmf.h>
#include <libiscsit.h>

/* what's this used for?? */
#define	ITADM_VERSION	"1.0"

/* SMF service info */
#define	ISCSIT_SVC	"svc:/network/iscsi/target:default"

#define	STMF_STALE(ret) {\
	if (ret == STMF_ERROR_PROV_DATA_STALE) {\
		output_config_error(ret, NULL);\
	} else if (ret != 0) {\
		output_config_error(ret,\
		    gettext("Configuration change failed"));\
	}\
}

#define	ITADM_CHKAUTH(sec) {\
	if (!chkauthattr(sec, itadm_uname)) {\
		(void) fprintf(stderr,\
		    gettext("Error, operation requires authorization %s"),\
		    sec);\
		(void) fprintf(stderr, "\n");\
		return (1);\
	}\
}


static struct option itadm_long[] = {
	{"alias",		required_argument,	NULL, 'l'},
	{"auth-method",		required_argument,	NULL, 'a'},
	{"chap-secret",		no_argument,		NULL, 's'},
	{"chap-secret-file",	required_argument,	NULL, 'S'},
	{"chap-user",		required_argument,	NULL, 'u'},
	{"force",		no_argument,		NULL, 'f'},
	{"help",		no_argument,		NULL, 'h'},
	{"help",		no_argument,		NULL, '?'},
	{"isns",		required_argument,	NULL, 'i'},
	{"isns-server",		required_argument,	NULL, 'I'},
	{"node-name",		required_argument,	NULL, 'n'},
	{"parsable",		no_argument,		NULL, 'p'},
	{"radius-secret",	no_argument,		NULL, 'd'},
	{"radius-secret-file",	required_argument,	NULL, 'D'},
	{"radius-server",	required_argument,	NULL, 'r'},
	{"tpg-tag",		required_argument,	NULL, 't'},
	{"verbose",		no_argument,		NULL, 'v'},
	{"version",		no_argument,		NULL, 'V'},
	{NULL, 0, NULL, 0}
};

char c_tgt[] =
"	create-target	[-a radius|chap|none|default] [-s]\n"
"			[-S <chap-secret-path>] [-u <chap-user-name>]\n"
"			[-n <target-node-name>] [-l <alias>]\n"
"			[-t <tpg-name>[,<tpg-name>]...]";

static char m_tgt[] =
"	modify-target	[-a radius|chap|none|default] [-s]\n"
"			[-S <chap-secret-path>] [-u <chap-username>]\n"
"			[-n <new-target-node-name>] [-l <alias>]\n"
"			[-t <tpg-name>[,<tpg-name>]...] <target-node-name>";

static char d_tgt[] =
"	delete-target	[-f] <target-node-name>";

static char l_tgt[] =
"	list-target	[-pv] [<target-node-name>]";

static char c_tpg[] =
"	create-tpg	<tpg-name> <IP-address>[:<port>]...";

static char l_tpg[] =
"	list-tpg	[-pv] [<tpg-name>]";

static char d_tpg[] =
"	delete-tpg	[-f] <tpg-name>";

static char c_ini[] =
"	create-initiator [-s] [-S <chap-secret-path>]\n"
"			[-u <chap-username>] <initiator-node-name>";

static char m_ini[] =
"	modify-initiator [-s] [-S <chap-secret-path>]\n"
"			[-u <chap-username>] <initiator-node-name>";

static char l_ini[] =
"	list-initiator	[-pv] [<initiator-node-name>]";

static char d_ini[] =
"	delete-initiator <initiator-node-name>";

static char m_def[] =
"	modify-defaults	[-a radius|chap|none] [-r <IP-address>[:<port>]] [-d]\n"
"			[-D <radius-secret-path>] [-i enable|disable]\n"
"			[-I <IP-address>[:<port>][,<IP-adddress>[:<port>]]...]";

static char l_def[] =
"	list-defaults	[-p]";


/* keep the order of this enum in the same order as the 'subcmds' struct */
typedef enum {
	CREATE_TGT,
	MODIFY_TGT,
	DELETE_TGT,
	LIST_TGT,
	CREATE_TPG,
	DELETE_TPG,
	LIST_TPG,
	CREATE_INI,
	MODIFY_INI,
	LIST_INI,
	DELETE_INI,
	MODIFY_DEF,
	LIST_DEF,
	NULL_SUBCMD	/* must always be last! */
} itadm_sub_t;

typedef struct {
	char		*name;
	char		*shortopts;
	char		*usemsg;
} itadm_subcmds_t;

static itadm_subcmds_t	subcmds[] = {
	{"create-target", ":a:sS:u:n:l:t:h?", c_tgt},
	{"modify-target", ":a:sS:u:n:l:t:h?", m_tgt},
	{"delete-target", ":fh?", d_tgt},
	{"list-target", ":hpv?", l_tgt},
	{"create-tpg", ":h?", c_tpg},
	{"delete-tpg", ":fh?", d_tpg},
	{"list-tpg", ":hpv?", l_tpg},
	{"create-initiator", ":sS:u:h?", c_ini},
	{"modify-initiator", ":sS:u:h?", m_ini},
	{"list-initiator", ":hpv?", l_ini},
	{"delete-initiator", ":h?", d_ini},
	{"modify-defaults", ":a:r:dD:i:I:h?", m_def},
	{"list-defaults", ":hp?", l_def},
	{NULL, ":h?", NULL},
};

/* used for checking if user is authorized */
static char *itadm_uname = NULL;

/* prototypes */
static int
itadm_get_password(nvlist_t *nvl, char *key, char *passfile,
    char *phrase);

static int
itadm_opt_to_arr(nvlist_t *nvl, char *key, char *opt, uint32_t *num);

static int
create_target(char *tgt, nvlist_t *proplist);

static int
modify_target(char *tgt, char *new, nvlist_t *proplist);

static int
delete_target(char *tgt, boolean_t force);

static int
list_target(char *tgt, boolean_t verbose, boolean_t script);

static int
create_tpg(char *tpg, int addrc, char **addrs);

static int
list_tpg(char *tpg, boolean_t verbose, boolean_t script);

static int
delete_tpg(char *tpg, boolean_t force);

static int
modify_initiator(char *ini, nvlist_t *proplist, boolean_t create);

static int
list_initiator(char *ini, boolean_t verbose, boolean_t script);

static int
delete_initiator(char *ini);

static int
modify_defaults(nvlist_t *proplist);

static int
list_defaults(boolean_t script);

static void
tag_name_to_num(char *tagname, uint16_t *tagnum);

/* prototype from iscsit_common.h */
extern int
sockaddr_to_str(struct sockaddr_storage *sa, char **addr);

static void output_config_error(int error_code, char *msg);

int
main(int argc, char *argv[])
{
	int		ret = 0;
	int		idx = NULL_SUBCMD;
	char		c;
	int		newargc = argc;
	char		**newargv = NULL;
	char		*objp;
	int		itind = 0;
	nvlist_t	*proplist = NULL;
	boolean_t	verbose = B_FALSE;
	boolean_t	script = B_FALSE;
	boolean_t	tbool;
	char		*targetname = NULL;
	char		*propname;
	boolean_t	force = B_FALSE;
	struct passwd	*pwd = NULL;
	uint32_t	count = 0;
	char		*smfstate = NULL;

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
		    gettext("Could not determine callers user name"));
		return (1);
	}

	itadm_uname = strdup(pwd->pw_name);

	/* increment past command & subcommand */
	newargc--;
	newargv = &(argv[1]);

	ret = nvlist_alloc(&proplist, NV_UNIQUE_NAME, 0);
	if (ret != 0) {
		ret = errno;
		output_config_error(ret, gettext("Could not allocate nvlist"));
		ret = 1;
		goto usage_error;
	}

	while ((ret == 0) && (newargv)) {
		c = getopt_long(newargc, newargv, subcmds[idx].shortopts,
		    itadm_long, &itind);
		if (c == -1) {
			break;
		}

		switch (c) {
			case 0:
				/* flag set by getopt */
				break;
			case 'a':
				ret = nvlist_add_string(proplist,
				    "auth", optarg);
				break;
			case 'd':
				ret = itadm_get_password(proplist,
				    "radiussecret", NULL,
				    gettext("Enter RADIUS secret: "));
				break;
			case 'D':
				ret = itadm_get_password(proplist,
				    "radiussecret", optarg, NULL);
				break;
			case 'f':
				force = B_TRUE;
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
			case 'i':
				if (strncmp(optarg, "enable", strlen(optarg))
				    == 0) {
					tbool = B_TRUE;
				} else if (strncmp(optarg, "disable",
				    strlen(optarg)) == 0) {
					tbool = B_FALSE;
				} else {
					(void) fprintf(stderr, "%s\n",
					    gettext("invalid value for -i"));
					ret = 1;
					break;
				}
				ret = nvlist_add_boolean_value(proplist,
				    "isns", tbool);
				break;
			case 'I':
				/* possibly multi-valued */
				ret = itadm_opt_to_arr(proplist,
				    "isnsserver", optarg, &count);
				if ((ret == 0) && (count > 8)) {
					(void) fprintf(stderr, "%s\n",
					    gettext(
					    "Too many iSNS servers specified, "
					    "maximum of 8 allowed"));
					ret = 1;
				}
				break;
			case 'l':
				ret = nvlist_add_string(proplist,
				    "alias", optarg);
				break;
			case 'n':
				targetname = strdup(optarg);
				if (targetname == NULL) {
					ret = ENOMEM;
				}
				break;
			case 'p':
				script = B_TRUE;
				break;
			case 'r':
				ret = nvlist_add_string(proplist,
				    "radiusserver", optarg);
				break;
			case 's':
				if ((idx == CREATE_TGT) ||
				    (idx == MODIFY_TGT)) {
					propname = "targetchapsecret";
				} else {
					propname = "chapsecret";
				}
				ret = itadm_get_password(proplist,
				    propname, NULL,
				    gettext("Enter CHAP secret: "));
				break;
			case 'S':
				if ((idx == CREATE_TGT) ||
				    (idx == MODIFY_TGT)) {
					propname = "targetchapsecret";
				} else {
					propname = "chapsecret";
				}
				ret = itadm_get_password(proplist,
				    propname, optarg, NULL);
				break;
			case 't':
				/* possibly multi-valued */
				ret = itadm_opt_to_arr(proplist,
				    "tpg-tag", optarg, NULL);
				break;
			case 'u':
				if ((idx == CREATE_TGT) ||
				    (idx == MODIFY_TGT)) {
					propname = "targetchapuser";
				} else {
					propname = "chapuser";
				}
				ret = nvlist_add_string(proplist,
				    propname, optarg);
				break;
			case 'v':
				verbose = B_TRUE;
				break;
			case ':':
				(void) fprintf(stderr,
				    gettext("Option %s requires an operand"),
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
	if ((itadm_sub_t)idx == NULL_SUBCMD) {
		(void) fprintf(stderr, "%s\n",
		    gettext("Error, no subcommand specified"));
		ret = 1;
		goto usage_error;
	}

	/*
	 * some subcommands take multiple operands, so adjust now that
	 * getopt is complete
	 */
	newargc -= optind;
	if (newargc == 0) {
		newargv = NULL;
		objp = NULL;
	} else {
		newargv = &(newargv[optind]);
		objp = newargv[0];
	}

	if (objp == NULL) {
		switch ((itadm_sub_t)idx) {
		case MODIFY_TGT:
		case DELETE_TGT:
		case CREATE_TPG:
		case DELETE_TPG:
		case CREATE_INI:
		case MODIFY_INI:
		case DELETE_INI:
			/* These subcommands need at least one operand */
			(void) fprintf(stderr,
			    gettext("Error, %s requires an operand"),
			    subcmds[idx].name);
			(void) fprintf(stderr, "\n");

			ret = 1;
			goto usage_error;
		default:
			break;
		}
	}

	if (newargc > 1) {
		switch ((itadm_sub_t)idx) {
		case MODIFY_TGT:
		case DELETE_TGT:
		case LIST_TGT:
		case DELETE_TPG:
		case LIST_TPG:
		case CREATE_INI:
		case MODIFY_INI:
		case LIST_INI:
		case DELETE_INI:
			/* These subcommands should have at most one operand */
			(void) fprintf(stderr,
			    gettext("Error, %s accepts only a single operand"),
			    subcmds[idx].name);
			(void) fprintf(stderr, "\n");

			ret = 1;
			goto usage_error;

		default:
			break;
		}
	}

	if (newargc > 0) {
		switch ((itadm_sub_t)idx) {
		case CREATE_TGT:
		case MODIFY_DEF:
		case LIST_DEF:
			/* These subcommands do not support an operand */
			(void) fprintf(stderr,
			    gettext("Error, %s does not support any operands"),
			    subcmds[idx].name);
			(void) fprintf(stderr, "\n");

			ret = 1;
			goto usage_error;

		default:
			break;
		}
	}

	/*
	 * XXX - this should probably get pushed down to the library
	 * depending on the decision to allow/disallow configuratoin
	 * without the service running.
	 */
	/*
	 * Make sure iSCSI target service is enabled before
	 * proceeding.
	 */
	smfstate = smf_get_state(ISCSIT_SVC);
	if (!smfstate ||
	    (strcmp(smfstate, SCF_STATE_STRING_ONLINE) != 0)) {
		(void) fprintf(stderr, "%s\n",
		    gettext("The iSCSI target service must be online "
		    "before running this command."));
		(void) fprintf(stderr,
		    gettext("Use 'svcadm enable -r %s'"), ISCSIT_SVC);
		(void) fprintf(stderr, "\n");
		(void) fprintf(stderr, "%s\n",
		    gettext("to enable the service and its prerequisite "
		    "services and/or"));
		(void) fprintf(stderr,
		    gettext("'svcs -x %s' to determine why it is not online."),
		    ISCSIT_SVC);
		(void) fprintf(stderr, "\n");

		return (1);
	}

	switch ((itadm_sub_t)idx) {
		case CREATE_TGT:
			/*
			 * OK for targetname to be NULL here.  If the
			 * user did not specify a target name,
			 * one will be generated.
			 */
			ret = create_target(targetname, proplist);
			break;
		case MODIFY_TGT:
			ret = modify_target(objp, targetname, proplist);
			break;
		case DELETE_TGT:
			ret = delete_target(objp, force);
			break;
		case LIST_TGT:
			ret = list_target(objp, verbose, script);
			break;
		case CREATE_TPG:
			ret = create_tpg(objp, newargc - 1, &(newargv[1]));
			break;
		case DELETE_TPG:
			ret = delete_tpg(objp, force);
			break;
		case LIST_TPG:
			ret = list_tpg(objp, verbose, script);
			break;
		case CREATE_INI:
			ret = modify_initiator(objp, proplist, B_TRUE);
			break;
		case MODIFY_INI:
			ret = modify_initiator(objp, proplist, B_FALSE);
			break;
		case LIST_INI:
			ret = list_initiator(objp, verbose, script);
			break;
		case DELETE_INI:
			ret = delete_initiator(objp);
			break;
		case MODIFY_DEF:
			ret = modify_defaults(proplist);
			break;
		case LIST_DEF:
			ret = list_defaults(script);
			break;
		default:
			ret = 1;
			goto usage_error;
	}

	if (ret != 0) {
		(void) fprintf(stderr,
		    gettext("itadm %s failed with error %d"),
		    subcmds[idx].name, ret);
		(void) fprintf(stderr, "\n");
	}
	return (ret);

usage_error:
	if (subcmds[idx].name) {
		(void) printf("%s\n%s\n", gettext("usage:"),
		    gettext(subcmds[idx].usemsg));
	} else {
		/* overall usage */
		(void) printf("%s\n",
		    gettext("usage: itadm <subcommand> <args> ..."));
		for (idx = 0; subcmds[idx].name != NULL; idx++) {
			if (!subcmds[idx].usemsg) {
				continue;
			}
			(void) printf("%s\n", gettext(subcmds[idx].usemsg));
		}
	}

	return (ret);
}

static int
create_target(char *tgt, nvlist_t *proplist)
{
	int		ret;
	it_config_t	*cfg = NULL;
	it_tgt_t	*tgtp;
	char		**tags = NULL;
	uint32_t	count = 0;
	nvlist_t	*errlist = NULL;
	int		i;
	it_tpg_t	*tpg = NULL;
	uint16_t	tagid = 0;
	it_tpgt_t	*tpgt;
	char		*sec = "solaris.smf.modify.stmf";
	boolean_t	did_it_config_load = B_FALSE;

	ITADM_CHKAUTH(sec);

	if (tgt) {
		/*
		 * Validate target name.
		 */
		if (!IS_IQN_NAME(tgt) && !IS_EUI_NAME(tgt)) {
			(void) fprintf(stderr, gettext("Invalid name %s"),
			    tgt);
			(void) fprintf(stderr, "\n");
			return (EINVAL);
		}
	}

	ret = it_config_load(&cfg);
	if (ret != 0) {
		output_config_error(ret,
		    gettext("Error retrieving iSCSI target configuration"));
		goto done;
	}

	did_it_config_load = B_TRUE;

	ret = it_tgt_create(cfg, &tgtp, tgt);
	if (ret != 0) {
		if (ret == EFAULT) {
			(void) fprintf(stderr,
			    gettext("Invalid iSCSI name %s"), tgt);
			(void) fprintf(stderr, "\n");
		} else if (ret == EEXIST) {
			(void) fprintf(stderr,
			    gettext("iSCSI target %s already configured"),
			    tgt);
			(void) fprintf(stderr, "\n");
		} else if (ret == E2BIG) {
			(void) fprintf(stderr,
			    gettext("Maximum of %d iSCSI targets"),
			    MAX_TARGETS);
			(void) fprintf(stderr, "\n");
		} else {
			output_config_error(ret,
			    gettext("Error creating target"));
		}

		goto done;
	}

	/* set the target portal group tags */
	ret = nvlist_lookup_string_array(proplist, "tpg-tag", &tags,
	    &count);

	if (ret == ENOENT) {
		/* none specified.  is this ok? */
		ret = 0;
	} else if (ret != 0) {
		output_config_error(ret, gettext("Internal error"));
		goto done;
	}

	/* special case, don't set any TPGs */
	if (tags && (count == 1) && (strcmp("default", tags[0]) == 0)) {
		count = 0;
	}

	for (i = 0; i < count; i++) {
		if (!tags[i]) {
			continue;
		}

		/* see that all referenced groups are already defined */
		tpg = cfg->config_tpg_list;
		while (tpg != NULL) {
			if (strcmp(tags[i], tpg->tpg_name) == 0) {
				break;
			}

			tpg = tpg->tpg_next;
		}
		if (tpg == NULL) {
			(void) fprintf(stderr,
			    gettext("Invalid tpg-tag %s, tag not defined"),
			    tags[i]);
			(void) fprintf(stderr, "\n");
			ret = 1;
			goto done;
		}

		/* generate the tag number to use */
		tag_name_to_num(tags[i], &tagid);

		ret = it_tpgt_create(cfg, tgtp, &tpgt, tags[i], tagid);
		if (ret != 0) {
			(void) fprintf(stderr, gettext(
			    "Could not add target portal group tag %s: "),
			    tags[i]);
			output_config_error(ret, NULL);
			goto done;
		}
		tagid++;
	}

	/* remove the tags from the proplist before continuing */
	if (tags) {
		(void) nvlist_remove_all(proplist, "tpg-tag");
	}

	ret = it_tgt_setprop(cfg, tgtp, proplist, &errlist);
	if (ret != 0) {
		(void) fprintf(stderr,
		    gettext("Error setting target properties: %d"), ret);
		(void) fprintf(stderr, "\n");
		if (errlist) {
			nvpair_t	*nvp = NULL;
			char		*nn;
			char		*nv;

			while ((nvp = nvlist_next_nvpair(errlist, nvp))
			    != NULL) {
				nv = NULL;

				nn = nvpair_name(nvp);
				(void) nvpair_value_string(nvp, &nv);

				if (nv != NULL) {
					(void) fprintf(stderr, "\t%s: %s\n",
					    nn, nv);
				}
			}

			nvlist_free(errlist);
		}
		goto done;
	}

	if (ret == 0) {
		ret = it_config_commit(cfg);
		STMF_STALE(ret);
	}

done:
	if (ret == 0) {
		(void) printf(gettext("Target %s successfully created"),
		    tgtp->tgt_name);
		(void) printf("\n");
	}

	if (did_it_config_load)
		it_config_free(cfg);

	return (ret);
}

int
list_target(char *tgt, boolean_t verbose, boolean_t script)
{
	int		ret;
	it_config_t	*cfg;
	it_tgt_t	*ptr;
	boolean_t	found = B_FALSE;
	boolean_t	first = B_TRUE;
	boolean_t	first_tag = B_TRUE;
	char		*gauth = "none";
	char		*galias = "-";
	char		*auth;
	char		*alias;
	char		*chapu;
	char		*chaps;
	it_tpgt_t	*tagp;
	char		*sec = "solaris.smf.read.stmf";
	stmfDevid	devid;
	stmfSessionList	*sess = NULL;
	stmfTargetProperties	props;
	char		*state;
	int		num_sessions;

	ITADM_CHKAUTH(sec);

	ret = it_config_load(&cfg);
	if (ret != 0) {
		output_config_error(ret,
		    gettext("Error retrieving iSCSI target configuration"));
		return (ret);
	}

	ptr = cfg->config_tgt_list;

	/* grab global defaults for auth, alias */
	if (cfg->config_global_properties) {
		(void) nvlist_lookup_string(cfg->config_global_properties,
		    "alias", &galias);
		(void) nvlist_lookup_string(cfg->config_global_properties,
		    "auth", &gauth);
	}

	for (; ptr != NULL; ptr = ptr->tgt_next) {
		if (found) {
			break;
		}

		if (tgt) {
			/*
			 * We do a case-insensitive match in case
			 * a non-lower case value got stored.
			 */
			if (strcasecmp(tgt, ptr->tgt_name) != 0) {
				continue;
			} else {
				found = B_TRUE;
			}
		}

		state = "-";
		num_sessions = 0;
		sess = NULL;

		/*
		 * make a best effort to retrieve target status and
		 * number of active sessions from STMF.
		 */
		ret = stmfDevidFromIscsiName(ptr->tgt_name, &devid);
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
		if (ret == STMF_STATUS_SUCCESS) {
			ret = stmfGetSessionList(&devid, &sess);
			if (ret == STMF_STATUS_SUCCESS) {
				num_sessions = sess->cnt;
				free(sess);
			}
		}

		/* reset ret so we don't return an error */
		ret = 0;

		if (!script && first) {
			(void) printf("%-61s%-9s%-9s\n", "TARGET NAME",
			    "STATE", "SESSIONS");
			first = B_FALSE;
		}

		if (!script) {
			/*
			 * try not to let columns run into each other.
			 * Stick a tab after too-long fields.
			 * Lengths chosen are for the 'common' cases.
			 */
			(void) printf("%-61s", ptr->tgt_name);
			if (strlen(ptr->tgt_name) > 60) {
				(void) printf("\t");
			}
			(void) printf("%-9s%-9d", state, num_sessions);
		} else {
			(void) printf("%s\t%s\t%d", ptr->tgt_name,
			    state, num_sessions);
		}

		if (!verbose) {
			(void) printf("\n");
			continue;
		}

		auth = gauth;
		alias = galias;
		chapu = "-";
		chaps = "unset";

		if (ptr->tgt_properties) {
			(void) nvlist_lookup_string(ptr->tgt_properties,
			    "auth", &auth);
			(void) nvlist_lookup_string(ptr->tgt_properties,
			    "alias", &alias);
			if (nvlist_exists(ptr->tgt_properties,
			    "targetchapsecret")) {
				chaps = "set";
			}
			(void) nvlist_lookup_string(ptr->tgt_properties,
			    "targetchapuser", &chapu);
		}

		if (!script) {
			(void) printf("\n\t%-20s\t%s\n\t%-20s\t%s %s\n"
			    "\t%-20s\t%s\n\t%-20s\t%s\n\t%-20s\t",
			    "alias:", alias, "auth:", auth,
			    ((auth == gauth) ? "(defaults)" : ""),
			    "targetchapuser:",
			    chapu, "targetchapsecret:", chaps, "tpg-tags:");
		} else {
			(void) printf("\t%s\t%s %s\t%s\t%s\t",
			    alias, auth,
			    ((auth == gauth) ? "(defaults)" : ""),
			    chapu, chaps);
		}

		first_tag = B_TRUE;
		tagp = ptr->tgt_tpgt_list;
		for (; tagp != NULL; tagp = tagp->tpgt_next) {
			if (!first_tag) {
				(void) printf(",");
			} else {
				first_tag = B_FALSE;
			}
			(void) printf("%s = %d",
			    tagp->tpgt_tpg_name, tagp->tpgt_tag);
		}

		if (first_tag) {
			/* didn't find any */
			(void) printf("default");
		}

		(void) printf("\n");
	}

	if (tgt && (!found)) {
		(void) fprintf(stderr,
		    gettext("Target %s not found!"), tgt);
		(void) fprintf(stderr, "\n");
		ret = 1;
	}

	it_config_free(cfg);

	return (ret);
}

int
delete_target(char *tgt, boolean_t force)
{
	int		ret;
	it_config_t	*cfg;
	it_tgt_t	*ptr;
	char		*sec = "solaris.smf.modify.stmf";

	ITADM_CHKAUTH(sec);

	if (!tgt) {
		(void) fprintf(stderr, "%s\n",
		    gettext("Error, no target specified"));
		return (EINVAL);
	}

	ret = it_config_load(&cfg);
	if (ret != 0) {
		output_config_error(ret,
		    gettext("Error retrieving iSCSI target configuration"));
		return (ret);
	}

	ptr = cfg->config_tgt_list;
	while (ptr) {
		/*
		 * We do a case-insensitive match in case
		 * a non-lower case value got stored.
		 */
		if (strcasecmp(ptr->tgt_name, tgt) == 0) {
			break;
		}

		ptr = ptr->tgt_next;
	}

	if (ptr) {
		ret = it_tgt_delete(cfg, ptr, force);

		if (ret != 0) {
			if (ret == EBUSY) {
				(void) fprintf(stderr,
				    gettext("The target is online or busy. "
				    "Use the -f (force) option, or "
				    "'stmfadm offline-target %s'"), tgt);
				(void) fprintf(stderr, "\n");
			} else {
				output_config_error(ret, gettext(
				    "Error deleting target"));
			}
		}

		if (ret == 0) {
			ret = it_config_commit(cfg);
			STMF_STALE(ret);
		}
	} else {
		(void) fprintf(stderr,
		    gettext("Target %s not found"), tgt);
		(void) fprintf(stderr, "\n");
		ret = 1;
	}

	it_config_free(cfg);

	return (ret);
}

static int
modify_target(char *tgt, char *newname, nvlist_t *proplist)
{
	int		ret;
	it_config_t	*cfg = NULL;
	it_tgt_t	*ptr = NULL;
	it_tgt_t	*tgtp = NULL;
	char		**tags = NULL;
	uint32_t	count = 0;
	nvlist_t	*errlist = NULL;
	int		i;
	it_tpg_t	*tpg = NULL;
	uint16_t	tagid;
	it_tpgt_t	*tpgt = NULL;
	char		*sec = "solaris.smf.modify.stmf";
	boolean_t	did_it_config_load = B_FALSE;

	ITADM_CHKAUTH(sec);

	/* XXX:  Do we need to offline anything here too? */

	if (!tgt) {
		(void) fprintf(stderr, "%s\n",
		    gettext("Error, no target specified"));
		ret = EINVAL;
		goto done;
	}

	ret = it_config_load(&cfg);
	if (ret != 0) {
		output_config_error(ret,
		    gettext("Error retrieving iSCSI target configuration"));
		goto done;
	}

	did_it_config_load = B_TRUE;

	/*
	 * If newname is specified, ensure it is a valid name.
	 */
	if (newname) {
		if (!validate_iscsi_name(newname)) {
			(void) fprintf(stderr,
			    gettext("Invalid iSCSI name %s"), newname);
			(void) fprintf(stderr, "\n");
			ret = 1;
			goto done;
		}
	}

	/*
	 * Loop through to verify that the target to be modified truly
	 * exists.  If this target is to be renamed, ensure the new
	 * name is not already in use.
	 */
	ptr = cfg->config_tgt_list;
	while (ptr) {
		/*
		 * Does a target with the new name already exist?
		 */
		if (newname &&
		    (strcasecmp(newname, ptr->tgt_name) == 0)) {
			(void) fprintf(stderr,
			    gettext("A target with name %s already exists"),
			    newname);
			(void) fprintf(stderr, "\n");
			ret = 1;
			goto done;
		}

		if (strcasecmp(ptr->tgt_name, tgt) == 0) {
			tgtp = ptr;
		}

		ptr = ptr ->tgt_next;
	}

	if (!tgtp) {
		(void) fprintf(stderr,
		    gettext("Target %s not found"), tgt);
		(void) fprintf(stderr, "\n");
		ret = EINVAL;
		goto done;
	}

	/* set the target portal group tags */
	ret = nvlist_lookup_string_array(proplist, "tpg-tag", &tags,
	    &count);

	if (ret == ENOENT) {
		/* none specified.  is this ok? */
		ret = 0;
	} else if (ret != 0) {
		output_config_error(ret, gettext("Internal error"));
		goto done;
	}

	/* special case, remove all explicit TPGs, and don't add any */
	if (tags && (count == 1) && (strcmp("default", tags[0]) == 0)) {
		count = 0;
	}

	for (i = 0; i < count; i++) {
		if (!tags || !tags[i]) {
			continue;
		}

		/* see that all referenced groups are already defined */
		tpg = cfg->config_tpg_list;
		while (tpg != NULL) {
			if (strcmp(tags[i], tpg->tpg_name) == 0) {
				break;
			}
			tpg = tpg->tpg_next;
		}
		if (tpg == NULL) {
			(void) fprintf(stderr,
			    gettext("Invalid tpg-name %s: not defined"),
			    tags[i]);
			(void) fprintf(stderr, "\n");
			ret = 1;
			goto done;
		}
	}

	/*
	 * don't recreate tags that are already associated,
	 * remove tags not requested.
	 */
	if (tags) {
		tpgt = tgtp->tgt_tpgt_list;
		while (tpgt) {
			for (i = 0; i < count; i++) {
				if (!tags[i]) {
					continue;
				}

				if (strcmp(tpgt->tpgt_tpg_name, tags[i])
				    == 0) {
					/* non-null tags will be created */
					tags[i] = NULL;
					break;
				}
			}
			if (i == count) {
				/* one to remove */
				it_tpgt_t	*ptr = tpgt;

				tpgt = ptr->tpgt_next;
				it_tpgt_delete(cfg, tgtp, ptr);
			} else {
				tpgt = tpgt->tpgt_next;
			}
		}
	}

	/* see if there are any left to add */
	for (i = 0; i < count; i++) {
		if (!tags || !tags[i]) {
			continue;
		}

		/* generate the tag number to use */
		tag_name_to_num(tags[i], &tagid);

		ret = it_tpgt_create(cfg, tgtp, &tpgt, tags[i], tagid);
		if (ret != 0) {
			if (ret == E2BIG) {
				(void) fprintf(stderr, "%s\n",
				    gettext("Error, no portal tag available"));
			} else {
				(void) fprintf(stderr, gettext(
				    "Could not add target portal group"
				    " tag %s: "), tags[i]);
				output_config_error(ret, NULL);
			}
			goto done;
		}
	}

	/* remove the tags from the proplist before continuing */
	(void) nvlist_remove_all(proplist, "tpg-tag");

	/*
	 * Rename this target, if requested.  Save the old name in
	 * the property list, so the kernel knows this is a renamed
	 * target, and not a new one.
	 */
	if (newname && (strlen(newname) > 0)) {
		ret = nvlist_add_string(proplist, "oldtargetname",
		    tgtp->tgt_name);
		if (ret != 0) {
			output_config_error(ret,
			    gettext("Error renaming target"));
			goto done;
		}
		(void) strlcpy(tgtp->tgt_name, newname,
		    sizeof (tgtp->tgt_name));
	}

	ret = it_tgt_setprop(cfg, tgtp, proplist, &errlist);
	if (ret != 0) {
		(void) fprintf(stderr,
		    gettext("Error setting target properties: %d"), ret);
		(void) fprintf(stderr, "\n");
		if (errlist) {
			nvpair_t	*nvp = NULL;
			char		*nn;
			char		*nv;

			while ((nvp = nvlist_next_nvpair(errlist, nvp))
			    != NULL) {
				nv = NULL;

				nn = nvpair_name(nvp);
				(void) nvpair_value_string(nvp, &nv);

				if (nv != NULL) {
					(void) fprintf(stderr, "\t%s: %s\n",
					    nn, nv);
				}
			}

			nvlist_free(errlist);
		}
		goto done;
	}

	if (ret == 0) {
		ret = it_config_commit(cfg);
		STMF_STALE(ret);
	}

done:
	if (ret == 0) {
		(void) printf(gettext("Target %s successfully modified"),
		    tgtp->tgt_name);
		(void) printf("\n");
	}

	if (did_it_config_load)
		it_config_free(cfg);

	return (ret);
}

int
create_tpg(char *tpg, int addrc, char **addrs)
{
	int		ret;
	it_config_t	*cfg;
	it_tpg_t	*tpgp;
	int		count = 0;
	it_portal_t	*ptl;
	char		*sec = "solaris.smf.modify.stmf";
	int 		i = 0;

	ITADM_CHKAUTH(sec);

	if (!tpg) {
		(void) fprintf(stderr, "%s\n",
		    gettext("Error, no target portal group specified"));
		return (EINVAL);
	}

	if (strlen(tpg) > (MAX_TPG_NAMELEN - 1)) {
		(void) fprintf(stderr,
		    gettext("Target Portal Group name must be no longer "
		    "than %d characters"), (MAX_TPG_NAMELEN - 1));
		(void) fprintf(stderr, "\n");
		return (EINVAL);
	}

	if (!addrs || (addrc <= 0)) {
		(void) fprintf(stderr, "%s\n",
		    gettext("Error, no portal addresses specified"));
		return (EINVAL);
	}

	ret = it_config_load(&cfg);
	if (ret != 0) {
		output_config_error(ret,
		    gettext("Error retrieving iSCSI target configuration"));
		return (ret);
	}

	tpgp = cfg->config_tpg_list;
	while (tpgp != NULL) {
		if (strcmp(tpgp->tpg_name, tpg) == 0) {
			(void) fprintf(stderr,
			    gettext("Target Portal Group %s already exists"),
			    tpg);
			(void) fprintf(stderr, "\n");
			it_config_free(cfg);
			return (1);
		}
		tpgp = tpgp->tpg_next;
	}

	/*
	 * Ensure that the addrs don't contain commas.
	 */
	for (i = 0; i < addrc; i++) {
		if (strchr(addrs[i], ',')) {
			(void) fprintf(stderr,
			    gettext("Bad portal name %s"),
			    addrs[i]);
			(void) fprintf(stderr, "\n");

			it_config_free(cfg);
			return (EINVAL);
		}
	}

	/*
	 * Create the portal group and first portal
	 */
	ret = it_tpg_create(cfg, &tpgp, tpg, addrs[count]);
	if (ret != 0) {
		if (ret == EEXIST) {
			(void) fprintf(stderr,
			    gettext("Portal %s already in use"),
			    addrs[count]);
			(void) fprintf(stderr, "\n");
		} else {
			output_config_error(ret, gettext("Could not create the "
			    "target portal group"));
		}
		it_config_free(cfg);
		return (ret);
	}

	/*
	 * Add the remaining portals
	 */
	for (count = 1; count < addrc; count++) {
		if (!addrs[count]) {
			continue;
		}

		ret = it_portal_create(cfg, tpgp, &ptl, addrs[count]);
		if (ret != 0) {
			if (ret == EEXIST) {
				(void) fprintf(stderr,
				    gettext("Portal %s already in use"),
				    addrs[count]);
				(void) fprintf(stderr, "\n");
			} else {
				(void) fprintf(stderr,
				    gettext("Error adding portal %s: "),
				    addrs[count]);
				output_config_error(ret, NULL);
				break;
			}
		}
	}

	if (ret == 0) {
		ret = it_config_commit(cfg);
		STMF_STALE(ret);
	}

	it_config_free(cfg);

	return (ret);
}

static int
list_tpg(char *tpg, boolean_t verbose, boolean_t script)
{
	int		ret;
	it_config_t	*cfg;
	it_tpg_t	*ptr;
	boolean_t	found = B_FALSE;
	it_portal_t	*portal;
	boolean_t	first = B_TRUE;
	boolean_t	first_portal;
	char		*pstr;
	char		*sec = "solaris.smf.read.stmf";

	ITADM_CHKAUTH(sec);

	ret = it_config_load(&cfg);
	if (ret != 0) {
		output_config_error(ret,
		    gettext("Error retrieving iSCSI target configuration"));
		return (ret);
	}

	ptr = cfg->config_tpg_list;

	for (; ptr != NULL; ptr = ptr->tpg_next) {
		if (found) {
			break;
		}

		if (tpg) {
			if (strcmp(tpg, ptr->tpg_name) != 0) {
				continue;
			} else {
				found = B_TRUE;
			}
		}

		if (!script && first) {
			(void) printf("%-30s%-9s\n", "TARGET PORTAL GROUP",
			    "PORTAL COUNT");
			first = B_FALSE;
		}

		if (!script) {
			(void) printf("%-30s", ptr->tpg_name);
			if (strlen(ptr->tpg_name) > 30) {
				(void) printf("\t");
			}
			(void) printf("%-9d", ptr->tpg_portal_count);
		} else {
			(void) printf("%s\t%d", ptr->tpg_name,
			    ptr->tpg_portal_count);
		}

		if (!verbose) {
			(void) printf("\n");
			continue;
		}

		if (!script) {
			(void) printf("\n    portals:");
		}

		first_portal = B_TRUE;

		portal = ptr->tpg_portal_list;
		for (; portal != NULL; portal = portal->portal_next) {
			ret = sockaddr_to_str(&(portal->portal_addr), &pstr);
			if (ret != 0) {
				/* invalid addr? */
				continue;
			}
			if (!first_portal) {
				(void) printf(",");
			} else {
				(void) printf("\t");
				first_portal = B_FALSE;
			}

			(void) printf("%s", pstr);
			free(pstr);
		}

		if (first_portal) {
			/* none found */
			(void) printf("\t<none>");
		}

		(void) printf("\n");
	}

	if (tpg && (!found)) {
		(void) fprintf(stderr,
		    gettext("Target Portal Group %s not found!\n"), tpg);
		(void) fprintf(stderr, "\n");
		ret = 1;
	}

	it_config_free(cfg);

	return (ret);
}

static int
delete_tpg(char *tpg, boolean_t force)
{
	int		ret;
	it_config_t	*cfg;
	it_tpg_t	*ptpg = NULL;
	char		*sec = "solaris.smf.modify.stmf";

	ITADM_CHKAUTH(sec);

	if (!tpg) {
		(void) fprintf(stderr, "%s\n",
		    gettext("Error, no target portal group specified"));
		return (EINVAL);
	}

	ret = it_config_load(&cfg);
	if (ret != 0) {
		output_config_error(ret,
		    gettext("Error retrieving iSCSI target configuration"));
		return (ret);
	}

	ptpg = cfg->config_tpg_list;
	for (; ptpg != NULL; ptpg = ptpg->tpg_next) {
		if (strcmp(tpg, ptpg->tpg_name) == 0) {
			break;
		}
	}

	if (!ptpg) {
		(void) fprintf(stderr,
		    gettext("Target portal group %s does not exist"),
		    tpg);
		(void) fprintf(stderr, "\n");
		ret = 1;
	} else {
		ret = it_tpg_delete(cfg, ptpg, force);
		if (ret == EBUSY) {
			(void) fprintf(stderr, "%s\n",
			    gettext(
			    "Target portal group associated with one or more "
			    "targets.  Cannot delete."));
		} else if (ret != 0) {
			output_config_error(ret, gettext("Could not delete "
			    "target portal group"));
		}

		if (ret == 0) {
			ret = it_config_commit(cfg);
			STMF_STALE(ret);
		}
	}

	it_config_free(cfg);

	return (ret);
}

static int
modify_initiator(char *ini, nvlist_t *proplist, boolean_t create)
{
	int		ret;
	it_config_t	*cfg;
	it_ini_t	*inip;
	nvlist_t	*errlist = NULL;
	nvpair_t	*nvp = NULL;
	char		*sec = "solaris.smf.modify.stmf";
	boolean_t	changed = B_TRUE;

	ITADM_CHKAUTH(sec);

	if (!ini) {
		(void) fprintf(stderr, "%s\n",
		    gettext("Error, no initiator specified"));
		return (EINVAL);
	} else if (create) {
		/*
		 * validate input name - what are the rules for EUI
		 * and IQN values?
		 */
		if (!IS_IQN_NAME(ini) && !IS_EUI_NAME(ini)) {
			(void) fprintf(stderr, gettext("Invalid name %s"),
			    ini);
			(void) fprintf(stderr, "\n");
			return (EINVAL);
		}
	}

	/*
	 * See if any properties were actually specified.
	 */
	if (proplist) {
		nvp = nvlist_next_nvpair(proplist, nvp);
	}

	if ((nvp == NULL) && !create) {
		changed = B_FALSE;
	}

	/*
	 * If no properties, and this is really a modify op, verify
	 * that the requested initiator exists, but then don't do anything.
	 * Modifying non-existent is an error; doing nothing to a defined
	 * initiator is not.
	 */

	ret = it_config_load(&cfg);
	if (ret != 0) {
		output_config_error(ret,
		    gettext("Error retrieving iSCSI target configuration"));
		return (ret);
	}

	inip = cfg->config_ini_list;
	while (inip) {
		if (strcasecmp(inip->ini_name, ini) == 0) {
			break;
		}

		inip = inip->ini_next;
	}

	if (create) {
		if (inip) {
			(void) fprintf(stderr,
			    gettext("Initiator %s already exists"),
			    inip->ini_name);
			(void) fprintf(stderr, "\n");
			ret = EINVAL;
		} else {
			ret = it_ini_create(cfg, &inip, ini);
			if (ret != 0) {
				if (ret == EFAULT) {
					(void) fprintf(stderr,
					    gettext("Invalid iSCSI name %s"),
					    ini);
					(void) fprintf(stderr, "\n");
				} else {
					output_config_error(ret, gettext(
					    "Error creating initiator"));
				}
			}
		}
	} else if (!inip) {
		ret = ENOENT;
		(void) fprintf(stderr,
		    gettext("Error, initiator %s not found"),
		    ini);
		(void) fprintf(stderr, "\n");
	}

	if ((ret == 0) && nvp) {
		ret = it_ini_setprop(inip, proplist, &errlist);

		if (ret != 0) {
			(void) fprintf(stderr,
			    gettext("Error setting initiator properties: %d"),
			    ret);
			(void) fprintf(stderr, "\n");
			if (errlist) {
				nvpair_t	*nvp = NULL;
				char		*nn;
				char		*nv;

				while ((nvp = nvlist_next_nvpair(errlist, nvp))
				    != NULL) {
					nv = NULL;

					nn = nvpair_name(nvp);
					(void) nvpair_value_string(nvp, &nv);

					if (nv != NULL) {
						(void) fprintf(stderr,
						    "\t%s: %s\n", nn, nv);
					}
				}

				nvlist_free(errlist);
			}
		}
	}

	if ((ret == 0) && changed) {
		ret = it_config_commit(cfg);
		STMF_STALE(ret);
	}

	it_config_free(cfg);

	return (ret);
}

static int
list_initiator(char *ini, boolean_t verbose, boolean_t script) /* ARGSUSED */
{
	int		ret;
	it_config_t	*cfg;
	it_ini_t	*ptr;
	boolean_t	found = B_FALSE;
	boolean_t	first = B_TRUE;
	char		*isecret;
	char		*iuser;
	char		*sec = "solaris.smf.read.stmf";

	ITADM_CHKAUTH(sec);

	ret = it_config_load(&cfg);
	if (ret != 0) {
		output_config_error(ret,
		    gettext("Error retrieving iSCSI target configuration"));
		return (ret);
	}

	ptr = cfg->config_ini_list;

	for (; ptr != NULL; ptr = ptr->ini_next) {
		isecret = "unset";
		iuser = "<none>";

		if (found) {
			break;
		}

		if (ini) {
			if (strcasecmp(ini, ptr->ini_name) != 0) {
				continue;
			} else {
				found = B_TRUE;
			}
		}

		if (ptr->ini_properties) {
			if (nvlist_exists(ptr->ini_properties, "chapsecret")) {
				isecret = "set";
			}
			(void) nvlist_lookup_string(ptr->ini_properties,
			    "chapuser", &iuser);

		}

		/* there's nothing to print for verbose yet */
		if (!script && first) {
			(void) printf("%-61s%-10s%-7s\n", "INITIATOR NAME",
			    "CHAPUSER", "SECRET");
			first = B_FALSE;
		}

		if (!script) {
			/*
			 * try not to let columns run into each other.
			 * Stick a tab after too-long fields.
			 * Lengths chosen are for the 'common' cases.
			 */
			(void) printf("%-61s", ptr->ini_name);

			if (strlen(ptr->ini_name) > 60) {
				(void) printf("\t");
			}

			(void) printf("%-15s", iuser);
			if (strlen(iuser) >= 15) {
				(void) printf("\t");
			}

			(void) printf("%-4s", isecret);
		} else {
			(void) printf("%s\t%s\t%s", ptr->ini_name,
			    iuser, isecret);
		}

		(void) printf("\n");
	}

	if (ini && (!found)) {
		(void) fprintf(stderr,
		    gettext("Initiator %s not found!"), ini);
		(void) fprintf(stderr, "\n");
		ret = 1;
	}

	it_config_free(cfg);

	return (ret);
}

int
delete_initiator(char *ini)
{
	int		ret;
	it_config_t	*cfg;
	it_ini_t	*ptr;
	char		*sec = "solaris.smf.modify.stmf";

	ITADM_CHKAUTH(sec);

	if (!ini) {
		(void) fprintf(stderr, "%s\n",
		    gettext("Error, no initiator specified"));
		return (EINVAL);
	}

	ret = it_config_load(&cfg);
	if (ret != 0) {
		output_config_error(ret,
		    gettext("Error retrieving iSCSI target configuration"));
		return (ret);
	}

	ptr = cfg->config_ini_list;
	while (ptr) {
		if (strcasecmp(ptr->ini_name, ini) == 0) {
			break;
		}

		ptr = ptr->ini_next;
	}

	if (ptr) {
		it_ini_delete(cfg, ptr);

		ret = it_config_commit(cfg);
		STMF_STALE(ret);
	} else {
		(void) fprintf(stderr,
		    gettext("Initiator %s not found"), ini);
		(void) fprintf(stderr, "\n");
		ret = 1;
	}

	return (ret);
}

static int
modify_defaults(nvlist_t *proplist)
{
	int		ret;
	it_config_t	*cfg;
	nvlist_t	*errlist = NULL;
	nvpair_t	*nvp = NULL;
	char		*sec = "solaris.smf.modify.stmf";

	ITADM_CHKAUTH(sec);

	if (proplist) {
		/* make sure at least one property is specified */
		nvp = nvlist_next_nvpair(proplist, nvp);
	}

	if (nvp == NULL) {
		/* empty list */
		(void) fprintf(stderr, "%s\n",
		    gettext("Error, no properties specified"));
		return (EINVAL);
	}

	ret = it_config_load(&cfg);
	if (ret != 0) {
		output_config_error(ret,
		    gettext("Error retrieving iSCSI target configuration"));
		return (ret);
	}

	ret = it_config_setprop(cfg, proplist, &errlist);
	if (ret != 0) {
		(void) fprintf(stderr,
		    gettext("Error setting global properties: %d"),
		    ret);
		(void) fprintf(stderr, "\n");
		if (errlist) {
			nvpair_t	*nvp = NULL;
			char		*nn;
			char		*nv;

			while ((nvp = nvlist_next_nvpair(errlist, nvp))
			    != NULL) {
				nv = NULL;

				nn = nvpair_name(nvp);
				(void) nvpair_value_string(nvp, &nv);

				if (nv != NULL) {
					(void) fprintf(stderr, "\t%s: %s\n",
					    nn, nv);
				}
			}

			nvlist_free(errlist);
		}
	}

	if (ret == 0) {
		ret = it_config_commit(cfg);
		STMF_STALE(ret);
	}

	it_config_free(cfg);

	return (ret);
}

static int
list_defaults(boolean_t script)
{
	int		ret;
	it_config_t	*cfg;
	nvlist_t	*nvl;
	char		*alias = "<none>";
	char		*auth = "<none>";
	char		*isns = "disabled";
	char		**isvrs = NULL;
	uint32_t	scount = 0;
	char		*rsvr = "<none>";
	char		*rsecret = "unset";
	boolean_t	val = B_FALSE;
	int		i;
	char		*sec = "solaris.smf.read.stmf";

	ITADM_CHKAUTH(sec);

	ret = it_config_load(&cfg);
	if (ret != 0) {
		output_config_error(ret,
		    gettext("Error retrieving iSCSI target configuration"));
		return (ret);
	}

	nvl = cfg->config_global_properties;

	/* look up all possible options */
	(void) nvlist_lookup_string(nvl, "alias", &alias);
	(void) nvlist_lookup_string(nvl, "auth", &auth);
	(void) nvlist_lookup_boolean_value(nvl, "isns", &val);
	if (val == B_TRUE) {
		isns = "enabled";
	}
	(void) nvlist_lookup_string_array(nvl, "isnsserver", &isvrs,
	    &scount);
	(void) nvlist_lookup_string(nvl, "radiusserver", &rsvr);
	if (nvlist_exists(nvl, "radiussecret")) {
		rsecret = "set";
	}

	if (!script) {
		(void) printf("%s:\n\n",
		    gettext("iSCSI Target Default Properties"));
	}

	if (script) {
		(void) printf("%s\t%s\t%s\t%s\t%s\t",
		    alias, auth, rsvr, rsecret, isns);
	} else {
		(void) printf("%-15s\t%s\n%-15s\t%s\n%-15s\t%s\n%-15s\t%s\n"
		    "%-15s\t%s\n%-15s\t",
		    "alias:", alias, "auth:", auth, "radiusserver:",
		    rsvr, "radiussecret:", rsecret, "isns:", isns,
		    "isnsserver:");
	}

	for (i = 0; i < scount; i++) {
		if (!isvrs || !isvrs[i]) {
			break;
		}
		if (i > 0) {
			(void) printf(",");
		}
		(void) printf("%s", isvrs[i]);
	}

	if (i == 0) {
		(void) printf("%s", "<none>");
	}

	(void) printf("\n");

	it_config_free(cfg);

	return (0);
}

static int
itadm_get_password(nvlist_t *nvl, char *key, char *passfile,
    char *phrase)
{
	int		ret = 0;
	char		*pass;
	char		buf[1024];
	int		fd;
	struct stat64	sbuf;
	size_t		rd;

	if (!nvl || !key) {
		return (EINVAL);
	}

	if (passfile) {
		ret = stat64(passfile, &sbuf);
		if ((ret != 0) || (!S_ISREG(sbuf.st_mode))) {
			(void) fprintf(stderr,
			    gettext("Invalid secret file %s"),
			    passfile);
			(void) fprintf(stderr, "\n");
			return (EBADF);
		}

		fd = open64(passfile, O_RDONLY);
		if (fd == -1) {
			ret = errno;
			(void) fprintf(stderr,
			    gettext("Could not open secret file %s: "),
			    passfile);
			output_config_error(ret, NULL);
			return (ret);
		}

		rd = read(fd, buf, sbuf.st_size);
		(void) close(fd);

		if (rd != sbuf.st_size) {
			ret = EIO;
			(void) fprintf(stderr,
			    gettext("Could not read secret file %s: "),
			    passfile);
			output_config_error(ret, NULL);
			return (ret);
		}

		/* ensure buf is properly terminated */
		buf[rd] = '\0';

		/* if last char is a newline, strip it off */
		if (buf[rd - 1] == '\n') {
			buf[rd - 1] = '\0';
		}

		/* validate length */
		if ((strlen(buf) > 255) || (strlen(buf) < 12)) {
			(void) fprintf(stderr, "%s\n",
			    gettext(
			    "Secret must be between 12 and 255 characters"));
			return (EINVAL);
		}
	} else {
		/* prompt for secret */
		if (!phrase) {
			return (EINVAL);
		}

		pass = getpassphrase(phrase);
		if (!pass) {
			ret = errno;
			output_config_error(ret,
			    gettext("Could not read secret"));
			return (ret);
		}

		/* validate length */
		if ((strlen(pass) > 255) || (strlen(pass) < 12)) {
			(void) fprintf(stderr, "%s\n",
			    gettext(
			    "Secret must be between 12 and 255 characters"));
			return (EINVAL);
		}

		(void) strlcpy(buf, pass, sizeof (buf));

		/* confirm entered secret */
		pass = getpassphrase(gettext("Re-enter secret: "));
		if (!pass) {
			ret = errno;
			output_config_error(ret,
			    gettext("Could not read secret"));
			return (ret);
		}

		if (strcmp(buf, pass) != 0) {
			ret = EINVAL;
			(void) fprintf(stderr, "%s\n",
			    gettext("Secret validation failed"));
			return (ret);
		}

	}

	ret = nvlist_add_string(nvl, key, buf);

	return (ret);
}

static int
itadm_opt_to_arr(nvlist_t *nvl, char *key, char *opt, uint32_t *num)
{
	int		count;
	char		*bufp;
	char		**arr;

	if (!opt || !key || !nvl) {
		return (EINVAL);
	}

	bufp = opt;
	count = 1;

	for (;;) {
		bufp = strchr(bufp, ',');
		if (!bufp) {
			break;
		}
		bufp++;
		count++;
	}

	arr = calloc(count, sizeof (char *));
	if (!arr) {
		return (ENOMEM);
	}

	bufp = opt;
	/* set delimiter to comma */
	(void) bufsplit(",", 0, NULL);

	/* split up that buf! */
	(void) bufsplit(bufp, count, arr);

	/* if requested, return the number of array members found */
	if (num) {
		*num = count;
	}

	return (nvlist_add_string_array(nvl, key, arr, count));
}

static void
tag_name_to_num(char *tagname, uint16_t *tagnum)
{
	ulong_t		id;
	char		*ptr = NULL;

	if (!tagname || !tagnum) {
		return;
	}

	*tagnum = 0;

	id = strtoul(tagname, &ptr, 10);

	/* Must be entirely numeric and in-range */
	if (ptr && (*ptr != '\0')) {
		return;
	}

	if ((id <= UINT16_MAX) && (id > 1)) {
		*tagnum = (uint16_t)id;
	}
}

/*
 * Print error messages to stderr for errnos and expected stmf errors.
 * This function should generally not be used for cases where the
 * calling code can generate a more detailed error message based on
 * the contextual knowledge of the meaning of specific errors.
 */
static void
output_config_error(int error, char *msg)
{

	if (msg) {
		(void) fprintf(stderr, "%s: ", msg);
	}

	if (error & STMF_STATUS_ERROR) {
		switch (error) {
		case STMF_ERROR_PERM:
			(void) fprintf(stderr, "%s",
			    gettext("permission denied"));
			break;
		case STMF_ERROR_BUSY:
			(void) fprintf(stderr, "%s",
			    gettext("resource busy"));
			break;
		case STMF_ERROR_NOMEM:
			(void) fprintf(stderr, "%s",
			    gettext("out of memory"));
			break;
		case STMF_ERROR_SERVICE_NOT_FOUND:
			(void) fprintf(stderr, "%s",
			    gettext("STMF service not found"));
			break;
		case STMF_ERROR_SERVICE_DATA_VERSION:
			(void) fprintf(stderr, "%s",
			    gettext("STMF service version incorrect"));
			break;
		case STMF_ERROR_PROV_DATA_STALE:
			(void) fprintf(stderr, "%s",
			    gettext("Configuration changed during processing. "
			    "Check the configuration, then retry this "
			    "command if appropriate."));
			break;
		default:
			(void) fprintf(stderr, "%s", gettext("unknown error"));
			break;
		}
	} else {
		char buf[80] = "";

		(void) strerror_r(error, buf, sizeof (buf));
		(void) fprintf(stderr, "%s", buf);
	}

	(void) fprintf(stderr, "\n");
}

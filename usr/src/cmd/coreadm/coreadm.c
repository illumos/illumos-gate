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
 *
 * Copyright (c) 2017, Joyent, Inc.
 */

#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <libintl.h>
#include <locale.h>
#include <sys/stat.h>
#include <sys/corectl.h>
#include <libproc.h>
#include <libscf.h>
#include <libscf_priv.h>
#include <assert.h>

#define	E_SUCCESS	0		/* Exit status for success */
#define	E_ERROR		1		/* Exit status for error */
#define	E_USAGE		2		/* Exit status for usage error */

static	const	char	PATH_CONFIG[] = "/etc/coreadm.conf";
static	const	char	PATH_CONFIG_OLD[] = "/etc/coreadm.conf.old";

#define	COREADM_INST_NAME	"system/coreadm:default"
#define	COREADM_INST_FMRI	\
    SCF_FMRI_SVC_PREFIX SCF_FMRI_SERVICE_PREFIX COREADM_INST_NAME

#define	CONFIG_PARAMS		"config_params"
#define	GLOBAL_ENABLED		"global_enabled"
#define	PROCESS_ENABLED		"process_enabled"
#define	GLOBAL_SETID_ENABLED	"global_setid_enabled"
#define	PROCESS_SETID_ENABLED	"process_setid_enabled"
#define	GLOBAL_LOG_ENABLED	"global_log_enabled"
#define	GLOBAL_PATTERN		"global_pattern"
#define	GLOBAL_CONTENT		"global_content"
#define	INIT_PATTERN		"init_pattern"
#define	INIT_CONTENT		"init_content"

static	char		*command;
static	uint64_t	options;
static	int		alloptions;
static	char		*glob_pattern;
static	char		gpattern[PATH_MAX];
static	core_content_t	glob_content = CC_CONTENT_INVALID;
static	char		*init_pattern;
static	char		ipattern[PATH_MAX];
static	core_content_t	init_content = CC_CONTENT_INVALID;
static	char		*proc_pattern;
static	size_t		proc_size;
static	core_content_t	proc_content = CC_CONTENT_INVALID;

static	int		report_settings(void);
static	int		do_processes(int, char **);
static	int		do_modify(boolean_t);
static	int		do_update(void);
static	int		do_legacy(void);

static scf_propvec_t prop_gpattern = { GLOBAL_PATTERN, NULL, SCF_TYPE_ASTRING };
static scf_propvec_t prop_gcontent = { GLOBAL_CONTENT, NULL, SCF_TYPE_ASTRING };
static scf_propvec_t prop_ipattern = { INIT_PATTERN, NULL, SCF_TYPE_ASTRING };
static scf_propvec_t prop_icontent = { INIT_CONTENT, NULL, SCF_TYPE_ASTRING };
static scf_propvec_t prop_option[] = {
    { GLOBAL_ENABLED, NULL, SCF_TYPE_BOOLEAN, NULL, CC_GLOBAL_PATH },
    { PROCESS_ENABLED, NULL, SCF_TYPE_BOOLEAN, NULL, CC_PROCESS_PATH },
    { GLOBAL_SETID_ENABLED, NULL, SCF_TYPE_BOOLEAN, NULL, CC_GLOBAL_SETID },
    { PROCESS_SETID_ENABLED, NULL, SCF_TYPE_BOOLEAN, NULL, CC_PROCESS_SETID },
    { GLOBAL_LOG_ENABLED, NULL, SCF_TYPE_BOOLEAN, NULL, CC_GLOBAL_LOG },
    { NULL }
};
#define	MAX_PROPS	(4 + (sizeof (prop_option) / sizeof (scf_propvec_t)))

static void
usage(void)
{
	(void) fprintf(stderr, gettext(
"usage:\n"));
	(void) fprintf(stderr, gettext(
"    %s [ -g pattern ] [ -i pattern ] [ -G content ] [ -I content ]\n"),
	    command);
	(void) fprintf(stderr, gettext(
"            [ -e {global | process | global-setid | proc-setid | log} ]\n"));
	(void) fprintf(stderr, gettext(
"            [ -d {global | process | global-setid | proc-setid | log} ]\n"));
	(void) fprintf(stderr, gettext(
"    %s [ -p pattern ] [ -P content ] [ pid ... ]\n"), command);
	exit(E_USAGE);
}

static int
perm(void)
{
	(void) fprintf(stderr, gettext("%s: insufficient privileges to "
	    "exercise the -[GIgied] options\n"), command);
	return (E_USAGE);
}

static int
parse_content(char *arg, core_content_t *content)
{
	if (proc_str2content(arg, content) == 0)
		return (0);
	(void) fprintf(stderr, gettext("%s: invalid content string '%s'\n"),
	    command, arg);
	return (1);
}

int
main(int argc, char **argv)
{
	int flag;
	int opt;
	int modify;
	int update = 0;
	int legacy_update = 0;
	int error = 0;
	int npids;
	char **pidlist;

	char curpid[11];
	char *curpid_ptr = &curpid[0];

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/* command name (e.g., "coreadm") */
	if ((command = strrchr(argv[0], '/')) != NULL)
		command++;
	else
		command = argv[0];

	while ((opt = getopt(argc, argv, "g:G:i:I:p:P:e:d:uU?")) != EOF) {
		switch (opt) {
		case 'g':
			glob_pattern = optarg;
			break;
		case 'i':
			init_pattern = optarg;
			break;
		case 'p':
			proc_pattern = optarg;
			proc_size = strlen(proc_pattern) + 1;
			break;
		case 'G':
			error |= parse_content(optarg, &glob_content);
			break;
		case 'I':
			error |= parse_content(optarg, &init_content);
			break;
		case 'P':
			error |= parse_content(optarg, &proc_content);
			break;
		case 'e':
		case 'd':
			if (strcmp(optarg, "global") == 0)
				flag = CC_GLOBAL_PATH;
			else if (strcmp(optarg, "process") == 0)
				flag = CC_PROCESS_PATH;
			else if (strcmp(optarg, "global-setid") == 0)
				flag = CC_GLOBAL_SETID;
			else if (strcmp(optarg, "proc-setid") == 0)
				flag = CC_PROCESS_SETID;
			else if (strcmp(optarg, "log") == 0)
				flag = CC_GLOBAL_LOG;
			else {
				flag = 0;
				error = 1;
			}
			if (opt == 'e')
				options |= flag;
			else
				options &= ~flag;
			alloptions |= flag;
			break;
		case 'U':
			update = 1;
			break;
		case 'u':
			legacy_update = 1;
			break;
		case '?':
		default:
			error = 1;
			break;
		}
	}

	npids = argc - optind;
	pidlist = argv + optind;

	if (error)
		usage();

	/*
	 * If 'modify' is true, we must modify the system settings
	 * and update the configuration file with the new parameters.
	 */
	modify = glob_pattern != NULL || glob_content != CC_CONTENT_INVALID ||
	    init_pattern != NULL || init_content != CC_CONTENT_INVALID ||
	    alloptions != 0;

	if ((update || legacy_update) && (modify || proc_pattern != NULL ||
	    proc_content != CC_CONTENT_INVALID || npids != 0)) {
		(void) fprintf(stderr,
		    gettext("%s: the -u option must stand alone\n"), command);
		usage();
	}
	if (modify &&
	    (proc_pattern != NULL || proc_content != CC_CONTENT_INVALID)) {
		(void) fprintf(stderr, gettext(
		    "%s: -[GIgied] and -[Pp] options are mutually exclusive\n"),
		    command);
		usage();
	}
	if (modify && npids != 0) {
		(void) fprintf(stderr, gettext(
		    "%s: -[GIgied] options cannot have a process-id list\n"),
		    command);
		usage();
	}
	if (glob_pattern != NULL && glob_pattern[0] != '/') {
		(void) fprintf(stderr, gettext(
		    "%s: The -g option must specify an absolute path\n"),
		    command);
		usage();
	}
	if ((proc_pattern != NULL || proc_content != CC_CONTENT_INVALID) &&
	    npids == 0) {
		(void) sprintf(curpid, "%u", (uint_t)getppid());
		npids = 1;
		pidlist = &curpid_ptr;
	}

	if (legacy_update)
		return (do_legacy());
	if (update)
		return (do_update());
	if (modify)
		return (do_modify(B_FALSE));
	if (npids != 0)
		return (do_processes(npids, pidlist));

	return (report_settings());
}

static int
report_settings(void)
{
	char content_str[PRCONTENTBUFSZ];

	if ((options = core_get_options()) == -1) {
		perror("core_get_options()");
		return (E_ERROR);
	}
	if (core_get_global_path(gpattern, sizeof (gpattern)) != 0) {
		perror("core_get_global_path()");
		return (E_ERROR);
	}
	if (core_get_default_path(ipattern, sizeof (ipattern)) != 0) {
		perror("core_get_default_path()");
		return (E_ERROR);
	}
	if (core_get_global_content(&glob_content) != 0) {
		perror("core_get_global_content()");
		return (E_ERROR);
	}
	if (core_get_default_content(&init_content) != 0) {
		perror("core_get_default_content()");
		return (E_ERROR);
	}

	(void) printf(gettext("     global core file pattern: %s\n"),
	    gpattern);
	(void) proc_content2str(glob_content, content_str,
	    sizeof (content_str));
	(void) printf(gettext("     global core file content: %s\n"),
	    content_str);
	(void) printf(gettext("       init core file pattern: %s\n"),
	    ipattern);
	(void) proc_content2str(init_content, content_str,
	    sizeof (content_str));
	(void) printf(gettext("       init core file content: %s\n"),
	    content_str);
	(void) printf(gettext("            global core dumps: %s\n"),
	    (options & CC_GLOBAL_PATH)? "enabled" : "disabled");
	(void) printf(gettext("       per-process core dumps: %s\n"),
	    (options & CC_PROCESS_PATH)? "enabled" : "disabled");
	(void) printf(gettext("      global setid core dumps: %s\n"),
	    (options & CC_GLOBAL_SETID)? "enabled" : "disabled");
	(void) printf(gettext(" per-process setid core dumps: %s\n"),
	    (options & CC_PROCESS_SETID)? "enabled" : "disabled");
	(void) printf(gettext("     global core dump logging: %s\n"),
	    (options & CC_GLOBAL_LOG)? "enabled" : "disabled");
	return (E_SUCCESS);
}

static int
do_processes(int npids, char **pidlist)
{
	char process_path[PATH_MAX];
	core_content_t content;
	pid_t pid;
	char *next;
	int rc = E_SUCCESS;
	char content_str[PRCONTENTBUFSZ];

	if (proc_pattern == NULL && proc_content == CC_CONTENT_INVALID) {
		while (npids-- > 0) {
			pid = strtol(*pidlist, &next, 10);
			if (*next != '\0' || !isdigit(**pidlist)) {
				(void) fprintf(stderr,
				    gettext("%s: invalid process-id\n"),
				    *pidlist);
				rc = E_USAGE;
			} else if (core_get_process_path(process_path,
			    sizeof (process_path), pid) != 0 ||
			    core_get_process_content(&content, pid) != 0) {
				perror(*pidlist);
				rc = E_USAGE;
			} else {
				(void) proc_content2str(content, content_str,
				    sizeof (content_str));
				(void) printf(gettext("%s:\t%s\t%s\n"),
				    *pidlist, process_path, content_str);
			}
			pidlist++;
		}
	} else {
		while (npids-- > 0) {
			pid = strtol(*pidlist, &next, 10);
			if (*next != '\0') {
				(void) fprintf(stderr,
				    gettext("%s: invalid process-id\n"),
				    *pidlist);
				rc = E_USAGE;
			} else {
				if (proc_pattern != NULL &&
				    core_set_process_path(proc_pattern,
				    proc_size, pid) != 0) {
					perror(*pidlist);
					rc = E_USAGE;
				}

				if (proc_content != CC_CONTENT_INVALID &&
				    core_set_process_content(
				    &proc_content, pid) != 0) {
					perror(*pidlist);
					rc = E_USAGE;
				}
			}
			pidlist++;
		}
	}

	return (rc);
}

static void
addprop(scf_propvec_t *props, int size, int count, scf_propvec_t *pv, void *ptr)
{
	assert(count + 1 < size);
	props[count] = *pv;
	props[count].pv_ptr = ptr;
}

static boolean_t
is_online(const char *fmri)
{
	char *state = smf_get_state(fmri);
	boolean_t result = state != NULL &&
	    strcmp(state, SCF_STATE_STRING_ONLINE) == 0;

	free(state);
	return (result);
}

/*
 * The user has specified the -g, -G, -i, -I, -d, or -e options to
 * modify the given configuration parameter. Perform the modification
 * in the smf repository and then perform a smf_refresh_instance which
 * will cause a coreadm -u to occur which will transfer ALL coreadm
 * configuration information from the repository to the kernel.
 */
static int
do_modify(boolean_t method)
{
	char gcontentstr[PRCONTENTBUFSZ];
	char icontentstr[PRCONTENTBUFSZ];
	scf_propvec_t *prop;
	scf_propvec_t properties[MAX_PROPS + 1];
	int count = 0;

	if (!method && !is_online(COREADM_INST_FMRI)) {
		(void) fprintf(stderr,
		    gettext("%s: coreadm service not online\n"), command);
		return (E_ERROR);
	}

	if (glob_pattern != NULL)
		addprop(properties, MAX_PROPS, count++, &prop_gpattern,
		    glob_pattern);

	if (glob_content != CC_CONTENT_INVALID) {
		(void) proc_content2str(glob_content, gcontentstr,
		    sizeof (gcontentstr));
		addprop(properties, MAX_PROPS, count++, &prop_gcontent,
		    gcontentstr);
	}

	if (init_pattern != NULL)
		addprop(properties, MAX_PROPS, count++, &prop_ipattern,
		    init_pattern);

	if (init_content != CC_CONTENT_INVALID) {
		(void) proc_content2str(init_content, icontentstr,
		    sizeof (icontentstr));
		addprop(properties, MAX_PROPS, count++, &prop_icontent,
		    icontentstr);
	}

	for (prop = prop_option; prop->pv_prop != NULL; prop++)
		if ((alloptions & prop->pv_aux) != 0)
			addprop(properties, MAX_PROPS, count++, prop, &options);

	properties[count].pv_prop = NULL;

	prop = NULL;
	if (scf_write_propvec(COREADM_INST_FMRI, CONFIG_PARAMS, properties,
	    &prop) == SCF_FAILED) {
		if (prop != NULL) {
			(void) fprintf(stderr, gettext(
			    "%s: Unable to write property '%s': %s"), command,
			    prop->pv_prop, scf_strerror(scf_error()));
		} else {
			(void) fprintf(stderr, gettext(
			    "%s: Unable to write configuration: %s\n"),
			    command, scf_strerror(scf_error()));
		}
		return (E_ERROR);
	}

	if (smf_refresh_instance(COREADM_INST_FMRI) != 0) {
		(void) fprintf(stderr,
		    gettext("%s: Unable to refresh %s: %s\n"
		    "Configuration stored but not made active.\n"),
		    command, COREADM_INST_FMRI, scf_strerror(scf_error()));
		return (E_ERROR);
	}

	return (E_SUCCESS);
}

static const char *
write_kernel(void)
{
	if (core_set_global_path(glob_pattern, strlen(glob_pattern) + 1) != 0)
		return ("core_set_global_path()");

	if (core_set_global_content(&glob_content) != 0)
		return ("core_set_global_content()");

	if (core_set_default_path(init_pattern, strlen(init_pattern) + 1) != 0)
		return ("core_set_default_path()");

	if (core_set_default_content(&init_content) != 0)
		return ("core_set_init_content()");

	if (core_set_options((int)options) != 0)
		return ("core_set_options()");

	return (NULL);
}

/*
 * BUFSIZE must be large enough to contain the longest path plus some more.
 */
#define	BUFSIZE	(PATH_MAX + 80)

static int
yes(char *name, char *value, int line)
{
	if (strcmp(value, "yes") == 0)
		return (1);
	if (strcmp(value, "no") == 0)
		return (0);
	(void) fprintf(stderr, gettext(
	    "\"%s\", line %d: warning: value must be yes or no: %s=%s\n"),
	    PATH_CONFIG, line, name, value);
	return (0);
}

static int
read_legacy(void)
{
	FILE *fp;
	int line;
	char buf[BUFSIZE];
	char name[BUFSIZE], value[BUFSIZE];
	int n, len;

	/* defaults */
	alloptions = CC_OPTIONS;
	options = CC_PROCESS_PATH;
	gpattern[0] = '\0';
	(void) strcpy(ipattern, "core");
	glob_content = init_content = CC_CONTENT_DEFAULT;

	glob_pattern = gpattern;
	init_pattern = ipattern;

	if ((fp = fopen(PATH_CONFIG, "r")) == NULL)
		return (0);

	for (line = 1; fgets(buf, sizeof (buf), fp) != NULL; line++) {
		/*
		 * Skip comment lines and empty lines.
		 */
		if (buf[0] == '#' || buf[0] == '\n')
			continue;
		/*
		 * Look for "name=value", with optional whitespace on either
		 * side, terminated by a newline, and consuming the whole line.
		 */
		/* LINTED - unbounded string specifier */
		n = sscanf(buf, " %[^=]=%s \n%n", name, value, &len);
		if (n >= 1 && name[0] != '\0' &&
		    (n == 1 || len == strlen(buf))) {
			if (n == 1)
				value[0] = '\0';
			if (strcmp(name, "COREADM_GLOB_PATTERN") == 0) {
				(void) strcpy(gpattern, value);
				continue;
			}
			if (strcmp(name, "COREADM_GLOB_CONTENT") == 0) {
				(void) proc_str2content(value, &glob_content);
				continue;
			}
			if (strcmp(name, "COREADM_INIT_PATTERN") == 0) {
				(void) strcpy(ipattern, value);
				continue;
			}
			if (strcmp(name, "COREADM_INIT_CONTENT") == 0) {
				(void) proc_str2content(value, &init_content);
				continue;
			}
			if (strcmp(name, "COREADM_GLOB_ENABLED") == 0) {
				if (yes(name, value, line))
					options |= CC_GLOBAL_PATH;
				continue;
			}
			if (strcmp(name, "COREADM_PROC_ENABLED") == 0) {
				if (yes(name, value, line))
					options |= CC_PROCESS_PATH;
				else
					options &= ~CC_PROCESS_PATH;
				continue;
			}
			if (strcmp(name, "COREADM_GLOB_SETID_ENABLED") == 0) {
				if (yes(name, value, line))
					options |= CC_GLOBAL_SETID;
				continue;
			}
			if (strcmp(name, "COREADM_PROC_SETID_ENABLED") == 0) {
				if (yes(name, value, line))
					options |= CC_PROCESS_SETID;
				continue;
			}
			if (strcmp(name, "COREADM_GLOB_LOG_ENABLED") == 0) {
				if (yes(name, value, line))
					options |= CC_GLOBAL_LOG;
				continue;
			}
			(void) fprintf(stderr, gettext(
			    "\"%s\", line %d: warning: invalid token: %s\n"),
			    PATH_CONFIG, line, name);
		} else {
			(void) fprintf(stderr,
			    gettext("\"%s\", line %d: syntax error\n"),
			    PATH_CONFIG, line);
		}
	}
	(void) fclose(fp);

	return (1);
}

/*
 * Loads and applies the coreadm configuration stored in the default
 * coreadm instance.  As this option is (only) used from within an SMF
 * service method, this function must return an SMF_EXIT_* exit status
 * to its caller.
 */
static int
do_update(void)
{
	char		*gcstr, *icstr;
	scf_propvec_t	properties[MAX_PROPS + 1];
	scf_propvec_t	*prop;
	int		count = 0;
	const char	*errstr;

	if (read_legacy()) {
		if ((errstr = write_kernel()) != NULL)
			goto error;

		if (do_modify(B_TRUE) != 0 ||
		    rename(PATH_CONFIG, PATH_CONFIG_OLD) != 0) {
			(void) fprintf(stderr, gettext(
			    "%s: failed to import legacy configuration.\n"),
			    command);
			return (SMF_EXIT_ERR_FATAL);
		}
		return (SMF_EXIT_OK);
	}

	addprop(properties, MAX_PROPS, count++, &prop_gpattern, &glob_pattern);
	addprop(properties, MAX_PROPS, count++, &prop_gcontent, &gcstr);
	addprop(properties, MAX_PROPS, count++, &prop_ipattern, &init_pattern);
	addprop(properties, MAX_PROPS, count++, &prop_icontent, &icstr);
	for (prop = prop_option; prop->pv_prop != NULL; prop++)
		addprop(properties, MAX_PROPS, count++, prop, &options);
	properties[count].pv_prop = NULL;

	alloptions = CC_OPTIONS;
	if (scf_read_propvec(COREADM_INST_FMRI, CONFIG_PARAMS, B_TRUE,
	    properties, &prop) == SCF_FAILED) {
		if (prop != NULL) {
			(void) fprintf(stderr, gettext(
			    "%s: configuration property '%s' not found.\n"),
			    command, prop->pv_prop);
		} else {
			(void) fprintf(stderr, gettext(
			    "%s: unable to read configuration: %s\n"),
			    command, scf_strerror(scf_error()));
		}
		return (SMF_EXIT_ERR_FATAL);
	}

	(void) proc_str2content(gcstr, &glob_content);
	(void) proc_str2content(icstr, &init_content);

	errstr = write_kernel();
	scf_clean_propvec(properties);
	if (errstr == NULL)
		return (SMF_EXIT_OK);

error:
	if (errno == EPERM) {
		(void) perm();
		return (SMF_EXIT_ERR_PERM);
	}
	perror(errstr);
	return (SMF_EXIT_ERR_FATAL);
}

static int do_legacy()
{
	const char *errstr;

	if (read_legacy() && (errstr = write_kernel()) != NULL) {
		if (errno == EPERM)
			return (perm());
		perror(errstr);
		return (E_ERROR);
	}

	return (E_SUCCESS);
}

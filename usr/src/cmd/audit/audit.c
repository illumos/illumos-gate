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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <fcntl.h>
#include <libscf.h>
#include <secdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/param.h>
#include <unistd.h>
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <locale.h>
#include <zone.h>
#include <audit_scf.h>

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SUNW_OST_OSCMD"
#endif

#define	VERIFY -1

/* GLOBALS */
static char	*progname = "audit";
static char	*usage = "audit [-n] | [-s] | [-t] | [-v]";
static int	silent = 0;

static void	display_smf_error();

static boolean_t is_audit_config_ok();		/* config validation  */
static boolean_t is_valid_zone(boolean_t);	/* operation ok in this zone? */
static boolean_t contains_valid_dirs(char *);	/* p_dir contents validation */
static boolean_t validate_path(char *);		/* is it path to dir? */
static void	start_auditd();			/* start audit daemon */
static int	sig_auditd(int);		/* send signal to auditd */

/*
 * audit() - This program serves as a general administrator's interface to
 *	the audit trail.  Only one option is valid at a time.
 *
 * input:
 *	audit -s
 *		- signal audit daemon to read audit configuration and
 *		  start auditd if needed.
 *	audit -n
 *		- signal audit daemon to use next audit_binfile directory.
 *	audit -t
 *		- signal audit daemon to disable auditing.
 *	audit -T
 *		- signal audit daemon to temporarily disable auditing reporting
 *		  no errors.
 *	audit -v
 *		- validate audit configuration parameters;
 *		  Print errors or "configuration ok".
 *
 *
 * output:
 *
 * returns:	0 - command successful
 *		>0 - command failed
 */

int
main(int argc, char *argv[])
{
	int	c;

	/* Internationalization */
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/* second or more options not allowed; please pick one */
	if (argc > 2) {
		(void) fprintf(stderr, gettext("usage: %s\n"), usage);
		exit(1);
	}

	/* first option required */
	if ((c = getopt(argc, argv, "nstTv")) == -1) {
		(void) fprintf(stderr, gettext("usage: %s\n"), usage);
		exit(1);
	}

	switch (c) {
	case 'n':
		if (!is_valid_zone(1))	/* 1 == display error if any */
			exit(1);

		if (sig_auditd(SIGUSR1) != 0)
			exit(1);
		break;
	case 's':
		if (!is_valid_zone(1))	/* 1 == display error if any */
			exit(1);
		else if (!is_audit_config_ok())
			exit(1);

		start_auditd();
		return (0);
	case 't':
		if (!is_valid_zone(0))	/* 0 == no error message display */
			exit(1);
		if (smf_disable_instance(AUDITD_FMRI, 0) != 0) {
			display_smf_error();
			exit(1);
		}
		break;
	case 'T':
		silent = 1;
		if (!is_valid_zone(0))	/* 0 == no error message display */
			exit(1);
		if (smf_disable_instance(AUDITD_FMRI, SMF_TEMPORARY) != 0) {
			exit(1);
		}
		break;
	case 'v':
		if (is_audit_config_ok()) {
			(void) fprintf(stderr, gettext("configuration ok\n"));
			exit(0);
		} else {
			exit(1);
		}
		break;
	default:
		(void) fprintf(stderr, gettext("usage: %s\n"), usage);
		exit(1);
	}

	return (0);
}

/*
 * sig_auditd(sig)
 *
 * send a signal to auditd service
 *
 * returns:	0 - successful
 *		1 - error
 */

static int
sig_auditd(int sig)
{
	scf_simple_prop_t *prop = NULL;
	uint64_t	*cid = NULL;

	if ((prop = scf_simple_prop_get(NULL, AUDITD_FMRI, SCF_PG_RESTARTER,
	    SCF_PROPERTY_CONTRACT)) == NULL) {
		display_smf_error();
		return (1);
	}
	if ((scf_simple_prop_numvalues(prop) < 0) ||
	    (cid = scf_simple_prop_next_count(prop)) == NULL) {
		scf_simple_prop_free(prop);
		display_smf_error();
		return (1);
	}
	if (sigsend(P_CTID, (ctid_t)*cid, sig) != 0) {
		perror("audit: can't signal auditd");
		scf_simple_prop_free(prop);
		return (1);
	}
	scf_simple_prop_free(prop);
	return (0);
}

/*
 * perform reasonableness check on audit configuration
 */

static boolean_t
is_audit_config_ok() {
	int			state = B_TRUE;	/* B_TRUE/B_FALSE = ok/not_ok */
	char			*cval_str;
	int			cval_int;
	kva_t			*kvlist;
	scf_plugin_kva_node_t   *plugin_kva_ll;
	scf_plugin_kva_node_t   *plugin_kva_ll_head;
	boolean_t		one_plugin_enabled = B_FALSE;

	/*
	 * There must be at least one active plugin configured; if the
	 * configured plugin is audit_binfile(5), then the p_dir must not be
	 * empty.
	 */
	if (!do_getpluginconfig_scf(NULL, &plugin_kva_ll)) {
		(void) fprintf(stderr,
		    gettext("Could not get plugin configuration.\n"));
		exit(1);
	}

	plugin_kva_ll_head = plugin_kva_ll;

	while (plugin_kva_ll != NULL) {
		kvlist = plugin_kva_ll->plugin_kva;

		if (!one_plugin_enabled) {
			cval_str = kva_match(kvlist, "active");
			if (atoi(cval_str) == 1) {
				one_plugin_enabled = B_TRUE;
			}
		}

		if (strcmp((char *)&(*plugin_kva_ll).plugin_name,
		    "audit_binfile") == 0) {
			cval_str = kva_match(kvlist, "p_dir");
			if (cval_str == NULL || cval_str[0] == '\0') {
				(void) fprintf(stderr,
				    gettext("%s: audit_binfile(5) \"p_dir:\" "
				    "attribute empty\n"), progname);
				state = B_FALSE;
			} else if (!contains_valid_dirs(cval_str)) {
				(void) fprintf(stderr,
				    gettext("%s: audit_binfile(5) \"p_dir:\" "
				    "attribute invalid\n"), progname);
				state = B_FALSE;
			}

			cval_str = kva_match(kvlist, "p_minfree");
			cval_int = atoi(cval_str);
			if (cval_int < 0 || cval_int > 100) {
				(void) fprintf(stderr,
				    gettext("%s: audit_binfile(5) "
				    "\"p_minfree:\" attribute invalid\n"),
				    progname);
				state = B_FALSE;
			}
		}

		plugin_kva_ll = plugin_kva_ll->next;
	}

	plugin_kva_ll_free(plugin_kva_ll_head);

	if (!one_plugin_enabled) {
		(void) fprintf(stderr, gettext("%s: no active plugin found\n"),
		    progname);
		state = B_FALSE;
	}

	return (state);
}

/*
 * The operations that call this function are only valid in the global
 * zone unless the perzone audit policy is set.
 *
 * "!silent" and "show_err" are slightly different; silent is from
 * -T for which no error messages should be displayed and show_err
 * applies to more options (including -T)
 *
 */

static boolean_t
is_valid_zone(boolean_t show_err)
{
	uint32_t	policy;

	if (auditon(A_GETPOLICY, (char *)&policy, 0) == -1) {
		if (!silent) {
			(void) fprintf(stderr, gettext(
			    "%s: Cannot read audit policy:  %s\n"),
			    progname, strerror(errno));
		}
		return (0);
	}
	if (policy & AUDIT_PERZONE)
		return (1);

	if (getzoneid() != GLOBAL_ZONEID) {
		if (show_err)
			(void) fprintf(stderr,
			    gettext("%s: Not valid in a local zone.\n"),
			    progname);
		return (0);
	} else {
		return (1);
	}
}

/*
 * Verify, whether the dirs_str contains at least one currently valid path to
 * the directory. All invalid paths are reported. In case no valid directory
 * path is found function returns B_FALSE, otherwise B_TRUE.
 */

static boolean_t
contains_valid_dirs(char *dirs_str)
{
	boolean_t	rc = B_FALSE;
	boolean_t	rc_validate_path = B_TRUE;
	char		*tok_ptr;
	char		*tok_lasts;

	if (dirs_str == NULL) {
		return (rc);
	}

	if ((tok_ptr = strtok_r(dirs_str, ",", &tok_lasts)) != NULL) {
		if (validate_path(tok_ptr)) {
			rc = B_TRUE;
		} else {
			rc_validate_path = B_FALSE;
		}
		while ((tok_ptr = strtok_r(NULL, ",", &tok_lasts)) != NULL) {
			if (validate_path(tok_ptr)) {
				rc = B_TRUE;
			} else {
				rc_validate_path = B_FALSE;
			}
		}
	}

	if (rc && !rc_validate_path) {
		(void) fprintf(stderr, gettext("%s: at least one valid "
		    "directory path found\n"), progname);
	}

	return (rc);
}

/*
 * Verify, that the dir_path is path to a directory.
 */

static boolean_t
validate_path(char *dir_path)
{
	boolean_t	rc = B_FALSE;
	struct stat	statbuf;

	if (dir_path == NULL) {
		return (rc);
	}

	if (stat(dir_path, &statbuf) == -1) {
		(void) fprintf(stderr, gettext("%s: %s error: %s\n"), progname,
		    dir_path, strerror(errno));
	} else if (statbuf.st_mode & S_IFDIR) {
			rc = B_TRUE;
	} else {
		(void) fprintf(stderr, gettext("%s: %s is not a directory\n"),
		    progname, dir_path);
	}

	return (rc);
}

/*
 * if auditd isn't running, start it.  Otherwise refresh.
 * First check to see if c2audit is loaded via the auditon()
 * system call, then check SMF state.
 */
static void
start_auditd()
{
	int	audit_state;
	char	*state;

	if (auditon(A_GETCOND, (caddr_t)&audit_state,
	    sizeof (audit_state)) != 0)
		exit(1);

	if ((state = smf_get_state(AUDITD_FMRI)) == NULL) {
		display_smf_error();
		exit(1);
	}
	if (strcmp(SCF_STATE_STRING_ONLINE, state) != 0) {
		if (smf_enable_instance(AUDITD_FMRI, 0) != 0) {
			display_smf_error();
			free(state);
			exit(1);
		}
	} else {
		if (smf_refresh_instance(AUDITD_FMRI) != 0) {
			display_smf_error();
			free(state);
			exit(1);
		}
	}
	free(state);
}

static void
display_smf_error()
{
	scf_error_t	rc = scf_error();

	switch (rc) {
	case SCF_ERROR_NOT_FOUND:
		(void) fprintf(stderr,
		    "SMF error: \"%s\" not found.\n",
		    AUDITD_FMRI);
		break;
	default:
		(void) fprintf(stderr, "SMF error: %s\n", scf_strerror(rc));
		break;
	}
}

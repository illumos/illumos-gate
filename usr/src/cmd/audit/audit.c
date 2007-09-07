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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fcntl.h>
#include <libscf.h>
#include <secdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/param.h>
#include <unistd.h>
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <locale.h>
#include <audit_sig_infc.h>
#include <zone.h>

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SUNW_OST_OSCMD"
#endif

#define	VERIFY -1

/* GLOBALS */
static char	*auditdatafile = AUDITDATAFILE;
static char	*progname = "audit";
static char	*usage = "audit [-n] | [-s] | [-t] | [-v filepath]";
static int	silent = 0;
static char	*instance_name = "svc:/system/auditd:default";

static int	get_auditd_pid();
static void	display_smf_error();

static boolean_t is_audit_control_ok(char *);	/* file validation  */
static boolean_t is_valid_zone(boolean_t);	/* operation ok in this zone? */
static int	start_auditd();			/* start audit daemon */

/*
 * audit() - This program serves as a general administrator's interface to
 *	the audit trail.  Only one option is valid at a time.
 *
 * input:
 *	audit -s
 *		- signal audit daemon to read audit_control file and
 *		  start auditd if needed.
 *	audit -n
 *		- signal audit daemon to use next audit_control audit directory.
 *	audit -t
 *		- signal audit daemon to disable auditing.
 *	audit -T
 *		- signal audit daemon to disable auditing report no errors.
 *	audit -v filepath
 *		- validate audit_control parameters but use filepath for
 *		  the name.  Emit errors or "syntax ok"
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
	pid_t pid; /* process id of auditd read from auditdatafile */
	int	sig = 0; /* signal to send auditd */
	char	c;
	char	*first_option;

	/* Internationalization */
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/* first option required */
	if ((c = getopt(argc, argv, "nstTv:")) == -1) {
		(void) fprintf(stderr, gettext("usage: %s\n"), usage);
		exit(3);
	}
	first_option = optarg;
	/* second or more options not allowed; please pick one */
	if (getopt(argc, argv, "nstTv:") != -1) {
		(void) fprintf(stderr, gettext("usage: %s\n"), usage);
		exit(5);
	}
	switch (c) {
	case 'n':
		if (!is_valid_zone(1))	/* 1 == display error if any */
			exit(10);

		sig = AU_SIG_NEXT_DIR;
		break;
	case 's':
		if (!is_valid_zone(1))	/* 1 == display error if any */
			exit(10);
		else if (!is_audit_control_ok(NULL))
			exit(7);

		return (start_auditd());
	case 't':
		if (!is_valid_zone(0))	/* 0 == no error message display */
			exit(10);
		/* use bmsunconv to permanently disable, -t for temporary */
		if (smf_disable_instance(instance_name, SMF_TEMPORARY) != 0) {
			display_smf_error();
			exit(11);
		}
		break;
	case 'T':
		silent = 1;
		if (!is_valid_zone(0))	/* 0 == no error message display */
			exit(10);

		if (smf_disable_instance(instance_name, SMF_TEMPORARY) != 0) {
			exit(11);
		}
		break;
	case 'v':
		if (is_audit_control_ok(first_option)) {
			(void) fprintf(stderr, gettext("syntax ok\n"));
			exit(0);
		} else {
			exit(8);
		}
		break;
	default:
		(void) fprintf(stderr, gettext("usage: %s\n"), usage);
		exit(6);
	}

	if (sig != 0) {
		if (get_auditd_pid(&pid) != 0) {
			(void) fprintf(stderr, "%s: %s\n", progname,
			    gettext("can't get process id of auditd from "
			    "audit_data(4)"));
			exit(4);
		}

		if (kill(pid, sig) != 0) {
			perror(progname);
			(void) fprintf(stderr,
			    gettext("%s: cannot signal auditd\n"), progname);
			exit(1);
		}
	}
	return (0);
}


/*
 * get_auditd_pid(&pid):
 *
 * reads PID from audit_data
 *
 * returns:	0 - successful
 *		1 - error
 */

static int
get_auditd_pid(pid_t *p_pid)
{
	FILE	*adp;		/* audit_data file pointer */
	int	retstat;

	if ((adp = fopen(auditdatafile, "r")) == NULL) {
		if (!silent)
			perror(progname);
		return (1);
	}
	retstat = (fscanf(adp, "%ld", p_pid) != 1);
	(void) fclose(adp);
	return (retstat);
}

/*
 * perform reasonableness check on audit_control or its standin; goal
 * is that "audit -s" (1) not crash the system and (2) c2audit/auditd
 * actually generates data.
 *
 * A NULL input is ok -- it is used to tell _openac() to use the
 * real audit_control file, not a substitute.
 */
#define	TRADITIONAL_MAX	1024

static boolean_t
is_audit_control_ok(char *filename) {
	char		buf[TRADITIONAL_MAX];
	int		outputs = 0;
	int		state = 1;	/* 1 is ok, 0 is not */
	int		rc;
	int		min;
	kva_t		*kvlist;
	char		*plugin_name;
	char		*plugin_dir;
	au_acinfo_t	*ach;

	ach = _openac(filename);	/* open audit_control */
	if (ach == NULL) {
		perror(progname);
		exit(9);
	}
	/*
	 * There must be at least one directory or one plugin
	 * defined.
	 */
	if ((rc = _getacdir(ach, buf, TRADITIONAL_MAX)) == 0) {
		outputs++;
	} else if (rc < -1) {	/* -1 is not found, others are errors */
		(void) fprintf(stderr,
			gettext("%s: audit_control \"dir:\" spec invalid\n"),
				progname);
		state = 0;	/* is_not_ok */
	}

	/*
	 * _getacplug -- all that is of interest is the return code.
	 */
	_rewindac(ach);	/* rewind audit_control */
	while ((rc = _getacplug(ach, &kvlist)) == 0) {
		plugin_name = kva_match(kvlist, "name");
		if (plugin_name == NULL) {
			(void) fprintf(stderr, gettext("%s: audit_control "
			    "\"plugin:\" missing name\n"), progname);
			state = 0;	/* is_not_ok */
		} else {
			if (strcmp(plugin_name, "audit_binfile.so") == 0) {
				plugin_dir = kva_match(kvlist, "p_dir");
				if ((plugin_dir == NULL) && (outputs == 0)) {
					(void) fprintf(stderr,
					    gettext("%s: audit_control "
					    "\"plugin:\" missing p_dir\n"),
					    progname);
					state = 0;	/* is_not_ok */
				} else {
					outputs++;
				}
			}
		}
		_kva_free(kvlist);
	}
	if (rc < -1) {
		(void) fprintf(stderr,
			gettext("%s: audit_control \"plugin:\" spec invalid\n"),
				progname);
		state = 0;	/* is_not_ok */
	}
	if (outputs == 0) {
		(void) fprintf(stderr,
			gettext("%s: audit_control must have either a "
				"valid \"dir:\" entry or a valid \"plugin:\" "
				"entry with \"p_dir:\" specified.\n"),
				progname);
		state = 0;	/* is_not_ok */
	}
	/* minfree is not required */
	_rewindac(ach);
	if ((rc = _getacmin(ach, &min)) < -1) {
		(void) fprintf(stderr,
			gettext(
			    "%s: audit_control \"minfree:\" spec invalid\n"),
			    progname);
		state = 0;	/* is_not_ok */
	}
	/* flags is not required */
	_rewindac(ach);
	if ((rc = _getacflg(ach, buf, TRADITIONAL_MAX)) < -1) {
		(void) fprintf(stderr,
			gettext("%s: audit_control \"flags:\" spec invalid\n"),
				progname);
		state = 0;	/* is_not_ok */
	}
	/* naflags is not required */
	_rewindac(ach);
	if ((rc = _getacna(ach, buf, TRADITIONAL_MAX)) < -1) {
		(void) fprintf(stderr,
			gettext(
			    "%s: audit_control \"naflags:\" spec invalid\n"),
			    progname);
		state = 0;	/* is_not_ok */
	}
	_endac(ach);
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
	long	policy;

	if (auditon(A_GETPOLICY, (char *)&policy, 0) == -1) {
		if (!silent)
			(void) fprintf(stderr, gettext(
			    "%s: Cannot read audit policy:  %s\n"),
			    progname, strerror(errno));
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
 * if auditd isn't running, start it.  Otherwise refresh.
 * First check to see if c2audit is loaded via the auditon()
 * system call, then check SMF state.
 */
static int
start_auditd()
{
	int	audit_state;
	char	*state;

	if (auditon(A_GETCOND, (caddr_t)&audit_state,
	    sizeof (audit_state)) != 0)
		return (12);

	if ((state = smf_get_state(instance_name)) == NULL) {
		display_smf_error();
		return (13);
	}
	if (strcmp(SCF_STATE_STRING_ONLINE, state) != 0) {
		if (smf_enable_instance(instance_name, 0) != 0) {
			display_smf_error();
			free(state);
			return (14);
		}
	} else {
		if (smf_refresh_instance(instance_name) != 0) {
			display_smf_error();
			free(state);
			return (15);
		}
	}
	free(state);
	return (0);
}

static void
display_smf_error()
{
	int	rc = scf_error();

	switch (rc) {
	case SCF_ERROR_NOT_FOUND:
		(void) fprintf(stderr,
		    "SMF error: \"%s\" not found.\n",
		    instance_name);
		break;
	default:
		(void) fprintf(stderr, "SMF error: %s\n", scf_strerror(rc));
		break;
	}
}

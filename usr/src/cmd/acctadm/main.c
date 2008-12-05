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

#include <sys/acctctl.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <libintl.h>
#include <libdllink.h>
#include <locale.h>
#include <priv.h>
#include <libscf.h>
#include <zone.h>

#include "utils.h"
#include "aconf.h"
#include "res.h"

static const char USAGE[] = "\
Usage:\n\
    acctadm [ {process | task | flow | net} ]\n\
    acctadm -s\n\
    acctadm -r [ {process | task | flow | net} ]\n\
    acctadm -x|-E|-D {process | task | flow | net}\n\
    acctadm -f filename {process | task | flow | net}\n\
    acctadm -e resources -d resources {process | task | flow | net}\n";

static const char OPTS[] = "rsxf:e:d:ED";

static void
usage()
{
	(void) fprintf(stderr, gettext(USAGE));
	exit(E_USAGE);
}

static void
setup_privs()
{
	priv_set_t *privset;

	if (seteuid(getuid()) == -1 || setegid(getgid()) == -1)
		die(gettext("seteuid()/setegid() failed"));

	/*
	 * Add our privileges and remove unneeded 'basic' privileges from the
	 * permitted set.
	 */
	if ((privset = priv_str_to_set("basic", ",", NULL)) == NULL)
		die(gettext("cannot setup privileges"));

	(void) priv_addset(privset, PRIV_SYS_ACCT);
	(void) priv_addset(privset, PRIV_FILE_DAC_WRITE);
	(void) priv_addset(privset, PRIV_SYS_DL_CONFIG);
	(void) priv_delset(privset, PRIV_FILE_LINK_ANY);
	(void) priv_delset(privset, PRIV_PROC_EXEC);
	(void) priv_delset(privset, PRIV_PROC_FORK);
	(void) priv_delset(privset, PRIV_PROC_INFO);
	(void) priv_delset(privset, PRIV_PROC_SESSION);
	priv_inverse(privset);
	if (setppriv(PRIV_OFF, PRIV_PERMITTED, privset) == -1)
		die(gettext("cannot setup privileges"));
	priv_freeset(privset);

	/*
	 * Clear the Inheritable and Limit sets.
	 */
	if ((privset = priv_allocset()) == NULL)
		die(gettext("cannot setup privileges"));
	priv_emptyset(privset);
	if (setppriv(PRIV_SET, PRIV_INHERITABLE, privset) == -1 ||
	    setppriv(PRIV_SET, PRIV_LIMIT, privset) == -1)
		die(gettext("cannot setup privileges"));

	/*
	 * Turn off the sys_acct, file_dac_write and dl_config privileges
	 * until needed.
	 */
	(void) priv_set(PRIV_OFF, PRIV_EFFECTIVE, PRIV_FILE_DAC_WRITE,
	    PRIV_SYS_ACCT, PRIV_SYS_DL_CONFIG, NULL);
}

int
main(int argc, char *argv[])
{
	int c;			/* options character */
	int type = 0;		/* type of accounting */
	int modified = 0;	/* have we modified any properties? */
	acctconf_t ac;		/* current configuration */
	char *typestr = NULL;	/* type of accounting argument string */
	char *enabled = NULL;	/* enabled resources string */
	char *disabled = NULL;	/* disabled resources string */
	char *file = NULL;
	int Eflg = 0;
	int Dflg = 0;
	int rflg = 0;
	int sflg = 0;
	int xflg = 0;
	int optcnt = 0;
	int state;
	const char *fmri;	/* FMRI for this instance */

	setup_privs();

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);
	(void) setprogname(argv[0]);

	for (; optind < argc; optind++) {
		while ((c = getopt(argc, argv, OPTS)) != (int)EOF) {
			switch (c) {
			case 'd':
				disabled = optarg;
				break;
			case 'e':
				enabled = optarg;
				break;
			case 'D':
				Dflg = 1;
				optcnt++;
				break;
			case 'E':
				Eflg = 1;
				optcnt++;
				break;
			case 'f':
				file = optarg;
				optcnt++;
				break;
			case 'r':
				rflg = 1;
				optcnt++;
				break;
			case 's':
				sflg = 1;
				optcnt++;
				break;
			case 'x':
				xflg = 1;
				optcnt++;
				break;
			case '?':
			default:
				usage();
			}
		}

		/*
		 * Permanently give up euid 0, egid 0 and privileges we
		 * don't need for the specified options.
		 */
		if (!(file || sflg)) {
			if (setreuid(getuid(), getuid()) == -1 ||
			    setregid(getgid(), getgid()) == -1)
				die(gettext("setreuid()/setregid() failed"));
			(void) priv_set(PRIV_OFF, PRIV_PERMITTED,
			    PRIV_FILE_DAC_WRITE, NULL);
		}
		if (!(disabled || enabled || Dflg || Eflg || file || sflg ||
		    xflg))
			(void) priv_set(PRIV_OFF, PRIV_PERMITTED,
			    PRIV_SYS_ACCT, PRIV_SYS_DL_CONFIG, NULL);

		if (optind < argc) {
			if (typestr != NULL) {
				warn(gettext("illegal argument -- %s\n"),
				    argv[optind]);
				usage();
			} else {
				typestr = argv[optind];
			}
		}
	}
	if (typestr != NULL) {
		if (strcmp(typestr, "process") == 0 ||
		    strcmp(typestr, "proc") == 0)
			type |= AC_PROC;
		else if (strcmp(typestr, "task") == 0)
			type |= AC_TASK;
		else if (strcmp(typestr, "flow") == 0)
			type |= AC_FLOW;
		else if (strcmp(typestr, "net") == 0)
			type |= AC_NET;
		else {
			warn(gettext("unknown accounting type -- %s\n"),
			    typestr);
			usage();
		}
	} else
		type = AC_PROC | AC_TASK | AC_FLOW | AC_NET;

	/*
	 * Drop the DL config privilege if we are not working with
	 * net.
	 */
	if ((type & AC_NET) == 0) {
		(void) priv_set(PRIV_OFF, PRIV_PERMITTED,
		    PRIV_SYS_DL_CONFIG, NULL);
	}
	/*
	 * check for invalid options
	 */
	if (optcnt > 1)
		usage();

	/*
	 * XXX For AC_NET, enabled/disabled should only be "basic" or
	 * "extended" - need to check it here.
	 */
	if ((enabled || disabled) && (rflg || Dflg || sflg || xflg || Eflg))
		usage();

	if ((file || xflg || Dflg || Eflg || enabled || disabled) &&
	    !typestr) {
		warn(gettext("accounting type must be specified\n"));
		usage();
	}

	if (rflg) {
		printgroups(type);
		return (E_SUCCESS);
	}

	/*
	 * If no arguments have been passed then just print out the current
	 * state and exit.
	 */
	if (!enabled && !disabled && !file &&
	    !Eflg && !rflg && !Dflg && !sflg && !xflg) {
		aconf_print(stdout, type);
		return (E_SUCCESS);
	}

	/*
	 * smf(5) start method.  The FMRI to operate on is retrieved from the
	 * SMF_FMRI environment variable that the restarter provides.
	 */
	if (sflg) {
		if ((fmri = getenv("SMF_FMRI")) != NULL)
			return (aconf_setup(fmri));

		warn(gettext("-s option should only be invoked by smf(5)\n"));
		return (E_ERROR);
	}

	assert(type == AC_PROC || type == AC_TASK || type == AC_FLOW ||
	    type == AC_NET);

	if ((type == AC_FLOW || type == AC_NET) && getzoneid() != GLOBAL_ZONEID)
		die(gettext("%s accounting cannot be configured in "
		    "non-global zones\n"), ac_type_name(type));

	fmri = aconf_type2fmri(type);
	if (aconf_scf_init(fmri) == -1)
		die(gettext("cannot connect to repository for %s\n"), fmri);

	/*
	 * Since the sys_acct the privilege allows use of acctctl() regardless
	 * of the accounting type, we check the smf(5) authorizations granted
	 * to the user to determine whether the user is allowed to change the
	 * configuration for this particular accounting type.
	 */
	if (!aconf_have_smf_auths())
		die(gettext("insufficient authorization to change %s extended "
		    "accounting configuration\n"), ac_type_name(type));

	if (xflg) {
		/*
		 * Turn off the specified accounting and close its file
		 */

		/*
		 * Stop net logging before turning it off so that the last
		 * set of logs can be written.
		 */
		if (type & AC_NET) {
			(void) priv_set(PRIV_ON, PRIV_EFFECTIVE,
			    PRIV_SYS_DL_CONFIG, NULL);
			(void) dladm_stop_usagelog(DLADM_LOGTYPE_FLOW);
			(void) priv_set(PRIV_OFF, PRIV_EFFECTIVE,
			    PRIV_SYS_DL_CONFIG, NULL);
		}
		state = AC_OFF;

		(void) priv_set(PRIV_ON, PRIV_EFFECTIVE, PRIV_SYS_ACCT, NULL);
		if (acctctl(type | AC_STATE_SET, &state, sizeof (int)) == -1)
			die(gettext("cannot disable %s accounting"),
			    ac_type_name(type));
		if (acctctl(type | AC_FILE_SET, NULL, 0) == -1)
			die(gettext("cannot close %s accounting file\n"),
			    ac_type_name(type));
		(void) priv_set(PRIV_OFF, PRIV_EFFECTIVE, PRIV_SYS_ACCT, NULL);

		if (aconf_set_bool(AC_PROP_STATE, B_FALSE) == -1)
			die(gettext("cannot update %s property\n"),
			    AC_PROP_STATE);
		if (aconf_set_string(AC_PROP_FILE, AC_STR_NONE) == -1)
			die(gettext("cannot update %s property\n"),
			    AC_PROP_FILE);
		modified++;
	}

	if (enabled || disabled) {
		char *tracked, *untracked;
		ac_res_t *buf;

		/*
		 * Enable/disable resources
		 */
		if ((buf = malloc(AC_BUFSIZE)) == NULL)
			die(gettext("not enough memory\n"));
		(void) memset(buf, 0, AC_BUFSIZE);
		if (acctctl(type | AC_RES_GET, buf, AC_BUFSIZE) == -1) {
			free(buf);
			die(gettext("cannot obtain list of resources\n"));
		}
		if (disabled) {
			/*
			 * Stop net logging before turning it off so that the
			 * last set of logs can be written.
			 */
			if (type & AC_NET) {
				(void) priv_set(PRIV_ON, PRIV_EFFECTIVE,
				    PRIV_SYS_DL_CONFIG, NULL);
				(void) dladm_stop_usagelog(strncmp(disabled,
				    "basic", strlen("basic")) == 0 ?
				    DLADM_LOGTYPE_LINK : DLADM_LOGTYPE_FLOW);
				(void) priv_set(PRIV_OFF, PRIV_EFFECTIVE,
				    PRIV_SYS_DL_CONFIG, NULL);
			}
			str2buf(buf, disabled, AC_OFF, type);
		}
		if (enabled)
			str2buf(buf, enabled, AC_ON, type);

		(void) priv_set(PRIV_ON, PRIV_EFFECTIVE, PRIV_SYS_ACCT, NULL);
		if (acctctl(type | AC_RES_SET, buf, AC_BUFSIZE) == -1) {
			free(buf);
			die(gettext("cannot enable/disable %s accounting "
			    "resources\n"), ac_type_name(type));
		}
		(void) priv_set(PRIV_OFF, PRIV_EFFECTIVE, PRIV_SYS_ACCT, NULL);

		tracked = buf2str(buf, AC_BUFSIZE, AC_ON, type);
		untracked = buf2str(buf, AC_BUFSIZE, AC_OFF, type);
		if (aconf_set_string(AC_PROP_TRACKED, tracked) == -1)
			die(gettext("cannot update %s property\n"),
			    AC_PROP_TRACKED);
		if (aconf_set_string(AC_PROP_UNTRACKED, untracked) == -1)
			die(gettext("cannot update %s property\n"),
			    AC_PROP_UNTRACKED);
		/*
		 * We will enable net logging after turning it on so that
		 * it can immediately start writing log.
		 */
		if (type & AC_NET && enabled != NULL) {
			/*
			 * Default logging interval for AC_NET is 20.
			 * XXX need to find the right place to
			 * configure it.
			 */
			(void) priv_set(PRIV_ON, PRIV_EFFECTIVE,
			    PRIV_SYS_DL_CONFIG, NULL);
			(void) dladm_start_usagelog(strncmp(enabled, "basic",
			    strlen("basic")) == 0 ? DLADM_LOGTYPE_LINK :
			    DLADM_LOGTYPE_FLOW, 20);
			(void) priv_set(PRIV_OFF, PRIV_EFFECTIVE,
			    PRIV_SYS_DL_CONFIG, NULL);
		}
		free(tracked);
		free(untracked);
		free(buf);
		modified++;
	}

	if (file) {
		/*
		 * Open new accounting file
		 */
		(void) priv_set(PRIV_ON, PRIV_EFFECTIVE, PRIV_SYS_ACCT, NULL);
		if (open_exacct_file(file, type) == -1)
			exit(E_ERROR);
		if (aconf_set_string(AC_PROP_FILE, file) == -1)
			die(gettext("cannot update %s property\n"),
			    AC_PROP_FILE);
		state = AC_ON;

		if (acctctl(type | AC_STATE_SET, &state, sizeof (int)) == -1)
			die(gettext("cannot enable %s accounting"),
			    ac_type_name(type));
		(void) priv_set(PRIV_OFF, PRIV_EFFECTIVE, PRIV_SYS_ACCT, NULL);

		if (aconf_set_bool(AC_PROP_STATE, B_TRUE) == -1)
			die(gettext("cannot update %s property\n"),
			    AC_PROP_STATE);
		modified++;
	}

	if (Dflg) {
		/*
		 * Disable accounting
		 */

		/*
		 * Stop net logging before turning it off so that the last
		 * set of logs can be written.
		 */
		if (type & AC_NET) {
			(void) priv_set(PRIV_ON, PRIV_EFFECTIVE,
			    PRIV_SYS_DL_CONFIG, NULL);
			(void) dladm_stop_usagelog(DLADM_LOGTYPE_FLOW);
			(void) priv_set(PRIV_OFF, PRIV_EFFECTIVE,
			    PRIV_SYS_DL_CONFIG, NULL);
		}
		state = AC_OFF;

		(void) priv_set(PRIV_ON, PRIV_EFFECTIVE, PRIV_SYS_ACCT, NULL);
		if (acctctl(type | AC_STATE_SET, &state, sizeof (int)) == -1)
			die(gettext("cannot disable %s accounting"),
			    ac_type_name(type));
		(void) priv_set(PRIV_OFF, PRIV_EFFECTIVE, PRIV_SYS_ACCT, NULL);

		if (aconf_set_bool(AC_PROP_STATE, B_FALSE) == -1)
			die(gettext("cannot update %s property\n"),
			    AC_PROP_STATE);
		modified++;
	}

	if (Eflg) {
		/*
		 * Enable accounting
		 */
		state = AC_ON;

		(void) priv_set(PRIV_ON, PRIV_EFFECTIVE, PRIV_SYS_ACCT, NULL);
		if (acctctl(type | AC_STATE_SET, &state, sizeof (int)) == -1)
			die(gettext("cannot enable %s accounting"),
			    ac_type_name(type));
		(void) priv_set(PRIV_OFF, PRIV_EFFECTIVE, PRIV_SYS_ACCT, NULL);

		if (aconf_set_bool(AC_PROP_STATE, B_TRUE) == -1)
			die(gettext("cannot update %s property\n"),
			    AC_PROP_STATE);
		modified++;
		if (type & AC_NET) {
			/*
			 * Default logging interval for AC_NET is 20,
			 * XXX need to find the right place to configure it.
			 */
			(void) priv_set(PRIV_ON, PRIV_EFFECTIVE,
			    PRIV_SYS_DL_CONFIG, NULL);
			(void) dladm_start_usagelog(DLADM_LOGTYPE_FLOW, 20);
			(void) priv_set(PRIV_OFF, PRIV_EFFECTIVE,
			    PRIV_SYS_DL_CONFIG, NULL);
		}
	}
	(void) priv_set(PRIV_OFF, PRIV_PERMITTED, PRIV_SYS_ACCT, NULL);

	if (modified) {
		char *smf_state;

		if (aconf_save() == -1)
			die(gettext("cannot save %s accounting "
			    "configuration\n"), ac_type_name(type));

		/*
		 * Enable or disable the instance depending on the effective
		 * configuration.  If the effective configuration results in
		 * extended accounting being 'on', the instance is enabled so
		 * the configuration is applied at the next boot.
		 */
		smf_state = smf_get_state(fmri);
		aconf_init(&ac, type);

		if (ac.state == AC_ON ||
		    strcmp(ac.file, AC_STR_NONE) != 0 ||
		    strcmp(ac.tracked, AC_STR_NONE) != 0) {
			if (strcmp(smf_state, SCF_STATE_STRING_ONLINE) != 0)
				if (smf_enable_instance(fmri, 0) == -1)
					die(gettext("cannot enable %s\n"),
					    fmri);
		} else {
			if (strcmp(smf_state, SCF_STATE_STRING_ONLINE) == 0)
				if (smf_disable_instance(fmri, 0) == -1)
					die(gettext("cannot disable %s\n"),
					    fmri);
		}
		free(smf_state);
	}
	aconf_scf_fini();
	return (E_SUCCESS);
}

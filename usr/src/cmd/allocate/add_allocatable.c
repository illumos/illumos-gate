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

/*
 * add_allocatable -
 *	a command-line interface to add device to device_allocate and
 *	device_maps.
 */

#ifndef	__EXTENSIONS__
#define	__EXTENSIONS__		/* needed for _strtok_r */
#endif

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <locale.h>
#include <libintl.h>
#include <pwd.h>
#include <nss_dbdefs.h>
#include <auth_attr.h>
#include <auth_list.h>
#include <zone.h>
#include <tsol/label.h>
#include <bsm/devices.h>
#include <bsm/devalloc.h>

#define	NO_OVERRIDE	-1

int check_args(da_args *);
int process_args(int, char **, da_args *, char *);
int scan_label(char *, char *);
void usage(da_args *, char *);

int system_labeled = 0;

int
main(int argc, char *argv[])
{
	int		rc;
	uid_t		uid;
	char		*progname;
	char		pwbuf[NSS_LINELEN_PASSWD];
	struct passwd	pwd;
	da_args		dargs;
	devinfo_t	devinfo;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);
	if ((progname = strrchr(argv[0], '/')) == NULL)
		progname = argv[0];
	else
		progname++;

	system_labeled = is_system_labeled();
	if (system_labeled) {
		/*
		 * this command can be run only in the global zone.
		 */
		if (getzoneid() != GLOBAL_ZONEID) {
			(void) fprintf(stderr, "%s%s", progname,
			    gettext(" : must be run in global zone\n"));
			exit(1);
		}
	} else {
		/*
		 * this command works in Trusted Extensions only.
		 */
		(void) fprintf(stderr, "%s%s", progname,
		    gettext(" : need to install Trusted Extensions\n"));
		exit(1);
	}

	dargs.optflag = 0;
	dargs.rootdir = NULL;
	dargs.devnames = NULL;
	dargs.devinfo = &devinfo;

	if (strcmp(progname, "add_allocatable") == 0) {
		dargs.optflag |= DA_ADD;
	} else if (strcmp(progname, "remove_allocatable") == 0) {
		dargs.optflag |= DA_REMOVE;
	} else {
		usage(&dargs, progname);
		exit(1);
	}

	uid = getuid();
	if ((getpwuid_r(uid, &pwd, pwbuf, sizeof (pwbuf))) == NULL) {
		(void) fprintf(stderr, "%s%s", progname,
		    gettext(" : getpwuid_r failed: "));
		(void) fprintf(stderr, "%s\n", strerror(errno));
		exit(2);
	}

	if (chkauthattr(DEVICE_CONFIG_AUTH, pwd.pw_name) != 1) {
		(void) fprintf(stderr, "%s%s%s", progname,
		    gettext(" : user lacks authorization:  \n"),
		    DEVICE_CONFIG_AUTH);
		exit(4);
	}

	if (process_args(argc, argv, &dargs, progname) != 0) {
		usage(&dargs, progname);
		exit(1);
	}

	if (dargs.optflag & DA_ADD) {
		if (check_args(&dargs) == NO_OVERRIDE) {
			(void) fprintf(stderr, "%s%s%s%s", progname,
			    gettext(" : entry exists for "),
			    dargs.devinfo->devname, gettext("\n"));
			usage(&dargs, progname);
			exit(3);
		}
	}

	if (dargs.optflag & DA_DEFATTRS)
		rc = da_update_defattrs(&dargs);
	else
		rc = da_update_device(&dargs);

	if ((rc != 0) && (!(dargs.optflag & DA_SILENT))) {
		if (rc == -2)
			(void) fprintf(stderr, "%s%s", progname,
			    gettext(" : device name/type/list missing\n"));
		else if (dargs.optflag & DA_ADD)
			(void) fprintf(stderr, "%s%s", progname,
			    gettext(" : error adding/updating device\n"));
		else if (dargs.optflag & DA_REMOVE)
			(void) fprintf(stderr, "%s%s", progname,
			    gettext(" : error removing device\n"));
		rc = 2;	/* exit code for 'Unknown system error' in man page */
	}

	return (rc);
}

int
process_args(int argc, char **argv, da_args *dargs, char *progname)
{
	int 		c;
	int		aflag, cflag, dflag, fflag, lflag, nflag, oflag, tflag;
	extern char	*optarg;
	devinfo_t	*devinfo;

	devinfo = dargs->devinfo;
	aflag = cflag = dflag = fflag = lflag = nflag = oflag = tflag = 0;
	devinfo->devname = devinfo->devtype = devinfo->devauths =
	    devinfo->devexec = devinfo->devopts = devinfo->devlist = NULL;
	devinfo->instance = 0;

	while ((c = getopt(argc, argv, "a:c:dfl:n:o:st:")) != EOF) {
		switch (c) {
		case 'a':
			devinfo->devauths = optarg;
			aflag++;
			break;
		case 'c':
			devinfo->devexec = optarg;
			if (strlen(devinfo->devexec) == 0) {
				if (!(dargs->optflag & DA_SILENT))
					(void) fprintf(stderr, "%s%s", progname,
					    gettext(" : device clean program"
					    " name not found\n"));
				return (1);
			}
			cflag++;
			break;
		case 'd':
			dargs->optflag |= DA_DEFATTRS;
			dflag++;
			break;
		case 'l':
			devinfo->devlist = optarg;
			if (strlen(devinfo->devlist) == 0) {
				if (!(dargs->optflag & DA_SILENT))
					(void) fprintf(stderr, "%s%s", progname,
					    gettext(" : device file list"
					    " not found\n"));
				return (1);
			}
			lflag++;
			break;
		case 'f':
			dargs->optflag |= DA_FORCE;
			fflag++;
			break;
		case 'n':
			devinfo->devname = optarg;
			if (strlen(devinfo->devname) == 0) {
				if (!(dargs->optflag & DA_SILENT))
					(void) fprintf(stderr, "%s%s", progname,
					    gettext(" : device name "
					    "not found\n"));
				return (1);
			}
			nflag++;
			break;
		case 'o':
			/* check for field delimiters in the option */
			if (strpbrk(optarg, ":;=") == NULL) {
				if (!(dargs->optflag & DA_SILENT)) {
					(void) fprintf(stderr, "%s%s%s",
					    progname,
					    gettext(" : invalid "
					    "key=val string: "),
					    optarg);
					(void) fprintf(stderr, "%s",
					    gettext("\n"));
				}
				return (1);
			}
			devinfo->devopts = optarg;
			if (dargs->optflag & DA_ADD) {
				if (scan_label(devinfo->devopts, progname) != 0)
					return (1);
			}
			oflag++;
			break;
		case 's':
			dargs->optflag |= DA_SILENT;
			break;
		case 't':
			devinfo->devtype = optarg;
			if (strlen(devinfo->devtype) == 0) {
				if (!(dargs->optflag & DA_SILENT))
					(void) fprintf(stderr, "%s%s", progname,
					    gettext(" : device type "
					    "not found\n"));
				return (1);
			}
			tflag++;
			break;
		default	:
			return (1);
		}
	}


	if (dargs->optflag & DA_ADD) {
		if (dflag) {
			/* -d requires -t, but does not like -n */
			if (nflag || tflag == 0)
				return (1);
		} else if (nflag == 0 && tflag == 0 && lflag == 0) {
			/* require at least -n or -t or -l to be specified */
			if (!(dargs->optflag & DA_SILENT))
				(void) fprintf(stderr, "%s%s", progname,
				    gettext(" : required options missing\n"));
			return (1);
		}
	} else if (dargs->optflag & DA_REMOVE) {
		if (dflag) {
			/* -d requires -t, but does not like -n */
			if (nflag || tflag == 0)
				return (1);
		} else if (nflag == 0 && tflag == 0) {
			/* require at least -n or -t to be specified */
			if (!(dargs->optflag & DA_SILENT))
				(void) fprintf(stderr, "%s%s", progname,
				    gettext(" : required options missing\n"));
			return (1);
		}
		/* there's a bunch not accepted by remove_allocatable */
		if (aflag || cflag || lflag || oflag)
			return (1);
	} else {
		return (1);
	}

	/* check for option specified more than once */
	if (aflag > 1 || cflag > 1 || lflag > 1 || fflag > 1 ||
	    nflag > 1 || tflag > 1) {
		if (!(dargs->optflag & DA_SILENT))
			(void) fprintf(stderr, "%s%s", progname,
			    gettext(" : multiple-defined options\n"));
		return (1);
	}

	return (0);
}

int
verify_label(char *token, char *progname)
{
	int		error = 0;
	char		*p, *val, *str;

	if ((strstr(token, DAOPT_MINLABEL) == NULL) &&
	    (strstr(token, DAOPT_MAXLABEL) == NULL)) {
		/* no label specified */
		return (0);
	}
	if ((val = strchr(token, '=')) == NULL)
		return (1);
	val++;
	/*
	 * if non-default labels are specified, check if they are correct
	 */
	if ((strcmp(val, DA_DEFAULT_MIN) != 0) &&
	    (strcmp(val, DA_DEFAULT_MAX) != 0)) {
		m_label_t	*slabel = NULL;

		str = strdup(val);
		/* get rid of double quotes if they exist */
		while (*str == '"')
			str++;
		if ((p = strchr(str, '"')) != NULL)
			*p = '\0';
		if (str_to_label(str, &slabel, MAC_LABEL, L_NO_CORRECTION,
		    &error) == -1) {
			(void) fprintf(stderr, "%s%s%s", progname,
			    gettext(" : bad label input: "),
			    val);
			(void) fprintf(stderr, "%s", gettext("\n"));
			free(str);
			m_label_free(slabel);
			return (1);
		}
		free(str);
		m_label_free(slabel);
	}

	return (0);
}

int
scan_label(char *devopts, char *progname)
{
	char		*tok = NULL;
	char		*lasts, *optsarg;

	if (devopts == NULL)
		return (0);

	if ((optsarg = strdup(devopts)) == NULL)
		return (1);

	if ((tok = strtok_r(optsarg, KV_TOKEN_DELIMIT, &lasts)) == NULL)
		return (1);

	if (verify_label(tok, progname) != 0) {
		free(optsarg);
		return (1);
	}

	while ((tok = strtok_r(NULL, KV_TOKEN_DELIMIT, &lasts)) != NULL) {
		if (verify_label(tok, progname) != 0) {
			free(optsarg);
			return (1);
		}
	}

	return (0);
}

int
check_args(da_args *dargs)
{
	int		nlen;
	char		*kval, *nopts, *ntok, *nstr,
	    *defmin, *defmax, *defauths, *defexec;
	kva_t		*kva;
	devinfo_t	*devinfo;
	devalloc_t	*da = NULL;
	da_defs_t	*da_defs = NULL;

	devinfo = dargs->devinfo;
	/*
	 * check if we're updating an existing entry without -f
	 */
	setdaent();
	da = getdanam(devinfo->devname);
	enddaent();
	if (da && !(dargs->optflag & DA_FORCE)) {
		freedaent(da);
		return (NO_OVERRIDE);
	}
	if ((devinfo->devopts == NULL) ||
	    (strstr(devinfo->devopts, DAOPT_MINLABEL) == NULL) ||
	    (strstr(devinfo->devopts, DAOPT_MAXLABEL) == NULL) ||
	    (devinfo->devauths == NULL) ||
	    (devinfo->devexec == NULL)) {
		/* fill in defaults as required */
		defmin = DA_DEFAULT_MIN;
		defmax = DA_DEFAULT_MAX;
		defauths = DEFAULT_DEV_ALLOC_AUTH;
		defexec = DA_DEFAULT_CLEAN;
		setdadefent();
		if (da_defs = getdadeftype(devinfo->devtype)) {
			kva = da_defs->devopts;
			if ((kval = kva_match(kva, DAOPT_MINLABEL)) != NULL)
				defmin = strdup(kval);
			if ((kval = kva_match(kva, DAOPT_MAXLABEL)) != NULL)
				defmax = strdup(kval);
			if ((kval = kva_match(kva, DAOPT_AUTHS)) != NULL)
				defauths = strdup(kval);
			if ((kval = kva_match(kva, DAOPT_CSCRIPT)) != NULL)
				defexec = strdup(kval);
			freedadefent(da_defs);
		}
		enddadefent();
		if (devinfo->devauths == NULL)
			devinfo->devauths = defauths;
		if (devinfo->devexec == NULL)
			devinfo->devexec = defexec;
		if (devinfo->devopts == NULL) {
			/* add default minlabel and maxlabel */
			nlen = strlen(DAOPT_MINLABEL) + strlen(KV_ASSIGN) +
			    strlen(defmin) + strlen(KV_TOKEN_DELIMIT) +
			    strlen(DAOPT_MAXLABEL) + strlen(KV_ASSIGN) +
			    strlen(defmax) + 1;		/* +1 for terminator */
			if (nopts = (char *)malloc(nlen)) {
				(void) snprintf(nopts, nlen, "%s%s%s%s%s%s%s",
				    DAOPT_MINLABEL, KV_ASSIGN, defmin,
				    KV_TOKEN_DELIMIT,
				    DAOPT_MAXLABEL, KV_ASSIGN, defmax);
				devinfo->devopts = nopts;
			}
		} else {
			if (strstr(devinfo->devopts, DAOPT_MINLABEL) == NULL) {
				/* add default minlabel */
				ntok = DAOPT_MINLABEL;
				nstr = defmin;
				nlen = strlen(devinfo->devopts) +
				    strlen(KV_TOKEN_DELIMIT) +
				    strlen(ntok) + strlen(KV_ASSIGN) +
				    strlen(nstr) + 1;
				if (nopts = (char *)malloc(nlen)) {
					(void) snprintf(nopts, nlen,
					    "%s%s%s%s%s",
					    devinfo->devopts, KV_TOKEN_DELIMIT,
					    ntok, KV_ASSIGN, nstr);
					devinfo->devopts = nopts;
				}
			}
			if (strstr(devinfo->devopts, DAOPT_MAXLABEL) == NULL) {
				/* add default maxlabel */
				ntok = DAOPT_MAXLABEL;
				nstr = defmax;
				nlen = strlen(devinfo->devopts) +
				    strlen(KV_TOKEN_DELIMIT) +
				    strlen(ntok) + strlen(KV_ASSIGN) +
				    strlen(nstr) + 1;
				if (nopts = (char *)malloc(nlen)) {
					(void) snprintf(nopts, nlen,
					    "%s%s%s%s%s",
					    devinfo->devopts, KV_TOKEN_DELIMIT,
					    ntok, KV_ASSIGN, nstr);
					devinfo->devopts = nopts;
				}
			}
		}
	}

	return (0);
}

void
usage(da_args *dargs, char *progname)
{
	if (dargs->optflag & DA_SILENT)
		return;
	if (dargs->optflag & DA_ADD)
		(void) fprintf(stderr, "%s%s%s", gettext("Usage: "), progname,
		    gettext(" [-f][-s][-d] -n name -t type -l device-list"
		    "\n\t[-a authorization] [-c cleaning program] "
		    "[-o key=value]\n"));
	else if (dargs->optflag & DA_REMOVE)
		(void) fprintf(stderr, "%s%s%s", gettext("Usage: "), progname,
		    gettext(" [-f][-s][-d] [-n name|-t type]\n"));
	else
		(void) fprintf(stderr, gettext("Invalid usage\n"), progname);
}

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
 * Copyright (c) 2013 Gary Mills
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 2013 RackTop Systems.
 */

#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/param.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<ctype.h>
#include	<limits.h>
#include	<string.h>
#include	<userdefs.h>
#include	<errno.h>
#include	<project.h>
#include	<unistd.h>
#include	<user_attr.h>
#include	<libcmdutils.h>
#include	"users.h"
#include	"messages.h"
#include	"userdisp.h"
#include	"funcs.h"

/*
 *  useradd [-u uid [-o] | -g group | -G group [[, group]...] | -d dir [-m]
 *		| -s shell | -c comment | -k skel_dir | -b base_dir] ]
 *		[ -A authorization [, authorization ...]]
 *		[ -P profile [, profile ...]]
 *		[ -K key=value ]
 *		[ -R role [, role ...]] [-p project [, project ...]] login
 *  useradd -D [ -g group ] [ -b base_dir | -f inactive | -e expire |
 *		-s shell | -k skel_dir ]
 *		[ -A authorization [, authorization ...]]
 *		[ -P profile [, profile ...]] [ -K key=value ]
 *		[ -R role [, role ...]] [-p project [, project ...]] login
 *
 *	This command adds new user logins to the system.  Arguments are:
 *
 *	uid - an integer
 *	group - an existing group's integer ID or char string name
 *	dir - home directory
 *	shell - a program to be used as a shell
 *	comment - any text string
 *	skel_dir - a skeleton directory
 *	base_dir - a directory
 *	login - a string of printable chars except colon(:)
 *	authorization - One or more comma separated authorizations defined
 *			in auth_attr(4).
 *	profile - One or more comma separated execution profiles defined
 *		  in prof_attr(4)
 *	role - One or more comma-separated role names defined in user_attr(4)
 *	project - One or more comma-separated project names or numbers
 *
 */

extern struct userdefs *getusrdef();
extern void dispusrdef();

static void cleanup();

extern int check_perm(), valid_expire();
extern int putusrdef(), valid_uid();
extern int call_passmgmt(), edit_group(), create_home();
extern int edit_project();
extern int **valid_lgroup();
extern projid_t **valid_lproject();
extern void update_def(struct userdefs *);
extern void import_def(struct userdefs *);

static uid_t uid;			/* new uid */
static char *logname;			/* login name to add */
static struct userdefs *usrdefs;	/* defaults for useradd */

char *cmdname;

static char homedir[ PATH_MAX + 1 ];	/* home directory */
static char gidstring[32];		/* group id string representation */
static gid_t gid;			/* gid of new login */
static char uidstring[32];		/* user id string representation */
static char *uidstr = NULL;		/* uid from command line */
static char *base_dir = NULL;		/* base_dir from command line */
static char *group = NULL;		/* group from command line */
static char *grps = NULL;		/* multi groups from command line */
static char *dir = NULL;		/* home dir from command line */
static char *shell = NULL;		/* shell from command line */
static char *comment = NULL;		/* comment from command line */
static char *skel_dir = NULL;		/* skel dir from command line */
static long inact;			/* inactive days */
static char *inactstr = NULL;		/* inactive from command line */
static char inactstring[10];		/* inactivity string representation */
static char *expirestr = NULL;		/* expiration date from command line */
static char *projects = NULL;		/* project id's from command line */

static char *usertype = NULL;	/* type of user, either role or normal */

typedef enum {
	BASEDIR	= 0,
	SKELDIR,
	SHELL
} path_opt_t;


static void valid_input(path_opt_t, const char *);

int
main(argc, argv)
int argc;
char *argv[];
{
	int ch, ret, mflag = 0, oflag = 0, Dflag = 0, **gidlist = NULL;
	projid_t **projlist = NULL;
	char *ptr;			/* loc in a str, may be set by strtol */
	struct group *g_ptr;
	struct project p_ptr;
	char mybuf[PROJECT_BUFSZ];
	struct stat statbuf;		/* status buffer for stat */
	int warning;
	int busy = 0;
	char **nargv;			/* arguments for execvp of passmgmt */
	int argindex;			/* argument index into nargv */

	cmdname = argv[0];

	if (geteuid() != 0) {
		errmsg(M_PERM_DENIED);
		exit(EX_NO_PERM);
	}

	opterr = 0;			/* no print errors from getopt */
	usertype = getusertype(argv[0]);

	change_key(USERATTR_TYPE_KW, usertype);

	while ((ch = getopt(argc, argv,
		    "b:c:Dd:e:f:G:g:k:mop:s:u:A:P:R:K:")) != EOF)
		switch (ch) {
		case 'b':
			base_dir = optarg;
			break;

		case 'c':
			comment = optarg;
			break;

		case 'D':
			Dflag++;
			break;

		case 'd':
			dir = optarg;
			break;

		case 'e':
			expirestr = optarg;
			break;

		case 'f':
			inactstr = optarg;
			break;

		case 'G':
			grps = optarg;
			break;

		case 'g':
			group = optarg;
			break;

		case 'k':
			skel_dir = optarg;
			break;

		case 'm':
			mflag++;
			break;

		case 'o':
			oflag++;
			break;

		case 'p':
			projects = optarg;
			break;

		case 's':
			shell = optarg;
			break;

		case 'u':
			uidstr = optarg;
			break;

		case 'A':
			change_key(USERATTR_AUTHS_KW, optarg);
			break;

		case 'P':
			change_key(USERATTR_PROFILES_KW, optarg);
			break;

		case 'R':
			if (is_role(usertype)) {
				errmsg(M_ARUSAGE);
				exit(EX_SYNTAX);
			}
			change_key(USERATTR_ROLES_KW, optarg);
			break;

		case 'K':
			change_key(NULL, optarg);
			break;

		default:
		case '?':
			if (is_role(usertype))
				errmsg(M_ARUSAGE);
			else
				errmsg(M_AUSAGE);
			exit(EX_SYNTAX);
		}

	/* get defaults for adding new users */
	usrdefs = getusrdef(usertype);

	if (Dflag) {
		/* DISPLAY mode */

		/* check syntax */
		if (optind != argc) {
			if (is_role(usertype))
				errmsg(M_ARUSAGE);
			else
				errmsg(M_AUSAGE);
			exit(EX_SYNTAX);
		}

		if (uidstr != NULL || oflag || grps != NULL ||
		    dir != NULL || mflag || comment != NULL) {
			if (is_role(usertype))
				errmsg(M_ARUSAGE);
			else
				errmsg(M_AUSAGE);
			exit(EX_SYNTAX);
		}

		/* Group must be an existing group */
		if (group != NULL) {
			switch (valid_group(group, &g_ptr, &warning)) {
			case INVALID:
				errmsg(M_INVALID, group, "group id");
				exit(EX_BADARG);
				/*NOTREACHED*/
			case TOOBIG:
				errmsg(M_TOOBIG, "gid", group);
				exit(EX_BADARG);
				/*NOTREACHED*/
			case RESERVED:
			case UNIQUE:
				errmsg(M_GRP_NOTUSED, group);
				exit(EX_NAME_NOT_EXIST);
			}
			if (warning)
				warningmsg(warning, group);

			usrdefs->defgroup = g_ptr->gr_gid;
			usrdefs->defgname = g_ptr->gr_name;

		}

		/* project must be an existing project */
		if (projects != NULL) {
			switch (valid_project(projects, &p_ptr, mybuf,
			    sizeof (mybuf), &warning)) {
			case INVALID:
				errmsg(M_INVALID, projects, "project id");
				exit(EX_BADARG);
				/*NOTREACHED*/
			case TOOBIG:
				errmsg(M_TOOBIG, "projid", projects);
				exit(EX_BADARG);
				/*NOTREACHED*/
			case UNIQUE:
				errmsg(M_PROJ_NOTUSED, projects);
				exit(EX_NAME_NOT_EXIST);
			}
			if (warning)
				warningmsg(warning, projects);

			usrdefs->defproj = p_ptr.pj_projid;
			usrdefs->defprojname = p_ptr.pj_name;
		}

		/* base_dir must be an existing directory */
		if (base_dir != NULL) {
			valid_input(BASEDIR, base_dir);
			usrdefs->defparent = base_dir;
		}

		/* inactivity period is an integer */
		if (inactstr != NULL) {
			/* convert inactstr to integer */
			inact = strtol(inactstr, &ptr, 10);
			if (*ptr || inact < 0) {
				errmsg(M_INVALID, inactstr,
				    "inactivity period");
				exit(EX_BADARG);
			}

			usrdefs->definact = inact;
		}

		/* expiration string is a date, newer than today */
		if (expirestr != NULL) {
			if (*expirestr) {
				if (valid_expire(expirestr, (time_t *)0)
				    == INVALID) {
					errmsg(M_INVALID, expirestr,
					    "expiration date");
					exit(EX_BADARG);
				}
				usrdefs->defexpire = expirestr;
			} else
				/* Unset the expiration date */
				usrdefs->defexpire = "";
		}

		if (shell != NULL) {
			valid_input(SHELL, shell);
			usrdefs->defshell = shell;
		}
		if (skel_dir != NULL) {
			valid_input(SKELDIR, skel_dir);
			usrdefs->defskel = skel_dir;
		}
		update_def(usrdefs);

		/* change defaults for useradd */
		if (putusrdef(usrdefs, usertype) < 0) {
			errmsg(M_UPDATE, "created");
			exit(EX_UPDATE);
		}

		/* Now, display */
		dispusrdef(stdout, (D_ALL & ~D_RID), usertype);
		exit(EX_SUCCESS);

	}

	/* ADD mode */

	/* check syntax */
	if (optind != argc - 1 || (skel_dir != NULL && !mflag)) {
		if (is_role(usertype))
			errmsg(M_ARUSAGE);
		else
			errmsg(M_AUSAGE);
		exit(EX_SYNTAX);
	}

	logname = argv[optind];
	switch (valid_login(logname, (struct passwd **)NULL, &warning)) {
	case INVALID:
		errmsg(M_INVALID, logname, "login name");
		exit(EX_BADARG);
		/*NOTREACHED*/

	case NOTUNIQUE:
		errmsg(M_USED, logname);
		exit(EX_NAME_EXISTS);
		/*NOTREACHED*/

	case LONGNAME:
		errmsg(M_TOO_LONG, logname);
		exit(EX_BADARG);
		/*NOTREACHED*/
	}

	if (warning)
		warningmsg(warning, logname);
	if (uidstr != NULL) {
		/* convert uidstr to integer */
		errno = 0;
		uid = (uid_t)strtol(uidstr, &ptr, (int)10);
		if (*ptr || errno == ERANGE) {
			errmsg(M_INVALID, uidstr, "user id");
			exit(EX_BADARG);
		}

		switch (valid_uid(uid, NULL)) {
		case NOTUNIQUE:
			if (!oflag) {
				/* override not specified */
				errmsg(M_UID_USED, uid);
				exit(EX_ID_EXISTS);
			}
			break;
		case RESERVED:
			errmsg(M_RESERVED, uid);
			break;
		case TOOBIG:
			errmsg(M_TOOBIG, "uid", uid);
			exit(EX_BADARG);
			break;
		}

	} else {

		if (findnextuid(DEFRID+1, MAXUID, &uid) != 0) {
			errmsg(M_INVALID, "default id", "user id");
			exit(EX_ID_EXISTS);
		}
	}

	if (group != NULL) {
		switch (valid_group(group, &g_ptr, &warning)) {
		case INVALID:
			errmsg(M_INVALID, group, "group id");
			exit(EX_BADARG);
			/*NOTREACHED*/
		case TOOBIG:
			errmsg(M_TOOBIG, "gid", group);
			exit(EX_BADARG);
			/*NOTREACHED*/
		case RESERVED:
		case UNIQUE:
			errmsg(M_GRP_NOTUSED, group);
			exit(EX_NAME_NOT_EXIST);
			/*NOTREACHED*/
		}

		if (warning)
			warningmsg(warning, group);
		gid = g_ptr->gr_gid;

	} else gid = usrdefs->defgroup;

	if (grps != NULL) {
		if (!*grps)
			/* ignore -G "" */
			grps = (char *)0;
		else if (!(gidlist = valid_lgroup(grps, gid)))
			exit(EX_BADARG);
	}

	if (projects != NULL) {
		if (! *projects)
			projects = (char *)0;
		else if (! (projlist = valid_lproject(projects)))
			exit(EX_BADARG);
	}

	/* if base_dir is provided, check its validity; otherwise default */
	if (base_dir != NULL)
		valid_input(BASEDIR, base_dir);
	else
		base_dir = usrdefs->defparent;

	if (dir == NULL) {
		/* set homedir to home directory made from base_dir */
		(void) sprintf(homedir, "%s/%s", base_dir, logname);

	} else if (REL_PATH(dir)) {
		errmsg(M_RELPATH, dir);
		exit(EX_BADARG);

	} else
		(void) strcpy(homedir, dir);

	if (mflag) {
		/* Does home dir. already exist? */
		if (stat(homedir, &statbuf) == 0) {
			/* directory exists - don't try to create */
			mflag = 0;

			if (check_perm(statbuf, uid, gid, S_IXOTH) != 0)
				errmsg(M_NO_PERM, logname, homedir);
		}
	}
	/*
	 * if shell, skel_dir are provided, check their validity.
	 * Otherwise default.
	 */
	if (shell != NULL)
		valid_input(SHELL, shell);
	else
		shell = usrdefs->defshell;

	if (skel_dir != NULL)
		valid_input(SKELDIR, skel_dir);
	else
		skel_dir = usrdefs->defskel;

	if (inactstr != NULL) {
		/* convert inactstr to integer */
		inact = strtol(inactstr, &ptr, 10);
		if (*ptr || inact < 0) {
			errmsg(M_INVALID, inactstr, "inactivity period");
			exit(EX_BADARG);
		}
	} else inact = usrdefs->definact;

	/* expiration string is a date, newer than today */
	if (expirestr != NULL) {
		if (*expirestr) {
			if (valid_expire(expirestr, (time_t *)0) == INVALID) {
				errmsg(M_INVALID, expirestr, "expiration date");
				exit(EX_BADARG);
			}
			usrdefs->defexpire = expirestr;
		} else
			/* Unset the expiration date */
			expirestr = (char *)0;

	} else expirestr = usrdefs->defexpire;

	import_def(usrdefs);

	/* must now call passmgmt */

	/* set up arguments to  passmgmt in nargv array */
	nargv = malloc((30 + nkeys * 2) * sizeof (char *));
	argindex = 0;
	nargv[argindex++] = PASSMGMT;
	nargv[argindex++] = "-a";	/* add */

	if (comment != NULL) {
		/* comment */
		nargv[argindex++] = "-c";
		nargv[argindex++] = comment;
	}

	/* flags for home directory */
	nargv[argindex++] = "-h";
	nargv[argindex++] = homedir;

	/* set gid flag */
	nargv[argindex++] = "-g";
	(void) sprintf(gidstring, "%u", gid);
	nargv[argindex++] = gidstring;

	/* shell */
	nargv[argindex++] = "-s";
	nargv[argindex++] = shell;

	/* set inactive */
	nargv[argindex++] = "-f";
	(void) sprintf(inactstring, "%ld", inact);
	nargv[argindex++] = inactstring;

	/* set expiration date */
	if (expirestr != NULL) {
		nargv[argindex++] = "-e";
		nargv[argindex++] = expirestr;
	}

	/* set uid flag */
	nargv[argindex++] = "-u";
	(void) sprintf(uidstring, "%u", uid);
	nargv[argindex++] = uidstring;

	if (oflag) nargv[argindex++] = "-o";

	if (nkeys > 1)
		addkey_args(nargv, &argindex);

	/* finally - login name */
	nargv[argindex++] = logname;

	/* set the last to null */
	nargv[argindex++] = NULL;

	/* now call passmgmt */
	ret = PEX_FAILED;
	/*
	 * If call_passmgmt fails for any reason other than PEX_BADUID, exit
	 * is invoked with an appropriate error message. If PEX_BADUID is
	 * returned, then if the user specified the ID, exit is invoked
	 * with an appropriate error message. Otherwise we try to pick a
	 * different ID and try again. If we run out of IDs, i.e. no more
	 * users can be created, then -1 is returned and we terminate via exit.
	 * If PEX_BUSY is returned we increment a count, since we will stop
	 * trying if PEX_BUSY reaches 3. For PEX_SUCCESS we immediately
	 * terminate the loop.
	 */
	while (busy < 3 && ret != PEX_SUCCESS) {
		switch (ret = call_passmgmt(nargv)) {
		case PEX_SUCCESS:
			break;
		case PEX_BUSY:
			busy++;
			break;
		case PEX_HOSED_FILES:
			errmsg(M_HOSED_FILES);
			exit(EX_INCONSISTENT);
			break;

		case PEX_SYNTAX:
		case PEX_BADARG:
			/* should NEVER occur that passmgmt usage is wrong */
			if (is_role(usertype))
				errmsg(M_ARUSAGE);
			else
				errmsg(M_AUSAGE);
			exit(EX_SYNTAX);
			break;

		case PEX_BADUID:
			/*
			 * The uid has been taken. If it was specified by a
			 * user, then we must fail. Otherwise, keep trying
			 * to get a good uid until we run out of IDs.
			 */
			if (uidstr != NULL) {
				errmsg(M_UID_USED, uid);
				exit(EX_ID_EXISTS);
			} else {
				if (findnextuid(DEFRID+1, MAXUID, &uid) != 0) {
					errmsg(M_INVALID, "default id",
					    "user id");
					exit(EX_ID_EXISTS);
				}
				(void) sprintf(uidstring, "%u", uid);
			}
			break;

		case PEX_BADNAME:
			/* invalid loname */
			errmsg(M_USED, logname);
			exit(EX_NAME_EXISTS);
			break;

		default:
			errmsg(M_UPDATE, "created");
			exit(ret);
			break;
		}
	}
	if (busy == 3) {
		errmsg(M_UPDATE, "created");
		exit(ret);
	}

	/* add group entry */
	if ((grps != NULL) && edit_group(logname, (char *)0, gidlist, 0)) {
		errmsg(M_UPDATE, "created");
		cleanup(logname);
		exit(EX_UPDATE);
	}

	/* update project database */
	if ((projects != NULL) &&
	    edit_project(logname, (char *)NULL, projlist, 0)) {
		errmsg(M_UPDATE, "created");
		cleanup(logname);
		exit(EX_UPDATE);
	}

	/* create home directory */
	if (mflag &&
	    (create_home(homedir, skel_dir, uid, gid) != EX_SUCCESS)) {
		(void) edit_group(logname, (char *)0, (int **)0, 1);
		cleanup(logname);
		exit(EX_HOMEDIR);
	}

	return (ret);
}

static void
cleanup(logname)
char *logname;
{
	char *nargv[4];

	nargv[0] = PASSMGMT;
	nargv[1] = "-d";
	nargv[2] = logname;
	nargv[3] = NULL;

	switch (call_passmgmt(nargv)) {
	case PEX_SUCCESS:
		break;

	case PEX_SYNTAX:
		/* should NEVER occur that passmgmt usage is wrong */
		if (is_role(usertype))
			errmsg(M_ARUSAGE);
		else
			errmsg(M_AUSAGE);
		break;

	case PEX_BADUID:
		/* uid is used - shouldn't happen but print message anyway */
		errmsg(M_UID_USED, uid);
		break;

	case PEX_BADNAME:
		/* invalid loname */
		errmsg(M_USED, logname);
		break;

	default:
		errmsg(M_UPDATE, "created");
		break;
	}
}

/* Check the validity for shell, base_dir and skel_dir */

void
valid_input(path_opt_t opt, const char *input)
{
	struct stat	statbuf;

	if (REL_PATH(input)) {
		errmsg(M_RELPATH, input);
		exit(EX_BADARG);
	}
	if (stat(input, &statbuf) == -1) {
		errmsg(M_INVALID, input, "path");
		exit(EX_BADARG);
	}
	if (opt == SHELL) {
		if (!S_ISREG(statbuf.st_mode) ||
		    (statbuf.st_mode & 0555) != 0555) {
			errmsg(M_INVALID, input, "shell");
			exit(EX_BADARG);
		}
	} else {
		if (!S_ISDIR(statbuf.st_mode)) {
			errmsg(M_INVALID, input, "directory");
			exit(EX_BADARG);
		}
	}
}

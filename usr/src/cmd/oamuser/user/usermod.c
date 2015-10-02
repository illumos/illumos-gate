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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>
#include <string.h>
#include <userdefs.h>
#include <user_attr.h>
#include <nss_dbdefs.h>
#include <errno.h>
#include <project.h>
#include "users.h"
#include "messages.h"
#include "funcs.h"

/*
 *  usermod [-u uid [-o] | -g group | -G group [[,group]...]
 *		| -d dir [-m [-z|Z]]
 *		| -s shell | -c comment | -l new_logname]
 *		| -f inactive | -e expire ]
 *		[ -A authorization [, authorization ...]]
 *		[ -P profile [, profile ...]]
 *		[ -R role [, role ...]]
 *		[ -K key=value ]
 *		[ -p project [, project]] login
 *
 *	This command adds new user logins to the system.  Arguments are:
 *
 *	uid - an integer less than MAXUID
 *	group - an existing group's integer ID or char string name
 *	dir - a directory
 *	shell - a program to be used as a shell
 *	comment - any text string
 *	skel_dir - a directory
 *	base_dir - a directory
 *	rid - an integer less than 2**16 (USHORT)
 *	login - a string of printable chars except colon (:)
 *	inactive - number of days a login maybe inactive before it is locked
 *	expire - date when a login is no longer valid
 *	authorization - One or more comma separated authorizations defined
 *			in auth_attr(4).
 *	profile - One or more comma separated execution profiles defined
 *		  in prof_attr(4)
 *	role - One or more comma-separated role names defined in user_attr(4)
 *	key=value - One or more -K options each specifying a valid user_attr(4)
 *		attribute.
 *
 */

extern int **valid_lgroup(), isbusy(), get_default_zfs_flags();
extern int valid_uid(), check_perm(), create_home(), move_dir();
extern int valid_expire(), edit_group(), call_passmgmt();
extern projid_t **valid_lproject();

static uid_t uid;		/* new uid */
static gid_t gid;			/* gid of new login */
static char *new_logname = NULL;	/* new login name with -l option */
static char *uidstr = NULL;		/* uid from command line */
static char *group = NULL;		/* group from command line */
static char *grps = NULL;		/* multi groups from command line */
static char *dir = NULL;		/* home dir from command line */
static char *shell = NULL;		/* shell from command line */
static char *comment = NULL;		/* comment from command line */
static char *logname = NULL;		/* login name to add */
static char *inactstr = NULL;		/* inactive from command line */
static char *expire = NULL;		/* expiration date from command line */
static char *projects = NULL;		/* project ids from command line */
static char *usertype;

char *cmdname;
static char gidstring[32], uidstring[32];
char inactstring[10];

char *
strcpmalloc(str)
char *str;
{
	if (str == NULL)
		return (NULL);

	return (strdup(str));
}
struct passwd *
passwd_cpmalloc(opw)
struct passwd *opw;
{
	struct passwd *npw;

	if (opw == NULL)
		return (NULL);


	npw = malloc(sizeof (struct passwd));

	npw->pw_name = strcpmalloc(opw->pw_name);
	npw->pw_passwd = strcpmalloc(opw->pw_passwd);
	npw->pw_uid = opw->pw_uid;
	npw->pw_gid = opw->pw_gid;
	npw->pw_age = strcpmalloc(opw->pw_age);
	npw->pw_comment = strcpmalloc(opw->pw_comment);
	npw->pw_gecos  = strcpmalloc(opw->pw_gecos);
	npw->pw_dir = strcpmalloc(opw->pw_dir);
	npw->pw_shell = strcpmalloc(opw->pw_shell);

	return (npw);
}

int
main(argc, argv)
int argc;
char **argv;
{
	int ch, ret = EX_SUCCESS, call_pass = 0, oflag = 0, zfs_flags = 0;
	int tries, mflag = 0, inact, **gidlist, flag = 0, zflag = 0, Zflag = 0;
	boolean_t fail_if_busy = B_FALSE;
	char *ptr;
	struct passwd *pstruct;		/* password struct for login */
	struct passwd *pw;
	struct group *g_ptr;	/* validated group from -g */
	struct stat statbuf;		/* status buffer for stat */
#ifndef att
	FILE *pwf;		/* fille ptr for opened passwd file */
#endif
	int warning;
	projid_t **projlist;
	char **nargv;			/* arguments for execvp of passmgmt */
	int argindex;			/* argument index into nargv */
	userattr_t *ua;
	char *val;
	int isrole;			/* current account is role */

	cmdname = argv[0];

	if (geteuid() != 0) {
		errmsg(M_PERM_DENIED);
		exit(EX_NO_PERM);
	}

	opterr = 0;			/* no print errors from getopt */
	/* get user type based on the program name */
	usertype = getusertype(argv[0]);

	while ((ch = getopt(argc, argv,
				"c:d:e:f:G:g:l:mzZop:s:u:A:P:R:K:")) != EOF)
		switch (ch) {
		case 'c':
			comment = optarg;
			flag++;
			break;
		case 'd':
			dir = optarg;
			fail_if_busy = B_TRUE;
			flag++;
			break;
		case 'e':
			expire = optarg;
			flag++;
			break;
		case 'f':
			inactstr = optarg;
			flag++;
			break;
		case 'G':
			grps = optarg;
			flag++;
			break;
		case 'g':
			group = optarg;
			fail_if_busy = B_TRUE;
			flag++;
			break;
		case 'l':
			new_logname = optarg;
			fail_if_busy = B_TRUE;
			flag++;
			break;
		case 'm':
			mflag++;
			flag++;
			fail_if_busy = B_TRUE;
			break;
		case 'o':
			oflag++;
			flag++;
			fail_if_busy = B_TRUE;
			break;
		case 'p':
			projects = optarg;
			flag++;
			break;
		case 's':
			shell = optarg;
			flag++;
			break;
		case 'u':
			uidstr = optarg;
			flag++;
			fail_if_busy = B_TRUE;
			break;
		case 'Z':
			Zflag++;
			break;
		case 'z':
			zflag++;
			break;
		case 'A':
			change_key(USERATTR_AUTHS_KW, optarg);
			flag++;
			break;
		case 'P':
			change_key(USERATTR_PROFILES_KW, optarg);
			flag++;
			break;
		case 'R':
			change_key(USERATTR_ROLES_KW, optarg);
			flag++;
			break;
		case 'K':
			change_key(NULL, optarg);
			flag++;
			break;
		default:
		case '?':
			if (is_role(usertype))
				errmsg(M_MRUSAGE);
			else
				errmsg(M_MUSAGE);
			exit(EX_SYNTAX);
		}

	if (((!mflag) && (zflag || Zflag)) || (zflag && Zflag) ||
	    (mflag > 1 && (zflag || Zflag))) {
		if (is_role(usertype))
			errmsg(M_ARUSAGE);
		else
			errmsg(M_AUSAGE);
		exit(EX_SYNTAX);
	}


	if (optind != argc - 1 || flag == 0) {
		if (is_role(usertype))
			errmsg(M_MRUSAGE);
		else
			errmsg(M_MUSAGE);
		exit(EX_SYNTAX);
	}

	if ((!uidstr && oflag) || (mflag && !dir)) {
		if (is_role(usertype))
			errmsg(M_MRUSAGE);
		else
			errmsg(M_MUSAGE);
		exit(EX_SYNTAX);
	}

	logname = argv[optind];

	/* Determine whether the account is a role or not */
	if ((ua = getusernam(logname)) == NULL ||
	    (val = kva_match(ua->attr, USERATTR_TYPE_KW)) == NULL ||
	    strcmp(val, USERATTR_TYPE_NONADMIN_KW) != 0)
		isrole = 0;
	else
		isrole = 1;

	/* Verify that rolemod is used for roles and usermod for users */
	if (isrole != is_role(usertype)) {
		if (isrole)
			errmsg(M_ISROLE);
		else
			errmsg(M_ISUSER);
		exit(EX_SYNTAX);
	}

	/* Set the usertype key; defaults to the commandline  */
	usertype = getsetdefval(USERATTR_TYPE_KW, usertype);

	if (is_role(usertype)) {
		/* Roles can't have roles */
		if (getsetdefval(USERATTR_ROLES_KW, NULL) != NULL) {
			errmsg(M_MRUSAGE);
			exit(EX_SYNTAX);
		}
		/* If it was an ordinary user, delete its roles */
		if (!isrole)
			change_key(USERATTR_ROLES_KW, "");
	}

#ifdef att
	pw = getpwnam(logname);
#else
	/*
	 * Do this with fgetpwent to make sure we are only looking on local
	 * system (since passmgmt only works on local system).
	 */
	if ((pwf = fopen("/etc/passwd", "r")) == NULL) {
		errmsg(M_OOPS, "open", "/etc/passwd");
		exit(EX_FAILURE);
	}
	while ((pw = fgetpwent(pwf)) != NULL)
		if (strcmp(pw->pw_name, logname) == 0)
			break;

	fclose(pwf);
#endif

	if (pw == NULL) {
		char		pwdb[NSS_BUFLEN_PASSWD];
		struct passwd	pwd;

		if (getpwnam_r(logname, &pwd, pwdb, sizeof (pwdb)) == NULL) {
			/* This user does not exist. */
			errmsg(M_EXIST, logname);
			exit(EX_NAME_NOT_EXIST);
		} else {
			/* This user exists in non-local name service. */
			errmsg(M_NONLOCAL, logname);
			exit(EX_NOT_LOCAL);
		}
	}

	pstruct = passwd_cpmalloc(pw);

	/*
	 * We can't modify a logged in user if any of the following
	 * are being changed:
	 * uid (-u & -o), group (-g), home dir (-m), loginname (-l).
	 * If none of those are specified it is okay to go ahead
	 * some types of changes only take effect on next login, some
	 * like authorisations and profiles take effect instantly.
	 * One might think that -K type=role should require that the
	 * user not be logged in, however this would make it very
	 * difficult to make the root account a role using this command.
	 */
	if (isbusy(logname)) {
		if (fail_if_busy) {
			errmsg(M_BUSY, logname, "change");
			exit(EX_BUSY);
		}
		warningmsg(WARN_LOGGED_IN, logname);
	}

	if (new_logname && strcmp(new_logname, logname)) {
		switch (valid_login(new_logname, (struct passwd **)NULL,
			&warning)) {
		case INVALID:
			errmsg(M_INVALID, new_logname, "login name");
			exit(EX_BADARG);
			/*NOTREACHED*/

		case NOTUNIQUE:
			errmsg(M_USED, new_logname);
			exit(EX_NAME_EXISTS);
			/*NOTREACHED*/

		case LONGNAME:
			errmsg(M_TOO_LONG, new_logname);
			exit(EX_BADARG);
			/*NOTREACHED*/

		default:
			call_pass = 1;
			break;
		}
		if (warning)
			warningmsg(warning, logname);
	}

	if (uidstr) {
		/* convert uidstr to integer */
		errno = 0;
		uid = (uid_t)strtol(uidstr, &ptr, (int)10);
		if (*ptr || errno == ERANGE) {
			errmsg(M_INVALID, uidstr, "user id");
			exit(EX_BADARG);
		}

		if (uid != pstruct->pw_uid) {
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

			call_pass = 1;

		} else {
			/* uid's the same, so don't change anything */
			uidstr = NULL;
			oflag = 0;
		}

	} else uid = pstruct->pw_uid;

	if (group) {
		switch (valid_group(group, &g_ptr, &warning)) {
		case INVALID:
			errmsg(M_INVALID, group, "group id");
			exit(EX_BADARG);
			/*NOTREACHED*/
		case TOOBIG:
			errmsg(M_TOOBIG, "gid", group);
			exit(EX_BADARG);
			/*NOTREACHED*/
		case UNIQUE:
			errmsg(M_GRP_NOTUSED, group);
			exit(EX_NAME_NOT_EXIST);
			/*NOTREACHED*/
		case RESERVED:
			gid = (gid_t)strtol(group, &ptr, (int)10);
			errmsg(M_RESERVED_GID, gid);
			break;
		}
		if (warning)
			warningmsg(warning, group);

		if (g_ptr != NULL)
			gid = g_ptr->gr_gid;
		else
			gid = pstruct->pw_gid;

		/* call passmgmt if gid is different, else ignore group */
		if (gid != pstruct->pw_gid)
			call_pass = 1;
		else group = NULL;

	} else gid = pstruct->pw_gid;

	if (grps && *grps) {
		if (!(gidlist = valid_lgroup(grps, gid)))
			exit(EX_BADARG);
	} else
		gidlist = (int **)0;

	if (projects && *projects) {
		if (! (projlist = valid_lproject(projects)))
			exit(EX_BADARG);
	} else
		projlist = (projid_t **)0;

	if (dir) {
		if (REL_PATH(dir)) {
			errmsg(M_RELPATH, dir);
			exit(EX_BADARG);
		}
		if (strcmp(pstruct->pw_dir, dir) == 0) {
			/* home directory is the same so ignore dflag & mflag */
			dir = NULL;
			mflag = 0;
		} else call_pass = 1;
	}

	if (mflag) {
		if (stat(dir, &statbuf) == 0) {
			/* Home directory exists */
			if (check_perm(statbuf, pstruct->pw_uid,
			    pstruct->pw_gid, S_IWOTH|S_IXOTH) != 0) {
				errmsg(M_NO_PERM, logname, dir);
				exit(EX_NO_PERM);
			}

		} else {
			zfs_flags = get_default_zfs_flags();
			if (zflag || mflag > 1)
				zfs_flags |= MANAGE_ZFS;
			else if (Zflag)
				zfs_flags &= ~MANAGE_ZFS;
			ret = create_home(dir, NULL, uid, gid, zfs_flags);
		}

		if (ret == EX_SUCCESS)
			ret = move_dir(pstruct->pw_dir, dir,
			    logname, zfs_flags);

		if (ret != EX_SUCCESS)
			exit(ret);
	}

	if (shell) {
		if (REL_PATH(shell)) {
			errmsg(M_RELPATH, shell);
			exit(EX_BADARG);
		}
		if (strcmp(pstruct->pw_shell, shell) == 0) {
			/* ignore s option if shell is not different */
			shell = NULL;
		} else {
			if (stat(shell, &statbuf) < 0 ||
			    (statbuf.st_mode & S_IFMT) != S_IFREG ||
			    (statbuf.st_mode & 0555) != 0555) {

				errmsg(M_INVALID, shell, "shell");
				exit(EX_BADARG);
			}

			call_pass = 1;
		}
	}

	if (comment) {
		/* ignore comment if comment is not changed */
		if (strcmp(pstruct->pw_comment, comment))
			call_pass = 1;
		else
			comment = NULL;
	}

	/* inactive string is a positive integer */
	if (inactstr) {
		/* convert inactstr to integer */
		inact = (int)strtol(inactstr, &ptr, 10);
		if (*ptr || inact < 0) {
			errmsg(M_INVALID, inactstr, "inactivity period");
			exit(EX_BADARG);
		}
		call_pass = 1;
	}

	/* expiration string is a date, newer than today */
	if (expire) {
		if (*expire &&
		    valid_expire(expire, (time_t *)0) == INVALID) {
			errmsg(M_INVALID, expire, "expiration date");
			exit(EX_BADARG);
		}
		call_pass = 1;
	}

	if (nkeys > 0)
		call_pass = 1;

	/* that's it for validations - now do the work */

	if (grps) {
		/* redefine login's supplentary group memberships */
		ret = edit_group(logname, new_logname, gidlist, 1);
		if (ret != EX_SUCCESS) {
			errmsg(M_UPDATE, "modified");
			exit(ret);
		}
	}
	if (projects) {
		ret = edit_project(logname, (char *)NULL, projlist, 0);
		if (ret != EX_SUCCESS) {
			errmsg(M_UPDATE, "modified");
			exit(ret);
		}
	}


	if (!call_pass) exit(ret);

	/* only get to here if need to call passmgmt */
	/* set up arguments to  passmgmt in nargv array */
	nargv = malloc((30 + nkeys * 2) * sizeof (char *));

	argindex = 0;
	nargv[argindex++] = PASSMGMT;
	nargv[argindex++] = "-m";	/* modify */

	if (comment) {	/* comment */
		nargv[argindex++] = "-c";
		nargv[argindex++] = comment;
	}

	if (dir) {
		/* flags for home directory */
		nargv[argindex++] = "-h";
		nargv[argindex++] = dir;
	}

	if (group) {
		/* set gid flag */
		nargv[argindex++] = "-g";
		(void) sprintf(gidstring, "%u", gid);
		nargv[argindex++] = gidstring;
	}

	if (shell) { 	/* shell */
		nargv[argindex++] = "-s";
		nargv[argindex++] = shell;
	}

	if (inactstr) {
		nargv[argindex++] = "-f";
		nargv[argindex++] = inactstr;
	}

	if (expire) {
		nargv[argindex++] = "-e";
		nargv[argindex++] = expire;
	}

	if (uidstr) {	/* set uid flag */
		nargv[argindex++] = "-u";
		(void) sprintf(uidstring, "%u", uid);
		nargv[argindex++] = uidstring;
	}

	if (oflag) nargv[argindex++] = "-o";

	if (new_logname) {	/* redefine login name */
		nargv[argindex++] = "-l";
		nargv[argindex++] = new_logname;
	}

	if (nkeys > 0)
		addkey_args(nargv, &argindex);

	/* finally - login name */
	nargv[argindex++] = logname;

	/* set the last to null */
	nargv[argindex++] = NULL;

	/* now call passmgmt */
	ret = PEX_FAILED;
	for (tries = 3; ret != PEX_SUCCESS && tries--; ) {
		switch (ret = call_passmgmt(nargv)) {
		case PEX_SUCCESS:
		case PEX_BUSY:
			break;

		case PEX_HOSED_FILES:
			errmsg(M_HOSED_FILES);
			exit(EX_INCONSISTENT);
			break;

		case PEX_SYNTAX:
		case PEX_BADARG:
			/* should NEVER occur that passmgmt usage is wrong */
			if (is_role(usertype))
				errmsg(M_MRUSAGE);
			else
				errmsg(M_MUSAGE);
			exit(EX_SYNTAX);
			break;

		case PEX_BADUID:
			/* uid in use - shouldn't happen print message anyway */
			errmsg(M_UID_USED, uid);
			exit(EX_ID_EXISTS);
			break;

		case PEX_BADNAME:
			/* invalid loname */
			errmsg(M_USED, logname);
			exit(EX_NAME_EXISTS);
			break;

		default:
			errmsg(M_UPDATE, "modified");
			exit(ret);
			break;
		}
	}
	if (tries == 0) {
		errmsg(M_UPDATE, "modified");
	}

	exit(ret);
	/*NOTREACHED*/
}

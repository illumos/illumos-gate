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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <errno.h>
#include <deflt.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <exec_attr.h>
#include <user_attr.h>
#include <auth_attr.h>
#include <prof_attr.h>
#include <errno.h>
#include <priv.h>

#include <bsm/adt.h>
#include <bsm/adt_event.h>

#ifndef	TEXT_DOMAIN			/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

extern int cannot_audit(int);

static char *pathsearch(char *);
static int getrealpath(const char *, char *);
static int checkattrs(char *, int, char *[]);
static void sanitize_environ();
static uid_t get_uid(char *);
static gid_t get_gid(char *);
static priv_set_t *get_privset(const char *);
static priv_set_t *get_granted_privs(uid_t);
static void get_default_privs(const char *, priv_set_t *);
static void get_profile_privs(char *, char **, int *, priv_set_t *);

static int isnumber(char *);
static void usage(void);

extern char **environ;

#define	PROFLIST_SEP	","

int
main(int argc, char *argv[])
{
	char		*cmd;
	char		**cmdargs;
	char		cmd_realpath[MAXPATHLEN];
	int		c;
	char 		*pset = NULL;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "P:")) != EOF) {
		switch (c) {
		case 'P':
			if (pset == NULL) {
				pset = optarg;
				break;
			}
			/* FALLTHROUGH */
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage();

	cmd = argv[0];
	cmdargs = &argv[0];

	if (pset != NULL) {
		uid_t uid = getuid();
		priv_set_t *wanted = get_privset(pset);
		priv_set_t *granted;

		adt_session_data_t *ah;		/* audit session handle */
		adt_event_data_t *event;	/* event to be generated */
		char cwd[MAXPATHLEN];

		granted = get_granted_privs(uid);

		/* Audit use */
		if (adt_start_session(&ah, NULL, ADT_USE_PROC_DATA) != 0) {
			perror("pfexec: adt_start_session");
			exit(EXIT_FAILURE);
		}
		if ((event = adt_alloc_event(ah, ADT_prof_cmd)) == NULL) {
			perror("pfexec: adt_alloc_event");
			exit(EXIT_FAILURE);
		}
		if ((event->adt_prof_cmd.cwdpath =
		    getcwd(cwd, sizeof (cwd))) == NULL) {
			(void) fprintf(stderr,
			    gettext("pfexec: can't add cwd path\n"));
			exit(EXIT_FAILURE);
		}

		event->adt_prof_cmd.cmdpath = cmd;
		event->adt_prof_cmd.argc = argc - 1;
		event->adt_prof_cmd.argv = &argv[1];
		event->adt_prof_cmd.envp = environ;

		if (granted != NULL) {
			priv_intersect(granted, wanted);
			event->adt_prof_cmd.inherit_set = wanted;
			if (adt_put_event(event, ADT_SUCCESS,
			    ADT_SUCCESS) != 0) {
				perror("pfexec: adt_put_event");
				exit(EXIT_FAILURE);
			}
			if (setppriv(PRIV_ON, PRIV_INHERITABLE, wanted) != 0) {
				(void) fprintf(stderr,
				    gettext("setppriv(): %s\n"),
				    strerror(errno));
				exit(EXIT_FAILURE);
			}
			/* Trick exec into thinking we're not suid */
			(void) setppriv(PRIV_ON, PRIV_PERMITTED, wanted);
			priv_freeset(event->adt_prof_cmd.inherit_set);
		} else {
			if (adt_put_event(event, ADT_SUCCESS,
			    ADT_SUCCESS) != 0) {
				perror("pfexec: adt_put_event");
				exit(EXIT_FAILURE);
			}
		}
		adt_free_event(event);
		(void) adt_end_session(ah);
		(void) setreuid(uid, uid);
		(void) execvp(cmd, cmdargs);
		(void) fprintf(stderr,
		    gettext("pfexec: can't execute %s: %s\n"),
		    cmd, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((cmd = pathsearch(cmd)) == NULL)
		exit(EXIT_FAILURE);

	if (getrealpath(cmd, cmd_realpath) == 0)
		exit(EXIT_FAILURE);

	if (checkattrs(cmd_realpath, argc, argv) == 0)
		exit(EXIT_FAILURE);

	(void) execv(cmd, cmdargs);
	/*
	 * We'd be here only if execv fails.
	 */
	(void) fprintf(stderr, gettext("pfexec: can't execute %s: %s\n"),
	    cmd, strerror(errno));
	exit(EXIT_FAILURE);
/* LINTED */
}


/*
 * gets realpath for cmd.
 * return 1 on success, 0 on failure.
 */
static int
getrealpath(const char *cmd, char *cmd_realpath)
{
	if (realpath(cmd, cmd_realpath) == NULL) {
		(void) fprintf(stderr,
		    gettext("pfexec: can't get real path of ``%s''\n"), cmd);
		return (0);
	}
	return (1);
}

/*
 * gets execution attributed for cmd, sets uids/gids, checks environ.
 * returns 1 on success, 0 on failure.
 */
static int
checkattrs(char *cmd_realpath, int argc, char *argv[])
{
	char			*value;
	uid_t			uid, euid;
	gid_t			gid = (gid_t)-1;
	gid_t			egid = (gid_t)-1;
	struct passwd		*pwent;
	execattr_t		*exec;
	priv_set_t		*lset = NULL;
	priv_set_t		*iset = NULL;

	adt_session_data_t	*ah;		/* audit session handle */
	adt_event_data_t	*event;		/* event to be generated */
	char			cwd[MAXPATHLEN];

	uid = euid = getuid();
	if ((pwent = getpwuid(uid)) == NULL) {
		(void) fprintf(stderr, "%d: ", (int)uid);
		(void) fprintf(stderr, gettext("can't get passwd entry\n"));
		return (0);
	}
	/* Set up to audit use */
	if (adt_start_session(&ah, NULL, ADT_USE_PROC_DATA) != 0) {
		perror("pfexec: adt_start_session");
		return (0);
	}
	if ((event = adt_alloc_event(ah, ADT_prof_cmd)) == NULL) {
		perror("pfexec: adt_alloc_event");
		return (0);
	}
	if ((event->adt_prof_cmd.cwdpath = getcwd(cwd, sizeof (cwd))) == NULL) {
		(void) fprintf(stderr, gettext("pfexec: can't add cwd path\n"));
		return (0);
	}
	/*
	 * Get the exec attrs: uid, gid, euid and egid
	 */
	if ((exec = getexecuser(pwent->pw_name,
	    KV_COMMAND, (char *)cmd_realpath, GET_ONE)) == NULL) {
		(void) fprintf(stderr, "%s: ", cmd_realpath);
		(void) fprintf(stderr,
		    gettext("can't get execution attributes\n"));
		return (0);
	}
	if ((value = kva_match(exec->attr, EXECATTR_UID_KW)) != NULL) {
		euid = uid = get_uid(value);
		event->adt_prof_cmd.proc_euid = uid;
		event->adt_prof_cmd.proc_ruid = uid;
	}
	if ((value = kva_match(exec->attr, EXECATTR_GID_KW)) != NULL) {
		egid = gid = get_gid(value);
		event->adt_prof_cmd.proc_egid = gid;
		event->adt_prof_cmd.proc_rgid = gid;
	}
	if ((value = kva_match(exec->attr, EXECATTR_EUID_KW)) != NULL) {
		event->adt_prof_cmd.proc_euid = euid = get_uid(value);
	}
	if ((value = kva_match(exec->attr, EXECATTR_EGID_KW)) != NULL) {
		event->adt_prof_cmd.proc_egid = egid = get_gid(value);
	}
	if ((value = kva_match(exec->attr, EXECATTR_LPRIV_KW)) != NULL) {
		lset = get_privset(value);
		event->adt_prof_cmd.limit_set = lset;
	}
	if ((value = kva_match(exec->attr, EXECATTR_IPRIV_KW)) != NULL) {
		iset = get_privset(value);
		event->adt_prof_cmd.inherit_set = iset;
	}
	if (euid == uid || iset != NULL) {
		sanitize_environ();
	}

	/* Finish audit info */
	event->adt_prof_cmd.cmdpath = cmd_realpath;
	event->adt_prof_cmd.argc = argc - 1;
	event->adt_prof_cmd.argv = &argv[1];
	event->adt_prof_cmd.envp = environ;
	if (adt_put_event(event, ADT_SUCCESS, ADT_SUCCESS) != 0) {
		perror("pfexec: adt_put_event");
		return (0);
	}
	adt_free_event(event);
	(void) adt_end_session(ah);

set_attrs:
	/*
	 * Set gids/uids and privileges.
	 *
	 */
	if ((gid != (gid_t)-1) || (egid != (gid_t)-1)) {
		if ((setregid(gid, egid) == -1)) {
			(void) fprintf(stderr, "%s: ", cmd_realpath);
			(void) fprintf(stderr, gettext("can't set gid\n"));
			return (0);
		}
	}
	if (lset != NULL && setppriv(PRIV_SET, PRIV_LIMIT, lset) != 0 ||
	    iset != NULL && setppriv(PRIV_ON, PRIV_INHERITABLE, iset) != 0) {
		(void) fprintf(stderr, gettext("%s: can't set privileges\n"),
		    cmd_realpath);
		return (0);
	}
	if (setreuid(uid, euid) == -1) {
		(void) fprintf(stderr, "%s: ", cmd_realpath);
		(void) fprintf(stderr, gettext("can't set uid\n"));
		return (0);
	}
	if (iset != NULL && getppriv(PRIV_INHERITABLE, iset) == 0)
		(void) setppriv(PRIV_SET, PRIV_PERMITTED, iset);

	free_execattr(exec);

	return (1);
}


/*
 * cleans up environ. code from su.c
 */
static void
sanitize_environ()
{
	char	**pp = environ;
	char	**qq, *p;

	while ((p = *pp) != NULL) {
		if (*p == 'L' && p[1] == 'D' && p[2] == '_') {
			for (qq = pp; (*qq = qq[1]) != NULL; qq++) {
				;
			}
		} else {
			pp++;
		}
	}
}


static uid_t
get_uid(char *value)
{
	struct passwd *passwd_ent;

	if ((passwd_ent = getpwnam(value)) != NULL)
		return (passwd_ent->pw_uid);

	if (isnumber(value))
		return (atoi(value));

	(void) fprintf(stderr, "pfexec: %s: ", value);
	(void) fprintf(stderr, gettext("can't get user entry\n"));
	exit(EXIT_FAILURE);
	/*NOTREACHED*/
}


static uid_t
get_gid(char *value)
{
	struct group *group_ent;

	if ((group_ent = getgrnam(value)) != NULL)
		return (group_ent->gr_gid);

	if (isnumber(value))
		return (atoi(value));

	(void) fprintf(stderr, "pfexec: %s: ", value);
	(void) fprintf(stderr, gettext("can't get group entry\n"));
	exit(EXIT_FAILURE);
	/*NOTREACHED*/
}


static int
isnumber(char *s)
{
	int c;

	if (*s == '\0')
		return (0);

	while ((c = *s++) != '\0') {
		if (!isdigit(c)) {
			return (0);
		}
	}

	return (1);
}

static priv_set_t *
get_privset(const char *s)
{
	priv_set_t *res;

	if ((res = priv_str_to_set(s, ",", NULL)) == NULL) {
		(void) fprintf(stderr, "%s: bad privilege set\n", s);
		exit(EXIT_FAILURE);
	}
	return (res);
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext("pfexec [-P privset] cmd [arg ..]\n"));
	exit(EXIT_FAILURE);
}


/*
 * This routine exists on failure and returns NULL if no granted privileges
 * are set.
 */
static priv_set_t *
get_granted_privs(uid_t uid)
{
	struct passwd *pwent;
	userattr_t *ua;
	char *profs;
	priv_set_t *res;
	char *profArray[MAXPROFS];
	int profcnt = 0;

	res = priv_allocset();
	if (res == NULL) {
		perror("priv_allocset");
		exit(EXIT_FAILURE);
	}

	priv_emptyset(res);

	if ((pwent = getpwuid(uid)) == NULL) {
		(void) fprintf(stderr, "%d: ", (int)uid);
		(void) fprintf(stderr, gettext("can't get passwd entry\n"));
		exit(EXIT_FAILURE);
	}

	ua = getusernam(pwent->pw_name);

	if (ua != NULL && ua->attr != NULL &&
	    (profs = kva_match(ua->attr, USERATTR_PROFILES_KW)) != NULL) {
		get_profile_privs(profs, profArray, &profcnt, res);
		free_proflist(profArray, profcnt);
	}

	get_default_privs(pwent->pw_name, res);

	if (ua != NULL)
		free_userattr(ua);

	return (res);
}

static void
get_default_privs(const char *user, priv_set_t *pset)
{
	char *profs = NULL;
	char *profArray[MAXPROFS];
	int profcnt = 0;

	if (_get_user_defs(user, NULL, &profs) == 0) {
		/* get privileges from default profiles */
		if (profs != NULL) {
			get_profile_privs(profs, profArray, &profcnt, pset);
			free_proflist(profArray, profcnt);
			_free_user_defs(NULL, profs);
		}
	}
}

static void
get_profile_privs(char *profiles, char **profArray, int *profcnt,
	priv_set_t *pset)
{

	char		*prof;
	char		*lasts;
	profattr_t	*pa;
	char		*privs;
	int		i;

	for (prof = strtok_r(profiles, PROFLIST_SEP, &lasts);
	    prof != NULL;
	    prof = strtok_r(NULL, PROFLIST_SEP, &lasts))
		getproflist(prof, profArray, profcnt);

	/* get the privileges from list of profiles */
	for (i = 0; i < *profcnt; i++) {

		if ((pa = getprofnam(profArray[i])) == NULL) {
			/*
			 *  this should never happen.
			 *  unless the database has an undefined profile
			 */
			continue;
		}

		/* get privs from this profile */
		privs = kva_match(pa->attr, PROFATTR_PRIVS_KW);
		if (privs != NULL) {
			priv_set_t *tmp = priv_str_to_set(privs, ",", NULL);
			if (tmp != NULL) {
				priv_union(tmp, pset);
				priv_freeset(tmp);
			}
		}

		free_profattr(pa);
	}
}

/*
 * True if someone (user, group, other) can execute this file.
 */
#define	S_ISEXEC(mode)	(((mode)&(S_IXUSR|S_IXGRP|S_IXOTH)) != 0)

/*
 * This function can return either the first argument or dynamically
 * allocated memory.  Reuse with care.
 */
static char *
pathsearch(char *cmd)
{
	char *path, *dir, *result;
	char buf[MAXPATHLEN];
	struct stat stbuf;

	/*
	 * Implement shell like PATH searching; if the pathname contains
	 * one or more slashes, don't search the path, even if the '/'
	 * isn't the first character. (E.g., ./command or dir/command)
	 * No path equals to a search in ".", just like the shell.
	 */
	if (strchr(cmd, '/') != NULL)
		return (cmd);

	path = getenv("PATH");
	if (path == NULL)
		return (cmd);

	/*
	 * We need to copy $PATH because our sub processes may need it.
	 */
	path = strdup(path);
	if (path == NULL) {
		perror("pfexec: strdup $PATH");
		exit(EXIT_FAILURE);
	}

	result = NULL;
	for (dir = strtok(path, ":"); dir; dir = strtok(NULL, ":")) {
		if (snprintf(buf, sizeof (buf), "%s/%s", dir, cmd) >=
		    sizeof (buf)) {
			continue;
		}
		if (stat(buf, &stbuf) < 0)
			continue;
		/*
		 * Shells typically call access() with E_OK flag
		 * to determine if the effective uid can execute
		 * the file. We don't know what the eventual euid
		 * will be; it is determined by the exec_attr
		 * attributes which depend on the full pathname of
		 * the command. Therefore, we match the first regular
		 * file we find that is executable by someone.
		 */
		if (S_ISREG(stbuf.st_mode) && S_ISEXEC(stbuf.st_mode)) {
			result = strdup(buf);
			break;
		}
	}
	free(path);
	if (result == NULL)
		(void) fprintf(stderr, gettext("%s: Command not found\n"), cmd);
	return (result);
}

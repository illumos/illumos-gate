/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/task.h>

#include <alloca.h>
#include <libproc.h>
#include <libintl.h>
#include <libgen.h>
#include <limits.h>
#include <project.h>
#include <pwd.h>
#include <secdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/varargs.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <priv_utils.h>

#include "utils.h"

#define	OPTIONS_STRING	"Fc:lp:v"
#define	NENV		8
#define	ENVSIZE		255
#define	PATH		"PATH=/usr/bin"
#define	SUPATH		"PATH=/usr/sbin:/usr/bin"
#define	SHELL		"/usr/bin/sh"
#define	SHELL2		"/sbin/sh"
#define	TIMEZONEFILE	"/etc/default/init"
#define	LOGINFILE	"/etc/default/login"
#define	GLOBAL_ERR_SZ	1024
#define	GRAB_RETRY_MAX	100

static const char *pname;
extern char **environ;
static char *supath = SUPATH;
static char *path = PATH;
static char global_error[GLOBAL_ERR_SZ];
static int verbose = 0;

static priv_set_t *nset;

/* Private definitions for libproject */
extern projid_t setproject_proc(const char *, const char *, int, pid_t,
    struct ps_prochandle *, struct project *);
extern priv_set_t *setproject_initpriv(void);

static void usage(void);

static void preserve_error(const char *format, ...);

static int update_running_proc(int, char *, char *);
static int set_ids(struct ps_prochandle *, struct project *,
    struct passwd *);
static struct passwd *match_user(uid_t, char *, int);
static void setproject_err(char *, char *, int, struct project *);

static void
usage(void)
{
	(void) fprintf(stderr, gettext("usage: \n\t%s [-v] [-p project] "
	    "[-c pid | [-Fl] [command [args ...]]]\n"), pname);
	exit(2);
}

int
main(int argc, char *argv[])
{
	int c;
	struct passwd *pw;
	char *projname = NULL;
	uid_t uid;
	int login_flag = 0;
	int finalize_flag = TASK_NORMAL;
	int newproj_flag = 0;
	taskid_t taskid;
	char *shell;
	char *env[NENV];
	char **targs;
	char *filename, *procname = NULL;
	int error;

	nset = setproject_initpriv();
	if (nset == NULL)
		die(gettext("privilege initialization failed\n"));

	pname = getpname(argv[0]);

	while ((c = getopt(argc, argv, OPTIONS_STRING)) != EOF) {
		switch (c) {
		case 'v':
			verbose = 1;
			break;
		case 'p':
			newproj_flag = 1;
			projname = optarg;
			break;
		case 'F':
			finalize_flag = TASK_FINAL;
			break;
		case 'l':
			login_flag++;
			break;
		case 'c':
			procname = optarg;
			break;
		case '?':
		default:
			usage();
			/*NOTREACHED*/
		}
	}

	/* -c option is invalid with -F, -l, or a specified command */
	if ((procname != NULL) &&
	    (finalize_flag == TASK_FINAL || login_flag || optind < argc))
		usage();

	if (procname != NULL) {
		/* Change project/task of an existing process */
		return (update_running_proc(newproj_flag, procname, projname));
	}

	/*
	 * Get user data, so that we can confirm project membership as
	 * well as construct an appropriate login environment.
	 */
	uid = getuid();
	if ((pw = match_user(uid, projname, 1)) == NULL) {
		die("%s\n", global_error);
	}

	/*
	 * If no projname was specified, we're just creating a new task
	 * under the current project, so we can just set the new taskid.
	 * If our project is changing, we need to update any attendant
	 * pool/rctl bindings, so let setproject() do the dirty work.
	 */
	(void) __priv_bracket(PRIV_ON);
	if (projname == NULL) {
		if (settaskid(getprojid(), finalize_flag) == -1)
			if (errno == EAGAIN)
				die(gettext("resource control limit has been "
				    "reached"));
			else
				die(gettext("settaskid failed"));
	} else {
		if ((error = setproject(projname,
		    pw->pw_name, finalize_flag)) != 0) {
			setproject_err(pw->pw_name, projname, error, NULL);
			if (error < 0)
				die("%s\n", global_error);
			else
				warn("%s\n", global_error);
		}
	}
	__priv_relinquish();

	taskid = gettaskid();

	if (verbose)
		(void) fprintf(stderr, "%d\n", (int)taskid);

	/*
	 * Validate user's shell from passwd database.
	 */
	if (strcmp(pw->pw_shell, "") == 0) {
		if (access(SHELL, X_OK) == 0)
			pw->pw_shell = SHELL;
		else
			pw->pw_shell = SHELL2;
	}

	if (login_flag) {
		/*
		 * Since we've been invoked as a "simulated login", set up the
		 * environment.
		 */
		char *cur_tz = getenv("TZ");
		char *cur_term = getenv("TERM");

		char **envnext;

		size_t len_home = strlen(pw->pw_dir) + strlen("HOME=") + 1;
		size_t len_logname = strlen(pw->pw_name) + strlen("LOGNAME=") +
		    1;
		size_t len_shell = strlen(pw->pw_shell) + strlen("SHELL=") + 1;
		size_t len_mail = strlen(pw->pw_name) +
		    strlen("MAIL=/var/mail/") + 1;
		size_t len_tz;
		size_t len_term;

		char *env_home = safe_malloc(len_home);
		char *env_logname = safe_malloc(len_logname);
		char *env_shell = safe_malloc(len_shell);
		char *env_mail = safe_malloc(len_mail);
		char *env_tz;
		char *env_term;

		(void) snprintf(env_home, len_home, "HOME=%s", pw->pw_dir);
		(void) snprintf(env_logname, len_logname, "LOGNAME=%s",
		    pw->pw_name);
		(void) snprintf(env_shell, len_shell, "SHELL=%s", pw->pw_shell);
		(void) snprintf(env_mail, len_mail, "MAIL=/var/mail/%s",
		    pw->pw_name);

		env[0] = env_home;
		env[1] = env_logname;
		env[2] = (pw->pw_uid == 0 ? supath : path);
		env[3] = env_shell;
		env[4] = env_mail;
		env[5] = NULL;
		env[6] = NULL;
		env[7] = NULL;

		envnext = (char **)&env[5];

		/*
		 * It's possible that TERM wasn't defined in the outer
		 * environment.
		 */
		if (cur_term != NULL) {
			len_term = strlen(cur_term) + strlen("TERM=") + 1;
			env_term = safe_malloc(len_term);

			(void) snprintf(env_term, len_term, "TERM=%s",
			    cur_term);
			*envnext = env_term;
			envnext++;
		}

		/*
		 * It is also possible that TZ wasn't defined in the outer
		 * environment.  In that case, we must attempt to open the file
		 * defining the default timezone and select the appropriate
		 * entry. If there is no default timezone there, try
		 * TIMEZONE in /etc/default/login, duplicating the algorithm
		 * that login uses.
		 */
		if (cur_tz != NULL) {
			len_tz = strlen(cur_tz) + strlen("TZ=") + 1;
			env_tz = safe_malloc(len_tz);

			(void) snprintf(env_tz, len_tz, "TZ=%s", cur_tz);
			*envnext = env_tz;
		} else {
			if ((env_tz = getdefault(TIMEZONEFILE, "TZ=",
			    "TZ=")) != NULL)
				*envnext = env_tz;
			else {
				env_tz = getdefault(LOGINFILE, "TIMEZONE=",
				    "TZ=");
				*envnext = env_tz;
			}
		}

		environ = (char **)&env[0];

		/*
		 * Prefix the shell string with a hyphen, indicating a login
		 * shell.
		 */
		shell = safe_malloc(PATH_MAX);
		(void) snprintf(shell, PATH_MAX, "-%s", basename(pw->pw_shell));
	} else {
		shell = basename(pw->pw_shell);
	}

	/*
	 * If there are no arguments, we launch the user's shell; otherwise, the
	 * remaining commands are assumed to form a valid command invocation
	 * that we can exec.
	 */
	if (optind >= argc) {
		targs = alloca(2 * sizeof (char *));
		filename = pw->pw_shell;
		targs[0] = shell;
		targs[1] = NULL;
	} else {
		targs = &argv[optind];
		filename = targs[0];
	}

	if (execvp(filename, targs) == -1)
		die(gettext("exec of %s failed"), targs[0]);

	/*
	 * We should never get here.
	 */
	return (1);
}

static int
update_running_proc(int newproj_flag, char *procname, char *projname)
{
	struct ps_prochandle *p;
	prcred_t original_prcred, current_prcred;
	projid_t prprojid;
	taskid_t taskid;
	int error = 0, gret;
	struct project project;
	char prbuf[PROJECT_BUFSZ];
	struct passwd *passwd_entry;
	int grab_retry_count = 0;

	/*
	 * Catch signals from terminal. There isn't much sense in
	 * doing anything but ignoring them since we don't do anything
	 * after the point we'd be capable of handling them again.
	 */
	(void) sigignore(SIGHUP);
	(void) sigignore(SIGINT);
	(void) sigignore(SIGQUIT);
	(void) sigignore(SIGTERM);

	/* flush stdout before grabbing the proc to avoid deadlock */
	(void) fflush(stdout);

	/*
	 * We need to grab the process, which will force it to stop execution
	 * until the grab is released, in order to aquire some information about
	 * it, such as its current project (which is achieved via an injected
	 * system call and therefore needs an agent) and its credentials. We
	 * will then need to release it again because it may be a process that
	 * we rely on for later calls, for example nscd.
	 */
	if ((p = proc_arg_grab(procname, PR_ARG_PIDS, 0, &gret)) == NULL) {
		warn(gettext("failed to grab for process %s: %s\n"),
		    procname, Pgrab_error(gret));
		return (1);
	}
	if (Pcreate_agent(p) != 0) {
		Prelease(p, 0);
		warn(gettext("cannot control process %s\n"), procname);
		return (1);
	}

	/*
	 * The victim process is now held. Do not call any functions
	 * which generate stdout/stderr until the process has been
	 * released.
	 */

/*
 * The target process will soon be restarted (in case it is in newtask's
 * execution path) and then stopped again. We need to ensure that our cached
 * data doesn't change while the process runs so return here if the target
 * process changes its user id in between our stop operations, so that we can
 * try again.
 */
pgrab_retry:

	/* Cache required information about the process. */
	if (Pcred(p, &original_prcred, 0) != 0) {
		preserve_error(gettext("cannot get process credentials %s\n"),
		    procname);
		error = 1;
	}
	if ((prprojid = pr_getprojid(p)) == -1) {
		preserve_error(gettext("cannot get process project id %s\n"),
		    procname);
		error = 1;
	}

	/*
	 * We now have all the required information, so release the target
	 * process and perform our sanity checks. The process needs to be
	 * running at this point because it may be in the execution path of the
	 * calls made below.
	 */
	Pdestroy_agent(p);
	Prelease(p, 0);

	/* if our data acquisition failed, then we can't continue. */
	if (error) {
		warn("%s\n", global_error);
		return (1);
	}

	if (newproj_flag == 0) {
		/*
		 * Just changing the task, so set projname to the current
		 * project of the running process.
		 */
		if (getprojbyid(prprojid, &project, &prbuf,
		    PROJECT_BUFSZ) == NULL) {
			warn(gettext("unable to get project name "
			    "for projid %d"), prprojid);
			return (1);
		}
		projname = project.pj_name;
	} else {
		/*
		 * cache info for the project which user passed in via the
		 * command line
		 */
		if (getprojbyname(projname, &project, &prbuf,
		    PROJECT_BUFSZ) == NULL) {
			warn(gettext("unknown project \"%s\"\n"), projname);
			return (1);
		}
	}

	/*
	 * Use our cached information to verify that the owner of the running
	 * process is a member of proj
	 */
	if ((passwd_entry = match_user(original_prcred.pr_ruid,
	    projname, 0)) == NULL) {
		warn("%s\n", global_error);
		return (1);
	}

	/*
	 * We can now safely stop the process again in order to change the
	 * project and taskid as required.
	 */
	if ((p = proc_arg_grab(procname, PR_ARG_PIDS, 0, &gret)) == NULL) {
		warn(gettext("failed to grab for process %s: %s\n"),
		    procname, Pgrab_error(gret));
		return (1);
	}
	if (Pcreate_agent(p) != 0) {
		Prelease(p, 0);
		warn(gettext("cannot control process %s\n"), procname);
		return (1);
	}

	/*
	 * Now that the target process is stopped, check the validity of our
	 * cached info. If we aren't superuser then match_user() will have
	 * checked to make sure that the owner of the process is in the relevant
	 * project. If our ruid has changed, then match_user()'s conclusion may
	 * be invalid.
	 */
	if (getuid() != 0) {
		if (Pcred(p, &current_prcred, 0) != 0) {
			Pdestroy_agent(p);
			Prelease(p, 0);
			warn(gettext("can't get process credentials %s\n"),
			    procname);
			return (1);
		}

		if (original_prcred.pr_ruid != current_prcred.pr_ruid) {
			if (grab_retry_count++ < GRAB_RETRY_MAX)
				goto pgrab_retry;

			warn(gettext("process consistently changed its "
			    "user id %s\n"), procname);
			return (1);
		}
	}

	error = set_ids(p, &project, passwd_entry);

	if (verbose)
		taskid = pr_gettaskid(p);

	Pdestroy_agent(p);
	Prelease(p, 0);

	if (error) {
		/*
		 * error is serious enough to stop, only if negative.
		 * Otherwise, it simply indicates one of the resource
		 * control assignments failed, which is worth warning
		 * about.
		 */
		warn("%s\n", global_error);
		if (error < 0)
			return (1);
	}

	if (verbose)
		(void) fprintf(stderr, "%d\n", (int)taskid);

	return (0);
}

static int
set_ids(struct ps_prochandle *p, struct project *project,
    struct passwd *passwd_entry)
{
	int be_su = 0;
	prcred_t old_prcred;
	int error;
	prpriv_t *old_prpriv, *new_prpriv;
	size_t prsz = sizeof (prpriv_t);
	priv_set_t *eset, *pset;
	int ind;

	if (Pcred(p, &old_prcred, 0) != 0) {
		preserve_error(gettext("can't get process credentials"));
		return (1);
	}

	old_prpriv = proc_get_priv(Pstatus(p)->pr_pid);
	if (old_prpriv == NULL) {
		preserve_error(gettext("can't get process privileges"));
		return (1);
	}

	prsz = PRIV_PRPRIV_SIZE(old_prpriv);

	new_prpriv = malloc(prsz);
	if (new_prpriv == NULL) {
		preserve_error(gettext("can't allocate memory"));
		free(old_prpriv);
		return (1);
	}

	(void) memcpy(new_prpriv, old_prpriv, prsz);

	/*
	 * If the process already has the proc_taskid privilege,
	 * we don't need to elevate its privileges; if it doesn't,
	 * we try to do it here.
	 * As we do not wish to leave a window in which the process runs
	 * with elevated privileges, we make sure that the process dies
	 * when we go away unexpectedly.
	 */

	ind = priv_getsetbyname(PRIV_EFFECTIVE);
	eset = (priv_set_t *)&new_prpriv->pr_sets[new_prpriv->pr_setsize * ind];
	ind = priv_getsetbyname(PRIV_PERMITTED);
	pset = (priv_set_t *)&new_prpriv->pr_sets[new_prpriv->pr_setsize * ind];

	if (!priv_issubset(nset, eset)) {
		be_su = 1;
		priv_union(nset, eset);
		priv_union(nset, pset);
		if (Psetflags(p, PR_KLC) != 0) {
			preserve_error(gettext("cannot set process "
			    "privileges"));
			(void) Punsetflags(p, PR_KLC);
			free(new_prpriv);
			free(old_prpriv);
			return (1);
		}
		(void) __priv_bracket(PRIV_ON);
		if (Psetpriv(p, new_prpriv) != 0) {
			(void) __priv_bracket(PRIV_OFF);
			preserve_error(gettext("cannot set process "
			    "privileges"));
			(void) Punsetflags(p, PR_KLC);
			free(new_prpriv);
			free(old_prpriv);
			return (1);
		}
		(void) __priv_bracket(PRIV_OFF);
	}

	(void) __priv_bracket(PRIV_ON);
	if ((error = setproject_proc(project->pj_name,
	    passwd_entry->pw_name, 0, Pstatus(p)->pr_pid, p, project)) != 0) {
		/* global_error is set by setproject_err */
		setproject_err(passwd_entry->pw_name, project->pj_name,
		    error, project);
	}
	(void) __priv_bracket(PRIV_OFF);

	/* relinquish added privileges */
	if (be_su) {
		(void) __priv_bracket(PRIV_ON);
		if (Psetpriv(p, old_prpriv) != 0) {
			/*
			 * We shouldn't ever be in a state where we can't
			 * set the process back to its old creds, but we
			 * don't want to take the chance of leaving a
			 * non-privileged process with enhanced creds. So,
			 * release the process from libproc control, knowing
			 * that it will be killed.
			 */
			(void) __priv_bracket(PRIV_OFF);
			Pdestroy_agent(p);
			die(gettext("cannot relinquish superuser credentials "
			    "for pid %d. The process was killed."),
			    Pstatus(p)->pr_pid);
		}
		(void) __priv_bracket(PRIV_OFF);
		if (Punsetflags(p, PR_KLC) != 0)
			preserve_error(gettext("error relinquishing "
			    "credentials. Process %d will be killed."),
			    Pstatus(p)->pr_pid);
	}
	free(new_prpriv);
	free(old_prpriv);

	return (error);
}

/*
 * preserve_error() should be called rather than warn() by any
 * function that is called while the victim process is being
 * held by Pgrab.
 *
 * It saves a single error message to be printed until after
 * the process has been released. Since multiple errors are not
 * stored, any error should be considered critical.
 */
void
preserve_error(const char *format, ...)
{
	va_list alist;

	va_start(alist, format);

	/*
	 * GLOBAL_ERR_SZ is pretty big. If the error is longer
	 * than that, just truncate it, rather than chance missing
	 * the error altogether.
	 */
	(void) vsnprintf(global_error, GLOBAL_ERR_SZ-1, format, alist);

	va_end(alist);

}

/*
 * Given the input arguments, return the passwd structure that matches best.
 * Also, since we use getpwnam() and friends, subsequent calls to this
 * function will re-use the memory previously returned.
 */
static struct passwd *
match_user(uid_t uid, char *projname, int is_my_uid)
{
	char prbuf[PROJECT_BUFSZ], username[LOGNAME_MAX+1];
	struct project prj;
	char *tmp_name;
	struct passwd *pw = NULL;

	/*
	 * In order to allow users with the same UID but distinguishable
	 * user names to be in different projects we play a guessing
	 * game of which username is most appropriate. If we're checking
	 * for the uid of the calling process, the login name is a
	 * good starting point.
	 */
	if (is_my_uid) {
		if ((tmp_name = getlogin()) == NULL ||
		    (pw = getpwnam(tmp_name)) == NULL || (pw->pw_uid != uid) ||
		    (pw->pw_name == NULL))
			pw = NULL;
	}

	/*
	 * If the login name doesn't work,  we try the first match for
	 * the current uid in the password file.
	 */
	if (pw == NULL) {
		if (((pw = getpwuid(uid)) == NULL) || pw->pw_name == NULL) {
			preserve_error(gettext("cannot find username "
			    "for uid %d"), uid);
			return (NULL);
		}
	}

	/*
	 * If projname wasn't supplied, we've done our best, so just return
	 * what we've got now. Alternatively, if newtask's invoker has
	 * superuser privileges, return the pw structure we've got now, with
	 * no further checking from inproj(). Superuser should be able to
	 * join any project, and the subsequent call to setproject() will
	 * allow this.
	 */
	if (projname == NULL || getuid() == (uid_t)0)
		return (pw);

	(void) strlcpy(username, pw->pw_name, sizeof (username));

	if (inproj(username, projname, prbuf, PROJECT_BUFSZ) == 0) {
		char **u;
		tmp_name = NULL;

		/*
		 * If the previous guesses didn't work, walk through all
		 * project members and test for UID-equivalence.
		 */

		if (getprojbyname(projname, &prj, prbuf,
		    PROJECT_BUFSZ) == NULL) {
			preserve_error(gettext("unknown project \"%s\""),
			    projname);
			return (NULL);
		}

		for (u = prj.pj_users; *u; u++) {
			if ((pw = getpwnam(*u)) == NULL)
				continue;

			if (pw->pw_uid == uid) {
				tmp_name = pw->pw_name;
				break;
			}
		}

		if (tmp_name == NULL) {
			preserve_error(gettext("user \"%s\" is not a member of "
			    "project \"%s\""), username, projname);
			return (NULL);
		}
	}

	return (pw);
}

void
setproject_err(char *username, char *projname, int error, struct project *proj)
{
	kva_t *kv_array = NULL;
	char prbuf[PROJECT_BUFSZ];
	struct project local_proj;

	switch (error) {
	case SETPROJ_ERR_TASK:
		if (errno == EAGAIN)
			preserve_error(gettext("resource control limit has "
			    "been reached"));
		else if (errno == ESRCH)
			preserve_error(gettext("user \"%s\" is not a member of "
			    "project \"%s\""), username, projname);
		else if (errno == EACCES)
			preserve_error(gettext("the invoking task is final"));
		else
			preserve_error(
			    gettext("could not join project \"%s\""),
			    projname);
		break;
	case SETPROJ_ERR_POOL:
		if (errno == EACCES)
			preserve_error(gettext("no resource pool accepting "
			    "default bindings exists for project \"%s\""),
			    projname);
		else if (errno == ESRCH)
			preserve_error(gettext("specified resource pool does "
			    "not exist for project \"%s\""), projname);
		else
			preserve_error(gettext("could not bind to default "
			    "resource pool for project \"%s\""), projname);
		break;
	default:
		if (error <= 0) {
			preserve_error(gettext("setproject failed for "
			    "project \"%s\""), projname);
			return;
		}
		/*
		 * If we have a stopped target process it may be in
		 * getprojbyname()'s execution path which would make it unsafe
		 * to access the project table, so only do that if the caller
		 * hasn't provided a cached version of the project structure.
		 */
		if (proj == NULL)
			proj = getprojbyname(projname, &local_proj, prbuf,
			    PROJECT_BUFSZ);

		if (proj == NULL || (kv_array = _str2kva(proj->pj_attr,
		    KV_ASSIGN, KV_DELIMITER)) == NULL ||
		    kv_array->length < error) {
			preserve_error(gettext("warning, resource control "
			    "assignment failed for project \"%s\" "
			    "attribute %d"),
			    projname, error);
			if (kv_array)
				_kva_free(kv_array);
			return;
		}
		preserve_error(gettext("warning, %s resource control "
		    "assignment failed for project \"%s\""),
		    kv_array->data[error - 1].key, projname);
		_kva_free(kv_array);
	}
}

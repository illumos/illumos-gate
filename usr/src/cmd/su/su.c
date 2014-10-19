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
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved	*/

/*	Copyright (c) 1987, 1988 Microsoft Corporation	*/
/*	  All Rights Reserved	*/

/*
 *	su [-] [name [arg ...]] change userid, `-' changes environment.
 *	If SULOG is defined, all attempts to su to another user are
 *	logged there.
 *	If CONSOLE is defined, all successful attempts to su to uid 0
 *	are also logged there.
 *
 *	If su cannot create, open, or write entries into SULOG,
 *	(or on the CONSOLE, if defined), the entry will not
 *	be logged -- thus losing a record of the su's attempted
 *	during this period.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <unistd.h>
#include <stdlib.h>
#include <crypt.h>
#include <pwd.h>
#include <shadow.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <locale.h>
#include <syslog.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <grp.h>
#include <deflt.h>
#include <limits.h>
#include <errno.h>
#include <stdarg.h>
#include <user_attr.h>
#include <priv.h>

#include <bsm/adt.h>
#include <bsm/adt_event.h>

#include <security/pam_appl.h>

#define	PATH	"/usr/bin:"		/* path for users other than root */
#define	SUPATH	"/usr/sbin:/usr/bin"	/* path for root */
#define	SUPRMT	"PS1=# "		/* primary prompt for root */
#define	ELIM 128
#define	ROOT 0
#ifdef	DYNAMIC_SU
#define	EMBEDDED_NAME	"embedded_su"
#define	DEF_ATTEMPTS	3		/* attempts to change password */
#endif	/* DYNAMIC_SU */

#define	PW_FALSE	1		/* no password change */
#define	PW_TRUE		2		/* successful password change */
#define	PW_FAILED	3		/* failed password change */

/*
 * Intervals to sleep after failed su
 */
#ifndef SLEEPTIME
#define	SLEEPTIME	4
#endif

#define	DEFAULT_LOGIN "/etc/default/login"
#define	DEFFILE "/etc/default/su"


char	*Sulog, *Console;
char	*Path, *Supath;

/*
 * Locale variables to be propagated to "su -" environment
 */
static char *initvar;
static char *initenv[] = {
	"TZ", "LANG", "LC_CTYPE",
	"LC_NUMERIC", "LC_TIME", "LC_COLLATE",
	"LC_MONETARY", "LC_MESSAGES", "LC_ALL", 0};
static char mail[30] = { "MAIL=/var/mail/" };

static void envalt(void);
static void log(char *, char *, int);
static void to(int);

enum messagemode { USAGE, ERR, WARN };
static void message(enum messagemode, char *, ...);

static char *alloc_vsprintf(const char *, va_list);
static char *tail(char *);

static void audit_success(int, struct passwd *);
static void audit_logout(adt_session_data_t *, au_event_t);
static void audit_failure(int, struct passwd *, char *, int);

#ifdef DYNAMIC_SU
static void validate(char *, int *);
static int legalenvvar(char *);
static int su_conv(int, struct pam_message **, struct pam_response **, void *);
static int emb_su_conv(int, struct pam_message **, struct pam_response **,
    void *);
static void freeresponse(int, struct pam_response **response);
static struct pam_conv pam_conv = {su_conv, NULL};
static struct pam_conv emb_pam_conv = {emb_su_conv, NULL};
static void quotemsg(char *, ...);
static void readinitblock(void);
#else	/* !DYNAMIC_SU */
static void update_audit(struct passwd *pwd);
#endif	/* DYNAMIC_SU */

static pam_handle_t	*pamh = NULL;	/* Authentication handle */
struct	passwd pwd;
char	pwdbuf[1024];			/* buffer for getpwnam_r() */
char	shell[] = "/usr/bin/sh";	/* default shell */
char	safe_shell[] = "/sbin/sh";	/* "fallback" shell */
char	su[PATH_MAX] = "su";		/* arg0 for exec of shprog */
char	homedir[PATH_MAX] = "HOME=";
char	logname[20] = "LOGNAME=";
char	*suprmt = SUPRMT;
char	termtyp[PATH_MAX] = "TERM=";
char	*term;
char	shelltyp[PATH_MAX] = "SHELL=";
char	*hz;
char	tznam[PATH_MAX];
char	hzname[10] = "HZ=";
char	path[PATH_MAX] = "PATH=";
char	supath[PATH_MAX] = "PATH=";
char	*envinit[ELIM];
extern	char **environ;
char *ttyn;
char *username;					/* the invoker */
static	int	dosyslog = 0;			/* use syslog? */
char	*myname;
#ifdef	DYNAMIC_SU
int pam_flags = 0;
boolean_t embedded = B_FALSE;
#endif	/* DYNAMIC_SU */

int
main(int argc, char **argv)
{
#ifndef DYNAMIC_SU
	struct spwd sp;
	char  spbuf[1024];		/* buffer for getspnam_r() */
	char *password;
#endif	/* !DYNAMIC_SU */
	char *nptr;
	char *pshell;
	int eflag = 0;
	int envidx = 0;
	uid_t uid;
	gid_t gid;
	char *dir, *shprog, *name;
	char *ptr;
	char *prog = argv[0];
#ifdef DYNAMIC_SU
	int sleeptime = SLEEPTIME;
	char **pam_env = 0;
	int flags = 0;
	int retcode;
	int idx = 0;
#endif	/* DYNAMIC_SU */
	int pw_change = PW_FALSE;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it wasn't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	myname = tail(argv[0]);

#ifdef	DYNAMIC_SU
	if (strcmp(myname, EMBEDDED_NAME) == 0) {
		embedded = B_TRUE;
		setbuf(stdin, NULL);
		setbuf(stdout, NULL);
		readinitblock();
	}
#endif	/* DYNAMIC_SU */

	if (argc > 1 && *argv[1] == '-') {
		/* Explicitly check for just `-' (no trailing chars) */
		if (strlen(argv[1]) == 1) {
			eflag++;	/* set eflag if `-' is specified */
			argv++;
			argc--;
		} else {
			message(USAGE,
			    gettext("Usage: %s [-] [ username [ arg ... ] ]"),
			    prog);
			exit(1);
		}
	}

	/*
	 * Determine specified userid, get their password file entry,
	 * and set variables to values in password file entry fields.
	 */
	if (argc > 1) {
		/*
		 * Usernames can't start with a `-', so we check for that to
		 * catch bad usage (like "su - -c ls").
		 */
		if (*argv[1] == '-') {
			message(USAGE,
			    gettext("Usage: %s [-] [ username [ arg ... ] ]"),
			    prog);
			exit(1);
		} else
			nptr = argv[1];	/* use valid command-line username */
	} else
		nptr = "root";		/* use default "root" username */

	if (defopen(DEFFILE) == 0) {

		if (Sulog = defread("SULOG="))
			Sulog = strdup(Sulog);
		if (Console = defread("CONSOLE="))
			Console = strdup(Console);
		if (Path = defread("PATH="))
			Path = strdup(Path);
		if (Supath = defread("SUPATH="))
			Supath = strdup(Supath);
		if ((ptr = defread("SYSLOG=")) != NULL)
			dosyslog = strcmp(ptr, "YES") == 0;

		(void) defopen(NULL);
	}
	(void) strlcat(path, (Path) ? Path : PATH, sizeof (path));
	(void) strlcat(supath, (Supath) ? Supath : SUPATH, sizeof (supath));

	if ((ttyn = ttyname(0)) == NULL)
		if ((ttyn = ttyname(1)) == NULL)
			if ((ttyn = ttyname(2)) == NULL)
				ttyn = "/dev/???";
	if ((username = cuserid(NULL)) == NULL)
		username = "(null)";

	/*
	 * if Sulog defined, create SULOG, if it does not exist, with
	 * mode read/write user. Change owner and group to root
	 */
	if (Sulog != NULL) {
		(void) close(open(Sulog, O_WRONLY | O_APPEND | O_CREAT,
		    (S_IRUSR|S_IWUSR)));
		(void) chown(Sulog, (uid_t)ROOT, (gid_t)ROOT);
	}

#ifdef DYNAMIC_SU
	if (pam_start(embedded ? EMBEDDED_NAME : "su", nptr,
	    embedded ? &emb_pam_conv : &pam_conv, &pamh) != PAM_SUCCESS)
		exit(1);
	if (pam_set_item(pamh, PAM_TTY, ttyn) != PAM_SUCCESS)
		exit(1);
	if (getpwuid_r(getuid(), &pwd, pwdbuf, sizeof (pwdbuf)) == NULL ||
	    pam_set_item(pamh, PAM_AUSER, pwd.pw_name) != PAM_SUCCESS)
		exit(1);
#endif	/* DYNAMIC_SU */

	openlog("su", LOG_CONS, LOG_AUTH);

#ifdef DYNAMIC_SU

	/*
	 * Use the same value of sleeptime and password required that
	 * login(1) uses.
	 * This is obtained by reading the file /etc/default/login
	 * using the def*() functions
	 */
	if (defopen(DEFAULT_LOGIN) == 0) {
		if ((ptr = defread("SLEEPTIME=")) != NULL) {
			sleeptime = atoi(ptr);
			if (sleeptime < 0 || sleeptime > 5)
				sleeptime = SLEEPTIME;
		}

		if ((ptr = defread("PASSREQ=")) != NULL &&
		    strcasecmp("YES", ptr) == 0)
			pam_flags |= PAM_DISALLOW_NULL_AUTHTOK;

		(void) defopen((char *)NULL);
	}
	/*
	 * Ignore SIGQUIT and SIGINT
	 */
	(void) signal(SIGQUIT, SIG_IGN);
	(void) signal(SIGINT, SIG_IGN);

	/* call pam_authenticate() to authenticate the user through PAM */
	if (getpwnam_r(nptr, &pwd, pwdbuf, sizeof (pwdbuf)) == NULL)
		retcode = PAM_USER_UNKNOWN;
	else if ((flags = (getuid() != (uid_t)ROOT)) != 0) {
		retcode = pam_authenticate(pamh, pam_flags);
	} else /* root user does not need to authenticate */
		retcode = PAM_SUCCESS;

	if (retcode != PAM_SUCCESS) {
		/*
		 * 1st step: audit and log the error.
		 * 2nd step: sleep.
		 * 3rd step: print out message to user.
		 */
		/* don't let audit_failure distinguish a role here */
		audit_failure(PW_FALSE, NULL, nptr, retcode);
		switch (retcode) {
		case PAM_USER_UNKNOWN:
			closelog();
			(void) sleep(sleeptime);
			message(ERR, gettext("Unknown id: %s"), nptr);
			break;

		case PAM_AUTH_ERR:
			if (Sulog != NULL)
				log(Sulog, nptr, 0);	/* log entry */
			if (dosyslog)
				syslog(LOG_CRIT, "'su %s' failed for %s on %s",
				    pwd.pw_name, username, ttyn);
			closelog();
			(void) sleep(sleeptime);
			message(ERR, gettext("Sorry"));
			break;

		case PAM_CONV_ERR:
		default:
			if (dosyslog)
				syslog(LOG_CRIT, "'su %s' failed for %s on %s",
				    pwd.pw_name, username, ttyn);
			closelog();
			(void) sleep(sleeptime);
			message(ERR, gettext("Sorry"));
			break;
		}

		(void) signal(SIGQUIT, SIG_DFL);
		(void) signal(SIGINT, SIG_DFL);
		exit(1);
	}
	if (flags)
		validate(username, &pw_change);
	if (pam_setcred(pamh, PAM_REINITIALIZE_CRED) != PAM_SUCCESS) {
		message(ERR, gettext("unable to set credentials"));
		exit(2);
	}
	if (dosyslog)
		syslog(pwd.pw_uid == 0 ? LOG_NOTICE : LOG_INFO,
		    "'su %s' succeeded for %s on %s",
		    pwd.pw_name, username, ttyn);
	closelog();
	(void) signal(SIGQUIT, SIG_DFL);
	(void) signal(SIGINT, SIG_DFL);
#else	/* !DYNAMIC_SU */
	if ((getpwnam_r(nptr, &pwd, pwdbuf, sizeof (pwdbuf)) == NULL) ||
	    (getspnam_r(nptr, &sp, spbuf, sizeof (spbuf)) == NULL)) {
		message(ERR, gettext("Unknown id: %s"), nptr);
		audit_failure(PW_FALSE, NULL, nptr, PAM_USER_UNKNOWN);
		closelog();
		exit(1);
	}

	/*
	 * Prompt for password if invoking user is not root or
	 * if specified(new) user requires a password
	 */
	if (sp.sp_pwdp[0] == '\0' || getuid() == (uid_t)ROOT)
		goto ok;
	password = getpass(gettext("Password:"));

	if ((strcmp(sp.sp_pwdp, crypt(password, sp.sp_pwdp)) != 0)) {
		/* clear password file entry */
		(void) memset((void *)spbuf, 0, sizeof (spbuf));
		if (Sulog != NULL)
			log(Sulog, nptr, 0);    /* log entry */
		message(ERR, gettext("Sorry"));
		audit_failure(PW_FALSE, NULL, nptr, PAM_AUTH_ERR);
		if (dosyslog)
			syslog(LOG_CRIT, "'su %s' failed for %s on %s",
			    pwd.pw_name, username, ttyn);
		closelog();
		exit(2);
	}
	/* clear password file entry */
	(void) memset((void *)spbuf, 0, sizeof (spbuf));
ok:
	/* update audit session in a non-pam environment */
	update_audit(&pwd);
	if (dosyslog)
		syslog(pwd.pw_uid == 0 ? LOG_NOTICE : LOG_INFO,
		    "'su %s' succeeded for %s on %s",
		    pwd.pw_name, username, ttyn);
#endif	/* DYNAMIC_SU */

	audit_success(pw_change, &pwd);
	uid = pwd.pw_uid;
	gid = pwd.pw_gid;
	dir = strdup(pwd.pw_dir);
	shprog = strdup(pwd.pw_shell);
	name = strdup(pwd.pw_name);

	if (Sulog != NULL)
		log(Sulog, nptr, 1);	/* log entry */

	/* set user and group ids to specified user */

	/* set the real (and effective) GID */
	if (setgid(gid) == -1) {
		message(ERR, gettext("Invalid GID"));
		exit(2);
	}
	/* Initialize the supplementary group access list. */
	if (!nptr)
		exit(2);
	if (initgroups(nptr, gid) == -1) {
		exit(2);
	}
	/* set the real (and effective) UID */
	if (setuid(uid) == -1) {
		message(ERR, gettext("Invalid UID"));
		exit(2);
	}

	/*
	 * If new user's shell field is neither NULL nor equal to /usr/bin/sh,
	 * set:
	 *
	 *	pshell = their shell
	 *	su = [-]last component of shell's pathname
	 *
	 * Otherwise, set the shell to /usr/bin/sh and set argv[0] to '[-]su'.
	 */
	if (shprog[0] != '\0' && strcmp(shell, shprog) != 0) {
		char *p;

		pshell = shprog;
		(void) strcpy(su, eflag ? "-" : "");

		if ((p = strrchr(pshell, '/')) != NULL)
			(void) strlcat(su, p + 1, sizeof (su));
		else
			(void) strlcat(su, pshell, sizeof (su));
	} else {
		pshell = shell;
		(void) strcpy(su, eflag ? "-su" : "su");
	}

	/*
	 * set environment variables for new user;
	 * arg0 for exec of shprog must now contain `-'
	 * so that environment of new user is given
	 */
	if (eflag) {
		int j;
		char *var;

		if (strlen(dir) == 0) {
			(void) strcpy(dir, "/");
			message(WARN, gettext("No directory! Using home=/"));
		}
		(void) strlcat(homedir, dir, sizeof (homedir));
		(void) strlcat(logname, name, sizeof (logname));
		if (hz = getenv("HZ"))
			(void) strlcat(hzname, hz, sizeof (hzname));

		(void) strlcat(shelltyp, pshell, sizeof (shelltyp));

		if (chdir(dir) < 0) {
			message(ERR, gettext("No directory!"));
			exit(1);
		}
		envinit[envidx = 0] = homedir;
		envinit[++envidx] = ((uid == (uid_t)ROOT) ? supath : path);
		envinit[++envidx] = logname;
		envinit[++envidx] = hzname;
		if ((term = getenv("TERM")) != NULL) {
			(void) strlcat(termtyp, term, sizeof (termtyp));
			envinit[++envidx] = termtyp;
		}
		envinit[++envidx] = shelltyp;

		(void) strlcat(mail, name, sizeof (mail));
		envinit[++envidx] = mail;

		/*
		 * Fetch the relevant locale/TZ environment variables from
		 * the inherited environment.
		 *
		 * We have a priority here for setting TZ. If TZ is set in
		 * in the inherited environment, that value remains top
		 * priority. If the file /etc/default/login has TIMEZONE set,
		 * that has second highest priority.
		 */
		tznam[0] = '\0';
		for (j = 0; initenv[j] != 0; j++) {
			if (initvar = getenv(initenv[j])) {

				/*
				 * Skip over values beginning with '/' for
				 * security.
				 */
				if (initvar[0] == '/')  continue;

				if (strcmp(initenv[j], "TZ") == 0) {
					(void) strcpy(tznam, "TZ=");
					(void) strlcat(tznam, initvar,
					    sizeof (tznam));

				} else {
					var = (char *)
					    malloc(strlen(initenv[j])
					    + strlen(initvar)
					    + 2);
					if (var == NULL) {
						perror("malloc");
						exit(4);
					}
					(void) strcpy(var, initenv[j]);
					(void) strcat(var, "=");
					(void) strcat(var, initvar);
					envinit[++envidx] = var;
				}
			}
		}

		/*
		 * Check if TZ was found. If not then try to read it from
		 * /etc/default/login.
		 */
		if (tznam[0] == '\0') {
			if (defopen(DEFAULT_LOGIN) == 0) {
				if (initvar = defread("TIMEZONE=")) {
					(void) strcpy(tznam, "TZ=");
					(void) strlcat(tznam, initvar,
					    sizeof (tznam));
				}
				(void) defopen(NULL);
			}
		}

		if (tznam[0] != '\0')
			envinit[++envidx] = tznam;

#ifdef DYNAMIC_SU
		/*
		 * set the PAM environment variables -
		 * check for legal environment variables
		 */
		if ((pam_env = pam_getenvlist(pamh)) != 0) {
			while (pam_env[idx] != 0) {
				if (envidx + 2 < ELIM &&
				    legalenvvar(pam_env[idx])) {
					envinit[++envidx] = pam_env[idx];
				}
				idx++;
			}
		}
#endif	/* DYNAMIC_SU */
		envinit[++envidx] = NULL;
		environ = envinit;
	} else {
		char **pp = environ, **qq, *p;

		while ((p = *pp) != NULL) {
			if (*p == 'L' && p[1] == 'D' && p[2] == '_') {
				for (qq = pp; (*qq = qq[1]) != NULL; qq++)
					;
				/* pp is not advanced */
			} else {
				pp++;
			}
		}
	}

#ifdef DYNAMIC_SU
	if (pamh)
		(void) pam_end(pamh, PAM_SUCCESS);
#endif	/* DYNAMIC_SU */

	/*
	 * if new user is root:
	 *	if CONSOLE defined, log entry there;
	 *	if eflag not set, change environment to that of root.
	 */
	if (uid == (uid_t)ROOT) {
		if (Console != NULL)
			if (strcmp(ttyn, Console) != 0) {
				(void) signal(SIGALRM, to);
				(void) alarm(30);
				log(Console, nptr, 1);
				(void) alarm(0);
			}
		if (!eflag)
			envalt();
	}

	/*
	 * Default for SIGCPU and SIGXFSZ.  Shells inherit
	 * signal disposition from parent.  And the
	 * shells should have default dispositions for these
	 * signals.
	 */
	(void) signal(SIGXCPU, SIG_DFL);
	(void) signal(SIGXFSZ, SIG_DFL);

#ifdef	DYNAMIC_SU
	if (embedded) {
		(void) puts("SUCCESS");
		/*
		 * After this point, we're no longer talking the
		 * embedded_su protocol, so turn it off.
		 */
		embedded = B_FALSE;
	}
#endif	/* DYNAMIC_SU */

	/*
	 * if additional arguments, exec shell program with array
	 * of pointers to arguments:
	 *	-> if shell = default, then su = [-]su
	 *	-> if shell != default, then su = [-]last component of
	 *						shell's pathname
	 *
	 * if no additional arguments, exec shell with arg0 of su
	 * where:
	 *	-> if shell = default, then su = [-]su
	 *	-> if shell != default, then su = [-]last component of
	 *						shell's pathname
	 */
	if (argc > 2) {
		argv[1] = su;
		(void) execv(pshell, &argv[1]);
	} else
		(void) execl(pshell, su, 0);


	/*
	 * Try to clean up after an administrator who has made a mistake
	 * configuring root's shell; if root's shell is other than /sbin/sh,
	 * try exec'ing /sbin/sh instead.
	 */
	if ((uid == (uid_t)ROOT) && (strcmp(name, "root") == 0) &&
	    (strcmp(safe_shell, pshell) != 0)) {
		message(WARN,
		    gettext("No shell %s.  Trying fallback shell %s."),
		    pshell, safe_shell);

		if (eflag) {
			(void) strcpy(su, "-sh");
			(void) strlcpy(shelltyp + strlen("SHELL="),
			    safe_shell, sizeof (shelltyp) - strlen("SHELL="));
		} else {
			(void) strcpy(su, "sh");
		}

		if (argc > 2) {
			argv[1] = su;
			(void) execv(safe_shell, &argv[1]);
		} else {
			(void) execl(safe_shell, su, 0);
		}
		message(ERR, gettext("Couldn't exec fallback shell %s: %s"),
		    safe_shell, strerror(errno));
	} else {
		message(ERR, gettext("No shell"));
	}
	return (3);
}

/*
 * Environment altering routine -
 *	This routine is called when a user is su'ing to root
 *	without specifying the - flag.
 *	The user's PATH and PS1 variables are reset
 *	to the correct value for root.
 *	All of the user's other environment variables retain
 *	their current values after the su (if they are exported).
 */
static void
envalt(void)
{
	/*
	 * If user has PATH variable in their environment, change its value
	 *		to /bin:/etc:/usr/bin ;
	 * if user does not have PATH variable, add it to the user's
	 *		environment;
	 * if either of the above fail, an error message is printed.
	 */
	if (putenv(supath) != 0) {
		message(ERR,
		    gettext("unable to obtain memory to expand environment"));
		exit(4);
	}

	/*
	 * If user has PROMPT variable in their environment, change its value
	 *		to # ;
	 * if user does not have PROMPT variable, add it to the user's
	 *		environment;
	 * if either of the above fail, an error message is printed.
	 */
	if (putenv(suprmt) != 0) {
		message(ERR,
		    gettext("unable to obtain memory to expand environment"));
		exit(4);
	}
}

/*
 * Logging routine -
 *	where = SULOG or CONSOLE
 *	towho = specified user ( user being su'ed to )
 *	how = 0 if su attempt failed; 1 if su attempt succeeded
 */
static void
log(char *where, char *towho, int how)
{
	FILE *logf;
	time_t now;
	struct tm *tmp;

	/*
	 * open SULOG or CONSOLE - if open fails, return
	 */
	if ((logf = fopen(where, "a")) == NULL)
		return;

	now = time(0);
	tmp = localtime(&now);

	/*
	 * write entry into SULOG or onto CONSOLE - if write fails, return
	 */
	(void) fprintf(logf, "SU %.2d/%.2d %.2d:%.2d %c %s %s-%s\n",
	    tmp->tm_mon + 1, tmp->tm_mday, tmp->tm_hour, tmp->tm_min,
	    how ? '+' : '-', ttyn + sizeof ("/dev/") - 1, username, towho);

	(void) fclose(logf);	/* close SULOG or CONSOLE */
}

/*ARGSUSED*/
static void
to(int sig)
{}

/*
 * audit_success - audit successful su
 *
 *	Entry	process audit context established -- i.e., pam_setcred()
 *			or equivalent called.
 *		pw_change = PW_TRUE, if successful password change audit
 *				required.
 *		pwd = passwd entry for new user.
 */

static void
audit_success(int pw_change, struct passwd *pwd)
{
	adt_session_data_t	*ah = NULL;
	adt_event_data_t	*event;
	au_event_t		event_id = ADT_su;
	userattr_t		*user_entry;
	char			*kva_value;

	if (adt_start_session(&ah, NULL, ADT_USE_PROC_DATA) != 0) {
		syslog(LOG_AUTH | LOG_ALERT,
		    "adt_start_session(ADT_su): %m");
		return;
	}
	if (((user_entry = getusernam(pwd->pw_name)) != NULL) &&
	    ((kva_value = kva_match((kva_t *)user_entry->attr,
	    USERATTR_TYPE_KW)) != NULL) &&
	    ((strcmp(kva_value, USERATTR_TYPE_NONADMIN_KW) == 0) ||
	    (strcmp(kva_value, USERATTR_TYPE_ADMIN_KW) == 0))) {
		event_id = ADT_role_login;
	}
	free_userattr(user_entry);	/* OK to use, checks for NULL */

	/* since proc uid/gid not yet updated */
	if (adt_set_user(ah, pwd->pw_uid, pwd->pw_gid, pwd->pw_uid,
	    pwd->pw_gid, NULL, ADT_USER) != 0) {
		syslog(LOG_AUTH | LOG_ERR,
		    "adt_set_user(ADT_su, ADT_FAILURE): %m");
	}
	if ((event = adt_alloc_event(ah, event_id)) == NULL) {
		syslog(LOG_AUTH | LOG_ALERT, "adt_alloc_event(ADT_su): %m");
	} else if (adt_put_event(event, ADT_SUCCESS, ADT_SUCCESS) != 0) {
		syslog(LOG_AUTH | LOG_ALERT,
		    "adt_put_event(ADT_su, ADT_SUCCESS): %m");
	}

	if (pw_change == PW_TRUE) {
		/* Also audit password change */
		adt_free_event(event);
		if ((event = adt_alloc_event(ah, ADT_passwd)) == NULL) {
			syslog(LOG_AUTH | LOG_ALERT,
			    "adt_alloc_event(ADT_passwd): %m");
		} else if (adt_put_event(event, ADT_SUCCESS,
		    ADT_SUCCESS) != 0) {
			syslog(LOG_AUTH | LOG_ALERT,
			    "adt_put_event(ADT_passwd, ADT_SUCCESS): %m");
		}
	}
	adt_free_event(event);
	/*
	 * The preceeding code is a noop if audit isn't enabled,
	 * but, let's not make a new process when it's not necessary.
	 */
	if (adt_audit_state(AUC_AUDITING)) {
		audit_logout(ah, event_id);	/* fork to catch logout */
	}
	(void) adt_end_session(ah);
}


/*
 * audit_logout - audit successful su logout
 *
 *	Entry	ah = Successful su audit handle
 *		event_id = su event ID: ADT_su, ADT_role_login
 *
 *	Exit	Errors are just ignored and we go on.
 *		su logout event written.
 */
static void
audit_logout(adt_session_data_t *ah, au_event_t event_id)
{
	adt_event_data_t	*event;
	int			status;		/* wait status */
	pid_t			pid;
	priv_set_t		*priv;		/* waiting process privs */

	if (event_id == ADT_su) {
		event_id = ADT_su_logout;
	} else {
		event_id = ADT_role_logout;
	}
	if ((event = adt_alloc_event(ah, event_id)) == NULL) {
		syslog(LOG_AUTH | LOG_ALERT,
		    "adt_alloc_event(ADT_su_logout): %m");
		return;
	}
	if ((priv = priv_allocset())  == NULL) {
		syslog(LOG_AUTH | LOG_ALERT,
		    "su audit_logout: could not alloc basic privs: %m");
		adt_free_event(event);
		return;
	}

	/*
	 * The child returns and continues su processing.
	 * The parent's sole job is to wait for child exit, write the
	 * logout audit record, and replay the child's exit code.
	 */
	if ((pid = fork()) == 0) {
		/* child */

		adt_free_event(event);
		priv_freeset(priv);
		return;
	}
	if (pid == -1) {
		/* failure */

		syslog(LOG_AUTH | LOG_ALERT,
		    "su audit_logout: could not fork: %m");
		adt_free_event(event);
		priv_freeset(priv);
		return;
	}

	/* parent process */

	/*
	 * When this routine is called, the current working
	 * directory is the unknown and there are unknown open
	 * files. For the waiting process, change the current
	 * directory to root and close open files so that
	 * directories can be unmounted if necessary.
	 */
	if (chdir("/") != 0) {
		syslog(LOG_AUTH | LOG_ALERT,
		    "su audit_logout: could not chdir /: %m");
	}
	/*
	 * Reduce privileges to just those needed.
	 */
	priv_basicset(priv);
	(void) priv_delset(priv, PRIV_PROC_EXEC);
	(void) priv_delset(priv, PRIV_PROC_FORK);
	(void) priv_delset(priv, PRIV_PROC_INFO);
	(void) priv_delset(priv, PRIV_PROC_SESSION);
	(void) priv_delset(priv, PRIV_FILE_LINK_ANY);
	if ((priv_addset(priv, PRIV_PROC_AUDIT) != 0) ||
	    (setppriv(PRIV_SET, PRIV_PERMITTED, priv) != 0)) {
		syslog(LOG_AUTH | LOG_ALERT,
		    "su audit_logout: could not reduce privs: %m");
	}
	closefrom(0);
	priv_freeset(priv);

	for (;;) {
		if (pid != waitpid(pid, &status, WUNTRACED)) {
			if (errno == ECHILD) {
				/*
				 * No existing child with the given pid. Lets
				 * audit the logout.
				 */
				break;
			}
			continue;
		}

		if (WIFEXITED(status) || WIFSIGNALED(status)) {
			/*
			 * The child shell exited or was terminated by
			 * a signal. Lets audit logout.
			 */
			break;
		} else if (WIFSTOPPED(status)) {
			pid_t pgid;
			int fd;
			void (*sg_handler)();
			/*
			 * The child shell has been stopped/suspended.
			 * We need to suspend here as well and pass down
			 * the control to the parent process.
			 */
			sg_handler = signal(WSTOPSIG(status), SIG_DFL);
			(void) sigsend(P_PGID, getpgrp(), WSTOPSIG(status));
			/*
			 * We stop here. When resumed, mark the child
			 * shell group as foreground process group
			 * which gives the child shell a control over
			 * the controlling terminal.
			 */
			(void) signal(WSTOPSIG(status), sg_handler);

			pgid = getpgid(pid);
			if ((fd = open("/dev/tty", O_RDWR)) != -1) {
				/*
				 * Pass down the control over the controlling
				 * terminal iff we are in a foreground process
				 * group. Otherwise, we are in a background
				 * process group and the kernel will send
				 * SIGTTOU signal to stop us (by default).
				 */
				if (tcgetpgrp(fd) == getpgrp()) {
					(void) tcsetpgrp(fd, pgid);
				}
				(void) close(fd);
			}
			/* Wake up the child shell */
			(void) sigsend(P_PGID, pgid, SIGCONT);
		}
	}

	(void) adt_put_event(event, ADT_SUCCESS, ADT_SUCCESS);
	adt_free_event(event);
	(void) adt_end_session(ah);
	exit(WEXITSTATUS(status));
}


/*
 * audit_failure - audit failed su
 *
 *	Entry	New audit context not set.
 *		pw_change == PW_FALSE, if no password change requested.
 *			     PW_FAILED, if failed password change audit
 *				      required.
 *		pwd = NULL, or password entry to use.
 *		user = username entered.  Add to record if pwd == NULL.
 *		pamerr = PAM error code; reason for failure.
 */

static void
audit_failure(int pw_change, struct passwd *pwd, char *user, int pamerr)
{
	adt_session_data_t	*ah;	/* audit session handle */
	adt_event_data_t	*event;	/* event to generate */
	au_event_t		event_id = ADT_su;
	userattr_t		*user_entry;
	char			*kva_value;

	if (adt_start_session(&ah, NULL, ADT_USE_PROC_DATA) != 0) {
		syslog(LOG_AUTH | LOG_ALERT,
		    "adt_start_session(ADT_su, ADT_FAILURE): %m");
		return;
	}

	if (pwd != NULL) {
		/* target user authenticated, merge audit state */
		if (adt_set_user(ah, pwd->pw_uid, pwd->pw_gid, pwd->pw_uid,
		    pwd->pw_gid, NULL, ADT_UPDATE) != 0) {
			syslog(LOG_AUTH | LOG_ERR,
			    "adt_set_user(ADT_su, ADT_FAILURE): %m");
		}
		if (((user_entry = getusernam(pwd->pw_name)) != NULL) &&
		    ((kva_value = kva_match((kva_t *)user_entry->attr,
		    USERATTR_TYPE_KW)) != NULL) &&
		    ((strcmp(kva_value, USERATTR_TYPE_NONADMIN_KW) == 0) ||
		    (strcmp(kva_value, USERATTR_TYPE_ADMIN_KW) == 0))) {
			event_id = ADT_role_login;
		}
		free_userattr(user_entry);	/* OK to use, checks for NULL */
	}
	if ((event = adt_alloc_event(ah, event_id)) == NULL) {
		syslog(LOG_AUTH | LOG_ALERT,
		    "adt_alloc_event(ADT_su, ADT_FAILURE): %m");
		return;
	}
	/*
	 * can't tell if user not found is a role, so always use su
	 * If we do pass in pwd when the JNI is fixed, then can
	 * distinguish and set name in both su and role_login
	 */
	if (pwd == NULL) {
		/*
		 * this should be "fail_user" rather than "message"
		 * see adt_xml.  The JNI breaks, so for now we leave
		 * this alone.
		 */
		event->adt_su.message = user;
	}
	if (adt_put_event(event, ADT_FAILURE,
	    ADT_FAIL_PAM + pamerr) != 0) {
		syslog(LOG_AUTH | LOG_ALERT,
		    "adt_put_event(ADT_su(ADT_FAIL, %s): %m",
		    pam_strerror(pamh, pamerr));
	}
	if (pw_change != PW_FALSE) {
		/* Also audit password change failed */
		adt_free_event(event);
		if ((event = adt_alloc_event(ah, ADT_passwd)) == NULL) {
			syslog(LOG_AUTH | LOG_ALERT,
			    "su: adt_alloc_event(ADT_passwd): %m");
		} else if (adt_put_event(event, ADT_FAILURE,
		    ADT_FAIL_PAM + pamerr) != 0) {
			syslog(LOG_AUTH | LOG_ALERT,
			    "su: adt_put_event(ADT_passwd, ADT_FAILURE): %m");
		}
	}
	adt_free_event(event);
	(void) adt_end_session(ah);
}

#ifdef DYNAMIC_SU
/*
 * su_conv():
 *	This is the conv (conversation) function called from
 *	a PAM authentication module to print error messages
 *	or garner information from the user.
 */
/*ARGSUSED*/
static int
su_conv(int num_msg, struct pam_message **msg, struct pam_response **response,
    void *appdata_ptr)
{
	struct pam_message	*m;
	struct pam_response	*r;
	char			*temp;
	int			k;
	char			respbuf[PAM_MAX_RESP_SIZE];

	if (num_msg <= 0)
		return (PAM_CONV_ERR);

	*response = (struct pam_response *)calloc(num_msg,
	    sizeof (struct pam_response));
	if (*response == NULL)
		return (PAM_BUF_ERR);

	k = num_msg;
	m = *msg;
	r = *response;
	while (k--) {

		switch (m->msg_style) {

		case PAM_PROMPT_ECHO_OFF:
			errno = 0;
			temp = getpassphrase(m->msg);
			if (errno == EINTR)
				return (PAM_CONV_ERR);
			if (temp != NULL) {
				r->resp = strdup(temp);
				if (r->resp == NULL) {
					freeresponse(num_msg, response);
					return (PAM_BUF_ERR);
				}
			}
			break;

		case PAM_PROMPT_ECHO_ON:
			if (m->msg != NULL) {
				(void) fputs(m->msg, stdout);
			}

			(void) fgets(respbuf, sizeof (respbuf), stdin);
			temp = strchr(respbuf, '\n');
			if (temp != NULL)
				*temp = '\0';

			r->resp = strdup(respbuf);
			if (r->resp == NULL) {
				freeresponse(num_msg, response);
				return (PAM_BUF_ERR);
			}
			break;

		case PAM_ERROR_MSG:
			if (m->msg != NULL) {
				(void) fputs(m->msg, stderr);
				(void) fputs("\n", stderr);
			}
			break;

		case PAM_TEXT_INFO:
			if (m->msg != NULL) {
				(void) fputs(m->msg, stdout);
				(void) fputs("\n", stdout);
			}
			break;

		default:
			break;
		}
		m++;
		r++;
	}
	return (PAM_SUCCESS);
}

/*
 * emb_su_conv():
 *	This is the conv (conversation) function called from
 *	a PAM authentication module to print error messages
 *	or garner information from the user.
 *	This version is used for embedded_su.
 */
/*ARGSUSED*/
static int
emb_su_conv(int num_msg, struct pam_message **msg,
    struct pam_response **response, void *appdata_ptr)
{
	struct pam_message	*m;
	struct pam_response	*r;
	char			*temp;
	int			k;
	char			respbuf[PAM_MAX_RESP_SIZE];

	if (num_msg <= 0)
		return (PAM_CONV_ERR);

	*response = (struct pam_response *)calloc(num_msg,
	    sizeof (struct pam_response));
	if (*response == NULL)
		return (PAM_BUF_ERR);

	/* First, send the prompts */
	(void) printf("CONV %d\n", num_msg);
	k = num_msg;
	m = *msg;
	while (k--) {
		switch (m->msg_style) {

		case PAM_PROMPT_ECHO_OFF:
			(void) puts("PAM_PROMPT_ECHO_OFF");
			goto msg_common;

		case PAM_PROMPT_ECHO_ON:
			(void) puts("PAM_PROMPT_ECHO_ON");
			goto msg_common;

		case PAM_ERROR_MSG:
			(void) puts("PAM_ERROR_MSG");
			goto msg_common;

		case PAM_TEXT_INFO:
			(void) puts("PAM_TEXT_INFO");
			/* fall through to msg_common */
msg_common:
			if (m->msg == NULL)
				quotemsg(NULL);
			else
				quotemsg("%s", m->msg);
			break;

		default:
			break;
		}
		m++;
	}

	/* Next, collect the responses */
	k = num_msg;
	m = *msg;
	r = *response;
	while (k--) {

		switch (m->msg_style) {

		case PAM_PROMPT_ECHO_OFF:
		case PAM_PROMPT_ECHO_ON:
			(void) fgets(respbuf, sizeof (respbuf), stdin);

			temp = strchr(respbuf, '\n');
			if (temp != NULL)
				*temp = '\0';

			r->resp = strdup(respbuf);
			if (r->resp == NULL) {
				freeresponse(num_msg, response);
				return (PAM_BUF_ERR);
			}

			break;

		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO:
			break;

		default:
			break;
		}
		m++;
		r++;
	}
	return (PAM_SUCCESS);
}

static void
freeresponse(int num_msg, struct pam_response **response)
{
	struct pam_response *r;
	int i;

	/* free responses */
	r = *response;
	for (i = 0; i < num_msg; i++, r++) {
		if (r->resp != NULL) {
			/* Zap it in case it's a password */
			(void) memset(r->resp, '\0', strlen(r->resp));
			free(r->resp);
		}
	}
	free(*response);
	*response = NULL;
}

/*
 * Print a message, applying quoting for lines starting with '.'.
 *
 * I18n note:  \n is "safe" in all locales, and all locales use
 * a high-bit-set character to start multibyte sequences, so
 * scanning for a \n followed by a '.' is safe.
 */
static void
quotemsg(char *fmt, ...)
{
	if (fmt != NULL) {
		char *msg;
		char *p;
		boolean_t bol;
		va_list v;

		va_start(v, fmt);
		msg = alloc_vsprintf(fmt, v);
		va_end(v);

		bol = B_TRUE;
		for (p = msg; *p != '\0'; p++) {
			if (bol) {
				if (*p == '.')
					(void) putchar('.');
				bol = B_FALSE;
			}
			(void) putchar(*p);
			if (*p == '\n')
				bol = B_TRUE;
		}
		(void) putchar('\n');
		free(msg);
	}
	(void) putchar('.');
	(void) putchar('\n');
}

/*
 * validate - Check that the account is valid for switching to.
 */
static void
validate(char *usernam, int *pw_change)
{
	int error;
	int tries;

	if ((error = pam_acct_mgmt(pamh, pam_flags)) != PAM_SUCCESS) {
		if (Sulog != NULL)
			log(Sulog, pwd.pw_name, 0);    /* log entry */
		if (error == PAM_NEW_AUTHTOK_REQD) {
			tries = 0;
			message(ERR, gettext("Password for user "
			    "'%s' has expired"), pwd.pw_name);
			while ((error = pam_chauthtok(pamh,
			    PAM_CHANGE_EXPIRED_AUTHTOK)) != PAM_SUCCESS) {
				if ((error == PAM_AUTHTOK_ERR ||
				    error == PAM_TRY_AGAIN) &&
				    (tries++ < DEF_ATTEMPTS)) {
					continue;
				}
				message(ERR, gettext("Sorry"));
				audit_failure(PW_FAILED, &pwd, NULL, error);
				if (dosyslog)
					syslog(LOG_CRIT,
					    "'su %s' failed for %s on %s",
					    pwd.pw_name, usernam, ttyn);
				closelog();
				exit(1);
			}
			*pw_change = PW_TRUE;
			return;
		} else {
			message(ERR, gettext("Sorry"));
			audit_failure(PW_FALSE, &pwd, NULL, error);
			if (dosyslog)
				syslog(LOG_CRIT, "'su %s' failed for %s on %s",
				    pwd.pw_name, usernam, ttyn);
			closelog();
			exit(3);
		}
	}
}

static char *illegal[] = {
	"SHELL=",
	"HOME=",
	"LOGNAME=",
#ifndef NO_MAIL
	"MAIL=",
#endif
	"CDPATH=",
	"IFS=",
	"PATH=",
	"TZ=",
	"HZ=",
	"TERM=",
	0
};

/*
 * legalenvvar - can PAM modules insert this environmental variable?
 */

static int
legalenvvar(char *s)
{
	register char **p;

	for (p = illegal; *p; p++)
		if (strncmp(s, *p, strlen(*p)) == 0)
			return (0);

	if (s[0] == 'L' && s[1] == 'D' && s[2] == '_')
		return (0);

	return (1);
}

/*
 * The embedded_su protocol allows the client application to supply
 * an initialization block terminated by a line with just a "." on it.
 *
 * This initialization block is currently unused, reserved for future
 * expansion.  Ignore it.  This is made very slightly more complex by
 * the desire to cleanly ignore input lines of any length, while still
 * correctly detecting a line with just a "." on it.
 *
 * I18n note:  It appears that none of the Solaris-supported locales
 * use 0x0a for any purpose other than newline, so looking for '\n'
 * seems safe.
 * All locales use high-bit-set leadin characters for their multi-byte
 * sequences, so a line consisting solely of ".\n" is what it appears
 * to be.
 */
static void
readinitblock(void)
{
	char buf[100];
	boolean_t bol;

	bol = B_TRUE;
	for (;;) {
		if (fgets(buf, sizeof (buf), stdin) == NULL)
			return;
		if (bol && strcmp(buf, ".\n") == 0)
			return;
		bol = (strchr(buf, '\n') != NULL);
	}
}
#else	/* !DYNAMIC_SU */
static void
update_audit(struct passwd *pwd)
{
	adt_session_data_t	*ah;	/* audit session handle */

	if (adt_start_session(&ah, NULL, ADT_USE_PROC_DATA) != 0) {
		message(ERR, gettext("Sorry"));
		if (dosyslog)
			syslog(LOG_CRIT, "'su %s' failed for %s "
			    "cannot start audit session %m",
			    pwd->pw_name, username);
		closelog();
		exit(2);
	}
	if (adt_set_user(ah, pwd->pw_uid, pwd->pw_gid, pwd->pw_uid,
	    pwd->pw_gid, NULL, ADT_UPDATE) != 0) {
		if (dosyslog)
			syslog(LOG_CRIT, "'su %s' failed for %s "
			    "cannot update audit session %m",
			    pwd->pw_name, username);
		closelog();
		exit(2);
	}
}
#endif	/* DYNAMIC_SU */

/*
 * Report an error, either a fatal one, a warning, or a usage message,
 * depending on the mode parameter.
 */
/*ARGSUSED*/
static void
message(enum messagemode mode, char *fmt, ...)
{
	char *s;
	va_list v;

	va_start(v, fmt);
	s = alloc_vsprintf(fmt, v);
	va_end(v);

#ifdef	DYNAMIC_SU
	if (embedded) {
		if (mode == WARN) {
			(void) printf("CONV 1\n");
			(void) printf("PAM_ERROR_MSG\n");
		} else { /* ERR, USAGE */
			(void) printf("ERROR\n");
		}
		if (mode == USAGE) {
			quotemsg("%s", s);
		} else { /* ERR, WARN */
			quotemsg("%s: %s", myname, s);
		}
	} else {
#endif	/* DYNAMIC_SU */
		if (mode == USAGE) {
			(void) fprintf(stderr, "%s\n", s);
		} else { /* ERR, WARN */
			(void) fprintf(stderr, "%s: %s\n", myname, s);
		}
#ifdef	DYNAMIC_SU
	}
#endif	/* DYNAMIC_SU */

	free(s);
}

/*
 * Return a pointer to the last path component of a.
 */
static char *
tail(char *a)
{
	char *p;

	p = strrchr(a, '/');
	if (p == NULL)
		p = a;
	else
		p++;	/* step over the '/' */

	return (p);
}

static char *
alloc_vsprintf(const char *fmt, va_list ap1)
{
	va_list ap2;
	int n;
	char buf[1];
	char *s;

	/*
	 * We need to scan the argument list twice.  Save off a copy
	 * of the argument list pointer(s) for the second pass.  Note that
	 * we are responsible for va_end'ing our copy.
	 */
	va_copy(ap2, ap1);

	/*
	 * vsnprintf into a dummy to get a length.  One might
	 * think that passing 0 as the length to snprintf would
	 * do what we want, but it's defined not to.
	 *
	 * Perhaps we should sprintf into a 100 character buffer
	 * or something like that, to avoid two calls to snprintf
	 * in most cases.
	 */
	n = vsnprintf(buf, sizeof (buf), fmt, ap2);
	va_end(ap2);

	/*
	 * Allocate an appropriately-sized buffer.
	 */
	s = malloc(n + 1);
	if (s == NULL) {
		perror("malloc");
		exit(4);
	}

	(void) vsnprintf(s, n+1, fmt, ap1);

	return (s);
}

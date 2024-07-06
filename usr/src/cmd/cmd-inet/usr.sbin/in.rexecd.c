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
 * Copyright 2023 OmniOS Community Edition (OmniOSce) Association.
 */

/*	Copyright (c) 1983-1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/filio.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <netdb.h>
#include <syslog.h>
#include <nss_dbdefs.h>
#include <security/pam_appl.h>
#include <deflt.h>

#ifdef SYSV
#include <shadow.h>
#endif /* SYSV */

#ifndef NCARGS
#define	NCARGS	5120
#endif /* NCARGS */

#ifdef SYSV
#define	rindex	strrchr
#define	killpg(a, b)	kill(-(a), (b))
#else
char  *sprintf();
#endif	/* SYSV */

#define	MAXFD(A, B) ((A) > (B) ? (A) : (B))
#define	_PATH_DEFAULT_LOGIN	"/etc/default/login"

static void error(char *fmt, ...);
static void doit(int f, struct sockaddr_storage *fromp);
static void getstr(char *buf, int cnt, char *err);

static int legalenvvar(char *s);

/* Function decls. for functions not in any header file.  (Grrrr.) */
extern int audit_rexecd_setup(void);
extern int audit_rexecd_success(char *, char *, char *);
extern int audit_rexecd_fail(char *, char *, char *, char *);
extern int audit_settid(int);	/* set termnal ID */

/* PAM conversation function */
static int rexec_conv(int, const struct pam_message **,
    struct pam_response **, void *);

static pam_handle_t *pamh;	/* authentication handle */
static struct pam_conv conv = {
			rexec_conv,
			NULL
		};

/*
 * remote execute server:
 *	username\0
 *	password\0
 *	command\0
 *	data
 *
 * in.rexecd has been modified to run as the user invoking it. Hence there is no
 * need to limit any privileges.
 */
/*ARGSUSED*/
int
main(int argc, char **argv)
{
	struct sockaddr_storage from;
	socklen_t fromlen;

	openlog("rexec", LOG_PID | LOG_ODELAY, LOG_DAEMON);
	(void) audit_rexecd_setup();	/* BSM */
	fromlen = (socklen_t)sizeof (from);
	if (getpeername(0, (struct sockaddr *)&from, &fromlen) < 0) {
		(void) fprintf(stderr, "%s: ", argv[0]);
		perror("getpeername");
		exit(1);
	}

	if (audit_settid(0) != 0) {
		perror("settid");
		exit(1);
	}

	doit(0, &from);
	return (0);
}

static char	username[20] = "USER=";
static char	homedir[64] = "HOME=";
static char	shell[64] = "SHELL=";

static char	*envinit[] =
#ifdef SYSV
	{homedir, shell, (char *)0, username,
	(char *)0, (char *)0, (char *)0, (char *)0,
	(char *)0, (char *)0, (char *)0, (char *)0,
	(char *)0, (char *)0, (char *)0, (char *)0,
	(char *)0, (char *)0, (char *)0, (char *)0,
	(char *)0};
#define	ENVINIT_PATH	2	/* position of PATH in envinit[] */
#define	PAM_ENV_ELIM	16	/* max PAM environment variables */

/*
 *	See PSARC opinion 1992/025
 */
static char	userpath[] = "PATH=/usr/bin:";
static char	rootpath[] = "PATH=/usr/sbin:/usr/bin";
#else
	    {homedir, shell, "PATH=:/usr/ucb:/bin:/usr/bin", username, 0};
#endif /* SYSV */

static struct	sockaddr_storage asin;
static char pass[16];

static void
doit(int f, struct sockaddr_storage *fromp)
{
	char cmdbuf[NCARGS+1], *cp;
	char user[16];
	char hostname [MAXHOSTNAMELEN + 1];
	struct passwd *pwd, pw_data;
	char pwdbuf[NSS_BUFLEN_PASSWD];
	int s;
	ushort_t port;
	pid_t pid;
	int pv[2], cc;
	fd_set readfrom, ready;
	char buf[BUFSIZ], sig;
	int one = 1;
	int idx = 0, end_env = 0;
	char **pam_env;
	int status = PAM_AUTH_ERR;
	char abuf[INET6_ADDRSTRLEN];
	struct in_addr v4dst;
	socklen_t fromplen;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	int pam_flags = 0;

	(void) signal(SIGINT, SIG_DFL);
	(void) signal(SIGQUIT, SIG_DFL);
	(void) signal(SIGTERM, SIG_DFL);
#ifdef DEBUG
	{
		int t = open("/dev/tty", 2);
		if (t >= 0) {
#ifdef SYSV
			(void) setsid();
#else
			(void) ioctl(t, TIOCNOTTY, (char *)0);
#endif	/* SYSV */
			(void) close(t);
		}
	}
#endif
	if (fromp->ss_family == AF_INET) {
		sin = (struct sockaddr_in *)fromp;
		fromplen = sizeof (struct sockaddr_in);
		asin.ss_family = AF_INET;  /* used for bind */
	} else if (fromp->ss_family == AF_INET6) {
		sin6 = (struct sockaddr_in6 *)fromp;
		fromplen = sizeof (struct sockaddr_in6);
		asin.ss_family = AF_INET6; /* used for bind */
	} else {
		syslog(LOG_ERR, "unknown address family %d\n",
		    fromp->ss_family);
		exit(1);
	}
	/*
	 * store common info. for audit record
	 */

	if (getnameinfo((const struct sockaddr *) fromp, fromplen, hostname,
	    sizeof (hostname), NULL, 0, 0) != 0) {
		if (fromp->ss_family == AF_INET6) {
			if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
				struct in_addr ipv4_addr;

				IN6_V4MAPPED_TO_INADDR(&sin6->sin6_addr,
				    &ipv4_addr);
				inet_ntop(AF_INET, &ipv4_addr, abuf,
				    sizeof (abuf));
			} else {
				inet_ntop(AF_INET6, &sin6->sin6_addr,
				    abuf, sizeof (abuf));
			}
		} else if (fromp->ss_family == AF_INET) {
				inet_ntop(AF_INET, &sin->sin_addr,
				    abuf, sizeof (abuf));
			}
		(void) strncpy(hostname, abuf, sizeof (hostname));
	}
	(void) dup2(f, 0);
	(void) dup2(f, 1);
	(void) dup2(f, 2);
	(void) alarm(60);
	port = 0;
	for (;;) {
		char c;
		if (read(f, &c, 1) != 1)
			exit(1);
		if (c == 0)
			break;
		port = port * 10 + c - '0';
	}
	(void) alarm(0);
	if (port != 0) {
		s = socket(fromp->ss_family, SOCK_STREAM, 0);
		if (s < 0)
			exit(1);
		if (bind(s, (struct sockaddr *)&asin, fromplen) < 0)
			exit(1);
		(void) alarm(60);
		if (fromp->ss_family == AF_INET) {
			sin->sin_port = htons((ushort_t)port);
		} else if (fromp->ss_family == AF_INET6) {
			sin6->sin6_port = htons((ushort_t)port);
		}
		if (connect(s, (struct sockaddr *)fromp, fromplen) < 0)
			exit(1);
		(void) alarm(0);
	}
	getstr(user, sizeof (user), "username");
	getstr(pass, sizeof (pass), "password");
	getstr(cmdbuf, sizeof (cmdbuf), "command");

	pwd = getpwnam_r(user, &pw_data, pwdbuf, sizeof (pwdbuf));
	if (pwd == NULL) {
		(void) audit_rexecd_fail("Login incorrect", hostname, user,
		    cmdbuf);	    /* BSM */
		error("Login incorrect.\n");
		exit(1);
	}

	if (defopen(_PATH_DEFAULT_LOGIN) == 0) {
		int flags;
		char *p;
		flags = defcntl(DC_GETFLAGS, 0);
		TURNOFF(flags, DC_CASE);
		(void) defcntl(DC_SETFLAGS, flags);
		if ((p = defread("PASSREQ=")) != NULL &&
		    strcasecmp(p, "YES") == 0) {
			pam_flags |= PAM_DISALLOW_NULL_AUTHTOK;
		}
		defopen(NULL);
	}

	if (pam_start("rexec", user, &conv, &pamh) != PAM_SUCCESS) {
		exit(1);
	}
	if (pam_set_item(pamh, PAM_RHOST, hostname) != PAM_SUCCESS) {
		exit(1);
	}

	if ((status = pam_authenticate(pamh, pam_flags)) != PAM_SUCCESS) {
		switch (status) {
		case PAM_USER_UNKNOWN:
			(void) audit_rexecd_fail("Login incorrect", hostname,
			    user, cmdbuf);		/* BSM */
			error("Login incorrect.\n");
			break;
		default:
			(void) audit_rexecd_fail("Password incorrect", hostname,
			    user, cmdbuf);	/* BSM */
			error("Password incorrect.\n");
		}
		pam_end(pamh, status);
		exit(1);
	}
	if ((status = pam_acct_mgmt(pamh, pam_flags)) != PAM_SUCCESS) {
		(void) audit_rexecd_fail("Account or Password Expired",
		    hostname, user, cmdbuf);
		switch (status) {
			case PAM_NEW_AUTHTOK_REQD:
				error("Password Expired.\n");
				break;
			case PAM_PERM_DENIED:
				error("Account Expired.\n");
				break;
			case PAM_AUTHTOK_EXPIRED:
				error("Password Expired.\n");
				break;
			default:
				error("Login incorrect.\n");
				break;
		}
		pam_end(pamh, status);
		exit(1);
	}

	(void) write(2, "\0", 1);

	if (setgid((gid_t)pwd->pw_gid) < 0) {
		(void) audit_rexecd_fail("Can't setgid", hostname,
		    user, cmdbuf);	/* BSM */
		error("setgid");
		pam_end(pamh, PAM_ABORT);
		exit(1);
	}
	(void) initgroups(pwd->pw_name, pwd->pw_gid);

	if ((status = pam_setcred(pamh, PAM_ESTABLISH_CRED)) != PAM_SUCCESS) {
		(void) audit_rexecd_fail("Unable to establish credentials",
		    hostname, user, cmdbuf);	/* BSM */
		error("Unable to establish credentials.\n");
		pam_end(pamh, PAM_SUCCESS);
	}

	(void) audit_rexecd_success(hostname, user, cmdbuf);	/* BSM */

	if (setuid((uid_t)pwd->pw_uid) < 0) {
		(void) audit_rexecd_fail("Can't setuid", hostname,
		    user, cmdbuf);	/* BSM */
		error("setuid");
		pam_end(pamh, PAM_ABORT);
		exit(1);
	}


	if (port) {
		(void) pipe(pv);
		pid = fork();
		if (pid == (pid_t)-1)  {
			error("Try again.\n");
			pam_end(pamh, PAM_ABORT);
			exit(1);
		}
		if (pid) {
			/*
			 * since the daemon is running as the user no need
			 * to prune privileges.
			 */
			(void) close(0); (void) close(1); (void) close(2);
			(void) close(f); (void) close(pv[1]);
			FD_ZERO(&readfrom);
			FD_SET(s, &readfrom);
			FD_SET(pv[0], &readfrom);
			(void) ioctl(pv[0], FIONBIO, (char *)&one);
			/* should set s nbio! */
			do {
				ready = readfrom;
				if (select(MAXFD(s, pv[0])+1, &ready, NULL,
				    NULL, NULL) < 0) {
					perror("select:");
					exit(1);
				}
				if (FD_ISSET(s, &ready)) {
					if (read(s, &sig, 1) <= 0)
						FD_CLR(s, &readfrom);
					else
						(void) killpg(pid, sig);
				}
				if (FD_ISSET(pv[0], &ready)) {
					cc = read(pv[0], buf, sizeof (buf));
					if (cc <= 0) {
						(void) shutdown(s, 1+1);
						FD_CLR(pv[0], &readfrom);
					} else
						(void) write(s, buf, cc);
				}
			} while (FD_ISSET(s, &readfrom) ||
			    FD_ISSET(pv[0], &readfrom));
			exit(0);
		}
		/* setpgrp(0, getpid()); */
		(void) setsid();	/* Should be the same as above. */
		(void) close(s); (void)close(pv[0]);
		(void) dup2(pv[1], 2);
	}

	if (*pwd->pw_shell == '\0')
		pwd->pw_shell = "/bin/sh";
	if (f > 2)
		(void) close(f);
	/* Change directory only after becoming the appropriate user. */
	if (chdir(pwd->pw_dir) < 0) {
		error("No remote directory.\n");
		pam_end(pamh, PAM_ABORT);
		exit(1);
	}
#ifdef	SYSV
	if (pwd->pw_uid)
		envinit[ENVINIT_PATH] = userpath;
	else
		envinit[ENVINIT_PATH] = rootpath;
#endif	/* SYSV */
	(void) strncat(homedir, pwd->pw_dir, sizeof (homedir) - 6);
	(void) strncat(shell, pwd->pw_shell, sizeof (shell) - 7);
	(void) strncat(username, pwd->pw_name, sizeof (username) - 6);

	/*
	 * add PAM environment variables set by modules
	 * -- only allowed 16 (PAM_ENV_ELIM)
	 * -- check to see if the environment variable is legal
	 */
	for (end_env = 0; envinit[end_env] != 0; end_env++)
		;
	if ((pam_env = pam_getenvlist(pamh)) != 0) {
		while (pam_env[idx] != 0) {
			if (idx < PAM_ENV_ELIM &&
			    legalenvvar(pam_env[idx])) {
				envinit[end_env + idx] = pam_env[idx];
			}
			idx++;
		}
	}

	pam_end(pamh, PAM_SUCCESS);

	cp = rindex(pwd->pw_shell, '/');
	if (cp)
		cp++;
	else
		cp = pwd->pw_shell;
	(void) execle(pwd->pw_shell, cp, "-c", cmdbuf, (char *)0, envinit);
	perror(pwd->pw_shell);
	exit(1);
}

static void
getstr(char *buf, int cnt, char *err)
{
	char c;

	do {
		if (read(0, &c, 1) != 1)
			exit(1);
		*buf++ = c;
		if (--cnt == 0) {
			error("%s too long\n", err);
			exit(1);
		}
	} while (c != 0);
}

static void
error(char *fmt, ...)
{
	va_list ap;
	char buf[BUFSIZ];

	buf[0] = 1;
	va_start(ap, fmt);
	(void) vsprintf(buf+1, fmt, ap);
	va_end(ap);
	(void) write(2, buf, strlen(buf));
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
	"USER=",
	0
};

/*
 * legalenvvar - can PAM insert this environmental variable?
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
 * rexec_conv -  This is the conv (conversation) function called from
 *	a PAM authentication module to print error messages
 *	or garner information from the user.
 */

static int
rexec_conv(int num_msg, const struct pam_message **msg,
    struct pam_response **response, void *appdata_ptr)
{
	const struct pam_message *m;
	struct pam_response *r;
	int i;

	if (num_msg <= 0)
		return (PAM_CONV_ERR);

	*response = calloc(num_msg, sizeof (struct pam_response));
	if (*response == NULL)
		return (PAM_BUF_ERR);

	m = *msg;
	r = *response;

	if (m->msg_style == PAM_PROMPT_ECHO_OFF) {
		if (pass[0] != '\0') {
			r->resp = strdup(pass);
			if (r->resp == NULL) {
				/* free responses */
				r = *response;
				for (i = 0; i < num_msg; i++, r++) {
					if (r->resp)
						free(r->resp);
				}
				free(*response);
				*response = NULL;
				return (PAM_BUF_ERR);
			}
		}
	}

	return (PAM_SUCCESS);
}

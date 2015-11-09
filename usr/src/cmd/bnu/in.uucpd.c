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

/*
 * 4.2BSD, 2.9BSD, or ATTSVR4 TCP/IP server for uucico
 * uucico's TCP channel causes this server to be run at the remote end.
 */

#include "uucp.h"
#include <netdb.h>
#ifdef BSD2_9
#include <sys/localopts.h>
#include <sys/file.h>
#endif	/* BSD2_9 */
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#ifdef ATTSVTTY
#include <sys/termio.h>
#else
#include <sys/ioctl.h>
#endif
#include <pwd.h>
#ifdef ATTSVR4
#include <shadow.h>
#endif

#include <security/pam_appl.h>

static int uucp_conv();
struct pam_conv conv = {uucp_conv, NULL };
pam_handle_t    *pamh;

#if !defined(BSD4_2) && !defined(BSD2_9) && !defined(ATTSVR4)
--- You must have either BSD4_2, BSD2_9, or ATTSVR4 defined for this to work
#endif	/* !BSD4_2 && !BSD2_9 */
#if defined(BSD4_2) && defined(BSD2_9)
--- You may not have both BSD4_2 and BSD2_9 defined for this to work
#endif	/* check for stupidity */

struct	passwd nouser = {
	"", "nope", (uid_t)-1, (gid_t)-1, "", "", "", "", "" };
#ifdef ATTSVR4
struct	spwd noupass = { "", "nope" };
#endif
struct	sockaddr_in hisctladdr;
socklen_t hisaddrlen = (socklen_t)sizeof (hisctladdr);
struct	sockaddr_in myctladdr;
int nolog;		/* don't log in utmp or wtmp */

char Username[64];
char Loginname[64];
char *nenv[] = {
	Username,
	Loginname,
	NULL,
};
extern char **environ;

static void doit(struct sockaddr_in *);
static void dologout(void);

int
main(argc, argv)
int argc;
char **argv;
{
#ifndef BSDINETD
	int s, tcp_socket;
	struct servent *sp;
#endif	/* !BSDINETD */
	extern int errno;

	if (argc > 1 && strcmp(argv[1], "-n") == 0)
		nolog = 1;
	environ = nenv;
#ifdef BSDINETD
	close(1); close(2);
	dup(0); dup(0);
	hisaddrlen = (socklen_t)sizeof (hisctladdr);
	if (getpeername(0, (struct sockaddr *)&hisctladdr, &hisaddrlen) < 0) {
		fprintf(stderr, "%s: ", argv[0]);
		perror("getpeername");
		_exit(1);
	}
	if (fork() == 0)
		doit(&hisctladdr);
	dologout();
	exit(1);
#else	/* !BSDINETD */
	sp = getservbyname("uucp", "tcp");
	if (sp == NULL) {
		perror("uucpd: getservbyname");
		exit(1);
	}
	if (fork())
		exit(0);
#ifdef ATTSVR4
	setsid();
#else
	if ((s = open("/dev/tty", 2)) >= 0) {
		ioctl(s, TIOCNOTTY, (char *)0);
		close(s);
	}
#endif

#ifdef ATTSVR4
	memset((void *)&myctladdr, 0, sizeof (myctladdr));
#else
	bzero((char *)&myctladdr, sizeof (myctladdr));
#endif
	myctladdr.sin_family = AF_INET;
	myctladdr.sin_port = sp->s_port;
#if defined(BSD4_2) || defined(ATTSVR4)
	tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (tcp_socket < 0) {
		perror("uucpd: socket");
		exit(1);
	}
	if (bind(tcp_socket, (char *)&myctladdr, sizeof (myctladdr)) < 0) {
		perror("uucpd: bind");
		exit(1);
	}
	listen(tcp_socket, 3);	/* at most 3 simultaneuos uucp connections */
	signal(SIGCHLD, dologout);

	for (;;) {
		s = accept(tcp_socket, &hisctladdr, &hisaddrlen);
		if (s < 0) {
			if (errno == EINTR)
				continue;
			perror("uucpd: accept");
			exit(1);
		}
		if (fork() == 0) {
			close(0); close(1); close(2);
			dup(s); dup(s); dup(s);
			close(tcp_socket); close(s);
			doit(&hisctladdr);
			exit(1);
		}
		close(s);
	}
#endif	/* BSD4_2 */

#ifdef BSD2_9
	for (;;) {
		signal(SIGCHLD, dologout);
		s = socket(SOCK_STREAM, 0,  &myctladdr,
			SO_ACCEPTCONN|SO_KEEPALIVE);
		if (s < 0) {
			perror("uucpd: socket");
			exit(1);
		}
		if (accept(s, &hisctladdr) < 0) {
			if (errno == EINTR) {
				close(s);
				continue;
			}
			perror("uucpd: accept");
			exit(1);
		}
		if (fork() == 0) {
			close(0); close(1); close(2);
			dup(s); dup(s); dup(s);
			close(s);
			doit(&hisctladdr);
			exit(1);
		}
	}
#endif	/* BSD2_9 */
#endif	/* !BSDINETD */

	/* NOTREACHED */
}

static void
doit(sinp)
struct sockaddr_in *sinp;
{
	char user[64], passwd[64];
	struct passwd *pw, *getpwnam();
	int error;

	alarm(60);
	printf("login: "); fflush(stdout);
	if (readline(user, sizeof (user)) < 0) {
		fprintf(stderr, "user read\n");
		return;
	}

	/*
	 * Call pam_start to initiate a PAM authentication operation
	 */

	if ((pam_start("uucp", user, &conv, &pamh)) != PAM_SUCCESS)
		return;
	if ((pam_set_item(pamh, PAM_TTY, ttyname(0))) != PAM_SUCCESS)
		return;

	if (pam_authenticate(pamh, PAM_SILENT) != PAM_SUCCESS) {
		/* force a delay if passwd bad */
		sleep(4);
		fprintf(stderr, "Login incorrect.");
		pam_end(pamh, PAM_ABORT);
		return;
	}

	if ((error = pam_acct_mgmt(pamh, PAM_SILENT)) != PAM_SUCCESS) {
		switch (error) {
		case PAM_NEW_AUTHTOK_REQD:
			fprintf(stderr, "Password Expired.");
			break;
		case PAM_PERM_DENIED:
			fprintf(stderr, "Account Expired.");
			break;
		case PAM_AUTHTOK_EXPIRED:
			fprintf(stderr, "Password Expired.");
			break;
		default:
			fprintf(stderr, "Login incorrect.");
			break;
		}
		pam_end(pamh, PAM_ABORT);
		return;
	}

	if ((pw = getpwnam(user)) == NULL || strcmp(pw->pw_shell, UUCICO)) {
		/* force a delay if user bad */
		sleep(4);
		fprintf(stderr, "Login incorrect.");
		pam_end(pamh, PAM_USER_UNKNOWN);
		return;
	}

	alarm(0);

	sprintf(Username, "USER=%s", user);
	sprintf(Loginname, "LOGNAME=%s", user);
	if (!nolog)
		if (dologin(pw, sinp)) {
			pam_end(pamh, PAM_ABORT);
			_exit(1);
		}

	/* set the real (and effective) GID */
	if (setgid(pw->pw_gid) == -1) {
		fprintf(stderr, "Login incorrect.");
		pam_end(pamh, PAM_PERM_DENIED);
		return;
	}

	/*
	 * Initialize the supplementary group access list.
	 */
	if (initgroups(user, pw->pw_gid) == -1) {
		fprintf(stderr, "Login incorrect.");
		pam_end(pamh, PAM_PERM_DENIED);
		return;
	}

	if (pam_setcred(pamh, PAM_ESTABLISH_CRED) != PAM_SUCCESS) {
		fprintf(stderr, "Login incorrect.");
		pam_end(pamh, PAM_CRED_INSUFFICIENT);
		return;
	}

	/* set the real (and effective) UID */
	if (setuid(pw->pw_uid) == -1) {
		fprintf(stderr, "Login incorrect.");
		pam_end(pamh, PAM_CRED_ERR);
		return;
	}

	chdir(pw->pw_dir);

	pam_end(pamh, PAM_SUCCESS);

#if defined(BSD4_2) || defined(ATTSVR4)
	execl(UUCICO, "uucico", "-u", user, (char *)0);
#endif	/* BSD4_2 */
#ifdef BSD2_9
	sprintf(passwd, "-h%s", inet_ntoa(sinp->sin_addr));
	execl(UUCICO, "uucico", passwd, (char *)0);
#endif	/* BSD2_9 */
	perror("uucico server: execl");
}

int
readline(p, n)
char *p;
int n;
{
	char c;

	while (n-- > 0) {
		if (read(0, &c, 1) <= 0)
			return (-1);
		c &= 0177;
		if (c == '\n' || c == '\r') {
			*p = '\0';
			return (0);
		}
		*p++ = c;
	}
	return (-1);
}

#ifdef ATTSVR4
#include <sac.h>	/* for SC_WILDC */
#include <utmpx.h>
#else	/* !ATTSVR4 */
#include <utmp.h>
#endif	/* !ATTSVR4 */
#if defined(BSD4_2) || defined(ATTSVR4)
#include <fcntl.h>
#endif	/* BSD4_2 */

#ifdef BSD2_9
#define	O_APPEND	0 /* kludge */
#define	wait3(a, b, c)	wait2(a, b)
#endif	/* BSD2_9 */

#define	SCPYN(a, b)	strncpy(a, b, sizeof (a))

#ifdef ATTSVR4
struct	utmpx utmp;
#else	/* !ATTSVR4 */
struct	utmp utmp;
#endif	/* !ATTSVR4 */

static void
dologout(void)
{
#ifdef ATTSVR4
	int status;
#else	/* !ATTSVR4 */
	union wait status;
#endif	/* !ATSVR4 */
	int pid, wtmp;
	/* the following 2 variables are needed for utmp mgmt */
	struct utmpx	ut;

#ifdef BSDINETD
	while ((pid = wait(&status)) > 0) {
#else	/* !BSDINETD */
	while ((pid = wait3(&status, WNOHANG, 0)) > 0) {
#endif	/* !BSDINETD */
		if (nolog)
			continue;
#ifdef ATTSVR4
		/* clear out any residue from utmpx buffer */
		(void) memset((char *)&ut, 0, sizeof (ut));

		SCPYN(utmp.ut_user, "");
		ut.ut_id[0] = 'u';
		ut.ut_id[1] = 'u';
		ut.ut_id[2] = SC_WILDC;
		ut.ut_id[3] = SC_WILDC;
		sprintf(ut.ut_line, "uucp%.4d", pid);
		ut.ut_pid  = getpid();
		ut.ut_type = DEAD_PROCESS;
		ut.ut_exit.e_termination = status & 0xFF;
		ut.ut_exit.e_exit = WEXITSTATUS(status);
		SCPYN(ut.ut_host, "");
		ut.ut_syslen = 1;
		(void) gettimeofday(&ut.ut_tv, NULL);

		/*
		 * XXX: UUCPD does not do any pam session management.
		 *	There is no way for the parent process to close
		 *	the pam session after a child has exited.
		 */

		updwtmpx(WTMPX_FILE, &ut);
#else	/* !ATTSVR4 */
		wtmp = open("/usr/adm/wtmp", O_WRONLY|O_APPEND);
		if (wtmp >= 0) {
			sprintf(utmp.ut_line, "uucp%.4d", pid);
			SCPYN(utmp.ut_name, "");
			SCPYN(utmp.ut_host, "");
			(void) time(&utmp.ut_time);
#ifdef BSD2_9
			(void) lseek(wtmp, 0L, 2);
#endif	/* BSD2_9 */
			(void) write(wtmp, (char *)&utmp, sizeof (utmp));
			(void) close(wtmp);
		}
#endif	/* !ATTSVR4 */
	}
}

/*
 * Record login in wtmp file.
 */
int
dologin(pw, sin)
struct passwd *pw;
struct sockaddr_in *sin;
{
	char line[32];
	char remotehost[32];
	int wtmp;
	struct hostent *hp = gethostbyaddr((const char *)&sin->sin_addr,
		sizeof (struct in_addr), AF_INET);
	struct utmpx	ut;

	if (hp) {
		strncpy(remotehost, hp->h_name, sizeof (remotehost));
		endhostent();
	} else
		strncpy(remotehost, (char *)inet_ntoa(sin->sin_addr),
		    sizeof (remotehost));
#ifdef ATTSVR4
	/* clear wtmpx entry */
	(void) memset((void *)&ut, 0, sizeof (ut));

	SCPYN(ut.ut_user, pw->pw_name);
	ut.ut_id[0] = 'u';
	ut.ut_id[1] = 'u';
	ut.ut_id[2] = SC_WILDC;
	ut.ut_id[3] = SC_WILDC;
	/* hack, but must be unique and no tty line */
	sprintf(line, "uucp%.4d", getpid());
	SCPYN(ut.ut_line, line);
	ut.ut_pid = getpid();
	ut.ut_type = USER_PROCESS;
	ut.ut_exit.e_termination = 0;
	ut.ut_exit.e_exit = 0;
	SCPYN(ut.ut_host, remotehost);
	ut.ut_syslen = strlen(remotehost) + 1;
	(void) gettimeofday(&ut.ut_tv, 0);
	updwtmpx(WTMPX_FILE, &ut);

	/*
	 * XXX:
	 * 	We no longer do session management in uucpd because
	 *	there is no way to do the "pam_close_session()".
	 *
	 *	Processes like "init" can do a pam_close_session()
	 *	because they can use the utmp entry to retrieve
	 *	the proper username, ttyname, etc. --
	 *	uucpd only writes to the wtmp file.
	 *
	 *	ftpd (which also only writes to the wtmp file)
	 *	can do a pam_close_session() because it doesn't fork().
	 *
	 *	if (pam_set_item(pamh, PAM_RHOST, remotehost) != PAM_SUCCESS)
	 *		return (1);
	 *	if (pam_set_item(pamh, PAM_TTY, line) != PAM_SUCCESS)
	 *		return (1);
	 *	if (pam_open_session(pamh, 0) != PAM_SUCCESS) {
	 *		return (1);
	 *	}
	 */

#else	/* !ATTSVR4 */
	wtmp = open("/usr/adm/wtmp", O_WRONLY|O_APPEND);
	if (wtmp >= 0) {
		/* hack, but must be unique and no tty line */
		sprintf(line, "uucp%.4d", getpid());
		SCPYN(utmp.ut_line, line);
		SCPYN(utmp.ut_name, pw->pw_name);
		SCPYN(utmp.ut_host, remotehost);
		time(&utmp.ut_time);
#ifdef BSD2_9
		(void) lseek(wtmp, 0L, 2);
#endif	/* BSD2_9 */
		(void) write(wtmp, (char *)&utmp, sizeof (utmp));
		(void) close(wtmp);
	}
#endif	/* !ATTSVR4 */

	return (0);
}

/*
 * uucp_conv	- This is the conv (conversation) function called from
 *		a PAM authentication module to print error messages
 *		or garner information from the user.
 */

static int
uucp_conv(num_msg, msg, response, appdata_ptr)
	int num_msg;
	struct pam_message **msg;
	struct pam_response **response;
	void *appdata_ptr;
{
	struct pam_message	*m;
	struct pam_response	*r;
	char			*temp;
	static char		passwd[64];
	int			k, i;

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
			/*
			 * we do this instead of using passed in message
			 * to prevent possible breakage of uucp protocol.
			 */
			printf("Password: "); fflush(stdout);
			if (readline(passwd, sizeof (passwd)) < 0) {
				fprintf(stderr, "passwd read\n");
				return (PAM_SUCCESS);
			}
			temp = passwd;
			if (temp != NULL) {
				r->resp = strdup(temp);
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

			m++;
			r++;
			break;

		case PAM_PROMPT_ECHO_ON:
			if (m->msg != NULL) {
				fputs(m->msg, stdout);
				fflush(stdout);
			}
			r->resp = (char *)malloc(PAM_MAX_RESP_SIZE);
			if (r->resp == NULL) {
				/* free the response */
				r = *response;
				for (i = 0; i < num_msg; i++, r++) {
					if (r->resp)
						free(r->resp);
				}
				free(*response);
				*response = NULL;
				return (PAM_BUF_ERR);
			}
			(void) fgets(r->resp, PAM_MAX_RESP_SIZE, stdin);
			m++;
			r++;
			break;

		case PAM_ERROR_MSG:
			if (m->msg != NULL) {
				fputs(m->msg, stderr);
				fputs("\n", stderr);
			}
			m++;
			r++;
			break;
		case PAM_TEXT_INFO:
			if (m->msg != NULL) {
				fputs(m->msg, stdout);
				fputs("\n", stdout);
			}
			m++;
			r++;
			break;

		default:
			break;
		}
	}
	return (PAM_SUCCESS);
}

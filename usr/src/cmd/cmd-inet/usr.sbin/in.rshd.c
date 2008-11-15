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

/*	Copyright (c) 1983-1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#define	_FILE_OFFSET_BITS 64

/*
 * remote shell server:
 *	remuser\0
 *	locuser\0
 *	command\0
 *	data
 */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/telioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/select.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <netdb.h>
#include <syslog.h>
#include <fcntl.h>
#include <ctype.h>
#include <locale.h>

#include <sys/resource.h>
#include <sys/filio.h>
#include <shadow.h>
#include <stdlib.h>

#include <security/pam_appl.h>
#include <deflt.h>

#include <k5-int.h>
#include <krb5_repository.h>
#include <com_err.h>
#include <kcmd.h>

#include <addr_match.h>
#include <store_forw_creds.h>

#ifndef NCARGS
#define	NCARGS	5120
#endif /* !NCARGS */

static void error(char *, ...);
static void doit(int, struct sockaddr_storage *, char **);
static void getstr(int, char *, int, char *);

static int legalenvvar(char *);
static void add_to_envinit(char *);
static int locale_envmatch(char *, char *);

/* Function decls. for functions not in any header file.  (Grrrr.) */
extern int audit_rshd_setup(void);
extern int audit_rshd_success(char *, char *, char *, char *);
extern int audit_rshd_fail(char *, char *, char *, char *, char *);
extern int audit_settid(int);

static int do_encrypt = 0;
static pam_handle_t *pamh;

/*
 * This is the shell/kshell daemon. The very basic protocol for checking
 * authentication and authorization is:
 * 1) Check authentication.
 * 2) Check authorization via the access-control files:
 *    ~/.k5login (using krb5_kuserok) and/or
 * Execute command if configured authoriztion checks pass, else deny
 * permission.
 *
 * The configuration is done either by command-line arguments passed by inetd,
 * or by the name of the daemon. If command-line arguments are present, they
 * take priority. The options are:
 * -k allow kerberos authentication (krb5 only; krb4 support is not provided)
 * -5 same as `-k', mainly for compatability with MIT
 * -e allow encrypted session
 * -c demand authenticator checksum
 * -i ignore authenticator checksum
 * -U Refuse connections that cannot be mapped to a name via `gethostbyname'
 * -s <tos>	Set the IP TOS option
 * -S <keytab>	Set the keytab file to use
 * -M <realm>	Set the Kerberos realm to use
 */

#define	ARGSTR	"ek5ciUD:M:S:L:?:"
#define	RSHD_BUFSIZ	(50 * 1024)

static krb5_context bsd_context;
static krb5_keytab keytab = NULL;
static krb5_ccache ccache = NULL;
static krb5_keyblock *sessionkey = NULL;

static int require_encrypt = 0;
static int resolve_hostname = 0;
static int krb5auth_flag = 0;	/* Flag set, when KERBEROS is enabled */
static enum kcmd_proto kcmd_protocol;

#ifdef DEBUG
static int debug_port = 0;
#endif /* DEBUG */

/*
 * There are two authentication related masks:
 * auth_ok and auth_sent.
 * The auth_ok mask is the or'ing of authentication
 * systems any one of which can be used.
 * The auth_sent mask is the or'ing of one or more authentication/authorization
 * systems that succeeded.  If the and'ing
 * of these two masks is true, then authorization is successful.
 */

#define	AUTH_KRB5	(0x2)
static int auth_ok = 0;
static int auth_sent = 0;
static int checksum_required = 0;
static int checksum_ignored = 0;

/*
 * Leave room for 4 environment variables to be passed.
 * The "-L env_var" option has been added primarily to
 * maintain compatability with MIT.
 */
#define	MAXENV	4
static char *save_env[MAXENV];
static int num_env = 0;

static void usage(void);
static krb5_error_code recvauth(int, int *);

/*ARGSUSED*/
int
main(int argc, char **argv, char **renvp)
{
	struct linger linger;
	int on = 1, fromlen;
	struct sockaddr_storage from;
	int fd = 0;

	extern int opterr, optind;
	extern char *optarg;
	int ch;
	int tos = -1;
	krb5_error_code status;

	openlog("rsh", LOG_PID | LOG_ODELAY, LOG_DAEMON);
	(void) audit_rshd_setup();	/* BSM */
	fromlen = sizeof (from);

	(void) setlocale(LC_ALL, "");

	/*
	 * Analyze parameters.
	 */
	opterr = 0;
	while ((ch = getopt(argc, argv, ARGSTR)) != EOF)
		switch (ch) {
		case '5':
		case 'k':
			auth_ok |= AUTH_KRB5;
			krb5auth_flag++;
			break;

		case 'c':
			checksum_required = 1;
			krb5auth_flag++;
			break;
		case 'i':
			checksum_ignored = 1;
			krb5auth_flag++;
			break;

		case 'e':
			require_encrypt = 1;
			krb5auth_flag++;
			break;
#ifdef DEBUG
		case 'D':
			debug_port = atoi(optarg);
			break;
#endif /* DEBUG */
		case 'U':
			resolve_hostname = 1;
			break;

		case 'M':
			krb5_set_default_realm(bsd_context, optarg);
			krb5auth_flag++;
			break;

		case 'S':
			if ((status = krb5_kt_resolve(bsd_context, optarg,
				&keytab))) {
				com_err("rsh", status,
					gettext("while resolving "
						"srvtab file %s"), optarg);
				exit(2);
			}
			krb5auth_flag++;
			break;

		case 's':
			if (optarg == NULL || ((tos = atoi(optarg)) < 0) ||
				(tos > 255)) {
				syslog(LOG_ERR, "rshd: illegal tos value: "
				    "%s\n", optarg);
			}
			break;

		case 'L':
			if (num_env < MAXENV) {
				save_env[num_env] = strdup(optarg);
				if (!save_env[num_env++]) {
					com_err("rsh", ENOMEM,
						gettext("in saving env"));
					exit(2);
				}
			} else {
				(void) fprintf(stderr, gettext("rshd: Only %d"
						" -L arguments allowed\n"),
						MAXENV);
				exit(2);
			}
			break;

		case '?':
		default:
			usage();
			exit(1);
			break;
		}

	if (optind == 0) {
		usage();
		exit(1);
	}
	argc -= optind;
	argv += optind;

	if (krb5auth_flag > 0) {
		status = krb5_init_context(&bsd_context);
		if (status) {
			syslog(LOG_ERR, "Error initializing krb5: %s",
			    error_message(status));
			exit(1);
		}
	}

	if (!checksum_required && !checksum_ignored)
		checksum_ignored = 1;

	if (checksum_required && checksum_ignored) {
		syslog(LOG_CRIT, gettext("Checksums are required and ignored."
		"These options are mutually exclusive"
		"--check the documentation."));
		error("Configuration error: mutually exclusive "
				"options specified.\n");
		exit(1);
	}

#ifdef DEBUG
	if (debug_port) {
		int s;
		struct sockaddr_in sin;

		if ((s = socket(AF_INET, SOCK_STREAM, PF_UNSPEC)) < 0) {
			fprintf(stderr, gettext("Error in socket: %s\n"),
					strerror(errno));
			exit(2);
		}
		(void) memset((char *)&sin, 0, sizeof (sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(debug_port);
		sin.sin_addr.s_addr = INADDR_ANY;

		(void) setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
			(char *)&on, sizeof (on));

		if ((bind(s, (struct sockaddr *)&sin, sizeof (sin))) < 0) {
			(void) fprintf(stderr, gettext("Error in bind: %s\n"),
					strerror(errno));
			exit(2);
		}
		if ((listen(s, 5)) < 0) {
			(void) fprintf(stderr, gettext("Error in listen: %s\n"),
					strerror(errno));
			exit(2);
		}
		if ((fd = accept(s, (struct sockaddr *)&from,
					&fromlen)) < 0) {
			(void) fprintf(stderr, gettext("Error in accept: %s\n"),
					strerror(errno));
			exit(2);
		}
		(void) close(s);
	}
	else
#endif /* DEBUG */
	{
		if (getpeername(STDIN_FILENO, (struct sockaddr *)&from,
				(socklen_t *)&fromlen) < 0) {
			(void) fprintf(stderr, "rshd: ");
			perror("getpeername");
			_exit(1);
		}
		fd = STDIN_FILENO;
	}

	if (audit_settid(fd) != 0) {
		perror("settid");
		exit(1);
	}

	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&on,
	    sizeof (on)) < 0)
		syslog(LOG_WARNING, "setsockopt (SO_KEEPALIVE): %m");
	linger.l_onoff = 1;
	linger.l_linger = 60;			/* XXX */
	if (setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *)&linger,
	    sizeof (linger)) < 0)
		syslog(LOG_WARNING, "setsockopt (SO_LINGER): %m");

	if ((tos != -1) && (setsockopt(fd, IPPROTO_IP, IP_TOS, (char *)&tos,
				sizeof (tos)) < 0) &&
				(errno != ENOPROTOOPT)) {
		syslog(LOG_ERR, "setsockopt (IP_TOS %d): %m");
	}

	doit(dup(fd), &from, renvp);
	return (0);
}

/*
 * locale environments to be passed to shells.
 */
static char *localeenv[] = {
	"LANG",
	"LC_CTYPE", "LC_NUMERIC", "LC_TIME", "LC_COLLATE",
	"LC_MONETARY", "LC_MESSAGES", "LC_ALL", NULL};

/*
 * The following is for the environment variable list
 * used in the call to execle().  envinit is declared here,
 * but populated after the call to getpwnam().
 */
static char	*homedir;	/* "HOME=" */
static char	*shell;		/* "SHELL=" */
static char	*username;	/* "USER=" */
static char	*tz;		/* "TZ=" */

static char	homestr[] = "HOME=";
static char	shellstr[] = "SHELL=";
static char	userstr[] = "USER=";
static char	tzstr[] = "TZ=";

static char	**envinit;
#define	PAM_ENV_ELIM	16	/* allow 16 PAM environment variables */
#define	USERNAME_LEN	16	/* maximum number of characters in user name */

/*
 *	See PSARC opinion 1992/025
 */
static char	userpath[] = "PATH=/usr/bin:";
static char	rootpath[] = "PATH=/usr/sbin:/usr/bin";

static char cmdbuf[NCARGS+1];
static char hostname [MAXHOSTNAMELEN + 1];
static char locuser[USERNAME_LEN + 1];
static char remuser[USERNAME_LEN + 1];

#define	KRB5_RECVAUTH_V5	5
#define	SIZEOF_INADDR sizeof	(struct in_addr)

#define	MAX_REPOSITORY_LEN	255
static char repository[MAX_REPOSITORY_LEN];

static char *kremuser;
static krb5_principal client = NULL;

static char	remote_addr[64];
static char	local_addr[64];

#define	_PATH_DEFAULT_LOGIN "/etc/default/login"

static void
doit(int f, struct sockaddr_storage *fromp, char **renvp)
{
	char *cp;

	struct passwd *pwd;
	char *path;
	char *tzenv;
	struct spwd *shpwd;
	struct stat statb;
	char **lenvp;

	krb5_error_code status;
	int valid_checksum;
	int cnt;
	int sin_len;
	struct sockaddr_in localaddr;

	int s;
	in_port_t port;
	pid_t pid;
	int pv[2], pw[2], px[2], cc;
	char buf[RSHD_BUFSIZ];
	char sig;
	int one = 1;
	int v = 0;
	int err = 0;
	int idx = 0;
	char **pam_env;
	char abuf[INET6_ADDRSTRLEN];
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	int fromplen;
	int homedir_len, shell_len, username_len, tz_len;
	int no_name;
	boolean_t bad_port;
	int netf = 0;

	(void) signal(SIGINT, SIG_DFL);
	(void) signal(SIGQUIT, SIG_DFL);
	(void) signal(SIGTERM, SIG_DFL);
	(void) signal(SIGXCPU, SIG_DFL);
	(void) signal(SIGXFSZ, SIG_DFL);
	(void) sigset(SIGCHLD, SIG_IGN);
	(void) signal(SIGPIPE, SIG_DFL);
	(void) signal(SIGHUP, SIG_DFL);

#ifdef DEBUG
	{ int t = open("/dev/tty", 2);
	    if (t >= 0) {
		(void) setsid();
		(void) close(t);
	    }
	}
#endif
	if (fromp->ss_family == AF_INET) {
		sin = (struct sockaddr_in *)fromp;
		port = ntohs((ushort_t)sin->sin_port);
		fromplen = sizeof (struct sockaddr_in);
	} else if (fromp->ss_family == AF_INET6) {
		sin6 = (struct sockaddr_in6 *)fromp;
		port = ntohs((ushort_t)sin6->sin6_port);
		fromplen = sizeof (struct sockaddr_in6);
	} else {
		syslog(LOG_ERR, "wrong address family\n");
		exit(1);
	}

	if (fromp->ss_family == AF_INET6) {
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			struct in_addr ipv4_addr;

			IN6_V4MAPPED_TO_INADDR(&sin6->sin6_addr, &ipv4_addr);
			(void) inet_ntop(AF_INET, &ipv4_addr, abuf,
			    sizeof (abuf));
		} else {
			(void) inet_ntop(AF_INET6, &sin6->sin6_addr, abuf,
			    sizeof (abuf));
		}
	} else if (fromp->ss_family == AF_INET) {
		(void) inet_ntop(AF_INET, &sin->sin_addr, abuf, sizeof (abuf));
	}

	sin_len = sizeof (struct sockaddr_in);
	if (getsockname(f, (struct sockaddr *)&localaddr, &sin_len) < 0) {
		perror("getsockname");
		exit(1);
	}

	netf = f;

	bad_port = (port >= IPPORT_RESERVED ||
		port < (uint_t)(IPPORT_RESERVED/2));

	/* Get the name of the client side host to use later */
	no_name = (getnameinfo((const struct sockaddr *) fromp, fromplen,
		hostname, sizeof (hostname), NULL, 0, 0) != 0);

	if (bad_port || no_name != 0) {
		/*
		 * If there is no host name available then use the
		 * IP address to identify the host in the PAM call
		 * below.  Do the same if a bad port was used, to
		 * prevent untrustworthy authentication.
		 */
		(void) strlcpy(hostname, abuf, sizeof (hostname));
	}

	if (no_name != 0) {
		/*
		 * If the '-U' option was given on the cmd line,
		 * we must be able to lookup the hostname
		 */
		if (resolve_hostname) {
			syslog(LOG_ERR, "rshd: Couldn't resolve your "
			    "address into a host name.\r\n Please "
			    "contact your net administrator");
			exit(1);
		}
	} else {
		/*
		 * Even if getnameinfo() succeeded, we still have to check
		 * for spoofing.
		 */
		check_address("rshd", fromp, sin, sin6, abuf, hostname,
		    sizeof (hostname));
	}

	if (!krb5auth_flag && bad_port) {
		if (no_name)
			syslog(LOG_NOTICE, "connection from %s - "
			    "bad port\n", abuf);
		else
			syslog(LOG_NOTICE, "connection from %s (%s) - "
			    "bad port\n", hostname, abuf);
		exit(1);
	}

	(void) alarm(60);
	port = 0;
	for (;;) {
		char c;
		if ((cc = read(f, &c, 1)) != 1) {
			if (cc < 0)
				syslog(LOG_NOTICE, "read: %m");
			(void) shutdown(f, 1+1);
			exit(1);
		}
		if (c == 0)
			break;
		port = port * 10 + c - '0';
	}
	(void) alarm(0);
	if (port != 0) {
		int lport = 0;
		struct sockaddr_storage ctl_addr;
		int addrlen;

		(void) memset(&ctl_addr, 0, sizeof (ctl_addr));
		addrlen = sizeof (ctl_addr);
		if (getsockname(f, (struct sockaddr *)&ctl_addr,
			&addrlen) < 0) {
			syslog(LOG_ERR, "getsockname: %m");
			exit(1);
		}
get_port:
		/*
		 * 0 means that rresvport_addr() will bind to a port in
		 * the anonymous priviledged port range.
		 */
		if (krb5auth_flag) {
			/*
			 * Kerberos does not support IPv6 yet.
			 */
			lport = IPPORT_RESERVED - 1;
		}
		s = rresvport_addr(&lport, &ctl_addr);

		if (s < 0) {
			syslog(LOG_ERR, "can't get stderr port: %m");
			exit(1);
		}
		if (!krb5auth_flag && (port >= IPPORT_RESERVED)) {
			syslog(LOG_ERR, "2nd port not reserved\n");
			exit(1);
		}
		if (fromp->ss_family == AF_INET) {
			sin->sin_port = htons((ushort_t)port);
		} else if (fromp->ss_family == AF_INET6) {
			sin6->sin6_port = htons((ushort_t)port);
		}
		if (connect(s, (struct sockaddr *)fromp, fromplen) < 0) {
			if (errno == EADDRINUSE) {
				(void) close(s);
				goto get_port;
			}
			syslog(LOG_INFO, "connect second port: %m");
			exit(1);
		}
	}
	(void) dup2(f, 0);
	(void) dup2(f, 1);
	(void) dup2(f, 2);

#ifdef DEBUG
	syslog(LOG_NOTICE, "rshd: Client hostname = %s", hostname);
	if (debug_port)
		syslog(LOG_NOTICE, "rshd: Debug port is %d", debug_port);
	if (krb5auth_flag > 0)
		syslog(LOG_NOTICE, "rshd: Kerberos mode is ON");
	else
		syslog(LOG_NOTICE, "rshd: Kerberos mode is OFF");
#endif /* DEBUG */

	if (krb5auth_flag > 0) {
		if ((status = recvauth(f, &valid_checksum))) {
			syslog(LOG_ERR, gettext("Kerberos Authentication "
					"failed \n"));
			error("Authentication failed: %s\n",
					error_message(status));
			(void) audit_rshd_fail("Kerberos Authentication "
				"failed", hostname, remuser, locuser, cmdbuf);
			exit(1);
		}

		if (checksum_required && !valid_checksum &&
			kcmd_protocol == KCMD_OLD_PROTOCOL) {
			syslog(LOG_WARNING, "Client did not supply required"
					" checksum--connection rejected.");
			error("Client did not supply required"
				"checksum--connection rejected.\n");
			(void) audit_rshd_fail("Client did not supply required"
				" checksum--connection rejected.", hostname,
				remuser, locuser, cmdbuf);	/* BSM */
			goto signout;
		}

		/*
		 * Authentication has succeeded, we now need
		 * to check authorization.
		 *
		 * krb5_kuserok returns 1 if OK.
		 */
		if (client && krb5_kuserok(bsd_context, client, locuser)) {
			auth_sent |= AUTH_KRB5;
		} else {
			syslog(LOG_ERR, "Principal %s (%s@%s) for local user "
				"%s failed krb5_kuserok.\n",
				kremuser, remuser, hostname, locuser);
		}
	} else {
		getstr(netf, remuser, sizeof (remuser), "remuser");
		getstr(netf, locuser, sizeof (locuser), "locuser");
		getstr(netf, cmdbuf, sizeof (cmdbuf), "command");
	}

#ifdef DEBUG
	syslog(LOG_NOTICE, "rshd: locuser = %s, remuser = %s, cmdbuf = %s",
			locuser, remuser, cmdbuf);
#endif /* DEBUG */

	/*
	 * Note that there is no rsh conv functions at present.
	 */
	if (krb5auth_flag > 0) {
		if ((err = pam_start("krsh", locuser, NULL, &pamh))
				!= PAM_SUCCESS) {
			syslog(LOG_ERR, "pam_start() failed: %s\n",
				pam_strerror(0, err));
			exit(1);
		}
	}
	else
	{
		if ((err = pam_start("rsh", locuser, NULL, &pamh))
				!= PAM_SUCCESS) {
			syslog(LOG_ERR, "pam_start() failed: %s\n",
				pam_strerror(0, err));
			exit(1);
		}
	}
	if ((err = pam_set_item(pamh, PAM_RHOST, hostname)) != PAM_SUCCESS) {
		syslog(LOG_ERR, "pam_set_item() failed: %s\n",
			pam_strerror(pamh, err));
		exit(1);
	}
	if ((err = pam_set_item(pamh, PAM_RUSER, remuser)) != PAM_SUCCESS) {
		syslog(LOG_ERR, "pam_set_item() failed: %s\n",
			pam_strerror(pamh, err));
		exit(1);
	}

	pwd = getpwnam(locuser);
	shpwd = getspnam(locuser);
	if ((pwd == NULL) || (shpwd == NULL)) {
		if (krb5auth_flag > 0)
			syslog(LOG_ERR, "Principal %s (%s@%s) for local user "
				"%s has no account.\n", kremuser, remuser,
							hostname, locuser);
		error("permission denied.\n");
		(void) audit_rshd_fail("Login incorrect", hostname,
			remuser, locuser, cmdbuf);	/* BSM */
		exit(1);
	}

	if (krb5auth_flag > 0) {
		(void) snprintf(repository, sizeof (repository),
					KRB5_REPOSITORY_NAME);
		/*
		 * We currently only support special handling of the
		 * KRB5 PAM repository
		 */
		if (strlen(locuser) != 0) {
			krb5_repository_data_t krb5_data;
			pam_repository_t pam_rep_data;

			krb5_data.principal = locuser;
			krb5_data.flags = SUNW_PAM_KRB5_ALREADY_AUTHENTICATED;

			pam_rep_data.type = repository;
			pam_rep_data.scope = (void *)&krb5_data;
			pam_rep_data.scope_len = sizeof (krb5_data);

			(void) pam_set_item(pamh, PAM_REPOSITORY,
					(void *)&pam_rep_data);
		}
	}

	if (shpwd->sp_pwdp != 0) {
		if (*shpwd->sp_pwdp != '\0') {
			if ((v = pam_authenticate(pamh, 0)) != PAM_SUCCESS) {
				error("permission denied\n");
				(void) audit_rshd_fail("Permission denied",
				    hostname, remuser, locuser, cmdbuf);
				(void) pam_end(pamh, v);
				exit(1);
			}
		} else {
			int flags;
			char *p;
			/*
			 * maintain 2.1 and 4.* and BSD semantics with
			 * anonymous rshd unless PASSREQ is set to YES in
			 * /etc/default/login: then we deny logins with empty
			 * passwords.
			 */
			if (defopen(_PATH_DEFAULT_LOGIN) == 0) {
				flags = defcntl(DC_GETFLAGS, 0);
				TURNOFF(flags, DC_CASE);
				(void) defcntl(DC_SETFLAGS, flags);

				if ((p = defread("PASSREQ=")) != NULL &&
				    strcasecmp(p, "YES") == 0) {
					error("permission denied\n");
					(void) audit_rshd_fail(
					    "Permission denied", hostname,
					    remuser, locuser, cmdbuf);
					(void) pam_end(pamh, PAM_ABORT);
					(void) defopen(NULL);
					syslog(LOG_AUTH|LOG_NOTICE,
					    "empty password not allowed for "
					    "%s from %s.", locuser, hostname);
					exit(1);
				}
				(void) defopen(NULL);
			}
			/*
			 * /etc/default/login not found or PASSREQ not set
			 * to YES. Allow logins without passwords.
			 */
		}
	}

	if (krb5auth_flag > 0) {
		if (require_encrypt && (!do_encrypt)) {
			error("You must use encryption.\n");
			(void) audit_rshd_fail("You must use encryption.",
				hostname, remuser, locuser, cmdbuf); /* BSM */
			goto signout;
		}

		if (!(auth_ok & auth_sent)) {
			if (auth_sent) {
				error("Another authentication mechanism "
				    "must be used to access this host.\n");
				(void) audit_rshd_fail("Another authentication"
					" mechanism must be used to access"
					" this host.\n", hostname, remuser,
					locuser, cmdbuf); /* BSM */
				goto signout;
			} else {
				error("Permission denied.\n");
				(void) audit_rshd_fail("Permission denied.",
					hostname, remuser, locuser, cmdbuf);
					/* BSM */
				goto signout;
			}
		}


		if (pwd->pw_uid && !access("/etc/nologin", F_OK)) {
			error("Logins currently disabled.\n");
			(void) audit_rshd_fail("Logins currently disabled.",
				hostname, remuser, locuser, cmdbuf);
			goto signout;
		}

		/* Log access to account */
		if (pwd && (pwd->pw_uid == 0)) {
			syslog(LOG_NOTICE, "Executing %s for user %s (%s@%s)"
			    " as ROOT", cmdbuf,
			    kremuser, remuser, hostname);
		}
	}

	if ((v = pam_acct_mgmt(pamh, 0)) != PAM_SUCCESS) {
		switch (v) {
		case PAM_NEW_AUTHTOK_REQD:
			error("password expired\n");
			(void) audit_rshd_fail("Password expired", hostname,
				remuser, locuser, cmdbuf); /* BSM */
			break;
		case PAM_PERM_DENIED:
			error("account expired\n");
			(void) audit_rshd_fail("Account expired", hostname,
				remuser, locuser, cmdbuf); /* BSM */
			break;
		case PAM_AUTHTOK_EXPIRED:
			error("password expired\n");
			(void) audit_rshd_fail("Password expired", hostname,
				remuser, locuser, cmdbuf); /* BSM */
			break;
		default:
			error("login incorrect\n");
			(void) audit_rshd_fail("Permission denied", hostname,
				remuser, locuser, cmdbuf); /* BSM */
			break;
		}
		(void) pam_end(pamh, PAM_ABORT);
		exit(1);
	}

	if (chdir(pwd->pw_dir) < 0) {
		(void) chdir("/");
#ifdef notdef
		error("No remote directory.\n");

		exit(1);
#endif
	}

	/*
	 * XXX There is no session management currently being done
	 */

	(void) write(STDERR_FILENO, "\0", 1);
	if (port || do_encrypt) {
		if ((pipe(pv) < 0)) {
			error("Can't make pipe.\n");
			(void) pam_end(pamh, PAM_ABORT);
			exit(1);
		}
		if (do_encrypt) {
			if (pipe(pw) < 0) {
				error("Can't make pipe 2.\n");
				(void) pam_end(pamh, PAM_ABORT);
				exit(1);
			}
			if (pipe(px) < 0) {
				error("Can't make pipe 3.\n");
				(void) pam_end(pamh, PAM_ABORT);
				exit(1);
			}
		}
		pid = fork();
		if (pid == (pid_t)-1)  {
			error("Fork (to start shell) failed on server.  "
				"Please try again later.\n");
			(void) pam_end(pamh, PAM_ABORT);
			exit(1);
		}
		if (pid) {
			fd_set ready;
			fd_set readfrom;

			(void) close(STDIN_FILENO);
			(void) close(STDOUT_FILENO);
			(void) close(STDERR_FILENO);
			(void) close(pv[1]);
			if (do_encrypt) {
				(void) close(pw[1]);
				(void) close(px[0]);
			} else {
				(void) close(f);
			}

			(void) FD_ZERO(&readfrom);

			FD_SET(pv[0], &readfrom);
			if (do_encrypt) {
				FD_SET(pw[0], &readfrom);
				FD_SET(f, &readfrom);
			}
			if (port)
				FD_SET(s, &readfrom);

			/* read f (net), write to px[1] (child stdin) */
			/* read pw[0] (child stdout), write to f (net) */
			/* read s (alt. channel), signal child */
			/* read pv[0] (child stderr), write to s */
			if (ioctl(pv[0], FIONBIO, (char *)&one) == -1)
				syslog(LOG_INFO, "ioctl FIONBIO: %m");
			if (do_encrypt &&
				ioctl(pw[0], FIONBIO, (char *)&one) == -1)
				syslog(LOG_INFO, "ioctl FIONBIO: %m");
			do {
				ready = readfrom;
				if (select(FD_SETSIZE, &ready, NULL,
					NULL, NULL) < 0) {
					if (errno == EINTR) {
						continue;
					} else {
						break;
					}
				}
				/*
				 * Read from child stderr, write to net
				 */
				if (port && FD_ISSET(pv[0], &ready)) {
					errno = 0;
					cc = read(pv[0], buf, sizeof (buf));
					if (cc <= 0) {
						(void) shutdown(s, 2);
						FD_CLR(pv[0], &readfrom);
					} else {
						(void) deswrite(s, buf, cc, 1);
					}
				}
				/*
				 * Read from alternate channel, signal child
				 */
				if (port && FD_ISSET(s, &ready)) {
					if ((int)desread(s, &sig, 1, 1) <= 0)
						FD_CLR(s, &readfrom);
					else
						(void) killpg(pid, sig);
				}
				/*
				 * Read from child stdout, write to net
				 */
				if (do_encrypt && FD_ISSET(pw[0], &ready)) {
					errno = 0;
					cc = read(pw[0], buf, sizeof (buf));
					if (cc <= 0) {
						(void) shutdown(f, 2);
						FD_CLR(pw[0], &readfrom);
					} else {
						(void) deswrite(f, buf, cc, 0);
					}
				}
				/*
				 * Read from the net, write to child stdin
				 */
				if (do_encrypt && FD_ISSET(f, &ready)) {
					errno = 0;
					cc = desread(f, buf, sizeof (buf), 0);
					if (cc <= 0) {
						(void) close(px[1]);
						FD_CLR(f, &readfrom);
					} else {
						int wcc;
						wcc = write(px[1], buf, cc);
						if (wcc == -1) {
							/*
							 * pipe closed,
							 * don't read any
							 * more
							 *
							 * might check for
							 * EPIPE
							 */
						    (void) close(px[1]);
						    FD_CLR(f, &readfrom);
						} else if (wcc != cc) {
						    /* CSTYLED */
						    syslog(LOG_INFO, gettext("only wrote %d/%d to child"),
						    wcc, cc);
						}
					}
				}
			} while ((port && FD_ISSET(s, &readfrom)) ||
				(port && FD_ISSET(pv[0], &readfrom)) ||
				(do_encrypt && FD_ISSET(f, &readfrom)) ||
				(do_encrypt && FD_ISSET(pw[0], &readfrom)));
#ifdef DEBUG
			syslog(LOG_INFO, "Shell process completed.");
#endif /* DEBUG */
			if (ccache)
				(void) pam_close_session(pamh, 0);
			(void) pam_end(pamh, PAM_SUCCESS);

			exit(0);
		} /* End of Parent block */

		(void) setsid();	/* Should be the same as above. */
		(void) close(pv[0]);
		(void) dup2(pv[1], 2);
		(void) close(pv[1]);
		if (port)
			(void) close(s);
		if (do_encrypt) {
			(void) close(f);
			(void) close(pw[0]);
			(void) close(px[1]);

			(void) dup2(px[0], 0);
			(void) dup2(pw[1], 1);

			(void) close(px[0]);
			(void) close(pw[1]);
		}
	}

	if (*pwd->pw_shell == '\0')
		pwd->pw_shell = "/bin/sh";
	if (!do_encrypt)
		(void) close(f);
	/*
	 * write audit record before making uid switch
	 */
	(void) audit_rshd_success(hostname, remuser, locuser, cmdbuf); /* BSM */

	/* set the real (and effective) GID */
	if (setgid(pwd->pw_gid) == -1) {
		error("Invalid gid.\n");
		(void) pam_end(pamh, PAM_ABORT);
		exit(1);
	}

	/*
	 * Initialize the supplementary group access list.
	 */
	if (strlen(locuser) == 0) {
		error("No local user.\n");
		(void) pam_end(pamh, PAM_ABORT);
		exit(1);
	}
	if (initgroups(locuser, pwd->pw_gid) == -1) {
		error("Initgroup failed.\n");
		(void) pam_end(pamh, PAM_ABORT);
		exit(1);
	}

	if ((v = pam_setcred(pamh, PAM_ESTABLISH_CRED)) != PAM_SUCCESS) {
		error("Insufficient credentials.\n");
		(void) pam_end(pamh, v);
		exit(1);
	}

	/* set the real (and effective) UID */
	if (setuid(pwd->pw_uid) == -1) {
		error("Invalid uid.\n");
		(void) pam_end(pamh, PAM_ABORT);
		exit(1);
	}

	/* Change directory only after becoming the appropriate user. */
	if (chdir(pwd->pw_dir) < 0) {
		(void) chdir("/");
		if (krb5auth_flag > 0) {
			syslog(LOG_ERR, "Principal %s  (%s@%s) for local user"
				" %s has no home directory.",
				kremuser, remuser, hostname, locuser);
			error("No remote directory.\n");
			goto signout;
		}
#ifdef notdef
		error("No remote directory.\n");
		exit(1);
#endif
	}

	path = (pwd->pw_uid == 0) ? rootpath : userpath;

	/*
	 * Space for the following environment variables are dynamically
	 * allocated because their lengths are not known before calling
	 * getpwnam().
	 */
	homedir_len = strlen(pwd->pw_dir) + strlen(homestr) + 1;
	shell_len = strlen(pwd->pw_shell) + strlen(shellstr) + 1;
	username_len = strlen(pwd->pw_name) + strlen(userstr) + 1;
	homedir = (char *)malloc(homedir_len);
	shell = (char *)malloc(shell_len);
	username = (char *)malloc(username_len);
	if (homedir == NULL || shell == NULL || username == NULL) {
		perror("malloc");
		exit(1);
	}
	(void) snprintf(homedir, homedir_len, "%s%s", homestr, pwd->pw_dir);
	(void) snprintf(shell, shell_len, "%s%s", shellstr, pwd->pw_shell);
	(void) snprintf(username, username_len, "%s%s", userstr, pwd->pw_name);

	/* Pass timezone to executed command. */
	if (tzenv = getenv("TZ")) {
		tz_len = strlen(tzenv) + strlen(tzstr) + 1;
		tz = malloc(tz_len);
		if (tz != NULL)
			(void) snprintf(tz, tz_len, "%s%s", tzstr, tzenv);
	}

	add_to_envinit(homedir);
	add_to_envinit(shell);
	add_to_envinit(path);
	add_to_envinit(username);
	add_to_envinit(tz);

	if (krb5auth_flag > 0) {
		int length;
		char *buffer;

		/*
		 * If we have KRB5CCNAME set, then copy into the child's
		 * environment.  This can't really have a fixed position
		 * because `tz' may or may not be set.
		 */
		if (getenv("KRB5CCNAME")) {
			length = (int)strlen(getenv("KRB5CCNAME")) +
					(int)strlen("KRB5CCNAME=") + 1;
			buffer = (char *)malloc(length);

			if (buffer) {
				(void) snprintf(buffer, length, "KRB5CCNAME=%s",
						getenv("KRB5CCNAME"));
				add_to_envinit(buffer);
			}
		} {
			/* These two are covered by ADDRPAD */
			length = strlen(inet_ntoa(localaddr.sin_addr)) + 1 +
					strlen("KRB5LOCALADDR=");
			(void) snprintf(local_addr, length, "KRB5LOCALADDR=%s",
				inet_ntoa(localaddr.sin_addr));
			add_to_envinit(local_addr);

			length = strlen(inet_ntoa(sin->sin_addr)) + 1 +
					strlen("KRB5REMOTEADDR=");
			(void) snprintf(remote_addr, length,
				"KRB5REMOTEADDR=%s", inet_ntoa(sin->sin_addr));
			add_to_envinit(remote_addr);
		}

		/*
		 * If we do anything else, make sure there is
		 * space in the array.
		 */
		for (cnt = 0; cnt < num_env; cnt++) {
			char *buf;

			if (getenv(save_env[cnt])) {
				length = (int)strlen(getenv(save_env[cnt])) +
					(int)strlen(save_env[cnt]) + 2;

				buf = (char *)malloc(length);
				if (buf) {
					(void) snprintf(buf, length, "%s=%s",
						save_env[cnt],
						getenv(save_env[cnt]));
					add_to_envinit(buf);
				}
			}
		}

	}

	/*
	 * add PAM environment variables set by modules
	 * -- only allowed 16 (PAM_ENV_ELIM)
	 * -- check to see if the environment variable is legal
	 */
	if ((pam_env = pam_getenvlist(pamh)) != 0) {
		while (pam_env[idx] != 0) {
			if (idx < PAM_ENV_ELIM &&
			    legalenvvar(pam_env[idx])) {
				add_to_envinit(pam_env[idx]);
			}
			idx++;
		}
	}

	(void) pam_end(pamh, PAM_SUCCESS);

	/*
	 * Pick up locale environment variables, if any.
	 */
	lenvp = renvp;
	while (*lenvp != NULL) {
		int	index;

		for (index = 0; localeenv[index] != NULL; index++)
			/*
			 * locale_envmatch() returns 1 if
			 * *lenvp is localenev[index] and valid.
			 */
			if (locale_envmatch(localeenv[index], *lenvp)) {
				add_to_envinit(*lenvp);
				break;
			}

		lenvp++;
	}

	cp = strrchr(pwd->pw_shell, '/');
	if (cp != NULL)
		cp++;
	else
		cp = pwd->pw_shell;
	/*
	 * rdist has been moved to /usr/bin, so /usr/ucb/rdist might not
	 * be present on a system.  So if it doesn't exist we fall back
	 * and try for it in /usr/bin.  We take care to match the space
	 * after the name because the only purpose of this is to protect
	 * the internal call from old rdist's, not humans who type
	 * "rsh foo /usr/ucb/rdist".
	 */
#define	RDIST_PROG_NAME	"/usr/ucb/rdist -Server"
	if (strncmp(cmdbuf, RDIST_PROG_NAME, strlen(RDIST_PROG_NAME)) == 0) {
		if (stat("/usr/ucb/rdist", &statb) != 0) {
			(void) strncpy(cmdbuf + 5, "bin", 3);
		}
	}

#ifdef DEBUG
	syslog(LOG_NOTICE, "rshd: cmdbuf = %s", cmdbuf);
	if (do_encrypt)
		syslog(LOG_NOTICE, "rshd: cmd to be exec'ed = %s",
			((char *)cmdbuf + 3));
#endif /* DEBUG */

	if (do_encrypt && (strncmp(cmdbuf, "-x ", 3) == 0)) {
		(void) execle(pwd->pw_shell, cp, "-c", (char *)cmdbuf + 3,
				NULL, envinit);
	} else {
		(void) execle(pwd->pw_shell, cp, "-c", cmdbuf, NULL,
				envinit);
	}

	perror(pwd->pw_shell);
	exit(1);

signout:
	if (ccache)
		(void) pam_close_session(pamh, 0);
	ccache = NULL;
	(void) pam_end(pamh, PAM_ABORT);
	exit(1);
}

static void
getstr(fd, buf, cnt, err)
	int fd;
	char *buf;
	int cnt;
	char *err;
{
	char c;

	do {
		if (read(fd, &c, 1) != 1)
			exit(1);
		if (cnt-- == 0) {
			error("%s too long\n", err);
			exit(1);
		}
		*buf++ = c;
	} while (c != 0);
}

/*PRINTFLIKE1*/
static void
error(char *fmt, ...)
{
	va_list ap;
	char buf[RSHD_BUFSIZ];

	buf[0] = 1;
	va_start(ap, fmt);
	(void) vsnprintf(&buf[1], sizeof (buf) - 1, fmt, ap);
	va_end(ap);
	(void) write(STDERR_FILENO, buf, strlen(buf));
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
	"TZ=",
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
 * Add a string to the environment of the new process.
 */

static void
add_to_envinit(char *string)
{
	/*
	 * Reserve space for 2 * 8 = 16 environment entries initially which
	 * should be enough to avoid reallocation of "envinit" in most cases.
	 */
	static int	size = 8;
	static int	index = 0;

	if (string == NULL)
		return;

	if ((envinit == NULL) || (index == size)) {
		size *= 2;
		envinit = realloc(envinit, (size + 1) * sizeof (char *));
		if (envinit == NULL) {
			perror("malloc");
			exit(1);
		}
	}

	envinit[index++] = string;
	envinit[index] = NULL;
}

/*
 * Check if lenv and penv matches or not.
 */
static int
locale_envmatch(char *lenv, char *penv)
{
	while ((*lenv == *penv) && (*lenv != '\0') && (*penv != '=')) {
		lenv++;
		penv++;
	}

	/*
	 * '/' is eliminated for security reason.
	 */
	return ((*lenv == '\0' && *penv == '=' && *(penv + 1) != '/'));
}

#ifndef	KRB_SENDAUTH_VLEN
#define	KRB_SENDAUTH_VLEN	8	/* length for version strings */
#endif

/* MUST be KRB_SENDAUTH_VLEN chars */
#define	KRB_SENDAUTH_VERS	"AUTHV0.1"
#define	SIZEOF_INADDR sizeof (struct in_addr)

static krb5_error_code
recvauth(int netf, int *valid_checksum)
{
	krb5_auth_context auth_context = NULL;
	krb5_error_code status;
	struct sockaddr_in laddr;
	int len;
	krb5_data inbuf;
	krb5_authenticator *authenticator;
	krb5_ticket *ticket;
	krb5_rcache rcache;
	krb5_data version;
	krb5_encrypt_block eblock;	/* eblock for encrypt/decrypt */
	krb5_data desinbuf;
	krb5_data desoutbuf;
	char des_inbuf[2 * RSHD_BUFSIZ];
			/* needs to be > largest read size */
	char des_outbuf[2 * RSHD_BUFSIZ + 4];
			/* needs to be > largest write size */

	*valid_checksum = 0;
	len = sizeof (laddr);

	if (getsockname(netf, (struct sockaddr *)&laddr, &len)) {
		exit(1);
	}

	if (status = krb5_auth_con_init(bsd_context, &auth_context))
		return (status);

	if (status = krb5_auth_con_genaddrs(bsd_context, auth_context, netf,
		KRB5_AUTH_CONTEXT_GENERATE_REMOTE_FULL_ADDR))
		return (status);

	status = krb5_auth_con_getrcache(bsd_context, auth_context, &rcache);
	if (status)
		return (status);

	if (!rcache) {
		krb5_principal server;

		status = krb5_sname_to_principal(bsd_context, 0, 0,
			KRB5_NT_SRV_HST, &server);
		if (status)
			return (status);

		status = krb5_get_server_rcache(bsd_context,
			krb5_princ_component(bsd_context, server, 0),
			&rcache);
		krb5_free_principal(bsd_context, server);
		if (status)
			return (status);

		status = krb5_auth_con_setrcache(bsd_context, auth_context,
							rcache);
		if (status)
			return (status);
	}

	status = krb5_recvauth_version(bsd_context, &auth_context, &netf,
		NULL,		/* Specify daemon principal */
		0,		/* no flags */
		keytab,		/* normally NULL to use v5srvtab */
		&ticket,	/* return ticket */
		&version);	/* application version string */


	if (status) {
		getstr(netf, locuser, sizeof (locuser), "locuser");
		getstr(netf, cmdbuf, sizeof (cmdbuf), "command");
		getstr(netf, remuser, sizeof (locuser), "remuser");
		return (status);
	}
	getstr(netf, locuser, sizeof (locuser), "locuser");
	getstr(netf, cmdbuf, sizeof (cmdbuf), "command");

	/* Must be V5  */

	kcmd_protocol = KCMD_UNKNOWN_PROTOCOL;
	if (version.length != 9 || version.data == NULL) {
		syslog(LOG_ERR, "bad application version length");
		error(gettext("bad application version length\n"));
		exit(1);
	}
	if (strncmp(version.data, "KCMDV0.1", 9) == 0) {
		kcmd_protocol = KCMD_OLD_PROTOCOL;
	} else if (strncmp(version.data, "KCMDV0.2", 9) == 0) {
		kcmd_protocol = KCMD_NEW_PROTOCOL;
	} else {
		syslog(LOG_ERR, "Unrecognized KCMD protocol (%s)",
			(char *)version.data);
		error(gettext("Unrecognized KCMD protocol (%s)"),
			(char *)version.data);
		exit(1);
	}
	getstr(netf, remuser, sizeof (locuser), "remuser");

	if ((status = krb5_unparse_name(bsd_context, ticket->enc_part2->client,
			&kremuser)))
		return (status);

	if ((status = krb5_copy_principal(bsd_context,
				ticket->enc_part2->client, &client)))
		return (status);


	if (checksum_required && (kcmd_protocol == KCMD_OLD_PROTOCOL)) {
		if ((status = krb5_auth_con_getauthenticator(bsd_context,
			auth_context, &authenticator)))
			return (status);

		if (authenticator->checksum && checksum_required) {
			struct sockaddr_in adr;
			int adr_length = sizeof (adr);
			int chksumsize = strlen(cmdbuf) + strlen(locuser) + 32;
			krb5_data input;
			krb5_keyblock key;

			char *chksumbuf = (char *)malloc(chksumsize);

			if (chksumbuf == 0)
				goto error_cleanup;
			if (getsockname(netf, (struct sockaddr *)&adr,
					&adr_length) != 0)
				goto error_cleanup;

			(void) snprintf(chksumbuf, chksumsize, "%u:",
					ntohs(adr.sin_port));
			if (strlcat(chksumbuf, cmdbuf,
					chksumsize) >= chksumsize) {
				syslog(LOG_ERR, "cmd buffer too long.");
				free(chksumbuf);
				return (-1);
			}
			if (strlcat(chksumbuf, locuser,
					chksumsize) >= chksumsize) {
				syslog(LOG_ERR, "locuser too long.");
				free(chksumbuf);
				return (-1);
			}

			input.data = chksumbuf;
			input.length = strlen(chksumbuf);
			key.magic = ticket->enc_part2->session->magic;
			key.enctype = ticket->enc_part2->session->enctype;
			key.contents = ticket->enc_part2->session->contents;
			key.length = ticket->enc_part2->session->length;

			status = krb5_c_verify_checksum(bsd_context,
			    &key, 0, &input, authenticator->checksum,
			    (unsigned int *)valid_checksum);

			if (status == 0 && *valid_checksum == 0)
			    status = KRB5KRB_AP_ERR_BAD_INTEGRITY;
error_cleanup:
			if (chksumbuf)
				krb5_xfree(chksumbuf);
			if (status) {
				krb5_free_authenticator(bsd_context,
						authenticator);
				return (status);
			}
		}
		krb5_free_authenticator(bsd_context, authenticator);
	}


	if ((strncmp(cmdbuf, "-x ", 3) == 0)) {
		if (krb5_privacy_allowed()) {
			do_encrypt = 1;
		} else {
			syslog(LOG_ERR, "rshd: Encryption not supported");
			error("rshd: Encryption not supported. \n");
			exit(2);
		}

		status = krb5_auth_con_getremotesubkey(bsd_context,
						    auth_context,
						    &sessionkey);
		if (status) {
			syslog(LOG_ERR, "Error getting KRB5 session subkey");
			error(gettext("Error getting KRB5 session subkey"));
			exit(1);
		}
		/*
		 * The "new" protocol requires that a subkey be sent.
		 */
		if (sessionkey == NULL && kcmd_protocol == KCMD_NEW_PROTOCOL) {
			syslog(LOG_ERR, "No KRB5 session subkey sent");
			error(gettext("No KRB5 session subkey sent"));
			exit(1);
		}
		/*
		 * The "old" protocol does not permit an authenticator subkey.
		 * The key is taken from the ticket instead (see below).
		 */
		if (sessionkey != NULL && kcmd_protocol == KCMD_OLD_PROTOCOL) {
			syslog(LOG_ERR, "KRB5 session subkey not permitted "
				"with old KCMD protocol");
			error(gettext("KRB5 session subkey not permitted "
				"with old KCMD protocol"));
			exit(1);
		}
		/*
		 * If no key at this point, use the session key from
		 * the ticket.
		 */
		if (sessionkey == NULL) {
			/*
			 * Save the session key so we can configure the crypto
			 * module later.
			 */
			status = krb5_copy_keyblock(bsd_context,
						ticket->enc_part2->session,
						&sessionkey);
			if (status) {
				syslog(LOG_ERR, "krb5_copy_keyblock failed");
				error(gettext("krb5_copy_keyblock failed"));
				exit(1);
			}
		}
		/*
		 * If session key still cannot be found, we must
		 * exit because encryption is required here
		 * when encr_flag (-x) is set.
		 */
		if (sessionkey == NULL) {
			syslog(LOG_ERR, "Could not find an encryption key");
			error(gettext("Could not find an encryption key"));
			exit(1);
		}

		/*
		 * Initialize parameters/buffers for desread & deswrite here.
		 */
		desinbuf.data = des_inbuf;
		desoutbuf.data = des_outbuf;
		desinbuf.length = sizeof (des_inbuf);
		desoutbuf.length = sizeof (des_outbuf);

		eblock.crypto_entry = sessionkey->enctype;
		eblock.key = (krb5_keyblock *)sessionkey;

		init_encrypt(do_encrypt, bsd_context, kcmd_protocol,
				&desinbuf, &desoutbuf, SERVER, &eblock);
	}

	ticket->enc_part2->session = 0;

	if ((status = krb5_read_message(bsd_context, (krb5_pointer) & netf,
				&inbuf))) {
		error(gettext("Error reading message: %s\n"),
				error_message(status));
		exit(1);
	}

	if (inbuf.length) {
		krb5_creds **creds = NULL;

		/* Forwarding being done, read creds */
		if ((status = krb5_rd_cred(bsd_context,
					    auth_context, &inbuf, &creds,
					    NULL))) {
			error("Can't get forwarded credentials: %s\n",
				error_message(status));
			exit(1);
		}

		/* Store the forwarded creds in the ccache */
		if ((status = store_forw_creds(bsd_context,
					    creds, ticket, locuser,
					    &ccache))) {
			error("Can't store forwarded credentials: %s\n",
				error_message(status));
			exit(1);
		}
		krb5_free_creds(bsd_context, *creds);
	}

	krb5_free_ticket(bsd_context, ticket);
	return (0);
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext("%s: rshd [-k5eciU] "
			"[-P path] [-M realm] [-s tos] "
#ifdef DEBUG
			"[-D port] "
#endif /* DEBUG */
			"[-S keytab]"), gettext("usage"));

	syslog(LOG_ERR, "%s: rshd [-k5eciU] [-P path] [-M realm] [-s tos] "
#ifdef DEBUG
			"[-D port] "
#endif /* DEBUG */
			"[-S keytab]", gettext("usage"));
}

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

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * rlogin - remote login
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stropts.h>
#include <sys/ttold.h>
#include <sys/sockio.h>
#include <sys/tty.h>
#include <sys/ptyvar.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <priv_utils.h>

#include <stdio.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <setjmp.h>
#include <netdb.h>
#include <fcntl.h>
#include <locale.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <k5-int.h>
#include <profile/prof_int.h>
#include <com_err.h>
#include <kcmd.h>
#include <krb5.h>

/* signal disposition - signal handler or SIG_IGN, SIG_ERR, etc. */
typedef void (*sigdisp_t)(int);

extern errcode_t	profile_get_options_boolean(profile_t, char **,
    profile_options_boolean *);
extern errcode_t	profile_get_options_string(profile_t, char **,
    profile_option_strings *);

#define	RLOGIN_BUFSIZ	(1024 * 50)
static char des_inbuf[2 * RLOGIN_BUFSIZ];
					/* needs to be > largest read size */
static char des_outbuf[2 * RLOGIN_BUFSIZ];
					/* needs to be > largest write size */
static krb5_data desinbuf, desoutbuf;
static krb5_encrypt_block eblock;	/* eblock for encrypt/decrypt */
static krb5_keyblock *session_key;
static krb5_creds *cred;
static krb5_context bsd_context = NULL;
static krb5_auth_context auth_context;

static char *krb_realm;

static	int krb5auth_flag;	/* Flag set, when KERBEROS is enabled */
static profile_options_boolean autologin_option[] = {
	{ "autologin", &krb5auth_flag, 0 },
	{ NULL, NULL, 0 }
};

static	int fflag, Fflag;	/* Flag set, when option -f / -F used */
static	int encrypt_flag;	/* Flag set, when the "-x" option is used */

/* Flag set, if -PN / -PO is specified */
static boolean_t rcmdoption_done;

/* Flags set, if corres. cmd line options are turned on */
static boolean_t encrypt_done, fwd_done, fwdable_done;

static profile_options_boolean option[] = {
	{ "encrypt", &encrypt_flag, 0 },
	{ "forward", &fflag, 0 },
	{ "forwardable", &Fflag, 0 },
	{ NULL, NULL, 0 }
};

static char *rcmdproto;
static profile_option_strings rcmdversion[] = {
	{ "rcmd_protocol", &rcmdproto, 0 },
	{ NULL, NULL, 0 }
};

static char rlogin[] = "rlogin";

static char *realmdef[] = { "realms", NULL, rlogin, NULL };
static char *appdef[] = { "appdefaults", rlogin, NULL };

#ifndef TIOCPKT_WINDOW
#define	TIOCPKT_WINDOW 0x80
#endif /* TIOCPKT_WINDOW */

#ifndef sigmask
#define	sigmask(m)	(1 << ((m)-1))
#endif

#define	set2mask(setp)	((setp)->__sigbits[0])
#define	mask2set(mask, setp) \
	((mask) == -1 ? sigfillset(setp) : (((setp)->__sigbits[0]) = (mask)))

#ifdef DEBUG
#define	DEBUGOPTSTRING	"D:"
#else
#define	DEBUGOPTSTRING	""
#endif	/* DEBUG */

static	boolean_t ttcompat;
static	struct termios savetty;

static	char *host;
static	int port_number;
static	int rem = -1;
static	char cmdchar = '~';
static	boolean_t nocmdchar;
static	boolean_t eight;
static	boolean_t litout;
static	boolean_t null_local_username;
/*
 * Note that this list of speeds is shorter than the list of speeds
 * supported by termios.  This is because we can't be sure other rlogind's
 * in the world will correctly cope with values other than what 4.2/4.3BSD
 * supported.
 */
static	char *speeds[] =
	{ "0", "50", "75", "110", "134", "150", "200", "300",
	    "600", "1200", "1800", "2400", "4800", "9600", "19200",
	    "38400" };
static	char term[256] = "network";
static	void lostpeer(void);
static	boolean_t dosigwinch;
static	struct winsize winsize;
static	void sigwinch(int);
static	void oob(void);
static	void doit(int);
static	sigdisp_t sigdisp(int);

#define	CRLF "\r\n"

static	pid_t child;
static	void catchild(int);
/* LINTED */
static	void copytochild(int);
static	void writeroob(int);
static	void stop(char), echo(char);

static	int defflags, tabflag;
static	int deflflags;
static	char deferase, defkill;
static	struct tchars deftc;
static	struct ltchars defltc;
static	struct tchars notc = { (char)-1, (char)-1, (char)-1,
				(char)-1, (char)-1, (char)-1 };
static	struct ltchars noltc =	{ (char)-1, (char)-1, (char)-1,
				(char)-1, (char)-1, (char)-1 };

static	void done(int);
static	void mode(int);
static	int reader(int);
static	void writer(void);
static	void prf(const char *, ...);
static	void sendwindow(void);
static	int compat_ioctl(int, int, void *);

static void
sigsetmask(int mask)
{
	sigset_t oset;
	sigset_t nset;

	(void) sigprocmask(0, NULL, &nset);
	mask2set(mask, &nset);
	(void) sigprocmask(SIG_SETMASK, &nset, &oset);
}

static int
sigblock(int mask)
{
	sigset_t oset;
	sigset_t nset;

	(void) sigprocmask(0, NULL, &nset);
	mask2set(mask, &nset);
	(void) sigprocmask(SIG_BLOCK, &nset, &oset);
	return (set2mask(&oset));
}

static void
pop(int status) {
	if (ttcompat) {
		/*
		 * Pop ttcompat module
		 */
		(void) ioctl(STDIN_FILENO, I_POP, 0);
	}
	(void) tcsetattr(STDIN_FILENO, TCSANOW, &savetty);
	exit(status);
}

static void
usage(void) {
	(void) fprintf(stderr, "%s\n%s\n",
	    gettext("usage: rlogin [-option] [-option...] "
		"[-k realm] [-l username] host"),
	    gettext("       where option is e, 8, E, L, A, a, K, x, "
		"PN / PO, f or F"));
	pop(EXIT_FAILURE);
}

/* PRINTFLIKE(0) */
static void
die(const char *format, ...)
{
	va_list	ap;

	va_start(ap, format);
	(void) vfprintf(stderr, format, ap);
	va_end(ap);
	usage();
}

static void
usage_forward(void)
{
	die(gettext("rlogin: Only one of -f and -F allowed.\n"));
}

int
main(int argc, char **argv)
{
	int c;
	char *cp, *cmd, *name = NULL;
	struct passwd *pwd;
	uid_t uid;
	int options = 0, oldmask;
	int on = 1;
	speed_t speed = 0;
	int getattr_ret;
	char *tmp;
	int sock;
	krb5_flags authopts;
	krb5_error_code status;
	enum kcmd_proto kcmd_proto = KCMD_NEW_PROTOCOL;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (__init_suid_priv(0, PRIV_NET_PRIVADDR, NULL) == -1) {
		(void) fprintf(stderr,
		    gettext("Insufficient privileges, "
			"rlogin must be set-uid root\n"));
		exit(1);
	}

	{
		int it;

		if ((getattr_ret = tcgetattr(STDIN_FILENO, &savetty)) < 0)
			perror("tcgetattr");
		it = ioctl(STDIN_FILENO, I_FIND, "ttcompat");
		if (it < 0) {
			perror("ioctl I_FIND ttcompat");
			return (EXIT_FAILURE);
		}
		if (it == 0) {
			if (ioctl(STDIN_FILENO, I_PUSH, "ttcompat") < 0) {
				perror("ioctl I_PUSH ttcompat");
				exit(EXIT_FAILURE);
			}
			ttcompat = B_TRUE;
		}
	}

	/*
	 * Determine command name used to invoke to rlogin(1). Users can
	 * create links named by a host pointing to the binary and type
	 * "hostname" to log into that host afterwards.
	 */
	cmd = strrchr(argv[0], '/');
	cmd = (cmd != NULL) ? (cmd + 1) : argv[0];

	if (strcmp(cmd, rlogin) == 0) {
		if (argc < 2)
			usage();
		if (*argv[1] != '-') {
			host = argv[1];
			argc--;
			argv[1] = argv[0];
			argv++;
		}
	} else {
		host = cmd;
	}

	while ((c = getopt(argc, argv,
	    DEBUGOPTSTRING "8AEFLP:aKde:fk:l:x")) != -1) {
		switch (c) {
		case '8':
			eight = B_TRUE;
			break;
		case 'A':
			krb5auth_flag++;
			break;
#ifdef DEBUG
		case 'D':
			portnumber = htons(atoi(optarg));
			krb5auth_flag++;
			break;
#endif /* DEBUG */
		case 'E':
			nocmdchar = B_TRUE;
			break;
		case 'F':
			if (fflag)
				usage_forward();
			Fflag = 1;
			krb5auth_flag++;
			fwdable_done = B_TRUE;
			break;
		case 'f':
			if (Fflag)
				usage_forward();
			fflag = 1;
			krb5auth_flag++;
			fwd_done = B_TRUE;
			break;
		case 'L':
			litout = B_TRUE;
			break;
		case 'P':
			if (strcmp(optarg, "N") == 0)
				kcmd_proto = KCMD_NEW_PROTOCOL;
			else if (strcmp(optarg, "O") == 0)
				kcmd_proto = KCMD_OLD_PROTOCOL;
			else
				die(gettext("rlogin: Only -PN or -PO "
				    "allowed.\n"));
			if (rcmdoption_done)
				die(gettext("rlogin: Only one of -PN and -PO "
				    "allowed.\n"));
			rcmdoption_done = B_TRUE;
			krb5auth_flag++;
			break;
		case 'a':
		case 'K':
		/*
		 * Force the remote host to prompt for a password by sending
		 * a NULL username. These options are mutually exclusive with
		 * the -A, -x, -f, -F, -k <realm> options.
		 */
			null_local_username = B_TRUE;
			break;
		case 'd':
			options |= SO_DEBUG;
			break;
		case 'e': {
			int c;

			cp = optarg;

			if ((c = *cp) != '\\') {
				cmdchar = c;
			} else {
				c = cp[1];
				if (c == '\0' || c == '\\') {
					cmdchar = '\\';
				} else if (c >= '0' && c <= '7') {
					long lc;

					lc = strtol(&cp[1], NULL, 8);
					if (lc < 0 || lc > 255)
						die(gettext("rlogin: octal "
						    "escape character %s too "
						    "large.\n"), cp);
					cmdchar = (char)lc;
				} else {
					die(gettext("rlogin: unrecognized "
					    "escape character option %s.\n"),
					    cp);
				}
			}
			break;
		}
		case 'k':
			krb_realm = optarg;
			krb5auth_flag++;
			break;
		case 'l':
			name = optarg;
			break;
		case 'x':
			encrypt_flag = 1;
			krb5auth_flag++;
			encrypt_done = B_TRUE;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (host == NULL) {
		if (argc == 0)
			usage();
		argc--;
		host = *argv++;
	}

	if (argc > 0)
		usage();

	pwd = getpwuid(uid = getuid());
	if (pwd == NULL) {
		(void) fprintf(stderr, gettext("getpwuid(): can not find "
			"password entry for user id %d."), uid);
		return (EXIT_FAILURE);
	}
	if (name == NULL)
		name = pwd->pw_name;

	/*
	 * If the `-a or -K' options are issued on the cmd line, we reset
	 * all flags associated with other KRB5 specific options, since
	 * these options are mutually exclusive with the rest.
	 */
	if (null_local_username) {
		krb5auth_flag = 0;
		fflag = Fflag = encrypt_flag = 0;
		(void) fprintf(stderr,
				gettext("Note: The -a (or -K) option nullifies "
					"all other Kerberos-specific\noptions "
					"you may have used.\n"));
	} else if (!krb5auth_flag) {
		/* is autologin set in krb5.conf? */
		status = krb5_init_context(&bsd_context);
		/* don't sweat failure here */
		if (!status) {
			/*
			 * note that the call to profile_get_options_boolean
			 * with autologin_option can affect value of
			 * krb5auth_flag
			 */
			profile_get_options_boolean(bsd_context->profile,
						appdef,
						autologin_option);
		}
	}

	if (krb5auth_flag) {
		if (!bsd_context) {
			status = krb5_init_context(&bsd_context);
			if (status) {
				com_err(rlogin, status,
				    gettext("while initializing krb5"));
				return (EXIT_FAILURE);
			}
		}
		/*
		 * Set up buffers for desread and deswrite.
		 */
		desinbuf.data = des_inbuf;
		desoutbuf.data = des_outbuf;
		desinbuf.length = sizeof (des_inbuf);
		desoutbuf.length = sizeof (des_outbuf);

		/*
		 * Get our local realm to look up local realm options.
		 */
		status = krb5_get_default_realm(bsd_context, &realmdef[1]);
		if (status) {
			com_err(rlogin, status,
				gettext("while getting default realm"));
			return (EXIT_FAILURE);
		}
		/*
		 * Check the realms section in krb5.conf for encryption,
		 * forward & forwardable info
		 */
		profile_get_options_boolean(bsd_context->profile, realmdef,
						option);
		/*
		 * Check the appdefaults section
		 */
		profile_get_options_boolean(bsd_context->profile, appdef,
						option);
		profile_get_options_string(bsd_context->profile, appdef,
						rcmdversion);

		/*
		 * Set the *_flag variables, if the corresponding *_done are
		 * set to 1, because we dont want the config file values
		 * overriding the command line options.
		 */
		if (encrypt_done)
			encrypt_flag = 1;
		if (fwd_done) {
			fflag = 1;
			Fflag = 0;
		} else if (fwdable_done) {
			Fflag = 1;
			fflag = 0;
		}
		if (!rcmdoption_done && (rcmdproto != NULL)) {
			if (strncmp(rcmdproto, "rcmdv2", 6) == 0) {
				kcmd_proto = KCMD_NEW_PROTOCOL;
			} else if (strncmp(rcmdproto, "rcmdv1", 6) == 0) {
				kcmd_proto = KCMD_OLD_PROTOCOL;
			} else {
				(void) fprintf(stderr, gettext("Unrecognized "
					"KCMD protocol (%s)"), rcmdproto);
				return (EXIT_FAILURE);
			}
		}

		if (encrypt_flag && (!krb5_privacy_allowed())) {
			(void) fprintf(stderr, gettext("rlogin: "
					"Encryption not supported.\n"));
			return (EXIT_FAILURE);
		}
	}

	if (port_number == 0) {
		if (krb5auth_flag) {
			struct servent *sp;

			/*
			 * If the krb5auth_flag is set (via -A, -f, -F, -k) &
			 * if there is an entry in /etc/services for Kerberos
			 * login, attempt to login with Kerberos. If we fail
			 * at any step,  use the standard rlogin
			 */
			sp = getservbyname(encrypt_flag ?
			    "eklogin" : "klogin", "tcp");
			if (sp == NULL) {
				port_number = encrypt_flag ?
				    htons(2105) : htons(543);
			} else {
				port_number = sp->s_port;
			}
		} else {
			port_number = htons(IPPORT_LOGINSERVER);
		}
	}

	cp = getenv("TERM");
	if (cp) {
		(void) strncpy(term, cp, sizeof (term));
		term[sizeof (term) - 1] = '\0';
	}
	if (getattr_ret == 0) {
		speed = cfgetospeed(&savetty);
		/*
		 * "Be conservative in what we send" -- Only send baud rates
		 * which at least all 4.x BSD derivatives are known to handle
		 * correctly.
		 * NOTE:  This code assumes new termios speed values will
		 * be "higher" speeds.
		 */
		if (speed > B38400)
			speed = B38400;
	}

	/*
	 * Only put the terminal speed info in if we have room
	 * so we don't overflow the buffer, and only if we have
	 * a speed we recognize.
	 */
	if (speed > 0 && speed < sizeof (speeds)/sizeof (char *) &&
	    strlen(term) + strlen("/") + strlen(speeds[speed]) + 1 <
	    sizeof (term)) {
		(void) strcat(term, "/");
		(void) strcat(term, speeds[speed]);
	}
	(void) sigset(SIGPIPE, (sigdisp_t)lostpeer);
	/* will use SIGUSR1 for window size hack, so hold it off */
	oldmask = sigblock(sigmask(SIGURG) | sigmask(SIGUSR1));

	/*
	 * Determine if v4 literal address and if so store it to one
	 * side. This is to correct the undesired behaviour of rcmd_af
	 * which converts a passed in v4 literal address to a v4 mapped
	 * v6 literal address. If it was a v4 literal we then re-assign
	 * it to host.
	 */
	tmp = NULL;
	if (inet_addr(host) != (in_addr_t)-1)
		tmp = host;

	if (krb5auth_flag) {
		authopts = AP_OPTS_MUTUAL_REQUIRED;

		/* Piggy-back forwarding flags on top of authopts; */
		/* they will be reset in kcmd */
		if (fflag || Fflag)
			authopts |= OPTS_FORWARD_CREDS;
		if (Fflag)
			authopts |= OPTS_FORWARDABLE_CREDS;

		status = kcmd(&sock, &host, port_number,
			null_local_username ? "" : pwd->pw_name,
			name, term, NULL,
			"host", krb_realm, bsd_context, &auth_context,
			&cred,
			NULL,		/* No need for sequence number */
			NULL,		/* No need for server seq # */
			authopts,
			0,		/* Not any port # */
			&kcmd_proto);

		if (status != 0) {
			/*
			 * If new protocol requested, we dont fallback to
			 * less secure ones.
			 */
			if (kcmd_proto == KCMD_NEW_PROTOCOL) {
				(void) fprintf(stderr, gettext("rlogin: kcmdv2 "
					"to host %s failed - %s\n"
					"Fallback to normal rlogin denied."),
					host, error_message(status));
				return (EXIT_FAILURE);
			}
			if (status != -1) {
				(void) fprintf(stderr, gettext("rlogin: kcmd "
						"to host %s failed - %s,\n"
						"trying normal rlogin...\n\n"),
						host, error_message(status));
			} else {
				(void) fprintf(stderr,
					gettext("trying normal rlogin...\n"));
			}
			/*
			 * kcmd() failed, so we have to
			 * fallback to normal rlogin
			 */
			port_number = htons(IPPORT_LOGINSERVER);
			krb5auth_flag = 0;
			fflag = Fflag = encrypt_flag = 0;
			null_local_username = B_FALSE;
		} else {
			(void) fprintf(stderr,
			    gettext("connected with Kerberos V5\n"));

			/*
			 * Setup eblock for desread and deswrite.
			 */
			session_key = &cred->keyblock;

			if (kcmd_proto == KCMD_NEW_PROTOCOL) {
				status = krb5_auth_con_getlocalsubkey(
				    bsd_context,
				    auth_context,
				    &session_key);
				if (status) {
					com_err(rlogin, status,
					    "determining subkey for session");
					return (EXIT_FAILURE);
				}
				if (session_key == NULL) {
					com_err(rlogin, 0,
					    "no subkey negotiated for "
					    "connection");
					return (EXIT_FAILURE);
				}
			}

			eblock.crypto_entry = session_key->enctype;
			eblock.key = (krb5_keyblock *)session_key;

			init_encrypt(encrypt_flag, bsd_context, kcmd_proto,
			    &desinbuf, &desoutbuf, CLIENT, &eblock);

			rem = sock;
			if (rem < 0)
				pop(EXIT_FAILURE);
		}
	}

	/*
	 * Don't merge this with the "if" statement above because
	 * "krb5auth_flag" might be set to false inside it.
	 */
	if (!krb5auth_flag) {
		rem = rcmd_af(&host, port_number,
			null_local_username ? "" : pwd->pw_name,
			name, term, NULL, AF_INET6);
		if (rem < 0)
			pop(EXIT_FAILURE);
	}

	/* Never need our privilege again */
	__priv_relinquish();

	if (tmp != NULL)
		host = tmp;

	if (options & SO_DEBUG &&
	    setsockopt(rem, SOL_SOCKET, SO_DEBUG, (char *)&on,
			    sizeof (on)) < 0)
		perror("rlogin: setsockopt (SO_DEBUG)");

	{
		int bufsize = 8192;

		(void) setsockopt(rem, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize,
			sizeof (int));
	}

	doit(oldmask);
	return (0);
}

static void
doit(int oldmask)
{
	struct sgttyb sb;
	int atmark;

	if (ioctl(STDIN_FILENO, TIOCGETP, (char *)&sb) == -1)
		perror("ioctl TIOCGETP");
	defflags = sb.sg_flags;
	tabflag = defflags & O_TBDELAY;
	defflags &= ECHO | O_CRMOD;
	deferase = sb.sg_erase;
	defkill = sb.sg_kill;
	if (ioctl(STDIN_FILENO, TIOCLGET, (char *)&deflflags) == -1)
		perror("ioctl TIOCLGET");
	if (ioctl(STDIN_FILENO, TIOCGETC, (char *)&deftc) == -1)
		perror("ioctl TIOCGETC");
	notc.t_startc = deftc.t_startc;
	notc.t_stopc = deftc.t_stopc;
	if (ioctl(STDIN_FILENO, TIOCGLTC, (char *)&defltc) == -1)
		perror("ioctl TIOCGLTC");
	(void) sigset(SIGINT, SIG_IGN);
	if (sigdisp(SIGHUP) != SIG_IGN)
		(void) sigset(SIGHUP, exit);
	if (sigdisp(SIGQUIT) != SIG_IGN)
		(void) sigset(SIGQUIT, exit);
	child = fork();
	if (child == (pid_t)-1) {
		perror("rlogin: fork");
		done(EXIT_FAILURE);
	}
	if (child == 0) {
		mode(1);
		if (reader(oldmask) == 0) {
			prf(gettext("Connection to %.*s closed."),
			    MAXHOSTNAMELEN, host);
			exit(EXIT_SUCCESS);
		}
		(void) sleep(1);
		prf(gettext("\aConnection to %.*s closed."),
		    MAXHOSTNAMELEN, host);
		exit(EXIT_FAILURE);
	}

	/*
	 * We may still own the socket, and may have a pending SIGURG (or might
	 * receive one soon) that we really want to send to the reader.  Set a
	 * trap that simply copies such signals to the child.
	 */
#ifdef F_SETOWN_BUG_FIXED
	(void) sigset(SIGURG, copytochild);
#else
	(void) sigset(SIGURG, SIG_IGN);
#endif /* F_SETOWN_BUG_FIXED */
	(void) sigset(SIGUSR1, writeroob);
	/*
	 * Of course, if the urgent byte already arrived, allowing SIGURG
	 * won't get us notification.  So, we check to see if we've got
	 * an urgent byte.  If so, force a call to writeroob() to pretend
	 * we got SIGURG.
	 */
	if (ioctl(rem, SIOCATMARK, &atmark) >= 0) {
		if (atmark)
			writeroob(0);
	}
	sigsetmask(oldmask);
	(void) sigset(SIGCHLD, catchild);
	writer();
	prf(gettext("Closed connection to %.*s."), MAXHOSTNAMELEN, host);
	done(EXIT_SUCCESS);
}

/*
 * Get signal disposition (or signal handler) for a given signal
 */
static sigdisp_t
sigdisp(int sig)
{
	struct sigaction act;

	act.sa_handler = NULL;
	act.sa_flags = 0;
	(void) sigemptyset(&act.sa_mask);
	(void) sigaction(sig, NULL, &act);
	return (act.sa_handler);
}

static void
done(int status)
{
	pid_t w;

	mode(0);
	if (child > 0) {
		/* make sure catchild does not snap it up */
		(void) sigset(SIGCHLD, SIG_DFL);
		if (kill(child, SIGKILL) >= 0)
			while ((w = wait(0)) > (pid_t)0 && w != child)
				/* void */;
	}
	pop(status);
}

/*
 * Copy SIGURGs to the child process.
 */

/* ARGSUSED */
static void
copytochild(int signum)
{

	(void) kill(child, SIGURG);
}

/*
 * This is called when the reader process gets the out-of-band (urgent)
 * request to turn on the window-changing protocol.
 */

/* ARGSUSED */
static void
writeroob(int signum)
{
	int mask;

	if (!dosigwinch) {
		/*
		 * Start tracking window size.  It doesn't matter which
		 * order the next two are in, because we'll be unconditionally
		 * sending a size notification in a moment.
		 */
		(void) sigset(SIGWINCH, sigwinch);
		dosigwinch = B_TRUE;

		/*
		 * It would be bad if a SIGWINCH came in between the ioctl
		 * and sending the data.  It could result in the SIGWINCH
		 * handler sending a good message, and then us sending an
		 * outdated or inconsistent message.
		 *
		 * Instead, if the change is made before the
		 * ioctl, the sigwinch handler will send a size message
		 * and we'll send another, identical, one.  If the change
		 * is made after the ioctl, we'll send a message with the
		 * old value, and then the sigwinch handler will send
		 * a revised, correct one.
		 */
		mask = sigblock(sigmask(SIGWINCH));
		if (ioctl(STDIN_FILENO, TIOCGWINSZ, &winsize) == 0)
			sendwindow();
		sigsetmask(mask);
	}
}

/* ARGSUSED */
static void
catchild(int signum)
{
	int options;
	siginfo_t	info;
	int error;

	for (;;) {
		options = WNOHANG | WEXITED;
		error = waitid(P_ALL, 0, &info, options);
		if (error != 0)
			return;
		if (info.si_pid == 0)
			return;
		if (info.si_code == CLD_TRAPPED)
			continue;
		if (info.si_code == CLD_STOPPED)
			continue;
		done(info.si_status);
	}
}

/*
 * writer: write to remote: 0 -> line.
 * ~.	terminate
 * ~^Z	suspend rlogin process.
 * ~^Y  suspend rlogin process, but leave reader alone.
 */
static void
writer(void)
{
	char c;
	int n;
	boolean_t bol = B_TRUE;		/* beginning of line */
	boolean_t local = B_FALSE;

	for (;;) {
		n = read(STDIN_FILENO, &c, 1);
		if (n <= 0) {
			if (n == 0)
				break;
			if (errno == EINTR)
				continue;
			else {
				prf(gettext("Read error from terminal: %s"),
				    strerror(errno));
				break;
			}
		}
		/*
		 * If we're at the beginning of the line
		 * and recognize a command character, then
		 * we echo locally.  Otherwise, characters
		 * are echo'd remotely.  If the command
		 * character is doubled, this acts as a
		 * force and local echo is suppressed.
		 */
		if (bol && !nocmdchar) {
			bol = B_FALSE;
			if (c == cmdchar) {
				local = B_TRUE;
				continue;
			}
		} else if (local) {
			local = B_FALSE;
			if (c == '.' || c == deftc.t_eofc) {
				echo(c);
				break;
			}
			if (c == defltc.t_suspc || c == defltc.t_dsuspc) {
				bol = B_TRUE;
				echo(c);
				stop(c);
				continue;
			}
			if (c != cmdchar) {
				if (deswrite(rem, &cmdchar, 1, 0) < 0) {
					prf(gettext(
					    "Write error to network: %s"),
					    strerror(errno));
					break;
				}
			}
		}
		if ((n = deswrite(rem, &c, 1, 0)) <= 0) {
			if (n == 0)
				prf(gettext("line gone"));
			else
				prf(gettext("Write error to network: %s"),
				    strerror(errno));
			break;
		}
		bol = c == defkill || c == deftc.t_eofc ||
		    c == deftc.t_intrc || c == defltc.t_suspc ||
		    c == '\r' || c == '\n';
	}
}

static void
echo(char c)
{
	char buf[8];
	char *p = buf;

	c &= 0177;
	*p++ = cmdchar;
	if (c < ' ') {
		*p++ = '^';
		*p++ = c + '@';
	} else if (c == 0177) {
		*p++ = '^';
		*p++ = '?';
	} else
		*p++ = c;
	*p++ = '\r';
	*p++ = '\n';
	if (write(STDOUT_FILENO, buf, p - buf) < 0)
		prf(gettext("Write error to terminal: %s"), strerror(errno));
}

static void
stop(char cmdc)
{
	mode(0);
	(void) sigset(SIGCHLD, SIG_IGN);
	(void) kill(cmdc == defltc.t_suspc ? 0 : getpid(), SIGTSTP);
	(void) sigset(SIGCHLD, catchild);
	mode(1);
	sigwinch(0);			/* check for size changes */
}

/* ARGSUSED */
static void
sigwinch(int signum)
{
	struct winsize ws;

	if (dosigwinch && ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0 &&
	    memcmp(&winsize, &ws, sizeof (ws)) != 0) {
		winsize = ws;
		sendwindow();
	}
}

/*
 * Send the window size to the server via the magic escape.
 * Note:  SIGWINCH should be blocked when this is called, lest
 * winsize change underneath us and chaos result.
 */
static void
sendwindow(void)
{
	char obuf[4 + sizeof (struct winsize)];
	struct winsize *wp = (struct winsize *)(void *)(obuf+4);

	obuf[0] = -1;
	obuf[1] = -1;
	obuf[2] = 's';
	obuf[3] = 's';
	wp->ws_row = htons(winsize.ws_row);
	wp->ws_col = htons(winsize.ws_col);
	wp->ws_xpixel = htons(winsize.ws_xpixel);
	wp->ws_ypixel = htons(winsize.ws_ypixel);
	if (deswrite(rem, obuf, sizeof (obuf), 0) < 0)
		prf(gettext("Write error to network: %s"), strerror(errno));
}


/*
 * reader: read from remote: remote -> stdout
 */
#define	READING	1
#define	WRITING	2

static	char rcvbuf[8 * 1024];
static	int rcvcnt;
static	int rcvstate;
static	pid_t ppid;
static	jmp_buf rcvtop;

static void
oob(void)
{
	int out = FWRITE, atmark, n;
	int rcvd = 0;
	char waste[4*BUFSIZ], mark;
	struct sgttyb sb;
	fd_set exceptfds;
	struct timeval tv;
	int ret;

	FD_ZERO(&exceptfds);
	FD_SET(rem, &exceptfds);
	timerclear(&tv);
	ret = select(rem+1, NULL, NULL, &exceptfds, &tv);
	/*
	 * We may get an extra signal at start up time since we are trying
	 * to take all precautions not to miss the urgent byte. This
	 * means we may get here without any urgent data to process, in which
	 * case we do nothing and just return.
	 */
	if (ret <= 0)
		return;

	do {
		if (ioctl(rem, SIOCATMARK, &atmark) < 0) {
			break;
		}
		if (!atmark) {
			/*
			 * Urgent data not here yet.
			 * It may not be possible to send it yet
			 * if we are blocked for output
			 * and our input buffer is full.
			 */
			if (rcvcnt < sizeof (rcvbuf)) {
				n = desread(rem, rcvbuf + rcvcnt,
					sizeof (rcvbuf) - rcvcnt, 0);
				if (n <= 0)
					return;
				rcvd += n;
				rcvcnt += n;
			} else {
				/*
				 * We still haven't gotten to the urgent mark
				 * and we're out of buffer space.  Since we
				 * must clear our receive window to allow it
				 * to arrive, we will have to throw away
				 * these bytes.
				 */
				n = desread(rem, waste, sizeof (waste), 0);
				if (n <= 0)
					return;
			}
		}
	} while (atmark == 0);
	while (recv(rem, &mark, 1, MSG_OOB) < 0) {
		switch (errno) {

		case EWOULDBLOCK:
			/*
			 * We've reached the urgent mark, so the next
			 * data to arrive will be the urgent, but it must
			 * not have arrived yet.
			 */
			(void) sleep(1);
			continue;

		default:
			return;
		}
	}
	if (mark & TIOCPKT_WINDOW) {
		/*
		 * Let server know about window size changes
		 */
		(void) kill(ppid, SIGUSR1);
	}
	if (!eight && (mark & TIOCPKT_NOSTOP)) {
		if (ioctl(STDIN_FILENO, TIOCGETP, (char *)&sb) == -1)
			perror("ioctl TIOCGETP");
		sb.sg_flags &= ~O_CBREAK;
		sb.sg_flags |= O_RAW;
		if (compat_ioctl(STDIN_FILENO, TIOCSETP, &sb) == -1)
			perror("ioctl TIOCSETP 1");
		notc.t_stopc = -1;
		notc.t_startc = -1;
		if (compat_ioctl(STDIN_FILENO, TIOCSETC, &notc) == -1)
			perror("ioctl TIOCSETC");
	}
	if (!eight && (mark & TIOCPKT_DOSTOP)) {
		if (ioctl(STDIN_FILENO, TIOCGETP, (char *)&sb) == -1)
			perror("ioctl TIOCGETP");
		sb.sg_flags &= ~O_RAW;
		sb.sg_flags |= O_CBREAK;
		if (compat_ioctl(STDIN_FILENO, TIOCSETP, &sb) == -1)
			perror("ioctl TIOCSETP 2");
		notc.t_stopc = deftc.t_stopc;
		notc.t_startc = deftc.t_startc;
		if (compat_ioctl(STDIN_FILENO, TIOCSETC, &notc) == -1)
			perror("ioctl TIOCSETC");
	}
	if (mark & TIOCPKT_FLUSHWRITE) {
		if (ioctl(STDOUT_FILENO, TIOCFLUSH, (char *)&out) == -1)
			perror("ioctl TIOCFLUSH");
		for (;;) {
			if (ioctl(rem, SIOCATMARK, &atmark) < 0) {
				perror("ioctl SIOCATMARK");
				break;
			}
			if (atmark)
				break;
			n = desread(rem, waste, sizeof (waste), 0);
			if (n <= 0) {
				if (n < 0)
					prf(gettext(
					    "Read error from network: %s"),
					    strerror(errno));
				break;
			}
		}
		/*
		 * Don't want any pending data to be output,
		 * so clear the recv buffer.
		 * If we were hanging on a write when interrupted,
		 * don't want it to restart.  If we were reading,
		 * restart anyway.
		 */
		rcvcnt = 0;
		longjmp(rcvtop, 1);
	}
	/*
	 * If we filled the receive buffer while a read was pending,
	 * longjmp to the top to restart appropriately.  Don't abort
	 * a pending write, however, or we won't know how much was written.
	 */
	if (rcvd && rcvstate == READING)
		longjmp(rcvtop, 1);
}

/*
 * reader: read from remote: line -> 1
 */
static int
reader(int oldmask)
{
	/*
	 * 4.3bsd or later and SunOS 4.0 or later use the posiitive
	 * pid; otherwise use the negative.
	 */
	pid_t pid = getpid();
	int n, remaining;
	char *bufp = rcvbuf;

	(void) sigset(SIGTTOU, SIG_IGN);
	(void) sigset(SIGURG, (void (*)())oob);
	ppid = getppid();
	if (fcntl(rem, F_SETOWN, pid) == -1)
		perror("fcntl F_SETOWN");
	/*
	 * A SIGURG may have been posted before we were completely forked,
	 * which means we may not have received it. To insure we do not miss
	 * any urgent data, we force the signal. The signal hander will be
	 * able to determine if in fact there is urgent data or not.
	 */
	(void) kill(pid, SIGURG);
	(void) setjmp(rcvtop);
	sigsetmask(oldmask);
	for (;;) {
		while ((remaining = rcvcnt - (bufp - rcvbuf)) > 0) {
			rcvstate = WRITING;
			n = write(STDOUT_FILENO, bufp, remaining);
			if (n < 0) {
				if (errno != EINTR) {
					prf(gettext(
					    "Write error to terminal: %s"),
					    strerror(errno));
					return (-1);
				}
				continue;
			}
			bufp += n;
		}
		bufp = rcvbuf;
		rcvcnt = 0;
		rcvstate = READING;
		rcvcnt = desread(rem, rcvbuf, sizeof (rcvbuf), 0);
		if (rcvcnt == 0)
			return (0);
		if (rcvcnt < 0) {
			if (errno == EINTR)
				continue;
			prf(gettext("Read error from network: %s"),
			    strerror(errno));
			return (-1);
		}
	}
}

static void
mode(int f)
{
	struct tchars *tc;
	struct ltchars *ltc;
	struct sgttyb sb;
	int	lflags;

	if (ioctl(STDIN_FILENO, TIOCGETP, (char *)&sb) == -1)
		perror("ioctl TIOCGETP");
	if (ioctl(STDIN_FILENO, TIOCLGET, (char *)&lflags) == -1)
		perror("ioctl TIOCLGET");
	switch (f) {

	case 0:
		sb.sg_flags &= ~(O_CBREAK|O_RAW|O_TBDELAY);
		sb.sg_flags |= defflags|tabflag;
		tc = &deftc;
		ltc = &defltc;
		sb.sg_kill = defkill;
		sb.sg_erase = deferase;
		lflags = deflflags;
		break;

	case 1:
		sb.sg_flags |= (eight ? O_RAW : O_CBREAK);
		sb.sg_flags &= ~defflags;
		/* preserve tab delays, but turn off XTABS */
		if ((sb.sg_flags & O_TBDELAY) == O_XTABS)
			sb.sg_flags &= ~O_TBDELAY;
		tc = &notc;
		ltc = &noltc;
		sb.sg_kill = sb.sg_erase = -1;
		if (litout)
			lflags |= LLITOUT;
		break;

	default:
		/*NOTREACHED*/
		return;
	}
	if (compat_ioctl(STDIN_FILENO, TIOCSLTC, ltc) == -1)
		perror("ioctl TIOCSLTC");
	if (compat_ioctl(STDIN_FILENO, TIOCSETC, tc) == -1)
		perror("ioctl TIOCSETC");
	if (compat_ioctl(STDIN_FILENO, TIOCSETP, &sb) == -1)
		perror("ioctl TIOCSETP 3");
	if (compat_ioctl(STDIN_FILENO, TIOCLSET, &lflags) == -1)
		perror("ioctl TIOCLSET");
}

/* PRINTFLIKE(0) */
static void
prf(const char *format, ...)
{
	va_list	ap;

	va_start(ap, format);
	(void) vfprintf(stderr, format, ap);
	va_end(ap);
	(void) fputs(CRLF, stderr);
}

static void
lostpeer(void)
{
	(void) sigset(SIGPIPE, SIG_IGN);
	prf(gettext("\aConnection to %.*s closed."), MAXHOSTNAMELEN, host);
	done(EXIT_FAILURE);
}

static int
compat_ioctl(int des, int request, void *arg)
{
	struct termios	tb;
	boolean_t	flag = B_FALSE;

	if (ioctl(des, request, arg) < 0)
		return (-1);

	if (tcgetattr(des, &tb) < 0)
		return (-1);

	if (cfgetispeed(&tb) != cfgetispeed(&savetty)) {
		(void) cfsetispeed(&tb, cfgetispeed(&savetty));
		flag = B_TRUE;
	}
	if (cfgetospeed(&tb) != cfgetospeed(&savetty)) {
		(void) cfsetospeed(&tb, cfgetospeed(&savetty));
		flag = B_TRUE;
	}

	return (flag ? tcsetattr(des, TCSANOW, &tb) : 0);
}

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 *
 */

#define	_FILE_OFFSET_BITS 64

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
/* just for FIONBIO ... */
#include <sys/filio.h>
#include <sys/stat.h>
#include <sys/select.h>

#include <netinet/in.h>

#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <pwd.h>
#include <netdb.h>
#include <locale.h>
#include <priv_utils.h>

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

#define	RSH_BUFSIZ (1024 * 50)

static char des_inbuf[2 * RSH_BUFSIZ];	/* needs to be > largest read size */
static char des_outbuf[2 * RSH_BUFSIZ];	/* needs to be > largest write size */
static krb5_data desinbuf, desoutbuf;
static krb5_encrypt_block eblock;	/* eblock for encrypt/decrypt */
static krb5_context bsd_context = NULL;
static krb5_auth_context auth_context;
static krb5_creds *cred;
static krb5_keyblock *session_key;

static int encrypt_flag;	/* Flag set, when encryption is used */
static int krb5auth_flag;	/* Flag set, when KERBEROS is enabled */
static profile_options_boolean autologin_option[] = {
	{ "autologin", &krb5auth_flag, 0 },
	{ NULL, NULL, 0 }
};

static int no_krb5auth_flag = 0;
static int fflag;	/* Flag set, if creds to be fwd'ed via -f */
static int Fflag;	/* Flag set, if fwd'able creds to be fwd'ed via -F */

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

static char *realmdef[] = { "realms", NULL, "rsh", NULL };
static char *appdef[] = { "appdefaults", "rsh", NULL };

static void sendsig(int);
static sigdisp_t sigdisp(int);
static boolean_t init_service(boolean_t);
static int desrshread(int, char *, int);
static int desrshwrite(int, char *, int);

static int		options;
static int		rfd2;
static int		portnumber;

static const char	rlogin_path[] = "/usr/bin/rlogin";
static const char	dash_x[] = "-x ";	/* Note the blank after -x */

static boolean_t readiv, writeiv;

#define	set2mask(setp)	((setp)->__sigbits[0])
#define	mask2set(mask, setp) \
	((mask) == -1 ? sigfillset(setp) : (set2mask(setp) = (mask)))

#ifdef DEBUG
#define	DEBUGOPTSTRING	"D:"
#else
#define	DEBUGOPTSTRING	""
#endif	/* DEBUG */

static void
sigsetmask(int mask)
{
	sigset_t	nset;

	(void) sigprocmask(0, NULL, &nset);
	mask2set(mask, &nset);
	(void) sigprocmask(SIG_SETMASK, &nset, NULL);
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

static pid_t child_pid = -1;

/*
 * If you do a command like "rsh host output | wc"
 * and wc terminates, then the parent will receive SIGPIPE
 * and the child needs to be terminated.
 */
/* ARGSUSED */
static void
sigpipehandler(int signal)
{
	if (child_pid != -1)
		(void) kill(child_pid, SIGKILL);
	exit(EXIT_SUCCESS);
}

#define	mask(s)	(1 << ((s) - 1))

static void
usage(void) {
	(void) fprintf(stderr, "%s\n%s\n",
	    gettext("usage: rsh [ -PN / -PO ] [ -l login ] [ -n ] "
		"[ -k realm ] [ -a ] [ -x ] [ -f / -F ] host command"),
	    gettext("       rsh [ -PN / -PO ] [ -l login ] [ -k realm ] "
		"[ -a ] [ -x ] [ -f / -F ] host"));
	exit(EXIT_FAILURE);
}

static void
die(const char *message)
{
	(void) fputs(message, stderr);
	usage();
}

static void
usage_forward(void)
{
	die(gettext("rsh: Only one of -f and -F allowed.\n"));
}

/*
 * rsh - remote shell
 */
/* VARARGS */
int
main(int argc, char **argv)
{
	int c, rem;
	char *cmd, *cp, **ap, buf[RSH_BUFSIZ], **argv0, *args, *args_no_x;
	char *host = NULL, *user = NULL;
	int cc;
	boolean_t asrsh = B_FALSE;
	struct passwd *pwd;
	boolean_t readfrom_rem;
	boolean_t readfrom_rfd2;
	int one = 1;
	int omask;
	boolean_t nflag = B_FALSE;
	char *krb_realm = NULL;
	krb5_flags authopts;
	krb5_error_code status;
	enum kcmd_proto kcmd_proto = KCMD_NEW_PROTOCOL;
	uid_t uid = getuid();

	c = (argc + 1) * sizeof (char *);
	if ((argv0 = malloc(c)) == NULL) {
		perror("malloc");
		return (EXIT_FAILURE);
	}
	(void) memcpy(argv0, argv, c);

	(void) setlocale(LC_ALL, "");

	(void) textdomain(TEXT_DOMAIN);

	/*
	 * Determine command name used to invoke to rlogin(1). Users can
	 * create links named by a host pointing to the binary and type
	 * "hostname" to log into that host afterwards.
	 */
	cmd = strrchr(argv[0], '/');
	cmd = (cmd != NULL) ? (cmd + 1) : argv[0];

	/*
	 *	Add "remsh" as an alias for "rsh" (System III, V networking
	 *	add-ons often used this name for the remote shell since rsh
	 *	was already taken for the restricted shell).  Note that this
	 *	usurps the ability to use "remsh" as the name of a host (by
	 *	symlinking it to rsh), so we go one step farther:  if the
	 *	file "/usr/bin/remsh" does not exist, we behave as if "remsh"
	 *	is a host name.  If it does exist, we accept "remsh" as an
	 *	"rsh" alias.
	 */
	if (strcmp(cmd, "remsh") == 0) {
		struct stat sb;

		if (stat("/usr/bin/remsh", &sb) < 0)
			host = cmd;
	} else if (strcmp(cmd, "rsh") != 0) {
		host = cmd;
	}

	/* Handle legacy synopsis "rsh hostname options [command]". */
	if (host == NULL) {
		if (argc < 2)
			usage();
		if (*argv[1] != '-') {
			host = argv[1];
			argc--;
			argv[1] = argv[0];
			argv++;
			asrsh = B_TRUE;
		}
	}

	while ((c = getopt(argc, argv,
	    DEBUGOPTSTRING "8AFKLP:ade:fk:l:nwx")) != -1) {
		switch (c) {
#ifdef DEBUG
		case 'D':
			portnumber = htons(atoi(optarg));
			krb5auth_flag++;
			break;
#endif /* DEBUG */
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
		case 'P':
			if (strcmp(optarg, "N") == 0)
				kcmd_proto = KCMD_NEW_PROTOCOL;
			else if (strcmp(optarg, "O") == 0)
				kcmd_proto = KCMD_OLD_PROTOCOL;
			else
				die(gettext("rsh: Only -PN or -PO "
				    "allowed.\n"));
			if (rcmdoption_done)
				die(gettext("rsh: Only one of -PN and -PO "
				    "allowed.\n"));
			rcmdoption_done = B_TRUE;
			krb5auth_flag++;
			break;
		case 'a':
			krb5auth_flag++;
			break;
		case 'K':
			no_krb5auth_flag++;
			break;
		case 'd':
			options |= SO_DEBUG;
			break;
		case 'k':
			krb_realm = optarg;
			krb5auth_flag++;
			break;
		case 'l':
			user = optarg;
			break;
		case 'n':
			if (!nflag) {
				if (close(STDIN_FILENO) < 0) {
					perror("close");
					return (EXIT_FAILURE);
				}
				/*
				 * "STDION_FILENO" defined to 0 by POSIX
				 * and hence the lowest file descriptor.
				 * So the open(2) below is guaranteed to
				 * reopen it because we closed it above.
				 */
				if (open("/dev/null", O_RDONLY) < 0) {
					perror("open");
					return (EXIT_FAILURE);
				}
				nflag = B_TRUE;
			}
			break;
		case 'x':
			encrypt_flag = 1;
			krb5auth_flag++;
			encrypt_done = B_TRUE;
			break;
		/*
		 * Ignore the -L, -w, -e and -8 flags to allow aliases with
		 * rlogin to work. Actually rlogin(1) doesn't understand
		 * -w either but because "rsh -w hostname command" used
		 * to work we still accept it.
		 */
		case '8':
		case 'L':
		case 'e':
		case 'w':
		/*
		 * On the lines of the -L, -w, -e and -8 options above, we
		 * ignore the -A option too, in order to allow aliases with
		 * rlogin to work.
		 *
		 * Mind you !, the -a option to trigger Kerberos authentication
		 * in rsh, has a totally different usage in rlogin, its the
		 * -A option (in rlogin) which needs to be used to talk
		 * Kerberos.
		 */
		case 'A':
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
		asrsh = B_TRUE;
	}

	if (argc == 0) {
		(void) setreuid(uid, uid);
		if (nflag)
			usage();
		if (asrsh)
			*argv0 = "rlogin";
		(void) execv(rlogin_path, argv0);
		perror(rlogin_path);

		(void) fprintf(stderr, gettext("No local rlogin "
				"program found.\n"));
		return (EXIT_FAILURE);
	}

	if (__init_suid_priv(0, PRIV_NET_PRIVADDR, NULL) == -1) {
		(void) fprintf(stderr,
		    gettext("Insufficient privileges, "
			"rsh must be set-uid root\n"));
		return (EXIT_FAILURE);
	}

	pwd = getpwuid(uid);
	if (pwd == NULL) {
		(void) fprintf(stderr, gettext("who are you?\n"));
		return (EXIT_FAILURE);
	}
	if (user == NULL)
		user = pwd->pw_name;

	/*
	 * if the user disables krb5 on the cmdline (-K), then skip
	 * all krb5 setup.
	 *
	 * if the user does not disable krb5 or enable krb5 on the
	 * cmdline, check krb5.conf to see if it should be enabled.
	 */

	if (no_krb5auth_flag) {
		krb5auth_flag = 0;
		Fflag = fflag = encrypt_flag = 0;
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
			(void) profile_get_options_boolean(bsd_context->profile,
							appdef,
							autologin_option);
		}
	}

	if (krb5auth_flag) {
		if (!bsd_context) {
			status = krb5_init_context(&bsd_context);
			if (status) {
				com_err("rsh", status,
				    "while initializing krb5");
				return (EXIT_FAILURE);

			}
		}

		/*
		 * Get our local realm to look up local realm options.
		 */
		status = krb5_get_default_realm(bsd_context, &realmdef[1]);
		if (status) {
			com_err("rsh", status,
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
			(void) fprintf(stderr, gettext("rsh: Encryption not "
				"supported.\n"));
			return (EXIT_FAILURE);
		}
	}

	/*
	 * Connect with the service (shell/kshell) on the daemon side
	 */
	if (portnumber == 0) {
		while (!init_service(krb5auth_flag)) {
			/*
			 * Connecting to the 'kshell' service failed,
			 * fallback to normal rsh; Reset all KRB5 flags
			 * and connect to 'shell' service on the server
			 */
			krb5auth_flag = 0;
			encrypt_flag = fflag = Fflag = 0;
		}
	}

	cc = encrypt_flag ? strlen(dash_x) : 0;
	for (ap = argv; *ap != NULL; ap++)
		cc += strlen(*ap) + 1;
	cp = args = malloc(cc);
	if (cp == NULL)
		perror("malloc");
	if (encrypt_flag) {
		int length;

		length = strlcpy(args, dash_x, cc);
		cp += length;
		cc -= length;
	}
	args_no_x = args;

	for (ap = argv; *ap != NULL; ap++) {
		int length;

		length = strlcpy(cp, *ap, cc);
		assert(length < cc);
		cp += length;
		cc -= length;
		if (ap[1] != NULL) {
			*cp++ = ' ';
			cc--;
		}
	}

	if (krb5auth_flag) {
		authopts = AP_OPTS_MUTUAL_REQUIRED;
		/*
		 * Piggy-back forwarding flags on top of authopts;
		 * they will be reset in kcmd
		 */
		if (fflag || Fflag)
			authopts |= OPTS_FORWARD_CREDS;
		if (Fflag)
			authopts |= OPTS_FORWARDABLE_CREDS;

		status = kcmd(&rem, &host, portnumber,
				pwd->pw_name, user,
				args, &rfd2, "host", krb_realm,
				bsd_context, &auth_context, &cred,
				NULL,	/* No need for sequence number */
				NULL,	/* No need for server seq # */
				authopts,
				1,	/* Always set anyport */
				&kcmd_proto);
		if (status != 0) {
			/*
			 * If new protocol requested, we dont fallback to
			 * less secure ones.
			 */
			if (kcmd_proto == KCMD_NEW_PROTOCOL) {
				(void) fprintf(stderr, gettext("rsh: kcmdv2 "
					"to host %s failed - %s\n"
					"Fallback to normal rsh denied."),
					host, error_message(status));
				return (EXIT_FAILURE);
			}
			/* check NO_TKT_FILE or equivalent... */
			if (status != -1) {
				(void) fprintf(stderr,
				gettext("rsh: kcmd to host %s failed - %s\n"
				"trying normal rsh...\n\n"),
				host, error_message(status));
			} else {
				(void) fprintf(stderr,
					gettext("trying normal rsh...\n"));
			}
			/*
			 * kcmd() failed, so we now fallback to normal rsh,
			 * after resetting the KRB5 flags and the 'args' array
			 */
			krb5auth_flag = 0;
			encrypt_flag = fflag = Fflag = 0;
			args = args_no_x;
			(void) init_service(B_FALSE);
		} else {
			/*
			 * Set up buffers for desread and deswrite.
			 */
			desinbuf.data = des_inbuf;
			desoutbuf.data = des_outbuf;
			desinbuf.length = sizeof (des_inbuf);
			desoutbuf.length = sizeof (des_outbuf);

			session_key = &cred->keyblock;

			if (kcmd_proto == KCMD_NEW_PROTOCOL) {
				status = krb5_auth_con_getlocalsubkey(
				    bsd_context,
				    auth_context,
				    &session_key);
				if (status) {
					com_err("rsh", status,
					    "determining subkey for session");
					return (EXIT_FAILURE);
				}
				if (session_key == NULL) {
					com_err("rsh", 0, "no subkey "
					    "negotiated for connection");
					return (EXIT_FAILURE);
				}
			}

			eblock.crypto_entry = session_key->enctype;
			eblock.key = (krb5_keyblock *)session_key;

			init_encrypt(encrypt_flag, bsd_context, kcmd_proto,
			    &desinbuf, &desoutbuf, CLIENT, &eblock);
			if (encrypt_flag) {
				char *s = gettext("This rsh session is using "
				    "encryption for all data transmissions.");
				(void) write(STDERR_FILENO, s, strlen(s));
				(void) write(STDERR_FILENO, "\r\n", 2);
			}
		}
	}

	/*
	 * Don't merge this with the "if" statement above because
	 * "krb5auth_flag" might be set to false inside it.
	 */
	if (!krb5auth_flag) {
		rem = rcmd_af(&host, portnumber, pwd->pw_name, user, args,
		    &rfd2, AF_INET6);
		if (rem < 0)
			return (EXIT_FAILURE);
	}
	__priv_relinquish();

	if (rfd2 < 0) {
		(void) fprintf(stderr, gettext("rsh: can't establish "
				"stderr\n"));
		return (EXIT_FAILURE);
	}
	if (options & SO_DEBUG) {
		if (setsockopt(rem, SOL_SOCKET, SO_DEBUG, (char *)&one,
		    sizeof (one)) < 0)
			perror("rsh: setsockopt (stdin)");
		if (setsockopt(rfd2, SOL_SOCKET, SO_DEBUG, (char *)&one,
		    sizeof (one)) < 0)
			perror("rsh: setsockopt (stderr)");
	}
	omask = sigblock(mask(SIGINT)|mask(SIGQUIT)|mask(SIGTERM));

	if (sigdisp(SIGINT) != SIG_IGN)
		(void) sigset(SIGINT, sendsig);
	if (sigdisp(SIGQUIT) != SIG_IGN)
		(void) sigset(SIGQUIT, sendsig);
	if (sigdisp(SIGTERM) != SIG_IGN)
		(void) sigset(SIGTERM, sendsig);

	if (nflag) {
		(void) shutdown(rem, SHUT_WR);
	} else {
		child_pid = fork();
		if (child_pid < 0) {
			perror("rsh: fork");
			return (EXIT_FAILURE);
		}

		if (!encrypt_flag) {
			(void) ioctl(rfd2, FIONBIO, &one);
			(void) ioctl(rem, FIONBIO, &one);
		}

		if (child_pid == 0) {
			/* Child */
			fd_set remset;
			char *bp;
			int  wc;
			(void) close(rfd2);
		reread:
			errno = 0;
			cc = read(0, buf, sizeof (buf));
			if (cc <= 0)
				goto done;
			bp = buf;
		rewrite:
			FD_ZERO(&remset);
			FD_SET(rem, &remset);
			if (select(rem + 1, NULL, &remset, NULL, NULL) < 0) {
				if (errno != EINTR) {
					perror("rsh: select");
					return (EXIT_FAILURE);
				}
				goto rewrite;
			}
			if (!FD_ISSET(rem, &remset))
				goto rewrite;
			writeiv = B_FALSE;
			wc = desrshwrite(rem, bp, cc);
			if (wc < 0) {
				if (errno == EWOULDBLOCK)
					goto rewrite;
				goto done;
			}
			cc -= wc; bp += wc;
			if (cc == 0)
				goto reread;
			goto rewrite;
		done:
			(void) shutdown(rem, SHUT_WR);
			return (EXIT_SUCCESS);
		}
	}

#define	MAX(a, b)	(((a) > (b)) ? (a) : (b))

	sigsetmask(omask);
	readfrom_rem = B_TRUE;
	readfrom_rfd2 = B_TRUE;
	(void) sigset(SIGPIPE, sigpipehandler);
	do {
		fd_set readyset;

		FD_ZERO(&readyset);
		if (readfrom_rem)
			FD_SET(rem, &readyset);
		if (readfrom_rfd2)
			FD_SET(rfd2, &readyset);
		if (select(MAX(rem, rfd2) + 1, &readyset, NULL, NULL,
		    NULL) < 0) {
			if (errno != EINTR) {
				perror("rsh: select");
				return (EXIT_FAILURE);
			}
			continue;
		}
		if (FD_ISSET(rfd2, &readyset)) {
			errno = 0;
			readiv = B_TRUE;
			cc = desrshread(rfd2, buf, sizeof (buf));
			if (cc <= 0) {
				if (errno != EWOULDBLOCK)
					readfrom_rfd2 = B_FALSE;
			} else {
				(void) write(STDERR_FILENO, buf, cc);
			}
		}
		if (FD_ISSET(rem, &readyset)) {
			errno = 0;
			readiv = B_FALSE;
			cc = desrshread(rem, buf, sizeof (buf));
			if (cc <= 0) {
				if (errno != EWOULDBLOCK)
					readfrom_rem = B_FALSE;
			} else
				(void) write(STDOUT_FILENO, buf, cc);
		}
	} while (readfrom_rem || readfrom_rfd2);

	if (!nflag)
		(void) kill(child_pid, SIGKILL);
	return (EXIT_SUCCESS);
}

static void
sendsig(int signum)
{
	char	buffer;

	writeiv = B_TRUE;
	buffer = (char)signum;
	(void) desrshwrite(rfd2, &buffer, 1);
}

static boolean_t
init_service(boolean_t krb5flag)
{
	struct servent *sp;

	if (krb5flag) {
		sp = getservbyname("kshell", "tcp");
		if (sp == NULL) {
			(void) fprintf(stderr,
				gettext("rsh: kshell/tcp: unknown service.\n"
				"trying normal shell/tcp service\n"));
			return (B_FALSE);
		}
	} else {
		sp = getservbyname("shell", "tcp");
		if (sp == NULL) {
			portnumber = htons(IPPORT_CMDSERVER);
			return (B_TRUE);
		}
	}

	portnumber = sp->s_port;
	return (B_TRUE);
}

static int
desrshread(int fd, char *buf, int len)
{
	return (desread(fd, buf, len, readiv ? 1 : 0));
}

static int
desrshwrite(int fd, char *buf, int len)
{
	return (deswrite(fd, buf, len, writeiv ? 1 : 0));
}

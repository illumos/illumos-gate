/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 *
 */

#define	_FILE_OFFSET_BITS  64

/*
 * rcp
 */
#include <sys/param.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/acl.h>
#include <dirent.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pwd.h>
#include <netdb.h>
#include <wchar.h>
#include <stdlib.h>
#include <errno.h>
#include <locale.h>
#include <strings.h>
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <priv_utils.h>
#include <sys/sendfile.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <aclutils.h>
#include <sys/varargs.h>

/*
 * It seems like Berkeley got these from pathnames.h?
 */
#define	_PATH_RSH	"/usr/bin/rsh"
#define	_PATH_CP	"/usr/bin/cp"

#define	ACL_FAIL	1
#define	ACL_OK		0
#define	RCP_BUFSIZE	(64 * 1024)

#define	RCP_ACL	"/usr/lib/sunw,rcp"
		/* see PSARC/1993/004/opinion */

typedef struct _buf {
	int	cnt;
	char	*buf;
} BUF;

static char *cmd_sunw;
static struct passwd *pwd;
static int errs;
static int pflag;
static uid_t userid;
static int rem;
static int zflag;
static int iamremote;
static int iamrecursive;
static int targetshouldbedirectory;
static int aclflag;
static int acl_aclflag;
static int retval = 0;
static int portnumber = 0;

static void lostconn(void);
static char *search_char(unsigned char *, unsigned char);
static char *removebrackets(char *);
static char *colon(char *);
static int response(void);
static void usage(void);
static void source(int, char **);
static void sink(int, char **);
static void toremote(char *, int, char **);
static void tolocal(int, char **);
static void verifydir(char *);
static int okname(char *);
static int susystem(char *, char **);
static void rsource(char *, struct stat *);
static int sendacl(int);
static int recvacl(int, int, int);
static int zwrite(int, char *, int);
static void zopen(int, int);
static int zclose(int);
static int notzero(char *, int);
static BUF *allocbuf(BUF *, int, int);
static void error(char *fmt, ...);
static void addargs(char **, ...);

/*
 * As a 32 bit application, we can only transfer (2gb - 1) i.e 0x7FFFFFFF
 * bytes of data. We would like the size to be aligned to the nearest
 * MAXBOFFSET (8192) boundary for optimal performance.
 */
#define	SENDFILE_SIZE	0x7FFFE000

#include <k5-int.h>
#include <profile/prof_int.h>
#include <com_err.h>
#include <kcmd.h>

#define	NULLBUF	(BUF *) 0
#define	MAXARGS	10	/* Number of arguments passed to execv() */

static int sock;
static char *cmd, *cmd_orig, *cmd_sunw_orig;
static char *krb_realm = NULL;
static char *krb_cache = NULL;
static char *krb_config = NULL;
static char des_inbuf[2 * RCP_BUFSIZE];
				/* needs to be > largest read size */
static char des_outbuf[2 * RCP_BUFSIZE];
				/* needs to be > largest write size */

static krb5_data desinbuf, desoutbuf;
static krb5_encrypt_block eblock;	/* eblock for encrypt/decrypt */
static krb5_keyblock *session_key;	/* static key for session */
static krb5_context bsd_context = NULL;
static krb5_auth_context auth_context;
static krb5_flags authopts;
static krb5_error_code status;

static void try_normal_rcp(int, char **);
static int init_service(int);
static char **save_argv(int, char **);
static void answer_auth(char *, char *);
static int desrcpwrite(int, char *, int);
static int desrcpread(int, char *, int);

/*
 * Not sure why these two don't have their own header file declarations, but
 * lint complains about absent declarations so place some here. Sigh.
 */
extern errcode_t	profile_get_options_boolean(profile_t, char **,
    profile_options_boolean *);
extern errcode_t	profile_get_options_string(profile_t, char **,
    profile_option_strings *);

static int krb5auth_flag = 0;	/* Flag set, when KERBEROS is enabled */
static profile_options_boolean autologin_option[] = {
	{ "autologin", &krb5auth_flag, 0 },
	{ NULL, NULL, 0 }
};
static int no_krb5auth_flag = 0;

static int encrypt_flag = 0;	/* Flag set, when encryption is enabled */
static int encrypt_done = 0;	/* Flag set, if "-x" is specified */
static enum kcmd_proto kcmd_proto = KCMD_NEW_PROTOCOL;

/* Flag set, if -PN / -PO is specified */
static boolean_t rcmdoption_done = B_FALSE;

static profile_options_boolean option[] = {
	{ "encrypt", &encrypt_flag, 0 },
	{ NULL, NULL, 0 }
};

static char *rcmdproto = NULL;
static profile_option_strings rcmdversion[] = {
	{ "rcmd_protocol", &rcmdproto, 0 },
	{ NULL, NULL, 0 }
};

static char *realmdef[] = { "realms", NULL, "rcp", NULL };
static char *appdef[] = { "appdefaults", "rcp", NULL };
static char **prev_argv;
static int prev_argc;

int
main(int argc, char *argv[])
{
	int ch, fflag, tflag;
	char *targ;
	size_t cmdsiz;

	(void) setlocale(LC_ALL, "");

	if (strcmp(argv[0], RCP_ACL) == 0)
		aclflag = 1;

	if (!(pwd = getpwuid(userid = getuid()))) {
		(void) fprintf(stderr, "rcp: unknown user %d.\n",
		    (uint_t)userid);
		return (1);
	}

	fflag = tflag = 0;
	while ((ch = getopt(argc, argv, "axdfprtz:D:k:P:ZK")) != EOF) {
		switch (ch) {
		case 'd':
			targetshouldbedirectory = 1;
			break;
		case 'f':			/* "from" */
			fflag = 1;
			if (aclflag | acl_aclflag)
				/* ok response */
				(void) desrcpwrite(rem, "", 1);
			break;
		case 'p':			/* preserve access/mod times */
			++pflag;
			break;
		case 'r':
			++iamrecursive;
			break;
		case 't':			/* "to" */
			tflag = 1;
			break;
		case 'Z':
			acl_aclflag++;
			break;
		case 'K':
			no_krb5auth_flag++;
			break;
		case 'x':
			if (!krb5_privacy_allowed()) {
				(void) fprintf(stderr, gettext("rcp: "
				    "Encryption not supported.\n"));
				return (1);
			}
			encrypt_flag++;
			krb5auth_flag++;
			encrypt_done++;
			break;
		case 'k':
			if ((krb_realm = (char *)strdup(optarg)) == NULL) {
				(void) fprintf(stderr, gettext("rcp:"
				    " Cannot malloc.\n"));
				return (1);
			}
			krb5auth_flag++;
			break;
		case 'P':
			if (strncmp(optarg, "O", 1) == 0) {
				if (rcmdoption_done == B_TRUE) {
					(void) fprintf(stderr, gettext("rcp: "
					    "Only one of -PN and -PO "
					    "allowed.\n"));
					usage();
				}
				kcmd_proto = KCMD_OLD_PROTOCOL;
				rcmdoption_done = B_TRUE;
			} else if (strncmp(optarg, "N", 1) == 0) {
				if (rcmdoption_done == B_TRUE) {
					(void) fprintf(stderr, gettext("rcp: "
					    "Only one of -PN and -PO "
					    "allowed.\n"));
					usage();
				}
				kcmd_proto = KCMD_NEW_PROTOCOL;
				rcmdoption_done = B_TRUE;
			} else {
				usage();
			}
			krb5auth_flag++;
			break;
		case 'a':
			krb5auth_flag++;
			break;
#ifdef DEBUG
		case 'D':
			portnumber = htons(atoi(optarg));
			krb5auth_flag++;
			break;
#endif /* DEBUG */
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	/*
	 * if the user disables krb5 on the cmdline (-K), then skip
	 * all krb5 setup.
	 *
	 * if the user does not disable krb5 or enable krb5 on the
	 * cmdline, check krb5.conf to see if it should be enabled.
	 */

	if (no_krb5auth_flag) {
		krb5auth_flag = 0;
		fflag = encrypt_flag = 0;
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

	if (krb5auth_flag > 0) {
		if (!bsd_context) {
			status = krb5_init_context(&bsd_context);
			if (status) {
				com_err("rcp", status,
				    gettext("while initializing krb5"));
				return (1);
			}
		}

		/*
		 * Set up buffers for desread and deswrite.
		 */
		desinbuf.data = des_inbuf;
		desoutbuf.data = des_outbuf;
		desinbuf.length = sizeof (des_inbuf);
		desoutbuf.length = sizeof (des_outbuf);
	}

	if (fflag || tflag)
		if (encrypt_flag > 0)
			(void) answer_auth(krb_config, krb_cache);

	if (fflag) {
		iamremote = 1;
		(void) response();
		(void) setuid(userid);
		source(argc, argv);
		return (errs);
	}

	if (tflag) {
		iamremote = 1;
		(void) setuid(userid);
		sink(argc, argv);
		return (errs);
	}

	if (argc < 2)
		usage();

	/* This will make "rcmd_af()" magically get the proper privilege */
	if (__init_suid_priv(0, PRIV_NET_PRIVADDR, (char *)NULL) == -1) {
		(void) fprintf(stderr, "rcp: must be set-uid root\n");
		exit(1);
	}

	if (krb5auth_flag > 0) {
		/*
		 * Get our local realm to look up local realm options.
		 */
		status = krb5_get_default_realm(bsd_context, &realmdef[1]);
		if (status) {
			com_err("rcp", status,
			    gettext("while getting default realm"));
			return (1);
		}
		/*
		 * See if encryption should be done for this realm
		 */
		(void) profile_get_options_boolean(bsd_context->profile,
		    realmdef, option);
		/*
		 * Check the appdefaults section
		 */
		(void) profile_get_options_boolean(bsd_context->profile,
		    appdef, option);
		(void) profile_get_options_string(bsd_context->profile,
		    appdef, rcmdversion);
		if ((encrypt_done > 0) || (encrypt_flag > 0)) {
			if (krb5_privacy_allowed() == TRUE) {
				encrypt_flag++;
			} else {
				(void) fprintf(stderr, gettext("rcp: Encryption"
				    " not supported.\n"));
				return (1);
			}
		}

		if ((rcmdoption_done == B_FALSE) && (rcmdproto != NULL)) {
			if (strncmp(rcmdproto, "rcmdv2", 6) == 0) {
				kcmd_proto = KCMD_NEW_PROTOCOL;
			} else if (strncmp(rcmdproto, "rcmdv1", 6) == 0) {
				kcmd_proto = KCMD_OLD_PROTOCOL;
			} else {
				(void) fprintf(stderr, gettext("Unrecognized "
				    "KCMD protocol (%s)"), rcmdproto);
				return (1);
			}
		}
	}

	if (argc > 2)
		targetshouldbedirectory = 1;

	rem = -1;

	if (portnumber == 0) {
		if (krb5auth_flag > 0) {
			retval = init_service(krb5auth_flag);
			if (!retval) {
				/*
				 * Connecting to the kshell service failed,
				 * fallback to normal rcp & reset KRB5 flags.
				 */
				krb5auth_flag = encrypt_flag = 0;
				encrypt_done = 0;
				(void) init_service(krb5auth_flag);
			}
		}
		else
			(void) init_service(krb5auth_flag);
	}

#ifdef DEBUG
	if (retval || krb5auth_flag) {
		(void) fprintf(stderr, gettext("Kerberized rcp session, "
		    "port %d in use "), portnumber);
		if (kcmd_proto == KCMD_OLD_PROTOCOL)
			(void) fprintf(stderr, gettext("[kcmd ver.1]\n"));
		else
			(void) fprintf(stderr, gettext("[kcmd ver.2]\n"));
	} else {
		(void) fprintf(stderr, gettext("Normal rcp session, port %d "
		    "in use.\n"), portnumber);
	}
#endif /* DEBUG */

	if (krb5auth_flag > 0) {
		/*
		 * We calculate here a buffer size that can be used in the
		 * allocation of the three buffers cmd, cmd_orig and
		 * cmd_sunw_orig that are used to hold different incantations
		 * of rcp.
		 */
		cmdsiz = MAX(sizeof ("-x rcp -r -p -d -k ") +
		    strlen(krb_realm != NULL ? krb_realm : ""),
		    sizeof (RCP_ACL " -r -p -z -d"));

		if (((cmd = (char *)malloc(cmdsiz)) == NULL) ||
		    ((cmd_sunw_orig = (char *)malloc(cmdsiz)) == NULL) ||
		    ((cmd_orig = (char *)malloc(cmdsiz)) == NULL)) {
			(void) fprintf(stderr, gettext("rcp: Cannot "
			    "malloc.\n"));
			return (1);
		}

		(void) snprintf(cmd, cmdsiz, "%srcp %s%s%s%s%s",
		    encrypt_flag ? "-x " : "",
		    iamrecursive ? " -r" : "", pflag ? " -p" : "",
		    targetshouldbedirectory ? " -d" : "",
		    krb_realm != NULL ? " -k " : "",
		    krb_realm != NULL ? krb_realm : "");

		/*
		 * We would use cmd-orig as the 'cmd-buffer' if kerberized
		 * rcp fails, in which case we fallback to normal rcp. We also
		 * save argc & argv for the same purpose
		 */
		(void) snprintf(cmd_orig, cmdsiz, "rcp%s%s%s%s",
		    iamrecursive ? " -r" : "",
		    pflag ? " -p" : "",
		    zflag ? " -z" : "",
		    targetshouldbedirectory ? " -d" : "");

		(void) snprintf(cmd_sunw_orig, cmdsiz, "%s%s%s%s%s", RCP_ACL,
		    iamrecursive ? " -r" : "",
		    pflag ? " -p" : "",
		    zflag ? " -z" : "",
		    targetshouldbedirectory ? " -d" : "");

		prev_argc = argc;
		prev_argv = save_argv(argc, argv);

	} else {
		cmdsiz = sizeof ("rcp -r -p -z -d");
		if (((cmd = (char *)malloc(cmdsiz)) == NULL)) {
			(void) fprintf(stderr, gettext("rcp: Cannot "
			    "malloc.\n"));
			return (1);
		}

		(void) snprintf(cmd, cmdsiz, "rcp%s%s%s%s",
		    iamrecursive ? " -r" : "",
		    pflag ? " -p" : "",
		    zflag ? " -z" : "",
		    targetshouldbedirectory ? " -d" : "");
	}

	cmdsiz = sizeof (RCP_ACL " -r -p -z -d");
	if ((cmd_sunw = (char *)malloc(cmdsiz)) == NULL) {
		(void) fprintf(stderr, gettext("rcp: Cannot malloc.\n"));
		return (1);
	}

	(void) snprintf(cmd_sunw, cmdsiz, "%s%s%s%s%s", RCP_ACL,
	    iamrecursive ? " -r" : "",
	    pflag ? " -p" : "",
	    zflag ? " -z" : "",
	    targetshouldbedirectory ? " -d" : "");

	(void) signal(SIGPIPE, (void (*)(int))lostconn);

	if (targ = colon(argv[argc - 1]))
		toremote(targ, argc, argv);
	else {
		tolocal(argc, argv);
		if (targetshouldbedirectory)
			verifydir(argv[argc - 1]);
	}

	return (errs > 0 ? EXIT_FAILURE : EXIT_SUCCESS);
}


static void
toremote(char *targ, int argc, char *argv[])
{
	int i;
	char *host, *src, *suser, *thost, *tuser;
	char resp;
	size_t buffersize;
	char bp[RCP_BUFSIZE];
	krb5_creds *cred;
	char *arglist[MAXARGS+1];
	buffersize = RCP_BUFSIZE;

	*targ++ = 0;
	if (*targ == 0)
		targ = ".";

	if (thost = search_char((unsigned char *)argv[argc - 1], '@')) {
		*thost++ = 0;
		tuser = argv[argc - 1];
		if (*tuser == '\0')
			tuser = NULL;
		else if (!okname(tuser))
			exit(1);
	} else {
		thost = argv[argc - 1];
		tuser = NULL;
	}
	thost = removebrackets(thost);

	for (i = 0; i < argc - 1; i++) {
		src = colon(argv[i]);
		if (src) {			/* remote to remote */
			*src++ = 0;
			if (*src == 0)
				src = ".";
			host = search_char((unsigned char *)argv[i], '@');
			if (host) {
				*host++ = 0;
				host = removebrackets(host);
				suser = argv[i];
				if (*suser == '\0') {
					suser = pwd->pw_name;
				} else if (!okname(suser)) {
					errs++;
					continue;
				}
				(void) snprintf(bp, buffersize, "'%s%s%s:%s'",
				    tuser ? tuser : "", tuser ? "@" : "",
				    thost, targ);
				(void) addargs(arglist, "rsh", host, "-l",
				    suser, "-n", cmd, src, bp, (char *)NULL);
			} else {
				host = removebrackets(argv[i]);
				(void) snprintf(bp, buffersize, "'%s%s%s:%s'",
				    tuser ? tuser : "", tuser ? "@" : "",
				    thost, targ);
				(void) addargs(arglist, "rsh", host, "-n", cmd,
				    src, bp, (char *)NULL);
			}
			if (susystem(_PATH_RSH, arglist) == -1)
				errs++;
		} else {			/* local to remote */
			if (rem == -1) {
				host = thost;
				if (krb5auth_flag > 0) {

				(void) snprintf(bp, buffersize,
				    "%s -t %s", cmd, targ);
				authopts = AP_OPTS_MUTUAL_REQUIRED;
				status = kcmd(&sock, &host,
				    portnumber,
				    pwd->pw_name,
				    tuser ? tuser :
				    pwd->pw_name,
				    bp,
				    0,
				    "host",
				    krb_realm,
				    bsd_context,
				    &auth_context,
				    &cred,
				    0,	/* No seq # */
				    0,	/* No server seq # */
				    authopts,
				    0,	/* Not any port # */
				    &kcmd_proto);
				if (status) {
					/*
					 * If new protocol requested, we dont
					 * fallback to less secure ones.
					 */

					if (kcmd_proto == KCMD_NEW_PROTOCOL) {
						(void) fprintf(stderr,
						    gettext("rcp: kcmdv2 "
						    "to host %s failed - %s"
						    "\nFallback to normal "
						    "rcp denied."), host,
						    error_message(status));
						exit(1);
					}
					if (status != -1) {
						(void) fprintf(stderr,
						    gettext("rcp: kcmd to host "
						    "%s failed - %s,\n"
						    "trying normal rcp...\n\n"),
						    host,
						    error_message(status));
					} else {
						(void) fprintf(stderr,
						    gettext("trying normal"
						    " rcp...\n"));
					}
					/*
					 * kcmd() failed, so we have to
					 * fallback to normal rcp
					 */
					try_normal_rcp(prev_argc, prev_argv);
				} else {
					rem = sock;
					session_key = &cred->keyblock;
					if (kcmd_proto == KCMD_NEW_PROTOCOL) {
						/* CSTYLED */
						status = krb5_auth_con_getlocalsubkey(bsd_context, auth_context, &session_key);
						if (status) {
							com_err("rcp", status,
							    "determining "
							    "subkey for "
							    "session");
							exit(1);
						}
						if (!session_key) {
							com_err("rcp", 0,
							    "no subkey "
							    "negotiated for"
							    " connection");
							exit(1);
						}
					}
					eblock.crypto_entry =
					    session_key->enctype;
					eblock.key =
					    (krb5_keyblock *)session_key;

					init_encrypt(encrypt_flag,
					    bsd_context, kcmd_proto,
					    &desinbuf, &desoutbuf, CLIENT,
					    &eblock);
					if (encrypt_flag > 0) {
						char *s = gettext("This rcp "
						    "session is using "
						    "encryption for all "
						    "data transmissions."
						    "\r\n");

						(void) write(2, s, strlen(s));
					}
				}
				if (response() < 0)
					exit(1);

				} else {

					/*
					 * ACL support: try to find out if the
					 * remote site is running acl cognizant
					 * version of rcp. A special binary
					 * name is used for this purpose.
					 */
					aclflag = 1;
					acl_aclflag = 1;

					/*
					 * First see if the remote side will
					 * support both aclent_t and ace_t
					 * acl's?
					 */
					(void) snprintf(bp, buffersize,
					    "%s -tZ %s",
					    cmd_sunw, targ);
					rem = rcmd_af(&host, portnumber,
					    pwd->pw_name,
					    tuser ? tuser : pwd->pw_name,
					    bp, 0, AF_INET6);
					if (rem < 0)
						exit(1);

					/*
					 * This is similar to routine
					 * response(). If response is not ok,
					 * treat the other side as non-acl rcp.
					 */
					if (read(rem, &resp, sizeof (resp))
					    != sizeof (resp))
						lostconn();
					if (resp != 0) {
						acl_aclflag = 0;
						(void) snprintf(bp, buffersize,
						    "%s -t %s", cmd_sunw, targ);

						(void) close(rem);
						host = thost;
						rem = rcmd_af(&host, portnumber,
						    pwd->pw_name,
						    tuser ? tuser :
						    pwd->pw_name,
						    bp, 0, AF_INET6);
						if (rem < 0)
							exit(1);

						if (read(rem, &resp,
						    sizeof (resp))
						    != sizeof (resp))
							lostconn();
						if (resp != 0) {
							/*
							 * Not OK:
							 * The other side is
							 * running non-acl rcp.
							 * Try again with
							 * normal stuff.
							 */
							aclflag = 0;
							(void) snprintf(bp,
							    buffersize,
							    "%s -t %s", cmd,
							    targ);
							(void) close(rem);
							host = thost;
							rem = rcmd_af(&host,
							    portnumber,
							    pwd->pw_name,
							    tuser ? tuser :
							    pwd->pw_name, bp, 0,
							    AF_INET6);
							if (rem < 0)
								exit(1);
							if (response() < 0)
								exit(1);
						}
					}
					/* everything should be fine now */
					(void) setuid(userid);

				}
			}
			source(1, argv + i);
		}
	}
}

static void
tolocal(int argc, char *argv[])
{
	int i;
	char *host, *src, *suser, *lhost;
	char resp;
	size_t buffersize;
	char bp[RCP_BUFSIZE];
	krb5_creds *cred;
	char *arglist[MAXARGS+1];
	buffersize = RCP_BUFSIZE;

	for (i = 0; i < argc - 1; i++) {
		if (!(src = colon(argv[i]))) {	/* local to local */
			(void) addargs(arglist, "cp",
			    iamrecursive ? "-r" : "", pflag ? "-p" : "",
			    zflag ? "-z" : "", argv[i], argv[argc - 1],
			    (char *)NULL);
			if (susystem(_PATH_CP, arglist) == -1)
				errs++;
			continue;
		}
		*src++ = 0;
		if (*src == 0)
			src = ".";
		host = search_char((unsigned char *)argv[i], '@');
		if (host) {
			*host++ = 0;
			suser = argv[i];
			if (*suser == '\0') {
				suser = pwd->pw_name;
			} else if (!okname(suser)) {
				errs++;
				continue;
			}
		} else {
			host = argv[i];
			suser = pwd->pw_name;
		}
		host = removebrackets(host);
		lhost = host;
		if (krb5auth_flag > 0) {

			(void) snprintf(bp, buffersize, "%s -f %s", cmd, src);
			authopts = AP_OPTS_MUTUAL_REQUIRED;
			status = kcmd(&sock, &host,
			    portnumber,
			    pwd->pw_name, suser,
			    bp,
			    0,	/* &rfd2 */
			    "host",
			    krb_realm,
			    bsd_context,
			    &auth_context,
			    &cred,
			    0,	/* No seq # */
			    0,	/* No server seq # */
			    authopts,
			    1,	/* Not any port # */
			    &kcmd_proto);
			if (status) {
				/*
				 * If new protocol requested, we dont
				 * fallback to less secure ones.
				 */
				if (kcmd_proto == KCMD_NEW_PROTOCOL) {
					(void) fprintf(stderr,
					    gettext("rcp: kcmdv2 "
					    "to host %s failed - %s\n"
					    "Fallback to normal rcp denied."),
					    host, error_message(status));
					exit(1);
				}
				if (status != -1) {
					(void) fprintf(stderr,
					    gettext("rcp: kcmd "
					    "to host %s failed - %s,\n"
					    "trying normal rcp...\n\n"),
					    host, error_message(status));
				} else {
					(void) fprintf(stderr,
					    gettext("trying normal rcp...\n"));
				}
				/*
				 * kcmd() failed, so we have to
				 * fallback to normal rcp
				 */
				try_normal_rcp(prev_argc, prev_argv);
			} else {
				rem = sock;
				session_key = &cred->keyblock;
				if (kcmd_proto == KCMD_NEW_PROTOCOL) {
					status = krb5_auth_con_getlocalsubkey(
					    bsd_context, auth_context,
					    &session_key);
					if (status) {
						com_err("rcp", status,
						    "determining "
						    "subkey for session");
						exit(1);
					}
					if (!session_key) {
						com_err("rcp", 0,
						    "no subkey negotiated"
						    " for connection");
						exit(1);
					}
				}
				eblock.crypto_entry = session_key->enctype;
				eblock.key = (krb5_keyblock *)session_key;

				init_encrypt(encrypt_flag, bsd_context,
				    kcmd_proto,
				    &desinbuf, &desoutbuf, CLIENT,
				    &eblock);
				if (encrypt_flag > 0) {
					char *s = gettext("This rcp "
					    "session is using DES "
					    "encryption for all "
					    "data transmissions."
					    "\r\n");

					(void) write(2, s, strlen(s));
				}
			}

		}
		else
		{

			/*
			 * ACL support: try to find out if the remote site is
			 * running acl cognizant version of rcp.
			 */
			aclflag = 1;
			acl_aclflag = 1;

			(void) snprintf(bp, buffersize, "%s -Zf %s", cmd_sunw,
			    src);
			rem = rcmd_af(&host, portnumber, pwd->pw_name, suser,
			    bp, 0, AF_INET6);

			if (rem < 0) {
				++errs;
				continue;
			}

			/*
			 * The remote system is supposed to send an ok response.
			 * If there are any data other than "ok", it must be
			 * error messages from the remote system. We can assume
			 * the remote system is running non-acl version rcp.
			 */
			if (read(rem, &resp, sizeof (resp)) != sizeof (resp))
				lostconn();

			if (resp != 0) {

				/*
				 * Try again without ace_acl support
				 */
				acl_aclflag = 0;
				(void) snprintf(bp, buffersize, "%s -f %s",
				    cmd_sunw, src);
				(void) close(rem);
				rem = rcmd_af(&host, portnumber, pwd->pw_name,
				    suser, bp, 0, AF_INET6);

				if (rem < 0) {
					++errs;
					continue;
				}

				if (read(rem, &resp,
				    sizeof (resp)) != sizeof (resp))
					lostconn();

				if (resp != 0) {
					/*
					 * NOT ok:
					 * The other side is running non-acl
					 * rcp. Try again with normal stuff.
					 */
					aclflag = 0;
					(void) snprintf(bp, buffersize,
					    "%s -f %s", cmd, src);
					(void) close(rem);
					host = lhost;
					rem = rcmd_af(&host, portnumber,
					    pwd->pw_name, suser, bp, 0,
					    AF_INET6);
					if (rem < 0) {
						++errs;
						continue;
					}
				}
			}
		}

		sink(1, argv + argc - 1);

		(void) close(rem);
		rem = -1;
	}
}


static void
verifydir(char *cp)
{
	struct stat stb;

	if (stat(cp, &stb) >= 0) {
		if ((stb.st_mode & S_IFMT) == S_IFDIR)
			return;
		errno = ENOTDIR;
	}
	error("rcp: %s: %s.\n", cp, strerror(errno));
	exit(1);
}

static char *
colon(char *cp)
{
	boolean_t is_bracket_open = B_FALSE;

	for (; *cp; ++cp) {
		if (*cp == '[')
			is_bracket_open = B_TRUE;
		else if (*cp == ']')
			is_bracket_open = B_FALSE;
		else if (*cp == ':' && !is_bracket_open)
			return (cp);
		else if (*cp == '/')
			return (0);
	}
	return (0);
}

static int
okname(char *cp0)
{
	register char *cp = cp0;
	register int c;

	do {
		c = *cp;
		if (c & 0200)
			goto bad;
		if (!isalpha(c) && !isdigit(c) && c != '_' && c != '-')
			goto bad;
	} while (*++cp);
	return (1);
bad:
	(void) fprintf(stderr, "rcp: invalid user name %s\n", cp0);
	return (0);
}


static char *
removebrackets(char *str)
{
	char *newstr = str;

	if ((str[0] == '[') && (str[strlen(str) - 1] == ']')) {
		newstr = str + 1;
		str[strlen(str) - 1] = '\0';
	}
	return (newstr);
}

static int
susystem(char *path, char **arglist)
{
	int status, pid, w;
	register void (*istat)(), (*qstat)();
	int pfds[2];
	char buf[BUFSIZ];
	int cnt;
	boolean_t seen_stderr_traffic;

	/*
	 * Due to the fact that rcp uses rsh to copy between 2 remote
	 * machines, rsh doesn't return the exit status of the remote
	 * command, and we can't modify the rcmd protocol used by rsh
	 * (for interoperability reasons) we use the hack of using any
	 * output on stderr as indication that an error occurred and
	 * that we should return a non-zero error code.
	 */

	if (pipe(pfds) == -1) {
		(void) fprintf(stderr, "Couldn't create pipe: %s\n",
		    strerror(errno));
		return (-1);
	}

	if ((pid = vfork()) < 0) {
		(void) close(pfds[0]);
		(void) close(pfds[1]);
		(void) fprintf(stderr, "Couldn't fork child process: %s\n",
		    strerror(errno));
		return (-1);
	} else if (pid == 0) {
		/*
		 * Child.
		 */
		(void) close(pfds[0]);
		/*
		 * Send stderr messages down the pipe so that we can detect
		 * them in the parent process.
		 */
		if (pfds[1] != STDERR_FILENO) {
			(void) dup2(pfds[1], STDERR_FILENO);
			(void) close(pfds[1]);
		}
		/*
		 * This shell does not inherit the additional privilege
		 * we have in our Permitted set.
		 */
		(void) execv(path, arglist);
		_exit(127);
	}
	/*
	 * Parent.
	 */
	istat = signal(SIGINT, SIG_IGN);
	qstat = signal(SIGQUIT, SIG_IGN);

	(void) close(pfds[1]);
	seen_stderr_traffic = B_FALSE;
	while ((cnt = read(pfds[0], buf, sizeof (buf))) > 0) {
		/*
		 * If any data is read from the pipe the child process
		 * has output something on stderr so we set the boolean
		 * 'seen_stderr_traffic' to true, which will cause the
		 * function to return -1.
		 */
		(void) write(STDERR_FILENO, buf, cnt);
		seen_stderr_traffic = B_TRUE;
	}
	(void) close(pfds[0]);
	while ((w = wait(&status)) != pid && w != -1)
		;
	if (w == -1)
		status = -1;

	(void) signal(SIGINT, istat);
	(void) signal(SIGQUIT, qstat);

	return (seen_stderr_traffic ? -1 : status);
}

static void
source(int argc, char *argv[])
{
	struct stat stb;
	static BUF buffer;
	BUF *bp;
	int x, readerr, f, amt;
	char *last, *name, buf[RCP_BUFSIZE];
	off_t off, size, i;
	ssize_t cnt;
	struct linger lingerbuf;

	for (x = 0; x < argc; x++) {
		name = argv[x];
		if ((f = open(name, O_RDONLY, 0)) < 0) {
			error("rcp: %s: %s\n", name, strerror(errno));
			continue;
		}
		if (fstat(f, &stb) < 0)
			goto notreg;
		switch (stb.st_mode&S_IFMT) {

		case S_IFREG:
			break;

		case S_IFDIR:
			if (iamrecursive) {
				(void) close(f);
				rsource(name, &stb);
				continue;
			}
			/* FALLTHROUGH */
		default:
notreg:
			(void) close(f);
			error("rcp: %s: not a plain file\n", name);
			continue;
		}
		last = rindex(name, '/');
		if (last == 0)
			last = name;
		else
			last++;
		if (pflag) {
			time_t mtime, atime;
			time_t now;

			/*
			 * Make it compatible with possible future
			 * versions expecting microseconds.
			 */
			mtime = stb.st_mtime;
			atime = stb.st_atime;

			if ((mtime < 0) || (atime < 0)) {
				now = time(NULL);

				if (mtime < 0) {
					mtime = now;
					error("negative modification time on "
					    "%s; not preserving\n", name);
				}
				if (atime < 0) {
					atime = now;
					error("negative access time on "
					    "%s; not preserving\n", name);
				}
			}
			(void) snprintf(buf, sizeof (buf), "T%ld 0 %ld 0\n",
			    mtime, atime);
			(void) desrcpwrite(rem, buf, strlen(buf));
			if (response() < 0) {
				(void) close(f);
				continue;
			}
		}
		(void) snprintf(buf, sizeof (buf), "C%04o %lld %s\n",
		    (uint_t)(stb.st_mode & 07777), (longlong_t)stb.st_size,
		    last);
		(void) desrcpwrite(rem, buf, strlen(buf));
		if (response() < 0) {
			(void) close(f);
			continue;
		}

		/* ACL support: send */
		if (aclflag | acl_aclflag) {
			/* get acl from f and send it over */
			if (sendacl(f) == ACL_FAIL) {
				(void) close(f);
				continue;
			}
		}
		if ((krb5auth_flag > 0) || (iamremote == 1)) {
			bp = allocbuf(&buffer, f, RCP_BUFSIZE);
			if (bp == NULLBUF) {
				(void) close(f);
				continue;
			}
			readerr = 0;
			for (i = 0; i < stb.st_size; i += bp->cnt) {
				amt = bp->cnt;
				if (i + amt > stb.st_size)
					amt = stb.st_size - i;
				if (readerr == 0 &&
				    read(f, bp->buf, amt) != amt)
					readerr = errno;
				(void) desrcpwrite(rem, bp->buf, amt);
			}
			(void) close(f);
			if (readerr == 0)
				(void) desrcpwrite(rem, "", 1);
			else
				error("rcp: %s: %s\n", name,
				    error_message(readerr));
		} else {
			cnt = off = 0;
			size = stb.st_size;
			while (size != 0) {
				amt = MIN(size, SENDFILE_SIZE);
				cnt = sendfile(rem, f, &off, amt);
				if (cnt == -1) {
					if (errno == EINTR) {
						continue;
					} else {
						break;
					}
				}
				if (cnt == 0)
					break;
				size -= cnt;
			}
			if (cnt < 0) {
				error("rcp: %s: %s\n", name, strerror(errno));
			} else if (cnt == 0 && size != 0) {
				error("rcp: %s: unexpected end of file\n",
				    name);
				lingerbuf.l_onoff = 1;
				lingerbuf.l_linger = 0;
				(void) setsockopt(rem, SOL_SOCKET, SO_LINGER,
				    &lingerbuf, sizeof (lingerbuf));
				/*
				 * When response() (see below) is invoked it
				 * tries to read data from closed handle which
				 * triggers error and lostconn() function.
				 * lostconn() terminates the program with
				 * appropriate message.
				 */
				(void) close(rem);
				rem = -1;
			} else {
				(void) write(rem, "", 1);
			}
			(void) close(f);
		}
		(void) response();
	}
}


static void
rsource(char *name, struct stat *statp)
{
	DIR *d;
	struct dirent *dp;
	char *last, *vect[1];
	char path[MAXPATHLEN];

	if (!(d = opendir(name))) {
		error("rcp: %s: %s\n", name, strerror(errno));
		return;
	}
	last = rindex(name, '/');
	if (last == 0)
		last = name;
	else
		last++;
	if (pflag) {
		(void) snprintf(path, sizeof (path), "T%ld 0 %ld 0\n",
		    statp->st_mtime, statp->st_atime);
		(void) desrcpwrite(rem, path, strlen(path));
		if (response() < 0) {
			(void) closedir(d);
			return;
		}
	}
	(void) snprintf(path, sizeof (path), "D%04o %d %s\n",
	    (uint_t)(statp->st_mode & 07777), 0, last);
	(void) desrcpwrite(rem, path, strlen(path));

	/* acl support for directory */
	if (aclflag) {
		/* get acl from f and send it over */
		if (sendacl(d->dd_fd) == ACL_FAIL) {
			(void) closedir(d);
			return;
		}
	}

	if (response() < 0) {
		(void) closedir(d);
		return;
	}

	while (dp = readdir(d)) {
		if (dp->d_ino == 0)
			continue;
		if ((strcmp(dp->d_name, ".") == 0) ||
		    (strcmp(dp->d_name, "..") == 0))
			continue;
		if ((uint_t)strlen(name) + 1 + strlen(dp->d_name) >=
		    MAXPATHLEN - 1) {
			error("%s/%s: name too long.\n", name, dp->d_name);
			continue;
		}
		(void) snprintf(path, sizeof (path), "%s/%s",
		    name, dp->d_name);
		vect[0] = path;
		source(1, vect);
	}
	(void) closedir(d);
	(void) desrcpwrite(rem, "E\n", 2);
	(void) response();
}

static int
response(void)
{
	register char *cp;
	char ch, resp, rbuf[RCP_BUFSIZE];

	if (desrcpread(rem, &resp, 1) != 1)
		lostconn();
	cp = rbuf;
	switch (resp) {
	case 0:				/* ok */
		return (0);
	default:
		*cp++ = resp;
		/* FALLTHROUGH */
	case 1:				/* error, followed by err msg */
	case 2:				/* fatal error, "" */
		do {
			if (desrcpread(rem, &ch, sizeof (ch)) != sizeof (ch))
				lostconn();
			*cp++ = ch;
		} while (cp < &rbuf[RCP_BUFSIZE] && ch != '\n');

		if (!iamremote)
			(void) write(STDERR_FILENO, rbuf, cp - rbuf);
		++errs;
		if (resp == 1)
			return (-1);
		exit(1);
	}
	/*NOTREACHED*/
}

static void
lostconn(void)
{
	if (!iamremote)
		(void) fprintf(stderr, "rcp: lost connection\n");
	exit(1);
}


static void
sink(int argc, char *argv[])
{
	char *cp;
	static BUF buffer;
	struct stat stb;
	struct timeval tv[2];
	BUF *bp;
	off_t i, j;
	char ch, *targ, *why;
	int amt, count, exists, first, mask, mode;
	off_t size;
	int ofd, setimes, targisdir, wrerr;
	char *np, *vect[1], buf[RCP_BUFSIZE];
	char *namebuf = NULL;
	size_t namebuf_sz = 0;
	size_t need;

#define	atime	tv[0]
#define	mtime	tv[1]
#define	SCREWUP(str)	{ why = str; goto screwup; }

	setimes = targisdir = 0;
	mask = umask(0);
	if (!pflag)
		(void) umask(mask);
	if (argc != 1) {
		error("rcp: ambiguous target\n");
		exit(1);
	}
	targ = *argv;
	if (targetshouldbedirectory)
		verifydir(targ);
	(void) desrcpwrite(rem, "", 1);

	if (stat(targ, &stb) == 0 && (stb.st_mode & S_IFMT) == S_IFDIR)
		targisdir = 1;
	for (first = 1; ; first = 0) {
		cp = buf;
		if (desrcpread(rem, cp, 1) <= 0) {
			if (namebuf != NULL)
				free(namebuf);
			return;
		}

		if (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		do {
			if (desrcpread(rem, &ch, sizeof (ch)) != sizeof (ch))
				SCREWUP("lost connection");
			*cp++ = ch;
		} while (cp < &buf[RCP_BUFSIZE - 1] && ch != '\n');
		*cp = 0;

		if (buf[0] == '\01' || buf[0] == '\02') {
			if (iamremote == 0)
				(void) write(STDERR_FILENO, buf + 1,
				    strlen(buf + 1));
			if (buf[0] == '\02')
				exit(1);
			errs++;
			continue;
		}
		if (buf[0] == 'E') {
			(void) desrcpwrite(rem, "", 1);
			if (namebuf != NULL)
				free(namebuf);
			return;
		}

		if (ch == '\n')
			*--cp = 0;
		cp = buf;
		if (*cp == 'T') {
			setimes++;
			cp++;
			mtime.tv_sec = strtol(cp, &cp, 0);
			if (*cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			mtime.tv_usec = strtol(cp, &cp, 0);
			if (*cp++ != ' ')
				SCREWUP("mtime.usec not delimited");
			atime.tv_sec = strtol(cp, &cp, 0);
			if (*cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			atime.tv_usec = strtol(cp, &cp, 0);
			if (*cp++ != '\0')
				SCREWUP("atime.usec not delimited");
			(void) desrcpwrite(rem, "", 1);
			continue;
		}
		if (*cp != 'C' && *cp != 'D') {
			/*
			 * Check for the case "rcp remote:foo\* local:bar".
			 * In this case, the line "No match." can be returned
			 * by the shell before the rcp command on the remote is
			 * executed so the ^Aerror_message convention isn't
			 * followed.
			 */
			if (first) {
				error("%s\n", cp);
				exit(1);
			}
			SCREWUP("expected control record")
		}
		mode = 0;
		for (++cp; cp < buf + 5; cp++) {
			if (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			mode = (mode << 3) | (*cp - '0');
		}
		if (*cp++ != ' ')
			SCREWUP("mode not delimited");
		size = 0;
		while (isdigit(*cp))
			size = size * 10 + (*cp++ - '0');
		if (*cp++ != ' ')
			SCREWUP("size not delimited");
		if (targisdir) {
			need = strlen(targ) + sizeof ("/") + strlen(cp);
			if (need > namebuf_sz) {
				if ((namebuf = realloc(namebuf, need)) ==
				    NULL) {
					error("rcp: out of memory\n");
					exit(1);
				}
				namebuf_sz = need;
			}
			(void) snprintf(namebuf, need, "%s%s%s", targ,
			    *targ ? "/" : "", cp);
			np = namebuf;
		} else {
			np = targ;
		}

		exists = stat(np, &stb) == 0;
		if (buf[0] == 'D') {
			if (exists) {
				if ((stb.st_mode&S_IFMT) != S_IFDIR) {
					if (aclflag | acl_aclflag) {
						/*
						 * consume acl in the pipe
						 * fd = -1 to indicate the
						 * special case
						 */
						if (recvacl(-1, exists, pflag)
						    == ACL_FAIL) {
							goto bad;
						}
					}
					errno = ENOTDIR;
					goto bad;
				}
				if (pflag)
					(void) chmod(np, mode);
			} else if (mkdir(np, mode) < 0) {
				if (aclflag) {
					/* consume acl in the pipe */
					(void) recvacl(-1, exists, pflag);
				}
				goto bad;
			}

			/* acl support for directories */
			if (aclflag | acl_aclflag) {
				int dfd;

				if ((dfd = open(np, O_RDONLY)) == -1)
					goto bad;

				/* get acl and set it to ofd */
				if (recvacl(dfd, exists, pflag) == ACL_FAIL) {
					(void) close(dfd);
					if (!exists)
						(void) rmdir(np);
					goto bad;
				}
				(void) close(dfd);
			}

			vect[0] = np;
			sink(1, vect);
			if (setimes) {
				setimes = 0;
				if (utimes(np, tv) < 0)
					error("rcp: can't set "
					    "times on %s: %s\n",
					    np, strerror(errno));
			}
			continue;
		}

		if ((ofd = open(np, O_WRONLY|O_CREAT, mode)) < 0) {
bad:
			error("rcp: %s: %s\n", np, strerror(errno));
			continue;
		}

		/*
		 * If the output file exists we have to force zflag off
		 * to avoid erroneously seeking past old data.
		 */
		zopen(ofd, zflag && !exists);

		if (exists && pflag)
			(void) fchmod(ofd, mode);

		(void) desrcpwrite(rem, "", 1);

		/*
		 * ACL support: receiving
		 */
		if (aclflag | acl_aclflag) {
			/* get acl and set it to ofd */
			if (recvacl(ofd, exists, pflag) == ACL_FAIL) {
				(void) close(ofd);
				if (!exists)
					(void) unlink(np);
				continue;
			}
		}

		if ((bp = allocbuf(&buffer, ofd, RCP_BUFSIZE)) == 0) {
			(void) close(ofd);
			continue;
		}
		cp = bp->buf;
		count = 0;
		wrerr = 0;
		for (i = 0; i < size; i += RCP_BUFSIZE) {
			amt = RCP_BUFSIZE;
			if (i + amt > size)
				amt = size - i;
			count += amt;
			do {
				j = desrcpread(rem, cp, amt);
				if (j <= 0) {
					int sverrno = errno;

					/*
					 * Connection to supplier lost.
					 * Truncate file to correspond
					 * to amount already transferred.
					 *
					 * Note that we must call ftruncate()
					 * before any call to error() (which
					 * might result in a SIGPIPE and
					 * sudden death before we have a chance
					 * to correct the file's size).
					 */
					size = lseek(ofd, 0, SEEK_CUR);
					if ((ftruncate(ofd, size)  == -1) &&
					    (errno != EINVAL) &&
					    (errno != EACCES))
#define		TRUNCERR	"rcp: can't truncate %s: %s\n"
						error(TRUNCERR, np,
						    strerror(errno));
					error("rcp: %s\n",
					    j ? strerror(sverrno) :
					    "dropped connection");
					(void) close(ofd);
					exit(1);
				}
				amt -= j;
				cp += j;
			} while (amt > 0);
			if (count == bp->cnt) {
				cp = bp->buf;
				if (wrerr == 0 &&
				    zwrite(ofd, cp, count) < 0)
					wrerr++;
				count = 0;
			}
		}
		if (count != 0 && wrerr == 0 &&
		    zwrite(ofd, bp->buf, count) < 0)
			wrerr++;
		if (zclose(ofd) < 0)
			wrerr++;

		if ((ftruncate(ofd, size)  == -1) && (errno != EINVAL) &&
		    (errno != EACCES)) {
			error(TRUNCERR, np, strerror(errno));
		}
		(void) close(ofd);
		(void) response();
		if (setimes) {
			setimes = 0;
			if (utimes(np, tv) < 0)
				error("rcp: can't set times on %s: %s\n",
				    np, strerror(errno));
		}
		if (wrerr)
			error("rcp: %s: %s\n", np, strerror(errno));
		else
			(void) desrcpwrite(rem, "", 1);
	}
screwup:
	error("rcp: protocol screwup: %s\n", why);
	exit(1);
}

#ifndef roundup
#define	roundup(x, y)   ((((x)+((y)-1))/(y))*(y))
#endif /* !roundup */

static BUF *
allocbuf(BUF *bp, int fd, int blksize)
{
	struct stat stb;
	int size;

	if (fstat(fd, &stb) < 0) {
		error("rcp: fstat: %s\n", strerror(errno));
		return (0);
	}
	size = roundup(stb.st_blksize, blksize);
	if (size == 0)
		size = blksize;
	if (bp->cnt < size) {
		if (bp->buf != 0)
			free(bp->buf);
		bp->buf = (char *)malloc((uint_t)size);
		if (!bp->buf) {
			error("rcp: malloc: out of memory\n");
			return (0);
		}
	}
	bp->cnt = size;
	return (bp);
}

static void
usage(void)
{
	(void) fprintf(stderr, "%s: \t%s\t%s", gettext("Usage"),
	    gettext("\trcp [-p] [-a] [-x] [-k realm] [-PN / -PO] "
#ifdef DEBUG
	    "[-D port] "
#endif /* DEBUG */
	    "f1 f2; or:\n"),
	    gettext("\trcp [-r] [-p] [-a] [-x] "
#ifdef DEBUG
	    "[-D port] "
#endif /* DEBUG */
	    "[-k realm] [-PN / -PO] f1...fn d2\n"));
	exit(1);
}


/*
 * sparse file support
 */

static off_t zbsize;
static off_t zlastseek;

/* is it ok to try to create holes? */
static void
zopen(int fd, int flag)
{
	struct stat st;

	zbsize = 0;
	zlastseek = 0;

	if (flag &&
	    fstat(fd, &st) == 0 &&
	    (st.st_mode & S_IFMT) == S_IFREG)
		zbsize = st.st_blksize;
}

/* write and/or seek */
static int
zwrite(int fd, char *buf, int nbytes)
{
	off_t block = zbsize ? zbsize : nbytes;

	do {
		if (block > nbytes)
			block = nbytes;
		nbytes -= block;

		if (!zbsize || notzero(buf, block)) {
			register int n, count = block;

			do {
				if ((n = write(fd, buf, count)) < 0)
					return (-1);
				buf += n;
			} while ((count -= n) > 0);
			zlastseek = 0;
		} else {
			if (lseek(fd, (off_t)block, SEEK_CUR) < 0)
				return (-1);
			buf += block;
			zlastseek = 1;
		}
	} while (nbytes > 0);

	return (0);
}

/* write last byte of file if necessary */
static int
zclose(int fd)
{
	zbsize = 0;

	if (zlastseek && (lseek(fd, (off_t)-1, SEEK_CUR) < 0 ||
	    zwrite(fd, "", 1) < 0))
		return (-1);
	else
		return (0);
}

/* return true if buffer is not all zeros */
static int
notzero(char *p, int n)
{
	register int result = 0;

	while ((int)p & 3 && --n >= 0)
		result |= *p++;

	while ((n -= 4 * sizeof (int)) >= 0) {
		/* LINTED */
		result |= ((int *)p)[0];
		/* LINTED */
		result |= ((int *)p)[1];
		/* LINTED */
		result |= ((int *)p)[2];
		/* LINTED */
		result |= ((int *)p)[3];
		if (result)
			return (result);
		p += 4 * sizeof (int);
	}
	n += 4 * sizeof (int);

	while (--n >= 0)
		result |= *p++;

	return (result);
}

/*
 * New functions to support ACLs
 */

/*
 * Get acl from f and send it over.
 * ACL record includes acl entry count, acl text length, and acl text.
 */
static int
sendacl(int f)
{
	int		aclcnt;
	char		*acltext;
	char		buf[BUFSIZ];
	acl_t		*aclp;
	char		acltype;
	int		aclerror;
	int		trivial;


	aclerror = facl_get(f, ACL_NO_TRIVIAL, &aclp);
	if (aclerror != 0) {
		error("can't retrieve ACL: %s \n", acl_strerror(aclerror));
		return (ACL_FAIL);
	}

	/*
	 * if acl type is not ACLENT_T and were operating in acl_aclflag == 0
	 * then don't do the malloc and facl(fd, getcntcmd,...);
	 * since the remote side doesn't support alternate style ACL's.
	 */

	if (aclp && (acl_type(aclp) != ACLENT_T) && (acl_aclflag == 0)) {
		aclcnt = MIN_ACL_ENTRIES;
		acltype = 'A';
		trivial = ACL_IS_TRIVIAL;
	} else {

		aclcnt = (aclp != NULL) ? acl_cnt(aclp) : 0;

		if (aclp) {
			acltype = (acl_type(aclp) != ACLENT_T) ? 'Z' : 'A';
			aclcnt = acl_cnt(aclp);
			trivial = (acl_flags(aclp) & ACL_IS_TRIVIAL);
		} else {
			acltype = 'A';
			aclcnt = MIN_ACL_ENTRIES;
			trivial = ACL_IS_TRIVIAL;
		}

	}

	/* send the acl count over */
	(void) snprintf(buf, sizeof (buf), "%c%d\n", acltype, aclcnt);
	(void) desrcpwrite(rem, buf, strlen(buf));

	/*
	 * only send acl when we have an aclp, which would
	 * imply its not trivial.
	 */
	if (aclp && (trivial != ACL_IS_TRIVIAL)) {
		acltext = acl_totext(aclp, 0);
		if (acltext == NULL) {
			error("rcp: failed to convert to text\n");
			acl_free(aclp);
			return (ACL_FAIL);
		}

		/* send ACLs over: send the length first */
		(void) snprintf(buf, sizeof (buf), "%c%d\n",
		    acltype, strlen(acltext));

		(void) desrcpwrite(rem, buf, strlen(buf));
		(void) desrcpwrite(rem, acltext, strlen(acltext));
		free(acltext);
		if (response() < 0) {
			acl_free(aclp);
			return (ACL_FAIL);
		}

	}

	if (aclp)
		acl_free(aclp);
	return (ACL_OK);
}

/*
 * Use this routine to get acl entry count and acl text size (in bytes)
 */
static int
getaclinfo(int *cnt, int *acltype)
{
	char		buf[BUFSIZ];
	char		*cp;
	char		ch;

	/* get acl count */
	cp = buf;
	if (desrcpread(rem, cp, 1) <= 0)
		return (ACL_FAIL);

	switch (*cp++) {
	case 'A':
		*acltype = 0;
		break;
	case 'Z':
		*acltype = 1;
		break;
	default:
		error("rcp: expect an ACL record, but got %c\n", *cp);
		return (ACL_FAIL);
	}
	do {
		if (desrcpread(rem, &ch, sizeof (ch)) != sizeof (ch)) {
			error("rcp: lost connection ..\n");
			return (ACL_FAIL);
		}
		*cp++ = ch;
	} while (cp < &buf[BUFSIZ - 1] && ch != '\n');
	if (ch != '\n') {
		error("rcp: ACL record corrupted \n");
		return (ACL_FAIL);
	}
	cp = &buf[1];
	*cnt = strtol(cp, &cp, 0);
	if (*cp != '\n') {
		error("rcp: ACL record corrupted \n");
		return (ACL_FAIL);
	}
	return (ACL_OK);
}


/*
 * Receive acl from the pipe and set it to f
 */
static int
recvacl(int f, int exists, int preserve)
{
	int		aclcnt;		/* acl entry count */
	int		aclsize;	/* acl text length */
	int		j;
	char		*tp;
	char		*acltext;	/* external format */
	acl_t		*aclp;
	int		acltype;
	int		min_entries;
	int		aclerror;

	/* get acl count */
	if (getaclinfo(&aclcnt, &acltype) != ACL_OK)
		return (ACL_FAIL);

	if (acltype == 0) {
		min_entries = MIN_ACL_ENTRIES;
	} else {
		min_entries = 1;
	}

	if (aclcnt > min_entries) {
		/* get acl text size */
		if (getaclinfo(&aclsize, &acltype) != ACL_OK)
			return (ACL_FAIL);
		if ((acltext = malloc(aclsize + 1)) == NULL) {
			error("rcp: cant allocate memory: %d\n", aclsize);
			return (ACL_FAIL);
		}

		tp = acltext;
		do {
			j = desrcpread(rem, tp, aclsize);
			if (j <= 0) {
				error("rcp: %s\n", j ? strerror(errno) :
				    "dropped connection");
				exit(1);
			}
			aclsize -= j;
			tp += j;
		} while (aclsize > 0);
		*tp = '\0';

		if (preserve || !exists) {
			aclerror = acl_fromtext(acltext, &aclp);
			if (aclerror != 0) {
				error("rcp: failed to parse acl : %s\n",
				    acl_strerror(aclerror));
				free(acltext);
				return (ACL_FAIL);
			}

			if (f != -1) {
				if (facl_set(f, aclp) < 0) {
					error("rcp: failed to set acl\n");
					acl_free(aclp);
					free(acltext);
					return (ACL_FAIL);
				}
			}
			/* -1 means that just consume the data in the pipe */
			acl_free(aclp);
		}
		free(acltext);
		(void) desrcpwrite(rem, "", 1);
	}
	return (ACL_OK);
}


static char *
search_char(unsigned char *cp, unsigned char chr)
{
	int	len;

	while (*cp) {
		if (*cp == chr)
			return ((char *)cp);
		if ((len = mblen((char *)cp, MB_CUR_MAX)) <= 0)
			len = 1;
		cp += len;
	}
	return (0);
}


static int
desrcpread(int fd, char *buf, int len)
{
	return ((int)desread(fd, buf, len, 0));
}

static int
desrcpwrite(int fd, char *buf, int len)
{
	/*
	 * Note that rcp depends on the same file descriptor being both
	 * input and output to the remote side.  This is bogus, especially
	 * when rcp is being run by a rsh that pipes. Fix it here because
	 * it would require significantly more work in other places.
	 * --hartmans 1/96
	 */

	if (fd == 0)
		fd = 1;
	return ((int)deswrite(fd, buf, len, 0));
}

static char **
save_argv(int argc, char **argv)
{
	int i;

	char **local_argv = (char **)calloc((unsigned)argc + 1,
	    (unsigned)sizeof (char *));

	/*
	 * allocate an extra pointer, so that it is initialized to NULL and
	 * execv() will work
	 */
	for (i = 0; i < argc; i++) {
		local_argv[i] = strsave(argv[i]);
	}

	return (local_argv);
}

#define	SIZEOF_INADDR sizeof (struct in_addr)

static void
answer_auth(char *config_file, char *ccache_file)
{
	krb5_data pname_data, msg;
	krb5_creds creds, *new_creds;
	krb5_ccache cc;
	krb5_auth_context auth_context = NULL;

	if (config_file) {
		const char *filenames[2];

		filenames[1] = NULL;
		filenames[0] = config_file;
		if (krb5_set_config_files(bsd_context, filenames))
			exit(1);
	}
	(void) memset((char *)&creds, 0, sizeof (creds));

	if (krb5_read_message(bsd_context, (krb5_pointer) &rem, &pname_data))
		exit(1);

	if (krb5_read_message(bsd_context, (krb5_pointer) &rem,
	    &creds.second_ticket))
		exit(1);

	if (ccache_file == NULL) {
		if (krb5_cc_default(bsd_context, &cc))
			exit(1);
	} else {
		if (krb5_cc_resolve(bsd_context, ccache_file, &cc))
			exit(1);
	}

	if (krb5_cc_get_principal(bsd_context, cc, &creds.client))
		exit(1);

	if (krb5_parse_name(bsd_context, pname_data.data, &creds.server))
		exit(1);

	krb5_xfree(pname_data.data);
	if (krb5_get_credentials(bsd_context, KRB5_GC_USER_USER, cc, &creds,
	    &new_creds))
		exit(1);

	if (krb5_mk_req_extended(bsd_context, &auth_context,
	    AP_OPTS_USE_SESSION_KEY, NULL, new_creds, &msg))
		exit(1);

	if (krb5_write_message(bsd_context, (krb5_pointer) & rem, &msg)) {
		krb5_xfree(msg.data);
		exit(1);
	}
	/* setup eblock for des_read and write */
	(void) krb5_copy_keyblock(bsd_context,
	    &new_creds->keyblock, &session_key);

	/* OK process key */
	eblock.crypto_entry = session_key->enctype;
	eblock.key = (krb5_keyblock *)session_key;

	init_encrypt(encrypt_flag, bsd_context, KCMD_OLD_PROTOCOL,
	    &desinbuf, &desoutbuf, CLIENT, &eblock);
	/* cleanup */
	krb5_free_cred_contents(bsd_context, &creds);
	krb5_free_creds(bsd_context, new_creds);
	krb5_xfree(msg.data);
}


static void
try_normal_rcp(int cur_argc, char **cur_argv)
{
	char *target;

	/*
	 * Reset all KRB5 relevant flags and set the
	 * cmd-buffer so that normal rcp works
	 */
	krb5auth_flag = encrypt_flag = encrypt_done = 0;
	cmd = cmd_orig;
	cmd_sunw = cmd_sunw_orig;

	if (cur_argc < 2)
		usage();

	if (cur_argc > 2)
		targetshouldbedirectory = 1;

	rem = -1;

	prev_argc = cur_argc;
	prev_argv = save_argv(cur_argc, cur_argv);

	(void) init_service(krb5auth_flag);

	if (target = colon(cur_argv[cur_argc - 1])) {
		toremote(target, cur_argc, cur_argv);
	} else {
		tolocal(cur_argc, cur_argv);
		if (targetshouldbedirectory)
			verifydir(cur_argv[cur_argc - 1]);
	}
	exit(errs);
	/* NOTREACHED */
}


static int
init_service(int krb5flag)
{
	struct servent *sp;
	boolean_t success = B_FALSE;

	if (krb5flag > 0) {
		sp = getservbyname("kshell", "tcp");
		if (sp == NULL) {
			(void) fprintf(stderr,
			    gettext("rcp: kshell/tcp: unknown service.\n"
			    "trying normal shell/tcp service\n"));
		} else {
			portnumber = sp->s_port;
			success = B_TRUE;
		}
	} else {
		portnumber = htons(IPPORT_CMDSERVER);
		success = B_TRUE;
	}
	return (success);
}

/*PRINTFLIKE1*/
static void
error(char *fmt, ...)
{
	va_list ap;
	char buf[RCP_BUFSIZE];
	char *cp = buf;

	va_start(ap, fmt);
	errs++;
	*cp++ = 1;
	(void) vsnprintf(cp, sizeof (buf) - 1, fmt, ap);
	va_end(ap);

	(void) desrcpwrite(rem, buf, strlen(buf));
	if (iamremote == 0)
		(void) write(2, buf + 1, strlen(buf + 1));
}

static void
addargs(char **arglist, ...)
{
	va_list ap;
	int i = 0;
	char *pm;

	va_start(ap, arglist);
	while (i < MAXARGS && (pm = va_arg(ap, char *)) != NULL)
		if (strcmp(pm, ""))
			arglist[i++] = pm;
	arglist[i] = NULL;
	va_end(ap);
}

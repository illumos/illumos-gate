/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983 Regents of the University of California.
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
 */

#include "defs.h"
#include <string.h>
#include <syslog.h>
#include <k5-int.h>
#include <krb5defs.h>
#include <priv_utils.h>

#define	NHOSTS 100

/*
 * Remote distribution program.
 */

char	*distfile = NULL;
char	Tmpfile[] = "/tmp/rdistXXXXXX";
char	*tmpname = &Tmpfile[5];

int	debug;		/* debugging flag */
int	nflag;		/* NOP flag, just print commands without executing */
int	qflag;		/* Quiet. Don't print messages */
int	options;	/* global options */
int	iamremote;	/* act as remote server for transfering files */

FILE	*fin = NULL;	/* input file pointer */
int	rem = -1;	/* file descriptor to remote source/sink process */
char	host[32];	/* host name */
int	nerrs;		/* number of errors while sending/receiving */
char	user[10];	/* user's name */
char	homedir[128];	/* user's home directory */
char	buf[RDIST_BUFSIZ];	/* general purpose buffer */

struct	passwd *pw;	/* pointer to static area used by getpwent */
struct	group *gr;	/* pointer to static area used by getgrent */

char des_inbuf[2 * RDIST_BUFSIZ];	/* needs to be > largest read size */
char des_outbuf[2 * RDIST_BUFSIZ];	/* needs to be > largest write size */
krb5_data desinbuf, desoutbuf;
krb5_encrypt_block eblock;		/* eblock for encrypt/decrypt */
krb5_context bsd_context = NULL;
krb5_auth_context auth_context;
krb5_creds *cred;
char *krb_cache = NULL;
krb5_flags authopts;
krb5_error_code status;
enum kcmd_proto kcmd_proto = KCMD_NEW_PROTOCOL;

int encrypt_flag = 0;	/* Flag set when encryption is used */
int krb5auth_flag = 0;	/* Flag set, when KERBEROS is enabled */
static profile_options_boolean autologin_option[] = {
	{ "autologin", &krb5auth_flag, 0 },
	{ NULL, NULL, 0 }
};
static int no_krb5auth_flag = 0;

int debug_port = 0;

int retval = 0;
char *krb_realm = NULL;

/* Flag set, if -PN / -PO is specified */
static boolean_t rcmdoption_done = B_FALSE;

static int encrypt_done = 0;	/* Flag set, if -x is specified */
profile_options_boolean option[] = {
	{ "encrypt", &encrypt_flag, 0 },
	{ NULL, NULL, 0 }
};

static char *rcmdproto = NULL;
profile_option_strings rcmdversion[] = {
	{ "rcmd_protocol", &rcmdproto, 0 },
	{ NULL, NULL, 0 }
};

char *realmdef[] = { "realms", NULL, "rdist", NULL };
char *appdef[] = { "appdefaults", "rdist", NULL };

static void usage(void);
static char *prtype(int t);
static void prsubcmd(struct subcmd *s);
static void docmdargs(int nargs, char *args[]);
void prnames();
void prcmd();

int
main(argc, argv)
	int argc;
	char *argv[];
{
	register char *arg;
	int cmdargs = 0;
	char *dhosts[NHOSTS], **hp = dhosts;

	(void) setlocale(LC_ALL, "");

	pw = getpwuid(getuid());
	if (pw == NULL) {
		(void) fprintf(stderr, gettext("%s: Who are you?\n"), argv[0]);
		exit(1);
	}
	strncpy(user, pw->pw_name, sizeof (user));
	user[sizeof (user) - 1] = '\0';
	strncpy(homedir, pw->pw_dir, sizeof (homedir));
	homedir[sizeof (homedir) - 1] = '\0';
	gethostname(host, sizeof (host));

	while (--argc > 0) {
		if ((arg = *++argv)[0] != '-')
			break;
		if ((strcmp(arg, "-Server") == 0))
			iamremote++;
		else while (*++arg) {
			if (strncmp(*argv, "-PO", 3) == 0) {
				if (rcmdoption_done == B_TRUE) {
					(void) fprintf(stderr, gettext("rdist: "
						"Only one of -PN "
						"and -PO allowed.\n"));
					usage();
				}
				kcmd_proto = KCMD_OLD_PROTOCOL;
				krb5auth_flag++;
				rcmdoption_done = B_TRUE;
				break;
			}
			if (strncmp(*argv, "-PN", 3) == 0) {
				if (rcmdoption_done == B_TRUE) {
					(void) fprintf(stderr, gettext("rdist: "
						"Only one of -PN "
						"and -PO allowed.\n"));
					usage();
				}
				kcmd_proto = KCMD_NEW_PROTOCOL;
				krb5auth_flag++;
				rcmdoption_done = B_TRUE;
				break;
			}

			switch (*arg) {
#ifdef DEBUG
			case 'p':
				if (--argc <= 0)
					usage();
				debug_port = htons(atoi(*++argv));
				break;
#endif /* DEBUG */
			case 'k':
				if (--argc <= 0) {
					(void) fprintf(stderr, gettext("rdist: "
						"-k flag must be followed with "
						" a realm name.\n"));
					exit(1);
				}
				if ((krb_realm = strdup(*++argv)) == NULL) {
					(void) fprintf(stderr, gettext("rdist: "
						"Cannot malloc.\n"));
					exit(1);
				}
				krb5auth_flag++;
				break;

			case 'K':
				no_krb5auth_flag++;
				break;

			case 'a':
				krb5auth_flag++;
				break;

			case 'x':
				encrypt_flag++;
				encrypt_done++;
				krb5auth_flag++;
				break;

			case 'f':
				if (--argc <= 0)
					usage();
				distfile = *++argv;
				if (distfile[0] == '-' && distfile[1] == '\0')
					fin = stdin;
				break;

			case 'm':
				if (--argc <= 0)
					usage();
				if (hp >= &dhosts[NHOSTS-2]) {
					(void) fprintf(stderr, gettext("rdist:"
						" too many destination"
						" hosts\n"));
					exit(1);
				}
				*hp++ = *++argv;
				break;

			case 'd':
				if (--argc <= 0)
					usage();
				define(*++argv);
				break;

			case 'D':
				debug++;
				break;

			case 'c':
				cmdargs++;
				break;

			case 'n':
				if (options & VERIFY) {
					printf("rdist: -n overrides -v\n");
					options &= ~VERIFY;
				}
				nflag++;
				break;

			case 'q':
				qflag++;
				break;

			case 'b':
				options |= COMPARE;
				break;

			case 'R':
				options |= REMOVE;
				break;

			case 'v':
				if (nflag) {
					printf("rdist: -n overrides -v\n");
					break;
				}
				options |= VERIFY;
				break;

			case 'w':
				options |= WHOLE;
				break;

			case 'y':
				options |= YOUNGER;
				break;

			case 'h':
				options |= FOLLOW;
				break;

			case 'i':
				options |= IGNLNKS;
				break;

			default:
				usage();
			}
		}
	}
	*hp = NULL;

	mktemp(Tmpfile);

	/*
	 * if the user disables krb5 on the cmdline (-K), then skip
	 * all krb5 setup.
	 *
	 * if the user does not disable krb5 or enable krb5 on the
	 * cmdline, check krb5.conf to see if it should be enabled.
	 */

	if (no_krb5auth_flag) {
		krb5auth_flag = 0;
		encrypt_flag = 0;
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
				com_err("rdist", status,
				    gettext("while initializing krb5"));
				exit(1);
			}
		}

		/* Set up des buffers */
		desinbuf.data = des_inbuf;
		desoutbuf.data = des_outbuf;
		desinbuf.length = sizeof (des_inbuf);
		desoutbuf.length = sizeof (des_outbuf);

		/*
		 * Get our local realm to look up local realm options.
		 */
		status = krb5_get_default_realm(bsd_context, &realmdef[1]);
		if (status) {
			com_err("rdist", status,
				gettext("while getting default realm"));
			exit(1);
		}
		/*
		 * See if encryption should be done for this realm
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

		if ((encrypt_done > 0) || (encrypt_flag > 0)) {
			if (krb5_privacy_allowed() == TRUE) {
				encrypt_flag++;
			} else {
				(void) fprintf(stderr, gettext("rdist: "
						"Encryption not supported.\n"));
				exit(1);
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
				exit(1);
			}
		}
	}

	if (iamremote) {
		setreuid(getuid(), getuid());
		server();
		exit(nerrs != 0);
	}
	if (__init_suid_priv(0, PRIV_NET_PRIVADDR, NULL) == -1) {
		(void) fprintf(stderr,
			"rdist needs to run with sufficient privilege\n");
		exit(1);
	}

	if (cmdargs)
		docmdargs(argc, argv);
	else {
		if (fin == NULL) {
			if (distfile == NULL) {
				if ((fin = fopen("distfile", "r")) == NULL)
					fin = fopen("Distfile", "r");
			} else
				fin = fopen(distfile, "r");
			if (fin == NULL) {
				perror(distfile ? distfile : "distfile");
				exit(1);
			}
		}
		yyparse();
		if (nerrs == 0)
			docmds(dhosts, argc, argv);
	}

	return (nerrs != 0);
}

static void
usage()
{
	printf(gettext("Usage: rdist [-nqbhirvwyDax] [-PN / -PO] "
#ifdef DEBUG
	"[-p port] "
#endif /* DEBUG */
	"[-k realm] [-f distfile] [-d var=value] [-m host] [file ...]\n"));
	printf(gettext("or: rdist [-nqbhirvwyDax] [-PN / -PO] [-p port] "
	"[-k realm] -c source [...] machine[:dest]\n"));
	exit(1);
}

/*
 * rcp like interface for distributing files.
 */
static void
docmdargs(nargs, args)
	int nargs;
	char *args[];
{
	register struct namelist *nl, *prev;
	register char *cp;
	struct namelist *files, *hosts;
	struct subcmd *cmds;
	char *dest;
	static struct namelist tnl = { NULL, NULL };
	int i;

	if (nargs < 2)
		usage();

	prev = NULL;
	for (i = 0; i < nargs - 1; i++) {
		nl = makenl(args[i]);
		if (prev == NULL)
			files = prev = nl;
		else {
			prev->n_next = nl;
			prev = nl;
		}
	}

	cp = args[i];
	if ((dest = index(cp, ':')) != NULL)
		*dest++ = '\0';
	tnl.n_name = cp;
	hosts = expand(&tnl, E_ALL);
	if (nerrs)
		exit(1);

	if (dest == NULL || *dest == '\0')
		cmds = NULL;
	else {
		cmds = makesubcmd(INSTALL);
		cmds->sc_options = options;
		cmds->sc_name = dest;
	}

	if (debug) {
		printf("docmdargs()\nfiles = ");
		prnames(files);
		printf("hosts = ");
		prnames(hosts);
	}
	insert(NULL, files, hosts, cmds);
	docmds(NULL, 0, NULL);
}

/*
 * Print a list of NAME blocks (mostly for debugging).
 */
void
prnames(nl)
	register struct namelist *nl;
{
	printf("( ");
	while (nl != NULL) {
		printf("%s ", nl->n_name);
		nl = nl->n_next;
	}
	printf(")\n");
}

void
prcmd(c)
	struct cmd *c;
{
	extern char *prtype();

	while (c) {
		printf("c_type %s, c_name %s, c_label %s, c_files ",
			prtype(c->c_type), c->c_name,
			c->c_label?  c->c_label : "NULL");
		prnames(c->c_files);
		prsubcmd(c->c_cmds);
		c = c->c_next;
	}
}

static void
prsubcmd(s)
	struct subcmd *s;
{
	extern char *prtype();
	extern char *proptions();

	while (s) {
		printf("sc_type %s, sc_options %d%s, sc_name %s, sc_args ",
			prtype(s->sc_type),
			s->sc_options, proptions(s->sc_options),
			s->sc_name ? s->sc_name : "NULL");
		prnames(s->sc_args);
		s = s->sc_next;
	}
}

char *
prtype(t)
	int t;
{
	switch (t) {
		case EQUAL:
			return ("EQUAL");
		case LP:
			return ("LP");
		case RP:
			return ("RP");
		case SM:
			return ("SM");
		case ARROW:
			return ("ARROW");
		case COLON:
			return ("COLON");
		case DCOLON:
			return ("DCOLON");
		case NAME:
			return ("NAME");
		case STRING:
			return ("STRING");
		case INSTALL:
			return ("INSTALL");
		case NOTIFY:
			return ("NOTIFY");
		case EXCEPT:
			return ("EXCEPT");
		case PATTERN:
			return ("PATTERN");
		case SPECIAL:
			return ("SPECIAL");
		case OPTION:
			return ("OPTION");
	}
	return (NULL);
}

char *
proptions(o)
	int o;
{
	return (printb((unsigned short) o, OBITS));
}

char *
printb(v, bits)
	register char *bits;
	register unsigned short v;
{
	register int i, any = 0;
	register char c;
	char *p = buf;

	bits++;
	if (bits) {

		*p++ = '<';
		while ((i = *bits++) != 0) {
			if (v & (1 << (i-1))) {
				if (any)
					*p++ = ',';
				any = 1;
				for (; (c = *bits) > 32; bits++)
					*p++ = c;
			} else
				for (; *bits > 32; bits++)
					;
		}
		*p++ = '>';
	}

	*p = '\0';
	return (buf);
}

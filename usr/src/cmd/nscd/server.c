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
 * Copyright (c) 1994, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * Simple doors name server cache daemon
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <locale.h>
#include <sys/stat.h>
#include <tsol/label.h>
#include <zone.h>
#include <signal.h>
#include <sys/resource.h>
#include "cache.h"
#include "nscd_log.h"
#include "nscd_selfcred.h"
#include "nscd_frontend.h"
#include "nscd_common.h"
#include "nscd_admin.h"
#include "nscd_door.h"
#include "nscd_switch.h"

extern int 	optind;
extern int 	opterr;
extern int 	optopt;
extern char 	*optarg;

#define	NSCDOPT	"S:Kf:c:ge:p:n:i:l:d:s:h:o:GFR"

/* assume this is a single nscd  or, if multiple, the main nscd */
int		_whoami = NSCD_MAIN;
int		_doorfd = -1;
extern int	_logfd;
static char	*cfgfile = NULL;

extern nsc_ctx_t *cache_ctx_p[];

static void usage(char *);
static void detachfromtty(void);

static char	debug_level[32] = { 0 };
static char	logfile[128] = { 0 };
static int	will_become_server;

static char *
getcacheopt(char *s)
{
	while (*s && *s != ',')
		s++;
	return ((*s == ',') ? (s + 1) : NULL);
}

/*
 * declaring this causes the files backend to use hashing
 * this is of course an utter hack, but provides a nice
 * quiet back door to enable this feature for only the nscd.
 */
void
__nss_use_files_hash(void)
{
}

static int	saved_argc = 0;
static char	**saved_argv = NULL;
static char	saved_execname[MAXPATHLEN];

static void
save_execname()
{
	const char *name = getexecname();

	saved_execname[0] = 0;

	if (name[0] != '/') { /* started w/ relative path */
		(void) getcwd(saved_execname, MAXPATHLEN);
		(void) strlcat(saved_execname, "/", MAXPATHLEN);
	}
	(void) strlcat(saved_execname, name, MAXPATHLEN);
}

int
main(int argc, char ** argv)
{
	int		opt;
	int		errflg = 0;
	int		showstats = 0;
	int		doset = 0;
	nscd_rc_t	rc;
	char		*me = "main()";
	char		*ret_locale;
	char		*ret_textdomain;
	char		msg[128];
	struct		rlimit rl;

	ret_locale = setlocale(LC_ALL, "");
	if (ret_locale == NULL)
		(void) fprintf(stderr, gettext("Unable to set locale\n"));

	ret_textdomain = textdomain(TEXT_DOMAIN);
	if (ret_textdomain == NULL)
		(void) fprintf(stderr, gettext("Unable to set textdomain\n"));

	/*
	 * The admin model for TX is that labeled zones are managed
	 * in global zone where most trusted configuration database
	 * resides. However, nscd will run in any labeled zone if
	 * file /var/tsol/doors/nscd_per_label exists.
	 */
	if (is_system_labeled() && (getzoneid() != GLOBAL_ZONEID)) {
		struct stat sbuf;
		if (stat(TSOL_NSCD_PER_LABEL_FILE, &sbuf) < 0) {
			(void) fprintf(stderr,
			gettext("With Trusted Extensions nscd runs only in the "
			    "global zone (if nscd_per_label flag not set)\n"));
			exit(1);
		}
	}

	/*
	 *  Special case non-root user here - they can only print stats
	 */
	if (geteuid()) {
		if (argc != 2 ||
		    (strcmp(argv[1], "-g") && strcmp(argv[1], "-G"))) {
			(void) fprintf(stderr,
	gettext("Must be root to use any option other than -g\n\n"));
			usage(argv[0]);
		}

		if (_nscd_doorcall(NSCD_PING) != NSS_SUCCESS) {
			(void) fprintf(stderr,
			gettext("%s doesn't appear to be running.\n"),
			    argv[0]);
			exit(1);
		}
		if (_nscd_client_getadmin(argv[1][1]) != 0) {
			(void) fprintf(stderr,
	gettext("unable to get configuration and statistics data\n"));
			exit(1);
		}

		_nscd_client_showstats();
		exit(0);
	}

	/*
	 *  Determine if there is already a daemon (main nscd) running.
	 *  If not, will start it. Forker NSCD will always become a
	 *  daemon.
	 */
	will_become_server = (_nscd_doorcall(NSCD_PING) != NSS_SUCCESS);
	if (argc >= 2 && strcmp(argv[1], "-F") == 0) {
		will_become_server = 1;
		_whoami = NSCD_FORKER;

		/*
		 * allow time for the main nscd to get ready
		 * to receive the IMHERE door request this
		 * process will send later
		 */
		(void) usleep(100000);
	}

	/*
	 * first get the config file path. Also detect
	 * invalid option as soon as possible.
	 */
	while ((opt = getopt(argc, argv, NSCDOPT)) != EOF) {
		switch (opt) {

		case 'f':
			if ((cfgfile = strdup(optarg)) == NULL)
				exit(1);
			break;
		case 'g':
			if (will_become_server) {
				(void) fprintf(stderr,
		gettext("nscd not running, no statistics to show\n\n"));
				errflg++;
			}
			break;
		case 'i':
			if (will_become_server) {
				(void) fprintf(stderr,
		gettext("nscd not running, no cache to invalidate\n\n"));
				errflg++;
			}
			break;

		case '?':
			errflg++;
			break;
		}

	}
	if (errflg)
		usage(argv[0]);

	/*
	 *  perform more initialization and load configuration
	 * if to become server
	 */
	if (will_become_server) {

		/* initialize switch engine and config/stats management */
		if ((rc = _nscd_init(cfgfile)) != NSCD_SUCCESS) {
			(void) fprintf(stderr,
		gettext("initialization of switch failed (rc = %d)\n"), rc);
			exit(1);
		}
		_nscd_get_log_info(debug_level, sizeof (debug_level),
		    logfile, sizeof (logfile));

		/*
		 * initialize cache store
		 */
		if ((rc = init_cache(0)) != NSCD_SUCCESS) {
			(void) fprintf(stderr,
	gettext("initialization of cache store failed (rc = %d)\n"), rc);
			exit(1);
		}
	}

	/*
	 * process usual options
	 */
	optind = 1; /* this is a rescan */
	*msg = '\0';
	while ((opt = getopt(argc, argv, NSCDOPT)) != EOF) {

		switch (opt) {

		case 'K':		/* undocumented feature */
			(void) _nscd_doorcall(NSCD_KILLSERVER);
			exit(0);
			break;

		case 'G':
		case 'g':
			showstats++;
			break;

		case 'p':
			doset++;
			if (_nscd_add_admin_mod(optarg, 'p',
			    getcacheopt(optarg),
			    msg, sizeof (msg)) == -1)
				errflg++;
			break;

		case 'n':
			doset++;
			if (_nscd_add_admin_mod(optarg, 'n',
			    getcacheopt(optarg),
			    msg, sizeof (msg)) == -1)
				errflg++;
			break;

		case 'c':
			doset++;
			if (_nscd_add_admin_mod(optarg, 'c',
			    getcacheopt(optarg),
			    msg, sizeof (msg)) == -1)
				errflg++;
			break;

		case 'i':
			doset++;
			if (_nscd_add_admin_mod(optarg, 'i', NULL,
			    msg, sizeof (msg)) == -1)
				errflg++;
			break;

		case 'l':
			doset++;
			(void) strlcpy(logfile, optarg, sizeof (logfile));
			break;

		case 'd':
			doset++;
			(void) strlcpy(debug_level, optarg,
			    sizeof (debug_level));
			break;

		case 'S':
			/* silently ignore secure-mode */
			break;

		case 's':
			/* silently ignore suggested-size */
			break;

		case 'o':
			/* silently ignore old-data-ok */
			break;

		case 'h':
			doset++;
			if (_nscd_add_admin_mod(optarg, 'h',
			    getcacheopt(optarg),
			    msg, sizeof (msg)) == -1)
				errflg++;
			break;

		case 'e':
			doset++;
			if (_nscd_add_admin_mod(optarg, 'e',
			    getcacheopt(optarg),
			    msg, sizeof (msg)) == -1)
				errflg++;
			break;

		case 'F':
			_whoami = NSCD_FORKER;
			break;

		default:
			errflg++;
			break;
		}

	}

	if (errflg) {
		if (*msg != '\0')
			(void) fprintf(stderr, "\n%s: %s\n\n", argv[0], msg);
		usage(argv[0]);
	}

	/*
	 * if main nscd already running and not forker nscd,
	 * can only do admin work
	 */
	if (_whoami == NSCD_MAIN) {
		if (!will_become_server) {
			if (showstats) {
				if (_nscd_client_getadmin('g')) {
					(void) fprintf(stderr,
			gettext("Cannot contact nscd properly(?)\n"));
					exit(1);
				}
				_nscd_client_showstats();
			}

			if (doset) {
				if (_nscd_client_setadmin() < 0) {
					(void) fprintf(stderr,
				gettext("Error during admin call\n"));
					exit(1);
				}
			}
			if (!showstats && !doset) {
				(void) fprintf(stderr,
gettext("%s already running.... no administration option specified\n"),
				    argv[0]);
			}
			exit(0);
		}
	}

	/*
	 *   daemon from here on
	 */

	if (_whoami == NSCD_MAIN) {

		/* save enough info in case need to restart or fork */
		saved_argc = argc;
		saved_argv = argv;
		save_execname();

		/*
		 * if a log file is not specified, set it to
		 * "stderr" or "/dev/null" based on debug level
		 */
		if (*logfile == '\0') {
			if (*debug_level != '\0')
				/* we're debugging... */
				(void) strcpy(logfile, "stderr");
			else
				(void) strcpy(logfile, "/dev/null");
		}
		(void) _nscd_add_admin_mod(NULL, 'l', logfile,
		    msg, sizeof (msg));
		(void) _nscd_add_admin_mod(NULL, 'd', debug_level,
		    msg, sizeof (msg));

		/* activate command options */
		if (_nscd_server_setadmin(NULL) != NSCD_SUCCESS) {
			(void) fprintf(stderr,
			gettext("unable to set command line options\n"));
			exit(1);
		}

		if (*debug_level != '\0') {
			/* we're debugging, no forking of nscd */

			/*
			 * forker nscd will be started if self credential
			 * is configured
			 */
			_nscd_start_forker(saved_execname, saved_argc,
			    saved_argv);
		} else {
			/*
			 * daemonize the nscd (forker nscd will also
			 * be started if self credential is configured)
			 */
			detachfromtty();
		}
	} else { /* NSCD_FORKER */
		/*
		 * To avoid PUN (Per User Nscd) processes from becoming
		 * zombies after they exit, the forking nscd should
		 * ignore the SIGCLD signal so that it does not
		 * need to wait for every child PUN to exit.
		 */
		(void) signal(SIGCLD, SIG_IGN);
		(void) open("/dev/null", O_RDWR, 0);
		(void) dup(0);
		if (_logfd != 2)
			(void) dup(0);
	}

	/* set NOFILE to unlimited */
	rl.rlim_cur = rl.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_NOFILE, &rl) < 0) {
		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ERROR)
		(me, "Cannot set open file limit: %s\n", strerror(errno));
		exit(1);
	}

	/* set up door and establish our own server thread pool */
	if ((_doorfd = _nscd_setup_server(saved_execname, saved_argv)) == -1) {
		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ERROR)
		(me, "unable to set up door\n");
		exit(1);
	}

	/* inform the main nscd that this forker is ready */
	if (_whoami == NSCD_FORKER) {
		int	ret;

		for (ret = NSS_ALTRETRY; ret == NSS_ALTRETRY; )
			ret = _nscd_doorcall_sendfd(_doorfd,
			    NSCD_IMHERE | (NSCD_FORKER & NSCD_WHOAMI),
			    NULL, 0, NULL);
	}

	for (;;) {
		(void) pause();
		(void) _nscd_doorcall(NSCD_REFRESH);
	}

	/* NOTREACHED */
	/*LINTED E_FUNC_HAS_NO_RETURN_STMT*/
}

static void
usage(char *s)
{
	(void) fprintf(stderr,
	    "Usage: %s [-d debug_level] [-l logfilename]\n", s);
	(void) fprintf(stderr,
	    "	[-p cachename,positive_time_to_live]\n");
	(void) fprintf(stderr,
	    "	[-n cachename,negative_time_to_live]\n");
	(void) fprintf(stderr,
	    "	[-i cachename]\n");
	(void) fprintf(stderr,
	    "	[-h cachename,keep_hot_count]\n");
	(void) fprintf(stderr,
	    "	[-e cachename,\"yes\"|\"no\"] [-g] " \
	    "[-c cachename,\"yes\"|\"no\"]\n");
	(void) fprintf(stderr,
	    "	[-f configfilename] \n");
	(void) fprintf(stderr,
	    "\n	Supported caches:\n");
	(void) fprintf(stderr,
	    "	  auth_attr, bootparams, ethers\n");
	(void) fprintf(stderr,
	    "	  exec_attr, group, hosts, ipnodes, netmasks\n");
	(void) fprintf(stderr,
	    "	  networks, passwd, printers, prof_attr, project\n");
	(void) fprintf(stderr,
	    "	  protocols, rpc, services, tnrhtp, tnrhdb\n");
	(void) fprintf(stderr,
	    "	  user_attr\n");
	exit(1);
}

/*
 * detach from tty
 */
static void
detachfromtty(void)
{
	nscd_rc_t	rc;
	char		*me = "detachfromtty";

	if (_logfd > 0) {
		int i;
		for (i = 0; i < _logfd; i++)
			(void) close(i);
		closefrom(_logfd + 1);
	} else
		closefrom(0);

	(void) chdir("/");

	switch (fork1()) {
	case (pid_t)-1:

		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ERROR)
		(me, "unable to fork: pid = %d, %s\n",
		    getpid(), strerror(errno));

		exit(1);
		break;
	case 0:
		/* start the forker nscd if so configured */
		_nscd_start_forker(saved_execname, saved_argc, saved_argv);
		break;
	default:
		exit(0);
	}

	(void) setsid();
	(void) open("/dev/null", O_RDWR, 0);
	(void) dup(0);
	if (_logfd != 2)
		(void) dup(0);

	/*
	 * start monitoring the states of the name service clients
	 */
	rc = _nscd_init_smf_monitor();
	if (rc != NSCD_SUCCESS) {
		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ERROR)
	(me, "unable to start the SMF monitor (rc = %d)\n", rc);

		exit(-1);
	}
}

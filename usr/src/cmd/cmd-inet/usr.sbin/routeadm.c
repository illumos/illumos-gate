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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>
#include <stropts.h>
#include <errno.h>
#include <libintl.h>
#include <locale.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <procfs.h>
#include <inet/ip.h>
#include <inet/nd.h>
#include <net/if.h>

static char *myname;	/* copied from argv[0] */

#define	RA_CONF_FILE		"/etc/inet/routing.conf"
#define	RA_MAX_CONF_LINE	256
#define	ND_IP_FORWARDING	"ip_forwarding"
#define	ND_IP6_FORWARDING	"ip6_forwarding"
#define	ND_IP6_SENDREDIR	"ip6_send_redirects"
#define	ND_IP6_IGNREDIR		"ip6_ignore_redirect"
#define	ND_ON_STR		"\0" "1" "\0"
#define	ND_OFF_STR		"\0" "0" "\0"
#define	OPT_STRBUFSIZE		1024
#define	RAD_ARGNUM		10

#define	IPV4_ROUTING_DAEMON_DEF	"/usr/sbin/in.routed"
#define	IPV4_ROUTING_DAEMON_ARGS_DEF ""
#define	IPV4_ROUTING_STOP_CMD_DEF "kill -TERM `cat /var/tmp/in.routed.pid`"
#define	IPV6_ROUTING_DAEMON_DEF	"/usr/lib/inet/in.ripngd"
#define	IPV6_ROUTING_DAEMON_ARGS_DEF "-s"
#define	IPV6_ROUTING_STOP_CMD_DEF "kill -TERM `cat /var/tmp/in.ripngd.pid`"
#define	NDPD_DAEMON_DEF	"/usr/lib/inet/in.ndpd"
#define	NDPD_STOP_CMD_DEF "kill -TERM `cat /var/run/in.ndpd.pid`"

#define	IN_ROUTED_PID	"/var/run/in.routed.pid"
#define	IN_RIPNGD_PID	"/var/run/in.ripngd.pid"
#define	IN_NDPD_PID	"/var/run/in.ndpd.pid"

/*
 * The rad_stop_cmd is exec-ed only if rad_pidfile is NULL, i.e.,
 * default routing daemon has changed.
 */
typedef struct ra_daemon {
	size_t	rad_argvsize;
	char	**rad_argv;
	char	*rad_pidfile;
	char	*rad_stop_cmd;
} ra_daemon_t;

static ra_daemon_t v4d, v6d;
static char *ndpd_args[] = { NDPD_DAEMON_DEF, NULL };
static ra_daemon_t in_ndpd = { 2, ndpd_args, IN_NDPD_PID, NDPD_STOP_CMD_DEF };

static char nd_ip_forw_on[] =		ND_IP_FORWARDING ND_ON_STR;
static char nd_ip_forw_off[] =		ND_IP_FORWARDING ND_OFF_STR;
static char nd_ip6_forw_on[] =		ND_IP6_FORWARDING ND_ON_STR;
static char nd_ip6_forw_off[] =		ND_IP6_FORWARDING ND_OFF_STR;
static char nd_ip6_sendredir_on[] =	ND_IP6_SENDREDIR ND_ON_STR;
static char nd_ip6_sendredir_off[] =	ND_IP6_SENDREDIR ND_OFF_STR;
static char nd_ip6_ignredir_on[] =	ND_IP6_IGNREDIR ND_ON_STR;
static char nd_ip6_ignredir_off[] =	ND_IP6_IGNREDIR ND_OFF_STR;

static int		ipsock = -1;
static boolean_t	booting = B_FALSE;	/* boot script defaults? */
static boolean_t	forwarding_only = B_FALSE;

typedef enum option_values {
	OPT_INVALID, OPT_ENABLED, OPT_DISABLED, OPT_DEFAULT, OPT_UNKNOWN
} oval_t;

#define	OPT2STR(oval) \
	(oval == OPT_ENABLED ? "enabled" : \
	(oval == OPT_UNKNOWN ? "unknown" : \
	(oval == OPT_DISABLED ? "disabled" : "default")))
#define	OPT2INTLSTR(oval) \
	(oval == OPT_ENABLED ? gettext("enabled") : \
	(oval == OPT_UNKNOWN ? gettext("unknown") : \
	(oval == OPT_DISABLED ? gettext("disabled") : \
	gettext("default"))))

typedef oval_t (*ra_stat_func_t)(void);
typedef void (*ra_update_func_t)(void);

/*
 * A routeadm option.  These options are those that are enabled or disabled
 * with the -e and -d command-line options.
 */
typedef struct ra_opt {
	const char	*opt_name;
	oval_t		opt_new;	/* specified on command-line */
	oval_t		opt_newrev;	/* new revert value on command-line */
	oval_t		opt_conf;	/* value currently configured */
	oval_t		opt_rev;	/* revert value configured */
	oval_t		opt_def;	/* default value */
	ra_update_func_t opt_enable;
	ra_update_func_t opt_disable;
	ra_stat_func_t	opt_getcur;
} raopt_t;

#define	OPT_IS_FORWARDING(opt) \
	(strcmp((opt).opt_name, "ipv4-forwarding") == 0 || \
	    strcmp((opt).opt_name, "ipv6-forwarding") == 0)

/*
 * A routeadm variable.  These are assigned using the -s command-line
 * option.
 */
typedef struct ra_var {
	const char	*var_name;
	char		*var_new;	/* specified on command-line */
	char		*var_conf;	/* Currently configured value */
	char		*var_def;	/* The variable's default value */
} ravar_t;

static boolean_t init_daemon(ra_daemon_t *, ravar_t *, ravar_t *, ravar_t *,
    char *);
static oval_t v4forw_cur(void);
static oval_t v4rout_cur(void);
static oval_t v6forw_cur(void);
static oval_t v6rout_cur(void);
static void enable_v4forw(void);
static void disable_v4forw(void);
static void enable_v4rout(void);
static void disable_v4rout(void);
static void enable_v6forw(void);
static void disable_v6forw(void);
static void enable_v6rout(void);
static void disable_v6rout(void);
static void usage(void);
static void ra_update(void);
static void ra_report(boolean_t);
static int ra_parseconf(void);
static int ra_parseopt(char *, int, raopt_t *);
static int ra_parsevar(char *, int, ravar_t *);
static int ra_writeconf(void);
static raopt_t *ra_str2opt(const char *);
static oval_t ra_str2oval(const char *);
static ravar_t *ra_str2var(const char *);
static char *ra_intloptname(const char *);
static int open_ipsock(void);
static int ra_ndioctl(int, char *, int);
static pid_t ra_isrunning(ra_daemon_t *);
static void ra_rundaemon(ra_daemon_t *);
static void ra_killdaemon(ra_daemon_t *);
static int ra_numv6intfs(void);
static void start_ndpd(void);


/*
 * The list describing the supported options.  If an option is added here,
 * remember to also add support for the human readable description of the
 * option to the ra_intloptname() function.
 */
static raopt_t ra_opts[] = {
	{ "ipv4-forwarding",
	    OPT_INVALID, OPT_INVALID, OPT_INVALID, OPT_DISABLED, OPT_DISABLED,
	    enable_v4forw, disable_v4forw, v4forw_cur },
	{ "ipv4-routing",
	    OPT_INVALID, OPT_INVALID, OPT_INVALID, OPT_ENABLED, OPT_DEFAULT,
	    enable_v4rout, disable_v4rout, v4rout_cur },
	{ "ipv6-forwarding",
	    OPT_INVALID, OPT_INVALID, OPT_INVALID, OPT_DISABLED, OPT_DISABLED,
	    enable_v6forw, disable_v6forw, v6forw_cur },
	{ "ipv6-routing",
	    OPT_INVALID, OPT_INVALID, OPT_INVALID, OPT_DISABLED, OPT_DISABLED,
	    enable_v6rout, disable_v6rout, v6rout_cur },
	{ NULL,
	    OPT_INVALID, OPT_INVALID, OPT_INVALID, OPT_INVALID, OPT_INVALID,
	    NULL, NULL, NULL }
};

char *v_opt[] = {
#define	IPV4_ROUTING_DAEMON		0
	"ipv4-routing-daemon",
#define	IPV4_ROUTING_DAEMON_ARGS	1
	"ipv4-routing-daemon-args",
#define	IPV4_ROUTING_STOP_CMD		2
	"ipv4-routing-stop-cmd",
#define	IPV6_ROUTING_DAEMON		3
	"ipv6-routing-daemon",
#define	IPV6_ROUTING_DAEMON_ARGS	4
	"ipv6-routing-daemon-args",
#define	IPV6_ROUTING_STOP_CMD		5
	"ipv6-routing-stop-cmd",
	NULL
};


/*
 * the list describing the supported routeadm variables.
 */
static ravar_t ra_vars[] = {
	{ "ipv4-routing-daemon", NULL, NULL, IPV4_ROUTING_DAEMON_DEF },
	{ "ipv4-routing-daemon-args", NULL, NULL,
	    IPV4_ROUTING_DAEMON_ARGS_DEF },
	{ "ipv4-routing-stop-cmd", NULL, NULL, IPV4_ROUTING_STOP_CMD_DEF },
	{ "ipv6-routing-daemon", NULL, NULL, IPV6_ROUTING_DAEMON_DEF },
	{ "ipv6-routing-daemon-args", NULL, NULL,
	    IPV6_ROUTING_DAEMON_ARGS_DEF },
	{ "ipv6-routing-stop-cmd", NULL, NULL, IPV6_ROUTING_STOP_CMD_DEF },
	{ NULL, NULL, NULL, NULL }
};


static void
usage(void)
{
	(void) fprintf(stderr, gettext(
	    "usage: %1$s [-p] [-R <root-dir>]\n"
	    "       %1$s [-e <option>] [-d <option>] [-r <option>]\n"
	    "           [-s <var>=<val>] [-R <root-dir>]\n"
	    "       %1$s -u\n\n"
	    "       <option> is one of:\n"
	    "       ipv4-forwarding\n"
	    "       ipv4-routing\n"
	    "       ipv6-forwarding\n"
	    "       ipv6-routing\n\n"
	    "       <var> is one of:\n"
	    "       ipv4-routing-daemon\n"
	    "       ipv4-routing-daemon-args\n"
	    "       ipv4-routing-stop-cmd\n"
	    "       ipv6-routing-daemon\n"
	    "       ipv6-routing-daemon-args\n"
	    "       ipv6-routing-stop-cmd\n"), myname);
}

int
main(int argc, char *argv[])
{
	int		opt, status = 0, opt_index;
	raopt_t		*raopt;
	ravar_t		*ravar;
	oval_t		*val;
	boolean_t	modify = B_FALSE;
	boolean_t	update = B_FALSE;
	boolean_t	parseable = B_FALSE;
	char		*options, *value;
	int		fdnull;

	myname = argv[0];

	(void) setlocale(LC_ALL, "");

#if	!defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

	(void) textdomain(TEXT_DOMAIN);

	while ((opt = getopt(argc, argv, "bd:e:FpR:r:s:u")) != EOF) {
		switch (opt) {
		case 'b':
			/*
			 * This is a project-private option that allows the
			 * boot script to give us revert values for all of
			 * the options.	 These values will be used if the
			 * user hasn't set the options, or has reverted
			 * them using the -r flag.  We save these values in
			 * the config file so that we can fall back to
			 * these when the admin uses "-r <option>".
			 */
			booting = B_TRUE;
			break;
		case 'd':
		case 'e':
		case 'r':
			if ((raopt = ra_str2opt(optarg)) != NULL) {
				/*
				 * If -b was specified, then the
				 * values given are those we will revert to.
				 */
				if (booting)
					val = &raopt->opt_newrev;
				else
					val = &raopt->opt_new;
				switch (opt) {
				case 'd':
					*val = OPT_DISABLED;
					break;
				case 'e':
					*val = OPT_ENABLED;
					break;
				case 'r':
					*val = raopt->opt_def;
					break;
				}
			} else if ((ravar = ra_str2var(optarg)) != NULL) {
				if (opt != 'r') {
					usage();
					return (EXIT_FAILURE);
				}
				ravar->var_new = ravar->var_def;
			} else {
				(void) fprintf(stderr, gettext(
				    "%1$s: invalid option: %2$s\n"),
				    myname, optarg);
				usage();
				return (EXIT_FAILURE);
			}
			modify = B_TRUE;
			break;
		case 'F':
			/*
			 * This is a project-private option that allows the
			 * net-loopback method to configure IP forwarding
			 * before network interfaces are configured in
			 * net-physical.  This allows administrators to
			 * configure interface-specific IP forwarding
			 * settings in /etc/hostname*.* files by using the
			 * "router" or "-router" ifconfig commands.
			 */
			forwarding_only = B_TRUE;
			break;
		case 'p':
			parseable = B_TRUE;
			break;
		case 'R':
			if (chroot(optarg) == -1) {
				(void) fprintf(stderr, gettext(
				    "%1$s: failed to chroot to %2$s: %3$s\n"),
				    myname, optarg, strerror(errno));
				return (EXIT_FAILURE);
			}
			break;
		case 's':
			options = optarg;
			while (*options != '\0') {
				opt_index = getsubopt(&options, v_opt, &value);

				if (value == NULL) {
					usage();
					return (EXIT_FAILURE);
				}
				if (opt_index == -1) {
					(void) fprintf(stderr, gettext(
					    "%1$s: invalid variable: %2$s\n"),
					    myname, optarg);
					usage();
					return (EXIT_FAILURE);
				}

				ravar = &ra_vars[opt_index];
				if ((ravar->var_new = strdup(value)) == NULL) {
					(void) fprintf(stderr, gettext("%s: "
					    "unable to allocate memory.\n"),
					    myname);
					return (EXIT_FAILURE);
				}
			}
			modify = B_TRUE;
			break;
		case 'u':
			update = B_TRUE;
			break;
		default:
			usage();
			return (EXIT_FAILURE);
		}
	}

	if (argc > optind) {
		/* There shouldn't be any extra args. */
		usage();
		return (EXIT_FAILURE);
	}

	if (booting) {
		fdnull = open("/dev/null", O_RDWR);
		(void) dup2(fdnull, 2);
	}

	if (parseable && (update || modify)) {
		(void) fprintf(stderr, gettext("%s: the -p option cannot be "
		    "used with any of -deru\n"), myname);
		usage();
		return (EXIT_FAILURE);
	}

	if (ra_parseconf() != 0)
		return (EXIT_FAILURE);

	if (modify)
		status = ra_writeconf();

	/*
	 * In order to update the running system or print a report, the
	 * daemon structures must reflect the current state of the
	 * daemon configuration variables.
	 */
	if (!init_daemon(&v4d, &ra_vars[IPV4_ROUTING_DAEMON],
		&ra_vars[IPV4_ROUTING_DAEMON_ARGS],
		&ra_vars[IPV4_ROUTING_STOP_CMD], IN_ROUTED_PID) ||
	    !init_daemon(&v6d, &ra_vars[IPV6_ROUTING_DAEMON],
		&ra_vars[IPV6_ROUTING_DAEMON_ARGS],
		&ra_vars[IPV6_ROUTING_STOP_CMD], IN_RIPNGD_PID)) {
		return (EXIT_FAILURE);
	}

	if (update)
		ra_update();

	if (!modify && !update)
		ra_report(parseable);

	return (status == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}


/*
 * Initialize the daemon structure pointed to by rad with the variables
 * passed in.
 */
static boolean_t
init_daemon(ra_daemon_t *rad, ravar_t *rv_exec, ravar_t *rv_args,
    ravar_t *rv_kill, char *rv_pidfile)
{
	int i = 1;
	char *token = rv_args->var_conf;
	char *args;

	/*
	 * We only use the pidfile if the admin hasn't altered the name
	 * of the daemon or its kill command.
	 */
	if (strcmp(rv_exec->var_conf, rv_exec->var_def) != 0 ||
	    strcmp(rv_kill->var_conf, rv_kill->var_def) != 0) {
		rad->rad_pidfile = NULL;
		rad->rad_stop_cmd = rv_kill->var_conf;
	} else {
		rad->rad_pidfile = rv_pidfile;
		rad->rad_stop_cmd = NULL;
	}
	rad->rad_argvsize = RAD_ARGNUM;
	if ((rad->rad_argv = malloc(RAD_ARGNUM * sizeof (char *))) == NULL) {
		(void) fprintf(stderr, gettext("%s: out of memory\n"), myname);
		return (B_FALSE);
	}
	rad->rad_argv[0] = rv_exec->var_conf;
	if ((args = strdup(rv_args->var_conf)) == NULL) {
		(void) fprintf(stderr, gettext("%s: out of memory\n"), myname);
		free(rad->rad_argv);
		return (B_FALSE);
	}
	token = strtok(args, " ");
	while (token != NULL) {
		if (i == (rad->rad_argvsize - 1)) {
			rad->rad_argvsize += RAD_ARGNUM;
			if ((rad->rad_argv = realloc(rad->rad_argv,
			    rad->rad_argvsize * sizeof (char *))) == NULL) {
				(void) fprintf(stderr,
				    gettext("%s: out of memory\n"), myname);
				return (B_FALSE);
			}
		}
		rad->rad_argv[i] = token;
		token = strtok(NULL, " ");
		i++;
	}
	rad->rad_argv[i] = NULL;
	return (B_TRUE);
}

/* Apply currently configured values to the running system. */
static void
ra_update(void)
{
	int	i;

	for (i = 0; ra_opts[i].opt_name != NULL; i++) {
		/*
		 * If we're only updating forwarding settings, skip all
		 * options that aren't related to IP forwarding.
		 */
		if (forwarding_only && !OPT_IS_FORWARDING(ra_opts[i]))
			continue;

		/*
		 * Likewise, if we're booting (the net-init boot script has
		 * specified -b on the command line) and we're updating the
		 * rest of the options, skip the forwarding options we set
		 * in the network boot script.
		 */
		if (booting && OPT_IS_FORWARDING(ra_opts[i]))
			continue;

		switch (ra_opts[i].opt_conf) {
		case OPT_ENABLED:
			(ra_opts[i].opt_enable)();
			break;
		case OPT_DISABLED:
			(ra_opts[i].opt_disable)();
			break;
		case OPT_DEFAULT:
			switch (ra_opts[i].opt_rev) {
			case OPT_ENABLED:
				(ra_opts[i].opt_enable)();
				break;
			case OPT_DISABLED:
				(ra_opts[i].opt_disable)();
				break;
			}
		}
	}
}

/*
 * Print the configured values to stdout.  If parseable is set, the output
 * is machine readable.	 The parseable output is of the form:
 *    <varname> persistent=<opt_conf> default=<opt_rev> current=<opt_getcur()>
 * for options, and is of the form:
 *    <varname> persistent=<var_conf> default=<var_def>
 * for variables.
 */
static void
ra_report(boolean_t parseable)
{
	int	i;
	char	confstr[OPT_STRBUFSIZE];
	oval_t	curval;

	if (parseable) {
		for (i = 0; ra_opts[i].opt_name != NULL; i++) {
			curval = (ra_opts[i].opt_getcur)();
			(void) printf("%s persistent=%s default=%s "
			    "current=%s\n", ra_opts[i].opt_name,
			    OPT2STR(ra_opts[i].opt_conf),
			    OPT2STR(ra_opts[i].opt_rev),
			    OPT2STR(curval));
		}
		for (i = 0; ra_vars[i].var_name != NULL; i++) {
			(void) printf("%s persistent=\"%s\" "
			    "default=\"%s\" \n",
			    ra_vars[i].var_name, ra_vars[i].var_conf,
			    ra_vars[i].var_def);
		}
		return;
	}

	(void) printf(gettext(
	    "              Configuration   Current              Current\n"
	    "                     Option   Configuration        System State\n"
	    "---------------------------------------------------------------"
	    "\n"));
	for (i = 0; ra_opts[i].opt_name != NULL; i++) {
		if (ra_opts[i].opt_conf == OPT_DEFAULT) {
			(void) snprintf(confstr, sizeof (confstr),
			    "%s (%s)",
			    OPT2INTLSTR(ra_opts[i].opt_conf),
			    OPT2INTLSTR(ra_opts[i].opt_rev));
		} else {
			(void) snprintf(confstr, sizeof (confstr),
			    "%s", OPT2INTLSTR(ra_opts[i].opt_conf));
		}
		curval = (ra_opts[i].opt_getcur)();
		(void) printf(gettext("%1$27s   %2$-21s%3$s\n"),
		    ra_intloptname(ra_opts[i].opt_name), confstr,
		    OPT2INTLSTR(curval));
	}
	(void) printf("\n");
	for (i = 0; ra_vars[i].var_name != NULL; i++) {
		(void) snprintf(confstr, sizeof (confstr), "\"%s\"",
		    ra_vars[i].var_conf);
		(void) printf(gettext("%1$27s   %2$s\n"),
		    ra_intloptname(ra_vars[i].var_name), confstr);
	}
}

/*
 * Parse the configuration file and fill the ra_opts array with opt_conf
 * and opt_rev values, and the ra_vars array with opt_conf values.
 */
static int
ra_parseconf(void)
{
	FILE	*fp;
	uint_t	lineno;
	char	line[RA_MAX_CONF_LINE];
	char	*cp, *confstr;
	raopt_t	*raopt;
	ravar_t *ravar;

	if ((fp = fopen(RA_CONF_FILE, "r")) == NULL) {
		/*
		 * There's no config file, so we need to create one.  The
		 * system doesn't ship with one, so this is not an error
		 * condition.
		 *
		 * If we're being called from the net-loopback boot script
		 * (forwarding_only is set), then there isn't anything for
		 * us to do in the absense of a configuration file.  In
		 * this case, we would only set user-configured forwarding
		 * settings.  If the routing.conf file doesn't exist, then
		 * we just exit since the user obviously hasn't configured
		 * anything.
		 */
		if (forwarding_only)
			exit(EXIT_SUCCESS);

		return (ra_writeconf());
	}

	for (lineno = 1; fgets(line, sizeof (line), fp) != NULL; lineno++) {
		if (line[strlen(line) - 1] == '\n')
			line[strlen(line) - 1] = '\0';

		cp = line;

		/* Skip leading whitespace */
		while (isspace(*cp))
			cp++;

		/* Skip comment lines and empty lines */
		if (*cp == '#' || *cp == '\0')
			continue;

		/*
		 * Anything else must be of the form:
		 * <option> <value> <default_value>
		 */
		if ((confstr = strtok(cp, " ")) == NULL) {
			(void) fprintf(stderr,
			    gettext("%1$s: %2$s: invalid entry on line %3$d\n"),
			    myname, RA_CONF_FILE, lineno);
			continue;
		}

		if ((raopt = ra_str2opt(confstr)) != NULL) {
			if (ra_parseopt(confstr, lineno, raopt) != 0) {
				(void) fclose(fp);
				return (-1);
			}
		} else if ((ravar = ra_str2var(confstr)) != NULL) {
			if (ra_parsevar(confstr, lineno, ravar) != 0) {
				(void) fclose(fp);
				return (-1);
			}
		} else {
			(void) fprintf(stderr,
			    gettext("%1$s: %2$s: invalid option name on "
				"line %3$d\n"),
			    myname, RA_CONF_FILE, lineno);
			continue;
		}
	}

	(void) fclose(fp);

	/*
	 * We call ra_writeconf() here in case there were missing entries
	 * in the file.  If all entries have been read, ra_writeconf() will
	 * return without having written anything.
	 */
	return (ra_writeconf());
}

static int
ra_parseopt(char *confstr, int lineno, raopt_t *raopt)
{
	oval_t oval;

	if (raopt->opt_conf != OPT_INVALID) {
		(void) fprintf(stderr,
		    gettext("%1$s: %2$s: WARNING, option defined on "
			"multiple lines, ignoring line %3$d\n"),
		    myname, RA_CONF_FILE, lineno);
		return (0);
	}

	if ((confstr = strtok(NULL, " ")) == NULL) {
		(void) fprintf(stderr,
		    gettext("%1$s: %2$s: missing value on line %3$d\n"),
		    myname, RA_CONF_FILE, lineno);
		return (0);
	}
	if ((oval = ra_str2oval(confstr)) == OPT_INVALID) {
		(void) fprintf(stderr,
		    gettext("%1$s: %2$s: invalid option "
			"value on line %3$d\n"),
		    myname, RA_CONF_FILE, lineno);
		return (0);
	}
	raopt->opt_conf = oval;

	if ((confstr = strtok(NULL, " ")) == NULL) {
		(void) fprintf(stderr,
		    gettext("%1$s: %2$s: missing revert "
			"value on line %3$d\n"),
		    myname, RA_CONF_FILE, lineno);
		return (0);
	}
	if ((oval = ra_str2oval(confstr)) == OPT_INVALID) {
		(void) fprintf(stderr,
		    gettext("%1$s: %2$s: invalid revert "
			"value on line %3$d\n"),
		    myname, RA_CONF_FILE, lineno, confstr);
		return (0);
	}
	raopt->opt_rev = oval;
	return (0);
}

static int
ra_parsevar(char *confstr, int lineno, ravar_t *ravar)
{
	if (ravar->var_conf != NULL) {
		(void) fprintf(stderr,
		    gettext("%1$s: %2$s: WARNING, variable defined on "
			"multiple lines, ignoring line %3$d\n"),
		    myname, RA_CONF_FILE, lineno);
		return (0);
	}

	confstr = strtok(NULL, "=");
	if (confstr == NULL) {
		/*
		 * This isn't an error condition, it simply means that the
		 * variable has no value.
		 */
		ravar->var_conf = "";
		return (0);
	}

	if ((ravar->var_conf = strdup(confstr)) == NULL) {
		(void) fprintf(stderr, gettext("%s: "
		    "unable to allocate memory\n"), myname);
		return (-1);
	}
	return (0);
}

/*
 * Write options to the configuration file.  The options are gathered from
 * the ra_opts[] and ra_vars[] arrays.
 *
 * The format of the file is:
 * - comment lines start with '#'
 * - other lines are written in the form "<opt_name> <opt_new> <opt_newrev>"
 */
static int
ra_writeconf(void)
{
	int	fd, i;
	FILE	*fp;
	mode_t	mode = (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH); /* 0644 */
	boolean_t	changed = B_FALSE;

	/*
	 * At this point, the *_conf members are the current configuration
	 * in the /etc/inet/routing.conf file.  The *_new members are those
	 * that were passed in on the command line to override the current
	 * configuration.
	 */

	/* Make sure we don't needlessly overwrite the file. */
	for (i = 0; ra_opts[i].opt_name != NULL; i++) {
		if (ra_opts[i].opt_conf == OPT_INVALID) {
			/* there was no configuration for this option */
			ra_opts[i].opt_conf = ra_opts[i].opt_def;
			changed = B_TRUE;
		}
		if (ra_opts[i].opt_new != OPT_INVALID &&
		    ra_opts[i].opt_conf != ra_opts[i].opt_new) {
			/* the new configuration overrides the existing one */
			ra_opts[i].opt_conf = ra_opts[i].opt_new;
			changed = B_TRUE;
		}
		if (ra_opts[i].opt_newrev != OPT_INVALID &&
		    ra_opts[i].opt_rev != ra_opts[i].opt_newrev) {
			/* a new revert value was passed in */
			ra_opts[i].opt_rev = ra_opts[i].opt_newrev;
			changed = B_TRUE;
		}
	}

	for (i = 0; ra_vars[i].var_name != NULL; i++) {
		if (ra_vars[i].var_conf == NULL) {
			/* the variable wasn't in the configuration file */
			ra_vars[i].var_conf = ra_vars[i].var_def;
			changed = B_TRUE;
		}
		if (ra_vars[i].var_new != NULL &&
		    strcmp(ra_vars[i].var_conf, ra_vars[i].var_new) != 0) {
			/* a new variable value was passed in */
			ra_vars[i].var_conf = ra_vars[i].var_new;
			changed = B_TRUE;
		}
	}

	if (!changed)
		return (0);

	if ((fd = open(RA_CONF_FILE, O_WRONLY|O_CREAT|O_TRUNC, mode)) == -1) {
		(void) fprintf(stderr,
		    gettext("%1$s: failed to open %2$s: %3$s\n"),
		    myname, RA_CONF_FILE, strerror(errno));
		return (-1);
	}
	if ((fp = fdopen(fd, "w")) == NULL) {
		(void) fprintf(stderr,
		    gettext("%1$s: failed to open stream for %2$s: %3$s\n"),
		    myname, RA_CONF_FILE, strerror(errno));
		return (-1);
	}

	(void) fputs(
	    "#\n"
	    "# routing.conf\n"
	    "#\n"
	    "# Parameters for IP forwarding and routing.\n"
	    "# Do not edit this file by hand -- use routeadm(1m) instead.\n"
	    "#\n",
	    fp);

	/*
	 * Option entries are of the form:
	 * <name> <val> <revert-val>
	 */
	for (i = 0; ra_opts[i].opt_name != NULL; i++) {
		(void) fprintf(fp, "%s %s %s\n",
		    ra_opts[i].opt_name,
		    OPT2STR(ra_opts[i].opt_conf),
		    OPT2STR(ra_opts[i].opt_rev));
	}
	/*
	 * Variable entries are of the form:
	 * <name> =<value>
	 */
	for (i = 0; ra_vars[i].var_name != NULL; i++) {
		(void) fprintf(fp, "%s =%s\n",
		    ra_vars[i].var_name,
		    ra_vars[i].var_conf);
	}

	(void) fclose(fp);

	return (0);
}



/*
 * return the ra_opts array element whose opt_name matches the string
 * passed in as an argument.
 */
static raopt_t *
ra_str2opt(const char *optnamestr)
{
	int i;

	for (i = 0; ra_opts[i].opt_name != NULL; i++) {
		if (strcmp(optnamestr, ra_opts[i].opt_name) == 0)
			break;
	}
	if (ra_opts[i].opt_name == NULL)
		return (NULL);
	else
		return (&ra_opts[i]);
}

/* Convert a string to an option value. */
static oval_t
ra_str2oval(const char *valstr)
{
	if (strcmp(valstr, "enabled") == 0)
		return (OPT_ENABLED);
	else if (strcmp(valstr, "disabled") == 0)
		return (OPT_DISABLED);
	else if (strcmp(valstr, "default") == 0)
		return (OPT_DEFAULT);
	return (OPT_INVALID);
}

static ravar_t *
ra_str2var(const char *varnamestr)
{
	int i;

	for (i = 0; ra_vars[i].var_name != NULL; i++) {
		if (strcmp(varnamestr, ra_vars[i].var_name) == 0)
			break;
	}
	if (ra_vars[i].var_name == NULL)
		return (NULL);
	else
		return (&ra_vars[i]);
}

/*
 * Given an option name, this function provides an internationalized, human
 * readable version of the option name.
 */
static char *
ra_intloptname(const char *optname)
{
	if (strcmp(optname, "ipv4-forwarding") == 0)
		return (gettext("IPv4 forwarding"));
	else if (strcmp(optname, "ipv4-routing") == 0)
		return (gettext("IPv4 routing"));
	else if (strcmp(optname, "ipv6-forwarding") == 0)
		return (gettext("IPv6 forwarding"));
	else if (strcmp(optname, "ipv6-routing") == 0)
		return (gettext("IPv6 routing"));
	else if (strcmp(optname, "ipv4-routing-daemon") == 0)
		return (gettext("IPv4 routing daemon"));
	else if (strcmp(optname, "ipv4-routing-daemon-args") == 0)
		return (gettext("IPv4 routing daemon args"));
	else if (strcmp(optname, "ipv4-routing-stop-cmd") == 0)
		return (gettext("IPv4 routing daemon stop"));
	else if (strcmp(optname, "ipv6-routing-daemon") == 0)
		return (gettext("IPv6 routing daemon"));
	else if (strcmp(optname, "ipv6-routing-daemon-args") == 0)
		return (gettext("IPv6 routing daemon args"));
	else if (strcmp(optname, "ipv6-routing-stop-cmd") == 0)
		return (gettext("IPv6 routing daemon stop"));
	/*
	 * If we get here, there's a bug and someone should trip over this
	 * NULL pointer.
	 */
	return (NULL);
}

static int
open_ipsock(void)
{
	if (ipsock == -1 && (ipsock = socket(PF_INET6, SOCK_DGRAM, 0)) == -1) {
		(void) fprintf(stderr,
		    gettext("%1$s: unable to open %2$s: %3$s\n"),
		    myname, IP_DEV_NAME, strerror(errno));
	}
	return (ipsock);
}

static int
ra_ndioctl(int cmd, char *data, int ilen)
{
	struct strioctl	stri;

	if (open_ipsock() == -1)
		return (-1);

	stri.ic_cmd = cmd;
	stri.ic_timout = 0;
	stri.ic_len = ilen;
	stri.ic_dp = data;
	if (ioctl(ipsock, I_STR, &stri) == -1)
		return (-1);
	return (0);
}

/*
 * Returns the process id of the specified command if it's running, -1 if
 * it's not.
 */
static pid_t
ra_isrunning(ra_daemon_t *daemon)
{
	FILE	*pidfp;
	pid_t	pid = -1;
	char	procpath[MAXPATHLEN];
	int	procfd;
	psinfo_t	ps;

	if (daemon->rad_pidfile == NULL)
		return (-1);

	if ((pidfp = fopen(daemon->rad_pidfile, "r")) == NULL)
		return (-1);
	if (fscanf(pidfp, "%ld", &pid) != 1)
		return (-1);
	(void) fclose(pidfp);

	/* Make sure the process we're interested in is still running. */
	(void) snprintf(procpath, sizeof (procpath), "/proc/%ld/psinfo", pid);
	if ((procfd = open(procpath, O_RDONLY)) == -1)
		return (-1);
	if (read(procfd, &ps, sizeof (ps)) != sizeof (ps)) {
		(void) close(procfd);
		return (-1);
	}
	(void) close(procfd);
	if (strncmp(daemon->rad_argv[0], ps.pr_psargs,
	    strlen(daemon->rad_argv[0])) != 0) {
		return (-1);
	}

	return (pid);
}

/*
 * Fork and exec a daemon, and wait until it has daemonized to return.  We
 * first attempt to kill it if it's already running, as the command-line
 * arguments may have changed.
 */
static void
ra_rundaemon(ra_daemon_t *daemon)
{
	pid_t	daemon_pid;

	ra_killdaemon(daemon);

	if ((daemon_pid = fork()) == -1) {
		(void) fprintf(stderr,
		    gettext("%1$s: unable to fork %2$s: %3$s\n"),
		    myname, daemon->rad_argv[0], strerror(errno));
	} else if (daemon_pid == 0) {
		/* We're the child, execute the daemon. */
		if (execv(daemon->rad_argv[0], daemon->rad_argv) == -1) {
			(void) fprintf(stderr,
			    gettext("%1$s: unable to execute %2$s: %3$s\n"),
			    myname, daemon->rad_argv[0], strerror(errno));
			_exit(EXIT_FAILURE);
		}
	} else {
		/* Wait for the child to daemonize or terminate. */
		(void) wait(NULL);
	}
}

/*
 * If the daemon has a pidfile, use the pid to kill the targeted process.
 * Otherwise, use the daemon's configured stop command.
 */
static void
ra_killdaemon(ra_daemon_t *daemon)
{
	pid_t pid;

	/*
	 * rad_pidfile is cleared out if the user sets a non-default
	 * routing daemon
	 */
	if (daemon->rad_pidfile != NULL) {
		if ((pid = ra_isrunning(daemon)) == -1)
			return;
		if (kill(pid, SIGTERM) == -1) {
			(void) fprintf(stderr, gettext(
			    "%1$s: unable to kill %2$s: %3$s\n"), myname,
			    daemon->rad_argv[0], strerror(errno));
		}
	} else {
		if (system(daemon->rad_stop_cmd) == -1)
			if (!booting) {
				(void) fprintf(stderr, gettext("%1$s: "
				    "%2$s failed: %3$s\n"),
				    myname, daemon->rad_stop_cmd,
				    strerror(errno));
			}
	}
}

/*
 * Return the number of IPv6 addresses configured.  This answers the
 * generic question, "is IPv6 configured?".  We only start in.ndpd if IPv6
 * is configured, and we also only enable IPv6 routing if IPv6 is enabled.
 */
static int
ra_numv6intfs(void)
{
	static int num = -1;
	struct lifnum lifn;

	if (num != -1)
		return (num);

	if (open_ipsock() == -1)
		return (0);

	lifn.lifn_family = AF_INET6;
	lifn.lifn_flags = 0;

	if (ioctl(ipsock, SIOCGLIFNUM, &lifn) == -1)
		return (0);

	return (num = lifn.lifn_count);
}

/* Run in.ndpd */
static void
start_ndpd(void)
{
	ra_rundaemon(&in_ndpd);
}

/* Is ip_forwarding turned on? */
static oval_t
v4forw_cur(void)
{
	char ndbuf[] = ND_IP_FORWARDING;

	if (ra_ndioctl(ND_GET, ndbuf, sizeof (ndbuf)) == -1)
		return (OPT_DISABLED);
	return (atoi(ndbuf) == 0 ? OPT_DISABLED : OPT_ENABLED);
}

/* Is in.routed running? */
static oval_t
v4rout_cur(void)
{
	/*
	 * routeadm cannot really know the status of a user-configured
	 * routing daemon.  We clear the rad_pidfile field of the daemon
	 * structure when the user configures the daemon.
	 */
	if (v4d.rad_pidfile == NULL)
		return (OPT_UNKNOWN);
	return (ra_isrunning(&v4d) == -1 ? OPT_DISABLED : OPT_ENABLED);
}

/* Is ip6_forwarding turned on? */
static oval_t
v6forw_cur(void)
{
	char ndbuf[] = ND_IP6_FORWARDING;

	if (ra_ndioctl(ND_GET, ndbuf, sizeof (ndbuf)) == -1)
		return (OPT_DISABLED);
	return (atoi(ndbuf) == 0 ? OPT_DISABLED : OPT_ENABLED);
}

/* Is in.ripngd running? */
static oval_t
v6rout_cur(void)
{
	/*
	 * routeadm cannot really know the status of a user-configured
	 * routing daemon.  We clear the rad_pidfile field of the daemon
	 * structure when the user configures the daemon.
	 */
	if (v6d.rad_pidfile == NULL)
		return (OPT_UNKNOWN);
	return (ra_isrunning(&v6d) == -1 ? OPT_DISABLED : OPT_ENABLED);
}

static void
enable_v4forw(void)
{
	(void) ra_ndioctl(ND_SET, nd_ip_forw_on, sizeof (nd_ip_forw_on));
}

static void
disable_v4forw(void)
{
	(void) ra_ndioctl(ND_SET, nd_ip_forw_off, sizeof (nd_ip_forw_off));
}

static void
enable_v4rout(void)
{
	if (v4d.rad_argv[0][0] == '\0') {
		(void) fprintf(stderr, gettext("%1$s: %2$s is not set.\n"
		    "    Use -s to set the ipv4-routing-daemon variable, \n"
		    "    or use -d to disable ipv4-routing.\n"), myname,
		    ra_intloptname("ipv4-routing-daemon"));
	} else {
		ra_rundaemon(&v4d);
	}
}

static void
disable_v4rout(void)
{
	ra_killdaemon(&v4d);
}

/* Turn on ip6_forwarding, ip6_ignore_redirect, and ip6_send_redirects. */
static void
enable_v6forw(void)
{
	(void) ra_ndioctl(ND_SET, nd_ip6_sendredir_on,
	    sizeof (nd_ip6_sendredir_on));
	(void) ra_ndioctl(ND_SET, nd_ip6_forw_on, sizeof (nd_ip6_forw_on));
}

/*
 * in.ripngd is tied to IPv6 forwarding due to a limitation in its
 * implementation.  It will propagate routes blindly without checking if
 * forwarding is enabled on the interfaces it's using.	Until that's fixed,
 * make sure in.ripngd doesn't run if IPv6 forwarding isn't enabled.
 */
static void
disable_v6forw(void)
{
	pid_t pid;

	if ((pid = ra_isrunning(&v6d)) != -1 &&
	    kill(pid, SIGTERM) == -1) {
		(void) fprintf(stderr,
		    gettext("%1$s: unable to kill %2$s: %3$s\n"),
		    myname, v6d.rad_argv[0], strerror(errno));
	}

	(void) ra_ndioctl(ND_SET, nd_ip6_sendredir_off,
	    sizeof (nd_ip6_sendredir_off));
	(void) ra_ndioctl(ND_SET, nd_ip6_forw_off, sizeof (nd_ip6_forw_off));
}

/*
 * We only enable IPv6 routing if there is at least one IPv6 interface
 * configured.
 *
 * If in.ndpd isn't already running, then we start it here because
 * in.ripngd depends on having routes based on the prefixes configured by
 * in.ndpd.  We only start in.ripngd if IPv6 forwarding is enabled.  This
 * is due to a giant gap in in.ripngd's design which causes in.ripngd to
 * propagate routes on all interfaces regardless of their forwarding
 * status.  If that's fixed, then we can start in.ripngd regardless of the
 * global IPv6 forwarding status.
 */
static void
enable_v6rout(void)
{
	if (ra_numv6intfs() == 0)
		return;
	start_ndpd();
	if (v6forw_cur() != OPT_ENABLED)
		return;
	(void) ra_ndioctl(ND_SET, nd_ip6_ignredir_on,
	    sizeof (nd_ip6_ignredir_on));
	if (v6d.rad_argv[0][0] == '\0') {
		(void) fprintf(stderr, gettext("%1$s: %2$s is not set.\n"
			"    Use -s to set the ipv6-routing-daemon variable, \n"
			"    or use -d to disable ipv6-routing.\n"), myname,
		    ra_intloptname("ipv6-routing-daemon"));
	} else {
		ra_rundaemon(&v6d);
	}
}

static void
disable_v6rout(void)
{
	/*
	 * We always start in.ndpd if there is an IPv6 interface
	 * configured, regardless of the status of IPv6 routing.
	 */
	if (ra_numv6intfs() > 0)
		start_ndpd();

	(void) ra_ndioctl(ND_SET, nd_ip6_ignredir_off,
	    sizeof (nd_ip6_ignredir_off));
	ra_killdaemon(&v6d);
}

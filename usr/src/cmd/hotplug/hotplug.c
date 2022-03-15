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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <libintl.h>
#include <alloca.h>
#include <getopt.h>
#include <libhotplug.h>
#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/ddi_hp.h>

#if !defined(TEXT_DOMAIN)		/* should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it wasn't */
#endif

/*
 * Function prototypes.
 */
static int	cmd_list(int, char **, const char *);
static int	cmd_online(int, char **, const char *);
static int	cmd_offline(int, char **, const char *);
static int	cmd_enable(int, char **, const char *);
static int	cmd_disable(int, char **, const char *);
static int	cmd_poweron(int, char **, const char *);
static int	cmd_poweroff(int, char **, const char *);
static int	cmd_getpriv(int, char **, const char *);
static int	cmd_setpriv(int, char **, const char *);
static int	cmd_changestate(int, char **, const char *);
static void	parse_common(int, char **, const char *);
static void	parse_flags(int, char **, int *, const char *);
static void	parse_target(int, char **, char **, char **, const char *);
static void	parse_options(int, char **, char **, const char *);
static void	bad_option(int, int, const char *);
static void	usage(const char *);
static int	list_cb(hp_node_t, void *);
static int	list_long_cb(hp_node_t, void *);
static int	error_cb(hp_node_t, void *);
static void	print_options(const char *);
static void	print_error(int);
static int	state_atoi(char *);
static char	*state_itoa(int);
static short	valid_target(int);

/*
 * Define a conversion table for hotplug states.
 */
typedef struct {
	int	state;
	char	*state_str;
	short	valid_target;
} hpstate_t;

static hpstate_t hpstates[] = {
	{ DDI_HP_CN_STATE_EMPTY,	"EMPTY",	0 },
	{ DDI_HP_CN_STATE_PRESENT,	"PRESENT",	1 },
	{ DDI_HP_CN_STATE_POWERED,	"POWERED",	1 },
	{ DDI_HP_CN_STATE_ENABLED,	"ENABLED",	1 },
	{ DDI_HP_CN_STATE_PORT_EMPTY,	"PORT-EMPTY",	0 },
	{ DDI_HP_CN_STATE_PORT_PRESENT,	"PORT-PRESENT",	1 },
	{ DDI_HP_CN_STATE_OFFLINE,	"OFFLINE",	1 },
	{ DDI_HP_CN_STATE_ATTACHED,	"ATTACHED",	0 },
	{ DDI_HP_CN_STATE_MAINTENANCE,	"MAINTENANCE",	0 },
	{ DDI_HP_CN_STATE_ONLINE,	"ONLINE",	1 },
	{ 0, 0, 0 }
};

/*
 * Define tables of supported subcommands.
 */
typedef struct {
	char		*usage_str;
	char		*cmd_str;
	int		(*func)(int argc, char *argv[], const char *usage_str);
} subcmd_t;

static subcmd_t	subcmds[] = {
	{ "list       [-l] [-v] [<path> [<connection>]]", "list", cmd_list },
	{ "online     <path> <port>", "online", cmd_online },
	{ "offline    [-f] [-q] <path> <port>", "offline", cmd_offline },
	{ "enable     <path> <connector>", "enable", cmd_enable },
	{ "disable    [-f] [-q] <path> <connector>", "disable", cmd_disable },
	{ "poweron    <path> <connector>", "poweron", cmd_poweron },
	{ "poweroff   [-f] [-q] <path> <connector>", "poweroff", cmd_poweroff },
	{ "get        -o <options> <path> <connector>", "get", cmd_getpriv },
	{ "set        -o <options> <path> <connector>", "set", cmd_setpriv }
};

static subcmd_t hidden_subcmds[] = {
	{ "changestate  [-f] [-q] -s <state> <path> <connection>",
	    "changestate", cmd_changestate }
};

/*
 * Define tables of command line options.
 */
static const struct option common_opts[] = {
	{ "help",	no_argument,		0, '?' },
	{ "version",	no_argument,		0, 'V' },
	{ 0, 0, 0, 0 }
};

static const struct option list_opts[] = {
	{ "list-path",	no_argument,		0, 'l' },
	{ "verbose",	no_argument,		0, 'v' },
	{ 0, 0,	0, 0 }
};

static const struct option flag_opts[] = {
	{ "force",	no_argument,		0, 'f' },
	{ "query",	no_argument,		0, 'q' },
	{ 0, 0,	0, 0 }
};

static const struct option private_opts[] = {
	{ "options",	required_argument,	0, 'o' },
	{ 0, 0,	0, 0 }
};

static const struct option changestate_opts[] = {
	{ "force",	no_argument,		0, 'f' },
	{ "query",	no_argument,		0, 'q' },
	{ "state",	required_argument,	0, 's' },
	{ 0, 0,	0, 0 }
};

/*
 * Define exit codes.
 */
#define	EXIT_OK		0
#define	EXIT_EINVAL	1	/* invalid arguments */
#define	EXIT_ENOENT	2	/* path or connection doesn't exist */
#define	EXIT_FAILED	3	/* operation failed */
#define	EXIT_UNAVAIL	4	/* service not available */

/*
 * Global variables.
 */
static char 	*prog;
static char	version[] = "1.0";
extern int	errno;

/*
 * main()
 *
 *	The main routine determines which subcommand is used,
 *	and dispatches control to the corresponding function.
 */
int
main(int argc, char *argv[])
{
	int 		i, rv;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if ((prog = strrchr(argv[0], '/')) == NULL)
		prog = argv[0];
	else
		prog++;

	if (argc < 2) {
		usage(NULL);
		return (EXIT_EINVAL);
	}

	parse_common(argc, argv, NULL);

	/* Check the list of defined subcommands. */
	for (i = 0; i < (sizeof (subcmds) / sizeof (subcmd_t)); i++) {
		if (strcmp(argv[1], subcmds[i].cmd_str) == 0) {
			rv = subcmds[i].func(argc - 1, &argv[1],
			    subcmds[i].usage_str);
			goto finished;
		}
	}

	/* Check the list of hidden subcommands. */
	for (i = 0; i < (sizeof (hidden_subcmds) / sizeof (subcmd_t)); i++) {
		if (strcmp(argv[1], hidden_subcmds[i].cmd_str) == 0) {
			rv = hidden_subcmds[i].func(argc - 1, &argv[1],
			    hidden_subcmds[i].usage_str);
			goto finished;
		}
	}

	/* No matching subcommand found. */
	(void) fprintf(stderr, gettext("ERROR: %s: unknown subcommand '%s'\n"),
	    prog, argv[1]);
	usage(NULL);
	exit(EXIT_EINVAL);

finished:
	/* Determine exit code */
	switch (rv) {
	case 0:
		break;
	case EINVAL:
		return (EXIT_EINVAL);
	case ENXIO:
	case ENOENT:
		return (EXIT_ENOENT);
	case EBADF:
		return (EXIT_UNAVAIL);
	default:
		return (EXIT_FAILED);
	}

	return (EXIT_OK);
}

/*
 * cmd_list()
 *
 *	Subcommand to list hotplug information.
 */
static int
cmd_list(int argc, char *argv[], const char *usage_str)
{
	hp_node_t	root;
	char		*path = NULL;
	char		*connection = NULL;
	boolean_t	long_flag = B_FALSE;
	int		flags = 0;
	int		opt;

	/* Parse command line options */
	parse_common(argc, argv, usage_str);
	while ((opt = getopt_clip(argc, argv, "lv", list_opts, NULL)) != -1) {
		switch (opt) {
		case 'l':
			long_flag = B_TRUE;
			break;
		case 'v':
			flags |= HPINFOUSAGE;
			break;
		default:
			bad_option(opt, optopt, usage_str);
			break;
		}
	}
	parse_target(argc, argv, &path, &connection, usage_str);

	/* Default path is "/" */
	if (path == NULL)
		path = "/";

	/* Get hotplug information snapshot */
	if ((root = hp_init(path, connection, flags)) == NULL) {
		print_error(errno);
		return (errno);
	}

	/* Display hotplug information */
	(void) hp_traverse(root, NULL, long_flag ? list_long_cb : list_cb);

	/* Discard hotplug information snapshot */
	hp_fini(root);

	return (0);
}

/*
 * cmd_online()
 *
 *	Subcommand to online a hotplug port.
 */
static int
cmd_online(int argc, char *argv[], const char *usage_str)
{
	hp_node_t	root;
	hp_node_t	results = NULL;
	char		*path = NULL;
	char		*connection = NULL;
	int		rv;

	/* Parse command line options */
	parse_common(argc, argv, usage_str);
	parse_target(argc, argv, &path, &connection, usage_str);

	/* Path and connection are required */
	if ((path == NULL) || (connection == NULL)) {
		(void) fprintf(stderr, gettext("ERROR: too few arguments.\n"));
		usage(usage_str);
		return (EINVAL);
	}

	/* Get hotplug information snapshot */
	if ((root = hp_init(path, connection, 0)) == NULL) {
		print_error(errno);
		return (errno);
	}

	/* Verify target is a port */
	if (hp_type(root) != HP_NODE_PORT) {
		(void) fprintf(stderr,
		    gettext("ERROR: invalid target (must be a port).\n"));
		hp_fini(root);
		return (EINVAL);
	}

	/* Do state change */
	rv = hp_set_state(root, 0, DDI_HP_CN_STATE_ONLINE, &results);

	/* Display results */
	if (rv == EIO) {
		(void) fprintf(stderr, gettext("ERROR: failed to attach device "
		    "drivers or other internal errors.\n"));
	} else if (rv != 0) {
		print_error(rv);
	}
	if (results != NULL) {
		(void) hp_traverse(results, NULL, error_cb);
		hp_fini(results);
	}

	/* Discard hotplug information snapshot */
	hp_fini(root);

	return (rv);
}

/*
 * cmd_offline()
 *
 *	Subcommand to offline a hotplug port.
 */
static int
cmd_offline(int argc, char *argv[], const char *usage_str)
{
	hp_node_t	root;
	hp_node_t	results = NULL;
	char		*path = NULL;
	char		*connection = NULL;
	int		flags = 0;
	int		rv;

	/* Parse command line options */
	parse_common(argc, argv, usage_str);
	parse_flags(argc, argv, &flags, usage_str);
	parse_target(argc, argv, &path, &connection, usage_str);

	/* Path and connection are required */
	if ((path == NULL) || (connection == NULL)) {
		(void) fprintf(stderr, gettext("ERROR: too few arguments.\n"));
		usage(usage_str);
		return (EINVAL);
	}

	/* Get hotplug information snapshot */
	if ((root = hp_init(path, connection, 0)) == NULL) {
		print_error(errno);
		return (errno);
	}

	/* Verify target is a port */
	if (hp_type(root) != HP_NODE_PORT) {
		(void) fprintf(stderr,
		    gettext("ERROR: invalid target (must be a port).\n"));
		hp_fini(root);
		return (EINVAL);
	}

	/* Do state change */
	rv = hp_set_state(root, flags, DDI_HP_CN_STATE_OFFLINE, &results);

	/* Display results */
	print_error(rv);
	if (results != NULL) {
		(void) hp_traverse(results, NULL, error_cb);
		hp_fini(results);
	}

	/* Discard hotplug information snapshot */
	hp_fini(root);

	return (rv);
}

/*
 * cmd_enable()
 *
 *	Subcommand to enable a hotplug connector.
 */
static int
cmd_enable(int argc, char *argv[], const char *usage_str)
{
	hp_node_t	root;
	hp_node_t	results = NULL;
	char		*path = NULL;
	char		*connection = NULL;
	int		rv;

	/* Parse command line options */
	parse_common(argc, argv, usage_str);
	parse_target(argc, argv, &path, &connection, usage_str);

	/* Path and connection are required */
	if ((path == NULL) || (connection == NULL)) {
		(void) fprintf(stderr, gettext("ERROR: too few arguments.\n"));
		usage(usage_str);
		return (EINVAL);
	}

	/* Get hotplug information snapshot */
	if ((root = hp_init(path, connection, 0)) == NULL) {
		print_error(errno);
		return (errno);
	}

	/* Verify target is a connector */
	if (hp_type(root) != HP_NODE_CONNECTOR) {
		(void) fprintf(stderr,
		    gettext("ERROR: invalid target (must be a connector).\n"));
		hp_fini(root);
		return (EINVAL);
	}

	/* Do state change */
	rv = hp_set_state(root, 0, DDI_HP_CN_STATE_ENABLED, &results);

	/* Display results */
	print_error(rv);
	if (results != NULL) {
		(void) hp_traverse(results, NULL, error_cb);
		hp_fini(results);
	}

	/* Discard hotplug information snapshot */
	hp_fini(root);

	return (rv);
}

/*
 * cmd_disable()
 *
 *	Subcommand to disable a hotplug connector.
 */
static int
cmd_disable(int argc, char *argv[], const char *usage_str)
{
	hp_node_t	root;
	hp_node_t	results = NULL;
	char		*path = NULL;
	char		*connection = NULL;
	int		flags = 0;
	int		rv;

	/* Parse command line options */
	parse_common(argc, argv, usage_str);
	parse_flags(argc, argv, &flags, usage_str);
	parse_target(argc, argv, &path, &connection, usage_str);

	/* Path and connection are required */
	if ((path == NULL) || (connection == NULL)) {
		(void) fprintf(stderr, gettext("ERROR: too few arguments.\n"));
		usage(usage_str);
		return (EINVAL);
	}

	/* Get hotplug information snapshot */
	if ((root = hp_init(path, connection, 0)) == NULL) {
		print_error(errno);
		return (errno);
	}

	/* Verify target is a connector */
	if (hp_type(root) != HP_NODE_CONNECTOR) {
		(void) fprintf(stderr,
		    gettext("ERROR: invalid target (must be a connector).\n"));
		hp_fini(root);
		return (EINVAL);
	}

	/*
	 * Do nothing unless the connector is in the ENABLED state.
	 * Otherwise this subcommand becomes an alias for 'poweron.'
	 */
	if (hp_state(root) != DDI_HP_CN_STATE_ENABLED) {
		hp_fini(root);
		return (0);
	}

	/* Do state change */
	rv = hp_set_state(root, flags, DDI_HP_CN_STATE_POWERED, &results);

	/* Display results */
	print_error(rv);
	if (results != NULL) {
		(void) hp_traverse(results, NULL, error_cb);
		hp_fini(results);
	}

	/* Discard hotplug information snapshot */
	hp_fini(root);

	return (rv);
}

/*
 * cmd_poweron()
 *
 *	Subcommand to power on a hotplug connector.
 */
static int
cmd_poweron(int argc, char *argv[], const char *usage_str)
{
	hp_node_t	root;
	hp_node_t	results = NULL;
	char		*path = NULL;
	char		*connection = NULL;
	int		rv;

	/* Parse command line options */
	parse_common(argc, argv, usage_str);
	parse_target(argc, argv, &path, &connection, usage_str);

	/* Path and connection are required */
	if ((path == NULL) || (connection == NULL)) {
		(void) fprintf(stderr, gettext("ERROR: too few arguments.\n"));
		usage(usage_str);
		return (EINVAL);
	}

	/* Get hotplug information snapshot */
	if ((root = hp_init(path, connection, 0)) == NULL) {
		print_error(errno);
		return (errno);
	}

	/* Verify target is a connector */
	if (hp_type(root) != HP_NODE_CONNECTOR) {
		(void) fprintf(stderr,
		    gettext("ERROR: invalid target (must be a connector).\n"));
		hp_fini(root);
		return (EINVAL);
	}

	/*
	 * Do nothing if the connector is already powered.
	 * Otherwise this subcommand becomes an alias for 'disable.'
	 */
	if (hp_state(root) >= DDI_HP_CN_STATE_POWERED) {
		hp_fini(root);
		return (0);
	}

	/* Do state change */
	rv = hp_set_state(root, 0, DDI_HP_CN_STATE_POWERED, &results);

	/* Display results */
	print_error(rv);
	if (results != NULL) {
		(void) hp_traverse(results, NULL, error_cb);
		hp_fini(results);
	}

	/* Discard hotplug information snapshot */
	hp_fini(root);

	return (rv);
}

/*
 * cmd_poweroff()
 *
 *	Subcommand to power off a hotplug connector.
 */
static int
cmd_poweroff(int argc, char *argv[], const char *usage_str)
{
	hp_node_t	root;
	hp_node_t	results = NULL;
	char		*path = NULL;
	char		*connection = NULL;
	int		flags = 0;
	int		rv;

	/* Parse command line options */
	parse_common(argc, argv, usage_str);
	parse_flags(argc, argv, &flags, usage_str);
	parse_target(argc, argv, &path, &connection, usage_str);

	/* Path and connection are required */
	if ((path == NULL) || (connection == NULL)) {
		(void) fprintf(stderr, gettext("ERROR: too few arguments.\n"));
		usage(usage_str);
		return (EINVAL);
	}

	/* Get hotplug information snapshot */
	if ((root = hp_init(path, connection, 0)) == NULL) {
		print_error(errno);
		return (errno);
	}

	/* Verify target is a connector */
	if (hp_type(root) != HP_NODE_CONNECTOR) {
		(void) fprintf(stderr,
		    gettext("ERROR: invalid target (must be a connector).\n"));
		hp_fini(root);
		return (EINVAL);
	}

	/* Do state change */
	rv = hp_set_state(root, flags, DDI_HP_CN_STATE_PRESENT, &results);

	/* Display results */
	print_error(rv);
	if (results != NULL) {
		(void) hp_traverse(results, NULL, error_cb);
		hp_fini(results);
	}

	/* Discard hotplug information snapshot */
	hp_fini(root);

	return (rv);
}

/*
 * cmd_getpriv()
 *
 *	Subcommand to get and display bus private options.
 */
static int
cmd_getpriv(int argc, char *argv[], const char *usage_str)
{
	hp_node_t	root;
	char		*path = NULL;
	char		*connection = NULL;
	char		*options = NULL;
	char		*results = NULL;
	int		rv;

	/* Parse command line options */
	parse_common(argc, argv, usage_str);
	parse_options(argc, argv, &options, usage_str);
	parse_target(argc, argv, &path, &connection, usage_str);

	/* Options, path, and connection are all required */
	if ((options == NULL) || (path == NULL) || (connection == NULL)) {
		(void) fprintf(stderr, gettext("ERROR: too few arguments.\n"));
		usage(usage_str);
		return (EINVAL);
	}

	/* Get hotplug information snapshot */
	if ((root = hp_init(path, connection, 0)) == NULL) {
		print_error(errno);
		return (errno);
	}

	/* Verify target is a connector */
	if (hp_type(root) != HP_NODE_CONNECTOR) {
		(void) fprintf(stderr,
		    gettext("ERROR: invalid target (must be a connector).\n"));
		hp_fini(root);
		return (EINVAL);
	}

	/* Do the operation */
	rv = hp_get_private(root, options, &results);

	/* Display results */
	if (rv == ENOTSUP) {
		(void) fprintf(stderr,
		    gettext("ERROR: unsupported property name or value.\n"));
		(void) fprintf(stderr,
		    gettext("(Properties may depend upon connector state.)\n"));
	} else if (rv != 0) {
		print_error(rv);
	}
	if (results != NULL) {
		print_options(results);
		free(results);
	}

	/* Discard hotplug information snapshot */
	hp_fini(root);

	return (rv);
}

/*
 * cmd_setpriv()
 *
 *	Subcommand to set bus private options.
 */
static int
cmd_setpriv(int argc, char *argv[], const char *usage_str)
{
	hp_node_t	root;
	char		*path = NULL;
	char		*connection = NULL;
	char		*options = NULL;
	char		*results = NULL;
	int		rv;

	/* Parse command line options */
	parse_common(argc, argv, usage_str);
	parse_options(argc, argv, &options, usage_str);
	parse_target(argc, argv, &path, &connection, usage_str);

	/* Options, path, and connection are all required */
	if ((options == NULL) || (path == NULL) || (connection == NULL)) {
		(void) fprintf(stderr, gettext("ERROR: too few arguments.\n"));
		usage(usage_str);
		return (EINVAL);
	}

	/* Get hotplug information snapshot */
	if ((root = hp_init(path, connection, 0)) == NULL) {
		print_error(errno);
		return (errno);
	}

	/* Verify target is a connector */
	if (hp_type(root) != HP_NODE_CONNECTOR) {
		(void) fprintf(stderr,
		    gettext("ERROR: invalid target (must be a connector).\n"));
		hp_fini(root);
		return (EINVAL);
	}

	/* Do the operation */
	rv = hp_set_private(root, options, &results);

	/* Display results */
	if (rv == ENOTSUP) {
		(void) fprintf(stderr,
		    gettext("ERROR: unsupported property name or value.\n"));
		(void) fprintf(stderr,
		    gettext("(Properties may depend upon connector state.)\n"));
	} else if (rv != 0) {
		print_error(rv);
	}
	if (results != NULL) {
		print_options(results);
		free(results);
	}

	/* Discard hotplug information snapshot */
	hp_fini(root);

	return (rv);
}

/*
 * cmd_changestate()
 *
 *	Subcommand to initiate a state change operation.  This is
 *	a hidden subcommand to directly set a connector or port to
 *	a specific target state.
 */
static int
cmd_changestate(int argc, char *argv[], const char *usage_str)
{
	hp_node_t	root;
	hp_node_t	results = NULL;
	char		*path = NULL;
	char		*connection = NULL;
	int		state = -1;
	int		flags = 0;
	int		opt, rv;

	/* Parse command line options */
	parse_common(argc, argv, usage_str);
	while ((opt = getopt_clip(argc, argv, "fqs:", changestate_opts,
	    NULL)) != -1) {
		switch (opt) {
		case 'f':
			flags |= HPFORCE;
			break;
		case 'q':
			flags |= HPQUERY;
			break;
		case 's':
			if ((state = state_atoi(optarg)) == -1) {
				(void) printf("ERROR: invalid target state\n");
				return (EINVAL);
			}
			break;
		default:
			bad_option(opt, optopt, usage_str);
			break;
		}
	}
	parse_target(argc, argv, &path, &connection, usage_str);

	/* State, path, and connection are all required */
	if ((state == -1) || (path == NULL) || (connection == NULL)) {
		(void) fprintf(stderr, gettext("ERROR: too few arguments.\n"));
		usage(usage_str);
		return (EINVAL);
	}

	/* Check that target state is valid */
	if (valid_target(state) == 0) {
		(void) fprintf(stderr,
		    gettext("ERROR: invalid target state\n"));
		return (EINVAL);
	}

	/* Get hotplug information snapshot */
	if ((root = hp_init(path, connection, 0)) == NULL) {
		print_error(errno);
		return (errno);
	}

	/* Initiate state change operation on root of snapshot */
	rv = hp_set_state(root, flags, state, &results);

	/* Display results */
	print_error(rv);
	if (results) {
		(void) hp_traverse(results, NULL, error_cb);
		hp_fini(results);
	}

	/* Discard hotplug information snapshot */
	hp_fini(root);

	return (rv);
}

/*
 * parse_common()
 *
 *	Parse command line options that are common to the
 *	entire program, and to each of its subcommands.
 */
static void
parse_common(int argc, char *argv[], const char *usage_str)
{
	int		opt;
	extern int	opterr;
	extern int	optind;

	/* Turn off error reporting */
	opterr = 0;

	while ((opt = getopt_clip(argc, argv, "?V", common_opts, NULL)) != -1) {
		switch (opt) {
		case '?':
			if (optopt == '?') {
				usage(usage_str);
				exit(0);
			}
			break;
		case 'V':
			(void) printf(gettext("%s: Version %s\n"),
			    prog, version);
			exit(0);
		default:
			break;
		}
	}

	/* Reset option index */
	optind = 1;
}

/*
 * parse_flags()
 *
 *	Parse command line flags common to all downward state
 *	change operations (offline, disable, poweoff).
 */
static void
parse_flags(int argc, char *argv[], int *flagsp, const char *usage_str)
{
	int	opt;
	int	flags = 0;

	while ((opt = getopt_clip(argc, argv, "fq", flag_opts, NULL)) != -1) {
		switch (opt) {
		case 'f':
			flags |= HPFORCE;
			break;
		case 'q':
			flags |= HPQUERY;
			break;
		default:
			bad_option(opt, optopt, usage_str);
			break;
		}
	}

	*flagsp = flags;
}

/*
 * parse_options()
 *
 *	Parse command line options common to the bus private set and
 *	get subcommands.
 */
static void
parse_options(int argc, char *argv[], char **optionsp, const char *usage_str)
{
	int	opt;

	while ((opt = getopt_clip(argc, argv, "o:", private_opts,
	    NULL)) != -1) {
		switch (opt) {
		case 'o':
			*optionsp = optarg;
			break;
		default:
			bad_option(opt, optopt, usage_str);
			break;
		}
	}
}

/*
 * parse_target()
 *
 *	Parse the target path and connection name from the command line.
 */
static void
parse_target(int argc, char *argv[], char **pathp, char **connectionp,
    const char *usage_str)
{
	extern int	optind;

	if (optind < argc)
		*pathp = argv[optind++];

	if (optind < argc)
		*connectionp = argv[optind++];

	if (optind < argc) {
		(void) fprintf(stderr, gettext("ERROR: too many arguments.\n"));
		usage(usage_str);
		exit(EINVAL);
	}
}

/*
 * bad_option()
 *
 *	Routine to handle bad command line options.
 */
static void
bad_option(int opt, int optopt, const char *usage_str)
{
	switch (opt) {
	case ':':
		(void) fprintf(stderr,
		    gettext("ERROR: option '%c' requires an argument.\n"),
		    optopt);
		break;
	default:
		if (optopt == '?') {
			usage(usage_str);
			exit(EXIT_OK);
		}
		(void) fprintf(stderr,
		    gettext("ERROR: unrecognized option '%c'.\n"), optopt);
		break;
	}

	usage(usage_str);

	exit(EXIT_EINVAL);
}

/*
 * usage()
 *
 *	Display general usage of the command.  Including
 *	the usage synopsis of each defined subcommand.
 */
static void
usage(const char *usage_str)
{
	int	i;

	if (usage_str != NULL) {
		(void) fprintf(stderr, gettext("Usage:   %s  %s\n\n"),
		    prog, usage_str);
		return;
	}

	(void) fprintf(stderr, gettext("Usage:  %s  <subcommand> [<args>]\n\n"),
	    prog);

	(void) fprintf(stderr, gettext("Subcommands:\n\n"));

	for (i = 0; i < (sizeof (subcmds) / sizeof (subcmd_t)); i++)
		(void) fprintf(stderr, "   %s\n\n", subcmds[i].usage_str);
}

/*
 * list_cb()
 *
 *	Callback function for hp_traverse(), to display nodes
 *	of a hotplug information snapshot.  (Short version.)
 */
/*ARGSUSED*/
static int
list_cb(hp_node_t node, void *arg)
{
	hp_node_t	parent;

	/* Indent */
	for (parent = hp_parent(node); parent; parent = hp_parent(parent))
		if (hp_type(parent) == HP_NODE_DEVICE)
			(void) printf("     ");

	switch (hp_type(node)) {
	case HP_NODE_DEVICE:
		(void) printf("%s\n", hp_name(node));
		break;

	case HP_NODE_CONNECTOR:
		(void) printf("[%s]", hp_name(node));
		(void) printf("  (%s)", state_itoa(hp_state(node)));
		(void) printf("\n");
		break;

	case HP_NODE_PORT:
		(void) printf("<%s>", hp_name(node));
		(void) printf("  (%s)", state_itoa(hp_state(node)));
		(void) printf("\n");
		break;

	case HP_NODE_USAGE:
		(void) printf("{ %s }\n", hp_usage(node));
		break;
	}

	return (HP_WALK_CONTINUE);
}

/*
 * list_long_cb()
 *
 *	Callback function for hp_traverse(), to display nodes
 *	of a hotplug information snapshot.  (Long version.)
 */
/*ARGSUSED*/
static int
list_long_cb(hp_node_t node, void *arg)
{
	char	path[MAXPATHLEN];
	char	connection[MAXPATHLEN];

	if (hp_type(node) != HP_NODE_USAGE) {
		if (hp_path(node, path, connection) != 0)
			return (HP_WALK_CONTINUE);
		(void) printf("%s", path);
	}

	switch (hp_type(node)) {
	case HP_NODE_CONNECTOR:
		(void) printf(" [%s]", connection);
		(void) printf(" (%s)", state_itoa(hp_state(node)));
		break;

	case HP_NODE_PORT:
		(void) printf(" <%s>", connection);
		(void) printf(" (%s)", state_itoa(hp_state(node)));
		break;

	case HP_NODE_USAGE:
		(void) printf("    { %s }", hp_usage(node));
		break;
	}

	(void) printf("\n");

	return (HP_WALK_CONTINUE);
}

/*
 * error_cb()
 *
 *	Callback function for hp_traverse(), to display
 *	error results from a state change operation.
 */
/*ARGSUSED*/
static int
error_cb(hp_node_t node, void *arg)
{
	hp_node_t	child;
	char		*usage_str;
	static char	path[MAXPATHLEN];
	static char	connection[MAXPATHLEN];

	if (((child = hp_child(node)) != NULL) &&
	    (hp_type(child) == HP_NODE_USAGE)) {
		if (hp_path(node, path, connection) == 0)
			(void) printf("%s:\n", path);
		return (HP_WALK_CONTINUE);
	}

	if ((hp_type(node) == HP_NODE_USAGE) &&
	    ((usage_str = hp_usage(node)) != NULL))
		(void) printf("   { %s }\n", usage_str);

	return (HP_WALK_CONTINUE);
}

/*
 * print_options()
 *
 *	Parse and display bus private options.  The options are
 *	formatted as a string which conforms to the getsubopt(3C)
 *	format.  This routine only splits the string elements as
 *	separated by commas, and displays each portion on its own
 *	separate line of output.
 */
static void
print_options(const char *options)
{
	char	*buf, *curr, *next;
	size_t	len;

	/* Do nothing if options string is empty */
	if ((len = strlen(options)) == 0)
		return;

	/* To avoid modifying the input string, make a copy on the stack */
	if ((buf = (char *)alloca(len + 1)) == NULL) {
		(void) printf("%s\n", options);
		return;
	}
	(void) strlcpy(buf, options, len + 1);

	/* Iterate through each comma-separated name/value pair */
	curr = buf;
	do {
		if ((next = strchr(curr, ',')) != NULL) {
			*next = '\0';
			next++;
		}
		(void) printf("%s\n", curr);
	} while ((curr = next) != NULL);
}

/*
 * print_error()
 *
 *	Common routine to print error numbers in an appropriate way.
 *	Prints nothing if error code is 0.
 */
static void
print_error(int error)
{
	switch (error) {
	case 0:
		/* No error */
		return;
	case EACCES:
		(void) fprintf(stderr,
		    gettext("ERROR: operation not authorized.\n"));
		break;
	case EBADF:
		(void) fprintf(stderr,
		    gettext("ERROR: hotplug service is not available.\n"));
		break;
	case EBUSY:
		(void) fprintf(stderr,
		    gettext("ERROR: devices or resources are busy.\n"));
		break;
	case EEXIST:
		(void) fprintf(stderr,
		    gettext("ERROR: resource already exists.\n"));
		break;
	case EFAULT:
		(void) fprintf(stderr,
		    gettext("ERROR: internal failure in hotplug service.\n"));
		break;
	case EINVAL:
		(void) fprintf(stderr,
		    gettext("ERROR: invalid arguments.\n"));
		break;
	case ENOENT:
		(void) fprintf(stderr,
		    gettext("ERROR: there are no connections to display.\n"));
		(void) fprintf(stderr,
		    gettext("(See hotplug(8) for more information.)\n"));
		break;
	case ENXIO:
		(void) fprintf(stderr,
		    gettext("ERROR: no such path or connection.\n"));
		break;
	case ENOMEM:
		(void) fprintf(stderr,
		    gettext("ERROR: not enough memory.\n"));
		break;
	case ENOTSUP:
		(void) fprintf(stderr,
		    gettext("ERROR: operation not supported.\n"));
		break;
	case EIO:
		(void) fprintf(stderr,
		    gettext("ERROR: hardware or driver specific failure.\n"));
		break;
	default:
		(void) fprintf(stderr, gettext("ERROR: operation failed: %s\n"),
		    strerror(error));
		break;
	}
}

/*
 * state_atoi()
 *
 *	Convert a hotplug state from a string to an integer.
 */
static int
state_atoi(char *state)
{
	int	i;

	for (i = 0; hpstates[i].state_str != NULL; i++)
		if (strcasecmp(state, hpstates[i].state_str) == 0)
			return (hpstates[i].state);

	return (-1);
}

/*
 * state_itoa()
 *
 *	Convert a hotplug state from an integer to a string.
 */
static char *
state_itoa(int state)
{
	static char	unknown[] = "UNKNOWN";
	int		i;

	for (i = 0; hpstates[i].state_str != NULL; i++)
		if (state == hpstates[i].state)
			return (hpstates[i].state_str);

	return (unknown);
}

/*
 * valid_target()
 *
 *	Check if a state is a valid target for a changestate command.
 */
static short
valid_target(int state)
{
	int	i;

	for (i = 0; hpstates[i].state_str != NULL; i++)
		if (state == hpstates[i].state)
			return (hpstates[i].valid_target);

	return (0);
}

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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <locale.h>
#include <stdarg.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <stropts.h>
#include <errno.h>
#include <kstat.h>
#include <strings.h>
#include <getopt.h>
#include <unistd.h>
#include <priv.h>
#include <libintl.h>
#include <libdlpi.h>
#include <libdladm.h>
#include <liblaadm.h>
#include <libmacadm.h>

#define	AGGR_DEV	"aggr0"
#define	MAXPORT		256
#define	DUMP_LACP_FORMAT	"    %-9s %-8s %-7s %-12s "	\
	"%-5s %-4s %-4s %-9s %-7s\n"

typedef struct pktsum_s {
	uint64_t	ipackets;
	uint64_t	opackets;
	uint64_t	rbytes;
	uint64_t	obytes;
	uint32_t	ierrors;
	uint32_t	oerrors;
} pktsum_t;

typedef struct show_link_state {
	boolean_t	ls_firstonly;
	boolean_t	ls_donefirst;
	boolean_t	ls_stats;
	pktsum_t	ls_prevstats;
	boolean_t	ls_parseable;
} show_link_state_t;

typedef struct show_grp_state {
	uint32_t	gs_key;
	boolean_t	gs_lacp;
	boolean_t	gs_found;
	boolean_t	gs_stats;
	boolean_t	gs_firstonly;
	pktsum_t	gs_prevstats[MAXPORT];
	boolean_t	gs_parseable;
} show_grp_state_t;

typedef struct show_mac_state {
	boolean_t	ms_firstonly;
	boolean_t	ms_donefirst;
	pktsum_t	ms_prevstats;
	boolean_t	ms_parseable;
} show_mac_state_t;

typedef struct port_state {
	char			*state_name;
	aggr_port_state_t	state_num;
} port_state_t;

static port_state_t port_states[] = {
	{"standby", AGGR_PORT_STATE_STANDBY },
	{"attached", AGGR_PORT_STATE_ATTACHED }
};

#define	NPORTSTATES	(sizeof (port_states) / sizeof (port_state_t))

static void	do_show_link(int, char **);
static void	do_create_aggr(int, char **);
static void	do_delete_aggr(int, char **);
static void	do_add_aggr(int, char **);
static void	do_remove_aggr(int, char **);
static void	do_modify_aggr(int, char **);
static void	do_show_aggr(int, char **);
static void	do_up_aggr(int, char **);
static void	do_down_aggr(int, char **);
static void	do_show_dev(int, char **);

static void	link_stats(const char *, uint32_t);
static void	aggr_stats(uint16_t, uint32_t);
static void	dev_stats(const char *dev, uint32_t);

static void	get_mac_stats(const char *, uint_t, pktsum_t *);
static void	get_link_stats(const char *, pktsum_t *);
static uint64_t	mac_ifspeed(const char *, uint_t);
static char	*mac_link_state(const char *, uint_t);
static char	*mac_link_duplex(const char *, uint_t);
static void	stats_total(pktsum_t *, pktsum_t *, pktsum_t *);
static void	stats_diff(pktsum_t *, pktsum_t *, pktsum_t *);

typedef struct	cmd {
	char	*c_name;
	void	(*c_fn)(int, char **);
} cmd_t;

static cmd_t	cmds[] = {
	{ "show-link", do_show_link },
	{ "show-dev", do_show_dev },

	{ "create-aggr", do_create_aggr },
	{ "delete-aggr", do_delete_aggr },
	{ "add-aggr", do_add_aggr },
	{ "remove-aggr", do_remove_aggr },
	{ "modify-aggr", do_modify_aggr },
	{ "show-aggr", do_show_aggr },
	{ "up-aggr", do_up_aggr },
	{ "down-aggr", do_down_aggr }
};

static const struct option longopts[] = {
	{"vlan-id",	required_argument,	0, 'v'},
	{"dev",		required_argument,	0, 'd'},
	{"policy",	required_argument,	0, 'P'},
	{"lacp-mode",	required_argument,	0, 'l'},
	{"lacp-timer",	required_argument,	0, 'T'},
	{"unicast",	required_argument,	0, 'u'},
	{"statistics",	no_argument,		0, 's'},
	{"interval",	required_argument,	0, 'i'},
	{"lacp",	no_argument,		0, 'L'},
	{"temporary",	no_argument,		0, 't'},
	{"root-dir",	required_argument,	0, 'r'},
	{"parseable",	no_argument,		0, 'p'},
	{ 0, 0, 0, 0 }
};

static char *progname;

#define	PRINT_ERR_DIAG(s, diag, func) {					\
	(void) fprintf(stderr, gettext(s), progname, strerror(errno));	\
	if (diag != 0)							\
		(void) fprintf(stderr, " (%s)", func(diag));		\
	(void) fprintf(stderr, "\n");					\
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext(
	    "usage: dladm create-aggr [-t] [-R <root-dir>] [-P <policy>]\n"
	    "                    [-l <mode>] [-T <time>]\n"
	    "                    [-u <address>] -d <dev> ... <key>\n"
	    "             delete-aggr [-t] [-R <root-dir>] <key>\n"
	    "             add-aggr    [-t] [-R <root-dir>] -d <dev> ... <key>\n"
	    "             remove-aggr [-t] [-R <root-dir>] -d <dev> ... <key>\n"
	    "             modify-aggr [-t] [-R <root-dir>] [-P <policy>]\n"
	    "                    [-l <mode>] [-T <time>] [-u <address>] <key>\n"
	    "             show-aggr [-L] [-s] [-i <interval>] [-p] [<key>]\n"
	    "             show-dev [-s] [-i <interval>] [-p] [<dev>]\n"
	    "             show-link [-s] [-i <interval>] [-p] [<name>]\n"));
	exit(1);
}

int
main(int argc, char *argv[])
{
	int	i;
	cmd_t	*cmdp;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	progname = argv[0];

	if (argc < 2)
		usage();

	if (!priv_ineffect(PRIV_SYS_NET_CONFIG) ||
	    !priv_ineffect(PRIV_NET_RAWACCESS)) {
		(void) fprintf(stderr,
		    gettext("%s: insufficient privileges\n"), progname);
		exit(1);
	}

	for (i = 0; i < sizeof (cmds) / sizeof (cmds[0]); i++) {
		cmdp = &cmds[i];
		if (strcmp(argv[1], cmdp->c_name) == 0) {
			cmdp->c_fn(argc - 1, &argv[1]);
			exit(0);
		}
	}

	(void) fprintf(stderr, gettext("%s: unknown subcommand '%s'\n"),
	    progname, argv[1]);
	usage();

	return (0);
}


static void
do_create_aggr(int argc, char *argv[])
{
	char			option;
	uint16_t		key;
	uint32_t		policy = AGGR_POLICY_L4;
	aggr_lacp_mode_t	lacp_mode = AGGR_LACP_OFF;
	aggr_lacp_timer_t	lacp_timer = AGGR_LACP_TIMER_SHORT;
	laadm_port_attr_db_t	port[MAXPORT];
	uint_t			nport = 0;
	uint8_t			mac_addr[ETHERADDRL];
	boolean_t		mac_addr_fixed = B_FALSE;
	boolean_t		P_arg = B_FALSE;
	boolean_t		l_arg = B_FALSE;
	boolean_t		t_arg = B_FALSE;
	boolean_t		u_arg = B_FALSE;
	boolean_t		T_arg = B_FALSE;
	char			*altroot = NULL;
	char			*endp = NULL;
	laadm_diag_t		diag = 0;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":d:l:P:R:tu:T:",
	    longopts, NULL)) != -1) {
		switch (option) {
		case 'd':
			if (nport >= MAXPORT) {
				(void) fprintf(stderr,
				    gettext("%s: too many <dev> arguments\n"),
				    progname);
				exit(1);
			}

			if (strlcpy(port[nport].lp_devname, optarg,
			    MAXNAMELEN) >= MAXNAMELEN) {
				(void) fprintf(stderr,
				    gettext("%s: device name too long\n"),
				    progname);
				exit(1);
			}

			port[nport].lp_port = 0;

			nport++;
			break;
		case 'P':
			if (P_arg) {
				(void) fprintf(stderr, gettext(
				    "%s: the option -P cannot be specified "
				    "more than once\n"), progname);
				usage();
			}

			P_arg = B_TRUE;

			if (!laadm_str_to_policy(optarg, &policy)) {
				(void) fprintf(stderr,
				    gettext("%s: invalid policy '%s'\n"),
				    progname, optarg);
				exit(1);
			}
			break;
		case 'u':
			if (u_arg) {
				(void) fprintf(stderr, gettext(
				    "%s: the option -u cannot be specified "
				    "more than once\n"), progname);
				usage();
			}

			u_arg = B_TRUE;

			if (!laadm_str_to_mac_addr(optarg, &mac_addr_fixed,
			    mac_addr)) {
				(void) fprintf(stderr,
				    gettext("%s: invalid MAC address '%s'\n"),
				    progname, optarg);
				exit(1);
			}

			break;
		case 'l':
			if (l_arg) {
				(void) fprintf(stderr, gettext(
				    "%s: the option -l cannot be specified "
				    "more than once\n"), progname);
				usage();
			}

			l_arg = B_TRUE;

			if (!laadm_str_to_lacp_mode(optarg, &lacp_mode)) {
				(void) fprintf(stderr,
				    gettext("%s: invalid LACP mode '%s'\n"),
				    progname, optarg);
				exit(1);
			}

			break;
		case 'T':
			if (T_arg) {
				(void) fprintf(stderr, gettext(
				    "%s: the option -T cannot be specified "
				    "more than once\n"), progname);
				usage();
			}

			T_arg = B_TRUE;

			if (!laadm_str_to_lacp_timer(optarg, &lacp_timer)) {
				(void) fprintf(stderr,
				    gettext("%s: invalid LACP timer value"
				    " '%s'\n"),
				    progname, optarg);
				exit(1);
			}

			break;
		case 't':
			t_arg = B_TRUE;
			break;
		case 'R':
			altroot = optarg;
			break;
		case ':':
			(void) fprintf(stderr,
			    gettext("%s: option requires a value '-%c'\n"),
			    progname, optopt);
			exit(1);
			/*NOTREACHED*/
		case '?':
		default:
			(void) fprintf(stderr,
			    gettext("%s: unrecognized option '-%c'\n"),
			    progname, optopt);
			exit(1);
		}
	}

	if (nport == 0)
		usage();

	/* get key value (required last argument) */
	if (optind != (argc-1))
		usage();

	errno = 0;
	key = (int)strtol(argv[optind], &endp, 10);
	if (errno != 0 || key < 1 || *endp != '\0') {
		(void) fprintf(stderr,
		    gettext("%s: illegal key value '%d'\n"),
		    progname, key);
		exit(1);
	}

	if (laadm_create(key, nport, port, policy, mac_addr_fixed,
	    mac_addr, lacp_mode, lacp_timer, t_arg, altroot, &diag) < 0) {
		PRINT_ERR_DIAG("%s: create operation failed: %s", diag,
		    laadm_diag);
		exit(1);
	}
}

static void
do_delete_aggr(int argc, char *argv[])
{
	uint16_t		key;
	char			option;
	boolean_t		t_arg = B_FALSE;
	char			*altroot = NULL;
	char			*endp = NULL;
	laadm_diag_t		diag = 0;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":R:t", longopts,
	    NULL)) != -1) {
		switch (option) {

		case 't':
			t_arg = B_TRUE;
			break;
		case 'R':
			altroot = optarg;
			break;
		case ':':
			(void) fprintf(stderr,
			    gettext("%s: option requires a value '-%c'\n"),
			    progname, optopt);
			exit(1);
			break;
		case '?':
		default:
			(void) fprintf(stderr,
			    gettext("%s: unrecognized option '-%c'\n"),
			    progname, optopt);
			exit(1);
			break;
		}
	}

	/* get key value (required last argument) */
	if (optind != (argc-1))
		usage();

	errno = 0;
	key = (int)strtol(argv[optind], &endp, 10);
	if (errno != 0 || key < 1 || *endp != '\0') {
		(void) fprintf(stderr,
		    gettext("%s: illegal key value '%d'\n"),
		    progname, key);
		exit(1);
	}

	if (laadm_delete(key, t_arg, altroot, &diag) < 0) {
		PRINT_ERR_DIAG("%s: delete operation failed: %s", diag,
		    laadm_diag);
		exit(1);
	}
}

static void
do_add_aggr(int argc, char *argv[])
{
	char			option;
	uint16_t		key;
	laadm_port_attr_db_t	port[MAXPORT];
	uint_t			nport = 0;
	boolean_t		t_arg = B_FALSE;
	char			*altroot = NULL;
	char			*endp = NULL;
	laadm_diag_t		diag = 0;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":d:R:t", longopts,
	    NULL)) != -1) {
		switch (option) {
		case 'd':
			if (nport >= MAXPORT) {
				(void) fprintf(stderr,
				    gettext("%s: too many <dev> arguments\n"),
				    progname);
				exit(1);
			}

			if (strlcpy(port[nport].lp_devname, optarg,
			    MAXNAMELEN) >= MAXNAMELEN) {
				(void) fprintf(stderr,
				    gettext("%s: device name too long\n"),
				    progname);
				exit(1);
			}
			port[nport].lp_port = 0;

			nport++;
			break;
		case 't':
			t_arg = B_TRUE;
			break;
		case 'R':
			altroot = optarg;
			break;
		case ':':
			(void) fprintf(stderr,
			    gettext("%s: option requires a value '-%c'\n"),
			    progname, optopt);
			exit(1);
			/*NOTREACHED*/
		case '?':
		default:
			(void) fprintf(stderr,
			    gettext("%s: unrecognized option '-%c'\n"),
			    progname, optopt);
			exit(1);
		}
	}

	if (nport == 0)
		usage();

	/* get key value (required last argument) */
	if (optind != (argc-1))
		usage();

	errno = 0;
	key = (int)strtol(argv[optind], &endp, 10);
	if (errno != 0 || key < 1 || *endp != '\0') {
		(void) fprintf(stderr,
		    gettext("%s: illegal key value '%d'\n"),
		    progname, key);
		exit(1);
	}

	if (laadm_add(key, nport, port, t_arg, altroot, &diag) < 0) {
		/*
		 * checking ENOTSUP is a temporary workaround
		 * and should be removed once 6399681 is fixed.
		 */
		if (errno == ENOTSUP) {
			(void) fprintf(stderr,
			    gettext("%s: add operation failed: %s\n"),
			    progname,
			    gettext("device capabilities don't match"));
			exit(ENOTSUP);
		}
		PRINT_ERR_DIAG("%s: add operation failed: %s", diag,
		    laadm_diag);
		exit(1);
	}
}

static void
do_remove_aggr(int argc, char *argv[])
{
	char			option;
	uint16_t		key;
	laadm_port_attr_db_t	port[MAXPORT];
	uint_t			nport = 0;
	boolean_t		t_arg = B_FALSE;
	char			*altroot = NULL;
	char			*endp = NULL;
	laadm_diag_t		diag = 0;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":d:R:t",
	    longopts, NULL)) != -1) {
		switch (option) {
		case 'd':
			if (nport >= MAXPORT) {
				(void) fprintf(stderr,
				    gettext("%s: too many <dev> arguments\n"),
				    progname);
				exit(1);
			}

			if (strlcpy(port[nport].lp_devname, optarg,
			    MAXNAMELEN) >= MAXNAMELEN) {
				(void) fprintf(stderr,
				    gettext("%s: device name too long\n"),
				    progname);
				exit(1);
			}
			port[nport].lp_port = 0;

			nport++;
			break;
		case 't':
			t_arg = B_TRUE;
			break;
		case 'R':
			altroot = optarg;
			break;
		case ':':
			(void) fprintf(stderr,
			    gettext("%s: option requires a value '-%c'\n"),
			    progname, optopt);
			exit(1);
			/*NOTREACHED*/
		case '?':
		default:
			(void) fprintf(stderr,
			    gettext("%s: unrecognized option '-%c'\n"),
			    progname, optopt);
			exit(1);
		}
	}

	if (nport == 0)
		usage();

	/* get key value (required last argument) */
	if (optind != (argc-1))
		usage();

	errno = 0;
	key = (int)strtol(argv[optind], &endp, 10);
	if (errno != 0 || key < 1 || *endp != '\0') {
		(void) fprintf(stderr,
		    gettext("%s: illegal key value '%d'\n"),
		    progname, key);
		exit(1);
	}

	if (laadm_remove(key, nport, port, t_arg, altroot, &diag) < 0) {
		PRINT_ERR_DIAG("%s: remove operation failed: %s", diag,
		    laadm_diag);
		exit(1);
	}
}

static void
do_modify_aggr(int argc, char *argv[])
{
	char			option;
	uint16_t		key;
	uint32_t		policy = AGGR_POLICY_L4;
	aggr_lacp_mode_t	lacp_mode = AGGR_LACP_OFF;
	aggr_lacp_timer_t	lacp_timer = AGGR_LACP_TIMER_SHORT;
	uint8_t			mac_addr[ETHERADDRL];
	boolean_t		mac_addr_fixed = B_FALSE;
	uint8_t			modify_mask = 0;
	boolean_t		t_arg = B_FALSE;
	char			*altroot = NULL;
	char			*endp = NULL;
	laadm_diag_t		diag = 0;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":l:P:R:tu:T:", longopts,
	    NULL)) != -1) {
		switch (option) {
		case 'P':
			if (modify_mask & LAADM_MODIFY_POLICY) {
				(void) fprintf(stderr, gettext(
				    "%s: the option -P cannot be specified "
				    "more than once\n"), progname);
				usage();
			}

			modify_mask |= LAADM_MODIFY_POLICY;

			if (!laadm_str_to_policy(optarg, &policy)) {
				(void) fprintf(stderr,
				    gettext("%s: invalid policy '%s'\n"),
				    progname, optarg);
				exit(1);
			}
			break;
		case 'u':
			if (modify_mask & LAADM_MODIFY_MAC) {
				(void) fprintf(stderr, gettext(
				    "%s: the option -u cannot be specified "
				    "more than once\n"), progname);
				usage();
			}

			modify_mask |= LAADM_MODIFY_MAC;

			if (!laadm_str_to_mac_addr(optarg, &mac_addr_fixed,
			    mac_addr)) {
				(void) fprintf(stderr,
				    gettext("%s: invalid MAC address '%s'\n"),
				    progname, optarg);
				exit(1);
			}

			break;
		case 'l':
			if (modify_mask & LAADM_MODIFY_LACP_MODE) {
				(void) fprintf(stderr, gettext(
				    "%s: the option -l cannot be specified "
				    "more than once\n"), progname);
				usage();
			}

			modify_mask |= LAADM_MODIFY_LACP_MODE;

			if (!laadm_str_to_lacp_mode(optarg, &lacp_mode)) {
				(void) fprintf(stderr,
				    gettext("%s: invalid LACP mode '%s'\n"),
				    progname, optarg);
				exit(1);
			}

			break;
		case 'T':
			if (modify_mask & LAADM_MODIFY_LACP_TIMER) {
				(void) fprintf(stderr, gettext(
				    "%s: the option -T cannot be specified "
				    "more than once\n"), progname);
				usage();
			}

			modify_mask |= LAADM_MODIFY_LACP_TIMER;

			if (!laadm_str_to_lacp_timer(optarg, &lacp_timer)) {
				(void) fprintf(stderr,
				    gettext("%s: invalid LACP timer value"
				    " '%s'\n"),
				    progname, optarg);
				exit(1);
			}

			break;
		case 't':
			t_arg = B_TRUE;
			break;
		case 'R':
			altroot = optarg;
			break;
		case ':':
			(void) fprintf(stderr,
			    gettext("%s: option requires a value '-%c'\n"),
			    progname, optopt);
			exit(1);
			/*NOTREACHED*/
		case '?':
		default:
			(void) fprintf(stderr,
			    gettext("%s: unrecognized option '-%c'\n"),
			    progname, optopt);
			exit(1);
		}
	}

	if (modify_mask == 0) {
		(void) fprintf(stderr, gettext("%s: at least one of the "
		    "-PulT options must be specified\n"), progname);
		usage();
	}

	/* get key value (required last argument) */
	if (optind != (argc-1))
		usage();

	errno = 0;
	key = (int)strtol(argv[optind], &endp, 10);
	if (errno != 0 || key < 1 || *endp != '\0') {
		(void) fprintf(stderr,
		    gettext("%s: illegal key value '%d'\n"),
		    progname, key);
		exit(1);
	}


	if (laadm_modify(key, modify_mask, policy, mac_addr_fixed, mac_addr,
	    lacp_mode, lacp_timer, t_arg, altroot, &diag) < 0) {
		PRINT_ERR_DIAG("%s: modify operation failed: %s", diag,
		    laadm_diag);
		exit(1);
	}
}

static void
do_up_aggr(int argc, char *argv[])
{
	uint16_t	key = 0;
	char		*endp = NULL;
	laadm_diag_t	diag = 0;

	/* get aggregation key (optional last argument) */
	if (argc == 2) {
		errno = 0;
		key = (int)strtol(argv[1], &endp, 10);
		if (errno != 0 || key < 1 || *endp != '\0') {
			(void) fprintf(stderr,
			    gettext("%s: illegal key value '%d'\n"),
			    progname, key);
			exit(1);
		}
	} else if (argc > 2) {
		usage();
	}

	if (laadm_up(key, NULL, &diag) < 0) {
		if (key != 0) {
			(void) fprintf(stderr,
			    gettext("%s: could not bring up aggregation"
			    " '%u' : %s"), progname, key, strerror(errno));
			if (diag != 0)
				(void) fprintf(stderr, " (%s)",
				    laadm_diag(diag));
			(void) fprintf(stderr, "\n");
		} else {
			PRINT_ERR_DIAG(
			    "%s: could not bring aggregations up: %s",
			    diag, laadm_diag);
		}
		exit(1);
	}
}

static void
do_down_aggr(int argc, char *argv[])
{
	uint16_t	key = 0;
	char		*endp = NULL;

	/* get aggregation key (optional last argument) */
	if (argc == 2) {
		errno = 0;
		key = (int)strtol(argv[1], &endp, 10);
		if (errno != 0 || key < 1 || *endp != '\0') {
			(void) fprintf(stderr,
			    gettext("%s: illegal key value '%d'\n"),
			    progname, key);
			exit(1);
		}
	} else if (argc > 2) {
		usage();
	}

	if (laadm_down(key) < 0) {
		if (key != 0) {
			(void) fprintf(stderr,
			    gettext("%s: could not bring aggregation"
			    " down '%u' : %s"),
			    progname, key, strerror(errno));
			(void) fprintf(stderr, "\n");
		} else {
			(void) fprintf(stderr,
			    gettext("%s: could not bring aggregations"
			    " down: %s"), progname, strerror(errno));
		}
		exit(1);
	}
}

#define	TYPE_WIDTH	10

static void
print_link_parseable(const char *name, dladm_attr_t *dap, boolean_t legacy)
{
	char		type[TYPE_WIDTH];

	if (!legacy) {
		if (dap->da_vid != 0) {
			(void) snprintf(type, TYPE_WIDTH, "vlan %u",
			    dap->da_vid);
		} else {
			(void) snprintf(type, TYPE_WIDTH, "non-vlan");
		}
		if (strcmp(dap->da_dev, AGGR_DEV) == 0) {
			(void) printf("%s type=%s mtu=%d key=%u\n",
			    name, type, dap->da_max_sdu, dap->da_port);
		} else {
			(void) printf("%s type=%s mtu=%d device=%s\n",
			    name, type, dap->da_max_sdu, dap->da_dev);
		}
	} else {
		(void) printf("%s type=legacy mtu=%d device=%s\n",
		    name, dap->da_max_sdu, name);
	}
}

static void
print_link(const char *name, dladm_attr_t *dap, boolean_t legacy)
{
	char		type[TYPE_WIDTH];

	if (!legacy) {
		if (dap->da_vid != 0) {
			(void) snprintf(type, TYPE_WIDTH, gettext("vlan %u"),
			    dap->da_vid);
		} else {
			(void) snprintf(type, TYPE_WIDTH, gettext("non-vlan"));
		}
		if (strcmp(dap->da_dev, AGGR_DEV) == 0) {
			(void) printf(gettext("%-9s\ttype: %s\tmtu: %d"
			    "\taggregation: key %u\n"), name, type,
			    dap->da_max_sdu, dap->da_port);
		} else {
			(void) printf(gettext("%-9s\ttype: %s\tmtu: "
			    "%d\tdevice: %s\n"), name, type, dap->da_max_sdu,
			    dap->da_dev);
		}
	} else {
		(void) printf(gettext("%-9s\ttype: legacy\tmtu: "
		    "%d\tdevice: %s\n"), name, dap->da_max_sdu, name);
	}
}

static int
get_if_info(const char *name, dladm_attr_t *dlattrp, boolean_t *legacy)
{
	int	err;

	if ((err = dladm_info(name, dlattrp)) == 0) {
		*legacy = B_FALSE;
	} else if (err < 0 && errno == ENODEV) {
		int		fd;
		dlpi_if_attr_t	dia;
		dl_info_ack_t	dlia;

		/*
		 * A return value of ENODEV means that the specified
		 * device is not gldv3.
		 */
		if ((fd = dlpi_if_open(name, &dia, B_FALSE)) != -1 &&
		    dlpi_info(fd, -1, &dlia, NULL, NULL, NULL, NULL,
		    NULL, NULL) != -1) {
			(void) dlpi_close(fd);

			*legacy = B_TRUE;
			bzero(dlattrp, sizeof (*dlattrp));
			dlattrp->da_max_sdu = (uint_t)dlia.dl_max_sdu;
		} else {
			errno = ENOENT;
			return (-1);
		}
	} else {
		/*
		 * If the return value is not ENODEV, this means that
		 * user is either passing in a bogus interface name
		 * or a vlan interface name that doesn't exist yet.
		 */
		errno = ENOENT;
		return (-1);
	}
	return (0);
}

/* ARGSUSED */
static void
show_link(void *arg, const char *name)
{
	dladm_attr_t	dlattr;
	boolean_t	legacy = B_TRUE;
	show_link_state_t *state = (show_link_state_t *)arg;

	if (get_if_info(name, &dlattr, &legacy) < 0) {
		(void) fprintf(stderr, gettext("%s: invalid device '%s'\n"),
		    progname, name);
		exit(1);
	}

	if (state->ls_parseable) {
		print_link_parseable(name, &dlattr, legacy);
	} else {
		print_link(name, &dlattr, legacy);
	}
}

static void
show_link_stats(void *arg, const char *name)
{
	show_link_state_t *state = (show_link_state_t *)arg;
	pktsum_t stats, diff_stats;

	if (state->ls_firstonly) {
		if (state->ls_donefirst)
			return;
		state->ls_donefirst = B_TRUE;
	} else {
		bzero(&state->ls_prevstats, sizeof (state->ls_prevstats));
	}

	get_link_stats(name, &stats);
	stats_diff(&diff_stats, &stats, &state->ls_prevstats);

	(void) printf("%s", name);
	(void) printf("\t\t%-10llu", diff_stats.ipackets);
	(void) printf("%-12llu", diff_stats.rbytes);
	(void) printf("%-8u", diff_stats.ierrors);
	(void) printf("%-10llu", diff_stats.opackets);
	(void) printf("%-12llu", diff_stats.obytes);
	(void) printf("%-8u\n", diff_stats.oerrors);

	state->ls_prevstats = stats;
}

static void
dump_grp(laadm_grp_attr_sys_t	*grp, boolean_t parseable)
{
	char policy_str[LAADM_POLICY_STR_LEN];
	char addr_str[ETHERADDRL * 3];

	if (!parseable) {
		(void) printf(gettext("key: %d (0x%04x)"),
		    grp->lg_key, grp->lg_key);

		(void) printf(gettext("\tpolicy: %s"),
		    laadm_policy_to_str(grp->lg_policy, policy_str));

		(void) printf(gettext("\taddress: %s (%s)\n"),
		    laadm_mac_addr_to_str(grp->lg_mac, addr_str),
		    (grp->lg_mac_fixed) ? gettext("fixed") : gettext("auto"));
	} else {
		(void) printf("aggr key=%d", grp->lg_key);

		(void) printf(" policy=%s",
		    laadm_policy_to_str(grp->lg_policy, policy_str));

		(void) printf(" address=%s",
		    laadm_mac_addr_to_str(grp->lg_mac, addr_str));

		(void) printf(" address-type=%s\n",
		    (grp->lg_mac_fixed) ? "fixed" : "auto");
	}
}

static void
dump_grp_lacp(laadm_grp_attr_sys_t *grp, boolean_t parseable)
{
	const char *lacp_mode_str = laadm_lacp_mode_to_str(grp->lg_lacp_mode);
	const char *lacp_timer_str =
	    laadm_lacp_timer_to_str(grp->lg_lacp_timer);

	if (!parseable) {
		(void) printf(gettext("\t\tLACP mode: %s"), lacp_mode_str);
		(void) printf(gettext("\tLACP timer: %s\n"), lacp_timer_str);
	} else {
		(void) printf(" lacp-mode=%s", lacp_mode_str);
		(void) printf(" lacp-timer=%s\n", lacp_timer_str);
	}
}

static void
dump_grp_stats(laadm_grp_attr_sys_t *grp)
{
	(void) printf("key: %d", grp->lg_key);
	(void) printf("\tipackets  rbytes      opackets	 obytes		 ");
	(void) printf("%%ipkts	%%opkts\n");
}

static void
dump_ports_lacp_head(void)
{
	(void) printf(DUMP_LACP_FORMAT, gettext("device"), gettext("activity"),
	    gettext("timeout"), gettext("aggregatable"), gettext("sync"),
	    gettext("coll"), gettext("dist"), gettext("defaulted"),
	    gettext("expired"));
}

static void
dump_ports_head(void)
{
	(void) printf(gettext("	   device\taddress\t\t	speed\t\tduplex\tlink\t"
	    "state\n"));
}

static char *
port_state_to_str(aggr_port_state_t state_num)
{
	int			i;
	port_state_t		*state;

	for (i = 0; i < NPORTSTATES; i++) {
		state = &port_states[i];
		if (state->state_num == state_num)
			return (state->state_name);
	}

	return ("unknown");
}

static void
dump_port(laadm_port_attr_sys_t *port, boolean_t parseable)
{
	char *dev = port->lp_devname;
	uint_t portnum = port->lp_port;
	char buf[ETHERADDRL * 3];

	if (!parseable) {
		(void) printf("	   %-9s\t%s", dev, laadm_mac_addr_to_str(
		    port->lp_mac, buf));
		(void) printf("\t  %-5u Mbps", (int)(mac_ifspeed(dev, portnum) /
		    1000000ull));
		(void) printf("\t%s", mac_link_duplex(dev, portnum));
		(void) printf("\t%s", mac_link_state(dev, portnum));
		(void) printf("\t%s\n", port_state_to_str(port->lp_state));

	} else {
		(void) printf(" device=%s address=%s", dev,
		    laadm_mac_addr_to_str(port->lp_mac, buf));
		(void) printf(" speed=%u", (int)(mac_ifspeed(dev, portnum) /
		    1000000ull));
		(void) printf(" duplex=%s", mac_link_duplex(dev, portnum));
		(void) printf(" link=%s", mac_link_state(dev, portnum));
		(void) printf(" port=%s", port_state_to_str(port->lp_state));
	}
}

static void
dump_port_lacp(laadm_port_attr_sys_t *port)
{
	aggr_lacp_state_t *state = &port->lp_lacp_state;

	(void) printf(DUMP_LACP_FORMAT,
	    port->lp_devname, state->bit.activity ? "active" : "passive",
	    state->bit.timeout ? "short" : "long",
	    state->bit.aggregation ? "yes" : "no",
	    state->bit.sync ? "yes" : "no",
	    state->bit.collecting ? "yes" : "no",
	    state->bit.distributing ? "yes" : "no",
	    state->bit.defaulted ? "yes" : "no",
	    state->bit.expired ? "yes" : "no");
}

static void
dump_port_stat(int index, show_grp_state_t *state, pktsum_t *port_stats,
    pktsum_t *tot_stats)
{
	pktsum_t	diff_stats;
	pktsum_t	*old_stats = &state->gs_prevstats[index];

	stats_diff(&diff_stats, port_stats, old_stats);

	(void) printf("\t%-10llu", diff_stats.ipackets);
	(void) printf("%-12llu", diff_stats.rbytes);
	(void) printf("%-10llu", diff_stats.opackets);
	(void) printf("%-12llu", diff_stats.obytes);

	if (tot_stats->ipackets == 0)
		(void) printf("\t-");
	else
		(void) printf("\t%-6.1f", (double)diff_stats.ipackets/
		    (double)tot_stats->ipackets * 100);

	if (tot_stats->opackets == 0)
		(void) printf("\t-");
	else
		(void) printf("\t%-6.1f", (double)diff_stats.opackets/
		    (double)tot_stats->opackets * 100);

	(void) printf("\n");

	*old_stats = *port_stats;
}

static int
show_key(void *arg, laadm_grp_attr_sys_t *grp)
{
	show_grp_state_t	*state = (show_grp_state_t *)arg;
	int			i;
	pktsum_t		pktsumtot, port_stat;

	if (state->gs_key != 0 && state->gs_key != grp->lg_key)
		return (0);
	if (state->gs_firstonly) {
		if (state->gs_found)
			return (0);
	} else {
		bzero(&state->gs_prevstats, sizeof (state->gs_prevstats));
	}

	state->gs_found = B_TRUE;

	if (state->gs_stats) {
		/* show statistics */
		dump_grp_stats(grp);

		/* sum the ports statistics */
		bzero(&pktsumtot, sizeof (pktsumtot));
		for (i = 0; i < grp->lg_nports; i++) {
			get_mac_stats(grp->lg_ports[i].lp_devname,
			    grp->lg_ports[i].lp_port, &port_stat);
			stats_total(&pktsumtot, &port_stat,
			    &state->gs_prevstats[i]);
		}

		(void) printf("	   Total");
		(void) printf("\t%-10llu", pktsumtot.ipackets);
		(void) printf("%-12llu", pktsumtot.rbytes);
		(void) printf("%-10llu", pktsumtot.opackets);
		(void) printf("%-12llu\n", pktsumtot.obytes);

		for (i = 0; i < grp->lg_nports; i++) {
			get_mac_stats(grp->lg_ports[i].lp_devname,
			    grp->lg_ports[i].lp_port, &port_stat);
			(void) printf("	   %s", grp->lg_ports[i].lp_devname);
			dump_port_stat(i, state, &port_stat, &pktsumtot);
		}
	} else if (state->gs_lacp) {
		/* show LACP info */
		dump_grp(grp, state->gs_parseable);
		dump_grp_lacp(grp, state->gs_parseable);
		dump_ports_lacp_head();
		for (i = 0; i < grp->lg_nports; i++)
			dump_port_lacp(&grp->lg_ports[i]);
	} else {
		dump_grp(grp, state->gs_parseable);
		if (!state->gs_parseable)
			dump_ports_head();
		for (i = 0; i < grp->lg_nports; i++) {
			if (state->gs_parseable)
				(void) printf("dev key=%d", grp->lg_key);
			dump_port(&grp->lg_ports[i], state->gs_parseable);
			if (state->gs_parseable)
				(void) printf("\n");
		}
	}

	return (0);
}

static int
kstat_value(kstat_t *ksp, const char *name, uint8_t type, void *buf)
{
	kstat_named_t	*knp;

	if ((knp = kstat_data_lookup(ksp, (char *)name)) == NULL)
		return (-1);

	if (knp->data_type != type)
		return (-1);

	switch (type) {
	case KSTAT_DATA_UINT64:
		*(uint64_t *)buf = knp->value.ui64;
		break;
	case KSTAT_DATA_UINT32:
		*(uint32_t *)buf = knp->value.ui32;
		break;
	default:
		return (-1);
	}

	return (0);
}

static void
show_dev(void *arg, const char *dev)
{
	show_mac_state_t *state = (show_mac_state_t *)arg;

	(void) printf("%s", dev);

	if (!state->ms_parseable) {
		(void) printf(gettext("\t\tlink: %s"),
		    mac_link_state(dev, 0));
		(void) printf(gettext("\tspeed: %-5u Mbps"),
		    (unsigned int)(mac_ifspeed(dev, 0) / 1000000ull));
		(void) printf(gettext("\tduplex: %s\n"),
		    mac_link_duplex(dev, 0));
	} else {
		(void) printf(" link=%s", mac_link_state(dev, 0));
		(void) printf(" speed=%u",
		    (unsigned int)(mac_ifspeed(dev, 0) / 1000000ull));
		(void) printf(" duplex=%s\n", mac_link_duplex(dev, 0));
	}
}

/*ARGSUSED*/
static void
show_dev_stats(void *arg, const char *dev)
{
	show_mac_state_t *state = (show_mac_state_t *)arg;
	pktsum_t stats, diff_stats;

	if (state->ms_firstonly) {
		if (state->ms_donefirst)
			return;
		state->ms_donefirst = B_TRUE;
	} else {
		bzero(&state->ms_prevstats, sizeof (state->ms_prevstats));
	}

	get_mac_stats(dev, 0, &stats);
	stats_diff(&diff_stats, &stats, &state->ms_prevstats);

	(void) printf("%s", dev);
	(void) printf("\t\t%-10llu", diff_stats.ipackets);
	(void) printf("%-12llu", diff_stats.rbytes);
	(void) printf("%-8u", diff_stats.ierrors);
	(void) printf("%-10llu", diff_stats.opackets);
	(void) printf("%-12llu", diff_stats.obytes);
	(void) printf("%-8u\n", diff_stats.oerrors);

	state->ms_prevstats = stats;
}

static void
do_show_link(int argc, char *argv[])
{
	char		*name = NULL;
	int		option;
	boolean_t	s_arg = B_FALSE;
	boolean_t	i_arg = B_FALSE;
	uint32_t	interval = 0;
	show_link_state_t state;
	char		*endp = NULL;

	state.ls_stats = B_FALSE;
	state.ls_parseable = B_FALSE;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":psi:",
	    longopts, NULL)) != -1) {
		switch (option) {
		case 'p':
			state.ls_parseable = B_TRUE;
			break;
		case 's':
			if (s_arg) {
				(void) fprintf(stderr, gettext(
				    "%s: the option -s cannot be specified "
				    "more than once\n"), progname);
				usage();
			}

			s_arg = B_TRUE;
			break;
		case 'i':
			if (i_arg) {
				(void) fprintf(stderr, gettext(
				    "%s: the option -i cannot be specified "
				    "more than once\n"), progname);
				usage();
			}

			i_arg = B_TRUE;

			errno = 0;
			interval = (int)strtol(optarg, &endp, 10);
			if (errno != 0 || interval == 0 || *endp != '\0') {
				(void) fprintf(stderr,
				    gettext("%s: invalid interval value"
				    " '%d'\n"),
				    progname, interval);
				exit(1);
			}
			break;
		case ':':
			(void) fprintf(stderr,
			    gettext("%s: option requires a value '-%c'\n"),
			    progname, optopt);
			exit(1);
			/*NOTREACHED*/
		case '?':
		default:
			(void) fprintf(stderr,
			    gettext("%s: unrecognized option '-%c'\n"),
			    progname, optopt);
			exit(1);
		}
	}

	if (i_arg && !s_arg) {
		(void) fprintf(stderr, gettext("%s: the option -i "
		    "can be used only with -s\n"), progname);
		usage();
	}


	/* get link name (optional last argument) */
	if (optind == (argc-1))
		name = argv[optind];
	else if (optind != argc)
		usage();

	if (s_arg) {
		link_stats(name, interval);
		return;
	}

	if (name == NULL) {
		(void) dladm_walk(show_link, &state);
	} else {
		show_link(&state, name);
	}
}

static void
do_show_aggr(int argc, char *argv[])
{
	int			option;
	uint16_t		key = 0;
	boolean_t		L_arg = B_FALSE;
	boolean_t		s_arg = B_FALSE;
	boolean_t		i_arg = B_FALSE;
	show_grp_state_t	state;
	uint32_t		interval = 0;
	char			*endp = NULL;

	state.gs_stats = B_FALSE;
	state.gs_lacp = B_FALSE;
	state.gs_parseable = B_FALSE;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":Lpsi:",
	    longopts, NULL)) != -1) {
		switch (option) {
		case 'L':
			if (L_arg) {
				(void) fprintf(stderr, gettext(
				    "%s: the option -L cannot be specified "
				    "more than once\n"), progname);
				usage();
			}

			if (s_arg || i_arg) {
				(void) fprintf(stderr, gettext(
				    "%s: the option -L cannot be used with "
				    "any of -is\n"), progname);
				usage();
			}

			L_arg = B_TRUE;

			state.gs_lacp = B_TRUE;
			break;
		case 'p':
			state.gs_parseable = B_TRUE;
			break;
		case 's':
			if (s_arg) {
				(void) fprintf(stderr, gettext(
				    "%s: the option -s cannot be specified "
				    "more than once\n"), progname);
				usage();
			}

			if (L_arg) {
				(void) fprintf(stderr, gettext(
				    "%s: the option -L cannot be used "
				    "with -k\n"), progname);
				usage();
			}

			s_arg = B_TRUE;
			break;
		case 'i':
			if (i_arg) {
				(void) fprintf(stderr, gettext(
				    "%s: the option -i cannot be specified "
				    "more than once\n"), progname);
				usage();
			}

			if (L_arg) {
				(void) fprintf(stderr, gettext(
				    "%s: the option -i cannot be used "
				    "with -L\n"), progname);
				usage();
			}

			i_arg = B_TRUE;

			errno = 0;
			interval = (int)strtol(optarg, &endp, 10);
			if (errno != 0 || interval == 0 || *endp != '\0') {
				(void) fprintf(stderr,
				    gettext("%s: invalid interval value"
				    " '%d'\n"),
				    progname, interval);
				exit(1);
			}
			break;
		case ':':
			(void) fprintf(stderr,
			    gettext("%s: option requires a value '-%c'\n"),
			    progname, optopt);
			exit(1);
			/*NOTREACHED*/
		case '?':
		default:
			(void) fprintf(stderr,
			    gettext("%s: unrecognized option '-%c'\n"),
			    progname, optopt);
			exit(1);
		}
	}

	if (i_arg && !s_arg) {
		(void) fprintf(stderr, gettext("%s: the option -i "
		    "can be used only with -s\n"), progname);
		usage();
	}

	/* get aggregation key (optional last argument) */
	if (optind == (argc-1)) {
		errno = 0;
		key = (int)strtol(argv[optind], &endp, 10);
		if (errno != 0 || key < 1 || *endp != '\0') {
			(void) fprintf(stderr,
			    gettext("%s: illegal key value '%d'\n"),
			    progname, key);
			exit(1);
		}
	} else if (optind != argc) {
		usage();
	}

	if (s_arg) {
		aggr_stats(key, interval);
		return;
	}

	state.gs_key = key;
	state.gs_found = B_FALSE;

	(void) laadm_walk_sys(show_key, &state);

	if (key != 0 && !state.gs_found) {
		(void) fprintf(stderr,
		    gettext("%s: non-existent aggregation key '%u'\n"),
		    progname, key);
		exit(1);
	}
}

static void
do_show_dev(int argc, char *argv[])
{
	int		option;
	char		*dev = NULL;
	boolean_t	s_arg = B_FALSE;
	boolean_t	i_arg = B_FALSE;
	uint32_t	interval = 0;
	show_mac_state_t state;
	char		*endp = NULL;

	state.ms_parseable = B_FALSE;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":psi:",
	    longopts, NULL)) != -1) {
		switch (option) {
		case 'p':
			state.ms_parseable = B_TRUE;
			break;
		case 's':
			if (s_arg) {
				(void) fprintf(stderr, gettext(
				    "%s: the option -s cannot be specified "
				    "more than once\n"), progname);
				usage();
			}

			s_arg = B_TRUE;
			break;
		case 'i':
			if (i_arg) {
				(void) fprintf(stderr, gettext(
				    "%s: the option -i cannot be specified "
				    "more than once\n"), progname);
				usage();
			}

			i_arg = B_TRUE;

			errno = 0;
			interval = (int)strtol(optarg, &endp, 10);
			if (errno != 0 || interval == 0 || *endp != '\0') {
				(void) fprintf(stderr,
				    gettext("%s: invalid interval value"
				    " '%d'\n"),
				    progname, interval);
				exit(1);
			}
			break;
		case ':':
			(void) fprintf(stderr,
			    gettext("%s: option requires a value '-%c'\n"),
			    progname, optopt);
			exit(1);
			/*NOTREACHED*/
		case '?':
		default:
			(void) fprintf(stderr,
			    gettext("%s: unrecognized option '-%c'\n"),
			    progname, optopt);
			exit(1);
		}
	}

	if (i_arg && !s_arg) {
		(void) fprintf(stderr, gettext("%s: the option -i "
		    "can be used only with -s\n"), progname);
		usage();
	}

	/* get dev name (optional last argument) */
	if (optind == (argc-1))
		dev = argv[optind];
	else if (optind != argc)
		usage();

	if (dev != NULL) {
		int		index;
		char		drv[LIFNAMSIZ];
		dladm_attr_t	dlattr;
		boolean_t	legacy;

		/*
		 * Check for invalid devices.
		 * aggregations and vlans are not considered devices.
		 */
		if (strncmp(dev, "aggr", 4) == 0 ||
		    dlpi_if_parse(dev, drv, &index) < 0 ||
		    index >= 1000 ||
		    get_if_info(dev, &dlattr, &legacy) < 0) {
			(void) fprintf(stderr,
			    gettext("%s: invalid device '%s'\n"),
			    progname, dev);
			exit(1);
		}
	}

	if (s_arg) {
		dev_stats(dev, interval);
		return;
	}

	if (dev == NULL)
		(void) macadm_walk(show_dev, &state, B_TRUE);
	else
		show_dev(&state, dev);
}

/* ARGSUSED */
static void
link_stats(const char *link, uint32_t interval)
{
	dladm_attr_t		dlattr;
	boolean_t		legacy;
	show_link_state_t	state;

	if (link != NULL && get_if_info(link, &dlattr, &legacy) < 0) {
		(void) fprintf(stderr, gettext("%s: invalid device '%s'\n"),
		    progname, link);
		exit(1);
	}
	bzero(&state, sizeof (state));

	/*
	 * If an interval is specified, continuously show the stats
	 * only for the first MAC port.
	 */
	state.ls_firstonly = (interval != 0);

	for (;;) {
		(void) printf("\t\tipackets  rbytes	 ierrors ");
		(void) printf("opackets	 obytes	     oerrors\n");

		state.ls_donefirst = B_FALSE;
		if (link == NULL)
			(void) dladm_walk(show_link_stats, &state);
		else
			show_link_stats(&state, link);

		if (interval == 0)
			break;

		(void) sleep(interval);
	}
}

/* ARGSUSED */
static void
aggr_stats(uint16_t key, uint32_t interval)
{
	show_grp_state_t state;

	bzero(&state, sizeof (state));
	state.gs_stats = B_TRUE;
	state.gs_key = key;

	/*
	 * If an interval is specified, continuously show the stats
	 * only for the first group.
	 */
	state.gs_firstonly = (interval != 0);

	for (;;) {
		state.gs_found = B_FALSE;
		(void) laadm_walk_sys(show_key, &state);
		if (state.gs_key != 0 && !state.gs_found) {
			(void) fprintf(stderr,
			    gettext("%s: non-existent aggregation key '%u'\n"),
			    progname, key);
			exit(1);
		}

		if (interval == 0)
			break;

		(void) sleep(interval);
	}
}

/* ARGSUSED */
static void
dev_stats(const char *dev, uint32_t interval)
{
	show_mac_state_t state;

	bzero(&state, sizeof (state));

	/*
	 * If an interval is specified, continuously show the stats
	 * only for the first MAC port.
	 */
	state.ms_firstonly = (interval != 0);

	for (;;) {

		(void) printf("\t\tipackets  rbytes	 ierrors ");
		(void) printf("opackets	 obytes	     oerrors\n");

		state.ms_donefirst = B_FALSE;
		if (dev == NULL)
			(void) macadm_walk(show_dev_stats, &state, B_TRUE);
		else
			show_dev_stats(&state, dev);

		if (interval == 0)
			break;

		(void) sleep(interval);
	}
}

/* accumulate stats (s1 += (s2 - s3)) */
static void
stats_total(pktsum_t *s1, pktsum_t *s2, pktsum_t *s3)
{
	s1->ipackets += (s2->ipackets - s3->ipackets);
	s1->opackets += (s2->opackets - s3->opackets);
	s1->rbytes += (s2->rbytes - s3->rbytes);
	s1->obytes += (s2->obytes - s3->obytes);
	s1->ierrors += (s2->ierrors - s3->ierrors);
	s1->oerrors += (s2->oerrors - s3->oerrors);
}

/* compute stats differences (s1 = s2 - s3) */
static void
stats_diff(pktsum_t *s1, pktsum_t *s2, pktsum_t *s3)
{
	s1->ipackets = s2->ipackets - s3->ipackets;
	s1->opackets = s2->opackets - s3->opackets;
	s1->rbytes = s2->rbytes - s3->rbytes;
	s1->obytes = s2->obytes - s3->obytes;
	s1->ierrors = s2->ierrors - s3->ierrors;
	s1->oerrors = s2->oerrors - s3->oerrors;
}

/*
 * In the following routines, we do the first kstat_lookup()
 * assuming that the device is gldv3-based and that the kstat
 * name is of the format <driver_name><instance>/<port>. If the
 * lookup fails, we redo the kstat_lookup() using the kstat name
 * <driver_name><instance>. This second lookup is needed for
 * getting kstats from legacy devices. This can fail too if the
 * device is not attached or the device is legacy and doesn't
 * export the kstats we need.
 */
static void
get_stats(char *module, int instance, char *name, pktsum_t *stats)
{
	kstat_ctl_t	*kcp;
	kstat_t		*ksp;

	if ((kcp = kstat_open()) == NULL) {
		(void) fprintf(stderr,
		    gettext("%s: kstat open operation failed\n"),
		    progname);
		return;
	}

	if ((ksp = kstat_lookup(kcp, module, instance, name)) == NULL &&
	    (module == NULL ||
	    (ksp = kstat_lookup(kcp, NULL, -1, module)) == NULL)) {
		/*
		 * The kstat query could fail if the underlying MAC
		 * driver was already detached.
		 */
		(void) kstat_close(kcp);
		return;
	}

	if (kstat_read(kcp, ksp, NULL) == -1)
		goto bail;

	if (kstat_value(ksp, "ipackets64", KSTAT_DATA_UINT64,
	    &stats->ipackets) < 0)
		goto bail;

	if (kstat_value(ksp, "opackets64", KSTAT_DATA_UINT64,
	    &stats->opackets) < 0)
		goto bail;

	if (kstat_value(ksp, "rbytes64", KSTAT_DATA_UINT64,
	    &stats->rbytes) < 0)
		goto bail;

	if (kstat_value(ksp, "obytes64", KSTAT_DATA_UINT64,
	    &stats->obytes) < 0)
		goto bail;

	if (kstat_value(ksp, "ierrors", KSTAT_DATA_UINT32,
	    &stats->ierrors) < 0)
		goto bail;

	if (kstat_value(ksp, "oerrors", KSTAT_DATA_UINT32,
	    &stats->oerrors) < 0)
		goto bail;

	(void) kstat_close(kcp);
	return;

bail:
	(void) fprintf(stderr,
	    gettext("%s: kstat operation failed\n"),
	    progname);
	(void) kstat_close(kcp);
}

static void
get_mac_stats(const char *dev, uint_t port, pktsum_t *stats)
{
	char			name[MAXNAMELEN];

	bzero(stats, sizeof (*stats));

	(void) snprintf(name, MAXNAMELEN - 1, "%s/%u", dev, port);
	get_stats((char *)dev, 0, name, stats);
}

static void
get_link_stats(const char *link, pktsum_t *stats)
{
	bzero(stats, sizeof (*stats));
	get_stats(NULL, -1, (char *)link, stats);
}

static uint64_t
mac_ifspeed(const char *dev, uint_t port)
{
	char		name[MAXNAMELEN];
	kstat_ctl_t	*kcp;
	kstat_t		*ksp;
	uint64_t	ifspeed = 0;

	if ((kcp = kstat_open()) == NULL) {
		(void) fprintf(stderr,
		    gettext("%s: kstat open operation failed\n"),
		    progname);
		return (0);
	}

	(void) snprintf(name, MAXNAMELEN - 1, "%s/%u", dev, port);
	if ((ksp = kstat_lookup(kcp, (char *)dev, -1, name)) == NULL &&
	    (ksp = kstat_lookup(kcp, NULL, -1, (char *)dev)) == NULL) {

		/*
		 * The kstat query could fail if the underlying MAC
		 * driver was already detached.
		 */
		goto bail;
	}

	if (kstat_read(kcp, ksp, NULL) == -1) {
		(void) fprintf(stderr,
		    gettext("%s: kstat read failed\n"),
		    progname);
		goto bail;
	}

	if (kstat_value(ksp, "ifspeed", KSTAT_DATA_UINT64, &ifspeed) < 0) {
		(void) fprintf(stderr,
		    gettext("%s: kstat value failed\n"),
		    progname);
		goto bail;
	}

bail:
	(void) kstat_close(kcp);
	return (ifspeed);
}

static char *
mac_link_state(const char *dev, uint_t port)
{
	char		name[MAXNAMELEN];
	kstat_ctl_t	*kcp;
	kstat_t		*ksp;
	link_state_t	link_state;
	char		*state_str = "unknown";

	if ((kcp = kstat_open()) == NULL) {
		(void) fprintf(stderr,
		    gettext("%s: kstat open operation failed\n"),
		    progname);
		return (state_str);
	}

	(void) snprintf(name, MAXNAMELEN - 1, "%s/%u", dev, port);

	if ((ksp = kstat_lookup(kcp, (char *)dev, -1, name)) == NULL &&
	    (ksp = kstat_lookup(kcp, NULL, -1, (char *)dev)) == NULL) {
		/*
		 * The kstat query could fail if the underlying MAC
		 * driver was already detached.
		 */
		goto bail;
	}

	if (kstat_read(kcp, ksp, NULL) == -1) {
		(void) fprintf(stderr,
		    gettext("%s: kstat read failed\n"),
		    progname);
		goto bail;
	}

	if (kstat_value(ksp, "link_state", KSTAT_DATA_UINT32,
	    &link_state) < 0) {
		goto bail;
	}

	switch (link_state) {
	case LINK_STATE_UP:
		state_str = "up";
		break;
	case LINK_STATE_DOWN:
		state_str = "down";
		break;
	default:
		break;
	}

bail:
	(void) kstat_close(kcp);
	return (state_str);
}


static char *
mac_link_duplex(const char *dev, uint_t port)
{
	char		name[MAXNAMELEN];
	kstat_ctl_t	*kcp;
	kstat_t		*ksp;
	link_duplex_t	link_duplex;
	char		*duplex_str = "unknown";

	if ((kcp = kstat_open()) == NULL) {
		(void) fprintf(stderr,
		    gettext("%s: kstat open operation failed\n"),
		    progname);
		return (duplex_str);
	}

	(void) snprintf(name, MAXNAMELEN - 1, "%s/%u", dev, port);

	if ((ksp = kstat_lookup(kcp, (char *)dev, -1, name)) == NULL &&
	    (ksp = kstat_lookup(kcp, NULL, -1, (char *)dev)) == NULL) {
		/*
		 * The kstat query could fail if the underlying MAC
		 * driver was already detached.
		 */
		goto bail;
	}

	if (kstat_read(kcp, ksp, NULL) == -1) {
		(void) fprintf(stderr,
		    gettext("%s: kstat read failed\n"),
		    progname);
		goto bail;
	}

	if (kstat_value(ksp, "link_duplex", KSTAT_DATA_UINT32,
	    &link_duplex) < 0) {
		goto bail;
	}
	switch (link_duplex) {
	case LINK_DUPLEX_FULL:
		duplex_str = "full";
		break;
	case LINK_DUPLEX_HALF:
		duplex_str = "half";
		break;
	default:
		break;
	}

bail:
	(void) kstat_close(kcp);
	return (duplex_str);
}

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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <ctype.h>
#include <locale.h>
#include <signal.h>
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
#include <termios.h>
#include <pwd.h>
#include <auth_attr.h>
#include <auth_list.h>
#include <libintl.h>
#include <libdlpi.h>
#include <libdladm.h>
#include <liblaadm.h>
#include <libmacadm.h>
#include <libwladm.h>
#include <libinetutil.h>
#include <bsm/adt.h>
#include <bsm/adt_event.h>

#define	AGGR_DRV	"aggr"
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

typedef	void cmdfunc_t(int, char **);

static cmdfunc_t do_show_link, do_show_dev, do_show_wifi;
static cmdfunc_t do_create_aggr, do_delete_aggr, do_add_aggr, do_remove_aggr;
static cmdfunc_t do_modify_aggr, do_show_aggr, do_up_aggr, do_down_aggr;
static cmdfunc_t do_scan_wifi, do_connect_wifi, do_disconnect_wifi;
static cmdfunc_t do_show_linkprop, do_set_linkprop, do_reset_linkprop;
static cmdfunc_t do_create_secobj, do_delete_secobj, do_show_secobj;
static cmdfunc_t do_init_linkprop, do_init_secobj;

static void	show_linkprop_onelink(void *, const char *);

static void	link_stats(const char *, uint_t);
static void	aggr_stats(uint32_t, uint_t);
static void	dev_stats(const char *dev, uint32_t);

static void	get_mac_stats(const char *, pktsum_t *);
static void	get_link_stats(const char *, pktsum_t *);
static uint64_t	mac_ifspeed(const char *);
static char	*mac_link_state(const char *);
static char	*mac_link_duplex(const char *);
static void	stats_total(pktsum_t *, pktsum_t *, pktsum_t *);
static void	stats_diff(pktsum_t *, pktsum_t *, pktsum_t *);

static boolean_t str2int(const char *, int *);
static void	die(const char *, ...);
static void	die_optdup(int);
static void	die_opterr(int, int);
static void	die_laerr(laadm_diag_t, const char *, ...);
static void	die_wlerr(wladm_status_t, const char *, ...);
static void	die_dlerr(dladm_status_t, const char *, ...);
static void	warn(const char *, ...);
static void	warn_wlerr(wladm_status_t, const char *, ...);
static void	warn_dlerr(dladm_status_t, const char *, ...);

typedef struct	cmd {
	char		*c_name;
	cmdfunc_t	*c_fn;
} cmd_t;

static cmd_t	cmds[] = {
	{ "show-link",		do_show_link		},
	{ "show-dev",		do_show_dev		},
	{ "create-aggr",	do_create_aggr		},
	{ "delete-aggr",	do_delete_aggr		},
	{ "add-aggr",		do_add_aggr		},
	{ "remove-aggr",	do_remove_aggr		},
	{ "modify-aggr",	do_modify_aggr		},
	{ "show-aggr",		do_show_aggr		},
	{ "up-aggr",		do_up_aggr		},
	{ "down-aggr",		do_down_aggr		},
	{ "scan-wifi",		do_scan_wifi		},
	{ "connect-wifi",	do_connect_wifi		},
	{ "disconnect-wifi",	do_disconnect_wifi	},
	{ "show-wifi",		do_show_wifi		},
	{ "show-linkprop",	do_show_linkprop	},
	{ "set-linkprop",	do_set_linkprop		},
	{ "reset-linkprop",	do_reset_linkprop	},
	{ "create-secobj",	do_create_secobj	},
	{ "delete-secobj",	do_delete_secobj	},
	{ "show-secobj",	do_show_secobj		},
	{ "init-linkprop",	do_init_linkprop	},
	{ "init-secobj",	do_init_secobj		}
};

static const struct option longopts[] = {
	{"vlan-id",	required_argument,	0, 'v'	},
	{"dev",		required_argument,	0, 'd'	},
	{"policy",	required_argument,	0, 'P'	},
	{"lacp-mode",	required_argument,	0, 'l'	},
	{"lacp-timer",	required_argument,	0, 'T'	},
	{"unicast",	required_argument,	0, 'u'	},
	{"statistics",	no_argument,		0, 's'	},
	{"interval",	required_argument,	0, 'i'	},
	{"lacp",	no_argument,		0, 'L'	},
	{"temporary",	no_argument,		0, 't'	},
	{"root-dir",	required_argument,	0, 'r'	},
	{"parseable",	no_argument,		0, 'p'	},
	{ 0, 0, 0, 0 }
};

static const struct option prop_longopts[] = {
	{"temporary",	no_argument,		0, 't'	},
	{"root-dir",	required_argument,	0, 'R'	},
	{"prop",	required_argument,	0, 'p'	},
	{"parseable",	no_argument,		0, 'c'	},
	{"persistent",	no_argument,		0, 'P'	},
	{ 0, 0, 0, 0 }
};

static const struct option wifi_longopts[] = {
	{"parseable",	no_argument,		0, 'p'	},
	{"output",	required_argument,	0, 'o'	},
	{"essid",	required_argument,	0, 'e'	},
	{"bsstype",	required_argument,	0, 'b'	},
	{"mode",	required_argument,	0, 'm'	},
	{"key",		required_argument,	0, 'k'	},
	{"sec",		required_argument,	0, 's'	},
	{"auth",	required_argument,	0, 'a'	},
	{"create-ibss",	required_argument,	0, 'c'	},
	{"timeout",	required_argument,	0, 'T'	},
	{"all-links",	no_argument,		0, 'a'	},
	{"temporary",	no_argument,		0, 't'	},
	{"root-dir",	required_argument,	0, 'R'	},
	{"persistent",	no_argument,		0, 'P'	},
	{"file",	required_argument,	0, 'f'	},
	{ 0, 0, 0, 0 }
};

static char *progname;
static sig_atomic_t signalled;

static void
usage(void)
{
	(void) fprintf(stderr, gettext("usage:	dladm <subcommand> <args> ...\n"
	    "\tshow-link       [-p] [-s [-i <interval>]] [<name>]\n"
	    "\tshow-dev        [-p] [-s [-i <interval>]] [<dev>]\n"
	    "\n"
	    "\tcreate-aggr     [-t] [-R <root-dir>] [-P <policy>] [-l <mode>]\n"
	    "\t                [-T <time>] [-u <address>] -d <dev> ... <key>\n"
	    "\tmodify-aggr     [-t] [-R <root-dir>] [-P <policy>] [-l <mode>]\n"
	    "\t                [-T <time>] [-u <address>] <key>\n"
	    "\tdelete-aggr     [-t] [-R <root-dir>] <key>\n"
	    "\tadd-aggr        [-t] [-R <root-dir>] -d <dev> ... <key>\n"
	    "\tremove-aggr     [-t] [-R <root-dir>] -d <dev> ... <key>\n"
	    "\tshow-aggr       [-pL][-s [-i <interval>]] [<key>]\n"
	    "\n"
	    "\tscan-wifi       [-p] [-o <field>,...] [<name>]\n"
	    "\tconnect-wifi    [-e <essid>] [-i <bssid>] [-k <key>,...]"
	    " [-s wep]\n"
	    "\t                [-a open|shared] [-b bss|ibss] [-c] [-m a|b|g]\n"
	    "\t                [-T <time>] [<name>]\n"
	    "\tdisconnect-wifi [-a] [<name>]\n"
	    "\tshow-wifi       [-p] [-o <field>,...] [<name>]\n"
	    "\n"
	    "\tset-linkprop    [-t] [-R <root-dir>]  -p <prop>=<value>[,...]"
	    " <name>\n"
	    "\treset-linkprop  [-t] [-R <root-dir>] [-p <prop>,...] <name>\n"
	    "\tshow-linkprop   [-cP][-p <prop>,...] <name>\n"
	    "\n"
	    "\tcreate-secobj   [-t] [-R <root-dir>] [-f <file>] -c <class>"
	    " <secobj>\n"
	    "\tdelete-secobj   [-t] [-R <root-dir>] <secobj>[,...]\n"
	    "\tshow-secobj     [-pP][<secobj>,...]\n"));
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
	    !priv_ineffect(PRIV_NET_RAWACCESS))
		die("insufficient privileges");

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
	int			key;
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
	laadm_diag_t		diag = 0;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":d:l:P:R:tu:T:",
	    longopts, NULL)) != -1) {
		switch (option) {
		case 'd':
			if (nport >= MAXPORT)
				die("too many <dev> arguments");

			if (strlcpy(port[nport].lp_devname, optarg,
			    MAXNAMELEN) >= MAXNAMELEN)
				die("device name too long");

			nport++;
			break;
		case 'P':
			if (P_arg)
				die_optdup(option);

			P_arg = B_TRUE;
			if (!laadm_str_to_policy(optarg, &policy))
				die("invalid policy '%s'", optarg);
			break;
		case 'u':
			if (u_arg)
				die_optdup(option);

			u_arg = B_TRUE;
			if (!laadm_str_to_mac_addr(optarg, &mac_addr_fixed,
			    mac_addr))
				die("invalid MAC address '%s'", optarg);
			break;
		case 'l':
			if (l_arg)
				die_optdup(option);

			l_arg = B_TRUE;
			if (!laadm_str_to_lacp_mode(optarg, &lacp_mode))
				die("invalid LACP mode '%s'", optarg);
			break;
		case 'T':
			if (T_arg)
				die_optdup(option);

			T_arg = B_TRUE;
			if (!laadm_str_to_lacp_timer(optarg, &lacp_timer))
				die("invalid LACP timer value '%s'", optarg);
			break;
		case 't':
			t_arg = B_TRUE;
			break;
		case 'R':
			altroot = optarg;
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	if (nport == 0)
		usage();

	/* get key value (required last argument) */
	if (optind != (argc-1))
		usage();

	if (!str2int(argv[optind], &key) || key < 1)
		die("invalid key value '%s'", argv[optind]);

	if (laadm_create(key, nport, port, policy, mac_addr_fixed,
	    mac_addr, lacp_mode, lacp_timer, t_arg, altroot, &diag) < 0)
		die_laerr(diag, "create operation failed");
}

static void
do_delete_aggr(int argc, char *argv[])
{
	int			key;
	char			option;
	boolean_t		t_arg = B_FALSE;
	char			*altroot = NULL;
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
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	/* get key value (required last argument) */
	if (optind != (argc-1))
		usage();

	if (!str2int(argv[optind], &key) || key < 1)
		die("invalid key value '%s'", argv[optind]);

	if (laadm_delete(key, t_arg, altroot, &diag) < 0)
		die_laerr(diag, "delete operation failed");
}

static void
do_add_aggr(int argc, char *argv[])
{
	char			option;
	int			key;
	laadm_port_attr_db_t	port[MAXPORT];
	uint_t			nport = 0;
	boolean_t		t_arg = B_FALSE;
	char			*altroot = NULL;
	laadm_diag_t		diag = 0;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":d:R:t", longopts,
	    NULL)) != -1) {
		switch (option) {
		case 'd':
			if (nport >= MAXPORT)
				die("too many <dev> arguments");

			if (strlcpy(port[nport].lp_devname, optarg,
			    MAXNAMELEN) >= MAXNAMELEN)
				die("device name too long");

			nport++;
			break;
		case 't':
			t_arg = B_TRUE;
			break;
		case 'R':
			altroot = optarg;
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	if (nport == 0)
		usage();

	/* get key value (required last argument) */
	if (optind != (argc-1))
		usage();

	if (!str2int(argv[optind], &key) || key < 1)
		die("invalid key value '%s'", argv[optind]);

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
		die_laerr(diag, "add operation failed");
	}
}

static void
do_remove_aggr(int argc, char *argv[])
{
	char			option;
	int			key;
	laadm_port_attr_db_t	port[MAXPORT];
	uint_t			nport = 0;
	boolean_t		t_arg = B_FALSE;
	char			*altroot = NULL;
	laadm_diag_t		diag = 0;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":d:R:t",
	    longopts, NULL)) != -1) {
		switch (option) {
		case 'd':
			if (nport >= MAXPORT)
				die("too many <dev> arguments");

			if (strlcpy(port[nport].lp_devname, optarg,
			    MAXNAMELEN) >= MAXNAMELEN)
				die("device name too long");

			nport++;
			break;
		case 't':
			t_arg = B_TRUE;
			break;
		case 'R':
			altroot = optarg;
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	if (nport == 0)
		usage();

	/* get key value (required last argument) */
	if (optind != (argc-1))
		usage();

	if (!str2int(argv[optind], &key) || key < 1)
		die("invalid key value '%s'", argv[optind]);

	if (laadm_remove(key, nport, port, t_arg, altroot, &diag) < 0)
		die_laerr(diag, "remove operation failed");
}

static void
do_modify_aggr(int argc, char *argv[])
{
	char			option;
	int			key;
	uint32_t		policy = AGGR_POLICY_L4;
	aggr_lacp_mode_t	lacp_mode = AGGR_LACP_OFF;
	aggr_lacp_timer_t	lacp_timer = AGGR_LACP_TIMER_SHORT;
	uint8_t			mac_addr[ETHERADDRL];
	boolean_t		mac_addr_fixed = B_FALSE;
	uint8_t			modify_mask = 0;
	boolean_t		t_arg = B_FALSE;
	char			*altroot = NULL;
	laadm_diag_t		diag = 0;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":l:P:R:tu:T:", longopts,
	    NULL)) != -1) {
		switch (option) {
		case 'P':
			if (modify_mask & LAADM_MODIFY_POLICY)
				die_optdup(option);

			modify_mask |= LAADM_MODIFY_POLICY;

			if (!laadm_str_to_policy(optarg, &policy))
				die("invalid policy '%s'", optarg);
			break;
		case 'u':
			if (modify_mask & LAADM_MODIFY_MAC)
				die_optdup(option);

			modify_mask |= LAADM_MODIFY_MAC;

			if (!laadm_str_to_mac_addr(optarg, &mac_addr_fixed,
			    mac_addr))
				die("invalid MAC address '%s'", optarg);
			break;
		case 'l':
			if (modify_mask & LAADM_MODIFY_LACP_MODE)
				die_optdup(option);

			modify_mask |= LAADM_MODIFY_LACP_MODE;

			if (!laadm_str_to_lacp_mode(optarg, &lacp_mode))
				die("invalid LACP mode '%s'", optarg);
			break;
		case 'T':
			if (modify_mask & LAADM_MODIFY_LACP_TIMER)
				die_optdup(option);

			modify_mask |= LAADM_MODIFY_LACP_TIMER;

			if (!laadm_str_to_lacp_timer(optarg, &lacp_timer))
				die("invalid LACP timer value '%s'", optarg);
			break;
		case 't':
			t_arg = B_TRUE;
			break;
		case 'R':
			altroot = optarg;
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	if (modify_mask == 0)
		die("at least one of the -PulT options must be specified");

	/* get key value (required last argument) */
	if (optind != (argc-1))
		usage();

	if (!str2int(argv[optind], &key) || key < 1)
		die("invalid key value '%s'", argv[optind]);

	if (laadm_modify(key, modify_mask, policy, mac_addr_fixed, mac_addr,
	    lacp_mode, lacp_timer, t_arg, altroot, &diag) < 0)
		die_laerr(diag, "modify operation failed");
}

static void
do_up_aggr(int argc, char *argv[])
{
	int		key = 0;
	laadm_diag_t	diag = 0;

	/* get aggregation key (optional last argument) */
	if (argc == 2) {
		if (!str2int(argv[1], &key) || key < 1)
			die("invalid key value '%s'", argv[1]);
	} else if (argc > 2) {
		usage();
	}

	if (laadm_up(key, NULL, &diag) < 0) {
		if (key != 0) {
			die_laerr(diag, "could not bring up aggregation '%u'",
			    key);
		} else {
			die_laerr(diag, "could not bring aggregations up");
		}
	}
}

static void
do_down_aggr(int argc, char *argv[])
{
	int	key = 0;

	/* get aggregation key (optional last argument) */
	if (argc == 2) {
		if (!str2int(argv[1], &key) || key < 1)
			die("invalid key value '%s'", argv[1]);
	} else if (argc > 2) {
		usage();
	}

	if (laadm_down(key) < 0) {
		if (key != 0) {
			die("could not bring down aggregation '%u': %s",
			    key, strerror(errno));
		} else {
			die("could not bring down aggregations: %s",
			    strerror(errno));
		}
	}
}

#define	TYPE_WIDTH	10

static void
print_link_parseable(const char *name, dladm_attr_t *dap, boolean_t legacy)
{
	char	type[TYPE_WIDTH];

	if (!legacy) {
		char	drv[DLPI_LINKNAME_MAX];
		uint_t	instance;

		if (dap->da_vid != 0) {
			(void) snprintf(type, TYPE_WIDTH, "vlan %u",
			    dap->da_vid);
		} else {
			(void) snprintf(type, TYPE_WIDTH, "non-vlan");
		}

		if (dlpi_parselink(dap->da_dev, drv, &instance) != DLPI_SUCCESS)
			return;

		if (strncmp(drv, AGGR_DRV, sizeof (AGGR_DRV)) == 0) {
			(void) printf("%s type=%s mtu=%d key=%u\n",
			    name, type, dap->da_max_sdu, instance);
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
	char	type[TYPE_WIDTH];

	if (!legacy) {
		char 	drv[DLPI_LINKNAME_MAX];
		uint_t	instance;

		if (dap->da_vid != 0) {
			(void) snprintf(type, TYPE_WIDTH, gettext("vlan %u"),
			    dap->da_vid);
		} else {
			(void) snprintf(type, TYPE_WIDTH, gettext("non-vlan"));
		}

		if (dlpi_parselink(dap->da_dev, drv, &instance) != DLPI_SUCCESS)
			return;
		if (strncmp(drv, AGGR_DRV, sizeof (AGGR_DRV)) == 0) {
			(void) printf(gettext("%-9s\ttype: %s\tmtu: %d"
			    "\taggregation: key %u\n"), name, type,
			    dap->da_max_sdu, instance);
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
		dlpi_handle_t   dh;
		dlpi_info_t	dlinfo;

		/*
		 * A return value of ENODEV means that the specified
		 * device is not gldv3.
		 */
		if (dlpi_open(name, &dh, 0) != DLPI_SUCCESS) {
			errno = ENOENT;
			return (-1);
		}
		if (dlpi_info(dh, &dlinfo, 0) != DLPI_SUCCESS) {
			dlpi_close(dh);
			errno = EINVAL;
			return (-1);
		}
		dlpi_close(dh);
		*legacy = B_TRUE;
		bzero(dlattrp, sizeof (*dlattrp));
		dlattrp->da_max_sdu = dlinfo.di_max_sdu;

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

	if (get_if_info(name, &dlattr, &legacy) < 0)
		die("invalid link '%s'", name);

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
	char buf[ETHERADDRL * 3];

	if (!parseable) {
		(void) printf("	   %-9s\t%s", dev, laadm_mac_addr_to_str(
		    port->lp_mac, buf));
		(void) printf("\t %5uMb", (int)(mac_ifspeed(dev) /
		    1000000ull));
		(void) printf("\t%s", mac_link_duplex(dev));
		(void) printf("\t%s", mac_link_state(dev));
		(void) printf("\t%s\n", port_state_to_str(port->lp_state));

	} else {
		(void) printf(" device=%s address=%s", dev,
		    laadm_mac_addr_to_str(port->lp_mac, buf));
		(void) printf(" speed=%u", (int)(mac_ifspeed(dev) /
		    1000000ull));
		(void) printf(" duplex=%s", mac_link_duplex(dev));
		(void) printf(" link=%s", mac_link_state(dev));
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
			get_mac_stats(grp->lg_ports[i].lp_devname, &port_stat);
			stats_total(&pktsumtot, &port_stat,
			    &state->gs_prevstats[i]);
		}

		(void) printf("	   Total");
		(void) printf("\t%-10llu", pktsumtot.ipackets);
		(void) printf("%-12llu", pktsumtot.rbytes);
		(void) printf("%-10llu", pktsumtot.opackets);
		(void) printf("%-12llu\n", pktsumtot.obytes);

		for (i = 0; i < grp->lg_nports; i++) {
			get_mac_stats(grp->lg_ports[i].lp_devname, &port_stat);
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
		    mac_link_state(dev));
		(void) printf(gettext("\tspeed: %5uMb"),
		    (unsigned int)(mac_ifspeed(dev) / 1000000ull));
		(void) printf(gettext("\tduplex: %s\n"),
		    mac_link_duplex(dev));
	} else {
		(void) printf(" link=%s", mac_link_state(dev));
		(void) printf(" speed=%u",
		    (unsigned int)(mac_ifspeed(dev) / 1000000ull));
		(void) printf(" duplex=%s\n", mac_link_duplex(dev));
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

	get_mac_stats(dev, &stats);
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
	int		interval = 0;
	show_link_state_t state;

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
			if (s_arg)
				die_optdup(option);

			s_arg = B_TRUE;
			break;
		case 'i':
			if (i_arg)
				die_optdup(option);

			i_arg = B_TRUE;
			if (!str2int(optarg, &interval) || interval == 0)
				die("invalid interval value '%s'", optarg);
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	if (i_arg && !s_arg)
		die("the option -i can be used only with -s");

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
	int			key = 0;
	boolean_t		L_arg = B_FALSE;
	boolean_t		s_arg = B_FALSE;
	boolean_t		i_arg = B_FALSE;
	show_grp_state_t	state;
	int			interval = 0;

	state.gs_stats = B_FALSE;
	state.gs_lacp = B_FALSE;
	state.gs_parseable = B_FALSE;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":Lpsi:",
	    longopts, NULL)) != -1) {
		switch (option) {
		case 'L':
			if (L_arg)
				die_optdup(option);

			if (s_arg || i_arg) {
				die("the option -L cannot be used with -i "
				    "or -s");
			}

			L_arg = B_TRUE;
			state.gs_lacp = B_TRUE;
			break;
		case 'p':
			state.gs_parseable = B_TRUE;
			break;
		case 's':
			if (s_arg)
				die_optdup(option);

			if (L_arg)
				die("the option -s cannot be used with -L");

			s_arg = B_TRUE;
			break;
		case 'i':
			if (i_arg)
				die_optdup(option);

			if (L_arg)
				die("the option -i cannot be used with -L");

			i_arg = B_TRUE;
			if (!str2int(optarg, &interval) || interval == 0)
				die("invalid interval value '%s'", optarg);
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	if (i_arg && !s_arg)
		die("the option -i can be used only with -s");

	/* get aggregation key (optional last argument) */
	if (optind == (argc-1)) {
		if (!str2int(argv[optind], &key) || key < 1)
			die("invalid key value '%s'", argv[optind]);
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

	if (key != 0 && !state.gs_found)
		die("non-existent aggregation key '%u'", key);
}

static void
do_show_dev(int argc, char *argv[])
{
	int		option;
	char		*dev = NULL;
	boolean_t	s_arg = B_FALSE;
	boolean_t	i_arg = B_FALSE;
	int		interval = 0;
	show_mac_state_t state;

	state.ms_parseable = B_FALSE;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":psi:",
	    longopts, NULL)) != -1) {
		switch (option) {
		case 'p':
			state.ms_parseable = B_TRUE;
			break;
		case 's':
			if (s_arg)
				die_optdup(option);

			s_arg = B_TRUE;
			break;
		case 'i':
			if (i_arg)
				die_optdup(option);

			i_arg = B_TRUE;
			if (!str2int(optarg, &interval) || interval == 0)
				die("invalid interval value '%s'", optarg);
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	if (i_arg && !s_arg)
		die("the option -i can be used only with -s");

	/* get dev name (optional last argument) */
	if (optind == (argc-1))
		dev = argv[optind];
	else if (optind != argc)
		usage();

	if (dev != NULL) {
		uint_t		ppa;
		char		drv[DLPI_LINKNAME_MAX];
		dladm_attr_t	dlattr;
		boolean_t	legacy;

		/*
		 * Check for invalid devices.
		 * aggregations and vlans are not considered devices.
		 */
		if (dlpi_parselink(dev, drv, &ppa) != DLPI_SUCCESS ||
		    strcmp(drv, "aggr") == 0 || ppa >= 1000 ||
		    get_if_info(dev, &dlattr, &legacy) < 0)
			die("invalid device '%s'", dev);
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
link_stats(const char *link, uint_t interval)
{
	dladm_attr_t		dlattr;
	boolean_t		legacy;
	show_link_state_t	state;

	if (link != NULL && get_if_info(link, &dlattr, &legacy) < 0)
		die("invalid link '%s'", link);

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
aggr_stats(uint32_t key, uint_t interval)
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
		if (state.gs_key != 0 && !state.gs_found)
			die("non-existent aggregation key '%u'", key);

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
 * In the following routines, we do the first kstat_lookup() assuming that
 * the device is gldv3-based and that the kstat name is the one passed in
 * as the "name" argument. If the lookup fails, we redo the kstat_lookup()
 * omitting the kstat name. This second lookup is needed for getting kstats
 * from legacy devices. This can fail too if the device is not attached or
 * the device is legacy and doesn't export the kstats we need.
 */
static void
get_stats(char *module, int instance, char *name, pktsum_t *stats)
{
	kstat_ctl_t	*kcp;
	kstat_t		*ksp;

	if ((kcp = kstat_open()) == NULL) {
		warn("kstat open operation failed");
		return;
	}

	if ((ksp = kstat_lookup(kcp, module, instance, name)) == NULL &&
	    (ksp = kstat_lookup(kcp, module, instance, NULL)) == NULL) {
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
	(void) kstat_close(kcp);
}

static void
get_mac_stats(const char *dev, pktsum_t *stats)
{
	char	module[DLPI_LINKNAME_MAX];
	uint_t	instance;

	if (dlpi_parselink(dev, module, &instance) != DLPI_SUCCESS)
		return;
	bzero(stats, sizeof (*stats));
	get_stats(module, instance, "mac", stats);
}

static void
get_link_stats(const char *link, pktsum_t *stats)
{
	char	module[DLPI_LINKNAME_MAX];
	uint_t	instance;

	if (dlpi_parselink(link, module, &instance) != DLPI_SUCCESS)
		return;
	bzero(stats, sizeof (*stats));
	get_stats(module, instance, (char *)link, stats);
}

static int
get_single_mac_stat(const char *dev, const char *name, uint8_t type,
    void *val)
{
	char		module[DLPI_LINKNAME_MAX];
	uint_t		instance;
	kstat_ctl_t	*kcp;
	kstat_t		*ksp;

	if (dlpi_parselink(dev, module, &instance) != DLPI_SUCCESS)
		return (-1);

	if ((kcp = kstat_open()) == NULL) {
		warn("kstat open operation failed");
		return (-1);
	}

	if ((ksp = kstat_lookup(kcp, module, instance, "mac")) == NULL &&
	    (ksp = kstat_lookup(kcp, module, instance, NULL)) == NULL) {
		/*
		 * The kstat query could fail if the underlying MAC
		 * driver was already detached.
		 */
		goto bail;
	}

	if (kstat_read(kcp, ksp, NULL) == -1) {
		warn("kstat read failed");
		goto bail;
	}

	if (kstat_value(ksp, name, type, val) < 0)
		goto bail;

	(void) kstat_close(kcp);
	return (0);

bail:
	(void) kstat_close(kcp);
	return (-1);
}

static uint64_t
mac_ifspeed(const char *dev)
{
	uint64_t ifspeed = 0;

	(void) get_single_mac_stat(dev, "ifspeed", KSTAT_DATA_UINT64, &ifspeed);
	return (ifspeed);
}

static char *
mac_link_state(const char *dev)
{
	link_state_t	link_state;
	char		*state_str = "unknown";

	if (get_single_mac_stat(dev, "link_state", KSTAT_DATA_UINT32,
	    &link_state) != 0) {
		return (state_str);
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

	return (state_str);
}


static char *
mac_link_duplex(const char *dev)
{
	link_duplex_t	link_duplex;
	char		*duplex_str = "unknown";

	if (get_single_mac_stat(dev, "link_duplex", KSTAT_DATA_UINT32,
	    &link_duplex) != 0) {
		return (duplex_str);
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

	return (duplex_str);
}

#define	WIFI_CMD_SCAN	0x00000001
#define	WIFI_CMD_SHOW	0x00000002
#define	WIFI_CMD_ALL	(WIFI_CMD_SCAN | WIFI_CMD_SHOW)
typedef struct wifi_field {
	const char	*wf_name;
	const char	*wf_header;
	uint_t		wf_width;
	uint_t		wf_mask;
	uint_t		wf_cmdtype;
} wifi_field_t;

static wifi_field_t wifi_fields[] = {
{ "link",	"LINK",		10,	0,			WIFI_CMD_ALL},
{ "essid",	"ESSID",	19,	WLADM_WLAN_ATTR_ESSID,	WIFI_CMD_ALL},
{ "bssid",	"BSSID/IBSSID", 17,	WLADM_WLAN_ATTR_BSSID,	WIFI_CMD_ALL},
{ "ibssid",	"BSSID/IBSSID", 17,	WLADM_WLAN_ATTR_BSSID,	WIFI_CMD_ALL},
{ "mode",	"MODE",		6,	WLADM_WLAN_ATTR_MODE,	WIFI_CMD_ALL},
{ "speed",	"SPEED",	6,	WLADM_WLAN_ATTR_SPEED,	WIFI_CMD_ALL},
{ "auth",	"AUTH",		8,	WLADM_WLAN_ATTR_AUTH,	WIFI_CMD_SHOW},
{ "bsstype",	"BSSTYPE",	8,	WLADM_WLAN_ATTR_BSSTYPE, WIFI_CMD_ALL},
{ "sec",	"SEC",		6,	WLADM_WLAN_ATTR_SECMODE, WIFI_CMD_ALL},
{ "status",	"STATUS",	17,	WLADM_LINK_ATTR_STATUS, WIFI_CMD_SHOW},
{ "strength",	"STRENGTH",	10,	WLADM_WLAN_ATTR_STRENGTH, WIFI_CMD_ALL}}
;

static char *all_scan_wifi_fields =
	"link,essid,bssid,sec,strength,mode,speed,bsstype";
static char *all_show_wifi_fields =
	"link,status,essid,sec,strength,mode,speed,auth,bssid,bsstype";
static char *def_scan_wifi_fields =
	"link,essid,bssid,sec,strength,mode,speed";
static char *def_show_wifi_fields =
	"link,status,essid,sec,strength,mode,speed";

#define	WIFI_MAX_FIELDS		(sizeof (wifi_fields) / sizeof (wifi_field_t))
#define	WIFI_MAX_FIELD_LEN	32

typedef struct {
	char	*s_buf;
	char	**s_fields;	/* array of pointer to the fields in s_buf */
	uint_t	s_nfields;	/* the number of fields in s_buf */
} split_t;

/*
 * Free the split_t structure pointed to by `sp'.
 */
static void
splitfree(split_t *sp)
{
	free(sp->s_buf);
	free(sp->s_fields);
	free(sp);
}

/*
 * Split `str' into at most `maxfields' fields, each field at most `maxlen' in
 * length.  Return a pointer to a split_t containing the split fields, or NULL
 * on failure.
 */
static split_t *
split(const char *str, uint_t maxfields, uint_t maxlen)
{
	char	*field, *token, *lasts = NULL;
	split_t	*sp;

	if (*str == '\0' || maxfields == 0 || maxlen == 0)
		return (NULL);

	sp = calloc(sizeof (split_t), 1);
	if (sp == NULL)
		return (NULL);

	sp->s_buf = strdup(str);
	sp->s_fields = malloc(sizeof (char *) * maxfields);
	if (sp->s_buf == NULL || sp->s_fields == NULL)
		goto fail;

	token = sp->s_buf;
	while ((field = strtok_r(token, ",", &lasts)) != NULL) {
		if (sp->s_nfields == maxfields || strlen(field) > maxlen)
			goto fail;
		token = NULL;
		sp->s_fields[sp->s_nfields++] = field;
	}
	return (sp);
fail:
	splitfree(sp);
	return (NULL);
}

static int
parse_wifi_fields(char *str, wifi_field_t ***fields, uint_t *countp,
    uint_t cmdtype)
{
	uint_t		i, j;
	wifi_field_t	**wf = NULL;
	split_t		*sp;
	boolean_t	good_match = B_FALSE;

	if (cmdtype == WIFI_CMD_SCAN) {
		if (str == NULL)
			str = def_scan_wifi_fields;
		if (strcasecmp(str, "all") == 0)
			str = all_scan_wifi_fields;
	} else if (cmdtype == WIFI_CMD_SHOW) {
		if (str == NULL)
			str = def_show_wifi_fields;
		if (strcasecmp(str, "all") == 0)
			str = all_show_wifi_fields;
	} else {
		return (-1);
	}

	sp = split(str, WIFI_MAX_FIELDS, WIFI_MAX_FIELD_LEN);
	if (sp == NULL)
		return (-1);

	wf = malloc(sp->s_nfields * sizeof (wifi_field_t *));
	if (wf == NULL)
		goto fail;

	for (i = 0; i < sp->s_nfields; i++) {
		for (j = 0; j < WIFI_MAX_FIELDS; j++) {
			if (strcasecmp(sp->s_fields[i],
			    wifi_fields[j].wf_name) == 0) {
				good_match = wifi_fields[j].
				    wf_cmdtype & cmdtype;
				break;
			}
		}
		if (!good_match)
			goto fail;

		good_match = B_FALSE;
		wf[i] = &wifi_fields[j];
	}
	*countp = i;
	*fields = wf;
	splitfree(sp);
	return (0);
fail:
	free(wf);
	splitfree(sp);
	return (-1);
}

typedef struct print_wifi_state {
	const char	*ws_link;
	boolean_t	ws_parseable;
	boolean_t	ws_header;
	wifi_field_t	**ws_fields;
	uint_t		ws_nfields;
	boolean_t	ws_lastfield;
	uint_t		ws_overflow;
} print_wifi_state_t;

static void
print_wifi_head(print_wifi_state_t *statep)
{
	int		i;
	wifi_field_t	*wfp;

	for (i = 0; i < statep->ws_nfields; i++) {
		wfp = statep->ws_fields[i];
		if (i + 1 < statep->ws_nfields)
			(void) printf("%-*s ", wfp->wf_width, wfp->wf_header);
		else
			(void) printf("%s", wfp->wf_header);
	}
	(void) printf("\n");
}

static void
print_wifi_field(print_wifi_state_t *statep, wifi_field_t *wfp,
    const char *value)
{
	uint_t	width = wfp->wf_width;
	uint_t	valwidth = strlen(value);
	uint_t	compress;

	if (statep->ws_parseable) {
		(void) printf("%s=\"%s\"", wfp->wf_header, value);
	} else {
		if (value[0] == '\0')
			value = "--";
		if (statep->ws_lastfield) {
			(void) printf("%s", value);
			return;
		}

		if (valwidth > width) {
			statep->ws_overflow += valwidth - width;
		} else if (valwidth < width && statep->ws_overflow > 0) {
			compress = min(statep->ws_overflow, width - valwidth);
			statep->ws_overflow -= compress;
			width -= compress;
		}
		(void) printf("%-*s", width, value);
	}

	if (!statep->ws_lastfield)
		(void) putchar(' ');
}

static void
print_wlan_attr(print_wifi_state_t *statep, wifi_field_t *wfp,
    wladm_wlan_attr_t *attrp)
{
	char		buf[WLADM_STRSIZE];
	const char	*str = "";

	if (wfp->wf_mask == 0) {
		print_wifi_field(statep, wfp, statep->ws_link);
		return;
	}

	if ((wfp->wf_mask & attrp->wa_valid) == 0) {
		print_wifi_field(statep, wfp, "");
		return;
	}

	switch (wfp->wf_mask) {
	case WLADM_WLAN_ATTR_ESSID:
		str = wladm_essid2str(&attrp->wa_essid, buf);
		break;
	case WLADM_WLAN_ATTR_BSSID:
		str = wladm_bssid2str(&attrp->wa_bssid, buf);
		break;
	case WLADM_WLAN_ATTR_SECMODE:
		str = wladm_secmode2str(&attrp->wa_secmode, buf);
		break;
	case WLADM_WLAN_ATTR_STRENGTH:
		str = wladm_strength2str(&attrp->wa_strength, buf);
		break;
	case WLADM_WLAN_ATTR_MODE:
		str = wladm_mode2str(&attrp->wa_mode, buf);
		break;
	case WLADM_WLAN_ATTR_SPEED:
		str = wladm_speed2str(&attrp->wa_speed, buf);
		(void) strlcat(buf, "Mb", sizeof (buf));
		break;
	case WLADM_WLAN_ATTR_AUTH:
		str = wladm_auth2str(&attrp->wa_auth, buf);
		break;
	case WLADM_WLAN_ATTR_BSSTYPE:
		str = wladm_bsstype2str(&attrp->wa_bsstype, buf);
		break;
	}

	print_wifi_field(statep, wfp, str);
}

static boolean_t
print_scan_results(void *arg, wladm_wlan_attr_t *attrp)
{
	print_wifi_state_t	*statep = arg;
	int			i;

	if (statep->ws_header) {
		statep->ws_header = B_FALSE;
		if (!statep->ws_parseable)
			print_wifi_head(statep);
	}

	statep->ws_overflow = 0;
	for (i = 0; i < statep->ws_nfields; i++) {
		statep->ws_lastfield = (i + 1 == statep->ws_nfields);
		print_wlan_attr(statep, statep->ws_fields[i], attrp);
	}
	(void) putchar('\n');
	return (B_TRUE);
}

static boolean_t
scan_wifi(void *arg, const char *link)
{
	print_wifi_state_t	*statep = arg;
	wladm_status_t		status;

	statep->ws_link = link;
	status = wladm_scan(link, statep, print_scan_results);
	if (status != WLADM_STATUS_OK)
		die_wlerr(status, "cannot scan link '%s'", link);

	return (B_TRUE);
}

static void
print_link_attr(print_wifi_state_t *statep, wifi_field_t *wfp,
    wladm_link_attr_t *attrp)
{
	char		buf[WLADM_STRSIZE];
	const char	*str = "";

	if (strcmp(wfp->wf_name, "status") == 0) {
		if ((wfp->wf_mask & attrp->la_valid) != 0)
			str = wladm_linkstatus2str(&attrp->la_status, buf);
		print_wifi_field(statep, wfp, str);
		return;
	}
	print_wlan_attr(statep, wfp, &attrp->la_wlan_attr);
}

static boolean_t
show_wifi(void *arg, const char *link)
{
	int			i;
	print_wifi_state_t	*statep = arg;
	wladm_link_attr_t	attr;
	wladm_status_t		status;

	status = wladm_get_link_attr(link, &attr);
	if (status != WLADM_STATUS_OK)
		die_wlerr(status, "cannot get link attributes for '%s'", link);

	if (statep->ws_header) {
		statep->ws_header = B_FALSE;
		if (!statep->ws_parseable)
			print_wifi_head(statep);
	}

	statep->ws_link = link;
	statep->ws_overflow = 0;
	for (i = 0; i < statep->ws_nfields; i++) {
		statep->ws_lastfield = (i + 1 == statep->ws_nfields);
		print_link_attr(statep, statep->ws_fields[i], &attr);
	}
	(void) putchar('\n');
	return (B_TRUE);
}

static void
do_display_wifi(int argc, char **argv, int cmd)
{
	int			option;
	char			*fields_str = NULL;
	wifi_field_t		**fields;
	boolean_t		(*callback)(void *, const char *);
	uint_t			nfields;
	print_wifi_state_t	state;
	wladm_status_t		status;

	if (cmd == WIFI_CMD_SCAN)
		callback = scan_wifi;
	else if (cmd == WIFI_CMD_SHOW)
		callback = show_wifi;
	else
		return;

	state.ws_link = NULL;
	state.ws_parseable = B_FALSE;
	state.ws_header = B_TRUE;
	opterr = 0;
	while ((option = getopt_long(argc, argv, ":o:p",
	    wifi_longopts, NULL)) != -1) {
		switch (option) {
		case 'o':
			fields_str = optarg;
			break;
		case 'p':
			state.ws_parseable = B_TRUE;
			if (fields_str == NULL)
				fields_str = "all";
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	if (optind == (argc - 1))
		state.ws_link = argv[optind];
	else if (optind != argc)
		usage();

	if (parse_wifi_fields(fields_str, &fields, &nfields, cmd) < 0)
		die("invalid field(s) specified");

	state.ws_fields = fields;
	state.ws_nfields = nfields;

	if (state.ws_link == NULL) {
		status = wladm_walk(&state, callback);
		if (status != WLADM_STATUS_OK)
			die_wlerr(status, "cannot walk wifi links");
	} else {
		(void) (*callback)(&state, state.ws_link);
	}
	free(fields);
}

static void
do_scan_wifi(int argc, char **argv)
{
	do_display_wifi(argc, argv, WIFI_CMD_SCAN);
}

static void
do_show_wifi(int argc, char **argv)
{
	do_display_wifi(argc, argv, WIFI_CMD_SHOW);
}

typedef struct wlan_count_attr {
	uint_t		wc_count;
	const char	*wc_link;
} wlan_count_attr_t;

static boolean_t
do_count_wlan(void *arg, const char *link)
{
	wlan_count_attr_t *cp = arg;

	if (cp->wc_count == 0)
		cp->wc_link = strdup(link);
	cp->wc_count++;
	return (B_TRUE);
}

static int
parse_wep_keys(char *str, wladm_wep_key_t **keys, uint_t *key_countp)
{
	uint_t		i;
	split_t		*sp;
	wladm_wep_key_t	*wk;

	sp = split(str, WLADM_MAX_WEPKEYS, WLADM_MAX_WEPKEYNAME_LEN);
	if (sp == NULL)
		return (-1);

	wk = malloc(sp->s_nfields * sizeof (wladm_wep_key_t));
	if (wk == NULL)
		goto fail;

	for (i = 0; i < sp->s_nfields; i++) {
		char			*s;
		dladm_secobj_class_t	class;
		dladm_status_t		status;

		(void) strlcpy(wk[i].wk_name, sp->s_fields[i],
		    WLADM_MAX_WEPKEYNAME_LEN);

		wk[i].wk_idx = 1;
		if ((s = strrchr(wk[i].wk_name, ':')) != NULL) {
			if (s[1] == '\0' || s[2] != '\0' || !isdigit(s[1]))
				goto fail;

			wk[i].wk_idx = (uint_t)(s[1] - '0');
			*s = '\0';
		}
		wk[i].wk_len = WLADM_MAX_WEPKEY_LEN;

		status = dladm_get_secobj(wk[i].wk_name, &class,
		    wk[i].wk_val, &wk[i].wk_len, 0);
		if (status != DLADM_STATUS_OK) {
			if (status == DLADM_STATUS_NOTFOUND) {
				status = dladm_get_secobj(wk[i].wk_name,
				    &class, wk[i].wk_val, &wk[i].wk_len,
				    DLADM_OPT_PERSIST);
			}
			if (status != DLADM_STATUS_OK)
				goto fail;
		}
	}
	*keys = wk;
	*key_countp = i;
	splitfree(sp);
	return (0);
fail:
	free(wk);
	splitfree(sp);
	return (-1);
}

static void
do_connect_wifi(int argc, char **argv)
{
	int			option;
	wladm_wlan_attr_t	attr, *attrp;
	wladm_status_t		status = WLADM_STATUS_OK;
	int			timeout = WLADM_CONNECT_TIMEOUT_DEFAULT;
	const char		*link = NULL;
	wladm_wep_key_t		*keys = NULL;
	uint_t			key_count = 0;
	uint_t			flags = 0;
	wladm_secmode_t		keysecmode = WLADM_SECMODE_NONE;

	opterr = 0;
	(void) memset(&attr, 0, sizeof (attr));
	while ((option = getopt_long(argc, argv, ":e:i:a:m:b:s:k:T:c",
	    wifi_longopts, NULL)) != -1) {
		switch (option) {
		case 'e':
			status = wladm_str2essid(optarg, &attr.wa_essid);
			if (status != WLADM_STATUS_OK)
				die("invalid ESSID '%s'", optarg);

			attr.wa_valid |= WLADM_WLAN_ATTR_ESSID;
			/*
			 * Try to connect without doing a scan.
			 */
			flags |= WLADM_OPT_NOSCAN;
			break;
		case 'i':
			status = wladm_str2bssid(optarg, &attr.wa_bssid);
			if (status != WLADM_STATUS_OK)
				die("invalid BSSID %s", optarg);

			attr.wa_valid |= WLADM_WLAN_ATTR_BSSID;
			break;
		case 'a':
			status = wladm_str2auth(optarg, &attr.wa_auth);
			if (status != WLADM_STATUS_OK)
				die("invalid authentication mode '%s'", optarg);

			attr.wa_valid |= WLADM_WLAN_ATTR_AUTH;
			break;
		case 'm':
			status = wladm_str2mode(optarg, &attr.wa_mode);
			if (status != WLADM_STATUS_OK)
				die("invalid mode '%s'", optarg);

			attr.wa_valid |= WLADM_WLAN_ATTR_MODE;
			break;
		case 'b':
			status = wladm_str2bsstype(optarg, &attr.wa_bsstype);
			if (status != WLADM_STATUS_OK)
				die("invalid bsstype '%s'", optarg);

			attr.wa_valid |= WLADM_WLAN_ATTR_BSSTYPE;
			break;
		case 's':
			status = wladm_str2secmode(optarg, &attr.wa_secmode);
			if (status != WLADM_STATUS_OK)
				die("invalid security mode '%s'", optarg);

			attr.wa_valid |= WLADM_WLAN_ATTR_SECMODE;
			break;
		case 'k':
			if (parse_wep_keys(optarg, &keys, &key_count) < 0)
				die("invalid key(s) '%s'", optarg);

			keysecmode = WLADM_SECMODE_WEP;
			break;
		case 'T':
			if (strcasecmp(optarg, "forever") == 0) {
				timeout = -1;
				break;
			}
			if (!str2int(optarg, &timeout) || timeout < 0)
				die("invalid timeout value '%s'", optarg);
			break;
		case 'c':
			flags |= WLADM_OPT_CREATEIBSS;
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	if (keysecmode == WLADM_SECMODE_NONE) {
		if ((attr.wa_valid & WLADM_WLAN_ATTR_SECMODE) != 0 &&
		    attr.wa_secmode == WLADM_SECMODE_WEP)
			die("key required for security mode 'wep'");
	} else {
		if ((attr.wa_valid & WLADM_WLAN_ATTR_SECMODE) != 0 &&
		    attr.wa_secmode != keysecmode)
			die("incompatible -s and -k options");
	}
	attr.wa_secmode = keysecmode;
	attr.wa_valid |= WLADM_WLAN_ATTR_SECMODE;

	if (optind == (argc - 1))
		link = argv[optind];
	else if (optind != argc)
		usage();

	if (link == NULL) {
		wlan_count_attr_t wcattr;

		wcattr.wc_link = NULL;
		wcattr.wc_count = 0;
		(void) wladm_walk(&wcattr, do_count_wlan);
		if (wcattr.wc_count == 0) {
			die("no wifi links are available");
		} else if (wcattr.wc_count > 1) {
			die("link name is required when more than one wifi "
			    "link is available");
		}
		link = wcattr.wc_link;
	}
	attrp = (attr.wa_valid == 0) ? NULL : &attr;
again:
	status = wladm_connect(link, attrp, timeout, keys, key_count, flags);
	if (status != WLADM_STATUS_OK) {
		if ((flags & WLADM_OPT_NOSCAN) != 0) {
			/*
			 * Try again with scanning and filtering.
			 */
			flags &= ~WLADM_OPT_NOSCAN;
			goto again;
		}

		if (status == WLADM_STATUS_NOTFOUND) {
			if (attr.wa_valid == 0) {
				die("no wifi networks are available");
			} else {
				die("no wifi networks with the specified "
				    "criteria are available");
			}
		}
		die_wlerr(status, "cannot connect link '%s'", link);
	}
	free(keys);
}

/* ARGSUSED */
static boolean_t
do_all_disconnect_wifi(void *arg, const char *link)
{
	wladm_status_t	status;

	status = wladm_disconnect(link);
	if (status != WLADM_STATUS_OK)
		warn_wlerr(status, "cannot disconnect link '%s'", link);

	return (B_TRUE);
}

static void
do_disconnect_wifi(int argc, char **argv)
{
	int			option;
	const char		*link = NULL;
	boolean_t		all_links = B_FALSE;
	wladm_status_t		status;
	wlan_count_attr_t	wcattr;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":a",
	    wifi_longopts, NULL)) != -1) {
		switch (option) {
		case 'a':
			all_links = B_TRUE;
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	if (optind == (argc - 1))
		link = argv[optind];
	else if (optind != argc)
		usage();

	if (link == NULL) {
		if (!all_links) {
			wcattr.wc_link = NULL;
			wcattr.wc_count = 0;
			(void) wladm_walk(&wcattr, do_count_wlan);
			if (wcattr.wc_count == 0) {
				die("no wifi links are available");
			} else if (wcattr.wc_count > 1) {
				die("link name is required when more than "
				    "one wifi link is available");
			}
			link = wcattr.wc_link;
		} else {
			(void) wladm_walk(&all_links, do_all_disconnect_wifi);
			return;
		}
	}
	status = wladm_disconnect(link);
	if (status != WLADM_STATUS_OK)
		die_wlerr(status, "cannot disconnect link '%s'", link);
}

#define	MAX_PROPS		32
#define	MAX_PROP_VALS		32
#define	MAX_PROP_LINE		512

typedef struct prop_info {
	char		*pi_name;
	char		*pi_val[MAX_PROP_VALS];
	uint_t		pi_count;
} prop_info_t;

typedef struct prop_list {
	prop_info_t	pl_info[MAX_PROPS];
	uint_t		pl_count;
	char		*pl_buf;
} prop_list_t;

typedef struct show_linkprop_state {
	const char	*ls_link;
	char		*ls_line;
	char		**ls_propvals;
	prop_list_t	*ls_proplist;
	boolean_t	ls_parseable;
	boolean_t	ls_persist;
	boolean_t	ls_header;
} show_linkprop_state_t;

static void
free_props(prop_list_t *list)
{
	if (list != NULL) {
		free(list->pl_buf);
		free(list);
	}
}

static int
parse_props(char *str, prop_list_t **listp, boolean_t novalues)
{
	prop_list_t	*list;
	prop_info_t	*pip;
	char		*buf, *curr;
	int		len, i;

	list = malloc(sizeof (prop_list_t));
	if (list == NULL)
		return (-1);

	list->pl_count = 0;
	list->pl_buf = buf = strdup(str);
	if (buf == NULL)
		goto fail;

	curr = buf;
	len = strlen(buf);
	pip = NULL;
	for (i = 0; i < len; i++) {
		char		c = buf[i];
		boolean_t	match = (c == '=' || c == ',');

		if (!match && i != len - 1)
			continue;

		if (match) {
			buf[i] = '\0';
			if (*curr == '\0')
				goto fail;
		}

		if (pip != NULL && c != '=') {
			if (pip->pi_count > MAX_PROP_VALS)
				goto fail;

			if (novalues)
				goto fail;

			pip->pi_val[pip->pi_count] = curr;
			pip->pi_count++;
		} else {
			if (list->pl_count > MAX_PROPS)
				goto fail;

			pip = &list->pl_info[list->pl_count];
			pip->pi_name = curr;
			pip->pi_count = 0;
			list->pl_count++;
			if (c == ',')
				pip = NULL;
		}
		curr = buf + i + 1;
	}
	*listp = list;
	return (0);

fail:
	free_props(list);
	return (-1);
}

static void
print_linkprop_head(void)
{
	(void) printf("%-12s %-15s %-14s %-14s %-20s \n",
	    "LINK", "PROPERTY", "VALUE", "DEFAULT", "POSSIBLE");
}

static void
print_linkprop(show_linkprop_state_t *statep, const char *propname,
    dladm_prop_type_t type, const char *typename, const char *format,
    char **pptr)
{
	int		i;
	char		*ptr, *lim;
	char		buf[DLADM_STRSIZE];
	char		*unknown = "?", *notsup = "";
	char		**propvals = statep->ls_propvals;
	uint_t		valcnt = MAX_PROP_VALS;
	dladm_status_t	status;

	status = dladm_get_prop(statep->ls_link, type, propname,
	    propvals, &valcnt);
	if (status != DLADM_STATUS_OK) {
		if (status == DLADM_STATUS_NOTSUP || statep->ls_persist) {
			valcnt = 1;
			if (type == DLADM_PROP_VAL_CURRENT)
				propvals = &unknown;
			else
				propvals = &notsup;
		} else {
			die_dlerr(status, "cannot get link property '%s'",
			    propname);
		}
	}

	ptr = buf;
	lim = buf + DLADM_STRSIZE;
	for (i = 0; i < valcnt; i++) {
		if (propvals[i][0] == '\0' && !statep->ls_parseable)
			ptr += snprintf(ptr, lim - ptr, "--,");
		else
			ptr += snprintf(ptr, lim - ptr, "%s,", propvals[i]);
		if (ptr >= lim)
			break;
	}
	if (valcnt > 0)
		buf[strlen(buf) - 1] = '\0';

	lim = statep->ls_line + MAX_PROP_LINE;
	if (statep->ls_parseable) {
		*pptr += snprintf(*pptr, lim - *pptr,
		    "%s=\"%s\" ", typename, buf);
	} else {
		*pptr += snprintf(*pptr, lim - *pptr, format, buf);
	}
}

static boolean_t
show_linkprop(void *arg, const char *propname)
{
	show_linkprop_state_t	*statep = arg;
	char			*ptr = statep->ls_line;
	char			*lim = ptr + MAX_PROP_LINE;

	if (statep->ls_persist && dladm_is_prop_temponly(propname, NULL))
		return (B_TRUE);

	if (statep->ls_parseable)
		ptr += snprintf(ptr, lim - ptr, "LINK=\"%s\" ",
		    statep->ls_link);
	else
		ptr += snprintf(ptr, lim - ptr, "%-12s ", statep->ls_link);

	if (statep->ls_parseable)
		ptr += snprintf(ptr, lim - ptr, "PROPERTY=\"%s\" ", propname);
	else
		ptr += snprintf(ptr, lim - ptr, "%-15s ", propname);

	print_linkprop(statep, propname,
	    statep->ls_persist ? DLADM_PROP_VAL_PERSISTENT :
	    DLADM_PROP_VAL_CURRENT, "VALUE", "%-14s ", &ptr);
	print_linkprop(statep, propname, DLADM_PROP_VAL_DEFAULT,
	    "DEFAULT", "%-14s ", &ptr);
	print_linkprop(statep, propname, DLADM_PROP_VAL_MODIFIABLE,
	    "POSSIBLE", "%-20s ", &ptr);

	if (statep->ls_header) {
		statep->ls_header = B_FALSE;
		if (!statep->ls_parseable)
			print_linkprop_head();
	}
	(void) printf("%s\n", statep->ls_line);
	return (B_TRUE);
}

static void
do_show_linkprop(int argc, char **argv)
{
	int			option;
	prop_list_t		*proplist = NULL;
	show_linkprop_state_t	state;

	opterr = 0;
	state.ls_link = NULL;
	state.ls_propvals = NULL;
	state.ls_line = NULL;
	state.ls_parseable = B_FALSE;
	state.ls_persist = B_FALSE;
	state.ls_header = B_TRUE;
	while ((option = getopt_long(argc, argv, ":p:cP",
	    prop_longopts, NULL)) != -1) {
		switch (option) {
		case 'p':
			if (parse_props(optarg, &proplist, B_TRUE) < 0)
				die("invalid link properties specified");
			break;
		case 'c':
			state.ls_parseable = B_TRUE;
			break;
		case 'P':
			state.ls_persist = B_TRUE;
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	if (optind == (argc - 1))
		state.ls_link = argv[optind];
	else if (optind != argc)
		usage();

	state.ls_proplist = proplist;

	if (state.ls_link == NULL) {
		(void) dladm_walk(show_linkprop_onelink, &state);
	} else {
		show_linkprop_onelink(&state, state.ls_link);
	}
	free_props(proplist);
}

static void
show_linkprop_onelink(void *arg, const char *link)
{
	int			i, fd;
	char			linkname[MAXPATHLEN];
	char			*buf;
	dladm_status_t		status;
	prop_list_t		*proplist = NULL;
	show_linkprop_state_t	*statep;
	const char		*savep;

	statep = (show_linkprop_state_t *)arg;
	savep = statep->ls_link;
	statep->ls_link = link;
	proplist = statep->ls_proplist;

	/*
	 * When some WiFi links are opened for the first time, their hardware
	 * automatically scans for APs and does other slow operations.	Thus,
	 * if there are no open links, the retrieval of link properties
	 * (below) will proceed slowly unless we hold the link open.
	 */
	(void) snprintf(linkname, MAXPATHLEN, "/dev/%s", link);
	if ((fd = open(linkname, O_RDWR)) < 0)
		die("cannot open %s: %s", link, strerror(errno));

	buf = malloc((sizeof (char *) + DLADM_PROP_VAL_MAX) * MAX_PROP_VALS +
	    MAX_PROP_LINE);
	if (buf == NULL)
		die("insufficient memory");

	statep->ls_propvals = (char **)(void *)buf;
	for (i = 0; i < MAX_PROP_VALS; i++) {
		statep->ls_propvals[i] = buf + sizeof (char *) * MAX_PROP_VALS +
		    i * DLADM_PROP_VAL_MAX;
	}
	statep->ls_line = buf +
	    (sizeof (char *) + DLADM_PROP_VAL_MAX) * MAX_PROP_VALS;

	if (proplist != NULL) {
		for (i = 0; i < proplist->pl_count; i++) {
			if (!show_linkprop(statep,
			    proplist->pl_info[i].pi_name))
				break;
		}
	} else {
		status = dladm_walk_prop(link, statep, show_linkprop);
		if (status != DLADM_STATUS_OK)
			die_dlerr(status, "show-linkprop");
	}
	(void) close(fd);
	free(buf);
	statep->ls_link = savep;
}

static dladm_status_t
set_linkprop_persist(const char *link, const char *prop_name, char **prop_val,
    uint_t val_cnt, boolean_t reset)
{
	dladm_status_t	status;
	char		*errprop;

	status = dladm_set_prop(link, prop_name, prop_val, val_cnt,
	    DLADM_OPT_PERSIST, &errprop);

	if (status != DLADM_STATUS_OK) {
		if (reset) {
			warn_dlerr(status, "cannot persistently reset link "
			    "property '%s' on '%s'", errprop, link);
		} else {
			warn_dlerr(status, "cannot persistently set link "
			    "property '%s' on '%s'", errprop, link);
		}
	}
	return (status);
}

static void
set_linkprop(int argc, char **argv, boolean_t reset)
{
	int		i, option;
	char		errmsg[DLADM_STRSIZE];
	const char	*link = NULL;
	prop_list_t	*proplist = NULL;
	boolean_t	temp = B_FALSE;
	dladm_status_t	status = DLADM_STATUS_OK;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":p:R:t",
	    prop_longopts, NULL)) != -1) {
		switch (option) {
		case 'p':
			if (parse_props(optarg, &proplist, reset) < 0)
				die("invalid link properties specified");
			break;
		case 't':
			temp = B_TRUE;
			break;
		case 'R':
			status = dladm_set_rootdir(optarg);
			if (status != DLADM_STATUS_OK) {
				die_dlerr(status, "invalid directory "
				    "specified");
			}
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	if (optind == (argc - 1))
		link = argv[optind];
	else if (optind != argc)
		usage();

	if (link == NULL)
		die("link name must be specified");

	if (proplist == NULL) {
		char *errprop;

		if (!reset)
			die("link property must be specified");

		status = dladm_set_prop(link, NULL, NULL, 0, DLADM_OPT_TEMP,
		    &errprop);
		if (status != DLADM_STATUS_OK) {
			warn_dlerr(status, "cannot reset link property '%s' "
			    "on '%s'", errprop, link);
		}
		if (!temp) {
			dladm_status_t	s;

			s = set_linkprop_persist(link, NULL, NULL, 0, reset);
			if (s != DLADM_STATUS_OK)
				status = s;
		}
		goto done;
	}

	for (i = 0; i < proplist->pl_count; i++) {
		prop_info_t	*pip = &proplist->pl_info[i];
		char		**val;
		uint_t		count;
		dladm_status_t	s;

		if (reset) {
			val = NULL;
			count = 0;
		} else {
			val = pip->pi_val;
			count = pip->pi_count;
			if (count == 0) {
				warn("no value specified for '%s'",
				    pip->pi_name);
				status = DLADM_STATUS_BADARG;
				continue;
			}
		}
		s = dladm_set_prop(link, pip->pi_name, val, count,
		    DLADM_OPT_TEMP, NULL);
		if (s == DLADM_STATUS_OK) {
			if (!temp) {
				s = set_linkprop_persist(link,
				    pip->pi_name, val, count, reset);
				if (s != DLADM_STATUS_OK)
					status = s;
			}
			continue;
		}
		status = s;
		switch (s) {
		case DLADM_STATUS_NOTFOUND:
			warn("invalid link property '%s'", pip->pi_name);
			break;
		case DLADM_STATUS_BADVAL: {
			int		j;
			char		*ptr, *lim;
			char		**propvals = NULL;
			uint_t		valcnt = MAX_PROP_VALS;

			ptr = malloc((sizeof (char *) +
			    DLADM_PROP_VAL_MAX) * MAX_PROP_VALS +
			    MAX_PROP_LINE);

			propvals = (char **)(void *)ptr;
			if (propvals == NULL)
				die("insufficient memory");

			for (j = 0; j < MAX_PROP_VALS; j++) {
				propvals[j] = ptr + sizeof (char *) *
				    MAX_PROP_VALS +
				    j * DLADM_PROP_VAL_MAX;
			}
			s = dladm_get_prop(link, DLADM_PROP_VAL_MODIFIABLE,
			    pip->pi_name, propvals, &valcnt);

			ptr = errmsg;
			lim = ptr + DLADM_STRSIZE;
			*ptr = '\0';
			for (j = 0; j < valcnt && s == DLADM_STATUS_OK; j++) {
				ptr += snprintf(ptr, lim - ptr, "%s,",
				    propvals[j]);
				if (ptr >= lim)
					break;
			}
			if (ptr > errmsg) {
				*(ptr - 1) = '\0';
				warn("link property '%s' must be one of: %s",
				    pip->pi_name, errmsg);
			} else
				warn("invalid link property '%s'", *val);
			free(propvals);
			break;
		}
		default:
			if (reset) {
				warn_dlerr(status, "cannot reset link property "
				    "'%s' on '%s'", pip->pi_name, link);
			} else {
				warn_dlerr(status, "cannot set link property "
				    "'%s' on '%s'", pip->pi_name, link);
			}
			break;
		}
	}
done:
	free_props(proplist);
	if (status != DLADM_STATUS_OK)
		exit(1);
}

static void
do_set_linkprop(int argc, char **argv)
{
	set_linkprop(argc, argv, B_FALSE);
}

static void
do_reset_linkprop(int argc, char **argv)
{
	set_linkprop(argc, argv, B_TRUE);
}

static int
convert_secobj(char *buf, uint_t len, uint8_t *obj_val, uint_t *obj_lenp,
    dladm_secobj_class_t class)
{
	int error = 0;

	if (class != DLADM_SECOBJ_CLASS_WEP)
		return (ENOENT);

	switch (len) {
	case 5:			/* ASCII key sizes */
	case 13:
		(void) memcpy(obj_val, buf, len);
		*obj_lenp = len;
		break;
	case 10:		/* Hex key sizes, not preceded by 0x */
	case 26:
		error = hexascii_to_octet(buf, len, obj_val, obj_lenp);
		break;
	case 12:		/* Hex key sizes, preceded by 0x */
	case 28:
		if (strncmp(buf, "0x", 2) != 0)
			return (EINVAL);
		error = hexascii_to_octet(buf + 2, len - 2, obj_val, obj_lenp);
		break;
	default:
		return (EINVAL);
	}
	return (error);
}

/* ARGSUSED */
static void
defersig(int sig)
{
	signalled = sig;
}

static int
get_secobj_from_tty(uint_t try, const char *objname, char *buf)
{
	uint_t		len = 0;
	int		c;
	struct termios	stored, current;
	void		(*sigfunc)(int);

	/*
	 * Turn off echo -- but before we do so, defer SIGINT handling
	 * so that a ^C doesn't leave the terminal corrupted.
	 */
	sigfunc = signal(SIGINT, defersig);
	(void) fflush(stdin);
	(void) tcgetattr(0, &stored);
	current = stored;
	current.c_lflag &= ~(ICANON|ECHO);
	current.c_cc[VTIME] = 0;
	current.c_cc[VMIN] = 1;
	(void) tcsetattr(0, TCSANOW, &current);
again:
	if (try == 1)
		(void) printf(gettext("provide value for '%s': "), objname);
	else
		(void) printf(gettext("confirm value for '%s': "), objname);

	(void) fflush(stdout);
	while (signalled == 0) {
		c = getchar();
		if (c == '\n' || c == '\r') {
			if (len != 0)
				break;
			(void) putchar('\n');
			goto again;
		}

		buf[len++] = c;
		if (len >= DLADM_SECOBJ_VAL_MAX - 1)
			break;
		(void) putchar('*');
	}

	(void) putchar('\n');
	(void) fflush(stdin);

	/*
	 * Restore terminal setting and handle deferred signals.
	 */
	(void) tcsetattr(0, TCSANOW, &stored);

	(void) signal(SIGINT, sigfunc);
	if (signalled != 0)
		(void) kill(getpid(), signalled);

	return (len);
}

static int
get_secobj_val(char *obj_name, uint8_t *obj_val, uint_t *obj_lenp,
    dladm_secobj_class_t class, FILE *filep)
{
	int		rval;
	uint_t		len, len2;
	char		buf[DLADM_SECOBJ_VAL_MAX], buf2[DLADM_SECOBJ_VAL_MAX];

	if (filep == NULL) {
		len = get_secobj_from_tty(1, obj_name, buf);
		rval = convert_secobj(buf, len, obj_val, obj_lenp, class);
		if (rval == 0) {
			len2 = get_secobj_from_tty(2, obj_name, buf2);
			if (len != len2 || memcmp(buf, buf2, len) != 0)
				rval = ENOTSUP;
		}
		return (rval);
	} else {
		for (;;) {
			if (fgets(buf, sizeof (buf), filep) == NULL)
				break;
			if (isspace(buf[0]))
				continue;

			len = strlen(buf);
			if (buf[len - 1] == '\n') {
				buf[len - 1] = '\0';
				len--;
			}
			break;
		}
		(void) fclose(filep);
	}
	return (convert_secobj(buf, len, obj_val, obj_lenp, class));
}

static boolean_t
check_auth(const char *auth)
{
	struct passwd	*pw;

	if ((pw = getpwuid(getuid())) == NULL)
		return (B_FALSE);

	return (chkauthattr(auth, pw->pw_name) != 0);
}

static void
audit_secobj(char *auth, char *class, char *obj,
    boolean_t success, boolean_t create)
{
	adt_session_data_t	*ah;
	adt_event_data_t	*event;
	au_event_t		flag;
	char			*errstr;

	if (create) {
		flag = ADT_dladm_create_secobj;
		errstr = "ADT_dladm_create_secobj";
	} else {
		flag = ADT_dladm_delete_secobj;
		errstr = "ADT_dladm_delete_secobj";
	}

	if (adt_start_session(&ah, NULL, ADT_USE_PROC_DATA) != 0)
		die("adt_start_session: %s", strerror(errno));

	if ((event = adt_alloc_event(ah, flag)) == NULL)
		die("adt_alloc_event (%s): %s", errstr, strerror(errno));

	/* fill in audit info */
	if (create) {
		event->adt_dladm_create_secobj.auth_used = auth;
		event->adt_dladm_create_secobj.obj_class = class;
		event->adt_dladm_create_secobj.obj_name = obj;
	} else {
		event->adt_dladm_delete_secobj.auth_used = auth;
		event->adt_dladm_delete_secobj.obj_class = class;
		event->adt_dladm_delete_secobj.obj_name = obj;
	}

	if (success) {
		if (adt_put_event(event, ADT_SUCCESS, ADT_SUCCESS) != 0) {
			die("adt_put_event (%s, success): %s", errstr,
			    strerror(errno));
		}
	} else {
		if (adt_put_event(event, ADT_FAILURE,
		    ADT_FAIL_VALUE_AUTH) != 0) {
			die("adt_put_event: (%s, failure): %s", errstr,
			    strerror(errno));
		}
	}

	adt_free_event(event);
	(void) adt_end_session(ah);
}

#define	MAX_SECOBJS		32
#define	MAX_SECOBJ_NAMELEN	32
static void
do_create_secobj(int argc, char **argv)
{
	int			option, rval;
	FILE			*filep = NULL;
	char			*obj_name = NULL;
	char			*class_name = NULL;
	uint8_t			obj_val[DLADM_SECOBJ_VAL_MAX];
	uint_t			obj_len;
	boolean_t		success, temp = B_FALSE;
	dladm_status_t		status;
	dladm_secobj_class_t	class = -1;
	uid_t			euid;

	opterr = 0;
	(void) memset(obj_val, 0, DLADM_SECOBJ_VAL_MAX);
	while ((option = getopt_long(argc, argv, ":f:c:R:t",
	    wifi_longopts, NULL)) != -1) {
		switch (option) {
		case 'f':
			euid = geteuid();
			(void) seteuid(getuid());
			filep = fopen(optarg, "r");
			if (filep == NULL) {
				die("cannot open %s: %s", optarg,
				    strerror(errno));
			}
			(void) seteuid(euid);
			break;
		case 'c':
			class_name = optarg;
			status = dladm_str2secobjclass(optarg, &class);
			if (status != DLADM_STATUS_OK) {
				die("invalid secure object class '%s', "
				    "valid values are: wep", optarg);
			}
			break;
		case 't':
			temp = B_TRUE;
			break;
		case 'R':
			status = dladm_set_rootdir(optarg);
			if (status != DLADM_STATUS_OK) {
				die_dlerr(status, "invalid directory "
				    "specified");
			}
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	if (optind == (argc - 1))
		obj_name = argv[optind];
	else if (optind != argc)
		usage();

	if (class == -1)
		die("secure object class required");

	if (obj_name == NULL)
		die("secure object name required");

	success = check_auth(LINK_SEC_AUTH);
	audit_secobj(LINK_SEC_AUTH, class_name, obj_name, success, B_TRUE);
	if (!success)
		die("authorization '%s' is required", LINK_SEC_AUTH);

	rval = get_secobj_val(obj_name, obj_val, &obj_len, class, filep);
	if (rval != 0) {
		switch (rval) {
		case ENOENT:
			die("invalid secure object class");
			break;
		case EINVAL:
			die("invalid secure object value");
			break;
		case ENOTSUP:
			die("verification failed");
			break;
		default:
			die("invalid secure object: %s", strerror(rval));
			break;
		}
	}

	status = dladm_set_secobj(obj_name, class, obj_val, obj_len,
	    DLADM_OPT_CREATE | DLADM_OPT_TEMP);
	if (status != DLADM_STATUS_OK) {
		die_dlerr(status, "could not create secure object '%s'",
		    obj_name);
	}
	if (temp)
		return;

	status = dladm_set_secobj(obj_name, class, obj_val, obj_len,
	    DLADM_OPT_PERSIST);
	if (status != DLADM_STATUS_OK) {
		warn_dlerr(status, "could not persistently create secure "
		    "object '%s'", obj_name);
	}
}

static void
do_delete_secobj(int argc, char **argv)
{
	int		i, option;
	boolean_t	temp = B_FALSE;
	split_t		*sp = NULL;
	boolean_t	success;
	dladm_status_t	status, pstatus;

	opterr = 0;
	status = pstatus = DLADM_STATUS_OK;
	while ((option = getopt_long(argc, argv, ":R:t",
	    wifi_longopts, NULL)) != -1) {
		switch (option) {
		case 't':
			temp = B_TRUE;
			break;
		case 'R':
			status = dladm_set_rootdir(optarg);
			if (status != DLADM_STATUS_OK) {
				die_dlerr(status, "invalid directory "
				    "specified");
			}
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	if (optind == (argc - 1)) {
		sp = split(argv[optind], MAX_SECOBJS, MAX_SECOBJ_NAMELEN);
		if (sp == NULL) {
			die("invalid secure object name(s): '%s'",
			    argv[optind]);
		}
	} else if (optind != argc)
		usage();

	if (sp == NULL || sp->s_nfields < 1)
		die("secure object name required");

	success = check_auth(LINK_SEC_AUTH);
	audit_secobj(LINK_SEC_AUTH, "wep", argv[optind], success, B_FALSE);
	if (!success)
		die("authorization '%s' is required", LINK_SEC_AUTH);

	for (i = 0; i < sp->s_nfields; i++) {
		status = dladm_unset_secobj(sp->s_fields[i], DLADM_OPT_TEMP);
		if (!temp) {
			pstatus = dladm_unset_secobj(sp->s_fields[i],
			    DLADM_OPT_PERSIST);
		} else {
			pstatus = DLADM_STATUS_OK;
		}

		if (status != DLADM_STATUS_OK) {
			warn_dlerr(status, "could not delete secure object "
			    "'%s'", sp->s_fields[i]);
		}
		if (pstatus != DLADM_STATUS_OK) {
			warn_dlerr(pstatus, "could not persistently delete "
			    "secure object '%s'", sp->s_fields[i]);
		}
	}
	if (status != DLADM_STATUS_OK || pstatus != DLADM_STATUS_OK)
		exit(1);
}

typedef struct show_secobj_state {
	boolean_t	ss_persist;
	boolean_t	ss_parseable;
	boolean_t	ss_debug;
	boolean_t	ss_header;
} show_secobj_state_t;

static void
print_secobj_head(show_secobj_state_t *statep)
{
	(void) printf("%-20s %-20s ", "OBJECT", "CLASS");
	if (statep->ss_debug)
		(void) printf("%-30s", "VALUE");
	(void) putchar('\n');
}

static boolean_t
show_secobj(void *arg, const char *obj_name)
{
	uint_t			obj_len = DLADM_SECOBJ_VAL_MAX;
	uint8_t			obj_val[DLADM_SECOBJ_VAL_MAX];
	char			buf[DLADM_STRSIZE];
	uint_t			flags = 0;
	dladm_secobj_class_t	class;
	show_secobj_state_t	*statep = arg;
	dladm_status_t		status;

	if (statep->ss_persist)
		flags |= DLADM_OPT_PERSIST;

	status = dladm_get_secobj(obj_name, &class, obj_val, &obj_len, flags);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "cannot get secure object '%s'", obj_name);

	if (statep->ss_header) {
		statep->ss_header = B_FALSE;
		if (!statep->ss_parseable)
			print_secobj_head(statep);
	}

	if (statep->ss_parseable) {
		(void) printf("OBJECT=\"%s\" CLASS=\"%s\" ", obj_name,
		    dladm_secobjclass2str(class, buf));
	} else {
		(void) printf("%-20s %-20s ", obj_name,
		    dladm_secobjclass2str(class, buf));
	}

	if (statep->ss_debug) {
		char	val[DLADM_SECOBJ_VAL_MAX * 2];
		uint_t	len = sizeof (val);

		if (octet_to_hexascii(obj_val, obj_len, val, &len) == 0) {
			if (statep->ss_parseable)
				(void) printf("VALUE=\"0x%s\"", val);
			else
				(void) printf("0x%-30s", val);
		}
	}
	(void) putchar('\n');
	return (B_TRUE);
}

static void
do_show_secobj(int argc, char **argv)
{
	int			option;
	show_secobj_state_t	state;
	dladm_status_t		status;
	uint_t			i;
	split_t			*sp;
	uint_t			flags;

	opterr = 0;
	state.ss_persist = B_FALSE;
	state.ss_parseable = B_FALSE;
	state.ss_debug = B_FALSE;
	state.ss_header = B_TRUE;
	while ((option = getopt_long(argc, argv, ":pPd",
	    wifi_longopts, NULL)) != -1) {
		switch (option) {
		case 'p':
			state.ss_parseable = B_TRUE;
			break;
		case 'P':
			state.ss_persist = B_TRUE;
			break;
		case 'd':
			if (getuid() != 0)
				die("insufficient privileges");
			state.ss_debug = B_TRUE;
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	if (optind == (argc - 1)) {
		sp = split(argv[optind], MAX_SECOBJS, MAX_SECOBJ_NAMELEN);
		if (sp == NULL) {
			die("invalid secure object name(s): '%s'",
			    argv[optind]);
		}
		for (i = 0; i < sp->s_nfields; i++) {
			if (!show_secobj(&state, sp->s_fields[i]))
				break;
		}
		splitfree(sp);
		return;
	} else if (optind != argc)
		usage();

	flags = state.ss_persist ? DLADM_OPT_PERSIST : 0;
	status = dladm_walk_secobj(&state, show_secobj, flags);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "show-secobj");
}

/* ARGSUSED */
static void
do_init_linkprop(int argc, char **argv)
{
	dladm_status_t status;

	status = dladm_init_linkprop();
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "link property initialization failed");
}

/* ARGSUSED */
static void
do_init_secobj(int argc, char **argv)
{
	dladm_status_t status;

	status = dladm_init_secobj();
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "secure object initialization failed");
}

static boolean_t
str2int(const char *str, int *valp)
{
	int	val;
	char	*endp = NULL;

	errno = 0;
	val = strtol(str, &endp, 10);
	if (errno != 0 || *endp != '\0')
		return (B_FALSE);

	*valp = val;
	return (B_TRUE);
}

/* PRINTFLIKE1 */
static void
warn(const char *format, ...)
{
	va_list alist;

	format = gettext(format);
	(void) fprintf(stderr, "%s: warning: ", progname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);

	(void) putchar('\n');
}

/* PRINTFLIKE2 */
static void
warn_wlerr(wladm_status_t err, const char *format, ...)
{
	va_list alist;
	char	errmsg[WLADM_STRSIZE];

	format = gettext(format);
	(void) fprintf(stderr, gettext("%s: warning: "), progname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);
	(void) fprintf(stderr, ": %s\n", wladm_status2str(err, errmsg));
}

/* PRINTFLIKE2 */
static void
warn_dlerr(dladm_status_t err, const char *format, ...)
{
	va_list alist;
	char	errmsg[DLADM_STRSIZE];

	format = gettext(format);
	(void) fprintf(stderr, gettext("%s: warning: "), progname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);
	(void) fprintf(stderr, ": %s\n", dladm_status2str(err, errmsg));
}

/* PRINTFLIKE2 */
static void
die_laerr(laadm_diag_t diag, const char *format, ...)
{
	va_list alist;
	char	*errstr = strerror(errno);

	format = gettext(format);
	(void) fprintf(stderr, "%s: ", progname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);

	if (diag == 0)
		(void) fprintf(stderr, ": %s\n", errstr);
	else
		(void) fprintf(stderr, ": %s (%s)\n", errstr, laadm_diag(diag));

	exit(EXIT_FAILURE);
}

/* PRINTFLIKE2 */
static void
die_wlerr(wladm_status_t err, const char *format, ...)
{
	va_list alist;
	char	errmsg[WLADM_STRSIZE];

	format = gettext(format);
	(void) fprintf(stderr, "%s: ", progname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);
	(void) fprintf(stderr, ": %s\n", wladm_status2str(err, errmsg));

	exit(EXIT_FAILURE);
}

/* PRINTFLIKE2 */
static void
die_dlerr(dladm_status_t err, const char *format, ...)
{
	va_list alist;
	char	errmsg[DLADM_STRSIZE];

	format = gettext(format);
	(void) fprintf(stderr, "%s: ", progname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);
	(void) fprintf(stderr, ": %s\n", dladm_status2str(err, errmsg));

	exit(EXIT_FAILURE);
}

/* PRINTFLIKE1 */
static void
die(const char *format, ...)
{
	va_list alist;

	format = gettext(format);
	(void) fprintf(stderr, "%s: ", progname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);

	(void) putchar('\n');
	exit(EXIT_FAILURE);
}

static void
die_optdup(int opt)
{
	die("the option -%c cannot be specified more than once", opt);
}

static void
die_opterr(int opt, int opterr)
{
	switch (opterr) {
	case ':':
		die("option '-%c' requires a value", opt);
		break;
	case '?':
	default:
		die("unrecognized option '-%c'", opt);
		break;
	}
}

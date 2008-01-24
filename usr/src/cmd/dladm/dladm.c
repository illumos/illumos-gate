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
#include <sys/stat.h>
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
#include <libdevinfo.h>
#include <libdlpi.h>
#include <libdllink.h>
#include <libdlaggr.h>
#include <libdlwlan.h>
#include <libdlvlan.h>
#include <libdlvnic.h>
#include <libinetutil.h>
#include <bsm/adt.h>
#include <bsm/adt_event.h>

#define	AGGR_DRV		"aggr"
#define	MAXPORT			256
#define	BUFLEN(lim, ptr)	(((lim) > (ptr)) ? ((lim) - (ptr)) : 0)
#define	MAXLINELEN		1024
#define	SMF_UPGRADE_FILE		"/var/svc/profile/upgrade"
#define	SMF_UPGRADEDATALINK_FILE	"/var/svc/profile/upgrade_datalink"
#define	SMF_DLADM_UPGRADE_MSG		" # added by dladm(1M)"

typedef struct pktsum_s {
	uint64_t	ipackets;
	uint64_t	opackets;
	uint64_t	rbytes;
	uint64_t	obytes;
	uint32_t	ierrors;
	uint32_t	oerrors;
} pktsum_t;

typedef struct show_state {
	boolean_t	ls_firstonly;
	boolean_t	ls_donefirst;
	pktsum_t	ls_prevstats;
	boolean_t	ls_parseable;
	uint32_t	ls_flags;
	dladm_status_t	ls_status;
} show_state_t;

typedef struct show_grp_state {
	boolean_t	gs_lacp;
	boolean_t	gs_extended;
	boolean_t	gs_stats;
	boolean_t	gs_firstonly;
	boolean_t	gs_donefirst;
	pktsum_t	gs_prevstats[MAXPORT];
	boolean_t	gs_parseable;
	uint32_t	gs_flags;
	dladm_status_t	gs_status;
} show_grp_state_t;

typedef void cmdfunc_t(int, char **);

static cmdfunc_t do_show_link, do_show_dev, do_show_wifi, do_show_phys;
static cmdfunc_t do_create_aggr, do_delete_aggr, do_add_aggr, do_remove_aggr;
static cmdfunc_t do_modify_aggr, do_show_aggr, do_up_aggr;
static cmdfunc_t do_scan_wifi, do_connect_wifi, do_disconnect_wifi;
static cmdfunc_t do_show_linkprop, do_set_linkprop, do_reset_linkprop;
static cmdfunc_t do_create_secobj, do_delete_secobj, do_show_secobj;
static cmdfunc_t do_init_linkprop, do_init_secobj;
static cmdfunc_t do_create_vlan, do_delete_vlan, do_up_vlan, do_show_vlan;
static cmdfunc_t do_rename_link, do_delete_phys, do_init_phys;
static cmdfunc_t do_show_linkmap;

static void	altroot_cmd(char *, int, char **);
static int	show_linkprop_onelink(datalink_id_t, void *);

static void	link_stats(datalink_id_t, uint_t);
static void	aggr_stats(datalink_id_t, show_grp_state_t *, uint_t);
static void	dev_stats(const char *dev, uint32_t);

static int	get_one_kstat(const char *, const char *, uint8_t,
		    void *, boolean_t);
static void	get_mac_stats(const char *, pktsum_t *);
static void	get_link_stats(const char *, pktsum_t *);
static uint64_t	get_ifspeed(const char *, boolean_t);
static void	stats_total(pktsum_t *, pktsum_t *, pktsum_t *);
static void	stats_diff(pktsum_t *, pktsum_t *, pktsum_t *);
static const char	*get_linkstate(const char *, boolean_t, char *);
static const char	*get_linkduplex(const char *, boolean_t, char *);

static boolean_t str2int(const char *, int *);
static void	die(const char *, ...);
static void	die_optdup(int);
static void	die_opterr(int, int);
static void	die_dlerr(dladm_status_t, const char *, ...);
static void	warn(const char *, ...);
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
	{ "init-secobj",	do_init_secobj		},
	{ "create-vlan", 	do_create_vlan 		},
	{ "delete-vlan", 	do_delete_vlan 		},
	{ "show-vlan",		do_show_vlan		},
	{ "up-vlan",		do_up_vlan		},
	{ "rename-link",	do_rename_link 		},
	{ "delete-phys",	do_delete_phys 		},
	{ "show-phys",		do_show_phys		},
	{ "init-phys",		do_init_phys		},
	{ "show-linkmap",	do_show_linkmap		}
};

static const struct option lopts[] = {
	{"vlan-id",	required_argument,	0, 'v'},
	{"dev",		required_argument,	0, 'd'},
	{"policy",	required_argument,	0, 'P'},
	{"lacp-mode",	required_argument,	0, 'L'},
	{"lacp-timer",	required_argument,	0, 'T'},
	{"unicast",	required_argument,	0, 'u'},
	{"temporary",	no_argument,		0, 't'},
	{"root-dir",	required_argument,	0, 'R'},
	{"link",	required_argument,	0, 'l'},
	{"forcible",	no_argument,		0, 'f'},
	{ 0, 0, 0, 0 }
};

static const struct option show_lopts[] = {
	{"statistics",	no_argument,		0, 's'},
	{"interval",	required_argument,	0, 'i'},
	{"parseable",	no_argument,		0, 'p'},
	{"extended",	no_argument,		0, 'x'},
	{"persistent",	no_argument,		0, 'P'},
	{"lacp",	no_argument,		0, 'L'},
	{ 0, 0, 0, 0 }
};

static const struct option prop_longopts[] = {
	{"temporary",	no_argument,		0, 't'  },
	{"root-dir",	required_argument,	0, 'R'  },
	{"prop",	required_argument,	0, 'p'  },
	{"parseable",	no_argument,		0, 'c'  },
	{"persistent",	no_argument,		0, 'P'  },
	{ 0, 0, 0, 0 }
};

static const struct option wifi_longopts[] = {
	{"parseable",	no_argument,		0, 'p'  },
	{"output",	required_argument,	0, 'o'  },
	{"essid",	required_argument,	0, 'e'  },
	{"bsstype",	required_argument,	0, 'b'  },
	{"mode",	required_argument,	0, 'm'  },
	{"key",		required_argument,	0, 'k'  },
	{"sec",		required_argument,	0, 's'  },
	{"auth",	required_argument,	0, 'a'  },
	{"create-ibss",	required_argument,	0, 'c'  },
	{"timeout",	required_argument,	0, 'T'  },
	{"all-links",	no_argument,		0, 'a'  },
	{"temporary",	no_argument,		0, 't'  },
	{"root-dir",	required_argument,	0, 'R'  },
	{"persistent",	no_argument,		0, 'P'  },
	{"file",	required_argument,	0, 'f'  },
	{ 0, 0, 0, 0 }
};

static char *progname;
static sig_atomic_t signalled;

static void
usage(void)
{
	(void) fprintf(stderr, gettext("usage:	dladm <subcommand> <args> ...\n"
	    "\tshow-link       [-pP] [-s [-i <interval>]] [<link>]\n"
	    "\trename-link     [-R <root-dir>] <oldlink> <newlink>\n"
	    "\n"
	    "\tdelete-phys     <link>\n"
	    "\tshow-phys       [-pP] [<link>]\n"
	    "\tshow-dev        [-p]  [-s [-i <interval>]] [<dev>]\n"
	    "\n"
	    "\tcreate-aggr     [-t] [-R <root-dir>] [-P <policy>] [-L <mode>]\n"
	    "\t		[-T <time>] [-u <address>] [-l <link>] ... <link>\n"
	    "\tmodify-aggr     [-t] [-R <root-dir>] [-P <policy>] [-L <mode>]\n"
	    "\t		[-T <time>] [-u <address>] <link>\n"
	    "\tdelete-aggr     [-t] [-R <root-dir>] <link>\n"
	    "\tadd-aggr	[-t] [-R <root-dir>] [-l <link>] ... <link>\n"
	    "\tremove-aggr     [-t] [-R <root-dir>] [-l <link>] ... <link>"
	    "\n\tshow-aggr       [-pPLx][-s [-i <interval>]] [<link>]\n"
	    "\n"
	    "\tcreate-vlan     [-ft] [-R <root-dir>] -l <link> -v <vid> [link]"
	    "\n\tdelete-vlan     [-t]  [-R <root-dir>] <link>\n"
	    "\tshow-vlan       [-pP] [<link>]\n"
	    "\n"
	    "\tscan-wifi       [-p] [-o <field>,...] [<link>]\n"
	    "\tconnect-wifi    [-e <essid>] [-i <bssid>] [-k <key>,...]"
	    " [-s wep|wpa]\n"
	    "\t                [-a open|shared] [-b bss|ibss] [-c] [-m a|b|g]\n"
	    "\t                [-T <time>] [<link>]\n"
	    "\tdisconnect-wifi [-a] [<link>]\n"
	    "\tshow-wifi       [-p] [-o <field>,...] [<link>]\n"
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
	int			key = 0;
	uint32_t		policy = AGGR_POLICY_L4;
	aggr_lacp_mode_t	lacp_mode = AGGR_LACP_OFF;
	aggr_lacp_timer_t	lacp_timer = AGGR_LACP_TIMER_SHORT;
	dladm_aggr_port_attr_db_t	port[MAXPORT];
	uint_t			n, ndev, nlink;
	uint8_t			mac_addr[ETHERADDRL];
	boolean_t		mac_addr_fixed = B_FALSE;
	boolean_t		P_arg = B_FALSE;
	boolean_t		l_arg = B_FALSE;
	boolean_t		u_arg = B_FALSE;
	boolean_t		T_arg = B_FALSE;
	uint32_t		flags = DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST;
	char			*altroot = NULL;
	char			name[MAXLINKNAMELEN];
	char			*devs[MAXPORT];
	char			*links[MAXPORT];
	dladm_status_t		status;

	ndev = nlink = opterr = 0;
	while ((option = getopt_long(argc, argv, ":d:l:L:P:R:tfu:T:",
	    lopts, NULL)) != -1) {
		switch (option) {
		case 'd':
			if (ndev + nlink >= MAXPORT)
				die("too many ports specified");

			devs[ndev++] = optarg;
			break;
		case 'P':
			if (P_arg)
				die_optdup(option);

			P_arg = B_TRUE;
			if (!dladm_aggr_str2policy(optarg, &policy))
				die("invalid policy '%s'", optarg);
			break;
		case 'u':
			if (u_arg)
				die_optdup(option);

			u_arg = B_TRUE;
			if (!dladm_aggr_str2macaddr(optarg, &mac_addr_fixed,
			    mac_addr))
				die("invalid MAC address '%s'", optarg);
			break;
		case 'l':
			if (isdigit(optarg[strlen(optarg) - 1])) {

				/*
				 * Ended with digit, possibly a link name.
				 */
				if (ndev + nlink >= MAXPORT)
					die("too many ports specified");

				links[nlink++] = optarg;
				break;
			}
			/* FALLTHROUGH */
		case 'L':
			if (l_arg)
				die_optdup(option);

			l_arg = B_TRUE;
			if (!dladm_aggr_str2lacpmode(optarg, &lacp_mode))
				die("invalid LACP mode '%s'", optarg);
			break;
		case 'T':
			if (T_arg)
				die_optdup(option);

			T_arg = B_TRUE;
			if (!dladm_aggr_str2lacptimer(optarg, &lacp_timer))
				die("invalid LACP timer value '%s'", optarg);
			break;
		case 't':
			flags &= ~DLADM_OPT_PERSIST;
			break;
		case 'f':
			flags |= DLADM_OPT_FORCE;
			break;
		case 'R':
			altroot = optarg;
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	if (ndev + nlink == 0)
		usage();

	/* get key value or the aggregation name (required last argument) */
	if (optind != (argc-1))
		usage();

	if (!str2int(argv[optind], &key)) {
		if (strlcpy(name, argv[optind], MAXLINKNAMELEN) >=
		    MAXLINKNAMELEN) {
			die("link name too long '%s'", argv[optind]);
		}

		if (!dladm_valid_linkname(name))
			die("invalid link name '%s'", argv[optind]);
	} else {
		(void) snprintf(name, MAXLINKNAMELEN, "aggr%d", key);
	}

	if (altroot != NULL)
		altroot_cmd(altroot, argc, argv);

	for (n = 0; n < ndev; n++) {
		if (dladm_dev2linkid(devs[n], &port[n].lp_linkid) !=
		    DLADM_STATUS_OK) {
			die("invalid dev name '%s'", devs[n]);
		}
	}

	for (n = 0; n < nlink; n++) {
		if (dladm_name2info(links[n], &port[ndev + n].lp_linkid,
		    NULL, NULL, NULL) != DLADM_STATUS_OK) {
			die("invalid link name '%s'", links[n]);
		}
	}

	status = dladm_aggr_create(name, key, ndev + nlink, port, policy,
	    mac_addr_fixed, (const uchar_t *)mac_addr, lacp_mode,
	    lacp_timer, flags);
done:
	if (status != DLADM_STATUS_OK) {
		if (status == DLADM_STATUS_NONOTIF) {
			die_dlerr(status, "not all links have link up/down "
			    "detection; must use -f (see dladm(1M))\n");
		} else {
			die_dlerr(status, "create operation failed");
		}
	}
}

/*
 * arg is either the key or the aggr name. Validate it and convert it to
 * the linkid if altroot is NULL.
 */
static dladm_status_t
i_dladm_aggr_get_linkid(const char *altroot, const char *arg,
    datalink_id_t *linkidp, uint32_t flags)
{
	int		key = 0;
	char		*aggr = NULL;
	dladm_status_t	status;

	if (!str2int(arg, &key))
		aggr = (char *)arg;

	if (aggr == NULL && key == 0)
		return (DLADM_STATUS_LINKINVAL);

	if (altroot != NULL)
		return (DLADM_STATUS_OK);

	if (aggr != NULL) {
		status = dladm_name2info(aggr, linkidp, NULL, NULL, NULL);
	} else {
		status = dladm_key2linkid(key, linkidp, flags);
	}

	return (status);
}

static void
do_delete_aggr(int argc, char *argv[])
{
	char			option;
	char			*altroot = NULL;
	uint32_t		flags = DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST;
	dladm_status_t		status;
	datalink_id_t		linkid;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":R:t", lopts, NULL)) != -1) {
		switch (option) {
		case 't':
			flags &= ~DLADM_OPT_PERSIST;
			break;
		case 'R':
			altroot = optarg;
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	/* get key value or the aggregation name (required last argument) */
	if (optind != (argc-1))
		usage();

	status = i_dladm_aggr_get_linkid(altroot, argv[optind], &linkid, flags);
	if (status != DLADM_STATUS_OK)
		goto done;

	if (altroot != NULL)
		altroot_cmd(altroot, argc, argv);

	status = dladm_aggr_delete(linkid, flags);
done:
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "delete operation failed");
}

static void
do_add_aggr(int argc, char *argv[])
{
	char			option;
	uint_t			n, ndev, nlink;
	char			*altroot = NULL;
	uint32_t		flags = DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST;
	datalink_id_t		linkid;
	dladm_status_t		status;
	dladm_aggr_port_attr_db_t	port[MAXPORT];
	char			*devs[MAXPORT];
	char			*links[MAXPORT];

	ndev = nlink = opterr = 0;
	while ((option = getopt_long(argc, argv, ":d:l:R:tf", lopts,
	    NULL)) != -1) {
		switch (option) {
		case 'd':
			if (ndev + nlink >= MAXPORT)
				die("too many ports specified");

			devs[ndev++] = optarg;
			break;
		case 'l':
			if (ndev + nlink >= MAXPORT)
				die("too many ports specified");

			links[nlink++] = optarg;
			break;
		case 't':
			flags &= ~DLADM_OPT_PERSIST;
			break;
		case 'f':
			flags |= DLADM_OPT_FORCE;
			break;
		case 'R':
			altroot = optarg;
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	if (ndev + nlink == 0)
		usage();

	/* get key value or the aggregation name (required last argument) */
	if (optind != (argc-1))
		usage();

	if ((status = i_dladm_aggr_get_linkid(altroot, argv[optind], &linkid,
	    flags & (DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST))) !=
	    DLADM_STATUS_OK) {
		goto done;
	}

	if (altroot != NULL)
		altroot_cmd(altroot, argc, argv);

	for (n = 0; n < ndev; n++) {
		if (dladm_dev2linkid(devs[n], &(port[n].lp_linkid)) !=
		    DLADM_STATUS_OK) {
			die("invalid <dev> '%s'", devs[n]);
		}
	}

	for (n = 0; n < nlink; n++) {
		if (dladm_name2info(links[n], &port[n + ndev].lp_linkid,
		    NULL, NULL, NULL) != DLADM_STATUS_OK) {
			die("invalid <link> '%s'", links[n]);
		}
	}

	status = dladm_aggr_add(linkid, ndev + nlink, port, flags);
done:
	if (status != DLADM_STATUS_OK) {
		/*
		 * checking DLADM_STATUS_NOTSUP is a temporary workaround
		 * and should be removed once 6399681 is fixed.
		 */
		if (status == DLADM_STATUS_NOTSUP) {
			(void) fprintf(stderr,
			    gettext("%s: add operation failed: %s\n"),
			    progname,
			    gettext("link capabilities don't match"));
			exit(ENOTSUP);
		} else if (status == DLADM_STATUS_NONOTIF) {
			die_dlerr(status, "not all links have link up/down "
			    "detection; must use -f (see dladm(1M))\n");
		} else {
			die_dlerr(status, "add operation failed");
		}
	}
}

static void
do_remove_aggr(int argc, char *argv[])
{
	char				option;
	dladm_aggr_port_attr_db_t	port[MAXPORT];
	uint_t				n, ndev, nlink;
	char				*devs[MAXPORT];
	char				*links[MAXPORT];
	char				*altroot = NULL;
	uint32_t			flags;
	datalink_id_t			linkid;
	dladm_status_t			status;

	flags = DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST;
	ndev = nlink = opterr = 0;
	while ((option = getopt_long(argc, argv, ":d:l:R:t",
	    lopts, NULL)) != -1) {
		switch (option) {
		case 'd':
			if (ndev + nlink >= MAXPORT)
				die("too many ports specified");

			devs[ndev++] = optarg;
			break;
		case 'l':
			if (ndev + nlink >= MAXPORT)
				die("too many ports specified");

			links[nlink++] = optarg;
			break;
		case 't':
			flags &= ~DLADM_OPT_PERSIST;
			break;
		case 'R':
			altroot = optarg;
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	if (ndev + nlink == 0)
		usage();

	/* get key value or the aggregation name (required last argument) */
	if (optind != (argc-1))
		usage();

	status = i_dladm_aggr_get_linkid(altroot, argv[optind], &linkid, flags);
	if (status != DLADM_STATUS_OK)
		goto done;

	if (altroot != NULL)
		altroot_cmd(altroot, argc, argv);

	for (n = 0; n < ndev; n++) {
		if (dladm_dev2linkid(devs[n], &(port[n].lp_linkid)) !=
		    DLADM_STATUS_OK) {
			die("invalid <dev> '%s'", devs[n]);
		}
	}

	for (n = 0; n < nlink; n++) {
		if (dladm_name2info(links[n], &port[n + ndev].lp_linkid,
		    NULL, NULL, NULL) != DLADM_STATUS_OK) {
			die("invalid <link> '%s'", links[n]);
		}
	}

	status = dladm_aggr_remove(linkid, ndev + nlink, port, flags);
done:
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "remove operation failed");
}

static void
do_modify_aggr(int argc, char *argv[])
{
	char			option;
	uint32_t		policy = AGGR_POLICY_L4;
	aggr_lacp_mode_t	lacp_mode = AGGR_LACP_OFF;
	aggr_lacp_timer_t	lacp_timer = AGGR_LACP_TIMER_SHORT;
	uint8_t			mac_addr[ETHERADDRL];
	boolean_t		mac_addr_fixed = B_FALSE;
	uint8_t			modify_mask = 0;
	char			*altroot = NULL;
	uint32_t		flags = DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST;
	datalink_id_t		linkid;
	dladm_status_t		status;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":L:l:P:R:tu:T:", lopts,
	    NULL)) != -1) {
		switch (option) {
		case 'P':
			if (modify_mask & DLADM_AGGR_MODIFY_POLICY)
				die_optdup(option);

			modify_mask |= DLADM_AGGR_MODIFY_POLICY;

			if (!dladm_aggr_str2policy(optarg, &policy))
				die("invalid policy '%s'", optarg);
			break;
		case 'u':
			if (modify_mask & DLADM_AGGR_MODIFY_MAC)
				die_optdup(option);

			modify_mask |= DLADM_AGGR_MODIFY_MAC;

			if (!dladm_aggr_str2macaddr(optarg, &mac_addr_fixed,
			    mac_addr))
				die("invalid MAC address '%s'", optarg);
			break;
		case 'l':
		case 'L':
			if (modify_mask & DLADM_AGGR_MODIFY_LACP_MODE)
				die_optdup(option);

			modify_mask |= DLADM_AGGR_MODIFY_LACP_MODE;

			if (!dladm_aggr_str2lacpmode(optarg, &lacp_mode))
				die("invalid LACP mode '%s'", optarg);
			break;
		case 'T':
			if (modify_mask & DLADM_AGGR_MODIFY_LACP_TIMER)
				die_optdup(option);

			modify_mask |= DLADM_AGGR_MODIFY_LACP_TIMER;

			if (!dladm_aggr_str2lacptimer(optarg, &lacp_timer))
				die("invalid LACP timer value '%s'", optarg);
			break;
		case 't':
			flags &= ~DLADM_OPT_PERSIST;
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

	/* get key value or the aggregation name (required last argument) */
	if (optind != (argc-1))
		usage();

	status = i_dladm_aggr_get_linkid(altroot, argv[optind], &linkid, flags);
	if (status != DLADM_STATUS_OK)
		goto done;

	if (altroot != NULL)
		altroot_cmd(altroot, argc, argv);

	status = dladm_aggr_modify(linkid, modify_mask, policy, mac_addr_fixed,
	    (const uchar_t *)mac_addr, lacp_mode, lacp_timer, flags);

done:
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "modify operation failed");
}

static void
do_up_aggr(int argc, char *argv[])
{
	datalink_id_t	linkid = DATALINK_ALL_LINKID;
	dladm_status_t	status;

	/*
	 * get the key or the name of the aggregation (optional last argument)
	 */
	if (argc == 2) {
		if ((status = i_dladm_aggr_get_linkid(NULL, argv[1], &linkid,
		    DLADM_OPT_PERSIST)) != DLADM_STATUS_OK) {
			goto done;
		}
	} else if (argc > 2) {
		usage();
	}

	status = dladm_aggr_up(linkid);
done:
	if (status != DLADM_STATUS_OK) {
		if (argc == 2) {
			die_dlerr(status,
			    "could not bring up aggregation '%s'", argv[1]);
		} else {
			die_dlerr(status, "could not bring aggregations up");
		}
	}
}

static void
do_create_vlan(int argc, char *argv[])
{
	char		*link = NULL;
	char		drv[DLPI_LINKNAME_MAX];
	uint_t		ppa;
	datalink_id_t	linkid;
	int		vid = 0;
	char		option;
	uint32_t	flags = (DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST);
	char		*altroot = NULL;
	char		vlan[MAXLINKNAMELEN];
	dladm_status_t	status;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":tfl:v:",
	    lopts, NULL)) != -1) {
		switch (option) {
		case 'v':
			if (vid != 0)
				die_optdup(option);

			if (!str2int(optarg, &vid) || vid < 1 || vid > 4094)
				die("invalid VLAN identifier '%s'", optarg);

			break;
		case 'l':
			if (link != NULL)
				die_optdup(option);

			link = optarg;
			break;
		case 'f':
			flags |= DLADM_OPT_FORCE;
			break;
		case 't':
			flags &= ~DLADM_OPT_PERSIST;
			break;
		case 'R':
			altroot = optarg;
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	/* get vlan name if there is any */
	if ((vid == 0) || (link == NULL) || (argc - optind > 1))
		usage();

	if (optind == (argc - 1)) {
		if (strlcpy(vlan, argv[optind], MAXLINKNAMELEN) >=
		    MAXLINKNAMELEN) {
			die("vlan name too long '%s'", argv[optind]);
		}
	} else {
		if ((dlpi_parselink(link, drv, &ppa) != DLPI_SUCCESS) ||
		    (ppa >= 1000) ||
		    (dlpi_makelink(vlan, drv, vid * 1000 + ppa) !=
		    DLPI_SUCCESS)) {
			die("invalid link name '%s'", link);
		}
	}

	if (altroot != NULL)
		altroot_cmd(altroot, argc, argv);

	if (dladm_name2info(link, &linkid, NULL, NULL, NULL) !=
	    DLADM_STATUS_OK) {
		die("invalid link name '%s'", link);
	}

	if ((status = dladm_vlan_create(vlan, linkid, vid, flags)) !=
	    DLADM_STATUS_OK) {
		if (status == DLADM_STATUS_NOTSUP) {
			die_dlerr(status, "VLAN over '%s' may require lowered "
			    "MTU; must use -f (see dladm(1M))\n", link);
		} else {
			die_dlerr(status, "create operation failed");
		}
	}
}

static void
do_delete_vlan(int argc, char *argv[])
{
	char		option;
	uint32_t	flags = (DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST);
	char		*altroot = NULL;
	datalink_id_t	linkid;
	dladm_status_t	status;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":R:t", lopts, NULL)) != -1) {
		switch (option) {
		case 't':
			flags &= ~DLADM_OPT_PERSIST;
			break;
		case 'R':
			altroot = optarg;
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	/* get VLAN link name (required last argument) */
	if (optind != (argc - 1))
		usage();

	if (altroot != NULL)
		altroot_cmd(altroot, argc, argv);

	status = dladm_name2info(argv[optind], &linkid, NULL, NULL, NULL);
	if (status != DLADM_STATUS_OK)
		goto done;

	status = dladm_vlan_delete(linkid, flags);
done:
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "delete operation failed");
}

static void
do_up_vlan(int argc, char *argv[])
{
	datalink_id_t	linkid = DATALINK_ALL_LINKID;
	dladm_status_t	status;

	/*
	 * get the name of the VLAN (optional last argument)
	 */
	if (argc > 2)
		usage();

	if (argc == 2) {
		status = dladm_name2info(argv[1], &linkid, NULL, NULL, NULL);
		if (status != DLADM_STATUS_OK)
			goto done;
	}

	status = dladm_vlan_up(linkid);
done:
	if (status != DLADM_STATUS_OK) {
		if (argc == 2) {
			die_dlerr(status,
			    "could not bring up VLAN '%s'", argv[1]);
		} else {
			die_dlerr(status, "could not bring VLANs up");
		}
	}
}

static void
do_rename_link(int argc, char *argv[])
{
	char		option;
	char		*link1, *link2;
	char		*altroot = NULL;
	dladm_status_t	status;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":R:", lopts, NULL)) != -1) {
		switch (option) {
		case 'R':
			altroot = optarg;
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	/* get link1 and link2 name (required the last 2 arguments) */
	if (optind != (argc - 2))
		usage();

	if (altroot != NULL)
		altroot_cmd(altroot, argc, argv);

	link1 = argv[optind++];
	link2 = argv[optind];
	if ((status = dladm_rename_link(link1, link2)) != DLADM_STATUS_OK)
		die_dlerr(status, "rename operation failed");
}

static void
do_delete_phys(int argc, char *argv[])
{
	datalink_id_t	linkid = DATALINK_ALL_LINKID;
	dladm_status_t	status;

	/* get link name (required the last argument) */
	if (argc > 2)
		usage();

	if (argc == 2) {
		status = dladm_name2info(argv[1], &linkid, NULL, NULL, NULL);
		if (status != DLADM_STATUS_OK)
			die_dlerr(status, "cannot delete '%s'", argv[1]);
	}

	if ((status = dladm_phys_delete(linkid)) != DLADM_STATUS_OK) {
		if (argc == 2)
			die_dlerr(status, "cannot delete '%s'", argv[1]);
		else
			die_dlerr(status, "delete operation failed");
	}
}

/*ARGSUSED*/
static int
i_dladm_walk_linkmap(datalink_id_t linkid, void *arg)
{
	char			name[MAXLINKNAMELEN];
	char			mediabuf[DLADM_STRSIZE];
	char			classbuf[DLADM_STRSIZE];
	datalink_class_t	class;
	uint32_t		media;
	uint32_t		flags;

	if (dladm_datalink_id2info(linkid, &flags, &class, &media, name,
	    MAXLINKNAMELEN) == DLADM_STATUS_OK) {
		(void) dladm_class2str(class, classbuf);
		(void) dladm_media2str(media, mediabuf);
		(void) printf("%-12s%8d  %-12s%-20s %6d\n", name,
		    linkid, classbuf, mediabuf, flags);
	}
	return (DLADM_WALK_CONTINUE);
}

/*ARGSUSED*/
static void
do_show_linkmap(int argc, char *argv[])
{
	if (argc != 1)
		die("invalid arguments");

	(void) printf("%-12s%8s  %-12s%-20s %6s\n", "NAME", "LINKID",
	    "CLASS", "MEDIA", "FLAGS");
	(void) dladm_walk_datalink_id(i_dladm_walk_linkmap, NULL,
	    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE,
	    DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST);
}

/*
 * Delete inactive physical links.
 */
/*ARGSUSED*/
static int
purge_phys(datalink_id_t linkid, void *arg)
{
	datalink_class_t	class;
	uint32_t		flags;

	if (dladm_datalink_id2info(linkid, &flags, &class, NULL,
	    NULL, 0) != DLADM_STATUS_OK) {
		return (DLADM_WALK_CONTINUE);
	}

	if (class == DATALINK_CLASS_PHYS && !(flags & DLADM_OPT_ACTIVE))
		(void) dladm_phys_delete(linkid);

	return (DLADM_WALK_CONTINUE);
}

/*ARGSUSED*/
static void
do_init_phys(int argc, char *argv[])
{
	di_node_t devtree;

	if (argc > 1)
		usage();

	/*
	 * Force all the devices to attach, therefore all the network physical
	 * devices can be known to the dlmgmtd daemon.
	 */
	if ((devtree = di_init("/", DINFOFORCE | DINFOSUBTREE)) != DI_NODE_NIL)
		di_fini(devtree);

	(void) dladm_walk_datalink_id(purge_phys, NULL,
	    DATALINK_CLASS_PHYS, DATALINK_ANY_MEDIATYPE, DLADM_OPT_PERSIST);
}

static void
print_link_head(show_state_t *state)
{
	if (state->ls_donefirst)
		return;
	state->ls_donefirst = B_TRUE;

	if (state->ls_parseable)
		return;

	if (state->ls_flags & DLADM_OPT_ACTIVE) {
		(void) printf("%-12s%-8s%6s  %-9s%s\n", "LINK", "CLASS", "MTU",
		    "STATE", "OVER");
	} else {
		(void) printf("%-12s%-8s%s\n", "LINK", "CLASS", "OVER");
	}
}

/*
 * Print the active topology information.
 */
static dladm_status_t
print_link_topology(show_state_t *state, datalink_id_t linkid,
    datalink_class_t class, char **pptr, char *lim)
{
	char		*fmt;
	char		over[MAXLINKNAMELEN];
	uint32_t	flags = state->ls_flags;
	dladm_status_t	status = DLADM_STATUS_OK;

	if (state->ls_parseable)
		fmt = "OVER=\"%s";
	else
		fmt = "%s";

	if (class == DATALINK_CLASS_VLAN) {
		dladm_vlan_attr_t	vinfo;

		status = dladm_vlan_info(linkid, &vinfo, flags);
		if (status != DLADM_STATUS_OK)
			goto done;
		status = dladm_datalink_id2info(vinfo.dv_linkid, NULL, NULL,
		    NULL, over, sizeof (over));
		if (status != DLADM_STATUS_OK)
			goto done;

		/*LINTED: E_SEC_PRINTF_VAR_FMT*/
		*pptr += snprintf(*pptr, BUFLEN(lim, *pptr), fmt, over);
	} else if (class == DATALINK_CLASS_AGGR) {
		dladm_aggr_grp_attr_t	ginfo;
		int			i;

		status = dladm_aggr_info(linkid, &ginfo, flags);
		if (status != DLADM_STATUS_OK)
			goto done;

		if (ginfo.lg_nports == 0) {
			status = DLADM_STATUS_BADVAL;
			goto done;
		}
		for (i = 0; i < ginfo.lg_nports; i++) {
			status = dladm_datalink_id2info(
			    ginfo.lg_ports[i].lp_linkid, NULL, NULL, NULL, over,
			    sizeof (over));
			if (status != DLADM_STATUS_OK) {
				free(ginfo.lg_ports);
				goto done;
			}
			/*LINTED: E_SEC_PRINTF_VAR_FMT*/
			*pptr += snprintf(*pptr, BUFLEN(lim, *pptr), fmt, over);
			fmt = " %s";
		}
		free(ginfo.lg_ports);
	} else if (class == DATALINK_CLASS_VNIC) {
		dladm_vnic_attr_sys_t	vinfo;

		if ((status = dladm_vnic_info(linkid, &vinfo, flags)) !=
		    DLADM_STATUS_OK || (status = dladm_datalink_id2info(
		    vinfo.va_link_id, NULL, NULL, NULL, over,
		    sizeof (over))) != DLADM_STATUS_OK) {
			goto done;
		}

		/*LINTED: E_SEC_PRINTF_VAR_FMT*/
		*pptr += snprintf(*pptr, BUFLEN(lim, *pptr), fmt, over);
	} else {
		/*LINTED: E_SEC_PRINTF_VAR_FMT*/
		*pptr += snprintf(*pptr, BUFLEN(lim, *pptr), fmt,
		    state->ls_parseable ? "" : "--");
	}
	if (state->ls_parseable)
		*pptr += snprintf(*pptr, BUFLEN(lim, *pptr), "\"\n");
	else
		*pptr += snprintf(*pptr, BUFLEN(lim, *pptr), "\n");

done:
	return (status);
}

static dladm_status_t
print_link(show_state_t *state, datalink_id_t linkid, char **pptr, char *lim)
{
	char			link[MAXLINKNAMELEN];
	char			buf[DLADM_STRSIZE];
	datalink_class_t	class;
	uint_t			mtu;
	char			*fmt;
	uint32_t		flags;
	dladm_status_t		status;

	if ((status = dladm_datalink_id2info(linkid, &flags, &class, NULL,
	    link, sizeof (link))) != DLADM_STATUS_OK) {
		goto done;
	}

	if (!(state->ls_flags & flags)) {
		status = DLADM_STATUS_NOTFOUND;
		goto done;
	}

	if (state->ls_flags == DLADM_OPT_ACTIVE) {
		dladm_attr_t	dlattr;

		if (class == DATALINK_CLASS_PHYS) {
			dladm_phys_attr_t	dpa;
			dlpi_handle_t		dh;
			dlpi_info_t		dlinfo;

			if ((status = dladm_phys_info(linkid, &dpa,
			    DLADM_OPT_ACTIVE)) != DLADM_STATUS_OK) {
				goto done;
			}

			if (!dpa.dp_novanity)
				goto link_mtu;

			/*
			 * This is a physical link that does not have
			 * vanity naming support.
			 */
			if (dlpi_open(dpa.dp_dev, &dh, DLPI_DEVONLY) !=
			    DLPI_SUCCESS) {
				status = DLADM_STATUS_NOTFOUND;
				goto done;
			}

			if (dlpi_info(dh, &dlinfo, 0) != DLPI_SUCCESS) {
				dlpi_close(dh);
				status = DLADM_STATUS_BADARG;
				goto done;
			}

			dlpi_close(dh);
			mtu = dlinfo.di_max_sdu;
		} else {
link_mtu:
			status = dladm_info(linkid, &dlattr);
			if (status != DLADM_STATUS_OK)
				goto done;
			mtu = dlattr.da_max_sdu;
		}
	}

	if (state->ls_flags == DLADM_OPT_ACTIVE) {
		if (state->ls_parseable)
			fmt = "LINK=\"%s\" CLASS=\"%s\" MTU=\"%d\" ";
		else
			fmt = "%-12s%-8s%6d  ";
	} else {
		if (state->ls_parseable)
			fmt = "LINK=\"%s\" CLASS=\"%s\" ";
		else
			fmt = "%-12s%-8s";
	}

	(void) dladm_class2str(class, buf);
	if (state->ls_flags == DLADM_OPT_ACTIVE) {
		/*LINTED: E_SEC_PRINTF_VAR_FMT*/
		*pptr += snprintf(*pptr, BUFLEN(lim, *pptr), fmt, link,
		    buf, mtu);
	} else {
		/*LINTED: E_SEC_PRINTF_VAR_FMT*/
		*pptr += snprintf(*pptr, BUFLEN(lim, *pptr), fmt, link, buf);
	}

	(void) get_linkstate(link, B_TRUE, buf);
	if (state->ls_flags == DLADM_OPT_ACTIVE) {
		if (state->ls_parseable) {
			*pptr += snprintf(*pptr, BUFLEN(lim, *pptr),
			    "STATE=\"%s\" ", buf);
		} else {
			*pptr += snprintf(*pptr, BUFLEN(lim, *pptr),
			    "%-9s", buf);
		}
	}

	status = print_link_topology(state, linkid, class, pptr, lim);
	if (status != DLADM_STATUS_OK)
		goto done;

done:
	return (status);
}

static int
show_link(datalink_id_t linkid, void *arg)
{
	show_state_t	*state = arg;
	dladm_status_t	status;
	char		buf[MAXLINELEN];
	char		*ptr = buf, *lim = buf + MAXLINELEN;

	status = print_link(state, linkid, &ptr, lim);
	if (status != DLADM_STATUS_OK)
		goto done;
	print_link_head(state);
	(void) printf("%s", buf);

done:
	state->ls_status = status;
	return (DLADM_WALK_CONTINUE);
}

static int
show_link_stats(datalink_id_t linkid, void *arg)
{
	char link[MAXLINKNAMELEN];
	datalink_class_t class;
	show_state_t *state = arg;
	pktsum_t stats, diff_stats;
	dladm_phys_attr_t dpa;

	if (state->ls_firstonly) {
		if (state->ls_donefirst)
			return (DLADM_WALK_CONTINUE);
		state->ls_donefirst = B_TRUE;
	} else {
		bzero(&state->ls_prevstats, sizeof (state->ls_prevstats));
	}

	if (dladm_datalink_id2info(linkid, NULL, &class, NULL, link,
	    sizeof (link)) != DLADM_STATUS_OK) {
		return (DLADM_WALK_CONTINUE);
	}

	if (class == DATALINK_CLASS_PHYS) {
		if (dladm_phys_info(linkid, &dpa, DLADM_OPT_ACTIVE) !=
		    DLADM_STATUS_OK) {
			return (DLADM_WALK_CONTINUE);
		}
		if (dpa.dp_novanity)
			get_mac_stats(dpa.dp_dev, &stats);
		else
			get_link_stats(link, &stats);
	} else {
		get_link_stats(link, &stats);
	}
	stats_diff(&diff_stats, &stats, &state->ls_prevstats);

	(void) printf("%-12s", link);
	(void) printf("%-10llu", diff_stats.ipackets);
	(void) printf("%-12llu", diff_stats.rbytes);
	(void) printf("%-8u", diff_stats.ierrors);
	(void) printf("%-10llu", diff_stats.opackets);
	(void) printf("%-12llu", diff_stats.obytes);
	(void) printf("%-8u\n", diff_stats.oerrors);

	state->ls_prevstats = stats;
	return (DLADM_WALK_CONTINUE);
}

static void
print_port_stat(const char *port, pktsum_t *old_stats, pktsum_t *port_stats,
    pktsum_t *tot_stats, char **pptr, char *lim)
{
	pktsum_t	diff_stats;

	stats_diff(&diff_stats, port_stats, old_stats);
	*pptr += snprintf(*pptr, BUFLEN(lim, *pptr),
	    "%-12s%-10s%8llu  %8llu  %8llu  %8llu  ", "", port,
	    diff_stats.ipackets, diff_stats.rbytes, diff_stats.opackets,
	    diff_stats.obytes);

	if (tot_stats->ipackets == 0) {
		*pptr += snprintf(*pptr, BUFLEN(lim, *pptr), "%8s ", "--");
	} else {
		*pptr += snprintf(*pptr, BUFLEN(lim, *pptr), "%7.1f%% ",
		    (double)diff_stats.ipackets/
		    (double)tot_stats->ipackets * 100);
	}

	if (tot_stats->opackets == 0) {
		*pptr += snprintf(*pptr, BUFLEN(lim, *pptr), "%8s\n", "--");
	} else {
		*pptr += snprintf(*pptr, BUFLEN(lim, *pptr), "%7.1f%%\n",
		    (double)diff_stats.opackets/
		    (double)tot_stats->opackets * 100);
	}

	*old_stats = *port_stats;
}

static void
print_aggr_head(show_grp_state_t *state)
{
	if (state->gs_donefirst)
		return;
	state->gs_donefirst = B_TRUE;

	if (state->gs_parseable)
		return;

	if (state->gs_lacp) {
		(void) printf("%-12s%-12s%-13s%-5s%-5s%-5s%-10s%s\n", "LINK",
		    "PORT", "AGGREGATABLE", "SYNC", "COLL", "DIST",
		    "DEFAULTED", "EXPIRED");
	} else if (state->gs_extended) {
		(void) printf("%-12s%-14s%6s  %-9s%-9s%-18s%s\n", "LINK",
		    "PORT", "SPEED", "DUPLEX", "STATE", "ADDRESS", "PORTSTATE");
	} else if (!state->gs_stats) {
		(void) printf("%-12s%-8s%-24s%-13s%-11s%s\n", "LINK", "POLICY",
		    "ADDRPOLICY", "LACPACTIVITY", "LACPTIMER", "FLAGS");
	}
}

static dladm_status_t
print_aggr_info(show_grp_state_t *state, const char *link,
    dladm_aggr_grp_attr_t *ginfop, char **pptr, char *lim)
{
	char			buf[DLADM_STRSIZE];
	char			*fmt;
	char			addr_str[ETHERADDRL * 3];
	char			str[ETHERADDRL * 3 + 2];

	if (state->gs_parseable)
		fmt = "LINK=\"%s\" POLICY=\"%s\" ADDRPOLICY=\"%s%s\" ";
	else
		fmt = "%-12s%-8s%-6s%-18s";

	if (ginfop->lg_mac_fixed) {
		(void) dladm_aggr_macaddr2str(ginfop->lg_mac, addr_str);
		(void) snprintf(str, ETHERADDRL * 3 + 3, " (%s)", addr_str);
	} else {
		str[0] = '\0';
	}

	/*LINTED: E_SEC_PRINTF_VAR_FMT*/
	*pptr += snprintf(*pptr, BUFLEN(lim, *pptr), fmt, link,
	    dladm_aggr_policy2str(ginfop->lg_policy, buf),
	    ginfop->lg_mac_fixed ? "fixed" : "auto", str);

	(void) dladm_aggr_lacpmode2str(ginfop->lg_lacp_mode, buf);
	if (state->gs_parseable) {
		*pptr += snprintf(*pptr, BUFLEN(lim, *pptr),
		    "LACPACTIVITY=\"%s\" ", buf);
	} else {
		*pptr += snprintf(*pptr, BUFLEN(lim, *pptr), "%-13s", buf);
	}

	(void) dladm_aggr_lacptimer2str(ginfop->lg_lacp_timer, buf);
	if (state->gs_parseable) {
		*pptr += snprintf(*pptr, BUFLEN(lim, *pptr),
		    "LACPTIMER=\"%s\" FLAGS=\"%c----\"\n", buf,
		    ginfop->lg_force ? 'f' : '-');
	} else {
		*pptr += snprintf(*pptr, BUFLEN(lim, *pptr),
		    "%-11s%c----\n", buf, ginfop->lg_force ? 'f' : '-');
	}

	return (DLADM_STATUS_OK);
}

static dladm_status_t
print_aggr_extended(show_grp_state_t *state, const char *link,
    dladm_aggr_grp_attr_t *ginfop, char **pptr, char *lim)
{
	char			addr_str[ETHERADDRL * 3];
	char			port[MAXLINKNAMELEN];
	dladm_phys_attr_t	dpa;
	char			buf[DLADM_STRSIZE];
	char			*fmt;
	int			i;
	dladm_status_t		status;

	if (state->gs_parseable)
		fmt = "LINK=\"%s\" PORT=\"%s\" SPEED=\"%uMb\" DUPLEX=\"%s\" ";
	else
		fmt = "%-12s%-14s%4uMb  %-9s";

	(void) dladm_aggr_macaddr2str(ginfop->lg_mac, addr_str);

	/*LINTED: E_SEC_PRINTF_VAR_FMT*/
	*pptr += snprintf(*pptr, BUFLEN(lim, *pptr), fmt, link,
	    state->gs_parseable ? "" : "--",
	    (uint_t)((get_ifspeed(link, B_TRUE)) / 1000000ull),
	    get_linkduplex(link, B_TRUE, buf));

	(void) get_linkstate(link, B_TRUE, buf);
	if (state->gs_parseable) {
		*pptr += snprintf(*pptr, BUFLEN(lim, *pptr),
		    "STATE=\"%s\" ADDRESS=\"%s\" PORTSTATE=\"%s\"\n", buf,
		    addr_str, "");
	} else {
		*pptr += snprintf(*pptr, BUFLEN(lim, *pptr), "%-9s%-18s%s\n",
		    buf, addr_str, "--");
	}

	for (i = 0; i < ginfop->lg_nports; i++) {
		dladm_aggr_port_attr_t	*portp = &(ginfop->lg_ports[i]);
		const char		*tmp;

		if ((status = dladm_datalink_id2info(portp->lp_linkid, NULL,
		    NULL, NULL, port, sizeof (port))) != DLADM_STATUS_OK) {
			goto done;
		}

		if ((status = dladm_phys_info(portp->lp_linkid, &dpa,
		    DLADM_OPT_ACTIVE)) != DLADM_STATUS_OK) {
			goto done;
		}

		(void) dladm_aggr_macaddr2str(portp->lp_mac, addr_str);

		if (state->gs_parseable)
			tmp = link;
		else
			tmp = "";

		/*LINTED: E_SEC_PRINTF_VAR_FMT*/
		*pptr += snprintf(*pptr, BUFLEN(lim, *pptr), fmt, tmp, port,
		    (uint_t)((get_ifspeed(dpa.dp_dev, B_FALSE)) / 1000000ull),
		    get_linkduplex(dpa.dp_dev, B_FALSE, buf));

		(void) get_linkstate(dpa.dp_dev, B_FALSE, buf);
		if (state->gs_parseable) {
			*pptr += snprintf(*pptr, BUFLEN(lim, *pptr),
			    "STATE=\"%s\" ADDRESS=\"%s\" ", buf, addr_str);
		} else {
			*pptr += snprintf(*pptr, BUFLEN(lim, *pptr),
			    "%-9s%-18s", buf, addr_str);
		}

		(void) dladm_aggr_portstate2str(
		    ginfop->lg_ports[i].lp_state, buf);
		if (state->gs_parseable) {
			*pptr += snprintf(*pptr, BUFLEN(lim, *pptr),
			    "PORTSTATE=\"%s\"\n", buf);
		} else {
			*pptr += snprintf(*pptr, BUFLEN(lim, *pptr),
			    "%s\n", buf);
		}
	}

	status = DLADM_STATUS_OK;
done:
	return (status);
}

static dladm_status_t
print_aggr_lacp(show_grp_state_t *state, const char *link,
    dladm_aggr_grp_attr_t *ginfop, char **pptr, char *lim)
{
	char		port[MAXLINKNAMELEN];
	char		*fmt;
	const char	*dlink = link;
	int		i;
	dladm_status_t	status;

	if (state->gs_parseable) {
		fmt = "LINK=\"%s\" PORT=\"%s\" AGGREGATABLE=\"%s\" SYNC=\"%s\" "
		    "COLL=\"%s\" DIST=\"%s\" DEFAULTED=\"%s\" EXPITED=\"%s\"\n";
	} else {
		fmt = "%-12s%-12s%-13s%-5s%-5s%-5s%-10s%s\n";
	}

	for (i = 0; i < ginfop->lg_nports; i++) {
		aggr_lacp_state_t *lstate;

		status = dladm_datalink_id2info(ginfop->lg_ports[i].lp_linkid,
		    NULL, NULL, NULL, port, sizeof (port));
		if (status != DLADM_STATUS_OK)
			goto done;

		/*
		 * Only display link for the first port.
		 */
		if ((i > 0) && !(state->gs_parseable))
			dlink = "";
		lstate = &(ginfop->lg_ports[i].lp_lacp_state);

		/*LINTED: E_SEC_PRINTF_VAR_FMT*/
		*pptr += snprintf(*pptr, BUFLEN(lim, *pptr), fmt, dlink, port,
		    lstate->bit.aggregation ? "yes" : "no",
		    lstate->bit.sync ? "yes" : "no",
		    lstate->bit.collecting ? "yes" : "no",
		    lstate->bit.distributing ? "yes" : "no",
		    lstate->bit.defaulted ? "yes" : "no",
		    lstate->bit.expired ? "yes" : "no");
	}

	status = DLADM_STATUS_OK;
done:
	return (status);
}

static dladm_status_t
print_aggr_stats(show_grp_state_t *state, const char *link,
    dladm_aggr_grp_attr_t *ginfop, char **pptr, char *lim)
{
	char			port[MAXLINKNAMELEN];
	dladm_phys_attr_t	dpa;
	dladm_aggr_port_attr_t	*portp;
	pktsum_t		pktsumtot, port_stat;
	dladm_status_t		status;
	int			i;

	if (state->gs_firstonly) {
		if (state->gs_donefirst)
			return (DLADM_WALK_CONTINUE);
		state->gs_donefirst = B_TRUE;
	} else {
		bzero(&state->gs_prevstats, sizeof (state->gs_prevstats));
	}

	/* sum the ports statistics */
	bzero(&pktsumtot, sizeof (pktsumtot));

	for (i = 0; i < ginfop->lg_nports; i++) {

		portp = &(ginfop->lg_ports[i]);
		if ((status = dladm_phys_info(portp->lp_linkid, &dpa,
		    DLADM_OPT_ACTIVE)) != DLADM_STATUS_OK) {
			goto done;
		}

		get_mac_stats(dpa.dp_dev, &port_stat);
		stats_total(&pktsumtot, &port_stat, &state->gs_prevstats[i]);
	}

	*pptr += snprintf(*pptr, BUFLEN(lim, *pptr),
	    "%-12s%-10s%8llu  %8llu  %8llu  %8llu  %8s %8s\n", link, "--",
	    pktsumtot.ipackets, pktsumtot.rbytes, pktsumtot.opackets,
	    pktsumtot.obytes, "--", "--");

	for (i = 0; i < ginfop->lg_nports; i++) {
		portp = &(ginfop->lg_ports[i]);

		if ((status = dladm_phys_info(portp->lp_linkid, &dpa,
		    DLADM_OPT_ACTIVE)) != DLADM_STATUS_OK) {
			goto done;
		}

		get_mac_stats(dpa.dp_dev, &port_stat);

		if ((status = dladm_datalink_id2info(portp->lp_linkid, NULL,
		    NULL, NULL, port, sizeof (port))) != DLADM_STATUS_OK) {
			goto done;
		}

		print_port_stat(port, &state->gs_prevstats[i], &port_stat,
		    &pktsumtot, pptr, lim);
	}

	status = DLADM_STATUS_OK;
done:
	return (status);
}

static dladm_status_t
print_aggr(show_grp_state_t *state, datalink_id_t linkid, char **pptr,
    char *lim)
{
	char			link[MAXLINKNAMELEN];
	dladm_aggr_grp_attr_t	ginfo;
	uint32_t		flags;
	dladm_status_t		status;

	if ((status = dladm_datalink_id2info(linkid, &flags, NULL, NULL, link,
	    sizeof (link))) != DLADM_STATUS_OK) {
		return (status);
	}

	if (!(state->gs_flags & flags))
		return (DLADM_STATUS_NOTFOUND);

	status = dladm_aggr_info(linkid, &ginfo, state->gs_flags);
	if (status != DLADM_STATUS_OK)
		return (status);

	if (state->gs_lacp)
		status = print_aggr_lacp(state, link, &ginfo, pptr, lim);
	else if (state->gs_extended)
		status = print_aggr_extended(state, link, &ginfo, pptr, lim);
	else if (state->gs_stats)
		status = print_aggr_stats(state, link, &ginfo, pptr, lim);
	else
		status = print_aggr_info(state, link, &ginfo, pptr, lim);

done:
	free(ginfo.lg_ports);
	return (status);
}

static int
show_aggr(datalink_id_t linkid, void *arg)
{
	show_grp_state_t	*state = arg;
	dladm_status_t		status;
	char			buf[MAXLINELEN];
	char			*ptr = buf, *lim = buf + MAXLINELEN;

	status = print_aggr(state, linkid, &ptr, lim);
	if (status != DLADM_STATUS_OK)
		goto done;
	print_aggr_head(state);
	(void) printf("%s", buf);

done:
	state->gs_status = status;
	return (DLADM_WALK_CONTINUE);
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

static int
show_dev(const char *dev, void *arg)
{
	show_state_t	*state = arg;
	char		buf[DLADM_STRSIZE];
	char		*fmt;

	if (state->ls_parseable)
		fmt = "DEV=\"%s\" STATE=\"%s\" SPEED=\"%u\" ";
	else
		fmt = "%-12s%-10s%4uMb  ";

	if (!state->ls_donefirst) {
		if (!state->ls_parseable) {
			(void) printf("%-12s%-10s%6s  %s\n", "DEV", "STATE",
			    "SPEED", "DUPLEX");
		}
		state->ls_donefirst = B_TRUE;
	}

	/*LINTED: E_SEC_PRINTF_VAR_FMT*/
	(void) printf(fmt, dev, get_linkstate(dev, B_FALSE, buf),
	    (uint_t)(get_ifspeed(dev, B_FALSE) / 1000000ull));

	(void) get_linkduplex(dev, B_FALSE, buf);
	if (state->ls_parseable)
		(void) printf("DUPLEX=\"%s\"\n", buf);
	else
		(void) printf("%s\n", buf);

	return (DLADM_WALK_CONTINUE);
}

static int
show_dev_stats(const char *dev, void *arg)
{
	show_state_t *state = arg;
	pktsum_t stats, diff_stats;

	if (state->ls_firstonly) {
		if (state->ls_donefirst)
			return (DLADM_WALK_CONTINUE);
		state->ls_donefirst = B_TRUE;
	} else {
		bzero(&state->ls_prevstats, sizeof (state->ls_prevstats));
	}

	get_mac_stats(dev, &stats);
	stats_diff(&diff_stats, &stats, &state->ls_prevstats);

	(void) printf("%-12s", dev);
	(void) printf("%-10llu", diff_stats.ipackets);
	(void) printf("%-12llu", diff_stats.rbytes);
	(void) printf("%-8u", diff_stats.ierrors);
	(void) printf("%-10llu", diff_stats.opackets);
	(void) printf("%-12llu", diff_stats.obytes);
	(void) printf("%-8u\n", diff_stats.oerrors);

	state->ls_prevstats = stats;
	return (DLADM_WALK_CONTINUE);
}

static void
do_show_link(int argc, char *argv[])
{
	int		option;
	boolean_t	s_arg = B_FALSE;
	boolean_t	i_arg = B_FALSE;
	uint32_t	flags = DLADM_OPT_ACTIVE;
	boolean_t	p_arg = B_FALSE;
	datalink_id_t	linkid = DATALINK_ALL_LINKID;
	int		interval = 0;
	show_state_t	state;
	dladm_status_t	status;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":pPsi:",
	    show_lopts, NULL)) != -1) {
		switch (option) {
		case 'p':
			if (p_arg)
				die_optdup(option);

			p_arg = B_TRUE;
			break;
		case 's':
			if (s_arg)
				die_optdup(option);

			s_arg = B_TRUE;
			break;
		case 'P':
			if (flags != DLADM_OPT_ACTIVE)
				die_optdup(option);

			flags = DLADM_OPT_PERSIST;
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

	if (s_arg && (p_arg || flags != DLADM_OPT_ACTIVE))
		die("the option -%c cannot be used with -s", p_arg ? 'p' : 'P');

	/* get link name (optional last argument) */
	if (optind == (argc-1)) {
		uint32_t	f;

		if ((status = dladm_name2info(argv[optind], &linkid, &f,
		    NULL, NULL)) != DLADM_STATUS_OK) {
			die_dlerr(status, "link %s is not valid", argv[optind]);
		}

		if (!(f & flags)) {
			die_dlerr(DLADM_STATUS_BADARG, "link %s is %s",
			    argv[optind], flags == DLADM_OPT_PERSIST ?
			    "a temporary link" : "temporarily removed");
		}
	} else if (optind != argc) {
		usage();
	}

	if (s_arg) {
		link_stats(linkid, interval);
		return;
	}

	state.ls_parseable = p_arg;
	state.ls_flags = flags;
	state.ls_donefirst = B_FALSE;
	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(show_link, &state,
		    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE, flags);
	} else {
		(void) show_link(linkid, &state);
		if (state.ls_status != DLADM_STATUS_OK) {
			die_dlerr(state.ls_status, "failed to show link %s",
			    argv[optind]);
		}
	}
}

static void
do_show_aggr(int argc, char *argv[])
{
	boolean_t		L_arg = B_FALSE;
	boolean_t		s_arg = B_FALSE;
	boolean_t		i_arg = B_FALSE;
	boolean_t		p_arg = B_FALSE;
	boolean_t		x_arg = B_FALSE;
	show_grp_state_t	state;
	uint32_t		flags = DLADM_OPT_ACTIVE;
	datalink_id_t		linkid = DATALINK_ALL_LINKID;
	int			option;
	int			interval = 0;
	int			key;
	dladm_status_t		status;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":LpPxsi:",
	    show_lopts, NULL)) != -1) {
		switch (option) {
		case 'L':
			if (L_arg)
				die_optdup(option);

			L_arg = B_TRUE;
			break;
		case 'p':
			if (p_arg)
				die_optdup(option);

			p_arg = B_TRUE;
			break;
		case 'x':
			if (x_arg)
				die_optdup(option);

			x_arg = B_TRUE;
			break;
		case 'P':
			if (flags != DLADM_OPT_ACTIVE)
				die_optdup(option);

			flags = DLADM_OPT_PERSIST;
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

	if (s_arg && (L_arg || p_arg || x_arg || flags != DLADM_OPT_ACTIVE)) {
		die("the option -%c cannot be used with -s",
		    L_arg ? 'L' : (p_arg ? 'p' : (x_arg ? 'x' : 'P')));
	}

	if (L_arg && flags != DLADM_OPT_ACTIVE)
		die("the option -P cannot be used with -L");

	if (x_arg && (L_arg || flags != DLADM_OPT_ACTIVE))
		die("the option -%c cannot be used with -x", L_arg ? 'L' : 'P');

	/* get aggregation key or aggrname (optional last argument) */
	if (optind == (argc-1)) {
		if (!str2int(argv[optind], &key)) {
			status = dladm_name2info(argv[optind], &linkid, NULL,
			    NULL, NULL);
		} else {
			status = dladm_key2linkid((uint16_t)key,
			    &linkid, DLADM_OPT_ACTIVE);
		}

		if (status != DLADM_STATUS_OK)
			die("non-existent aggregation '%s'", argv[optind]);

	} else if (optind != argc) {
		usage();
	}

	bzero(&state, sizeof (state));
	state.gs_lacp = L_arg;
	state.gs_stats = s_arg;
	state.gs_flags = flags;
	state.gs_parseable = p_arg;
	state.gs_extended = x_arg;

	if (s_arg) {
		aggr_stats(linkid, &state, interval);
		return;
	}

	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(show_aggr, &state,
		    DATALINK_CLASS_AGGR, DATALINK_ANY_MEDIATYPE, flags);
	} else {
		(void) show_aggr(linkid, &state);
		if (state.gs_status != DLADM_STATUS_OK) {
			die_dlerr(state.gs_status, "failed to show aggr %s",
			    argv[optind]);
		}
	}
}

static void
do_show_dev(int argc, char *argv[])
{
	int		option;
	char		*dev = NULL;
	boolean_t	s_arg = B_FALSE;
	boolean_t	i_arg = B_FALSE;
	boolean_t	p_arg = B_FALSE;
	datalink_id_t	linkid;
	int		interval = 0;
	show_state_t	state;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":psi:",
	    show_lopts, NULL)) != -1) {
		switch (option) {
		case 'p':
			if (p_arg)
				die_optdup(option);

			p_arg = B_TRUE;
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

	if (s_arg && p_arg)
		die("the option -s cannot be used with -p");

	/* get dev name (optional last argument) */
	if (optind == (argc-1)) {
		uint32_t flags;

		dev = argv[optind];

		if (dladm_dev2linkid(dev, &linkid) != DLADM_STATUS_OK)
			die("invalid device %s", dev);

		if ((dladm_datalink_id2info(linkid, &flags, NULL, NULL,
		    NULL, 0) != DLADM_STATUS_OK) ||
		    !(flags & DLADM_OPT_ACTIVE)) {
			die("device %s has been removed", dev);
		}
	} else if (optind != argc) {
		usage();
	}

	if (s_arg) {
		dev_stats(dev, interval);
		return;
	}

	state.ls_donefirst = B_FALSE;
	state.ls_parseable = p_arg;
	if (dev == NULL) {
		(void) dladm_mac_walk(show_dev, &state);
	} else {
		(void) show_dev(dev, &state);
	}
}

static void
print_phys_head(show_state_t *state)
{
	if (state->ls_donefirst)
		return;
	state->ls_donefirst = B_TRUE;

	if (state->ls_parseable)
		return;

	if (state->ls_flags == DLADM_OPT_ACTIVE) {
		(void) printf("%-12s%-20s%-10s%6s  %-9s%s\n", "LINK",
		    "MEDIA", "STATE", "SPEED", "DUPLEX", "DEVICE");
	} else {
		(void) printf("%-12s%-12s%-20s%s\n", "LINK", "DEVICE",
		    "MEDIA", "FLAGS");
	}
}

static dladm_status_t
print_phys(show_state_t *state, datalink_id_t linkid, char **pptr, char *lim)
{
	char			link[MAXLINKNAMELEN];
	dladm_phys_attr_t	dpa;
	char			buf[DLADM_STRSIZE];
	uint32_t		flags;
	datalink_class_t	class;
	uint32_t		media;
	dladm_status_t		status;

	if ((status = dladm_datalink_id2info(linkid, &flags, &class, &media,
	    link, sizeof (link))) != DLADM_STATUS_OK) {
		goto done;
	}

	if (class != DATALINK_CLASS_PHYS) {
		status = DLADM_STATUS_BADARG;
		goto done;
	}

	if (!(state->ls_flags & flags)) {
		status = DLADM_STATUS_NOTFOUND;
		goto done;
	}

	status = dladm_phys_info(linkid, &dpa, state->ls_flags);
	if (status != DLADM_STATUS_OK)
		goto done;

	if (state->ls_flags == DLADM_OPT_ACTIVE) {
		char		name[MAXLINKNAMELEN];
		boolean_t	islink;

		if (!dpa.dp_novanity) {
			(void) strlcpy(name, link, sizeof (name));
			islink = B_TRUE;
		} else {
			/*
			 * This is a physical link that does not have
			 * vanity naming support.
			 */
			(void) strlcpy(name, dpa.dp_dev, sizeof (name));
			islink = B_FALSE;
		}

		if (state->ls_parseable) {
			*pptr += snprintf(*pptr, BUFLEN(lim, *pptr),
			    "LINK=\"%s\" MEDIA=\"%s\" ", link,
			    dladm_media2str(media, buf));
			*pptr += snprintf(*pptr, BUFLEN(lim, *pptr),
			    "STATE=\"%s\" SPEED=\"%uMb\" ",
			    get_linkstate(name, islink, buf),
			    (uint_t)((get_ifspeed(name, islink)) / 1000000ull));
			*pptr += snprintf(*pptr, BUFLEN(lim, *pptr),
			    "DUPLEX=\"%s\" DEVICE=\"%s\"\n",
			    get_linkduplex(name, islink, buf), dpa.dp_dev);
		} else {
			*pptr += snprintf(*pptr, BUFLEN(lim, *pptr),
			    "%-12s%-20s", link,
			    dladm_media2str(media, buf));
			*pptr += snprintf(*pptr, BUFLEN(lim, *pptr),
			    "%-10s%4uMb  ",
			    get_linkstate(name, islink, buf),
			    (uint_t)((get_ifspeed(name, islink)) / 1000000ull));
			*pptr += snprintf(*pptr, BUFLEN(lim, *pptr),
			    "%-9s%s\n", get_linkduplex(name, islink, buf),
			    dpa.dp_dev);
		}
	} else {
		if (state->ls_parseable) {
			*pptr += snprintf(*pptr, BUFLEN(lim, *pptr),
			    "LINK=\"%s\" DEVICE=\"%s\" MEDIA=\"%s\" "
			    "FLAGS=\"%c----\"\n", link, dpa.dp_dev,
			    dladm_media2str(media, buf),
			    flags & DLADM_OPT_ACTIVE ? '-' : 'r');
		} else {
			*pptr += snprintf(*pptr, BUFLEN(lim, *pptr),
			    "%-12s%-12s%-20s%c----\n", link,
			    dpa.dp_dev, dladm_media2str(media, buf),
			    flags & DLADM_OPT_ACTIVE ? '-' : 'r');
		}
	}

done:
	return (status);
}

static int
show_phys(datalink_id_t linkid, void *arg)
{
	show_state_t	*state = arg;
	dladm_status_t	status;
	char		buf[MAXLINELEN];
	char		*ptr = buf, *lim = buf + MAXLINELEN;

	status = print_phys(state, linkid, &ptr, lim);
	if (status != DLADM_STATUS_OK)
		goto done;
	print_phys_head(state);
	(void) printf("%s", buf);

done:
	state->ls_status = status;
	return (DLADM_WALK_CONTINUE);
}

static void
print_vlan_head(show_state_t *state)
{
	if (state->ls_donefirst)
		return;
	state->ls_donefirst = B_TRUE;

	if (state->ls_parseable)
		return;

	(void) printf("%-12s%5s   %-12s%s\n", "LINK", "VID", "OVER", "FLAGS");
}

/*
 * Print the active topology information.
 */
static dladm_status_t
print_vlan(show_state_t *state, datalink_id_t linkid, char **pptr, char *lim)
{
	char			link[MAXLINKNAMELEN];
	char			over[MAXLINKNAMELEN];
	char			*fmt;
	dladm_vlan_attr_t	vinfo;
	uint32_t		flags;
	dladm_status_t		status;

	if ((status = dladm_datalink_id2info(linkid, &flags, NULL, NULL, link,
	    sizeof (link))) != DLADM_STATUS_OK) {
		goto done;
	}

	if (!(state->ls_flags & flags)) {
		status = DLADM_STATUS_NOTFOUND;
		goto done;
	}

	if ((status = dladm_vlan_info(linkid, &vinfo, state->ls_flags)) !=
	    DLADM_STATUS_OK || (status = dladm_datalink_id2info(
	    vinfo.dv_linkid, NULL, NULL, NULL, over, sizeof (over))) !=
	    DLADM_STATUS_OK) {
		goto done;
	}

	if (state->ls_parseable)
		fmt = "LINK=\"%s\" VID=\"%d\" OVER=\"%s\" FLAGS=\"%c%c---\"\n";
	else
		fmt = "%-12s%5d   %-12s%c%c---\n";
	/*LINTED: E_SEC_PRINTF_VAR_FMT*/
	*pptr += snprintf(*pptr, BUFLEN(lim, *pptr), fmt, link,
	    vinfo.dv_vid, over, vinfo.dv_force ? 'f' : '-',
	    vinfo.dv_implicit ? 'i' : '-');

done:
	return (status);
}

static int
show_vlan(datalink_id_t linkid, void *arg)
{
	show_state_t	*state = arg;
	dladm_status_t	status;
	char		buf[MAXLINELEN];
	char		*ptr = buf, *lim = buf + MAXLINELEN;

	status = print_vlan(state, linkid, &ptr, lim);
	if (status != DLADM_STATUS_OK)
		goto done;
	print_vlan_head(state);
	(void) printf("%s", buf);

done:
	state->ls_status = status;
	return (DLADM_WALK_CONTINUE);
}

static void
do_show_phys(int argc, char *argv[])
{
	int		option;
	uint32_t	flags = DLADM_OPT_ACTIVE;
	boolean_t	p_arg = B_FALSE;
	datalink_id_t	linkid = DATALINK_ALL_LINKID;
	show_state_t	state;
	dladm_status_t	status;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":pP",
	    show_lopts, NULL)) != -1) {
		switch (option) {
		case 'p':
			if (p_arg)
				die_optdup(option);

			p_arg = B_TRUE;
			break;
		case 'P':
			if (flags != DLADM_OPT_ACTIVE)
				die_optdup(option);

			flags = DLADM_OPT_PERSIST;
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	/* get link name (optional last argument) */
	if (optind == (argc-1)) {
		if ((status = dladm_name2info(argv[optind], &linkid, NULL,
		    NULL, NULL)) != DLADM_STATUS_OK) {
			die_dlerr(status, "link %s is not valid", argv[optind]);
		}
	} else if (optind != argc) {
		usage();
	}

	state.ls_parseable = p_arg;
	state.ls_flags = flags;
	state.ls_donefirst = B_FALSE;

	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(show_phys, &state,
		    DATALINK_CLASS_PHYS, DATALINK_ANY_MEDIATYPE, flags);
	} else {
		(void) show_phys(linkid, &state);
		if (state.ls_status != DLADM_STATUS_OK) {
			die_dlerr(state.ls_status,
			    "failed to show physical link %s", argv[optind]);
		}
	}
}

static void
do_show_vlan(int argc, char *argv[])
{
	int		option;
	uint32_t	flags = DLADM_OPT_ACTIVE;
	boolean_t	p_arg = B_FALSE;
	datalink_id_t	linkid = DATALINK_ALL_LINKID;
	show_state_t	state;
	dladm_status_t	status;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":pP",
	    show_lopts, NULL)) != -1) {
		switch (option) {
		case 'p':
			if (p_arg)
				die_optdup(option);

			p_arg = B_TRUE;
			break;
		case 'P':
			if (flags != DLADM_OPT_ACTIVE)
				die_optdup(option);

			flags = DLADM_OPT_PERSIST;
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	/* get link name (optional last argument) */
	if (optind == (argc-1)) {
		if ((status = dladm_name2info(argv[optind], &linkid, NULL,
		    NULL, NULL)) != DLADM_STATUS_OK) {
			die_dlerr(status, "link %s is not valid", argv[optind]);
		}
	} else if (optind != argc) {
		usage();
	}

	state.ls_parseable = p_arg;
	state.ls_flags = flags;
	state.ls_donefirst = B_FALSE;

	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(show_vlan, &state,
		    DATALINK_CLASS_VLAN, DATALINK_ANY_MEDIATYPE, flags);
	} else {
		(void) show_vlan(linkid, &state);
		if (state.ls_status != DLADM_STATUS_OK) {
			die_dlerr(state.ls_status, "failed to show vlan %s",
			    argv[optind]);
		}
	}
}

static void
link_stats(datalink_id_t linkid, uint_t interval)
{
	show_state_t	state;

	bzero(&state, sizeof (state));

	/*
	 * If an interval is specified, continuously show the stats
	 * only for the first MAC port.
	 */
	state.ls_firstonly = (interval != 0);

	for (;;) {
		(void) printf("%-12s%-10s%-12s%-8s%-10s%-12s%-8s\n",
		    "LINK", "IPACKETS", "RBYTES", "IERRORS", "OPACKETS",
		    "OBYTES", "OERRORS");

		state.ls_donefirst = B_FALSE;
		if (linkid == DATALINK_ALL_LINKID) {
			(void) dladm_walk_datalink_id(show_link_stats, &state,
			    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE,
			    DLADM_OPT_ACTIVE);
		} else {
			(void) show_link_stats(linkid, &state);
		}

		if (interval == 0)
			break;

		(void) sleep(interval);
	}
}

static void
aggr_stats(datalink_id_t linkid, show_grp_state_t *state, uint_t interval)
{
	/*
	 * If an interval is specified, continuously show the stats
	 * only for the first group.
	 */
	state->gs_firstonly = (interval != 0);

	for (;;) {

		(void) printf("%-12s%-10s%8s  %8s  %8s  %8s  %-9s%s\n",
		    "LINK", "PORT", "IPACKETS", "RBYTES", "OPACKETS",
		    "OBYTES", "IPKTDIST", "OPKTDIST");

		state->gs_donefirst = B_FALSE;
		if (linkid == DATALINK_ALL_LINKID)
			(void) dladm_walk_datalink_id(show_aggr, state,
			    DATALINK_CLASS_AGGR, DATALINK_ANY_MEDIATYPE,
			    DLADM_OPT_ACTIVE);
		else
			(void) show_aggr(linkid, state);

		if (interval == 0)
			break;

		(void) sleep(interval);
	}
}

static void
dev_stats(const char *dev, uint32_t interval)
{
	show_state_t state;

	bzero(&state, sizeof (state));

	/*
	 * If an interval is specified, continuously show the stats
	 * only for the first MAC port.
	 */
	state.ls_firstonly = (interval != 0);

	for (;;) {

		(void) printf("%-12s%-10s%-12s%-8s%-10s%-12s%-8s\n",
		    "DEV", "IPACKETS", "RBYTES", "IERRORS", "OPACKETS",
		    "OBYTES", "OERRORS");

		state.ls_donefirst = B_FALSE;
		if (dev == NULL)
			(void) dladm_mac_walk(show_dev_stats, &state);
		else
			(void) show_dev_stats(dev, &state);

		if (interval == 0)
			break;

		(void) sleep(interval);
	}

	if (dev != NULL && state.ls_status != DLADM_STATUS_OK)
		die_dlerr(state.ls_status, "cannot show device '%s'", dev);
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

static void
get_stats(char *module, int instance, const char *name, pktsum_t *stats)
{
	kstat_ctl_t	*kcp;
	kstat_t		*ksp;

	if ((kcp = kstat_open()) == NULL) {
		warn("kstat open operation failed");
		return;
	}

	if ((ksp = kstat_lookup(kcp, module, instance, (char *)name)) == NULL) {
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

bail:
	(void) kstat_close(kcp);
	return;

}

static void
get_mac_stats(const char *dev, pktsum_t *stats)
{
	char module[DLPI_LINKNAME_MAX];
	uint_t instance;

	bzero(stats, sizeof (*stats));
	if (dlpi_parselink(dev, module, &instance) != DLPI_SUCCESS)
		return;

	get_stats(module, instance, "mac", stats);
}

static void
get_link_stats(const char *link, pktsum_t *stats)
{
	bzero(stats, sizeof (*stats));
	get_stats("link", 0, link, stats);
}

static int
query_kstat(char *module, int instance, const char *name, const char *stat,
    uint8_t type, void *val)
{
	kstat_ctl_t	*kcp;
	kstat_t		*ksp;

	if ((kcp = kstat_open()) == NULL) {
		warn("kstat open operation failed");
		return (-1);
	}

	if ((ksp = kstat_lookup(kcp, module, instance, (char *)name)) == NULL) {
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

	if (kstat_value(ksp, stat, type, val) < 0)
		goto bail;

	(void) kstat_close(kcp);
	return (0);

bail:
	(void) kstat_close(kcp);
	return (-1);
}

static int
get_one_kstat(const char *name, const char *stat, uint8_t type,
    void *val, boolean_t islink)
{
	char		module[DLPI_LINKNAME_MAX];
	uint_t		instance;

	if (islink) {
		return (query_kstat("link", 0, name, stat, type, val));
	} else {
		if (dlpi_parselink(name, module, &instance) != DLPI_SUCCESS)
			return (-1);

		return (query_kstat(module, instance, "mac", stat, type, val));
	}
}

static uint64_t
get_ifspeed(const char *name, boolean_t islink)
{
	uint64_t ifspeed = 0;

	(void) get_one_kstat(name, "ifspeed", KSTAT_DATA_UINT64,
	    &ifspeed, islink);

	return (ifspeed);
}

static const char *
get_linkstate(const char *name, boolean_t islink, char *buf)
{
	link_state_t	linkstate;

	if (get_one_kstat(name, "link_state", KSTAT_DATA_UINT32,
	    &linkstate, islink) != 0) {
		(void) strlcpy(buf, "unknown", DLADM_STRSIZE);
		return (buf);
	}
	return (dladm_linkstate2str(linkstate, buf));
}

static const char *
get_linkduplex(const char *name, boolean_t islink, char *buf)
{
	link_duplex_t	linkduplex;

	if (get_one_kstat(name, "link_duplex", KSTAT_DATA_UINT32,
	    &linkduplex, islink) != 0) {
		(void) strlcpy(buf, "unknown", DLADM_STRSIZE);
		return (buf);
	}

	return (dladm_linkduplex2str(linkduplex, buf));
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
{ "link",	"LINK",		10, 0,			WIFI_CMD_ALL},
{ "essid",	"ESSID",	19, DLADM_WLAN_ATTR_ESSID,	WIFI_CMD_ALL},
{ "bssid",	"BSSID/IBSSID", 17, DLADM_WLAN_ATTR_BSSID,	WIFI_CMD_ALL},
{ "ibssid",	"BSSID/IBSSID", 17, DLADM_WLAN_ATTR_BSSID,	WIFI_CMD_ALL},
{ "mode",	"MODE",		6,  DLADM_WLAN_ATTR_MODE,	WIFI_CMD_ALL},
{ "speed",	"SPEED",	6,  DLADM_WLAN_ATTR_SPEED,	WIFI_CMD_ALL},
{ "auth",	"AUTH",		8,  DLADM_WLAN_ATTR_AUTH,	WIFI_CMD_SHOW},
{ "bsstype",	"BSSTYPE",	8,  DLADM_WLAN_ATTR_BSSTYPE, WIFI_CMD_ALL},
{ "sec",	"SEC",		6,  DLADM_WLAN_ATTR_SECMODE, WIFI_CMD_ALL},
{ "status",	"STATUS",	17, DLADM_WLAN_LINKATTR_STATUS, WIFI_CMD_SHOW},
{ "strength",	"STRENGTH",	10, DLADM_WLAN_ATTR_STRENGTH, WIFI_CMD_ALL}}
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
	char		*ws_link;
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
    dladm_wlan_attr_t *attrp)
{
	char		buf[DLADM_STRSIZE];
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
	case DLADM_WLAN_ATTR_ESSID:
		str = dladm_wlan_essid2str(&attrp->wa_essid, buf);
		break;
	case DLADM_WLAN_ATTR_BSSID:
		str = dladm_wlan_bssid2str(&attrp->wa_bssid, buf);
		break;
	case DLADM_WLAN_ATTR_SECMODE:
		str = dladm_wlan_secmode2str(&attrp->wa_secmode, buf);
		break;
	case DLADM_WLAN_ATTR_STRENGTH:
		str = dladm_wlan_strength2str(&attrp->wa_strength, buf);
		break;
	case DLADM_WLAN_ATTR_MODE:
		str = dladm_wlan_mode2str(&attrp->wa_mode, buf);
		break;
	case DLADM_WLAN_ATTR_SPEED:
		str = dladm_wlan_speed2str(&attrp->wa_speed, buf);
		(void) strlcat(buf, "Mb", sizeof (buf));
		break;
	case DLADM_WLAN_ATTR_AUTH:
		str = dladm_wlan_auth2str(&attrp->wa_auth, buf);
		break;
	case DLADM_WLAN_ATTR_BSSTYPE:
		str = dladm_wlan_bsstype2str(&attrp->wa_bsstype, buf);
		break;
	}

	print_wifi_field(statep, wfp, str);
}

static boolean_t
print_scan_results(void *arg, dladm_wlan_attr_t *attrp)
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

static int
scan_wifi(datalink_id_t linkid, void *arg)
{
	print_wifi_state_t	*statep = arg;
	dladm_status_t		status;
	char			link[MAXLINKNAMELEN];

	if (dladm_datalink_id2info(linkid, NULL, NULL, NULL, link,
	    sizeof (link)) != DLADM_STATUS_OK) {
		return (DLADM_WALK_CONTINUE);
	}

	statep->ws_link = link;
	status = dladm_wlan_scan(linkid, statep, print_scan_results);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "cannot scan link '%s'", statep->ws_link);

	return (DLADM_WALK_CONTINUE);
}

static void
print_link_attr(print_wifi_state_t *statep, wifi_field_t *wfp,
    dladm_wlan_linkattr_t *attrp)
{
	char		buf[DLADM_STRSIZE];
	const char	*str = "";

	if (strcmp(wfp->wf_name, "status") == 0) {
		if ((wfp->wf_mask & attrp->la_valid) != 0)
			str = dladm_wlan_linkstatus2str(&attrp->la_status, buf);
		print_wifi_field(statep, wfp, str);
		return;
	}
	print_wlan_attr(statep, wfp, &attrp->la_wlan_attr);
}

static int
show_wifi(datalink_id_t linkid, void *arg)
{
	int			i;
	print_wifi_state_t	*statep = arg;
	dladm_wlan_linkattr_t	attr;
	dladm_status_t		status;
	char			link[MAXLINKNAMELEN];

	if (dladm_datalink_id2info(linkid, NULL, NULL, NULL, link,
	    sizeof (link)) != DLADM_STATUS_OK) {
		return (DLADM_WALK_CONTINUE);
	}

	status = dladm_wlan_get_linkattr(linkid, &attr);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "cannot get link attributes for %s", link);

	statep->ws_link = link;

	if (statep->ws_header) {
		statep->ws_header = B_FALSE;
		if (!statep->ws_parseable)
			print_wifi_head(statep);
	}

	statep->ws_overflow = 0;
	for (i = 0; i < statep->ws_nfields; i++) {
		statep->ws_lastfield = (i + 1 == statep->ws_nfields);
		print_link_attr(statep, statep->ws_fields[i], &attr);
	}
	(void) putchar('\n');
	return (DLADM_WALK_CONTINUE);
}

static void
do_display_wifi(int argc, char **argv, int cmd)
{
	int			option;
	char			*fields_str = NULL;
	wifi_field_t		**fields;
	int			(*callback)(datalink_id_t, void *);
	uint_t			nfields;
	print_wifi_state_t	state;
	datalink_id_t		linkid = DATALINK_ALL_LINKID;
	dladm_status_t		status;

	if (cmd == WIFI_CMD_SCAN)
		callback = scan_wifi;
	else if (cmd == WIFI_CMD_SHOW)
		callback = show_wifi;
	else
		return;

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

	if (optind == (argc - 1)) {
		if ((status = dladm_name2info(argv[optind], &linkid, NULL,
		    NULL, NULL)) != DLADM_STATUS_OK) {
			die_dlerr(status, "link %s is not valid", argv[optind]);
		}
	} else if (optind != argc) {
		usage();
	}

	if (parse_wifi_fields(fields_str, &fields, &nfields, cmd) < 0)
		die("invalid field(s) specified");

	state.ws_fields = fields;
	state.ws_nfields = nfields;

	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(callback, &state,
		    DATALINK_CLASS_PHYS, DL_WIFI, DLADM_OPT_ACTIVE);
	} else {
		(void) (*callback)(linkid, &state);
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
	datalink_id_t	wc_linkid;
} wlan_count_attr_t;

static int
do_count_wlan(datalink_id_t linkid, void *arg)
{
	wlan_count_attr_t *cp = arg;

	if (cp->wc_count == 0)
		cp->wc_linkid = linkid;
	cp->wc_count++;
	return (DLADM_WALK_CONTINUE);
}

static int
parse_wlan_keys(char *str, dladm_wlan_key_t **keys, uint_t *key_countp)
{
	uint_t			i;
	split_t			*sp;
	dladm_wlan_key_t	*wk;

	sp = split(str, DLADM_WLAN_MAX_WEPKEYS, DLADM_WLAN_MAX_KEYNAME_LEN);
	if (sp == NULL)
		return (-1);

	wk = malloc(sp->s_nfields * sizeof (dladm_wlan_key_t));
	if (wk == NULL)
		goto fail;

	for (i = 0; i < sp->s_nfields; i++) {
		char			*s;
		dladm_secobj_class_t	class;
		dladm_status_t		status;

		(void) strlcpy(wk[i].wk_name, sp->s_fields[i],
		    DLADM_WLAN_MAX_KEYNAME_LEN);

		wk[i].wk_idx = 1;
		if ((s = strrchr(wk[i].wk_name, ':')) != NULL) {
			if (s[1] == '\0' || s[2] != '\0' || !isdigit(s[1]))
				goto fail;

			wk[i].wk_idx = (uint_t)(s[1] - '0');
			*s = '\0';
		}
		wk[i].wk_len = DLADM_WLAN_MAX_KEY_LEN;

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
		wk[i].wk_class = class;
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
	dladm_wlan_attr_t	attr, *attrp;
	dladm_status_t		status = DLADM_STATUS_OK;
	int			timeout = DLADM_WLAN_CONNECT_TIMEOUT_DEFAULT;
	datalink_id_t		linkid = DATALINK_ALL_LINKID;
	dladm_wlan_key_t	*keys = NULL;
	uint_t			key_count = 0;
	uint_t			flags = 0;
	dladm_wlan_secmode_t	keysecmode = DLADM_WLAN_SECMODE_NONE;
	char			buf[DLADM_STRSIZE];

	opterr = 0;
	(void) memset(&attr, 0, sizeof (attr));
	while ((option = getopt_long(argc, argv, ":e:i:a:m:b:s:k:T:c",
	    wifi_longopts, NULL)) != -1) {
		switch (option) {
		case 'e':
			status = dladm_wlan_str2essid(optarg, &attr.wa_essid);
			if (status != DLADM_STATUS_OK)
				die("invalid ESSID '%s'", optarg);

			attr.wa_valid |= DLADM_WLAN_ATTR_ESSID;
			/*
			 * Try to connect without doing a scan.
			 */
			flags |= DLADM_WLAN_CONNECT_NOSCAN;
			break;
		case 'i':
			status = dladm_wlan_str2bssid(optarg, &attr.wa_bssid);
			if (status != DLADM_STATUS_OK)
				die("invalid BSSID %s", optarg);

			attr.wa_valid |= DLADM_WLAN_ATTR_BSSID;
			break;
		case 'a':
			status = dladm_wlan_str2auth(optarg, &attr.wa_auth);
			if (status != DLADM_STATUS_OK)
				die("invalid authentication mode '%s'", optarg);

			attr.wa_valid |= DLADM_WLAN_ATTR_AUTH;
			break;
		case 'm':
			status = dladm_wlan_str2mode(optarg, &attr.wa_mode);
			if (status != DLADM_STATUS_OK)
				die("invalid mode '%s'", optarg);

			attr.wa_valid |= DLADM_WLAN_ATTR_MODE;
			break;
		case 'b':
			if ((status = dladm_wlan_str2bsstype(optarg,
			    &attr.wa_bsstype)) != DLADM_STATUS_OK) {
				die("invalid bsstype '%s'", optarg);
			}

			attr.wa_valid |= DLADM_WLAN_ATTR_BSSTYPE;
			break;
		case 's':
			if ((status = dladm_wlan_str2secmode(optarg,
			    &attr.wa_secmode)) != DLADM_STATUS_OK) {
				die("invalid security mode '%s'", optarg);
			}

			attr.wa_valid |= DLADM_WLAN_ATTR_SECMODE;
			break;
		case 'k':
			if (parse_wlan_keys(optarg, &keys, &key_count) < 0)
				die("invalid key(s) '%s'", optarg);

			if (keys[0].wk_class == DLADM_SECOBJ_CLASS_WEP)
				keysecmode = DLADM_WLAN_SECMODE_WEP;
			else
				keysecmode = DLADM_WLAN_SECMODE_WPA;
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
			flags |= DLADM_WLAN_CONNECT_CREATEIBSS;
			flags |= DLADM_WLAN_CONNECT_CREATEIBSS;
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	if (keysecmode == DLADM_WLAN_SECMODE_NONE) {
		if ((attr.wa_valid & DLADM_WLAN_ATTR_SECMODE) != 0) {
			die("key required for security mode '%s'",
			    dladm_wlan_secmode2str(&attr.wa_secmode, buf));
		}
	} else {
		if ((attr.wa_valid & DLADM_WLAN_ATTR_SECMODE) != 0 &&
		    attr.wa_secmode != keysecmode)
			die("incompatible -s and -k options");
		attr.wa_valid |= DLADM_WLAN_ATTR_SECMODE;
		attr.wa_secmode = keysecmode;
	}

	if (optind == (argc - 1)) {
		if ((status = dladm_name2info(argv[optind], &linkid, NULL,
		    NULL, NULL)) != DLADM_STATUS_OK) {
			die_dlerr(status, "link %s is not valid", argv[optind]);
		}
	} else if (optind != argc) {
		usage();
	}

	if (linkid == DATALINK_ALL_LINKID) {
		wlan_count_attr_t wcattr;

		wcattr.wc_linkid = DATALINK_INVALID_LINKID;
		wcattr.wc_count = 0;
		(void) dladm_walk_datalink_id(do_count_wlan, &wcattr,
		    DATALINK_CLASS_PHYS, DL_WIFI, DLADM_OPT_ACTIVE);
		if (wcattr.wc_count == 0) {
			die("no wifi links are available");
		} else if (wcattr.wc_count > 1) {
			die("link name is required when more than one wifi "
			    "link is available");
		}
		linkid = wcattr.wc_linkid;
	}
	attrp = (attr.wa_valid == 0) ? NULL : &attr;
again:
	if ((status = dladm_wlan_connect(linkid, attrp, timeout, keys,
	    key_count, flags)) != DLADM_STATUS_OK) {
		if ((flags & DLADM_WLAN_CONNECT_NOSCAN) != 0) {
			/*
			 * Try again with scanning and filtering.
			 */
			flags &= ~DLADM_WLAN_CONNECT_NOSCAN;
			goto again;
		}

		if (status == DLADM_STATUS_NOTFOUND) {
			if (attr.wa_valid == 0) {
				die("no wifi networks are available");
			} else {
				die("no wifi networks with the specified "
				    "criteria are available");
			}
		}
		die_dlerr(status, "cannot connect");
	}
	free(keys);
}

/* ARGSUSED */
static int
do_all_disconnect_wifi(datalink_id_t linkid, void *arg)
{
	dladm_status_t	status;

	status = dladm_wlan_disconnect(linkid);
	if (status != DLADM_STATUS_OK)
		warn_dlerr(status, "cannot disconnect link");

	return (DLADM_WALK_CONTINUE);
}

static void
do_disconnect_wifi(int argc, char **argv)
{
	int			option;
	datalink_id_t		linkid = DATALINK_ALL_LINKID;
	boolean_t		all_links = B_FALSE;
	dladm_status_t		status;
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

	if (optind == (argc - 1)) {
		if ((status = dladm_name2info(argv[optind], &linkid, NULL,
		    NULL, NULL)) != DLADM_STATUS_OK) {
			die_dlerr(status, "link %s is not valid", argv[optind]);
		}
	} else if (optind != argc) {
		usage();
	}

	if (linkid == DATALINK_ALL_LINKID) {
		if (!all_links) {
			wcattr.wc_linkid = linkid;
			wcattr.wc_count = 0;
			(void) dladm_walk_datalink_id(do_count_wlan, &wcattr,
			    DATALINK_CLASS_PHYS, DL_WIFI, DLADM_OPT_ACTIVE);
			if (wcattr.wc_count == 0) {
				die("no wifi links are available");
			} else if (wcattr.wc_count > 1) {
				die("link name is required when more than "
				    "one wifi link is available");
			}
			linkid = wcattr.wc_linkid;
		} else {
			(void) dladm_walk_datalink_id(do_all_disconnect_wifi,
			    NULL, DATALINK_CLASS_PHYS, DL_WIFI,
			    DLADM_OPT_ACTIVE);
			return;
		}
	}
	status = dladm_wlan_disconnect(linkid);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "cannot disconnect");
}

#define	MAX_PROPS		32
#define	MAX_PROP_LINE		512

typedef struct prop_info {
	char		*pi_name;
	char		*pi_val[DLADM_MAX_PROP_VALCNT];
	uint_t		pi_count;
} prop_info_t;

typedef struct prop_list {
	prop_info_t	pl_info[MAX_PROPS];
	uint_t		pl_count;
	char		*pl_buf;
} prop_list_t;

typedef struct show_linkprop_state {
	char		ls_link[MAXLINKNAMELEN];
	char		*ls_line;
	char		**ls_propvals;
	prop_list_t	*ls_proplist;
	uint32_t	ls_parseable : 1,
			ls_persist : 1,
			ls_header : 1,
			ls_pad_bits : 29;
	dladm_status_t	ls_status;
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
			if (pip->pi_count > DLADM_MAX_PROP_VALCNT)
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
print_linkprop(datalink_id_t linkid, show_linkprop_state_t *statep,
    const char *propname, dladm_prop_type_t type, const char *typename,
    const char *format, char **pptr)
{
	int		i;
	char		*ptr, *lim;
	char		buf[DLADM_STRSIZE];
	char		*unknown = "?", *notsup = "";
	char		**propvals = statep->ls_propvals;
	uint_t		valcnt = DLADM_MAX_PROP_VALCNT;
	dladm_status_t	status;

	status = dladm_get_linkprop(linkid, type, propname, propvals, &valcnt);
	if (status != DLADM_STATUS_OK) {
		if (status == DLADM_STATUS_TEMPONLY) {
			if (type == DLADM_PROP_VAL_MODIFIABLE &&
			    statep->ls_persist) {
				valcnt = 1;
				propvals = &unknown;
			} else {
				statep->ls_status = status;
				return;
			}
		} else if (status == DLADM_STATUS_NOTSUP ||
		    statep->ls_persist) {
			valcnt = 1;
			if (type == DLADM_PROP_VAL_CURRENT)
				propvals = &unknown;
			else
				propvals = &notsup;
		} else {
			statep->ls_status = status;
			if (statep->ls_proplist) {
				warn_dlerr(status,
				    "cannot get link property '%s' for %s",
				    propname, statep->ls_link);
			}
			return;
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

static int
show_linkprop(datalink_id_t linkid, const char *propname, void *arg)
{
	show_linkprop_state_t	*statep = arg;
	char			*ptr = statep->ls_line;
	char			*lim = ptr + MAX_PROP_LINE;

	if (statep->ls_parseable)
		ptr += snprintf(ptr, lim - ptr, "LINK=\"%s\" ",
		    statep->ls_link);
	else
		ptr += snprintf(ptr, lim - ptr, "%-12s ", statep->ls_link);

	if (statep->ls_parseable)
		ptr += snprintf(ptr, lim - ptr, "PROPERTY=\"%s\" ", propname);
	else
		ptr += snprintf(ptr, lim - ptr, "%-15s ", propname);

	print_linkprop(linkid, statep, propname,
	    statep->ls_persist ? DLADM_PROP_VAL_PERSISTENT :
	    DLADM_PROP_VAL_CURRENT, "VALUE", "%-14s ", &ptr);

	/*
	 * If we failed to query the link property, for example, query
	 * the persistent value of a non-persistable link property, simply
	 * skip the output.
	 */
	if (statep->ls_status != DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);

	print_linkprop(linkid, statep, propname, DLADM_PROP_VAL_DEFAULT,
	    "DEFAULT", "%-14s ", &ptr);
	if (statep->ls_status != DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);

	print_linkprop(linkid, statep, propname, DLADM_PROP_VAL_MODIFIABLE,
	    "POSSIBLE", "%-20s ", &ptr);
	if (statep->ls_status != DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);

	if (statep->ls_header) {
		statep->ls_header = B_FALSE;
		if (!statep->ls_parseable)
			print_linkprop_head();
	}
	(void) printf("%s\n", statep->ls_line);
	return (DLADM_WALK_CONTINUE);
}

static void
do_show_linkprop(int argc, char **argv)
{
	int			option;
	prop_list_t		*proplist = NULL;
	datalink_id_t		linkid = DATALINK_ALL_LINKID;
	show_linkprop_state_t	state;
	uint32_t		flags = DLADM_OPT_ACTIVE;
	dladm_status_t		status;

	opterr = 0;
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
			flags = DLADM_OPT_PERSIST;
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	if (optind == (argc - 1)) {
		if ((status = dladm_name2info(argv[optind], &linkid, NULL,
		    NULL, NULL)) != DLADM_STATUS_OK) {
			die_dlerr(status, "link %s is not valid", argv[optind]);
		}
	} else if (optind != argc) {
		usage();
	}

	state.ls_proplist = proplist;
	state.ls_status = DLADM_STATUS_OK;

	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(show_linkprop_onelink, &state,
		    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE, flags);
	} else {
		(void) show_linkprop_onelink(linkid, &state);
	}
	free_props(proplist);

	if (state.ls_status != DLADM_STATUS_OK) {
		if (optind == (argc - 1)) {
			warn_dlerr(state.ls_status,
			    "show-linkprop failed for %s", argv[optind]);
		}
		exit(EXIT_FAILURE);
	}
}

static int
show_linkprop_onelink(datalink_id_t linkid, void *arg)
{
	int			i;
	char			*buf;
	uint32_t		flags;
	prop_list_t		*proplist = NULL;
	show_linkprop_state_t	*statep = arg;
	dlpi_handle_t		dh = NULL;

	statep->ls_status = DLADM_STATUS_OK;

	if (dladm_datalink_id2info(linkid, &flags, NULL, NULL, statep->ls_link,
	    MAXLINKNAMELEN) != DLADM_STATUS_OK) {
		statep->ls_status = DLADM_STATUS_NOTFOUND;
		return (DLADM_WALK_CONTINUE);
	}

	if ((statep->ls_persist && !(flags & DLADM_OPT_PERSIST)) ||
	    (!statep->ls_persist && !(flags & DLADM_OPT_ACTIVE))) {
		statep->ls_status = DLADM_STATUS_BADARG;
		return (DLADM_WALK_CONTINUE);
	}

	proplist = statep->ls_proplist;

	/*
	 * When some WiFi links are opened for the first time, their hardware
	 * automatically scans for APs and does other slow operations.	Thus,
	 * if there are no open links, the retrieval of link properties
	 * (below) will proceed slowly unless we hold the link open.
	 *
	 * Note that failure of dlpi_open() does not necessarily mean invalid
	 * link properties, because dlpi_open() may fail because of incorrect
	 * autopush configuration. Therefore, we ingore the return value of
	 * dlpi_open().
	 */
	if (!statep->ls_persist)
		(void) dlpi_open(statep->ls_link, &dh, 0);

	buf = malloc((sizeof (char *) + DLADM_PROP_VAL_MAX) *
	    DLADM_MAX_PROP_VALCNT + MAX_PROP_LINE);
	if (buf == NULL)
		die("insufficient memory");

	statep->ls_propvals = (char **)(void *)buf;
	for (i = 0; i < DLADM_MAX_PROP_VALCNT; i++) {
		statep->ls_propvals[i] = buf +
		    sizeof (char *) * DLADM_MAX_PROP_VALCNT +
		    i * DLADM_PROP_VAL_MAX;
	}
	statep->ls_line = buf +
	    (sizeof (char *) + DLADM_PROP_VAL_MAX) * DLADM_MAX_PROP_VALCNT;

	if (proplist != NULL) {
		for (i = 0; i < proplist->pl_count; i++) {
			(void) show_linkprop(linkid,
			    proplist->pl_info[i].pi_name, statep);
		}
	} else {
		(void) dladm_walk_linkprop(linkid, statep, show_linkprop);
	}
	if (dh != NULL)
		dlpi_close(dh);
	free(buf);
	return (DLADM_WALK_CONTINUE);
}

static dladm_status_t
set_linkprop_persist(datalink_id_t linkid, const char *prop_name,
    char **prop_val, uint_t val_cnt, boolean_t reset)
{
	dladm_status_t	status;

	status = dladm_set_linkprop(linkid, prop_name, prop_val, val_cnt,
	    DLADM_OPT_PERSIST);

	if (status != DLADM_STATUS_OK) {
		warn_dlerr(status, "cannot persistently %s link property",
		    reset ? "reset" : "set");
	}
	return (status);
}

static void
set_linkprop(int argc, char **argv, boolean_t reset)
{
	int		i, option;
	char		errmsg[DLADM_STRSIZE];
	char		*altroot = NULL;
	datalink_id_t	linkid;
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
			altroot = optarg;
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	/* get link name (required last argument) */
	if (optind != (argc - 1))
		usage();

	if (proplist == NULL && !reset)
		die("link property must be specified");

	if (altroot != NULL) {
		free_props(proplist);
		altroot_cmd(altroot, argc, argv);
	}

	status = dladm_name2info(argv[optind], &linkid, NULL, NULL, NULL);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "link %s is not valid", argv[optind]);

	if (proplist == NULL) {
		if ((status = dladm_set_linkprop(linkid, NULL, NULL, 0,
		    DLADM_OPT_ACTIVE)) != DLADM_STATUS_OK) {
			warn_dlerr(status, "cannot reset link property "
			    "on '%s'", argv[optind]);
		}
		if (!temp) {
			dladm_status_t	s;

			s = set_linkprop_persist(linkid, NULL, NULL, 0, reset);
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
		s = dladm_set_linkprop(linkid, pip->pi_name, val, count,
		    DLADM_OPT_ACTIVE);
		if (s == DLADM_STATUS_OK) {
			if (!temp) {
				s = set_linkprop_persist(linkid,
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
			uint_t		valcnt = DLADM_MAX_PROP_VALCNT;

			ptr = malloc((sizeof (char *) +
			    DLADM_PROP_VAL_MAX) * DLADM_MAX_PROP_VALCNT +
			    MAX_PROP_LINE);

			propvals = (char **)(void *)ptr;
			if (propvals == NULL)
				die("insufficient memory");

			for (j = 0; j < DLADM_MAX_PROP_VALCNT; j++) {
				propvals[j] = ptr + sizeof (char *) *
				    DLADM_MAX_PROP_VALCNT +
				    j * DLADM_PROP_VAL_MAX;
			}
			s = dladm_get_linkprop(linkid,
			    DLADM_PROP_VAL_MODIFIABLE, pip->pi_name, propvals,
			    &valcnt);

			if (s != DLADM_STATUS_OK) {
				warn_dlerr(status, "cannot set link property "
				    "'%s' on '%s'", pip->pi_name, argv[optind]);
				free(propvals);
				break;
			}

			ptr = errmsg;
			lim = ptr + DLADM_STRSIZE;
			*ptr = '\0';
			for (j = 0; j < valcnt; j++) {
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
				    "'%s' on '%s'", pip->pi_name, argv[optind]);
			} else {
				warn_dlerr(status, "cannot set link property "
				    "'%s' on '%s'", pip->pi_name, argv[optind]);
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

	if (class == DLADM_SECOBJ_CLASS_WPA) {
		if (len < 8 || len > 63)
			return (EINVAL);
		(void) memcpy(obj_val, buf, len);
		*obj_lenp = len;
		return (error);
	}

	if (class == DLADM_SECOBJ_CLASS_WEP) {
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
			error = hexascii_to_octet(buf + 2, len - 2,
			    obj_val, obj_lenp);
			break;
		default:
			return (EINVAL);
		}
		return (error);
	}

	return (ENOENT);
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
				    "valid values are: wep, wpa", optarg);
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
	    DLADM_OPT_CREATE | DLADM_OPT_ACTIVE);
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
	audit_secobj(LINK_SEC_AUTH, "unknown", argv[optind], success, B_FALSE);
	if (!success)
		die("authorization '%s' is required", LINK_SEC_AUTH);

	for (i = 0; i < sp->s_nfields; i++) {
		status = dladm_unset_secobj(sp->s_fields[i], DLADM_OPT_ACTIVE);
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

/*ARGSUSED*/
static int
i_dladm_init_linkprop(datalink_id_t linkid, void *arg)
{
	(void) dladm_init_linkprop(linkid);
	return (DLADM_WALK_CONTINUE);
}

/* ARGSUSED */
static void
do_init_linkprop(int argc, char **argv)
{
	/*
	 * linkprops of links of other classes have been initialized as a
	 * part of the dladm up-xxx operation.
	 */
	(void) dladm_walk_datalink_id(i_dladm_init_linkprop, NULL,
	    DATALINK_CLASS_PHYS, DATALINK_ANY_MEDIATYPE, DLADM_OPT_PERSIST);
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

/*
 * "-R" option support. It is used for live upgrading. Append dladm commands
 * to a upgrade script which will be run when the alternative root boots up:
 *
 * - If the dlmgmtd door file exists on the alternative root, append dladm
 * commands to the <altroot>/var/svc/profile/upgrade_datalink script. This
 * script will be run as part of the network/physical service. We cannot defer
 * this to /var/svc/profile/upgrade because then the configuration will not
 * be able to take effect before network/physical plumbs various interfaces.
 *
 * - If the dlmgmtd door file does not exist on the alternative root, append
 * dladm commands to the <altroot>/var/svc/profile/upgrade script, which will
 * be run in the manifest-import service.
 *
 * Note that the SMF team is considering to move the manifest-import service
 * to be run at the very begining of boot. Once that is done, the need for
 * the /var/svc/profile/upgrade_datalink script will not exist any more.
 */
static void
altroot_cmd(char *altroot, int argc, char *argv[])
{
	char		path[MAXPATHLEN];
	struct stat	stbuf;
	FILE		*fp;
	int		i;

	/*
	 * Check for the existence of the dlmgmtd door file, and determine
	 * the name of script file.
	 */
	(void) snprintf(path, MAXPATHLEN, "/%s/%s", altroot, DLMGMT_DOOR);
	if (stat(path, &stbuf) < 0) {
		(void) snprintf(path, MAXPATHLEN, "/%s/%s", altroot,
		    SMF_UPGRADE_FILE);
	} else {
		(void) snprintf(path, MAXPATHLEN, "/%s/%s", altroot,
		    SMF_UPGRADEDATALINK_FILE);
	}

	if ((fp = fopen(path, "a+")) == NULL)
		die("operation not supported on %s", altroot);

	(void) fprintf(fp, "/sbin/dladm ");
	for (i = 0; i < argc; i++) {
		/*
		 * Directly write to the file if it is not the "-R <altroot>"
		 * option. In which case, skip it.
		 */
		if (strcmp(argv[i], "-R") != 0)
			(void) fprintf(fp, "%s ", argv[i]);
		else
			i ++;
	}
	(void) fprintf(fp, "%s\n", SMF_DLADM_UPGRADE_MSG);
	(void) fclose(fp);
	exit(0);
}

/*
 * Convert the string to an integer. Note that the string must not have any
 * trailing non-integer characters.
 */
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

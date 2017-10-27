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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2016 Nexenta Systems, Inc.
 */

#include <stdio.h>
#include <ctype.h>
#include <dlfcn.h>
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
#include <limits.h>
#include <termios.h>
#include <pwd.h>
#include <auth_attr.h>
#include <auth_list.h>
#include <libintl.h>
#include <libdevinfo.h>
#include <libdlpi.h>
#include <libdladm.h>
#include <libdllink.h>
#include <libdlstat.h>
#include <libdlaggr.h>
#include <libdlwlan.h>
#include <libdlvlan.h>
#include <libdlvnic.h>
#include <libdlib.h>
#include <libdlether.h>
#include <libdliptun.h>
#include <libdlsim.h>
#include <libdlbridge.h>
#include <libinetutil.h>
#include <libvrrpadm.h>
#include <bsm/adt.h>
#include <bsm/adt_event.h>
#include <libdlvnic.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ib/ib_types.h>
#include <sys/processor.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if_types.h>
#include <stddef.h>
#include <stp_in.h>
#include <ofmt.h>

#define	MAXPORT			256
#define	MAXVNIC			256
#define	BUFLEN(lim, ptr)	(((lim) > (ptr)) ? ((lim) - (ptr)) : 0)
#define	MAXLINELEN		1024
#define	SMF_UPGRADE_FILE		"/var/svc/profile/upgrade"
#define	SMF_UPGRADEDATALINK_FILE	"/var/svc/profile/upgrade_datalink"
#define	SMF_DLADM_UPGRADE_MSG		" # added by dladm(1M)"
#define	DLADM_DEFAULT_COL	80

/*
 * used by the wifi show-* commands to set up ofmt_field_t structures.
 */
#define	WIFI_CMD_SCAN		0x00000001
#define	WIFI_CMD_SHOW		0x00000002
#define	WIFI_CMD_ALL		(WIFI_CMD_SCAN | WIFI_CMD_SHOW)

/* No larger than pktsum_t */
typedef struct brsum_s {
	uint64_t	drops;
	uint64_t	forward_dir;
	uint64_t	forward_mb;
	uint64_t	forward_unk;
	uint64_t	recv;
	uint64_t	sent;
} brsum_t;

/* No larger than pktsum_t */
typedef struct brlsum_s {
	uint32_t	cfgbpdu;
	uint32_t	tcnbpdu;
	uint32_t	rstpbpdu;
	uint32_t	txbpdu;
	uint64_t	drops;
	uint64_t	recv;
	uint64_t	xmit;
} brlsum_t;

typedef struct show_state {
	boolean_t	ls_firstonly;
	boolean_t	ls_donefirst;
	pktsum_t	ls_prevstats;
	uint32_t	ls_flags;
	dladm_status_t	ls_status;
	ofmt_handle_t	ls_ofmt;
	boolean_t	ls_parsable;
	boolean_t	ls_mac;
	boolean_t	ls_hwgrp;
} show_state_t;

typedef struct show_grp_state {
	pktsum_t	gs_prevstats[MAXPORT];
	uint32_t	gs_flags;
	dladm_status_t	gs_status;
	boolean_t	gs_parsable;
	boolean_t	gs_lacp;
	boolean_t	gs_extended;
	boolean_t	gs_stats;
	boolean_t	gs_firstonly;
	boolean_t	gs_donefirst;
	ofmt_handle_t	gs_ofmt;
} show_grp_state_t;

typedef struct show_vnic_state {
	datalink_id_t	vs_vnic_id;
	datalink_id_t	vs_link_id;
	char		vs_vnic[MAXLINKNAMELEN];
	char		vs_link[MAXLINKNAMELEN];
	boolean_t	vs_parsable;
	boolean_t	vs_found;
	boolean_t	vs_firstonly;
	boolean_t	vs_donefirst;
	boolean_t	vs_stats;
	boolean_t	vs_printstats;
	pktsum_t	vs_totalstats;
	pktsum_t	vs_prevstats[MAXVNIC];
	boolean_t	vs_etherstub;
	dladm_status_t	vs_status;
	uint32_t	vs_flags;
	ofmt_handle_t	vs_ofmt;
} show_vnic_state_t;

typedef struct show_part_state {
	datalink_id_t	ps_over_id;
	char		ps_part[MAXLINKNAMELEN];
	boolean_t	ps_parsable;
	boolean_t	ps_found;
	dladm_status_t	ps_status;
	uint32_t	ps_flags;
	ofmt_handle_t	ps_ofmt;
} show_part_state_t;

typedef struct show_ib_state {
	datalink_id_t	is_link_id;
	char		is_link[MAXLINKNAMELEN];
	boolean_t	is_parsable;
	dladm_status_t	is_status;
	uint32_t	is_flags;
	ofmt_handle_t	is_ofmt;
} show_ib_state_t;

typedef struct show_usage_state_s {
	boolean_t	us_plot;
	boolean_t	us_parsable;
	boolean_t	us_printheader;
	boolean_t	us_first;
	boolean_t	us_showall;
	ofmt_handle_t	us_ofmt;
} show_usage_state_t;

/*
 * callback functions for printing output and error diagnostics.
 */
static ofmt_cb_t print_default_cb, print_link_stats_cb, print_linkprop_cb;
static ofmt_cb_t print_lacp_cb, print_phys_one_mac_cb;
static ofmt_cb_t print_xaggr_cb, print_aggr_stats_cb;
static ofmt_cb_t print_phys_one_hwgrp_cb, print_wlan_attr_cb;
static ofmt_cb_t print_wifi_status_cb, print_link_attr_cb;

typedef void cmdfunc_t(int, char **, const char *);

static cmdfunc_t do_show_link, do_show_wifi, do_show_phys;
static cmdfunc_t do_create_aggr, do_delete_aggr, do_add_aggr, do_remove_aggr;
static cmdfunc_t do_modify_aggr, do_show_aggr, do_up_aggr;
static cmdfunc_t do_scan_wifi, do_connect_wifi, do_disconnect_wifi;
static cmdfunc_t do_show_linkprop, do_set_linkprop, do_reset_linkprop;
static cmdfunc_t do_create_secobj, do_delete_secobj, do_show_secobj;
static cmdfunc_t do_init_linkprop, do_init_secobj;
static cmdfunc_t do_create_vlan, do_delete_vlan, do_up_vlan, do_show_vlan;
static cmdfunc_t do_rename_link, do_delete_phys, do_init_phys;
static cmdfunc_t do_show_linkmap;
static cmdfunc_t do_show_ether;
static cmdfunc_t do_create_vnic, do_delete_vnic, do_show_vnic;
static cmdfunc_t do_up_vnic;
static cmdfunc_t do_create_part, do_delete_part, do_show_part, do_show_ib;
static cmdfunc_t do_up_part;
static cmdfunc_t do_create_etherstub, do_delete_etherstub, do_show_etherstub;
static cmdfunc_t do_create_simnet, do_modify_simnet;
static cmdfunc_t do_delete_simnet, do_show_simnet, do_up_simnet;
static cmdfunc_t do_show_usage;
static cmdfunc_t do_create_bridge, do_modify_bridge, do_delete_bridge;
static cmdfunc_t do_add_bridge, do_remove_bridge, do_show_bridge;
static cmdfunc_t do_create_iptun, do_modify_iptun, do_delete_iptun;
static cmdfunc_t do_show_iptun, do_up_iptun, do_down_iptun;

static void 	do_up_vnic_common(int, char **, const char *, boolean_t);

static int show_part(dladm_handle_t, datalink_id_t, void *);

static void	altroot_cmd(char *, int, char **);
static int	show_linkprop_onelink(dladm_handle_t, datalink_id_t, void *);

static void	link_stats(datalink_id_t, uint_t, char *, show_state_t *);
static void	aggr_stats(datalink_id_t, show_grp_state_t *, uint_t);
static void	vnic_stats(show_vnic_state_t *, uint32_t);

static int	get_one_kstat(const char *, const char *, uint8_t,
		    void *, boolean_t);
static void	get_mac_stats(const char *, pktsum_t *);
static void	get_link_stats(const char *, pktsum_t *);
static uint64_t	get_ifspeed(const char *, boolean_t);
static const char	*get_linkstate(const char *, boolean_t, char *);
static const char	*get_linkduplex(const char *, boolean_t, char *);

static iptun_type_t	iptun_gettypebyname(char *);
static const char	*iptun_gettypebyvalue(iptun_type_t);
static dladm_status_t	print_iptun(dladm_handle_t, datalink_id_t,
			    show_state_t *);
static int	print_iptun_walker(dladm_handle_t, datalink_id_t, void *);

static int	show_etherprop(dladm_handle_t, datalink_id_t, void *);
static void	show_ether_xprop(void *, dladm_ether_info_t *);
static boolean_t	link_is_ether(const char *, datalink_id_t *);

static boolean_t str2int(const char *, int *);
static void	die(const char *, ...);
static void	die_optdup(int);
static void	die_opterr(int, int, const char *);
static void	die_dlerr(dladm_status_t, const char *, ...);
static void	warn(const char *, ...);
static void	warn_dlerr(dladm_status_t, const char *, ...);

typedef struct	cmd {
	char		*c_name;
	cmdfunc_t	*c_fn;
	const char	*c_usage;
} cmd_t;

static cmd_t	cmds[] = {
	{ "rename-link",	do_rename_link,
	    "    rename-link      <oldlink> <newlink>"			},
	{ "show-link",		do_show_link,
	    "    show-link        [-pP] [-o <field>,..] [-s [-i <interval>]] "
	    "[<link>]\n"						},
	{ "create-aggr",	do_create_aggr,
	    "    create-aggr      [-t] [-P <policy>] [-L <mode>] [-T <time>] "
	    "[-u <address>]\n"
	    "\t\t     -l <link> [-l <link>...] <link>"			},
	{ "delete-aggr",	do_delete_aggr,
	    "    delete-aggr      [-t] <link>"				},
	{ "add-aggr",		do_add_aggr,
	    "    add-aggr         [-t] -l <link> [-l <link>...] <link>" },
	{ "remove-aggr",	do_remove_aggr,
	    "    remove-aggr      [-t] -l <link> [-l <link>...] <link>" },
	{ "modify-aggr",	do_modify_aggr,
	    "    modify-aggr      [-t] [-P <policy>] [-L <mode>] [-T <time>] "
	    "[-u <address>]\n"
	    "\t\t     <link>"						},
	{ "show-aggr",		do_show_aggr,
	    "    show-aggr        [-pPLx] [-o <field>,..] [-s [-i <interval>]] "
	    "[<link>]\n"						},
	{ "up-aggr",		do_up_aggr,	NULL			},
	{ "scan-wifi",		do_scan_wifi,
	    "    scan-wifi        [-p] [-o <field>,...] [<link>]"	},
	{ "connect-wifi",	do_connect_wifi,
	    "    connect-wifi     [-e <essid>] [-i <bssid>] [-k <key>,...] "
	    "[-s wep|wpa]\n"
	    "\t\t     [-a open|shared] [-b bss|ibss] [-c] [-m a|b|g] "
	    "[-T <time>]\n"
	    "\t\t     [<link>]"						},
	{ "disconnect-wifi",	do_disconnect_wifi,
	    "    disconnect-wifi  [-a] [<link>]"			},
	{ "show-wifi",		do_show_wifi,
	    "    show-wifi        [-p] [-o <field>,...] [<link>]\n"	},
	{ "set-linkprop",	do_set_linkprop,
	    "    set-linkprop     [-t] -p <prop>=<value>[,...] <name>"	},
	{ "reset-linkprop",	do_reset_linkprop,
	    "    reset-linkprop   [-t] [-p <prop>,...] <name>"		},
	{ "show-linkprop",	do_show_linkprop,
	    "    show-linkprop    [-cP] [-o <field>,...] [-p <prop>,...] "
	    "<name>\n"							},
	{ "show-ether",		do_show_ether,
	    "    show-ether       [-px][-o <field>,...] <link>\n"	},
	{ "create-secobj",	do_create_secobj,
	    "    create-secobj    [-t] [-f <file>] -c <class> <secobj>"	},
	{ "delete-secobj",	do_delete_secobj,
	    "    delete-secobj    [-t] <secobj>[,...]"			},
	{ "show-secobj",	do_show_secobj,
	    "    show-secobj      [-pP] [-o <field>,...] [<secobj>,...]\n" },
	{ "init-linkprop",	do_init_linkprop,	NULL		},
	{ "init-secobj",	do_init_secobj,		NULL		},
	{ "create-vlan", 	do_create_vlan,
	    "    create-vlan      [-ft] -l <link> -v <vid> [link]"	},
	{ "delete-vlan", 	do_delete_vlan,
	    "    delete-vlan      [-t] <link>"				},
	{ "show-vlan",		do_show_vlan,
	    "    show-vlan        [-pP] [-o <field>,..] [<link>]\n"	},
	{ "up-vlan",		do_up_vlan,		NULL		},
	{ "create-iptun",	do_create_iptun,
	    "    create-iptun     [-t] -T <type> "
	    "[-a {local|remote}=<addr>,...] <link>]" },
	{ "delete-iptun",	do_delete_iptun,
	    "    delete-iptun     [-t] <link>"				},
	{ "modify-iptun",	do_modify_iptun,
	    "    modify-iptun     [-t] -a {local|remote}=<addr>,... <link>" },
	{ "show-iptun",		do_show_iptun,
	    "    show-iptun       [-pP] [-o <field>,..] [<link>]\n"	},
	{ "up-iptun",		do_up_iptun,		NULL		},
	{ "down-iptun",		do_down_iptun,		NULL		},
	{ "delete-phys",	do_delete_phys,
	    "    delete-phys      <link>"				},
	{ "show-phys",		do_show_phys,
	    "    show-phys        [-m | -H | -P] [[-p] [-o <field>[,...]] "
	    "[<link>]\n"						},
	{ "init-phys",		do_init_phys,		NULL		},
	{ "show-linkmap",	do_show_linkmap,	NULL		},
	{ "create-vnic",	do_create_vnic,
	    "    create-vnic      [-t] -l <link> [-m <value> | auto |\n"
	    "\t\t     {factory [-n <slot-id>]} | {random [-r <prefix>]} |\n"
	    "\t\t     {vrrp -V <vrid> -A {inet | inet6}} [-v <vid> [-f]]\n"
	    "\t\t     [-p <prop>=<value>[,...]] <vnic-link>"	},
	{ "delete-vnic",	do_delete_vnic,
	    "    delete-vnic      [-t] <vnic-link>"			},
	{ "show-vnic",		do_show_vnic,
	    "    show-vnic        [-pP] [-l <link>] [-s [-i <interval>]] "
	    "[<link>]\n"						},
	{ "up-vnic",		do_up_vnic,		NULL		},
	{ "create-part",	do_create_part,
	    "    create-part      [-t] [-f] -l <link> [-P <pkey>]\n"
	    "\t\t     [-R <root-dir>] <part-link>"			},
	{ "delete-part",	do_delete_part,
	    "    delete-part      [-t] [-R <root-dir>] <part-link>"},
	{ "show-part",		do_show_part,
	    "    show-part        [-pP] [-o <field>,...][-l <linkover>]\n"
	    "\t\t     [<part-link>]"		},
	{ "show-ib",		do_show_ib,
	    "    show-ib          [-p] [-o <field>,...] [<link>]\n"	},
	{ "up-part",		do_up_part,		NULL		},
	{ "create-etherstub",	do_create_etherstub,
	    "    create-etherstub [-t] <link>"				},
	{ "delete-etherstub",	do_delete_etherstub,
	    "    delete-etherstub [-t] <link>"				},
	{ "show-etherstub",	do_show_etherstub,
	    "    show-etherstub   [-t] [<link>]\n"			},
	{ "create-simnet",	do_create_simnet,	NULL		},
	{ "modify-simnet",	do_modify_simnet,	NULL		},
	{ "delete-simnet",	do_delete_simnet,	NULL		},
	{ "show-simnet",	do_show_simnet,		NULL		},
	{ "up-simnet",		do_up_simnet,		NULL		},
	{ "create-bridge",	do_create_bridge,
	    "    create-bridge    [-R <root-dir>] [-P <protect>] "
	    "[-p <priority>]\n"
	    "\t\t     [-m <max-age>] [-h <hello-time>] [-d <forward-delay>]\n"
	    "\t\t     [-f <force-protocol>] [-l <link>]... <bridge>"	},
	{ "modify-bridge",	do_modify_bridge,
	    "    modify-bridge    [-R <root-dir>] [-P <protect>] "
	    "[-p <priority>]\n"
	    "\t\t     [-m <max-age>] [-h <hello-time>] [-d <forward-delay>]\n"
	    "\t\t     [-f <force-protocol>] <bridge>"			},
	{ "delete-bridge",	do_delete_bridge,
	    "    delete-bridge    [-R <root-dir>] <bridge>"		},
	{ "add-bridge",		do_add_bridge,
	    "    add-bridge       [-R <root-dir>] -l <link> [-l <link>]... "
	    "<bridge>"							},
	{ "remove-bridge",	do_remove_bridge,
	    "    remove-bridge    [-R <root-dir>] -l <link> [-l <link>]... "
	    "<bridge>"							},
	{ "show-bridge",	do_show_bridge,
	    "    show-bridge      [-p] [-o <field>,...] [-s [-i <interval>]] "
	    "[<bridge>]\n"
	    "    show-bridge      -l [-p] [-o <field>,...] [-s [-i <interval>]]"
	    " <bridge>\n"
	    "    show-bridge      -f [-p] [-o <field>,...] [-s [-i <interval>]]"
	    " <bridge>\n"
	    "    show-bridge      -t [-p] [-o <field>,...] [-s [-i <interval>]]"
	    " <bridge>\n"						},
	{ "show-usage",		do_show_usage,
	    "    show-usage       [-a] [-d | -F <format>] "
	    "[-s <DD/MM/YYYY,HH:MM:SS>]\n"
	    "\t\t     [-e <DD/MM/YYYY,HH:MM:SS>] -f <logfile> [<link>]"	}
};

static const struct option lopts[] = {
	{"vlan-id",	required_argument,	0, 'v'},
	{"output",	required_argument,	0, 'o'},
	{"dev",		required_argument,	0, 'd'},
	{"policy",	required_argument,	0, 'P'},
	{"lacp-mode",	required_argument,	0, 'L'},
	{"lacp-timer",	required_argument,	0, 'T'},
	{"unicast",	required_argument,	0, 'u'},
	{"temporary",	no_argument,		0, 't'},
	{"root-dir",	required_argument,	0, 'R'},
	{"link",	required_argument,	0, 'l'},
	{"forcible",	no_argument,		0, 'f'},
	{"bw-limit",	required_argument,	0, 'b'},
	{"mac-address",	required_argument,	0, 'm'},
	{"slot",	required_argument,	0, 'n'},
	{ 0, 0, 0, 0 }
};

static const struct option show_lopts[] = {
	{"statistics",	no_argument,		0, 's'},
	{"continuous",	no_argument,		0, 'S'},
	{"interval",	required_argument,	0, 'i'},
	{"parsable",	no_argument,		0, 'p'},
	{"parseable",	no_argument,		0, 'p'},
	{"extended",	no_argument,		0, 'x'},
	{"output",	required_argument,	0, 'o'},
	{"persistent",	no_argument,		0, 'P'},
	{"lacp",	no_argument,		0, 'L'},
	{ 0, 0, 0, 0 }
};

static const struct option iptun_lopts[] = {
	{"output",	required_argument,	0, 'o'},
	{"tunnel-type",	required_argument,	0, 'T'},
	{"address",	required_argument,	0, 'a'},
	{"root-dir",	required_argument,	0, 'R'},
	{"parsable",	no_argument,		0, 'p'},
	{"parseable",	no_argument,		0, 'p'},
	{"persistent",	no_argument,		0, 'P'},
	{ 0, 0, 0, 0 }
};

static char * const iptun_addropts[] = {
#define	IPTUN_LOCAL	0
	"local",
#define	IPTUN_REMOTE	1
	"remote",
	NULL};

static const struct {
	const char	*type_name;
	iptun_type_t	type_value;
} iptun_types[] = {
	{"ipv4",	IPTUN_TYPE_IPV4},
	{"ipv6",	IPTUN_TYPE_IPV6},
	{"6to4",	IPTUN_TYPE_6TO4},
	{NULL,		0}
};

static const struct option prop_longopts[] = {
	{"temporary",	no_argument,		0, 't'  },
	{"output",	required_argument,	0, 'o'  },
	{"root-dir",	required_argument,	0, 'R'  },
	{"prop",	required_argument,	0, 'p'  },
	{"parsable",	no_argument,		0, 'c'  },
	{"parseable",	no_argument,		0, 'c'  },
	{"persistent",	no_argument,		0, 'P'  },
	{ 0, 0, 0, 0 }
};

static const struct option wifi_longopts[] = {
	{"parsable",	no_argument,		0, 'p'  },
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

static const struct option showeth_lopts[] = {
	{"parsable",	no_argument,		0, 'p'	},
	{"parseable",	no_argument,		0, 'p'	},
	{"extended",	no_argument,		0, 'x'	},
	{"output",	required_argument,	0, 'o'	},
	{ 0, 0, 0, 0 }
};

static const struct option vnic_lopts[] = {
	{"temporary",	no_argument,		0, 't'	},
	{"root-dir",	required_argument,	0, 'R'	},
	{"dev",		required_argument,	0, 'd'	},
	{"mac-address",	required_argument,	0, 'm'	},
	{"cpus",	required_argument,	0, 'c'	},
	{"bw-limit",	required_argument,	0, 'b'	},
	{"slot",	required_argument,	0, 'n'	},
	{"mac-prefix",	required_argument,	0, 'r'	},
	{"vrid",	required_argument,	0, 'V'	},
	{"address-family",	required_argument,	0, 'A'	},
	{ 0, 0, 0, 0 }
};

static const struct option part_lopts[] = {
	{"temporary",	no_argument,		0, 't'  },
	{"pkey",	required_argument,	0, 'P'  },
	{"link",	required_argument,	0, 'l'  },
	{"force",	no_argument,		0, 'f'  },
	{"root-dir",	required_argument,	0, 'R'  },
	{"prop",	required_argument,	0, 'p'  },
	{ 0, 0, 0, 0 }
};

static const struct option show_part_lopts[] = {
	{"parsable",	no_argument,		0, 'p'  },
	{"parseable",	no_argument,		0, 'p'  },
	{"link",	required_argument,	0, 'l'  },
	{"persistent",	no_argument,		0, 'P'  },
	{"output",	required_argument,	0, 'o'  },
	{ 0, 0, 0, 0 }
};

static const struct option etherstub_lopts[] = {
	{"temporary",	no_argument,		0, 't'	},
	{"root-dir",	required_argument,	0, 'R'	},
	{ 0, 0, 0, 0 }
};

static const struct option usage_opts[] = {
	{"file",	required_argument,	0, 'f'	},
	{"format",	required_argument,	0, 'F'	},
	{"start",	required_argument,	0, 's'	},
	{"stop",	required_argument,	0, 'e'	},
	{ 0, 0, 0, 0 }
};

static const struct option simnet_lopts[] = {
	{"temporary",	no_argument,		0, 't'	},
	{"root-dir",	required_argument,	0, 'R'	},
	{"media",	required_argument,	0, 'm'	},
	{"peer",	required_argument,	0, 'p'	},
	{ 0, 0, 0, 0 }
};

static const struct option bridge_lopts[] = {
	{ "protect",		required_argument,	0, 'P' },
	{ "root-dir",		required_argument,	0, 'R'	},
	{ "forward-delay",	required_argument,	0, 'd'	},
	{ "force-protocol",	required_argument,	0, 'f'	},
	{ "hello-time",		required_argument,	0, 'h'	},
	{ "link",		required_argument,	0, 'l'	},
	{ "max-age",		required_argument,	0, 'm'	},
	{ "priority",		required_argument,	0, 'p'	},
	{ NULL, NULL, 0, 0 }
};

static const struct option bridge_show_lopts[] = {
	{ "forwarding", no_argument,		0, 'f' },
	{ "interval",	required_argument,	0, 'i' },
	{ "link",	no_argument,		0, 'l' },
	{ "output",	required_argument,	0, 'o' },
	{ "parsable",	no_argument,		0, 'p' },
	{ "parseable",	no_argument,		0, 'p' },
	{ "statistics",	no_argument,		0, 's' },
	{ "trill",	no_argument,		0, 't' },
	{ 0, 0, 0, 0 }
};

/*
 * structures for 'dladm show-ether'
 */
static const char *ptype[] = {LEI_ATTR_NAMES};

typedef struct ether_fields_buf_s
{
	char	eth_link[15];
	char	eth_ptype[8];
	char	eth_state[8];
	char	eth_autoneg[5];
	char	eth_spdx[31];
	char	eth_pause[6];
	char	eth_rem_fault[16];
} ether_fields_buf_t;

static const ofmt_field_t ether_fields[] = {
/* name,	field width,	offset	    callback */
{ "LINK",	16,
	offsetof(ether_fields_buf_t, eth_link), print_default_cb},
{ "PTYPE",	9,
	offsetof(ether_fields_buf_t, eth_ptype), print_default_cb},
{ "STATE",	9,
	offsetof(ether_fields_buf_t, eth_state),
	print_default_cb},
{ "AUTO",	6,
	offsetof(ether_fields_buf_t, eth_autoneg), print_default_cb},
{ "SPEED-DUPLEX", 32,
	offsetof(ether_fields_buf_t, eth_spdx), print_default_cb},
{ "PAUSE",	7,
	offsetof(ether_fields_buf_t, eth_pause), print_default_cb},
{ "REM_FAULT",	17,
	offsetof(ether_fields_buf_t, eth_rem_fault), print_default_cb},
{NULL,		0,
	0, 	NULL}}
;

typedef struct print_ether_state {
	const char	*es_link;
	boolean_t	es_parsable;
	boolean_t	es_header;
	boolean_t	es_extended;
	ofmt_handle_t	es_ofmt;
} print_ether_state_t;

/*
 * structures for 'dladm show-link -s' (print statistics)
 */
typedef enum {
	LINK_S_LINK,
	LINK_S_IPKTS,
	LINK_S_RBYTES,
	LINK_S_IERRORS,
	LINK_S_OPKTS,
	LINK_S_OBYTES,
	LINK_S_OERRORS
} link_s_field_index_t;

static const ofmt_field_t link_s_fields[] = {
/* name,	field width,	index,		callback	*/
{ "LINK",	15,		LINK_S_LINK,	print_link_stats_cb},
{ "IPACKETS",	10,		LINK_S_IPKTS,	print_link_stats_cb},
{ "RBYTES",	8,		LINK_S_RBYTES,	print_link_stats_cb},
{ "IERRORS",	10,		LINK_S_IERRORS,	print_link_stats_cb},
{ "OPACKETS",	12,		LINK_S_OPKTS,	print_link_stats_cb},
{ "OBYTES",	12,		LINK_S_OBYTES,	print_link_stats_cb},
{ "OERRORS",	8,		LINK_S_OERRORS,	print_link_stats_cb}}
;

typedef struct link_args_s {
	char		*link_s_link;
	pktsum_t	*link_s_psum;
} link_args_t;

/*
 * buffer used by print functions for show-{link,phys,vlan} commands.
 */
typedef struct link_fields_buf_s {
	char link_name[MAXLINKNAMELEN];
	char link_class[DLADM_STRSIZE];
	char link_mtu[11];
	char link_state[DLADM_STRSIZE];
	char link_bridge[MAXLINKNAMELEN * MAXPORT];
	char link_over[MAXLINKNAMELEN * MAXPORT];
	char link_phys_state[DLADM_STRSIZE];
	char link_phys_media[DLADM_STRSIZE];
	char link_phys_speed[DLADM_STRSIZE];
	char link_phys_duplex[DLPI_LINKNAME_MAX];
	char link_phys_device[DLPI_LINKNAME_MAX];
	char link_flags[6];
	char link_vlan_vid[6];
} link_fields_buf_t;

/*
 * structures for 'dladm show-link'
 */
static const ofmt_field_t link_fields[] = {
/* name,	field width,	index,	callback */
{ "LINK",	12,
	offsetof(link_fields_buf_t, link_name), print_default_cb},
{ "CLASS",	10,
	offsetof(link_fields_buf_t, link_class), print_default_cb},
{ "MTU",	7,
	offsetof(link_fields_buf_t, link_mtu), print_default_cb},
{ "STATE",	9,
	offsetof(link_fields_buf_t, link_state), print_default_cb},
{ "BRIDGE",	11,
    offsetof(link_fields_buf_t, link_bridge), print_default_cb},
{ "OVER",	30,
	offsetof(link_fields_buf_t, link_over), print_default_cb},
{ NULL,		0, 0, NULL}}
;

/*
 * structures for 'dladm show-aggr'
 */
typedef struct laggr_fields_buf_s {
	char laggr_name[DLPI_LINKNAME_MAX];
	char laggr_policy[9];
	char laggr_addrpolicy[ETHERADDRL * 3 + 3];
	char laggr_lacpactivity[14];
	char laggr_lacptimer[DLADM_STRSIZE];
	char laggr_flags[7];
} laggr_fields_buf_t;

typedef struct laggr_args_s {
	int			laggr_lport; /* -1 indicates the aggr itself */
	const char 		*laggr_link;
	dladm_aggr_grp_attr_t	*laggr_ginfop;
	dladm_status_t		*laggr_status;
	pktsum_t		*laggr_pktsumtot; /* -s only */
	pktsum_t		*laggr_diffstats; /* -s only */
	boolean_t		laggr_parsable;
} laggr_args_t;

static const ofmt_field_t laggr_fields[] = {
/* name,	field width,	offset,	callback */
{ "LINK",	16,
	offsetof(laggr_fields_buf_t, laggr_name), print_default_cb},
{ "POLICY",	9,
	offsetof(laggr_fields_buf_t, laggr_policy), print_default_cb},
{ "ADDRPOLICY",	ETHERADDRL * 3 + 3,
	offsetof(laggr_fields_buf_t, laggr_addrpolicy), print_default_cb},
{ "LACPACTIVITY", 14,
	offsetof(laggr_fields_buf_t, laggr_lacpactivity), print_default_cb},
{ "LACPTIMER",	12,
	offsetof(laggr_fields_buf_t, laggr_lacptimer), print_default_cb},
{ "FLAGS",	8,
	offsetof(laggr_fields_buf_t, laggr_flags), print_default_cb},
{ NULL,		0, 0, NULL}}
;

/*
 * structures for 'dladm show-aggr -x'.
 */
typedef enum {
	AGGR_X_LINK,
	AGGR_X_PORT,
	AGGR_X_SPEED,
	AGGR_X_DUPLEX,
	AGGR_X_STATE,
	AGGR_X_ADDRESS,
	AGGR_X_PORTSTATE
} aggr_x_field_index_t;

static const ofmt_field_t aggr_x_fields[] = {
/* name,	field width,	index		callback */
{ "LINK",	12,	AGGR_X_LINK,		print_xaggr_cb},
{ "PORT",	15,	AGGR_X_PORT,		print_xaggr_cb},
{ "SPEED",	5,	AGGR_X_SPEED,		print_xaggr_cb},
{ "DUPLEX",	10,	AGGR_X_DUPLEX,		print_xaggr_cb},
{ "STATE",	10,	AGGR_X_STATE,		print_xaggr_cb},
{ "ADDRESS",	19,	AGGR_X_ADDRESS,		print_xaggr_cb},
{ "PORTSTATE",	16,	AGGR_X_PORTSTATE,	print_xaggr_cb},
{ NULL,		0,	0,			NULL}}
;

/*
 * structures for 'dladm show-aggr -s'.
 */
typedef enum {
	AGGR_S_LINK,
	AGGR_S_PORT,
	AGGR_S_IPKTS,
	AGGR_S_RBYTES,
	AGGR_S_OPKTS,
	AGGR_S_OBYTES,
	AGGR_S_IPKTDIST,
	AGGR_S_OPKTDIST
} aggr_s_field_index_t;

static const ofmt_field_t aggr_s_fields[] = {
{ "LINK",		12,	AGGR_S_LINK, print_aggr_stats_cb},
{ "PORT",		10,	AGGR_S_PORT, print_aggr_stats_cb},
{ "IPACKETS",		8,	AGGR_S_IPKTS, print_aggr_stats_cb},
{ "RBYTES",		8,	AGGR_S_RBYTES, print_aggr_stats_cb},
{ "OPACKETS",		8,	AGGR_S_OPKTS, print_aggr_stats_cb},
{ "OBYTES",		8,	AGGR_S_OBYTES, print_aggr_stats_cb},
{ "IPKTDIST",		9,	AGGR_S_IPKTDIST, print_aggr_stats_cb},
{ "OPKTDIST",		15,	AGGR_S_OPKTDIST, print_aggr_stats_cb},
{ NULL,			0,	0,		NULL}}
;

/*
 * structures for 'dladm show-aggr -L'.
 */
typedef enum {
	AGGR_L_LINK,
	AGGR_L_PORT,
	AGGR_L_AGGREGATABLE,
	AGGR_L_SYNC,
	AGGR_L_COLL,
	AGGR_L_DIST,
	AGGR_L_DEFAULTED,
	AGGR_L_EXPIRED
} aggr_l_field_index_t;

static const ofmt_field_t aggr_l_fields[] = {
/* name,		field width,	index */
{ "LINK",		12,	AGGR_L_LINK,		print_lacp_cb},
{ "PORT",		13,	AGGR_L_PORT,		print_lacp_cb},
{ "AGGREGATABLE",	13,	AGGR_L_AGGREGATABLE,	print_lacp_cb},
{ "SYNC",		5,	AGGR_L_SYNC,		print_lacp_cb},
{ "COLL",		5,	AGGR_L_COLL,		print_lacp_cb},
{ "DIST",		5,	AGGR_L_DIST,		print_lacp_cb},
{ "DEFAULTED",		10,	AGGR_L_DEFAULTED,	print_lacp_cb},
{ "EXPIRED",		15,	AGGR_L_EXPIRED,		print_lacp_cb},
{ NULL,			0,	0,			NULL}}
;

/*
 * structures for 'dladm show-phys'
 */

static const ofmt_field_t phys_fields[] = {
/* name,	field width,	offset */
{ "LINK",	13,
	offsetof(link_fields_buf_t, link_name), print_default_cb},
{ "MEDIA",	21,
	offsetof(link_fields_buf_t, link_phys_media), print_default_cb},
{ "STATE",	11,
	offsetof(link_fields_buf_t, link_phys_state), print_default_cb},
{ "SPEED",	7,
	offsetof(link_fields_buf_t, link_phys_speed), print_default_cb},
{ "DUPLEX",	10,
	offsetof(link_fields_buf_t, link_phys_duplex), print_default_cb},
{ "DEVICE",	13,
	offsetof(link_fields_buf_t, link_phys_device), print_default_cb},
{ "FLAGS",	7,
	offsetof(link_fields_buf_t, link_flags), print_default_cb},
{ NULL,		0, NULL, 0}}
;

/*
 * structures for 'dladm show-phys -m'
 */

typedef enum {
	PHYS_M_LINK,
	PHYS_M_SLOT,
	PHYS_M_ADDRESS,
	PHYS_M_INUSE,
	PHYS_M_CLIENT
} phys_m_field_index_t;

static const ofmt_field_t phys_m_fields[] = {
/* name,	field width,	offset */
{ "LINK",	13,	PHYS_M_LINK,	print_phys_one_mac_cb},
{ "SLOT",	9,	PHYS_M_SLOT,	print_phys_one_mac_cb},
{ "ADDRESS",	19,	PHYS_M_ADDRESS,	print_phys_one_mac_cb},
{ "INUSE",	5,	PHYS_M_INUSE,	print_phys_one_mac_cb},
{ "CLIENT",	13,	PHYS_M_CLIENT,	print_phys_one_mac_cb},
{ NULL,		0,	0,		NULL}}
;

/*
 * structures for 'dladm show-phys -H'
 */

typedef enum {
	PHYS_H_LINK,
	PHYS_H_RINGTYPE,
	PHYS_H_RINGS,
	PHYS_H_CLIENTS
} phys_h_field_index_t;

#define	RINGSTRLEN	21

static const ofmt_field_t phys_h_fields[] = {
{ "LINK",	13,	PHYS_H_LINK,	print_phys_one_hwgrp_cb},
{ "RINGTYPE",	9,	PHYS_H_RINGTYPE,	print_phys_one_hwgrp_cb},
{ "RINGS",	RINGSTRLEN,	PHYS_H_RINGS,	print_phys_one_hwgrp_cb},
{ "CLIENTS",	24,	PHYS_H_CLIENTS,	print_phys_one_hwgrp_cb},
{ NULL,		0,	0,		NULL}}
;

/*
 * structures for 'dladm show-vlan'
 */
static const ofmt_field_t vlan_fields[] = {
{ "LINK",	16,
	offsetof(link_fields_buf_t, link_name), print_default_cb},
{ "VID",	9,
	offsetof(link_fields_buf_t, link_vlan_vid), print_default_cb},
{ "OVER",	13,
	offsetof(link_fields_buf_t, link_over), print_default_cb},
{ "FLAGS",	7,
	offsetof(link_fields_buf_t, link_flags), print_default_cb},
{ NULL,		0, 0, NULL}}
;

/*
 * structures common to 'dladm scan-wifi' and 'dladm show-wifi'
 * callback will be determined in parse_wifi_fields.
 */
static ofmt_field_t wifi_common_fields[] = {
{ "LINK",	11, 0,				NULL},
{ "ESSID",	20, DLADM_WLAN_ATTR_ESSID,	NULL},
{ "BSSID",	18, DLADM_WLAN_ATTR_BSSID,	NULL},
{ "IBSSID",	18, DLADM_WLAN_ATTR_BSSID,	NULL},
{ "MODE",	7,  DLADM_WLAN_ATTR_MODE,	NULL},
{ "SPEED",	7,  DLADM_WLAN_ATTR_SPEED,	NULL},
{ "BSSTYPE",	9,  DLADM_WLAN_ATTR_BSSTYPE,	NULL},
{ "SEC",	7,  DLADM_WLAN_ATTR_SECMODE,	NULL},
{ "STRENGTH",	11, DLADM_WLAN_ATTR_STRENGTH,	NULL},
{ NULL,		0,  0,				NULL}};

/*
 * the 'show-wifi' command supports all the fields in wifi_common_fields
 * plus the AUTH and STATUS fields.
 */
static ofmt_field_t wifi_show_fields[A_CNT(wifi_common_fields) + 2] = {
{ "AUTH",	9,  DLADM_WLAN_ATTR_AUTH,	NULL},
{ "STATUS",	18, DLADM_WLAN_LINKATTR_STATUS,	print_wifi_status_cb},
/* copy wifi_common_fields here */
};

static char *all_scan_wifi_fields =
	"link,essid,bssid,sec,strength,mode,speed,bsstype";
static char *all_show_wifi_fields =
	"link,status,essid,sec,strength,mode,speed,auth,bssid,bsstype";
static char *def_scan_wifi_fields =
	"link,essid,bssid,sec,strength,mode,speed";
static char *def_show_wifi_fields =
	"link,status,essid,sec,strength,mode,speed";

/*
 * structures for 'dladm show-linkprop'
 */
typedef enum {
	LINKPROP_LINK,
	LINKPROP_PROPERTY,
	LINKPROP_PERM,
	LINKPROP_VALUE,
	LINKPROP_DEFAULT,
	LINKPROP_POSSIBLE
} linkprop_field_index_t;

static const ofmt_field_t linkprop_fields[] = {
/* name,	field width,  index */
{ "LINK",	13,	LINKPROP_LINK,		print_linkprop_cb},
{ "PROPERTY",	16,	LINKPROP_PROPERTY,	print_linkprop_cb},
{ "PERM",	5,	LINKPROP_PERM,		print_linkprop_cb},
{ "VALUE",	15,	LINKPROP_VALUE,		print_linkprop_cb},
{ "DEFAULT",	15,	LINKPROP_DEFAULT,	print_linkprop_cb},
{ "POSSIBLE",	20,	LINKPROP_POSSIBLE,	print_linkprop_cb},
{ NULL,		0,	0,			NULL}}
;

#define	MAX_PROP_LINE		512

typedef struct show_linkprop_state {
	char			ls_link[MAXLINKNAMELEN];
	char			*ls_line;
	char			**ls_propvals;
	dladm_arg_list_t	*ls_proplist;
	boolean_t		ls_parsable;
	boolean_t		ls_persist;
	boolean_t		ls_header;
	dladm_status_t		ls_status;
	dladm_status_t		ls_retstatus;
	ofmt_handle_t		ls_ofmt;
} show_linkprop_state_t;

typedef struct set_linkprop_state {
	const char		*ls_name;
	boolean_t		ls_reset;
	boolean_t		ls_temp;
	dladm_status_t		ls_status;
} set_linkprop_state_t;

typedef struct linkprop_args_s {
	show_linkprop_state_t	*ls_state;
	char			*ls_propname;
	datalink_id_t		ls_linkid;
} linkprop_args_t;

/*
 * structures for 'dladm show-secobj'
 */
typedef struct secobj_fields_buf_s {
	char			ss_obj_name[DLADM_SECOBJ_VAL_MAX];
	char			ss_class[20];
	char			ss_val[30];
} secobj_fields_buf_t;

static const ofmt_field_t secobj_fields[] = {
{ "OBJECT",	21,
	offsetof(secobj_fields_buf_t, ss_obj_name), print_default_cb},
{ "CLASS",	21,
	offsetof(secobj_fields_buf_t, ss_class), print_default_cb},
{ "VALUE",	31,
	offsetof(secobj_fields_buf_t, ss_val), print_default_cb},
{ NULL,		0, 0, NULL}}
;

/*
 * structures for 'dladm show-vnic'
 */
typedef struct vnic_fields_buf_s
{
	char vnic_link[DLPI_LINKNAME_MAX];
	char vnic_over[DLPI_LINKNAME_MAX];
	char vnic_speed[6];
	char vnic_macaddr[18];
	char vnic_macaddrtype[19];
	char vnic_vid[6];
} vnic_fields_buf_t;

static const ofmt_field_t vnic_fields[] = {
{ "LINK",		13,
	offsetof(vnic_fields_buf_t, vnic_link),	print_default_cb},
{ "OVER",		13,
	offsetof(vnic_fields_buf_t, vnic_over),	print_default_cb},
{ "SPEED",		7,
	offsetof(vnic_fields_buf_t, vnic_speed), print_default_cb},
{ "MACADDRESS",		18,
	offsetof(vnic_fields_buf_t, vnic_macaddr), print_default_cb},
{ "MACADDRTYPE",	20,
	offsetof(vnic_fields_buf_t, vnic_macaddrtype), print_default_cb},
{ "VID",		7,
	offsetof(vnic_fields_buf_t, vnic_vid), print_default_cb},
{ NULL,			0, 0, NULL}}
;

/*
 * structures for 'dladm show-ib'
 */
typedef struct ib_fields_buf_s
{
	char ib_link[DLPI_LINKNAME_MAX];
	char ib_hcaguid[17];
	char ib_portguid[17];
	char ib_portnum[4];
	char ib_state[6];
	char ib_pkeys[MAXPKEYSTRSZ];
} ib_fields_buf_t;

static const ofmt_field_t ib_fields[] = {
{ "LINK",		13,
	offsetof(ib_fields_buf_t, ib_link),	print_default_cb},
{ "HCAGUID",		IBGUIDSTRLEN,
	offsetof(ib_fields_buf_t, ib_hcaguid),	print_default_cb},
{ "PORTGUID",		IBGUIDSTRLEN,
	offsetof(ib_fields_buf_t, ib_portguid),	print_default_cb},
{ "PORT",		IBPORTSTRLEN,
	offsetof(ib_fields_buf_t, ib_portnum), print_default_cb},
{ "STATE",		7,
	offsetof(ib_fields_buf_t, ib_state), print_default_cb},
{ "PKEYS",	18,
	offsetof(ib_fields_buf_t, ib_pkeys), print_default_cb},
{ NULL,			0, 0, NULL}};

/*
 * structures for 'dladm show-part'
 */
typedef struct part_fields_buf_s
{
	char part_link[DLPI_LINKNAME_MAX];
	char part_pkey[5];
	char part_over[DLPI_LINKNAME_MAX];
	char part_state[8];
	char part_flags[5];
} part_fields_buf_t;

static const ofmt_field_t part_fields[] = {
{ "LINK",		13,
	offsetof(part_fields_buf_t, part_link),	print_default_cb},
{ "PKEY",		MAXPKEYLEN,
	offsetof(part_fields_buf_t, part_pkey),	print_default_cb},
{ "OVER",		13,
	offsetof(part_fields_buf_t, part_over), print_default_cb},
{ "STATE",		9,
	offsetof(part_fields_buf_t, part_state), print_default_cb},
{ "FLAGS",	5,
	offsetof(part_fields_buf_t, part_flags), print_default_cb},
{ NULL,			0, 0, NULL}};

/*
 * structures for 'dladm show-simnet'
 */
typedef struct simnet_fields_buf_s
{
	char simnet_name[DLPI_LINKNAME_MAX];
	char simnet_media[DLADM_STRSIZE];
	char simnet_macaddr[18];
	char simnet_otherlink[DLPI_LINKNAME_MAX];
} simnet_fields_buf_t;

static const ofmt_field_t simnet_fields[] = {
{ "LINK",		12,
	offsetof(simnet_fields_buf_t, simnet_name), print_default_cb},
{ "MEDIA",		20,
	offsetof(simnet_fields_buf_t, simnet_media), print_default_cb},
{ "MACADDRESS",		18,
	offsetof(simnet_fields_buf_t, simnet_macaddr), print_default_cb},
{ "OTHERLINK",		12,
	offsetof(simnet_fields_buf_t, simnet_otherlink), print_default_cb},
{ NULL,			0, 0, NULL}}
;

/*
 * structures for 'dladm show-usage'
 */

typedef struct  usage_fields_buf_s {
	char	usage_link[12];
	char	usage_duration[10];
	char	usage_ipackets[9];
	char	usage_rbytes[10];
	char	usage_opackets[9];
	char	usage_obytes[10];
	char	usage_bandwidth[14];
} usage_fields_buf_t;

static const ofmt_field_t usage_fields[] = {
{ "LINK",	13,
	offsetof(usage_fields_buf_t, usage_link), print_default_cb},
{ "DURATION",	11,
	offsetof(usage_fields_buf_t, usage_duration), print_default_cb},
{ "IPACKETS",	10,
	offsetof(usage_fields_buf_t, usage_ipackets), print_default_cb},
{ "RBYTES",	11,
	offsetof(usage_fields_buf_t, usage_rbytes), print_default_cb},
{ "OPACKETS",	10,
	offsetof(usage_fields_buf_t, usage_opackets), print_default_cb},
{ "OBYTES",	11,
	offsetof(usage_fields_buf_t, usage_obytes), print_default_cb},
{ "BANDWIDTH",	15,
	offsetof(usage_fields_buf_t, usage_bandwidth), print_default_cb},
{ NULL,		0, 0, NULL}}
;


/*
 * structures for 'dladm show-usage link'
 */

typedef struct  usage_l_fields_buf_s {
	char	usage_l_link[12];
	char	usage_l_stime[13];
	char	usage_l_etime[13];
	char	usage_l_rbytes[8];
	char	usage_l_obytes[8];
	char	usage_l_bandwidth[14];
} usage_l_fields_buf_t;

static const ofmt_field_t usage_l_fields[] = {
/* name,	field width,	offset */
{ "LINK",	13,
	offsetof(usage_l_fields_buf_t, usage_l_link), print_default_cb},
{ "START",	14,
	offsetof(usage_l_fields_buf_t, usage_l_stime), print_default_cb},
{ "END",	14,
	offsetof(usage_l_fields_buf_t, usage_l_etime), print_default_cb},
{ "RBYTES",	9,
	offsetof(usage_l_fields_buf_t, usage_l_rbytes), print_default_cb},
{ "OBYTES",	9,
	offsetof(usage_l_fields_buf_t, usage_l_obytes), print_default_cb},
{ "BANDWIDTH",	15,
	offsetof(usage_l_fields_buf_t, usage_l_bandwidth), print_default_cb},
{ NULL,		0, 0, NULL}}
;

/* IPTUN_*FLAG_INDEX values are indices into iptun_flags below. */
enum { IPTUN_SFLAG_INDEX, IPTUN_IFLAG_INDEX, IPTUN_NUM_FLAGS };

/*
 * structures for 'dladm show-iptun'
 */
typedef struct iptun_fields_buf_s {
	char	iptun_name[MAXLINKNAMELEN];
	char	iptun_type[5];
	char	iptun_laddr[NI_MAXHOST];
	char	iptun_raddr[NI_MAXHOST];
	char	iptun_flags[IPTUN_NUM_FLAGS + 1];
} iptun_fields_buf_t;

static const ofmt_field_t iptun_fields[] = {
{ "LINK",	16,
	offsetof(iptun_fields_buf_t, iptun_name), print_default_cb },
{ "TYPE",	6,
	offsetof(iptun_fields_buf_t, iptun_type), print_default_cb },
{ "FLAGS",	7,
	offsetof(iptun_fields_buf_t, iptun_flags), print_default_cb },
{ "LOCAL",	20,
	offsetof(iptun_fields_buf_t, iptun_laddr), print_default_cb },
{ "REMOTE",	20,
	offsetof(iptun_fields_buf_t, iptun_raddr), print_default_cb },
{ NULL, 0, 0, NULL}
};

/*
 * structures for 'dladm show-bridge'.  These are based on sections 14.8.1.1.3
 * and 14.8.1.2.2 of IEEE 802.1D-2004.
 */
typedef struct bridge_fields_buf_s {
	char bridge_name[MAXLINKNAMELEN]; /* 14.4.1.2.3(b) */
	char bridge_protect[7];		/* stp or trill */
	char bridge_address[24];	/* 17.18.3, 7.12.5, 14.4.1.2.3(a) */
	char bridge_priority[7];	/* 17.18.3 9.2.5 - only upper 4 bits */
	char bridge_bmaxage[7];		/* 17.18.4 configured */
	char bridge_bhellotime[7];	/* 17.18.4 configured */
	char bridge_bfwddelay[7];	/* 17.18.4 configured */
	char bridge_forceproto[3];	/* 17.13.4 configured */
	char bridge_tctime[12];		/* 14.8.1.1.3(b) */
	char bridge_tccount[12];	/* 17.17.8 */
	char bridge_tchange[12];	/* 17.17.8 */
	char bridge_desroot[24];	/* 17.18.6 priority "/" MAC */
	char bridge_rootcost[12];	/* 17.18.6 */
	char bridge_rootport[12];	/* 17.18.6 */
	char bridge_maxage[7];		/* 17.18.7 for root */
	char bridge_hellotime[7];	/* 17.13.6 for root */
	char bridge_fwddelay[7];	/* 17.13.5 for root */
	char bridge_holdtime[12];	/* 17.13.12 for root */
} bridge_fields_buf_t;

static ofmt_field_t bridge_fields[] = {
/* name,	field width,	offset,	callback	*/
{ "BRIDGE",	12,
    offsetof(bridge_fields_buf_t, bridge_name), print_default_cb },
{ "PROTECT",	8,
    offsetof(bridge_fields_buf_t, bridge_protect), print_default_cb },
{ "ADDRESS",	19,
    offsetof(bridge_fields_buf_t, bridge_address), print_default_cb },
{ "PRIORITY",	9,
    offsetof(bridge_fields_buf_t, bridge_priority), print_default_cb },
{ "BMAXAGE",	8,
    offsetof(bridge_fields_buf_t, bridge_bmaxage), print_default_cb },
{ "BHELLOTIME",	11,
    offsetof(bridge_fields_buf_t, bridge_bhellotime), print_default_cb },
{ "BFWDDELAY",	10,
    offsetof(bridge_fields_buf_t, bridge_bfwddelay), print_default_cb },
{ "FORCEPROTO",	11,
    offsetof(bridge_fields_buf_t, bridge_forceproto), print_default_cb },
{ "TCTIME",	10,
    offsetof(bridge_fields_buf_t, bridge_tctime), print_default_cb },
{ "TCCOUNT",	10,
    offsetof(bridge_fields_buf_t, bridge_tccount), print_default_cb },
{ "TCHANGE",	10,
    offsetof(bridge_fields_buf_t, bridge_tchange), print_default_cb },
{ "DESROOT",	23,
    offsetof(bridge_fields_buf_t, bridge_desroot), print_default_cb },
{ "ROOTCOST",	11,
    offsetof(bridge_fields_buf_t, bridge_rootcost), print_default_cb },
{ "ROOTPORT",	11,
    offsetof(bridge_fields_buf_t, bridge_rootport), print_default_cb },
{ "MAXAGE",	8,
    offsetof(bridge_fields_buf_t, bridge_maxage), print_default_cb },
{ "HELLOTIME",	10,
    offsetof(bridge_fields_buf_t, bridge_hellotime), print_default_cb },
{ "FWDDELAY",	9,
    offsetof(bridge_fields_buf_t, bridge_fwddelay), print_default_cb },
{ "HOLDTIME",	9,
    offsetof(bridge_fields_buf_t, bridge_holdtime), print_default_cb },
{ NULL,		0, 0, NULL}};

/*
 * structures for 'dladm show-bridge -l'.  These are based on 14.4.1.2.3 and
 * 14.8.2.1.3 of IEEE 802.1D-2004.
 */
typedef struct bridge_link_fields_buf_s {
	char bridgel_link[MAXLINKNAMELEN];
	char bridgel_index[7];			/* 14.4.1.2.3(d1) */
	char bridgel_state[11];			/* 14.8.2.1.3(b) */
	char bridgel_uptime[7];			/* 14.8.2.1.3(a) */
	char bridgel_opercost[7]		/* 14.8.2.1.3(d) */;
	char bridgel_operp2p[4];		/* 14.8.2.1.3(p) */
	char bridgel_operedge[4];		/* 14.8.2.1.3(k) */
	char bridgel_desroot[23];		/* 14.8.2.1.3(e) */
	char bridgel_descost[12];		/* 14.8.2.1.3(f) */
	char bridgel_desbridge[23];		/* 14.8.2.1.3(g) */
	char bridgel_desport[7];		/* 14.8.2.1.3(h) */
	char bridgel_tcack[4];			/* 14.8.2.1.3(i) */
} bridge_link_fields_buf_t;

static ofmt_field_t bridge_link_fields[] = {
/* name,	field width,	offset,	callback	*/
{ "LINK",		12,
    offsetof(bridge_link_fields_buf_t, bridgel_link), print_default_cb },
{ "INDEX",	8,
    offsetof(bridge_link_fields_buf_t, bridgel_index), print_default_cb },
{ "STATE",	12,
    offsetof(bridge_link_fields_buf_t, bridgel_state), print_default_cb },
{ "UPTIME",	8,
    offsetof(bridge_link_fields_buf_t, bridgel_uptime), print_default_cb },
{ "OPERCOST",	9,
    offsetof(bridge_link_fields_buf_t, bridgel_opercost), print_default_cb },
{ "OPERP2P",	8,
    offsetof(bridge_link_fields_buf_t, bridgel_operp2p), print_default_cb },
{ "OPEREDGE",	9,
    offsetof(bridge_link_fields_buf_t, bridgel_operedge), print_default_cb },
{ "DESROOT",	22,
    offsetof(bridge_link_fields_buf_t, bridgel_desroot), print_default_cb },
{ "DESCOST",	11,
    offsetof(bridge_link_fields_buf_t, bridgel_descost), print_default_cb },
{ "DESBRIDGE",	22,
    offsetof(bridge_link_fields_buf_t, bridgel_desbridge), print_default_cb },
{ "DESPORT",	8,
    offsetof(bridge_link_fields_buf_t, bridgel_desport), print_default_cb },
{ "TCACK",	6,
    offsetof(bridge_link_fields_buf_t, bridgel_tcack), print_default_cb },
{ NULL,		0, 0, NULL}};

/*
 * structures for 'dladm show-bridge -s'.  These are not based on IEEE
 * 802.1D-2004.
 */
#define	ULONG_DIG	(((sizeof (ulong_t) * NBBY) * 3 / 10) + 1)
#define	UINT64_DIG	(((sizeof (uint64_t) * NBBY) * 3 / 10) + 1)
typedef struct bridge_statfields_buf_s {
	char bridges_name[MAXLINKNAMELEN];
	char bridges_drops[UINT64_DIG];
	char bridges_forwards[UINT64_DIG];
	char bridges_mbcast[UINT64_DIG];
	char bridges_unknown[UINT64_DIG];
	char bridges_recv[UINT64_DIG];
	char bridges_sent[UINT64_DIG];
} bridge_statfields_buf_t;

static ofmt_field_t bridge_statfields[] = {
/* name,	field width,	offset,	callback	*/
{ "BRIDGE",	12,
    offsetof(bridge_statfields_buf_t, bridges_name), print_default_cb },
{ "DROPS",	12,
    offsetof(bridge_statfields_buf_t, bridges_drops), print_default_cb },
{ "FORWARDS",	12,
    offsetof(bridge_statfields_buf_t, bridges_forwards), print_default_cb },
{ "MBCAST",	12,
    offsetof(bridge_statfields_buf_t, bridges_mbcast), print_default_cb },
{ "UNKNOWN",	12,
    offsetof(bridge_statfields_buf_t, bridges_unknown), print_default_cb },
{ "RECV",	12,
    offsetof(bridge_statfields_buf_t, bridges_recv), print_default_cb },
{ "SENT",	12,
    offsetof(bridge_statfields_buf_t, bridges_sent), print_default_cb },
{ NULL,		0, 0, NULL}};

/*
 * structures for 'dladm show-bridge -s -l'.  These are based in part on
 * section 14.6.1.1.3 of IEEE 802.1D-2004.
 */
typedef struct bridge_link_statfields_buf_s {
	char bridgels_link[MAXLINKNAMELEN];
	char bridgels_cfgbpdu[ULONG_DIG];
	char bridgels_tcnbpdu[ULONG_DIG];
	char bridgels_rstpbpdu[ULONG_DIG];
	char bridgels_txbpdu[ULONG_DIG];
	char bridgels_drops[UINT64_DIG];	/* 14.6.1.1.3(d) */
	char bridgels_recv[UINT64_DIG];		/* 14.6.1.1.3(a) */
	char bridgels_xmit[UINT64_DIG];		/* 14.6.1.1.3(c) */
} bridge_link_statfields_buf_t;

static ofmt_field_t bridge_link_statfields[] = {
/* name,	field width,	offset,	callback	*/
{ "LINK",	12,
    offsetof(bridge_link_statfields_buf_t, bridgels_link), print_default_cb },
{ "CFGBPDU",	9,
    offsetof(bridge_link_statfields_buf_t, bridgels_cfgbpdu),
    print_default_cb },
{ "TCNBPDU",	9,
    offsetof(bridge_link_statfields_buf_t, bridgels_tcnbpdu),
    print_default_cb },
{ "RSTPBPDU",	9,
    offsetof(bridge_link_statfields_buf_t, bridgels_rstpbpdu),
    print_default_cb },
{ "TXBPDU",	9,
    offsetof(bridge_link_statfields_buf_t, bridgels_txbpdu), print_default_cb },
{ "DROPS",	9,
    offsetof(bridge_link_statfields_buf_t, bridgels_drops), print_default_cb },
{ "RECV",	9,
    offsetof(bridge_link_statfields_buf_t, bridgels_recv), print_default_cb },
{ "XMIT",	9,
    offsetof(bridge_link_statfields_buf_t, bridgels_xmit), print_default_cb },
{ NULL,		0, 0, NULL}};

/*
 * structures for 'dladm show-bridge -f'.  These are based in part on
 * section  14.7.6.3.3 of IEEE 802.1D-2004.
 */
typedef struct bridge_fwd_fields_buf_s {
	char bridgef_dest[18];			/* 14.7.6.3.3(a) */
	char bridgef_age[8];
	char bridgef_flags[6];
	char bridgef_output[MAXLINKNAMELEN];	/* 14.7.6.3.3(c) */
} bridge_fwd_fields_buf_t;

static ofmt_field_t bridge_fwd_fields[] = {
/* name,	field width,	offset,	callback	*/
{ "DEST",	17,
    offsetof(bridge_fwd_fields_buf_t, bridgef_dest), print_default_cb },
{ "AGE",	7,
    offsetof(bridge_fwd_fields_buf_t, bridgef_age), print_default_cb },
{ "FLAGS",	6,
    offsetof(bridge_fwd_fields_buf_t, bridgef_flags), print_default_cb },
{ "OUTPUT",	12,
    offsetof(bridge_fwd_fields_buf_t, bridgef_output), print_default_cb },
{ NULL,		0, 0, NULL}};

/*
 * structures for 'dladm show-bridge -t'.
 */
typedef struct bridge_trill_fields_buf_s {
	char bridget_nick[6];
	char bridget_flags[6];
	char bridget_link[MAXLINKNAMELEN];
	char bridget_nexthop[18];
} bridge_trill_fields_buf_t;

static ofmt_field_t bridge_trill_fields[] = {
/* name,	field width,	offset,	callback	*/
{ "NICK",	5,
    offsetof(bridge_trill_fields_buf_t, bridget_nick), print_default_cb },
{ "FLAGS",	6,
    offsetof(bridge_trill_fields_buf_t, bridget_flags), print_default_cb },
{ "LINK",	12,
    offsetof(bridge_trill_fields_buf_t, bridget_link), print_default_cb },
{ "NEXTHOP",	17,
    offsetof(bridge_trill_fields_buf_t, bridget_nexthop), print_default_cb },
{ NULL,		0, 0, NULL}};

static char *progname;
static sig_atomic_t signalled;

/*
 * Handle to libdladm.  Opened in main() before the sub-command
 * specific function is called.
 */
static dladm_handle_t handle = NULL;

#define	DLADM_ETHERSTUB_NAME	"etherstub"
#define	DLADM_IS_ETHERSTUB(id)	(id == DATALINK_INVALID_LINKID)

static void
usage(void)
{
	int	i;
	cmd_t	*cmdp;
	(void) fprintf(stderr, gettext("usage:  dladm <subcommand> <args> ..."
	    "\n"));
	for (i = 0; i < sizeof (cmds) / sizeof (cmds[0]); i++) {
		cmdp = &cmds[i];
		if (cmdp->c_usage != NULL)
			(void) fprintf(stderr, "%s\n", gettext(cmdp->c_usage));
	}

	/* close dladm handle if it was opened */
	if (handle != NULL)
		dladm_close(handle);

	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	int	i;
	cmd_t	*cmdp;
	dladm_status_t status;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	progname = argv[0];

	if (argc < 2)
		usage();

	for (i = 0; i < sizeof (cmds) / sizeof (cmds[0]); i++) {
		cmdp = &cmds[i];
		if (strcmp(argv[1], cmdp->c_name) == 0) {
			/* Open the libdladm handle */
			if ((status = dladm_open(&handle)) != DLADM_STATUS_OK) {
				die_dlerr(status,
				    "could not open /dev/dld");
			}

			cmdp->c_fn(argc - 1, &argv[1], cmdp->c_usage);

			dladm_close(handle);
			return (EXIT_SUCCESS);
		}
	}

	(void) fprintf(stderr, gettext("%s: unknown subcommand '%s'\n"),
	    progname, argv[1]);
	usage();
	return (EXIT_FAILURE);
}

/*ARGSUSED*/
static int
show_usage_date(dladm_usage_t *usage, void *arg)
{
	show_usage_state_t	*state = (show_usage_state_t *)arg;
	time_t			stime;
	char			timebuf[20];
	dladm_status_t		status;
	uint32_t		flags;

	/*
	 * Only show usage information for existing links unless '-a'
	 * is specified.
	 */
	if (!state->us_showall) {
		if ((status = dladm_name2info(handle, usage->du_name,
		    NULL, &flags, NULL, NULL)) != DLADM_STATUS_OK) {
			return (status);
		}
		if ((flags & DLADM_OPT_ACTIVE) == 0)
			return (DLADM_STATUS_LINKINVAL);
	}

	stime = usage->du_stime;
	(void) strftime(timebuf, sizeof (timebuf), "%m/%d/%Y",
	    localtime(&stime));
	(void) printf("%s\n", timebuf);

	return (DLADM_STATUS_OK);
}

static int
show_usage_time(dladm_usage_t *usage, void *arg)
{
	show_usage_state_t	*state = (show_usage_state_t *)arg;
	char			buf[DLADM_STRSIZE];
	usage_l_fields_buf_t 	ubuf;
	time_t			time;
	double			bw;
	dladm_status_t		status;
	uint32_t		flags;

	/*
	 * Only show usage information for existing links unless '-a'
	 * is specified.
	 */
	if (!state->us_showall) {
		if ((status = dladm_name2info(handle, usage->du_name,
		    NULL, &flags, NULL, NULL)) != DLADM_STATUS_OK) {
			return (status);
		}
		if ((flags & DLADM_OPT_ACTIVE) == 0)
			return (DLADM_STATUS_LINKINVAL);
	}

	if (state->us_plot) {
		if (!state->us_printheader) {
			if (state->us_first) {
				(void) printf("# Time");
				state->us_first = B_FALSE;
			}
			(void) printf(" %s", usage->du_name);
			if (usage->du_last) {
				(void) printf("\n");
				state->us_first = B_TRUE;
				state->us_printheader = B_TRUE;
			}
		} else {
			if (state->us_first) {
				time = usage->du_etime;
				(void) strftime(buf, sizeof (buf), "%T",
				    localtime(&time));
				state->us_first = B_FALSE;
				(void) printf("%s", buf);
			}
			bw = (double)usage->du_bandwidth/1000;
			(void) printf(" %.2f", bw);
			if (usage->du_last) {
				(void) printf("\n");
				state->us_first = B_TRUE;
			}
		}
		return (DLADM_STATUS_OK);
	}

	bzero(&ubuf, sizeof (ubuf));

	(void) snprintf(ubuf.usage_l_link, sizeof (ubuf.usage_l_link), "%s",
	    usage->du_name);
	time = usage->du_stime;
	(void) strftime(buf, sizeof (buf), "%T", localtime(&time));
	(void) snprintf(ubuf.usage_l_stime, sizeof (ubuf.usage_l_stime), "%s",
	    buf);
	time = usage->du_etime;
	(void) strftime(buf, sizeof (buf), "%T", localtime(&time));
	(void) snprintf(ubuf.usage_l_etime, sizeof (ubuf.usage_l_etime), "%s",
	    buf);
	(void) snprintf(ubuf.usage_l_rbytes, sizeof (ubuf.usage_l_rbytes),
	    "%llu", usage->du_rbytes);
	(void) snprintf(ubuf.usage_l_obytes, sizeof (ubuf.usage_l_obytes),
	    "%llu", usage->du_obytes);
	(void) snprintf(ubuf.usage_l_bandwidth, sizeof (ubuf.usage_l_bandwidth),
	    "%s Mbps", dladm_bw2str(usage->du_bandwidth, buf));

	ofmt_print(state->us_ofmt, &ubuf);
	return (DLADM_STATUS_OK);
}

static int
show_usage_res(dladm_usage_t *usage, void *arg)
{
	show_usage_state_t	*state = (show_usage_state_t *)arg;
	char			buf[DLADM_STRSIZE];
	usage_fields_buf_t	ubuf;
	dladm_status_t		status;
	uint32_t		flags;

	/*
	 * Only show usage information for existing links unless '-a'
	 * is specified.
	 */
	if (!state->us_showall) {
		if ((status = dladm_name2info(handle, usage->du_name,
		    NULL, &flags, NULL, NULL)) != DLADM_STATUS_OK) {
			return (status);
		}
		if ((flags & DLADM_OPT_ACTIVE) == 0)
			return (DLADM_STATUS_LINKINVAL);
	}

	bzero(&ubuf, sizeof (ubuf));

	(void) snprintf(ubuf.usage_link, sizeof (ubuf.usage_link), "%s",
	    usage->du_name);
	(void) snprintf(ubuf.usage_duration, sizeof (ubuf.usage_duration),
	    "%llu", usage->du_duration);
	(void) snprintf(ubuf.usage_ipackets, sizeof (ubuf.usage_ipackets),
	    "%llu", usage->du_ipackets);
	(void) snprintf(ubuf.usage_rbytes, sizeof (ubuf.usage_rbytes),
	    "%llu", usage->du_rbytes);
	(void) snprintf(ubuf.usage_opackets, sizeof (ubuf.usage_opackets),
	    "%llu", usage->du_opackets);
	(void) snprintf(ubuf.usage_obytes, sizeof (ubuf.usage_obytes),
	    "%llu", usage->du_obytes);
	(void) snprintf(ubuf.usage_bandwidth, sizeof (ubuf.usage_bandwidth),
	    "%s Mbps", dladm_bw2str(usage->du_bandwidth, buf));

	ofmt_print(state->us_ofmt, &ubuf);

	return (DLADM_STATUS_OK);
}

static boolean_t
valid_formatspec(char *formatspec_str)
{
	if (strcmp(formatspec_str, "gnuplot") == 0)
		return (B_TRUE);
	return (B_FALSE);

}

/*ARGSUSED*/
static void
do_show_usage(int argc, char *argv[], const char *use)
{
	char			*file = NULL;
	int			opt;
	dladm_status_t		status;
	boolean_t		d_arg = B_FALSE;
	char			*stime = NULL;
	char			*etime = NULL;
	char			*resource = NULL;
	show_usage_state_t	state;
	boolean_t		o_arg = B_FALSE;
	boolean_t		F_arg = B_FALSE;
	char			*fields_str = NULL;
	char			*formatspec_str = NULL;
	char			*all_l_fields =
	    "link,start,end,rbytes,obytes,bandwidth";
	ofmt_handle_t		ofmt;
	ofmt_status_t		oferr;
	uint_t			ofmtflags = 0;

	bzero(&state, sizeof (show_usage_state_t));
	state.us_parsable = B_FALSE;
	state.us_printheader = B_FALSE;
	state.us_plot = B_FALSE;
	state.us_first = B_TRUE;

	while ((opt = getopt_long(argc, argv, "das:e:o:f:F:",
	    usage_opts, NULL)) != -1) {
		switch (opt) {
		case 'd':
			d_arg = B_TRUE;
			break;
		case 'a':
			state.us_showall = B_TRUE;
			break;
		case 'f':
			file = optarg;
			break;
		case 's':
			stime = optarg;
			break;
		case 'e':
			etime = optarg;
			break;
		case 'o':
			o_arg = B_TRUE;
			fields_str = optarg;
			break;
		case 'F':
			state.us_plot = F_arg = B_TRUE;
			formatspec_str = optarg;
			break;
		default:
			die_opterr(optopt, opt, use);
			break;
		}
	}

	if (file == NULL)
		die("show-usage requires a file");

	if (optind == (argc-1)) {
		uint32_t 	flags;

		resource = argv[optind];
		if (!state.us_showall &&
		    (((status = dladm_name2info(handle, resource, NULL, &flags,
		    NULL, NULL)) != DLADM_STATUS_OK) ||
		    ((flags & DLADM_OPT_ACTIVE) == 0))) {
			die("invalid link: '%s'", resource);
		}
	}

	if (F_arg && d_arg)
		die("incompatible -d and -F options");

	if (F_arg && valid_formatspec(formatspec_str) == B_FALSE)
		die("Format specifier %s not supported", formatspec_str);

	if (state.us_parsable)
		ofmtflags |= OFMT_PARSABLE;

	if (resource == NULL && stime == NULL && etime == NULL) {
		oferr = ofmt_open(fields_str, usage_fields, ofmtflags, 0,
		    &ofmt);
	} else {
		if (!o_arg || (o_arg && strcasecmp(fields_str, "all") == 0))
			fields_str = all_l_fields;
		oferr = ofmt_open(fields_str, usage_l_fields, ofmtflags, 0,
		    &ofmt);

	}
	ofmt_check(oferr, state.us_parsable, ofmt, die, warn);
	state.us_ofmt = ofmt;

	if (d_arg) {
		/* Print log dates */
		status = dladm_usage_dates(show_usage_date,
		    DLADM_LOGTYPE_LINK, file, resource, &state);
	} else if (resource == NULL && stime == NULL && etime == NULL &&
	    !F_arg) {
		/* Print summary */
		status = dladm_usage_summary(show_usage_res,
		    DLADM_LOGTYPE_LINK, file, &state);
	} else if (resource != NULL) {
		/* Print log entries for named resource */
		status = dladm_walk_usage_res(show_usage_time,
		    DLADM_LOGTYPE_LINK, file, resource, stime, etime, &state);
	} else {
		/* Print time and information for each link */
		status = dladm_walk_usage_time(show_usage_time,
		    DLADM_LOGTYPE_LINK, file, stime, etime, &state);
	}

	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "show-usage");
	ofmt_close(ofmt);
}

static void
do_create_aggr(int argc, char *argv[], const char *use)
{
	int			option;
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
	dladm_status_t		pstatus;
	char			propstr[DLADM_STRSIZE];
	dladm_arg_list_t	*proplist = NULL;
	int			i;
	datalink_id_t		linkid;

	ndev = nlink = opterr = 0;
	bzero(propstr, DLADM_STRSIZE);

	while ((option = getopt_long(argc, argv, ":d:l:L:P:R:tfu:T:p:",
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
		case 'p':
			(void) strlcat(propstr, optarg, DLADM_STRSIZE);
			if (strlcat(propstr, ",", DLADM_STRSIZE) >=
			    DLADM_STRSIZE)
				die("property list too long '%s'", propstr);
			break;

		default:
			die_opterr(optopt, option, use);
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
		if ((status = dladm_dev2linkid(handle, devs[n],
		    &port[n].lp_linkid)) != DLADM_STATUS_OK) {
			die_dlerr(status, "invalid dev name '%s'", devs[n]);
		}
	}

	for (n = 0; n < nlink; n++) {
		if ((status = dladm_name2info(handle, links[n],
		    &port[ndev + n].lp_linkid, NULL, NULL, NULL)) !=
		    DLADM_STATUS_OK) {
			die_dlerr(status, "invalid link name '%s'", links[n]);
		}
	}

	status = dladm_aggr_create(handle, name, key, ndev + nlink, port,
	    policy, mac_addr_fixed, (const uchar_t *)mac_addr, lacp_mode,
	    lacp_timer, flags);
	if (status != DLADM_STATUS_OK)
		goto done;

	if (dladm_parse_link_props(propstr, &proplist, B_FALSE)
	    != DLADM_STATUS_OK)
		die("invalid aggregation property");

	if (proplist == NULL)
		return;

	status = dladm_name2info(handle, name, &linkid, NULL, NULL, NULL);
	if (status != DLADM_STATUS_OK)
		goto done;

	for (i = 0; i < proplist->al_count; i++) {
		dladm_arg_info_t	*aip = &proplist->al_info[i];

		pstatus = dladm_set_linkprop(handle, linkid, aip->ai_name,
		    aip->ai_val, aip->ai_count, flags);

		if (pstatus != DLADM_STATUS_OK) {
			die_dlerr(pstatus,
			    "aggr creation succeeded but "
			    "could not set property '%s'", aip->ai_name);
		}
	}
done:
	dladm_free_props(proplist);
	if (status != DLADM_STATUS_OK) {
		if (status == DLADM_STATUS_NONOTIF) {
			die("not all links have link up/down detection; must "
			    "use -f (see dladm(1M))");
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
		status = dladm_name2info(handle, aggr, linkidp, NULL, NULL,
		    NULL);
	} else {
		status = dladm_key2linkid(handle, key, linkidp, flags);
	}

	return (status);
}

static void
do_delete_aggr(int argc, char *argv[], const char *use)
{
	int			option;
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
			die_opterr(optopt, option, use);
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

	status = dladm_aggr_delete(handle, linkid, flags);
done:
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "delete operation failed");
}

static void
do_add_aggr(int argc, char *argv[], const char *use)
{
	int			option;
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
			die_opterr(optopt, option, use);
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
		if ((status = dladm_dev2linkid(handle, devs[n],
		    &(port[n].lp_linkid))) != DLADM_STATUS_OK) {
			die_dlerr(status, "invalid <dev> '%s'", devs[n]);
		}
	}

	for (n = 0; n < nlink; n++) {
		if ((status = dladm_name2info(handle, links[n],
		    &port[n + ndev].lp_linkid, NULL, NULL, NULL)) !=
		    DLADM_STATUS_OK) {
			die_dlerr(status, "invalid <link> '%s'", links[n]);
		}
	}

	status = dladm_aggr_add(handle, linkid, ndev + nlink, port, flags);
done:
	if (status != DLADM_STATUS_OK) {
		/*
		 * checking DLADM_STATUS_NOTSUP is a temporary workaround
		 * and should be removed once 6399681 is fixed.
		 */
		if (status == DLADM_STATUS_NOTSUP) {
			die("add operation failed: link capabilities don't "
			    "match");
		} else if (status == DLADM_STATUS_NONOTIF) {
			die("not all links have link up/down detection; must "
			    "use -f (see dladm(1M))");
		} else {
			die_dlerr(status, "add operation failed");
		}
	}
}

static void
do_remove_aggr(int argc, char *argv[], const char *use)
{
	int				option;
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
			die_opterr(optopt, option, use);
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
		if ((status = dladm_dev2linkid(handle, devs[n],
		    &(port[n].lp_linkid))) != DLADM_STATUS_OK) {
			die_dlerr(status, "invalid <dev> '%s'", devs[n]);
		}
	}

	for (n = 0; n < nlink; n++) {
		if ((status = dladm_name2info(handle, links[n],
		    &port[n + ndev].lp_linkid, NULL, NULL, NULL)) !=
		    DLADM_STATUS_OK) {
			die_dlerr(status, "invalid <link> '%s'", links[n]);
		}
	}

	status = dladm_aggr_remove(handle, linkid, ndev + nlink, port, flags);
done:
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "remove operation failed");
}

static void
do_modify_aggr(int argc, char *argv[], const char *use)
{
	int			option;
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
			die_opterr(optopt, option, use);
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

	status = dladm_aggr_modify(handle, linkid, modify_mask, policy,
	    mac_addr_fixed, (const uchar_t *)mac_addr, lacp_mode, lacp_timer,
	    flags);

done:
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "modify operation failed");
}

/*ARGSUSED*/
static void
do_up_aggr(int argc, char *argv[], const char *use)
{
	datalink_id_t	linkid = DATALINK_ALL_LINKID;
	dladm_status_t	status;

	/*
	 * get the key or the name of the aggregation (optional last argument)
	 */
	if (argc == 2) {
		if ((status = i_dladm_aggr_get_linkid(NULL, argv[1], &linkid,
		    DLADM_OPT_PERSIST)) != DLADM_STATUS_OK)
			goto done;
	} else if (argc > 2) {
		usage();
	}

	status = dladm_aggr_up(handle, linkid);
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
do_create_vlan(int argc, char *argv[], const char *use)
{
	char			*link = NULL;
	char			drv[DLPI_LINKNAME_MAX];
	uint_t			ppa;
	datalink_id_t		linkid;
	datalink_id_t		dev_linkid;
	int			vid = 0;
	int			option;
	uint32_t		flags = (DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST);
	char			*altroot = NULL;
	char			vlan[MAXLINKNAMELEN];
	char			propstr[DLADM_STRSIZE];
	dladm_arg_list_t	*proplist = NULL;
	dladm_status_t		status;

	opterr = 0;
	bzero(propstr, DLADM_STRSIZE);

	while ((option = getopt_long(argc, argv, ":tfR:l:v:p:",
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
		case 't':
			flags &= ~DLADM_OPT_PERSIST;
			break;
		case 'R':
			altroot = optarg;
			break;
		case 'p':
			(void) strlcat(propstr, optarg, DLADM_STRSIZE);
			if (strlcat(propstr, ",", DLADM_STRSIZE) >=
			    DLADM_STRSIZE)
				die("property list too long '%s'", propstr);
			break;
		case 'f':
			flags |= DLADM_OPT_FORCE;
			break;
		default:
			die_opterr(optopt, option, use);
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

	if (dladm_name2info(handle, link, &dev_linkid, NULL, NULL, NULL) !=
	    DLADM_STATUS_OK) {
		die("invalid link name '%s'", link);
	}

	if (dladm_parse_link_props(propstr, &proplist, B_FALSE)
	    != DLADM_STATUS_OK)
		die("invalid vlan property");

	status = dladm_vlan_create(handle, vlan, dev_linkid, vid, proplist,
	    flags, &linkid);
	switch (status) {
	case DLADM_STATUS_OK:
		break;

	case DLADM_STATUS_NOTSUP:
		die("VLAN over '%s' may require lowered MTU; must use -f (see "
		    "dladm(1M))", link);
		break;

	case DLADM_STATUS_LINKBUSY:
		die("VLAN over '%s' may not use default_tag ID "
		    "(see dladm(1M))", link);
		break;

	default:
		die_dlerr(status, "create operation failed");
	}
}

static void
do_delete_vlan(int argc, char *argv[], const char *use)
{
	int		option;
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
			die_opterr(optopt, option, use);
			break;
		}
	}

	/* get VLAN link name (required last argument) */
	if (optind != (argc - 1))
		usage();

	if (altroot != NULL)
		altroot_cmd(altroot, argc, argv);

	status = dladm_name2info(handle, argv[optind], &linkid, NULL, NULL,
	    NULL);
	if (status != DLADM_STATUS_OK)
		goto done;

	status = dladm_vlan_delete(handle, linkid, flags);
done:
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "delete operation failed");
}

/*ARGSUSED*/
static void
do_up_vlan(int argc, char *argv[], const char *use)
{
	do_up_vnic_common(argc, argv, use, B_TRUE);
}

static void
do_rename_link(int argc, char *argv[], const char *use)
{
	int		option;
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
			die_opterr(optopt, option, use);
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
	if ((status = dladm_rename_link(handle, link1, link2)) !=
	    DLADM_STATUS_OK)
		die_dlerr(status, "rename operation failed");
}

/*ARGSUSED*/
static void
do_delete_phys(int argc, char *argv[], const char *use)
{
	datalink_id_t	linkid = DATALINK_ALL_LINKID;
	dladm_status_t	status;

	/* get link name (required the last argument) */
	if (argc > 2)
		usage();

	if (argc == 2) {
		if ((status = dladm_name2info(handle, argv[1], &linkid, NULL,
		    NULL, NULL)) != DLADM_STATUS_OK)
			die_dlerr(status, "cannot delete '%s'", argv[1]);
	}

	if ((status = dladm_phys_delete(handle, linkid)) != DLADM_STATUS_OK) {
		if (argc == 2)
			die_dlerr(status, "cannot delete '%s'", argv[1]);
		else
			die_dlerr(status, "delete operation failed");
	}
}

/*ARGSUSED*/
static int
i_dladm_walk_linkmap(dladm_handle_t dh, datalink_id_t linkid, void *arg)
{
	char			name[MAXLINKNAMELEN];
	char			mediabuf[DLADM_STRSIZE];
	char			classbuf[DLADM_STRSIZE];
	datalink_class_t	class;
	uint32_t		media;
	uint32_t		flags;

	if (dladm_datalink_id2info(dh, linkid, &flags, &class, &media, name,
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
do_show_linkmap(int argc, char *argv[], const char *use)
{
	if (argc != 1)
		die("invalid arguments");

	(void) printf("%-12s%8s  %-12s%-20s %6s\n", "NAME", "LINKID",
	    "CLASS", "MEDIA", "FLAGS");

	(void) dladm_walk_datalink_id(i_dladm_walk_linkmap, handle, NULL,
	    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE,
	    DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST);
}

/*
 * Delete inactive physical links.
 */
/*ARGSUSED*/
static int
purge_phys(dladm_handle_t dh, datalink_id_t linkid, void *arg)
{
	datalink_class_t	class;
	uint32_t		flags;

	if (dladm_datalink_id2info(dh, linkid, &flags, &class, NULL, NULL, 0)
	    != DLADM_STATUS_OK) {
		return (DLADM_WALK_CONTINUE);
	}

	if (class == DATALINK_CLASS_PHYS && !(flags & DLADM_OPT_ACTIVE))
		(void) dladm_phys_delete(dh, linkid);

	return (DLADM_WALK_CONTINUE);
}

/*ARGSUSED*/
static void
do_init_phys(int argc, char *argv[], const char *use)
{
	di_node_t	devtree;

	if (argc > 1)
		usage();

	/*
	 * Force all the devices to attach, therefore all the network physical
	 * devices can be known to the dlmgmtd daemon.
	 */
	if ((devtree = di_init("/", DINFOFORCE | DINFOSUBTREE)) != DI_NODE_NIL)
		di_fini(devtree);

	(void) dladm_walk_datalink_id(purge_phys, handle, NULL,
	    DATALINK_CLASS_PHYS, DATALINK_ANY_MEDIATYPE, DLADM_OPT_PERSIST);
}

/*
 * Print the active topology information.
 */
void
print_link_topology(show_state_t *state, datalink_id_t linkid,
    datalink_class_t class, link_fields_buf_t *lbuf)
{
	uint32_t	flags = state->ls_flags;
	dladm_status_t	status;
	char		tmpbuf[MAXLINKNAMELEN];

	lbuf->link_over[0] = '\0';
	lbuf->link_bridge[0] = '\0';

	switch (class) {
	case DATALINK_CLASS_AGGR:
	case DATALINK_CLASS_PHYS:
	case DATALINK_CLASS_ETHERSTUB:
		status = dladm_bridge_getlink(handle, linkid, lbuf->link_bridge,
		    sizeof (lbuf->link_bridge));
		if (status != DLADM_STATUS_OK &&
		    status != DLADM_STATUS_NOTFOUND)
			(void) strcpy(lbuf->link_bridge, "?");
		break;
	}

	switch (class) {
	case DATALINK_CLASS_VLAN: {
		dladm_vlan_attr_t	vinfo;

		if (dladm_vlan_info(handle, linkid, &vinfo, flags) !=
		    DLADM_STATUS_OK) {
			(void) strcpy(lbuf->link_over, "?");
			break;
		}
		if (dladm_datalink_id2info(handle, vinfo.dv_linkid, NULL, NULL,
		    NULL, lbuf->link_over, sizeof (lbuf->link_over)) !=
		    DLADM_STATUS_OK)
			(void) strcpy(lbuf->link_over, "?");
		break;
	}
	case DATALINK_CLASS_AGGR: {
		dladm_aggr_grp_attr_t	ginfo;
		int			i;

		if (dladm_aggr_info(handle, linkid, &ginfo, flags) !=
		    DLADM_STATUS_OK || ginfo.lg_nports == 0) {
			(void) strcpy(lbuf->link_over, "?");
			break;
		}
		for (i = 0; i < ginfo.lg_nports; i++) {
			if (dladm_datalink_id2info(handle,
			    ginfo.lg_ports[i].lp_linkid, NULL, NULL, NULL,
			    tmpbuf, sizeof (tmpbuf)) != DLADM_STATUS_OK) {
				(void) strcpy(lbuf->link_over, "?");
				break;
			}
			(void) strlcat(lbuf->link_over, tmpbuf,
			    sizeof (lbuf->link_over));
			if (i != (ginfo.lg_nports - 1)) {
				(void) strlcat(lbuf->link_over, ",",
				    sizeof (lbuf->link_over));
			}
		}
		free(ginfo.lg_ports);
		break;
	}
	case DATALINK_CLASS_VNIC: {
		dladm_vnic_attr_t	vinfo;

		if (dladm_vnic_info(handle, linkid, &vinfo, flags) !=
		    DLADM_STATUS_OK) {
			(void) strcpy(lbuf->link_over, "?");
			break;
		}
		if (dladm_datalink_id2info(handle, vinfo.va_link_id, NULL, NULL,
		    NULL, lbuf->link_over, sizeof (lbuf->link_over)) !=
		    DLADM_STATUS_OK)
			(void) strcpy(lbuf->link_over, "?");
		break;
	}

	case DATALINK_CLASS_PART: {
		dladm_part_attr_t	pinfo;

		if (dladm_part_info(handle, linkid, &pinfo, flags) !=
		    DLADM_STATUS_OK) {
			(void) strcpy(lbuf->link_over, "?");
			break;
		}
		if (dladm_datalink_id2info(handle, pinfo.dia_physlinkid, NULL,
		    NULL, NULL, lbuf->link_over, sizeof (lbuf->link_over)) !=
		    DLADM_STATUS_OK)
			(void) strcpy(lbuf->link_over, "?");
		break;
	}

	case DATALINK_CLASS_BRIDGE: {
		datalink_id_t *dlp;
		uint_t i, nports;

		if (dladm_datalink_id2info(handle, linkid, NULL, NULL,
		    NULL, tmpbuf, sizeof (tmpbuf)) != DLADM_STATUS_OK) {
			(void) strcpy(lbuf->link_over, "?");
			break;
		}
		if (tmpbuf[0] != '\0')
			tmpbuf[strlen(tmpbuf) - 1] = '\0';
		dlp = dladm_bridge_get_portlist(tmpbuf, &nports);
		if (dlp == NULL) {
			(void) strcpy(lbuf->link_over, "?");
			break;
		}
		for (i = 0; i < nports; i++) {
			if (dladm_datalink_id2info(handle, dlp[i], NULL,
			    NULL, NULL, tmpbuf, sizeof (tmpbuf)) !=
			    DLADM_STATUS_OK) {
				(void) strcpy(lbuf->link_over, "?");
				break;
			}
			(void) strlcat(lbuf->link_over, tmpbuf,
			    sizeof (lbuf->link_over));
			if (i != nports - 1) {
				(void) strlcat(lbuf->link_over, ",",
				    sizeof (lbuf->link_over));
			}
		}
		dladm_bridge_free_portlist(dlp);
		break;
	}

	case DATALINK_CLASS_SIMNET: {
		dladm_simnet_attr_t	slinfo;

		if (dladm_simnet_info(handle, linkid, &slinfo, flags) !=
		    DLADM_STATUS_OK) {
			(void) strcpy(lbuf->link_over, "?");
			break;
		}
		if (slinfo.sna_peer_link_id != DATALINK_INVALID_LINKID) {
			if (dladm_datalink_id2info(handle,
			    slinfo.sna_peer_link_id, NULL, NULL, NULL,
			    lbuf->link_over, sizeof (lbuf->link_over)) !=
			    DLADM_STATUS_OK)
				(void) strcpy(lbuf->link_over, "?");
		}
		break;
	}
	}
}

static dladm_status_t
print_link(show_state_t *state, datalink_id_t linkid, link_fields_buf_t *lbuf)
{
	char			link[MAXLINKNAMELEN];
	datalink_class_t	class;
	uint_t			mtu;
	uint32_t		flags;
	dladm_status_t		status;

	if ((status = dladm_datalink_id2info(handle, linkid, &flags, &class,
	    NULL, link, sizeof (link))) != DLADM_STATUS_OK) {
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

			if ((status = dladm_phys_info(handle, linkid, &dpa,
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
			status = dladm_info(handle, linkid, &dlattr);
			if (status != DLADM_STATUS_OK)
				goto done;
			mtu = dlattr.da_max_sdu;
		}
	}

	(void) snprintf(lbuf->link_name, sizeof (lbuf->link_name),
	    "%s", link);
	(void) dladm_class2str(class, lbuf->link_class);
	if (state->ls_flags == DLADM_OPT_ACTIVE) {
		(void) snprintf(lbuf->link_mtu, sizeof (lbuf->link_mtu),
		    "%u", mtu);
		(void) get_linkstate(link, B_TRUE, lbuf->link_state);
	}

	print_link_topology(state, linkid, class, lbuf);
done:
	return (status);
}

/* ARGSUSED */
static int
show_link(dladm_handle_t dh, datalink_id_t linkid, void *arg)
{
	show_state_t		*state = (show_state_t *)arg;
	dladm_status_t		status;
	link_fields_buf_t	lbuf;

	/*
	 * first get all the link attributes into lbuf;
	 */
	bzero(&lbuf, sizeof (link_fields_buf_t));
	if ((status = print_link(state, linkid, &lbuf)) == DLADM_STATUS_OK)
		ofmt_print(state->ls_ofmt, &lbuf);
	state->ls_status = status;
	return (DLADM_WALK_CONTINUE);
}

static boolean_t
print_link_stats_cb(ofmt_arg_t *ofarg, char *buf, uint_t bufsize)
{
	link_args_t *largs = ofarg->ofmt_cbarg;
	pktsum_t *diff_stats = largs->link_s_psum;

	switch (ofarg->ofmt_id) {
	case LINK_S_LINK:
		(void) snprintf(buf, bufsize, "%s", largs->link_s_link);
		break;
	case LINK_S_IPKTS:
		(void) snprintf(buf, bufsize, "%llu", diff_stats->ipackets);
		break;
	case LINK_S_RBYTES:
		(void) snprintf(buf, bufsize, "%llu", diff_stats->rbytes);
		break;
	case LINK_S_IERRORS:
		(void) snprintf(buf, bufsize, "%u", diff_stats->ierrors);
		break;
	case LINK_S_OPKTS:
		(void) snprintf(buf, bufsize, "%llu", diff_stats->opackets);
		break;
	case LINK_S_OBYTES:
		(void) snprintf(buf, bufsize, "%llu", diff_stats->obytes);
		break;
	case LINK_S_OERRORS:
		(void) snprintf(buf, bufsize, "%u", diff_stats->oerrors);
		break;
	default:
		die("invalid input");
		break;
	}
	return (B_TRUE);
}

static int
show_link_stats(dladm_handle_t dh, datalink_id_t linkid, void *arg)
{
	char			link[DLPI_LINKNAME_MAX];
	datalink_class_t	class;
	show_state_t		*state = arg;
	pktsum_t		stats, diff_stats;
	dladm_phys_attr_t	dpa;
	link_args_t		largs;

	if (state->ls_firstonly) {
		if (state->ls_donefirst)
			return (DLADM_WALK_CONTINUE);
		state->ls_donefirst = B_TRUE;
	} else {
		bzero(&state->ls_prevstats, sizeof (state->ls_prevstats));
	}

	if (dladm_datalink_id2info(dh, linkid, NULL, &class, NULL, link,
	    DLPI_LINKNAME_MAX) != DLADM_STATUS_OK) {
		return (DLADM_WALK_CONTINUE);
	}

	if (class == DATALINK_CLASS_PHYS) {
		if (dladm_phys_info(dh, linkid, &dpa, DLADM_OPT_ACTIVE) !=
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
	dladm_stats_diff(&diff_stats, &stats, &state->ls_prevstats);

	largs.link_s_link = link;
	largs.link_s_psum = &diff_stats;
	ofmt_print(state->ls_ofmt, &largs);

	state->ls_prevstats = stats;
	return (DLADM_WALK_CONTINUE);
}


static dladm_status_t
print_aggr_info(show_grp_state_t *state, const char *link,
    dladm_aggr_grp_attr_t *ginfop)
{
	char			addr_str[ETHERADDRL * 3];
	laggr_fields_buf_t	lbuf;

	(void) snprintf(lbuf.laggr_name, sizeof (lbuf.laggr_name),
	    "%s", link);

	(void) dladm_aggr_policy2str(ginfop->lg_policy,
	    lbuf.laggr_policy);

	if (ginfop->lg_mac_fixed) {
		(void) dladm_aggr_macaddr2str(ginfop->lg_mac, addr_str);
		(void) snprintf(lbuf.laggr_addrpolicy,
		    sizeof (lbuf.laggr_addrpolicy), "fixed (%s)", addr_str);
	} else {
		(void) snprintf(lbuf.laggr_addrpolicy,
		    sizeof (lbuf.laggr_addrpolicy), "auto");
	}

	(void) dladm_aggr_lacpmode2str(ginfop->lg_lacp_mode,
	    lbuf.laggr_lacpactivity);
	(void) dladm_aggr_lacptimer2str(ginfop->lg_lacp_timer,
	    lbuf.laggr_lacptimer);
	(void) snprintf(lbuf.laggr_flags, sizeof (lbuf.laggr_flags), "%c----",
	    ginfop->lg_force ? 'f' : '-');

	ofmt_print(state->gs_ofmt, &lbuf);

	return (DLADM_STATUS_OK);
}

static boolean_t
print_xaggr_cb(ofmt_arg_t *ofarg, char *buf, uint_t bufsize)
{
	const laggr_args_t 	*l = ofarg->ofmt_cbarg;
	boolean_t		is_port = (l->laggr_lport >= 0);
	char			tmpbuf[DLADM_STRSIZE];
	const char		*objname;
	dladm_aggr_port_attr_t	*portp;
	dladm_phys_attr_t	dpa;

	if (is_port) {
		portp = &(l->laggr_ginfop->lg_ports[l->laggr_lport]);
		if (dladm_phys_info(handle, portp->lp_linkid, &dpa,
		    DLADM_OPT_ACTIVE) != DLADM_STATUS_OK)
			objname = "?";
		else
			objname = dpa.dp_dev;
	} else {
		objname = l->laggr_link;
	}

	switch (ofarg->ofmt_id) {
	case AGGR_X_LINK:
		(void) snprintf(buf, bufsize, "%s",
		    (is_port && !l->laggr_parsable ? " " : l->laggr_link));
		break;
	case AGGR_X_PORT:
		if (is_port) {
			if (dladm_datalink_id2info(handle, portp->lp_linkid,
			    NULL, NULL, NULL, buf, bufsize) != DLADM_STATUS_OK)
				(void) sprintf(buf, "?");
		}
		break;

	case AGGR_X_SPEED:
		(void) snprintf(buf, bufsize, "%uMb",
		    (uint_t)((get_ifspeed(objname, !is_port)) / 1000000ull));
		break;

	case AGGR_X_DUPLEX:
		(void) get_linkduplex(objname, !is_port, tmpbuf);
		(void) strlcpy(buf, tmpbuf, bufsize);
		break;

	case AGGR_X_STATE:
		(void) get_linkstate(objname, !is_port, tmpbuf);
		(void) strlcpy(buf, tmpbuf, bufsize);
		break;
	case AGGR_X_ADDRESS:
		(void) dladm_aggr_macaddr2str(
		    (is_port ? portp->lp_mac : l->laggr_ginfop->lg_mac),
		    tmpbuf);
		(void) strlcpy(buf, tmpbuf, bufsize);
		break;
	case AGGR_X_PORTSTATE:
		if (is_port) {
			(void) dladm_aggr_portstate2str(portp->lp_state,
			    tmpbuf);
			(void) strlcpy(buf, tmpbuf, bufsize);
		}
		break;
	}
err:
	*(l->laggr_status) = DLADM_STATUS_OK;
	return (B_TRUE);
}

static dladm_status_t
print_aggr_extended(show_grp_state_t *state, const char *link,
    dladm_aggr_grp_attr_t *ginfop)
{
	int			i;
	dladm_status_t		status;
	laggr_args_t		largs;

	largs.laggr_lport = -1;
	largs.laggr_link = link;
	largs.laggr_ginfop = ginfop;
	largs.laggr_status = &status;
	largs.laggr_parsable = state->gs_parsable;

	ofmt_print(state->gs_ofmt, &largs);

	if (status != DLADM_STATUS_OK)
		goto done;

	for (i = 0; i < ginfop->lg_nports; i++) {
		largs.laggr_lport = i;
		ofmt_print(state->gs_ofmt, &largs);
		if (status != DLADM_STATUS_OK)
			goto done;
	}

	status = DLADM_STATUS_OK;
done:
	return (status);
}

static boolean_t
print_lacp_cb(ofmt_arg_t *ofarg, char *buf, uint_t bufsize)
{
	const laggr_args_t	*l = ofarg->ofmt_cbarg;
	int			portnum;
	boolean_t		is_port = (l->laggr_lport >= 0);
	dladm_aggr_port_attr_t	*portp;
	aggr_lacp_state_t	*lstate;

	if (!is_port)
		return (B_FALSE); /* cannot happen! */

	portnum = l->laggr_lport;
	portp = &(l->laggr_ginfop->lg_ports[portnum]);
	lstate = &(portp->lp_lacp_state);

	switch (ofarg->ofmt_id) {
	case AGGR_L_LINK:
		(void) snprintf(buf, bufsize, "%s",
		    (portnum > 0 ? "" : l->laggr_link));
		break;

	case AGGR_L_PORT:
		if (dladm_datalink_id2info(handle, portp->lp_linkid, NULL, NULL,
		    NULL, buf, bufsize) != DLADM_STATUS_OK)
			(void) sprintf(buf, "?");
		break;

	case AGGR_L_AGGREGATABLE:
		(void) snprintf(buf, bufsize, "%s",
		    (lstate->bit.aggregation ? "yes" : "no"));
		break;

	case AGGR_L_SYNC:
		(void) snprintf(buf, bufsize, "%s",
		    (lstate->bit.sync ? "yes" : "no"));
		break;

	case AGGR_L_COLL:
		(void) snprintf(buf, bufsize, "%s",
		    (lstate->bit.collecting ? "yes" : "no"));
		break;

	case AGGR_L_DIST:
		(void) snprintf(buf, bufsize, "%s",
		    (lstate->bit.distributing ? "yes" : "no"));
		break;

	case AGGR_L_DEFAULTED:
		(void) snprintf(buf, bufsize, "%s",
		    (lstate->bit.defaulted ? "yes" : "no"));
		break;

	case AGGR_L_EXPIRED:
		(void) snprintf(buf, bufsize, "%s",
		    (lstate->bit.expired ? "yes" : "no"));
		break;
	}

	*(l->laggr_status) = DLADM_STATUS_OK;
	return (B_TRUE);
}

static dladm_status_t
print_aggr_lacp(show_grp_state_t *state, const char *link,
    dladm_aggr_grp_attr_t *ginfop)
{
	int		i;
	dladm_status_t	status;
	laggr_args_t	largs;

	largs.laggr_link = link;
	largs.laggr_ginfop = ginfop;
	largs.laggr_status = &status;

	for (i = 0; i < ginfop->lg_nports; i++) {
		largs.laggr_lport = i;
		ofmt_print(state->gs_ofmt, &largs);
		if (status != DLADM_STATUS_OK)
			goto done;
	}

	status = DLADM_STATUS_OK;
done:
	return (status);
}

static boolean_t
print_aggr_stats_cb(ofmt_arg_t *ofarg, char *buf, uint_t bufsize)
{
	const laggr_args_t	*l = ofarg->ofmt_cbarg;
	int 			portnum;
	boolean_t		is_port = (l->laggr_lport >= 0);
	dladm_aggr_port_attr_t	*portp;
	dladm_status_t		*stat, status;
	pktsum_t		*diff_stats;

	stat = l->laggr_status;
	*stat = DLADM_STATUS_OK;

	if (is_port) {
		portnum = l->laggr_lport;
		portp = &(l->laggr_ginfop->lg_ports[portnum]);

		if ((status = dladm_datalink_id2info(handle,
		    portp->lp_linkid, NULL, NULL, NULL, buf, bufsize)) !=
		    DLADM_STATUS_OK) {
			goto err;
		}
		diff_stats = l->laggr_diffstats;
	}

	switch (ofarg->ofmt_id) {
	case AGGR_S_LINK:
		(void) snprintf(buf, bufsize, "%s",
		    (is_port ? "" : l->laggr_link));
		break;
	case AGGR_S_PORT:
		/*
		 * if (is_port), buf has port name. Otherwise we print
		 * STR_UNDEF_VAL
		 */
		break;

	case AGGR_S_IPKTS:
		if (is_port) {
			(void) snprintf(buf, bufsize, "%llu",
			    diff_stats->ipackets);
		} else {
			(void) snprintf(buf, bufsize, "%llu",
			    l->laggr_pktsumtot->ipackets);
		}
		break;

	case AGGR_S_RBYTES:
		if (is_port) {
			(void) snprintf(buf, bufsize, "%llu",
			    diff_stats->rbytes);
		} else {
			(void) snprintf(buf, bufsize, "%llu",
			    l->laggr_pktsumtot->rbytes);
		}
		break;

	case AGGR_S_OPKTS:
		if (is_port) {
			(void) snprintf(buf, bufsize, "%llu",
			    diff_stats->opackets);
		} else {
			(void) snprintf(buf, bufsize, "%llu",
			    l->laggr_pktsumtot->opackets);
		}
		break;
	case AGGR_S_OBYTES:
		if (is_port) {
			(void) snprintf(buf, bufsize, "%llu",
			    diff_stats->obytes);
		} else {
			(void) snprintf(buf, bufsize, "%llu",
			    l->laggr_pktsumtot->obytes);
		}
		break;

	case AGGR_S_IPKTDIST:
		if (is_port) {
			(void) snprintf(buf, bufsize, "%-6.1f",
			    (double)diff_stats->ipackets/
			    (double)l->laggr_pktsumtot->ipackets * 100);
		}
		break;
	case AGGR_S_OPKTDIST:
		if (is_port) {
			(void) snprintf(buf, bufsize, "%-6.1f",
			    (double)diff_stats->opackets/
			    (double)l->laggr_pktsumtot->opackets * 100);
		}
		break;
	}
	return (B_TRUE);

err:
	*stat = status;
	return (B_TRUE);
}

static dladm_status_t
print_aggr_stats(show_grp_state_t *state, const char *link,
    dladm_aggr_grp_attr_t *ginfop)
{
	dladm_phys_attr_t	dpa;
	dladm_aggr_port_attr_t	*portp;
	pktsum_t		pktsumtot, *port_stat;
	dladm_status_t		status;
	int			i;
	laggr_args_t		largs;

	/* sum the ports statistics */
	bzero(&pktsumtot, sizeof (pktsumtot));

	/* Allocate memory to keep stats of each port */
	port_stat = malloc(ginfop->lg_nports * sizeof (pktsum_t));
	if (port_stat == NULL) {
		/* Bail out; no memory */
		return (DLADM_STATUS_NOMEM);
	}


	for (i = 0; i < ginfop->lg_nports; i++) {

		portp = &(ginfop->lg_ports[i]);
		if ((status = dladm_phys_info(handle, portp->lp_linkid, &dpa,
		    DLADM_OPT_ACTIVE)) != DLADM_STATUS_OK) {
			goto done;
		}

		get_mac_stats(dpa.dp_dev, &port_stat[i]);

		/*
		 * Let's re-use gs_prevstats[] to store the difference of the
		 * counters since last use. We will store the new stats from
		 * port_stat[] once we have the stats displayed.
		 */

		dladm_stats_diff(&state->gs_prevstats[i], &port_stat[i],
		    &state->gs_prevstats[i]);
		dladm_stats_total(&pktsumtot, &pktsumtot,
		    &state->gs_prevstats[i]);
	}

	largs.laggr_lport = -1;
	largs.laggr_link = link;
	largs.laggr_ginfop = ginfop;
	largs.laggr_status = &status;
	largs.laggr_pktsumtot = &pktsumtot;

	ofmt_print(state->gs_ofmt, &largs);

	if (status != DLADM_STATUS_OK)
		goto done;

	for (i = 0; i < ginfop->lg_nports; i++) {
		largs.laggr_lport = i;
		largs.laggr_diffstats = &state->gs_prevstats[i];
		ofmt_print(state->gs_ofmt, &largs);
		if (status != DLADM_STATUS_OK)
			goto done;
	}

	status = DLADM_STATUS_OK;
	for (i = 0; i < ginfop->lg_nports; i++)
		state->gs_prevstats[i] = port_stat[i];

done:
	free(port_stat);
	return (status);
}

static dladm_status_t
print_aggr(show_grp_state_t *state, datalink_id_t linkid)
{
	char			link[MAXLINKNAMELEN];
	dladm_aggr_grp_attr_t	ginfo;
	uint32_t		flags;
	dladm_status_t		status;

	bzero(&ginfo, sizeof (dladm_aggr_grp_attr_t));
	if ((status = dladm_datalink_id2info(handle, linkid, &flags, NULL,
	    NULL, link, MAXLINKNAMELEN)) != DLADM_STATUS_OK) {
		return (status);
	}

	if (!(state->gs_flags & flags))
		return (DLADM_STATUS_NOTFOUND);

	status = dladm_aggr_info(handle, linkid, &ginfo, state->gs_flags);
	if (status != DLADM_STATUS_OK)
		return (status);

	if (state->gs_lacp)
		status = print_aggr_lacp(state, link, &ginfo);
	else if (state->gs_extended)
		status = print_aggr_extended(state, link, &ginfo);
	else if (state->gs_stats)
		status = print_aggr_stats(state, link, &ginfo);
	else
		status = print_aggr_info(state, link, &ginfo);

done:
	free(ginfo.lg_ports);
	return (status);
}

/* ARGSUSED */
static int
show_aggr(dladm_handle_t dh, datalink_id_t linkid, void *arg)
{
	show_grp_state_t	*state = arg;

	state->gs_status = print_aggr(state, linkid);
	return (DLADM_WALK_CONTINUE);
}

static void
do_show_link(int argc, char *argv[], const char *use)
{
	int		option;
	boolean_t	s_arg = B_FALSE;
	boolean_t	i_arg = B_FALSE;
	uint32_t	flags = DLADM_OPT_ACTIVE;
	boolean_t	p_arg = B_FALSE;
	datalink_id_t	linkid = DATALINK_ALL_LINKID;
	char		linkname[MAXLINKNAMELEN];
	uint32_t	interval = 0;
	show_state_t	state;
	dladm_status_t	status;
	boolean_t	o_arg = B_FALSE;
	char		*fields_str = NULL;
	char		*all_active_fields = "link,class,mtu,state,bridge,over";
	char		*all_inactive_fields = "link,class,bridge,over";
	char		*allstat_fields =
	    "link,ipackets,rbytes,ierrors,opackets,obytes,oerrors";
	ofmt_handle_t	ofmt;
	ofmt_status_t	oferr;
	uint_t		ofmtflags = 0;

	bzero(&state, sizeof (state));

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":pPsi:o:",
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
		case 'o':
			o_arg = B_TRUE;
			fields_str = optarg;
			break;
		case 'i':
			if (i_arg)
				die_optdup(option);

			i_arg = B_TRUE;
			if (!dladm_str2interval(optarg, &interval))
				die("invalid interval value '%s'", optarg);
			break;
		default:
			die_opterr(optopt, option, use);
			break;
		}
	}

	if (i_arg && !s_arg)
		die("the option -i can be used only with -s");

	if (s_arg && flags != DLADM_OPT_ACTIVE)
		die("the option -P cannot be used with -s");

	/* get link name (optional last argument) */
	if (optind == (argc-1)) {
		uint32_t	f;

		if (strlcpy(linkname, argv[optind], MAXLINKNAMELEN) >=
		    MAXLINKNAMELEN)
			die("link name too long");
		if ((status = dladm_name2info(handle, linkname, &linkid, &f,
		    NULL, NULL)) != DLADM_STATUS_OK) {
			die_dlerr(status, "link %s is not valid", linkname);
		}

		if (!(f & flags)) {
			die_dlerr(DLADM_STATUS_BADARG, "link %s is %s",
			    argv[optind], flags == DLADM_OPT_PERSIST ?
			    "a temporary link" : "temporarily removed");
		}
	} else if (optind != argc) {
		usage();
	}

	if (p_arg && !o_arg)
		die("-p requires -o");

	if (p_arg && strcasecmp(fields_str, "all") == 0)
		die("\"-o all\" is invalid with -p");

	if (!o_arg || (o_arg && strcasecmp(fields_str, "all") == 0)) {
		if (s_arg)
			fields_str = allstat_fields;
		else if (flags & DLADM_OPT_ACTIVE)
			fields_str = all_active_fields;
		else
			fields_str = all_inactive_fields;
	}

	state.ls_parsable = p_arg;
	state.ls_flags = flags;
	state.ls_donefirst = B_FALSE;

	if (s_arg) {
		link_stats(linkid, interval, fields_str, &state);
		return;
	}
	if (state.ls_parsable)
		ofmtflags |= OFMT_PARSABLE;
	else
		ofmtflags |= OFMT_WRAP;

	oferr = ofmt_open(fields_str, link_fields, ofmtflags, 0, &ofmt);
	ofmt_check(oferr, state.ls_parsable, ofmt, die, warn);
	state.ls_ofmt = ofmt;

	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(show_link, handle, &state,
		    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE, flags);
	} else {
		(void) show_link(handle, linkid, &state);
		if (state.ls_status != DLADM_STATUS_OK) {
			die_dlerr(state.ls_status, "failed to show link %s",
			    argv[optind]);
		}
	}
	ofmt_close(ofmt);
}

static void
do_show_aggr(int argc, char *argv[], const char *use)
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
	uint32_t		interval = 0;
	int			key;
	dladm_status_t		status;
	boolean_t		o_arg = B_FALSE;
	char			*fields_str = NULL;
	char			*all_fields =
	    "link,policy,addrpolicy,lacpactivity,lacptimer,flags";
	char			*all_lacp_fields =
	    "link,port,aggregatable,sync,coll,dist,defaulted,expired";
	char			*all_stats_fields =
	    "link,port,ipackets,rbytes,opackets,obytes,ipktdist,opktdist";
	char			*all_extended_fields =
	    "link,port,speed,duplex,state,address,portstate";
	const ofmt_field_t	*pf;
	ofmt_handle_t		ofmt;
	ofmt_status_t		oferr;
	uint_t			ofmtflags = 0;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":LpPxsi:o:",
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
		case 'o':
			o_arg = B_TRUE;
			fields_str = optarg;
			break;
		case 'i':
			if (i_arg)
				die_optdup(option);

			i_arg = B_TRUE;
			if (!dladm_str2interval(optarg, &interval))
				die("invalid interval value '%s'", optarg);
			break;
		default:
			die_opterr(optopt, option, use);
			break;
		}
	}

	if (p_arg && !o_arg)
		die("-p requires -o");

	if (p_arg && strcasecmp(fields_str, "all") == 0)
		die("\"-o all\" is invalid with -p");

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
			status = dladm_name2info(handle, argv[optind],
			    &linkid, NULL, NULL, NULL);
		} else {
			status = dladm_key2linkid(handle, (uint16_t)key,
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
	state.gs_parsable = p_arg;
	state.gs_extended = x_arg;

	if (!o_arg || (o_arg && strcasecmp(fields_str, "all") == 0)) {
		if (state.gs_lacp)
			fields_str = all_lacp_fields;
		else if (state.gs_stats)
			fields_str = all_stats_fields;
		else if (state.gs_extended)
			fields_str = all_extended_fields;
		else
			fields_str = all_fields;
	}

	if (state.gs_lacp) {
		pf = aggr_l_fields;
	} else if (state.gs_stats) {
		pf = aggr_s_fields;
	} else if (state.gs_extended) {
		pf = aggr_x_fields;
	} else {
		pf = laggr_fields;
	}

	if (state.gs_parsable)
		ofmtflags |= OFMT_PARSABLE;
	oferr = ofmt_open(fields_str, pf, ofmtflags, 0, &ofmt);
	ofmt_check(oferr, state.gs_parsable, ofmt, die, warn);
	state.gs_ofmt = ofmt;

	if (s_arg) {
		aggr_stats(linkid, &state, interval);
		ofmt_close(ofmt);
		return;
	}

	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(show_aggr, handle, &state,
		    DATALINK_CLASS_AGGR, DATALINK_ANY_MEDIATYPE, flags);
	} else {
		(void) show_aggr(handle, linkid, &state);
		if (state.gs_status != DLADM_STATUS_OK) {
			die_dlerr(state.gs_status, "failed to show aggr %s",
			    argv[optind]);
		}
	}
	ofmt_close(ofmt);
}

static dladm_status_t
print_phys_default(show_state_t *state, datalink_id_t linkid,
    const char *link, uint32_t flags, uint32_t media)
{
	dladm_phys_attr_t dpa;
	dladm_status_t status;
	link_fields_buf_t pattr;

	status = dladm_phys_info(handle, linkid, &dpa, state->ls_flags);
	if (status != DLADM_STATUS_OK)
		goto done;

	bzero(&pattr, sizeof (pattr));
	(void) snprintf(pattr.link_phys_device,
	    sizeof (pattr.link_phys_device), "%s", dpa.dp_dev);
	(void) dladm_media2str(media, pattr.link_phys_media);
	if (state->ls_flags == DLADM_OPT_ACTIVE) {
		boolean_t	islink;

		if (!dpa.dp_novanity) {
			(void) strlcpy(pattr.link_name, link,
			    sizeof (pattr.link_name));
			islink = B_TRUE;
		} else {
			/*
			 * This is a physical link that does not have
			 * vanity naming support.
			 */
			(void) strlcpy(pattr.link_name, dpa.dp_dev,
			    sizeof (pattr.link_name));
			islink = B_FALSE;
		}

		(void) get_linkstate(pattr.link_name, islink,
		    pattr.link_phys_state);
		(void) snprintf(pattr.link_phys_speed,
		    sizeof (pattr.link_phys_speed), "%u",
		    (uint_t)((get_ifspeed(pattr.link_name,
		    islink)) / 1000000ull));
		(void) get_linkduplex(pattr.link_name, islink,
		    pattr.link_phys_duplex);
	} else {
		(void) snprintf(pattr.link_name, sizeof (pattr.link_name),
		    "%s", link);
		(void) snprintf(pattr.link_flags, sizeof (pattr.link_flags),
		    "%c----", flags & DLADM_OPT_ACTIVE ? '-' : 'r');
	}

	ofmt_print(state->ls_ofmt, &pattr);

done:
	return (status);
}

typedef struct {
	show_state_t	*ms_state;
	char		*ms_link;
	dladm_macaddr_attr_t *ms_mac_attr;
} print_phys_mac_state_t;

/*
 *  callback for ofmt_print()
 */
static boolean_t
print_phys_one_mac_cb(ofmt_arg_t *ofarg, char *buf, uint_t bufsize)
{
	print_phys_mac_state_t *mac_state = ofarg->ofmt_cbarg;
	dladm_macaddr_attr_t *attr = mac_state->ms_mac_attr;
	boolean_t is_primary = (attr->ma_slot == 0);
	boolean_t is_parsable = mac_state->ms_state->ls_parsable;

	switch (ofarg->ofmt_id) {
	case PHYS_M_LINK:
		(void) snprintf(buf, bufsize, "%s",
		    (is_primary || is_parsable) ? mac_state->ms_link : " ");
		break;
	case PHYS_M_SLOT:
		if (is_primary)
			(void) snprintf(buf, bufsize, gettext("primary"));
		else
			(void) snprintf(buf, bufsize, "%d", attr->ma_slot);
		break;
	case PHYS_M_ADDRESS:
		(void) dladm_aggr_macaddr2str(attr->ma_addr, buf);
		break;
	case PHYS_M_INUSE:
		(void) snprintf(buf, bufsize, "%s",
		    attr->ma_flags & DLADM_MACADDR_USED ? gettext("yes") :
		    gettext("no"));
		break;
	case PHYS_M_CLIENT:
		/*
		 * CR 6678526: resolve link id to actual link name if
		 * it is valid.
		 */
		(void) snprintf(buf, bufsize, "%s", attr->ma_client_name);
		break;
	}

	return (B_TRUE);
}

typedef struct {
	show_state_t	*hs_state;
	char		*hs_link;
	dladm_hwgrp_attr_t *hs_grp_attr;
} print_phys_hwgrp_state_t;

static boolean_t
print_phys_one_hwgrp_cb(ofmt_arg_t *ofarg, char *buf, uint_t bufsize)
{
	int		i;
	boolean_t	first = B_TRUE;
	int		start = -1;
	int		end = -1;
	char		ringstr[RINGSTRLEN];
	char		ringsubstr[RINGSTRLEN];

	print_phys_hwgrp_state_t *hg_state = ofarg->ofmt_cbarg;
	dladm_hwgrp_attr_t *attr = hg_state->hs_grp_attr;

	switch (ofarg->ofmt_id) {
	case PHYS_H_LINK:
		(void) snprintf(buf, bufsize, "%s", attr->hg_link_name);
		break;
	case PHYS_H_RINGTYPE:
		(void) snprintf(buf, bufsize, "%s",
		    attr->hg_grp_type == DLADM_HWGRP_TYPE_RX ? "RX" : "TX");
		break;
	case PHYS_H_RINGS:
		ringstr[0] = '\0';
		for (i = 0; i < attr->hg_n_rings; i++) {
			uint_t 	index = attr->hg_rings[i];

			if (start == -1) {
				start = index;
				end = index;
			} else if (index == end + 1) {
				end = index;
			} else {
				if (start == end) {
					if (first) {
						(void) snprintf(
						    ringsubstr,
						    RINGSTRLEN, "%d",
						    start);
						first = B_FALSE;
					} else {
						(void) snprintf(
						    ringsubstr,
						    RINGSTRLEN, ",%d",
						    start);
					}
				} else {
					if (first) {
						(void) snprintf(
						    ringsubstr,
						    RINGSTRLEN,
						    "%d-%d",
						    start, end);
						first = B_FALSE;
					} else {
						(void) snprintf(
						    ringsubstr,
						    RINGSTRLEN,
						    ",%d-%d",
						    start, end);
					}
				}
				(void) strlcat(ringstr, ringsubstr,
				    RINGSTRLEN);
				start = index;
				end = index;
			}
		}
		/* The last one */
		if (start != -1) {
			if (first) {
				if (start == end) {
					(void) snprintf(buf, bufsize, "%d",
					    start);
				} else {
					(void) snprintf(buf, bufsize, "%d-%d",
					    start, end);
				}
			} else {
				if (start == end) {
					(void) snprintf(ringsubstr, RINGSTRLEN,
					    ",%d", start);
				} else {
					(void) snprintf(ringsubstr, RINGSTRLEN,
					    ",%d-%d", start, end);
				}
				(void) strlcat(ringstr, ringsubstr, RINGSTRLEN);
				(void) snprintf(buf, bufsize, "%s", ringstr);
			}
		}
		break;
	case PHYS_H_CLIENTS:
		if (attr->hg_client_names[0] == '\0') {
			(void) snprintf(buf, bufsize, "--");
		} else {
			(void) snprintf(buf, bufsize, "%s ",
			    attr->hg_client_names);
		}
		break;
	}

	return (B_TRUE);
}

/*
 * callback for dladm_walk_macaddr, invoked for each MAC address slot
 */
static boolean_t
print_phys_mac_callback(void *arg, dladm_macaddr_attr_t *attr)
{
	print_phys_mac_state_t *mac_state = arg;
	show_state_t *state = mac_state->ms_state;

	mac_state->ms_mac_attr = attr;
	ofmt_print(state->ls_ofmt, mac_state);

	return (B_TRUE);
}

/*
 * invoked by show-phys -m for each physical data-link
 */
static dladm_status_t
print_phys_mac(show_state_t *state, datalink_id_t linkid, char *link)
{
	print_phys_mac_state_t mac_state;

	mac_state.ms_state = state;
	mac_state.ms_link = link;

	return (dladm_walk_macaddr(handle, linkid, &mac_state,
	    print_phys_mac_callback));
}

/*
 * callback for dladm_walk_hwgrp, invoked for each MAC hwgrp
 */
static boolean_t
print_phys_hwgrp_callback(void *arg, dladm_hwgrp_attr_t *attr)
{
	print_phys_hwgrp_state_t *hwgrp_state = arg;
	show_state_t *state = hwgrp_state->hs_state;

	hwgrp_state->hs_grp_attr = attr;
	ofmt_print(state->ls_ofmt, hwgrp_state);

	return (B_TRUE);
}

/* invoked by show-phys -H for each physical data-link */
static dladm_status_t
print_phys_hwgrp(show_state_t *state, datalink_id_t linkid, char *link)
{
	print_phys_hwgrp_state_t hwgrp_state;

	hwgrp_state.hs_state = state;
	hwgrp_state.hs_link = link;
	return (dladm_walk_hwgrp(handle, linkid, &hwgrp_state,
	    print_phys_hwgrp_callback));
}

/*
 * Parse the "local=<laddr>,remote=<raddr>" sub-options for the -a option of
 * *-iptun subcommands.
 */
static void
iptun_process_addrarg(char *addrarg, iptun_params_t *params)
{
	char *addrval;

	while (*addrarg != '\0') {
		switch (getsubopt(&addrarg, iptun_addropts, &addrval)) {
		case IPTUN_LOCAL:
			params->iptun_param_flags |= IPTUN_PARAM_LADDR;
			if (strlcpy(params->iptun_param_laddr, addrval,
			    sizeof (params->iptun_param_laddr)) >=
			    sizeof (params->iptun_param_laddr))
				die("tunnel source address is too long");
			break;
		case IPTUN_REMOTE:
			params->iptun_param_flags |= IPTUN_PARAM_RADDR;
			if (strlcpy(params->iptun_param_raddr, addrval,
			    sizeof (params->iptun_param_raddr)) >=
			    sizeof (params->iptun_param_raddr))
				die("tunnel destination address is too long");
			break;
		default:
			die("invalid address type: %s", addrval);
			break;
		}
	}
}

/*
 * Convenience routine to process iptun-create/modify/delete subcommand
 * arguments.
 */
static void
iptun_process_args(int argc, char *argv[], const char *opts,
    iptun_params_t *params, uint32_t *flags, char *name, const char *use)
{
	int	option;
	char	*altroot = NULL;

	if (params != NULL)
		bzero(params, sizeof (*params));
	*flags = DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST;

	opterr = 0;
	while ((option = getopt_long(argc, argv, opts, iptun_lopts, NULL)) !=
	    -1) {
		switch (option) {
		case 'a':
			iptun_process_addrarg(optarg, params);
			break;
		case 'R':
			altroot = optarg;
			break;
		case 't':
			*flags &= ~DLADM_OPT_PERSIST;
			break;
		case 'T':
			params->iptun_param_type = iptun_gettypebyname(optarg);
			if (params->iptun_param_type == IPTUN_TYPE_UNKNOWN)
				die("unknown tunnel type: %s", optarg);
			params->iptun_param_flags |= IPTUN_PARAM_TYPE;
			break;
		default:
			die_opterr(optopt, option, use);
			break;
		}
	}

	/* Get the required tunnel name argument. */
	if (argc - optind != 1)
		usage();

	if (strlcpy(name, argv[optind], MAXLINKNAMELEN) >= MAXLINKNAMELEN)
		die("tunnel name is too long");

	if (altroot != NULL)
		altroot_cmd(altroot, argc, argv);
}

static void
do_create_iptun(int argc, char *argv[], const char *use)
{
	iptun_params_t	params;
	dladm_status_t	status;
	uint32_t	flags;
	char		name[MAXLINKNAMELEN];

	iptun_process_args(argc, argv, ":a:R:tT:", &params, &flags, name,
	    use);

	status = dladm_iptun_create(handle, name, &params, flags);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "could not create tunnel");
}

static void
do_delete_iptun(int argc, char *argv[], const char *use)
{
	uint32_t	flags;
	datalink_id_t	linkid;
	dladm_status_t	status;
	char		name[MAXLINKNAMELEN];

	iptun_process_args(argc, argv, ":R:t", NULL, &flags, name, use);

	status = dladm_name2info(handle, name, &linkid, NULL, NULL, NULL);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "could not delete tunnel");
	status = dladm_iptun_delete(handle, linkid, flags);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "could not delete tunnel");
}

static void
do_modify_iptun(int argc, char *argv[], const char *use)
{
	iptun_params_t	params;
	uint32_t	flags;
	dladm_status_t	status;
	char		name[MAXLINKNAMELEN];

	iptun_process_args(argc, argv, ":a:R:t", &params, &flags, name, use);

	if ((status = dladm_name2info(handle, name, &params.iptun_param_linkid,
	    NULL, NULL, NULL)) != DLADM_STATUS_OK)
		die_dlerr(status, "could not modify tunnel");
	status = dladm_iptun_modify(handle, &params, flags);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "could not modify tunnel");
}

static void
do_show_iptun(int argc, char *argv[], const char *use)
{
	char		option;
	datalink_id_t	linkid;
	uint32_t	flags = DLADM_OPT_ACTIVE;
	char		*name = NULL;
	dladm_status_t	status;
	const char	*fields_str = NULL;
	show_state_t	state;
	ofmt_handle_t	ofmt;
	ofmt_status_t	oferr;
	uint_t		ofmtflags = 0;

	bzero(&state, sizeof (state));
	opterr = 0;
	while ((option = getopt_long(argc, argv, ":pPo:",
	    iptun_lopts, NULL)) != -1) {
		switch (option) {
		case 'o':
			fields_str = optarg;
			break;
		case 'p':
			state.ls_parsable = B_TRUE;
			ofmtflags = OFMT_PARSABLE;
			break;
		case 'P':
			flags = DLADM_OPT_PERSIST;
			break;
		default:
			die_opterr(optopt, option, use);
			break;
		}
	}

	/*
	 * Get the optional tunnel name argument.  If there is one, it must
	 * be the last thing remaining on the command-line.
	 */
	if (argc - optind > 1)
		die(gettext(use));
	if (argc - optind == 1)
		name = argv[optind];

	oferr = ofmt_open(fields_str, iptun_fields, ofmtflags,
	    DLADM_DEFAULT_COL, &ofmt);
	ofmt_check(oferr, state.ls_parsable, ofmt, die, warn);

	state.ls_ofmt = ofmt;
	state.ls_flags = flags;

	if (name == NULL) {
		(void) dladm_walk_datalink_id(print_iptun_walker, handle,
		    &state, DATALINK_CLASS_IPTUN, DATALINK_ANY_MEDIATYPE,
		    flags);
		status = state.ls_status;
	} else {
		if ((status = dladm_name2info(handle, name, &linkid, NULL, NULL,
		    NULL)) == DLADM_STATUS_OK)
			status = print_iptun(handle, linkid, &state);
	}

	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "unable to obtain tunnel status");
}

/* ARGSUSED */
static void
do_up_iptun(int argc, char *argv[], const char *use)
{
	datalink_id_t	linkid = DATALINK_ALL_LINKID;
	dladm_status_t	status = DLADM_STATUS_OK;

	/*
	 * Get the optional tunnel name argument.  If there is one, it must
	 * be the last thing remaining on the command-line.
	 */
	if (argc - optind > 1)
		usage();
	if (argc - optind == 1) {
		status = dladm_name2info(handle, argv[optind], &linkid, NULL,
		    NULL, NULL);
	}
	if (status == DLADM_STATUS_OK)
		status = dladm_iptun_up(handle, linkid);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "unable to configure IP tunnel links");
}

/* ARGSUSED */
static void
do_down_iptun(int argc, char *argv[], const char *use)
{
	datalink_id_t	linkid = DATALINK_ALL_LINKID;
	dladm_status_t	status = DLADM_STATUS_OK;

	/*
	 * Get the optional tunnel name argument.  If there is one, it must
	 * be the last thing remaining on the command-line.
	 */
	if (argc - optind > 1)
		usage();
	if (argc - optind == 1) {
		status = dladm_name2info(handle, argv[optind], &linkid, NULL,
		    NULL, NULL);
	}
	if (status == DLADM_STATUS_OK)
		status = dladm_iptun_down(handle, linkid);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "unable to bring down IP tunnel links");
}

static iptun_type_t
iptun_gettypebyname(char *typestr)
{
	int i;

	for (i = 0; iptun_types[i].type_name != NULL; i++) {
		if (strncmp(iptun_types[i].type_name, typestr,
		    strlen(iptun_types[i].type_name)) == 0) {
			return (iptun_types[i].type_value);
		}
	}
	return (IPTUN_TYPE_UNKNOWN);
}

static const char *
iptun_gettypebyvalue(iptun_type_t type)
{
	int i;

	for (i = 0; iptun_types[i].type_name != NULL; i++) {
		if (iptun_types[i].type_value == type)
			return (iptun_types[i].type_name);
	}
	return (NULL);
}

static dladm_status_t
print_iptun(dladm_handle_t dh, datalink_id_t linkid, show_state_t *state)
{
	dladm_status_t		status;
	iptun_params_t		params;
	iptun_fields_buf_t	lbuf;
	const char		*laddr;
	const char		*raddr;

	params.iptun_param_linkid = linkid;
	status = dladm_iptun_getparams(dh, &params, state->ls_flags);
	if (status != DLADM_STATUS_OK)
		return (status);

	/* LINK */
	status = dladm_datalink_id2info(dh, linkid, NULL, NULL, NULL,
	    lbuf.iptun_name, sizeof (lbuf.iptun_name));
	if (status != DLADM_STATUS_OK)
		return (status);

	/* TYPE */
	(void) strlcpy(lbuf.iptun_type,
	    iptun_gettypebyvalue(params.iptun_param_type),
	    sizeof (lbuf.iptun_type));

	/* FLAGS */
	(void) memset(lbuf.iptun_flags, '-', IPTUN_NUM_FLAGS);
	lbuf.iptun_flags[IPTUN_NUM_FLAGS] = '\0';
	if (params.iptun_param_flags & IPTUN_PARAM_IPSECPOL)
		lbuf.iptun_flags[IPTUN_SFLAG_INDEX] = 's';
	if (params.iptun_param_flags & IPTUN_PARAM_IMPLICIT)
		lbuf.iptun_flags[IPTUN_IFLAG_INDEX] = 'i';

	/* LOCAL */
	if (params.iptun_param_flags & IPTUN_PARAM_LADDR)
		laddr = params.iptun_param_laddr;
	else
		laddr = (state->ls_parsable) ? "" : "--";
	(void) strlcpy(lbuf.iptun_laddr, laddr, sizeof (lbuf.iptun_laddr));

	/* REMOTE */
	if (params.iptun_param_flags & IPTUN_PARAM_RADDR)
		raddr = params.iptun_param_raddr;
	else
		raddr = (state->ls_parsable) ? "" : "--";
	(void) strlcpy(lbuf.iptun_raddr, raddr, sizeof (lbuf.iptun_raddr));

	ofmt_print(state->ls_ofmt, &lbuf);

	return (DLADM_STATUS_OK);
}

static int
print_iptun_walker(dladm_handle_t dh, datalink_id_t linkid, void *arg)
{
	((show_state_t *)arg)->ls_status = print_iptun(dh, linkid, arg);
	return (DLADM_WALK_CONTINUE);
}

static dladm_status_t
print_phys(show_state_t *state, datalink_id_t linkid)
{
	char			link[MAXLINKNAMELEN];
	uint32_t		flags;
	dladm_status_t		status;
	datalink_class_t	class;
	uint32_t		media;

	if ((status = dladm_datalink_id2info(handle, linkid, &flags, &class,
	    &media, link, MAXLINKNAMELEN)) != DLADM_STATUS_OK) {
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

	if (state->ls_mac)
		status = print_phys_mac(state, linkid, link);
	else if (state->ls_hwgrp)
		status = print_phys_hwgrp(state, linkid, link);
	else
		status = print_phys_default(state, linkid, link, flags, media);

done:
	return (status);
}

/* ARGSUSED */
static int
show_phys(dladm_handle_t dh, datalink_id_t linkid, void *arg)
{
	show_state_t	*state = arg;

	state->ls_status = print_phys(state, linkid);
	return (DLADM_WALK_CONTINUE);
}

/*
 * Print the active topology information.
 */
static dladm_status_t
print_vlan(show_state_t *state, datalink_id_t linkid, link_fields_buf_t *l)
{
	dladm_vlan_attr_t	vinfo;
	uint32_t		flags;
	dladm_status_t		status;

	if ((status = dladm_datalink_id2info(handle, linkid, &flags, NULL, NULL,
	    l->link_name, sizeof (l->link_name))) != DLADM_STATUS_OK) {
		goto done;
	}

	if (!(state->ls_flags & flags)) {
		status = DLADM_STATUS_NOTFOUND;
		goto done;
	}

	if ((status = dladm_vlan_info(handle, linkid, &vinfo,
	    state->ls_flags)) != DLADM_STATUS_OK ||
	    (status = dladm_datalink_id2info(handle, vinfo.dv_linkid, NULL,
	    NULL, NULL, l->link_over, sizeof (l->link_over))) !=
	    DLADM_STATUS_OK) {
		goto done;
	}

	(void) snprintf(l->link_vlan_vid, sizeof (l->link_vlan_vid), "%d",
	    vinfo.dv_vid);
	(void) snprintf(l->link_flags, sizeof (l->link_flags), "%c----",
	    vinfo.dv_force ? 'f' : '-');

done:
	return (status);
}

/* ARGSUSED */
static int
show_vlan(dladm_handle_t dh, datalink_id_t linkid, void *arg)
{
	show_state_t		*state = arg;
	dladm_status_t		status;
	link_fields_buf_t	lbuf;

	bzero(&lbuf, sizeof (link_fields_buf_t));
	status = print_vlan(state, linkid, &lbuf);
	if (status != DLADM_STATUS_OK)
		goto done;

	ofmt_print(state->ls_ofmt, &lbuf);

done:
	state->ls_status = status;
	return (DLADM_WALK_CONTINUE);
}

static void
do_show_phys(int argc, char *argv[], const char *use)
{
	int		option;
	uint32_t	flags = DLADM_OPT_ACTIVE;
	boolean_t	p_arg = B_FALSE;
	boolean_t	o_arg = B_FALSE;
	boolean_t	m_arg = B_FALSE;
	boolean_t	H_arg = B_FALSE;
	datalink_id_t	linkid = DATALINK_ALL_LINKID;
	show_state_t	state;
	dladm_status_t	status;
	char		*fields_str = NULL;
	char		*all_active_fields =
	    "link,media,state,speed,duplex,device";
	char		*all_inactive_fields = "link,device,media,flags";
	char		*all_mac_fields = "link,slot,address,inuse,client";
	char		*all_hwgrp_fields = "link,ringtype,rings,clients";
	const ofmt_field_t *pf;
	ofmt_handle_t	ofmt;
	ofmt_status_t	oferr;
	uint_t		ofmtflags = 0;

	bzero(&state, sizeof (state));
	opterr = 0;
	while ((option = getopt_long(argc, argv, ":pPo:mH",
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
		case 'o':
			o_arg = B_TRUE;
			fields_str = optarg;
			break;
		case 'm':
			m_arg = B_TRUE;
			break;
		case 'H':
			H_arg = B_TRUE;
			break;
		default:
			die_opterr(optopt, option, use);
			break;
		}
	}

	if (p_arg && !o_arg)
		die("-p requires -o");

	if (m_arg && H_arg)
		die("-m cannot combine with -H");

	if (p_arg && strcasecmp(fields_str, "all") == 0)
		die("\"-o all\" is invalid with -p");

	/* get link name (optional last argument) */
	if (optind == (argc-1)) {
		if ((status = dladm_name2info(handle, argv[optind], &linkid,
		    NULL, NULL, NULL)) != DLADM_STATUS_OK) {
			die_dlerr(status, "link %s is not valid", argv[optind]);
		}
	} else if (optind != argc) {
		usage();
	}

	state.ls_parsable = p_arg;
	state.ls_flags = flags;
	state.ls_donefirst = B_FALSE;
	state.ls_mac = m_arg;
	state.ls_hwgrp = H_arg;

	if (m_arg && !(flags & DLADM_OPT_ACTIVE)) {
		/*
		 * We can only display the factory MAC addresses of
		 * active data-links.
		 */
		die("-m not compatible with -P");
	}

	if (!o_arg || (o_arg && strcasecmp(fields_str, "all") == 0)) {
		if (state.ls_mac)
			fields_str = all_mac_fields;
		else if (state.ls_hwgrp)
			fields_str = all_hwgrp_fields;
		else if (state.ls_flags & DLADM_OPT_ACTIVE) {
			fields_str = all_active_fields;
		} else {
			fields_str = all_inactive_fields;
		}
	}

	if (state.ls_mac) {
		pf = phys_m_fields;
	} else if (state.ls_hwgrp) {
		pf = phys_h_fields;
	} else {
		pf = phys_fields;
	}

	if (state.ls_parsable)
		ofmtflags |= OFMT_PARSABLE;
	oferr = ofmt_open(fields_str, pf, ofmtflags, 0, &ofmt);
	ofmt_check(oferr, state.ls_parsable, ofmt, die, warn);
	state.ls_ofmt = ofmt;

	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(show_phys, handle, &state,
		    DATALINK_CLASS_PHYS, DATALINK_ANY_MEDIATYPE, flags);
	} else {
		(void) show_phys(handle, linkid, &state);
		if (state.ls_status != DLADM_STATUS_OK) {
			die_dlerr(state.ls_status,
			    "failed to show physical link %s", argv[optind]);
		}
	}
	ofmt_close(ofmt);
}

static void
do_show_vlan(int argc, char *argv[], const char *use)
{
	int		option;
	uint32_t	flags = DLADM_OPT_ACTIVE;
	boolean_t	p_arg = B_FALSE;
	datalink_id_t	linkid = DATALINK_ALL_LINKID;
	show_state_t	state;
	dladm_status_t	status;
	boolean_t	o_arg = B_FALSE;
	char		*fields_str = NULL;
	ofmt_handle_t	ofmt;
	ofmt_status_t	oferr;
	uint_t		ofmtflags = 0;

	bzero(&state, sizeof (state));

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":pPo:",
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
		case 'o':
			o_arg = B_TRUE;
			fields_str = optarg;
			break;
		default:
			die_opterr(optopt, option, use);
			break;
		}
	}

	/* get link name (optional last argument) */
	if (optind == (argc-1)) {
		if ((status = dladm_name2info(handle, argv[optind], &linkid,
		    NULL, NULL, NULL)) != DLADM_STATUS_OK) {
			die_dlerr(status, "link %s is not valid", argv[optind]);
		}
	} else if (optind != argc) {
		usage();
	}

	state.ls_parsable = p_arg;
	state.ls_flags = flags;
	state.ls_donefirst = B_FALSE;

	if (!o_arg || (o_arg && strcasecmp(fields_str, "all") == 0))
		fields_str = NULL;

	if (state.ls_parsable)
		ofmtflags |= OFMT_PARSABLE;
	oferr = ofmt_open(fields_str, vlan_fields, ofmtflags, 0, &ofmt);
	ofmt_check(oferr, state.ls_parsable, ofmt, die, warn);
	state.ls_ofmt = ofmt;

	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(show_vlan, handle, &state,
		    DATALINK_CLASS_VLAN, DATALINK_ANY_MEDIATYPE, flags);
	} else {
		(void) show_vlan(handle, linkid, &state);
		if (state.ls_status != DLADM_STATUS_OK) {
			die_dlerr(state.ls_status, "failed to show vlan %s",
			    argv[optind]);
		}
	}
	ofmt_close(ofmt);
}

static void
do_create_vnic(int argc, char *argv[], const char *use)
{
	datalink_id_t		linkid, dev_linkid;
	char			devname[MAXLINKNAMELEN];
	char			name[MAXLINKNAMELEN];
	boolean_t		l_arg = B_FALSE;
	uint32_t		flags = DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST;
	char			*altroot = NULL;
	int			option;
	char			*endp = NULL;
	dladm_status_t		status;
	vnic_mac_addr_type_t	mac_addr_type = VNIC_MAC_ADDR_TYPE_UNKNOWN;
	uchar_t			*mac_addr = NULL;
	int			mac_slot = -1;
	uint_t			maclen = 0, mac_prefix_len = 0;
	char			propstr[DLADM_STRSIZE];
	dladm_arg_list_t	*proplist = NULL;
	int			vid = 0;
	int			af = AF_UNSPEC;
	vrid_t			vrid = VRRP_VRID_NONE;

	opterr = 0;
	bzero(propstr, DLADM_STRSIZE);

	while ((option = getopt_long(argc, argv, ":tfR:l:m:n:p:r:v:V:A:H",
	    vnic_lopts, NULL)) != -1) {
		switch (option) {
		case 't':
			flags &= ~DLADM_OPT_PERSIST;
			break;
		case 'R':
			altroot = optarg;
			break;
		case 'l':
			if (strlcpy(devname, optarg, MAXLINKNAMELEN) >=
			    MAXLINKNAMELEN)
				die("link name too long");
			l_arg = B_TRUE;
			break;
		case 'm':
			if (mac_addr_type != VNIC_MAC_ADDR_TYPE_UNKNOWN)
				die("cannot specify -m option twice");

			if (strcmp(optarg, "fixed") == 0) {
				/*
				 * A fixed MAC address must be specified
				 * by its value, not by the keyword 'fixed'.
				 */
				die("'fixed' is not a valid MAC address");
			}
			if (dladm_vnic_str2macaddrtype(optarg,
			    &mac_addr_type) != DLADM_STATUS_OK) {
				mac_addr_type = VNIC_MAC_ADDR_TYPE_FIXED;
				/* MAC address specified by value */
				mac_addr = _link_aton(optarg, (int *)&maclen);
				if (mac_addr == NULL) {
					if (maclen == (uint_t)-1)
						die("invalid MAC address");
					else
						die("out of memory");
				}
			}
			break;
		case 'n':
			errno = 0;
			mac_slot = (int)strtol(optarg, &endp, 10);
			if (errno != 0 || *endp != '\0')
				die("invalid slot number");
			break;
		case 'p':
			(void) strlcat(propstr, optarg, DLADM_STRSIZE);
			if (strlcat(propstr, ",", DLADM_STRSIZE) >=
			    DLADM_STRSIZE)
				die("property list too long '%s'", propstr);
			break;
		case 'r':
			mac_addr = _link_aton(optarg, (int *)&mac_prefix_len);
			if (mac_addr == NULL) {
				if (mac_prefix_len == (uint_t)-1)
					die("invalid MAC address");
				else
					die("out of memory");
			}
			break;
		case 'V':
			if (!str2int(optarg, (int *)&vrid) ||
			    vrid < VRRP_VRID_MIN || vrid > VRRP_VRID_MAX) {
				die("invalid VRRP identifier '%s'", optarg);
			}

			break;
		case 'A':
			if (strcmp(optarg, "inet") == 0)
				af = AF_INET;
			else if (strcmp(optarg, "inet6") == 0)
				af = AF_INET6;
			else
				die("invalid address family '%s'", optarg);
			break;
		case 'v':
			if (vid != 0)
				die_optdup(option);

			if (!str2int(optarg, &vid) || vid < 1 || vid > 4094)
				die("invalid VLAN identifier '%s'", optarg);

			break;
		case 'f':
			flags |= DLADM_OPT_FORCE;
			break;
		default:
			die_opterr(optopt, option, use);
		}
	}

	if (mac_addr_type == VNIC_MAC_ADDR_TYPE_UNKNOWN)
		mac_addr_type = VNIC_MAC_ADDR_TYPE_AUTO;

	/*
	 * 'f' - force, flag can be specified only with 'v' - vlan.
	 */
	if ((flags & DLADM_OPT_FORCE) != 0 && vid == 0)
		die("-f option can only be used with -v");

	if (mac_prefix_len != 0 && mac_addr_type != VNIC_MAC_ADDR_TYPE_RANDOM &&
	    mac_addr_type != VNIC_MAC_ADDR_TYPE_FIXED)
		usage();

	if (mac_addr_type == VNIC_MAC_ADDR_TYPE_VRID) {
		if (vrid == VRRP_VRID_NONE || af == AF_UNSPEC ||
		    mac_addr != NULL || maclen != 0 || mac_slot != -1 ||
		    mac_prefix_len != 0) {
			usage();
		}
	} else if ((af != AF_UNSPEC || vrid != VRRP_VRID_NONE)) {
		usage();
	}

	/* check required options */
	if (!l_arg)
		usage();

	if (mac_slot != -1 && mac_addr_type != VNIC_MAC_ADDR_TYPE_FACTORY)
		usage();

	/* the VNIC id is the required operand */
	if (optind != (argc - 1))
		usage();

	if (strlcpy(name, argv[optind], MAXLINKNAMELEN) >= MAXLINKNAMELEN)
		die("link name too long '%s'", argv[optind]);

	if (!dladm_valid_linkname(name))
		die("invalid link name '%s'", argv[optind]);

	if (altroot != NULL)
		altroot_cmd(altroot, argc, argv);

	if (dladm_name2info(handle, devname, &dev_linkid, NULL, NULL, NULL) !=
	    DLADM_STATUS_OK)
		die("invalid link name '%s'", devname);

	if (dladm_parse_link_props(propstr, &proplist, B_FALSE)
	    != DLADM_STATUS_OK)
		die("invalid vnic property");

	status = dladm_vnic_create(handle, name, dev_linkid, mac_addr_type,
	    mac_addr, maclen, &mac_slot, mac_prefix_len, vid, vrid, af,
	    &linkid, proplist, flags);
	switch (status) {
	case DLADM_STATUS_OK:
		break;

	case DLADM_STATUS_LINKBUSY:
		die("VLAN over '%s' may not use default_tag ID "
		    "(see dladm(1M))", devname);
		break;

	default:
		die_dlerr(status, "vnic creation over %s failed", devname);
	}

	dladm_free_props(proplist);
	free(mac_addr);
}

static void
do_etherstub_check(const char *name, datalink_id_t linkid, boolean_t etherstub,
    uint32_t flags)
{
	boolean_t is_etherstub;
	dladm_vnic_attr_t attr;

	if (dladm_vnic_info(handle, linkid, &attr, flags) != DLADM_STATUS_OK) {
		/*
		 * Let the delete continue anyway.
		 */
		return;
	}
	is_etherstub = (attr.va_link_id == DATALINK_INVALID_LINKID);
	if (is_etherstub != etherstub) {
		die("'%s' is not %s", name,
		    (is_etherstub ? "a vnic" : "an etherstub"));
	}
}

static void
do_delete_vnic_common(int argc, char *argv[], const char *use,
    boolean_t etherstub)
{
	int option;
	uint32_t flags = DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST;
	datalink_id_t linkid;
	char *altroot = NULL;
	dladm_status_t status;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":R:t", lopts,
	    NULL)) != -1) {
		switch (option) {
		case 't':
			flags &= ~DLADM_OPT_PERSIST;
			break;
		case 'R':
			altroot = optarg;
			break;
		default:
			die_opterr(optopt, option, use);
		}
	}

	/* get vnic name (required last argument) */
	if (optind != (argc - 1))
		usage();

	if (altroot != NULL)
		altroot_cmd(altroot, argc, argv);

	status = dladm_name2info(handle, argv[optind], &linkid, NULL, NULL,
	    NULL);
	if (status != DLADM_STATUS_OK)
		die("invalid link name '%s'", argv[optind]);

	if ((flags & DLADM_OPT_ACTIVE) != 0) {
		do_etherstub_check(argv[optind], linkid, etherstub,
		    DLADM_OPT_ACTIVE);
	}
	if ((flags & DLADM_OPT_PERSIST) != 0) {
		do_etherstub_check(argv[optind], linkid, etherstub,
		    DLADM_OPT_PERSIST);
	}

	status = dladm_vnic_delete(handle, linkid, flags);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "vnic deletion failed");
}

static void
do_delete_vnic(int argc, char *argv[], const char *use)
{
	do_delete_vnic_common(argc, argv, use, B_FALSE);
}

/* ARGSUSED */
static void
do_up_vnic_common(int argc, char *argv[], const char *use, boolean_t vlan)
{
	datalink_id_t	linkid = DATALINK_ALL_LINKID;
	dladm_status_t	status;
	char 		*type;

	type = vlan ? "vlan" : "vnic";

	/*
	 * get the id or the name of the vnic/vlan (optional last argument)
	 */
	if (argc == 2) {
		status = dladm_name2info(handle, argv[1], &linkid, NULL, NULL,
		    NULL);
		if (status != DLADM_STATUS_OK)
			goto done;

	} else if (argc > 2) {
		usage();
	}

	if (vlan)
		status = dladm_vlan_up(handle, linkid);
	else
		status = dladm_vnic_up(handle, linkid, 0);

done:
	if (status != DLADM_STATUS_OK) {
		if (argc == 2) {
			die_dlerr(status,
			    "could not bring up %s '%s'", type, argv[1]);
		} else {
			die_dlerr(status, "could not bring %ss up", type);
		}
	}
}

static void
do_up_vnic(int argc, char *argv[], const char *use)
{
	do_up_vnic_common(argc, argv, use, B_FALSE);
}

static void
dump_vnics_head(const char *dev)
{
	if (strlen(dev))
		(void) printf("%s", dev);

	(void) printf("\tipackets  rbytes      opackets  obytes          ");

	if (strlen(dev))
		(void) printf("%%ipkts  %%opkts\n");
	else
		(void) printf("\n");
}

static void
dump_vnic_stat(const char *name, datalink_id_t vnic_id,
    show_vnic_state_t *state, pktsum_t *vnic_stats, pktsum_t *tot_stats)
{
	pktsum_t	diff_stats;
	pktsum_t	*old_stats = &state->vs_prevstats[vnic_id];

	dladm_stats_diff(&diff_stats, vnic_stats, old_stats);

	(void) printf("%s", name);

	(void) printf("\t%-10llu", diff_stats.ipackets);
	(void) printf("%-12llu", diff_stats.rbytes);
	(void) printf("%-10llu", diff_stats.opackets);
	(void) printf("%-12llu", diff_stats.obytes);

	if (tot_stats) {
		if (tot_stats->ipackets == 0) {
			(void) printf("\t-");
		} else {
			(void) printf("\t%-6.1f", (double)diff_stats.ipackets/
			    (double)tot_stats->ipackets * 100);
		}
		if (tot_stats->opackets == 0) {
			(void) printf("\t-");
		} else {
			(void) printf("\t%-6.1f", (double)diff_stats.opackets/
			    (double)tot_stats->opackets * 100);
		}
	}
	(void) printf("\n");

	*old_stats = *vnic_stats;
}

/*
 * Called from the walker dladm_vnic_walk_sys() for each vnic to display
 * vnic information or statistics.
 */
static dladm_status_t
print_vnic(show_vnic_state_t *state, datalink_id_t linkid)
{
	dladm_vnic_attr_t	attr, *vnic = &attr;
	dladm_status_t		status;
	boolean_t		is_etherstub;
	char			devname[MAXLINKNAMELEN];
	char			vnic_name[MAXLINKNAMELEN];
	char			mstr[MAXMACADDRLEN * 3];
	vnic_fields_buf_t	vbuf;

	if ((status = dladm_vnic_info(handle, linkid, vnic, state->vs_flags)) !=
	    DLADM_STATUS_OK)
		return (status);

	is_etherstub = (vnic->va_link_id == DATALINK_INVALID_LINKID);
	if (state->vs_etherstub != is_etherstub) {
		/*
		 * Want all etherstub but it's not one, or want
		 * non-etherstub and it's one.
		 */
		return (DLADM_STATUS_OK);
	}

	if (state->vs_link_id != DATALINK_ALL_LINKID) {
		if (state->vs_link_id != vnic->va_link_id)
			return (DLADM_STATUS_OK);
	}

	if (dladm_datalink_id2info(handle, linkid, NULL, NULL,
	    NULL, vnic_name, sizeof (vnic_name)) != DLADM_STATUS_OK)
		return (DLADM_STATUS_BADARG);

	bzero(devname, sizeof (devname));
	if (!is_etherstub &&
	    dladm_datalink_id2info(handle, vnic->va_link_id, NULL, NULL,
	    NULL, devname, sizeof (devname)) != DLADM_STATUS_OK)
		(void) sprintf(devname, "?");

	state->vs_found = B_TRUE;
	if (state->vs_stats) {
		/* print vnic statistics */
		pktsum_t vnic_stats;

		if (state->vs_firstonly) {
			if (state->vs_donefirst)
				return (0);
			state->vs_donefirst = B_TRUE;
		}

		if (!state->vs_printstats) {
			/*
			 * get vnic statistics and add to the sum for the
			 * named device.
			 */
			get_link_stats(vnic_name, &vnic_stats);
			dladm_stats_total(&state->vs_totalstats, &vnic_stats,
			    &state->vs_prevstats[vnic->va_vnic_id]);
		} else {
			/* get and print vnic statistics */
			get_link_stats(vnic_name, &vnic_stats);
			dump_vnic_stat(vnic_name, linkid, state, &vnic_stats,
			    &state->vs_totalstats);
		}
		return (DLADM_STATUS_OK);
	} else {
		(void) snprintf(vbuf.vnic_link, sizeof (vbuf.vnic_link),
		    "%s", vnic_name);

		if (!is_etherstub) {

			(void) snprintf(vbuf.vnic_over, sizeof (vbuf.vnic_over),
			    "%s", devname);
			(void) snprintf(vbuf.vnic_speed,
			    sizeof (vbuf.vnic_speed), "%u",
			    (uint_t)((get_ifspeed(vnic_name, B_TRUE))
			    / 1000000ull));

			switch (vnic->va_mac_addr_type) {
			case VNIC_MAC_ADDR_TYPE_FIXED:
			case VNIC_MAC_ADDR_TYPE_PRIMARY:
				(void) snprintf(vbuf.vnic_macaddrtype,
				    sizeof (vbuf.vnic_macaddrtype),
				    gettext("fixed"));
				break;
			case VNIC_MAC_ADDR_TYPE_RANDOM:
				(void) snprintf(vbuf.vnic_macaddrtype,
				    sizeof (vbuf.vnic_macaddrtype),
				    gettext("random"));
				break;
			case VNIC_MAC_ADDR_TYPE_FACTORY:
				(void) snprintf(vbuf.vnic_macaddrtype,
				    sizeof (vbuf.vnic_macaddrtype),
				    gettext("factory, slot %d"),
				    vnic->va_mac_slot);
				break;
			case VNIC_MAC_ADDR_TYPE_VRID:
				(void) snprintf(vbuf.vnic_macaddrtype,
				    sizeof (vbuf.vnic_macaddrtype),
				    gettext("vrrp, %d/%s"),
				    vnic->va_vrid, vnic->va_af == AF_INET ?
				    "inet" : "inet6");
				break;
			}

			if (strlen(vbuf.vnic_macaddrtype) > 0) {
				(void) snprintf(vbuf.vnic_macaddr,
				    sizeof (vbuf.vnic_macaddr), "%s",
				    dladm_aggr_macaddr2str(vnic->va_mac_addr,
				    mstr));
			}

			(void) snprintf(vbuf.vnic_vid, sizeof (vbuf.vnic_vid),
			    "%d", vnic->va_vid);
		}

		ofmt_print(state->vs_ofmt, &vbuf);

		return (DLADM_STATUS_OK);
	}
}

/* ARGSUSED */
static int
show_vnic(dladm_handle_t dh, datalink_id_t linkid, void *arg)
{
	show_vnic_state_t	*state = arg;

	state->vs_status = print_vnic(state, linkid);
	return (DLADM_WALK_CONTINUE);
}

static void
do_show_vnic_common(int argc, char *argv[], const char *use,
    boolean_t etherstub)
{
	int			option;
	boolean_t		s_arg = B_FALSE;
	boolean_t		i_arg = B_FALSE;
	boolean_t		l_arg = B_FALSE;
	uint32_t		interval = 0, flags = DLADM_OPT_ACTIVE;
	datalink_id_t		linkid = DATALINK_ALL_LINKID;
	datalink_id_t		dev_linkid = DATALINK_ALL_LINKID;
	show_vnic_state_t	state;
	dladm_status_t		status;
	boolean_t		o_arg = B_FALSE;
	char			*fields_str = NULL;
	const ofmt_field_t	*pf;
	char			*all_e_fields = "link";
	ofmt_handle_t		ofmt;
	ofmt_status_t		oferr;
	uint_t			ofmtflags = 0;

	bzero(&state, sizeof (state));
	opterr = 0;
	while ((option = getopt_long(argc, argv, ":pPl:si:o:", lopts,
	    NULL)) != -1) {
		switch (option) {
		case 'p':
			state.vs_parsable = B_TRUE;
			break;
		case 'P':
			flags = DLADM_OPT_PERSIST;
			break;
		case 'l':
			if (etherstub)
				die("option not supported for this command");

			if (strlcpy(state.vs_link, optarg, MAXLINKNAMELEN) >=
			    MAXLINKNAMELEN)
				die("link name too long");

			l_arg = B_TRUE;
			break;
		case 's':
			if (s_arg) {
				die("the option -s cannot be specified "
				    "more than once");
			}
			s_arg = B_TRUE;
			break;
		case 'i':
			if (i_arg) {
				die("the option -i cannot be specified "
				    "more than once");
			}
			i_arg = B_TRUE;
			if (!dladm_str2interval(optarg, &interval))
				die("invalid interval value '%s'", optarg);
			break;
		case 'o':
			o_arg = B_TRUE;
			fields_str = optarg;
			break;
		default:
			die_opterr(optopt, option, use);
		}
	}

	if (i_arg && !s_arg)
		die("the option -i can be used only with -s");

	/* get vnic ID (optional last argument) */
	if (optind == (argc - 1)) {
		status = dladm_name2info(handle, argv[optind], &linkid, NULL,
		    NULL, NULL);
		if (status != DLADM_STATUS_OK) {
			die_dlerr(status, "invalid vnic name '%s'",
			    argv[optind]);
		}
		(void) strlcpy(state.vs_vnic, argv[optind], MAXLINKNAMELEN);
	} else if (optind != argc) {
		usage();
	}

	if (l_arg) {
		status = dladm_name2info(handle, state.vs_link, &dev_linkid,
		    NULL, NULL, NULL);
		if (status != DLADM_STATUS_OK) {
			die_dlerr(status, "invalid link name '%s'",
			    state.vs_link);
		}
	}

	state.vs_vnic_id = linkid;
	state.vs_link_id = dev_linkid;
	state.vs_etherstub = etherstub;
	state.vs_found = B_FALSE;
	state.vs_flags = flags;

	if (!o_arg || (o_arg && strcasecmp(fields_str, "all") == 0)) {
		if (etherstub)
			fields_str = all_e_fields;
	}
	pf = vnic_fields;

	if (state.vs_parsable)
		ofmtflags |= OFMT_PARSABLE;
	oferr = ofmt_open(fields_str, pf, ofmtflags, 0, &ofmt);
	ofmt_check(oferr, state.vs_parsable, ofmt, die, warn);
	state.vs_ofmt = ofmt;

	if (s_arg) {
		/* Display vnic statistics */
		vnic_stats(&state, interval);
		ofmt_close(ofmt);
		return;
	}

	/* Display vnic information */
	state.vs_donefirst = B_FALSE;

	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(show_vnic, handle, &state,
		    DATALINK_CLASS_VNIC | DATALINK_CLASS_ETHERSTUB,
		    DATALINK_ANY_MEDIATYPE, flags);
	} else {
		(void) show_vnic(handle, linkid, &state);
		if (state.vs_status != DLADM_STATUS_OK) {
			ofmt_close(ofmt);
			die_dlerr(state.vs_status, "failed to show vnic '%s'",
			    state.vs_vnic);
		}
	}
	ofmt_close(ofmt);
}

static void
do_show_vnic(int argc, char *argv[], const char *use)
{
	do_show_vnic_common(argc, argv, use, B_FALSE);
}

static void
do_create_etherstub(int argc, char *argv[], const char *use)
{
	uint32_t flags;
	char *altroot = NULL;
	int option;
	dladm_status_t status;
	char name[MAXLINKNAMELEN];
	uchar_t mac_addr[ETHERADDRL];

	name[0] = '\0';
	bzero(mac_addr, sizeof (mac_addr));
	flags = DLADM_OPT_ANCHOR | DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST;

	opterr = 0;
	while ((option = getopt_long(argc, argv, "tR:",
	    etherstub_lopts, NULL)) != -1) {
		switch (option) {
		case 't':
			flags &= ~DLADM_OPT_PERSIST;
			break;
		case 'R':
			altroot = optarg;
			break;
		default:
			die_opterr(optopt, option, use);
		}
	}

	/* the etherstub id is the required operand */
	if (optind != (argc - 1))
		usage();

	if (strlcpy(name, argv[optind], MAXLINKNAMELEN) >= MAXLINKNAMELEN)
		die("link name too long '%s'", argv[optind]);

	if (!dladm_valid_linkname(name))
		die("invalid link name '%s'", argv[optind]);

	if (altroot != NULL)
		altroot_cmd(altroot, argc, argv);

	status = dladm_vnic_create(handle, name, DATALINK_INVALID_LINKID,
	    VNIC_MAC_ADDR_TYPE_AUTO, mac_addr, ETHERADDRL, NULL, 0, 0,
	    VRRP_VRID_NONE, AF_UNSPEC, NULL, NULL, flags);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "etherstub creation failed");
}

static void
do_delete_etherstub(int argc, char *argv[], const char *use)
{
	do_delete_vnic_common(argc, argv, use, B_TRUE);
}

/* ARGSUSED */
static void
do_show_etherstub(int argc, char *argv[], const char *use)
{
	do_show_vnic_common(argc, argv, use, B_TRUE);
}

/* ARGSUSED */
static void
do_up_simnet(int argc, char *argv[], const char *use)
{
	(void) dladm_simnet_up(handle, DATALINK_ALL_LINKID, 0);
}

static void
do_create_simnet(int argc, char *argv[], const char *use)
{
	uint32_t flags;
	char *altroot = NULL;
	char *media = NULL;
	uint32_t mtype = DL_ETHER;
	int option;
	dladm_status_t status;
	char name[MAXLINKNAMELEN];

	name[0] = '\0';
	flags = DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":tR:m:",
	    simnet_lopts, NULL)) != -1) {
		switch (option) {
		case 't':
			flags &= ~DLADM_OPT_PERSIST;
			break;
		case 'R':
			altroot = optarg;
			break;
		case 'm':
			media = optarg;
			break;
		default:
			die_opterr(optopt, option, use);
		}
	}

	/* the simnet id is the required operand */
	if (optind != (argc - 1))
		usage();

	if (strlcpy(name, argv[optind], MAXLINKNAMELEN) >= MAXLINKNAMELEN)
		die("link name too long '%s'", argv[optind]);

	if (!dladm_valid_linkname(name))
		die("invalid link name '%s'", name);

	if (media != NULL) {
		mtype = dladm_str2media(media);
		if (mtype != DL_ETHER && mtype != DL_WIFI)
			die("media type '%s' is not supported", media);
	}

	if (altroot != NULL)
		altroot_cmd(altroot, argc, argv);

	status = dladm_simnet_create(handle, name, mtype, flags);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "simnet creation failed");
}

static void
do_delete_simnet(int argc, char *argv[], const char *use)
{
	int option;
	uint32_t flags = DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST;
	datalink_id_t linkid;
	char *altroot = NULL;
	dladm_status_t status;
	dladm_simnet_attr_t slinfo;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":tR:", simnet_lopts,
	    NULL)) != -1) {
		switch (option) {
		case 't':
			flags &= ~DLADM_OPT_PERSIST;
			break;
		case 'R':
			altroot = optarg;
			break;
		default:
			die_opterr(optopt, option, use);
		}
	}

	/* get simnet name (required last argument) */
	if (optind != (argc - 1))
		usage();

	if (!dladm_valid_linkname(argv[optind]))
		die("invalid link name '%s'", argv[optind]);

	if (altroot != NULL)
		altroot_cmd(altroot, argc, argv);

	status = dladm_name2info(handle, argv[optind], &linkid, NULL, NULL,
	    NULL);
	if (status != DLADM_STATUS_OK)
		die("simnet '%s' not found", argv[optind]);

	if ((status = dladm_simnet_info(handle, linkid, &slinfo,
	    flags)) != DLADM_STATUS_OK)
		die_dlerr(status, "failed to retrieve simnet information");

	status = dladm_simnet_delete(handle, linkid, flags);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "simnet deletion failed");
}

static void
do_modify_simnet(int argc, char *argv[], const char *use)
{
	int option;
	uint32_t flags = DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST;
	datalink_id_t linkid;
	datalink_id_t peer_linkid;
	char *altroot = NULL;
	dladm_status_t status;
	boolean_t p_arg = B_FALSE;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":tR:p:", simnet_lopts,
	    NULL)) != -1) {
		switch (option) {
		case 't':
			flags &= ~DLADM_OPT_PERSIST;
			break;
		case 'R':
			altroot = optarg;
			break;
		case 'p':
			if (p_arg)
				die_optdup(option);
			p_arg = B_TRUE;
			if (strcasecmp(optarg, "none") == 0)
				peer_linkid = DATALINK_INVALID_LINKID;
			else if (dladm_name2info(handle, optarg, &peer_linkid,
			    NULL, NULL, NULL) != DLADM_STATUS_OK)
				die("invalid peer link name '%s'", optarg);
			break;
		default:
			die_opterr(optopt, option, use);
		}
	}

	/* get simnet name (required last argument) */
	if (optind != (argc - 1))
		usage();

	/* Nothing to do if no peer link argument */
	if (!p_arg)
		return;

	if (altroot != NULL)
		altroot_cmd(altroot, argc, argv);

	status = dladm_name2info(handle, argv[optind], &linkid, NULL, NULL,
	    NULL);
	if (status != DLADM_STATUS_OK)
		die("invalid link name '%s'", argv[optind]);

	status = dladm_simnet_modify(handle, linkid, peer_linkid, flags);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "simnet modification failed");
}

static dladm_status_t
print_simnet(show_state_t *state, datalink_id_t linkid)
{
	dladm_simnet_attr_t	slinfo;
	uint32_t		flags;
	dladm_status_t		status;
	simnet_fields_buf_t	slbuf;
	char			mstr[ETHERADDRL * 3];

	bzero(&slbuf, sizeof (slbuf));
	if ((status = dladm_datalink_id2info(handle, linkid, &flags, NULL, NULL,
	    slbuf.simnet_name, sizeof (slbuf.simnet_name)))
	    != DLADM_STATUS_OK)
		return (status);

	if (!(state->ls_flags & flags))
		return (DLADM_STATUS_NOTFOUND);

	if ((status = dladm_simnet_info(handle, linkid, &slinfo,
	    state->ls_flags)) != DLADM_STATUS_OK)
		return (status);

	if (slinfo.sna_peer_link_id != DATALINK_INVALID_LINKID &&
	    (status = dladm_datalink_id2info(handle, slinfo.sna_peer_link_id,
	    NULL, NULL, NULL, slbuf.simnet_otherlink,
	    sizeof (slbuf.simnet_otherlink))) !=
	    DLADM_STATUS_OK)
		return (status);

	if (slinfo.sna_mac_len > sizeof (slbuf.simnet_macaddr))
		return (DLADM_STATUS_BADVAL);

	(void) strlcpy(slbuf.simnet_macaddr,
	    dladm_aggr_macaddr2str(slinfo.sna_mac_addr, mstr),
	    sizeof (slbuf.simnet_macaddr));
	(void) dladm_media2str(slinfo.sna_type, slbuf.simnet_media);

	ofmt_print(state->ls_ofmt, &slbuf);
	return (status);
}

/* ARGSUSED */
static int
show_simnet(dladm_handle_t dh, datalink_id_t linkid, void *arg)
{
	show_state_t		*state = arg;

	state->ls_status = print_simnet(state, linkid);
	return (DLADM_WALK_CONTINUE);
}

static void
do_show_simnet(int argc, char *argv[], const char *use)
{
	int		option;
	uint32_t	flags = DLADM_OPT_ACTIVE;
	boolean_t	p_arg = B_FALSE;
	datalink_id_t	linkid = DATALINK_ALL_LINKID;
	show_state_t	state;
	dladm_status_t	status;
	boolean_t	o_arg = B_FALSE;
	ofmt_handle_t	ofmt;
	ofmt_status_t	oferr;
	char		*all_fields = "link,media,macaddress,otherlink";
	char		*fields_str = all_fields;
	uint_t		ofmtflags = 0;

	bzero(&state, sizeof (state));

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":pPo:",
	    show_lopts, NULL)) != -1) {
		switch (option) {
		case 'p':
			if (p_arg)
				die_optdup(option);

			p_arg = B_TRUE;
			state.ls_parsable = p_arg;
			break;
		case 'P':
			if (flags != DLADM_OPT_ACTIVE)
				die_optdup(option);

			flags = DLADM_OPT_PERSIST;
			break;
		case 'o':
			o_arg = B_TRUE;
			fields_str = optarg;
			break;
		default:
			die_opterr(optopt, option, use);
			break;
		}
	}

	if (p_arg && !o_arg)
		die("-p requires -o");

	if (strcasecmp(fields_str, "all") == 0) {
		if (p_arg)
			die("\"-o all\" is invalid with -p");
		fields_str = all_fields;
	}

	/* get link name (optional last argument) */
	if (optind == (argc-1)) {
		if ((status = dladm_name2info(handle, argv[optind], &linkid,
		    NULL, NULL, NULL)) != DLADM_STATUS_OK) {
			die_dlerr(status, "link %s is not valid", argv[optind]);
		}
	} else if (optind != argc) {
		usage();
	}

	state.ls_flags = flags;
	state.ls_donefirst = B_FALSE;
	if (state.ls_parsable)
		ofmtflags |= OFMT_PARSABLE;
	oferr = ofmt_open(fields_str, simnet_fields, ofmtflags, 0, &ofmt);
	ofmt_check(oferr, state.ls_parsable, ofmt, die, warn);
	state.ls_ofmt = ofmt;

	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(show_simnet, handle, &state,
		    DATALINK_CLASS_SIMNET, DATALINK_ANY_MEDIATYPE, flags);
	} else {
		(void) show_simnet(handle, linkid, &state);
		if (state.ls_status != DLADM_STATUS_OK) {
			ofmt_close(ofmt);
			die_dlerr(state.ls_status, "failed to show simnet %s",
			    argv[optind]);
		}
	}
	ofmt_close(ofmt);
}

static void
link_stats(datalink_id_t linkid, uint_t interval, char *fields_str,
    show_state_t *state)
{
	ofmt_handle_t	ofmt;
	ofmt_status_t	oferr;
	uint_t		ofmtflags = 0;

	if (state->ls_parsable)
		ofmtflags |= OFMT_PARSABLE;
	oferr = ofmt_open(fields_str, link_s_fields, ofmtflags, 0, &ofmt);
	ofmt_check(oferr, state->ls_parsable, ofmt, die, warn);
	state->ls_ofmt = ofmt;

	/*
	 * If an interval is specified, continuously show the stats
	 * only for the first MAC port.
	 */
	state->ls_firstonly = (interval != 0);

	for (;;) {
		state->ls_donefirst = B_FALSE;
		if (linkid == DATALINK_ALL_LINKID) {
			(void) dladm_walk_datalink_id(show_link_stats, handle,
			    state, DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE,
			    DLADM_OPT_ACTIVE);
		} else {
			(void) show_link_stats(handle, linkid, state);
		}

		if (interval == 0)
			break;

		(void) fflush(stdout);
		(void) sleep(interval);
	}
	ofmt_close(ofmt);
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
		state->gs_donefirst = B_FALSE;
		if (linkid == DATALINK_ALL_LINKID)
			(void) dladm_walk_datalink_id(show_aggr, handle, state,
			    DATALINK_CLASS_AGGR, DATALINK_ANY_MEDIATYPE,
			    DLADM_OPT_ACTIVE);
		else
			(void) show_aggr(handle, linkid, state);

		if (interval == 0)
			break;

		(void) fflush(stdout);
		(void) sleep(interval);
	}
}

/* ARGSUSED */
static void
vnic_stats(show_vnic_state_t *sp, uint32_t interval)
{
	show_vnic_state_t	state;
	boolean_t		specific_link, specific_dev;

	/* Display vnic statistics */
	dump_vnics_head(sp->vs_link);

	bzero(&state, sizeof (state));
	state.vs_stats = B_TRUE;
	state.vs_vnic_id = sp->vs_vnic_id;
	state.vs_link_id = sp->vs_link_id;

	/*
	 * If an interval is specified, and a vnic ID is not specified,
	 * continuously show the stats only for the first vnic.
	 */
	specific_link = (sp->vs_vnic_id != DATALINK_ALL_LINKID);
	specific_dev = (sp->vs_link_id != DATALINK_ALL_LINKID);

	for (;;) {
		/* Get stats for each vnic */
		state.vs_found = B_FALSE;
		state.vs_donefirst = B_FALSE;
		state.vs_printstats = B_FALSE;
		state.vs_flags = DLADM_OPT_ACTIVE;

		if (!specific_link) {
			(void) dladm_walk_datalink_id(show_vnic, handle, &state,
			    DATALINK_CLASS_VNIC, DATALINK_ANY_MEDIATYPE,
			    DLADM_OPT_ACTIVE);
		} else {
			(void) show_vnic(handle, sp->vs_vnic_id, &state);
			if (state.vs_status != DLADM_STATUS_OK) {
				die_dlerr(state.vs_status,
				    "failed to show vnic '%s'", sp->vs_vnic);
			}
		}

		if (specific_link && !state.vs_found)
			die("non-existent vnic '%s'", sp->vs_vnic);
		if (specific_dev && !state.vs_found)
			die("device %s has no vnics", sp->vs_link);

		/* Show totals */
		if ((specific_link | specific_dev) && !interval) {
			(void) printf("Total");
			(void) printf("\t%-10llu",
			    state.vs_totalstats.ipackets);
			(void) printf("%-12llu",
			    state.vs_totalstats.rbytes);
			(void) printf("%-10llu",
			    state.vs_totalstats.opackets);
			(void) printf("%-12llu\n",
			    state.vs_totalstats.obytes);
		}

		/* Show stats for each vnic */
		state.vs_donefirst = B_FALSE;
		state.vs_printstats = B_TRUE;

		if (!specific_link) {
			(void) dladm_walk_datalink_id(show_vnic, handle, &state,
			    DATALINK_CLASS_VNIC, DATALINK_ANY_MEDIATYPE,
			    DLADM_OPT_ACTIVE);
		} else {
			(void) show_vnic(handle, sp->vs_vnic_id, &state);
			if (state.vs_status != DLADM_STATUS_OK) {
				die_dlerr(state.vs_status,
				    "failed to show vnic '%s'", sp->vs_vnic);
			}
		}

		if (interval == 0)
			break;

		(void) fflush(stdout);
		(void) sleep(interval);
	}
}

static void
get_mac_stats(const char *dev, pktsum_t *stats)
{
	kstat_ctl_t	*kcp;
	kstat_t		*ksp;
	char module[DLPI_LINKNAME_MAX];
	uint_t instance;


	bzero(stats, sizeof (*stats));

	if (dlpi_parselink(dev, module, &instance) != DLPI_SUCCESS)
		return;

	if ((kcp = kstat_open()) == NULL) {
		warn("kstat open operation failed");
		return;
	}

	ksp = dladm_kstat_lookup(kcp, module, instance, "mac", NULL);
	if (ksp != NULL)
		dladm_get_stats(kcp, ksp, stats);

	(void) kstat_close(kcp);

}

static void
get_link_stats(const char *link, pktsum_t *stats)
{
	kstat_ctl_t	*kcp;
	kstat_t		*ksp;

	bzero(stats, sizeof (*stats));

	if ((kcp = kstat_open()) == NULL) {
		warn("kstat_open operation failed");
		return;
	}

	ksp = dladm_kstat_lookup(kcp, "link", 0, link, NULL);

	if (ksp != NULL)
		dladm_get_stats(kcp, ksp, stats);

	(void) kstat_close(kcp);
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

	if (dladm_kstat_value(ksp, stat, type, val) < 0)
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
		(void) strlcpy(buf, "?", DLADM_STRSIZE);
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

static int
parse_wifi_fields(char *str, ofmt_handle_t *ofmt, uint_t cmdtype,
    boolean_t parsable)
{
	ofmt_field_t	*template, *of;
	ofmt_cb_t	*fn;
	ofmt_status_t	oferr;

	if (cmdtype == WIFI_CMD_SCAN) {
		template = wifi_common_fields;
		if (str == NULL)
			str = def_scan_wifi_fields;
		if (strcasecmp(str, "all") == 0)
			str = all_scan_wifi_fields;
		fn = print_wlan_attr_cb;
	} else if (cmdtype == WIFI_CMD_SHOW) {
		bcopy(wifi_common_fields, &wifi_show_fields[2],
		    sizeof (wifi_common_fields));
		template = wifi_show_fields;
		if (str == NULL)
			str = def_show_wifi_fields;
		if (strcasecmp(str, "all") == 0)
			str = all_show_wifi_fields;
		fn = print_link_attr_cb;
	} else {
		return (-1);
	}

	for (of = template; of->of_name != NULL; of++) {
		if (of->of_cb == NULL)
			of->of_cb = fn;
	}

	oferr = ofmt_open(str, template, (parsable ? OFMT_PARSABLE : 0),
	    0, ofmt);
	ofmt_check(oferr, parsable, *ofmt, die, warn);
	return (0);
}

typedef struct print_wifi_state {
	char		*ws_link;
	boolean_t	ws_parsable;
	boolean_t	ws_header;
	ofmt_handle_t	ws_ofmt;
} print_wifi_state_t;

typedef struct  wlan_scan_args_s {
	print_wifi_state_t	*ws_state;
	void			*ws_attr;
} wlan_scan_args_t;

static boolean_t
print_wlan_attr_cb(ofmt_arg_t *ofarg, char *buf, uint_t bufsize)
{
	wlan_scan_args_t	*w = ofarg->ofmt_cbarg;
	print_wifi_state_t	*statep = w->ws_state;
	dladm_wlan_attr_t	*attrp = w->ws_attr;
	char			tmpbuf[DLADM_STRSIZE];

	if (ofarg->ofmt_id == 0) {
		(void) strlcpy(buf, (char *)statep->ws_link, bufsize);
		return (B_TRUE);
	}

	if ((ofarg->ofmt_id & attrp->wa_valid) == 0)
		return (B_TRUE);

	switch (ofarg->ofmt_id) {
	case DLADM_WLAN_ATTR_ESSID:
		(void) dladm_wlan_essid2str(&attrp->wa_essid, tmpbuf);
		break;
	case DLADM_WLAN_ATTR_BSSID:
		(void) dladm_wlan_bssid2str(&attrp->wa_bssid, tmpbuf);
		break;
	case DLADM_WLAN_ATTR_SECMODE:
		(void) dladm_wlan_secmode2str(&attrp->wa_secmode, tmpbuf);
		break;
	case DLADM_WLAN_ATTR_STRENGTH:
		(void) dladm_wlan_strength2str(&attrp->wa_strength, tmpbuf);
		break;
	case DLADM_WLAN_ATTR_MODE:
		(void) dladm_wlan_mode2str(&attrp->wa_mode, tmpbuf);
		break;
	case DLADM_WLAN_ATTR_SPEED:
		(void) dladm_wlan_speed2str(&attrp->wa_speed, tmpbuf);
		(void) strlcat(tmpbuf, "Mb", sizeof (tmpbuf));
		break;
	case DLADM_WLAN_ATTR_AUTH:
		(void) dladm_wlan_auth2str(&attrp->wa_auth, tmpbuf);
		break;
	case DLADM_WLAN_ATTR_BSSTYPE:
		(void) dladm_wlan_bsstype2str(&attrp->wa_bsstype, tmpbuf);
		break;
	}
	(void) strlcpy(buf, tmpbuf, bufsize);

	return (B_TRUE);
}

static boolean_t
print_scan_results(void *arg, dladm_wlan_attr_t *attrp)
{
	print_wifi_state_t	*statep = arg;
	wlan_scan_args_t	warg;

	bzero(&warg, sizeof (warg));
	warg.ws_state = statep;
	warg.ws_attr = attrp;
	ofmt_print(statep->ws_ofmt, &warg);
	return (B_TRUE);
}

static int
scan_wifi(dladm_handle_t dh, datalink_id_t linkid, void *arg)
{
	print_wifi_state_t	*statep = arg;
	dladm_status_t		status;
	char			link[MAXLINKNAMELEN];

	if ((status = dladm_datalink_id2info(dh, linkid, NULL, NULL, NULL, link,
	    sizeof (link))) != DLADM_STATUS_OK) {
		return (DLADM_WALK_CONTINUE);
	}

	statep->ws_link = link;
	status = dladm_wlan_scan(dh, linkid, statep, print_scan_results);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "cannot scan link '%s'", statep->ws_link);

	return (DLADM_WALK_CONTINUE);
}

static boolean_t
print_wifi_status_cb(ofmt_arg_t *ofarg, char *buf, uint_t bufsize)
{
	static char		tmpbuf[DLADM_STRSIZE];
	wlan_scan_args_t	*w = ofarg->ofmt_cbarg;
	dladm_wlan_linkattr_t	*attrp = w->ws_attr;

	if ((ofarg->ofmt_id & attrp->la_valid) != 0) {
		(void) dladm_wlan_linkstatus2str(&attrp->la_status, tmpbuf);
		(void) strlcpy(buf, tmpbuf, bufsize);
	}
	return (B_TRUE);
}

static boolean_t
print_link_attr_cb(ofmt_arg_t *ofarg, char *buf, uint_t bufsize)
{
	wlan_scan_args_t	*w = ofarg->ofmt_cbarg, w1;
	print_wifi_state_t	*statep = w->ws_state;
	dladm_wlan_linkattr_t	*attrp = w->ws_attr;

	bzero(&w1, sizeof (w1));
	w1.ws_state = statep;
	w1.ws_attr = &attrp->la_wlan_attr;
	ofarg->ofmt_cbarg = &w1;
	return (print_wlan_attr_cb(ofarg, buf, bufsize));
}

static int
show_wifi(dladm_handle_t dh, datalink_id_t linkid, void *arg)
{
	print_wifi_state_t	*statep = arg;
	dladm_wlan_linkattr_t	attr;
	dladm_status_t		status;
	char			link[MAXLINKNAMELEN];
	wlan_scan_args_t	warg;

	if ((status = dladm_datalink_id2info(dh, linkid, NULL, NULL, NULL, link,
	    sizeof (link))) != DLADM_STATUS_OK) {
		return (DLADM_WALK_CONTINUE);
	}

	/* dladm_wlan_get_linkattr() memsets attr with 0 */
	status = dladm_wlan_get_linkattr(dh, linkid, &attr);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "cannot get link attributes for %s", link);

	statep->ws_link = link;

	bzero(&warg, sizeof (warg));
	warg.ws_state = statep;
	warg.ws_attr = &attr;
	ofmt_print(statep->ws_ofmt, &warg);
	return (DLADM_WALK_CONTINUE);
}

static void
do_display_wifi(int argc, char **argv, int cmd, const char *use)
{
	int			option;
	char			*fields_str = NULL;
	int		(*callback)(dladm_handle_t, datalink_id_t, void *);
	print_wifi_state_t	state;
	datalink_id_t		linkid = DATALINK_ALL_LINKID;
	dladm_status_t		status;

	if (cmd == WIFI_CMD_SCAN)
		callback = scan_wifi;
	else if (cmd == WIFI_CMD_SHOW)
		callback = show_wifi;
	else
		return;

	state.ws_parsable = B_FALSE;
	state.ws_header = B_TRUE;
	opterr = 0;
	while ((option = getopt_long(argc, argv, ":o:p",
	    wifi_longopts, NULL)) != -1) {
		switch (option) {
		case 'o':
			fields_str = optarg;
			break;
		case 'p':
			state.ws_parsable = B_TRUE;
			break;
		default:
			die_opterr(optopt, option, use);
		}
	}

	if (state.ws_parsable && fields_str == NULL)
		die("-p requires -o");

	if (state.ws_parsable && strcasecmp(fields_str, "all") == 0)
		die("\"-o all\" is invalid with -p");

	if (optind == (argc - 1)) {
		if ((status = dladm_name2info(handle, argv[optind], &linkid,
		    NULL, NULL, NULL)) != DLADM_STATUS_OK) {
			die_dlerr(status, "link %s is not valid", argv[optind]);
		}
	} else if (optind != argc) {
		usage();
	}

	if (parse_wifi_fields(fields_str, &state.ws_ofmt, cmd,
	    state.ws_parsable) < 0)
		die("invalid field(s) specified");

	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(callback, handle, &state,
		    DATALINK_CLASS_PHYS | DATALINK_CLASS_SIMNET,
		    DL_WIFI, DLADM_OPT_ACTIVE);
	} else {
		(void) (*callback)(handle, linkid, &state);
	}
	ofmt_close(state.ws_ofmt);
}

static void
do_scan_wifi(int argc, char **argv, const char *use)
{
	do_display_wifi(argc, argv, WIFI_CMD_SCAN, use);
}

static void
do_show_wifi(int argc, char **argv, const char *use)
{
	do_display_wifi(argc, argv, WIFI_CMD_SHOW, use);
}

typedef struct wlan_count_attr {
	uint_t		wc_count;
	datalink_id_t	wc_linkid;
} wlan_count_attr_t;

/* ARGSUSED */
static int
do_count_wlan(dladm_handle_t dh, datalink_id_t linkid, void *arg)
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
	dladm_wlan_key_t	*wk;
	int			nfields = 1;
	char			*field, *token, *lasts = NULL, c;

	token = str;
	while ((c = *token++) != NULL) {
		if (c == ',')
			nfields++;
	}
	token = strdup(str);
	if (token == NULL)
		return (-1);

	wk = malloc(nfields * sizeof (dladm_wlan_key_t));
	if (wk == NULL)
		goto fail;

	token = str;
	for (i = 0; i < nfields; i++) {
		char			*s;
		dladm_secobj_class_t	class;
		dladm_status_t		status;

		field = strtok_r(token, ",", &lasts);
		token = NULL;

		(void) strlcpy(wk[i].wk_name, field,
		    DLADM_WLAN_MAX_KEYNAME_LEN);

		wk[i].wk_idx = 1;
		if ((s = strrchr(wk[i].wk_name, ':')) != NULL) {
			if (s[1] == '\0' || s[2] != '\0' || !isdigit(s[1]))
				goto fail;

			wk[i].wk_idx = (uint_t)(s[1] - '0');
			*s = '\0';
		}
		wk[i].wk_len = DLADM_WLAN_MAX_KEY_LEN;

		status = dladm_get_secobj(handle, wk[i].wk_name, &class,
		    wk[i].wk_val, &wk[i].wk_len, 0);
		if (status != DLADM_STATUS_OK) {
			if (status == DLADM_STATUS_NOTFOUND) {
				status = dladm_get_secobj(handle, wk[i].wk_name,
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
	free(token);
	return (0);
fail:
	free(wk);
	free(token);
	return (-1);
}

static void
do_connect_wifi(int argc, char **argv, const char *use)
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
			die_opterr(optopt, option, use);
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
		if ((status = dladm_name2info(handle, argv[optind], &linkid,
		    NULL, NULL, NULL)) != DLADM_STATUS_OK) {
			die_dlerr(status, "link %s is not valid", argv[optind]);
		}
	} else if (optind != argc) {
		usage();
	}

	if (linkid == DATALINK_ALL_LINKID) {
		wlan_count_attr_t wcattr;

		wcattr.wc_linkid = DATALINK_INVALID_LINKID;
		wcattr.wc_count = 0;
		(void) dladm_walk_datalink_id(do_count_wlan, handle, &wcattr,
		    DATALINK_CLASS_PHYS | DATALINK_CLASS_SIMNET,
		    DL_WIFI, DLADM_OPT_ACTIVE);
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
	if ((status = dladm_wlan_connect(handle, linkid, attrp, timeout, keys,
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
do_all_disconnect_wifi(dladm_handle_t dh, datalink_id_t linkid, void *arg)
{
	dladm_status_t	status;

	status = dladm_wlan_disconnect(dh, linkid);
	if (status != DLADM_STATUS_OK)
		warn_dlerr(status, "cannot disconnect link");

	return (DLADM_WALK_CONTINUE);
}

static void
do_disconnect_wifi(int argc, char **argv, const char *use)
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
			die_opterr(optopt, option, use);
			break;
		}
	}

	if (optind == (argc - 1)) {
		if ((status = dladm_name2info(handle, argv[optind], &linkid,
		    NULL, NULL, NULL)) != DLADM_STATUS_OK) {
			die_dlerr(status, "link %s is not valid", argv[optind]);
		}
	} else if (optind != argc) {
		usage();
	}

	if (linkid == DATALINK_ALL_LINKID) {
		if (!all_links) {
			wcattr.wc_linkid = linkid;
			wcattr.wc_count = 0;
			(void) dladm_walk_datalink_id(do_count_wlan, handle,
			    &wcattr,
			    DATALINK_CLASS_PHYS | DATALINK_CLASS_SIMNET,
			    DL_WIFI, DLADM_OPT_ACTIVE);
			if (wcattr.wc_count == 0) {
				die("no wifi links are available");
			} else if (wcattr.wc_count > 1) {
				die("link name is required when more than "
				    "one wifi link is available");
			}
			linkid = wcattr.wc_linkid;
		} else {
			(void) dladm_walk_datalink_id(do_all_disconnect_wifi,
			    handle, NULL,
			    DATALINK_CLASS_PHYS | DATALINK_CLASS_SIMNET,
			    DL_WIFI, DLADM_OPT_ACTIVE);
			return;
		}
	}
	status = dladm_wlan_disconnect(handle, linkid);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "cannot disconnect");
}

static void
print_linkprop(datalink_id_t linkid, show_linkprop_state_t *statep,
    const char *propname, dladm_prop_type_t type, const char *format,
    char **pptr)
{
	int		i;
	char		*ptr, *lim;
	char		buf[DLADM_STRSIZE];
	char		*unknown = "--", *notsup = "";
	char		**propvals = statep->ls_propvals;
	uint_t		valcnt = DLADM_MAX_PROP_VALCNT;
	dladm_status_t	status;

	status = dladm_get_linkprop(handle, linkid, type, propname, propvals,
	    &valcnt);
	if (status != DLADM_STATUS_OK) {
		if (status == DLADM_STATUS_TEMPONLY) {
			if (type == DLADM_PROP_VAL_MODIFIABLE &&
			    statep->ls_persist) {
				valcnt = 1;
				propvals = &unknown;
			} else {
				statep->ls_status = status;
				statep->ls_retstatus = status;
				return;
			}
		} else if (status == DLADM_STATUS_NOTSUP ||
		    statep->ls_persist) {
			valcnt = 1;
			if (type == DLADM_PROP_VAL_CURRENT ||
			    type == DLADM_PROP_VAL_PERM)
				propvals = &unknown;
			else
				propvals = &notsup;
		} else if (status == DLADM_STATUS_NOTDEFINED) {
			propvals = &notsup; /* STR_UNDEF_VAL */
		} else {
			if (statep->ls_proplist &&
			    statep->ls_status == DLADM_STATUS_OK) {
				warn_dlerr(status,
				    "cannot get link property '%s' for %s",
				    propname, statep->ls_link);
			}
			statep->ls_status = status;
			statep->ls_retstatus = status;
			return;
		}
	}

	statep->ls_status = DLADM_STATUS_OK;

	buf[0] = '\0';
	ptr = buf;
	lim = buf + DLADM_STRSIZE;
	for (i = 0; i < valcnt; i++) {
		if (propvals[i][0] == '\0' && !statep->ls_parsable)
			ptr += snprintf(ptr, lim - ptr, "--,");
		else
			ptr += snprintf(ptr, lim - ptr, "%s,", propvals[i]);
		if (ptr >= lim)
			break;
	}
	if (valcnt > 0)
		buf[strlen(buf) - 1] = '\0';

	lim = statep->ls_line + MAX_PROP_LINE;
	if (statep->ls_parsable) {
		*pptr += snprintf(*pptr, lim - *pptr,
		    "%s", buf);
	} else {
		*pptr += snprintf(*pptr, lim - *pptr, format, buf);
	}
}

static boolean_t
print_linkprop_cb(ofmt_arg_t *ofarg, char *buf, uint_t bufsize)
{
	linkprop_args_t		*arg = ofarg->ofmt_cbarg;
	char 			*propname = arg->ls_propname;
	show_linkprop_state_t	*statep = arg->ls_state;
	char			*ptr = statep->ls_line;
	char			*lim = ptr + MAX_PROP_LINE;
	datalink_id_t		linkid = arg->ls_linkid;

	switch (ofarg->ofmt_id) {
	case LINKPROP_LINK:
		(void) snprintf(ptr, lim - ptr, "%s", statep->ls_link);
		break;
	case LINKPROP_PROPERTY:
		(void) snprintf(ptr, lim - ptr, "%s", propname);
		break;
	case LINKPROP_VALUE:
		print_linkprop(linkid, statep, propname,
		    statep->ls_persist ? DLADM_PROP_VAL_PERSISTENT :
		    DLADM_PROP_VAL_CURRENT, "%s", &ptr);
		/*
		 * If we failed to query the link property, for example, query
		 * the persistent value of a non-persistable link property,
		 * simply skip the output.
		 */
		if (statep->ls_status != DLADM_STATUS_OK) {
			/*
			 * Ignore the temponly error when we skip printing
			 * link properties to avoid returning failure on exit.
			 */
			if (statep->ls_retstatus == DLADM_STATUS_TEMPONLY)
				statep->ls_retstatus = DLADM_STATUS_OK;
			goto skip;
		}
		ptr = statep->ls_line;
		break;
	case LINKPROP_PERM:
		print_linkprop(linkid, statep, propname,
		    DLADM_PROP_VAL_PERM, "%s", &ptr);
		if (statep->ls_status != DLADM_STATUS_OK)
			goto skip;
		ptr = statep->ls_line;
		break;
	case LINKPROP_DEFAULT:
		print_linkprop(linkid, statep, propname,
		    DLADM_PROP_VAL_DEFAULT, "%s", &ptr);
		if (statep->ls_status != DLADM_STATUS_OK)
			goto skip;
		ptr = statep->ls_line;
		break;
	case LINKPROP_POSSIBLE:
		print_linkprop(linkid, statep, propname,
		    DLADM_PROP_VAL_MODIFIABLE, "%s ", &ptr);
		if (statep->ls_status != DLADM_STATUS_OK)
			goto skip;
		ptr = statep->ls_line;
		break;
	default:
		die("invalid input");
		break;
	}
	(void) strlcpy(buf, ptr, bufsize);
	return (B_TRUE);
skip:
	return ((statep->ls_status == DLADM_STATUS_OK) ?
	    B_TRUE : B_FALSE);
}

static boolean_t
linkprop_is_supported(datalink_id_t  linkid, const char *propname,
    show_linkprop_state_t *statep)
{
	dladm_status_t	status;
	uint_t		valcnt = DLADM_MAX_PROP_VALCNT;

	/* if used with -p flag, always print output */
	if (statep->ls_proplist != NULL)
		return (B_TRUE);

	status = dladm_get_linkprop(handle, linkid, DLADM_PROP_VAL_DEFAULT,
	    propname, statep->ls_propvals, &valcnt);

	if (status == DLADM_STATUS_OK)
		return (B_TRUE);

	/*
	 * A system wide default value is not available for the
	 * property. Check if current value can be retrieved.
	 */
	status = dladm_get_linkprop(handle, linkid, DLADM_PROP_VAL_CURRENT,
	    propname, statep->ls_propvals, &valcnt);

	return (status == DLADM_STATUS_OK);
}

/* ARGSUSED */
static int
show_linkprop(dladm_handle_t dh, datalink_id_t linkid, const char *propname,
    void *arg)
{
	show_linkprop_state_t	*statep = arg;
	linkprop_args_t		ls_arg;

	bzero(&ls_arg, sizeof (ls_arg));
	ls_arg.ls_state = statep;
	ls_arg.ls_propname = (char *)propname;
	ls_arg.ls_linkid = linkid;

	/*
	 * This will need to be fixed when kernel interfaces are added
	 * to enable walking of all known private properties. For now,
	 * we are limited to walking persistent private properties only.
	 */
	if ((propname[0] == '_') && !statep->ls_persist &&
	    (statep->ls_proplist == NULL))
		return (DLADM_WALK_CONTINUE);
	if (!statep->ls_parsable &&
	    !linkprop_is_supported(linkid, propname, statep))
		return (DLADM_WALK_CONTINUE);

	ofmt_print(statep->ls_ofmt, &ls_arg);

	return (DLADM_WALK_CONTINUE);
}

static void
do_show_linkprop(int argc, char **argv, const char *use)
{
	int			option;
	char			propstr[DLADM_STRSIZE];
	dladm_arg_list_t	*proplist = NULL;
	datalink_id_t		linkid = DATALINK_ALL_LINKID;
	show_linkprop_state_t	state;
	uint32_t		flags = DLADM_OPT_ACTIVE;
	dladm_status_t		status;
	char			*fields_str = NULL;
	ofmt_handle_t		ofmt;
	ofmt_status_t		oferr;
	uint_t			ofmtflags = 0;

	bzero(propstr, DLADM_STRSIZE);
	opterr = 0;
	state.ls_propvals = NULL;
	state.ls_line = NULL;
	state.ls_parsable = B_FALSE;
	state.ls_persist = B_FALSE;
	state.ls_header = B_TRUE;
	state.ls_retstatus = DLADM_STATUS_OK;

	while ((option = getopt_long(argc, argv, ":p:cPo:",
	    prop_longopts, NULL)) != -1) {
		switch (option) {
		case 'p':
			(void) strlcat(propstr, optarg, DLADM_STRSIZE);
			if (strlcat(propstr, ",", DLADM_STRSIZE) >=
			    DLADM_STRSIZE)
				die("property list too long '%s'", propstr);
			break;
		case 'c':
			state.ls_parsable = B_TRUE;
			break;
		case 'P':
			state.ls_persist = B_TRUE;
			flags = DLADM_OPT_PERSIST;
			break;
		case 'o':
			fields_str = optarg;
			break;
		default:
			die_opterr(optopt, option, use);
			break;
		}
	}

	if (optind == (argc - 1)) {
		if ((status = dladm_name2info(handle, argv[optind], &linkid,
		    NULL, NULL, NULL)) != DLADM_STATUS_OK) {
			die_dlerr(status, "link %s is not valid", argv[optind]);
		}
	} else if (optind != argc) {
		usage();
	}

	if (dladm_parse_link_props(propstr, &proplist, B_TRUE)
	    != DLADM_STATUS_OK)
		die("invalid link properties specified");
	state.ls_proplist = proplist;
	state.ls_status = DLADM_STATUS_OK;

	if (state.ls_parsable)
		ofmtflags |= OFMT_PARSABLE;
	else
		ofmtflags |= OFMT_WRAP;

	oferr = ofmt_open(fields_str, linkprop_fields, ofmtflags, 0, &ofmt);
	ofmt_check(oferr, state.ls_parsable, ofmt, die, warn);
	state.ls_ofmt = ofmt;

	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(show_linkprop_onelink, handle,
		    &state, DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE, flags);
	} else {
		(void) show_linkprop_onelink(handle, linkid, &state);
	}
	ofmt_close(ofmt);
	dladm_free_props(proplist);

	if (state.ls_retstatus != DLADM_STATUS_OK) {
		dladm_close(handle);
		exit(EXIT_FAILURE);
	}
}

static int
show_linkprop_onelink(dladm_handle_t hdl, datalink_id_t linkid, void *arg)
{
	int			i;
	char			*buf;
	uint32_t		flags;
	dladm_arg_list_t	*proplist = NULL;
	show_linkprop_state_t	*statep = arg;
	dlpi_handle_t		dh = NULL;

	statep->ls_status = DLADM_STATUS_OK;

	if (dladm_datalink_id2info(hdl, linkid, &flags, NULL, NULL,
	    statep->ls_link, MAXLINKNAMELEN) != DLADM_STATUS_OK) {
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
		for (i = 0; i < proplist->al_count; i++) {
			(void) show_linkprop(hdl, linkid,
			    proplist->al_info[i].ai_name, statep);
		}
	} else {
		(void) dladm_walk_linkprop(hdl, linkid, statep,
		    show_linkprop);
	}
	if (dh != NULL)
		dlpi_close(dh);
	free(buf);
	return (DLADM_WALK_CONTINUE);
}

static int
reset_one_linkprop(dladm_handle_t dh, datalink_id_t linkid,
    const char *propname, void *arg)
{
	set_linkprop_state_t	*statep = arg;
	dladm_status_t		status;

	status = dladm_set_linkprop(dh, linkid, propname, NULL, 0,
	    DLADM_OPT_ACTIVE | (statep->ls_temp ? 0 : DLADM_OPT_PERSIST));
	if (status != DLADM_STATUS_OK &&
	    status != DLADM_STATUS_PROPRDONLY &&
	    status != DLADM_STATUS_NOTSUP) {
		warn_dlerr(status, "cannot reset link property '%s' on '%s'",
		    propname, statep->ls_name);
		statep->ls_status = status;
	}

	return (DLADM_WALK_CONTINUE);
}

static void
set_linkprop(int argc, char **argv, boolean_t reset, const char *use)
{
	int			i, option;
	char			errmsg[DLADM_STRSIZE];
	char			*altroot = NULL;
	datalink_id_t		linkid;
	boolean_t		temp = B_FALSE;
	dladm_status_t		status = DLADM_STATUS_OK;
	char			propstr[DLADM_STRSIZE];
	dladm_arg_list_t	*proplist = NULL;

	opterr = 0;
	bzero(propstr, DLADM_STRSIZE);

	while ((option = getopt_long(argc, argv, ":p:R:t",
	    prop_longopts, NULL)) != -1) {
		switch (option) {
		case 'p':
			(void) strlcat(propstr, optarg, DLADM_STRSIZE);
			if (strlcat(propstr, ",", DLADM_STRSIZE) >=
			    DLADM_STRSIZE)
				die("property list too long '%s'", propstr);
			break;
		case 't':
			temp = B_TRUE;
			break;
		case 'R':
			altroot = optarg;
			break;
		default:
			die_opterr(optopt, option, use);

		}
	}

	/* get link name (required last argument) */
	if (optind != (argc - 1))
		usage();

	if (dladm_parse_link_props(propstr, &proplist, reset) !=
	    DLADM_STATUS_OK)
		die("invalid link properties specified");

	if (proplist == NULL && !reset)
		die("link property must be specified");

	if (altroot != NULL) {
		dladm_free_props(proplist);
		altroot_cmd(altroot, argc, argv);
	}

	status = dladm_name2info(handle, argv[optind], &linkid, NULL, NULL,
	    NULL);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "link %s is not valid", argv[optind]);

	if (proplist == NULL) {
		set_linkprop_state_t	state;

		state.ls_name = argv[optind];
		state.ls_reset = reset;
		state.ls_temp = temp;
		state.ls_status = DLADM_STATUS_OK;

		(void) dladm_walk_linkprop(handle, linkid, &state,
		    reset_one_linkprop);

		status = state.ls_status;
		goto done;
	}

	for (i = 0; i < proplist->al_count; i++) {
		dladm_arg_info_t	*aip = &proplist->al_info[i];
		char		**val;
		uint_t		count;

		if (reset) {
			val = NULL;
			count = 0;
		} else {
			val = aip->ai_val;
			count = aip->ai_count;
			if (count == 0) {
				warn("no value specified for '%s'",
				    aip->ai_name);
				status = DLADM_STATUS_BADARG;
				continue;
			}
		}
		status = dladm_set_linkprop(handle, linkid, aip->ai_name, val,
		    count, DLADM_OPT_ACTIVE | (temp ? 0 : DLADM_OPT_PERSIST));
		switch (status) {
		case DLADM_STATUS_OK:
			break;
		case DLADM_STATUS_NOTFOUND:
			warn("invalid link property '%s'", aip->ai_name);
			break;
		case DLADM_STATUS_BADVAL: {
			int		j;
			char		*ptr, *lim;
			char		**propvals = NULL;
			uint_t		valcnt = DLADM_MAX_PROP_VALCNT;
			dladm_status_t	s;

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
			s = dladm_get_linkprop(handle, linkid,
			    DLADM_PROP_VAL_MODIFIABLE, aip->ai_name, propvals,
			    &valcnt);

			if (s != DLADM_STATUS_OK) {
				warn_dlerr(status, "cannot set link property "
				    "'%s' on '%s'", aip->ai_name, argv[optind]);
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
				    aip->ai_name, errmsg);
			} else
				warn("invalid link property '%s'", *val);
			free(propvals);
			break;
		}
		default:
			if (reset) {
				warn_dlerr(status, "cannot reset link property "
				    "'%s' on '%s'", aip->ai_name, argv[optind]);
			} else {
				warn_dlerr(status, "cannot set link property "
				    "'%s' on '%s'", aip->ai_name, argv[optind]);
			}
			break;
		}
	}
done:
	dladm_free_props(proplist);
	if (status != DLADM_STATUS_OK) {
		dladm_close(handle);
		exit(EXIT_FAILURE);
	}
}

static void
do_set_linkprop(int argc, char **argv, const char *use)
{
	set_linkprop(argc, argv, B_FALSE, use);
}

static void
do_reset_linkprop(int argc, char **argv, const char *use)
{
	set_linkprop(argc, argv, B_TRUE, use);
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

static void
do_create_secobj(int argc, char **argv, const char *use)
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
			die_opterr(optopt, option, use);
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

	if (!dladm_valid_secobj_name(obj_name))
		die("invalid secure object name '%s'", obj_name);

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

	status = dladm_set_secobj(handle, obj_name, class, obj_val, obj_len,
	    DLADM_OPT_CREATE | DLADM_OPT_ACTIVE);
	if (status != DLADM_STATUS_OK) {
		die_dlerr(status, "could not create secure object '%s'",
		    obj_name);
	}
	if (temp)
		return;

	status = dladm_set_secobj(handle, obj_name, class, obj_val, obj_len,
	    DLADM_OPT_PERSIST);
	if (status != DLADM_STATUS_OK) {
		warn_dlerr(status, "could not persistently create secure "
		    "object '%s'", obj_name);
	}
}

static void
do_delete_secobj(int argc, char **argv, const char *use)
{
	int		i, option;
	boolean_t	temp = B_FALSE;
	boolean_t	success;
	dladm_status_t	status, pstatus;
	int		nfields = 1;
	char		*field, *token, *lasts = NULL, c;

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
			die_opterr(optopt, option, use);
			break;
		}
	}

	if (optind != (argc - 1))
		die("secure object name required");

	token = argv[optind];
	while ((c = *token++) != NULL) {
		if (c == ',')
			nfields++;
	}
	token = strdup(argv[optind]);
	if (token == NULL)
		die("no memory");

	success = check_auth(LINK_SEC_AUTH);
	audit_secobj(LINK_SEC_AUTH, "unknown", argv[optind], success, B_FALSE);
	if (!success)
		die("authorization '%s' is required", LINK_SEC_AUTH);

	for (i = 0; i < nfields; i++) {

		field = strtok_r(token, ",", &lasts);
		token = NULL;
		status = dladm_unset_secobj(handle, field, DLADM_OPT_ACTIVE);
		if (!temp) {
			pstatus = dladm_unset_secobj(handle, field,
			    DLADM_OPT_PERSIST);
		} else {
			pstatus = DLADM_STATUS_OK;
		}

		if (status != DLADM_STATUS_OK) {
			warn_dlerr(status, "could not delete secure object "
			    "'%s'", field);
		}
		if (pstatus != DLADM_STATUS_OK) {
			warn_dlerr(pstatus, "could not persistently delete "
			    "secure object '%s'", field);
		}
	}
	free(token);

	if (status != DLADM_STATUS_OK || pstatus != DLADM_STATUS_OK) {
		dladm_close(handle);
		exit(EXIT_FAILURE);
	}
}

typedef struct show_secobj_state {
	boolean_t	ss_persist;
	boolean_t	ss_parsable;
	boolean_t	ss_header;
	ofmt_handle_t	ss_ofmt;
} show_secobj_state_t;


static boolean_t
show_secobj(dladm_handle_t dh, void *arg, const char *obj_name)
{
	uint_t			obj_len = DLADM_SECOBJ_VAL_MAX;
	uint8_t			obj_val[DLADM_SECOBJ_VAL_MAX];
	char			buf[DLADM_STRSIZE];
	uint_t			flags = 0;
	dladm_secobj_class_t	class;
	show_secobj_state_t	*statep = arg;
	dladm_status_t		status;
	secobj_fields_buf_t	sbuf;

	bzero(&sbuf, sizeof (secobj_fields_buf_t));
	if (statep->ss_persist)
		flags |= DLADM_OPT_PERSIST;

	status = dladm_get_secobj(dh, obj_name, &class, obj_val, &obj_len,
	    flags);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "cannot get secure object '%s'", obj_name);

	(void) snprintf(sbuf.ss_obj_name, sizeof (sbuf.ss_obj_name),
	    obj_name);
	(void) dladm_secobjclass2str(class, buf);
	(void) snprintf(sbuf.ss_class, sizeof (sbuf.ss_class), "%s", buf);
	if (getuid() == 0) {
		char	val[DLADM_SECOBJ_VAL_MAX * 2];
		uint_t	len = sizeof (val);

		if (octet_to_hexascii(obj_val, obj_len, val, &len) == 0)
			(void) snprintf(sbuf.ss_val,
			    sizeof (sbuf.ss_val), "%s", val);
	}
	ofmt_print(statep->ss_ofmt, &sbuf);
	return (B_TRUE);
}

static void
do_show_secobj(int argc, char **argv, const char *use)
{
	int			option;
	show_secobj_state_t	state;
	dladm_status_t		status;
	boolean_t		o_arg = B_FALSE;
	uint_t			i;
	uint_t			flags;
	char			*fields_str = NULL;
	char			*def_fields = "object,class";
	char			*all_fields = "object,class,value";
	char			*field, *token, *lasts = NULL, c;
	ofmt_handle_t		ofmt;
	ofmt_status_t		oferr;
	uint_t			ofmtflags = 0;

	opterr = 0;
	bzero(&state, sizeof (state));
	state.ss_parsable = B_FALSE;
	fields_str = def_fields;
	state.ss_persist = B_FALSE;
	state.ss_parsable = B_FALSE;
	state.ss_header = B_TRUE;
	while ((option = getopt_long(argc, argv, ":pPo:",
	    wifi_longopts, NULL)) != -1) {
		switch (option) {
		case 'p':
			state.ss_parsable = B_TRUE;
			break;
		case 'P':
			state.ss_persist = B_TRUE;
			break;
		case 'o':
			o_arg = B_TRUE;
			if (strcasecmp(optarg, "all") == 0)
				fields_str = all_fields;
			else
				fields_str = optarg;
			break;
		default:
			die_opterr(optopt, option, use);
			break;
		}
	}

	if (state.ss_parsable && !o_arg)
		die("option -c requires -o");

	if (state.ss_parsable && fields_str == all_fields)
		die("\"-o all\" is invalid with -p");

	if (state.ss_parsable)
		ofmtflags |= OFMT_PARSABLE;
	oferr = ofmt_open(fields_str, secobj_fields, ofmtflags, 0, &ofmt);
	ofmt_check(oferr, state.ss_parsable, ofmt, die, warn);
	state.ss_ofmt = ofmt;

	flags = state.ss_persist ? DLADM_OPT_PERSIST : 0;

	if (optind == (argc - 1)) {
		uint_t obj_fields = 1;

		token = argv[optind];
		if (token == NULL)
			die("secure object name required");
		while ((c = *token++) != NULL) {
			if (c == ',')
				obj_fields++;
		}
		token = strdup(argv[optind]);
		if (token == NULL)
			die("no memory");
		for (i = 0; i < obj_fields; i++) {
			field = strtok_r(token, ",", &lasts);
			token = NULL;
			if (!show_secobj(handle, &state, field))
				break;
		}
		free(token);
		ofmt_close(ofmt);
		return;
	} else if (optind != argc)
		usage();

	status = dladm_walk_secobj(handle, &state, show_secobj, flags);

	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "show-secobj");
	ofmt_close(ofmt);
}

/*ARGSUSED*/
static int
i_dladm_init_linkprop(dladm_handle_t dh, datalink_id_t linkid, void *arg)
{
	(void) dladm_init_linkprop(dh, linkid, B_TRUE);
	return (DLADM_WALK_CONTINUE);
}

/*ARGSUSED*/
void
do_init_linkprop(int argc, char **argv, const char *use)
{
	int			option;
	dladm_status_t		status;
	datalink_id_t		linkid = DATALINK_ALL_LINKID;
	datalink_media_t	media = DATALINK_ANY_MEDIATYPE;
	uint_t			any_media = B_TRUE;

	opterr = 0;
	while ((option = getopt(argc, argv, ":w")) != -1) {
		switch (option) {
		case 'w':
			media = DL_WIFI;
			any_media = B_FALSE;
			break;
		default:
			/*
			 * Because init-linkprop is not a public command,
			 * print the usage instead.
			 */
			usage();
			break;
		}
	}

	if (optind == (argc - 1)) {
		if ((status = dladm_name2info(handle, argv[optind], &linkid,
		    NULL, NULL, NULL)) != DLADM_STATUS_OK)
			die_dlerr(status, "link %s is not valid", argv[optind]);
	} else if (optind != argc) {
		usage();
	}

	if (linkid == DATALINK_ALL_LINKID) {
		/*
		 * linkprops of links of other classes have been initialized as
		 * part of the dladm up-xxx operation.
		 */
		(void) dladm_walk_datalink_id(i_dladm_init_linkprop, handle,
		    NULL, DATALINK_CLASS_PHYS, media, DLADM_OPT_PERSIST);
	} else {
		(void) dladm_init_linkprop(handle, linkid, any_media);
	}
}

static void
do_show_ether(int argc, char **argv, const char *use)
{
	int 			option;
	datalink_id_t		linkid;
	print_ether_state_t 	state;
	char			*fields_str = NULL;
	ofmt_handle_t		ofmt;
	ofmt_status_t		oferr;
	uint_t			ofmtflags = 0;

	bzero(&state, sizeof (state));
	state.es_link = NULL;
	state.es_parsable = B_FALSE;

	while ((option = getopt_long(argc, argv, "o:px",
	    showeth_lopts, NULL)) != -1) {
		switch (option) {
			case 'x':
				state.es_extended = B_TRUE;
				break;
			case 'p':
				state.es_parsable = B_TRUE;
				break;
			case 'o':
				fields_str = optarg;
				break;
			default:
				die_opterr(optopt, option, use);
				break;
		}
	}

	if (optind == (argc - 1))
		state.es_link = argv[optind];

	if (state.es_parsable)
		ofmtflags |= OFMT_PARSABLE;
	oferr = ofmt_open(fields_str, ether_fields, ofmtflags,
	    DLADM_DEFAULT_COL, &ofmt);
	ofmt_check(oferr, state.es_parsable, ofmt, die, warn);
	state.es_ofmt = ofmt;

	if (state.es_link == NULL) {
		(void) dladm_walk_datalink_id(show_etherprop, handle, &state,
		    DATALINK_CLASS_PHYS, DL_ETHER, DLADM_OPT_ACTIVE);
	} else {
		if (!link_is_ether(state.es_link, &linkid))
			die("invalid link specified");
		(void) show_etherprop(handle, linkid, &state);
	}
	ofmt_close(ofmt);
}

static int
show_etherprop(dladm_handle_t dh, datalink_id_t linkid, void *arg)
{
	print_ether_state_t	*statep = arg;
	ether_fields_buf_t	ebuf;
	dladm_ether_info_t	eattr;
	dladm_status_t		status;

	bzero(&ebuf, sizeof (ether_fields_buf_t));
	if (dladm_datalink_id2info(dh, linkid, NULL, NULL, NULL,
	    ebuf.eth_link, sizeof (ebuf.eth_link)) != DLADM_STATUS_OK) {
		return (DLADM_WALK_CONTINUE);
	}

	status = dladm_ether_info(dh, linkid, &eattr);
	if (status != DLADM_STATUS_OK)
		goto cleanup;

	(void) strlcpy(ebuf.eth_ptype, "current", sizeof (ebuf.eth_ptype));

	(void) dladm_ether_autoneg2str(ebuf.eth_autoneg,
	    sizeof (ebuf.eth_autoneg), &eattr, CURRENT);
	(void) dladm_ether_pause2str(ebuf.eth_pause,
	    sizeof (ebuf.eth_pause), &eattr, CURRENT);
	(void) dladm_ether_spdx2str(ebuf.eth_spdx,
	    sizeof (ebuf.eth_spdx), &eattr, CURRENT);
	(void) strlcpy(ebuf.eth_state,
	    dladm_linkstate2str(eattr.lei_state, ebuf.eth_state),
	    sizeof (ebuf.eth_state));
	(void) strlcpy(ebuf.eth_rem_fault,
	    (eattr.lei_attr[CURRENT].le_fault ? "fault" : "none"),
	    sizeof (ebuf.eth_rem_fault));

	ofmt_print(statep->es_ofmt, &ebuf);

	if (statep->es_extended)
		show_ether_xprop(arg, &eattr);

cleanup:
	dladm_ether_info_done(&eattr);
	return (DLADM_WALK_CONTINUE);
}

/* ARGSUSED */
static void
do_init_secobj(int argc, char **argv, const char *use)
{
	dladm_status_t	status;

	status = dladm_init_secobj(handle);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "secure object initialization failed");
}

enum bridge_func {
	brCreate, brAdd, brModify
};

static void
create_modify_add_bridge(int argc, char **argv, const char *use,
    enum bridge_func func)
{
	int			option;
	uint_t			n, i, nlink;
	uint32_t		flags = DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST;
	char			*altroot = NULL;
	char			*links[MAXPORT];
	datalink_id_t		linkids[MAXPORT];
	dladm_status_t		status;
	const char		*bridge;
	UID_STP_CFG_T		cfg, cfg_old;
	dladm_bridge_prot_t	brprot = DLADM_BRIDGE_PROT_UNKNOWN;
	dladm_bridge_prot_t	brprot_old;

	/* Set up the default configuration values */
	cfg.field_mask = 0;
	cfg.bridge_priority = DEF_BR_PRIO;
	cfg.max_age = DEF_BR_MAXAGE;
	cfg.hello_time = DEF_BR_HELLOT;
	cfg.forward_delay = DEF_BR_FWDELAY;
	cfg.force_version = DEF_FORCE_VERS;

	nlink = opterr = 0;
	while ((option = getopt_long(argc, argv, ":P:R:d:f:h:l:m:p:",
	    bridge_lopts, NULL)) != -1) {
		switch (option) {
		case 'P':
			if (func == brAdd)
				die_opterr(optopt, option, use);
			status = dladm_bridge_str2prot(optarg, &brprot);
			if (status != DLADM_STATUS_OK)
				die_dlerr(status, "protection %s", optarg);
			break;
		case 'R':
			altroot = optarg;
			break;
		case 'd':
			if (func == brAdd)
				die_opterr(optopt, option, use);
			if (cfg.field_mask & BR_CFG_DELAY)
				die("forwarding delay set more than once");
			if (!str2int(optarg, &cfg.forward_delay) ||
			    cfg.forward_delay < MIN_BR_FWDELAY ||
			    cfg.forward_delay > MAX_BR_FWDELAY)
				die("incorrect forwarding delay");
			cfg.field_mask |= BR_CFG_DELAY;
			break;
		case 'f':
			if (func == brAdd)
				die_opterr(optopt, option, use);
			if (cfg.field_mask & BR_CFG_FORCE_VER)
				die("force protocol set more than once");
			if (!str2int(optarg, &cfg.force_version) ||
			    cfg.force_version < 0)
				die("incorrect force protocol");
			cfg.field_mask |= BR_CFG_FORCE_VER;
			break;
		case 'h':
			if (func == brAdd)
				die_opterr(optopt, option, use);
			if (cfg.field_mask & BR_CFG_HELLO)
				die("hello time set more than once");
			if (!str2int(optarg, &cfg.hello_time) ||
			    cfg.hello_time < MIN_BR_HELLOT ||
			    cfg.hello_time > MAX_BR_HELLOT)
				die("incorrect hello time");
			cfg.field_mask |= BR_CFG_HELLO;
			break;
		case 'l':
			if (func == brModify)
				die_opterr(optopt, option, use);
			if (nlink >= MAXPORT)
				die("too many links specified");
			links[nlink++] = optarg;
			break;
		case 'm':
			if (func == brAdd)
				die_opterr(optopt, option, use);
			if (cfg.field_mask & BR_CFG_AGE)
				die("max age set more than once");
			if (!str2int(optarg, &cfg.max_age) ||
			    cfg.max_age < MIN_BR_MAXAGE ||
			    cfg.max_age > MAX_BR_MAXAGE)
				die("incorrect max age");
			cfg.field_mask |= BR_CFG_AGE;
			break;
		case 'p':
			if (func == brAdd)
				die_opterr(optopt, option, use);
			if (cfg.field_mask & BR_CFG_PRIO)
				die("priority set more than once");
			if (!str2int(optarg, &cfg.bridge_priority) ||
			    cfg.bridge_priority < MIN_BR_PRIO ||
			    cfg.bridge_priority > MAX_BR_PRIO)
				die("incorrect priority");
			cfg.bridge_priority &= 0xF000;
			cfg.field_mask |= BR_CFG_PRIO;
			break;
		default:
			die_opterr(optopt, option, use);
			break;
		}
	}

	/* get the bridge name (required last argument) */
	if (optind != (argc-1))
		usage();

	bridge = argv[optind];
	if (!dladm_valid_bridgename(bridge))
		die("invalid bridge name '%s'", bridge);

	/*
	 * Get the current properties, if any, and merge in with changes.  This
	 * is necessary (even with the field_mask feature) so that the
	 * value-checking macros will produce the right results with proposed
	 * changes to existing configuration.  We only need it for those
	 * parameters, though.
	 */
	(void) dladm_bridge_get_properties(bridge, &cfg_old, &brprot_old);
	if (brprot == DLADM_BRIDGE_PROT_UNKNOWN)
		brprot = brprot_old;
	if (!(cfg.field_mask & BR_CFG_AGE))
		cfg.max_age = cfg_old.max_age;
	if (!(cfg.field_mask & BR_CFG_HELLO))
		cfg.hello_time = cfg_old.hello_time;
	if (!(cfg.field_mask & BR_CFG_DELAY))
		cfg.forward_delay = cfg_old.forward_delay;

	if (!CHECK_BRIDGE_CONFIG(cfg)) {
		warn("illegal forward delay / max age / hello time "
		    "combination");
		if (NO_MAXAGE(cfg)) {
			die("no max age possible: need forward delay >= %d or "
			    "hello time <= %d", MIN_FWDELAY_NOM(cfg),
			    MAX_HELLOTIME_NOM(cfg));
		} else if (SMALL_MAXAGE(cfg)) {
			if (CAPPED_MAXAGE(cfg))
				die("max age too small: need age >= %d and "
				    "<= %d or hello time <= %d",
				    MIN_MAXAGE(cfg), MAX_MAXAGE(cfg),
				    MAX_HELLOTIME(cfg));
			else
				die("max age too small: need age >= %d or "
				    "hello time <= %d",
				    MIN_MAXAGE(cfg), MAX_HELLOTIME(cfg));
		} else if (FLOORED_MAXAGE(cfg)) {
			die("max age too large: need age >= %d and <= %d or "
			    "forward delay >= %d",
			    MIN_MAXAGE(cfg), MAX_MAXAGE(cfg),
			    MIN_FWDELAY(cfg));
		} else {
			die("max age too large: need age <= %d or forward "
			    "delay >= %d",
			    MAX_MAXAGE(cfg), MIN_FWDELAY(cfg));
		}
	}

	if (altroot != NULL)
		altroot_cmd(altroot, argc, argv);

	for (n = 0; n < nlink; n++) {
		datalink_class_t class;
		uint32_t media;
		char pointless[DLADM_STRSIZE];

		if (dladm_name2info(handle, links[n], &linkids[n], NULL, &class,
		    &media) != DLADM_STATUS_OK)
			die("invalid link name '%s'", links[n]);
		if (class & ~(DATALINK_CLASS_PHYS | DATALINK_CLASS_AGGR |
		    DATALINK_CLASS_ETHERSTUB | DATALINK_CLASS_SIMNET))
			die("%s %s cannot be bridged",
			    dladm_class2str(class, pointless), links[n]);
		if (media != DL_ETHER && media != DL_100VG &&
		    media != DL_ETH_CSMA && media != DL_100BT)
			die("%s interface %s cannot be bridged",
			    dladm_media2str(media, pointless), links[n]);
	}

	if (func == brCreate)
		flags |= DLADM_OPT_CREATE;

	if (func != brAdd) {
		status = dladm_bridge_configure(handle, bridge, &cfg, brprot,
		    flags);
		if (status != DLADM_STATUS_OK)
			die_dlerr(status, "create operation failed");
	}

	status = DLADM_STATUS_OK;
	for (n = 0; n < nlink; n++) {
		status = dladm_bridge_setlink(handle, linkids[n], bridge);
		if (status != DLADM_STATUS_OK)
			break;
	}

	if (n >= nlink) {
		/*
		 * We were successful.  If we're creating a new bridge, then
		 * there's just one more step: enabling.  If we're modifying or
		 * just adding links, then we're done.
		 */
		if (func != brCreate ||
		    (status = dladm_bridge_enable(bridge)) == DLADM_STATUS_OK)
			return;
	}

	/* clean up the partial configuration */
	for (i = 0; i < n; i++)
		(void) dladm_bridge_setlink(handle, linkids[i], "");

	/* if failure for brCreate, then delete the bridge */
	if (func == brCreate)
		(void) dladm_bridge_delete(handle, bridge, flags);

	if (n < nlink)
		die_dlerr(status, "unable to add link %s to bridge %s",
		    links[n], bridge);
	else
		die_dlerr(status, "unable to enable bridge %s", bridge);
}

static void
do_create_bridge(int argc, char **argv, const char *use)
{
	create_modify_add_bridge(argc, argv, use, brCreate);
}

static void
do_modify_bridge(int argc, char **argv, const char *use)
{
	create_modify_add_bridge(argc, argv, use, brModify);
}

static void
do_add_bridge(int argc, char **argv, const char *use)
{
	create_modify_add_bridge(argc, argv, use, brAdd);
}

static void
do_delete_bridge(int argc, char **argv, const char *use)
{
	char			option;
	char			*altroot = NULL;
	uint32_t		flags = DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST;
	dladm_status_t		status;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":R:", bridge_lopts, NULL)) !=
	    -1) {
		switch (option) {
		case 'R':
			altroot = optarg;
			break;
		default:
			die_opterr(optopt, option, use);
			break;
		}
	}

	/* get the bridge name (required last argument) */
	if (optind != (argc-1))
		usage();

	if (altroot != NULL)
		altroot_cmd(altroot, argc, argv);

	status = dladm_bridge_delete(handle, argv[optind], flags);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "delete operation failed");
}

static void
do_remove_bridge(int argc, char **argv, const char *use)
{
	char		option;
	uint_t		n, nlink;
	char		*links[MAXPORT];
	datalink_id_t	linkids[MAXPORT];
	char		*altroot = NULL;
	dladm_status_t	status;
	boolean_t	removed_one;

	nlink = opterr = 0;
	while ((option = getopt_long(argc, argv, ":R:l:", bridge_lopts,
	    NULL)) != -1) {
		switch (option) {
		case 'R':
			altroot = optarg;
			break;
		case 'l':
			if (nlink >= MAXPORT)
				die("too many links specified");
			links[nlink++] = optarg;
			break;
		default:
			die_opterr(optopt, option, use);
			break;
		}
	}

	if (nlink == 0)
		usage();

	/* get the bridge name (required last argument) */
	if (optind != (argc-1))
		usage();

	if (altroot != NULL)
		altroot_cmd(altroot, argc, argv);

	for (n = 0; n < nlink; n++) {
		char bridge[MAXLINKNAMELEN];

		if (dladm_name2info(handle, links[n], &linkids[n], NULL, NULL,
		    NULL) != DLADM_STATUS_OK)
			die("invalid link name '%s'", links[n]);
		status = dladm_bridge_getlink(handle, linkids[n], bridge,
		    sizeof (bridge));
		if (status != DLADM_STATUS_OK &&
		    status != DLADM_STATUS_NOTFOUND) {
			die_dlerr(status, "cannot get bridge status on %s",
			    links[n]);
		}
		if (status == DLADM_STATUS_NOTFOUND ||
		    strcmp(bridge, argv[optind]) != 0)
			die("link %s is not on bridge %s", links[n],
			    argv[optind]);
	}

	removed_one = B_FALSE;
	for (n = 0; n < nlink; n++) {
		status = dladm_bridge_setlink(handle, linkids[n], "");
		if (status == DLADM_STATUS_OK) {
			removed_one = B_TRUE;
		} else {
			warn_dlerr(status,
			    "cannot remove link %s from bridge %s",
			    links[n], argv[optind]);
		}
	}
	if (!removed_one)
		die("unable to remove any links from bridge %s", argv[optind]);
}

static void
fmt_int(char *buf, size_t buflen, int value, int runvalue,
    boolean_t printstar)
{
	(void) snprintf(buf, buflen, "%d", value);
	if (value != runvalue && printstar)
		(void) strlcat(buf, "*", buflen);
}

static void
fmt_bridge_id(char *buf, size_t buflen, UID_BRIDGE_ID_T *bid)
{
	(void) snprintf(buf, buflen, "%u/%x:%x:%x:%x:%x:%x", bid->prio,
	    bid->addr[0], bid->addr[1], bid->addr[2], bid->addr[3],
	    bid->addr[4], bid->addr[5]);
}

static dladm_status_t
print_bridge(show_state_t *state, datalink_id_t linkid,
    bridge_fields_buf_t *bbuf)
{
	char			link[MAXLINKNAMELEN];
	datalink_class_t	class;
	uint32_t		flags;
	dladm_status_t		status;
	UID_STP_CFG_T		smfcfg, runcfg;
	UID_STP_STATE_T		stpstate;
	dladm_bridge_prot_t	smfprot, runprot;

	if ((status = dladm_datalink_id2info(handle, linkid, &flags, &class,
	    NULL, link, sizeof (link))) != DLADM_STATUS_OK)
		return (status);

	if (!(state->ls_flags & flags))
		return (DLADM_STATUS_NOTFOUND);

	/* Convert observability node name back to bridge name */
	if (!dladm_observe_to_bridge(link))
		return (DLADM_STATUS_NOTFOUND);
	(void) strlcpy(bbuf->bridge_name, link, sizeof (bbuf->bridge_name));

	/*
	 * If the running value differs from the one in SMF, and parsable
	 * output is not requested, then we show the running value with an
	 * asterisk.
	 */
	(void) dladm_bridge_get_properties(bbuf->bridge_name, &smfcfg,
	    &smfprot);
	(void) dladm_bridge_run_properties(bbuf->bridge_name, &runcfg,
	    &runprot);
	(void) snprintf(bbuf->bridge_protect, sizeof (bbuf->bridge_protect),
	    "%s%s", state->ls_parsable || smfprot == runprot ? "" : "*",
	    dladm_bridge_prot2str(runprot));
	fmt_int(bbuf->bridge_priority, sizeof (bbuf->bridge_priority),
	    smfcfg.bridge_priority, runcfg.bridge_priority,
	    !state->ls_parsable && (runcfg.field_mask & BR_CFG_AGE));
	fmt_int(bbuf->bridge_bmaxage, sizeof (bbuf->bridge_bmaxage),
	    smfcfg.max_age, runcfg.max_age,
	    !state->ls_parsable && (runcfg.field_mask & BR_CFG_AGE));
	fmt_int(bbuf->bridge_bhellotime,
	    sizeof (bbuf->bridge_bhellotime), smfcfg.hello_time,
	    runcfg.hello_time,
	    !state->ls_parsable && (runcfg.field_mask & BR_CFG_HELLO));
	fmt_int(bbuf->bridge_bfwddelay, sizeof (bbuf->bridge_bfwddelay),
	    smfcfg.forward_delay, runcfg.forward_delay,
	    !state->ls_parsable && (runcfg.field_mask & BR_CFG_DELAY));
	fmt_int(bbuf->bridge_forceproto, sizeof (bbuf->bridge_forceproto),
	    smfcfg.force_version, runcfg.force_version,
	    !state->ls_parsable && (runcfg.field_mask & BR_CFG_FORCE_VER));
	fmt_int(bbuf->bridge_holdtime, sizeof (bbuf->bridge_holdtime),
	    smfcfg.hold_time, runcfg.hold_time,
	    !state->ls_parsable && (runcfg.field_mask & BR_CFG_HOLD_TIME));

	if (dladm_bridge_state(bbuf->bridge_name, &stpstate) ==
	    DLADM_STATUS_OK) {
		fmt_bridge_id(bbuf->bridge_address,
		    sizeof (bbuf->bridge_address), &stpstate.bridge_id);
		(void) snprintf(bbuf->bridge_tctime,
		    sizeof (bbuf->bridge_tctime), "%lu",
		    stpstate.timeSince_Topo_Change);
		(void) snprintf(bbuf->bridge_tccount,
		    sizeof (bbuf->bridge_tccount), "%lu",
		    stpstate.Topo_Change_Count);
		(void) snprintf(bbuf->bridge_tchange,
		    sizeof (bbuf->bridge_tchange), "%u", stpstate.Topo_Change);
		fmt_bridge_id(bbuf->bridge_desroot,
		    sizeof (bbuf->bridge_desroot), &stpstate.designated_root);
		(void) snprintf(bbuf->bridge_rootcost,
		    sizeof (bbuf->bridge_rootcost), "%lu",
		    stpstate.root_path_cost);
		(void) snprintf(bbuf->bridge_rootport,
		    sizeof (bbuf->bridge_rootport), "%u", stpstate.root_port);
		(void) snprintf(bbuf->bridge_maxage,
		    sizeof (bbuf->bridge_maxage), "%d", stpstate.max_age);
		(void) snprintf(bbuf->bridge_hellotime,
		    sizeof (bbuf->bridge_hellotime), "%d", stpstate.hello_time);
		(void) snprintf(bbuf->bridge_fwddelay,
		    sizeof (bbuf->bridge_fwddelay), "%d",
		    stpstate.forward_delay);
	}
	return (DLADM_STATUS_OK);
}

static dladm_status_t
print_bridge_stats(show_state_t *state, datalink_id_t linkid,
    bridge_statfields_buf_t *bbuf)
{
	char			link[MAXLINKNAMELEN];
	datalink_class_t	class;
	uint32_t		flags;
	dladm_status_t		status;
	kstat_ctl_t		*kcp;
	kstat_t			*ksp;
	brsum_t			*brsum = (brsum_t *)&state->ls_prevstats;
	brsum_t			newval;

#ifndef lint
	/* This is a compile-time assertion; optimizer normally fixes this */
	extern void brsum_t_is_too_large(void);

	if (sizeof (*brsum) > sizeof (state->ls_prevstats))
		brsum_t_is_too_large();
#endif

	if (state->ls_firstonly) {
		if (state->ls_donefirst)
			return (DLADM_WALK_CONTINUE);
		state->ls_donefirst = B_TRUE;
	} else {
		bzero(brsum, sizeof (*brsum));
	}
	bzero(&newval, sizeof (newval));

	if ((status = dladm_datalink_id2info(handle, linkid, &flags, &class,
	    NULL, link, sizeof (link))) != DLADM_STATUS_OK)
		return (status);

	if (!(state->ls_flags & flags))
		return (DLADM_STATUS_NOTFOUND);

	if ((kcp = kstat_open()) == NULL) {
		warn("kstat open operation failed");
		return (DLADM_STATUS_OK);
	}
	if ((ksp = kstat_lookup(kcp, "bridge", 0, link)) != NULL &&
	    kstat_read(kcp, ksp, NULL) != -1) {
		if (dladm_kstat_value(ksp, "drops", KSTAT_DATA_UINT64,
		    &newval.drops) == DLADM_STATUS_OK) {
			(void) snprintf(bbuf->bridges_drops,
			    sizeof (bbuf->bridges_drops), "%llu",
			    newval.drops - brsum->drops);
		}
		if (dladm_kstat_value(ksp, "forward_direct", KSTAT_DATA_UINT64,
		    &newval.forward_dir) == DLADM_STATUS_OK) {
			(void) snprintf(bbuf->bridges_forwards,
			    sizeof (bbuf->bridges_forwards), "%llu",
			    newval.forward_dir - brsum->forward_dir);
		}
		if (dladm_kstat_value(ksp, "forward_mbcast", KSTAT_DATA_UINT64,
		    &newval.forward_mb) == DLADM_STATUS_OK) {
			(void) snprintf(bbuf->bridges_mbcast,
			    sizeof (bbuf->bridges_mbcast), "%llu",
			    newval.forward_mb - brsum->forward_mb);
		}
		if (dladm_kstat_value(ksp, "forward_unknown", KSTAT_DATA_UINT64,
		    &newval.forward_unk) == DLADM_STATUS_OK) {
			(void) snprintf(bbuf->bridges_unknown,
			    sizeof (bbuf->bridges_unknown), "%llu",
			    newval.forward_unk - brsum->forward_unk);
		}
		if (dladm_kstat_value(ksp, "recv", KSTAT_DATA_UINT64,
		    &newval.recv) == DLADM_STATUS_OK) {
			(void) snprintf(bbuf->bridges_recv,
			    sizeof (bbuf->bridges_recv), "%llu",
			    newval.recv - brsum->recv);
		}
		if (dladm_kstat_value(ksp, "sent", KSTAT_DATA_UINT64,
		    &newval.sent) == DLADM_STATUS_OK) {
			(void) snprintf(bbuf->bridges_sent,
			    sizeof (bbuf->bridges_sent), "%llu",
			    newval.sent - brsum->sent);
		}
	}
	(void) kstat_close(kcp);

	/* Convert observability node name back to bridge name */
	if (!dladm_observe_to_bridge(link))
		return (DLADM_STATUS_NOTFOUND);
	(void) strlcpy(bbuf->bridges_name, link, sizeof (bbuf->bridges_name));

	*brsum = newval;

	return (DLADM_STATUS_OK);
}

/*
 * This structure carries around extra state information for the show-bridge
 * command and allows us to use common support functions.
 */
typedef struct {
	show_state_t	state;
	boolean_t	show_stats;
	const char	*bridge;
} show_brstate_t;

/* ARGSUSED */
static int
show_bridge(dladm_handle_t handle, datalink_id_t linkid, void *arg)
{
	show_brstate_t	*brstate = arg;
	void *buf;

	if (brstate->show_stats) {
		bridge_statfields_buf_t bbuf;

		bzero(&bbuf, sizeof (bbuf));
		brstate->state.ls_status = print_bridge_stats(&brstate->state,
		    linkid, &bbuf);
		buf = &bbuf;
	} else {
		bridge_fields_buf_t bbuf;

		bzero(&bbuf, sizeof (bbuf));
		brstate->state.ls_status = print_bridge(&brstate->state, linkid,
		    &bbuf);
		buf = &bbuf;
	}
	if (brstate->state.ls_status == DLADM_STATUS_OK)
		ofmt_print(brstate->state.ls_ofmt, buf);
	return (DLADM_WALK_CONTINUE);
}

static void
fmt_bool(char *buf, size_t buflen, int val)
{
	(void) strlcpy(buf, val ? "yes" : "no", buflen);
}

static dladm_status_t
print_bridge_link(show_state_t *state, datalink_id_t linkid,
    bridge_link_fields_buf_t *bbuf)
{
	datalink_class_t	class;
	uint32_t		flags;
	dladm_status_t		status;
	UID_STP_PORT_STATE_T	stpstate;

	status = dladm_datalink_id2info(handle, linkid, &flags, &class, NULL,
	    bbuf->bridgel_link, sizeof (bbuf->bridgel_link));
	if (status != DLADM_STATUS_OK)
		return (status);

	if (!(state->ls_flags & flags))
		return (DLADM_STATUS_NOTFOUND);

	if (dladm_bridge_link_state(handle, linkid, &stpstate) ==
	    DLADM_STATUS_OK) {
		(void) snprintf(bbuf->bridgel_index,
		    sizeof (bbuf->bridgel_index), "%u", stpstate.port_no);
		if (dlsym(RTLD_PROBE, "STP_IN_state2str")) {
			(void) strlcpy(bbuf->bridgel_state,
			    STP_IN_state2str(stpstate.state),
			    sizeof (bbuf->bridgel_state));
		} else {
			(void) snprintf(bbuf->bridgel_state,
			    sizeof (bbuf->bridgel_state), "%u",
			    stpstate.state);
		}
		(void) snprintf(bbuf->bridgel_uptime,
		    sizeof (bbuf->bridgel_uptime), "%lu", stpstate.uptime);
		(void) snprintf(bbuf->bridgel_opercost,
		    sizeof (bbuf->bridgel_opercost), "%lu",
		    stpstate.oper_port_path_cost);
		fmt_bool(bbuf->bridgel_operp2p, sizeof (bbuf->bridgel_operp2p),
		    stpstate.oper_point2point);
		fmt_bool(bbuf->bridgel_operedge,
		    sizeof (bbuf->bridgel_operedge), stpstate.oper_edge);
		fmt_bridge_id(bbuf->bridgel_desroot,
		    sizeof (bbuf->bridgel_desroot), &stpstate.designated_root);
		(void) snprintf(bbuf->bridgel_descost,
		    sizeof (bbuf->bridgel_descost), "%lu",
		    stpstate.designated_cost);
		fmt_bridge_id(bbuf->bridgel_desbridge,
		    sizeof (bbuf->bridgel_desbridge),
		    &stpstate.designated_bridge);
		(void) snprintf(bbuf->bridgel_desport,
		    sizeof (bbuf->bridgel_desport), "%u",
		    stpstate.designated_port);
		fmt_bool(bbuf->bridgel_tcack, sizeof (bbuf->bridgel_tcack),
		    stpstate.top_change_ack);
	}
	return (DLADM_STATUS_OK);
}

static dladm_status_t
print_bridge_link_stats(show_state_t *state, datalink_id_t linkid,
    bridge_link_statfields_buf_t *bbuf)
{
	datalink_class_t	class;
	uint32_t		flags;
	dladm_status_t		status;
	UID_STP_PORT_STATE_T	stpstate;
	kstat_ctl_t		*kcp;
	kstat_t			*ksp;
	char			bridge[MAXLINKNAMELEN];
	char			kstatname[MAXLINKNAMELEN*2 + 1];
	brlsum_t		*brlsum = (brlsum_t *)&state->ls_prevstats;
	brlsum_t		newval;

#ifndef lint
	/* This is a compile-time assertion; optimizer normally fixes this */
	extern void brlsum_t_is_too_large(void);

	if (sizeof (*brlsum) > sizeof (state->ls_prevstats))
		brlsum_t_is_too_large();
#endif

	if (state->ls_firstonly) {
		if (state->ls_donefirst)
			return (DLADM_WALK_CONTINUE);
		state->ls_donefirst = B_TRUE;
	} else {
		bzero(brlsum, sizeof (*brlsum));
	}
	bzero(&newval, sizeof (newval));

	status = dladm_datalink_id2info(handle, linkid, &flags, &class, NULL,
	    bbuf->bridgels_link, sizeof (bbuf->bridgels_link));
	if (status != DLADM_STATUS_OK)
		return (status);

	if (!(state->ls_flags & flags))
		return (DLADM_STATUS_NOTFOUND);

	if (dladm_bridge_link_state(handle, linkid, &stpstate) ==
	    DLADM_STATUS_OK) {
		newval.cfgbpdu = stpstate.rx_cfg_bpdu_cnt;
		newval.tcnbpdu = stpstate.rx_tcn_bpdu_cnt;
		newval.rstpbpdu = stpstate.rx_rstp_bpdu_cnt;
		newval.txbpdu = stpstate.txCount;

		(void) snprintf(bbuf->bridgels_cfgbpdu,
		    sizeof (bbuf->bridgels_cfgbpdu), "%lu",
		    newval.cfgbpdu - brlsum->cfgbpdu);
		(void) snprintf(bbuf->bridgels_tcnbpdu,
		    sizeof (bbuf->bridgels_tcnbpdu), "%lu",
		    newval.tcnbpdu - brlsum->tcnbpdu);
		(void) snprintf(bbuf->bridgels_rstpbpdu,
		    sizeof (bbuf->bridgels_rstpbpdu), "%lu",
		    newval.rstpbpdu - brlsum->rstpbpdu);
		(void) snprintf(bbuf->bridgels_txbpdu,
		    sizeof (bbuf->bridgels_txbpdu), "%lu",
		    newval.txbpdu - brlsum->txbpdu);
	}

	if ((status = dladm_bridge_getlink(handle, linkid, bridge,
	    sizeof (bridge))) != DLADM_STATUS_OK)
		goto bls_out;
	(void) snprintf(kstatname, sizeof (kstatname), "%s0-%s", bridge,
	    bbuf->bridgels_link);
	if ((kcp = kstat_open()) == NULL) {
		warn("kstat open operation failed");
		goto bls_out;
	}
	if ((ksp = kstat_lookup(kcp, "bridge", 0, kstatname)) != NULL &&
	    kstat_read(kcp, ksp, NULL) != -1) {
		if (dladm_kstat_value(ksp, "drops", KSTAT_DATA_UINT64,
		    &newval.drops) != -1) {
			(void) snprintf(bbuf->bridgels_drops,
			    sizeof (bbuf->bridgels_drops), "%llu",
			    newval.drops - brlsum->drops);
		}
		if (dladm_kstat_value(ksp, "recv", KSTAT_DATA_UINT64,
		    &newval.recv) != -1) {
			(void) snprintf(bbuf->bridgels_recv,
			    sizeof (bbuf->bridgels_recv), "%llu",
			    newval.recv - brlsum->recv);
		}
		if (dladm_kstat_value(ksp, "xmit", KSTAT_DATA_UINT64,
		    &newval.xmit) != -1) {
			(void) snprintf(bbuf->bridgels_xmit,
			    sizeof (bbuf->bridgels_xmit), "%llu",
			    newval.xmit - brlsum->xmit);
		}
	}
	(void) kstat_close(kcp);
bls_out:
	*brlsum = newval;

	return (status);
}

static void
show_bridge_link(datalink_id_t linkid, show_brstate_t *brstate)
{
	void *buf;

	if (brstate->show_stats) {
		bridge_link_statfields_buf_t bbuf;

		bzero(&bbuf, sizeof (bbuf));
		brstate->state.ls_status = print_bridge_link_stats(
		    &brstate->state, linkid, &bbuf);
		buf = &bbuf;
	} else {
		bridge_link_fields_buf_t bbuf;

		bzero(&bbuf, sizeof (bbuf));
		brstate->state.ls_status = print_bridge_link(&brstate->state,
		    linkid, &bbuf);
		buf = &bbuf;
	}
	if (brstate->state.ls_status == DLADM_STATUS_OK)
		ofmt_print(brstate->state.ls_ofmt, buf);
}

/* ARGSUSED */
static int
show_bridge_link_walk(dladm_handle_t handle, datalink_id_t linkid, void *arg)
{
	show_brstate_t	*brstate = arg;
	char bridge[MAXLINKNAMELEN];

	if (dladm_bridge_getlink(handle, linkid, bridge, sizeof (bridge)) ==
	    DLADM_STATUS_OK && strcmp(bridge, brstate->bridge) == 0) {
		show_bridge_link(linkid, brstate);
	}
	return (DLADM_WALK_CONTINUE);
}

static void
show_bridge_fwd(dladm_handle_t handle, bridge_listfwd_t *blf,
    show_state_t *state)
{
	bridge_fwd_fields_buf_t bbuf;

	bzero(&bbuf, sizeof (bbuf));
	(void) snprintf(bbuf.bridgef_dest, sizeof (bbuf.bridgef_dest),
	    "%s", ether_ntoa((struct ether_addr *)blf->blf_dest));
	if (blf->blf_is_local) {
		(void) strlcpy(bbuf.bridgef_flags, "L",
		    sizeof (bbuf.bridgef_flags));
	} else {
		(void) snprintf(bbuf.bridgef_age, sizeof (bbuf.bridgef_age),
		    "%2d.%03d", blf->blf_ms_age / 1000, blf->blf_ms_age % 1000);
		if (blf->blf_trill_nick != 0) {
			(void) snprintf(bbuf.bridgef_output,
			    sizeof (bbuf.bridgef_output), "%u",
			    blf->blf_trill_nick);
		}
	}
	if (blf->blf_linkid != DATALINK_INVALID_LINKID &&
	    blf->blf_trill_nick == 0) {
		state->ls_status = dladm_datalink_id2info(handle,
		    blf->blf_linkid, NULL, NULL, NULL, bbuf.bridgef_output,
		    sizeof (bbuf.bridgef_output));
	}
	if (state->ls_status == DLADM_STATUS_OK)
		ofmt_print(state->ls_ofmt, &bbuf);
}

static void
show_bridge_trillnick(trill_listnick_t *tln, show_state_t *state)
{
	bridge_trill_fields_buf_t bbuf;

	bzero(&bbuf, sizeof (bbuf));
	(void) snprintf(bbuf.bridget_nick, sizeof (bbuf.bridget_nick),
	    "%u", tln->tln_nick);
	if (tln->tln_ours) {
		(void) strlcpy(bbuf.bridget_flags, "L",
		    sizeof (bbuf.bridget_flags));
	} else {
		state->ls_status = dladm_datalink_id2info(handle,
		    tln->tln_linkid, NULL, NULL, NULL, bbuf.bridget_link,
		    sizeof (bbuf.bridget_link));
		(void) snprintf(bbuf.bridget_nexthop,
		    sizeof (bbuf.bridget_nexthop), "%s",
		    ether_ntoa((struct ether_addr *)tln->tln_nexthop));
	}
	if (state->ls_status == DLADM_STATUS_OK)
		ofmt_print(state->ls_ofmt, &bbuf);
}

static void
do_show_bridge(int argc, char **argv, const char *use)
{
	int		option;
	enum {
		bridgeMode, linkMode, fwdMode, trillMode
	}		op_mode = bridgeMode;
	uint32_t	flags = DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST;
	boolean_t	parsable = B_FALSE;
	datalink_id_t	linkid = DATALINK_ALL_LINKID;
	int		interval = 0;
	show_brstate_t	brstate;
	dladm_status_t	status;
	char		*fields_str = NULL;
	/* default: bridge-related data */
	char		*all_fields = "bridge,protect,address,priority,bmaxage,"
	    "bhellotime,bfwddelay,forceproto,tctime,tccount,tchange,"
	    "desroot,rootcost,rootport,maxage,hellotime,fwddelay,holdtime";
	char		*default_fields = "bridge,protect,address,priority,"
	    "desroot";
	char		*all_statfields = "bridge,drops,forwards,mbcast,"
	    "unknown,recv,sent";
	char		*default_statfields = "bridge,drops,forwards,mbcast,"
	    "unknown";
	/* -l: link-related data */
	char		*all_link_fields = "link,index,state,uptime,opercost,"
	    "operp2p,operedge,desroot,descost,desbridge,desport,tcack";
	char		*default_link_fields = "link,state,uptime,desroot";
	char		*all_link_statfields = "link,cfgbpdu,tcnbpdu,rstpbpdu,"
	    "txbpdu,drops,recv,xmit";
	char		*default_link_statfields = "link,drops,recv,xmit";
	/* -f: bridge forwarding table related data */
	char		*default_fwd_fields = "dest,age,flags,output";
	/* -t: TRILL nickname table related data */
	char		*default_trill_fields = "nick,flags,link,nexthop";
	char		*default_str;
	char		*all_str;
	ofmt_field_t	*field_arr;
	ofmt_handle_t	ofmt;
	ofmt_status_t	oferr;
	uint_t		ofmtflags = 0;

	bzero(&brstate, sizeof (brstate));

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":fi:lo:pst",
	    bridge_show_lopts, NULL)) != -1) {
		switch (option) {
		case 'f':
			if (op_mode != bridgeMode && op_mode != fwdMode)
				die("-f is incompatible with -l or -t");
			op_mode = fwdMode;
			break;
		case 'i':
			if (interval != 0)
				die_optdup(option);
			if (!str2int(optarg, &interval) || interval == 0)
				die("invalid interval value '%s'", optarg);
			break;
		case 'l':
			if (op_mode != bridgeMode && op_mode != linkMode)
				die("-l is incompatible with -f or -t");
			op_mode = linkMode;
			break;
		case 'o':
			fields_str = optarg;
			break;
		case 'p':
			if (parsable)
				die_optdup(option);
			parsable = B_TRUE;
			break;
		case 's':
			if (brstate.show_stats)
				die_optdup(option);
			brstate.show_stats = B_TRUE;
			break;
		case 't':
			if (op_mode != bridgeMode && op_mode != trillMode)
				die("-t is incompatible with -f or -l");
			op_mode = trillMode;
			break;
		default:
			die_opterr(optopt, option, use);
			break;
		}
	}

	if (interval != 0 && !brstate.show_stats)
		die("the -i option can be used only with -s");

	if ((op_mode == fwdMode || op_mode == trillMode) && brstate.show_stats)
		die("the -f/-t and -s options cannot be used together");

	/* get the bridge name (optional last argument) */
	if (optind == (argc-1)) {
		char lname[MAXLINKNAMELEN];
		uint32_t lnkflg;
		datalink_class_t class;

		brstate.bridge = argv[optind];
		(void) snprintf(lname, sizeof (lname), "%s0", brstate.bridge);
		if ((status = dladm_name2info(handle, lname, &linkid, &lnkflg,
		    &class, NULL)) != DLADM_STATUS_OK) {
			die_dlerr(status, "bridge %s is not valid",
			    brstate.bridge);
		}

		if (class != DATALINK_CLASS_BRIDGE)
			die("%s is not a bridge", brstate.bridge);

		if (!(lnkflg & flags)) {
			die_dlerr(DLADM_STATUS_BADARG,
			    "bridge %s is temporarily removed", brstate.bridge);
		}
	} else if (optind != argc) {
		usage();
	} else if (op_mode != bridgeMode) {
		die("bridge name required for -l, -f, or -t");
		return;
	}

	brstate.state.ls_parsable = parsable;
	brstate.state.ls_flags = flags;
	brstate.state.ls_firstonly = (interval != 0);

	switch (op_mode) {
	case bridgeMode:
		if (brstate.show_stats) {
			default_str = default_statfields;
			all_str = all_statfields;
			field_arr = bridge_statfields;
		} else {
			default_str = default_fields;
			all_str = all_fields;
			field_arr = bridge_fields;
		}
		break;

	case linkMode:
		if (brstate.show_stats) {
			default_str = default_link_statfields;
			all_str = all_link_statfields;
			field_arr = bridge_link_statfields;
		} else {
			default_str = default_link_fields;
			all_str = all_link_fields;
			field_arr = bridge_link_fields;
		}
		break;

	case fwdMode:
		default_str = all_str = default_fwd_fields;
		field_arr = bridge_fwd_fields;
		break;

	case trillMode:
		default_str = all_str = default_trill_fields;
		field_arr = bridge_trill_fields;
		break;
	}

	if (fields_str == NULL)
		fields_str = default_str;
	else if (strcasecmp(fields_str, "all") == 0)
		fields_str = all_str;

	if (parsable)
		ofmtflags |= OFMT_PARSABLE;
	oferr = ofmt_open(fields_str, field_arr, ofmtflags, 0, &ofmt);
	ofmt_check(oferr, brstate.state.ls_parsable, ofmt, die, warn);
	brstate.state.ls_ofmt = ofmt;

	for (;;) {
		brstate.state.ls_donefirst = B_FALSE;
		switch (op_mode) {
		case bridgeMode:
			if (linkid == DATALINK_ALL_LINKID) {
				(void) dladm_walk_datalink_id(show_bridge,
				    handle, &brstate, DATALINK_CLASS_BRIDGE,
				    DATALINK_ANY_MEDIATYPE, flags);
			} else {
				(void) show_bridge(handle, linkid, &brstate);
				if (brstate.state.ls_status !=
				    DLADM_STATUS_OK) {
					die_dlerr(brstate.state.ls_status,
					    "failed to show bridge %s",
					    brstate.bridge);
				}
			}
			break;

		case linkMode: {
			datalink_id_t *dlp;
			uint_t i, nlinks;

			dlp = dladm_bridge_get_portlist(brstate.bridge,
			    &nlinks);
			if (dlp != NULL) {
				for (i = 0; i < nlinks; i++)
					show_bridge_link(dlp[i], &brstate);
				dladm_bridge_free_portlist(dlp);
			} else if (errno == ENOENT) {
				/* bridge not running; iterate on libdladm */
				(void) dladm_walk_datalink_id(
				    show_bridge_link_walk, handle,
				    &brstate, DATALINK_CLASS_PHYS |
				    DATALINK_CLASS_AGGR |
				    DATALINK_CLASS_ETHERSTUB,
				    DATALINK_ANY_MEDIATYPE, flags);
			} else {
				die("unable to get port list for bridge %s: %s",
				    brstate.bridge, strerror(errno));
			}
			break;
		}

		case fwdMode: {
			bridge_listfwd_t *blf;
			uint_t i, nfwd;

			blf = dladm_bridge_get_fwdtable(handle, brstate.bridge,
			    &nfwd);
			if (blf == NULL) {
				die("unable to get forwarding entries for "
				    "bridge %s", brstate.bridge);
			} else {
				for (i = 0; i < nfwd; i++)
					show_bridge_fwd(handle, blf + i,
					    &brstate.state);
				dladm_bridge_free_fwdtable(blf);
			}
			break;
		}

		case trillMode: {
			trill_listnick_t *tln;
			uint_t i, nnick;

			tln = dladm_bridge_get_trillnick(brstate.bridge,
			    &nnick);
			if (tln == NULL) {
				if (errno == ENOENT)
					die("bridge %s is not running TRILL",
					    brstate.bridge);
				else
					die("unable to get TRILL nickname "
					    "entries for bridge %s",
					    brstate.bridge);
			} else {
				for (i = 0; i < nnick; i++)
					show_bridge_trillnick(tln + i,
					    &brstate.state);
				dladm_bridge_free_trillnick(tln);
			}
			break;
		}
		}
		if (interval == 0)
			break;
		(void) sleep(interval);
	}
}

/*
 * "-R" option support. It is used for live upgrading. Append dladm commands
 * to a upgrade script which will be run when the alternative root boots up:
 *
 * - If the /etc/dladm/datalink.conf file exists on the alternative root,
 * append dladm commands to the <altroot>/var/svc/profile/upgrade_datalink
 * script. This script will be run as part of the network/physical service.
 * We cannot defer this to /var/svc/profile/upgrade because then the
 * configuration will not be able to take effect before network/physical
 * plumbs various interfaces.
 *
 * - If the /etc/dladm/datalink.conf file does not exist on the alternative
 * root, append dladm commands to the <altroot>/var/svc/profile/upgrade script,
 * which will be run in the manifest-import service.
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
	 * Check for the existence of the /etc/dladm/datalink.conf
	 * configuration file, and determine the name of script file.
	 */
	(void) snprintf(path, MAXPATHLEN, "/%s/etc/dladm/datalink.conf",
	    altroot);
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
	dladm_close(handle);
	exit(EXIT_SUCCESS);
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

	(void) putc('\n', stderr);
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

/*
 * Also closes the dladm handle if it is not NULL.
 */
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

	/* close dladm handle if it was opened */
	if (handle != NULL)
		dladm_close(handle);

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

	(void) putc('\n', stderr);

	/* close dladm handle if it was opened */
	if (handle != NULL)
		dladm_close(handle);

	exit(EXIT_FAILURE);
}

static void
die_optdup(int opt)
{
	die("the option -%c cannot be specified more than once", opt);
}

static void
die_opterr(int opt, int opterr, const char *usage)
{
	switch (opterr) {
	case ':':
		die("option '-%c' requires a value\nusage: %s", opt,
		    gettext(usage));
		break;
	case '?':
	default:
		die("unrecognized option '-%c'\nusage: %s", opt,
		    gettext(usage));
		break;
	}
}

static void
show_ether_xprop(void *arg, dladm_ether_info_t *eattr)
{
	print_ether_state_t	*statep = arg;
	ether_fields_buf_t	ebuf;
	int			i;

	for (i = CAPABLE; i <= PEERADV; i++)  {
		bzero(&ebuf, sizeof (ebuf));
		(void) strlcpy(ebuf.eth_ptype, ptype[i],
		    sizeof (ebuf.eth_ptype));
		(void) dladm_ether_autoneg2str(ebuf.eth_autoneg,
		    sizeof (ebuf.eth_autoneg), eattr, i);
		(void) dladm_ether_spdx2str(ebuf.eth_spdx,
		    sizeof (ebuf.eth_spdx), eattr, i);
		(void) dladm_ether_pause2str(ebuf.eth_pause,
		    sizeof (ebuf.eth_pause), eattr, i);
		(void) strlcpy(ebuf.eth_rem_fault,
		    (eattr->lei_attr[i].le_fault ? "fault" : "none"),
		    sizeof (ebuf.eth_rem_fault));
		ofmt_print(statep->es_ofmt, &ebuf);
	}

}

static boolean_t
link_is_ether(const char *link, datalink_id_t *linkid)
{
	uint32_t media;
	datalink_class_t class;

	if (dladm_name2info(handle, link, linkid, NULL, &class, &media) ==
	    DLADM_STATUS_OK) {
		if (class == DATALINK_CLASS_PHYS && media == DL_ETHER)
			return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * default output callback function that, when invoked,
 * prints string which is offset by ofmt_arg->ofmt_id within buf.
 */
static boolean_t
print_default_cb(ofmt_arg_t *ofarg, char *buf, uint_t bufsize)
{
	char *value;

	value = (char *)ofarg->ofmt_cbarg + ofarg->ofmt_id;
	(void) strlcpy(buf, value, bufsize);
	return (B_TRUE);
}

/*
 * Called from the walker dladm_walk_datalink_id() for each IB partition to
 * display IB partition specific information.
 */
static dladm_status_t
print_part(show_part_state_t *state, datalink_id_t linkid)
{
	dladm_part_attr_t	attr;
	dladm_status_t		status;
	dladm_conf_t		conf;
	char			part_over[MAXLINKNAMELEN];
	char			part_name[MAXLINKNAMELEN];
	part_fields_buf_t	pbuf;
	boolean_t		force_in_conf = B_FALSE;

	/*
	 * Get the information about the IB partition from the partition
	 * datlink ID 'linkid'.
	 */
	if ((status = dladm_part_info(handle, linkid, &attr, state->ps_flags))
	    != DLADM_STATUS_OK)
		return (status);

	/*
	 * If an IB Phys link name was provided on the command line we have
	 * the Phys link's datalink ID in the ps_over_id field of the state
	 * structure. Proceed only if the IB partition represented by 'linkid'
	 * was created over Phys link denoted by ps_over_id. The
	 * 'dia_physlinkid' field of dladm_part_attr_t represents the IB Phys
	 * link over which the partition was created.
	 */
	if (state->ps_over_id != DATALINK_ALL_LINKID)
		if (state->ps_over_id != attr.dia_physlinkid)
			return (DLADM_STATUS_OK);

	/*
	 * The linkid argument passed to this function is the datalink ID
	 * of the IB Partition. Get the partitions name from this linkid.
	 */
	if (dladm_datalink_id2info(handle, linkid, NULL, NULL,
	    NULL, part_name, sizeof (part_name)) != DLADM_STATUS_OK)
		return (DLADM_STATUS_BADARG);

	bzero(part_over, sizeof (part_over));

	/*
	 * The 'dia_physlinkid' field contains the datalink ID of the IB Phys
	 * link over which the partition was created. Use this linkid to get the
	 * linkover field.
	 */
	if (dladm_datalink_id2info(handle, attr.dia_physlinkid, NULL, NULL,
	    NULL, part_over, sizeof (part_over)) != DLADM_STATUS_OK)
		(void) sprintf(part_over, "?");
	state->ps_found = B_TRUE;

	/*
	 * Read the FFORCE field from this datalink's persistent configuration
	 * database line to determine if this datalink was created forcibly.
	 * If this datalink is a temporary datalink, then it will not have an
	 * entry in the persistent configuration, so check if force create flag
	 * is set in the partition attributes.
	 *
	 * We need this two level check since persistent partitions brought up
	 * by up-part during boot will have force create flag always set, since
	 * we want up-part to always succeed even if the port is currently down
	 * or P_Key is not yet available in the subnet.
	 */
	if ((status = dladm_getsnap_conf(handle, linkid, &conf)) ==
	    DLADM_STATUS_OK) {
		(void) dladm_get_conf_field(handle, conf, FFORCE,
		    &force_in_conf, sizeof (boolean_t));
		dladm_destroy_conf(handle, conf);
	} else if (status == DLADM_STATUS_NOTFOUND) {
		/*
		 * for a temp link the force create flag will determine
		 * whether it was created with force flag.
		 */
		force_in_conf = ((attr.dia_flags & DLADM_PART_FORCE_CREATE)
		    != 0);
	}

	(void) snprintf(pbuf.part_link, sizeof (pbuf.part_link),
	    "%s", part_name);

	(void) snprintf(pbuf.part_over, sizeof (pbuf.part_over),
	    "%s", part_over);

	(void) snprintf(pbuf.part_pkey, sizeof (pbuf.part_pkey),
	    "%X", attr.dia_pkey);

	(void) get_linkstate(pbuf.part_link, B_TRUE, pbuf.part_state);

	(void) snprintf(pbuf.part_flags, sizeof (pbuf.part_flags),
	    "%c----", force_in_conf ? 'f' : '-');

	ofmt_print(state->ps_ofmt, &pbuf);

	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static int
show_part(dladm_handle_t dh, datalink_id_t linkid, void *arg)
{
	((show_part_state_t *)arg)->ps_status = print_part(arg, linkid);
	return (DLADM_WALK_CONTINUE);
}

/*
 * Show the information about the IB partition objects.
 */
static void
do_show_part(int argc, char *argv[], const char *use)
{
	int			option;
	boolean_t		l_arg = B_FALSE;
	uint32_t		flags = DLADM_OPT_ACTIVE;
	datalink_id_t		linkid = DATALINK_ALL_LINKID;
	datalink_id_t		over_linkid = DATALINK_ALL_LINKID;
	char			over_link[MAXLINKNAMELEN];
	show_part_state_t	state;
	dladm_status_t		status;
	boolean_t		o_arg = B_FALSE;
	char			*fields_str = NULL;
	ofmt_handle_t		ofmt;
	ofmt_status_t		oferr;
	uint_t			ofmtflags = 0;

	bzero(&state, sizeof (state));
	opterr = 0;
	while ((option = getopt_long(argc, argv, ":pPl:o:", show_part_lopts,
	    NULL)) != -1) {
		switch (option) {
		case 'p':
			state.ps_parsable = B_TRUE;
			break;
		case 'P':
			flags = DLADM_OPT_PERSIST;
			break;
		case 'l':
			/*
			 * The data link ID of the IB Phys link. When this
			 * argument is provided we list only the partition
			 * objects created over this IB Phys link.
			 */
			if (strlcpy(over_link, optarg, MAXLINKNAMELEN) >=
			    MAXLINKNAMELEN)
				die("link name too long");

			l_arg = B_TRUE;
			break;
		case 'o':
			o_arg = B_TRUE;
			fields_str = optarg;
			break;
		default:
			die_opterr(optopt, option, use);
		}
	}

	/*
	 * Get the partition ID (optional last argument).
	 */
	if (optind == (argc - 1)) {
		status = dladm_name2info(handle, argv[optind], &linkid, NULL,
		    NULL, NULL);
		if (status != DLADM_STATUS_OK) {
			die_dlerr(status, "invalid partition link name '%s'",
			    argv[optind]);
		}
		(void) strlcpy(state.ps_part, argv[optind], MAXLINKNAMELEN);
	} else if (optind != argc) {
		usage();
	}

	if (state.ps_parsable && !o_arg)
		die("-p requires -o");

	/*
	 * If an IB Phys link name was provided as an argument, then get its
	 * datalink ID.
	 */
	if (l_arg) {
		status = dladm_name2info(handle, over_link, &over_linkid, NULL,
		    NULL, NULL);
		if (status != DLADM_STATUS_OK) {
			die_dlerr(status, "invalid link name '%s'", over_link);
		}
	}

	state.ps_over_id = over_linkid; /* IB Phys link ID */
	state.ps_found = B_FALSE;
	state.ps_flags = flags;

	if (state.ps_parsable)
		ofmtflags |= OFMT_PARSABLE;
	oferr = ofmt_open(fields_str, part_fields, ofmtflags, 0, &ofmt);
	ofmt_check(oferr, state.ps_parsable, ofmt, die, warn);
	state.ps_ofmt = ofmt;

	/*
	 * If a specific IB partition name was not provided as an argument,
	 * walk all the datalinks and display the information for all
	 * IB partitions. If IB Phys link was provided limit it to only
	 * IB partitions created over that IB Phys link.
	 */
	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(show_part, handle, &state,
		    DATALINK_CLASS_PART, DATALINK_ANY_MEDIATYPE, flags);
	} else {
		(void) show_part(handle, linkid, &state);
		if (state.ps_status != DLADM_STATUS_OK) {
			ofmt_close(ofmt);
			die_dlerr(state.ps_status, "failed to show IB partition"
			    " '%s'", state.ps_part);
		}
	}
	ofmt_close(ofmt);
}


/*
 * Called from the walker dladm_walk_datalink_id() for each IB Phys link to
 * display IB specific information for these Phys links.
 */
static dladm_status_t
print_ib(show_ib_state_t *state, datalink_id_t phys_linkid)
{
	dladm_ib_attr_t		attr;
	dladm_status_t		status;
	char			linkname[MAXLINKNAMELEN];
	char			pkeystr[MAXPKEYLEN];
	int			i;
	ib_fields_buf_t		ibuf;

	bzero(&attr, sizeof (attr));

	/*
	 * Get the attributes of the IB Phys link from active/Persistent config
	 * based on the flag passed.
	 */
	if ((status = dladm_ib_info(handle, phys_linkid, &attr,
	    state->is_flags)) != DLADM_STATUS_OK)
		return (status);

	if ((state->is_link_id != DATALINK_ALL_LINKID) && (state->is_link_id
	    != attr.dia_physlinkid)) {
		dladm_free_ib_info(&attr);
		return (DLADM_STATUS_OK);
	}

	/*
	 * Get the data link name for the phys_linkid. If we are doing show-ib
	 * for all IB Phys links, we have only the datalink IDs not the
	 * datalink name.
	 */
	if (dladm_datalink_id2info(handle, phys_linkid, NULL, NULL, NULL,
	    linkname, MAXLINKNAMELEN) != DLADM_STATUS_OK)
		return (status);

	(void) snprintf(ibuf.ib_link, sizeof (ibuf.ib_link),
	    "%s", linkname);

	(void) snprintf(ibuf.ib_portnum, sizeof (ibuf.ib_portnum),
	    "%d", attr.dia_portnum);

	(void) snprintf(ibuf.ib_hcaguid, sizeof (ibuf.ib_hcaguid),
	    "%llX", attr.dia_hca_guid);

	(void) snprintf(ibuf.ib_portguid, sizeof (ibuf.ib_portguid),
	    "%llX", attr.dia_port_guid);

	(void) get_linkstate(linkname, B_TRUE, ibuf.ib_state);

	/*
	 * Create a comma separated list of pkeys from the pkey table returned
	 * by the IP over IB driver instance.
	 */
	bzero(ibuf.ib_pkeys, attr.dia_port_pkey_tbl_sz * sizeof (ib_pkey_t));
	for (i = 0; i < attr.dia_port_pkey_tbl_sz; i++) {
		if (attr.dia_port_pkeys[i] != IB_PKEY_INVALID_FULL &&
		    attr.dia_port_pkeys[i] != IB_PKEY_INVALID_LIMITED) {
			if (i == 0)
				(void) snprintf(pkeystr, MAXPKEYLEN, "%X",
				    attr.dia_port_pkeys[i]);
			else
				(void) snprintf(pkeystr, MAXPKEYLEN, ",%X",
				    attr.dia_port_pkeys[i]);
			(void) strlcat(ibuf.ib_pkeys, pkeystr, MAXPKEYSTRSZ);
		}
	}

	dladm_free_ib_info(&attr);

	ofmt_print(state->is_ofmt, &ibuf);

	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static int
show_ib(dladm_handle_t dh, datalink_id_t linkid, void *arg)
{
	((show_ib_state_t *)arg)->is_status = print_ib(arg, linkid);
	return (DLADM_WALK_CONTINUE);
}

/*
 * Show the properties of one/all IB Phys links. This is different from
 * show-phys command since this will display IB specific information about the
 * Phys link like, HCA GUID, PORT GUID, PKEYS active for this port etc.
 */
static void
do_show_ib(int argc, char *argv[], const char *use)
{
	int			option;
	uint32_t		flags = DLADM_OPT_ACTIVE;
	datalink_id_t		linkid = DATALINK_ALL_LINKID;
	show_ib_state_t		state;
	dladm_status_t		status;
	boolean_t		o_arg = B_FALSE;
	char			*fields_str = NULL;
	ofmt_handle_t		ofmt;
	ofmt_status_t		oferr;
	uint_t			ofmtflags = 0;

	bzero(&state, sizeof (state));
	opterr = 0;
	while ((option = getopt_long(argc, argv, ":po:", show_lopts,
	    NULL)) != -1) {
		switch (option) {
		case 'p':
			state.is_parsable = B_TRUE;
			break;
		case 'o':
			o_arg = B_TRUE;
			fields_str = optarg;
			break;
		default:
			die_opterr(optopt, option, use);
		}
	}

	/* get IB Phys link ID (optional last argument) */
	if (optind == (argc - 1)) {
		status = dladm_name2info(handle, argv[optind], &linkid, NULL,
		    NULL, NULL);
		if (status != DLADM_STATUS_OK) {
			die_dlerr(status, "invalid IB port name '%s'",
			    argv[optind]);
		}
		(void) strlcpy(state.is_link, argv[optind], MAXLINKNAMELEN);
	} else if (optind != argc) {
		usage();
	}

	if (state.is_parsable && !o_arg)
		die("-p requires -o");

	/*
	 * linkid is the data link ID of the IB Phys link. By default it will
	 * be DATALINK_ALL_LINKID.
	 */
	state.is_link_id = linkid;
	state.is_flags = flags;

	if (state.is_parsable)
		ofmtflags |= OFMT_PARSABLE;
	oferr = ofmt_open(fields_str, ib_fields, ofmtflags, 0, &ofmt);
	ofmt_check(oferr, state.is_parsable, ofmt, die, warn);
	state.is_ofmt = ofmt;

	/*
	 * If we are going to display the information for all IB Phys links
	 * then we'll walk through all the datalinks for datalinks of Phys
	 * class and media type IB.
	 */
	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(show_ib, handle, &state,
		    DATALINK_CLASS_PHYS, DL_IB, flags);
	} else {
		/*
		 * We need to display the information only for the IB phys link
		 * linkid. Call show_ib for this link.
		 */
		(void) show_ib(handle, linkid, &state);
		if (state.is_status != DLADM_STATUS_OK) {
			ofmt_close(ofmt);
			die_dlerr(state.is_status, "failed to show IB Phys link"
			    " '%s'", state.is_link);
		}
	}
	ofmt_close(ofmt);
}

/*
 * Create an IP over Infiniband partition object over an IB Phys link. The IB
 * Phys link is associated with an Infiniband HCA port. The IB partition object
 * is created over a port, pkey combination. This partition object represents
 * an instance of IP over IB interface.
 */
/* ARGSUSED */
static void
do_create_part(int argc, char *argv[], const char *use)
{
	int		status, option;
	int		flags = DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST;
	char		*pname;
	char		*l_arg = NULL;
	char		*altroot = NULL;
	datalink_id_t	physlinkid = 0;
	datalink_id_t	partlinkid = 0;
	unsigned long	opt_pkey;
	ib_pkey_t	pkey = 0;
	char		*endp = NULL;
	char		propstr[DLADM_STRSIZE];
	dladm_arg_list_t	*proplist = NULL;

	propstr[0] = '\0';
	while ((option = getopt_long(argc, argv, ":tfl:P:R:p:",
	    part_lopts, NULL)) != -1) {
		switch (option) {
		case 't':
			/*
			 * Create a temporary IB partition object. This
			 * instance is not entered into the persistent database
			 * so it will not be recreated automatically on a
			 * reboot.
			 */
			flags &= ~DLADM_OPT_PERSIST;
			break;
		case 'l':
			/*
			 * The IB phys link over which the partition object will
			 * be created.
			 */
			l_arg = optarg;
			break;
		case 'R':
			altroot = optarg;
			break;
		case 'p':
			(void) strlcat(propstr, optarg, DLADM_STRSIZE);
			if (strlcat(propstr, ",", DLADM_STRSIZE) >=
			    DLADM_STRSIZE)
				die("property list too long '%s'", propstr);
			break;
		case 'P':
			/*
			 * The P_Key for the port, pkey tuple of the partition
			 * object. This P_Key should exist in the IB subnet.
			 * The partition creation for a non-existent P_Key will
			 * fail unless the -f option is used.
			 *
			 * The P_Key is expected to be a hexadecimal number.
			 */
			opt_pkey = strtoul(optarg, &endp, 16);
			if (errno == ERANGE || opt_pkey > USHRT_MAX ||
			    *endp != '\0')
				die("Invalid pkey");

			pkey = (ib_pkey_t)opt_pkey;
			break;
		case 'f':
			flags |= DLADM_OPT_FORCE;
			break;
		default:
			die_opterr(optopt, option, use);
			break;
		}
	}

	/* check required options */
	if (!l_arg)
		usage();

	/* the partition name is a required operand */
	if (optind != (argc - 1))
		usage();

	pname = argv[argc - 1];

	/*
	 * Verify that the partition object's name is in the valid link name
	 * format.
	 */
	if (!dladm_valid_linkname(pname))
		die("Invalid link name '%s'", pname);

	/* pkey is a mandatory argument */
	if (pkey == 0)
		usage();

	if (altroot != NULL)
		altroot_cmd(altroot, argc, argv);

	/*
	 * Get the data link id of the IB Phys link over which we will be
	 * creating partition object.
	 */
	if (dladm_name2info(handle, l_arg,
	    &physlinkid, NULL, NULL, NULL) != DLADM_STATUS_OK)
		die("invalid link name '%s'", l_arg);

	/*
	 * parse the property list provided with -p option.
	 */
	if (dladm_parse_link_props(propstr, &proplist, B_FALSE)
	    != DLADM_STATUS_OK)
		die("invalid IB partition property");

	/*
	 * Call the library routine to create the partition object.
	 */
	status = dladm_part_create(handle, physlinkid, pkey, flags, pname,
	    &partlinkid, proplist);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status,
		    "partition %x creation over %s failed", pkey, l_arg);
}

/*
 * Delete an IP over Infiniband partition object. The partition object should
 * be unplumbed before attempting the delete.
 */
static void
do_delete_part(int argc, char *argv[], const char *use)
{
	int option, flags = DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST;
	int status;
	char *altroot = NULL;
	datalink_id_t	partid;

	opterr = 0;
	while ((option = getopt_long(argc, argv, "R:t", part_lopts,
	    NULL)) != -1) {
		switch (option) {
		case 't':
			flags &= ~DLADM_OPT_PERSIST;
			break;
		case 'R':
			altroot = optarg;
			break;
		default:
			die_opterr(optopt, option, use);
		}
	}

	/* get partition name (required last argument) */
	if (optind != (argc - 1))
		usage();

	if (altroot != NULL)
		altroot_cmd(altroot, argc, argv);

	/*
	 * Get the data link id of the partition object given the partition
	 * name.
	 */
	status = dladm_name2info(handle, argv[optind], &partid, NULL, NULL,
	    NULL);
	if (status != DLADM_STATUS_OK)
		die("invalid link name '%s'", argv[optind]);

	/*
	 * Call the library routine to delete the IB partition. This will
	 * result in the IB partition object and all its resources getting
	 * deleted.
	 */
	status = dladm_part_delete(handle, partid, flags);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "%s: partition deletion failed",
		    argv[optind]);
}

/*
 * Bring up all or one IB partition already present in the persistent database
 * but not active yet.
 *
 * This sub-command is used during the system boot up to bring up all IB
 * partitions present in the persistent database. This is similar to a
 * create partition except that, the partitions are always created even if the
 * HCA port is down or P_Key is not present in the IB subnet. This is similar
 * to using the 'force' option while creating the partition except that the 'f'
 * flag will be set in the flags field only if the create-part for this command
 * was called with '-f' option.
 */
/* ARGSUSED */
static void
do_up_part(int argc, char *argv[], const char *use)
{
	datalink_id_t	partid = DATALINK_ALL_LINKID;
	dladm_status_t status;

	/*
	 * If a partition name was passed as an argument, get its data link
	 * id. By default we'll attempt to bring up all IB partition data
	 * links.
	 */
	if (argc == 2) {
		status = dladm_name2info(handle, argv[argc - 1], &partid, NULL,
		    NULL, NULL);
		if (status != DLADM_STATUS_OK)
			return;
	} else if (argc > 2) {
		usage();
	}

	(void) dladm_part_up(handle, partid, 0);
}

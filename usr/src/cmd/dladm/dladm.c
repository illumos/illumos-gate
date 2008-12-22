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
#include <libdladm.h>
#include <libdllink.h>
#include <libdlstat.h>
#include <libdlaggr.h>
#include <libdlwlan.h>
#include <libdlvlan.h>
#include <libdlvnic.h>
#include <libdlether.h>
#include <libinetutil.h>
#include <bsm/adt.h>
#include <bsm/adt_event.h>
#include <libdlvnic.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/processor.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if_types.h>
#include <stddef.h>

#define	STR_UNDEF_VAL		"--"
#define	MAXPORT			256
#define	MAXVNIC			256
#define	BUFLEN(lim, ptr)	(((lim) > (ptr)) ? ((lim) - (ptr)) : 0)
#define	MAXLINELEN		1024
#define	SMF_UPGRADE_FILE		"/var/svc/profile/upgrade"
#define	SMF_UPGRADEDATALINK_FILE	"/var/svc/profile/upgrade_datalink"
#define	SMF_DLADM_UPGRADE_MSG		" # added by dladm(1M)"

#define	CMD_TYPE_ANY		0xffffffff
#define	WIFI_CMD_SCAN		0x00000001
#define	WIFI_CMD_SHOW		0x00000002
#define	WIFI_CMD_ALL		(WIFI_CMD_SCAN | WIFI_CMD_SHOW)

/*
 * Data structures and routines for printing output.
 * All non-parseable output is assumed to be in a columnar format.
 * Multiple fields in parsable output are separated by ':'; single
 * field output is printed as-is.
 *
 * Each sub-command is associated with a global array of pointers,
 * print_field_t *fields[], where the print_field_t contains information
 * about the format in which the output is to be printed.
 *
 * Sub-commands may be implemented in one of two ways:
 * (i)  the implementation could get all field values into a character
 *      buffer, with pf_offset containing the offset (for pf_name) within
 *      the buffer. The sub-command would make the needed system calls
 *      to obtain all possible column values and then invoke the
 *      dladm_print_field() function to print the specific fields
 *      requested in the command line. See the comments for dladm_print_field
 *      for further details.
 * (ii) Alternatively, each fields[i] entry could store a pf_index value
 *      that uniquely identifies the column to be printed. The implementation
 *      of the sub-command would then invoke dladm_print_output() with a
 *      callback function whose semantics are described below (see comments
 *      for dladm_print_output())
 *
 * Thus, an implementation of a sub-command must provide the following:
 *
 * static print_field_t sub_command_fields[] = {
 *	{<name>, <header>,<field width>,  <offset_or_index>, cmdtype},
 *	:
 *	{<name>, <header>,<field width>,  <offset_or_index>, cmdtype}
 * };
 *
 * #define	SUB_COMMAND_MAX_FIELDS sizeof \
 *		(sub_comand_fields) / sizeof (print_field_t))
 *
 * print_state_t sub_command_print_state;
 *
 * The function that parses command line arguments (typically
 * do_sub_command()) should then contain an invocation like:
 *
 *	fields = parse_output_fields(fields_str, sub_command_fields,
 *	    SUB_COMMAND_MAX_FIELDS, CMD_TYPE_ANY, &nfields);
 *
 * and store the resulting fields and nfields value in a print_state_t
 * structure tracked for the command.
 *
 *	sub_command_print_state.ps_fields = fields;
 *	sub_command_print_state.ps_nfields = nfields;
 *
 * To print the column header for the output, the print_header()
 * function must then be invoked by do_sub_command().
 *
 * Then if method (i) is used for the sub_command, the do_sub_command()
 * function should make the necessary system calls to fill up the buffer
 * and then invoke dladm_print_field(). An example of this method is
 * the implementation of do_show_link() and show_link();
 *
 * If method (ii) is used, do_sub_command should invoke dladm_print_output()
 * with a callback function that will be called for each field to be printed.
 * The callback function will be passed a pointer to the print_field_t
 * for the field, and the pf_index may then be used to identify the
 * system call required to find the value to be printed.
 */

typedef struct print_field_s {
	const char	*pf_name;	/* name of column to be printed */
	const char	*pf_header;	/* header for this column */
	uint_t		pf_width;
	union {
		uint_t	_pf_index;	/* private index for sub-command */
		size_t	_pf_offset;
	}_pf_un;
#define	pf_index	_pf_un._pf_index
#define	pf_offset	_pf_un._pf_offset;
	uint_t		pf_cmdtype;
} print_field_t;

/*
 * The state of the output is tracked in a print_state_t structure.
 * Each ps_fields[i] entry points at the global print_field_t array for
 * the sub-command, where ps_nfields is the number of requested fields.
 */
typedef struct print_state_s {
	print_field_t	**ps_fields;
	uint_t		ps_nfields;
	boolean_t	ps_lastfield;
	uint_t		ps_overflow;
} print_state_t;

typedef char *(*print_callback_t)(print_field_t *, void *);
static print_field_t **parse_output_fields(char *, print_field_t *, int,
    uint_t, uint_t *);
/*
 * print the header for the output
 */
static void print_header(print_state_t *);
static void print_field(print_state_t *, print_field_t *, const char *,
    boolean_t);

/*
 * to print output values, call dladm_print_output with a callback
 * function (*func)() that should parse the args and return an
 * unformatted character buffer with the value to be printed.
 *
 * dladm_print_output() prints the character buffer using the formatting
 * information provided in the print_field_t for that column.
 */
static void dladm_print_output(print_state_t *, boolean_t,
    print_callback_t, void *);

/*
 * helper function that, when invoked as dladm_print_field(pf, buf)
 * prints string which is offset by pf->pf_offset  within buf
 */
static char *dladm_print_field(print_field_t *, void *);


#define	MAX_FIELD_LEN	32


typedef struct show_state {
	boolean_t	ls_firstonly;
	boolean_t	ls_donefirst;
	pktsum_t	ls_prevstats;
	uint32_t	ls_flags;
	dladm_status_t	ls_status;
	print_state_t	ls_print;
	boolean_t	ls_parseable;
	boolean_t	ls_printheader;
	boolean_t	ls_mac;
	boolean_t	ls_hwgrp;
} show_state_t;

typedef struct show_grp_state {
	pktsum_t	gs_prevstats[MAXPORT];
	uint32_t	gs_flags;
	dladm_status_t	gs_status;
	boolean_t	gs_parseable;
	boolean_t	gs_lacp;
	boolean_t	gs_extended;
	boolean_t	gs_stats;
	boolean_t	gs_firstonly;
	boolean_t	gs_donefirst;
	boolean_t	gs_printheader;
	print_state_t	gs_print;
} show_grp_state_t;

typedef struct show_vnic_state {
	datalink_id_t	vs_vnic_id;
	datalink_id_t	vs_link_id;
	char		vs_vnic[MAXLINKNAMELEN];
	char		vs_link[MAXLINKNAMELEN];
	boolean_t	vs_parseable;
	boolean_t	vs_printheader;
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
	print_state_t	vs_print;
} show_vnic_state_t;

typedef struct show_usage_state_s {
	boolean_t	us_plot;
	boolean_t	us_parseable;
	boolean_t	us_printheader;
	boolean_t	us_first;
	print_state_t	us_print;
} show_usage_state_t;

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
static cmdfunc_t do_create_etherstub, do_delete_etherstub, do_show_etherstub;
static cmdfunc_t do_show_usage;

static void 	do_up_vnic_common(int, char **, const char *, boolean_t);

static void	altroot_cmd(char *, int, char **);
static int	show_linkprop_onelink(datalink_id_t, void *);

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

static int	show_etherprop(datalink_id_t, void *);
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
	{ "show-link",		do_show_link,
	    "\tshow-link\t[-pP] [-o <field>,..] [-s [-i <interval>]] [<link>]"},
	{ "rename-link",	do_rename_link,
	    "\trename-link\t[-R <root-dir>] <oldlink> <newlink>\n"	},
	{ "create-aggr",	do_create_aggr,
	    "\tcreate-aggr\t[-t] [-R <root-dir>] [-P <policy>] [-L <mode>]\n"
	    "\t\t\t[-T <time>] [-u <address>] [-l <link>] ... <link>"	},
	{ "delete-aggr",	do_delete_aggr,
	    "\tdelete-aggr\t[-t] [-R <root-dir>] <link>"		},
	{ "add-aggr",		do_add_aggr,
	    "\tadd-aggr\t[-t] [-R <root-dir>] [-l <link>] ... <link>"	},
	{ "remove-aggr",	do_remove_aggr,
	    "\tremove-aggr\t[-t] [-R <root-dir>] [-l <link>] ... <link>"},
	{ "modify-aggr",	do_modify_aggr,
	    "\tmodify-aggr\t[-t] [-R <root-dir>] [-P <policy>] [-L <mode>]\n"
	    "\t\t\t[-T <time>] [-u <address>] <link>"			},
	{ "show-aggr",		do_show_aggr,
	    "\tshow-aggr\t[-pPLx] [-o <field>,..] [-s [-i <interval>]] "
	    "[<link>]\n"						},
	{ "up-aggr",		do_up_aggr,		NULL		},
	{ "scan-wifi",		do_scan_wifi,
	    "\tscan-wifi\t[-p] [-o <field>,...] [<link>]"		},
	{ "connect-wifi",	do_connect_wifi,
	    "\tconnect-wifi\t[-e <essid>] [-i <bssid>] [-k <key>,...] "
	    "[-s wep|wpa]\n"
	    "\t\t\t[-a open|shared] [-b bss|ibss] [-c] [-m a|b|g]\n"
	    "\t\t\t[-T <time>] [<link>]"				},
	{ "disconnect-wifi",	do_disconnect_wifi,
	    "\tdisconnect-wifi\t[-a] [<link>]"				},
	{ "show-wifi",		do_show_wifi,
	    "\tshow-wifi\t[-p] [-o <field>,...] [<link>]\n"		},
	{ "show-linkprop",	do_show_linkprop,
	    "\tshow-linkprop\t[-cP] [-o <field>,...] [-p <prop>,...] <name>"},
	{ "set-linkprop",	do_set_linkprop,
	    "\tset-linkprop\t[-t] [-R <root-dir>] -p <prop>=<value>[,...] "
	    "<name>"							},
	{ "reset-linkprop",	do_reset_linkprop,
	    "\treset-linkprop\t[-t] [-R <root-dir>] [-p <prop>,...] <name>\n" },
	{ "show-ether",		do_show_ether,
	    "\tshow-ether\t[-px][-o <field>,...] <link>\n"		},
	{ "create-secobj",	do_create_secobj,
	    "\tcreate-secobj\t[-t] [-R <root-dir>] [-f <file>] -c <class> "
	    "<secobj>"							},
	{ "delete-secobj",	do_delete_secobj,
	    "\tdelete-secobj\t[-t] [-R <root-dir>] <secobj>[,...]"	},
	{ "show-secobj",	do_show_secobj,
	    "\tshow-secobj\t[-pP] [-o <field>,...] [<secobj>,...]\n"	},
	{ "init-linkprop",	do_init_linkprop,	NULL		},
	{ "init-secobj",	do_init_secobj,		NULL		},
	{ "create-vlan", 	do_create_vlan,
	    "\tcreate-vlan\t[-ft] [-R <root-dir>] -l <link> -v <vid> [link]" },
	{ "delete-vlan", 	do_delete_vlan,
	    "\tdelete-vlan\t[-t] [-R <root-dir>] <link>"		},
	{ "show-vlan",		do_show_vlan,
	    "\tshow-vlan\t[-pP] [-o <field>,..] [<link>]\n"		},
	{ "up-vlan",		do_up_vlan,		NULL		},
	{ "delete-phys",	do_delete_phys,
	    "\tdelete-phys\t<link>"					},
	{ "show-phys",		do_show_phys,
	    "\tshow-phys\t[-pP] [-o <field>,..] [-H] [<link>]"		},
	{ "init-phys",		do_init_phys,		NULL		},
	{ "show-linkmap",	do_show_linkmap,	NULL		},
	{ "create-vnic",	do_create_vnic,
	    "\tcreate-vnic     [-t] [-R <root-dir>] -l <link> [-m <value> |"
	    " auto |\n"
	    "\t                {factory [-n <slot-identifier>]} |\n"
	    "\t                {random [-r <prefix>]}] [-v vlan-tag [-f]]\n"
	    "\t                -p <prop>=<value>[,...] [-H]"
	    " <vnic-link>\n"	},
	{ "delete-vnic",	do_delete_vnic,
	    "\tdelete-vnic     [-t] [-R <root-dir>] <vnic-link>\n" 	},
	{ "show-vnic",		do_show_vnic,
	    "\tshow-vnic       [-pP] [-l <link>] [-s [-i <interval>]]"	},
	{ "up-vnic",		do_up_vnic,		NULL		},
	{ "create-etherstub",	do_create_etherstub,
	    "\tcreate-etherstub [-t] [-R <root-dir>] <link>\n"		},
	{ "delete-etherstub",	do_delete_etherstub,
	    "\tdelete-etherstub [-t] [-R <root-dir>] <link>\n"		},
	{ "show-etherstub",	do_show_etherstub,
	    "\tshow-etherstub  [-t] [-R <root-dir>] [<link>]\n" 	},
	{ "show-usage",		do_show_usage,
	    "\tshow-usage      [-d|-p -F <format>] [-f <filename>]\n"
	    "\t                [-s <time>] [-e <time>] <link>\n"	}
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
	{"parseable",	no_argument,		0, 'p'},
	{"extended",	no_argument,		0, 'x'},
	{"output",	required_argument,	0, 'o'},
	{"persistent",	no_argument,		0, 'P'},
	{"lacp",	no_argument,		0, 'L'},
	{ 0, 0, 0, 0 }
};

static const struct option prop_longopts[] = {
	{"temporary",	no_argument,		0, 't'  },
	{"output",	required_argument,	0, 'o'  },
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
static const struct option showeth_lopts[] = {
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
	{ 0, 0, 0, 0 }
};

static const struct option etherstub_lopts[] = {
	{"temporary",	no_argument,		0, 't'	},
	{"root-dir",	required_argument,	0, 'R'	},
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

static print_field_t ether_fields[] = {
/* name,	header,			field width,  offset,	cmdtype */
{ "link",	"LINK",			15,
    offsetof(ether_fields_buf_t, eth_link),	CMD_TYPE_ANY},
{ "ptype",	"PTYPE",		8,
    offsetof(ether_fields_buf_t, eth_ptype),	CMD_TYPE_ANY},
{ "state",	"STATE",		8,
    offsetof(ether_fields_buf_t, eth_state),	CMD_TYPE_ANY},
{ "auto",	"AUTO",			5,
    offsetof(ether_fields_buf_t, eth_autoneg),	CMD_TYPE_ANY},
{ "speed-duplex", "SPEED-DUPLEX",	31,
    offsetof(ether_fields_buf_t, eth_spdx),	CMD_TYPE_ANY},
{ "pause",	"PAUSE",		6,
    offsetof(ether_fields_buf_t, eth_pause),	CMD_TYPE_ANY},
{ "rem_fault",	"REM_FAULT",		16,
    offsetof(ether_fields_buf_t, eth_rem_fault),	CMD_TYPE_ANY}}
;
#define	ETHER_MAX_FIELDS	(sizeof (ether_fields) / sizeof (print_field_t))

typedef struct print_ether_state {
	const char	*es_link;
	boolean_t	es_parseable;
	boolean_t	es_header;
	boolean_t	es_extended;
	print_state_t	es_print;
} print_ether_state_t;

/*
 * structures for 'dladm show-link -s' (print statistics)
 */
typedef enum {
	DEVS_LINK,
	DEVS_IPKTS,
	DEVS_RBYTES,
	DEVS_IERRORS,
	DEVS_OPKTS,
	DEVS_OBYTES,
	DEVS_OERRORS
} devs_field_index_t;

static print_field_t devs_fields[] = {
/* name,	header,		field width,	index,		cmdtype	*/
{ "link",	"LINK",			15,	DEVS_LINK,	CMD_TYPE_ANY},
{ "ipackets",	"IPACKETS",		10,	DEVS_IPKTS,	CMD_TYPE_ANY},
{ "rbytes",	"RBYTES",		8,	DEVS_RBYTES,	CMD_TYPE_ANY},
{ "ierrors",	"IERRORS",		10,	DEVS_IERRORS,	CMD_TYPE_ANY},
{ "opackets",	"OPACKETS",		12,	DEVS_OPKTS,	CMD_TYPE_ANY},
{ "obytes",	"OBYTES",		12,	DEVS_OBYTES,	CMD_TYPE_ANY},
{ "oerrors",	"OERRORS",		8,	DEVS_OERRORS,	CMD_TYPE_ANY}}
;
#define	DEVS_MAX_FIELDS	(sizeof (devs_fields) / sizeof (print_field_t))

/*
 * buffer used by print functions for show-{link,phys,vlan} commands.
 */
typedef struct link_fields_buf_s {
	char link_name[MAXLINKNAMELEN];
	char link_class[DLADM_STRSIZE];
	char link_mtu[11];
	char link_state[DLADM_STRSIZE];
	char link_over[MAXLINKNAMELEN];
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
static print_field_t link_fields[] = {
/* name,	header,		field width,	offset,	cmdtype		*/
{ "link",	"LINK",		11,
    offsetof(link_fields_buf_t, link_name),	CMD_TYPE_ANY},
{ "class",	"CLASS",	 8,
    offsetof(link_fields_buf_t, link_class),	CMD_TYPE_ANY},
{ "mtu",	"MTU",		 6,
    offsetof(link_fields_buf_t, link_mtu),	CMD_TYPE_ANY},
{ "state",	"STATE",	 8,
    offsetof(link_fields_buf_t, link_state),	CMD_TYPE_ANY},
{ "over",	"OVER",		DLPI_LINKNAME_MAX,
    offsetof(link_fields_buf_t, link_over),	CMD_TYPE_ANY}}
;
#define	DEV_LINK_FIELDS	(sizeof (link_fields) / sizeof (print_field_t))

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
	pktsum_t		*laggr_prevstats; /* -s only */
	boolean_t		laggr_parseable;
} laggr_args_t;

static print_field_t laggr_fields[] = {
/* name,		header,		field width,	offset,	cmdtype	*/
{ "link",		"LINK",		15,
    offsetof(laggr_fields_buf_t, laggr_name),		CMD_TYPE_ANY},
{ "policy",		"POLICY",	 8,
    offsetof(laggr_fields_buf_t, laggr_policy),	CMD_TYPE_ANY},
{ "addrpolicy",		"ADDRPOLICY",	 ETHERADDRL * 3 + 2,
    offsetof(laggr_fields_buf_t, laggr_addrpolicy),	CMD_TYPE_ANY},
{ "lacpactivity",	"LACPACTIVITY",	 13,
    offsetof(laggr_fields_buf_t, laggr_lacpactivity),	CMD_TYPE_ANY},
{ "lacptimer",		"LACPTIMER",	 11,
    offsetof(laggr_fields_buf_t, laggr_lacptimer),	CMD_TYPE_ANY},
{ "flags",		"FLAGS",	 7,
    offsetof(laggr_fields_buf_t, laggr_flags),	CMD_TYPE_ANY}}
;
#define	LAGGR_MAX_FIELDS	(sizeof (laggr_fields) / sizeof (print_field_t))

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

static print_field_t aggr_x_fields[] = {
/* name,	header,		field width,	index,		cmdtype	*/
{ "link",	"LINK",			11,	AGGR_X_LINK,	CMD_TYPE_ANY},
{ "port",	"PORT",			14,	AGGR_X_PORT,	CMD_TYPE_ANY},
{ "speed",	"SPEED",		4,	AGGR_X_SPEED,	CMD_TYPE_ANY},
{ "duplex",	"DUPLEX",		9,	AGGR_X_DUPLEX,	CMD_TYPE_ANY},
{ "state",	"STATE",		9,	AGGR_X_STATE,	CMD_TYPE_ANY},
{ "address",	"ADDRESS",		18,	AGGR_X_ADDRESS,	CMD_TYPE_ANY},
{ "portstate",	"PORTSTATE",		15,	AGGR_X_PORTSTATE, CMD_TYPE_ANY}}
;
#define	AGGR_X_MAX_FIELDS \
	(sizeof (aggr_x_fields) / sizeof (print_field_t))

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

static print_field_t aggr_s_fields[] = {
/* name,		header,		field width,	index,	cmdtype	*/
{ "link",		"LINK",		11,	AGGR_S_LINK,
    CMD_TYPE_ANY},
{ "port",		"PORT",		9,	AGGR_S_PORT,
    CMD_TYPE_ANY},
{ "ipackets",		"IPACKETS",	7,	AGGR_S_IPKTS,
    CMD_TYPE_ANY},
{ "rbytes",		"RBYTES",	7,	AGGR_S_RBYTES,
    CMD_TYPE_ANY},
{ "opackets",		"OPACKETS",	7,	AGGR_S_OPKTS,
    CMD_TYPE_ANY},
{ "obytes",		"OBYTES",	7,	AGGR_S_OBYTES,
    CMD_TYPE_ANY},
{ "ipktdist",		"IPKTDIST",	8,	AGGR_S_IPKTDIST,
    CMD_TYPE_ANY},
{ "opktdist",		"OPKTDIST",	14,	AGGR_S_OPKTDIST,
    CMD_TYPE_ANY}}
;
#define	AGGR_S_MAX_FIELDS \
	(sizeof (aggr_s_fields) / sizeof (print_field_t))

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

static print_field_t aggr_l_fields[] = {
/* name,		header,		field width,	index,	cmdtype	*/
{ "link",		"LINK",		11,	AGGR_L_LINK,
    CMD_TYPE_ANY},
{ "port",		"PORT",		12,	AGGR_L_PORT,
    CMD_TYPE_ANY},
{ "aggregatable",	"AGGREGATABLE",	12,	AGGR_L_AGGREGATABLE,
    CMD_TYPE_ANY},
{ "sync",		"SYNC",		4,	AGGR_L_SYNC,
    CMD_TYPE_ANY},
{ "coll",		"COLL",		4,	AGGR_L_COLL,
    CMD_TYPE_ANY},
{ "dist",		"DIST",		4,	AGGR_L_DIST,
    CMD_TYPE_ANY},
{ "defaulted",		"DEFAULTED",	9,	AGGR_L_DEFAULTED,
    CMD_TYPE_ANY},
{ "expired",		"EXPIRED",	14,	AGGR_L_EXPIRED,
    CMD_TYPE_ANY}}
;
#define	AGGR_L_MAX_FIELDS \
	(sizeof (aggr_l_fields) / sizeof (print_field_t))

/*
 * structures for 'dladm show-phys'
 */

static print_field_t phys_fields[] = {
/* name,	header,		field width,	offset,	cmdtype		*/
{ "link",	"LINK",			12,
    offsetof(link_fields_buf_t, link_name),		CMD_TYPE_ANY},
{ "media",	"MEDIA",		20,
    offsetof(link_fields_buf_t, link_phys_media),	CMD_TYPE_ANY},
{ "state",	"STATE",		10,
    offsetof(link_fields_buf_t, link_phys_state),	CMD_TYPE_ANY},
{ "speed",	"SPEED",		6,
    offsetof(link_fields_buf_t, link_phys_speed),	CMD_TYPE_ANY},
{ "duplex",	"DUPLEX",		9,
    offsetof(link_fields_buf_t, link_phys_duplex),	CMD_TYPE_ANY},
{ "device",	"DEVICE",		12,
    offsetof(link_fields_buf_t, link_phys_device),	CMD_TYPE_ANY},
{ "flags",	"FLAGS",		6,
    offsetof(link_fields_buf_t, link_flags),		CMD_TYPE_ANY}}
;
#define	PHYS_MAX_FIELDS	(sizeof (phys_fields) / sizeof (print_field_t))

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

static print_field_t phys_m_fields[] = {
/* name,	header,		field width,	offset,	cmdtype		*/
{ "link",	"LINK",		12,	PHYS_M_LINK,	CMD_TYPE_ANY},
{ "slot",	"SLOT",		8,	PHYS_M_SLOT,	CMD_TYPE_ANY},
{ "address",	"ADDRESS",	18,	PHYS_M_ADDRESS,	CMD_TYPE_ANY},
{ "inuse",	"INUSE",	4,	PHYS_M_INUSE,	CMD_TYPE_ANY},
{ "client",	"CLIENT",	12,	PHYS_M_CLIENT,	CMD_TYPE_ANY}}
;
#define	PHYS_M_MAX_FIELDS (sizeof (phys_m_fields) / sizeof (print_field_t))

/*
 * structures for 'dladm show-phys -H'
 */

typedef enum {
	PHYS_H_LINK,
	PHYS_H_GROUP,
	PHYS_H_GRPTYPE,
	PHYS_H_RINGS,
	PHYS_H_CLIENTS
} phys_h_field_index_t;

static print_field_t phys_h_fields[] = {
/* name,	header,		field width,	offset,	cmdtype		*/
{ "link",	"LINK",		12,	PHYS_H_LINK,	CMD_TYPE_ANY},
{ "group",	"GROUP",	8,	PHYS_H_GROUP,	CMD_TYPE_ANY},
{ "grouptype",	"TYPE",		6,	PHYS_H_GRPTYPE,	CMD_TYPE_ANY},
{ "rings",	"NUM-RINGS",	16,	PHYS_H_RINGS,	CMD_TYPE_ANY},
{ "clients",	"CLIENTS",	20,	PHYS_H_CLIENTS,	CMD_TYPE_ANY}}
;
#define	PHYS_H_MAX_FIELDS (sizeof (phys_h_fields) / sizeof (print_field_t))

/*
 * structures for 'dladm show-vlan'
 */
static print_field_t vlan_fields[] = {
/* name,	header,		field width,	offset,	cmdtype		*/
{ "link",	"LINK",			15,
    offsetof(link_fields_buf_t, link_name),		CMD_TYPE_ANY},
{ "vid",	"VID",			8,
    offsetof(link_fields_buf_t, link_vlan_vid),	CMD_TYPE_ANY},
{ "over",	"OVER",			12,
    offsetof(link_fields_buf_t, link_over),		CMD_TYPE_ANY},
{ "flags",	"FLAGS",		6,
    offsetof(link_fields_buf_t, link_flags),		CMD_TYPE_ANY}}
;
#define	VLAN_MAX_FIELDS	(sizeof (vlan_fields) / sizeof (print_field_t))


/*
 * structures for 'dladm show-wifi'
 */
static print_field_t wifi_fields[] = {
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

#define	WIFI_MAX_FIELDS		(sizeof (wifi_fields) / sizeof (print_field_t))

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

static print_field_t linkprop_fields[] = {
/* name,	header,		field width,  index,		cmdtype */
{ "link",	"LINK",		12,	LINKPROP_LINK,		CMD_TYPE_ANY},
{ "property",	"PROPERTY",	15,	LINKPROP_PROPERTY,	CMD_TYPE_ANY},
{ "perm",	"PERM",		4,	LINKPROP_PERM,		CMD_TYPE_ANY},
{ "value",	"VALUE",	14,	LINKPROP_VALUE,		CMD_TYPE_ANY},
{ "default",	"DEFAULT",	14,	LINKPROP_DEFAULT, 	CMD_TYPE_ANY},
{ "possible",	"POSSIBLE",	20,	LINKPROP_POSSIBLE,	CMD_TYPE_ANY}}
;
#define	LINKPROP_MAX_FIELDS					\
	(sizeof (linkprop_fields) / sizeof (print_field_t))

#define	MAX_PROP_LINE		512

typedef struct show_linkprop_state {
	char			ls_link[MAXLINKNAMELEN];
	char			*ls_line;
	char			**ls_propvals;
	dladm_arg_list_t	*ls_proplist;
	boolean_t		ls_parseable;
	boolean_t		ls_persist;
	boolean_t		ls_header;
	dladm_status_t		ls_status;
	dladm_status_t		ls_retstatus;
	print_state_t		ls_print;
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
static print_field_t secobj_fields[] = {
/* name,	header,		field width,	offset,	cmdtype		*/
{ "object",	"OBJECT",		20,
    offsetof(secobj_fields_buf_t, ss_obj_name),	CMD_TYPE_ANY},
{ "class",	"CLASS",		20,
    offsetof(secobj_fields_buf_t, ss_class),	CMD_TYPE_ANY},
{ "value",	"VALUE",		30,
    offsetof(secobj_fields_buf_t, ss_val),	CMD_TYPE_ANY}}
;
#define	DEV_SOBJ_FIELDS	(sizeof (secobj_fields) / sizeof (print_field_t))

/*
 * structures for 'dladm show-vnic'
 */
typedef struct vnic_fields_buf_s
{
	char vnic_link[DLPI_LINKNAME_MAX];
	char vnic_over[DLPI_LINKNAME_MAX];
	char vnic_speed[6];
	char vnic_macaddr[19];
	char vnic_macaddrtype[19];
	char vnic_vid[6];
} vnic_fields_buf_t;

static print_field_t vnic_fields[] = {
/* name,		header,		field width,	offset,	cmdtype	*/
{ "link",		"LINK",		12,
    offsetof(vnic_fields_buf_t, vnic_link),		CMD_TYPE_ANY},
{ "over",		"OVER",		12,
    offsetof(vnic_fields_buf_t, vnic_over),		CMD_TYPE_ANY},
{ "speed",		"SPEED",	6,
    offsetof(vnic_fields_buf_t, vnic_speed),		CMD_TYPE_ANY},
{ "macaddr",		"MACADDRESS",	20,
    offsetof(vnic_fields_buf_t, vnic_macaddr),		CMD_TYPE_ANY},
{ "macaddrtype",	"MACADDRTYPE",	19,
    offsetof(vnic_fields_buf_t, vnic_macaddrtype),	CMD_TYPE_ANY},
{ "vid",		"VID",		6,
    offsetof(vnic_fields_buf_t, vnic_vid),		CMD_TYPE_ANY}}
;
#define	VNIC_MAX_FIELDS	(sizeof (vnic_fields) / sizeof (print_field_t))

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

static print_field_t usage_fields[] = {
/* name,	header,		field width,	offset,	cmdtype		*/
{ "link",	"LINK",			12,
    offsetof(usage_fields_buf_t, usage_link),		CMD_TYPE_ANY},
{ "duration",	"DURATION",		10,
    offsetof(usage_fields_buf_t, usage_duration),	CMD_TYPE_ANY},
{ "ipackets",	"IPACKETS",		9,
    offsetof(usage_fields_buf_t, usage_ipackets),	CMD_TYPE_ANY},
{ "rbytes",	"RBYTES",		10,
    offsetof(usage_fields_buf_t, usage_rbytes),		CMD_TYPE_ANY},
{ "opackets",	"OPACKETS",		9,
    offsetof(usage_fields_buf_t, usage_opackets),	CMD_TYPE_ANY},
{ "obytes",	"OBYTES",		10,
    offsetof(usage_fields_buf_t, usage_obytes),		CMD_TYPE_ANY},
{ "bandwidth",	"BANDWIDTH",		14,
    offsetof(usage_fields_buf_t, usage_bandwidth),	CMD_TYPE_ANY}}
;

#define	USAGE_MAX_FIELDS	(sizeof (usage_fields) / sizeof (print_field_t))

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

static print_field_t usage_l_fields[] = {
/* name,	header,		field width,	offset,	cmdtype		*/
{ "link",	"LINK",		12,
    offsetof(usage_l_fields_buf_t, usage_l_link),	CMD_TYPE_ANY},
{ "start",	"START",	13,
    offsetof(usage_l_fields_buf_t, usage_l_stime),	CMD_TYPE_ANY},
{ "end",	"END",		13,
    offsetof(usage_l_fields_buf_t, usage_l_etime),	CMD_TYPE_ANY},
{ "rbytes",	"RBYTES",	8,
    offsetof(usage_l_fields_buf_t, usage_l_rbytes),	CMD_TYPE_ANY},
{ "obytes",	"OBYTES",	8,
    offsetof(usage_l_fields_buf_t, usage_l_obytes),	CMD_TYPE_ANY},
{ "bandwidth",	"BANDWIDTH",	14,
    offsetof(usage_l_fields_buf_t, usage_l_bandwidth),	CMD_TYPE_ANY}}
;

#define	USAGE_L_MAX_FIELDS \
	(sizeof (usage_l_fields) /sizeof (print_field_t))

static char *progname;
static sig_atomic_t signalled;

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

	for (i = 0; i < sizeof (cmds) / sizeof (cmds[0]); i++) {
		cmdp = &cmds[i];
		if (strcmp(argv[1], cmdp->c_name) == 0) {
			cmdp->c_fn(argc - 1, &argv[1], cmdp->c_usage);
			exit(0);
		}
	}

	(void) fprintf(stderr, gettext("%s: unknown subcommand '%s'\n"),
	    progname, argv[1]);
	usage();

	return (0);
}

/*ARGSUSED*/
static int
show_usage_date(dladm_usage_t *usage, void *arg)
{

	time_t	stime;
	char	timebuf[20];

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

	if (!state->us_parseable && !state->us_printheader) {
		print_header(&state->us_print);
		state->us_printheader = B_TRUE;
	}

	dladm_print_output(&state->us_print, state->us_parseable,
	    dladm_print_field, (void *)&ubuf);

	return (DLADM_STATUS_OK);
}

static int
show_usage_res(dladm_usage_t *usage, void *arg)
{
	show_usage_state_t	*state = (show_usage_state_t *)arg;
	char			buf[DLADM_STRSIZE];
	usage_fields_buf_t	ubuf;

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

	if (!state->us_parseable && !state->us_printheader) {
		print_header(&state->us_print);
		state->us_printheader = B_TRUE;
	}

	dladm_print_output(&state->us_print, state->us_parseable,
	    dladm_print_field, (void *)&ubuf);

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
	boolean_t		p_arg = B_FALSE;
	char			*stime = NULL;
	char			*etime = NULL;
	char			*resource = NULL;
	show_usage_state_t	state;
	boolean_t		o_arg = B_FALSE;
	boolean_t		F_arg = B_FALSE;
	char			*fields_str = NULL;
	char			*formatspec_str = NULL;
	print_field_t		**fields;
	uint_t			nfields;
	char			*all_fields =
	    "link,duration,ipackets,rbytes,opackets,obytes,bandwidth";
	char			*all_l_fields =
	    "link,start,end,rbytes,obytes,bandwidth";

	bzero(&state, sizeof (show_usage_state_t));
	state.us_parseable = B_FALSE;
	state.us_printheader = B_FALSE;
	state.us_plot = B_FALSE;
	state.us_first = B_TRUE;

	while ((opt = getopt(argc, argv, "dps:e:o:f:F:")) != -1) {
		switch (opt) {
		case 'd':
			d_arg = B_TRUE;
			break;
		case 'p':
			state.us_plot = p_arg = B_TRUE;
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
			F_arg = B_TRUE;
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
		resource = argv[optind];
	}

	if (resource == NULL && stime == NULL && etime == NULL) {
		if (!o_arg || (o_arg && strcasecmp(fields_str, "all") == 0))
			fields_str = all_fields;
		fields = parse_output_fields(fields_str, usage_fields,
		    USAGE_MAX_FIELDS, CMD_TYPE_ANY, &nfields);
	} else {
		if (!o_arg || (o_arg && strcasecmp(fields_str, "all") == 0))
			fields_str = all_l_fields;
		fields = parse_output_fields(fields_str, usage_l_fields,
		    USAGE_L_MAX_FIELDS, CMD_TYPE_ANY, &nfields);
	}

	if (fields == NULL) {
		die("invalid fields(s) specified");
		return;
	}
	state.us_print.ps_fields = fields;
	state.us_print.ps_nfields = nfields;

	if (p_arg && d_arg)
		die("plot and date options are incompatible");

	if (p_arg && !F_arg)
		die("specify format speicifier: -F <format>");

	if (F_arg && valid_formatspec(formatspec_str) == B_FALSE)
		die("Format specifier %s not supported", formatspec_str);

	if (d_arg) {
		/* Print log dates */
		status = dladm_usage_dates(show_usage_date,
		    DLADM_LOGTYPE_LINK, file, resource, &state);
	} else if (resource == NULL && stime == NULL && etime == NULL &&
	    !p_arg) {
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
}

static void
do_create_aggr(int argc, char *argv[], const char *use)
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
	dladm_status_t		pstatus;
	dladm_arg_list_t	*proplist = NULL;
	int			i;
	datalink_id_t		linkid;

	ndev = nlink = opterr = 0;
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
			if (dladm_parse_link_props(optarg, &proplist, B_FALSE)
			    != DLADM_STATUS_OK)
				die("invalid aggregation property");
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
	if (status != DLADM_STATUS_OK)
		goto done;

	if (proplist == NULL)
		return;

	status = dladm_name2info(name, &linkid, NULL, NULL, NULL);
	if (status != DLADM_STATUS_OK)
		goto done;

	for (i = 0; i < proplist->al_count; i++) {
		dladm_arg_info_t	*aip = &proplist->al_info[i];

		pstatus = dladm_set_linkprop(linkid, aip->ai_name,
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
do_delete_aggr(int argc, char *argv[], const char *use)
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

	status = dladm_aggr_delete(linkid, flags);
done:
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "delete operation failed");
}

static void
do_add_aggr(int argc, char *argv[], const char *use)
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
do_remove_aggr(int argc, char *argv[], const char *use)
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
do_modify_aggr(int argc, char *argv[], const char *use)
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

	status = dladm_aggr_modify(linkid, modify_mask, policy, mac_addr_fixed,
	    (const uchar_t *)mac_addr, lacp_mode, lacp_timer, flags);

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
do_create_vlan(int argc, char *argv[], const char *use)
{
	char			*link = NULL;
	char			drv[DLPI_LINKNAME_MAX];
	uint_t			ppa;
	datalink_id_t		linkid;
	datalink_id_t		dev_linkid;
	int			vid = 0;
	char			option;
	uint32_t		flags = (DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST);
	char			*altroot = NULL;
	char			vlan[MAXLINKNAMELEN];
	dladm_arg_list_t	*proplist = NULL;
	dladm_status_t		status;

	opterr = 0;
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
			if (dladm_parse_link_props(optarg, &proplist, B_FALSE)
			    != DLADM_STATUS_OK) {
				die("invalid vlan property");
			}
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

	if (dladm_name2info(link, &dev_linkid, NULL, NULL, NULL) !=
	    DLADM_STATUS_OK) {
		die("invalid link name '%s'", link);
	}

	if ((status = dladm_vlan_create(vlan, dev_linkid, vid, proplist, flags,
	    &linkid)) != DLADM_STATUS_OK) {
		die_dlerr(status, "create operation over %s failed", link);
	}
}

static void
do_delete_vlan(int argc, char *argv[], const char *use)
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
			die_opterr(optopt, option, use);
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

/*ARGSUSED*/
static void
do_up_vlan(int argc, char *argv[], const char *use)
{
	do_up_vnic_common(argc, argv, use, B_TRUE);
}

static void
do_rename_link(int argc, char *argv[], const char *use)
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
	if ((status = dladm_rename_link(link1, link2)) != DLADM_STATUS_OK)
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
do_show_linkmap(int argc, char *argv[], const char *use)
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
do_init_phys(int argc, char *argv[], const char *use)
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


/*
 * Print the active topology information.
 */
static dladm_status_t
print_link_topology(show_state_t *state, datalink_id_t linkid,
    datalink_class_t class, link_fields_buf_t *lbuf)
{
	uint32_t	flags = state->ls_flags;
	dladm_status_t	status = DLADM_STATUS_OK;
	char		tmpbuf[MAXLINKNAMELEN];

	if (!state->ls_parseable)
		(void) sprintf(lbuf->link_over, STR_UNDEF_VAL);
	else
		(void) sprintf(lbuf->link_over, "");

	if (class == DATALINK_CLASS_VLAN) {
		dladm_vlan_attr_t	vinfo;

		status = dladm_vlan_info(linkid, &vinfo, flags);
		if (status != DLADM_STATUS_OK)
			goto done;
		status = dladm_datalink_id2info(vinfo.dv_linkid, NULL, NULL,
		    NULL, lbuf->link_over, sizeof (lbuf->link_over));
		if (status != DLADM_STATUS_OK)
			goto done;
	} else if (class == DATALINK_CLASS_AGGR) {
		dladm_aggr_grp_attr_t	ginfo;
		int			i;

		(void) sprintf(lbuf->link_over, "");

		status = dladm_aggr_info(linkid, &ginfo, flags);
		if (status != DLADM_STATUS_OK)
			goto done;

		if (ginfo.lg_nports == 0) {
			status = DLADM_STATUS_BADVAL;
			goto done;
		}
		for (i = 0; i < ginfo.lg_nports; i++) {
			status = dladm_datalink_id2info(
			    ginfo.lg_ports[i].lp_linkid, NULL, NULL, NULL,
			    tmpbuf, sizeof (tmpbuf));
			if (status != DLADM_STATUS_OK) {
				free(ginfo.lg_ports);
				goto done;
			}
			(void) strlcat(lbuf->link_over, tmpbuf,
			    sizeof (lbuf->link_over));
			if (i != (ginfo.lg_nports - 1)) {
				(void) strlcat(lbuf->link_over, " ",
				    sizeof (lbuf->link_over));
			}
		}
		free(ginfo.lg_ports);
	} else if (class == DATALINK_CLASS_VNIC) {
		dladm_vnic_attr_t	vinfo;

		if ((status = dladm_vnic_info(linkid, &vinfo, flags)) !=
		    DLADM_STATUS_OK || (status = dladm_datalink_id2info(
		    vinfo.va_link_id, NULL, NULL, NULL, lbuf->link_over,
		    sizeof (lbuf->link_over)) != DLADM_STATUS_OK)) {
			goto done;
		}
	}
done:
	return (status);
}

static dladm_status_t
print_link(show_state_t *state, datalink_id_t linkid, link_fields_buf_t *lbuf)
{
	char			link[MAXLINKNAMELEN];
	datalink_class_t	class;
	uint_t			mtu;
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

	(void) snprintf(lbuf->link_name, sizeof (lbuf->link_name),
	    "%s", link);
	(void) dladm_class2str(class, lbuf->link_class);
	if (state->ls_flags == DLADM_OPT_ACTIVE) {
		(void) snprintf(lbuf->link_mtu, sizeof (lbuf->link_mtu),
		    "%u", mtu);
		(void) get_linkstate(link, B_TRUE, lbuf->link_state);
	}

	status = print_link_topology(state, linkid, class, lbuf);
	if (status != DLADM_STATUS_OK)
		goto done;

done:
	return (status);
}

static int
show_link(datalink_id_t linkid, void *arg)
{
	show_state_t		*state = (show_state_t *)arg;
	dladm_status_t		status;
	link_fields_buf_t	lbuf;

	/*
	 * first get all the link attributes into lbuf;
	 */
	bzero(&lbuf, sizeof (link_fields_buf_t));
	status = print_link(state, linkid, &lbuf);

	if (status != DLADM_STATUS_OK)
		goto done;

	if (!state->ls_parseable && !state->ls_printheader) {
		print_header(&state->ls_print);
		state->ls_printheader = B_TRUE;
	}

	dladm_print_output(&state->ls_print, state->ls_parseable,
	    dladm_print_field, (void *)&lbuf);

done:
	state->ls_status = status;
	return (DLADM_WALK_CONTINUE);
}

static int
show_link_stats(datalink_id_t linkid, void *arg)
{
	char			link[DLPI_LINKNAME_MAX];
	datalink_class_t	class;
	show_state_t		*state = (show_state_t *)arg;
	pktsum_t		stats, diff_stats;
	dladm_phys_attr_t	dpa;

	if (state->ls_firstonly) {
		if (state->ls_donefirst)
			return (DLADM_WALK_CONTINUE);
		state->ls_donefirst = B_TRUE;
	} else {
		bzero(&state->ls_prevstats, sizeof (state->ls_prevstats));
	}

	if (dladm_datalink_id2info(linkid, NULL, &class, NULL, link,
	    DLPI_LINKNAME_MAX) != DLADM_STATUS_OK) {
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
	dladm_stats_diff(&diff_stats, &stats, &state->ls_prevstats);

	(void) printf("%-12s", link);
	(void) printf("%-10llu", diff_stats.ipackets);
	(void) printf("%-12llu", diff_stats.rbytes);
	(void) printf("%-8llu", diff_stats.ierrors);
	(void) printf("%-10llu", diff_stats.opackets);
	(void) printf("%-12llu", diff_stats.obytes);
	(void) printf("%-8llu\n", diff_stats.oerrors);

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

	if (!state->gs_parseable && !state->gs_printheader) {
		print_header(&state->gs_print);
		state->gs_printheader = B_TRUE;
	}

	dladm_print_output(&state->gs_print, state->gs_parseable,
	    dladm_print_field, (void *)&lbuf);

	return (DLADM_STATUS_OK);
}

static char *
print_xaggr_callback(print_field_t *pf, void *arg)
{
	const laggr_args_t 	*l = arg;
	int 			portnum;
	static char 		buf[DLADM_STRSIZE];
	boolean_t		is_port = (l->laggr_lport >= 0);
	dladm_aggr_port_attr_t *portp;
	dladm_phys_attr_t	dpa;
	dladm_status_t		*stat, status;

	stat = l->laggr_status;
	*stat = DLADM_STATUS_OK;

	if (is_port) {
		portnum = l->laggr_lport;
		portp = &(l->laggr_ginfop->lg_ports[portnum]);
		if ((status = dladm_datalink_id2info(portp->lp_linkid,
		    NULL, NULL, NULL, buf, sizeof (buf))) !=
		    DLADM_STATUS_OK) {
			goto err;
		}
		if ((status = dladm_phys_info(portp->lp_linkid, &dpa,
		    DLADM_OPT_ACTIVE)) != DLADM_STATUS_OK) {
			goto err;
		}
	}

	switch (pf->pf_index) {
	case AGGR_X_LINK:
		(void) snprintf(buf, sizeof (buf), "%s",
		    (is_port && !l->laggr_parseable ? " " : l->laggr_link));
		break;
	case AGGR_X_PORT:
		if (is_port)
			break;
		return ("");
		break;

	case AGGR_X_SPEED:
		if (is_port) {
			(void) snprintf(buf, sizeof (buf), "%uMb",
			    (uint_t)((get_ifspeed(dpa.dp_dev,
			    B_FALSE)) / 1000000ull));
		} else {
			(void) snprintf(buf, sizeof (buf), "%uMb",
			    (uint_t)((get_ifspeed(l->laggr_link,
			    B_TRUE)) / 1000000ull));
		}
		break;

	case AGGR_X_DUPLEX:
		if (is_port)
			(void) get_linkduplex(dpa.dp_dev, B_FALSE, buf);
		else
			(void) get_linkduplex(l->laggr_link, B_TRUE, buf);
		break;

	case AGGR_X_STATE:
		if (is_port)
			(void) get_linkstate(dpa.dp_dev,  B_FALSE, buf);
		else
			(void) get_linkstate(l->laggr_link, B_TRUE, buf);
		break;
	case AGGR_X_ADDRESS:
		(void) dladm_aggr_macaddr2str(
		    (is_port ? portp->lp_mac : l->laggr_ginfop->lg_mac),
		    buf);
		break;
	case AGGR_X_PORTSTATE:
		if (is_port)
			(void) dladm_aggr_portstate2str(
			    portp->lp_state, buf);
		else
			return ("");
		break;
	}
	return (buf);

err:
	*stat = status;
	buf[0] = '\0';
	return (buf);
}

static dladm_status_t
print_aggr_extended(show_grp_state_t *state, const char *link,
    dladm_aggr_grp_attr_t *ginfop)
{
	int			i;
	dladm_status_t		status;
	laggr_args_t		largs;

	if (!state->gs_parseable && !state->gs_printheader) {
		print_header(&state->gs_print);
		state->gs_printheader = B_TRUE;
	}

	largs.laggr_lport = -1;
	largs.laggr_link = link;
	largs.laggr_ginfop = ginfop;
	largs.laggr_status = &status;
	largs.laggr_parseable = state->gs_parseable;

	dladm_print_output(&state->gs_print, state->gs_parseable,
	    print_xaggr_callback, &largs);

	if (status != DLADM_STATUS_OK)
		goto done;

	for (i = 0; i < ginfop->lg_nports; i++) {
		largs.laggr_lport = i;
		dladm_print_output(&state->gs_print, state->gs_parseable,
		    print_xaggr_callback, &largs);
		if (status != DLADM_STATUS_OK)
			goto done;
	}

	status = DLADM_STATUS_OK;
done:
	return (status);
}


static char *
print_lacp_callback(print_field_t *pf, void *arg)
{
	const laggr_args_t	*l = arg;
	int			portnum;
	static char		buf[DLADM_STRSIZE];
	boolean_t		is_port = (l->laggr_lport >= 0);
	dladm_aggr_port_attr_t	*portp;
	dladm_status_t		*stat, status;
	aggr_lacp_state_t	*lstate;

	if (!is_port) {
		return (NULL); /* cannot happen! */
	}

	stat = l->laggr_status;

	portnum = l->laggr_lport;
	portp = &(l->laggr_ginfop->lg_ports[portnum]);
	if ((status = dladm_datalink_id2info(portp->lp_linkid,
	    NULL, NULL, NULL, buf, sizeof (buf))) != DLADM_STATUS_OK) {
			goto err;
	}
	lstate = &(portp->lp_lacp_state);

	switch (pf->pf_index) {
	case AGGR_L_LINK:
		(void) snprintf(buf, sizeof (buf), "%s",
		    (portnum > 0 ? "" : l->laggr_link));
		break;

	case AGGR_L_PORT:
		break;

	case AGGR_L_AGGREGATABLE:
		(void) snprintf(buf, sizeof (buf), "%s",
		    (lstate->bit.aggregation ? "yes" : "no"));
		break;

	case AGGR_L_SYNC:
		(void) snprintf(buf, sizeof (buf), "%s",
		    (lstate->bit.sync ? "yes" : "no"));
		break;

	case AGGR_L_COLL:
		(void) snprintf(buf, sizeof (buf), "%s",
		    (lstate->bit.collecting ? "yes" : "no"));
		break;

	case AGGR_L_DIST:
		(void) snprintf(buf, sizeof (buf), "%s",
		    (lstate->bit.distributing ? "yes" : "no"));
		break;

	case AGGR_L_DEFAULTED:
		(void) snprintf(buf, sizeof (buf), "%s",
		    (lstate->bit.defaulted ? "yes" : "no"));
		break;

	case AGGR_L_EXPIRED:
		(void) snprintf(buf, sizeof (buf), "%s",
		    (lstate->bit.expired ? "yes" : "no"));
		break;
	}

	*stat = DLADM_STATUS_OK;
	return (buf);

err:
	*stat = status;
	buf[0] = '\0';
	return (buf);
}

static dladm_status_t
print_aggr_lacp(show_grp_state_t *state, const char *link,
    dladm_aggr_grp_attr_t *ginfop)
{
	int		i;
	dladm_status_t	status;
	laggr_args_t	largs;

	if (!state->gs_parseable && !state->gs_printheader) {
		print_header(&state->gs_print);
		state->gs_printheader = B_TRUE;
	}

	largs.laggr_link = link;
	largs.laggr_ginfop = ginfop;
	largs.laggr_status = &status;

	for (i = 0; i < ginfop->lg_nports; i++) {
		largs.laggr_lport = i;
		dladm_print_output(&state->gs_print, state->gs_parseable,
		    print_lacp_callback, &largs);
		if (status != DLADM_STATUS_OK)
			goto done;
	}

	status = DLADM_STATUS_OK;
done:
	return (status);
}

static char *
print_aggr_stats_callback(print_field_t *pf, void *arg)
{
	const laggr_args_t	*l = arg;
	int 			portnum;
	static char		buf[DLADM_STRSIZE];
	boolean_t		is_port = (l->laggr_lport >= 0);
	dladm_aggr_port_attr_t	*portp;
	dladm_phys_attr_t	dpa;
	dladm_status_t		*stat, status;
	pktsum_t		port_stat, diff_stats;

	stat = l->laggr_status;
	*stat = DLADM_STATUS_OK;

	if (is_port) {
		portnum = l->laggr_lport;
		portp = &(l->laggr_ginfop->lg_ports[portnum]);
		if ((status = dladm_phys_info(portp->lp_linkid, &dpa,
		    DLADM_OPT_ACTIVE)) != DLADM_STATUS_OK) {
			goto err;
		}

		get_mac_stats(dpa.dp_dev, &port_stat);

		if ((status = dladm_datalink_id2info(portp->lp_linkid, NULL,
		    NULL, NULL, buf, sizeof (buf))) != DLADM_STATUS_OK) {
			goto err;
		}

		dladm_stats_diff(&diff_stats, &port_stat, l->laggr_prevstats);
	}

	switch (pf->pf_index) {
	case AGGR_S_LINK:
		(void) snprintf(buf, sizeof (buf), "%s",
		    (is_port ? "" : l->laggr_link));
		break;
	case AGGR_S_PORT:
		if (is_port)
			break;
		return ("");
		break;

	case AGGR_S_IPKTS:
		if (is_port) {
			(void) snprintf(buf, sizeof (buf), "%llu",
			    diff_stats.ipackets);
		} else {
			(void) snprintf(buf, sizeof (buf), "%llu",
			    l->laggr_pktsumtot->ipackets);
		}
		break;

	case AGGR_S_RBYTES:
		if (is_port) {
			(void) snprintf(buf, sizeof (buf), "%llu",
			    diff_stats.rbytes);
		} else {
			(void) snprintf(buf, sizeof (buf), "%llu",
			    l->laggr_pktsumtot->rbytes);
		}
		break;

	case AGGR_S_OPKTS:
		if (is_port) {
			(void) snprintf(buf, sizeof (buf), "%llu",
			    diff_stats.opackets);
		} else {
			(void) snprintf(buf, sizeof (buf), "%llu",
			    l->laggr_pktsumtot->opackets);
		}
		break;
	case AGGR_S_OBYTES:
		if (is_port) {
			(void) snprintf(buf, sizeof (buf), "%llu",
			    diff_stats.obytes);
		} else {
			(void) snprintf(buf, sizeof (buf), "%llu",
			    l->laggr_pktsumtot->obytes);

		}
		break;

	case AGGR_S_IPKTDIST:
		if (is_port) {
			(void) snprintf(buf, sizeof (buf), "%-6.1f",
			    (double)diff_stats.opackets/
			    (double)l->laggr_pktsumtot->ipackets * 100);
		} else {
			return ("");
		}
		break;
	case AGGR_S_OPKTDIST:
		if (is_port) {
			(void) snprintf(buf, sizeof (buf), "%-6.1f",
			    (double)diff_stats.opackets/
			    (double)l->laggr_pktsumtot->opackets * 100);
		} else {
			return ("");
		}
		break;
	}
	return (buf);

err:
	*stat = status;
	buf[0] = '\0';
	return (buf);
}

static dladm_status_t
print_aggr_stats(show_grp_state_t *state, const char *link,
    dladm_aggr_grp_attr_t *ginfop)
{
	dladm_phys_attr_t	dpa;
	dladm_aggr_port_attr_t	*portp;
	pktsum_t		pktsumtot, port_stat;
	dladm_status_t		status;
	int			i;
	laggr_args_t		largs;

	/* sum the ports statistics */
	bzero(&pktsumtot, sizeof (pktsumtot));

	for (i = 0; i < ginfop->lg_nports; i++) {

		portp = &(ginfop->lg_ports[i]);
		if ((status = dladm_phys_info(portp->lp_linkid, &dpa,
		    DLADM_OPT_ACTIVE)) != DLADM_STATUS_OK) {
			goto done;
		}

		get_mac_stats(dpa.dp_dev, &port_stat);
		dladm_stats_total(&pktsumtot, &port_stat,
		    &state->gs_prevstats[i]);
	}

	if (!state->gs_parseable && !state->gs_printheader) {
		print_header(&state->gs_print);
		state->gs_printheader = B_TRUE;
	}

	largs.laggr_lport = -1;
	largs.laggr_link = link;
	largs.laggr_ginfop = ginfop;
	largs.laggr_status = &status;
	largs.laggr_pktsumtot = &pktsumtot;

	dladm_print_output(&state->gs_print, state->gs_parseable,
	    print_aggr_stats_callback, &largs);

	if (status != DLADM_STATUS_OK)
		goto done;

	for (i = 0; i < ginfop->lg_nports; i++) {
		largs.laggr_lport = i;
		largs.laggr_prevstats = &state->gs_prevstats[i];
		dladm_print_output(&state->gs_print, state->gs_parseable,
		    print_aggr_stats_callback, &largs);
		if (status != DLADM_STATUS_OK)
			goto done;
	}

	status = DLADM_STATUS_OK;
done:
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
	if ((status = dladm_datalink_id2info(linkid, &flags, NULL, NULL, link,
	    MAXLINKNAMELEN)) != DLADM_STATUS_OK) {
		return (status);
	}

	if (!(state->gs_flags & flags))
		return (DLADM_STATUS_NOTFOUND);

	status = dladm_aggr_info(linkid, &ginfo, state->gs_flags);
	if (status != DLADM_STATUS_OK)
		return (status);

	if (state->gs_lacp)
		status = print_aggr_lacp(state, link, &ginfo);
	else if (state->gs_extended)
		status = print_aggr_extended(state, link, &ginfo);
	else if (state->gs_stats)
		status = print_aggr_stats(state, link, &ginfo);
	else {
		status = print_aggr_info(state, link, &ginfo);
	}

done:
	free(ginfo.lg_ports);
	return (status);
}

static int
show_aggr(datalink_id_t linkid, void *arg)
{
	show_grp_state_t	*state = arg;
	dladm_status_t		status;

	status = print_aggr(state, linkid);
	if (status != DLADM_STATUS_OK)
		goto done;

done:
	state->gs_status = status;
	return (DLADM_WALK_CONTINUE);
}

static void
do_show_link(int argc, char *argv[], const char *use)
{
	int		option;
	boolean_t	s_arg = B_FALSE;
	boolean_t	S_arg = B_FALSE;
	boolean_t	i_arg = B_FALSE;
	uint32_t	flags = DLADM_OPT_ACTIVE;
	boolean_t	p_arg = B_FALSE;
	datalink_id_t	linkid = DATALINK_ALL_LINKID;
	char		linkname[MAXLINKNAMELEN];
	int		interval = 0;
	show_state_t	state;
	dladm_status_t	status;
	boolean_t	o_arg = B_FALSE;
	char		*fields_str = NULL;
	print_field_t	**fields;
	uint_t		nfields;
	char		*all_active_fields = "link,class,mtu,state,over";
	char		*all_inactive_fields = "link,class,over";
	char		*allstat_fields =
	    "link,ipackets,rbytes,ierrors,opackets,obytes,oerrors";

	bzero(&state, sizeof (state));

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":pPsSi:o:",
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
		case 'S':
			if (S_arg)
				die_optdup(option);

			S_arg = B_TRUE;
			break;
		case 'o':
			o_arg = B_TRUE;
			fields_str = optarg;
			break;
		case 'i':
			if (i_arg)
				die_optdup(option);

			i_arg = B_TRUE;
			if (!str2int(optarg, &interval) || interval == 0)
				die("invalid interval value '%s'", optarg);
			break;
		default:
			die_opterr(optopt, option, use);
			break;
		}
	}

	if (i_arg && !(s_arg || S_arg))
		die("the option -i can be used only with -s or -S");

	if (s_arg && S_arg)
		die("the -s option cannot be used with -S");

	if (s_arg && flags != DLADM_OPT_ACTIVE)
		die("the option -P cannot be used with -s");

	if (S_arg && (p_arg || flags != DLADM_OPT_ACTIVE))
		die("the option -%c cannot be used with -S", p_arg ? 'p' : 'P');

	/* get link name (optional last argument) */
	if (optind == (argc-1)) {
		uint32_t	f;

		if (strlcpy(linkname, argv[optind], MAXLINKNAMELEN)
		    >= MAXLINKNAMELEN) {
			(void) fprintf(stderr,
			    gettext("%s: link name too long\n"),
			    progname);
			exit(1);
		}
		if ((status = dladm_name2info(linkname, &linkid, &f,
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

	if (S_arg) {
		dladm_continuous(linkid, NULL, interval, LINK_REPORT);
		return;
	}

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

	state.ls_parseable = p_arg;
	state.ls_flags = flags;
	state.ls_donefirst = B_FALSE;

	if (s_arg) {
		link_stats(linkid, interval, fields_str, &state);
		return;
	}

	fields = parse_output_fields(fields_str, link_fields, DEV_LINK_FIELDS,
	    CMD_TYPE_ANY, &nfields);

	if (fields == NULL)
		die("invalid field(s) specified");

	state.ls_print.ps_fields = fields;
	state.ls_print.ps_nfields = nfields;

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
	int			interval = 0;
	int			key;
	dladm_status_t		status;
	boolean_t		o_arg = B_FALSE;
	char			*fields_str = NULL;
	print_field_t		**fields;
	uint_t			nfields;
	char			*all_fields =
	    "link,policy,addrpolicy,lacpactivity,lacptimer,flags";
	char			*all_lacp_fields =
	    "link,port,aggregatable,sync,coll,dist,defaulted,expired";
	char			*all_stats_fields =
	    "link,port,ipackets,rbytes,opackets,obytes,ipktdist,opktdist";
	char			*all_extended_fields =
	    "link,port,speed,duplex,state,address,portstate";
	print_field_t		*pf;
	int			pfmax;

	bzero(&state, sizeof (state));

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
			if (!str2int(optarg, &interval) || interval == 0)
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
		pfmax = AGGR_L_MAX_FIELDS;
	} else if (state.gs_stats) {
		pf = aggr_s_fields;
		pfmax = AGGR_S_MAX_FIELDS;
	} else if (state.gs_extended) {
		pf = aggr_x_fields;
		pfmax = AGGR_X_MAX_FIELDS;
	} else {
		pf = laggr_fields;
		pfmax = LAGGR_MAX_FIELDS;
	}
	fields = parse_output_fields(fields_str, pf, pfmax, CMD_TYPE_ANY,
	    &nfields);

	if (fields == NULL) {
		die("invalid field(s) specified");
		return;
	}

	state.gs_print.ps_fields = fields;
	state.gs_print.ps_nfields = nfields;

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

static dladm_status_t
print_phys_default(show_state_t *state, datalink_id_t linkid,
    const char *link, uint32_t flags, uint32_t media)
{
	dladm_phys_attr_t dpa;
	dladm_status_t status;
	link_fields_buf_t pattr;

	status = dladm_phys_info(linkid, &dpa, state->ls_flags);
	if (status != DLADM_STATUS_OK)
		goto done;

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

	if (!state->ls_parseable && !state->ls_printheader) {
		print_header(&state->ls_print);
		state->ls_printheader = B_TRUE;
	}

	dladm_print_output(&state->ls_print, state->ls_parseable,
	    dladm_print_field, (void *)&pattr);

done:
	return (status);
}

typedef struct {
	show_state_t	*ms_state;
	char		*ms_link;
	dladm_macaddr_attr_t *ms_mac_attr;
} print_phys_mac_state_t;

/* callback of dladm_print_output() */
static char *
print_phys_one_mac_callback(print_field_t *pf, void *arg)
{
	print_phys_mac_state_t *mac_state = arg;
	dladm_macaddr_attr_t *attr = mac_state->ms_mac_attr;
	static char buf[DLADM_STRSIZE];
	boolean_t is_primary = (attr->ma_slot == 0);
	boolean_t is_parseable = mac_state->ms_state->ls_parseable;

	switch (pf->pf_index) {
	case PHYS_M_LINK:
		(void) snprintf(buf, sizeof (buf), "%s",
		    (is_primary || is_parseable) ? mac_state->ms_link : " ");
		break;
	case PHYS_M_SLOT:
		if (is_primary)
			(void) snprintf(buf, sizeof (buf), gettext("primary"));
		else
			(void) snprintf(buf, sizeof (buf), "%d", attr->ma_slot);
		break;
	case PHYS_M_ADDRESS:
		(void) dladm_aggr_macaddr2str(attr->ma_addr, buf);
		break;
	case PHYS_M_INUSE:
		(void) snprintf(buf, sizeof (buf), "%s",
		    attr->ma_flags & DLADM_MACADDR_USED ? gettext("yes") :
		    gettext("no"));
		break;
	case PHYS_M_CLIENT:
		/*
		 * CR 6678526: resolve link id to actual link name if
		 * it is valid.
		 */
		(void) snprintf(buf, sizeof (buf), "%s", attr->ma_client_name);
		break;
	}

	return (buf);
}

typedef struct {
	show_state_t	*hs_state;
	char		*hs_link;
	dladm_hwgrp_attr_t *hs_grp_attr;
} print_phys_hwgrp_state_t;

static char *
print_phys_one_hwgrp_callback(print_field_t *pf, void *arg)
{
	print_phys_hwgrp_state_t *hg_state = arg;
	dladm_hwgrp_attr_t *attr = hg_state->hs_grp_attr;
	static char buf[DLADM_STRSIZE];

	switch (pf->pf_index) {
	case PHYS_H_LINK:
		(void) snprintf(buf, sizeof (buf), "%s", attr->hg_link_name);
		break;
	case PHYS_H_GROUP:
		(void) snprintf(buf, sizeof (buf), "%d", attr->hg_grp_num);
		break;
	case PHYS_H_GRPTYPE:
		(void) snprintf(buf, sizeof (buf), "%s",
		    attr->hg_grp_type == DLADM_HWGRP_TYPE_RX ? "RX" : "TX");
		break;
	case PHYS_H_RINGS:
		(void) snprintf(buf, sizeof (buf), "%d", attr->hg_n_rings);
		break;
	case PHYS_H_CLIENTS:
		if (attr->hg_client_names[0] == '\0') {
			(void) snprintf(buf, sizeof (buf), "--");
		} else {
			(void) snprintf(buf, sizeof (buf), "%s ",
			    attr->hg_client_names);
		}
		break;
	}

	return (buf);
}

/* callback of dladm_walk_macaddr, invoked for each MAC address slot */
static boolean_t
print_phys_mac_callback(void *arg, dladm_macaddr_attr_t *attr)
{
	print_phys_mac_state_t *mac_state = arg;
	show_state_t *state = mac_state->ms_state;

	if (!state->ls_parseable && !state->ls_printheader) {
		print_header(&state->ls_print);
		state->ls_printheader = B_TRUE;
	}

	mac_state->ms_mac_attr = attr;
	dladm_print_output(&state->ls_print, state->ls_parseable,
	    print_phys_one_mac_callback, mac_state);

	return (B_TRUE);
}

/* invoked by show-phys -m for each physical data-link */
static dladm_status_t
print_phys_mac(show_state_t *state, datalink_id_t linkid, char *link)
{
	print_phys_mac_state_t mac_state;

	mac_state.ms_state = state;
	mac_state.ms_link = link;

	return (dladm_walk_macaddr(linkid, &mac_state,
	    print_phys_mac_callback));
}

/* callback of dladm_walk_hwgrp, invoked for each MAC hwgrp */
static boolean_t
print_phys_hwgrp_callback(void *arg, dladm_hwgrp_attr_t *attr)
{
	print_phys_hwgrp_state_t *hwgrp_state = arg;
	show_state_t *state = hwgrp_state->hs_state;

	if (!state->ls_parseable && !state->ls_printheader) {
		print_header(&state->ls_print);
		state->ls_printheader = B_TRUE;
	}
	hwgrp_state->hs_grp_attr = attr;
	dladm_print_output(&state->ls_print, state->ls_parseable,
	    print_phys_one_hwgrp_callback, hwgrp_state);

	return (B_TRUE);
}

/* invoked by show-phys -H for each physical data-link */
static dladm_status_t
print_phys_hwgrp(show_state_t *state, datalink_id_t linkid, char *link)
{
	print_phys_hwgrp_state_t hwgrp_state;

	hwgrp_state.hs_state = state;
	hwgrp_state.hs_link = link;
	return (dladm_walk_hwgrp(linkid, &hwgrp_state,
	    print_phys_hwgrp_callback));
}

static dladm_status_t
print_phys(show_state_t *state, datalink_id_t linkid)
{
	char			link[MAXLINKNAMELEN];
	uint32_t		flags;
	dladm_status_t		status;
	datalink_class_t	class;
	uint32_t		media;

	if ((status = dladm_datalink_id2info(linkid, &flags, &class, &media,
	    link, MAXLINKNAMELEN)) != DLADM_STATUS_OK) {
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

static int
show_phys(datalink_id_t linkid, void *arg)
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

	if ((status = dladm_datalink_id2info(linkid, &flags, NULL, NULL,
	    l->link_name, sizeof (l->link_name))) != DLADM_STATUS_OK) {
		goto done;
	}

	if (!(state->ls_flags & flags)) {
		status = DLADM_STATUS_NOTFOUND;
		goto done;
	}

	if ((status = dladm_vlan_info(linkid, &vinfo, state->ls_flags)) !=
	    DLADM_STATUS_OK || (status = dladm_datalink_id2info(
	    vinfo.dv_linkid, NULL, NULL, NULL, l->link_over,
	    sizeof (l->link_over))) != DLADM_STATUS_OK) {
		goto done;
	}

	(void) snprintf(l->link_vlan_vid, sizeof (l->link_vlan_vid), "%d",
	    vinfo.dv_vid);
	(void) snprintf(l->link_flags, sizeof (l->link_flags), "%c----",
	    vinfo.dv_force ? 'f' : '-');

done:
	return (status);
}

static int
show_vlan(datalink_id_t linkid, void *arg)
{
	show_state_t		*state = arg;
	dladm_status_t		status;
	link_fields_buf_t	lbuf;

	bzero(&lbuf, sizeof (link_fields_buf_t));
	status = print_vlan(state, linkid, &lbuf);
	if (status != DLADM_STATUS_OK)
		goto done;

	if (!state->ls_parseable && !state->ls_printheader) {
		print_header(&state->ls_print);
		state->ls_printheader = B_TRUE;
	}

	dladm_print_output(&state->ls_print, state->ls_parseable,
	    dladm_print_field, (void *)&lbuf);

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
	print_field_t	**fields;
	uint_t		nfields;
	char		*all_active_fields =
	    "link,media,state,speed,duplex,device";
	char		*all_inactive_fields = "link,device,media,flags";
	char		*all_mac_fields = "link,slot,address,inuse,client";
	char		*all_hwgrp_fields =
	    "link,group,grouptype,rings,clients";
	print_field_t	*pf;
	int		pfmax;

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
		pfmax = PHYS_M_MAX_FIELDS;
	} else if (state.ls_hwgrp) {
		pf = phys_h_fields;
		pfmax = PHYS_H_MAX_FIELDS;
	} else {
		pf = phys_fields;
		pfmax = PHYS_MAX_FIELDS;
	}

	fields = parse_output_fields(fields_str, pf,
	    pfmax, CMD_TYPE_ANY, &nfields);

	if (fields == NULL) {
		die("invalid field(s) specified");
		return;
	}

	state.ls_print.ps_fields = fields;
	state.ls_print.ps_nfields = nfields;

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
	print_field_t	**fields;
	uint_t		nfields;
	char		*all_fields = "link,vid,over,flags";

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

	if (p_arg && !o_arg)
		die("-p requires -o");

	if (p_arg && strcasecmp(fields_str, "all") == 0)
		die("\"-o all\" is invalid with -p");

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

	if (!o_arg || (o_arg && strcasecmp(fields_str, "all") == 0))
		fields_str = all_fields;

	fields = parse_output_fields(fields_str, vlan_fields, VLAN_MAX_FIELDS,
	    CMD_TYPE_ANY, &nfields);

	if (fields == NULL) {
		die("invalid field(s) specified");
		return;
	}
	state.ls_print.ps_fields = fields;
	state.ls_print.ps_nfields = nfields;

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
do_create_vnic(int argc, char *argv[], const char *use)
{
	datalink_id_t		linkid, dev_linkid;
	char			devname[MAXLINKNAMELEN];
	char			name[MAXLINKNAMELEN];
	boolean_t		l_arg = B_FALSE;
	uint32_t		flags = DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST;
	char			*altroot = NULL;
	char			option;
	char			*endp = NULL;
	dladm_status_t		status;
	vnic_mac_addr_type_t	mac_addr_type = VNIC_MAC_ADDR_TYPE_AUTO;
	uchar_t			*mac_addr;
	int			mac_slot = -1, maclen = 0, mac_prefix_len = 0;
	dladm_arg_list_t	*proplist = NULL;
	uint16_t		vid = 0;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":tfR:l:m:n:p:r:v:H",
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
				mac_addr = _link_aton(optarg, &maclen);
				if (mac_addr == NULL) {
					if (maclen == -1)
						die("invalid MAC address");
					else
						die("out of memory");
					exit(1);
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
			if (dladm_parse_link_props(optarg, &proplist, B_FALSE)
			    != DLADM_STATUS_OK)
				die("invalid vnic property");
			break;
		case 'r':
			mac_addr = _link_aton(optarg, &mac_prefix_len);
			if (mac_addr == NULL) {
				if (mac_prefix_len == -1)
					die("invalid MAC address");
				else
					die("out of memory");
				exit(1);
			}
			break;
		case 'v':
			vid = (int)strtol(optarg, &endp, 10);
			if (errno != 0 || *endp != '\0' || vid == 0)
				/* VID of 0 is invalid */
				die("invalid VLAN id");
			break;
		case 'f':
			flags |= DLADM_OPT_FORCE;
			break;
		case 'H':
			flags |= DLADM_OPT_HWRINGS;
			break;
		default:
			die_opterr(optopt, option, use);
		}
	}

	/*
	 * 'f' - force, flag can be specified only with 'v' - vlan.
	 */
	if ((flags & DLADM_OPT_FORCE) != 0 && vid == 0)
		die("-f option can only be used with -v");

	if (mac_prefix_len != 0 && mac_addr_type != VNIC_MAC_ADDR_TYPE_RANDOM &&
	    mac_addr_type != VNIC_MAC_ADDR_TYPE_FIXED)
		usage();

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

	if (dladm_name2info(devname, &dev_linkid, NULL, NULL, NULL) !=
	    DLADM_STATUS_OK)
		die("invalid link name '%s'", devname);

	status = dladm_vnic_create(name, dev_linkid, mac_addr_type, mac_addr,
	    maclen, &mac_slot, mac_prefix_len, vid, &linkid, proplist, flags);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "vnic creation over %s failed", devname);

	dladm_free_props(proplist);
}

static void
do_etherstub_check(const char *name, datalink_id_t linkid, boolean_t etherstub,
    uint32_t flags)
{
	boolean_t is_etherstub;
	dladm_vnic_attr_t attr;

	if (dladm_vnic_info(linkid, &attr, flags) != DLADM_STATUS_OK) {
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
	char option;
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

	status = dladm_name2info(argv[optind], &linkid, NULL, NULL, NULL);
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

	status = dladm_vnic_delete(linkid, flags);
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
		status = dladm_name2info(argv[1], &linkid, NULL, NULL, NULL);
		if (status != DLADM_STATUS_OK)
			goto done;

	} else if (argc > 2) {
		usage();
	}

	if (vlan)
		status = dladm_vlan_up(linkid);
	else
		status = dladm_vnic_up(linkid, 0);

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

	if ((status = dladm_vnic_info(linkid, vnic, state->vs_flags)) !=
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

	if (dladm_datalink_id2info(linkid, NULL, NULL,
	    NULL, vnic_name, sizeof (vnic_name)) != DLADM_STATUS_OK)
		return (DLADM_STATUS_BADARG);

	bzero(devname, sizeof (devname));
	if (!is_etherstub &&
	    dladm_datalink_id2info(vnic->va_link_id, NULL, NULL,
	    NULL, devname, sizeof (devname)) != DLADM_STATUS_OK)
		return (DLADM_STATUS_BADARG);

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

		if (!state->vs_parseable && !state->vs_printheader) {
			print_header(&state->vs_print);
			state->vs_printheader = B_TRUE;
		}

		dladm_print_output(&state->vs_print, state->vs_parseable,
		    dladm_print_field, (void *)&vbuf);

		return (DLADM_STATUS_OK);
	}
}

static int
show_vnic(datalink_id_t linkid, void *arg)
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
	char			*endp = NULL;
	uint32_t		interval = 0, flags = DLADM_OPT_ACTIVE;
	datalink_id_t		linkid = DATALINK_ALL_LINKID;
	datalink_id_t		dev_linkid = DATALINK_ALL_LINKID;
	show_vnic_state_t	state;
	dladm_status_t		status;
	boolean_t		o_arg = B_FALSE;
	char			*fields_str = NULL;
	print_field_t  		**fields;
	print_field_t		*pf;
	int			pfmax;
	uint_t			nfields;
	char			*all_fields =
	    "link,over,speed,macaddr,macaddrtype,vid";
	char			*all_e_fields =
	    "link";

	bzero(&state, sizeof (state));
	opterr = 0;
	while ((option = getopt_long(argc, argv, ":pPl:si:o:", lopts,
	    NULL)) != -1) {
		switch (option) {
		case 'p':
			state.vs_parseable = B_TRUE;
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
			interval = (int)strtol(optarg, &endp, 10);
			if (errno != 0 || interval == 0 || *endp != '\0')
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
		status = dladm_name2info(argv[optind], &linkid, NULL,
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
		status = dladm_name2info(state.vs_link, &dev_linkid, NULL,
		    NULL, NULL);
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
		else
			fields_str = all_fields;
	}

	pf = vnic_fields;
	pfmax = VNIC_MAX_FIELDS;

	fields = parse_output_fields(fields_str, pf, pfmax, CMD_TYPE_ANY,
	    &nfields);

	if (fields == NULL) {
		die("invalid field(s) specified");
		return;
	}

	state.vs_print.ps_fields = fields;
	state.vs_print.ps_nfields = nfields;

	if (s_arg) {
		/* Display vnic statistics */
		vnic_stats(&state, interval);
		return;
	}

	/* Display vnic information */
	state.vs_donefirst = B_FALSE;

	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(show_vnic, &state,
		    DATALINK_CLASS_VNIC | DATALINK_CLASS_ETHERSTUB,
		    DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);
	} else {
		(void) show_vnic(linkid, &state);
		if (state.vs_status != DLADM_STATUS_OK) {
			die_dlerr(state.vs_status, "failed to show vnic '%s'",
			    state.vs_vnic);
		}
	}
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
	char option;
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

	status = dladm_vnic_create(name, DATALINK_INVALID_LINKID,
	    VNIC_MAC_ADDR_TYPE_AUTO, mac_addr, ETHERADDRL, NULL, 0, 0, NULL,
	    NULL, flags);
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

static void
link_stats(datalink_id_t linkid, uint_t interval, char *fields_str,
    show_state_t *state)
{
	print_field_t	**fields;
	uint_t		nfields;

	fields = parse_output_fields(fields_str, devs_fields, DEVS_MAX_FIELDS,
	    CMD_TYPE_ANY, &nfields);
	if (fields == NULL) {
		die("invalid field(s) specified");
		return;
	}

	state->ls_print.ps_fields = fields;
	state->ls_print.ps_nfields = nfields;

	/*
	 * If an interval is specified, continuously show the stats
	 * only for the first MAC port.
	 */
	state->ls_firstonly = (interval != 0);

	if (!state->ls_parseable)
		print_header(&state->ls_print);
	for (;;) {
		state->ls_donefirst = B_FALSE;
		if (linkid == DATALINK_ALL_LINKID) {
			(void) dladm_walk_datalink_id(show_link_stats, state,
			    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE,
			    DLADM_OPT_ACTIVE);
		} else {
			(void) show_link_stats(linkid, state);
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
			(void) dladm_walk_datalink_id(show_vnic, &state,
			    DATALINK_CLASS_VNIC, DATALINK_ANY_MEDIATYPE,
			    DLADM_OPT_ACTIVE);
		} else {
			(void) show_vnic(sp->vs_vnic_id, &state);
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
			(void) dladm_walk_datalink_id(show_vnic, &state,
			    DATALINK_CLASS_VNIC, DATALINK_ANY_MEDIATYPE,
			    DLADM_OPT_ACTIVE);
		} else {
			(void) show_vnic(sp->vs_vnic_id, &state);
			if (state.vs_status != DLADM_STATUS_OK) {
				die_dlerr(state.vs_status,
				    "failed to show vnic '%s'", sp->vs_vnic);
			}
		}

		if (interval == 0)
			break;

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
parse_wifi_fields(char *str, print_field_t ***fields, uint_t *countp,
    uint_t cmdtype)
{

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
	*fields = parse_output_fields(str, wifi_fields, WIFI_MAX_FIELDS,
	    cmdtype, countp);
	if (*fields != NULL)
		return (0);
	return (-1);
}
static print_field_t **
parse_output_fields(char *str, print_field_t *template, int max_fields,
    uint_t cmdtype, uint_t *countp)
{
	split_t		*sp;
	boolean_t	good_match = B_FALSE;
	uint_t		i, j;
	print_field_t	**pf = NULL;

	sp = split(str, max_fields, MAX_FIELD_LEN);

	if (sp == NULL)
		return (NULL);

	pf = malloc(sp->s_nfields * sizeof (print_field_t *));
	if (pf == NULL)
		goto fail;

	for (i = 0; i < sp->s_nfields; i++) {
		for (j = 0; j < max_fields; j++) {
			if (strcasecmp(sp->s_fields[i],
			    template[j].pf_name) == 0) {
				good_match = template[j]. pf_cmdtype & cmdtype;
				break;
			}
		}
		if (!good_match)
			goto fail;

		good_match = B_FALSE;
		pf[i] = &template[j];
	}
	*countp = i;
	splitfree(sp);
	return (pf);
fail:
	free(pf);
	splitfree(sp);
	return (NULL);
}

typedef struct print_wifi_state {
	char		*ws_link;
	boolean_t	ws_parseable;
	boolean_t	ws_header;
	print_state_t	ws_print_state;
} print_wifi_state_t;

typedef struct  wlan_scan_args_s {
	print_wifi_state_t	*ws_state;
	void			*ws_attr;
} wlan_scan_args_t;

static void
print_field(print_state_t *statep, print_field_t *pfp, const char *value,
    boolean_t parseable)
{
	uint_t	width = pfp->pf_width;
	uint_t	valwidth;
	uint_t	compress;

	/*
	 * Parsable fields are separated by ':'. If such a field contains
	 * a ':' or '\', this character is prefixed by a '\'.
	 */
	if (parseable) {
		char	c;

		if (statep->ps_nfields == 1) {
			(void) printf("%s", value);
			return;
		}
		while ((c = *value++) != '\0') {
			if (c == ':' || c == '\\')
				(void) putchar('\\');
			(void) putchar(c);
		}
		if (!statep->ps_lastfield)
			(void) putchar(':');
		return;
	} else {
		if (value[0] == '\0')
			value = STR_UNDEF_VAL;
		if (statep->ps_lastfield) {
			(void) printf("%s", value);
			statep->ps_overflow = 0;
			return;
		}

		valwidth = strlen(value);
		if (valwidth > width) {
			statep->ps_overflow += valwidth - width;
		} else if (valwidth < width && statep->ps_overflow > 0) {
			compress = min(statep->ps_overflow, width - valwidth);
			statep->ps_overflow -= compress;
			width -= compress;
		}
		(void) printf("%-*s", width, value);
	}

	if (!statep->ps_lastfield)
		(void) putchar(' ');
}

static char *
print_wlan_attr(print_field_t *wfp, void *warg)
{
	static char		buf[DLADM_STRSIZE];
	wlan_scan_args_t	*w = warg;
	print_wifi_state_t	*statep = w->ws_state;
	dladm_wlan_attr_t	*attrp = w->ws_attr;

	if (wfp->pf_index == 0) {
		return ((char *)statep->ws_link);
	}

	if ((wfp->pf_index & attrp->wa_valid) == 0) {
		return ("");
	}

	switch (wfp->pf_index) {
	case DLADM_WLAN_ATTR_ESSID:
		(void) dladm_wlan_essid2str(&attrp->wa_essid, buf);
		break;
	case DLADM_WLAN_ATTR_BSSID:
		(void) dladm_wlan_bssid2str(&attrp->wa_bssid, buf);
		break;
	case DLADM_WLAN_ATTR_SECMODE:
		(void) dladm_wlan_secmode2str(&attrp->wa_secmode, buf);
		break;
	case DLADM_WLAN_ATTR_STRENGTH:
		(void) dladm_wlan_strength2str(&attrp->wa_strength, buf);
		break;
	case DLADM_WLAN_ATTR_MODE:
		(void) dladm_wlan_mode2str(&attrp->wa_mode, buf);
		break;
	case DLADM_WLAN_ATTR_SPEED:
		(void) dladm_wlan_speed2str(&attrp->wa_speed, buf);
		(void) strlcat(buf, "Mb", sizeof (buf));
		break;
	case DLADM_WLAN_ATTR_AUTH:
		(void) dladm_wlan_auth2str(&attrp->wa_auth, buf);
		break;
	case DLADM_WLAN_ATTR_BSSTYPE:
		(void) dladm_wlan_bsstype2str(&attrp->wa_bsstype, buf);
		break;
	}

	return (buf);
}

static boolean_t
print_scan_results(void *arg, dladm_wlan_attr_t *attrp)
{
	print_wifi_state_t	*statep = arg;
	wlan_scan_args_t	warg;

	if (statep->ws_header) {
		statep->ws_header = B_FALSE;
		if (!statep->ws_parseable)
			print_header(&statep->ws_print_state);
	}

	statep->ws_print_state.ps_overflow = 0;
	bzero(&warg, sizeof (warg));
	warg.ws_state = statep;
	warg.ws_attr = attrp;
	dladm_print_output(&statep->ws_print_state, statep->ws_parseable,
	    print_wlan_attr, &warg);
	return (B_TRUE);
}

static int
scan_wifi(datalink_id_t linkid, void *arg)
{
	print_wifi_state_t	*statep = arg;
	dladm_status_t		status;
	char			link[MAXLINKNAMELEN];

	if ((status = dladm_datalink_id2info(linkid, NULL, NULL, NULL, link,
	    sizeof (link))) != DLADM_STATUS_OK) {
		return (DLADM_WALK_CONTINUE);
	}

	statep->ws_link = link;
	status = dladm_wlan_scan(linkid, statep, print_scan_results);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "cannot scan link '%s'", statep->ws_link);

	return (DLADM_WALK_CONTINUE);
}

static char *
print_link_attr(print_field_t *wfp, void *warg)
{
	static char		buf[DLADM_STRSIZE];
	char			*ptr;
	wlan_scan_args_t	*w = warg, w1;
	print_wifi_state_t	*statep = w->ws_state;
	dladm_wlan_linkattr_t	*attrp = w->ws_attr;

	if (strcmp(wfp->pf_name, "status") == 0) {
		if ((wfp->pf_index & attrp->la_valid) != 0)
			(void) dladm_wlan_linkstatus2str(
			    &attrp->la_status, buf);
		return (buf);
	}
	statep->ws_print_state.ps_overflow = 0;
	bzero(&w1, sizeof (w1));
	w1.ws_state = statep;
	w1.ws_attr = &attrp->la_wlan_attr;
	ptr = print_wlan_attr(wfp, &w1);
	return (ptr);
}

static int
show_wifi(datalink_id_t linkid, void *arg)
{
	print_wifi_state_t	*statep = arg;
	dladm_wlan_linkattr_t	attr;
	dladm_status_t		status;
	char			link[MAXLINKNAMELEN];
	wlan_scan_args_t	warg;

	if ((status = dladm_datalink_id2info(linkid, NULL, NULL, NULL, link,
	    sizeof (link))) != DLADM_STATUS_OK) {
		return (DLADM_WALK_CONTINUE);
	}

	/* dladm_wlan_get_linkattr() memsets attr with 0 */
	status = dladm_wlan_get_linkattr(linkid, &attr);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "cannot get link attributes for %s", link);

	statep->ws_link = link;

	if (statep->ws_header) {
		statep->ws_header = B_FALSE;
		if (!statep->ws_parseable)
			print_header(&statep->ws_print_state);
	}

	statep->ws_print_state.ps_overflow = 0;
	bzero(&warg, sizeof (warg));
	warg.ws_state = statep;
	warg.ws_attr = &attr;
	dladm_print_output(&statep->ws_print_state, statep->ws_parseable,
	    print_link_attr, &warg);
	return (DLADM_WALK_CONTINUE);
}

static void
do_display_wifi(int argc, char **argv, int cmd, const char *use)
{
	int			option;
	char			*fields_str = NULL;
	print_field_t		**fields;
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
			break;
		default:
			die_opterr(optopt, option, use);
		}
	}

	if (state.ws_parseable && fields_str == NULL)
		die("-p requires -o");

	if (state.ws_parseable && strcasecmp(fields_str, "all") == 0)
		die("\"-o all\" is invalid with -p");

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

	bzero(&state.ws_print_state, sizeof (state.ws_print_state));
	state.ws_print_state.ps_fields = fields;
	state.ws_print_state.ps_nfields = nfields;

	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(callback, &state,
		    DATALINK_CLASS_PHYS, DL_WIFI, DLADM_OPT_ACTIVE);
	} else {
		(void) (*callback)(linkid, &state);
	}
	free(fields);
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

static void
print_linkprop(datalink_id_t linkid, show_linkprop_state_t *statep,
    const char *propname, dladm_prop_type_t type,
    const char *format, char **pptr)
{
	int		i;
	char		*ptr, *lim;
	char		buf[DLADM_STRSIZE];
	char		*unknown = "--", *notsup = "";
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

	ptr = buf;
	lim = buf + DLADM_STRSIZE;
	for (i = 0; i < valcnt; i++) {
		if (propvals[i][0] == '\0' && !statep->ls_parseable)
			ptr += snprintf(ptr, lim - ptr, STR_UNDEF_VAL",");
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
		    "%s", buf);
	} else {
		*pptr += snprintf(*pptr, lim - *pptr, format, buf);
	}
}

static char *
linkprop_callback(print_field_t *pf, void *ls_arg)
{
	linkprop_args_t		*arg = ls_arg;
	char 			*propname = arg->ls_propname;
	show_linkprop_state_t	*statep = arg->ls_state;
	char			*ptr = statep->ls_line;
	char			*lim = ptr + MAX_PROP_LINE;
	datalink_id_t		linkid = arg->ls_linkid;

	switch (pf->pf_index) {
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
		if (statep->ls_status != DLADM_STATUS_OK)
			goto skip;
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
	return (ptr);
skip:
	if (statep->ls_status != DLADM_STATUS_OK)
		return (NULL);
	else
		return ("");
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

	status = dladm_get_linkprop(linkid, DLADM_PROP_VAL_DEFAULT,
	    propname, statep->ls_propvals, &valcnt);

	if (status == DLADM_STATUS_OK)
		return (B_TRUE);

	/*
	 * A system wide default value is not available for the
	 * property. Check if current value can be retrieved.
	 */
	status = dladm_get_linkprop(linkid, DLADM_PROP_VAL_CURRENT,
	    propname, statep->ls_propvals, &valcnt);

	return (status == DLADM_STATUS_OK);
}

static int
show_linkprop(datalink_id_t linkid, const char *propname, void *arg)
{
	show_linkprop_state_t	*statep = arg;
	linkprop_args_t		ls_arg;

	bzero(&ls_arg, sizeof (ls_arg));
	ls_arg.ls_state = statep;
	ls_arg.ls_propname = (char *)propname;
	ls_arg.ls_linkid = linkid;

	if (statep->ls_header) {
		statep->ls_header = B_FALSE;
		if (!statep->ls_parseable)
			print_header(&statep->ls_print);
	}
	if (!statep->ls_parseable &&
	    !linkprop_is_supported(linkid, propname, statep))
		return (DLADM_WALK_CONTINUE);

	dladm_print_output(&statep->ls_print, statep->ls_parseable,
	    linkprop_callback, (void *)&ls_arg);

	return (DLADM_WALK_CONTINUE);
}

static void
do_show_linkprop(int argc, char **argv, const char *use)
{
	int			option;
	dladm_arg_list_t	*proplist = NULL;
	datalink_id_t		linkid = DATALINK_ALL_LINKID;
	show_linkprop_state_t	state;
	uint32_t		flags = DLADM_OPT_ACTIVE;
	dladm_status_t		status;
	char			*fields_str = NULL;
	print_field_t		**fields;
	uint_t			nfields;
	boolean_t		o_arg = B_FALSE;
	char			*all_fields =
	    "link,property,perm,value,default,possible";

	fields_str = all_fields;

	opterr = 0;
	state.ls_propvals = NULL;
	state.ls_line = NULL;
	state.ls_parseable = B_FALSE;
	state.ls_persist = B_FALSE;
	state.ls_header = B_TRUE;
	state.ls_retstatus = DLADM_STATUS_OK;
	while ((option = getopt_long(argc, argv, ":p:cPo:",
	    prop_longopts, NULL)) != -1) {
		switch (option) {
		case 'p':
			if (dladm_parse_link_props(optarg, &proplist, B_TRUE)
			    != DLADM_STATUS_OK)
				die("invalid link properties specified");
			break;
		case 'c':
			state.ls_parseable = B_TRUE;
			break;
		case 'P':
			state.ls_persist = B_TRUE;
			flags = DLADM_OPT_PERSIST;
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

	if (state.ls_parseable && !o_arg)
		die("-c requires -o");

	if (state.ls_parseable && fields_str == all_fields)
		die("\"-o all\" is invalid with -c");

	if (optind == (argc - 1)) {
		if ((status = dladm_name2info(argv[optind], &linkid, NULL,
		    NULL, NULL)) != DLADM_STATUS_OK) {
			die_dlerr(status, "link %s is not valid", argv[optind]);
		}
	} else if (optind != argc) {
		usage();
	}

	bzero(&state.ls_print, sizeof (print_state_t));
	state.ls_proplist = proplist;
	state.ls_status = DLADM_STATUS_OK;

	fields = parse_output_fields(fields_str, linkprop_fields,
	    LINKPROP_MAX_FIELDS, CMD_TYPE_ANY, &nfields);

	if (fields == NULL) {
		die("invalid field(s) specified");
		return;
	}

	state.ls_print.ps_fields = fields;
	state.ls_print.ps_nfields = nfields;
	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(show_linkprop_onelink, &state,
		    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE, flags);
	} else {
		(void) show_linkprop_onelink(linkid, &state);
	}
	dladm_free_props(proplist);

	if (state.ls_retstatus != DLADM_STATUS_OK)
		exit(EXIT_FAILURE);
}

static int
show_linkprop_onelink(datalink_id_t linkid, void *arg)
{
	int			i;
	char			*buf;
	uint32_t		flags;
	dladm_arg_list_t	*proplist = NULL;
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
		for (i = 0; i < proplist->al_count; i++) {
			(void) show_linkprop(linkid,
			    proplist->al_info[i].ai_name, statep);
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
		warn_dlerr(status, "cannot persistently %s link property '%s'",
		    reset ? "reset" : "set", prop_name);
	}
	return (status);
}

static int
reset_one_linkprop(datalink_id_t linkid, const char *propname, void *arg)
{
	set_linkprop_state_t	*statep = arg;
	dladm_status_t		status;

	status = dladm_set_linkprop(linkid, propname, NULL, 0,
	    DLADM_OPT_ACTIVE);
	if (status != DLADM_STATUS_OK) {
		warn_dlerr(status, "cannot reset link property '%s' on '%s'",
		    propname, statep->ls_name);
	}
	if (!statep->ls_temp) {
		dladm_status_t	s;

		s = set_linkprop_persist(linkid, propname, NULL, 0,
		    statep->ls_reset);
		if (s != DLADM_STATUS_OK)
			status = s;
	}
	if (status != DLADM_STATUS_OK)
		statep->ls_status = status;

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
	dladm_arg_list_t	*proplist = NULL;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":p:R:t",
	    prop_longopts, NULL)) != -1) {
		switch (option) {
		case 'p':
			if (dladm_parse_link_props(optarg, &proplist, reset) !=
			    DLADM_STATUS_OK) {
				die("invalid link properties specified");
			}
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

	if (proplist == NULL && !reset)
		die("link property must be specified");

	if (altroot != NULL) {
		dladm_free_props(proplist);
		altroot_cmd(altroot, argc, argv);
	}

	status = dladm_name2info(argv[optind], &linkid, NULL, NULL, NULL);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "link %s is not valid", argv[optind]);

	if (proplist == NULL) {
		set_linkprop_state_t	state;

		state.ls_name = argv[optind];
		state.ls_reset = reset;
		state.ls_temp = temp;
		state.ls_status = DLADM_STATUS_OK;

		(void) dladm_walk_linkprop(linkid, &state, reset_one_linkprop);

		status = state.ls_status;
		goto done;
	}

	for (i = 0; i < proplist->al_count; i++) {
		dladm_arg_info_t	*aip = &proplist->al_info[i];
		char		**val;
		uint_t		count;
		dladm_status_t	s;

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
		s = dladm_set_linkprop(linkid, aip->ai_name, val, count,
		    DLADM_OPT_ACTIVE);
		if (s == DLADM_STATUS_OK) {
			if (!temp) {
				s = set_linkprop_persist(linkid,
				    aip->ai_name, val, count, reset);
				if (s != DLADM_STATUS_OK)
					status = s;
			}
			continue;
		}
		status = s;
		switch (s) {
		case DLADM_STATUS_NOTFOUND:
			warn("invalid link property '%s'", aip->ai_name);
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
	if (status != DLADM_STATUS_OK)
		exit(1);
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
do_delete_secobj(int argc, char **argv, const char *use)
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
			die_opterr(optopt, option, use);
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
	boolean_t	ss_header;
	print_state_t	ss_print;
} show_secobj_state_t;


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
	secobj_fields_buf_t	sbuf;

	bzero(&sbuf, sizeof (secobj_fields_buf_t));
	if (statep->ss_persist)
		flags |= DLADM_OPT_PERSIST;

	status = dladm_get_secobj(obj_name, &class, obj_val, &obj_len, flags);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "cannot get secure object '%s'", obj_name);

	if (statep->ss_header) {
		statep->ss_header = B_FALSE;
		if (!statep->ss_parseable)
			print_header(&statep->ss_print);
	}

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
	dladm_print_output(&statep->ss_print, statep->ss_parseable,
	    dladm_print_field, (void *)&sbuf);
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
	split_t			*sp;
	uint_t			flags;
	char			*fields_str = NULL;
	print_field_t		**fields;
	uint_t			nfields;
	char			*def_fields = "object,class";
	char			*all_fields = "object,class,value";

	opterr = 0;
	bzero(&state, sizeof (state));
	state.ss_parseable = B_FALSE;
	fields_str = def_fields;
	state.ss_persist = B_FALSE;
	state.ss_parseable = B_FALSE;
	state.ss_header = B_TRUE;
	while ((option = getopt_long(argc, argv, ":pPo:",
	    wifi_longopts, NULL)) != -1) {
		switch (option) {
		case 'p':
			state.ss_parseable = B_TRUE;
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

	if (state.ss_parseable && !o_arg)
		die("option -c requires -o");

	if (state.ss_parseable && fields_str == all_fields)
		die("\"-o all\" is invalid with -p");

	fields = parse_output_fields(fields_str, secobj_fields,
	    DEV_SOBJ_FIELDS, CMD_TYPE_ANY, &nfields);

	if (fields == NULL) {
		die("invalid field(s) specified");
		return;
	}
	state.ss_print.ps_fields = fields;
	state.ss_print.ps_nfields = nfields;

	flags = state.ss_persist ? DLADM_OPT_PERSIST : 0;
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

	status = dladm_walk_secobj(&state, show_secobj, flags);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "show-secobj");
}

/*ARGSUSED*/
static int
i_dladm_init_linkprop(datalink_id_t linkid, void *arg)
{
	(void) dladm_init_linkprop(linkid, B_TRUE);
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
		if ((status = dladm_name2info(argv[optind], &linkid, NULL, NULL,
		    NULL)) != DLADM_STATUS_OK)
			die_dlerr(status, "link %s is not valid", argv[optind]);
	} else if (optind != argc) {
		usage();
	}

	if (linkid == DATALINK_ALL_LINKID) {
		/*
		 * linkprops of links of other classes have been initialized as
		 * part of the dladm up-xxx operation.
		 */
		(void) dladm_walk_datalink_id(i_dladm_init_linkprop, NULL,
		    DATALINK_CLASS_PHYS, media, DLADM_OPT_PERSIST);
	} else {
		(void) dladm_init_linkprop(linkid, any_media);
	}
}

/* ARGSUSED */
static void
do_show_ether(int argc, char **argv, const char *use)
{
	int 			option;
	datalink_id_t		linkid;
	print_ether_state_t 	state;
	print_field_t 		**fields;
	boolean_t		o_arg = B_FALSE;
	char			*fields_str;
	uint_t			nfields;
	char			*all_fields =
	    "link,ptype,state,auto,speed-duplex,pause,rem_fault";
	char			*default_fields =
	    "link,ptype,state,auto,speed-duplex,pause";

	fields_str = default_fields;
	bzero(&state, sizeof (state));
	state.es_link = NULL;
	state.es_parseable = B_FALSE;

	while ((option = getopt_long(argc, argv, "o:px",
	    showeth_lopts, NULL)) != -1) {
		switch (option) {
			case 'x':
				state.es_extended = B_TRUE;
				break;
			case 'p':
				state.es_parseable = B_TRUE;
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

	if (state.es_parseable && !o_arg)
		die("-p requires -o");

	if (state.es_parseable && fields_str == all_fields)
		die("\"-o all\" is invalid with -p");

	if (optind == (argc - 1))
		state.es_link = argv[optind];

	fields = parse_output_fields(fields_str, ether_fields,
	    ETHER_MAX_FIELDS, CMD_TYPE_ANY, &nfields);

	if (fields == NULL) {
		die("invalid field(s) specified");
		exit(EXIT_FAILURE);
	}
	state.es_print.ps_fields = fields;
	state.es_print.ps_nfields = nfields;

	if (state.es_link == NULL) {
		(void) dladm_walk_datalink_id(show_etherprop, &state,
		    DATALINK_CLASS_PHYS, DL_ETHER,
		    DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST);
	} else {
		if (!link_is_ether(state.es_link, &linkid)) {
			die("invalid link specified");
		}
		(void) show_etherprop(linkid, &state);
	}

	exit(DLADM_STATUS_OK);

}

static char *
dladm_print_field(print_field_t *pf, void *arg)
{
	char *value;

	value = (char *)arg + pf->pf_offset;
	return (value);
}

static int
show_etherprop(datalink_id_t linkid, void *arg)
{
	print_ether_state_t	*statep = arg;
	ether_fields_buf_t	ebuf;
	dladm_ether_info_t	eattr;
	dladm_status_t		status;

	bzero(&ebuf, sizeof (ether_fields_buf_t));
	if (dladm_datalink_id2info(linkid, NULL, NULL, NULL,
	    ebuf.eth_link, sizeof (ebuf.eth_link)) != DLADM_STATUS_OK) {
		return (DLADM_WALK_CONTINUE);
	}

	if (!statep->es_header && !statep->es_parseable) {
		print_header(&statep->es_print);
		statep->es_header = B_TRUE;
	}

	status = dladm_ether_info(linkid, &eattr);
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

	dladm_print_output(&statep->es_print, statep->es_parseable,
	    dladm_print_field, &ebuf);

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
	dladm_status_t status;

	status = dladm_init_secobj();
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "secure object initialization failed");
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
		dladm_print_output(&statep->es_print, statep->es_parseable,
		    dladm_print_field, &ebuf);
	}

}

static void
dladm_print_output(print_state_t *statep, boolean_t parseable,
    print_callback_t fn, void *arg)
{
	int i;
	char *value;
	print_field_t **pf;

	pf = statep->ps_fields;
	for (i = 0; i < statep->ps_nfields; i++) {
		statep->ps_lastfield = (i + 1 == statep->ps_nfields);
		value = (*fn)(pf[i], arg);
		if (value != NULL)
			print_field(statep, pf[i], value, parseable);
	}
	(void) putchar('\n');
}

static void
print_header(print_state_t *ps)
{
	int i;
	print_field_t **pf;

	pf = ps->ps_fields;
	for (i = 0; i < ps->ps_nfields; i++) {
		ps->ps_lastfield = (i + 1 == ps->ps_nfields);
		print_field(ps, pf[i], pf[i]->pf_header, B_FALSE);
	}
	(void) putchar('\n');
}

static boolean_t
link_is_ether(const char *link, datalink_id_t *linkid)
{
	uint32_t media;
	datalink_class_t class;

	if (dladm_name2info(link, linkid, NULL, &class, &media) ==
	    DLADM_STATUS_OK) {
		if (class == DATALINK_CLASS_PHYS && media == DL_ETHER)
			return (B_TRUE);
	}
	return (B_FALSE);
}

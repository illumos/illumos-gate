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
#include <stddef.h>

#define	AGGR_DRV		"aggr"
#define	STR_UNDEF_VAL		"--"
#define	MAXPORT			256
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
 * data structures and routines for printing output.
 * All non-parseable output is assumed to be in a columnar format.
 * Parseable output will be printed as <pf_header>="<value>"
 *
 * Each sub-command is associated with a global array of pointers,
 * print_field_t *fields[], where the print_field_t contains information
 * about the format in which the output is  to be printed.
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
 * system call required to find the value to be printed. An example of
 * this implementation may be found in the do_show_dev() and print_dev()
 * invocation.
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
	uint32_t	ls_flags;
	dladm_status_t	ls_status;
	print_state_t	ls_print;
	boolean_t	ls_parseable;
	boolean_t	ls_printheader;
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
static cmdfunc_t do_show_ether;

static void	altroot_cmd(char *, int, char **);
static int	show_linkprop_onelink(datalink_id_t, void *);

static void	link_stats(datalink_id_t, uint_t);
static void	aggr_stats(datalink_id_t, show_grp_state_t *, uint_t);
static void	dev_stats(const char *dev, uint32_t, char *, show_state_t *);

static int	get_one_kstat(const char *, const char *, uint8_t,
		    void *, boolean_t);
static void	get_mac_stats(const char *, pktsum_t *);
static void	get_link_stats(const char *, pktsum_t *);
static uint64_t	get_ifspeed(const char *, boolean_t);
static void	stats_total(pktsum_t *, pktsum_t *, pktsum_t *);
static void	stats_diff(pktsum_t *, pktsum_t *, pktsum_t *);
static const char	*get_linkstate(const char *, boolean_t, char *);
static const char	*get_linkduplex(const char *, boolean_t, char *);

static int	show_etherprop(datalink_id_t, void *);
static void	show_ether_xprop(datalink_id_t, void *);
static boolean_t get_speed_duplex(datalink_id_t, const char *, char *,
    char *, boolean_t);
static char 	*pause_str(int, int);
static boolean_t	link_is_ether(const char *, datalink_id_t *);

#define	IS_FDX	0x10
#define	IS_HDX	0x01

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
	{ "show-ether",		do_show_ether		},
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
	{ 0, 0, 0, 0 }
};

static const struct option show_lopts[] = {
	{"statistics",	no_argument,		0, 's'},
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

/*
 * structures for 'dladm show-ether'
 */
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
 * structures for 'dladm show-dev'.
 */
typedef enum {
	DEV_LINK,
	DEV_STATE,
	DEV_SPEED,
	DEV_DUPLEX
} dev_field_index_t;

static print_field_t dev_fields[] = {
/* name,	header,		field width,	index,		cmdtype */
{ "link",	"LINK",			15,	DEV_LINK,	CMD_TYPE_ANY},
{ "state",	"STATE",		6,	DEV_STATE,	CMD_TYPE_ANY},
{ "speed",	"SPEED",		8,	DEV_SPEED,	CMD_TYPE_ANY},
{ "duplex",	"DUPLEX",		8,	DEV_DUPLEX,	CMD_TYPE_ANY}}
;
#define	DEV_MAX_FIELDS	(sizeof (dev_fields) / sizeof (print_field_t))

/*
 * structures for 'dladm show-dev -s' (print statistics)
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
typedef struct dev_args_s {
	char		*devs_link;
	pktsum_t 	*devs_psum;
} dev_args_t;
static char *print_dev_stats(print_field_t *, void *);
static char *print_dev(print_field_t *, void *);

/*
 * buffer used by print functions for show-{link,phys,vlan} commands.
 */
typedef struct link_fields_buf_s {
	char link_name[MAXLINKNAMELEN];
	char link_class[DLADM_STRSIZE];
	char link_mtu[6];
	char link_state[DLADM_STRSIZE];
	char link_over[MAXLINKNAMELEN];
	char link_phys_state[6];
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
	(sizeof (aggr_l_fields) / sizeof (print_field_t))

/*
 * structures for 'dladm show-dev -L'.
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
{ "speed",	"SPEED",		4,
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
	LINKPROP_VALUE,
	LINKPROP_DEFAULT,
	LINKPROP_POSSIBLE
} linkprop_field_index_t;

static print_field_t linkprop_fields[] = {
/* name,	header,		field width,  index,		cmdtype */
{ "link",	"LINK",		12,	LINKPROP_LINK,		CMD_TYPE_ANY},
{ "property",	"PROPERTY",	15,	LINKPROP_PROPERTY,	CMD_TYPE_ANY},
{ "value",	"VALUE",	14,	LINKPROP_VALUE,		CMD_TYPE_ANY},
{ "default",	"DEFAULT",	14,	LINKPROP_DEFAULT, 	CMD_TYPE_ANY},
{ "possible",	"POSSIBLE",	20,	LINKPROP_POSSIBLE,	CMD_TYPE_ANY}}
;
#define	LINKPROP_MAX_FIELDS					\
	(sizeof (linkprop_fields) / sizeof (print_field_t))

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
	boolean_t	ls_parseable;
	boolean_t	ls_persist;
	boolean_t	ls_header;
	dladm_status_t	ls_status;
	dladm_status_t	ls_retstatus;
	print_state_t	ls_print;
} show_linkprop_state_t;

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

static char *progname;
static sig_atomic_t signalled;

static void
usage(void)
{
	(void) fprintf(stderr, gettext("usage:	dladm <subcommand> <args> ...\n"
	    "\tshow-link       [-pP] [-o <field>,..] [-s [-i <interval>]] "
	    "[<link>]\n"
	    "\trename-link     [-R <root-dir>] <oldlink> <newlink>\n"
	    "\n"
	    "\tdelete-phys     <link>\n"
	    "\tshow-phys       [-pP] [-o <field>,..] [<link>]\n"
	    "\tshow-dev        [-p] [-o <field>,..] [-s [-i <interval>]] "
	    "[<dev>]\n"
	    "\n"
	    "\tcreate-aggr     [-t] [-R <root-dir>] [-P <policy>] [-L <mode>]\n"
	    "\t		[-T <time>] [-u <address>] [-l <link>] ... <link>\n"
	    "\tmodify-aggr     [-t] [-R <root-dir>] [-P <policy>] [-L <mode>]\n"
	    "\t		[-T <time>] [-u <address>] <link>\n"
	    "\tdelete-aggr     [-t] [-R <root-dir>] <link>\n"
	    "\tadd-aggr        [-t] [-R <root-dir>] [-l <link>] ... <link>\n"
	    "\tremove-aggr     [-t] [-R <root-dir>] [-l <link>] ... <link>"
	    "\n\tshow-aggr       [-pPLx] [-o <field>,..] [-s [-i <interval>]] "
	    "[<link>]\n"
	    "\n"
	    "\tcreate-vlan     [-ft] [-R <root-dir>] -l <link> -v <vid> [link]"
	    "\n\tdelete-vlan     [-t]  [-R <root-dir>] <link>\n"
	    "\tshow-vlan       [-pP] [-o <field>,..] [<link>]\n"
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
	    "\tshow-linkprop   [-cP][-o <field>,...][-p <prop>,...] <name>\n"
	    "\n"
	    "\tcreate-secobj   [-t] [-R <root-dir>] [-f <file>] -c <class>"
	    " <secobj>\n"
	    "\tdelete-secobj   [-t] [-R <root-dir>] <secobj>[,...]\n"
	    "\tshow-secobj     [-pP][-o <field>,...][<secobj>,...]\n"
	    "\n"
	    "\tshow-ether      [-px][-o <field>,...] <link>\n"));

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
			die_dlerr(status, "not all links have link up/down "
			    "detection; must use -f (see dladm(1M))\n");
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


/*
 * Print the active topology information.
 */
static dladm_status_t
print_link_topology(show_state_t *state, datalink_id_t linkid,
    datalink_class_t class, link_fields_buf_t *lbuf)
{
	uint32_t	flags = state->ls_flags;
	dladm_status_t	status = DLADM_STATUS_OK;

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
			    lbuf->link_over, sizeof (lbuf->link_over));
			if (status != DLADM_STATUS_OK) {
				free(ginfo.lg_ports);
				goto done;
			}
		}
		free(ginfo.lg_ports);
	} else if (class == DATALINK_CLASS_VNIC) {
		dladm_vnic_attr_sys_t	vinfo;

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
		    "%d", mtu);
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
	char link[DLPI_LINKNAME_MAX];
	datalink_class_t class;
	show_state_t *state = (show_state_t *)arg;
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
		if (is_port) {
			(void) dladm_aggr_portstate2str(
			    portp->lp_state, buf);
		} else {
			return (STR_UNDEF_VAL);
		}
		break;
	case AGGR_X_ADDRESS:
		(void) dladm_aggr_macaddr2str(
		    (is_port ? portp->lp_mac : l->laggr_ginfop->lg_mac),
		    buf);
		break;

	case AGGR_X_PORTSTATE:
		(void) snprintf(buf, sizeof (buf), "%s",
		    (is_port ? dladm_aggr_portstate2str(portp->lp_state, buf):
		    (l->laggr_parseable ? "" : STR_UNDEF_VAL)));
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

		stats_diff(&diff_stats, &port_stat, l->laggr_prevstats);
	}

	switch (pf->pf_index) {
	case AGGR_S_LINK:
		(void) snprintf(buf, sizeof (buf), "%s",
		    (is_port ? "" : l->laggr_link));
		break;
	case AGGR_S_PORT:
		if (is_port)
			break;
		return (STR_UNDEF_VAL);
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
			return (STR_UNDEF_VAL);
		}
		break;
	case AGGR_S_OPKTDIST:
		if (is_port) {
			(void) snprintf(buf, sizeof (buf), "%-6.1f",
			    (double)diff_stats.opackets/
			    (double)l->laggr_pktsumtot->opackets * 100);
		} else {
			(void) sprintf(buf, STR_UNDEF_VAL);
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
		stats_total(&pktsumtot, &port_stat, &state->gs_prevstats[i]);
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

static char *
print_dev(print_field_t *pf, void *arg)
{
	const char *dev = arg;
	static char buf[DLADM_STRSIZE];

	switch (pf->pf_index) {
	case DEV_LINK:
		(void) snprintf(buf, sizeof (buf), "%s", dev);
		break;
	case DEV_STATE:
		(void) get_linkstate(dev, B_FALSE, buf);
		break;
	case DEV_SPEED:
		(void) snprintf(buf, sizeof (buf), "%uMb",
		    (unsigned int)(get_ifspeed(dev, B_FALSE) / 1000000ull));
		break;
	case DEV_DUPLEX:
		(void) get_linkduplex(dev, B_FALSE, buf);
		break;
	default:
		die("invalid index '%d'", pf->pf_index);
		break;
	}
	return (buf);
}

static int
show_dev(const char *dev, void *arg)
{
	show_state_t	*state = arg;

	if (!state->ls_parseable && !state->ls_printheader) {
		print_header(&state->ls_print);
		state->ls_printheader = B_TRUE;
	}

	dladm_print_output(&state->ls_print, state->ls_parseable,
	    print_dev, (void *)dev);

	return (DLADM_WALK_CONTINUE);
}

static char *
print_dev_stats(print_field_t *pf, void *arg)
{
	dev_args_t *dargs = arg;
	pktsum_t *diff_stats = dargs->devs_psum;
	static char buf[DLADM_STRSIZE];

	switch (pf->pf_index) {
	case DEVS_LINK:
		(void) snprintf(buf, sizeof (buf), "%s", dargs->devs_link);
		break;
	case DEVS_IPKTS:
		(void) snprintf(buf, sizeof (buf), "%llu",
		    diff_stats->ipackets);
		break;
	case DEVS_RBYTES:
		(void) snprintf(buf, sizeof (buf), "%llu",
		    diff_stats->rbytes);
		break;
	case DEVS_IERRORS:
		(void) snprintf(buf, sizeof (buf), "%u",
		    diff_stats->ierrors);
		break;
	case DEVS_OPKTS:
		(void) snprintf(buf, sizeof (buf), "%llu",
		    diff_stats->opackets);
		break;
	case DEVS_OBYTES:
		(void) snprintf(buf, sizeof (buf), "%llu",
		    diff_stats->obytes);
		break;
	case DEVS_OERRORS:
		(void) snprintf(buf, sizeof (buf), "%u",
		    diff_stats->oerrors);
		break;
	default:
		die("invalid input");
		break;
	}
	return (buf);
}

static int
show_dev_stats(const char *dev, void *arg)
{
	show_state_t *state = arg;
	pktsum_t stats, diff_stats;
	dev_args_t dargs;

	if (state->ls_firstonly) {
		if (state->ls_donefirst)
			return (DLADM_WALK_CONTINUE);
		state->ls_donefirst = B_TRUE;
	} else {
		bzero(&state->ls_prevstats, sizeof (state->ls_prevstats));
	}

	get_mac_stats(dev, &stats);
	stats_diff(&diff_stats, &stats, &state->ls_prevstats);

	dargs.devs_link = (char *)dev;
	dargs.devs_psum = &diff_stats;
	dladm_print_output(&state->ls_print, state->ls_parseable,
	    print_dev_stats, &dargs);

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
	boolean_t	o_arg = B_FALSE;
	char		*fields_str = NULL;
	print_field_t	**fields;
	uint_t		nfields;
	char		*all_active_fields = "link,class,mtu,state,over";
	char		*all_inactive_fields = "link,class,over";

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

	if (!o_arg || (o_arg && strcasecmp(fields_str, "all") == 0)) {
		if (state.ls_flags & DLADM_OPT_ACTIVE)
			fields_str = all_active_fields;
		else
			fields_str = all_inactive_fields;
	}


	fields = parse_output_fields(fields_str, link_fields, DEV_LINK_FIELDS,
	    CMD_TYPE_ANY, &nfields);

	if (fields == NULL) {
		die("invalid field(s) specified");
		return;
	}

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
	boolean_t	o_arg = B_FALSE;
	char		*fields_str = NULL;
	print_field_t   **fields;
	uint_t		nfields;
	char		*all_fields =
	    "link,policy,addrpolicy,lacpactivity,lacptimer,flags";
	char		*all_lacp_fields =
	    "link,port,aggregatable,sync,coll,dist,defaulted,expired";
	char		*all_stats_fields =
	    "link,port,ipackets,rbytes,opackets,obytes,ipktdist,opktdist";
	char		*all_extended_fields =
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

static void
do_show_dev(int argc, char *argv[])
{
	int		option;
	char		*dev = NULL;
	boolean_t	s_arg = B_FALSE;
	boolean_t	i_arg = B_FALSE;
	boolean_t	o_arg = B_FALSE;
	boolean_t	p_arg = B_FALSE;
	datalink_id_t	linkid;
	int		interval = 0;
	show_state_t	state;
	char		*fields_str = NULL;
	print_field_t	**fields;
	uint_t		nfields;
	char		*all_fields = "link,state,speed,duplex";
	static char	*allstat_fields =
	    "link,ipackets,rbytes,ierrors,opackets,obytes,oerrors";

	bzero(&state, sizeof (state));
	fields_str = all_fields;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":psi:o:",
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
			die_opterr(optopt, option);
			break;
		}
	}

	if (i_arg && !s_arg)
		die("the option -i can be used only with -s");

	if (o_arg && strcasecmp(fields_str, "all") == 0) {
		if (!s_arg)
			fields_str = all_fields;
		else
			fields_str = allstat_fields;
	}

	if (!o_arg && s_arg)
		fields_str = allstat_fields;

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

	state.ls_parseable = p_arg;
	state.ls_donefirst = B_FALSE;

	if (s_arg) {
		dev_stats(dev, interval, fields_str, &state);
		return;
	}

	fields = parse_output_fields(fields_str, dev_fields, DEV_MAX_FIELDS,
	    CMD_TYPE_ANY, &nfields);

	if (fields == NULL) {
		die("invalid field(s) specified");
		return;
	}

	state.ls_print.ps_fields = fields;
	state.ls_print.ps_nfields = nfields;

	if (dev == NULL) {
		(void) dladm_mac_walk(show_dev, &state);
	} else {
		(void) show_dev(dev, &state);
	}
}


static dladm_status_t
print_phys(show_state_t *state, datalink_id_t linkid, link_fields_buf_t *pattr)
{
	char			link[MAXLINKNAMELEN];
	dladm_phys_attr_t	dpa;
	uint32_t		flags;
	datalink_class_t	class;
	uint32_t		media;
	dladm_status_t		status;

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

	status = dladm_phys_info(linkid, &dpa, state->ls_flags);
	if (status != DLADM_STATUS_OK)
		goto done;

	(void) snprintf(pattr->link_phys_device,
	    sizeof (pattr->link_phys_device), "%s", dpa.dp_dev);
	(void) dladm_media2str(media, pattr->link_phys_media);
	if (state->ls_flags == DLADM_OPT_ACTIVE) {
		boolean_t	islink;

		if (!dpa.dp_novanity) {
			(void) strlcpy(pattr->link_name, link,
			    sizeof (pattr->link_name));
			islink = B_TRUE;
		} else {
			/*
			 * This is a physical link that does not have
			 * vanity naming support.
			 */
			(void) strlcpy(pattr->link_name, dpa.dp_dev,
			    sizeof (pattr->link_name));
			islink = B_FALSE;
		}

		(void) get_linkstate(pattr->link_name, islink,
		    pattr->link_phys_state);
		(void) snprintf(pattr->link_phys_speed,
		    sizeof (pattr->link_phys_speed), "%u",
		    (uint_t)((get_ifspeed(pattr->link_name,
		    islink)) / 1000000ull));
		(void) get_linkduplex(pattr->link_name, islink,
		    pattr->link_phys_duplex);
	} else {
		(void) snprintf(pattr->link_name, sizeof (pattr->link_name),
		    "%s", link);
		(void) snprintf(pattr->link_flags, sizeof (pattr->link_flags),
		    "%c----", flags & DLADM_OPT_ACTIVE ? '-' : 'r');
	}

done:
	return (status);
}

static int
show_phys(datalink_id_t linkid, void *arg)
{
	show_state_t	*state = arg;
	dladm_status_t	status;
	link_fields_buf_t	pattr;

	status = print_phys(state, linkid, &pattr);
	if (status != DLADM_STATUS_OK)
		goto done;

	if (!state->ls_parseable && !state->ls_printheader) {
		print_header(&state->ls_print);
		state->ls_printheader = B_TRUE;
	}

	dladm_print_output(&state->ls_print, state->ls_parseable,
	    dladm_print_field, (void *)&pattr);

done:
	state->ls_status = status;
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
	(void) snprintf(l->link_flags, sizeof (l->link_flags), "%c%c---",
	    vinfo.dv_force ? 'f' : '-', vinfo.dv_implicit ? 'i' : '-');

done:
	return (status);
}

static int
show_vlan(datalink_id_t linkid, void *arg)
{
	show_state_t	*state = arg;
	dladm_status_t	status;
	link_fields_buf_t	lbuf;

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
do_show_phys(int argc, char *argv[])
{
	int		option;
	uint32_t	flags = DLADM_OPT_ACTIVE;
	boolean_t	p_arg = B_FALSE;
	boolean_t	o_arg = B_FALSE;
	datalink_id_t	linkid = DATALINK_ALL_LINKID;
	show_state_t	state;
	dladm_status_t	status;
	char			*fields_str = NULL;
	print_field_t		**fields;
	uint_t			nfields;
	char			*all_active_fields =
	    "link,media,state,speed,duplex,device";
	char			*all_inactive_fields =
	    "link,device,media,flags";

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

	if (!o_arg || (o_arg && strcasecmp(fields_str, "all") == 0)) {
		if (state.ls_flags & DLADM_OPT_ACTIVE)
			fields_str = all_active_fields;
		else
			fields_str = all_inactive_fields;
	}

	fields = parse_output_fields(fields_str, phys_fields,
	    PHYS_MAX_FIELDS, CMD_TYPE_ANY, &nfields);

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
do_show_vlan(int argc, char *argv[])
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
dev_stats(const char *dev, uint32_t interval, char *fields_str,
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

	for (;;) {

		if (!state->ls_parseable)
			print_header(&state->ls_print);
		state->ls_donefirst = B_FALSE;

		if (dev == NULL)
			(void) dladm_mac_walk(show_dev_stats, state);
		else
			(void) show_dev_stats(dev, state);

		if (interval == 0)
			break;

		(void) sleep(interval);
	}

	if (dev != NULL && state->ls_status != DLADM_STATUS_OK)
		die_dlerr(state->ls_status, "cannot show device '%s'", dev);
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

	if (dladm_kstat_value(ksp, "ipackets64", KSTAT_DATA_UINT64,
	    &stats->ipackets) < 0)
		goto bail;

	if (dladm_kstat_value(ksp, "opackets64", KSTAT_DATA_UINT64,
	    &stats->opackets) < 0)
		goto bail;

	if (dladm_kstat_value(ksp, "rbytes64", KSTAT_DATA_UINT64,
	    &stats->rbytes) < 0)
		goto bail;

	if (dladm_kstat_value(ksp, "obytes64", KSTAT_DATA_UINT64,
	    &stats->obytes) < 0)
		goto bail;

	if (dladm_kstat_value(ksp, "ierrors", KSTAT_DATA_UINT32,
	    &stats->ierrors) < 0)
		goto bail;

	if (dladm_kstat_value(ksp, "oerrors", KSTAT_DATA_UINT32,
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
	uint_t	valwidth = strlen(value);
	uint_t	compress;

	if (parseable) {
		(void) printf("%s=\"%s\"", pfp->pf_header, value);
	} else {
		if (value[0] == '\0')
			value = STR_UNDEF_VAL;
		if (statep->ps_lastfield) {
			(void) printf("%s", value);
			return;
		}

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
do_display_wifi(int argc, char **argv, int cmd)
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

	/*
	 * buf is a string of form [<propname>=<value>][,<propname>=<value>]+
	 * where each <value> string itself could be a comma-separated array.
	 * The loop below will count the number of propname assignments
	 * in pl_count; for each property, there is a pip entry with
	 * pi_name == <propname>, pi_count == # of elements in <value> array.
	 * pi_val[] contains the actual values.
	 *
	 * This could really be a combination of  calls to
	 * strtok (token delimiter is ",") and strchr (chr '=')
	 * with appropriate null/string-bound-checks.
	 */

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
print_linkprop(datalink_id_t linkid, show_linkprop_state_t *statep,
    const char *propname, dladm_prop_type_t type,
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
				statep->ls_retstatus = status;
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
	dladm_print_output(&statep->ls_print, statep->ls_parseable,
	    linkprop_callback, (void *)&ls_arg);

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
	char			*fields_str = NULL;
	print_field_t		**fields;
	uint_t			nfields;
	char			*all_fields =
	    "link,property,value,default,possible";

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
		case 'o':
			if (strcasecmp(optarg, "all") == 0)
				fields_str = all_fields;
			else
				fields_str = optarg;
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
	free_props(proplist);

	if (state.ls_retstatus != DLADM_STATUS_OK)
		exit(EXIT_FAILURE);
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
		status = dladm_set_linkprop(linkid, NULL, NULL, 0,
		    DLADM_OPT_ACTIVE);
		if (status != DLADM_STATUS_OK) {
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
do_show_secobj(int argc, char **argv)
{
	int			option;
	show_secobj_state_t	state;
	dladm_status_t		status;
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
			if (strcasecmp(optarg, "all") == 0)
				fields_str = all_fields;
			else
				fields_str = optarg;
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

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
do_show_ether(int argc, char **argv)
{
	int 			option;
	datalink_id_t		linkid;
	print_ether_state_t 	state;
	print_field_t 		**fields;
	char			*fields_str;
	uint_t			nfields;
	char *all_fields =
	    "link,ptype,state,auto,speed-duplex,pause,rem_fault";
	char *default_fields =
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
				if (strcasecmp(optarg, "all") == 0)
					fields_str = all_fields;
				else
					fields_str = optarg;
				break;
			default:
				die_opterr(optopt, option);
				break;
		}
	}

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
	print_ether_state_t *statep = arg;
	char buf[DLADM_STRSIZE];
	int speed;
	uint64_t s;
	uint32_t autoneg, pause, asmpause, adv_rf, cap_rf, lp_rf;
	ether_fields_buf_t ebuf;
	char speed_unit = 'M';

	if (dladm_datalink_id2info(linkid, NULL, NULL, NULL,
	    ebuf.eth_link, sizeof (ebuf.eth_link)) != DLADM_STATUS_OK) {
		return (DLADM_WALK_CONTINUE);
	}

	if (!statep->es_header && !statep->es_parseable) {
		print_header(&statep->es_print);
		statep->es_header = B_TRUE;
	}
	(void) snprintf(ebuf.eth_ptype, sizeof (ebuf.eth_ptype),
	    "%s", "current");

	(void) dladm_get_single_mac_stat(linkid, "link_autoneg",
	    KSTAT_DATA_UINT32, &autoneg);
	(void) snprintf(ebuf.eth_autoneg, sizeof (ebuf.eth_autoneg),
	    "%s", (autoneg ? "yes" : "no"));

	(void) dladm_get_single_mac_stat(linkid, "link_pause",
	    KSTAT_DATA_UINT32, &pause);
	(void) dladm_get_single_mac_stat(linkid, "link_asmpause",
	    KSTAT_DATA_UINT32, &asmpause);
	(void) snprintf(ebuf.eth_pause, sizeof (ebuf.eth_pause),
	    "%s", pause_str(pause, asmpause));

	(void) dladm_get_single_mac_stat(linkid, "ifspeed",
	    KSTAT_DATA_UINT64, &s);
	speed = (int)(s/1000000ull);

	if (speed >= 1000) {
		speed = speed/1000;
		speed_unit = 'G';
	}
	(void) get_linkduplex(ebuf.eth_link, B_FALSE, buf);
	(void) snprintf(ebuf.eth_spdx, sizeof (ebuf.eth_spdx), "%d%c-%c",
	    speed, speed_unit, buf[0]);

	(void) get_linkstate(ebuf.eth_link, B_FALSE, buf);
	(void) snprintf(ebuf.eth_state, sizeof (ebuf.eth_state),
	    "%s", buf);

	(void) dladm_get_single_mac_stat(linkid, "adv_rem_fault",
	    KSTAT_DATA_UINT32, &adv_rf);
	(void) dladm_get_single_mac_stat(linkid, "cap_rem_fault",
	    KSTAT_DATA_UINT32, &cap_rf);
	(void) dladm_get_single_mac_stat(linkid, "lp_rem_fault",
	    KSTAT_DATA_UINT32, &lp_rf);
	(void) snprintf(ebuf.eth_rem_fault, sizeof (ebuf.eth_rem_fault),
	    "%s", (adv_rf == 0 && lp_rf == 0 ? "none" : "fault"));

	dladm_print_output(&statep->es_print, statep->es_parseable,
	    dladm_print_field, &ebuf);

	if (statep->es_extended)
		show_ether_xprop(linkid, arg);

	return (DLADM_WALK_CONTINUE);
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

static void
show_ether_xprop(datalink_id_t linkid, void *arg)
{
	print_ether_state_t *statep = arg;
	char buf[DLADM_STRSIZE];
	uint32_t autoneg, pause, asmpause, adv_rf, cap_rf, lp_rf;
	boolean_t add_comma, r1;
	ether_fields_buf_t ebuf;

	/* capable */
	bzero(&ebuf, sizeof (ebuf));
	(void) snprintf(ebuf.eth_link, sizeof (ebuf.eth_link), "");

	(void) snprintf(ebuf.eth_ptype, sizeof (ebuf.eth_ptype),
	    "%s", "capable");
	(void) snprintf(ebuf.eth_state, sizeof (ebuf.eth_state),
	    STR_UNDEF_VAL);

	(void) dladm_get_single_mac_stat(linkid, "cap_autoneg",
	    KSTAT_DATA_UINT32, &autoneg);
	(void) snprintf(ebuf.eth_autoneg, sizeof (ebuf.eth_autoneg),
	    "%s", (autoneg ? "yes" : "no"));

	add_comma = B_FALSE;
	bzero(buf, sizeof (buf));
	r1 = get_speed_duplex(linkid, "cap_1000", buf, "1G", B_FALSE);
	if (r1)
		add_comma = B_TRUE;
	r1 = get_speed_duplex(linkid, "cap_100", buf, "100M", add_comma);
	if (r1)
		add_comma = B_TRUE;
	r1 = get_speed_duplex(linkid, "cap_10", buf, "10M", add_comma);
	add_comma = B_FALSE;
	(void) snprintf(ebuf.eth_spdx, sizeof (ebuf.eth_spdx), "%s", buf);

	(void) dladm_get_single_mac_stat(linkid, "cap_pause",
	    KSTAT_DATA_UINT32, &pause);
	(void) dladm_get_single_mac_stat(linkid, "cap_asmpause",
	    KSTAT_DATA_UINT32, &asmpause);
	(void) snprintf(ebuf.eth_pause, sizeof (ebuf.eth_pause),
	    "%s", pause_str(pause, asmpause));

	(void) dladm_get_single_mac_stat(linkid, "adv_rem_fault",
	    KSTAT_DATA_UINT32, &adv_rf);
	(void) dladm_get_single_mac_stat(linkid, "cap_rem_fault",
	    KSTAT_DATA_UINT32, &cap_rf);
	(void) dladm_get_single_mac_stat(linkid, "lp_rem_fault",
	    KSTAT_DATA_UINT32, &lp_rf);

	(void) snprintf(ebuf.eth_rem_fault, sizeof (ebuf.eth_rem_fault),
	    "%s", (cap_rf ? "yes" : "no"));

	dladm_print_output(&statep->es_print, statep->es_parseable,
	    dladm_print_field, &ebuf);

	/* advertised */
	bzero(&ebuf, sizeof (ebuf));
	(void) snprintf(ebuf.eth_ptype, sizeof (ebuf.eth_ptype),
	    "%s", "adv");
	(void) snprintf(ebuf.eth_state, sizeof (ebuf.eth_state),
	    STR_UNDEF_VAL);

	(void) dladm_get_single_mac_stat(linkid, "adv_cap_autoneg",
	    KSTAT_DATA_UINT32, &autoneg);
	(void) snprintf(ebuf.eth_autoneg, sizeof (ebuf.eth_autoneg),
	    "%s", (autoneg ? "yes" : "no"));

	add_comma = B_FALSE;
	bzero(buf, sizeof (buf));
	r1 = get_speed_duplex(linkid, "adv_cap_1000", buf, "1G", add_comma);
	if (r1)
		add_comma = B_TRUE;
	r1 = get_speed_duplex(linkid, "adv_cap_100", buf, "100M", add_comma);
	if (r1)
		add_comma = B_TRUE;
	r1 = get_speed_duplex(linkid, "adv_cap_10", buf, "10M", add_comma);
	add_comma = B_FALSE;
	(void) snprintf(ebuf.eth_spdx, sizeof (ebuf.eth_spdx), "%s", buf);

	(void) dladm_get_single_mac_stat(linkid, "adv_cap_pause",
	    KSTAT_DATA_UINT32, &pause);
	(void) dladm_get_single_mac_stat(linkid, "adv_cap_asmpause",
	    KSTAT_DATA_UINT32, &asmpause);
	(void) snprintf(ebuf.eth_pause, sizeof (ebuf.eth_pause),
	    "%s", pause_str(pause, asmpause));

	(void) snprintf(ebuf.eth_rem_fault, sizeof (ebuf.eth_rem_fault),
	    "%s", (adv_rf ? "fault" : "none"));

	dladm_print_output(&statep->es_print, statep->es_parseable,
	    dladm_print_field, &ebuf);

	/* peeradv */
	bzero(&ebuf, sizeof (ebuf));
	(void) snprintf(ebuf.eth_ptype, sizeof (ebuf.eth_ptype),
	    "%s", "peeradv");
	(void) snprintf(ebuf.eth_state, sizeof (ebuf.eth_state),
	    STR_UNDEF_VAL);

	(void) dladm_get_single_mac_stat(linkid, "lp_cap_autoneg",
	    KSTAT_DATA_UINT32, &autoneg);
	(void) snprintf(ebuf.eth_autoneg, sizeof (ebuf.eth_autoneg),
	    "%s", (autoneg ? "yes" : "no"));

	add_comma = B_FALSE;
	bzero(buf, sizeof (buf));
	r1 = get_speed_duplex(linkid, "lp_cap_1000", buf, "1G", add_comma);
	if (r1)
		add_comma = B_TRUE;
	r1 = get_speed_duplex(linkid, "lp_cap_100", buf, "100M", add_comma);
	if (r1)
		add_comma = B_TRUE;
	r1 = get_speed_duplex(linkid, "lp_cap_10", buf, "10M", add_comma);
	(void) snprintf(ebuf.eth_spdx, sizeof (ebuf.eth_spdx), "%s", buf);

	(void) dladm_get_single_mac_stat(linkid, "lp_cap_pause",
	    KSTAT_DATA_UINT32, &pause);
	(void) dladm_get_single_mac_stat(linkid, "lp_cap_asmpause",
	    KSTAT_DATA_UINT32, &asmpause);
	(void) snprintf(ebuf.eth_pause, sizeof (ebuf.eth_pause),
	    "%s", pause_str(pause, asmpause));

	(void) snprintf(ebuf.eth_rem_fault, sizeof (ebuf.eth_rem_fault),
	    "%s", (lp_rf ? "fault" : "none"));

	dladm_print_output(&statep->es_print, statep->es_parseable,
	    dladm_print_field, &ebuf);
}

static boolean_t
get_speed_duplex(datalink_id_t linkid, const char *mii_prop_prefix,
    char *spbuf, char *sp, boolean_t add_comma)
{
	int speed, duplex = 0;
	boolean_t ret = B_FALSE;
	char mii_prop[DLADM_STRSIZE];

	(void) snprintf(mii_prop, DLADM_STRSIZE, "%sfdx", mii_prop_prefix);
	(void) dladm_get_single_mac_stat(linkid, mii_prop, KSTAT_DATA_UINT32,
	    &speed);
	if (speed) {
		ret = B_TRUE;
		duplex  |= IS_FDX;
	}
	(void) snprintf(mii_prop, DLADM_STRSIZE, "%shdx", mii_prop_prefix);
	(void) dladm_get_single_mac_stat(linkid, mii_prop,
	    KSTAT_DATA_UINT32, &speed);
	if (speed) {
		ret = B_TRUE;
		duplex |= IS_HDX;
	}
	if (ret) {
		if (add_comma)
			(void) strncat(spbuf, ",", DLADM_STRSIZE);
		(void) strncat(spbuf, sp, DLADM_STRSIZE);
		if ((duplex & (IS_FDX|IS_HDX)) == (IS_FDX|IS_HDX))
			(void) strncat(spbuf, "-fh", DLADM_STRSIZE);
		else if (duplex & IS_FDX)
			(void) strncat(spbuf, "-f", DLADM_STRSIZE);
		else if (duplex & IS_HDX)
			(void) strncat(spbuf, "-h", DLADM_STRSIZE);
	}
	return (ret);
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

static char *
pause_str(int pause, int asmpause)
{
	if (pause == 1)
		return ("bi");
	if (asmpause == 1)
		return ("tx");
	return ("none");
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

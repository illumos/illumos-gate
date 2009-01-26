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
#include <netdb.h>
#include <libintl.h>
#include <libdlflow.h>
#include <libdllink.h>
#include <libdlstat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ethernet.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <stddef.h>

#define	CMD_TYPE_ANY	0xffffffff
#define	STR_UNDEF_VAL	"--"


/*
 * data structures and routines for printing output.
 */

typedef struct print_field_s {
	const char	*pf_name;
	const char	*pf_header;
	uint_t		pf_width;
	union {
		uint_t	_pf_index;
		size_t	_pf_offset;
	}_pf_un;
#define	pf_index	_pf_un._pf_index
#define	pf_offset	_pf_un._pf_offset;
	uint_t	pf_cmdtype;
} print_field_t;

typedef struct print_state_s {
	print_field_t	**ps_fields;
	uint_t		ps_nfields;
	boolean_t	ps_lastfield;
	uint_t		ps_overflow;
} print_state_t;

typedef struct show_usage_state_s {
	boolean_t	us_plot;
	boolean_t	us_parseable;
	boolean_t	us_printheader;
	boolean_t	us_first;
	print_state_t	us_print;
} show_usage_state_t;

typedef char *(*print_callback_t)(print_field_t *, void *);
static print_field_t **parse_output_fields(char *, print_field_t *, int,
    uint_t, uint_t *);

static void print_header(print_state_t *);
static void print_field(print_state_t *, print_field_t *, const char *,
    boolean_t);

static void flowadm_print_output(print_state_t *, boolean_t,
    print_callback_t, void *);

/*
 * helper function that, when invoked as flowadm(print_field(pf, buf)
 * prints string which is offset by pf->pf_offset within buf.
 */
static char *flowadm_print_field(print_field_t *, void *);

#define	MAX_FIELD_LEN	32

typedef void cmdfunc_t(int, char **);

static cmdfunc_t do_add_flow, do_remove_flow, do_init_flow, do_show_flow;
static cmdfunc_t do_show_flowprop, do_set_flowprop, do_reset_flowprop;
static cmdfunc_t do_show_usage;

static int	show_flow(dladm_flow_attr_t *, void *);
static int	show_flows_onelink(dladm_handle_t, datalink_id_t, void *);

static void	flow_stats(const char *, datalink_id_t,  uint_t);
static void	get_flow_stats(const char *, pktsum_t *);
static int	show_flow_stats(dladm_flow_attr_t *, void *);
static int	show_link_flow_stats(dladm_handle_t, datalink_id_t, void *);

static int	remove_flow(dladm_flow_attr_t *, void *);

static int	show_flowprop(dladm_flow_attr_t *, void *);
static void	show_flowprop_one_flow(void *, const char *);
static int	show_flowprop_onelink(dladm_handle_t, datalink_id_t, void *);

static void	die(const char *, ...);
static void	die_optdup(int);
static void	die_opterr(int, int);
static void	die_dlerr(dladm_status_t, const char *, ...);
static void	warn(const char *, ...);
static void	warn_dlerr(dladm_status_t, const char *, ...);

typedef struct	cmd {
	char	*c_name;
	void	(*c_fn)(int, char **);
} cmd_t;

static cmd_t	cmds[] = {
	{ "add-flow", do_add_flow },
	{ "remove-flow", do_remove_flow },
	{ "show-flowprop", do_show_flowprop },
	{ "set-flowprop", do_set_flowprop },
	{ "reset-flowprop", do_reset_flowprop },
	{ "show-flow", do_show_flow },
	{ "init-flow", do_init_flow },
	{ "show-usage", do_show_usage }
};

static const struct option longopts[] = {
	{"link",		required_argument,	0, 'l'},
	{"parseable",		no_argument,		0, 'p'},
	{"statistics",		no_argument,		0, 's'},
	{"interval",		required_argument,	0, 'i'},
	{"temporary",		no_argument,		0, 't'},
	{"root-dir",		required_argument,	0, 'R'},
	{ 0, 0, 0, 0 }
};

static const struct option prop_longopts[] = {
	{"link",		required_argument,	0, 'l'},
	{"temporary",		no_argument,		0, 't'},
	{"root-dir",		required_argument,	0, 'R'},
	{"prop",		required_argument,	0, 'p'},
	{"attr",		required_argument,	0, 'a'},
	{ 0, 0, 0, 0 }
};

/*
 * structures for 'flowadm show-flow'
 */

typedef struct show_flow_state {
	boolean_t		fs_firstonly;
	boolean_t		fs_donefirst;
	pktsum_t		fs_prevstats;
	uint32_t		fs_flags;
	dladm_status_t		fs_status;
	print_state_t		fs_print;
	const char		*fs_flow;
	const char		*fs_link;
	boolean_t		fs_parseable;
	boolean_t		fs_printheader;
	boolean_t		fs_persist;
	boolean_t		fs_stats;
	uint64_t		fs_mask;
} show_flow_state_t;

/*
 * structures for 'flowadm remove-flow'
 */

typedef struct remove_flow_state {
	boolean_t	fs_tempop;
	const char	*fs_altroot;
	dladm_status_t	fs_status;
} remove_flow_state_t;

typedef struct flow_args_s {
	const char		*fa_link;
	int			fa_attrno;	/* -1 indicates flow itself */
	uint64_t		fa_mask;
	dladm_flow_attr_t	*fa_finfop;
	dladm_status_t		*fa_status;
	boolean_t		fa_parseable;
} flow_args_t;

#define	PROTO_MAXSTR_LEN	7
#define	PORT_MAXSTR_LEN		6
#define	DSFIELD_MAXSTR_LEN	10

typedef struct flow_fields_buf_s
{
	char flow_name[MAXFLOWNAMELEN];
	char flow_link[MAXLINKNAMELEN];
	char flow_ipaddr[INET6_ADDRSTRLEN+4];
	char flow_proto[PROTO_MAXSTR_LEN];
	char flow_port[PORT_MAXSTR_LEN];
	char flow_dsfield[DSFIELD_MAXSTR_LEN];
} flow_fields_buf_t;

static print_field_t flow_fields[] = {
/* name,	header,		field width,	index,		cmdtype	*/
{  "flow",	"FLOW",		11,
    offsetof(flow_fields_buf_t, flow_name),	CMD_TYPE_ANY},
{  "link",	"LINK",		11,
    offsetof(flow_fields_buf_t, flow_link),	CMD_TYPE_ANY},
{  "ipaddr",	"IPADDR",	30,
    offsetof(flow_fields_buf_t, flow_ipaddr),	CMD_TYPE_ANY},
{  "proto",	"PROTO",	6,
    offsetof(flow_fields_buf_t, flow_proto),	CMD_TYPE_ANY},
{  "port",	 "PORT",	7,
    offsetof(flow_fields_buf_t, flow_port),	CMD_TYPE_ANY},
{  "dsfld",	"DSFLD",	9,
    offsetof(flow_fields_buf_t, flow_dsfield),	CMD_TYPE_ANY}}
;

#define	FLOW_MAX_FIELDS		(sizeof (flow_fields) / sizeof (print_field_t))

/*
 * structures for 'flowadm show-flowprop'
 */
typedef enum {
	FLOWPROP_FLOW,
	FLOWPROP_PROPERTY,
	FLOWPROP_VALUE,
	FLOWPROP_DEFAULT,
	FLOWPROP_POSSIBLE
} flowprop_field_index_t;

static print_field_t flowprop_fields[] = {
/* name,	header,		fieldwidth,	index,		cmdtype */
{ "flow",	"FLOW",		12,	FLOWPROP_FLOW,		CMD_TYPE_ANY},
{ "property",	"PROPERTY",	15,	FLOWPROP_PROPERTY,	CMD_TYPE_ANY},
{ "value",	"VALUE",	14,	FLOWPROP_VALUE,		CMD_TYPE_ANY},
{ "default",	"DEFAULT",	14,	FLOWPROP_DEFAULT,	CMD_TYPE_ANY},
{ "possible",	"POSSIBLE",	20,	FLOWPROP_POSSIBLE,	CMD_TYPE_ANY}}
;
#define	FLOWPROP_MAX_FIELDS					\
	(sizeof (flowprop_fields) / sizeof (print_field_t))

#define	MAX_PROP_LINE		512

typedef struct show_flowprop_state {
	const char		*fs_flow;
	datalink_id_t		fs_linkid;
	char			*fs_line;
	char			**fs_propvals;
	dladm_arg_list_t	*fs_proplist;
	boolean_t		fs_parseable;
	boolean_t		fs_persist;
	boolean_t		fs_header;
	dladm_status_t		fs_status;
	dladm_status_t		fs_retstatus;
	print_state_t		fs_print;
} show_flowprop_state_t;

typedef struct set_flowprop_state {
	const char	*fs_name;
	boolean_t	fs_reset;
	boolean_t	fs_temp;
	dladm_status_t	fs_status;
} set_flowprop_state_t;

typedef struct flowprop_args_s {
	show_flowprop_state_t	*fs_state;
	char			*fs_propname;
	char			*fs_flowname;
} flowprop_args_t;

/*
 * structures for 'flow show-usage'
 */

typedef struct  usage_fields_buf_s {
	char	usage_flow[12];
	char	usage_duration[10];
	char	usage_ipackets[9];
	char	usage_rbytes[10];
	char	usage_opackets[9];
	char	usage_obytes[10];
	char	usage_bandwidth[14];
} usage_fields_buf_t;

static print_field_t usage_fields[] = {
/* name,	header,		field width,	offset,	cmdtype		*/
{ "flow",	"FLOW",			12,
    offsetof(usage_fields_buf_t, usage_flow),		CMD_TYPE_ANY},
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
	char	usage_l_flow[12];
	char	usage_l_stime[13];
	char	usage_l_etime[13];
	char	usage_l_rbytes[8];
	char	usage_l_obytes[8];
	char	usage_l_bandwidth[14];
} usage_l_fields_buf_t;

static print_field_t usage_l_fields[] = {
/* name,	header,		field width,	offset,	cmdtype		*/
{ "flow",	"FLOW",		12,
    offsetof(usage_l_fields_buf_t, usage_l_flow),	CMD_TYPE_ANY},
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

#define	PRI_HI		100
#define	PRI_LO 		10
#define	PRI_NORM	50

#define	FLOWADM_CONF	"/etc/dladm/flowadm.conf"
#define	BLANK_LINE(s)	((s[0] == '\0') || (s[0] == '#') || (s[0] == '\n'))

static char *progname;

boolean_t		t_arg = B_FALSE; /* changes are persistent */
char			*altroot = NULL;

/*
 * Handle to libdladm.  Opened in main() before the sub-command
 * specific function is called.
 */
static dladm_handle_t handle = NULL;

static const char *attr_table[] =
	{"local_ip", "remote_ip", "transport", "local_port", "dsfield"};

#define	NATTR	(sizeof (attr_table)/sizeof (char *))

static void
usage(void)
{
	(void) fprintf(stderr, gettext("usage: flowadm <subcommand>"
	    " <args>...\n"
	    "    add-flow       [-t] -l <link> -a <attr>=<value>[,...]\n"
	    "\t\t   [-p <prop>=<value>,...] <flow>\n"
	    "    remove-flow    [-t] {-l <link> | <flow>}\n"
	    "    show-flow      [-p] [-s [-i <interval>]] [-l <link>] "
	    "[<flow>]\n\n"
	    "    set-flowprop   [-t] -p <prop>=<value>[,...] <flow>\n"
	    "    reset-flowprop [-t] [-p <prop>,...] <flow>\n"
	    "    show-flowprop  [-cP] [-l <link>] [-p <prop>,...] "
	    "[<flow>]\n\n"
	    "    show-usage     [-d|-p -F <format>] "
	    "[-s <DD/MM/YYYY,HH:MM:SS>]\n"
	    "\t\t   [-e <DD/MM/YYYY,HH:MM:SS>] -f <logfile> [<flow>]\n"));

	/* close dladm handle if it was opened */
	if (handle != NULL)
		dladm_close(handle);

	exit(1);
}

int
main(int argc, char *argv[])
{
	int	i, arglen, cmdlen;
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
		arglen = strlen(argv[1]);
		cmdlen = strlen(cmdp->c_name);
		if ((arglen == cmdlen) && (strncmp(argv[1], cmdp->c_name,
		    cmdlen) == 0)) {
			/* Open the libdladm handle */
			if ((status = dladm_open(&handle)) != DLADM_STATUS_OK) {
				die_dlerr(status,
				    "could not open /dev/dld");
			}

			cmdp->c_fn(argc - 1, &argv[1]);

			dladm_close(handle);
			exit(EXIT_SUCCESS);
		}
	}

	(void) fprintf(stderr, gettext("%s: unknown subcommand '%s'\n"),
	    progname, argv[1]);
	usage();

	return (0);
}

static const char *
match_attr(char *attr)
{
	int i;

	for (i = 0; i < NATTR; i++) {
		if (strlen(attr) == strlen(attr_table[i]) &&
		    strncmp(attr, attr_table[i], strlen(attr_table[i])) == 0) {
			return (attr);
		}
	}
	return (NULL);
}

/* ARGSUSED */
static void
do_init_flow(int argc, char *argv[])
{
	dladm_status_t status;

	status = dladm_flow_init(handle);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "flows initialization failed");
}

/* ARGSUSED */
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

	(void) snprintf(ubuf.usage_l_flow, sizeof (ubuf.usage_l_flow), "%s",
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

	flowadm_print_output(&state->us_print, state->us_parseable,
	    flowadm_print_field, (void *)&ubuf);

	return (DLADM_STATUS_OK);
}

static int
show_usage_res(dladm_usage_t *usage, void *arg)
{
	show_usage_state_t	*state = (show_usage_state_t *)arg;
	char			buf[DLADM_STRSIZE];
	usage_fields_buf_t	ubuf;

	bzero(&ubuf, sizeof (ubuf));

	(void) snprintf(ubuf.usage_flow, sizeof (ubuf.usage_flow), "%s",
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

	flowadm_print_output(&state->us_print, state->us_parseable,
	    flowadm_print_field, (void *)&ubuf);

	return (DLADM_STATUS_OK);
}

static boolean_t
valid_formatspec(char *formatspec_str)
{
	if (strcmp(formatspec_str, "gnuplot") == 0)
		return (B_TRUE);
	return (B_FALSE);
}

/* ARGSUSED */
static void
do_show_usage(int argc, char *argv[])
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
	    "flow,duration,ipackets,rbytes,opackets,obytes,bandwidth";
	char			*all_l_fields =
	    "flow,start,end,rbytes,obytes,bandwidth";

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
			die_opterr(optopt, opt);
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
		    DLADM_LOGTYPE_FLOW, file, resource, &state);
	} else if (resource == NULL && stime == NULL && etime == NULL &&
	    !p_arg) {
		/* Print summary */
		status = dladm_usage_summary(show_usage_res,
		    DLADM_LOGTYPE_FLOW, file, &state);
	} else if (resource != NULL) {
		/* Print log entries for named resource */
		status = dladm_walk_usage_res(show_usage_time,
		    DLADM_LOGTYPE_FLOW, file, resource, stime, etime, &state);
	} else {
		/* Print time and information for each link */
		status = dladm_walk_usage_time(show_usage_time,
		    DLADM_LOGTYPE_FLOW, file, stime, etime, &state);
	}

	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "show-usage");
}

static void
do_add_flow(int argc, char *argv[])
{
	char			devname[MAXLINKNAMELEN];
	char			*name = NULL;
	uint_t			index;
	datalink_id_t		linkid;

	char			option;
	boolean_t		l_arg = B_FALSE;
	dladm_arg_list_t	*proplist = NULL;
	dladm_arg_list_t	*attrlist = NULL;
	dladm_status_t		status;

	while ((option = getopt_long(argc, argv, "tR:l:a:p:",
	    prop_longopts, NULL)) != -1) {
		switch (option) {
		case 't':
			t_arg = B_TRUE;
			break;
		case 'R':
			altroot = optarg;
			break;
		case 'l':
			if (strlcpy(devname, optarg,
			    MAXLINKNAMELEN) >= MAXLINKNAMELEN) {
				die("link name too long");
			}
			if (dladm_name2info(handle, devname, &linkid, NULL,
			    NULL, NULL) != DLADM_STATUS_OK)
				die("invalid link '%s'", devname);
			l_arg = B_TRUE;
			break;
		case 'a':
			if (dladm_parse_flow_attrs(optarg, &attrlist, B_FALSE)
			    != DLADM_STATUS_OK)
				die("invalid flow attribute specified");
			break;
		case 'p':
			if (dladm_parse_flow_props(optarg, &proplist, B_FALSE)
			    != DLADM_STATUS_OK)
				die("invalid flow property specified");
			break;
		default:
			die_opterr(optopt, option);
		}
	}
	if (!l_arg) {
		die("link is required");
	}

	opterr = 0;
	index = optind;

	if ((index != (argc - 1)) || match_attr(argv[index]) != NULL) {
		die("flow name is required");
	} else {
		/* get flow name; required last argument */
		if (strlen(argv[index]) >= MAXFLOWNAMELEN)
			die("flow name too long");
		name = argv[index];
	}

	status = dladm_flow_add(handle, linkid, attrlist, proplist, name,
	    t_arg, altroot);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "add flow failed");

	dladm_free_attrs(attrlist);
	dladm_free_props(proplist);
}

static void
do_remove_flow(int argc, char *argv[])
{
	char			option;
	char			*flowname = NULL;
	char			linkname[MAXLINKNAMELEN];
	datalink_id_t		linkid = DATALINK_ALL_LINKID;
	boolean_t		l_arg = B_FALSE;
	remove_flow_state_t	state;
	dladm_status_t		status;

	bzero(&state, sizeof (state));

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":tR:l:",
	    longopts, NULL)) != -1) {
		switch (option) {
		case 't':
			t_arg = B_TRUE;
			break;
		case 'R':
			altroot = optarg;
			break;
		case 'l':
			if (strlcpy(linkname, optarg,
			    MAXLINKNAMELEN) >= MAXLINKNAMELEN) {
				die("link name too long");
			}
			if (dladm_name2info(handle, linkname, &linkid, NULL,
			    NULL, NULL) != DLADM_STATUS_OK) {
				die("invalid link '%s'", linkname);
			}
			l_arg = B_TRUE;
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	/* when link not specified get flow name */
	if (!l_arg) {
		if (optind != (argc-1)) {
			usage();
		} else {
			if (strlen(argv[optind]) >= MAXFLOWNAMELEN)
				die("flow name too long");
			flowname = argv[optind];
		}
		status = dladm_flow_remove(handle, flowname, t_arg, altroot);
	} else {
		/* if link is specified then flow name should not be there */
		if (optind == argc-1)
			usage();
		/* walk the link to find flows and remove them */
		state.fs_tempop = t_arg;
		state.fs_altroot = altroot;
		state.fs_status = DLADM_STATUS_OK;
		status = dladm_walk_flow(remove_flow, handle, linkid, &state,
		    B_FALSE);
		/*
		 * check if dladm_walk_flow terminated early and see if the
		 * walker function as any status for us
		 */
		if (status == DLADM_STATUS_OK)
			status = state.fs_status;
	}

	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "remove flow failed");
}

/*
 * Walker function for removing a flow through dladm_walk_flow();
 */
static int
remove_flow(dladm_flow_attr_t *attr, void *arg)
{
	remove_flow_state_t	*state = (remove_flow_state_t *)arg;

	state->fs_status = dladm_flow_remove(handle, attr->fa_flowname,
	    state->fs_tempop, state->fs_altroot);

	if (state->fs_status == DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);
	else
		return (DLADM_WALK_TERMINATE);
}

static char *
flowadm_print_field(print_field_t *pf, void *arg)
{
	char *value;

	value = (char *)arg + pf->pf_offset;
	return (value);
}

/*ARGSUSED*/
static dladm_status_t
print_flow(show_flow_state_t *state, dladm_flow_attr_t *attr,
    flow_fields_buf_t *fbuf)
{
	char		link[MAXLINKNAMELEN];
	dladm_status_t	status;

	if ((status = dladm_datalink_id2info(handle, attr->fa_linkid, NULL,
	    NULL, NULL, link, sizeof (link))) != DLADM_STATUS_OK) {
		return (status);
	}

	(void) snprintf(fbuf->flow_name, sizeof (fbuf->flow_name),
	    "%s", attr->fa_flowname);
	(void) snprintf(fbuf->flow_link, sizeof (fbuf->flow_link),
	    "%s", link);

	(void) dladm_flow_attr_ip2str(attr, fbuf->flow_ipaddr,
	    sizeof (fbuf->flow_ipaddr));
	(void) dladm_flow_attr_proto2str(attr, fbuf->flow_proto,
	    sizeof (fbuf->flow_proto));
	(void) dladm_flow_attr_port2str(attr, fbuf->flow_port,
	    sizeof (fbuf->flow_port));
	(void) dladm_flow_attr_dsfield2str(attr, fbuf->flow_dsfield,
	    sizeof (fbuf->flow_dsfield));

	return (DLADM_STATUS_OK);
}

/*
 * Walker function for showing flow attributes through dladm_walk_flow().
 */
static int
show_flow(dladm_flow_attr_t *attr, void *arg)
{
	show_flow_state_t	*statep = arg;
	dladm_status_t		status;
	flow_fields_buf_t	fbuf;

	/*
	 * first get all the flow attributes into fbuf;
	 */
	bzero(&fbuf, sizeof (fbuf));
	status = print_flow(statep, attr, &fbuf);

	if (status != DLADM_STATUS_OK)
		goto done;

	if (!statep->fs_parseable && !statep->fs_printheader) {
		print_header(&statep->fs_print);
		statep->fs_printheader = B_TRUE;
	}

	flowadm_print_output(&statep->fs_print, statep->fs_parseable,
	    flowadm_print_field, (void *)&fbuf);

done:
	statep->fs_status = status;
	return (DLADM_WALK_CONTINUE);
}

static void
show_one_flow(void *arg, const char *name)
{
	dladm_flow_attr_t	attr;

	if (dladm_flow_info(handle, name, &attr) != DLADM_STATUS_OK)
		die("invalid flow: '%s'", name);
	else
		(void) show_flow(&attr, arg);
}

/*
 * Wrapper of dladm_walk_flow(show_flow,...) to make it usable to
 * dladm_walk_datalink_id(). Used for showing flow attributes for
 * all flows on all links.
 */
static int
show_flows_onelink(dladm_handle_t dh, datalink_id_t linkid, void *arg)
{
	show_flow_state_t *state = arg;

	(void) dladm_walk_flow(show_flow, dh, linkid, arg, state->fs_persist);

	return (DLADM_WALK_CONTINUE);
}

static void
get_flow_stats(const char *flowname, pktsum_t *stats)
{
	kstat_ctl_t	*kcp;
	kstat_t		*ksp;

	bzero(stats, sizeof (*stats));

	if ((kcp = kstat_open()) == NULL) {
		warn("kstat open operation failed");
		return;
	}

	ksp = dladm_kstat_lookup(kcp, NULL, -1, flowname, "flow");

	if (ksp != NULL)
		dladm_get_stats(kcp, ksp, stats);

	(void) kstat_close(kcp);
}

/* ARGSUSED */
static int
show_flow_stats(dladm_flow_attr_t *attr, void *arg)
{
	show_flow_state_t *state = (show_flow_state_t *)arg;
	const char *name = attr->fa_flowname;
	pktsum_t stats, diff_stats;

	if (state->fs_firstonly) {
		if (state->fs_donefirst)
			return (DLADM_WALK_TERMINATE);
		state->fs_donefirst = B_TRUE;
	} else {
		bzero(&state->fs_prevstats, sizeof (state->fs_prevstats));
	}

	get_flow_stats(name, &stats);
	dladm_stats_diff(&diff_stats, &stats, &state->fs_prevstats);

	(void) printf("%-12s", name);
	(void) printf("%-10llu", diff_stats.ipackets);
	(void) printf("%-12llu", diff_stats.rbytes);
	(void) printf("%-8llu", diff_stats.ierrors);
	(void) printf("%-10llu", diff_stats.opackets);
	(void) printf("%-12llu", diff_stats.obytes);
	(void) printf("%-8llu\n", diff_stats.oerrors);

	state->fs_prevstats = stats;

	return (DLADM_WALK_CONTINUE);
}

/*
 * Wrapper of dladm_walk_flow(show_flow,...) to make it usable for
 * dladm_walk_datalink_id(). Used for showing flow stats for
 * all flows on all links.
 */
static int
show_link_flow_stats(dladm_handle_t dh, datalink_id_t linkid, void * arg)
{
	if (dladm_walk_flow(show_flow_stats, dh, linkid, arg, B_FALSE)
	    == DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);
	else
		return (DLADM_WALK_TERMINATE);
}

/* ARGSUSED */
static void
flow_stats(const char *flow, datalink_id_t linkid,  uint_t interval)
{
	show_flow_state_t	state;
	dladm_flow_attr_t	attr;

	if (flow != NULL &&
	    dladm_flow_info(handle, flow, &attr) != DLADM_STATUS_OK)
		die("invalid flow %s", flow);

	bzero(&state, sizeof (state));

	/*
	 * If an interval is specified, continuously show the stats
	 * for only the first flow.
	 */
	state.fs_firstonly = (interval != 0);

	for (;;) {
		if (!state.fs_donefirst)
			(void) printf("%-12s%-10s%-12s%-8s%-10s%-12s%-8s\n",
			    "FLOW", "IPACKETS", "RBYTES", "IERRORS",
			    "OPACKETS", "OBYTES", "OERRORS");

		state.fs_donefirst = B_FALSE;

		/* Show stats for named flow */
		if (flow != NULL)  {
			state.fs_flow = flow;
			(void) show_flow_stats(&attr, &state);

		/* Show all stats on a link */
		} else if (linkid != DATALINK_INVALID_LINKID) {
			(void) dladm_walk_flow(show_flow_stats, handle, linkid,
			    &state, B_FALSE);

		/* Show all stats by datalink */
		} else {
			(void) dladm_walk_datalink_id(show_link_flow_stats,
			    handle, &state, DATALINK_CLASS_ALL,
			    DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);
		}

		if (interval == 0)
			break;

		(void) sleep(interval);
	}
}

static void
do_show_flow(int argc, char *argv[])
{
	char			flowname[MAXFLOWNAMELEN];
	char			linkname[MAXLINKNAMELEN];
	datalink_id_t		linkid = DATALINK_ALL_LINKID;
	int			option;
	boolean_t		s_arg = B_FALSE;
	boolean_t		S_arg = B_FALSE;
	boolean_t		i_arg = B_FALSE;
	boolean_t		l_arg = B_FALSE;
	boolean_t		o_arg = B_FALSE;
	uint32_t		interval = 0;
	char			*endp = NULL;
	show_flow_state_t	state;
	char			*fields_str = NULL;
	print_field_t		**fields;
	uint_t			nfields;
	char			*all_fields =
	    "flow,link,ipaddr,proto,port,dsfld";

	bzero(&state, sizeof (state));

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":pPsSi:l:o:",
	    longopts, NULL)) != -1) {
		switch (option) {
		case 'p':
			state.fs_parseable = B_TRUE;
			break;
		case 'P':
			state.fs_persist = B_TRUE;
			break;
		case 's':
			if (s_arg)
				die_optdup(option);

			s_arg = B_TRUE;
			break;
		case 'S':
			if (S_arg)
				die_optdup(option);

			S_arg = B_TRUE;
			break;
		case 'o':
			if (o_arg)
				die_optdup(option);

			o_arg = B_TRUE;
			fields_str = optarg;
			break;
		case 'i':
			if (i_arg)
				die_optdup(option);

			i_arg = B_TRUE;

			errno = 0;
			interval = (int)strtol(optarg, &endp, 10);
			if (errno != 0 || interval == 0 || *endp != '\0')
				die("invalid interval value" " '%d'\n",
				    interval);
			break;
		case 'l':
			if (strlcpy(linkname, optarg, MAXLINKNAMELEN)
			    >= MAXLINKNAMELEN)
				die("link name too long\n");
			if (dladm_name2info(handle, linkname, &linkid, NULL,
			    NULL, NULL) != DLADM_STATUS_OK)
				die("invalid link '%s'", linkname);
			l_arg = B_TRUE;
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}
	if (state.fs_parseable && !o_arg)
		die("-p requires -o");

	if (state.fs_parseable && strcasecmp(fields_str, "all") == 0)
		die("\"-o all\" is invalid with -p");

	if (i_arg && !(s_arg || S_arg))
		die("the -i option can be used only with -s or -S");

	if (s_arg && S_arg)
		die("the -s option cannot be used with -S");

	/* get flow name (optional last argument */
	if (optind == (argc-1)) {
		if (strlcpy(flowname, argv[optind], MAXFLOWNAMELEN)
		    >= MAXFLOWNAMELEN)
			die("flow name too long");
		state.fs_flow = flowname;
	}

	if (s_arg) {
		flow_stats(state.fs_flow, linkid, interval);
		return;
	}

	if (S_arg) {
		dladm_continuous(handle, linkid, state.fs_flow, interval,
		    FLOW_REPORT);
		return;
	}

	if (!o_arg || (o_arg && strcasecmp(fields_str, "all") == 0))
		fields_str = all_fields;

	fields = parse_output_fields(fields_str, flow_fields, FLOW_MAX_FIELDS,
	    CMD_TYPE_ANY, &nfields);

	if (fields == NULL) {
		die("invalid fields(s) specified");
		return;
	}

	state.fs_print.ps_fields = fields;
	state.fs_print.ps_nfields = nfields;

	/* Show attributes of one flow */
	if (state.fs_flow != NULL) {
		show_one_flow(&state, state.fs_flow);

	/* Show attributes of flows on one link */
	} else if (l_arg) {
		(void) show_flows_onelink(handle, linkid, &state);

	/* Show attributes of all flows on all links */
	} else {
		(void) dladm_walk_datalink_id(show_flows_onelink, handle,
		    &state, DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE,
		    DLADM_OPT_ACTIVE);
	}
}

static dladm_status_t
set_flowprop_persist(const char *flow, const char *prop_name, char **prop_val,
    uint_t val_cnt, boolean_t reset)
{
	dladm_status_t	status;
	char		*errprop;

	status = dladm_set_flowprop(handle, flow, prop_name, prop_val, val_cnt,
	    DLADM_OPT_PERSIST, &errprop);

	if (status != DLADM_STATUS_OK) {
		warn_dlerr(status, "cannot persistently %s flow "
		    "property '%s' on '%s'", reset? "reset": "set",
		    errprop, flow);
	}
	return (status);
}

static void
set_flowprop(int argc, char **argv, boolean_t reset)
{
	int		i, option;
	char		errmsg[DLADM_STRSIZE];
	const char	*flow = NULL;
	dladm_arg_list_t	*proplist = NULL;
	boolean_t	temp = B_FALSE;
	dladm_status_t	status = DLADM_STATUS_OK;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":p:R:t",
	    prop_longopts, NULL)) != -1) {
		switch (option) {
		case 'p':
			if (dladm_parse_flow_props(optarg, &proplist, reset)
			    != DLADM_STATUS_OK)
				die("invalid flow property specified");
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

	if (optind == (argc - 1)) {
		if (strlen(argv[optind]) >= MAXFLOWNAMELEN)
			die("flow name too long");
		flow = argv[optind];
	} else if (optind != argc) {
		usage();
	}
	if (flow == NULL)
		die("flow name must be specified");

	if (proplist == NULL) {
		char *errprop;

		if (!reset)
			die("flow property must be specified");

		status = dladm_set_flowprop(handle, flow, NULL, NULL, 0,
		    DLADM_OPT_ACTIVE, &errprop);
		if (status != DLADM_STATUS_OK) {
			warn_dlerr(status, "cannot reset flow property '%s' "
			    "on '%s'", errprop, flow);
		}
		if (!temp) {
			dladm_status_t	s;

			s = set_flowprop_persist(flow, NULL, NULL, 0, reset);
			if (s != DLADM_STATUS_OK)
				status = s;
		}
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
		s = dladm_set_flowprop(handle, flow, aip->ai_name, val, count,
		    DLADM_OPT_ACTIVE, NULL);
		if (s == DLADM_STATUS_OK) {
			if (!temp) {
				s = set_flowprop_persist(flow,
				    aip->ai_name, val, count, reset);
				if (s != DLADM_STATUS_OK)
					status = s;
			}
			continue;
		}
		status = s;
		switch (s) {
		case DLADM_STATUS_NOTFOUND:
			warn("invalid flow property '%s'", aip->ai_name);
			break;
		case DLADM_STATUS_BADVAL: {
			int		j;
			char		*ptr, *lim;
			char		**propvals = NULL;
			uint_t		valcnt = DLADM_MAX_PROP_VALCNT;

			ptr = malloc((sizeof (char *) +
			    DLADM_PROP_VAL_MAX) * DLADM_MAX_PROP_VALCNT +
			    MAX_PROP_LINE);

			if (ptr == NULL)
				die("insufficient memory");
			propvals = (char **)(void *)ptr;

			for (j = 0; j < DLADM_MAX_PROP_VALCNT; j++) {
				propvals[j] = ptr + sizeof (char *) *
				    DLADM_MAX_PROP_VALCNT +
				    j * DLADM_PROP_VAL_MAX;
			}
			s = dladm_get_flowprop(handle, flow,
			    DLADM_PROP_VAL_MODIFIABLE, aip->ai_name, propvals,
			    &valcnt);

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
				warn("flow property '%s' must be one of: %s",
				    aip->ai_name, errmsg);
			} else
				warn("%s is an invalid value for "
				    "flow property %s", *val, aip->ai_name);
			free(propvals);
			break;
		}
		default:
			if (reset) {
				warn_dlerr(status, "cannot reset flow property "
				    "'%s' on '%s'", aip->ai_name, flow);
			} else {
				warn_dlerr(status, "cannot set flow property "
				    "'%s' on '%s'", aip->ai_name, flow);
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
do_set_flowprop(int argc, char **argv)
{
	set_flowprop(argc, argv, B_FALSE);
}

static void
do_reset_flowprop(int argc, char **argv)
{
	set_flowprop(argc, argv, B_TRUE);
}

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
	char    errmsg[DLADM_STRSIZE];

	format = gettext(format);
	(void) fprintf(stderr, gettext("%s: warning: "), progname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);
	(void) fprintf(stderr, ": %s\n", dladm_status2str(err, errmsg));
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

static void
print_flowprop(const char *flowname, show_flowprop_state_t *statep,
    const char *propname, dladm_prop_type_t type,
    const char *format, char **pptr)
{
	int		i;
	char		*ptr, *lim;
	char		buf[DLADM_STRSIZE];
	char		*unknown = "--", *notsup = "";
	char		**propvals = statep->fs_propvals;
	uint_t		valcnt = DLADM_MAX_PROP_VALCNT;
	dladm_status_t	status;

	status = dladm_get_flowprop(handle, flowname, type, propname, propvals,
	    &valcnt);
	if (status != DLADM_STATUS_OK) {
		if (status == DLADM_STATUS_TEMPONLY) {
			if (type == DLADM_PROP_VAL_MODIFIABLE &&
			    statep->fs_persist) {
				valcnt = 1;
				propvals = &unknown;
			} else {
				statep->fs_status = status;
				statep->fs_retstatus = status;
				return;
			}
		} else if (status == DLADM_STATUS_NOTSUP ||
		    statep->fs_persist) {
			valcnt = 1;
			if (type == DLADM_PROP_VAL_CURRENT)
				propvals = &unknown;
			else
				propvals = &notsup;
		} else {
			if ((statep->fs_proplist != NULL) &&
			    statep->fs_status == DLADM_STATUS_OK) {
				warn("invalid flow property '%s'", propname);
			}
			statep->fs_status = status;
			statep->fs_retstatus = status;
			return;
		}
	}

	statep->fs_status = DLADM_STATUS_OK;

	ptr = buf;
	lim = buf + DLADM_STRSIZE;
	for (i = 0; i < valcnt; i++) {
		if (propvals[i][0] == '\0' && !statep->fs_parseable)
			ptr += snprintf(ptr, lim - ptr, STR_UNDEF_VAL",");
		else
			ptr += snprintf(ptr, lim - ptr, "%s,", propvals[i]);
		if (ptr >= lim)
			break;
	}
	if (valcnt > 0)
		buf[strlen(buf) - 1] = '\0';

	lim = statep->fs_line + MAX_PROP_LINE;
	if (statep->fs_parseable) {
		*pptr += snprintf(*pptr, lim - *pptr,
		    "%s", buf);
	} else {
		*pptr += snprintf(*pptr, lim - *pptr, format, buf);
	}
}

static char *
flowprop_callback(print_field_t *pf, void *fs_arg)
{
	flowprop_args_t		*arg = fs_arg;
	char 			*propname = arg->fs_propname;
	show_flowprop_state_t	*statep = arg->fs_state;
	char			*ptr = statep->fs_line;
	char			*lim = ptr + MAX_PROP_LINE;
	char			*flowname = arg->fs_flowname;

	switch (pf->pf_index) {
	case FLOWPROP_FLOW:
		(void) snprintf(ptr, lim - ptr, "%s", statep->fs_flow);
		break;
	case FLOWPROP_PROPERTY:
		(void) snprintf(ptr, lim - ptr, "%s", propname);
		break;
	case FLOWPROP_VALUE:
		print_flowprop(flowname, statep, propname,
		    statep->fs_persist ? DLADM_PROP_VAL_PERSISTENT :
		    DLADM_PROP_VAL_CURRENT, "%s", &ptr);
		/*
		 * If we failed to query the flow property, for example, query
		 * the persistent value of a non-persistable flow property,
		 * simply skip the output.
		 */
		if (statep->fs_status != DLADM_STATUS_OK)
			goto skip;
		ptr = statep->fs_line;
		break;
	case FLOWPROP_DEFAULT:
		print_flowprop(flowname, statep, propname,
		    DLADM_PROP_VAL_DEFAULT, "%s", &ptr);
		if (statep->fs_status != DLADM_STATUS_OK)
			goto skip;
		ptr = statep->fs_line;
		break;
	case FLOWPROP_POSSIBLE:
		print_flowprop(flowname, statep, propname,
		    DLADM_PROP_VAL_MODIFIABLE, "%s ", &ptr);
		if (statep->fs_status != DLADM_STATUS_OK)
			goto skip;
		ptr = statep->fs_line;
		break;
	default:
		die("invalid input");
		break;
	}
	return (ptr);
skip:
	if (statep->fs_status != DLADM_STATUS_OK)
		return (NULL);
	else
		return ("");
}

static int
show_one_flowprop(void *arg, const char *propname)
{
	show_flowprop_state_t	*statep = arg;
	flowprop_args_t		fs_arg;

	bzero(&fs_arg, sizeof (fs_arg));
	fs_arg.fs_state = statep;
	fs_arg.fs_propname = (char *)propname;
	fs_arg.fs_flowname = (char *)statep->fs_flow;

	if (statep->fs_header) {
		statep->fs_header = B_FALSE;
		if (!statep ->fs_parseable)
			print_header(&statep->fs_print);
	}
	flowadm_print_output(&statep->fs_print, statep->fs_parseable,
	    flowprop_callback, (void *)&fs_arg);

	return (DLADM_WALK_CONTINUE);
}

/* Walker function called by dladm_walk_flow to display flow properties */
static int
show_flowprop(dladm_flow_attr_t *attr, void *arg)
{
	show_flowprop_one_flow(arg, attr->fa_flowname);
	return (DLADM_WALK_CONTINUE);
}

/*
 * Wrapper of dladm_walk_flow(show_walk_fn,...) to make it
 * usable to dladm_walk_datalink_id()
 */
static int
show_flowprop_onelink(dladm_handle_t dh, datalink_id_t linkid, void *arg)
{
	char	name[MAXLINKNAMELEN];

	if (dladm_datalink_id2info(dh, linkid, NULL, NULL, NULL, name,
	    sizeof (name)) != DLADM_STATUS_OK)
		return (DLADM_WALK_TERMINATE);

	(void) dladm_walk_flow(show_flowprop, dh, linkid, arg, B_FALSE);

	return (DLADM_WALK_CONTINUE);
}

static void
do_show_flowprop(int argc, char **argv)
{
	int			option;
	boolean_t		o_arg = B_FALSE;
	dladm_arg_list_t	*proplist = NULL;
	show_flowprop_state_t	state;
	char			*fields_str = NULL;
	print_field_t		**fields;
	uint_t			nfields;
	char			*all_fields =
	    "flow,property,value,default,possible";

	fields_str = all_fields;
	opterr = 0;
	state.fs_propvals = NULL;
	state.fs_line = NULL;
	state.fs_parseable = B_FALSE;
	state.fs_persist = B_FALSE;
	state.fs_header = B_TRUE;
	state.fs_retstatus = DLADM_STATUS_OK;
	state.fs_linkid = DATALINK_INVALID_LINKID;
	state.fs_flow = NULL;

	while ((option = getopt_long(argc, argv, ":p:cPl:o:",
	    prop_longopts, NULL)) != -1) {
		switch (option) {
		case 'p':
			if (dladm_parse_flow_props(optarg, &proplist, B_TRUE)
			    != DLADM_STATUS_OK)
				die("invalid flow properties specified");
			break;
		case 'c':
			state.fs_parseable = B_TRUE;
			break;
		case 'P':
			state.fs_persist = B_TRUE;
			break;
		case 'l':
			if (dladm_name2info(handle, optarg, &state.fs_linkid,
			    NULL, NULL, NULL) != DLADM_STATUS_OK)
				die("invalid link '%s'", optarg);
			break;
		case 'o':
			o_arg = B_TRUE;
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

	if (state.fs_parseable && !o_arg)
		die("-p requires -o");

	if (state.fs_parseable && strcasecmp(fields_str, "all") == 0)
		die("\"-o all\" is invalid with -p");

	if (optind == (argc - 1)) {
		if (strlen(argv[optind]) >= MAXFLOWNAMELEN)
			die("flow name too long");
		state.fs_flow = argv[optind];
	} else if (optind != argc) {
		usage();
	}
	bzero(&state.fs_print, sizeof (print_state_t));
	state.fs_proplist = proplist;
	state.fs_status = DLADM_STATUS_OK;

	fields = parse_output_fields(fields_str, flowprop_fields,
	    FLOWPROP_MAX_FIELDS, CMD_TYPE_ANY, &nfields);

	if (fields == NULL) {
		die("invalid field(s) specified");
		return;
	}

	state.fs_print.ps_fields = fields;
	state.fs_print.ps_nfields = nfields;

	/* Show properties for one flow */
	if (state.fs_flow != NULL) {
		show_flowprop_one_flow(&state, state.fs_flow);

	/* Show properties for all flows on one link */
	} else if (state.fs_linkid != DATALINK_INVALID_LINKID) {
		(void) show_flowprop_onelink(handle, state.fs_linkid, &state);

	/* Show properties for all flows on all links */
	} else {
		(void) dladm_walk_datalink_id(show_flowprop_onelink, handle,
		    &state, DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE,
		    DLADM_OPT_ACTIVE);
	}

	dladm_free_props(proplist);
}

static void
show_flowprop_one_flow(void *arg, const char *flow)
{
	int			i;
	char			*buf;
	dladm_status_t		status;
	dladm_arg_list_t	*proplist = NULL;
	show_flowprop_state_t	*statep = arg;
	dladm_flow_attr_t	attr;
	const char		*savep;

	/*
	 * Do not print flow props for invalid flows.
	 */
	if ((status = dladm_flow_info(handle, flow, &attr)) !=
	    DLADM_STATUS_OK) {
		die("invalid flow: '%s'", flow);
	}

	savep = statep->fs_flow;
	statep->fs_flow = flow;

	proplist = statep->fs_proplist;

	buf = malloc((sizeof (char *) + DLADM_PROP_VAL_MAX)
	    * DLADM_MAX_PROP_VALCNT + MAX_PROP_LINE);
	if (buf == NULL)
		die("insufficient memory");

	statep->fs_propvals = (char **)(void *)buf;
	for (i = 0; i < DLADM_MAX_PROP_VALCNT; i++) {
		statep->fs_propvals[i] = buf +
		    sizeof (char *) * DLADM_MAX_PROP_VALCNT +
		    i * DLADM_PROP_VAL_MAX;
	}
	statep->fs_line = buf +
	    (sizeof (char *) + DLADM_PROP_VAL_MAX) * DLADM_MAX_PROP_VALCNT;

	/* show only specified flow properties */
	if (proplist != NULL) {
		for (i = 0; i < proplist->al_count; i++) {
			if (show_one_flowprop(statep,
			    proplist->al_info[i].ai_name) != DLADM_STATUS_OK)
				break;
		}

	/* show all flow properties */
	} else {
		status = dladm_walk_flowprop(show_one_flowprop, flow, statep);
		if (status != DLADM_STATUS_OK)
			die_dlerr(status, "show-flowprop");
	}
	free(buf);
	statep->fs_flow = savep;
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

static void
flowadm_print_output(print_state_t *statep, boolean_t parseable,
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

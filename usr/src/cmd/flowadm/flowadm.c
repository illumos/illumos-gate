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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2017 Joyent, Inc.
 */

#include <stdio.h>
#include <locale.h>
#include <stdarg.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <stropts.h>
#include <errno.h>
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
#include <ofmt.h>

typedef struct show_flow_state {
	dladm_status_t		fs_status;
	ofmt_handle_t		fs_ofmt;
	const char		*fs_flow;
	boolean_t		fs_parsable;
	boolean_t		fs_persist;
} show_flow_state_t;

typedef void cmdfunc_t(int, char **);

static cmdfunc_t do_add_flow, do_remove_flow, do_init_flow, do_show_flow;
static cmdfunc_t do_show_flowprop, do_set_flowprop, do_reset_flowprop;

static int	show_flow(dladm_handle_t, dladm_flow_attr_t *, void *);
static int	show_flows_onelink(dladm_handle_t, datalink_id_t, void *);

static int	remove_flow(dladm_handle_t, dladm_flow_attr_t *, void *);

static int	show_flowprop(dladm_handle_t, dladm_flow_attr_t *, void *);
static void	show_flowprop_one_flow(void *, const char *);
static int	show_flowprop_onelink(dladm_handle_t, datalink_id_t, void *);

static void	die(const char *, ...);
static void	die_optdup(int);
static void	die_opterr(int, int);
static void	die_dlerr(dladm_status_t, const char *, ...);
static void	warn(const char *, ...);
static void	warn_dlerr(dladm_status_t, const char *, ...);

/* callback functions for printing output */
static ofmt_cb_t print_flowprop_cb, print_default_cb;

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
};

static const struct option longopts[] = {
	{"link",		required_argument,	0, 'l'},
	{"parsable",		no_argument,		0, 'p'},
	{"parseable",		no_argument,		0, 'p'},
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
 * structures for 'flowadm remove-flow'
 */
typedef struct remove_flow_state {
	boolean_t	fs_tempop;
	const char	*fs_altroot;
	dladm_status_t	fs_status;
} remove_flow_state_t;

#define	PROTO_MAXSTR_LEN	7
#define	PORT_MAXSTR_LEN		6
#define	DSFIELD_MAXSTR_LEN	10
#define	NULL_OFMT		{NULL, 0, 0, NULL}

typedef struct flow_fields_buf_s
{
	char flow_name[MAXFLOWNAMELEN];
	char flow_link[MAXLINKNAMELEN];
	char flow_ipaddr[INET6_ADDRSTRLEN+4];
	char flow_proto[PROTO_MAXSTR_LEN];
	char flow_lport[PORT_MAXSTR_LEN];
	char flow_rport[PORT_MAXSTR_LEN];
	char flow_dsfield[DSFIELD_MAXSTR_LEN];
} flow_fields_buf_t;

static ofmt_field_t flow_fields[] = {
/* name,	field width,	index */
{  "FLOW",	12,
	offsetof(flow_fields_buf_t, flow_name), print_default_cb},
{  "LINK",	12,
	offsetof(flow_fields_buf_t, flow_link), print_default_cb},
{  "IPADDR",	25,
	offsetof(flow_fields_buf_t, flow_ipaddr), print_default_cb},
{  "PROTO",	7,
	offsetof(flow_fields_buf_t, flow_proto), print_default_cb},
{  "LPORT",	8,
	offsetof(flow_fields_buf_t, flow_lport), print_default_cb},
{  "RPORT",	8,
	offsetof(flow_fields_buf_t, flow_rport), print_default_cb},
{  "DSFLD",	10,
	offsetof(flow_fields_buf_t, flow_dsfield), print_default_cb},
NULL_OFMT}
;

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

static ofmt_field_t flowprop_fields[] = {
/* name,	fieldwidth,	index, 		callback */
{ "FLOW",	13,	FLOWPROP_FLOW,		print_flowprop_cb},
{ "PROPERTY",	16,	FLOWPROP_PROPERTY,	print_flowprop_cb},
{ "VALUE",	15,	FLOWPROP_VALUE,		print_flowprop_cb},
{ "DEFAULT",	15,	FLOWPROP_DEFAULT,	print_flowprop_cb},
{ "POSSIBLE",	21,	FLOWPROP_POSSIBLE,	print_flowprop_cb},
NULL_OFMT}
;

#define	MAX_PROP_LINE		512

typedef struct show_flowprop_state {
	const char		*fs_flow;
	datalink_id_t		fs_linkid;
	char			*fs_line;
	char			**fs_propvals;
	dladm_arg_list_t	*fs_proplist;
	boolean_t		fs_parsable;
	boolean_t		fs_persist;
	boolean_t		fs_header;
	dladm_status_t		fs_status;
	dladm_status_t		fs_retstatus;
	ofmt_handle_t		fs_ofmt;
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

static char *progname;

boolean_t		t_arg = B_FALSE; /* changes are persistent */
char			*altroot = NULL;

/*
 * Handle to libdladm.  Opened in main() before the sub-command
 * specific function is called.
 */
static dladm_handle_t handle = NULL;

static const char *attr_table[] =
	{"local_ip", "remote_ip", "transport", "local_port", "remote_port",
	    "dsfield"};

#define	NATTR	(sizeof (attr_table)/sizeof (char *))

static void
usage(void)
{
	(void) fprintf(stderr, gettext("usage: flowadm <subcommand>"
	    " <args>...\n"
	    "    add-flow       [-t] -l <link> -a <attr>=<value>[,...]\n"
	    "\t\t   [-p <prop>=<value>,...] <flow>\n"
	    "    remove-flow    [-t] {-l <link> | <flow>}\n"
	    "    show-flow      [-p] [-l <link>] "
	    "[<flow>]\n\n"
	    "    set-flowprop   [-t] -p <prop>=<value>[,...] <flow>\n"
	    "    reset-flowprop [-t] [-p <prop>,...] <flow>\n"
	    "    show-flowprop  [-cP] [-l <link>] [-p <prop>,...] "
	    "[<flow>]\n"));

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

static void
do_add_flow(int argc, char *argv[])
{
	char			devname[MAXLINKNAMELEN];
	char			*name = NULL;
	uint_t			index;
	datalink_id_t		linkid;

	char			option;
	boolean_t		l_arg = B_FALSE;
	char			propstr[DLADM_STRSIZE];
	char			attrstr[DLADM_STRSIZE];
	dladm_arg_list_t	*proplist = NULL;
	dladm_arg_list_t	*attrlist = NULL;
	dladm_status_t		status;

	bzero(propstr, DLADM_STRSIZE);
	bzero(attrstr, DLADM_STRSIZE);

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
			(void) strlcat(attrstr, optarg, DLADM_STRSIZE);
			if (strlcat(attrstr, ",", DLADM_STRSIZE) >=
			    DLADM_STRSIZE)
				die("attribute list too long '%s'", attrstr);
			break;
		case 'p':
			(void) strlcat(propstr, optarg, DLADM_STRSIZE);
			if (strlcat(propstr, ",", DLADM_STRSIZE) >=
			    DLADM_STRSIZE)
				die("property list too long '%s'", propstr);
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

	if (dladm_parse_flow_attrs(attrstr, &attrlist, B_FALSE)
	    != DLADM_STATUS_OK)
		die("invalid flow attribute specified");
	if (dladm_parse_flow_props(propstr, &proplist, B_FALSE)
	    != DLADM_STATUS_OK)
		die("invalid flow property specified");

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
/*ARGSUSED*/
static int
remove_flow(dladm_handle_t handle, dladm_flow_attr_t *attr, void *arg)
{
	remove_flow_state_t	*state = (remove_flow_state_t *)arg;

	state->fs_status = dladm_flow_remove(handle, attr->fa_flowname,
	    state->fs_tempop, state->fs_altroot);

	if (state->fs_status == DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);
	else
		return (DLADM_WALK_TERMINATE);
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
	if ((attr->fa_flow_desc.fd_mask & FLOW_ULP_PORT_LOCAL) != 0) {
		(void) dladm_flow_attr_port2str(attr, fbuf->flow_lport,
		    sizeof (fbuf->flow_lport));
	}
	if ((attr->fa_flow_desc.fd_mask & FLOW_ULP_PORT_REMOTE) != 0) {
		(void) dladm_flow_attr_port2str(attr, fbuf->flow_rport,
		    sizeof (fbuf->flow_rport));
	}
	(void) dladm_flow_attr_dsfield2str(attr, fbuf->flow_dsfield,
	    sizeof (fbuf->flow_dsfield));

	return (DLADM_STATUS_OK);
}

/*
 * Walker function for showing flow attributes through dladm_walk_flow().
 */
/*ARGSUSED*/
static int
show_flow(dladm_handle_t handle, dladm_flow_attr_t *attr, void *arg)
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

	ofmt_print(statep->fs_ofmt, (void *)&fbuf);

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
		(void) show_flow(handle, &attr, arg);
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
do_show_flow(int argc, char *argv[])
{
	char			flowname[MAXFLOWNAMELEN];
	char			linkname[MAXLINKNAMELEN];
	datalink_id_t		linkid = DATALINK_ALL_LINKID;
	int			option;
	boolean_t		l_arg = B_FALSE;
	boolean_t		o_arg = B_FALSE;
	show_flow_state_t	state;
	char			*fields_str = NULL;
	ofmt_handle_t		ofmt;
	ofmt_status_t		oferr;
	uint_t			ofmtflags = 0;

	bzero(&state, sizeof (state));

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":pPl:o:",
	    longopts, NULL)) != -1) {
		switch (option) {
		case 'p':
			state.fs_parsable = B_TRUE;
			ofmtflags |= OFMT_PARSABLE;
			break;
		case 'P':
			state.fs_persist = B_TRUE;
			break;
		case 'o':
			if (o_arg)
				die_optdup(option);

			o_arg = B_TRUE;
			fields_str = optarg;
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

	/* get flow name (optional last argument */
	if (optind == (argc-1)) {
		if (strlcpy(flowname, argv[optind], MAXFLOWNAMELEN)
		    >= MAXFLOWNAMELEN)
			die("flow name too long");
		state.fs_flow = flowname;
	}

	oferr = ofmt_open(fields_str, flow_fields, ofmtflags, 0, &ofmt);
	ofmt_check(oferr, state.fs_parsable, ofmt, die, warn);
	state.fs_ofmt = ofmt;

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
	ofmt_close(ofmt);
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
	int			i, option;
	char			errmsg[DLADM_STRSIZE];
	const char		*flow = NULL;
	char			propstr[DLADM_STRSIZE];
	dladm_arg_list_t	*proplist = NULL;
	boolean_t		temp = B_FALSE;
	dladm_status_t		status = DLADM_STATUS_OK;

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

	if (dladm_parse_flow_props(propstr, &proplist, reset)
	    != DLADM_STATUS_OK)
		die("invalid flow property specified");

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

	(void) putc('\n', stderr);
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
		if (propvals[i][0] == '\0' && !statep->fs_parsable)
			ptr += snprintf(ptr, lim - ptr, "--,");
		else
			ptr += snprintf(ptr, lim - ptr, "%s,", propvals[i]);
		if (ptr >= lim)
			break;
	}
	if (valcnt > 0)
		buf[strlen(buf) - 1] = '\0';

	lim = statep->fs_line + MAX_PROP_LINE;
	if (statep->fs_parsable) {
		*pptr += snprintf(*pptr, lim - *pptr,
		    "%s", buf);
	} else {
		*pptr += snprintf(*pptr, lim - *pptr, format, buf);
	}
}

static boolean_t
print_flowprop_cb(ofmt_arg_t *of_arg, char *buf, uint_t bufsize)
{
	flowprop_args_t		*arg = of_arg->ofmt_cbarg;
	char 			*propname = arg->fs_propname;
	show_flowprop_state_t	*statep = arg->fs_state;
	char			*ptr = statep->fs_line;
	char			*lim = ptr + MAX_PROP_LINE;
	char			*flowname = arg->fs_flowname;

	switch (of_arg->ofmt_id) {
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
	(void) strlcpy(buf, ptr, bufsize);
	return (B_TRUE);
skip:
	buf[0] = '\0';
	return ((statep->fs_status == DLADM_STATUS_OK) ?
	    B_TRUE : B_FALSE);
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

	ofmt_print(statep->fs_ofmt, (void *)&fs_arg);

	return (DLADM_WALK_CONTINUE);
}

/*ARGSUSED*/
/* Walker function called by dladm_walk_flow to display flow properties */
static int
show_flowprop(dladm_handle_t handle, dladm_flow_attr_t *attr, void *arg)
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
	dladm_arg_list_t	*proplist = NULL;
	show_flowprop_state_t	state;
	char			*fields_str = NULL;
	ofmt_handle_t		ofmt;
	ofmt_status_t		oferr;
	uint_t			ofmtflags = 0;

	opterr = 0;
	state.fs_propvals = NULL;
	state.fs_line = NULL;
	state.fs_parsable = B_FALSE;
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
			state.fs_parsable = B_TRUE;
			ofmtflags |= OFMT_PARSABLE;
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
			fields_str = optarg;
			break;
		default:
			die_opterr(optopt, option);
			break;
		}
	}

	if (optind == (argc - 1)) {
		if (strlen(argv[optind]) >= MAXFLOWNAMELEN)
			die("flow name too long");
		state.fs_flow = argv[optind];
	} else if (optind != argc) {
		usage();
	}
	state.fs_proplist = proplist;
	state.fs_status = DLADM_STATUS_OK;

	oferr = ofmt_open(fields_str, flowprop_fields, ofmtflags, 0, &ofmt);
	ofmt_check(oferr, state.fs_parsable, ofmt, die, warn);
	state.fs_ofmt = ofmt;

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
	ofmt_close(ofmt);
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

/*
 * default output callback function that, when invoked from dladm_print_output,
 * prints string which is offset by of_arg->ofmt_id within buf.
 */
static boolean_t
print_default_cb(ofmt_arg_t *of_arg, char *buf, uint_t bufsize)
{
	char *value;

	value = (char *)of_arg->ofmt_cbarg + of_arg->ofmt_id;
	(void) strlcpy(buf, value, bufsize);
	return (B_TRUE);
}

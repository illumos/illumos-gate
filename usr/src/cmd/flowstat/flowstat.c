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

typedef struct flow_chain_s {
	char			fc_flowname[MAXFLOWNAMELEN];
	boolean_t		fc_visited;
	flow_stat_t		*fc_stat;
	struct flow_chain_s	*fc_next;
} flow_chain_t;

typedef struct show_flow_state {
	flow_chain_t	*fs_flowchain;
	ofmt_handle_t	fs_ofmt;
	char		fs_unit;
	boolean_t	fs_parsable;
} show_flow_state_t;

typedef struct show_history_state_s {
	boolean_t	us_plot;
	boolean_t	us_parsable;
	boolean_t	us_printheader;
	boolean_t	us_first;
	boolean_t	us_showall;
	ofmt_handle_t	us_ofmt;
} show_history_state_t;

static void	do_show_history(int, char **);

static int	query_flow_stats(dladm_handle_t, dladm_flow_attr_t *, void *);
static int	query_link_flow_stats(dladm_handle_t, datalink_id_t, void *);

static void	die(const char *, ...);
static void	die_optdup(int);
static void	die_opterr(int, int, const char *);
static void	die_dlerr(dladm_status_t, const char *, ...);
static void	warn(const char *, ...);

/* callback functions for printing output */
static ofmt_cb_t print_default_cb, print_flow_stats_cb;
static void flowstat_ofmt_check(ofmt_status_t, boolean_t, ofmt_handle_t);

#define	NULL_OFMT		{NULL, 0, 0, NULL}

/*
 * structures for flowstat (printing live statistics)
 */
typedef enum {
	FLOW_S_FLOW,
	FLOW_S_IPKTS,
	FLOW_S_RBYTES,
	FLOW_S_IERRORS,
	FLOW_S_OPKTS,
	FLOW_S_OBYTES,
	FLOW_S_OERRORS
} flow_s_field_index_t;

static ofmt_field_t flow_s_fields[] = {
/* name,	field width,	index,		callback */
{ "FLOW",	15,	FLOW_S_FLOW,	print_flow_stats_cb},
{ "IPKTS",	8,	FLOW_S_IPKTS,	print_flow_stats_cb},
{ "RBYTES",	8,	FLOW_S_RBYTES,	print_flow_stats_cb},
{ "IERRS",	8,	FLOW_S_IERRORS,	print_flow_stats_cb},
{ "OPKTS",	8,	FLOW_S_OPKTS,	print_flow_stats_cb},
{ "OBYTES",	8,	FLOW_S_OBYTES,	print_flow_stats_cb},
{ "OERRS",	8,	FLOW_S_OERRORS,	print_flow_stats_cb},
NULL_OFMT}
;

typedef struct flow_args_s {
	char		*flow_s_flow;
	flow_stat_t	*flow_s_stat;
	char		flow_s_unit;
	boolean_t	flow_s_parsable;
} flow_args_t;

/*
 * structures for 'flowstat -h'
 */
typedef struct  history_fields_buf_s {
	char	history_flow[12];
	char	history_duration[10];
	char	history_ipackets[9];
	char	history_rbytes[10];
	char	history_opackets[9];
	char	history_obytes[10];
	char	history_bandwidth[14];
} history_fields_buf_t;

static ofmt_field_t history_fields[] = {
/* name,	field width,	offset */
{ "FLOW",	13,
	offsetof(history_fields_buf_t, history_flow), print_default_cb},
{ "DURATION",	11,
	offsetof(history_fields_buf_t, history_duration), print_default_cb},
{ "IPACKETS",	10,
	offsetof(history_fields_buf_t, history_ipackets), print_default_cb},
{ "RBYTES",	11,
	offsetof(history_fields_buf_t, history_rbytes), print_default_cb},
{ "OPACKETS",	10,
	offsetof(history_fields_buf_t, history_opackets), print_default_cb},
{ "OBYTES",	11,
	offsetof(history_fields_buf_t, history_obytes), print_default_cb},
{ "BANDWIDTH",	15,
	offsetof(history_fields_buf_t, history_bandwidth), print_default_cb},
NULL_OFMT}
;

typedef struct  history_l_fields_buf_s {
	char	history_l_flow[12];
	char	history_l_stime[13];
	char	history_l_etime[13];
	char	history_l_rbytes[8];
	char	history_l_obytes[8];
	char	history_l_bandwidth[14];
} history_l_fields_buf_t;

static ofmt_field_t history_l_fields[] = {
/* name,	field width,	offset */
{ "FLOW",	13,
	offsetof(history_l_fields_buf_t, history_l_flow), print_default_cb},
{ "START",	14,
	offsetof(history_l_fields_buf_t, history_l_stime), print_default_cb},
{ "END",	14,
	offsetof(history_l_fields_buf_t, history_l_etime), print_default_cb},
{ "RBYTES",	9,
	offsetof(history_l_fields_buf_t, history_l_rbytes), print_default_cb},
{ "OBYTES",	9,
	offsetof(history_l_fields_buf_t, history_l_obytes), print_default_cb},
{ "BANDWIDTH",	15,
	offsetof(history_l_fields_buf_t, history_l_bandwidth),
	    print_default_cb},
NULL_OFMT}
;

static char *progname;

/*
 * Handle to libdladm.  Opened in main() before the sub-command
 * specific function is called.
 */
static dladm_handle_t handle = NULL;

const char *usage_ermsg = "flowstat [-r | -t] [-i interval] "
	    "[-l link] [flow]\n"
	    "       flowstat [-A] [-i interval] [-p] [ -o field[,...]]\n"
	    "                [-u R|K|M|G|T|P] [-l link] [flow]\n"
	    "       flowstat -h [-a] [-d] [-F format]"
	    " [-s <DD/MM/YYYY,HH:MM:SS>]\n"
	    "                [-e <DD/MM/YYYY,HH:MM:SS>] -f <logfile> "
	    "[<flow>]";

static void
usage(void)
{
	(void) fprintf(stderr, "%s\n", gettext(usage_ermsg));

	/* close dladm handle if it was opened */
	if (handle != NULL)
		dladm_close(handle);

	exit(1);
}

boolean_t
flowstat_unit(char *oarg, char *unit)
{
	if ((strcmp(oarg, "R") == 0) || (strcmp(oarg, "K") == 0) ||
	    (strcmp(oarg, "M") == 0) || (strcmp(oarg, "G") == 0) ||
	    (strcmp(oarg, "T") == 0) || (strcmp(oarg, "P") == 0)) {
		*unit = oarg[0];
		return (B_TRUE);
	}

	return (B_FALSE);
}

void
map_to_units(char *buf, uint_t bufsize, double num, char unit,
    boolean_t parsable)
{
	if (parsable) {
		(void) snprintf(buf, bufsize, "%.0lf", num);
		return;
	}

	if (unit == '\0') {
		int index;

		for (index = 0; (int)(num/1000) != 0; index++, num /= 1000)
			;

		switch (index) {
			case 0:
				unit = '\0';
				break;
			case 1:
				unit = 'K';
				break;
			case 2:
				unit = 'M';
				break;
			case 3:
				unit = 'G';
				break;
			case 4:
				unit = 'T';
				break;
			case 5:
				/* Largest unit supported */
			default:
				unit = 'P';
				break;
		}
	} else  {
		switch (unit) {
			case 'R':
				/* Already raw numbers */
				unit = '\0';
				break;
			case 'K':
				num /= 1000;
				break;
			case 'M':
				num /= (1000*1000);
				break;
			case 'G':
				num /= (1000*1000*1000);
				break;
			case 'T':
				num /= (1000.0*1000.0*1000.0*1000.0);
				break;
			case 'P':
				/* Largest unit supported */
			default:
				num /= (1000.0*1000.0*1000.0*1000.0*1000.0);
				break;
		}
	}

	if (unit == '\0')
		(void) snprintf(buf, bufsize, " %7.0lf%c", num, unit);
	else
		(void) snprintf(buf, bufsize, " %6.2lf%c", num, unit);
}

flow_chain_t *
get_flow_prev_stat(const char *flowname, void *arg)
{
	show_flow_state_t	*state = arg;
	flow_chain_t		*flow_curr = NULL;

	/* Scan prev flowname list and look for entry matching this entry */
	for (flow_curr = state->fs_flowchain; flow_curr;
	    flow_curr = flow_curr->fc_next) {
		if (strcmp(flow_curr->fc_flowname, flowname) == 0)
			break;
	}

	/* New flow, add it */
	if (flow_curr == NULL) {
		flow_curr = (flow_chain_t *)malloc(sizeof (flow_chain_t));
		if (flow_curr == NULL)
			goto done;
		(void) strncpy(flow_curr->fc_flowname, flowname,
		    MAXFLOWNAMELEN);
		flow_curr->fc_stat = NULL;
		flow_curr->fc_next = state->fs_flowchain;
		state->fs_flowchain = flow_curr;
	}
done:
	return (flow_curr);
}

/*
 * Number of flows may change while flowstat -i is executing.
 * Free memory allocated for flows that are no longer there.
 * Prepare for next iteration by marking visited = false for
 * existing stat entries.
 */
static void
cleanup_removed_flows(show_flow_state_t *state)
{
	flow_chain_t	*fcurr;
	flow_chain_t	*fprev;
	flow_chain_t	*tofree;

	/* Delete all nodes from the list that have fc_visited marked false */
	fcurr = state->fs_flowchain;
	while (fcurr != NULL) {
		if (fcurr->fc_visited) {
			fcurr->fc_visited = B_FALSE;
			fprev = fcurr;
			fcurr = fcurr->fc_next;
			continue;
		}

		/* Is it head of the list? */
		if (fcurr == state->fs_flowchain)
			state->fs_flowchain = fcurr->fc_next;
		else
			fprev->fc_next = fcurr->fc_next;

		/* fprev remains the same */
		tofree = fcurr;
		fcurr = fcurr->fc_next;

		/* Free stats memory for the removed flow */
		dladm_flow_stat_free(tofree->fc_stat);
		free(tofree);
	}
}

static boolean_t
print_flow_stats_cb(ofmt_arg_t *of_arg, char *buf, uint_t bufsize)
{
	flow_args_t	*fargs = of_arg->ofmt_cbarg;
	flow_stat_t	*diff_stats = fargs->flow_s_stat;
	char		unit = fargs->flow_s_unit;
	boolean_t	parsable = fargs->flow_s_parsable;

	switch (of_arg->ofmt_id) {
	case FLOW_S_FLOW:
		(void) snprintf(buf, bufsize, "%s", fargs->flow_s_flow);
		break;
	case FLOW_S_IPKTS:
		map_to_units(buf, bufsize, diff_stats->fl_ipackets, unit,
		    parsable);
		break;
	case FLOW_S_RBYTES:
		map_to_units(buf, bufsize, diff_stats->fl_rbytes, unit,
		    parsable);
		break;
	case FLOW_S_IERRORS:
		map_to_units(buf, bufsize, diff_stats->fl_ierrors, unit,
		    parsable);
		break;
	case FLOW_S_OPKTS:
		map_to_units(buf, bufsize, diff_stats->fl_opackets, unit,
		    parsable);
		break;
	case FLOW_S_OBYTES:
		map_to_units(buf, bufsize, diff_stats->fl_obytes, unit,
		    parsable);
		break;
	case FLOW_S_OERRORS:
		map_to_units(buf, bufsize, diff_stats->fl_oerrors, unit,
		    parsable);
		break;
	default:
		die("invalid input");
		break;
	}
	return (B_TRUE);
}

/* ARGSUSED */
static int
query_flow_stats(dladm_handle_t handle, dladm_flow_attr_t *attr, void *arg)
{
	show_flow_state_t	*state = arg;
	flow_chain_t		*flow_node;
	flow_stat_t		*curr_stat;
	flow_stat_t		*prev_stat;
	flow_stat_t		*diff_stat;
	char			*flowname = attr->fa_flowname;
	flow_args_t		fargs;

	/* Get previous stats for the flow */
	flow_node = get_flow_prev_stat(flowname, arg);
	if (flow_node == NULL)
		goto done;

	flow_node->fc_visited = B_TRUE;
	prev_stat = flow_node->fc_stat;

	/* Query library for current stats */
	curr_stat = dladm_flow_stat_query(flowname);
	if (curr_stat == NULL)
		goto done;

	/* current stats - prev iteration stats */
	diff_stat = dladm_flow_stat_diff(curr_stat, prev_stat);

	/* Free prev stats */
	dladm_flow_stat_free(prev_stat);

	/* Prev <- curr stats */
	flow_node->fc_stat = curr_stat;

	if (diff_stat == NULL)
		goto done;

	/* Print stats */
	fargs.flow_s_flow = flowname;
	fargs.flow_s_stat = diff_stat;
	fargs.flow_s_unit = state->fs_unit;
	fargs.flow_s_parsable = state->fs_parsable;
	ofmt_print(state->fs_ofmt, &fargs);

	/* Free diff stats */
	dladm_flow_stat_free(diff_stat);
done:
	return (DLADM_WALK_CONTINUE);
}

/*
 * Wrapper of dladm_walk_flow(query_flow_stats,...) to make it usable for
 * dladm_walk_datalink_id(). Used for showing flow stats for
 * all flows on all links.
 */
static int
query_link_flow_stats(dladm_handle_t dh, datalink_id_t linkid, void * arg)
{
	if (dladm_walk_flow(query_flow_stats, dh, linkid, arg, B_FALSE)
	    == DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);
	else
		return (DLADM_WALK_TERMINATE);
}

void
print_all_stats(name_value_stat_entry_t *stat_entry)
{
	name_value_stat_t	*curr_stat;

	printf("%s\n", stat_entry->nve_header);

	for (curr_stat = stat_entry->nve_stats; curr_stat != NULL;
	    curr_stat = curr_stat->nv_nextstat) {
		printf("\t%15s", curr_stat->nv_statname);
		printf("\t%15llu\n", curr_stat->nv_statval);
	}
}

/* ARGSUSED */
static int
dump_one_flow_stats(dladm_handle_t handle, dladm_flow_attr_t *attr, void *arg)
{
	char	*flowname = attr->fa_flowname;
	void	*stat;

	stat = dladm_flow_stat_query_all(flowname);
	if (stat == NULL)
		goto done;
	print_all_stats(stat);
	dladm_flow_stat_query_all_free(stat);

done:
	return (DLADM_WALK_CONTINUE);
}

/*
 * Wrapper of dladm_walk_flow(query_flow_stats,...) to make it usable for
 * dladm_walk_datalink_id(). Used for showing flow stats for
 * all flows on all links.
 */
static int
dump_link_flow_stats(dladm_handle_t dh, datalink_id_t linkid, void * arg)
{
	if (dladm_walk_flow(dump_one_flow_stats, dh, linkid, arg, B_FALSE)
	    == DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);
	else
		return (DLADM_WALK_TERMINATE);
}

static void
dump_all_flow_stats(dladm_flow_attr_t *attrp, void *arg, datalink_id_t linkid,
    boolean_t flow_arg)
{
	/* Show stats for named flow */
	if (flow_arg)  {
		(void) dump_one_flow_stats(handle, attrp, arg);

	/* Show stats for flows on one link */
	} else if (linkid != DATALINK_INVALID_LINKID) {
		(void) dladm_walk_flow(dump_one_flow_stats, handle, linkid,
		    arg, B_FALSE);

	/* Show stats for all flows on all links */
	} else {
		(void) dladm_walk_datalink_id(dump_link_flow_stats,
		    handle, arg, DATALINK_CLASS_ALL,
		    DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);
	}
}

int
main(int argc, char *argv[])
{
	dladm_status_t 		status;
	int			option;
	boolean_t		r_arg = B_FALSE;
	boolean_t		t_arg = B_FALSE;
	boolean_t		p_arg = B_FALSE;
	boolean_t		i_arg = B_FALSE;
	boolean_t		o_arg = B_FALSE;
	boolean_t		u_arg = B_FALSE;
	boolean_t		A_arg = B_FALSE;
	boolean_t		flow_arg = B_FALSE;
	datalink_id_t		linkid = DATALINK_ALL_LINKID;
	char			linkname[MAXLINKNAMELEN];
	char			flowname[MAXFLOWNAMELEN];
	uint32_t		interval = 0;
	char			unit = '\0';
	show_flow_state_t	state;
	char			*fields_str = NULL;
	char			*o_fields_str = NULL;

	char			*total_stat_fields =
	    "flow,ipkts,rbytes,ierrs,opkts,obytes,oerrs";
	char			*rx_stat_fields =
	    "flow,ipkts,rbytes,ierrs";
	char			*tx_stat_fields =
	    "flow,opkts,obytes,oerrs";

	ofmt_handle_t		ofmt;
	ofmt_status_t		oferr;
	uint_t			ofmtflags = OFMT_RIGHTJUST;

	dladm_flow_attr_t	attr;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	progname = argv[0];

	/* Open the libdladm handle */
	if ((status = dladm_open(&handle)) != DLADM_STATUS_OK)
		die_dlerr(status, "could not open /dev/dld");

	bzero(&state, sizeof (state));

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":rtApi:o:u:l:h",
	    NULL, NULL)) != -1) {
		switch (option) {
		case 'r':
			if (r_arg)
				die_optdup(option);

			r_arg = B_TRUE;
			break;
		case 't':
			if (t_arg)
				die_optdup(option);

			t_arg = B_TRUE;
			break;
		case 'A':
			if (A_arg)
				die_optdup(option);

			A_arg = B_TRUE;
			break;
		case 'p':
			if (p_arg)
				die_optdup(option);

			p_arg = B_TRUE;
			break;
		case 'i':
			if (i_arg)
				die_optdup(option);

			i_arg = B_TRUE;
			if (!dladm_str2interval(optarg, &interval))
				die("invalid interval value '%s'", optarg);
			break;
		case 'o':
			o_arg = B_TRUE;
			o_fields_str = optarg;
			break;
		case 'u':
			if (u_arg)
				die_optdup(option);

			u_arg = B_TRUE;
			if (!flowstat_unit(optarg, &unit))
				die("invalid unit value '%s',"
				    "unit must be R|K|M|G|T|P", optarg);
			break;
		case 'l':
			if (strlcpy(linkname, optarg, MAXLINKNAMELEN)
			    >= MAXLINKNAMELEN)
				die("link name too long\n");
			if (dladm_name2info(handle, linkname, &linkid, NULL,
			    NULL, NULL) != DLADM_STATUS_OK)
				die("invalid link '%s'", linkname);
			break;
		case 'h':
			if (r_arg || t_arg || p_arg || o_arg || u_arg ||
			    i_arg || A_arg) {
				die("the option -h is not compatible with "
				    "-r, -t, -p, -o, -u, -i, -A");
			}
			do_show_history(argc, argv);
			return (0);
			break;
		default:
			die_opterr(optopt, option, usage_ermsg);
			break;
		}
	}

	if (r_arg && t_arg)
		die("the option -t and -r are not compatible");

	if (u_arg && p_arg)
		die("the option -u and -p are not compatible");

	if (p_arg && !o_arg)
		die("-p requires -o");

	if (p_arg && strcasecmp(o_fields_str, "all") == 0)
		die("\"-o all\" is invalid with -p");

	if (A_arg &&
	    (r_arg || t_arg || p_arg || o_arg || u_arg || i_arg))
		die("the option -A is not compatible with "
		    "-r, -t, -p, -o, -u, -i");

	/* get flow name (optional last argument) */
	if (optind == (argc-1)) {
		if (strlcpy(flowname, argv[optind], MAXFLOWNAMELEN)
		    >= MAXFLOWNAMELEN)
			die("flow name too long");
		flow_arg = B_TRUE;
	} else if (optind != argc) {
		usage();
	}

	if (flow_arg &&
	    dladm_flow_info(handle, flowname, &attr) != DLADM_STATUS_OK)
		die("invalid flow %s", flowname);

	if (A_arg) {
		dump_all_flow_stats(&attr, &state, linkid, flow_arg);
		return (0);
	}

	state.fs_unit = unit;
	state.fs_parsable = p_arg;

	if (state.fs_parsable)
		ofmtflags |= OFMT_PARSABLE;

	if (r_arg)
		fields_str = rx_stat_fields;
	else if (t_arg)
		fields_str = tx_stat_fields;
	else
		fields_str = total_stat_fields;

	if (o_arg) {
		fields_str = (strcasecmp(o_fields_str, "all") == 0) ?
		    fields_str : o_fields_str;
	}

	oferr = ofmt_open(fields_str, flow_s_fields, ofmtflags, 0, &ofmt);
	flowstat_ofmt_check(oferr, state.fs_parsable, ofmt);
	state.fs_ofmt = ofmt;

	for (;;) {
		/* Show stats for named flow */
		if (flow_arg)  {
			(void) query_flow_stats(handle, &attr, &state);

		/* Show stats for flows on one link */
		} else if (linkid != DATALINK_INVALID_LINKID) {
			(void) dladm_walk_flow(query_flow_stats, handle, linkid,
			    &state, B_FALSE);

		/* Show stats for all flows on all links */
		} else {
			(void) dladm_walk_datalink_id(query_link_flow_stats,
			    handle, &state, DATALINK_CLASS_ALL,
			    DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);
		}

		if (interval == 0)
			break;

		(void) fflush(stdout);
		cleanup_removed_flows(&state);
		(void) sleep(interval);
	}
	ofmt_close(ofmt);

	dladm_close(handle);
	return (0);
}

/* ARGSUSED */
static int
show_history_date(dladm_usage_t *history, void *arg)
{
	show_history_state_t	*state = (show_history_state_t *)arg;
	time_t			stime;
	char			timebuf[20];
	dladm_flow_attr_t	attr;
	dladm_status_t		status;

	/*
	 * Only show historical information for existing flows unless '-a'
	 * is specified.
	 */
	if (!state->us_showall && ((status = dladm_flow_info(handle,
	    history->du_name, &attr)) != DLADM_STATUS_OK)) {
		return (status);
	}

	stime = history->du_stime;
	(void) strftime(timebuf, sizeof (timebuf), "%m/%d/%Y",
	    localtime(&stime));
	(void) printf("%s\n", timebuf);

	return (DLADM_STATUS_OK);
}

static int
show_history_time(dladm_usage_t *history, void *arg)
{
	show_history_state_t	*state = (show_history_state_t *)arg;
	char			buf[DLADM_STRSIZE];
	history_l_fields_buf_t 	ubuf;
	time_t			time;
	double			bw;
	dladm_flow_attr_t	attr;
	dladm_status_t		status;

	/*
	 * Only show historical information for existing flows unless '-a'
	 * is specified.
	 */
	if (!state->us_showall && ((status = dladm_flow_info(handle,
	    history->du_name, &attr)) != DLADM_STATUS_OK)) {
		return (status);
	}

	if (state->us_plot) {
		if (!state->us_printheader) {
			if (state->us_first) {
				(void) printf("# Time");
				state->us_first = B_FALSE;
			}
			(void) printf(" %s", history->du_name);
			if (history->du_last) {
				(void) printf("\n");
				state->us_first = B_TRUE;
				state->us_printheader = B_TRUE;
			}
		} else {
			if (state->us_first) {
				time = history->du_etime;
				(void) strftime(buf, sizeof (buf), "%T",
				    localtime(&time));
				state->us_first = B_FALSE;
				(void) printf("%s", buf);
			}
			bw = (double)history->du_bandwidth/1000;
			(void) printf(" %.2f", bw);
			if (history->du_last) {
				(void) printf("\n");
				state->us_first = B_TRUE;
			}
		}
		return (DLADM_STATUS_OK);
	}

	bzero(&ubuf, sizeof (ubuf));

	(void) snprintf(ubuf.history_l_flow, sizeof (ubuf.history_l_flow), "%s",
	    history->du_name);
	time = history->du_stime;
	(void) strftime(buf, sizeof (buf), "%T", localtime(&time));
	(void) snprintf(ubuf.history_l_stime, sizeof (ubuf.history_l_stime),
	    "%s", buf);
	time = history->du_etime;
	(void) strftime(buf, sizeof (buf), "%T", localtime(&time));
	(void) snprintf(ubuf.history_l_etime, sizeof (ubuf.history_l_etime),
	    "%s", buf);
	(void) snprintf(ubuf.history_l_rbytes, sizeof (ubuf.history_l_rbytes),
	    "%llu", history->du_rbytes);
	(void) snprintf(ubuf.history_l_obytes, sizeof (ubuf.history_l_obytes),
	    "%llu", history->du_obytes);
	(void) snprintf(ubuf.history_l_bandwidth,
	    sizeof (ubuf.history_l_bandwidth), "%s Mbps",
	    dladm_bw2str(history->du_bandwidth, buf));

	ofmt_print(state->us_ofmt, (void *)&ubuf);
	return (DLADM_STATUS_OK);
}

static int
show_history_res(dladm_usage_t *history, void *arg)
{
	show_history_state_t	*state = (show_history_state_t *)arg;
	char			buf[DLADM_STRSIZE];
	history_fields_buf_t	ubuf;
	dladm_flow_attr_t	attr;
	dladm_status_t		status;

	/*
	 * Only show historical information for existing flows unless '-a'
	 * is specified.
	 */
	if (!state->us_showall && ((status = dladm_flow_info(handle,
	    history->du_name, &attr)) != DLADM_STATUS_OK)) {
		return (status);
	}

	bzero(&ubuf, sizeof (ubuf));

	(void) snprintf(ubuf.history_flow, sizeof (ubuf.history_flow), "%s",
	    history->du_name);
	(void) snprintf(ubuf.history_duration, sizeof (ubuf.history_duration),
	    "%llu", history->du_duration);
	(void) snprintf(ubuf.history_ipackets, sizeof (ubuf.history_ipackets),
	    "%llu", history->du_ipackets);
	(void) snprintf(ubuf.history_rbytes, sizeof (ubuf.history_rbytes),
	    "%llu", history->du_rbytes);
	(void) snprintf(ubuf.history_opackets, sizeof (ubuf.history_opackets),
	    "%llu", history->du_opackets);
	(void) snprintf(ubuf.history_obytes, sizeof (ubuf.history_obytes),
	    "%llu", history->du_obytes);
	(void) snprintf(ubuf.history_bandwidth, sizeof (ubuf.history_bandwidth),
	    "%s Mbps", dladm_bw2str(history->du_bandwidth, buf));

	ofmt_print(state->us_ofmt, (void *)&ubuf);

	return (DLADM_STATUS_OK);
}

static boolean_t
valid_formatspec(char *formatspec_str)
{
	return (strcmp(formatspec_str, "gnuplot") == 0);
}

/* ARGSUSED */
static void
do_show_history(int argc, char *argv[])
{
	char			*file = NULL;
	int			opt;
	dladm_status_t		status;
	boolean_t		d_arg = B_FALSE;
	char			*stime = NULL;
	char			*etime = NULL;
	char			*resource = NULL;
	show_history_state_t	state;
	boolean_t		o_arg = B_FALSE;
	boolean_t		F_arg = B_FALSE;
	char			*fields_str = NULL;
	char			*formatspec_str = NULL;
	char			*all_fields =
	    "flow,duration,ipackets,rbytes,opackets,obytes,bandwidth";
	char			*all_l_fields =
	    "flow,start,end,rbytes,obytes,bandwidth";
	ofmt_handle_t		ofmt;
	ofmt_status_t		oferr;
	uint_t			ofmtflags = 0;

	bzero(&state, sizeof (show_history_state_t));
	state.us_parsable = B_FALSE;
	state.us_printheader = B_FALSE;
	state.us_plot = B_FALSE;
	state.us_first = B_TRUE;

	while ((opt = getopt(argc, argv, "das:e:o:f:F:")) != -1) {
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
			die_opterr(optopt, opt, usage_ermsg);
		}
	}

	if (file == NULL)
		die("-h requires a file");

	if (optind == (argc-1)) {
		dladm_flow_attr_t	attr;

		resource = argv[optind];
		if (!state.us_showall &&
		    dladm_flow_info(handle, resource, &attr) !=
		    DLADM_STATUS_OK) {
			die("invalid flow: '%s'", resource);
		}
	}

	if (state.us_parsable)
		ofmtflags |= OFMT_PARSABLE;
	if (resource == NULL && stime == NULL && etime == NULL) {
		if (!o_arg || (o_arg && strcasecmp(fields_str, "all") == 0))
			fields_str = all_fields;
		oferr = ofmt_open(fields_str, history_fields, ofmtflags,
		    0, &ofmt);
	} else {
		if (!o_arg || (o_arg && strcasecmp(fields_str, "all") == 0))
			fields_str = all_l_fields;
		oferr = ofmt_open(fields_str, history_l_fields, ofmtflags,
		    0, &ofmt);
	}

	flowstat_ofmt_check(oferr, state.us_parsable, ofmt);
	state.us_ofmt = ofmt;

	if (F_arg && d_arg)
		die("incompatible -d and -F options");

	if (F_arg && !valid_formatspec(formatspec_str))
		die("Format specifier %s not supported", formatspec_str);

	if (d_arg) {
		/* Print log dates */
		status = dladm_usage_dates(show_history_date,
		    DLADM_LOGTYPE_FLOW, file, resource, &state);
	} else if (resource == NULL && stime == NULL && etime == NULL &&
	    !F_arg) {
		/* Print summary */
		status = dladm_usage_summary(show_history_res,
		    DLADM_LOGTYPE_FLOW, file, &state);
	} else if (resource != NULL) {
		/* Print log entries for named resource */
		status = dladm_walk_usage_res(show_history_time,
		    DLADM_LOGTYPE_FLOW, file, resource, stime, etime, &state);
	} else {
		/* Print time and information for each flow */
		status = dladm_walk_usage_time(show_history_time,
		    DLADM_LOGTYPE_FLOW, file, stime, etime, &state);
	}

	ofmt_close(ofmt);
	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "-h");
	dladm_close(handle);
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

static void
flowstat_ofmt_check(ofmt_status_t oferr, boolean_t parsable,
    ofmt_handle_t ofmt)
{
	char buf[OFMT_BUFSIZE];

	if (oferr == OFMT_SUCCESS)
		return;
	(void) ofmt_strerror(ofmt, oferr, buf, sizeof (buf));
	/*
	 * All errors are considered fatal in parsable mode.
	 * NOMEM errors are always fatal, regardless of mode.
	 * For other errors, we print diagnostics in human-readable
	 * mode and processs what we can.
	 */
	if (parsable || oferr == OFMT_ENOFIELDS) {
		ofmt_close(ofmt);
		die(buf);
	} else {
		warn(buf);
	}
}

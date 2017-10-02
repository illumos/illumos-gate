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
#include <libinetutil.h>
#include <bsm/adt.h>
#include <bsm/adt_event.h>
#include <stddef.h>
#include <ofmt.h>

typedef struct link_chain_s {
	datalink_id_t		lc_linkid;
	boolean_t		lc_visited;
	dladm_stat_chain_t	*lc_statchain[DLADM_STAT_NUM_STATS];
	struct link_chain_s	*lc_next;
} link_chain_t;

typedef void *	(*stats2str_t)(const char *, void *,
		    char, boolean_t);

typedef struct show_state {
	link_chain_t	*ls_linkchain;
	boolean_t	ls_stattype[DLADM_STAT_NUM_STATS];
	stats2str_t	ls_stats2str[DLADM_STAT_NUM_STATS];
	ofmt_handle_t	ls_ofmt;
	char		ls_unit;
	boolean_t	ls_parsable;
} show_state_t;

typedef struct show_history_state_s {
	boolean_t	hs_plot;
	boolean_t	hs_parsable;
	boolean_t	hs_printheader;
	boolean_t	hs_first;
	boolean_t	hs_showall;
	ofmt_handle_t	hs_ofmt;
} show_history_state_t;

/*
 * callback functions for printing output and error diagnostics.
 */
static ofmt_cb_t print_default_cb;

typedef void cmdfunc_t(int, char **, const char *);

static cmdfunc_t do_show, do_show_history, do_show_phys, do_show_link;
static cmdfunc_t do_show_aggr;

static void	die(const char *, ...);
static void	die_optdup(int);
static void	die_opterr(int, int, const char *);
static void	die_dlerr(dladm_status_t, const char *, ...);
static void	warn(const char *, ...);

typedef struct	cmd {
	char		*c_name;
	cmdfunc_t	*c_fn;
	const char	*c_usage;
} cmd_t;

static cmd_t	cmds[] = {
	{ "",		do_show,
	    "dlstat [-r | -t] [-i <interval>] [link]\n"
	    "       dlstat [-a | -A] [-i <interval>] [-p] [ -o field[,...]]\n"
	    "              [-u R|K|M|G|T|P] [link]"},
	{ "show-phys", do_show_phys,
	    "dlstat show-phys [-r | -t] [-i interval] [-a]\n"
	    "                 [-p] [ -o field[,...]] [-u R|K|M|G|T|P] "
	    "[link]"},
	{ "show-link", do_show_link,
	    "dlstat show-link [-r [-F] | -t] [-i interval] [-a]\n"
	    "                 [-p] [ -o field[,...]] [-u R|K|M|G|T|P] "
	    "[link]\n"
	    "       dlstat show-link -h [-a] [-d] [-F <format>]\n"
	    "                 [-s <DD/MM/YYYY,HH:MM:SS>] "
	    "[-e <DD/MM/YYYY,HH:MM:SS>]\n"
	    "                 -f <logfile> [<link>]" },
	{ "show-aggr", do_show_aggr,
	    "dlstat show-aggr [-r | -t] [-i interval] [-p]\n"
	    "                 [ -o field[,...]] [-u R|K|M|G|T|P] "
	    " [link]" }
};

#define	MAXSTATLEN 15

/*
 * dlstat : total stat fields
 */
typedef struct total_fields_buf_s {
	char t_linkname[MAXLINKNAMELEN];
	char t_ipackets[MAXSTATLEN];
	char t_rbytes[MAXSTATLEN];
	char t_opackets[MAXSTATLEN];
	char t_obytes[MAXSTATLEN];
} total_fields_buf_t;

static ofmt_field_t total_s_fields[] = {
{ "LINK",	15,
    offsetof(total_fields_buf_t, t_linkname),	print_default_cb},
{ "IPKTS",	8,
    offsetof(total_fields_buf_t, t_ipackets),	print_default_cb},
{ "RBYTES",	8,
    offsetof(total_fields_buf_t, t_rbytes),	print_default_cb},
{ "OPKTS",	8,
    offsetof(total_fields_buf_t, t_opackets),	print_default_cb},
{ "OBYTES",	8,
    offsetof(total_fields_buf_t, t_obytes),	print_default_cb},
{ NULL,		0,	0,		NULL}};

/*
 * dlstat show-phys: both Rx and Tx stat fields
 */
typedef struct ring_fields_buf_s {
	char r_linkname[MAXLINKNAMELEN];
	char r_type[MAXSTATLEN];
	char r_id[MAXSTATLEN];
	char r_index[MAXSTATLEN];
	char r_packets[MAXSTATLEN];
	char r_bytes[MAXSTATLEN];
} ring_fields_buf_t;

static ofmt_field_t ring_s_fields[] = {
{ "LINK",	15,
    offsetof(ring_fields_buf_t, r_linkname),	print_default_cb},
{ "TYPE",	5,
    offsetof(ring_fields_buf_t, r_type),	print_default_cb},
{ "ID",		7,
    offsetof(ring_fields_buf_t, r_id),		print_default_cb},
{ "INDEX",	6,
    offsetof(ring_fields_buf_t, r_index),	print_default_cb},
{ "PKTS",	8,
    offsetof(ring_fields_buf_t, r_packets),	print_default_cb},
{ "BYTES",	8,
    offsetof(ring_fields_buf_t, r_bytes),	print_default_cb},
{ NULL,		0,		0,		NULL}};

/*
 * dlstat show-phys -r: Rx Ring stat fields
 */
typedef struct rx_ring_fields_buf_s {
	char rr_linkname[MAXLINKNAMELEN];
	char rr_type[MAXSTATLEN];
	char rr_id[MAXSTATLEN];
	char rr_index[MAXSTATLEN];
	char rr_ipackets[MAXSTATLEN];
	char rr_rbytes[MAXSTATLEN];
} rx_ring_fields_buf_t;

static ofmt_field_t rx_ring_s_fields[] = {
{ "LINK",	15,
    offsetof(rx_ring_fields_buf_t, rr_linkname),	print_default_cb},
{ "TYPE",	5,
    offsetof(rx_ring_fields_buf_t, rr_type),		print_default_cb},
{ "ID",		7,
    offsetof(rx_ring_fields_buf_t, rr_id),		print_default_cb},
{ "INDEX",	6,
    offsetof(rx_ring_fields_buf_t, rr_index),		print_default_cb},
{ "IPKTS",	8,
    offsetof(rx_ring_fields_buf_t, rr_ipackets),	print_default_cb},
{ "RBYTES",	8,
    offsetof(rx_ring_fields_buf_t, rr_rbytes),		print_default_cb},
{ NULL,		0,		0,		NULL}};

/*
 * dlstat show-phys -t: Tx Ring stat fields
 */
typedef struct tx_ring_fields_buf_s {
	char tr_linkname[MAXLINKNAMELEN];
	char tr_type[MAXSTATLEN];
	char tr_id[MAXSTATLEN];
	char tr_index[MAXSTATLEN];
	char tr_opackets[MAXSTATLEN];
	char tr_obytes[MAXSTATLEN];
} tx_ring_fields_buf_t;

static ofmt_field_t tx_ring_s_fields[] = {
{ "LINK",	15,
    offsetof(tx_ring_fields_buf_t, tr_linkname),	print_default_cb},
{ "TYPE",	5,
    offsetof(tx_ring_fields_buf_t, tr_type),		print_default_cb},
{ "ID",		7,
    offsetof(tx_ring_fields_buf_t, tr_id),		print_default_cb},
{ "INDEX",	6,
    offsetof(tx_ring_fields_buf_t, tr_index),		print_default_cb},
{ "OPKTS",	8,
    offsetof(tx_ring_fields_buf_t, tr_opackets),	print_default_cb},
{ "OBYTES",	8,
    offsetof(tx_ring_fields_buf_t, tr_obytes),		print_default_cb},
{ NULL,		0,		0,		NULL}};

/*
 * dlstat show-link: both Rx and Tx lane fields
 */
typedef struct lane_fields_buf_s {
	char l_linkname[MAXLINKNAMELEN];
	char l_type[MAXSTATLEN];
	char l_id[MAXSTATLEN];
	char l_index[MAXSTATLEN];
	char l_packets[MAXSTATLEN];
	char l_bytes[MAXSTATLEN];
} lane_fields_buf_t;

static ofmt_field_t lane_s_fields[] = {
{ "LINK",	15,
    offsetof(lane_fields_buf_t, l_linkname),	print_default_cb},
{ "TYPE",	5,
    offsetof(lane_fields_buf_t, l_type),	print_default_cb},
{ "ID",		7,
    offsetof(lane_fields_buf_t, l_id),		print_default_cb},
{ "INDEX",	6,
    offsetof(lane_fields_buf_t, l_index),	print_default_cb},
{ "PKTS",	8,
    offsetof(lane_fields_buf_t, l_packets),	print_default_cb},
{ "BYTES",	8,
    offsetof(lane_fields_buf_t, l_bytes),	print_default_cb},
{ NULL,		0,		0,		NULL}};

/*
 * dlstat show-link -r, dlstat -r: Rx Lane stat fields
 */
typedef struct rx_lane_fields_buf_s {
	char rl_linkname[MAXLINKNAMELEN];
	char rl_type[MAXSTATLEN];
	char rl_id[MAXSTATLEN];
	char rl_index[MAXSTATLEN];
	char rl_ipackets[MAXSTATLEN];
	char rl_rbytes[MAXSTATLEN];
	char rl_intrs[MAXSTATLEN];
	char rl_polls[MAXSTATLEN];
	char rl_sdrops[MAXSTATLEN];
	char rl_chl10[MAXSTATLEN];
	char rl_ch10_50[MAXSTATLEN];
	char rl_chg50[MAXSTATLEN];
} rx_lane_fields_buf_t;

static ofmt_field_t rx_lane_s_fields[] = {
{ "LINK",	10,
    offsetof(rx_lane_fields_buf_t, rl_linkname),	print_default_cb},
{ "TYPE",	5,
    offsetof(rx_lane_fields_buf_t, rl_type),		print_default_cb},
{ "ID",		7,
    offsetof(rx_lane_fields_buf_t, rl_id),		print_default_cb},
{ "INDEX",	6,
    offsetof(rx_lane_fields_buf_t, rl_index),		print_default_cb},
{ "IPKTS",	8,
    offsetof(rx_lane_fields_buf_t, rl_ipackets),	print_default_cb},
{ "RBYTES",	8,
    offsetof(rx_lane_fields_buf_t, rl_rbytes),		print_default_cb},
{ "INTRS",	8,
    offsetof(rx_lane_fields_buf_t, rl_intrs),		print_default_cb},
{ "POLLS",	8,
    offsetof(rx_lane_fields_buf_t, rl_polls),		print_default_cb},
{ "SDROPS",	8,
    offsetof(rx_lane_fields_buf_t, rl_sdrops),		print_default_cb},
{ "CH<10",	8,
    offsetof(rx_lane_fields_buf_t, rl_chl10),		print_default_cb},
{ "CH10-50",	8,
    offsetof(rx_lane_fields_buf_t, rl_ch10_50),		print_default_cb},
{ "CH>50",	8,
    offsetof(rx_lane_fields_buf_t, rl_chg50),		print_default_cb},
{ NULL,		0,		0,		NULL}};

/*
 * dlstat show-link -r -F: Rx fanout stat fields
 */
typedef struct rx_fanout_lane_fields_buf_s {
	char rfl_linkname[MAXLINKNAMELEN];
	char rfl_type[MAXSTATLEN];
	char rfl_id[MAXSTATLEN];
	char rfl_index[MAXSTATLEN];
	char rfl_fout[MAXSTATLEN];
	char rfl_ipackets[MAXSTATLEN];
	char rfl_rbytes[MAXSTATLEN];
} rx_fanout_lane_fields_buf_t;

static ofmt_field_t rx_fanout_lane_s_fields[] = {
{ "LINK",	15,
    offsetof(rx_fanout_lane_fields_buf_t, rfl_linkname), print_default_cb},
{ "TYPE",	5,
    offsetof(rx_fanout_lane_fields_buf_t, rfl_type),	print_default_cb},
{ "ID",		7,
    offsetof(rx_fanout_lane_fields_buf_t, rfl_id),	print_default_cb},
{ "INDEX",	6,
    offsetof(rx_fanout_lane_fields_buf_t, rfl_index),	print_default_cb},
{ "FOUT",	6,
    offsetof(rx_fanout_lane_fields_buf_t, rfl_fout),	print_default_cb},
{ "IPKTS",	8,
    offsetof(rx_fanout_lane_fields_buf_t, rfl_ipackets), print_default_cb},
{ "RBYTES",	8,
    offsetof(rx_fanout_lane_fields_buf_t, rfl_rbytes),	print_default_cb},
{ NULL,		0,		0,		NULL}};

/*
 * dlstat show-link -t: Tx Lane stat fields
 */
typedef struct tx_lane_fields_buf_s {
	char tl_linkname[MAXLINKNAMELEN];
	char tl_index[MAXSTATLEN];
	char tl_type[MAXSTATLEN];
	char tl_id[MAXSTATLEN];
	char tl_opackets[MAXSTATLEN];
	char tl_obytes[MAXSTATLEN];
	char tl_blockcnt[MAXSTATLEN];
	char tl_unblockcnt[MAXSTATLEN];
	char tl_sdrops[MAXSTATLEN];
} tx_lane_fields_buf_t;

static ofmt_field_t tx_lane_s_fields[] = {
{ "LINK",	15,
    offsetof(tx_lane_fields_buf_t, tl_linkname),	print_default_cb},
{ "TYPE",	5,
    offsetof(tx_lane_fields_buf_t, tl_type),		print_default_cb},
{ "ID",		7,
    offsetof(tx_lane_fields_buf_t, tl_id),		print_default_cb},
{ "INDEX",	6,
    offsetof(tx_lane_fields_buf_t, tl_index),		print_default_cb},
{ "OPKTS",	8,
    offsetof(tx_lane_fields_buf_t, tl_opackets),	print_default_cb},
{ "OBYTES",	8,
    offsetof(tx_lane_fields_buf_t, tl_obytes),		print_default_cb},
{ "BLKCNT",	8,
    offsetof(tx_lane_fields_buf_t, tl_blockcnt),	print_default_cb},
{ "UBLKCNT",	8,
    offsetof(tx_lane_fields_buf_t, tl_unblockcnt),	print_default_cb},
{ "SDROPS",	8,
    offsetof(tx_lane_fields_buf_t, tl_sdrops),		print_default_cb},
{ NULL,		0,		0,		NULL}};

/*
 * dlstat show-aggr: aggr port stat fields
 */
typedef struct aggr_port_fields_buf_s {
	char ap_linkname[MAXLINKNAMELEN];
	char ap_portname[MAXLINKNAMELEN];
	char ap_ipackets[MAXSTATLEN];
	char ap_rbytes[MAXSTATLEN];
	char ap_opackets[MAXSTATLEN];
	char ap_obytes[MAXSTATLEN];
} aggr_port_fields_buf_t;

static ofmt_field_t aggr_port_s_fields[] = {
{ "LINK",	15,
    offsetof(aggr_port_fields_buf_t, ap_linkname),	print_default_cb},
{ "PORT",	15,
    offsetof(aggr_port_fields_buf_t, ap_portname),	print_default_cb},
{ "IPKTS",	8,
    offsetof(aggr_port_fields_buf_t, ap_ipackets),	print_default_cb},
{ "RBYTES",	8,
    offsetof(aggr_port_fields_buf_t, ap_rbytes),	print_default_cb},
{ "OPKTS",	8,
    offsetof(aggr_port_fields_buf_t, ap_opackets),	print_default_cb},
{ "OBYTES",	8,
    offsetof(aggr_port_fields_buf_t, ap_obytes),	print_default_cb},
{ NULL,		0,		0,		NULL}};

/*
 * structures for 'dlstat show-link -h'
 */
typedef struct  history_fields_buf_s {
	char	h_link[12];
	char	h_duration[10];
	char	h_ipackets[9];
	char	h_rbytes[10];
	char	h_opackets[9];
	char	h_obytes[10];
	char	h_bandwidth[14];
} history_fields_buf_t;

static ofmt_field_t history_fields[] = {
{ "LINK",	13,
	offsetof(history_fields_buf_t, h_link), print_default_cb},
{ "DURATION",	11,
	offsetof(history_fields_buf_t, h_duration), print_default_cb},
{ "IPKTS",	10,
	offsetof(history_fields_buf_t, h_ipackets), print_default_cb},
{ "RBYTES",	11,
	offsetof(history_fields_buf_t, h_rbytes), print_default_cb},
{ "OPKTS",	10,
	offsetof(history_fields_buf_t, h_opackets), print_default_cb},
{ "OBYTES",	11,
	offsetof(history_fields_buf_t, h_obytes), print_default_cb},
{ "BANDWIDTH",	15,
	offsetof(history_fields_buf_t, h_bandwidth), print_default_cb},
{ NULL,		0, 0, NULL}};

/*
 * structures for 'dlstat show-link -h link'
 */
typedef struct  history_l_fields_buf_s {
	char	hl_link[12];
	char	hl_stime[13];
	char	hl_etime[13];
	char	hl_rbytes[8];
	char	hl_obytes[8];
	char	hl_bandwidth[14];
} history_l_fields_buf_t;

static ofmt_field_t history_l_fields[] = {
/* name,	field width,	offset */
{ "LINK",	13,
	offsetof(history_l_fields_buf_t, hl_link), print_default_cb},
{ "START",	14,
	offsetof(history_l_fields_buf_t, hl_stime), print_default_cb},
{ "END",	14,
	offsetof(history_l_fields_buf_t, hl_etime), print_default_cb},
{ "RBYTES",	9,
	offsetof(history_l_fields_buf_t, hl_rbytes), print_default_cb},
{ "OBYTES",	9,
	offsetof(history_l_fields_buf_t, hl_obytes), print_default_cb},
{ "BANDWIDTH",	15,
	offsetof(history_l_fields_buf_t, hl_bandwidth), print_default_cb},
{ NULL,		0, 0, NULL}}
;

static char *progname;

/*
 * Handle to libdladm.  Opened in main() before the sub-command
 * specific function is called.
 */
static dladm_handle_t handle = NULL;

static void
usage(void)
{
	int	i;
	cmd_t	*cmdp;

	(void) fprintf(stderr, gettext("usage: "));
	for (i = 0; i < sizeof (cmds) / sizeof (cmds[0]); i++) {
		cmdp = &cmds[i];
		if (cmdp->c_usage != NULL)
			(void) fprintf(stderr, "%s\n", gettext(cmdp->c_usage));
	}

	/* close dladm handle if it was opened */
	if (handle != NULL)
		dladm_close(handle);

	exit(1);
}

int
main(int argc, char *argv[])
{
	int		i;
	cmd_t		*cmdp;
	dladm_status_t	status;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	progname = argv[0];

	/* Open the libdladm handle */
	if ((status = dladm_open(&handle)) != DLADM_STATUS_OK)
		die_dlerr(status, "could not open /dev/dld");

	if (argc == 1) {
		do_show(argc - 1, NULL, cmds[0].c_usage);
		goto done;
	}

	for (i = 0; i < sizeof (cmds) / sizeof (cmds[0]); i++) {
		cmdp = &cmds[i];
		if (strcmp(argv[1], cmdp->c_name) == 0) {
			cmdp->c_fn(argc - 1, &argv[1], cmdp->c_usage);
			goto done;
		}
	}

	do_show(argc, &argv[0], cmds[0].c_usage);

done:
	dladm_close(handle);
	return (0);
}

/*ARGSUSED*/
static int
show_history_date(dladm_usage_t *history, void *arg)
{
	show_history_state_t	*state = arg;
	time_t			stime;
	char			timebuf[20];
	dladm_status_t		status;
	uint32_t		flags;

	/*
	 * Only show history information for existing links unless '-a'
	 * is specified.
	 */
	if (!state->hs_showall) {
		if ((status = dladm_name2info(handle, history->du_name,
		    NULL, &flags, NULL, NULL)) != DLADM_STATUS_OK) {
			return (status);
		}
		if ((flags & DLADM_OPT_ACTIVE) == 0)
			return (DLADM_STATUS_LINKINVAL);
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
	show_history_state_t	*state = arg;
	char			buf[DLADM_STRSIZE];
	history_l_fields_buf_t 	ubuf;
	time_t			time;
	double			bw;
	dladm_status_t		status;
	uint32_t		flags;

	/*
	 * Only show history information for existing links unless '-a'
	 * is specified.
	 */
	if (!state->hs_showall) {
		if ((status = dladm_name2info(handle, history->du_name,
		    NULL, &flags, NULL, NULL)) != DLADM_STATUS_OK) {
			return (status);
		}
		if ((flags & DLADM_OPT_ACTIVE) == 0)
			return (DLADM_STATUS_LINKINVAL);
	}

	if (state->hs_plot) {
		if (!state->hs_printheader) {
			if (state->hs_first) {
				(void) printf("# Time");
				state->hs_first = B_FALSE;
			}
			(void) printf(" %s", history->du_name);
			if (history->du_last) {
				(void) printf("\n");
				state->hs_first = B_TRUE;
				state->hs_printheader = B_TRUE;
			}
		} else {
			if (state->hs_first) {
				time = history->du_etime;
				(void) strftime(buf, sizeof (buf), "%T",
				    localtime(&time));
				state->hs_first = B_FALSE;
				(void) printf("%s", buf);
			}
			bw = (double)history->du_bandwidth/1000;
			(void) printf(" %.2f", bw);
			if (history->du_last) {
				(void) printf("\n");
				state->hs_first = B_TRUE;
			}
		}
		return (DLADM_STATUS_OK);
	}

	bzero(&ubuf, sizeof (ubuf));

	(void) snprintf(ubuf.hl_link, sizeof (ubuf.hl_link), "%s",
	    history->du_name);
	time = history->du_stime;
	(void) strftime(buf, sizeof (buf), "%T", localtime(&time));
	(void) snprintf(ubuf.hl_stime, sizeof (ubuf.hl_stime), "%s",
	    buf);
	time = history->du_etime;
	(void) strftime(buf, sizeof (buf), "%T", localtime(&time));
	(void) snprintf(ubuf.hl_etime, sizeof (ubuf.hl_etime), "%s",
	    buf);
	(void) snprintf(ubuf.hl_rbytes, sizeof (ubuf.hl_rbytes),
	    "%llu", history->du_rbytes);
	(void) snprintf(ubuf.hl_obytes, sizeof (ubuf.hl_obytes),
	    "%llu", history->du_obytes);
	(void) snprintf(ubuf.hl_bandwidth, sizeof (ubuf.hl_bandwidth),
	    "%s Mbps", dladm_bw2str(history->du_bandwidth, buf));

	ofmt_print(state->hs_ofmt, &ubuf);
	return (DLADM_STATUS_OK);
}

static int
show_history_res(dladm_usage_t *history, void *arg)
{
	show_history_state_t	*state = arg;
	char			buf[DLADM_STRSIZE];
	history_fields_buf_t	ubuf;
	dladm_status_t		status;
	uint32_t		flags;

	/*
	 * Only show history information for existing links unless '-a'
	 * is specified.
	 */
	if (!state->hs_showall) {
		if ((status = dladm_name2info(handle, history->du_name,
		    NULL, &flags, NULL, NULL)) != DLADM_STATUS_OK) {
			return (status);
		}
		if ((flags & DLADM_OPT_ACTIVE) == 0)
			return (DLADM_STATUS_LINKINVAL);
	}

	bzero(&ubuf, sizeof (ubuf));

	(void) snprintf(ubuf.h_link, sizeof (ubuf.h_link), "%s",
	    history->du_name);
	(void) snprintf(ubuf.h_duration, sizeof (ubuf.h_duration),
	    "%llu", history->du_duration);
	(void) snprintf(ubuf.h_ipackets, sizeof (ubuf.h_ipackets),
	    "%llu", history->du_ipackets);
	(void) snprintf(ubuf.h_rbytes, sizeof (ubuf.h_rbytes),
	    "%llu", history->du_rbytes);
	(void) snprintf(ubuf.h_opackets, sizeof (ubuf.h_opackets),
	    "%llu", history->du_opackets);
	(void) snprintf(ubuf.h_obytes, sizeof (ubuf.h_obytes),
	    "%llu", history->du_obytes);
	(void) snprintf(ubuf.h_bandwidth, sizeof (ubuf.h_bandwidth),
	    "%s Mbps", dladm_bw2str(history->du_bandwidth, buf));

	ofmt_print(state->hs_ofmt, &ubuf);

	return (DLADM_STATUS_OK);
}

static boolean_t
valid_formatspec(char *formatspec_str)
{
	return (strcmp(formatspec_str, "gnuplot") == 0);
}

/*ARGSUSED*/
static void
do_show_history(int argc, char *argv[], const char *use)
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
	char			*all_l_fields =
	    "link,start,end,rbytes,obytes,bandwidth";
	ofmt_handle_t		ofmt;
	ofmt_status_t		oferr;
	uint_t			ofmtflags = 0;

	bzero(&state, sizeof (show_history_state_t));
	state.hs_parsable = B_FALSE;
	state.hs_printheader = B_FALSE;
	state.hs_plot = B_FALSE;
	state.hs_first = B_TRUE;

	while ((opt = getopt(argc, argv, "das:e:o:f:F:")) != -1) {
		switch (opt) {
		case 'd':
			d_arg = B_TRUE;
			break;
		case 'a':
			state.hs_showall = B_TRUE;
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
			state.hs_plot = F_arg = B_TRUE;
			formatspec_str = optarg;
			break;
		default:
			die_opterr(optopt, opt, use);
			break;
		}
	}

	if (file == NULL)
		die("show-link -h requires a file");

	if (optind == (argc-1)) {
		uint32_t 	flags;

		resource = argv[optind];
		if (!state.hs_showall &&
		    (((status = dladm_name2info(handle, resource, NULL, &flags,
		    NULL, NULL)) != DLADM_STATUS_OK) ||
		    ((flags & DLADM_OPT_ACTIVE) == 0))) {
			die("invalid link: '%s'", resource);
		}
	}

	if (F_arg && d_arg)
		die("incompatible -d and -F options");

	if (F_arg && !valid_formatspec(formatspec_str))
		die("Format specifier %s not supported", formatspec_str);

	if (state.hs_parsable)
		ofmtflags |= OFMT_PARSABLE;

	if (resource == NULL && stime == NULL && etime == NULL) {
		oferr = ofmt_open(fields_str, history_fields, ofmtflags, 0,
		    &ofmt);
	} else {
		if (!o_arg || (o_arg && strcasecmp(fields_str, "all") == 0))
			fields_str = all_l_fields;
		oferr = ofmt_open(fields_str, history_l_fields, ofmtflags, 0,
		    &ofmt);

	}
	ofmt_check(oferr, state.hs_parsable, ofmt, die, warn);
	state.hs_ofmt = ofmt;

	if (d_arg) {
		/* Print log dates */
		status = dladm_usage_dates(show_history_date,
		    DLADM_LOGTYPE_LINK, file, resource, &state);
	} else if (resource == NULL && stime == NULL && etime == NULL &&
	    !F_arg) {
		/* Print summary */
		status = dladm_usage_summary(show_history_res,
		    DLADM_LOGTYPE_LINK, file, &state);
	} else if (resource != NULL) {
		/* Print log entries for named resource */
		status = dladm_walk_usage_res(show_history_time,
		    DLADM_LOGTYPE_LINK, file, resource, stime, etime, &state);
	} else {
		/* Print time and information for each link */
		status = dladm_walk_usage_time(show_history_time,
		    DLADM_LOGTYPE_LINK, file, stime, etime, &state);
	}

	if (status != DLADM_STATUS_OK)
		die_dlerr(status, "show-link -h");
	ofmt_close(ofmt);
}

boolean_t
dlstat_unit(char *oarg, char *unit)
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

link_chain_t *
get_link_prev_stat(datalink_id_t linkid, void *arg)
{
	show_state_t	*state = (show_state_t *)arg;
	link_chain_t	*link_curr = NULL;

	/* Scan prev linkid list and look for entry matching this entry */
	for (link_curr = state->ls_linkchain; link_curr;
	    link_curr = link_curr->lc_next) {
		if (link_curr->lc_linkid == linkid)
			break;
	}
				/* New link, add it */
	if (link_curr == NULL) {
		link_curr = (link_chain_t *)malloc(sizeof (link_chain_t));
		if (link_curr == NULL)
			goto done;
		link_curr->lc_linkid = linkid;
		bzero(&link_curr->lc_statchain,
		    sizeof (link_curr->lc_statchain));
		link_curr->lc_next = state->ls_linkchain;
		state->ls_linkchain = link_curr;
	}
done:
	return (link_curr);
}

/*
 * Number of links may change while dlstat with -i is executing.
 * Free memory allocated for links that are no longer there.
 * Prepare for next iteration by marking visited = false for existing stat
 * entries.
 */
static void
cleanup_removed_links(show_state_t *state)
{
	link_chain_t	*lcurr;
	link_chain_t	*lprev;
	link_chain_t	*tofree;
	int		i;

	/* Delete all nodes from the list that have lc_visited marked false */
	lcurr = state->ls_linkchain;
	while (lcurr != NULL) {
		if (lcurr->lc_visited) {
			lcurr->lc_visited = B_FALSE;
			lprev = lcurr;
			lcurr = lcurr->lc_next;
			continue;
		}
				/* Is it head of the list? */
		if (lcurr == state->ls_linkchain)
			state->ls_linkchain = lcurr->lc_next;
		else
			lprev->lc_next = lcurr->lc_next;
				/* lprev remains the same */
		tofree = lcurr;
		lcurr = lcurr->lc_next;

				/* Free stats memory for the removed link */
		for (i = 0; i < DLADM_STAT_NUM_STATS; i++) {
			if (state->ls_stattype[i])
				dladm_link_stat_free(tofree->lc_statchain[i]);
		}
		free(tofree);
	}
}

void *
print_total_stats(const char *linkname, void *statentry, char unit,
    boolean_t parsable)
{
	total_stat_entry_t	*sentry = statentry;
	total_stat_t		*link_stats = &sentry->tse_stats;
	total_fields_buf_t	*buf;

	buf = malloc(sizeof (total_fields_buf_t));
	if (buf == NULL)
		goto done;

	(void) snprintf(buf->t_linkname, sizeof (buf->t_linkname), "%s",
	    linkname);

	map_to_units(buf->t_ipackets, sizeof (buf->t_ipackets),
	    link_stats->ts_ipackets, unit, parsable);

	map_to_units(buf->t_rbytes, sizeof (buf->t_rbytes),
	    link_stats->ts_rbytes, unit, parsable);

	map_to_units(buf->t_opackets, sizeof (buf->t_opackets),
	    link_stats->ts_opackets, unit, parsable);

	map_to_units(buf->t_obytes, sizeof (buf->t_obytes),
	    link_stats->ts_obytes, unit, parsable);

done:
	return (buf);
}

void *
print_rx_generic_ring_stats(const char *linkname, void *statentry, char unit,
    boolean_t parsable)
{
	ring_stat_entry_t	*sentry = statentry;
	ring_stat_t		*link_stats = &sentry->re_stats;
	ring_fields_buf_t	*buf;

	buf = malloc(sizeof (ring_fields_buf_t));
	if (buf == NULL)
		goto done;

	(void) snprintf(buf->r_linkname, sizeof (buf->r_linkname), "%s",
	    linkname);

	(void) snprintf(buf->r_type, sizeof (buf->r_type), "rx");

	if (sentry->re_index == DLSTAT_INVALID_ENTRY) {
		(void) snprintf(buf->r_index, sizeof (buf->r_index), "--");
	} else {
		(void) snprintf(buf->r_index, sizeof (buf->r_index),
		    "%llu", sentry->re_index);
	}

	map_to_units(buf->r_packets, sizeof (buf->r_packets),
	    link_stats->r_packets, unit, parsable);

	map_to_units(buf->r_bytes, sizeof (buf->r_bytes),
	    link_stats->r_bytes, unit, parsable);

done:
	return (buf);
}

void *
print_tx_generic_ring_stats(const char *linkname, void *statentry, char unit,
    boolean_t parsable)
{
	ring_stat_entry_t	*sentry = statentry;
	ring_stat_t		*link_stats = &sentry->re_stats;
	ring_fields_buf_t	*buf;

	buf = malloc(sizeof (ring_fields_buf_t));
	if (buf == NULL)
		goto done;

	(void) snprintf(buf->r_linkname, sizeof (buf->r_linkname), "%s",
	    linkname);

	(void) snprintf(buf->r_type, sizeof (buf->r_type), "tx");

	if (sentry->re_index == DLSTAT_INVALID_ENTRY) {
		(void) snprintf(buf->r_index, sizeof (buf->r_index), "--");
	} else {
		(void) snprintf(buf->r_index, sizeof (buf->r_index),
		    "%llu", sentry->re_index);
	}

	map_to_units(buf->r_packets, sizeof (buf->r_packets),
	    link_stats->r_packets, unit, parsable);

	map_to_units(buf->r_bytes, sizeof (buf->r_bytes),
	    link_stats->r_bytes, unit, parsable);

done:
	return (buf);
}

void *
print_rx_ring_stats(const char *linkname, void *statentry, char unit,
    boolean_t parsable)
{
	ring_stat_entry_t	*sentry = statentry;
	ring_stat_t		*link_stats = &sentry->re_stats;
	rx_ring_fields_buf_t	*buf;

	buf = malloc(sizeof (rx_ring_fields_buf_t));
	if (buf == NULL)
		goto done;

	(void) snprintf(buf->rr_linkname, sizeof (buf->rr_linkname), "%s",
	    linkname);

	(void) snprintf(buf->rr_type, sizeof (buf->rr_type), "rx");

	if (sentry->re_index == DLSTAT_INVALID_ENTRY) {
		(void) snprintf(buf->rr_index, sizeof (buf->rr_index), "--");
	} else {
		(void) snprintf(buf->rr_index, sizeof (buf->rr_index),
		    "%llu", sentry->re_index);
	}

	map_to_units(buf->rr_ipackets, sizeof (buf->rr_ipackets),
	    link_stats->r_packets, unit, parsable);

	map_to_units(buf->rr_rbytes, sizeof (buf->rr_rbytes),
	    link_stats->r_bytes, unit, parsable);

done:
	return (buf);
}

void *
print_tx_ring_stats(const char *linkname, void *statentry, char unit,
    boolean_t parsable)
{
	ring_stat_entry_t	*sentry = statentry;
	ring_stat_t		*link_stats = &sentry->re_stats;
	tx_ring_fields_buf_t	*buf;

	buf = malloc(sizeof (tx_ring_fields_buf_t));
	if (buf == NULL)
		goto done;

	(void) snprintf(buf->tr_linkname, sizeof (buf->tr_linkname), "%s",
	    linkname);

	(void) snprintf(buf->tr_type, sizeof (buf->tr_type), "tx");

	if (sentry->re_index == DLSTAT_INVALID_ENTRY) {
		(void) snprintf(buf->tr_index, sizeof (buf->tr_index), "--");
	} else {
		(void) snprintf(buf->tr_index, sizeof (buf->tr_index),
		    "%llu", sentry->re_index);
	}

	map_to_units(buf->tr_opackets, sizeof (buf->tr_opackets),
	    link_stats->r_packets, unit, parsable);

	map_to_units(buf->tr_obytes, sizeof (buf->tr_obytes),
	    link_stats->r_bytes, unit, parsable);

done:
	return (buf);
}

void *
print_rx_generic_lane_stats(const char *linkname, void *statentry, char unit,
    boolean_t parsable)
{
	rx_lane_stat_entry_t	*sentry = statentry;
	rx_lane_stat_t		*link_stats = &sentry->rle_stats;
	lane_fields_buf_t	*buf;

	if (sentry->rle_id == L_DFNCT)
		return (NULL);

	buf = malloc(sizeof (lane_fields_buf_t));
	if (buf == NULL)
		goto done;

	(void) snprintf(buf->l_linkname, sizeof (buf->l_linkname), "%s",
	    linkname);

	(void) snprintf(buf->l_type, sizeof (buf->l_type), "rx");

	if (sentry->rle_id == L_HWLANE)
		(void) snprintf(buf->l_id, sizeof (buf->l_id), "hw");
	else if (sentry->rle_id == L_SWLANE)
		(void) snprintf(buf->l_id, sizeof (buf->l_id), "sw");
	else if (sentry->rle_id == L_LOCAL)
		(void) snprintf(buf->l_id, sizeof (buf->l_id), "local");
	else if (sentry->rle_id == L_BCAST)
		(void) snprintf(buf->l_id, sizeof (buf->l_id), "bcast");
	else
		(void) snprintf(buf->l_id, sizeof (buf->l_id), "--");

	if (sentry->rle_index == DLSTAT_INVALID_ENTRY) {
		(void) snprintf(buf->l_index, sizeof (buf->l_index), "--");
	} else {
		(void) snprintf(buf->l_index, sizeof (buf->l_index),
		    "%llu", sentry->rle_index);
	}

	map_to_units(buf->l_packets, sizeof (buf->l_packets),
	    link_stats->rl_ipackets, unit, parsable);

	map_to_units(buf->l_bytes, sizeof (buf->l_bytes),
	    link_stats->rl_rbytes, unit, parsable);

done:
	return (buf);
}

void *
print_tx_generic_lane_stats(const char *linkname, void *statentry, char unit,
    boolean_t parsable)
{
	tx_lane_stat_entry_t	*sentry = statentry;
	tx_lane_stat_t		*link_stats = &sentry->tle_stats;
	lane_fields_buf_t	*buf;

	if (sentry->tle_id == L_DFNCT)
		return (NULL);

	buf = malloc(sizeof (lane_fields_buf_t));
	if (buf == NULL)
		goto done;

	(void) snprintf(buf->l_linkname, sizeof (buf->l_linkname), "%s",
	    linkname);

	(void) snprintf(buf->l_type, sizeof (buf->l_type), "tx");

	if (sentry->tle_id == L_HWLANE)
		(void) snprintf(buf->l_id, sizeof (buf->l_id), "hw");
	else if (sentry->tle_id == L_SWLANE)
		(void) snprintf(buf->l_id, sizeof (buf->l_id), "sw");
	else if (sentry->tle_id == L_BCAST)
		(void) snprintf(buf->l_id, sizeof (buf->l_id), "bcast");
	else
		(void) snprintf(buf->l_id, sizeof (buf->l_id), "--");

	if (sentry->tle_index == DLSTAT_INVALID_ENTRY) {
		(void) snprintf(buf->l_index, sizeof (buf->l_index), "--");
	} else {
		(void) snprintf(buf->l_index, sizeof (buf->l_index),
		    "%llu", sentry->tle_index);
	}
	map_to_units(buf->l_packets, sizeof (buf->l_packets),
	    link_stats->tl_opackets, unit, parsable);

	map_to_units(buf->l_bytes, sizeof (buf->l_bytes),
	    link_stats->tl_obytes, unit, parsable);

done:
	return (buf);
}

void *
print_rx_lane_stats(const char *linkname, void *statentry, char unit,
    boolean_t parsable)
{
	rx_lane_stat_entry_t	*sentry = statentry;
	rx_lane_stat_t		*link_stats = &sentry->rle_stats;
	rx_lane_fields_buf_t	*buf;

	if (sentry->rle_id == L_DFNCT)
		return (NULL);

	buf = malloc(sizeof (rx_lane_fields_buf_t));
	if (buf == NULL)
		goto done;

	(void) snprintf(buf->rl_linkname, sizeof (buf->rl_linkname), "%s",
	    linkname);

	(void) snprintf(buf->rl_type, sizeof (buf->rl_type), "rx");

	if (sentry->rle_id == L_HWLANE)
		(void) snprintf(buf->rl_id, sizeof (buf->rl_id), "hw");
	else if (sentry->rle_id == L_SWLANE)
		(void) snprintf(buf->rl_id, sizeof (buf->rl_id), "sw");
	else if (sentry->rle_id == L_LOCAL)
		(void) snprintf(buf->rl_id, sizeof (buf->rl_id), "local");
	else if (sentry->rle_id == L_BCAST)
		(void) snprintf(buf->rl_id, sizeof (buf->rl_id), "bcast");
	else
		(void) snprintf(buf->rl_id, sizeof (buf->rl_id), "--");

	if (sentry->rle_index == DLSTAT_INVALID_ENTRY) {
		(void) snprintf(buf->rl_index, sizeof (buf->rl_index), "--");
	} else {
		(void) snprintf(buf->rl_index, sizeof (buf->rl_index),
		    "%llu", sentry->rle_index);
	}

	map_to_units(buf->rl_ipackets, sizeof (buf->rl_ipackets),
	    link_stats->rl_ipackets, unit, parsable);

	map_to_units(buf->rl_rbytes, sizeof (buf->rl_rbytes),
	    link_stats->rl_rbytes, unit, parsable);

	map_to_units(buf->rl_intrs, sizeof (buf->rl_intrs),
	    link_stats->rl_intrs, unit, parsable);

	map_to_units(buf->rl_polls, sizeof (buf->rl_polls),
	    link_stats->rl_polls, unit, parsable);

	map_to_units(buf->rl_sdrops, sizeof (buf->rl_sdrops),
	    link_stats->rl_sdrops, unit, parsable);

	map_to_units(buf->rl_chl10, sizeof (buf->rl_chl10),
	    link_stats->rl_chl10, unit, parsable);

	map_to_units(buf->rl_ch10_50, sizeof (buf->rl_ch10_50),
	    link_stats->rl_ch10_50, unit, parsable);

	map_to_units(buf->rl_chg50, sizeof (buf->rl_chg50),
	    link_stats->rl_chg50, unit, parsable);

done:
	return (buf);
}

void *
print_tx_lane_stats(const char *linkname, void *statentry, char unit,
    boolean_t parsable)
{
	tx_lane_stat_entry_t	*sentry = statentry;
	tx_lane_stat_t		*link_stats = &sentry->tle_stats;
	tx_lane_fields_buf_t	*buf = NULL;

	if (sentry->tle_id == L_DFNCT)
		return (NULL);

	buf = malloc(sizeof (tx_lane_fields_buf_t));
	if (buf == NULL)
		goto done;

	(void) snprintf(buf->tl_linkname, sizeof (buf->tl_linkname), "%s",
	    linkname);

	(void) snprintf(buf->tl_type, sizeof (buf->tl_type), "tx");

	if (sentry->tle_id == L_HWLANE)
		(void) snprintf(buf->tl_id, sizeof (buf->tl_id), "hw");
	else if (sentry->tle_id == L_SWLANE)
		(void) snprintf(buf->tl_id, sizeof (buf->tl_id), "sw");
	else if (sentry->tle_id == L_BCAST)
		(void) snprintf(buf->tl_id, sizeof (buf->tl_id), "bcast");
	else
		(void) snprintf(buf->tl_id, sizeof (buf->tl_id), "--");

	if (sentry->tle_index == DLSTAT_INVALID_ENTRY) {
		(void) snprintf(buf->tl_index, sizeof (buf->tl_index), "--");
	} else {
		(void) snprintf(buf->tl_index, sizeof (buf->tl_index),
		    "%llu", sentry->tle_index);
	}

	map_to_units(buf->tl_opackets, sizeof (buf->tl_opackets),
	    link_stats->tl_opackets, unit, parsable);

	map_to_units(buf->tl_obytes, sizeof (buf->tl_obytes),
	    link_stats->tl_obytes, unit, parsable);

	map_to_units(buf->tl_blockcnt, sizeof (buf->tl_blockcnt),
	    link_stats->tl_blockcnt, unit, parsable);

	map_to_units(buf->tl_unblockcnt, sizeof (buf->tl_unblockcnt),
	    link_stats->tl_unblockcnt, unit, parsable);

	map_to_units(buf->tl_sdrops, sizeof (buf->tl_sdrops),
	    link_stats->tl_sdrops, unit, parsable);

done:
	return (buf);
}

void *
print_fanout_stats(const char *linkname, void *statentry, char unit,
    boolean_t parsable)
{
	fanout_stat_entry_t		*sentry = statentry;
	fanout_stat_t			*link_stats = &sentry->fe_stats;
	rx_fanout_lane_fields_buf_t	*buf;

	buf = malloc(sizeof (rx_fanout_lane_fields_buf_t));
	if (buf == NULL)
		goto done;

	(void) snprintf(buf->rfl_linkname, sizeof (buf->rfl_linkname), "%s",
	    linkname);

	(void) snprintf(buf->rfl_type, sizeof (buf->rfl_type), "rx");

	if (sentry->fe_id == L_HWLANE)
		(void) snprintf(buf->rfl_id, sizeof (buf->rfl_id), "hw");
	else if (sentry->fe_id == L_SWLANE)
		(void) snprintf(buf->rfl_id, sizeof (buf->rfl_id), "sw");
	else if (sentry->fe_id == L_LCLSWLANE)
		(void) snprintf(buf->rfl_id, sizeof (buf->rfl_id), "lcl/sw");
	else if (sentry->fe_id == L_LOCAL)
		(void) snprintf(buf->rfl_id, sizeof (buf->rfl_id), "local");
	else if (sentry->fe_id == L_BCAST)
		(void) snprintf(buf->rfl_id, sizeof (buf->rfl_id), "bcast");
	else
		(void) snprintf(buf->rfl_id, sizeof (buf->rfl_id), "--");

	if (sentry->fe_index == DLSTAT_INVALID_ENTRY) {
		(void) snprintf(buf->rfl_index, sizeof (buf->rfl_index), "--");
	} else {
		(void) snprintf(buf->rfl_index, sizeof (buf->rfl_index),
		    "%llu", sentry->fe_index);
	}

	if (sentry->fe_foutindex == DLSTAT_INVALID_ENTRY)
		(void) snprintf(buf->rfl_fout, sizeof (buf->rfl_fout), "--");
	else {
		(void) snprintf(buf->rfl_fout, sizeof (buf->rfl_fout), "%llu",
		    sentry->fe_foutindex);
	}

	map_to_units(buf->rfl_ipackets, sizeof (buf->rfl_ipackets),
	    link_stats->f_ipackets, unit, parsable);

	map_to_units(buf->rfl_rbytes, sizeof (buf->rfl_rbytes),
	    link_stats->f_rbytes, unit, parsable);

done:
	return (buf);
}

void *
print_aggr_port_stats(const char *linkname, void *statentry, char unit,
    boolean_t parsable)
{
	aggr_port_stat_entry_t	*sentry = statentry;
	aggr_port_stat_t	*link_stats = &sentry->ape_stats;
	aggr_port_fields_buf_t	*buf;
	char			portname[MAXLINKNAMELEN];

	buf = malloc(sizeof (aggr_port_fields_buf_t));
	if (buf == NULL)
		goto done;

	(void) snprintf(buf->ap_linkname, sizeof (buf->ap_linkname), "%s",
	    linkname);

	if (dladm_datalink_id2info(handle, sentry->ape_portlinkid, NULL,
	    NULL, NULL, portname, DLPI_LINKNAME_MAX)
	    != DLADM_STATUS_OK) {
		(void) snprintf(buf->ap_portname,
		    sizeof (buf->ap_portname), "--");
	} else {
		(void) snprintf(buf->ap_portname,
		    sizeof (buf->ap_portname), "%s", portname);
	}

	map_to_units(buf->ap_ipackets, sizeof (buf->ap_ipackets),
	    link_stats->ap_ipackets, unit, parsable);

	map_to_units(buf->ap_rbytes, sizeof (buf->ap_rbytes),
	    link_stats->ap_rbytes, unit, parsable);

	map_to_units(buf->ap_opackets, sizeof (buf->ap_opackets),
	    link_stats->ap_opackets, unit, parsable);

	map_to_units(buf->ap_obytes, sizeof (buf->ap_obytes),
	    link_stats->ap_obytes, unit, parsable);

done:
	return (buf);
}

dladm_stat_chain_t *
query_link_stats(dladm_handle_t dh, datalink_id_t linkid, void *arg,
    dladm_stat_type_t stattype)
{
	link_chain_t		*link_node;
	dladm_stat_chain_t	*curr_stat;
	dladm_stat_chain_t	*prev_stat = NULL;
	dladm_stat_chain_t	*diff_stat = NULL;

	/*  Get prev iteration stat for this link */
	link_node = get_link_prev_stat(linkid, arg);
	if (link_node == NULL)
		goto done;

	link_node->lc_visited = B_TRUE;
	prev_stat = link_node->lc_statchain[stattype];

	/* Query library for current stats */
	curr_stat = dladm_link_stat_query(dh, linkid, stattype);
	if (curr_stat == NULL)
		goto done;

	/* current stats - prev iteration stats */
	diff_stat = dladm_link_stat_diffchain(curr_stat, prev_stat, stattype);

	/* Free prev stats */
	dladm_link_stat_free(prev_stat);

	/* Prev <- curr stats */
	link_node->lc_statchain[stattype] = curr_stat;

done:
	return (diff_stat);
}

void
walk_dlstat_stats(show_state_t *state, const char *linkname,
    dladm_stat_type_t stattype, dladm_stat_chain_t *diff_stat)
{
	dladm_stat_chain_t  *curr;

	/* Unpack invidual stat entry and call library consumer's callback */
	for (curr = diff_stat; curr != NULL; curr = curr->dc_next) {
		void	*fields_buf;

		/* Format the raw numbers for printing */
		fields_buf = state->ls_stats2str[stattype](linkname,
		    curr->dc_statentry, state->ls_unit, state->ls_parsable);
		/* Print the stats */
		if (fields_buf != NULL)
			ofmt_print(state->ls_ofmt, fields_buf);
		free(fields_buf);
	}
}

static int
show_queried_stats(dladm_handle_t dh, datalink_id_t linkid, void *arg)
{
	show_state_t		*state = arg;
	int 			i;
	dladm_stat_chain_t	*diff_stat;
	char			linkname[DLPI_LINKNAME_MAX];

	if (dladm_datalink_id2info(dh, linkid, NULL, NULL, NULL, linkname,
	    DLPI_LINKNAME_MAX) != DLADM_STATUS_OK) {
		goto done;
	}

	for (i = 0; i < DLADM_STAT_NUM_STATS; i++) {
		if (state->ls_stattype[i]) {
			/*
			 * Query library for stats
			 * Stats are returned as chain of raw numbers
			 */
			diff_stat = query_link_stats(handle, linkid, arg, i);
			walk_dlstat_stats(state, linkname, i, diff_stat);
			dladm_link_stat_free(diff_stat);
		}
	}
done:
	return (DLADM_WALK_CONTINUE);
}

void
show_link_stats(datalink_id_t linkid, show_state_t state, uint32_t interval)
{
	for (;;) {
		if (linkid == DATALINK_ALL_LINKID) {
			(void) dladm_walk_datalink_id(show_queried_stats,
			    handle, &state, DATALINK_CLASS_ALL,
			    DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);
		} else {
			(void) show_queried_stats(handle, linkid, &state);
		}

		if (interval == 0)
			break;

		cleanup_removed_links(&state);
		(void) sleep(interval);
	}
}

void
print_all_stats(dladm_handle_t dh, datalink_id_t linkid,
    dladm_stat_chain_t *stat_chain)
{
	dladm_stat_chain_t	*curr;
	name_value_stat_entry_t	*stat_entry;
	name_value_stat_t	*curr_stat;
	boolean_t		stat_printed = B_FALSE;
	char			linkname[MAXLINKNAMELEN];
	char			prev_linkname[MAXLINKNAMELEN];

	if (dladm_datalink_id2info(dh, linkid, NULL, NULL, NULL, linkname,
	    DLPI_LINKNAME_MAX) != DLADM_STATUS_OK)
		return;

	for (curr = stat_chain; curr != NULL; curr = curr->dc_next) {
		stat_entry = curr->dc_statentry;
		/*
		 * Print header
		 * If link name is already printed in previous iteration,
		 * don't print again
		 */
		if (strcmp(prev_linkname, linkname) != 0)
			printf("%s \n", linkname);
		printf("  %s \n", stat_entry->nve_header);

		/* Print stat fields */
		for (curr_stat = stat_entry->nve_stats; curr_stat != NULL;
		    curr_stat = curr_stat->nv_nextstat) {
			printf("\t%15s", curr_stat->nv_statname);
			printf("\t\t%15llu\n", curr_stat->nv_statval);
		}

		strncpy(prev_linkname, linkname, MAXLINKNAMELEN);
		stat_printed = B_TRUE;
	}
	if (stat_printed)
		printf("---------------------------------------------------\n");
}

static int
dump_queried_stats(dladm_handle_t dh, datalink_id_t linkid, void *arg)
{
	boolean_t		*stattype = arg;
	int			i;
	dladm_stat_chain_t	*stat_chain;

	for (i = 0; i < DLADM_STAT_NUM_STATS; i++) {
		if (stattype[i]) {
			stat_chain = dladm_link_stat_query_all(dh, linkid, i);
			print_all_stats(dh, linkid, stat_chain);
			dladm_link_stat_query_all_free(stat_chain);
		}
	}
done:
	return (DLADM_WALK_CONTINUE);
}

void
dump_all_link_stats(datalink_id_t linkid, boolean_t *stattype)
{
	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(dump_queried_stats,
		    handle, stattype, DATALINK_CLASS_ALL,
		    DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);
	} else {
		(void) dump_queried_stats(handle, linkid, stattype);
	}
}

static void
do_show(int argc, char *argv[], const char *use)
{
	int			option;
	boolean_t		r_arg = B_FALSE;
	boolean_t		t_arg = B_FALSE;
	boolean_t		i_arg = B_FALSE;
	boolean_t		p_arg = B_FALSE;
	boolean_t		o_arg = B_FALSE;
	boolean_t		u_arg = B_FALSE;
	boolean_t		a_arg = B_FALSE;
	boolean_t		A_arg = B_FALSE;
	uint32_t		flags = DLADM_OPT_ACTIVE;
	datalink_id_t		linkid = DATALINK_ALL_LINKID;
	uint32_t		interval = 0;
	char			unit = '\0';
	show_state_t		state;
	dladm_status_t		status;
	char			*fields_str = NULL;
	char			*o_fields_str = NULL;

	char			*total_stat_fields =
	    "link,ipkts,rbytes,opkts,obytes";
	char			*rx_total_stat_fields =
	    "link,ipkts,rbytes,intrs,polls,ch<10,ch10-50,ch>50";
	char			*tx_total_stat_fields =
	    "link,opkts,obytes,blkcnt,ublkcnt";

	ofmt_handle_t		ofmt;
	ofmt_status_t		oferr;
	uint_t			ofmtflags = OFMT_RIGHTJUST;
	ofmt_field_t 		*oftemplate;

	bzero(&state, sizeof (state));
	opterr = 0;
	while ((option = getopt_long(argc, argv, ":rtaApi:o:u:",
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
		case 'a':
			if (a_arg)
				die_optdup(option);

			a_arg = B_TRUE;
			break;
		case 'A':
			if (A_arg)
				die_optdup(option);

			A_arg = B_TRUE;
			break;
		case 'i':
			if (i_arg)
				die_optdup(option);

			i_arg = B_TRUE;
			if (!dladm_str2interval(optarg, &interval))
				die("invalid interval value '%s'", optarg);
			break;
		case 'p':
			if (p_arg)
				die_optdup(option);

			p_arg = B_TRUE;
			break;
		case 'o':
			o_arg = B_TRUE;
			o_fields_str = optarg;
			break;
		case 'u':
			if (u_arg)
				die_optdup(option);

			u_arg = B_TRUE;
			if (!dlstat_unit(optarg, &unit))
				die("invalid unit value '%s',"
				    "unit must be R|K|M|G|T|P", optarg);
			break;
		default:
			die_opterr(optopt, option, use);
			break;
		}
	}

	if (r_arg && t_arg)
		die("the options -t and -r are not compatible");

	if (u_arg && p_arg)
		die("the options -u and -p are not compatible");

	if (p_arg && !o_arg)
		die("-p requires -o");

	if (p_arg && strcasecmp(o_fields_str, "all") == 0)
		die("\"-o all\" is invalid with -p");

	if (a_arg && A_arg)
		die("the options -a and -A are not compatible");

	if (a_arg &&
	    (p_arg || o_arg || u_arg || i_arg)) {
		die("the option -a is not compatible with "
		    "-p, -o, -u, -i");
	}

	if (A_arg &&
	    (r_arg || t_arg || p_arg || o_arg || u_arg || i_arg)) {
		die("the option -A is not compatible with "
		    "-r, -t, -p, -o, -u, -i");
	}

	/* get link name (optional last argument) */
	if (optind == (argc-1)) {
		if (strlen(argv[optind]) >= MAXLINKNAMELEN)
			die("link name too long");

		if ((status = dladm_name2info(handle, argv[optind], &linkid,
		    NULL, NULL, NULL)) != DLADM_STATUS_OK) {
			die_dlerr(status, "link %s is not valid", argv[optind]);
		}
	} else if (optind != argc) {
		if (argc != 0)
			usage();
	}

	if (a_arg) {
		boolean_t	stattype[DLADM_STAT_NUM_STATS];

		bzero(&stattype, sizeof (stattype));
		if (r_arg) {
			stattype[DLADM_STAT_RX_LANE_TOTAL] = B_TRUE;
		} else if (t_arg) {
			stattype[DLADM_STAT_TX_LANE_TOTAL] = B_TRUE;
		} else {		/* Display both Rx and Tx lanes */
			stattype[DLADM_STAT_TOTAL] = B_TRUE;
		}

		dump_all_link_stats(linkid, stattype);
		return;
	}

	if (A_arg) {
		boolean_t	stattype[DLADM_STAT_NUM_STATS];
		int		i;

		for (i = 0; i < DLADM_STAT_NUM_STATS; i++)
			stattype[i] = B_TRUE;

		dump_all_link_stats(linkid, stattype);
		return;
	}

	state.ls_unit = unit;
	state.ls_parsable = p_arg;

	if (state.ls_parsable)
		ofmtflags |= OFMT_PARSABLE;

	if (r_arg) {
		fields_str = rx_total_stat_fields;
		oftemplate = rx_lane_s_fields;
		state.ls_stattype[DLADM_STAT_RX_LANE_TOTAL] = B_TRUE;
		state.ls_stats2str[DLADM_STAT_RX_LANE_TOTAL] =
		    print_rx_lane_stats;
	} else if (t_arg) {
		fields_str = tx_total_stat_fields;
		oftemplate = tx_lane_s_fields;
		state.ls_stattype[DLADM_STAT_TX_LANE_TOTAL] = B_TRUE;
		state.ls_stats2str[DLADM_STAT_TX_LANE_TOTAL] =
		    print_tx_lane_stats;
	} else {		/* Display both Rx and Tx lanes total */
		fields_str = total_stat_fields;
		oftemplate = total_s_fields;
		state.ls_stattype[DLADM_STAT_TOTAL] = B_TRUE;
		state.ls_stats2str[DLADM_STAT_TOTAL] = print_total_stats;
	}

	if (o_arg) {
		fields_str = (strcasecmp(o_fields_str, "all") == 0) ?
		    fields_str : o_fields_str;
	}

	oferr = ofmt_open(fields_str, oftemplate, ofmtflags, 0, &ofmt);
	ofmt_check(oferr, state.ls_parsable, ofmt, die, warn);
	state.ls_ofmt = ofmt;

	show_link_stats(linkid, state, interval);

	ofmt_close(ofmt);
}

static void
do_show_phys(int argc, char *argv[], const char *use)
{
	int			option;
	boolean_t		r_arg = B_FALSE;
	boolean_t		t_arg = B_FALSE;
	boolean_t		i_arg = B_FALSE;
	boolean_t		p_arg = B_FALSE;
	boolean_t		o_arg = B_FALSE;
	boolean_t		u_arg = B_FALSE;
	boolean_t		a_arg = B_FALSE;
	uint32_t		flags = DLADM_OPT_ACTIVE;
	datalink_id_t		linkid = DATALINK_ALL_LINKID;
	char			linkname[MAXLINKNAMELEN];
	uint32_t		interval = 0;
	char			unit = '\0';
	show_state_t		state;
	dladm_status_t		status;
	char			*fields_str = NULL;
	char			*o_fields_str = NULL;
	char			*ring_stat_fields =
	    "link,type,index,pkts,bytes";
	char			*rx_ring_stat_fields =
	    "link,type,index,ipkts,rbytes";
	char			*tx_ring_stat_fields =
	    "link,type,index,opkts,obytes";

	ofmt_handle_t		ofmt;
	ofmt_status_t		oferr;
	uint_t			ofmtflags = OFMT_RIGHTJUST;
	ofmt_field_t 		*oftemplate;

	bzero(&state, sizeof (state));
	opterr = 0;
	while ((option = getopt_long(argc, argv, ":rtapi:o:u:",
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
		case 'a':
			if (a_arg)
				die_optdup(option);

			a_arg = B_TRUE;
			break;
		case 'i':
			if (i_arg)
				die_optdup(option);

			i_arg = B_TRUE;
			if (!dladm_str2interval(optarg, &interval))
				die("invalid interval value '%s'", optarg);
			break;
		case 'p':
			if (p_arg)
				die_optdup(option);

			p_arg = B_TRUE;
			break;
		case 'o':
			o_arg = B_TRUE;
			o_fields_str = optarg;
			break;
		case 'u':
			if (u_arg)
				die_optdup(option);

			u_arg = B_TRUE;
			if (!dlstat_unit(optarg, &unit))
				die("invalid unit value '%s',"
				    "unit must be R|K|M|G|T|P", optarg);
			break;
		default:
			die_opterr(optopt, option, use);
			break;
		}
	}

	if (r_arg && t_arg)
		die("the options -t and -r are not compatible");

	if (u_arg && p_arg)
		die("the options -u and -p are not compatible");

	if (p_arg && !o_arg)
		die("-p requires -o");

	if (p_arg && strcasecmp(o_fields_str, "all") == 0)
		die("\"-o all\" is invalid with -p");

	if (a_arg &&
	    (p_arg || o_arg || u_arg || i_arg)) {
		die("the option -a is not compatible with "
		    "-p, -o, -u, -i");
	}


	/* get link name (optional last argument) */
	if (optind == (argc-1)) {
		if (strlen(argv[optind]) >= MAXLINKNAMELEN)
			die("link name too long");

		if ((status = dladm_name2info(handle, argv[optind], &linkid,
		    NULL, NULL, NULL)) != DLADM_STATUS_OK) {
			die_dlerr(status, "link %s is not valid", argv[optind]);
		}
	} else if (optind != argc) {
		usage();
	}

	if (a_arg) {
		boolean_t	stattype[DLADM_STAT_NUM_STATS];

		bzero(&stattype, sizeof (stattype));

		if (r_arg) {
			stattype[DLADM_STAT_RX_RING] = B_TRUE;
		} else if (t_arg) {
			stattype[DLADM_STAT_TX_RING] = B_TRUE;
		} else {		/* Display both Rx and Tx lanes */
			stattype[DLADM_STAT_RX_RING] = B_TRUE;
			stattype[DLADM_STAT_TX_RING] = B_TRUE;
		}

		dump_all_link_stats(linkid, stattype);
		return;
	}

	state.ls_unit = unit;
	state.ls_parsable = p_arg;

	if (state.ls_parsable)
		ofmtflags |= OFMT_PARSABLE;

	if (r_arg) {
		fields_str = rx_ring_stat_fields;
		oftemplate = rx_ring_s_fields;
		state.ls_stattype[DLADM_STAT_RX_RING] = B_TRUE;
		state.ls_stats2str[DLADM_STAT_RX_RING] = print_rx_ring_stats;
	} else if (t_arg) {
		fields_str = tx_ring_stat_fields;
		oftemplate = tx_ring_s_fields;
		state.ls_stattype[DLADM_STAT_TX_RING] = B_TRUE;
		state.ls_stats2str[DLADM_STAT_TX_RING] = print_tx_ring_stats;
	} else {		/* Display both Rx and Tx lanes */
		fields_str = ring_stat_fields;
		oftemplate = ring_s_fields;
		state.ls_stattype[DLADM_STAT_RX_RING] = B_TRUE;
		state.ls_stattype[DLADM_STAT_TX_RING] = B_TRUE;
		state.ls_stats2str[DLADM_STAT_RX_RING] =
		    print_rx_generic_ring_stats;
		state.ls_stats2str[DLADM_STAT_TX_RING] =
		    print_tx_generic_ring_stats;
	}

	if (o_arg) {
		fields_str = (strcasecmp(o_fields_str, "all") == 0) ?
		    fields_str : o_fields_str;
	}

	oferr = ofmt_open(fields_str, oftemplate, ofmtflags, 0, &ofmt);
	ofmt_check(oferr, state.ls_parsable, ofmt, die, warn);
	state.ls_ofmt = ofmt;

	show_link_stats(linkid, state, interval);

	ofmt_close(ofmt);
}

static void
do_show_link(int argc, char *argv[], const char *use)
{
	int			option;
	boolean_t		r_arg = B_FALSE;
	boolean_t		F_arg = B_FALSE;
	boolean_t		t_arg = B_FALSE;
	boolean_t		i_arg = B_FALSE;
	boolean_t		p_arg = B_FALSE;
	boolean_t		o_arg = B_FALSE;
	boolean_t		u_arg = B_FALSE;
	boolean_t		a_arg = B_FALSE;
	uint32_t		flags = DLADM_OPT_ACTIVE;
	datalink_id_t		linkid = DATALINK_ALL_LINKID;
	uint32_t		interval = 0;
	char			unit = '\0';
	show_state_t		state;
	dladm_status_t		status;
	char			*fields_str = NULL;
	char			*o_fields_str = NULL;

	char			*lane_stat_fields =
	    "link,type,id,index,pkts,bytes";
	char			*rx_lane_stat_fields =
	    "link,type,id,index,ipkts,rbytes,intrs,polls,ch<10,ch10-50,ch>50";
	char			*tx_lane_stat_fields =
	    "link,type,id,index,opkts,obytes,blkcnt,ublkcnt";
	char			*rx_fanout_stat_fields =
	    "link,id,index,fout,ipkts,rbytes";

	ofmt_handle_t		ofmt;
	ofmt_status_t		oferr;
	uint_t			ofmtflags = OFMT_RIGHTJUST;
	ofmt_field_t 		*oftemplate;

	bzero(&state, sizeof (state));
	opterr = 0;
	while ((option = getopt_long(argc, argv, ":hrtFapi:o:u:",
	    NULL, NULL)) != -1) {
		switch (option) {
		case 'h':
			if (r_arg || F_arg || t_arg || i_arg || p_arg ||
			    o_arg || u_arg || a_arg) {
				die("the option -h is not compatible with "
				    "-r, -F, -t, -i, -p, -o, -u, -a");
			}
			do_show_history(argc, &argv[0], use);
			return;
		case 'r':
			if (r_arg)
				die_optdup(option);

			r_arg = B_TRUE;
			break;
		case 'F':
			if (F_arg)
				die_optdup(option);

			F_arg = B_TRUE;
			break;
		case 't':
			if (t_arg)
				die_optdup(option);

			t_arg = B_TRUE;
			break;
		case 'a':
			if (a_arg)
				die_optdup(option);

			a_arg = B_TRUE;
			break;
		case 'i':
			if (i_arg)
				die_optdup(option);

			i_arg = B_TRUE;
			if (!dladm_str2interval(optarg, &interval))
				die("invalid interval value '%s'", optarg);
			break;
		case 'p':
			if (p_arg)
				die_optdup(option);

			p_arg = B_TRUE;
			break;
		case 'o':
			o_arg = B_TRUE;
			o_fields_str = optarg;
			break;
		case 'u':
			if (u_arg)
				die_optdup(option);

			u_arg = B_TRUE;
			if (!dlstat_unit(optarg, &unit))
				die("invalid unit value '%s',"
				    "unit must be R|K|M|G|T|P", optarg);
			break;
		default:
			die_opterr(optopt, option, use);
			break;
		}
	}

	if (r_arg && t_arg)
		die("the options -t and -r are not compatible");

	if (u_arg && p_arg)
		die("the options -u and -p are not compatible");

	if (F_arg && !r_arg)
		die("-F must be used with -r");

	if (p_arg && !o_arg)
		die("-p requires -o");

	if (p_arg && strcasecmp(o_fields_str, "all") == 0)
		die("\"-o all\" is invalid with -p");

	if (a_arg &&
	    (p_arg || o_arg || u_arg || i_arg)) {
		die("the option -a is not compatible with "
		    "-p, -o, -u, -i");
	}

	/* get link name (optional last argument) */
	if (optind == (argc-1)) {
		if (strlen(argv[optind]) >= MAXLINKNAMELEN)
			die("link name too long");

		if ((status = dladm_name2info(handle, argv[optind], &linkid,
		    NULL, NULL, NULL)) != DLADM_STATUS_OK) {
			die_dlerr(status, "link %s is not valid", argv[optind]);
		}
	} else if (optind != argc) {
		usage();
	}

	if (a_arg) {
		boolean_t	stattype[DLADM_STAT_NUM_STATS];

		bzero(&stattype, sizeof (stattype));

		if (r_arg) {
			if (F_arg) {
				stattype[DLADM_STAT_RX_LANE_FOUT] = B_TRUE;
			} else {
				stattype[DLADM_STAT_RX_LANE] = B_TRUE;
			}
		} else if (t_arg) {
			stattype[DLADM_STAT_TX_LANE] = B_TRUE;
		} else {		/* Display both Rx and Tx lanes */
			stattype[DLADM_STAT_RX_LANE] = B_TRUE;
			stattype[DLADM_STAT_TX_LANE] = B_TRUE;
		}

		dump_all_link_stats(linkid, stattype);
		return;
	}

	state.ls_unit = unit;
	state.ls_parsable = p_arg;

	if (state.ls_parsable)
		ofmtflags |= OFMT_PARSABLE;

	if (r_arg) {
		if (F_arg) {
			fields_str = rx_fanout_stat_fields;
			oftemplate = rx_fanout_lane_s_fields;
			state.ls_stattype[DLADM_STAT_RX_LANE_FOUT] = B_TRUE;
			state.ls_stats2str[DLADM_STAT_RX_LANE_FOUT] =
			    print_fanout_stats;
		} else {
			fields_str = rx_lane_stat_fields;
			oftemplate = rx_lane_s_fields;
			state.ls_stattype[DLADM_STAT_RX_LANE] = B_TRUE;
			state.ls_stats2str[DLADM_STAT_RX_LANE] =
			    print_rx_lane_stats;
		}
	} else if (t_arg) {
		fields_str = tx_lane_stat_fields;
		oftemplate = tx_lane_s_fields;
		state.ls_stattype[DLADM_STAT_TX_LANE] = B_TRUE;
		state.ls_stats2str[DLADM_STAT_TX_LANE] = print_tx_lane_stats;
	} else {		/* Display both Rx and Tx lanes */
		fields_str = lane_stat_fields;
		oftemplate = lane_s_fields;
		state.ls_stattype[DLADM_STAT_RX_LANE] = B_TRUE;
		state.ls_stattype[DLADM_STAT_TX_LANE] = B_TRUE;
		state.ls_stats2str[DLADM_STAT_RX_LANE] =
		    print_rx_generic_lane_stats;
		state.ls_stats2str[DLADM_STAT_TX_LANE] =
		    print_tx_generic_lane_stats;
	}
	if (o_arg) {
		fields_str = (strcasecmp(o_fields_str, "all") == 0) ?
		    fields_str : o_fields_str;
	}

	oferr = ofmt_open(fields_str, oftemplate, ofmtflags, 0, &ofmt);
	ofmt_check(oferr, state.ls_parsable, ofmt, die, warn);

	state.ls_ofmt = ofmt;

	show_link_stats(linkid, state, interval);

	ofmt_close(ofmt);
}

static void
do_show_aggr(int argc, char *argv[], const char *use)
{
	int			option;
	boolean_t		r_arg = B_FALSE;
	boolean_t		t_arg = B_FALSE;
	boolean_t		i_arg = B_FALSE;
	boolean_t		p_arg = B_FALSE;
	boolean_t		o_arg = B_FALSE;
	boolean_t		u_arg = B_FALSE;
	uint32_t		flags = DLADM_OPT_ACTIVE;
	datalink_id_t		linkid = DATALINK_ALL_LINKID;
	uint32_t		interval = 0;
	char			unit = '\0';
	show_state_t		state;
	dladm_status_t		status;
	char			*fields_str = NULL;
	char			*o_fields_str = NULL;

	char			*aggr_stat_fields =
	    "link,port,ipkts,rbytes,opkts,obytes";
	char			*rx_aggr_stat_fields = "link,port,ipkts,rbytes";
	char			*tx_aggr_stat_fields = "link,port,opkts,obytes";

	ofmt_handle_t		ofmt;
	ofmt_status_t		oferr;
	uint_t			ofmtflags = OFMT_RIGHTJUST;
	ofmt_field_t 		*oftemplate;

	bzero(&state, sizeof (state));
	opterr = 0;
	while ((option = getopt_long(argc, argv, ":rtpi:o:u:",
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
		case 'i':
			if (i_arg)
				die_optdup(option);

			i_arg = B_TRUE;
			if (!dladm_str2interval(optarg, &interval))
				die("invalid interval value '%s'", optarg);
			break;
		case 'p':
			if (p_arg)
				die_optdup(option);

			p_arg = B_TRUE;
			break;
		case 'o':
			o_arg = B_TRUE;
			o_fields_str = optarg;
			break;
		case 'u':
			if (u_arg)
				die_optdup(option);

			u_arg = B_TRUE;
			if (!dlstat_unit(optarg, &unit))
				die("invalid unit value '%s',"
				    "unit must be R|K|M|G|T|P", optarg);
			break;
		default:
			die_opterr(optopt, option, use);
			break;
		}
	}

	if (r_arg && t_arg)
		die("the options -t and -r are not compatible");

	if (u_arg && p_arg)
		die("the options -u and -p are not compatible");

	if (p_arg && !o_arg)
		die("-p requires -o");

	if (p_arg && strcasecmp(o_fields_str, "all") == 0)
		die("\"-o all\" is invalid with -p");


	/* get link name (optional last argument) */
	if (optind == (argc-1)) {
		if (strlen(argv[optind]) >= MAXLINKNAMELEN)
			die("link name too long");

		if ((status = dladm_name2info(handle, argv[optind], &linkid,
		    NULL, NULL, NULL)) != DLADM_STATUS_OK) {
			die_dlerr(status, "link %s is not valid", argv[optind]);
		}
	} else if (optind != argc) {
		usage();
	}

	state.ls_unit = unit;
	state.ls_parsable = p_arg;

	if (state.ls_parsable)
		ofmtflags |= OFMT_PARSABLE;

	oftemplate = aggr_port_s_fields;
	state.ls_stattype[DLADM_STAT_AGGR_PORT] = B_TRUE;
	state.ls_stats2str[DLADM_STAT_AGGR_PORT] = print_aggr_port_stats;

	if (r_arg)
		fields_str = rx_aggr_stat_fields;
	else if (t_arg)
		fields_str = tx_aggr_stat_fields;
	else
		fields_str = aggr_stat_fields;

	if (o_arg) {
		fields_str = (strcasecmp(o_fields_str, "all") == 0) ?
		    fields_str : o_fields_str;
	}

	oferr = ofmt_open(fields_str, oftemplate, ofmtflags, 0, &ofmt);
	ofmt_check(oferr, state.ls_parsable, ofmt, die, warn);
	state.ls_ofmt = ofmt;

	show_link_stats(linkid, state, interval);

	ofmt_close(ofmt);
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

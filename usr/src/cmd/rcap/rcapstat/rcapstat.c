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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <libintl.h>
#include <locale.h>

#include "rcapd.h"
#include "utils.h"
#include "rcapd_stat.h"
#include "statcommon.h"

static char mode[RC_MODE_LEN];
static rcapd_stat_hdr_t hdr;
static int global;
static int unformatted;
static time_t stat_mod = 0;

static uint_t timestamp_fmt = NODATE;

typedef struct col {
	rcid_t		col_id;
	char		col_name[LC_NAME_LEN];
	uint64_t	col_nproc;
	uint64_t	col_vmsize;
	uint64_t	col_rsssize;
	uint64_t	col_rsslimit;
	uint64_t	col_paged_eff;
	uint64_t	col_paged_eff_old;
	uint64_t	col_paged_eff_avg;
	uint64_t	col_paged_att;
	uint64_t	col_paged_att_old;
	uint64_t	col_paged_att_avg;
	uint64_t	col_count;
	int		col_fresh;
	struct col	*col_next;
	struct col	*col_prev;
	lcollection_stat_t	col_src_stat;
	lcollection_stat_t	col_old_stat;
} col_t;

static col_t *col_head;
static int ncol;

static col_t *
col_find(rcid_t id)
{
	col_t *col;
	for (col = col_head; col != NULL; col = col->col_next)
		if (col->col_id.rcid_type == id.rcid_type &&
		    col->col_id.rcid_val == id.rcid_val)
			return (col);
	return (NULL);
}

static col_t *
col_insert(rcid_t id)
{
	col_t *new_col;

	new_col = malloc(sizeof (col_t));
	if (new_col == NULL) {
		(void) fprintf(stderr, gettext("rcapstat: malloc() failed\n"));
		exit(E_ERROR);
	}
	(void) memset(new_col, 0, sizeof (col_t));
	new_col->col_next = col_head;
	new_col->col_id = id;
	if (col_head != NULL)
		col_head->col_prev = new_col;
	col_head = new_col;
	ncol++;
	return (new_col);
}

static void
col_remove(col_t *col)
{
	if (col->col_prev != NULL)
		col->col_prev->col_next = col->col_next;
	if (col->col_next != NULL)
		col->col_next->col_prev = col->col_prev;
	if (col_head == col)
		col_head = col->col_next;
	ncol--;
	free(col);
}

static void
usage()
{
	(void) fprintf(stderr,
	    gettext("usage: rcapstat [-g] [-p | -z] [-T d|u] "
	    "[interval [count]]\n"));
	exit(E_USAGE);
}

static void
format_size(char *str, uint64_t size, int length)
{
	char tag = 'K';
	if (size >= 10000) {
		size = (size + 512) / 1024;
		tag = 'M';
		if (size >= 10000) {
			size = (size + 512) / 1024;
			tag = 'G';
		}
	}
	(void) snprintf(str, length, "%4lld%c", size, tag);
}

static int
read_stats(rcid_type_t stat_type)
{
	int fd;
	int proc_fd;
	char procfile[20];
	uint64_t pid;
	col_t *col, *col_next;
	lcollection_report_t report;
	struct stat st;

	if ((fd = open(STAT_FILE_DEFAULT, O_RDONLY)) < 0) {
		warn(gettext("rcapd is not active\n"));
		return (E_ERROR);
	}

	if (fstat(fd, &st) == 0)
		stat_mod = st.st_mtime;

	if (read(fd, &hdr, sizeof (hdr)) != sizeof (hdr)) {
		(void) fprintf(stderr,
		    gettext("rcapstat: can't read stat file header: %s\n"),
		    strerror(errno));
		(void) close(fd);
		return (E_ERROR);
	}

	/*
	 * Check if rcapd is running
	 */
	pid = hdr.rs_pid;
	(void) snprintf(procfile, 20, "/proc/%lld/psinfo", pid);
	if ((proc_fd = open(procfile, O_RDONLY)) < 0) {
		warn(gettext("rcapd is not active\n"));
		(void) close(fd);
		return (E_ERROR);
	}
	(void) close(proc_fd);

	(void) strncpy(mode, hdr.rs_mode, RC_MODE_LEN);
	for (col = col_head; col != NULL; col = col->col_next) {
		col->col_fresh = 0;
		col->col_paged_eff = 0;
		col->col_paged_att = 0;
	}

	while (read(fd, &report, sizeof (report)) == sizeof (report)) {
		if (report.lcol_id.rcid_type != stat_type)
			continue;

		col = col_find(report.lcol_id);
		if (col == NULL) {
			col = col_insert(report.lcol_id);
			col->col_paged_eff_old = col->col_paged_eff =
			    report.lcol_stat.lcols_pg_eff;
			col->col_paged_att_old = col->col_paged_att =
			    report.lcol_stat.lcols_pg_att;
			col->col_count = 0;
		}
		(void) strncpy(col->col_name, report.lcol_name, LC_NAME_LEN);
		col->col_vmsize = report.lcol_image_size;
		col->col_rsssize = report.lcol_rss;
		col->col_rsslimit = report.lcol_rss_cap;
		col->col_fresh = 1;
		if (report.lcol_stat.lcols_pg_eff > col->col_paged_eff_old) {
			col->col_paged_eff =
			    report.lcol_stat.lcols_pg_eff -
			    col->col_paged_eff_old;
			if (report.lcol_stat.lcols_scan_count > col->col_count)
				col->col_paged_eff_avg =
				    col->col_paged_eff /
				    (report.lcol_stat.lcols_scan_count -
				    col->col_count);
		} else {
			col->col_paged_eff_avg = 0;
		}
		if (report.lcol_stat.lcols_pg_att > col->col_paged_att_old) {
			col->col_paged_att =
			    report.lcol_stat.lcols_pg_att -
			    col->col_paged_att_old;
			if (report.lcol_stat.lcols_scan_count > col->col_count)
				col->col_paged_att_avg =
				    col->col_paged_att /
				    (report.lcol_stat.lcols_scan_count -
				    col->col_count);
		} else {
			col->col_paged_att_avg = 0;
		}
		col->col_paged_eff_old = report.lcol_stat.lcols_pg_eff;
		col->col_paged_att_old = report.lcol_stat.lcols_pg_att;
		col->col_nproc =
		    report.lcol_stat.lcols_proc_in -
		    report.lcol_stat.lcols_proc_out;
		col->col_count = report.lcol_stat.lcols_scan_count;
		col->col_src_stat = report.lcol_stat;
	}

	/*
	 * Remove stale data
	 */
	col = col_head;
	while (col != NULL) {
		col_next = col->col_next;
		if (col->col_fresh == 0)
			col_remove(col);
		col = col_next;
	}
	(void) close(fd);
	return (E_SUCCESS);
}

/*
 * Print each collection's interval statistics.
 */
/*ARGSUSED*/
static void
print_unformatted_stats(void)
{
	col_t *col;

#define	DELTA(field) \
	(col->col_src_stat.field - col->col_old_stat.field)

	col = col_head;
	while (col != NULL) {
		if (bcmp(&col->col_src_stat, &col->col_old_stat,
		    sizeof (col->col_src_stat)) == 0) {
			col = col->col_next;
			continue;
		}
		(void) printf("%s %s status: succeeded/attempted (k): "
		    "%llu/%llu, ineffective/scans/unenforced/samplings:  "
		    "%llu/%llu/%llu/%llu, RSS min/max (k): %llu/%llu, cap %llu "
		    "kB, processes/thpt: %llu/%llu, %llu scans over %lld ms\n",
		    mode, col->col_name, DELTA(lcols_pg_eff),
		    DELTA(lcols_pg_att), DELTA(lcols_scan_ineffective),
		    DELTA(lcols_scan), DELTA(lcols_unenforced_cap),
		    DELTA(lcols_rss_sample), col->col_src_stat.lcols_min_rss,
		    col->col_src_stat.lcols_max_rss, col->col_rsslimit,
		    (col->col_src_stat.lcols_proc_in -
		    col->col_old_stat.lcols_proc_out), DELTA(lcols_proc_out),
		    DELTA(lcols_scan_count),
		    NSEC2MSEC(DELTA(lcols_scan_time_complete)));
		col->col_old_stat = col->col_src_stat;

		col = col->col_next;
	}

	if (global)
		(void) printf(gettext("physical memory utilization: %3u%%   "
		    "cap enforcement threshold: %3u%%\n"), hdr.rs_pressure_cur,
		    hdr.rs_pressure_cap);
#undef DELTA
}

static void
print_stats(rcid_type_t stat_type)
{
	col_t *col;
	char size[6];
	char limit[6];
	char rss[6];
	char nproc[6];
	char paged_att[6];
	char paged_eff[6];
	char paged_att_avg[6];
	char paged_eff_avg[6];
	static int count = 0;

	/*
	 * Print a header once every 20 times if we're only displaying reports
	 * for one collection (10 times if -g is used).  Print a header every
	 * interval otherwise.
	 */
	if (count == 0 || ncol != 1)
		(void) printf("%6s %-15s %5s %5s %5s %5s %5s %5s %5s %5s\n",
		    "id", (stat_type == RCIDT_PROJECT ?  "project" : "zone"),
		    "nproc", "vm", "rss", "cap",
		    "at", "avgat", "pg", "avgpg");
	if (++count >= 20 || (count >= 10 && global != 0) || ncol != 1)
		count = 0;

	for (col = col_head; col != NULL; col = col->col_next) {
		if (col->col_id.rcid_type != stat_type)
			continue;

		if (col->col_paged_att == 0)
			(void) strlcpy(nproc, "-", sizeof (nproc));
		else
			(void) snprintf(nproc, sizeof (nproc), "%lld",
			    col->col_nproc);
		format_size(size, col->col_vmsize, 6);
		format_size(rss, col->col_rsssize, 6);
		format_size(limit, col->col_rsslimit, 6);
		format_size(paged_att, col->col_paged_att, 6);
		format_size(paged_eff, col->col_paged_eff, 6);
		format_size(paged_att_avg, col->col_paged_att_avg, 6);
		format_size(paged_eff_avg, col->col_paged_eff_avg, 6);
		(void) printf("%6lld %-15s %5s %5s %5s %5s %5s %5s %5s %5s\n",
		    col->col_id.rcid_val, col->col_name,
		    nproc,
		    size, rss, limit,
		    paged_att, paged_att_avg,
		    paged_eff, paged_eff_avg);
	}
	if (global)
		(void) printf(gettext("physical memory utilization: %3u%%   "
		    "cap enforcement threshold: %3u%%\n"), hdr.rs_pressure_cur,
		    hdr.rs_pressure_cap);
}

int
main(int argc, char *argv[])
{
	int interval = 5;
	int count;
	int always = 1;
	int opt;
	int projects = 0;
	int zones = 0;
	/* project reporting is the default if no option is specified */
	rcid_type_t stat_type = RCIDT_PROJECT;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);
	(void) setpname("rcapstat");

	global = unformatted = 0;
	while ((opt = getopt(argc, argv, "gpuzT:")) != (int)EOF) {
		switch (opt) {
		case 'g':
			global = 1;
			break;
		case 'p':
			projects = 1;
			stat_type = RCIDT_PROJECT;
			break;
		case 'u':
			unformatted = 1;
			break;
		case 'z':
			stat_type = RCIDT_ZONE;
			zones = 1;
			break;
		case 'T':
			if (optarg) {
				if (*optarg == 'u')
					timestamp_fmt = UDATE;
				else if (*optarg == 'd')
					timestamp_fmt = DDATE;
				else
					usage();
			} else {
				usage();
			}
			break;
		default:
			usage();
		}
	}

	if (argc > optind)
		if ((interval = xatoi(argv[optind++])) <= 0)
			die(gettext("invalid interval specified\n"));
	if (argc > optind) {
		if ((count = xatoi(argv[optind++])) <= 0)
			die(gettext("invalid count specified\n"));
		always = 0;
	}
	if (argc > optind || (projects > 0 && zones > 0))
		usage();

	while (always || count-- > 0) {
		if (read_stats(stat_type) != E_SUCCESS)
			return (E_ERROR);
		if (timestamp_fmt != NODATE)
			print_timestamp(timestamp_fmt);
		if (!unformatted) {
			print_stats(stat_type);
			(void) fflush(stdout);
			if (count || always)
				(void) sleep(interval);
		} else {
			struct stat st;

			print_unformatted_stats();
			(void) fflush(stdout);
			while (stat(STAT_FILE_DEFAULT, &st) == 0 &&
			    st.st_mtime == stat_mod)
				(void) usleep((useconds_t)(0.2 * MICROSEC));
		}
	}

	return (E_SUCCESS);
}

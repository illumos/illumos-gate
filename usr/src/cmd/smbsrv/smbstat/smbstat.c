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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * smbstat: Server Message Block File System statistics
 *
 * The statistics this CLI displays come from two sources:
 *
 * 1) The kernel module 'smbsrv'.
 * 2) The SMB workers task queue statistics the task queue manager of Solaris
 *    maintains.
 *
 * The flow of the code is the following:
 *
 *
 * 			+----------------+
 * 			| Initialization |
 * 			+----------------+
 *				|
 *				|
 *				v
 *		  +--------------------------*
 *		  | Take a snapshot the data | <--------+
 *		  +--------------------------+		|
 *				|			|
 * 				|			|
 *				v			|
 *		    +----------------------+		|
 *		    | Process the snapshot |		|
 *		    +----------------------+		|
 *				|			|
 *				|			|
 *				v			|
 *	     +------------------------------------+	|
 *	     | Print the result of the processing |	|
 *	     +------------------------------------+	|
 *				|			|
 *				|			|
 *				v			|
 *		Yes	---------------			|
 *	+------------ < interval == 0 ? >		|
 * 	|		---------------			|
 *	|		       |			|
 * 	|		       | No			|
 * 	|		       v			|
 *	|	   +------------------------+		|
 * 	|	   | Sleep for the duration | ----------+
 * 	|	   |   of the interval.     |
 * 	|	   +------------------------+
 * 	|
 * 	+---------------------+
 *			      |
 *			      v
 *
 *			    Exit
 *
 * There are two sets of snapshots. One set for the smbsrv module and the other
 * for the task queue (SMB workers). Each set contains 2 snapshots. One is
 * labeled 'current' the other one 'previous'. Their role changes after each
 * snapshot. The 'current' becomes 'previous' and vice versa.
 * The first snapshot taken is compared against the data gathered since the
 * smbsrv module was loaded. Subsequent snapshots will be compared against the
 * previous snapshot.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <kstat.h>
#include <stdarg.h>
#include <errno.h>
#include <inttypes.h>
#include <strings.h>
#include <utility.h>
#include <libintl.h>
#include <zone.h>
#include <termios.h>
#include <stropts.h>
#include <math.h>
#include <umem.h>
#include <locale.h>
#include <smbsrv/smb_kstat.h>

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif /* TEXT_DOMAIN */

#define	SMBSTAT_ID_NO_CPU	-1
#define	SMBSTAT_SNAPSHOT_COUNT	2		/* Must be a power of 2 */
#define	SMBSTAT_SNAPSHOT_MASK	(SMBSTAT_SNAPSHOT_COUNT - 1)

#define	SMBSTAT_HELP	\
	"Usage: smbstat [-acnrtuz] [interval]\n" \
	"    -c: display counters\n" \
	"    -t: display throughput\n" \
	"    -u: display utilization\n" \
	"    -r: display requests\n" \
	"        -a: all the requests (supported and unsupported)\n" \
	"        -z: skip the requests not received\n" \
	"        -n: display in alphabetic order\n" \
	"    interval: refresh cycle in seconds\n"

#define	SMBSRV_COUNTERS_BANNER	"\n  nbt   tcp users trees files pipes\n"
#define	SMBSRV_COUNTERS_FORMAT	"%5d %5d %5d %5d %5d %5d\n"

#define	SMBSRV_THROUGHPUT_BANNER	\
	"\nrbytes/s   tbytes/s    reqs/s     reads/s   writes/s\n"
#define	SMBSRV_THROUGHPUT_FORMAT	\
	"%1.3e  %1.3e  %1.3e  %1.3e  %1.3e\n"

#define	SMBSRV_UTILIZATION_BANNER	\
	"\n  wcnt       rcnt       wtime      rtime" \
	"     w%%   r%%   u%%  sat usr%% sys%%  idle%%\n"
#define	SMBSRV_UTILIZATION_FORMAT	\
	"%1.3e  %1.3e  %1.3e  %1.3e  %3.0f  %3.0f  %3.0f  %s " \
	"%3.0f  %3.0f    %3.0f\n"

#define	SMBSRV_REQUESTS_BANNER	\
	"\n%30s code   %%   rbytes/s   tbytes/s     req/s     rt-mean"	\
	"   rt-stddev\n"
#define	SMBSRV_REQUESTS_FORMAT	\
	"%30s  %02X   %3.0f  %1.3e  %1.3e  %1.3e  %1.3e  %1.3e\n"

typedef enum {
	CPU_TICKS_IDLE = 0,
	CPU_TICKS_USER,
	CPU_TICKS_KERNEL,
	CPU_TICKS_SENTINEL
} cpu_state_idx_t;

typedef struct smbstat_cpu_snapshot {
	processorid_t	cs_id;
	int		cs_state;
	uint64_t	cs_ticks[CPU_TICKS_SENTINEL];
} smbstat_cpu_snapshot_t;

typedef struct smbstat_srv_snapshot {
	hrtime_t	ss_snaptime;
	smbsrv_kstats_t	ss_data;
} smbstat_srv_snapshot_t;

typedef struct smbstat_wrk_snapshot {
	uint64_t	ws_maxthreads;
	uint64_t	ws_bnalloc;
} smbstat_wrk_snapshot_t;

typedef struct smbstat_req_info {
	char		ri_name[KSTAT_STRLEN];
	int		ri_opcode;
	double		ri_pct;
	double		ri_tbs;
	double		ri_rbs;
	double		ri_rqs;
	double		ri_stddev;
	double		ri_mean;
} smbstat_req_info_t;

typedef struct smbstat_srv_info {
	double		si_hretime;
	double		si_etime;
	double		si_total_nreqs;
	/*
	 * Counters
	 */
	uint32_t	si_nbt_sess;	/* NBT sessions */
	uint32_t	si_tcp_sess;	/* TCP sessions */
	uint32_t	si_users;	/* Users logged in */
	uint32_t	si_trees;	/* Trees connected */
	uint32_t	si_files;	/* Open files */
	uint32_t	si_pipes;	/* Open pipes */
	/*
	 * Throughput of the server
	 */
	double		si_tbs;		/* Bytes transmitted / second */
	double		si_rbs;		/* Bytes received / second */
	double		si_rqs;		/* Requests treated / second */
	double		si_rds;		/* Reads treated / second */
	double		si_wrs;		/* Writes treated / second */
	/*
	 * Utilization of the server
	 */
	double		si_wpct;	/* */
	double		si_rpct;	/* */
	double		si_upct;	/* Utilization in % */
	double		si_avw;		/* Average number of requests waiting */
	double		si_avr;		/* Average number of requests running */
	double		si_wserv;	/* Average waiting time */
	double		si_rserv;	/* Average running time */
	boolean_t	si_sat;
	double		si_ticks[CPU_TICKS_SENTINEL];
	/*
	 * Latency & Throughput per request
	 */
	smbstat_req_info_t	si_reqs1[SMB_COM_NUM];
	smbstat_req_info_t	si_reqs2[SMB2__NCMDS];
} smbstat_srv_info_t;

static void smbstat_init(void);
static void smbstat_fini(void);
static void smbstat_kstat_snapshot(void);
static void smbstat_kstat_process(void);
static void smbstat_kstat_print(void);

static void smbstat_print_counters(void);
static void smbstat_print_throughput(void);
static void smbstat_print_utilization(void);
static void smbstat_print_requests(void);

static void smbstat_cpu_init(void);
static void smbstat_cpu_fini(void);
static smbstat_cpu_snapshot_t *smbstat_cpu_current_snapshot(void);
static smbstat_cpu_snapshot_t *smbstat_cpu_previous_snapshot(void);
static void smbstat_cpu_snapshot(void);
static void smbstat_cpu_process(void);

static void smbstat_wrk_init(void);
static void smbstat_wrk_fini(void);
static void smbstat_wrk_snapshot(void);
static void smbstat_wrk_process(void);
static smbstat_wrk_snapshot_t *smbstat_wrk_current_snapshot(void);

static void smbstat_srv_init(void);
static void smbstat_srv_fini(void);
static void smbstat_srv_snapshot(void);
static void smbstat_srv_process(void);
static void smbstat_srv_process_counters(smbstat_srv_snapshot_t *);
static void smbstat_srv_process_throughput(smbstat_srv_snapshot_t *,
    smbstat_srv_snapshot_t *);
static void smbstat_srv_process_utilization(smbstat_srv_snapshot_t *,
    smbstat_srv_snapshot_t *);
static void smbstat_srv_process_requests(smbstat_srv_snapshot_t *,
    smbstat_srv_snapshot_t *);
static void smbstat_srv_process_one_req(smbstat_req_info_t *,
    smb_kstat_req_t *, smb_kstat_req_t *, boolean_t);

static smbstat_srv_snapshot_t *smbstat_srv_current_snapshot(void);
static smbstat_srv_snapshot_t *smbstat_srv_previous_snapshot(void);

static void *smbstat_zalloc(size_t);
static void smbstat_free(void *, size_t);
static void smbstat_fail(int, char *, ...);
static void smbstat_snapshot_inc_idx(void);
static void smbstat_usage(FILE *, int);
static uint_t smbstat_strtoi(char const *, char *);
static double smbstat_hrtime_delta(hrtime_t, hrtime_t);
static double smbstat_sub_64(uint64_t, uint64_t);
static void smbstat_req_order(void);
static double smbstat_zero(double);
static void smbstat_termio_init(void);

#pragma does_not_return(smbstat_fail, smbstat_usage)

static char *smbstat_cpu_states[CPU_TICKS_SENTINEL] = {
	"cpu_ticks_idle",
	"cpu_ticks_user",
	"cpu_ticks_kernel"
};

static boolean_t	smbstat_opt_a = B_FALSE;	/* all */
static boolean_t	smbstat_opt_c = B_FALSE;	/* counters */
static boolean_t	smbstat_opt_n = B_FALSE;	/* by name */
static boolean_t	smbstat_opt_u = B_FALSE;	/* utilization */
static boolean_t	smbstat_opt_t = B_FALSE;	/* throughput */
static boolean_t	smbstat_opt_r = B_FALSE;	/* requests */
static boolean_t	smbstat_opt_z = B_FALSE;	/* non-zero requests */

static uint_t		smbstat_interval = 0;
static long		smbstat_nrcpus = 0;
static kstat_ctl_t	*smbstat_ksc = NULL;
static kstat_t		*smbstat_srv_ksp = NULL;
static kstat_t		*smbstat_wrk_ksp = NULL;
static struct winsize	smbstat_ws;
static uint16_t		smbstat_rows = 0;

static int smbstat_snapshot_idx = 0;
static smbstat_cpu_snapshot_t *smbstat_cpu_snapshots[SMBSTAT_SNAPSHOT_COUNT];
static smbstat_srv_snapshot_t smbstat_srv_snapshots[SMBSTAT_SNAPSHOT_COUNT];
static smbstat_wrk_snapshot_t smbstat_wrk_snapshots[SMBSTAT_SNAPSHOT_COUNT];
static smbstat_srv_info_t smbstat_srv_info;

/*
 * main
 */
int
main(int argc, char *argv[])
{
	int	c;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if (is_system_labeled()) {
		(void) fprintf(stderr,
		    gettext("%s: Trusted Extensions not supported.\n"),
		    argv[0]);
		return (1);
	}

	while ((c = getopt(argc, argv, "achnrtuz")) != EOF) {
		switch (c) {
		case 'a':
			smbstat_opt_a = B_TRUE;
			break;
		case 'n':
			smbstat_opt_n = B_TRUE;
			break;
		case 'u':
			smbstat_opt_u = B_TRUE;
			break;
		case 'c':
			smbstat_opt_c = B_TRUE;
			break;
		case 'r':
			smbstat_opt_r = B_TRUE;
			break;
		case 't':
			smbstat_opt_t = B_TRUE;
			break;
		case 'z':
			smbstat_opt_z = B_TRUE;
			break;
		case 'h':
			smbstat_usage(stdout, 0);
		default:
			smbstat_usage(stderr, 1);
		}
	}

	if (!smbstat_opt_u &&
	    !smbstat_opt_c &&
	    !smbstat_opt_r &&
	    !smbstat_opt_t) {
		/* Default options when none is specified. */
		smbstat_opt_u = B_TRUE;
		smbstat_opt_t = B_TRUE;
	}

	if (optind < argc) {
		smbstat_interval =
		    smbstat_strtoi(argv[optind], "invalid count");
		optind++;
	}

	if ((argc - optind) > 1)
		smbstat_usage(stderr, 1);

	(void) atexit(smbstat_fini);
	smbstat_init();
	for (;;) {
		smbstat_kstat_snapshot();
		smbstat_kstat_process();
		smbstat_kstat_print();
		if (smbstat_interval == 0)
			break;
		(void) sleep(smbstat_interval);
		smbstat_snapshot_inc_idx();
	}
	return (0);
}

/*
 * smbstat_init
 *
 * Global initialization.
 */
static void
smbstat_init(void)
{
	if ((smbstat_ksc = kstat_open()) == NULL)
		smbstat_fail(1, gettext("kstat_open(): can't open /dev/kstat"));

	smbstat_cpu_init();
	smbstat_srv_init();
	smbstat_wrk_init();
	smbstat_req_order();
}

/*
 * smbstat_fini
 *
 * Releases the resources smbstat_init() allocated.
 */
static void
smbstat_fini(void)
{
	smbstat_wrk_fini();
	smbstat_srv_fini();
	smbstat_cpu_fini();
	(void) kstat_close(smbstat_ksc);
}

/*
 * smbstat_kstat_snapshot
 *
 * Takes a snapshot of the data.
 */
static void
smbstat_kstat_snapshot(void)
{
	smbstat_cpu_snapshot();
	smbstat_srv_snapshot();
	smbstat_wrk_snapshot();
}

/*
 * smbstat_kstat_process
 */
static void
smbstat_kstat_process(void)
{
	smbstat_cpu_process();
	smbstat_srv_process();
	smbstat_wrk_process();
}

/*
 * smbstat_kstat_print
 *
 * Print the data processed.
 */
static void
smbstat_kstat_print(void)
{
	smbstat_termio_init();
	smbstat_print_counters();
	smbstat_print_throughput();
	smbstat_print_utilization();
	smbstat_print_requests();
	(void) fflush(stdout);
}

/*
 * smbstat_print_counters
 *
 * Displays the SMB server counters (session, users...).
 */
static void
smbstat_print_counters(void)
{
	if (!smbstat_opt_c)
		return;

	if (smbstat_opt_u || smbstat_opt_r || smbstat_opt_t ||
	    (smbstat_rows == 0) || (smbstat_rows >= smbstat_ws.ws_row)) {
		(void) printf(SMBSRV_COUNTERS_BANNER);
		smbstat_rows = 1;
	}

	(void) printf(SMBSRV_COUNTERS_FORMAT,
	    smbstat_srv_info.si_nbt_sess,
	    smbstat_srv_info.si_tcp_sess,
	    smbstat_srv_info.si_users,
	    smbstat_srv_info.si_trees,
	    smbstat_srv_info.si_files,
	    smbstat_srv_info.si_pipes);

	++smbstat_rows;
}
/*
 * smbstat_print_throughput
 *
 * Formats the SMB server throughput output.
 */
static void
smbstat_print_throughput(void)
{
	if (!smbstat_opt_t)
		return;

	if (smbstat_opt_u || smbstat_opt_r || smbstat_opt_c ||
	    (smbstat_rows == 0) || (smbstat_rows >= smbstat_ws.ws_row)) {
		(void) printf(SMBSRV_THROUGHPUT_BANNER);
		smbstat_rows = 1;
	}
	(void) printf(SMBSRV_THROUGHPUT_FORMAT,
	    smbstat_zero(smbstat_srv_info.si_rbs),
	    smbstat_zero(smbstat_srv_info.si_tbs),
	    smbstat_zero(smbstat_srv_info.si_rqs),
	    smbstat_zero(smbstat_srv_info.si_rds),
	    smbstat_zero(smbstat_srv_info.si_wrs));

	++smbstat_rows;
}

/*
 * smbstat_print_utilization
 */
static void
smbstat_print_utilization(void)
{
	char	*sat;
	if (!smbstat_opt_u)
		return;

	if (smbstat_opt_t || smbstat_opt_r || smbstat_opt_c ||
	    (smbstat_rows == 0) || (smbstat_rows >= smbstat_ws.ws_row)) {
		(void) printf(SMBSRV_UTILIZATION_BANNER);
		smbstat_rows = 1;
	}

	if (smbstat_srv_info.si_sat)
		sat = "yes";
	else
		sat = "no ";

	(void) printf(SMBSRV_UTILIZATION_FORMAT,
	    smbstat_srv_info.si_avw,
	    smbstat_srv_info.si_avr,
	    smbstat_srv_info.si_wserv,
	    smbstat_srv_info.si_rserv,
	    smbstat_zero(smbstat_srv_info.si_wpct),
	    smbstat_zero(smbstat_srv_info.si_rpct),
	    smbstat_zero(smbstat_srv_info.si_upct),
	    sat,
	    smbstat_srv_info.si_ticks[CPU_TICKS_USER],
	    smbstat_srv_info.si_ticks[CPU_TICKS_KERNEL],
	    smbstat_srv_info.si_ticks[CPU_TICKS_IDLE]);

	++smbstat_rows;
}

/*
 * smbstat_print_requests
 */
static void
smbstat_print_requests(void)
{
	smbstat_req_info_t	*prq;
	int			i;

	if (!smbstat_opt_r)
		return;

	(void) printf(SMBSRV_REQUESTS_BANNER, "       ");

	prq = smbstat_srv_info.si_reqs1;
	for (i = 0; i < SMB_COM_NUM; i++) {
		if (!smbstat_opt_a &&
		    strncmp(prq[i].ri_name, "Invalid", sizeof ("Invalid")) == 0)
			continue;

		if (!smbstat_opt_z || (prq[i].ri_pct != 0)) {
			(void) printf(SMBSRV_REQUESTS_FORMAT,
			    prq[i].ri_name,
			    prq[i].ri_opcode,
			    smbstat_zero(prq[i].ri_pct),
			    smbstat_zero(prq[i].ri_rbs),
			    smbstat_zero(prq[i].ri_tbs),
			    smbstat_zero(prq[i].ri_rqs),
			    prq[i].ri_mean,
			    prq[i].ri_stddev);
		}
	}

	prq = smbstat_srv_info.si_reqs2;
	for (i = 0; i < SMB2__NCMDS; i++) {
		if (!smbstat_opt_a && i == SMB2_INVALID_CMD)
			continue;

		if (!smbstat_opt_z || (prq[i].ri_pct != 0)) {
			(void) printf(SMBSRV_REQUESTS_FORMAT,
			    prq[i].ri_name,
			    prq[i].ri_opcode,
			    smbstat_zero(prq[i].ri_pct),
			    smbstat_zero(prq[i].ri_rbs),
			    smbstat_zero(prq[i].ri_tbs),
			    smbstat_zero(prq[i].ri_rqs),
			    prq[i].ri_mean,
			    prq[i].ri_stddev);
		}
	}
}

/*
 * smbstat_cpu_init
 */
static void
smbstat_cpu_init(void)
{
	size_t	size;
	int	i;

	smbstat_nrcpus = sysconf(_SC_CPUID_MAX) + 1;
	size = smbstat_nrcpus * sizeof (smbstat_cpu_snapshot_t);

	for (i = 0; i < SMBSTAT_SNAPSHOT_COUNT; i++)
		smbstat_cpu_snapshots[i] = smbstat_zalloc(size);
}

/*
 * smbstat_cpu_fini
 */
static void
smbstat_cpu_fini(void)
{
	size_t	size;
	int	i;

	size = smbstat_nrcpus * sizeof (smbstat_cpu_snapshot_t);

	for (i = 0; i < SMBSTAT_SNAPSHOT_COUNT; i++)
		smbstat_free(smbstat_cpu_snapshots[i], size);
}

/*
 * smbstat_cpu_current_snapshot
 */
static smbstat_cpu_snapshot_t *
smbstat_cpu_current_snapshot(void)
{
	return (smbstat_cpu_snapshots[smbstat_snapshot_idx]);
}

/*
 * smbstat_cpu_previous_snapshot
 */
static smbstat_cpu_snapshot_t *
smbstat_cpu_previous_snapshot(void)
{
	int	idx;

	idx = (smbstat_snapshot_idx - 1) & SMBSTAT_SNAPSHOT_MASK;
	return (smbstat_cpu_snapshots[idx]);
}

/*
 * smbstat_cpu_snapshot
 */
static void
smbstat_cpu_snapshot(void)
{
	kstat_t			*ksp;
	kstat_named_t		*ksn;
	smbstat_cpu_snapshot_t	*curr;
	long			i;
	int			j;

	curr =  smbstat_cpu_current_snapshot();

	for (i = 0; i < smbstat_nrcpus;	i++, curr++) {
		curr->cs_id = SMBSTAT_ID_NO_CPU;
		curr->cs_state = p_online(i, P_STATUS);
		/* If no valid CPU is present, move on to the next one */
		if (curr->cs_state == -1)
			continue;

		curr->cs_id = i;

		ksp = kstat_lookup(smbstat_ksc, "cpu", i, "sys");
		if (ksp == NULL)
			smbstat_fail(1,
			    gettext("kstat_lookup('cpu sys %d') failed"), i);

		if (kstat_read(smbstat_ksc, ksp, NULL) == -1)
			smbstat_fail(1,
			    gettext("kstat_read('cpu sys %d') failed"), i);

		for (j = 0; j < CPU_TICKS_SENTINEL; j++) {
			ksn = kstat_data_lookup(ksp, smbstat_cpu_states[j]);
			if (ksn == NULL)
				smbstat_fail(1,
				    gettext("kstat_data_lookup('%s') failed"),
				    smbstat_cpu_states[j]);
			curr->cs_ticks[j] = ksn->value.ui64;
		}
	}
}

/*
 * smbstat_cpu_process
 */
static void
smbstat_cpu_process(void)
{
	smbstat_cpu_snapshot_t	*curr, *prev;
	double			total_ticks;
	double			agg_ticks[CPU_TICKS_SENTINEL];
	int			i, j;

	curr =  smbstat_cpu_current_snapshot();
	prev =  smbstat_cpu_previous_snapshot();
	bzero(agg_ticks, sizeof (agg_ticks));
	total_ticks = 0;

	for (i = 0; i < smbstat_nrcpus; i++, curr++, prev++) {
		for (j = 0; j < CPU_TICKS_SENTINEL; j++) {
			agg_ticks[j] +=	smbstat_sub_64(curr->cs_ticks[j],
			    prev->cs_ticks[j]);
			total_ticks += smbstat_sub_64(curr->cs_ticks[j],
			    prev->cs_ticks[j]);
		}
	}

	for (j = 0; j < CPU_TICKS_SENTINEL; j++)
		smbstat_srv_info.si_ticks[j] =
		    (agg_ticks[j] * 100.0) / total_ticks;
}

/*
 * smbstat_wrk_init
 */
static void
smbstat_wrk_init(void)
{
	smbstat_wrk_ksp =
	    kstat_lookup(smbstat_ksc, "unix", -1, SMBSRV_KSTAT_WORKERS);
	if (smbstat_wrk_ksp == NULL)
		smbstat_fail(1,
		    gettext("cannot retrieve smbsrv workers kstat\n"));
}

static void
smbstat_wrk_fini(void)
{
	smbstat_wrk_ksp = NULL;
}

/*
 * smbstat_wrk_snapshot
 */
static void
smbstat_wrk_snapshot(void)
{
	smbstat_wrk_snapshot_t	*curr;
	kstat_named_t		*kn;

	curr = smbstat_wrk_current_snapshot();

	if (kstat_read(smbstat_ksc, smbstat_wrk_ksp, NULL) == -1)
		smbstat_fail(1, gettext("kstat_read('%s') failed"),
		    smbstat_wrk_ksp->ks_name);

	kn = kstat_data_lookup(smbstat_wrk_ksp, "maxthreads");
	if ((kn == NULL) || (kn->data_type != KSTAT_DATA_UINT64))
		smbstat_fail(1, gettext("kstat_read('%s') failed"),
		    "maxthreads");
	curr->ws_maxthreads = kn->value.ui64;

	kn = kstat_data_lookup(smbstat_wrk_ksp, "bnalloc");
	if ((kn == NULL) || (kn->data_type != KSTAT_DATA_UINT64))
		smbstat_fail(1, gettext("kstat_read('%s') failed"),
		    "bnalloc");
	curr->ws_bnalloc = kn->value.ui64;
}

/*
 * smbstat_wrk_process
 */
static void
smbstat_wrk_process(void)
{
	smbstat_wrk_snapshot_t	*curr;

	curr = smbstat_wrk_current_snapshot();

	if (curr->ws_bnalloc >= curr->ws_maxthreads)
		smbstat_srv_info.si_sat = B_TRUE;
	else
		smbstat_srv_info.si_sat = B_FALSE;
}

/*
 * smbstat_wrk_current_snapshot
 */
static smbstat_wrk_snapshot_t *
smbstat_wrk_current_snapshot(void)
{
	return (&smbstat_wrk_snapshots[smbstat_snapshot_idx]);
}

/*
 * smbstat_srv_init
 */
static void
smbstat_srv_init(void)
{
	smbstat_srv_ksp = kstat_lookup(smbstat_ksc, SMBSRV_KSTAT_MODULE,
	    getzoneid(), SMBSRV_KSTAT_STATISTICS);
	if (smbstat_srv_ksp == NULL)
		smbstat_fail(1, gettext("cannot retrieve smbsrv kstat\n"));
}

/*
 * smbstat_srv_fini
 */
static void
smbstat_srv_fini(void)
{
	smbstat_srv_ksp = NULL;
}

/*
 * smbstat_srv_snapshot
 *
 * Take a snapshot of the smbsrv module statistics.
 */
static void
smbstat_srv_snapshot(void)
{
	smbstat_srv_snapshot_t	*curr;

	curr = smbstat_srv_current_snapshot();

	if ((kstat_read(smbstat_ksc, smbstat_srv_ksp, NULL) == -1) ||
	    (smbstat_srv_ksp->ks_data_size != sizeof (curr->ss_data)))
		smbstat_fail(1, gettext("kstat_read('%s') failed"),
		    smbstat_srv_ksp->ks_name);

	curr->ss_snaptime = smbstat_srv_ksp->ks_snaptime;
	bcopy(smbstat_srv_ksp->ks_data, &curr->ss_data, sizeof (curr->ss_data));
}

/*
 * smbstat_srv_process
 *
 * Processes the snapshot data.
 */
static void
smbstat_srv_process(void)
{
	smbstat_srv_snapshot_t	*curr, *prev;

	curr = smbstat_srv_current_snapshot();
	prev = smbstat_srv_previous_snapshot();

	if (prev->ss_snaptime == 0)
		smbstat_srv_info.si_hretime =
		    smbstat_hrtime_delta(curr->ss_data.ks_start_time,
		    curr->ss_snaptime);
	else
		smbstat_srv_info.si_hretime =
		    smbstat_hrtime_delta(prev->ss_snaptime, curr->ss_snaptime);

	smbstat_srv_info.si_etime = smbstat_srv_info.si_hretime / NANOSEC;
	smbstat_srv_info.si_total_nreqs =
	    smbstat_sub_64(curr->ss_data.ks_nreq, prev->ss_data.ks_nreq);

	if (smbstat_opt_c)
		smbstat_srv_process_counters(curr);
	if (smbstat_opt_t)
		smbstat_srv_process_throughput(curr, prev);
	if (smbstat_opt_u)
		smbstat_srv_process_utilization(curr, prev);
	if (smbstat_opt_r)
		smbstat_srv_process_requests(curr, prev);
}

/*
 * smbstat_srv_process_counters
 */
static void
smbstat_srv_process_counters(smbstat_srv_snapshot_t *curr)
{
	smbstat_srv_info.si_nbt_sess = curr->ss_data.ks_nbt_sess;
	smbstat_srv_info.si_tcp_sess = curr->ss_data.ks_tcp_sess;
	smbstat_srv_info.si_users = curr->ss_data.ks_users;
	smbstat_srv_info.si_trees = curr->ss_data.ks_trees;
	smbstat_srv_info.si_files = curr->ss_data.ks_files;
	smbstat_srv_info.si_pipes = curr->ss_data.ks_pipes;
}

/*
 * smbstat_srv_process_throughput
 *
 * Processes the data relative to the throughput of the smbsrv module and
 * stores the results in the structure smbstat_srv_info.
 */
static void
smbstat_srv_process_throughput(
    smbstat_srv_snapshot_t	*curr,
    smbstat_srv_snapshot_t	*prev)
{
	smbstat_srv_info.si_tbs =
	    smbstat_sub_64(curr->ss_data.ks_txb, prev->ss_data.ks_txb);
	smbstat_srv_info.si_tbs /= smbstat_srv_info.si_etime;
	smbstat_srv_info.si_rbs =
	    smbstat_sub_64(curr->ss_data.ks_rxb, prev->ss_data.ks_rxb);
	smbstat_srv_info.si_rbs /= smbstat_srv_info.si_etime;
	smbstat_srv_info.si_rqs = smbstat_srv_info.si_total_nreqs;
	smbstat_srv_info.si_rqs /= smbstat_srv_info.si_etime;

	smbstat_srv_info.si_rds = smbstat_sub_64(
	    curr->ss_data.ks_reqs1[SMB_COM_READ].kr_nreq,
	    prev->ss_data.ks_reqs1[SMB_COM_READ].kr_nreq);
	smbstat_srv_info.si_rds += smbstat_sub_64(
	    curr->ss_data.ks_reqs1[SMB_COM_LOCK_AND_READ].kr_nreq,
	    prev->ss_data.ks_reqs1[SMB_COM_LOCK_AND_READ].kr_nreq);
	smbstat_srv_info.si_rds += smbstat_sub_64(
	    curr->ss_data.ks_reqs1[SMB_COM_READ_RAW].kr_nreq,
	    prev->ss_data.ks_reqs1[SMB_COM_READ_RAW].kr_nreq);
	smbstat_srv_info.si_rds += smbstat_sub_64(
	    curr->ss_data.ks_reqs1[SMB_COM_READ_ANDX].kr_nreq,
	    prev->ss_data.ks_reqs1[SMB_COM_READ_ANDX].kr_nreq);
	smbstat_srv_info.si_rds += smbstat_sub_64(
	    curr->ss_data.ks_reqs2[SMB2_READ].kr_nreq,
	    prev->ss_data.ks_reqs2[SMB2_READ].kr_nreq);
	smbstat_srv_info.si_rds /= smbstat_srv_info.si_etime;

	smbstat_srv_info.si_wrs = smbstat_sub_64(
	    curr->ss_data.ks_reqs1[SMB_COM_WRITE].kr_nreq,
	    prev->ss_data.ks_reqs1[SMB_COM_WRITE].kr_nreq);
	smbstat_srv_info.si_wrs += smbstat_sub_64(
	    curr->ss_data.ks_reqs1[SMB_COM_WRITE_AND_UNLOCK].kr_nreq,
	    prev->ss_data.ks_reqs1[SMB_COM_WRITE_AND_UNLOCK].kr_nreq);
	smbstat_srv_info.si_wrs += smbstat_sub_64(
	    curr->ss_data.ks_reqs1[SMB_COM_WRITE_RAW].kr_nreq,
	    prev->ss_data.ks_reqs1[SMB_COM_WRITE_RAW].kr_nreq);
	smbstat_srv_info.si_wrs += smbstat_sub_64(
	    curr->ss_data.ks_reqs1[SMB_COM_WRITE_AND_CLOSE].kr_nreq,
	    prev->ss_data.ks_reqs1[SMB_COM_WRITE_AND_CLOSE].kr_nreq);
	smbstat_srv_info.si_wrs += smbstat_sub_64(
	    curr->ss_data.ks_reqs1[SMB_COM_WRITE_ANDX].kr_nreq,
	    prev->ss_data.ks_reqs1[SMB_COM_WRITE_ANDX].kr_nreq);
	smbstat_srv_info.si_wrs += smbstat_sub_64(
	    curr->ss_data.ks_reqs2[SMB2_WRITE].kr_nreq,
	    prev->ss_data.ks_reqs2[SMB2_WRITE].kr_nreq);
	smbstat_srv_info.si_wrs /= smbstat_srv_info.si_etime;
}

/*
 * smbstat_srv_process_utilization
 *
 * Processes the data relative to the utilization of the smbsrv module and
 * stores the results in the structure smbstat_srv_info.
 */
static void
smbstat_srv_process_utilization(
    smbstat_srv_snapshot_t	*curr,
    smbstat_srv_snapshot_t	*prev)
{
	double	tw_delta, tr_delta;
	double	w_delta, r_delta;
	double	tps, rqs;

	w_delta = smbstat_hrtime_delta(prev->ss_data.ks_utilization.ku_wlentime,
	    curr->ss_data.ks_utilization.ku_wlentime);
	r_delta = smbstat_hrtime_delta(prev->ss_data.ks_utilization.ku_rlentime,
	    curr->ss_data.ks_utilization.ku_rlentime);
	tw_delta = smbstat_hrtime_delta(prev->ss_data.ks_utilization.ku_wtime,
	    curr->ss_data.ks_utilization.ku_wtime);
	tr_delta = smbstat_hrtime_delta(prev->ss_data.ks_utilization.ku_rtime,
	    curr->ss_data.ks_utilization.ku_rtime);
	rqs = smbstat_srv_info.si_total_nreqs / smbstat_srv_info.si_etime;

	/* Average number of requests waiting */
	if (w_delta != 0)
		smbstat_srv_info.si_avw = w_delta / smbstat_srv_info.si_hretime;
	else
		smbstat_srv_info.si_avw = 0.0;

	/* Average number of request running */
	if (r_delta != 0)
		smbstat_srv_info.si_avr = r_delta / smbstat_srv_info.si_hretime;
	else
		smbstat_srv_info.si_avr = 0.0;

	/* Utilization */
	smbstat_srv_info.si_upct =
	    (smbstat_srv_info.si_avr / curr->ss_data.ks_maxreqs) * 100;

	/* Average wait service time in milliseconds */
	smbstat_srv_info.si_rserv = 0.0;
	smbstat_srv_info.si_wserv = 0.0;
	if (rqs > 0.0 &&
	    (smbstat_srv_info.si_avw != 0.0 ||
	    smbstat_srv_info.si_avr != 0.0)) {
		tps = 1 / rqs;
		if (smbstat_srv_info.si_avw != 0.0)
			smbstat_srv_info.si_wserv =
			    smbstat_srv_info.si_avw * tps;
		if (smbstat_srv_info.si_avr != 0.0)
			smbstat_srv_info.si_rserv =
			    smbstat_srv_info.si_avr * tps;
	}

	/* % of time there is a transaction waiting for service */
	if (tw_delta != 0) {
		smbstat_srv_info.si_wpct = tw_delta;
		smbstat_srv_info.si_wpct /= smbstat_srv_info.si_hretime;
		smbstat_srv_info.si_wpct *= 100.0;
	} else {
		smbstat_srv_info.si_wpct = 0.0;
	}

	/* % of time there is a transaction running */
	if (tr_delta != 0) {
		smbstat_srv_info.si_rpct = tr_delta;
		smbstat_srv_info.si_rpct /= smbstat_srv_info.si_hretime;
		smbstat_srv_info.si_rpct *= 100.0;
	} else {
		smbstat_srv_info.si_rpct = 0.0;
	}
}

/*
 * smbstat_srv_process_requests
 *
 * Processes the data relative to the SMB requests and stores the results in
 * the structure smbstat_srv_info.
 */
static void
smbstat_srv_process_requests(
    smbstat_srv_snapshot_t	*curr,
    smbstat_srv_snapshot_t	*prev)
{
	smbstat_req_info_t	*info;
	smb_kstat_req_t		*curr_req;
	smb_kstat_req_t		*prev_req;
	int			i, idx;
	boolean_t	firstcall = (prev->ss_snaptime == 0);

	for (i = 0; i < SMB_COM_NUM; i++) {
		info = &smbstat_srv_info.si_reqs1[i];
		idx = info[i].ri_opcode & 0xFF;
		curr_req = &curr->ss_data.ks_reqs1[idx];
		prev_req = &prev->ss_data.ks_reqs1[idx];
		smbstat_srv_process_one_req(
		    info, curr_req, prev_req, firstcall);
	}

	for (i = 0; i < SMB2__NCMDS; i++) {
		info = &smbstat_srv_info.si_reqs2[i];
		curr_req = &curr->ss_data.ks_reqs2[i];
		prev_req = &prev->ss_data.ks_reqs2[i];
		smbstat_srv_process_one_req(
		    info, curr_req, prev_req, firstcall);
	}
}

static void
smbstat_srv_process_one_req(
	smbstat_req_info_t	*info,
	smb_kstat_req_t		*curr_req,
	smb_kstat_req_t		*prev_req,
	boolean_t		firstcall)
{
	double			nrqs;

	nrqs = smbstat_sub_64(curr_req->kr_nreq,
	    prev_req->kr_nreq);

	info->ri_rqs = nrqs / smbstat_srv_info.si_etime;

	info->ri_rbs = smbstat_sub_64(
	    curr_req->kr_rxb,
	    prev_req->kr_rxb) /
	    smbstat_srv_info.si_etime;

	info->ri_tbs = smbstat_sub_64(
	    curr_req->kr_txb,
	    prev_req->kr_txb) /
	    smbstat_srv_info.si_etime;

	info->ri_pct = nrqs * 100;
	if (smbstat_srv_info.si_total_nreqs > 0)
		info->ri_pct /= smbstat_srv_info.si_total_nreqs;

	if (firstcall) {
		/* First time. Take the aggregate */
		info->ri_stddev =
		    curr_req->kr_a_stddev;
		info->ri_mean = curr_req->kr_a_mean;
	} else {
		/* Take the differential */
		info->ri_stddev =
		    curr_req->kr_d_stddev;
		info->ri_mean = curr_req->kr_d_mean;
	}
	if (nrqs > 0) {
		info->ri_stddev /= nrqs;
		info->ri_stddev = sqrt(info->ri_stddev);
	} else {
		info->ri_stddev = 0;
	}
	info->ri_stddev /= NANOSEC;
	info->ri_mean /= NANOSEC;
}


/*
 * smbstat_srv_current_snapshot
 *
 * Returns the current snapshot.
 */
static smbstat_srv_snapshot_t *
smbstat_srv_current_snapshot(void)
{
	return (&smbstat_srv_snapshots[smbstat_snapshot_idx]);
}

/*
 * smbstat_srv_previous_snapshot
 *
 * Returns the previous snapshot.
 */
static smbstat_srv_snapshot_t *
smbstat_srv_previous_snapshot(void)
{
	int	idx;

	idx = (smbstat_snapshot_idx - 1) & SMBSTAT_SNAPSHOT_MASK;
	return (&smbstat_srv_snapshots[idx]);
}

/*
 * smbstat_usage
 *
 * Prints out a help message.
 */
static void
smbstat_usage(FILE *fd, int exit_code)
{
	(void) fprintf(fd, gettext(SMBSTAT_HELP));
	exit(exit_code);
}

/*
 * smbstat_fail
 *
 * Prints out to stderr an error message and exits the process.
 */
static void
smbstat_fail(int do_perror, char *message, ...)
{
	va_list args;

	va_start(args, message);
	(void) fprintf(stderr, gettext("smbstat: "));
	/* LINTED E_SEC_PRINTF_VAR_FMT */
	(void) vfprintf(stderr, message, args);
	va_end(args);
	if (do_perror)
		(void) fprintf(stderr, ": %s", strerror(errno));
	(void) fprintf(stderr, "\n");
	exit(1);
}

/*
 * smbstat_sub_64
 *
 * Substract 2 uint64_t and returns a double.
 */
static double
smbstat_sub_64(uint64_t a, uint64_t b)
{
	return ((double)(a - b));
}

/*
 * smbstat_zero
 *
 * Returns zero if the value passed in is less than 1.
 */
static double
smbstat_zero(double value)
{
	if (value < 1)
		value = 0;
	return (value);
}

/*
 * smbstat_strtoi
 *
 * Converts a string representing an integer value into its binary value.
 * If the conversion fails this routine exits the process.
 */
static uint_t
smbstat_strtoi(char const *val, char *errmsg)
{
	char	*end;
	long	tmp;

	errno = 0;
	tmp = strtol(val, &end, 10);
	if (*end != '\0' || errno)
		smbstat_fail(1, "%s %s", errmsg, val);
	return ((uint_t)tmp);
}

/*
 * smbstat_termio_init
 *
 * Determines the size of the terminal associated with the process.
 */
static void
smbstat_termio_init(void)
{
	char	*envp;

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &smbstat_ws) != -1) {
		if (smbstat_ws.ws_row == 0) {
			envp = getenv("LINES");
			if (envp != NULL)
				smbstat_ws.ws_row = atoi(envp);
		}

		if (smbstat_ws.ws_col == 0) {
			envp = getenv("COLUMNS");
			if (envp != NULL)
				smbstat_ws.ws_row = atoi(envp);
		}
	}
	if (smbstat_ws.ws_col == 0)
		smbstat_ws.ws_col = 80;
	if (smbstat_ws.ws_row == 0)
		smbstat_ws.ws_row = 25;
}

/*
 * smbstat_snapshot_idx_inc
 *
 * Increments the snapshot index.
 */
static void
smbstat_snapshot_inc_idx(void)
{
	smbstat_snapshot_idx++;
	smbstat_snapshot_idx &= SMBSTAT_SNAPSHOT_MASK;
}

/*
 * smbstat_req_cmp_name
 *
 * Call back function passed to qsort() when the list of requests must be sorted
 * by name.
 */
static int
smbstat_req_cmp_name(const void *obj1, const void *obj2)
{
	return (strncasecmp(
	    ((smbstat_req_info_t *)obj1)->ri_name,
	    ((smbstat_req_info_t *)obj2)->ri_name,
	    sizeof (((smbstat_req_info_t *)obj2)->ri_name)));
}

/*
 * smbstat_req_order
 *
 * Snapshots the smbsrv module statistics once to get the name of the requests.
 * The request list is smbstat_srv_info is then sorted by name or by code
 * depending on the boolean smbstat_opt_a.
 * The function should be called once during initialization.
 */
static void
smbstat_req_order(void)
{
	smbstat_srv_snapshot_t  *ss;
	smbstat_req_info_t	*info;
	smb_kstat_req_t		*reqs;
	int			i;

	smbstat_srv_snapshot();
	ss = smbstat_srv_current_snapshot();

	reqs = ss->ss_data.ks_reqs1;
	info = smbstat_srv_info.si_reqs1;
	for (i = 0; i < SMB_COM_NUM; i++) {
		(void) strlcpy(info[i].ri_name, reqs[i].kr_name,
		    sizeof (reqs[i].kr_name));
		info[i].ri_opcode = i;
	}
	if (smbstat_opt_n)
		qsort(info, SMB_COM_NUM, sizeof (smbstat_req_info_t),
		    smbstat_req_cmp_name);

	reqs = ss->ss_data.ks_reqs2;
	info = smbstat_srv_info.si_reqs2;
	for (i = 0; i < SMB2__NCMDS; i++) {
		(void) strlcpy(info[i].ri_name, reqs[i].kr_name,
		    sizeof (reqs[i].kr_name));
		info[i].ri_opcode = i;
	}
	if (smbstat_opt_n)
		qsort(info, SMB2__NCMDS, sizeof (smbstat_req_info_t),
		    smbstat_req_cmp_name);
}

/*
 * Return the number of ticks delta between two hrtime_t
 * values. Attempt to cater for various kinds of overflow
 * in hrtime_t - no matter how improbable.
 */
static double
smbstat_hrtime_delta(hrtime_t old, hrtime_t new)
{
	uint64_t	del;

	if ((new >= old) && (old >= 0L))
		return ((double)(new - old));
	/*
	 * We've overflowed the positive portion of an hrtime_t.
	 */
	if (new < 0L) {
		/*
		 * The new value is negative. Handle the case where the old
		 * value is positive or negative.
		 */
		uint64_t n1;
		uint64_t o1;

		n1 = -new;
		if (old > 0L)
			return ((double)(n1 - old));

		o1 = -old;
		del = n1 - o1;
		return ((double)del);
	}

	/*
	 * Either we've just gone from being negative to positive *or* the last
	 * entry was positive and the new entry is also positive but *less* than
	 * the old entry. This implies we waited quite a few days on a very fast
	 * system between displays.
	 */
	if (old < 0L) {
		uint64_t o2;
		o2 = -old;
		del = UINT64_MAX - o2;
	} else {
		del = UINT64_MAX - old;
	}
	del += new;
	return ((double)del);
}

static void *
smbstat_zalloc(size_t size)
{
	void	*ptr;

	ptr = umem_zalloc(size, UMEM_DEFAULT);
	if (ptr == NULL)
		smbstat_fail(1,	gettext("out of memory"));
	return (ptr);
}

static void
smbstat_free(void *ptr, size_t size)
{
	umem_free(ptr, size);
}

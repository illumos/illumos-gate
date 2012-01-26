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
 * Copyright 2012 Joyent, Inc.  All rights reserved.
 */


#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <kstat.h>
#include <errno.h>
#include <sys/zone.h>

typedef struct {
	boolean_t	valid;
	uint64_t	rqueue;
	uint64_t	rticks;
	uint32_t	fss_share_pct;
	uint64_t	fss_pri_hi;
	uint64_t	fss_pri_avg;
	double		avrun1;
	uint64_t	ns_usr;
	uint64_t	ns_sys;
	uint64_t	ns_wt;
	uint64_t	cpu_cap;
	uint64_t	cpu_baseline;
	uint64_t	cpu_cap_usage;
	uint64_t	above_base_sec;
	uint64_t	delay_cnt;
	uint64_t	delay_time;
	/* Values from the previous cycle so we can diff */
	uint64_t	prv_rticks;
	uint64_t	prv_ns_usr;
	uint64_t	prv_ns_sys;
	uint64_t	prv_ns_wt;
	uint64_t	prv_above_base_sec;
	uint64_t	prv_delay_cnt;
	uint64_t	prv_delay_time;
} zinfo_t;

/*
 * MAX_ZONEID is only 10000, so it is a lot faster to go direct to the entry
 * we want, even though valid entries in this array will be sparse.
 */

static zinfo_t	zinfo[MAX_ZONEID];
static uint32_t	nsec_per_tick = 0;

static void
usage()
{
	(void) fprintf(stderr, "zschedstat [-r] [interval [count]]\n");
	exit(1);
}

static void
get_zone_misc(int zid, kstat_t *ksp)
{
	kstat_named_t	*kp;

	kp = (kstat_named_t *)kstat_data_lookup(ksp, "run_queue");
	zinfo[zid].rqueue = kp->value.ui64;

	kp = (kstat_named_t *)kstat_data_lookup(ksp, "run_ticks");
	zinfo[zid].rticks = kp->value.ui64;

	kp = (kstat_named_t *)kstat_data_lookup(ksp, "fss_share_percent");
	zinfo[zid].fss_share_pct = kp->value.ui32;

	kp = (kstat_named_t *)kstat_data_lookup(ksp, "fss_pri_hi");
	zinfo[zid].fss_pri_hi = kp->value.ui64;

	kp = (kstat_named_t *)kstat_data_lookup(ksp, "fss_pri_avg");
	zinfo[zid].fss_pri_avg = kp->value.ui64;

	kp = (kstat_named_t *)kstat_data_lookup(ksp, "avenrun_1min");
	zinfo[zid].avrun1 = (double)kp->value.ui32 / FSCALE;

	kp = (kstat_named_t *)kstat_data_lookup(ksp, "nsec_user");
	zinfo[zid].ns_usr = kp->value.ui64;

	kp = (kstat_named_t *)kstat_data_lookup(ksp, "nsec_sys");
	zinfo[zid].ns_sys = kp->value.ui64;

	kp = (kstat_named_t *)kstat_data_lookup(ksp, "nsec_waitrq");
	zinfo[zid].ns_wt = kp->value.ui64;
}

static void
get_zone_caps(int zid, kstat_t *ksp)
{
	kstat_named_t	*kp;

	kp = (kstat_named_t *)kstat_data_lookup(ksp, "value");
	zinfo[zid].cpu_cap = kp->value.ui64;

	kp = (kstat_named_t *)kstat_data_lookup(ksp, "baseline");
	zinfo[zid].cpu_baseline = kp->value.ui64;

	kp = (kstat_named_t *)kstat_data_lookup(ksp, "usage");
	zinfo[zid].cpu_cap_usage = kp->value.ui64;

	kp = (kstat_named_t *)kstat_data_lookup(ksp, "above_base_sec");
	zinfo[zid].above_base_sec = kp->value.ui64;
}

static void
get_zone_vfs(int zid, kstat_t *ksp)
{
	kstat_named_t	*kp;

	kp = (kstat_named_t *)kstat_data_lookup(ksp, "delay_cnt");
	zinfo[zid].delay_cnt = kp->value.ui64;

	kp = (kstat_named_t *)kstat_data_lookup(ksp, "delay_time");
	zinfo[zid].delay_time = kp->value.ui64;
}

static void
read_kstats()
{
	kstat_ctl_t	*kc;
	kstat_t		*ksp;

	if ((kc = kstat_open()) == NULL) {
		(void) fprintf(stderr, "open failed\n");
		exit(1);
	}

	for (ksp = kc->kc_chain; ksp; ksp = ksp->ks_next) {
		if (strcmp("zones", ksp->ks_module) == 0 &&
		    strcmp("zone_misc", ksp->ks_class) == 0) {
			if (kstat_read(kc, ksp, NULL) == -1) {
				(void) fprintf(stderr, "read failed\n");
				exit(1);
			}
			zinfo[ksp->ks_instance].valid = B_TRUE;

			get_zone_misc(ksp->ks_instance, ksp);

		} else if (strcmp("caps", ksp->ks_module) == 0 &&
		    strcmp("zone_caps", ksp->ks_class) == 0 &&
		    strncmp("cpucaps_zone", ksp->ks_name, 12) == 0) {
			if (kstat_read(kc, ksp, NULL) == -1) {
				(void) fprintf(stderr, "read failed\n");
				exit(1);
			}
			zinfo[ksp->ks_instance].valid = B_TRUE;

			get_zone_caps(ksp->ks_instance, ksp);

		} else if (strcmp("zone_vfs", ksp->ks_module) == 0) {
			if (kstat_read(kc, ksp, NULL) == -1) {
				(void) fprintf(stderr, "read failed\n");
				exit(1);
			}
			zinfo[ksp->ks_instance].valid = B_TRUE;

			get_zone_vfs(ksp->ks_instance, ksp);

		} else if (nsec_per_tick == 0 &&
		    strcmp("unix", ksp->ks_module) == 0 &&
		    strcmp("system_misc", ksp->ks_name) == 0) {
			kstat_named_t	*kp;

			if (kstat_read(kc, ksp, NULL) == -1) {
				(void) fprintf(stderr, "read failed\n");
				exit(1);
			}

			kp = (kstat_named_t *)kstat_data_lookup(ksp,
			    "nsec_per_tick");
			nsec_per_tick = kp->value.ui32;
		}
	}

	(void) kstat_close(kc);
}

static float
fmt_nsec(uint64_t curr, uint64_t prv)
{
	float s;
	uint64_t nsec;

	nsec = curr - prv;
	s = (float)nsec / (long)NANOSEC;

	return (s);
}

/* convert usecs to msecs */
static float
fmt_usec(uint64_t curr, uint64_t prv)
{
	float s;
	uint64_t usec;

	usec = curr - prv;
	s = (float)usec / (long)MILLISEC;

	return (s);
}

static float
fmt_ticks(uint64_t curr, uint64_t prv)
{
	float s;
	uint64_t ticks, nsec;

	ticks = curr - prv;
	nsec = ticks * nsec_per_tick;

	s = (float)nsec / (long)NANOSEC;

	return (s);
}

static void
print_data(boolean_t parse)
{
	int i;
	char *fmt;

	if (parse) {
		fmt = "%d,%lld,%.2f,%.1f,%lld,%lld,%lld,%lld,%lld,"
		    "%.2f,%lld,%.2f,%.2f,%.2f,%.2f\n";
	} else {
		fmt = "%4d %2lld %6.2f %5.1f %2lld %2lld %5lld %5lld %2lld "
		    "%5.2f %4lld %6.2f %6.2f %6.2f %6.2f\n";

		(void) printf("%4s %2s %6s %5s %2s %2s %5s %5s %2s "
		    "%5s %4s %6s %6s %6s %6s\n",
		    "zid", "rq", "rsec", "sh%", "ph", "pa", "cap", "usage",
		    "bs", "1mla", "dcnt", "dms", "user", "sys", "wtrq");
	}

	for (i = 0; i < MAX_ZONEID; i++) {
		if (zinfo[i].valid == B_FALSE)
			continue;

		/*LINTED E_SEC_PRINTF_VAR_FMT*/
		(void) printf(fmt,
		    i,
		    zinfo[i].rqueue,
		    fmt_ticks(zinfo[i].rticks, zinfo[i].prv_rticks),
		    (float)zinfo[i].fss_share_pct / (float)10,
		    zinfo[i].fss_pri_hi,
		    zinfo[i].fss_pri_avg,
		    zinfo[i].cpu_cap,
		    zinfo[i].cpu_cap_usage,
		    zinfo[i].above_base_sec - zinfo[i].prv_above_base_sec,
		    zinfo[i].avrun1,
		    zinfo[i].delay_cnt - zinfo[i].prv_delay_cnt,
		    fmt_usec(zinfo[i].delay_time, zinfo[i].prv_delay_time),
		    fmt_nsec(zinfo[i].ns_usr, zinfo[i].prv_ns_usr),
		    fmt_nsec(zinfo[i].ns_sys, zinfo[i].prv_ns_sys),
		    fmt_nsec(zinfo[i].ns_wt, zinfo[i].prv_ns_wt));

		zinfo[i].valid = B_FALSE;
		zinfo[i].prv_rticks = zinfo[i].rticks;
		zinfo[i].prv_ns_usr = zinfo[i].ns_usr;
		zinfo[i].prv_ns_sys = zinfo[i].ns_sys;
		zinfo[i].prv_ns_wt = zinfo[i].ns_wt;
		zinfo[i].prv_above_base_sec = zinfo[i].above_base_sec;
		zinfo[i].prv_delay_cnt = zinfo[i].delay_cnt;
		zinfo[i].prv_delay_time = zinfo[i].delay_time;
	}
}

int
main(int argc, char **argv)
{
	int interval = 5;
	int count;
	int forever = 1;
	int arg;
	extern int optind;
	boolean_t do_parse = B_FALSE;

	while ((arg = getopt(argc, argv, "r")) != EOF) {
		switch (arg) {
		case 'r':
			do_parse = B_TRUE;
			break;
		default:
			usage();
		}
	}

	if (argc > optind) {
		interval = atoi(argv[optind]);
		optind++;

		if (argc > optind) {
			count = atoi(argv[optind]);
			forever = 0;
			optind++;
		}
	}
	if (argc > optind)
		usage();

	for (;;) {
		read_kstats();
		print_data(do_parse);
		if (forever == 0 && --count == 0)
			break;
		(void) sleep(interval);
	}

	return (0);
}

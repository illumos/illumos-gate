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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>				/* sleep() */
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <thread.h>
#include <time.h>
#include <kstat.h>
#include <sys/sysinfo.h>
#include <sys/sysmacros.h>
#include "powerd.h"

/*
 * External Variables
 */
extern	pwr_info_t	*info;

/*
 * State Variables
 */
static	kstat_ctl_t	*kc;			/* libkstat cookie */
static	int		ncpus;
static	kstat_t		**cpu_stats_list = NULL;
static	kstat_t		old_cpu_stats, new_cpu_stats;
static	hrtime_t	tty_snaptime;
static	kstat_t		*load_ave_ksp;
static	ulong_t		load_ave;
static	hrtime_t	last_load_ave_change;
static	kstat_t		*conskbd_ksp, *consms_ksp;
static	kstat_t		*nfs_client2_kstat, *nfs_client3_kstat;
static	kstat_t		*nfs_server2_kstat, *nfs_server3_kstat;
static	uint64_t	old_nfs_calls, new_nfs_calls;

typedef	struct activity_data {
		struct	activity_data	*next;
		struct	activity_data	*prev;
		int			activity_delta;
		hrtime_t		snaptime;
} activity_data_t;

#define	NULLACTIVITY (activity_data_t *)0
static	activity_data_t	*disk_act_start = NULLACTIVITY;
static	activity_data_t	*disk_act_end = NULLACTIVITY;
static	activity_data_t	*tty_act_start = NULLACTIVITY;
static	activity_data_t	*tty_act_end = NULLACTIVITY;
static	activity_data_t	*nfs_act_start = NULLACTIVITY;
static	activity_data_t	*nfs_act_end = NULLACTIVITY;

struct diskinfo {
	struct diskinfo *next;
	kstat_t 	*ks;
	kstat_io_t 	new_kios, old_kios;
};

#define	NULLDISK (struct diskinfo *)0
static	struct diskinfo zerodisk = { NULL, NULL };
static	struct diskinfo *firstdisk = NULLDISK;
static	struct diskinfo *lastdisk = NULLDISK;
static	struct diskinfo *snip = NULLDISK;

#define	CPU_STAT(ksp, name)	(((kstat_named_t *)safe_kstat_data_lookup( \
				    (ksp), (name)))->value.ui64)
#define	DISK_DELTA(x)	(disk->new_kios.x - disk->old_kios.x)
#define	CPU_DELTA(x)	(CPU_STAT(&new_cpu_stats, (x)) - \
			    CPU_STAT(&old_cpu_stats, (x)))
#define	FSHIFT		8
#define	FSCALE		(1<<FSHIFT)

/*
 * Local Functions
 */
static	void	init_all(void);
static	void	init_disks(void);
static	void	cpu_stats_init(void);
static	void	load_ave_init(void);
static	void	nfs_init(void);
static	void	conskbd_init(void);
static	void	consms_init(void);
static	int	diskinfo_load(void);
static	int	cpu_stats_load(void);
static	int	load_ave_load(void);
static	int	nfs_load(void);
static	void	fail(char *, ...);
static	void	safe_zalloc(void **, int, int);
static	void	*safe_kstat_data_lookup(kstat_t *, char *);
static	int	kscmp(kstat_t *, kstat_t *);
static	void	keep_activity_data(activity_data_t **, activity_data_t **,
					int *, int, hrtime_t);
static	int	check_activity(activity_data_t *, int, hrtime_t *, int);
static	void	kstat_copy(kstat_t *, kstat_t *, int);

void
sysstat_init()
{
	info->pd_ttychars_sum = 0;
	info->pd_loadaverage = 0;
	info->pd_diskreads_sum = 0;
	info->pd_nfsreqs_sum = 0;

	if ((kc = kstat_open()) == NULL) {
		fail("kstat_open(): can't open /dev/kstat");
	}
	init_all();
}

static void
init_all(void)
{
	char *msg = "kstat_read(): can't read kstat";

	init_disks();
	if (diskinfo_load() != 0) {
		fail(msg);
	}

	cpu_stats_init();
	if (cpu_stats_load() != 0) {
		fail(msg);
	}

	load_ave_init();
	last_load_ave_change = gethrtime();
	if (load_ave_load() != 0) {
		fail(msg);
	}

	nfs_init();
	if (nfs_load() != 0) {
		fail(msg);
	}
	conskbd_init();
	consms_init();
}

int
last_disk_activity(hrtime_t *hr_now, int threshold)
{
	return (check_activity(disk_act_start, info->pd_diskreads_sum, hr_now,
			threshold));
}

int
last_tty_activity(hrtime_t *hr_now, int threshold)
{
	return (check_activity(tty_act_start, info->pd_ttychars_sum, hr_now,
			threshold));
}

int
last_load_ave_activity(hrtime_t *hr_now)
{
	return ((*hr_now - last_load_ave_change) / NANOSEC);
}

int
last_nfs_activity(hrtime_t *hr_now, int threshold)
{
	return (check_activity(nfs_act_start, info->pd_nfsreqs_sum, hr_now,
			threshold));
}

static void
init_disks(void)
{
	struct diskinfo	*disk, *prevdisk, *comp;
	kstat_t		*ksp;

	disk = &zerodisk;

	/*
	 * Patch the snip in the diskinfo list (see below)
	 */
	if (snip) {
		lastdisk->next = snip;
	}

	for (ksp = kc->kc_chain; ksp; ksp = ksp->ks_next) {
		if (ksp->ks_type != KSTAT_TYPE_IO ||
				strcmp(ksp->ks_class, "disk") != 0) {
			continue;
		}
		prevdisk = disk;
		if (disk->next) {
			disk = disk->next;
		} else {
			safe_zalloc((void **)&disk->next,
				sizeof (struct diskinfo), 0);
			disk = disk->next;
			disk->next = NULLDISK;
		}
		disk->ks = ksp;
		(void *) memset((void *)&disk->new_kios, 0,
			sizeof (kstat_io_t));
		disk->new_kios.wlastupdate = disk->ks->ks_crtime;
		disk->new_kios.rlastupdate = disk->ks->ks_crtime;

		/*
		 * Insertion sort on (ks_module, ks_instance, ks_name)
		 */
		comp = &zerodisk;
		while (kscmp(disk->ks, comp->next->ks) > 0) {
			comp = comp->next;
		}
		if (prevdisk != comp) {
			prevdisk->next = disk->next;
			disk->next = comp->next;
			comp->next = disk;
			disk = prevdisk;
		}
	}
	/*
	 * Put a snip in the linked list of diskinfos.  The idea:
	 * If there was a state change such that now there are fewer
	 * disks, we snip the list and retain the tail, rather than
	 * freeing it.  At the next state change, we clip the tail back on.
	 * This prevents a lot of malloc/free activity, and it's simpler.
	 */
	lastdisk = disk;
	snip = disk->next;
	disk->next = NULLDISK;

	firstdisk = zerodisk.next;
}

static int
diskinfo_load(void)
{
	struct diskinfo *disk;

	for (disk = firstdisk; disk; disk = disk->next) {
		disk->old_kios = disk->new_kios;
		if (kstat_read(kc, disk->ks,
				(void *)&disk->new_kios) == -1) {
			return (1);
		}
	}

	return (0);
}

int
check_disks(hrtime_t *hr_now, int threshold)
{
	struct diskinfo *disk;
	int		delta = 0;
	hrtime_t	time = 0;

	while (kstat_chain_update(kc) || diskinfo_load()) {
		init_all();
	}
	for (disk = firstdisk; disk; disk = disk->next) {
		if (time == 0) {
			time = disk->new_kios.wlastupdate;
		}
		delta += DISK_DELTA(reads);
		if (DISK_DELTA(reads) > 0) {
			time = MAX(time, disk->new_kios.wlastupdate);
		}
	}
	keep_activity_data(&disk_act_start, &disk_act_end,
			&info->pd_diskreads_sum, delta, time);
#ifdef DEBUG
	(void) printf("    Disk reads = %d\n", delta);
#endif
	return (check_activity(disk_act_start, info->pd_diskreads_sum, hr_now,
			threshold));
}

static void
cpu_stats_init(void)
{
	kstat_t	*ksp;

	ncpus = 0;
	for (ksp = kc->kc_chain; ksp; ksp = ksp->ks_next) {
		if (strcmp(ksp->ks_module, "cpu") == 0 &&
		    strcmp(ksp->ks_name, "sys") == 0)
			ncpus++;
	}

	safe_zalloc((void **)&cpu_stats_list, ncpus * sizeof (*cpu_stats_list),
	    1);

	ncpus = 0;
	for (ksp = kc->kc_chain; ksp; ksp = ksp->ks_next) {
		if (strcmp(ksp->ks_module, "cpu") == 0 &&
		    strcmp(ksp->ks_name, "sys") == 0 &&
		    kstat_read(kc, ksp, NULL) != -1)
			cpu_stats_list[ncpus++] = ksp;
	}

	if (ncpus == 0)
		fail("can't find any cpu statistics");
}

static int
cpu_stats_load(void)
{
	int		i, j;
	kstat_named_t	*nkp, *tkp;

	tty_snaptime = 0;
	kstat_copy(&new_cpu_stats, &old_cpu_stats, 1);

	/*
	 * Sum across all cpus
	 */
	for (i = 0; i < ncpus; i++) {
		if (kstat_read(kc, cpu_stats_list[i], NULL) == -1)
			return (1);

		if (i == 0) {
			kstat_copy(cpu_stats_list[i], &new_cpu_stats, 1);
			continue;
		} else {
			/*
			 * Other CPUs' statistics are accumulated in
			 * new_cpu_stats, initialized at the first iteration of
			 * the loop.
			 */
			nkp = (kstat_named_t *)new_cpu_stats.ks_data;
			tkp = (kstat_named_t *)cpu_stats_list[i]->ks_data;
			for (j = 0; j < cpu_stats_list[i]->ks_ndata; j++)
				(nkp++)->value.ui64 += (tkp++)->value.ui64;
			tty_snaptime = MAX(tty_snaptime,
			    cpu_stats_list[i]->ks_snaptime);
		}
	}

	return (0);
}

int
check_tty(hrtime_t *hr_now, int threshold)
{
	int	delta;

	while (kstat_chain_update(kc) || cpu_stats_load()) {
		init_all();
	}
	delta = CPU_DELTA("rawch") + CPU_DELTA("outch");
	keep_activity_data(&tty_act_start, &tty_act_end,
			&info->pd_ttychars_sum, delta, tty_snaptime);
#ifdef DEBUG
	(void) printf("    Tty chars = %d\n", delta);
#endif
	return (check_activity(tty_act_start, info->pd_ttychars_sum, hr_now,
			threshold));
}

static void
load_ave_init(void)
{
	if ((load_ave_ksp = kstat_lookup(kc, "unix", 0, "system_misc")) ==
			NULL) {
		fail("kstat_lookup('unix', 0, 'system_misc') failed");
	}
}

static int
load_ave_load(void)
{
	if (kstat_read(kc, load_ave_ksp, NULL) == -1) {
		return (1);
	}
	load_ave = ((kstat_named_t *)safe_kstat_data_lookup(
		load_ave_ksp, "avenrun_1min"))->value.l;

	return (0);
}

int
check_load_ave(hrtime_t *hr_now, float threshold)
{
	while (kstat_chain_update(kc) || load_ave_load()) {
		init_all();
	}
	info->pd_loadaverage = (double)load_ave / FSCALE;
	if (info->pd_loadaverage > threshold) {
		last_load_ave_change = load_ave_ksp->ks_snaptime;
	}
#ifdef DEBUG
	(void) printf("    Load average = %f\n", ((double)load_ave / FSCALE));
#endif
	return ((*hr_now - last_load_ave_change) / NANOSEC);
}

static void
nfs_init(void)
{
	nfs_client2_kstat = kstat_lookup(kc, "nfs", 0, "rfsreqcnt_v2");
	nfs_client3_kstat = kstat_lookup(kc, "nfs", 0, "rfsreqcnt_v3");
	nfs_server2_kstat = kstat_lookup(kc, "nfs", 0, "rfsproccnt_v2");
	nfs_server3_kstat = kstat_lookup(kc, "nfs", 0, "rfsproccnt_v3");
}

static int
nfs_load(void)
{
	kstat_named_t	*kstat_ptr;
	int		index;
	uint64_t	total_calls = 0;
	uint64_t	getattr_calls = 0;
	uint64_t	null_calls = 0;
	uint64_t	access_calls = 0;

	if (!nfs_client2_kstat && !nfs_client3_kstat && !nfs_server2_kstat &&
			!nfs_server3_kstat) {
		return (0);
	}

	/*
	 * NFS client "getattr", NFS3 client "access", and NFS server "null"
	 * requests are excluded from consideration.
	 */
	if (nfs_client2_kstat) {
		if (kstat_read(kc, nfs_client2_kstat, NULL) == -1) {
			return (1);
		}
		kstat_ptr = KSTAT_NAMED_PTR(nfs_client2_kstat);
		for (index = 0; index < nfs_client2_kstat->ks_ndata; index++) {
			total_calls += kstat_ptr[index].value.ui64;
		}
		getattr_calls =
			((kstat_named_t *)safe_kstat_data_lookup(
			nfs_client2_kstat, "getattr"))->value.ui64;
	}

	if (nfs_client3_kstat) {
		if (kstat_read(kc, nfs_client3_kstat, NULL) == -1) {
			return (1);
		}
		kstat_ptr = KSTAT_NAMED_PTR(nfs_client3_kstat);
		for (index = 0; index < nfs_client3_kstat->ks_ndata; index++) {
			total_calls += kstat_ptr[index].value.ui64;
		}
		getattr_calls +=
			((kstat_named_t *)safe_kstat_data_lookup(
			nfs_client3_kstat, "getattr"))->value.ui64;
		access_calls =
			((kstat_named_t *)safe_kstat_data_lookup(
			nfs_client3_kstat, "access"))->value.ui64;
	}

	if (nfs_server2_kstat) {
		if (kstat_read(kc, nfs_server2_kstat, NULL) == -1) {
			return (1);
		}
		kstat_ptr = KSTAT_NAMED_PTR(nfs_server2_kstat);
		for (index = 0; index < nfs_server2_kstat->ks_ndata; index++) {
			total_calls += kstat_ptr[index].value.ui64;
		}
		null_calls =
			((kstat_named_t *)safe_kstat_data_lookup(
			nfs_server2_kstat, "null"))->value.ui64;
	}

	if (nfs_server3_kstat) {
		if (kstat_read(kc, nfs_server3_kstat, NULL) == -1) {
			return (1);
		}
		kstat_ptr = KSTAT_NAMED_PTR(nfs_server3_kstat);
		for (index = 0; index < nfs_server3_kstat->ks_ndata; index++) {
			total_calls += kstat_ptr[index].value.ui64;
		}
		null_calls +=
			((kstat_named_t *)safe_kstat_data_lookup(
			nfs_server3_kstat, "null"))->value.ui64;
	}

	old_nfs_calls = new_nfs_calls;
	new_nfs_calls = total_calls -
		(getattr_calls + access_calls + null_calls);

	return (0);
}

int
check_nfs(hrtime_t *hr_now, int threshold)
{
	int		delta;
	hrtime_t	time = 0;

	while (kstat_chain_update(kc) || nfs_load()) {
		init_all();
	}

	if (!nfs_client2_kstat && !nfs_client3_kstat && !nfs_server2_kstat &&
			!nfs_server3_kstat) {
		return (0);
	}

	if (nfs_client2_kstat) {
		time = MAX(time, nfs_client2_kstat->ks_snaptime);
	}
	if (nfs_client3_kstat) {
		time = MAX(time, nfs_client3_kstat->ks_snaptime);
	}
	if (nfs_server2_kstat) {
		time = MAX(time, nfs_server2_kstat->ks_snaptime);
	}
	if (nfs_server3_kstat) {
		time = MAX(time, nfs_server3_kstat->ks_snaptime);
	}
	delta = (int)(new_nfs_calls - old_nfs_calls);
	keep_activity_data(&nfs_act_start, &nfs_act_end,
			&info->pd_nfsreqs_sum, delta, time);
#ifdef DEBUG
	(void) printf("    NFS requests = %d\n", delta);
#endif
	return (check_activity(nfs_act_start, info->pd_nfsreqs_sum, hr_now,
			threshold));
}

static void
conskbd_init(void)
{
	conskbd_ksp = kstat_lookup(kc, "conskbd", 0, "activity");
}

/*
 * Return the number of seconds since the last keystroke on console keyboard.
 * Caller responsible for error reporting.
 */
long
conskbd_idle_time(void)
{
	void *p;

	if (conskbd_ksp == NULL || kstat_read(kc, conskbd_ksp, NULL) == -1 ||
	    (p = kstat_data_lookup(conskbd_ksp, "idle_sec")) == NULL)
		return ((time_t)-1);

	return (((kstat_named_t *)p)->value.l);
}

static void
consms_init(void)
{
	consms_ksp = kstat_lookup(kc, "consms", 0, "activity");
}

/*
 * Return the number of seconds since the most recent action (movement or
 * click) of the console mouse.  Caller responsible for error reporting.
 */
long
consms_idle_time(void)
{
	void *p;

	if (consms_ksp == NULL || kstat_read(kc, consms_ksp, NULL) == -1 ||
	    (p = kstat_data_lookup(consms_ksp, "idle_sec")) == NULL)
		return ((time_t)-1);

	return (((kstat_named_t *)p)->value.l);
}

static void
fail(char *fmt, ...)
{
	char new_fmt[256];
	const char *fmtptr = new_fmt;
	va_list	args;
	size_t len;

	len = sizeof (new_fmt);
	va_start(args, fmt);
	if (snprintf(new_fmt, len, "powerd: %s", fmt) > len)
		syslog(LOG_ERR, "powerd: syslog message too large");
	else
		vsyslog(LOG_ERR, fmtptr, args);
	va_end(args);

	thr_exit((void *) 0);
}

static void
safe_zalloc(void **ptr, int size, int free_first)
{
	if (free_first && *ptr != NULL) {
		free(*ptr);
	}
	if ((*ptr = (void *) malloc(size)) == NULL) {
		fail("malloc failed");
	}
	(void *) memset(*ptr, 0, size);
}

static void *
safe_kstat_data_lookup(kstat_t *ksp, char *name)
{
	void *fp = kstat_data_lookup(ksp, name);

	if (fp == NULL) {
		fail("kstat_data_lookup('%s', '%s') failed",
			ksp->ks_name, name);
	}
	return (fp);
}

static int
kscmp(kstat_t *ks1, kstat_t *ks2)
{
	int cmp;

	cmp = strcmp(ks1->ks_module, ks2->ks_module);
	if (cmp != 0) {
		return (cmp);
	}
	cmp = ks1->ks_instance - ks2->ks_instance;
	if (cmp != 0) {
		return (cmp);
	}
	return (strcmp(ks1->ks_name, ks2->ks_name));
}

static void
keep_activity_data(activity_data_t **act_start, activity_data_t **act_end,
			int *delta_sum, int delta, hrtime_t time)
{
	activity_data_t *node = NULLACTIVITY;
	hrtime_t	hr_now;
	int		idle_time = info->pd_idle_time * 60;

	/*
	 * Add new nodes to the beginning of the list.
	 */
	safe_zalloc((void **)&node, sizeof (activity_data_t), 0);
	node->activity_delta = delta;
	*delta_sum += delta;
	node->snaptime = time;
	node->next = *act_start;
	if (*act_start == NULLACTIVITY) {
		*act_end = node;
	} else {
		(*act_start)->prev = node;
	}
	*act_start = node;

	/*
	 * Remove nodes that are time-stamped later than the idle time.
	 */
	hr_now = gethrtime();
	node = *act_end;
	while ((int)((hr_now - node->snaptime) / NANOSEC) > idle_time &&
			node->prev != NULLACTIVITY) {
		*delta_sum -= node->activity_delta;
		*act_end = node->prev;
		(*act_end)->next = NULLACTIVITY;
		free(node);
		node = *act_end;
	}
}

static int
check_activity(activity_data_t *act_start, int delta_sum, hrtime_t *time,
			int thold)
{
	activity_data_t	*node;
	int		sum = 0;
	int		idle_time = info->pd_idle_time * 60;

	/*
	 * No need to walk the list if the sum of the deltas are not greater
	 * than the threshold value.
	 */
	if (delta_sum <= thold) {
		return (idle_time);
	}

	/*
	 * Walk through the list and add up the activity deltas.  When the
	 * sum is greater than the threshold value, difference of current
	 * time and the snaptime of that node will give us the idle time.
	 */
	node = act_start;
	while (node->next != NULLACTIVITY) {
		sum += node->activity_delta;
		if (sum > thold) {
			return ((*time - node->snaptime) / NANOSEC);
		}
		node = node->next;
	}
	sum += node->activity_delta;
	if (sum > thold) {
		return ((*time - node->snaptime) / NANOSEC);
	}

	return (idle_time);
}

static void
kstat_copy(kstat_t *src, kstat_t *dst, int fr)
{
	if (fr)
		free(dst->ks_data);

	*dst = *src;
	if (src->ks_data != NULL) {
		safe_zalloc(&dst->ks_data, src->ks_data_size, 0);
		(void) memcpy(dst->ks_data, src->ks_data, src->ks_data_size);
	} else {
		dst->ks_data = NULL;
		dst->ks_data_size = 0;
	}
}

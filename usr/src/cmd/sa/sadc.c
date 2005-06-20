/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * sadc.c writes system activity binary data to a file or stdout.
 *
 * Usage: sadc [t n] [file]
 *
 * if t and n are not specified, it writes a dummy record to data file. This
 * usage is particularly used at system booting.  If t and n are specified, it
 * writes system data n times to file every t seconds.  In both cases, if file
 * is not specified, it writes data to stdout.
 */

#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/var.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <kstat.h>
#include <memory.h>
#include <nlist.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <strings.h>

#include "sa.h"

#define	MAX(x1, x2)	((x1) >= (x2) ? (x1) : (x2))

static	kstat_ctl_t	*kc;		/* libkstat cookie */
static	int	ncpus;
static	int	oncpus;
static	kstat_t	**cpu_stat_list = NULL;
static	kstat_t	**ocpu_stat_list = NULL;
static	int	ncaches;
static	kstat_t	**kmem_cache_list = NULL;

static	kstat_t	*sysinfo_ksp, *vminfo_ksp, *var_ksp;
static	kstat_t *system_misc_ksp, *ufs_inode_ksp, *kmem_oversize_ksp;
static	kstat_t *file_cache_ksp;
static	kstat_named_t *ufs_inode_size_knp, *nproc_knp;
static	kstat_named_t *file_total_knp, *file_avail_knp;
static	kstat_named_t *oversize_alloc_knp, *oversize_fail_knp;
static	int slab_create_index, slab_destroy_index, slab_size_index;
static	int buf_size_index, buf_avail_index, alloc_fail_index;

static	struct	iodevinfo zeroiodev = { NULL, NULL };
static	struct	iodevinfo *firstiodev = NULL;
static	struct	iodevinfo *lastiodev = NULL;
static	struct	iodevinfo *snip = NULL;
static	ulong_t	niodevs;

static	void	all_stat_init(void);
static	int	all_stat_load(void);
static	void	fail(int, char *, ...);
static	void	safe_zalloc(void **, int, int);
static	kid_t	safe_kstat_read(kstat_ctl_t *, kstat_t *, void *);
static	kstat_t	*safe_kstat_lookup(kstat_ctl_t *, char *, int, char *);
static	void	*safe_kstat_data_lookup(kstat_t *, char *);
static	int	safe_kstat_data_index(kstat_t *, char *);
static	void	init_iodevs(void);
static	int	iodevinfo_load(void);
static	int	kstat_copy(const kstat_t *, kstat_t *);
static	void	diff_two_arrays(kstat_t ** const [], size_t, size_t,
    kstat_t ** const []);
static	void	compute_cpu_stat_adj(void);

static	char	*cmdname = "sadc";

static	struct var var;

static	struct sa d;
static	int64_t	cpu_stat_adj[CPU_STATES] = {0};

static	long	ninode;

int
main(int argc, char *argv[])
{
	int ct;
	unsigned ti;
	int fp;
	time_t min;
	struct stat buf;
	char *fname;
	struct iodevinfo *iodev;
	off_t flength;

	ct = argc >= 3? atoi(argv[2]): 0;
	min = time((time_t *)0);
	ti = argc >= 3? atoi(argv[1]): 0;

	if ((kc = kstat_open()) == NULL)
		fail(1, "kstat_open(): can't open /dev/kstat");
	all_stat_init();
	init_iodevs();

	if (argc == 3 || argc == 1) {
		/*
		 * no data file is specified, direct data to stdout.
		 */
		fp = 1;
	} else {
		struct flock lock;

		fname = (argc == 2) ? argv[1] : argv[3];
		/*
		 * Open or Create a data file. If the file doesn't exist, then
		 * it will be created.
		 */
		if ((fp = open(fname, O_WRONLY | O_APPEND | O_CREAT, 0644))
		    == -1)
			fail(1, "can't open data file");
		/*
		 * Lock the entire data file to prevent data corruption
		 */
		lock.l_type = F_WRLCK;
		lock.l_whence = SEEK_SET;
		lock.l_start = 0;
		lock.l_len = 0;
		if (fcntl(fp, F_SETLK, &lock) == -1)
			fail(1, "can't lock data file");
		/*
		 * Get data file statistics for use in determining whether
		 * truncation required and where rollback recovery should
		 * be applied.
		 */
		if (fstat(fp, &buf) == -1)
			fail(1, "can't get data file information");
		/*
		 * If the data file was opened and is too old, truncate it
		 */
		if (min - buf.st_mtime > 86400)
			if (ftruncate(fp, 0) == -1)
				fail(1, "can't truncate data file");
		/*
		 * Remember filesize for rollback on error (bug #1223549)
		 */
		flength = buf.st_size;
	}

	memset(&d, 0, sizeof (d));

	/*
	 * If n == 0, write the additional dummy record.
	 */
	if (ct == 0) {
		d.valid = 0;
		d.ts = min;
		d.niodevs = niodevs;

		if (write(fp, &d, sizeof (struct sa)) != sizeof (struct sa))
			ftruncate(fp, flength), fail(1, "write failed");

		for (iodev = firstiodev; iodev; iodev = iodev->next) {
			if (write(fp, iodev, sizeof (struct iodevinfo)) !=
			    sizeof (struct iodevinfo))
				ftruncate(fp, flength), fail(1, "write failed");
		}
	}

	for (;;) {
		do {
			(void) kstat_chain_update(kc);
			all_stat_init();
			init_iodevs();
		} while (all_stat_load() || iodevinfo_load());

		d.ts = time((time_t *)0);
		d.valid = 1;
		d.niodevs = niodevs;

		if (write(fp, &d, sizeof (struct sa)) != sizeof (struct sa))
			ftruncate(fp, flength), fail(1, "write failed");

		for (iodev = firstiodev; iodev; iodev = iodev->next) {
			if (write(fp, iodev, sizeof (struct iodevinfo)) !=
			    sizeof (struct iodevinfo))
				ftruncate(fp, flength), fail(1, "write failed");
		}
		if (--ct > 0) {
			sleep(ti);
		} else {
			close(fp);
			return (0);
		}
	}

	/*NOTREACHED*/
}

/*
 * Get various KIDs for subsequent all_stat_load operations.
 */

static void
all_stat_init(void)
{
	kstat_t *ksp;

	/*
	 * Initialize global statistics
	 */

	sysinfo_ksp	= safe_kstat_lookup(kc, "unix", 0, "sysinfo");
	vminfo_ksp	= safe_kstat_lookup(kc, "unix", 0, "vminfo");
	kmem_oversize_ksp = safe_kstat_lookup(kc, "vmem", -1, "kmem_oversize");
	var_ksp		= safe_kstat_lookup(kc, "unix", 0, "var");
	system_misc_ksp	= safe_kstat_lookup(kc, "unix", 0, "system_misc");
	file_cache_ksp	= safe_kstat_lookup(kc, "unix", 0, "file_cache");
	ufs_inode_ksp	= kstat_lookup(kc, "ufs", 0, "inode_cache");

	safe_kstat_read(kc, system_misc_ksp, NULL);
	nproc_knp	= safe_kstat_data_lookup(system_misc_ksp, "nproc");

	safe_kstat_read(kc, file_cache_ksp, NULL);
	file_avail_knp = safe_kstat_data_lookup(file_cache_ksp, "buf_avail");
	file_total_knp = safe_kstat_data_lookup(file_cache_ksp, "buf_total");

	safe_kstat_read(kc, kmem_oversize_ksp, NULL);
	oversize_alloc_knp = safe_kstat_data_lookup(kmem_oversize_ksp,
	    "mem_total");
	oversize_fail_knp = safe_kstat_data_lookup(kmem_oversize_ksp, "fail");

	if (ufs_inode_ksp != NULL) {
		safe_kstat_read(kc, ufs_inode_ksp, NULL);
		ufs_inode_size_knp = safe_kstat_data_lookup(ufs_inode_ksp,
			"size");
		ninode = ((kstat_named_t *)
			safe_kstat_data_lookup(ufs_inode_ksp,
			"maxsize"))->value.l;
	}

	/*
	 * Load constant values now -- no need to reread each time
	 */

	safe_kstat_read(kc, var_ksp, (void *) &var);

	/*
	 * Initialize per-CPU and per-kmem-cache statistics
	 */

	ncpus = ncaches = 0;
	for (ksp = kc->kc_chain; ksp; ksp = ksp->ks_next) {
		if (strncmp(ksp->ks_name, "cpu_stat", 8) == 0)
			ncpus++;
		if (strcmp(ksp->ks_class, "kmem_cache") == 0)
			ncaches++;
	}

	safe_zalloc((void **)&cpu_stat_list, ncpus * sizeof (kstat_t *), 1);
	safe_zalloc((void **)&kmem_cache_list, ncaches * sizeof (kstat_t *), 1);

	ncpus = ncaches = 0;
	for (ksp = kc->kc_chain; ksp; ksp = ksp->ks_next) {
		if (strncmp(ksp->ks_name, "cpu_stat", 8) == 0 &&
		    kstat_read(kc, ksp, NULL) != -1)
			cpu_stat_list[ncpus++] = ksp;
		if (strcmp(ksp->ks_class, "kmem_cache") == 0 &&
		    kstat_read(kc, ksp, NULL) != -1)
			kmem_cache_list[ncaches++] = ksp;
	}

	if (ncpus == 0)
		fail(1, "can't find any cpu statistics");

	if (ncaches == 0)
		fail(1, "can't find any kmem_cache statistics");

	ksp = kmem_cache_list[0];
	safe_kstat_read(kc, ksp, NULL);
	buf_size_index = safe_kstat_data_index(ksp, "buf_size");
	slab_create_index = safe_kstat_data_index(ksp, "slab_create");
	slab_destroy_index = safe_kstat_data_index(ksp, "slab_destroy");
	slab_size_index = safe_kstat_data_index(ksp, "slab_size");
	buf_avail_index = safe_kstat_data_index(ksp, "buf_avail");
	alloc_fail_index = safe_kstat_data_index(ksp, "alloc_fail");
}

/*
 * load statistics, summing across CPUs where needed
 */

static int
all_stat_load(void)
{
	int i, j;
	cpu_stat_t cs;
	ulong_t *np, *tp;
	uint64_t cpu_tick[4] = {0, 0, 0, 0};

	memset(&d, 0, sizeof (d));

	/*
	 * Global statistics
	 */

	safe_kstat_read(kc, sysinfo_ksp, (void *) &d.si);
	safe_kstat_read(kc, vminfo_ksp, (void *) &d.vmi);
	safe_kstat_read(kc, system_misc_ksp, NULL);
	safe_kstat_read(kc, file_cache_ksp, NULL);

	if (ufs_inode_ksp != NULL) {
		safe_kstat_read(kc, ufs_inode_ksp, NULL);
		d.szinode = ufs_inode_size_knp->value.ul;
	}

	d.szfile = file_total_knp->value.ui64 - file_avail_knp->value.ui64;
	d.szproc = nproc_knp->value.ul;

	d.mszinode = (ninode > d.szinode) ? ninode : d.szinode;
	d.mszfile = d.szfile;
	d.mszproc = var.v_proc;

	/*
	 * Per-CPU statistics.
	 */

	for (i = 0; i < ncpus; i++) {
		if (kstat_read(kc, cpu_stat_list[i], (void *) &cs) == -1)
			return (1);

		np = (ulong_t *)&d.csi;
		tp = (ulong_t *)&cs.cpu_sysinfo;

		/*
		 * Accumulate cpu ticks for CPU_IDLE, CPU_USER, CPU_KERNEL and
		 * CPU_WAIT with respect to each of the cpus.
		 */
		for (j = 0; j < CPU_STATES; j++)
			cpu_tick[j] += tp[j];

		for (j = 0; j < sizeof (cpu_sysinfo_t); j += sizeof (ulong_t))
			*np++ += *tp++;
		np = (ulong_t *)&d.cvmi;
		tp = (ulong_t *)&cs.cpu_vminfo;
		for (j = 0; j < sizeof (cpu_vminfo_t); j += sizeof (ulong_t))
			*np++ += *tp++;
	}

	/*
	 * Per-cache kmem statistics.
	 */

	for (i = 0; i < ncaches; i++) {
		kstat_named_t *knp;
		u_longlong_t slab_create, slab_destroy, slab_size, mem_total;
		u_longlong_t buf_size, buf_avail, alloc_fail;
		int kmi_index;

		if (kstat_read(kc, kmem_cache_list[i], NULL) == -1)
			return (1);
		knp = kmem_cache_list[i]->ks_data;
		slab_create	= knp[slab_create_index].value.ui64;
		slab_destroy	= knp[slab_destroy_index].value.ui64;
		slab_size	= knp[slab_size_index].value.ui64;
		buf_size	= knp[buf_size_index].value.ui64;
		buf_avail	= knp[buf_avail_index].value.ui64;
		alloc_fail	= knp[alloc_fail_index].value.ui64;
		if (buf_size <= 256)
			kmi_index = KMEM_SMALL;
		else
			kmi_index = KMEM_LARGE;
		mem_total = (slab_create - slab_destroy) * slab_size;

		d.kmi.km_mem[kmi_index] += (ulong_t)mem_total;
		d.kmi.km_alloc[kmi_index] +=
			(ulong_t)mem_total - buf_size * buf_avail;
		d.kmi.km_fail[kmi_index] += (ulong_t)alloc_fail;
	}

	safe_kstat_read(kc, kmem_oversize_ksp, NULL);

	d.kmi.km_alloc[KMEM_OSIZE] = d.kmi.km_mem[KMEM_OSIZE] =
		oversize_alloc_knp->value.ui64;
	d.kmi.km_fail[KMEM_OSIZE] = oversize_fail_knp->value.ui64;

	/*
	 * Adjust CPU statistics so the delta calculations in sar will
	 * be correct when facing changes to the set of online CPUs.
	 */
	compute_cpu_stat_adj();
	for (i = 0; i < CPU_STATES; i++)
		d.csi.cpu[i] = (cpu_tick[i] + cpu_stat_adj[i]) / ncpus;

	return (0);
}

static void
fail(int do_perror, char *message, ...)
{
	va_list args;

	va_start(args, message);
	fprintf(stderr, "%s: ", cmdname);
	vfprintf(stderr, message, args);
	va_end(args);
	if (do_perror)
		fprintf(stderr, ": %s", strerror(errno));
	fprintf(stderr, "\n");
	exit(2);
}

static void
safe_zalloc(void **ptr, int size, int free_first)
{
	if (free_first && *ptr != NULL)
		free(*ptr);
	if ((*ptr = malloc(size)) == NULL)
		fail(1, "malloc failed");
	memset(*ptr, 0, size);
}

static kid_t
safe_kstat_read(kstat_ctl_t *kc, kstat_t *ksp, void *data)
{
	kid_t kstat_chain_id = kstat_read(kc, ksp, data);

	if (kstat_chain_id == -1)
		fail(1, "kstat_read(%x, '%s') failed", kc, ksp->ks_name);
	return (kstat_chain_id);
}

static kstat_t *
safe_kstat_lookup(kstat_ctl_t *kc, char *ks_module, int ks_instance,
	char *ks_name)
{
	kstat_t *ksp = kstat_lookup(kc, ks_module, ks_instance, ks_name);

	if (ksp == NULL)
		fail(0, "kstat_lookup('%s', %d, '%s') failed",
			ks_module == NULL ? "" : ks_module,
			ks_instance,
			ks_name == NULL ? "" : ks_name);
	return (ksp);
}

static void *
safe_kstat_data_lookup(kstat_t *ksp, char *name)
{
	void *fp = kstat_data_lookup(ksp, name);

	if (fp == NULL)
		fail(0, "kstat_data_lookup('%s', '%s') failed",
			ksp->ks_name, name);
	return (fp);
}

static int
safe_kstat_data_index(kstat_t *ksp, char *name)
{
	return ((int)((char *)safe_kstat_data_lookup(ksp, name) -
		(char *)ksp->ks_data) / (ksp->ks_data_size / ksp->ks_ndata));
}

static int
kscmp(kstat_t *ks1, kstat_t *ks2)
{
	int cmp;

	cmp = strcmp(ks1->ks_module, ks2->ks_module);
	if (cmp != 0)
		return (cmp);
	cmp = ks1->ks_instance - ks2->ks_instance;
	if (cmp != 0)
		return (cmp);
	return (strcmp(ks1->ks_name, ks2->ks_name));
}

static void
init_iodevs(void)
{
	struct iodevinfo *iodev, *previodev, *comp;
	kstat_t *ksp;

	iodev = &zeroiodev;
	niodevs = 0;

	/*
	 * Patch the snip in the iodevinfo list (see below)
	 */
	if (snip)
		lastiodev->next = snip;

	for (ksp = kc->kc_chain; ksp; ksp = ksp->ks_next) {

		if (ksp->ks_type != KSTAT_TYPE_IO)
			continue;
		previodev = iodev;
		if (iodev->next)
			iodev = iodev->next;
		else {
			safe_zalloc((void **) &iodev->next,
				sizeof (struct iodevinfo), 0);
			iodev = iodev->next;
			iodev->next = NULL;
		}
		iodev->ksp = ksp;
		iodev->ks = *ksp;
		memset((void *)&iodev->kios, 0, sizeof (kstat_io_t));
		iodev->kios.wlastupdate = iodev->ks.ks_crtime;
		iodev->kios.rlastupdate = iodev->ks.ks_crtime;

		/*
		 * Insertion sort on (ks_module, ks_instance, ks_name)
		 */
		comp = &zeroiodev;
		while (kscmp(&iodev->ks, &comp->next->ks) > 0)
			comp = comp->next;
		if (previodev != comp) {
			previodev->next = iodev->next;
			iodev->next = comp->next;
			comp->next = iodev;
			iodev = previodev;
		}
		niodevs++;
	}
	/*
	 * Put a snip in the linked list of iodevinfos.  The idea:
	 * If there was a state change such that now there are fewer
	 * iodevs, we snip the list and retain the tail, rather than
	 * freeing it.  At the next state change, we clip the tail back on.
	 * This prevents a lot of malloc/free activity, and it's simpler.
	 */
	lastiodev = iodev;
	snip = iodev->next;
	iodev->next = NULL;

	firstiodev = zeroiodev.next;
}

static int
iodevinfo_load(void)
{
	struct iodevinfo *iodev;

	for (iodev = firstiodev; iodev; iodev = iodev->next) {
		if (kstat_read(kc, iodev->ksp, (void *) &iodev->kios) == -1)
			return (1);
	}
	return (0);
}

static int
kstat_copy(const kstat_t *src, kstat_t *dst)
{
	*dst = *src;

	if (src->ks_data != NULL) {
		if ((dst->ks_data = malloc(src->ks_data_size)) == NULL)
			return (-1);
		bcopy(src->ks_data, dst->ks_data, src->ks_data_size);
	} else {
		dst->ks_data = NULL;
		dst->ks_data_size = 0;
	}
	return (0);
}

/*
 * Determine what is different between two sets of kstats; s[0] and s[1]
 * are arrays of kstats of size ns0 and ns1, respectively, and sorted by
 * instance number.  u[0] and u[1] are two arrays which must be
 * caller-zallocated; each must be of size MAX(ns0, ns1).  When the
 * function terminates, u[0] contains all s[0]-unique items and u[1]
 * contains all s[1]-unique items.  Any unused entries in u[0] and u[1]
 * are left NULL.
 */
static void
diff_two_arrays(kstat_t ** const s[], size_t ns0, size_t ns1,
    kstat_t ** const u[])
{
	kstat_t **s0p = s[0], **s1p = s[1];
	kstat_t **u0p = u[0], **u1p = u[1];
	int i = 0, j = 0;

	while (i < ns0 && j < ns1) {
		if ((*s0p)->ks_instance == (*s1p)->ks_instance) {
			if ((*s0p)->ks_kid != (*s1p)->ks_kid) {
				/*
				 * The instance is the same, but this
				 * CPU has been offline during the
				 * interval, so we consider *u0p to
				 * be s0p-unique, and similarly for
				 * *u1p.
				 */
				*(u0p++) = *s0p;
				*(u1p++) = *s1p;
			}
			s0p++;
			i++;
			s1p++;
			j++;
		} else if ((*s0p)->ks_instance < (*s1p)->ks_instance) {
			*(u0p++) = *(s0p++);
			i++;
		} else {
			*(u1p++) = *(s1p++);
			j++;
		}
	}

	while (i < ns0) {
		*(u0p++) = *(s0p++);
		i++;
	}
	while (j < ns1) {
		*(u1p++) = *(s1p++);
		j++;
	}
}

static int
cpuid_compare(const void *p1, const void *p2)
{
	return ((*(kstat_t **)p1)->ks_instance -
	    (*(kstat_t **)p2)->ks_instance);
}

/*
 * Identify those CPUs which were not present for the whole interval so
 * their statistics can be removed from the aggregate.
 */
static void
compute_cpu_stat_adj(void)
{
	int i, j;

	if (ocpu_stat_list) {
		kstat_t **s[2];
		kstat_t **inarray[2];
		int max_cpus = MAX(ncpus, oncpus);

		qsort(cpu_stat_list, ncpus, sizeof (*cpu_stat_list),
		    cpuid_compare);
		qsort(ocpu_stat_list, oncpus, sizeof (*ocpu_stat_list),
		    cpuid_compare);

		s[0] = ocpu_stat_list;
		s[1] = cpu_stat_list;

		safe_zalloc((void *)&inarray[0], sizeof (**inarray) * max_cpus,
		    0);
		safe_zalloc((void *)&inarray[1], sizeof (**inarray) * max_cpus,
		    0);
		diff_two_arrays(s, oncpus, ncpus, inarray);

		for (i = 0; i < max_cpus; i++) {
			if (inarray[0][i])
				for (j = 0; j < CPU_STATES; j++)
					cpu_stat_adj[j] +=
					    ((cpu_stat_t *)inarray[0][i]
					    ->ks_data)->cpu_sysinfo.cpu[j];
			if (inarray[1][i])
				for (j = 0; j < CPU_STATES; j++)
					cpu_stat_adj[j] -=
					    ((cpu_stat_t *)inarray[1][i]
					    ->ks_data)->cpu_sysinfo.cpu[j];
		}

		free(inarray[0]);
		free(inarray[1]);
	}

	/*
	 * Preserve the last interval's CPU stats.
	 */
	if (cpu_stat_list) {
		for (i = 0; i < oncpus; i++)
			free(ocpu_stat_list[i]->ks_data);

		oncpus = ncpus;
		safe_zalloc((void **)&ocpu_stat_list, oncpus *
		    sizeof (*ocpu_stat_list), 1);
		for (i = 0; i < ncpus; i++) {
			safe_zalloc((void *)&ocpu_stat_list[i],
			    sizeof (*ocpu_stat_list[0]), 0);
			if (kstat_copy(cpu_stat_list[i], ocpu_stat_list[i]))
				fail(1, "kstat_copy() failed");
		}
	}
}

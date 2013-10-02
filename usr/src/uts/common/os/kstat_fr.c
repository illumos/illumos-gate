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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013, Joyent, Inc. All rights reserved.
 */

/*
 * Kernel statistics framework
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/vmsystm.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/vmem.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/kstat.h>
#include <sys/sysinfo.h>
#include <sys/cpuvar.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/dnlc.h>
#include <sys/var.h>
#include <sys/debug.h>
#include <sys/kobj.h>
#include <sys/avl.h>
#include <sys/pool_pset.h>
#include <sys/cpupart.h>
#include <sys/zone.h>
#include <sys/loadavg.h>
#include <vm/page.h>
#include <vm/anon.h>
#include <vm/seg_kmem.h>

/*
 * Global lock to protect the AVL trees and kstat_chain_id.
 */
static kmutex_t kstat_chain_lock;

/*
 * Every install/delete kstat bumps kstat_chain_id.  This is used by:
 *
 * (1)	/dev/kstat, to detect changes in the kstat chain across ioctls;
 *
 * (2)	kstat_create(), to assign a KID (kstat ID) to each new kstat.
 *	/dev/kstat uses the KID as a cookie for kstat lookups.
 *
 * We reserve the first two IDs because some kstats are created before
 * the well-known ones (kstat_headers = 0, kstat_types = 1).
 *
 * We also bump the kstat_chain_id if a zone is gaining or losing visibility
 * into a particular kstat, which is logically equivalent to a kstat being
 * installed/deleted.
 */

kid_t kstat_chain_id = 2;

/*
 * As far as zones are concerned, there are 3 types of kstat:
 *
 * 1) Those which have a well-known name, and which should return per-zone data
 * depending on which zone is doing the kstat_read().  sockfs:0:sock_unix_list
 * is an example of this type of kstat.
 *
 * 2) Those which should only be exported to a particular list of zones.
 * For example, in the case of nfs:*:mntinfo, we don't want zone A to be
 * able to see NFS mounts associated with zone B, while we want the
 * global zone to be able to see all mounts on the system.
 *
 * 3) Those that can be exported to all zones.  Most system-related
 * kstats fall within this category.
 *
 * An ekstat_t thus contains a list of kstats that the zone is to be
 * exported to.  The lookup of a name:instance:module thus translates to a
 * lookup of name:instance:module:myzone; if the kstat is not exported
 * to all zones, and does not have the caller's zoneid explicitly
 * enumerated in the list of zones to be exported to, it is the same as
 * if the kstat didn't exist.
 *
 * Writing to kstats is currently disallowed from within a non-global
 * zone, although this restriction could be removed in the future.
 */
typedef struct kstat_zone {
	zoneid_t zoneid;
	struct kstat_zone *next;
} kstat_zone_t;

/*
 * Extended kstat structure -- for internal use only.
 */
typedef struct ekstat {
	kstat_t		e_ks;		/* the kstat itself */
	size_t		e_size;		/* total allocation size */
	kthread_t	*e_owner;	/* thread holding this kstat */
	kcondvar_t	e_cv;		/* wait for owner == NULL */
	avl_node_t	e_avl_bykid;	/* AVL tree to sort by KID */
	avl_node_t	e_avl_byname;	/* AVL tree to sort by name */
	kstat_zone_t	e_zone;		/* zone to export stats to */
} ekstat_t;

static uint64_t kstat_initial[8192];
static void *kstat_initial_ptr = kstat_initial;
static size_t kstat_initial_avail = sizeof (kstat_initial);
static vmem_t *kstat_arena;

#define	KSTAT_ALIGN	(sizeof (uint64_t))

static avl_tree_t kstat_avl_bykid;
static avl_tree_t kstat_avl_byname;

/*
 * Various pointers we need to create kstats at boot time in kstat_init()
 */
extern	kstat_named_t	*segmapcnt_ptr;
extern	uint_t		segmapcnt_ndata;
extern	int		segmap_kstat_update(kstat_t *, int);
extern	kstat_named_t	*biostats_ptr;
extern	uint_t		biostats_ndata;
extern	kstat_named_t	*pollstats_ptr;
extern	uint_t		pollstats_ndata;

extern	int	vac;
extern	uint_t	nproc;
extern	time_t	boot_time;
extern	sysinfo_t	sysinfo;
extern	vminfo_t	vminfo;

struct {
	kstat_named_t ncpus;
	kstat_named_t lbolt;
	kstat_named_t deficit;
	kstat_named_t clk_intr;
	kstat_named_t vac;
	kstat_named_t nproc;
	kstat_named_t avenrun_1min;
	kstat_named_t avenrun_5min;
	kstat_named_t avenrun_15min;
	kstat_named_t boot_time;
} system_misc_kstat = {
	{ "ncpus",		KSTAT_DATA_UINT32 },
	{ "lbolt",		KSTAT_DATA_UINT32 },
	{ "deficit",		KSTAT_DATA_UINT32 },
	{ "clk_intr",		KSTAT_DATA_UINT32 },
	{ "vac",		KSTAT_DATA_UINT32 },
	{ "nproc",		KSTAT_DATA_UINT32 },
	{ "avenrun_1min",	KSTAT_DATA_UINT32 },
	{ "avenrun_5min",	KSTAT_DATA_UINT32 },
	{ "avenrun_15min",	KSTAT_DATA_UINT32 },
	{ "boot_time",		KSTAT_DATA_UINT32 },
};

struct {
	kstat_named_t physmem;
	kstat_named_t nalloc;
	kstat_named_t nfree;
	kstat_named_t nalloc_calls;
	kstat_named_t nfree_calls;
	kstat_named_t kernelbase;
	kstat_named_t econtig;
	kstat_named_t freemem;
	kstat_named_t availrmem;
	kstat_named_t lotsfree;
	kstat_named_t desfree;
	kstat_named_t minfree;
	kstat_named_t fastscan;
	kstat_named_t slowscan;
	kstat_named_t nscan;
	kstat_named_t desscan;
	kstat_named_t pp_kernel;
	kstat_named_t pagesfree;
	kstat_named_t pageslocked;
	kstat_named_t pagestotal;
} system_pages_kstat = {
	{ "physmem",		KSTAT_DATA_ULONG },
	{ "nalloc",		KSTAT_DATA_ULONG },
	{ "nfree",		KSTAT_DATA_ULONG },
	{ "nalloc_calls",	KSTAT_DATA_ULONG },
	{ "nfree_calls",	KSTAT_DATA_ULONG },
	{ "kernelbase",		KSTAT_DATA_ULONG },
	{ "econtig", 		KSTAT_DATA_ULONG },
	{ "freemem", 		KSTAT_DATA_ULONG },
	{ "availrmem", 		KSTAT_DATA_ULONG },
	{ "lotsfree", 		KSTAT_DATA_ULONG },
	{ "desfree", 		KSTAT_DATA_ULONG },
	{ "minfree", 		KSTAT_DATA_ULONG },
	{ "fastscan", 		KSTAT_DATA_ULONG },
	{ "slowscan", 		KSTAT_DATA_ULONG },
	{ "nscan", 		KSTAT_DATA_ULONG },
	{ "desscan", 		KSTAT_DATA_ULONG },
	{ "pp_kernel", 		KSTAT_DATA_ULONG },
	{ "pagesfree", 		KSTAT_DATA_ULONG },
	{ "pageslocked", 	KSTAT_DATA_ULONG },
	{ "pagestotal",		KSTAT_DATA_ULONG },
};

static int header_kstat_update(kstat_t *, int);
static int header_kstat_snapshot(kstat_t *, void *, int);
static int system_misc_kstat_update(kstat_t *, int);
static int system_pages_kstat_update(kstat_t *, int);

static struct {
	char	name[KSTAT_STRLEN];
	size_t	size;
	uint_t	min_ndata;
	uint_t	max_ndata;
} kstat_data_type[KSTAT_NUM_TYPES] = {
	{ "raw",		1,			0,	INT_MAX	},
	{ "name=value",		sizeof (kstat_named_t),	0,	INT_MAX	},
	{ "interrupt",		sizeof (kstat_intr_t),	1,	1	},
	{ "i/o",		sizeof (kstat_io_t),	1,	1	},
	{ "event_timer",	sizeof (kstat_timer_t),	0,	INT_MAX	},
};

int
kstat_zone_find(kstat_t *k, zoneid_t zoneid)
{
	ekstat_t *e = (ekstat_t *)k;
	kstat_zone_t *kz;

	ASSERT(MUTEX_HELD(&kstat_chain_lock));
	for (kz = &e->e_zone; kz != NULL; kz = kz->next) {
		if (zoneid == ALL_ZONES || kz->zoneid == ALL_ZONES)
			return (1);
		if (zoneid == kz->zoneid)
			return (1);
	}
	return (0);
}

void
kstat_zone_remove(kstat_t *k, zoneid_t zoneid)
{
	ekstat_t *e = (ekstat_t *)k;
	kstat_zone_t *kz, *t = NULL;

	mutex_enter(&kstat_chain_lock);
	if (zoneid == e->e_zone.zoneid) {
		kz = e->e_zone.next;
		ASSERT(kz != NULL);
		e->e_zone.zoneid = kz->zoneid;
		e->e_zone.next = kz->next;
		goto out;
	}
	for (kz = &e->e_zone; kz->next != NULL; kz = kz->next) {
		if (kz->next->zoneid == zoneid) {
			t = kz->next;
			kz->next = t->next;
			break;
		}
	}
	ASSERT(t != NULL);	/* we removed something */
	kz = t;
out:
	kstat_chain_id++;
	mutex_exit(&kstat_chain_lock);
	kmem_free(kz, sizeof (*kz));
}

void
kstat_zone_add(kstat_t *k, zoneid_t zoneid)
{
	ekstat_t *e = (ekstat_t *)k;
	kstat_zone_t *kz;

	kz = kmem_alloc(sizeof (*kz), KM_NOSLEEP);
	if (kz == NULL)
		return;
	mutex_enter(&kstat_chain_lock);
	kz->zoneid = zoneid;
	kz->next = e->e_zone.next;
	e->e_zone.next = kz;
	kstat_chain_id++;
	mutex_exit(&kstat_chain_lock);
}

/*
 * Compare the list of zones for the given kstats, returning 0 if they match
 * (ie, one list contains ALL_ZONES or both lists contain the same zoneid).
 * In practice, this is called indirectly by kstat_hold_byname(), so one of the
 * two lists always has one element, and this is an O(n) operation rather than
 * O(n^2).
 */
static int
kstat_zone_compare(ekstat_t *e1, ekstat_t *e2)
{
	kstat_zone_t *kz1, *kz2;

	ASSERT(MUTEX_HELD(&kstat_chain_lock));
	for (kz1 = &e1->e_zone; kz1 != NULL; kz1 = kz1->next) {
		for (kz2 = &e2->e_zone; kz2 != NULL; kz2 = kz2->next) {
			if (kz1->zoneid == ALL_ZONES ||
			    kz2->zoneid == ALL_ZONES)
				return (0);
			if (kz1->zoneid == kz2->zoneid)
				return (0);
		}
	}
	return (e1->e_zone.zoneid < e2->e_zone.zoneid ? -1 : 1);
}

/*
 * Support for keeping kstats sorted in AVL trees for fast lookups.
 */
static int
kstat_compare_bykid(const void *a1, const void *a2)
{
	const kstat_t *k1 = a1;
	const kstat_t *k2 = a2;

	if (k1->ks_kid < k2->ks_kid)
		return (-1);
	if (k1->ks_kid > k2->ks_kid)
		return (1);
	return (kstat_zone_compare((ekstat_t *)k1, (ekstat_t *)k2));
}

static int
kstat_compare_byname(const void *a1, const void *a2)
{
	const kstat_t *k1 = a1;
	const kstat_t *k2 = a2;
	int s;

	s = strcmp(k1->ks_module, k2->ks_module);
	if (s > 0)
		return (1);
	if (s < 0)
		return (-1);

	if (k1->ks_instance < k2->ks_instance)
		return (-1);
	if (k1->ks_instance > k2->ks_instance)
		return (1);

	s = strcmp(k1->ks_name, k2->ks_name);
	if (s > 0)
		return (1);
	if (s < 0)
		return (-1);

	return (kstat_zone_compare((ekstat_t *)k1, (ekstat_t *)k2));
}

static kstat_t *
kstat_hold(avl_tree_t *t, ekstat_t *template)
{
	kstat_t *ksp;
	ekstat_t *e;

	mutex_enter(&kstat_chain_lock);
	for (;;) {
		ksp = avl_find(t, template, NULL);
		if (ksp == NULL)
			break;
		e = (ekstat_t *)ksp;
		if (e->e_owner == NULL) {
			e->e_owner = curthread;
			break;
		}
		cv_wait(&e->e_cv, &kstat_chain_lock);
	}
	mutex_exit(&kstat_chain_lock);
	return (ksp);
}

void
kstat_rele(kstat_t *ksp)
{
	ekstat_t *e = (ekstat_t *)ksp;

	mutex_enter(&kstat_chain_lock);
	ASSERT(e->e_owner == curthread);
	e->e_owner = NULL;
	cv_broadcast(&e->e_cv);
	mutex_exit(&kstat_chain_lock);
}

kstat_t *
kstat_hold_bykid(kid_t kid, zoneid_t zoneid)
{
	ekstat_t e;

	e.e_ks.ks_kid = kid;
	e.e_zone.zoneid = zoneid;
	e.e_zone.next = NULL;

	return (kstat_hold(&kstat_avl_bykid, &e));
}

kstat_t *
kstat_hold_byname(const char *ks_module, int ks_instance, const char *ks_name,
    zoneid_t ks_zoneid)
{
	ekstat_t e;

	kstat_set_string(e.e_ks.ks_module, ks_module);
	e.e_ks.ks_instance = ks_instance;
	kstat_set_string(e.e_ks.ks_name, ks_name);
	e.e_zone.zoneid = ks_zoneid;
	e.e_zone.next = NULL;
	return (kstat_hold(&kstat_avl_byname, &e));
}

static ekstat_t *
kstat_alloc(size_t size)
{
	ekstat_t *e = NULL;

	size = P2ROUNDUP(sizeof (ekstat_t) + size, KSTAT_ALIGN);

	if (kstat_arena == NULL) {
		if (size <= kstat_initial_avail) {
			e = kstat_initial_ptr;
			kstat_initial_ptr = (char *)kstat_initial_ptr + size;
			kstat_initial_avail -= size;
		}
	} else {
		e = vmem_alloc(kstat_arena, size, VM_NOSLEEP);
	}

	if (e != NULL) {
		bzero(e, size);
		e->e_size = size;
		cv_init(&e->e_cv, NULL, CV_DEFAULT, NULL);
	}

	return (e);
}

static void
kstat_free(ekstat_t *e)
{
	cv_destroy(&e->e_cv);
	vmem_free(kstat_arena, e, e->e_size);
}

/*
 * Create various system kstats.
 */
void
kstat_init(void)
{
	kstat_t *ksp;
	ekstat_t *e;
	avl_tree_t *t = &kstat_avl_bykid;

	/*
	 * Set up the kstat vmem arena.
	 */
	kstat_arena = vmem_create("kstat",
	    kstat_initial, sizeof (kstat_initial), KSTAT_ALIGN,
	    segkmem_alloc, segkmem_free, heap_arena, 0, VM_SLEEP);

	/*
	 * Make initial kstats appear as though they were allocated.
	 */
	for (e = avl_first(t); e != NULL; e = avl_walk(t, e, AVL_AFTER))
		(void) vmem_xalloc(kstat_arena, e->e_size, KSTAT_ALIGN,
		    0, 0, e, (char *)e + e->e_size,
		    VM_NOSLEEP | VM_BESTFIT | VM_PANIC);

	/*
	 * The mother of all kstats.  The first kstat in the system, which
	 * always has KID 0, has the headers for all kstats (including itself)
	 * as its data.  Thus, the kstat driver does not need any special
	 * interface to extract the kstat chain.
	 */
	kstat_chain_id = 0;
	ksp = kstat_create("unix", 0, "kstat_headers", "kstat", KSTAT_TYPE_RAW,
	    0, KSTAT_FLAG_VIRTUAL | KSTAT_FLAG_VAR_SIZE);
	if (ksp) {
		ksp->ks_lock = &kstat_chain_lock;
		ksp->ks_update = header_kstat_update;
		ksp->ks_snapshot = header_kstat_snapshot;
		kstat_install(ksp);
	} else {
		panic("cannot create kstat 'kstat_headers'");
	}

	ksp = kstat_create("unix", 0, "kstat_types", "kstat",
	    KSTAT_TYPE_NAMED, KSTAT_NUM_TYPES, 0);
	if (ksp) {
		int i;
		kstat_named_t *kn = KSTAT_NAMED_PTR(ksp);

		for (i = 0; i < KSTAT_NUM_TYPES; i++) {
			kstat_named_init(&kn[i], kstat_data_type[i].name,
			    KSTAT_DATA_ULONG);
			kn[i].value.ul = i;
		}
		kstat_install(ksp);
	}

	ksp = kstat_create("unix", 0, "sysinfo", "misc", KSTAT_TYPE_RAW,
	    sizeof (sysinfo_t), KSTAT_FLAG_VIRTUAL);
	if (ksp) {
		ksp->ks_data = (void *) &sysinfo;
		kstat_install(ksp);
	}

	ksp = kstat_create("unix", 0, "vminfo", "vm", KSTAT_TYPE_RAW,
	    sizeof (vminfo_t), KSTAT_FLAG_VIRTUAL);
	if (ksp) {
		ksp->ks_data = (void *) &vminfo;
		kstat_install(ksp);
	}

	ksp = kstat_create("unix", 0, "segmap", "vm", KSTAT_TYPE_NAMED,
	    segmapcnt_ndata, KSTAT_FLAG_VIRTUAL);
	if (ksp) {
		ksp->ks_data = (void *) segmapcnt_ptr;
		ksp->ks_update = segmap_kstat_update;
		kstat_install(ksp);
	}

	ksp = kstat_create("unix", 0, "biostats", "misc", KSTAT_TYPE_NAMED,
	    biostats_ndata, KSTAT_FLAG_VIRTUAL);
	if (ksp) {
		ksp->ks_data = (void *) biostats_ptr;
		kstat_install(ksp);
	}

	ksp = kstat_create("unix", 0, "var", "misc", KSTAT_TYPE_RAW,
	    sizeof (struct var), KSTAT_FLAG_VIRTUAL);
	if (ksp) {
		ksp->ks_data = (void *) &v;
		kstat_install(ksp);
	}

	ksp = kstat_create("unix", 0, "system_misc", "misc", KSTAT_TYPE_NAMED,
	    sizeof (system_misc_kstat) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);
	if (ksp) {
		ksp->ks_data = (void *) &system_misc_kstat;
		ksp->ks_update = system_misc_kstat_update;
		kstat_install(ksp);
	}

	ksp = kstat_create("unix", 0, "system_pages", "pages", KSTAT_TYPE_NAMED,
	    sizeof (system_pages_kstat) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);
	if (ksp) {
		ksp->ks_data = (void *) &system_pages_kstat;
		ksp->ks_update = system_pages_kstat_update;
		kstat_install(ksp);
	}

	ksp = kstat_create("poll", 0, "pollstats", "misc", KSTAT_TYPE_NAMED,
	    pollstats_ndata, KSTAT_FLAG_VIRTUAL | KSTAT_FLAG_WRITABLE);

	if (ksp) {
		ksp->ks_data = pollstats_ptr;
		kstat_install(ksp);
	}
}

/*
 * Caller of this should ensure that the string pointed by src
 * doesn't change while kstat's lock is held. Not doing so defeats
 * kstat's snapshot strategy as explained in <sys/kstat.h>
 */
void
kstat_named_setstr(kstat_named_t *knp, const char *src)
{
	if (knp->data_type != KSTAT_DATA_STRING)
		panic("kstat_named_setstr('%p', '%p'): "
		    "named kstat is not of type KSTAT_DATA_STRING",
		    (void *)knp, (void *)src);

	KSTAT_NAMED_STR_PTR(knp) = (char *)src;
	if (src != NULL)
		KSTAT_NAMED_STR_BUFLEN(knp) = strlen(src) + 1;
	else
		KSTAT_NAMED_STR_BUFLEN(knp) = 0;
}

void
kstat_set_string(char *dst, const char *src)
{
	bzero(dst, KSTAT_STRLEN);
	(void) strncpy(dst, src, KSTAT_STRLEN - 1);
}

void
kstat_named_init(kstat_named_t *knp, const char *name, uchar_t data_type)
{
	kstat_set_string(knp->name, name);
	knp->data_type = data_type;

	if (data_type == KSTAT_DATA_STRING)
		kstat_named_setstr(knp, NULL);
}

void
kstat_timer_init(kstat_timer_t *ktp, const char *name)
{
	kstat_set_string(ktp->name, name);
}

/* ARGSUSED */
static int
default_kstat_update(kstat_t *ksp, int rw)
{
	uint_t i;
	size_t len = 0;
	kstat_named_t *knp;

	/*
	 * Named kstats with variable-length long strings have a standard
	 * way of determining how much space is needed to hold the snapshot:
	 */
	if (ksp->ks_data != NULL && ksp->ks_type == KSTAT_TYPE_NAMED &&
	    (ksp->ks_flags & KSTAT_FLAG_VAR_SIZE)) {

		/*
		 * Add in the space required for the strings
		 */
		knp = KSTAT_NAMED_PTR(ksp);
		for (i = 0; i < ksp->ks_ndata; i++, knp++) {
			if (knp->data_type == KSTAT_DATA_STRING)
				len += KSTAT_NAMED_STR_BUFLEN(knp);
		}
		ksp->ks_data_size =
		    ksp->ks_ndata * sizeof (kstat_named_t) + len;
	}
	return (0);
}

static int
default_kstat_snapshot(kstat_t *ksp, void *buf, int rw)
{
	kstat_io_t *kiop;
	hrtime_t cur_time;
	size_t	namedsz;

	ksp->ks_snaptime = cur_time = gethrtime();

	if (rw == KSTAT_WRITE) {
		if (!(ksp->ks_flags & KSTAT_FLAG_WRITABLE))
			return (EACCES);
		bcopy(buf, ksp->ks_data, ksp->ks_data_size);
		return (0);
	}

	/*
	 * KSTAT_TYPE_NAMED kstats are defined to have ks_ndata
	 * number of kstat_named_t structures, followed by an optional
	 * string segment. The ks_data generally holds only the
	 * kstat_named_t structures. So we copy it first. The strings,
	 * if any, are copied below. For other kstat types, ks_data holds the
	 * entire buffer.
	 */

	namedsz = sizeof (kstat_named_t) * ksp->ks_ndata;
	if (ksp->ks_type == KSTAT_TYPE_NAMED && ksp->ks_data_size > namedsz)
		bcopy(ksp->ks_data, buf, namedsz);
	else
		bcopy(ksp->ks_data, buf, ksp->ks_data_size);

	/*
	 * Apply kstat type-specific data massaging
	 */
	switch (ksp->ks_type) {

	case KSTAT_TYPE_IO:
		/*
		 * Normalize time units and deal with incomplete transactions
		 */
		kiop = (kstat_io_t *)buf;

		scalehrtime(&kiop->wtime);
		scalehrtime(&kiop->wlentime);
		scalehrtime(&kiop->wlastupdate);
		scalehrtime(&kiop->rtime);
		scalehrtime(&kiop->rlentime);
		scalehrtime(&kiop->rlastupdate);

		if (kiop->wcnt != 0) {
			/* like kstat_waitq_exit */
			hrtime_t wfix = cur_time - kiop->wlastupdate;
			kiop->wlastupdate = cur_time;
			kiop->wlentime += kiop->wcnt * wfix;
			kiop->wtime += wfix;
		}

		if (kiop->rcnt != 0) {
			/* like kstat_runq_exit */
			hrtime_t rfix = cur_time - kiop->rlastupdate;
			kiop->rlastupdate = cur_time;
			kiop->rlentime += kiop->rcnt * rfix;
			kiop->rtime += rfix;
		}
		break;

	case KSTAT_TYPE_NAMED:
		/*
		 * Massage any long strings in at the end of the buffer
		 */
		if (ksp->ks_data_size > namedsz) {
			uint_t i;
			kstat_named_t *knp = buf;
			char *dst = (char *)(knp + ksp->ks_ndata);
			/*
			 * Copy strings and update pointers
			 */
			for (i = 0; i < ksp->ks_ndata; i++, knp++) {
				if (knp->data_type == KSTAT_DATA_STRING &&
				    KSTAT_NAMED_STR_PTR(knp) != NULL) {
					bcopy(KSTAT_NAMED_STR_PTR(knp), dst,
					    KSTAT_NAMED_STR_BUFLEN(knp));
					KSTAT_NAMED_STR_PTR(knp) = dst;
					dst += KSTAT_NAMED_STR_BUFLEN(knp);
				}
			}
			ASSERT(dst <= ((char *)buf + ksp->ks_data_size));
		}
		break;
	}
	return (0);
}

static int
header_kstat_update(kstat_t *header_ksp, int rw)
{
	int nkstats = 0;
	ekstat_t *e;
	avl_tree_t *t = &kstat_avl_bykid;
	zoneid_t zoneid;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	ASSERT(MUTEX_HELD(&kstat_chain_lock));

	zoneid = getzoneid();
	for (e = avl_first(t); e != NULL; e = avl_walk(t, e, AVL_AFTER)) {
		if (kstat_zone_find((kstat_t *)e, zoneid) &&
		    (e->e_ks.ks_flags & KSTAT_FLAG_INVALID) == 0) {
			nkstats++;
		}
	}
	header_ksp->ks_ndata = nkstats;
	header_ksp->ks_data_size = nkstats * sizeof (kstat_t);
	return (0);
}

/*
 * Copy out the data section of kstat 0, which consists of the list
 * of all kstat headers.  By specification, these headers must be
 * copied out in order of increasing KID.
 */
static int
header_kstat_snapshot(kstat_t *header_ksp, void *buf, int rw)
{
	ekstat_t *e;
	avl_tree_t *t = &kstat_avl_bykid;
	zoneid_t zoneid;

	header_ksp->ks_snaptime = gethrtime();

	if (rw == KSTAT_WRITE)
		return (EACCES);

	ASSERT(MUTEX_HELD(&kstat_chain_lock));

	zoneid = getzoneid();
	for (e = avl_first(t); e != NULL; e = avl_walk(t, e, AVL_AFTER)) {
		if (kstat_zone_find((kstat_t *)e, zoneid) &&
		    (e->e_ks.ks_flags & KSTAT_FLAG_INVALID) == 0) {
			bcopy(&e->e_ks, buf, sizeof (kstat_t));
			buf = (char *)buf + sizeof (kstat_t);
		}
	}

	return (0);
}

/* ARGSUSED */
static int
system_misc_kstat_update(kstat_t *ksp, int rw)
{
	int myncpus = ncpus;
	int *loadavgp = &avenrun[0];
	int loadavg[LOADAVG_NSTATS];
	time_t zone_boot_time;
	clock_t zone_lbolt;
	hrtime_t zone_hrtime;
	size_t zone_nproc;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	if (!INGLOBALZONE(curproc)) {
		/*
		 * Here we grab cpu_lock which is OK as long as no-one in the
		 * future attempts to lookup this particular kstat
		 * (unix:0:system_misc) while holding cpu_lock.
		 */
		mutex_enter(&cpu_lock);
		if (pool_pset_enabled()) {
			psetid_t mypsid = zone_pset_get(curproc->p_zone);
			int error;

			myncpus = zone_ncpus_get(curproc->p_zone);
			ASSERT(myncpus > 0);
			error = cpupart_get_loadavg(mypsid, &loadavg[0],
			    LOADAVG_NSTATS);
			ASSERT(error == 0);
			loadavgp = &loadavg[0];
		}
		mutex_exit(&cpu_lock);
	}

	if (INGLOBALZONE(curproc)) {
		zone_boot_time = boot_time;
		zone_lbolt = ddi_get_lbolt();
		zone_nproc = nproc;
	} else {
		zone_boot_time = curproc->p_zone->zone_boot_time;

		zone_hrtime = gethrtime();
		zone_lbolt = (clock_t)(NSEC_TO_TICK(zone_hrtime) -
		    NSEC_TO_TICK(curproc->p_zone->zone_zsched->p_mstart));
		mutex_enter(&curproc->p_zone->zone_nlwps_lock);
		zone_nproc = curproc->p_zone->zone_nprocs;
		mutex_exit(&curproc->p_zone->zone_nlwps_lock);
	}

	system_misc_kstat.ncpus.value.ui32		= (uint32_t)myncpus;
	system_misc_kstat.lbolt.value.ui32		= (uint32_t)zone_lbolt;
	system_misc_kstat.deficit.value.ui32		= (uint32_t)deficit;
	system_misc_kstat.clk_intr.value.ui32		= (uint32_t)zone_lbolt;
	system_misc_kstat.vac.value.ui32		= (uint32_t)vac;
	system_misc_kstat.nproc.value.ui32		= (uint32_t)zone_nproc;
	system_misc_kstat.avenrun_1min.value.ui32	= (uint32_t)loadavgp[0];
	system_misc_kstat.avenrun_5min.value.ui32	= (uint32_t)loadavgp[1];
	system_misc_kstat.avenrun_15min.value.ui32	= (uint32_t)loadavgp[2];
	system_misc_kstat.boot_time.value.ui32		= (uint32_t)
	    zone_boot_time;
	return (0);
}

#ifdef	__sparc
extern caddr_t	econtig32;
#else	/* !__sparc */
extern caddr_t	econtig;
#endif	/* __sparc */

/* ARGSUSED */
static int
system_pages_kstat_update(kstat_t *ksp, int rw)
{
	kobj_stat_t kobj_stat;

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	}

	kobj_stat_get(&kobj_stat);
	system_pages_kstat.physmem.value.ul	= (ulong_t)physmem;
	system_pages_kstat.nalloc.value.ul	= kobj_stat.nalloc;
	system_pages_kstat.nfree.value.ul	= kobj_stat.nfree;
	system_pages_kstat.nalloc_calls.value.ul = kobj_stat.nalloc_calls;
	system_pages_kstat.nfree_calls.value.ul	= kobj_stat.nfree_calls;
	system_pages_kstat.kernelbase.value.ul	= (ulong_t)KERNELBASE;

#ifdef	__sparc
	/*
	 * kstat should REALLY be modified to also report kmem64_base and
	 * kmem64_end (see sun4u/os/startup.c), as the virtual address range
	 * [ kernelbase .. econtig ] no longer is truly reflective of the
	 * kernel's vallocs...
	 */
	system_pages_kstat.econtig.value.ul	= (ulong_t)econtig32;
#else	/* !__sparc */
	system_pages_kstat.econtig.value.ul	= (ulong_t)econtig;
#endif	/* __sparc */

	system_pages_kstat.freemem.value.ul	= (ulong_t)freemem;
	system_pages_kstat.availrmem.value.ul	= (ulong_t)availrmem;
	system_pages_kstat.lotsfree.value.ul	= (ulong_t)lotsfree;
	system_pages_kstat.desfree.value.ul	= (ulong_t)desfree;
	system_pages_kstat.minfree.value.ul	= (ulong_t)minfree;
	system_pages_kstat.fastscan.value.ul	= (ulong_t)fastscan;
	system_pages_kstat.slowscan.value.ul	= (ulong_t)slowscan;
	system_pages_kstat.nscan.value.ul	= (ulong_t)nscan;
	system_pages_kstat.desscan.value.ul	= (ulong_t)desscan;
	system_pages_kstat.pagesfree.value.ul	= (ulong_t)freemem;
	system_pages_kstat.pageslocked.value.ul	= (ulong_t)(availrmem_initial -
	    availrmem);
	system_pages_kstat.pagestotal.value.ul	= (ulong_t)total_pages;
	/*
	 * pp_kernel represents total pages used by the kernel since the
	 * startup. This formula takes into account the boottime kernel
	 * footprint and also considers the availrmem changes because of
	 * user explicit page locking.
	 */
	system_pages_kstat.pp_kernel.value.ul   = (ulong_t)(physinstalled -
	    obp_pages - availrmem - k_anoninfo.ani_mem_resv -
	    anon_segkp_pages_locked - pages_locked -
	    pages_claimed - pages_useclaim);

	return (0);
}

kstat_t *
kstat_create(const char *ks_module, int ks_instance, const char *ks_name,
    const char *ks_class, uchar_t ks_type, uint_t ks_ndata, uchar_t ks_flags)
{
	return (kstat_create_zone(ks_module, ks_instance, ks_name, ks_class,
	    ks_type, ks_ndata, ks_flags, ALL_ZONES));
}

/*
 * Allocate and initialize a kstat structure.  Or, if a dormant kstat with
 * the specified name exists, reactivate it.  Returns a pointer to the kstat
 * on success, NULL on failure.  The kstat will not be visible to the
 * kstat driver until kstat_install().
 */
kstat_t *
kstat_create_zone(const char *ks_module, int ks_instance, const char *ks_name,
    const char *ks_class, uchar_t ks_type, uint_t ks_ndata, uchar_t ks_flags,
    zoneid_t ks_zoneid)
{
	size_t ks_data_size;
	kstat_t *ksp;
	ekstat_t *e;
	avl_index_t where;
	char namebuf[KSTAT_STRLEN + 16];

	if (avl_numnodes(&kstat_avl_bykid) == 0) {
		avl_create(&kstat_avl_bykid, kstat_compare_bykid,
		    sizeof (ekstat_t), offsetof(struct ekstat, e_avl_bykid));

		avl_create(&kstat_avl_byname, kstat_compare_byname,
		    sizeof (ekstat_t), offsetof(struct ekstat, e_avl_byname));
	}

	/*
	 * If ks_name == NULL, set the ks_name to <module><instance>.
	 */
	if (ks_name == NULL) {
		char buf[KSTAT_STRLEN];
		kstat_set_string(buf, ks_module);
		(void) sprintf(namebuf, "%s%d", buf, ks_instance);
		ks_name = namebuf;
	}

	/*
	 * Make sure it's a valid kstat data type
	 */
	if (ks_type >= KSTAT_NUM_TYPES) {
		cmn_err(CE_WARN, "kstat_create('%s', %d, '%s'): "
		    "invalid kstat type %d",
		    ks_module, ks_instance, ks_name, ks_type);
		return (NULL);
	}

	/*
	 * Don't allow persistent virtual kstats -- it makes no sense.
	 * ks_data points to garbage when the client goes away.
	 */
	if ((ks_flags & KSTAT_FLAG_PERSISTENT) &&
	    (ks_flags & KSTAT_FLAG_VIRTUAL)) {
		cmn_err(CE_WARN, "kstat_create('%s', %d, '%s'): "
		    "cannot create persistent virtual kstat",
		    ks_module, ks_instance, ks_name);
		return (NULL);
	}

	/*
	 * Don't allow variable-size physical kstats, since the framework's
	 * memory allocation for physical kstat data is fixed at creation time.
	 */
	if ((ks_flags & KSTAT_FLAG_VAR_SIZE) &&
	    !(ks_flags & KSTAT_FLAG_VIRTUAL)) {
		cmn_err(CE_WARN, "kstat_create('%s', %d, '%s'): "
		    "cannot create variable-size physical kstat",
		    ks_module, ks_instance, ks_name);
		return (NULL);
	}

	/*
	 * Make sure the number of data fields is within legal range
	 */
	if (ks_ndata < kstat_data_type[ks_type].min_ndata ||
	    ks_ndata > kstat_data_type[ks_type].max_ndata) {
		cmn_err(CE_WARN, "kstat_create('%s', %d, '%s'): "
		    "ks_ndata=%d out of range [%d, %d]",
		    ks_module, ks_instance, ks_name, (int)ks_ndata,
		    kstat_data_type[ks_type].min_ndata,
		    kstat_data_type[ks_type].max_ndata);
		return (NULL);
	}

	ks_data_size = kstat_data_type[ks_type].size * ks_ndata;

	/*
	 * If the named kstat already exists and is dormant, reactivate it.
	 */
	ksp = kstat_hold_byname(ks_module, ks_instance, ks_name, ks_zoneid);
	if (ksp != NULL) {
		if (!(ksp->ks_flags & KSTAT_FLAG_DORMANT)) {
			/*
			 * The named kstat exists but is not dormant --
			 * this is a kstat namespace collision.
			 */
			kstat_rele(ksp);
			cmn_err(CE_WARN,
			    "kstat_create('%s', %d, '%s'): namespace collision",
			    ks_module, ks_instance, ks_name);
			return (NULL);
		}
		if ((strcmp(ksp->ks_class, ks_class) != 0) ||
		    (ksp->ks_type != ks_type) ||
		    (ksp->ks_ndata != ks_ndata) ||
		    (ks_flags & KSTAT_FLAG_VIRTUAL)) {
			/*
			 * The name is the same, but the other key parameters
			 * differ from those of the dormant kstat -- bogus.
			 */
			kstat_rele(ksp);
			cmn_err(CE_WARN, "kstat_create('%s', %d, '%s'): "
			    "invalid reactivation of dormant kstat",
			    ks_module, ks_instance, ks_name);
			return (NULL);
		}
		/*
		 * Return dormant kstat pointer to caller.  As usual,
		 * the kstat is marked invalid until kstat_install().
		 */
		ksp->ks_flags |= KSTAT_FLAG_INVALID;
		kstat_rele(ksp);
		return (ksp);
	}

	/*
	 * Allocate memory for the new kstat header and, if this is a physical
	 * kstat, the data section.
	 */
	e = kstat_alloc(ks_flags & KSTAT_FLAG_VIRTUAL ? 0 : ks_data_size);
	if (e == NULL) {
		cmn_err(CE_NOTE, "kstat_create('%s', %d, '%s'): "
		    "insufficient kernel memory",
		    ks_module, ks_instance, ks_name);
		return (NULL);
	}

	/*
	 * Initialize as many fields as we can.  The caller may reset
	 * ks_lock, ks_update, ks_private, and ks_snapshot as necessary.
	 * Creators of virtual kstats may also reset ks_data.  It is
	 * also up to the caller to initialize the kstat data section,
	 * if necessary.  All initialization must be complete before
	 * calling kstat_install().
	 */
	e->e_zone.zoneid = ks_zoneid;
	e->e_zone.next = NULL;

	ksp = &e->e_ks;
	ksp->ks_crtime		= gethrtime();
	kstat_set_string(ksp->ks_module, ks_module);
	ksp->ks_instance	= ks_instance;
	kstat_set_string(ksp->ks_name, ks_name);
	ksp->ks_type		= ks_type;
	kstat_set_string(ksp->ks_class, ks_class);
	ksp->ks_flags		= ks_flags | KSTAT_FLAG_INVALID;
	if (ks_flags & KSTAT_FLAG_VIRTUAL)
		ksp->ks_data	= NULL;
	else
		ksp->ks_data	= (void *)(e + 1);
	ksp->ks_ndata		= ks_ndata;
	ksp->ks_data_size	= ks_data_size;
	ksp->ks_snaptime	= ksp->ks_crtime;
	ksp->ks_update		= default_kstat_update;
	ksp->ks_private		= NULL;
	ksp->ks_snapshot	= default_kstat_snapshot;
	ksp->ks_lock		= NULL;

	mutex_enter(&kstat_chain_lock);

	/*
	 * Add our kstat to the AVL trees.
	 */
	if (avl_find(&kstat_avl_byname, e, &where) != NULL) {
		mutex_exit(&kstat_chain_lock);
		cmn_err(CE_WARN,
		    "kstat_create('%s', %d, '%s'): namespace collision",
		    ks_module, ks_instance, ks_name);
		kstat_free(e);
		return (NULL);
	}
	avl_insert(&kstat_avl_byname, e, where);

	/*
	 * Loop around until we find an unused KID.
	 */
	do {
		ksp->ks_kid = kstat_chain_id++;
	} while (avl_find(&kstat_avl_bykid, e, &where) != NULL);
	avl_insert(&kstat_avl_bykid, e, where);

	mutex_exit(&kstat_chain_lock);

	return (ksp);
}

/*
 * Activate a fully initialized kstat and make it visible to /dev/kstat.
 */
void
kstat_install(kstat_t *ksp)
{
	zoneid_t zoneid = ((ekstat_t *)ksp)->e_zone.zoneid;

	/*
	 * If this is a variable-size kstat, it MUST provide kstat data locking
	 * to prevent data-size races with kstat readers.
	 */
	if ((ksp->ks_flags & KSTAT_FLAG_VAR_SIZE) && ksp->ks_lock == NULL) {
		panic("kstat_install('%s', %d, '%s'): "
		    "cannot create variable-size kstat without data lock",
		    ksp->ks_module, ksp->ks_instance, ksp->ks_name);
	}

	if (kstat_hold_bykid(ksp->ks_kid, zoneid) != ksp) {
		cmn_err(CE_WARN, "kstat_install(%p): does not exist",
		    (void *)ksp);
		return;
	}

	if (ksp->ks_type == KSTAT_TYPE_NAMED && ksp->ks_data != NULL) {
		int has_long_strings = 0;
		uint_t i;
		kstat_named_t *knp = KSTAT_NAMED_PTR(ksp);

		for (i = 0; i < ksp->ks_ndata; i++, knp++) {
			if (knp->data_type == KSTAT_DATA_STRING) {
				has_long_strings = 1;
				break;
			}
		}
		/*
		 * It is an error for a named kstat with fields of
		 * KSTAT_DATA_STRING to be non-virtual.
		 */
		if (has_long_strings && !(ksp->ks_flags & KSTAT_FLAG_VIRTUAL)) {
			panic("kstat_install('%s', %d, '%s'): "
			    "named kstat containing KSTAT_DATA_STRING "
			    "is not virtual",
			    ksp->ks_module, ksp->ks_instance,
			    ksp->ks_name);
		}
		/*
		 * The default snapshot routine does not handle KSTAT_WRITE
		 * for long strings.
		 */
		if (has_long_strings && (ksp->ks_flags & KSTAT_FLAG_WRITABLE) &&
		    (ksp->ks_snapshot == default_kstat_snapshot)) {
			panic("kstat_install('%s', %d, '%s'): "
			    "named kstat containing KSTAT_DATA_STRING "
			    "is writable but uses default snapshot routine",
			    ksp->ks_module, ksp->ks_instance, ksp->ks_name);
		}
	}

	if (ksp->ks_flags & KSTAT_FLAG_DORMANT) {

		/*
		 * We are reactivating a dormant kstat.  Initialize the
		 * caller's underlying data to the value it had when the
		 * kstat went dormant, and mark the kstat as active.
		 * Grab the provider's kstat lock if it's not already held.
		 */
		kmutex_t *lp = ksp->ks_lock;
		if (lp != NULL && MUTEX_NOT_HELD(lp)) {
			mutex_enter(lp);
			(void) KSTAT_UPDATE(ksp, KSTAT_WRITE);
			mutex_exit(lp);
		} else {
			(void) KSTAT_UPDATE(ksp, KSTAT_WRITE);
		}
		ksp->ks_flags &= ~KSTAT_FLAG_DORMANT;
	}

	/*
	 * Now that the kstat is active, make it visible to the kstat driver.
	 */
	ksp->ks_flags &= ~KSTAT_FLAG_INVALID;
	kstat_rele(ksp);
}

/*
 * Remove a kstat from the system.  Or, if it's a persistent kstat,
 * just update the data and mark it as dormant.
 */
void
kstat_delete(kstat_t *ksp)
{
	kmutex_t *lp;
	ekstat_t *e = (ekstat_t *)ksp;
	zoneid_t zoneid;
	kstat_zone_t *kz;

	ASSERT(ksp != NULL);

	if (ksp == NULL)
		return;

	zoneid = e->e_zone.zoneid;

	lp = ksp->ks_lock;

	if (lp != NULL && MUTEX_HELD(lp)) {
		panic("kstat_delete(%p): caller holds data lock %p",
		    (void *)ksp, (void *)lp);
	}

	if (kstat_hold_bykid(ksp->ks_kid, zoneid) != ksp) {
		cmn_err(CE_WARN, "kstat_delete(%p): does not exist",
		    (void *)ksp);
		return;
	}

	if (ksp->ks_flags & KSTAT_FLAG_PERSISTENT) {
		/*
		 * Update the data one last time, so that all activity
		 * prior to going dormant has been accounted for.
		 */
		KSTAT_ENTER(ksp);
		(void) KSTAT_UPDATE(ksp, KSTAT_READ);
		KSTAT_EXIT(ksp);

		/*
		 * Mark the kstat as dormant and restore caller-modifiable
		 * fields to default values, so the kstat is readable during
		 * the dormant phase.
		 */
		ksp->ks_flags |= KSTAT_FLAG_DORMANT;
		ksp->ks_lock = NULL;
		ksp->ks_update = default_kstat_update;
		ksp->ks_private = NULL;
		ksp->ks_snapshot = default_kstat_snapshot;
		kstat_rele(ksp);
		return;
	}

	/*
	 * Remove the kstat from the framework's AVL trees,
	 * free the allocated memory, and increment kstat_chain_id so
	 * /dev/kstat clients can detect the event.
	 */
	mutex_enter(&kstat_chain_lock);
	avl_remove(&kstat_avl_bykid, e);
	avl_remove(&kstat_avl_byname, e);
	kstat_chain_id++;
	mutex_exit(&kstat_chain_lock);

	kz = e->e_zone.next;
	while (kz != NULL) {
		kstat_zone_t *t = kz;

		kz = kz->next;
		kmem_free(t, sizeof (*t));
	}
	kstat_rele(ksp);
	kstat_free(e);
}

void
kstat_delete_byname_zone(const char *ks_module, int ks_instance,
    const char *ks_name, zoneid_t ks_zoneid)
{
	kstat_t *ksp;

	ksp = kstat_hold_byname(ks_module, ks_instance, ks_name, ks_zoneid);
	if (ksp != NULL) {
		kstat_rele(ksp);
		kstat_delete(ksp);
	}
}

void
kstat_delete_byname(const char *ks_module, int ks_instance, const char *ks_name)
{
	kstat_delete_byname_zone(ks_module, ks_instance, ks_name, ALL_ZONES);
}

/*
 * The sparc V9 versions of these routines can be much cheaper than
 * the poor 32-bit compiler can comprehend, so they're in sparcv9_subr.s.
 * For simplicity, however, we always feed the C versions to lint.
 */
#if !defined(__sparc) || defined(lint) || defined(__lint)

void
kstat_waitq_enter(kstat_io_t *kiop)
{
	hrtime_t new, delta;
	ulong_t wcnt;

	new = gethrtime_unscaled();
	delta = new - kiop->wlastupdate;
	kiop->wlastupdate = new;
	wcnt = kiop->wcnt++;
	if (wcnt != 0) {
		kiop->wlentime += delta * wcnt;
		kiop->wtime += delta;
	}
}

void
kstat_waitq_exit(kstat_io_t *kiop)
{
	hrtime_t new, delta;
	ulong_t wcnt;

	new = gethrtime_unscaled();
	delta = new - kiop->wlastupdate;
	kiop->wlastupdate = new;
	wcnt = kiop->wcnt--;
	ASSERT((int)wcnt > 0);
	kiop->wlentime += delta * wcnt;
	kiop->wtime += delta;
}

void
kstat_runq_enter(kstat_io_t *kiop)
{
	hrtime_t new, delta;
	ulong_t rcnt;

	new = gethrtime_unscaled();
	delta = new - kiop->rlastupdate;
	kiop->rlastupdate = new;
	rcnt = kiop->rcnt++;
	if (rcnt != 0) {
		kiop->rlentime += delta * rcnt;
		kiop->rtime += delta;
	}
}

void
kstat_runq_exit(kstat_io_t *kiop)
{
	hrtime_t new, delta;
	ulong_t rcnt;

	new = gethrtime_unscaled();
	delta = new - kiop->rlastupdate;
	kiop->rlastupdate = new;
	rcnt = kiop->rcnt--;
	ASSERT((int)rcnt > 0);
	kiop->rlentime += delta * rcnt;
	kiop->rtime += delta;
}

void
kstat_waitq_to_runq(kstat_io_t *kiop)
{
	hrtime_t new, delta;
	ulong_t wcnt, rcnt;

	new = gethrtime_unscaled();

	delta = new - kiop->wlastupdate;
	kiop->wlastupdate = new;
	wcnt = kiop->wcnt--;
	ASSERT((int)wcnt > 0);
	kiop->wlentime += delta * wcnt;
	kiop->wtime += delta;

	delta = new - kiop->rlastupdate;
	kiop->rlastupdate = new;
	rcnt = kiop->rcnt++;
	if (rcnt != 0) {
		kiop->rlentime += delta * rcnt;
		kiop->rtime += delta;
	}
}

void
kstat_runq_back_to_waitq(kstat_io_t *kiop)
{
	hrtime_t new, delta;
	ulong_t wcnt, rcnt;

	new = gethrtime_unscaled();

	delta = new - kiop->rlastupdate;
	kiop->rlastupdate = new;
	rcnt = kiop->rcnt--;
	ASSERT((int)rcnt > 0);
	kiop->rlentime += delta * rcnt;
	kiop->rtime += delta;

	delta = new - kiop->wlastupdate;
	kiop->wlastupdate = new;
	wcnt = kiop->wcnt++;
	if (wcnt != 0) {
		kiop->wlentime += delta * wcnt;
		kiop->wtime += delta;
	}
}

#endif

void
kstat_timer_start(kstat_timer_t *ktp)
{
	ktp->start_time = gethrtime();
}

void
kstat_timer_stop(kstat_timer_t *ktp)
{
	hrtime_t	etime;
	u_longlong_t	num_events;

	ktp->stop_time = etime = gethrtime();
	etime -= ktp->start_time;
	num_events = ktp->num_events;
	if (etime < ktp->min_time || num_events == 0)
		ktp->min_time = etime;
	if (etime > ktp->max_time)
		ktp->max_time = etime;
	ktp->elapsed_time += etime;
	ktp->num_events = num_events + 1;
}

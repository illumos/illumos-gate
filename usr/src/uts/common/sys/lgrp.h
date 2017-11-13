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
 *
 * Copyright 2017 RackTop Systems.
 */

#ifndef	_LGRP_H
#define	_LGRP_H

/*
 * locality group definitions for kernel
 */

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	LGRP_NONE	(-1)		/* non-existent lgroup ID */

#if !defined(_KERNEL) && !defined(_FAKE_KERNEL) && !defined(_KMEMUSER)
typedef struct lgrp_mem_policy_info { int opaque[2]; }	lgrp_mem_policy_info_t;
#endif	/* !_KERNEL && !_FAKE_KERNEL && !_KMEMUSER */

#if defined(_KERNEL) || defined(_FAKE_KERNEL) || defined(_KMEMUSER)
#include <sys/cpuvar.h>
#include <sys/bitmap.h>
#include <sys/vnode.h>
#include <vm/anon.h>
#include <vm/seg.h>
#include <sys/lgrp_user.h>
#include <sys/param.h>

typedef	uint32_t	lgrp_load_t;	/* lgrp_loadavg type */
typedef uintptr_t	lgrp_handle_t;	/* lgrp handle */

#define	LGRP_NONE_SUCH		LGRP_NONE	/* non-existent lgroup ID */
/* null platform handle */
#define	LGRP_NULL_HANDLE	((lgrp_handle_t)0xbadbad)
#define	LGRP_DEFAULT_HANDLE	((lgrp_handle_t)0xbabecafe) /* uma handle */
#define	LGRP_ROOTID		(0)		/* root lgroup ID */

/*
 * Maximum number of lgrps a platform may define.
 */
#define	NLGRPS_MAX		64
#define	LGRP_LOADAVG_MAX	UINT32_MAX

/*
 * The load-average we expect for one cpu-bound thread's worth of load
 */
#define	LGRP_LOADAVG_THREAD_MAX		65516

/*
 * The input to the load-average generating function for one cpu-bound thread's
 * worth of load
 */

#define	LGRP_LOADAVG_IN_THREAD_MAX	128

/*
 * LPL actions
 */

typedef enum {
	LPL_INCREMENT,
	LPL_DECREMENT
} lpl_act_t;

/*
 * lgroup statistics.  Most of these are counters that are updated
 * dynamically so they are hashed to CPU buckets to reduce cache
 * interference.  The remaining statistics are snapshots of kernel
 * data, so they aren't stored in the array of counter stats.
 *
 * For the hashed stats to make sense, you have to sum all the buckets for
 * that stat, hence macros are provided to read the stats.
 */

#define	LGRP_NUM_CPU_BUCKETS	8	/* must be power of 2 */
#define	LGRP_CPU_BUCKET_MASK	(LGRP_NUM_CPU_BUCKETS - 1)

/*
 * Flags for what to do with lgroup memory policy
 * Used for heap and stack where policy is extended to new segments added to
 * the end
 */
#define	LGRP_MP_FLAG_EXTEND_UP		0x1	/* policy should extend up */
#define	LGRP_MP_FLAG_EXTEND_DOWN	0x2	/* policy should extend down */

#define	LGRP_STAT(stats, bucket, whichstat) \
	((stats)->ls_data[bucket][whichstat])

/* Return a pointer suitable for an atomic 64-bit op on the bucket */
#define	LGRP_STAT_WRITE_PTR(stats, whichstat) \
	(&LGRP_STAT(stats, (CPU->cpu_id) & LGRP_CPU_BUCKET_MASK, \
	    whichstat))

/* Sum up all the buckets and return the value in 'val' */
#define	LGRP_STAT_READ(stats, whichstat, val) {				\
	int bkt;							\
	for (val = 0, bkt = 0; bkt < LGRP_NUM_CPU_BUCKETS; bkt++)	\
		val += LGRP_STAT(stats, bkt, whichstat);		\
}

/* Reset all buckets for the stat to 0 */
#define	LGRP_STAT_RESET(stats, stat) {					\
	int i;								\
	for (i = 0; i < LGRP_NUM_CPU_BUCKETS; i++)			\
		LGRP_STAT(stats, i, stat) = 0;				\
}

/*
 * Define all of the statistics that are kept for lgrp kstats,
 * and their corresponding text names.
 */

typedef enum lgrp_stat_types {
	LGRP_NUM_MIGR,		/* # migrations away from this lgrp */
	LGRP_NUM_ALLOC_FAIL,	/* # times alloc fails for chosen lgrp */
	LGRP_PM_SRC_PGS,	/* # pages migrated from this lgrp */
	LGRP_PM_DEST_PGS,	/* # pages migrated to this lgrp */
	LGRP_PM_FAIL_ALLOC_PGS,	/* # pages failed to migrate to this lgrp */
	LGRP_PM_FAIL_LOCK_PGS,	/* # pages failed to migrate from this lgrp */
	LGRP_PMM_PGS,		/* # pages marked to migrate from this lgrp */
	LGRP_PMM_FAIL_PGS,	/* # pages marked to migrate from this lgrp */
	LGRP_NUM_DEFAULT,	/* # of times default policy applied */
	LGRP_NUM_NEXT,		/* # of times next touch policy applied */
	LGRP_NUM_RANDOM,	/* # of times random policy applied */
	LGRP_NUM_RANDOM_PROC,	/* # of times random proc policy applied */
	LGRP_NUM_RANDOM_PSET,	/* # of times random pset policy applied */
	LGRP_NUM_ROUNDROBIN,	/* # of times round robin policy applied */
	LGRP_NUM_NEXT_SEG,	/* # of times next to seg policy applied */
	LGRP_NUM_COUNTER_STATS,	/* always last */
	LGRP_CTR_STATS_ALLOC = 16	/* cache-align pad - multiple of 8 */
				/* always keep >= LGRP_NUM_COUNTER_STATS */
} lgrp_stat_t;

typedef enum lgrp_snap_stat_types {
	LGRP_NUM_CPUS,		/* number of CPUs */
	LGRP_NUM_PG_FREE,	/* # of free pages */
	LGRP_NUM_PG_AVAIL,	/* # of allocatable physical pages */
	LGRP_NUM_PG_INSTALL,	/* # of installed physical pages */
	LGRP_LOADAVG,		/* unscaled load average of this lgrp */
	LGRP_LOADAVG_SCALE,	/* load unit of one CPU bound thread */
	LGRP_NUM_SNAPSHOT_STATS	/* always last */
} lgrp_snap_stat_t;

#define	LGRP_KSTAT_NAMES		\
static char *lgrp_kstat_names[] = {	\
					\
	/* Counter stats */		\
	"lwp migrations",		\
	"alloc fail",			\
	"pages migrated from",		\
	"pages migrated to",		\
	"pages failed to migrate to",	\
	"pages failed to migrate from",	\
	"pages marked for migration",	\
	"pages failed to mark",		\
	"default policy",		\
	"next-touch policy",		\
	"random policy",		\
	"span process policy",		\
	"span psrset policy",		\
	"round robin policy",		\
	"next-seg policy",		\
					\
	/* Snapshot stats */		\
	"cpus",				\
	"pages free",			\
	"pages avail",			\
	"pages installed",		\
	"load average",			\
	"loadscale"			\
}

#define	LGRP_NUM_STATS	((int)LGRP_NUM_COUNTER_STATS +			\
	(int)LGRP_NUM_SNAPSHOT_STATS)

/*
 * The contents of this structure are opaque and should only be
 * accessed through the LGRP_STAT macro.
 */
struct lgrp_stats {
	int64_t ls_data[LGRP_NUM_CPU_BUCKETS][LGRP_CTR_STATS_ALLOC];
};

/* The kernel's version of a bitmap of lgroups */
typedef uint64_t klgrpset_t;

/*
 * This really belongs in memnode.h, but it must be defined here to avoid
 * recursive inclusion problems. Note that memnode.h includes this header.
 */
typedef	uint64_t	mnodeset_t;

/*
 * lgroup structure
 *
 * Visible to generic code and contains the lgroup ID, CPUs in this lgroup,
 * and a platform handle used to identify this lgroup to the lgroup platform
 * support code
 */
typedef struct lgrp {

	lgrp_id_t 	lgrp_id;	/* which lgroup	*/
	int		lgrp_latency;
	lgrp_handle_t  	lgrp_plathand;	/* handle for platform calls */
	struct lgrp	*lgrp_parent;	/* parent lgroup */
	uint_t		lgrp_reserved1;	/* filler */
	uint_t		lgrp_childcnt;	/* number of children lgroups */
	klgrpset_t	lgrp_children;	/* children lgroups */
	klgrpset_t	lgrp_leaves;	/* (direct decendant) leaf lgroups */

	/*
	 * set of lgroups containing a given type of resource
	 * at this level of locality
	 */
	klgrpset_t	lgrp_set[LGRP_RSRC_COUNT];

	mnodeset_t	lgrp_mnodes;	/* set of memory nodes in this lgroup */
	uint_t		lgrp_nmnodes;	/* number of memnodes */
	uint_t		lgrp_reserved2;	/* filler */

	struct cpu	*lgrp_cpu;	/* pointer to a cpu may be null */
	uint_t		lgrp_cpucnt;	/* number of cpus in this lgrp	*/
	kstat_t		*lgrp_kstat;	/* per-lgrp kstats */
} lgrp_t;

/*
 * lgroup load average structure
 */

typedef struct lgrp_ld {
	lgrp_load_t	lpl_loadavg;	/* load average		*/
	uint_t		lpl_ncpu;	/* how many cpus	*/
	lgrp_id_t	lpl_lgrpid;	/* which group this lpl part of */
	lgrp_t		*lpl_lgrp;	/* ptr to lpl's lgrp */
	struct lgrp_ld	*lpl_parent;	/* lpl of parent lgrp */
	struct cpu	*lpl_cpus;	/* list of cpus in lpl */
					/* NULL for non-leaf lgrps */
	uint_t		lpl_nrset;	/* no. of leaf lpls for lgrp */
	hrtime_t	lpl_homed_time;	/* time of last homing to this lpl */
	uint_t		lpl_rset_sz;	/* Resource set capacity */
	struct lgrp_ld	**lpl_rset;	/* leaf lpls for lgrp */
					/* contains ptr to self for leaf lgrp */
	int		*lpl_id2rset;	/* mapping of lgrpid to rset index */
} lpl_t;

/*
 * 1 << LGRP_MAX_EFFECT_SHFT ==  lgrp_loadavg_max_effect
 */
#define	LGRP_MAX_EFFECT_SHFT 16

/*
 * Operations handled by lgrp_config()
 */
typedef enum lgrp_config_flag {
	LGRP_CONFIG_NOP,
	LGRP_CONFIG_CPU_ADD,
	LGRP_CONFIG_CPU_DEL,
	LGRP_CONFIG_CPU_ONLINE,
	LGRP_CONFIG_CPU_OFFLINE,
	LGRP_CONFIG_CPUPART_ADD,
	LGRP_CONFIG_CPUPART_DEL,
	LGRP_CONFIG_MEM_ADD,
	LGRP_CONFIG_MEM_DEL,
	LGRP_CONFIG_MEM_RENAME,
	LGRP_CONFIG_GEN_UPDATE,
	LGRP_CONFIG_FLATTEN,
	LGRP_CONFIG_LAT_CHANGE_ALL,
	LGRP_CONFIG_LAT_CHANGE
} lgrp_config_flag_t;

/*
 * Stages of lgroup framework initialization (done through lgrp_init()):
 *
 * 1) Initialize common and platform specific code (called in mlsetup())
 *
 * 2) Setup root lgroup and add CPU 0 to lgroup(s) (called near beginning of
 *    main() before startup())
 *
 * 3) Probe from CPU 0 and copy and release any BOP_ALLOC-ed memory temporarily
 *    allocated before kernel memory allocator is setup (called in main()
 *    after startup(), gethrtime() is setup, and before interrupts enabled)
 *
 * 4) Check for null proc LPA on Starcat, collapse lgroup topology (if
 *    necessary), setup lgroup kstats, etc. (called before start_other_cpus())
 *
 * 5) Finish any lgroup initialization needed including updating lgroup
 *    topology after all CPUs started (called after start_other_cpus())
 */
typedef enum lgrp_init_stages {
	LGRP_INIT_STAGE1,
	LGRP_INIT_STAGE2,
	LGRP_INIT_STAGE3,
	LGRP_INIT_STAGE4,
	LGRP_INIT_STAGE5
} lgrp_init_stages_t;

/*
 * Memory allocation policies
 */
typedef enum lgrp_mem_policy {
	LGRP_MEM_POLICY_DEFAULT,
	LGRP_MEM_POLICY_NEXT,		/* near LWP to next touch */
	LGRP_MEM_POLICY_RANDOM_PROC,	/* randomly across process */
	LGRP_MEM_POLICY_RANDOM_PSET,	/* randomly across processor set */
	LGRP_MEM_POLICY_RANDOM,		/* randomly across all lgroups */
	LGRP_MEM_POLICY_ROUNDROBIN,	/* round robin across all lgroups */
	LGRP_MEM_POLICY_NEXT_CPU,	/* Near next CPU to touch memory */
	LGRP_MEM_POLICY_NEXT_SEG,	/* lgrp specified directly by seg */
	LGRP_NUM_MEM_POLICIES
} lgrp_mem_policy_t;

/*
 * Search scopes for finding resouces
 */
typedef	enum lgrp_res_ss {
	LGRP_SRCH_LOCAL,		/* Search local lgroup only */
	LGRP_SRCH_HIER			/* Search entire hierarchy */
} lgrp_res_ss_t;

/*
 * Cookie used for lgrp mnode selection
 */
typedef struct lgrp_mnode_cookie {
	lgrp_t		*lmc_lgrp;	/* lgrp under consideration */
	mnodeset_t	lmc_nodes;	/* nodes not yet tried in lgrp */
	int		lmc_cnt;	/* how many nodes in untried set */
	mnodeset_t	lmc_tried;	/* nodes already tried */
	int		lmc_ntried;	/* how many nodes in tried set */
	lgrp_res_ss_t	lmc_scope;	/* consider non-local nodes? */
	ushort_t	lmc_rand;	/* a "random" number */
} lgrp_mnode_cookie_t;

/*
 * Information needed to implement memory allocation policy
 */
typedef struct lgrp_mem_policy_info {
	int		mem_policy;		/* memory allocation policy */
	lgrp_id_t	mem_lgrpid;		/* lgroup id */
} lgrp_mem_policy_info_t;

/*
 * Shared memory policy segment
 */
typedef struct lgrp_shm_policy_seg {
	u_offset_t		shm_off;	/* offset into shared object */
	size_t			shm_size;	/* size of segment */
	lgrp_mem_policy_info_t	shm_policy;	/* memory allocation policy */
	avl_node_t		shm_tree;	/* AVL tree */
} lgrp_shm_policy_seg_t;

/*
 * Shared memory locality info
 */
typedef struct lgrp_shm_locality {
	size_t		loc_count;		/* reference count */
	avl_tree_t	*loc_tree;		/* policy segment tree */
	krwlock_t	loc_lock;		/* protects tree */
} lgrp_shm_locality_t;

/*
 * Queries that may be made to determine lgroup memory size
 */
typedef enum {
	LGRP_MEM_SIZE_FREE,		/* number of free pages */
	LGRP_MEM_SIZE_AVAIL,		/* number of pages in phys_avail */
	LGRP_MEM_SIZE_INSTALL		/* number of pages in phys_install */
} lgrp_mem_query_t;

/*
 * Argument for the memory copy-rename operation, contains the source and the
 * destination platform handles.
 */
typedef struct lgrp_config_mem_rename {
	lgrp_handle_t lmem_rename_from;
	lgrp_handle_t lmem_rename_to;
} lgrp_config_mem_rename_t;

/* Macro to clear an lgroup bitmap */
#define	klgrpset_clear(klgrpset) \
	(klgrpset) = (klgrpset_t)0

/* Macro to fill an lgroup bitmap */
#define	klgrpset_fill(klgrpset) \
	(klgrpset) = (klgrpset_t)(-1)

/* Macro to add an lgroup to an lgroup bitmap */
#define	klgrpset_add(klgrpset, lgrpid) \
	(klgrpset) |= ((klgrpset_t)1 << (lgrpid))

/* Macro to delete an lgroup from an lgroup bitmap */
#define	klgrpset_del(klgrpset, lgrpid) \
	(klgrpset) &= ~((klgrpset_t)1 << (lgrpid))

/* Macro to copy a klgrpset into another klgrpset */
#define	klgrpset_copy(klgrpset_to, klgrpset_from) \
	(klgrpset_to) = (klgrpset_from)

/* Macro to perform an 'and' operation on a pair of lgroup bitmaps */
#define	klgrpset_and(klgrpset_rslt, klgrpset_arg) \
	(klgrpset_rslt) &= (klgrpset_arg)

/* Macro to perform an 'or' operation on a pair of lgroup bitmaps */
#define	klgrpset_or(klgrpset_rslt, klgrpset_arg) \
	(klgrpset_rslt) |= (klgrpset_arg)

/* Macro to perform a 'diff' operation on a pair of lgroup bitmaps */
#define	klgrpset_diff(klgrpset_rslt, klgrpset_arg) \
	(klgrpset_rslt) &= ~(klgrpset_arg)

/* Macro to check if an lgroup is a member of an lgrpset */
#define	klgrpset_ismember(klgrpset, lgrpid) \
	((klgrpset) & ((klgrpset_t)1 << (lgrpid)))

/* Macro to check if an lgroup bitmap is empty */
#define	klgrpset_isempty(klgrpset) \
	((klgrpset) == (klgrpset_t)0)

/* Macro to check if two lgrpsets intersect */
#define	klgrpset_intersects(klgrpset1, klgrpset2) \
	((klgrpset1) & (klgrpset2))

/* Macro to count the number of members in an lgrpset */
#define	klgrpset_nlgrps(klgrpset, count)				\
{									\
	lgrp_id_t	lgrpid;						\
	for (lgrpid = 0, count = 0; lgrpid <= lgrp_alloc_max; lgrpid++) {\
		if (klgrpset_ismember(klgrpset, lgrpid))		\
			count++;					\
	}								\
}

/* Macro to get total memory size (in bytes) of a given set of lgroups */
#define	klgrpset_totalsize(klgrpset, size)				\
{									\
	lgrp_handle_t	hand;						\
	lgrp_id_t	lgrpid;						\
									\
	for (lgrpid = 0, size = 0; lgrpid <= lgrp_alloc_max; lgrpid++) {\
		if (klgrpset_ismember(klgrpset, lgrpid) &&		\
		    lgrp_table[lgrpid])	{				\
			hand = lgrp_table[lgrpid]->lgrp_plathand;	\
			size += lgrp_plat_mem_size(hand,		\
			    LGRP_MEM_SIZE_AVAIL) * PAGESIZE;		\
		}							\
	}								\
}

/*
 * Does this lgroup exist?
 */
#define	LGRP_EXISTS(lgrp)	\
	(lgrp != NULL && lgrp->lgrp_id != LGRP_NONE)

/*
 * Macro for testing if a CPU is contained in an lgrp.
 */
#define	LGRP_CONTAINS_CPU(lgrp, cpu)	\
	(klgrpset_ismember(lgrp->lgrp_set[LGRP_RSRC_CPU],	\
	    cpu->cpu_lpl->lpl_lgrpid))

/*
 * Initialize an lgrp_mnode_cookie
 */
#define	LGRP_MNODE_COOKIE_INIT(c, lgrp, scope)	\
{							\
	bzero(&(c), sizeof (lgrp_mnode_cookie_t));	\
	(&(c))->lmc_lgrp = lgrp;			\
	(&(c))->lmc_nodes = lgrp->lgrp_mnodes;		\
	(&(c))->lmc_cnt = lgrp->lgrp_nmnodes;		\
	(&(c))->lmc_scope = scope;			\
	(&(c))->lmc_rand = (ushort_t)gethrtime_unscaled() >> 4;	\
}

/*
 * Upgrade cookie scope from LGRP_SRCH_LOCAL to LGRP_SRCH_HIER.
 */
#define	LGRP_MNODE_COOKIE_UPGRADE(c)	\
{							\
	ASSERT((&(c))->lmc_scope == LGRP_SRCH_LOCAL);	\
	(&(c))->lmc_scope = LGRP_SRCH_HIER;		\
}

/*
 * Macro to see whether memory allocation policy can be reapplied
 */
#define	LGRP_MEM_POLICY_REAPPLICABLE(p) \
	(p == LGRP_MEM_POLICY_NEXT)

/*
 * Return true if lgrp has CPU resources in the cpupart
 */
#define	LGRP_CPUS_IN_PART(lgrpid, cpupart) \
	(cpupart->cp_lgrploads[lgrpid].lpl_ncpu > 0)

extern int	lgrp_alloc_max;
extern lgrp_t	*lgrp_table[NLGRPS_MAX];	/* indexed by lgrp_id */
extern int		nlgrps;		/* number of lgroups in machine */
extern int		nlgrpsmax;	/* max number of lgroups on platform */
extern lgrp_gen_t	lgrp_gen;	/* generation of lgroup hierarchy */
extern int		lgrp_initialized; /* single-CPU initialization done */
extern int		lgrp_topo_initialized; /* lgrp topology constructed */
extern lgrp_t		*lgrp_root;	/* root lgroup */
extern unsigned int	lgrp_topo_levels;
extern lpl_t		*lpl_bootstrap;	/* bootstrap lpl for non-active CPUs */


/* generic interfaces */

/*
 * lgroup management
 */
int	lgrp_optimizations(void);
void	lgrp_init(lgrp_init_stages_t);
lgrp_t	*lgrp_create(void);
void	lgrp_destroy(lgrp_t *);
void	lgrp_config(lgrp_config_flag_t, uintptr_t, uintptr_t);
lgrp_t	*lgrp_hand_to_lgrp(lgrp_handle_t);

/*
 * lgroup stats
 */
void	lgrp_kstat_create(struct cpu *);
void	lgrp_kstat_destroy(struct cpu *);
void	lgrp_stat_add(lgrp_id_t, lgrp_stat_t, int64_t);
int64_t lgrp_stat_read(lgrp_id_t, lgrp_stat_t);

/*
 * lgroup memory
 */
lgrp_mem_policy_t	lgrp_madv_to_policy(uchar_t, size_t, int);
pgcnt_t	lgrp_mem_size(lgrp_id_t, lgrp_mem_query_t);
lgrp_t	*lgrp_mem_choose(struct seg *, caddr_t, size_t);
int	lgrp_memnode_choose(lgrp_mnode_cookie_t *);
lgrp_mem_policy_t	lgrp_mem_policy_default(size_t, int);
int	lgrp_mnode_update(klgrpset_t, klgrpset_t *);
lgrp_t	*lgrp_pfn_to_lgrp(pfn_t);
lgrp_t	*lgrp_phys_to_lgrp(u_longlong_t);	/* used by numat driver */
int	lgrp_privm_policy_set(lgrp_mem_policy_t, lgrp_mem_policy_info_t *,
    size_t);
void	lgrp_shm_policy_init(struct anon_map *, vnode_t *);
void	lgrp_shm_policy_fini(struct anon_map *, vnode_t *);
lgrp_mem_policy_info_t	*lgrp_shm_policy_get(struct anon_map *, ulong_t,
    vnode_t *, u_offset_t);
int	lgrp_shm_policy_set(lgrp_mem_policy_t, struct anon_map *, ulong_t,
    vnode_t *, u_offset_t, size_t);

/*
 * Used by numat driver
 */
int	lgrp_query_cpu(processorid_t, lgrp_id_t *);
int	lgrp_query_load(processorid_t, lgrp_load_t *);

/*
 * lgroup thread placement
 */
lpl_t	*lgrp_affinity_best(kthread_t *, struct cpupart *, lgrp_id_t,
    boolean_t);
void	lgrp_affinity_init(lgrp_affinity_t **);
void	lgrp_affinity_free(lgrp_affinity_t **);
lpl_t	*lgrp_choose(kthread_t *t, struct cpupart *);
lgrp_t	*lgrp_home_lgrp(void);
lgrp_id_t	lgrp_home_id(kthread_t *);
void	lgrp_loadavg(lpl_t *, uint_t, int);
void	lgrp_move_thread(kthread_t *, lpl_t *, int);
uint64_t lgrp_get_trthr_migrations(void);
void 	lgrp_update_trthr_migrations(uint64_t);

/*
 * lgroup topology
 */
int	lgrp_leaf_add(lgrp_t *, lgrp_t **, int, klgrpset_t *);
int	lgrp_leaf_delete(lgrp_t *, lgrp_t **, int, klgrpset_t *);
int	lgrp_rsets_empty(klgrpset_t *);
int	lgrp_rsets_member(klgrpset_t *, lgrp_id_t);
int	lgrp_topo_flatten(int, lgrp_t **, int, klgrpset_t *);
int	lgrp_topo_ht_limit(void);
int	lgrp_topo_ht_limit_default(void);
int	lgrp_topo_ht_limit_set(int);
int	lgrp_topo_update(lgrp_t **, int, klgrpset_t *);

/*
 * lpl topology
 */
void	lpl_topo_bootstrap(lpl_t *, int);
int	lpl_topo_flatten(int);
int	lpl_topo_verify(struct cpupart *);


/* platform interfaces */
void	lgrp_plat_init(lgrp_init_stages_t);
lgrp_t	*lgrp_plat_alloc(lgrp_id_t lgrpid);
void	lgrp_plat_config(lgrp_config_flag_t, uintptr_t);
lgrp_handle_t	lgrp_plat_cpu_to_hand(processorid_t);
lgrp_handle_t	lgrp_plat_pfn_to_hand(pfn_t);
int	lgrp_plat_max_lgrps(void);
pgcnt_t	lgrp_plat_mem_size(lgrp_handle_t, lgrp_mem_query_t);
int	lgrp_plat_latency(lgrp_handle_t, lgrp_handle_t);
lgrp_handle_t	lgrp_plat_root_hand(void);

extern uint32_t		lgrp_expand_proc_thresh;
extern uint32_t		lgrp_expand_proc_diff;
extern pgcnt_t		lgrp_mem_free_thresh;
extern uint32_t		lgrp_loadavg_tolerance;
extern uint32_t		lgrp_loadavg_max_effect;
extern uint32_t		lgrp_load_thresh;
extern lgrp_mem_policy_t lgrp_mem_policy_root;

#endif	/* _KERNEL || _FAKE_KERNEL || _KMEMUSER */

#ifdef	__cplusplus
}
#endif

#endif /* _LGRP_H */

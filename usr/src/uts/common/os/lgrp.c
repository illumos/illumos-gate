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
 */

/*
 * Basic NUMA support in terms of locality groups
 *
 * Solaris needs to know which CPUs, memory, etc. are near each other to
 * provide good performance on NUMA machines by optimizing for locality.
 * In order to do this, a new abstraction called a "locality group (lgroup)"
 * has been introduced to keep track of which CPU-like and memory-like hardware
 * resources are close to each other.  Currently, latency is the only measure
 * used to determine how to group hardware resources into lgroups, but this
 * does not limit the groupings to be based solely on latency.  Other factors
 * may be used to determine the groupings in the future.
 *
 * Lgroups are organized into a hieararchy or topology that represents the
 * latency topology of the machine.  There is always at least a root lgroup in
 * the system.  It represents all the hardware resources in the machine at a
 * latency big enough that any hardware resource can at least access any other
 * hardware resource within that latency.  A Uniform Memory Access (UMA)
 * machine is represented with one lgroup (the root).  In contrast, a NUMA
 * machine is represented at least by the root lgroup and some number of leaf
 * lgroups where the leaf lgroups contain the hardware resources within the
 * least latency of each other and the root lgroup still contains all the
 * resources in the machine.  Some number of intermediate lgroups may exist
 * which represent more levels of locality than just the local latency of the
 * leaf lgroups and the system latency of the root lgroup.  Non-leaf lgroups
 * (eg. root and intermediate lgroups) contain the next nearest resources to
 * its children lgroups.  Thus, the lgroup hierarchy from a given leaf lgroup
 * to the root lgroup shows the hardware resources from closest to farthest
 * from the leaf lgroup such that each successive ancestor lgroup contains
 * the next nearest resources at the next level of locality from the previous.
 *
 * The kernel uses the lgroup abstraction to know how to allocate resources
 * near a given process/thread.  At fork() and lwp/thread_create() time, a
 * "home" lgroup is chosen for a thread.  This is done by picking the lgroup
 * with the lowest load average.  Binding to a processor or processor set will
 * change the home lgroup for a thread.  The scheduler has been modified to try
 * to dispatch a thread on a CPU in its home lgroup.  Physical memory
 * allocation is lgroup aware too, so memory will be allocated from the current
 * thread's home lgroup if possible.  If the desired resources are not
 * available, the kernel traverses the lgroup hierarchy going to the parent
 * lgroup to find resources at the next level of locality until it reaches the
 * root lgroup.
 */

#include <sys/lgrp.h>
#include <sys/lgrp_user.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/var.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/cpupart.h>
#include <sys/kmem.h>
#include <vm/seg.h>
#include <vm/seg_kmem.h>
#include <vm/seg_spt.h>
#include <vm/seg_vn.h>
#include <vm/as.h>
#include <sys/atomic.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/kstat.h>
#include <sys/sysmacros.h>
#include <sys/pg.h>
#include <sys/promif.h>
#include <sys/sdt.h>

lgrp_gen_t	lgrp_gen = 0;		/* generation of lgroup hierarchy */
lgrp_t *lgrp_table[NLGRPS_MAX]; /* table of all initialized lgrp_t structs */
				/* indexed by lgrp_id */
int	nlgrps;			/* number of lgroups in machine */
int	lgrp_alloc_hint = -1;	/* hint for where to try to allocate next */
int	lgrp_alloc_max = 0;	/* max lgroup ID allocated so far */

/*
 * Kstat data for lgroups.
 *
 * Actual kstat data is collected in lgrp_stats array.
 * The lgrp_kstat_data array of named kstats is used to extract data from
 * lgrp_stats and present it to kstat framework. It is protected from partallel
 * modifications by lgrp_kstat_mutex. This may cause some contention when
 * several kstat commands run in parallel but this is not the
 * performance-critical path.
 */
extern struct lgrp_stats lgrp_stats[];	/* table of per-lgrp stats */

/*
 * Declare kstat names statically for enums as defined in the header file.
 */
LGRP_KSTAT_NAMES;

static void	lgrp_kstat_init(void);
static int	lgrp_kstat_extract(kstat_t *, int);
static void	lgrp_kstat_reset(lgrp_id_t);

static struct kstat_named lgrp_kstat_data[LGRP_NUM_STATS];
static kmutex_t lgrp_kstat_mutex;


/*
 * max number of lgroups supported by the platform
 */
int	nlgrpsmax = 0;

/*
 * The root lgroup. Represents the set of resources at the system wide
 * level of locality.
 */
lgrp_t		*lgrp_root = NULL;

/*
 * During system bootstrap cp_default does not contain the list of lgrp load
 * averages (cp_lgrploads). The list is allocated after the first CPU is brought
 * on-line when cp_default is initialized by cpupart_initialize_default().
 * Configuring CPU0 may create a two-level topology with root and one leaf node
 * containing CPU0. This topology is initially constructed in a special
 * statically allocated 2-element lpl list lpl_bootstrap_list and later cloned
 * to cp_default when cp_default is initialized. The lpl_bootstrap_list is used
 * for all lpl operations until cp_default is fully constructed.
 *
 * The lpl_bootstrap_list is maintained by the code in lgrp.c. Every other
 * consumer who needs default lpl should use lpl_bootstrap which is a pointer to
 * the first element of lpl_bootstrap_list.
 *
 * CPUs that are added to the system, but have not yet been assigned to an
 * lgrp will use lpl_bootstrap as a default lpl. This is necessary because
 * on some architectures (x86) it's possible for the slave CPU startup thread
 * to enter the dispatcher or allocate memory before calling lgrp_cpu_init().
 */
#define	LPL_BOOTSTRAP_SIZE 2
static lpl_t	lpl_bootstrap_list[LPL_BOOTSTRAP_SIZE];
lpl_t		*lpl_bootstrap;
static lpl_t	*lpl_bootstrap_rset[LPL_BOOTSTRAP_SIZE];
static int	lpl_bootstrap_id2rset[LPL_BOOTSTRAP_SIZE];

/*
 * If cp still references the bootstrap lpl, it has not yet been added to
 * an lgrp. lgrp_mem_choose() uses this macro to detect the case where
 * a thread is trying to allocate memory close to a CPU that has no lgrp.
 */
#define	LGRP_CPU_HAS_NO_LGRP(cp)	((cp)->cpu_lpl == lpl_bootstrap)

static lgrp_t	lroot;

/*
 * Size, in bytes, beyond which random memory allocation policy is applied
 * to non-shared memory.  Default is the maximum size, so random memory
 * allocation won't be used for non-shared memory by default.
 */
size_t	lgrp_privm_random_thresh = (size_t)(-1);

/* the maximum effect that a single thread can have on it's lgroup's load */
#define	LGRP_LOADAVG_MAX_EFFECT(ncpu) \
	((lgrp_loadavg_max_effect) / (ncpu))
uint32_t	lgrp_loadavg_max_effect = LGRP_LOADAVG_THREAD_MAX;


/*
 * Size, in bytes, beyond which random memory allocation policy is applied to
 * shared memory.  Default is 8MB (2 ISM pages).
 */
size_t	lgrp_shm_random_thresh = 8*1024*1024;

/*
 * Whether to do processor set aware memory allocation by default
 */
int	lgrp_mem_pset_aware = 0;

/*
 * Set the default memory allocation policy for root lgroup
 */
lgrp_mem_policy_t	lgrp_mem_policy_root = LGRP_MEM_POLICY_RANDOM;

/*
 * Set the default memory allocation policy.  For most platforms,
 * next touch is sufficient, but some platforms may wish to override
 * this.
 */
lgrp_mem_policy_t	lgrp_mem_default_policy = LGRP_MEM_POLICY_NEXT;


/*
 * lgroup CPU event handlers
 */
static void	lgrp_cpu_init(struct cpu *);
static void	lgrp_cpu_fini(struct cpu *, lgrp_id_t);
static lgrp_t	*lgrp_cpu_to_lgrp(struct cpu *);

/*
 * lgroup memory event handlers
 */
static void	lgrp_mem_init(int, lgrp_handle_t, boolean_t);
static void	lgrp_mem_fini(int, lgrp_handle_t, boolean_t);
static void	lgrp_mem_rename(int, lgrp_handle_t, lgrp_handle_t);

/*
 * lgroup CPU partition event handlers
 */
static void	lgrp_part_add_cpu(struct cpu *, lgrp_id_t);
static void	lgrp_part_del_cpu(struct cpu *);

/*
 * lgroup framework initialization
 */
static void	lgrp_main_init(void);
static void	lgrp_main_mp_init(void);
static void	lgrp_root_init(void);
static void	lgrp_setup(void);

/*
 * lpl topology
 */
static void	lpl_init(lpl_t *, lpl_t *, lgrp_t *);
static void	lpl_clear(lpl_t *);
static void	lpl_leaf_insert(lpl_t *, struct cpupart *);
static void	lpl_leaf_remove(lpl_t *, struct cpupart *);
static void	lpl_rset_add(lpl_t *, lpl_t *);
static void	lpl_rset_del(lpl_t *, lpl_t *);
static int	lpl_rset_contains(lpl_t *, lpl_t *);
static void	lpl_cpu_adjcnt(lpl_act_t, struct cpu *);
static void	lpl_child_update(lpl_t *, struct cpupart *);
static int	lpl_pick(lpl_t *, lpl_t *);
static void	lpl_verify_wrapper(struct cpupart *);

/*
 * defines for lpl topology verifier return codes
 */

#define	LPL_TOPO_CORRECT			0
#define	LPL_TOPO_PART_HAS_NO_LPL		-1
#define	LPL_TOPO_CPUS_NOT_EMPTY			-2
#define	LPL_TOPO_LGRP_MISMATCH			-3
#define	LPL_TOPO_MISSING_PARENT			-4
#define	LPL_TOPO_PARENT_MISMATCH		-5
#define	LPL_TOPO_BAD_CPUCNT			-6
#define	LPL_TOPO_RSET_MISMATCH			-7
#define	LPL_TOPO_LPL_ORPHANED			-8
#define	LPL_TOPO_LPL_BAD_NCPU			-9
#define	LPL_TOPO_RSET_MSSNG_LF			-10
#define	LPL_TOPO_CPU_HAS_BAD_LPL		-11
#define	LPL_TOPO_NONLEAF_HAS_CPUS		-12
#define	LPL_TOPO_LGRP_NOT_LEAF			-13
#define	LPL_TOPO_BAD_RSETCNT			-14

/*
 * Return whether lgroup optimizations should be enabled on this system
 */
int
lgrp_optimizations(void)
{
	/*
	 * System must have more than 2 lgroups to enable lgroup optimizations
	 *
	 * XXX This assumes that a 2 lgroup system has an empty root lgroup
	 * with one child lgroup containing all the resources. A 2 lgroup
	 * system with a root lgroup directly containing CPUs or memory might
	 * need lgroup optimizations with its child lgroup, but there
	 * isn't such a machine for now....
	 */
	if (nlgrps > 2)
		return (1);

	return (0);
}

/*
 * Setup root lgroup
 */
static void
lgrp_root_init(void)
{
	lgrp_handle_t	hand;
	int		i;
	lgrp_id_t	id;

	/*
	 * Create the "root" lgroup
	 */
	ASSERT(nlgrps == 0);
	id = nlgrps++;

	lgrp_root = &lroot;

	lgrp_root->lgrp_cpu = NULL;
	lgrp_root->lgrp_mnodes = 0;
	lgrp_root->lgrp_nmnodes = 0;
	hand = lgrp_plat_root_hand();
	lgrp_root->lgrp_plathand = hand;

	lgrp_root->lgrp_id = id;
	lgrp_root->lgrp_cpucnt = 0;
	lgrp_root->lgrp_childcnt = 0;
	klgrpset_clear(lgrp_root->lgrp_children);
	klgrpset_clear(lgrp_root->lgrp_leaves);
	lgrp_root->lgrp_parent = NULL;
	lgrp_root->lgrp_latency = lgrp_plat_latency(hand, hand);

	for (i = 0; i < LGRP_RSRC_COUNT; i++)
		klgrpset_clear(lgrp_root->lgrp_set[i]);

	lgrp_root->lgrp_kstat = NULL;

	lgrp_table[id] = lgrp_root;

	/*
	 * Setup initial lpl list for CPU0 and initial t0 home.
	 * The only lpl space we have so far is lpl_bootstrap. It is used for
	 * all topology operations until cp_default is initialized at which
	 * point t0.t_lpl will be updated.
	 */
	lpl_bootstrap = lpl_bootstrap_list;
	t0.t_lpl = lpl_bootstrap;
	cp_default.cp_nlgrploads = LPL_BOOTSTRAP_SIZE;
	lpl_bootstrap_list[1].lpl_lgrpid = 1;

	/*
	 * Set up the bootstrap rset
	 * Since the bootstrap toplogy has just the root, and a leaf,
	 * the rset contains just the leaf, and both lpls can use the same rset
	 */
	lpl_bootstrap_rset[0] = &lpl_bootstrap_list[1];
	lpl_bootstrap_list[0].lpl_rset_sz = 1;
	lpl_bootstrap_list[0].lpl_rset = lpl_bootstrap_rset;
	lpl_bootstrap_list[0].lpl_id2rset = lpl_bootstrap_id2rset;

	lpl_bootstrap_list[1].lpl_rset_sz = 1;
	lpl_bootstrap_list[1].lpl_rset = lpl_bootstrap_rset;
	lpl_bootstrap_list[1].lpl_id2rset = lpl_bootstrap_id2rset;

	cp_default.cp_lgrploads = lpl_bootstrap;
}

/*
 * Initialize the lgroup framework and allow the platform to do the same
 *
 * This happens in stages during boot and is all funnelled through this routine
 * (see definition of lgrp_init_stages_t to see what happens at each stage and
 * when)
 */
void
lgrp_init(lgrp_init_stages_t stage)
{
	/*
	 * Initialize the platform
	 */
	lgrp_plat_init(stage);

	switch (stage) {
	case LGRP_INIT_STAGE1:
		/*
		 * Set max number of lgroups supported on this platform which
		 * must be less than the max number of lgroups supported by the
		 * common lgroup framework (eg. NLGRPS_MAX is max elements in
		 * lgrp_table[], etc.)
		 */
		nlgrpsmax = lgrp_plat_max_lgrps();
		ASSERT(nlgrpsmax <= NLGRPS_MAX);
		break;

	case LGRP_INIT_STAGE2:
		lgrp_setup();
		break;

	case LGRP_INIT_STAGE4:
		lgrp_main_init();
		break;

	case LGRP_INIT_STAGE5:
		lgrp_main_mp_init();
		break;

	default:
		break;
	}
}

/*
 * Create the root and cpu0's lgroup, and set t0's home.
 */
static void
lgrp_setup(void)
{
	/*
	 * Setup the root lgroup
	 */
	lgrp_root_init();

	/*
	 * Add cpu0 to an lgroup
	 */
	lgrp_config(LGRP_CONFIG_CPU_ADD, (uintptr_t)CPU, 0);
	lgrp_config(LGRP_CONFIG_CPU_ONLINE, (uintptr_t)CPU, 0);
}

/*
 * true when lgrp initialization has been completed.
 */
int	lgrp_initialized = 0;

/*
 * True when lgrp topology is constructed.
 */
int	lgrp_topo_initialized = 0;

/*
 * Init routine called after startup(), /etc/system has been processed,
 * and cpu0 has been added to an lgroup.
 */
static void
lgrp_main_init(void)
{
	cpu_t		*cp = CPU;
	lgrp_id_t	lgrpid;
	int		i;
	extern void	pg_cpu0_reinit();

	/*
	 * Enforce a valid lgrp_mem_default_policy
	 */
	if ((lgrp_mem_default_policy <= LGRP_MEM_POLICY_DEFAULT) ||
	    (lgrp_mem_default_policy >= LGRP_NUM_MEM_POLICIES) ||
	    (lgrp_mem_default_policy == LGRP_MEM_POLICY_NEXT_SEG))
		lgrp_mem_default_policy = LGRP_MEM_POLICY_NEXT;

	/*
	 * See if mpo should be disabled.
	 * This may happen in the case of null proc LPA on Starcat.
	 * The platform won't be able to detect null proc LPA until after
	 * cpu0 and memory have already been added to lgroups.
	 * When and if it is detected, the Starcat platform will return
	 * a different platform handle for cpu0 which is what we check for
	 * here. If mpo should be disabled move cpu0 to it's rightful place
	 * (the root), and destroy the remaining lgroups. This effectively
	 * provides an UMA lgroup topology.
	 */
	lgrpid = cp->cpu_lpl->lpl_lgrpid;
	if (lgrp_table[lgrpid]->lgrp_plathand !=
	    lgrp_plat_cpu_to_hand(cp->cpu_id)) {
		lgrp_part_del_cpu(cp);
		lgrp_cpu_fini(cp, lgrpid);

		lgrp_cpu_init(cp);
		lgrp_part_add_cpu(cp, cp->cpu_lpl->lpl_lgrpid);

		ASSERT(cp->cpu_lpl->lpl_lgrpid == LGRP_ROOTID);

		/*
		 * Notify the PG subsystem that the CPU's lgrp
		 * association has changed
		 */
		pg_cpu0_reinit();

		/*
		 * Destroy all lgroups except for root
		 */
		for (i = 0; i <= lgrp_alloc_max; i++) {
			if (LGRP_EXISTS(lgrp_table[i]) &&
			    lgrp_table[i] != lgrp_root)
				lgrp_destroy(lgrp_table[i]);
		}

		/*
		 * Fix up root to point at itself for leaves and resources
		 * and not have any children
		 */
		lgrp_root->lgrp_childcnt = 0;
		klgrpset_clear(lgrp_root->lgrp_children);
		klgrpset_clear(lgrp_root->lgrp_leaves);
		klgrpset_add(lgrp_root->lgrp_leaves, LGRP_ROOTID);
		klgrpset_clear(lgrp_root->lgrp_set[LGRP_RSRC_MEM]);
		klgrpset_add(lgrp_root->lgrp_set[LGRP_RSRC_MEM], LGRP_ROOTID);
	}

	/*
	 * Initialize kstats framework.
	 */
	lgrp_kstat_init();
	/*
	 * cpu0 is finally where it should be, so create it's lgroup's kstats
	 */
	mutex_enter(&cpu_lock);
	lgrp_kstat_create(cp);
	mutex_exit(&cpu_lock);

	lgrp_initialized = 1;
}

/*
 * Finish lgrp initialization after all CPUS are brought on-line.
 * This routine is called after start_other_cpus().
 */
static void
lgrp_main_mp_init(void)
{
	klgrpset_t changed;

	/*
	 * Update lgroup topology (if necessary)
	 */
	klgrpset_clear(changed);
	(void) lgrp_topo_update(lgrp_table, lgrp_alloc_max + 1, &changed);
	lgrp_topo_initialized = 1;
}

/*
 * Change latency of lgroup with specified lgroup platform handle (if one is
 * given) or change all lgroups with old latency to new latency
 */
void
lgrp_latency_change(lgrp_handle_t hand, u_longlong_t oldtime,
    u_longlong_t newtime)
{
	lgrp_t		*lgrp;
	int		i;

	for (i = 0; i <= lgrp_alloc_max; i++) {
		lgrp = lgrp_table[i];

		if (!LGRP_EXISTS(lgrp))
			continue;

		if ((hand == LGRP_NULL_HANDLE &&
		    lgrp->lgrp_latency == oldtime) ||
		    (hand != LGRP_NULL_HANDLE && lgrp->lgrp_plathand == hand))
			lgrp->lgrp_latency = (int)newtime;
	}
}

/*
 * Handle lgroup (re)configuration events (eg. addition of CPU, etc.)
 */
void
lgrp_config(lgrp_config_flag_t event, uintptr_t resource, uintptr_t where)
{
	klgrpset_t	changed;
	cpu_t		*cp;
	lgrp_id_t	id;
	int		rc;

	switch (event) {
	/*
	 * The following (re)configuration events are common code
	 * initiated. lgrp_plat_config() is called here to inform the
	 * platform of the reconfiguration event.
	 */
	case LGRP_CONFIG_CPU_ADD:
		cp = (cpu_t *)resource;

		/*
		 * Initialize the new CPU's lgrp related next/prev
		 * links, and give it a bootstrap lpl so that it can
		 * survive should it need to enter the dispatcher.
		 */
		cp->cpu_next_lpl = cp;
		cp->cpu_prev_lpl = cp;
		cp->cpu_next_lgrp = cp;
		cp->cpu_prev_lgrp = cp;
		cp->cpu_lpl = lpl_bootstrap;

		lgrp_plat_config(event, resource);
		atomic_inc_32(&lgrp_gen);

		break;
	case LGRP_CONFIG_CPU_DEL:
		lgrp_plat_config(event, resource);
		atomic_inc_32(&lgrp_gen);

		break;
	case LGRP_CONFIG_CPU_ONLINE:
		cp = (cpu_t *)resource;
		lgrp_cpu_init(cp);
		lgrp_part_add_cpu(cp, cp->cpu_lpl->lpl_lgrpid);
		rc = lpl_topo_verify(cp->cpu_part);
		if (rc != LPL_TOPO_CORRECT) {
			panic("lpl_topo_verify failed: %d", rc);
		}
		lgrp_plat_config(event, resource);
		atomic_inc_32(&lgrp_gen);

		break;
	case LGRP_CONFIG_CPU_OFFLINE:
		cp = (cpu_t *)resource;
		id = cp->cpu_lpl->lpl_lgrpid;
		lgrp_part_del_cpu(cp);
		lgrp_cpu_fini(cp, id);
		rc = lpl_topo_verify(cp->cpu_part);
		if (rc != LPL_TOPO_CORRECT) {
			panic("lpl_topo_verify failed: %d", rc);
		}
		lgrp_plat_config(event, resource);
		atomic_inc_32(&lgrp_gen);

		break;
	case LGRP_CONFIG_CPUPART_ADD:
		cp = (cpu_t *)resource;
		lgrp_part_add_cpu((cpu_t *)resource, (lgrp_id_t)where);
		rc = lpl_topo_verify(cp->cpu_part);
		if (rc != LPL_TOPO_CORRECT) {
			panic("lpl_topo_verify failed: %d", rc);
		}
		lgrp_plat_config(event, resource);

		break;
	case LGRP_CONFIG_CPUPART_DEL:
		cp = (cpu_t *)resource;
		lgrp_part_del_cpu((cpu_t *)resource);
		rc = lpl_topo_verify(cp->cpu_part);
		if (rc != LPL_TOPO_CORRECT) {
			panic("lpl_topo_verify failed: %d", rc);
		}
		lgrp_plat_config(event, resource);

		break;
	/*
	 * The following events are initiated by the memnode
	 * subsystem.
	 */
	case LGRP_CONFIG_MEM_ADD:
		lgrp_mem_init((int)resource, where, B_FALSE);
		atomic_inc_32(&lgrp_gen);

		break;
	case LGRP_CONFIG_MEM_DEL:
		lgrp_mem_fini((int)resource, where, B_FALSE);
		atomic_inc_32(&lgrp_gen);

		break;
	case LGRP_CONFIG_MEM_RENAME: {
		lgrp_config_mem_rename_t *ren_arg =
		    (lgrp_config_mem_rename_t *)where;

		lgrp_mem_rename((int)resource,
		    ren_arg->lmem_rename_from,
		    ren_arg->lmem_rename_to);
		atomic_inc_32(&lgrp_gen);

		break;
	}
	case LGRP_CONFIG_GEN_UPDATE:
		atomic_inc_32(&lgrp_gen);

		break;
	case LGRP_CONFIG_FLATTEN:
		if (where == 0)
			lgrp_topo_levels = (int)resource;
		else
			(void) lgrp_topo_flatten(resource,
			    lgrp_table, lgrp_alloc_max, &changed);

		break;
	/*
	 * Update any lgroups with old latency to new latency
	 */
	case LGRP_CONFIG_LAT_CHANGE_ALL:
		lgrp_latency_change(LGRP_NULL_HANDLE, (u_longlong_t)resource,
		    (u_longlong_t)where);

		break;
	/*
	 * Update lgroup with specified lgroup platform handle to have
	 * new latency
	 */
	case LGRP_CONFIG_LAT_CHANGE:
		lgrp_latency_change((lgrp_handle_t)resource, 0,
		    (u_longlong_t)where);

		break;
	case LGRP_CONFIG_NOP:

		break;
	default:
		break;
	}

}

/*
 * Called to add lgrp info into cpu structure from cpu_add_unit;
 * do not assume cpu is in cpu[] yet!
 *
 * CPUs are brought online with all other CPUs paused so we can't
 * allocate memory or we could deadlock the system, so we rely on
 * the platform to statically allocate as much space as we need
 * for the lgrp structs and stats.
 */
static void
lgrp_cpu_init(struct cpu *cp)
{
	klgrpset_t	changed;
	int		count;
	lgrp_handle_t	hand;
	int		first_cpu;
	lgrp_t		*my_lgrp;
	lgrp_id_t	lgrpid;
	struct cpu	*cptr;

	/*
	 * This is the first time through if the resource set
	 * for the root lgroup is empty. After cpu0 has been
	 * initially added to an lgroup, the root's CPU resource
	 * set can never be empty, since the system's last CPU
	 * cannot be offlined.
	 */
	if (klgrpset_isempty(lgrp_root->lgrp_set[LGRP_RSRC_CPU])) {
		/*
		 * First time through.
		 */
		first_cpu = 1;
	} else {
		/*
		 * If cpu0 needs to move lgroups, we may come
		 * through here again, at which time cpu_lock won't
		 * be held, and lgrp_initialized will be false.
		 */
		ASSERT(MUTEX_HELD(&cpu_lock) || !lgrp_initialized);
		ASSERT(cp->cpu_part != NULL);
		first_cpu = 0;
	}

	hand = lgrp_plat_cpu_to_hand(cp->cpu_id);
	my_lgrp = lgrp_hand_to_lgrp(hand);

	if (my_lgrp == NULL) {
		/*
		 * Create new lgrp and add it to lgroup topology
		 */
		my_lgrp = lgrp_create();
		my_lgrp->lgrp_plathand = hand;
		my_lgrp->lgrp_latency = lgrp_plat_latency(hand, hand);
		lgrpid = my_lgrp->lgrp_id;
		klgrpset_add(my_lgrp->lgrp_leaves, lgrpid);
		klgrpset_add(my_lgrp->lgrp_set[LGRP_RSRC_CPU], lgrpid);

		count = 0;
		klgrpset_clear(changed);
		count += lgrp_leaf_add(my_lgrp, lgrp_table, lgrp_alloc_max + 1,
		    &changed);
		/*
		 * May have added new intermediate lgroups, so need to add
		 * resources other than CPUs which are added below
		 */
		(void) lgrp_mnode_update(changed, NULL);
	} else if (my_lgrp->lgrp_latency == 0 && lgrp_plat_latency(hand, hand)
	    > 0) {
		/*
		 * Leaf lgroup was created, but latency wasn't available
		 * then.  So, set latency for it and fill in rest of lgroup
		 * topology  now that we know how far it is from other leaf
		 * lgroups.
		 */
		lgrpid = my_lgrp->lgrp_id;
		klgrpset_clear(changed);
		if (!klgrpset_ismember(my_lgrp->lgrp_set[LGRP_RSRC_CPU],
		    lgrpid))
			klgrpset_add(my_lgrp->lgrp_set[LGRP_RSRC_CPU], lgrpid);
		count = lgrp_leaf_add(my_lgrp, lgrp_table, lgrp_alloc_max + 1,
		    &changed);

		/*
		 * May have added new intermediate lgroups, so need to add
		 * resources other than CPUs which are added below
		 */
		(void) lgrp_mnode_update(changed, NULL);
	} else if (!klgrpset_ismember(my_lgrp->lgrp_set[LGRP_RSRC_CPU],
	    my_lgrp->lgrp_id)) {
		int	i;

		/*
		 * Update existing lgroup and lgroups containing it with CPU
		 * resource
		 */
		lgrpid = my_lgrp->lgrp_id;
		klgrpset_add(my_lgrp->lgrp_set[LGRP_RSRC_CPU], lgrpid);
		for (i = 0; i <= lgrp_alloc_max; i++) {
			lgrp_t		*lgrp;

			lgrp = lgrp_table[i];
			if (!LGRP_EXISTS(lgrp) ||
			    !lgrp_rsets_member(lgrp->lgrp_set, lgrpid))
				continue;

			klgrpset_add(lgrp->lgrp_set[LGRP_RSRC_CPU], lgrpid);
		}
	}

	lgrpid = my_lgrp->lgrp_id;
	cp->cpu_lpl = &cp->cpu_part->cp_lgrploads[lgrpid];

	/*
	 * For multi-lgroup systems, need to setup lpl for CPU0 or CPU0 will
	 * end up in lpl for lgroup 0 whether it is supposed to be in there or
	 * not since none of lgroup IDs in the lpl's have been set yet.
	 */
	if (first_cpu && nlgrpsmax > 1 && lgrpid != cp->cpu_lpl->lpl_lgrpid)
		cp->cpu_lpl->lpl_lgrpid = lgrpid;

	/*
	 * link the CPU into the lgrp's CPU list
	 */
	if (my_lgrp->lgrp_cpucnt == 0) {
		my_lgrp->lgrp_cpu = cp;
		cp->cpu_next_lgrp = cp->cpu_prev_lgrp = cp;
	} else {
		cptr = my_lgrp->lgrp_cpu;
		cp->cpu_next_lgrp = cptr;
		cp->cpu_prev_lgrp = cptr->cpu_prev_lgrp;
		cptr->cpu_prev_lgrp->cpu_next_lgrp = cp;
		cptr->cpu_prev_lgrp = cp;
	}
	my_lgrp->lgrp_cpucnt++;
}

lgrp_t *
lgrp_create(void)
{
	lgrp_t		*my_lgrp;
	lgrp_id_t	lgrpid;
	int		i;

	ASSERT(!lgrp_initialized || MUTEX_HELD(&cpu_lock));

	/*
	 * Find an open slot in the lgroup table and recycle unused lgroup
	 * left there if any
	 */
	my_lgrp = NULL;
	if (lgrp_alloc_hint == -1)
		/*
		 * Allocate from end when hint not set yet because no lgroups
		 * have been deleted yet
		 */
		lgrpid = nlgrps++;
	else {
		/*
		 * Start looking for next open slot from hint and leave hint
		 * at slot allocated
		 */
		for (i = lgrp_alloc_hint; i < nlgrpsmax; i++) {
			my_lgrp = lgrp_table[i];
			if (!LGRP_EXISTS(my_lgrp)) {
				lgrpid = i;
				nlgrps++;
				break;
			}
		}
		lgrp_alloc_hint = lgrpid;
	}

	/*
	 * Keep track of max lgroup ID allocated so far to cut down on searches
	 */
	if (lgrpid > lgrp_alloc_max)
		lgrp_alloc_max = lgrpid;

	/*
	 * Need to allocate new lgroup if next open slot didn't have one
	 * for recycling
	 */
	if (my_lgrp == NULL)
		my_lgrp = lgrp_plat_alloc(lgrpid);

	if (nlgrps > nlgrpsmax || my_lgrp == NULL)
		panic("Too many lgrps for platform (%d)", nlgrps);

	my_lgrp->lgrp_id = lgrpid;
	my_lgrp->lgrp_latency = 0;
	my_lgrp->lgrp_plathand = LGRP_NULL_HANDLE;
	my_lgrp->lgrp_parent = NULL;
	my_lgrp->lgrp_childcnt = 0;
	my_lgrp->lgrp_mnodes = (mnodeset_t)0;
	my_lgrp->lgrp_nmnodes = 0;
	klgrpset_clear(my_lgrp->lgrp_children);
	klgrpset_clear(my_lgrp->lgrp_leaves);
	for (i = 0; i < LGRP_RSRC_COUNT; i++)
		klgrpset_clear(my_lgrp->lgrp_set[i]);

	my_lgrp->lgrp_cpu = NULL;
	my_lgrp->lgrp_cpucnt = 0;

	if (my_lgrp->lgrp_kstat != NULL)
		lgrp_kstat_reset(lgrpid);

	lgrp_table[my_lgrp->lgrp_id] = my_lgrp;

	return (my_lgrp);
}

void
lgrp_destroy(lgrp_t *lgrp)
{
	int		i;

	/*
	 * Unless this lgroup is being destroyed on behalf of
	 * the boot CPU, cpu_lock must be held
	 */
	ASSERT(!lgrp_initialized || MUTEX_HELD(&cpu_lock));

	if (nlgrps == 1)
		cmn_err(CE_PANIC, "Can't destroy only lgroup!");

	if (!LGRP_EXISTS(lgrp))
		return;

	/*
	 * Set hint to lgroup being deleted and try to keep lower numbered
	 * hints to facilitate finding empty slots
	 */
	if (lgrp_alloc_hint == -1 || lgrp->lgrp_id < lgrp_alloc_hint)
		lgrp_alloc_hint = lgrp->lgrp_id;

	/*
	 * Mark this lgroup to be recycled by setting its lgroup ID to
	 * LGRP_NONE and clear relevant fields
	 */
	lgrp->lgrp_id = LGRP_NONE;
	lgrp->lgrp_latency = 0;
	lgrp->lgrp_plathand = LGRP_NULL_HANDLE;
	lgrp->lgrp_parent = NULL;
	lgrp->lgrp_childcnt = 0;

	klgrpset_clear(lgrp->lgrp_children);
	klgrpset_clear(lgrp->lgrp_leaves);
	for (i = 0; i < LGRP_RSRC_COUNT; i++)
		klgrpset_clear(lgrp->lgrp_set[i]);

	lgrp->lgrp_mnodes = (mnodeset_t)0;
	lgrp->lgrp_nmnodes = 0;

	lgrp->lgrp_cpu = NULL;
	lgrp->lgrp_cpucnt = 0;

	nlgrps--;
}

/*
 * Initialize kstat data. Called from lgrp intialization code.
 */
static void
lgrp_kstat_init(void)
{
	lgrp_stat_t	stat;

	mutex_init(&lgrp_kstat_mutex, NULL, MUTEX_DEFAULT, NULL);

	for (stat = 0; stat < LGRP_NUM_STATS; stat++)
		kstat_named_init(&lgrp_kstat_data[stat],
		    lgrp_kstat_names[stat], KSTAT_DATA_INT64);
}

/*
 * initialize an lgrp's kstats if needed
 * called with cpu_lock held but not with cpus paused.
 * we don't tear these down now because we don't know about
 * memory leaving the lgrp yet...
 */

void
lgrp_kstat_create(cpu_t *cp)
{
	kstat_t		*lgrp_kstat;
	lgrp_id_t	lgrpid;
	lgrp_t		*my_lgrp;

	ASSERT(MUTEX_HELD(&cpu_lock));

	lgrpid = cp->cpu_lpl->lpl_lgrpid;
	my_lgrp = lgrp_table[lgrpid];

	if (my_lgrp->lgrp_kstat != NULL)
		return; /* already initialized */

	lgrp_kstat = kstat_create("lgrp", lgrpid, NULL, "misc",
	    KSTAT_TYPE_NAMED, LGRP_NUM_STATS,
	    KSTAT_FLAG_VIRTUAL | KSTAT_FLAG_WRITABLE);

	if (lgrp_kstat != NULL) {
		lgrp_kstat->ks_lock = &lgrp_kstat_mutex;
		lgrp_kstat->ks_private = my_lgrp;
		lgrp_kstat->ks_data = &lgrp_kstat_data;
		lgrp_kstat->ks_update = lgrp_kstat_extract;
		my_lgrp->lgrp_kstat = lgrp_kstat;
		kstat_install(lgrp_kstat);
	}
}

/*
 * this will do something when we manage to remove now unused lgrps
 */

/* ARGSUSED */
void
lgrp_kstat_destroy(cpu_t *cp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
}

/*
 * Called when a CPU is off-lined.
 */
static void
lgrp_cpu_fini(struct cpu *cp, lgrp_id_t lgrpid)
{
	lgrp_t *my_lgrp;
	struct cpu *prev;
	struct cpu *next;

	ASSERT(MUTEX_HELD(&cpu_lock) || !lgrp_initialized);

	prev = cp->cpu_prev_lgrp;
	next = cp->cpu_next_lgrp;

	prev->cpu_next_lgrp = next;
	next->cpu_prev_lgrp = prev;

	/*
	 * just because I'm paranoid doesn't mean...
	 */

	cp->cpu_next_lgrp = cp->cpu_prev_lgrp = NULL;

	my_lgrp = lgrp_table[lgrpid];
	my_lgrp->lgrp_cpucnt--;

	/*
	 * Removing last CPU in lgroup, so update lgroup topology
	 */
	if (my_lgrp->lgrp_cpucnt == 0) {
		klgrpset_t	changed;
		int		count;
		int		i;

		my_lgrp->lgrp_cpu = NULL;

		/*
		 * Remove this lgroup from its lgroup CPU resources and remove
		 * lgroup from lgroup topology if it doesn't have any more
		 * resources in it now
		 */
		klgrpset_del(my_lgrp->lgrp_set[LGRP_RSRC_CPU], lgrpid);
		if (lgrp_rsets_empty(my_lgrp->lgrp_set)) {
			count = 0;
			klgrpset_clear(changed);
			count += lgrp_leaf_delete(my_lgrp, lgrp_table,
			    lgrp_alloc_max + 1, &changed);
			return;
		}

		/*
		 * This lgroup isn't empty, so just remove it from CPU
		 * resources of any lgroups that contain it as such
		 */
		for (i = 0; i <= lgrp_alloc_max; i++) {
			lgrp_t		*lgrp;

			lgrp = lgrp_table[i];
			if (!LGRP_EXISTS(lgrp) ||
			    !klgrpset_ismember(lgrp->lgrp_set[LGRP_RSRC_CPU],
			    lgrpid))
				continue;

			klgrpset_del(lgrp->lgrp_set[LGRP_RSRC_CPU], lgrpid);
		}
		return;
	}

	if (my_lgrp->lgrp_cpu == cp)
		my_lgrp->lgrp_cpu = next;

}

/*
 * Update memory nodes in target lgroups and return ones that get changed
 */
int
lgrp_mnode_update(klgrpset_t target, klgrpset_t *changed)
{
	int	count;
	int	i;
	int	j;
	lgrp_t	*lgrp;
	lgrp_t	*lgrp_rsrc;

	count = 0;
	if (changed)
		klgrpset_clear(*changed);

	if (klgrpset_isempty(target))
		return (0);

	/*
	 * Find each lgroup in target lgroups
	 */
	for (i = 0; i <= lgrp_alloc_max; i++) {
		/*
		 * Skip any lgroups that don't exist or aren't in target group
		 */
		lgrp = lgrp_table[i];
		if (!klgrpset_ismember(target, i) || !LGRP_EXISTS(lgrp)) {
			continue;
		}

		/*
		 * Initialize memnodes for intermediate lgroups to 0
		 * and update them from scratch since they may have completely
		 * changed
		 */
		if (lgrp->lgrp_childcnt && lgrp != lgrp_root) {
			lgrp->lgrp_mnodes = (mnodeset_t)0;
			lgrp->lgrp_nmnodes = 0;
		}

		/*
		 * Update memory nodes of of target lgroup with memory nodes
		 * from each lgroup in its lgroup memory resource set
		 */
		for (j = 0; j <= lgrp_alloc_max; j++) {
			int	k;

			/*
			 * Skip any lgroups that don't exist or aren't in
			 * memory resources of target lgroup
			 */
			lgrp_rsrc = lgrp_table[j];
			if (!LGRP_EXISTS(lgrp_rsrc) ||
			    !klgrpset_ismember(lgrp->lgrp_set[LGRP_RSRC_MEM],
			    j))
				continue;

			/*
			 * Update target lgroup's memnodes to include memnodes
			 * of this lgroup
			 */
			for (k = 0; k < sizeof (mnodeset_t) * NBBY; k++) {
				mnodeset_t	mnode_mask;

				mnode_mask = (mnodeset_t)1 << k;
				if ((lgrp_rsrc->lgrp_mnodes & mnode_mask) &&
				    !(lgrp->lgrp_mnodes & mnode_mask)) {
					lgrp->lgrp_mnodes |= mnode_mask;
					lgrp->lgrp_nmnodes++;
				}
			}
			count++;
			if (changed)
				klgrpset_add(*changed, lgrp->lgrp_id);
		}
	}

	return (count);
}

/*
 * Memory copy-rename. Called when the "mnode" containing the kernel cage memory
 * is moved from one board to another. The "from" and "to" arguments specify the
 * source and the destination of the move.
 *
 * See plat_lgrp_config() for a detailed description of the copy-rename
 * semantics.
 *
 * The lgrp_mem_rename() is called by the platform copy-rename code to update
 * the lgroup topology which is changing as memory moves from one lgroup to
 * another. It removes the mnode from the source lgroup and re-inserts it in the
 * target lgroup.
 *
 * The lgrp_mem_rename() function passes a flag to lgrp_mem_init() and
 * lgrp_mem_fini() telling that the insertion and deleteion are part of a DR
 * copy-rename operation.
 *
 * There is one case which requires special handling. If the system contains
 * only two boards (mnodes), the lgrp_mem_fini() removes the only mnode from the
 * lgroup hierarchy. This mnode is soon re-inserted back in the hierarchy by
 * lgrp_mem_init), but there is a window when the system has no memory in the
 * lgroup hierarchy. If another thread tries to allocate memory during this
 * window, the allocation will fail, although the system has physical memory.
 * This may cause a system panic or a deadlock (some sleeping memory allocations
 * happen with cpu_lock held which prevents lgrp_mem_init() from re-inserting
 * the mnode back).
 *
 * The lgrp_memnode_choose() function walks the lgroup hierarchy looking for the
 * lgrp with non-empty lgrp_mnodes. To deal with the special case above,
 * lgrp_mem_fini() does not remove the last mnode from the lroot->lgrp_mnodes,
 * but it updates the rest of the lgroup topology as if the mnode was actually
 * removed. The lgrp_mem_init() function recognizes that the mnode being
 * inserted represents such a special case and updates the topology
 * appropriately.
 */
void
lgrp_mem_rename(int mnode, lgrp_handle_t from, lgrp_handle_t to)
{
	/*
	 * Remove the memory from the source node and add it to the destination
	 * node.
	 */
	lgrp_mem_fini(mnode, from, B_TRUE);
	lgrp_mem_init(mnode, to, B_TRUE);
}

/*
 * Called to indicate that the lgrp with platform handle "hand" now
 * contains the memory identified by "mnode".
 *
 * LOCKING for this routine is a bit tricky. Usually it is called without
 * cpu_lock and it must must grab cpu_lock here to prevent racing with other
 * callers. During DR of the board containing the caged memory it may be called
 * with cpu_lock already held and CPUs paused.
 *
 * If the insertion is part of the DR copy-rename and the inserted mnode (and
 * only this mnode) is already present in the lgrp_root->lgrp_mnodes set, we are
 * dealing with the special case of DR copy-rename described in
 * lgrp_mem_rename().
 */
void
lgrp_mem_init(int mnode, lgrp_handle_t hand, boolean_t is_copy_rename)
{
	klgrpset_t	changed;
	int		count;
	int		i;
	lgrp_t		*my_lgrp;
	lgrp_id_t	lgrpid;
	mnodeset_t	mnodes_mask = ((mnodeset_t)1 << mnode);
	boolean_t	drop_lock = B_FALSE;
	boolean_t	need_synch = B_FALSE;

	/*
	 * Grab CPU lock (if we haven't already)
	 */
	if (!MUTEX_HELD(&cpu_lock)) {
		mutex_enter(&cpu_lock);
		drop_lock = B_TRUE;
	}

	/*
	 * This routine may be called from a context where we already
	 * hold cpu_lock, and have already paused cpus.
	 */
	if (!cpus_paused())
		need_synch = B_TRUE;

	/*
	 * Check if this mnode is already configured and return immediately if
	 * it is.
	 *
	 * NOTE: in special case of copy-rename of the only remaining mnode,
	 * lgrp_mem_fini() refuses to remove the last mnode from the root, so we
	 * recognize this case and continue as usual, but skip the update to
	 * the lgrp_mnodes and the lgrp_nmnodes. This restores the inconsistency
	 * in topology, temporarily introduced by lgrp_mem_fini().
	 */
	if (! (is_copy_rename && (lgrp_root->lgrp_mnodes == mnodes_mask)) &&
	    lgrp_root->lgrp_mnodes & mnodes_mask) {
		if (drop_lock)
			mutex_exit(&cpu_lock);
		return;
	}

	/*
	 * Update lgroup topology with new memory resources, keeping track of
	 * which lgroups change
	 */
	count = 0;
	klgrpset_clear(changed);
	my_lgrp = lgrp_hand_to_lgrp(hand);
	if (my_lgrp == NULL) {
		/* new lgrp */
		my_lgrp = lgrp_create();
		lgrpid = my_lgrp->lgrp_id;
		my_lgrp->lgrp_plathand = hand;
		my_lgrp->lgrp_latency = lgrp_plat_latency(hand, hand);
		klgrpset_add(my_lgrp->lgrp_leaves, lgrpid);
		klgrpset_add(my_lgrp->lgrp_set[LGRP_RSRC_MEM], lgrpid);

		if (need_synch)
			pause_cpus(NULL);
		count = lgrp_leaf_add(my_lgrp, lgrp_table, lgrp_alloc_max + 1,
		    &changed);
		if (need_synch)
			start_cpus();
	} else if (my_lgrp->lgrp_latency == 0 && lgrp_plat_latency(hand, hand)
	    > 0) {
		/*
		 * Leaf lgroup was created, but latency wasn't available
		 * then.  So, set latency for it and fill in rest of lgroup
		 * topology  now that we know how far it is from other leaf
		 * lgroups.
		 */
		klgrpset_clear(changed);
		lgrpid = my_lgrp->lgrp_id;
		if (!klgrpset_ismember(my_lgrp->lgrp_set[LGRP_RSRC_MEM],
		    lgrpid))
			klgrpset_add(my_lgrp->lgrp_set[LGRP_RSRC_MEM], lgrpid);
		if (need_synch)
			pause_cpus(NULL);
		count = lgrp_leaf_add(my_lgrp, lgrp_table, lgrp_alloc_max + 1,
		    &changed);
		if (need_synch)
			start_cpus();
	} else if (!klgrpset_ismember(my_lgrp->lgrp_set[LGRP_RSRC_MEM],
	    my_lgrp->lgrp_id)) {
		/*
		 * Add new lgroup memory resource to existing lgroup
		 */
		lgrpid = my_lgrp->lgrp_id;
		klgrpset_add(my_lgrp->lgrp_set[LGRP_RSRC_MEM], lgrpid);
		klgrpset_add(changed, lgrpid);
		count++;
		for (i = 0; i <= lgrp_alloc_max; i++) {
			lgrp_t		*lgrp;

			lgrp = lgrp_table[i];
			if (!LGRP_EXISTS(lgrp) ||
			    !lgrp_rsets_member(lgrp->lgrp_set, lgrpid))
				continue;

			klgrpset_add(lgrp->lgrp_set[LGRP_RSRC_MEM], lgrpid);
			klgrpset_add(changed, lgrp->lgrp_id);
			count++;
		}
	}

	/*
	 * Add memory node to lgroup and remove lgroup from ones that need
	 * to be updated
	 */
	if (!(my_lgrp->lgrp_mnodes & mnodes_mask)) {
		my_lgrp->lgrp_mnodes |= mnodes_mask;
		my_lgrp->lgrp_nmnodes++;
	}
	klgrpset_del(changed, lgrpid);

	/*
	 * Update memory node information for all lgroups that changed and
	 * contain new memory node as a resource
	 */
	if (count)
		(void) lgrp_mnode_update(changed, NULL);

	if (drop_lock)
		mutex_exit(&cpu_lock);
}

/*
 * Called to indicate that the lgroup associated with the platform
 * handle "hand" no longer contains given memory node
 *
 * LOCKING for this routine is a bit tricky. Usually it is called without
 * cpu_lock and it must must grab cpu_lock here to prevent racing with other
 * callers. During DR of the board containing the caged memory it may be called
 * with cpu_lock already held and CPUs paused.
 *
 * If the deletion is part of the DR copy-rename and the deleted mnode is the
 * only one present in the lgrp_root->lgrp_mnodes, all the topology is updated,
 * but lgrp_root->lgrp_mnodes is left intact. Later, lgrp_mem_init() will insert
 * the same mnode back into the topology. See lgrp_mem_rename() and
 * lgrp_mem_init() for additional details.
 */
void
lgrp_mem_fini(int mnode, lgrp_handle_t hand, boolean_t is_copy_rename)
{
	klgrpset_t	changed;
	int		count;
	int		i;
	lgrp_t		*my_lgrp;
	lgrp_id_t	lgrpid;
	mnodeset_t	mnodes_mask;
	boolean_t	drop_lock = B_FALSE;
	boolean_t	need_synch = B_FALSE;

	/*
	 * Grab CPU lock (if we haven't already)
	 */
	if (!MUTEX_HELD(&cpu_lock)) {
		mutex_enter(&cpu_lock);
		drop_lock = B_TRUE;
	}

	/*
	 * This routine may be called from a context where we already
	 * hold cpu_lock and have already paused cpus.
	 */
	if (!cpus_paused())
		need_synch = B_TRUE;

	my_lgrp = lgrp_hand_to_lgrp(hand);

	/*
	 * The lgrp *must* be pre-existing
	 */
	ASSERT(my_lgrp != NULL);

	/*
	 * Delete memory node from lgroups which contain it
	 */
	mnodes_mask = ((mnodeset_t)1 << mnode);
	for (i = 0; i <= lgrp_alloc_max; i++) {
		lgrp_t *lgrp = lgrp_table[i];
		/*
		 * Skip any non-existent lgroups and any lgroups that don't
		 * contain leaf lgroup of memory as a memory resource
		 */
		if (!LGRP_EXISTS(lgrp) ||
		    !(lgrp->lgrp_mnodes & mnodes_mask))
			continue;

		/*
		 * Avoid removing the last mnode from the root in the DR
		 * copy-rename case. See lgrp_mem_rename() for details.
		 */
		if (is_copy_rename &&
		    (lgrp == lgrp_root) && (lgrp->lgrp_mnodes == mnodes_mask))
			continue;

		/*
		 * Remove memory node from lgroup.
		 */
		lgrp->lgrp_mnodes &= ~mnodes_mask;
		lgrp->lgrp_nmnodes--;
		ASSERT(lgrp->lgrp_nmnodes >= 0);
	}
	ASSERT(lgrp_root->lgrp_nmnodes > 0);

	/*
	 * Don't need to update lgroup topology if this lgroup still has memory.
	 *
	 * In the special case of DR copy-rename with the only mnode being
	 * removed, the lgrp_mnodes for the root is always non-zero, but we
	 * still need to update the lgroup topology.
	 */
	if ((my_lgrp->lgrp_nmnodes > 0) &&
	    !(is_copy_rename && (my_lgrp == lgrp_root) &&
	    (my_lgrp->lgrp_mnodes == mnodes_mask))) {
		if (drop_lock)
			mutex_exit(&cpu_lock);
		return;
	}

	/*
	 * This lgroup does not contain any memory now
	 */
	klgrpset_clear(my_lgrp->lgrp_set[LGRP_RSRC_MEM]);

	/*
	 * Remove this lgroup from lgroup topology if it does not contain any
	 * resources now
	 */
	lgrpid = my_lgrp->lgrp_id;
	count = 0;
	klgrpset_clear(changed);
	if (lgrp_rsets_empty(my_lgrp->lgrp_set)) {
		/*
		 * Delete lgroup when no more resources
		 */
		if (need_synch)
			pause_cpus(NULL);
		count = lgrp_leaf_delete(my_lgrp, lgrp_table,
		    lgrp_alloc_max + 1, &changed);
		ASSERT(count > 0);
		if (need_synch)
			start_cpus();
	} else {
		/*
		 * Remove lgroup from memory resources of any lgroups that
		 * contain it as such
		 */
		for (i = 0; i <= lgrp_alloc_max; i++) {
			lgrp_t		*lgrp;

			lgrp = lgrp_table[i];
			if (!LGRP_EXISTS(lgrp) ||
			    !klgrpset_ismember(lgrp->lgrp_set[LGRP_RSRC_MEM],
			    lgrpid))
				continue;

			klgrpset_del(lgrp->lgrp_set[LGRP_RSRC_MEM], lgrpid);
		}
	}
	if (drop_lock)
		mutex_exit(&cpu_lock);
}

/*
 * Return lgroup with given platform handle
 */
lgrp_t *
lgrp_hand_to_lgrp(lgrp_handle_t hand)
{
	int	i;
	lgrp_t	*lgrp;

	if (hand == LGRP_NULL_HANDLE)
		return (NULL);

	for (i = 0; i <= lgrp_alloc_max; i++) {
		lgrp = lgrp_table[i];
		if (LGRP_EXISTS(lgrp) && lgrp->lgrp_plathand == hand)
			return (lgrp);
	}
	return (NULL);
}

/*
 * Return the home lgroup of the current thread.
 * We must do this with kernel preemption disabled, since we don't want our
 * thread to be re-homed while we're poking around with its lpl, and the lpl
 * should never be NULL.
 *
 * NOTE: Can't guarantee that lgroup will be valid once kernel preemption
 * is enabled because of DR.  Callers can use disable kernel preemption
 * around this call to guarantee that the lgroup will be valid beyond this
 * routine, since kernel preemption can be recursive.
 */
lgrp_t *
lgrp_home_lgrp(void)
{
	lgrp_t	*lgrp;
	lpl_t	*lpl;

	kpreempt_disable();

	lpl = curthread->t_lpl;
	ASSERT(lpl != NULL);
	ASSERT(lpl->lpl_lgrpid >= 0 && lpl->lpl_lgrpid <= lgrp_alloc_max);
	ASSERT(LGRP_EXISTS(lgrp_table[lpl->lpl_lgrpid]));
	lgrp = lgrp_table[lpl->lpl_lgrpid];

	kpreempt_enable();

	return (lgrp);
}

/*
 * Return ID of home lgroup for given thread
 * (See comments for lgrp_home_lgrp() for special care and handling
 * instructions)
 */
lgrp_id_t
lgrp_home_id(kthread_t *t)
{
	lgrp_id_t	lgrp;
	lpl_t		*lpl;

	ASSERT(t != NULL);
	/*
	 * We'd like to ASSERT(MUTEX_HELD(&ttoproc(t)->p_lock)), but we
	 * cannot since the HAT layer can call into this routine to
	 * determine the locality for its data structures in the context
	 * of a page fault.
	 */

	kpreempt_disable();

	lpl = t->t_lpl;
	ASSERT(lpl != NULL);
	ASSERT(lpl->lpl_lgrpid >= 0 && lpl->lpl_lgrpid <= lgrp_alloc_max);
	lgrp = lpl->lpl_lgrpid;

	kpreempt_enable();

	return (lgrp);
}

/*
 * Return lgroup containing the physical memory for the given page frame number
 */
lgrp_t *
lgrp_pfn_to_lgrp(pfn_t pfn)
{
	lgrp_handle_t	hand;
	int		i;
	lgrp_t		*lgrp;

	hand = lgrp_plat_pfn_to_hand(pfn);
	if (hand != LGRP_NULL_HANDLE)
		for (i = 0; i <= lgrp_alloc_max; i++) {
			lgrp = lgrp_table[i];
			if (LGRP_EXISTS(lgrp) && lgrp->lgrp_plathand == hand)
				return (lgrp);
		}
	return (NULL);
}

/*
 * Return lgroup containing the physical memory for the given page frame number
 */
lgrp_t *
lgrp_phys_to_lgrp(u_longlong_t physaddr)
{
	lgrp_handle_t	hand;
	int		i;
	lgrp_t		*lgrp;
	pfn_t		pfn;

	pfn = btop(physaddr);
	hand = lgrp_plat_pfn_to_hand(pfn);
	if (hand != LGRP_NULL_HANDLE)
		for (i = 0; i <= lgrp_alloc_max; i++) {
			lgrp = lgrp_table[i];
			if (LGRP_EXISTS(lgrp) && lgrp->lgrp_plathand == hand)
				return (lgrp);
		}
	return (NULL);
}

/*
 * Return the leaf lgroup containing the given CPU
 *
 * The caller needs to take precautions necessary to prevent
 * "cpu", and it's lpl from going away across a call to this function.
 * hint: kpreempt_disable()/kpreempt_enable()
 */
static lgrp_t *
lgrp_cpu_to_lgrp(cpu_t *cpu)
{
	return (cpu->cpu_lpl->lpl_lgrp);
}

/*
 * Return the sum of the partition loads in an lgrp divided by
 * the number of CPUs in the lgrp.  This is our best approximation
 * of an 'lgroup load average' for a useful per-lgroup kstat.
 */
static uint64_t
lgrp_sum_loadavgs(lgrp_t *lgrp)
{
	cpu_t *cpu;
	int ncpu;
	uint64_t loads = 0;

	mutex_enter(&cpu_lock);

	cpu = lgrp->lgrp_cpu;
	ncpu = lgrp->lgrp_cpucnt;

	if (cpu == NULL || ncpu == 0) {
		mutex_exit(&cpu_lock);
		return (0ull);
	}

	do {
		loads += cpu->cpu_lpl->lpl_loadavg;
		cpu = cpu->cpu_next_lgrp;
	} while (cpu != lgrp->lgrp_cpu);

	mutex_exit(&cpu_lock);

	return (loads / ncpu);
}

void
lgrp_stat_add(lgrp_id_t lgrpid, lgrp_stat_t stat, int64_t val)
{
	struct lgrp_stats *pstats;

	/*
	 * Verify that the caller isn't trying to add to
	 * a statistic for an lgroup that has gone away
	 */
	if (lgrpid < 0 || lgrpid > lgrp_alloc_max)
		return;

	pstats = &lgrp_stats[lgrpid];
	atomic_add_64((uint64_t *)LGRP_STAT_WRITE_PTR(pstats, stat), val);
}

int64_t
lgrp_stat_read(lgrp_id_t lgrpid, lgrp_stat_t stat)
{
	uint64_t val;
	struct lgrp_stats *pstats;

	if (lgrpid < 0 || lgrpid > lgrp_alloc_max)
		return ((int64_t)0);

	pstats = &lgrp_stats[lgrpid];
	LGRP_STAT_READ(pstats, stat, val);
	return (val);
}

/*
 * Reset all kstats for lgrp specified by its lgrpid.
 */
static void
lgrp_kstat_reset(lgrp_id_t lgrpid)
{
	lgrp_stat_t stat;

	if (lgrpid < 0 || lgrpid > lgrp_alloc_max)
		return;

	for (stat = 0; stat < LGRP_NUM_COUNTER_STATS; stat++) {
		LGRP_STAT_RESET(&lgrp_stats[lgrpid], stat);
	}
}

/*
 * Collect all per-lgrp statistics for the lgrp associated with this
 * kstat, and store them in the ks_data array.
 *
 * The superuser can reset all the running counter statistics for an
 * lgrp by writing to any of the lgrp's stats.
 */
static int
lgrp_kstat_extract(kstat_t *ksp, int rw)
{
	lgrp_stat_t		stat;
	struct kstat_named	*ksd;
	lgrp_t			*lgrp;
	lgrp_id_t		lgrpid;

	lgrp = (lgrp_t *)ksp->ks_private;

	ksd = (struct kstat_named *)ksp->ks_data;
	ASSERT(ksd == (struct kstat_named *)&lgrp_kstat_data);

	lgrpid = lgrp->lgrp_id;

	if (lgrpid == LGRP_NONE) {
		/*
		 * Return all zeroes as stats for freed lgrp.
		 */
		for (stat = 0; stat < LGRP_NUM_COUNTER_STATS; stat++) {
			ksd[stat].value.i64 = 0;
		}
		ksd[stat + LGRP_NUM_CPUS].value.i64 = 0;
		ksd[stat + LGRP_NUM_PG_INSTALL].value.i64 = 0;
		ksd[stat + LGRP_NUM_PG_AVAIL].value.i64 = 0;
		ksd[stat + LGRP_NUM_PG_FREE].value.i64 = 0;
		ksd[stat + LGRP_LOADAVG].value.i64 = 0;
	} else if (rw != KSTAT_WRITE) {
		/*
		 * Handle counter stats
		 */
		for (stat = 0; stat < LGRP_NUM_COUNTER_STATS; stat++) {
			ksd[stat].value.i64 = lgrp_stat_read(lgrpid, stat);
		}

		/*
		 * Handle kernel data snapshot stats
		 */
		ksd[stat + LGRP_NUM_CPUS].value.i64 = lgrp->lgrp_cpucnt;
		ksd[stat + LGRP_NUM_PG_INSTALL].value.i64 =
		    lgrp_mem_size(lgrpid, LGRP_MEM_SIZE_INSTALL);
		ksd[stat + LGRP_NUM_PG_AVAIL].value.i64 =
		    lgrp_mem_size(lgrpid, LGRP_MEM_SIZE_AVAIL);
		ksd[stat + LGRP_NUM_PG_FREE].value.i64 =
		    lgrp_mem_size(lgrpid, LGRP_MEM_SIZE_FREE);
		ksd[stat + LGRP_LOADAVG].value.i64 = lgrp_sum_loadavgs(lgrp);
		ksd[stat + LGRP_LOADAVG_SCALE].value.i64 =
		    lgrp_loadavg_max_effect;
	} else {
		lgrp_kstat_reset(lgrpid);
	}

	return (0);
}

int
lgrp_query_cpu(processorid_t id, lgrp_id_t *lp)
{
	cpu_t	*cp;

	mutex_enter(&cpu_lock);

	if ((cp = cpu_get(id)) == NULL) {
		mutex_exit(&cpu_lock);
		return (EINVAL);
	}

	if (cpu_is_offline(cp) || cpu_is_poweredoff(cp)) {
		mutex_exit(&cpu_lock);
		return (EINVAL);
	}

	ASSERT(cp->cpu_lpl != NULL);

	*lp = cp->cpu_lpl->lpl_lgrpid;

	mutex_exit(&cpu_lock);

	return (0);
}

int
lgrp_query_load(processorid_t id, lgrp_load_t *lp)
{
	cpu_t *cp;

	mutex_enter(&cpu_lock);

	if ((cp = cpu_get(id)) == NULL) {
		mutex_exit(&cpu_lock);
		return (EINVAL);
	}

	ASSERT(cp->cpu_lpl != NULL);

	*lp = cp->cpu_lpl->lpl_loadavg;

	mutex_exit(&cpu_lock);

	return (0);
}

/*
 * Add a resource named by lpl_leaf to rset of lpl_target
 *
 * This routine also adjusts ncpu and nrset if the call succeeds in adding a
 * resource. It is adjusted here, as this is presently the only place that we
 * can be certain a resource addition has succeeded.
 *
 * We keep the list of rsets sorted so that the dispatcher can quickly walk the
 * list in order until it reaches a NULL.  (This list is required to be NULL
 * terminated, too).  This is done so that we can mark start pos + 1, so that
 * each lpl is traversed sequentially, but in a different order.  We hope this
 * will improve performance a bit.  (Hopefully, less read-to-own traffic...)
 */

void
lpl_rset_add(lpl_t *lpl_target, lpl_t *lpl_leaf)
{
	int		i;
	int		entry_slot = 0;

	/* return if leaf is already present */
	for (i = 0; i < lpl_target->lpl_nrset; i++) {
		if (lpl_target->lpl_rset[i] == lpl_leaf) {
			return;
		}

		if (lpl_target->lpl_rset[i]->lpl_lgrpid >
		    lpl_leaf->lpl_lgrpid) {
			break;
		}
	}

	/* insert leaf, update counts */
	entry_slot = i;
	i = lpl_target->lpl_nrset++;

	/*
	 * Start at the end of the rset array and work backwards towards the
	 * slot into which the new lpl will be inserted. This effectively
	 * preserves the current ordering by scooting everybody over one entry,
	 * and placing the new entry into the space created.
	 */
	while (i-- > entry_slot) {
		lpl_target->lpl_rset[i + 1] = lpl_target->lpl_rset[i];
		lpl_target->lpl_id2rset[lpl_target->lpl_rset[i]->lpl_lgrpid] =
		    i + 1;
	}

	lpl_target->lpl_rset[entry_slot] = lpl_leaf;
	lpl_target->lpl_id2rset[lpl_leaf->lpl_lgrpid] = entry_slot;

	lpl_target->lpl_ncpu += lpl_leaf->lpl_ncpu;
}

/*
 * Update each of lpl_parent's children with a reference to their parent.
 * The lgrp topology is used as the reference since it is fully
 * consistent and correct at this point.
 * This should be called after any potential change in lpl_parent's
 * rset.
 */
static void
lpl_child_update(lpl_t *lpl_parent, struct cpupart *cp)
{
	klgrpset_t	children;
	int		i;

	children = lgrp_table[lpl_parent->lpl_lgrpid]->lgrp_children;
	if (klgrpset_isempty(children))
		return; /* nothing to do */

	for (i = 0; i <= lgrp_alloc_max; i++) {
		if (klgrpset_ismember(children, i)) {
			/*
			 * (Re)set the parent. It may be incorrect if
			 * lpl_parent is new in the topology.
			 */
			cp->cp_lgrploads[i].lpl_parent = lpl_parent;
		}
	}
}

/*
 * Delete resource lpl_leaf from rset of lpl_target, assuming it's there.
 *
 * This routine also adjusts ncpu and nrset if the call succeeds in deleting a
 * resource. The values are adjusted here, as this is the only place that we can
 * be certain a resource was successfully deleted.
 */
void
lpl_rset_del(lpl_t *lpl_target, lpl_t *lpl_leaf)
{
	int i;
	lpl_t *leaf;

	if (lpl_target->lpl_nrset == 0)
		return;

	/* find leaf in intermediate node */
	for (i = 0; i < lpl_target->lpl_nrset; i++) {
		if (lpl_target->lpl_rset[i] == lpl_leaf)
			break;
	}

	/* return if leaf not found */
	if (lpl_target->lpl_rset[i] != lpl_leaf)
		return;

	/* prune leaf, compress array */
	lpl_target->lpl_rset[lpl_target->lpl_nrset--] = NULL;
	lpl_target->lpl_id2rset[lpl_leaf->lpl_lgrpid] = -1;
	lpl_target->lpl_ncpu--;
	do {
		lpl_target->lpl_rset[i] = lpl_target->lpl_rset[i + 1];
		/*
		 * Update the lgrp id <=> rset mapping
		 */
		if ((leaf = lpl_target->lpl_rset[i]) != NULL) {
			lpl_target->lpl_id2rset[leaf->lpl_lgrpid] = i;
		}
	} while (i++ < lpl_target->lpl_nrset);
}

/*
 * Check to see if the resource set of the target lpl contains the
 * supplied leaf lpl.  This returns 1 if the lpl is found, 0 if it is not.
 */

int
lpl_rset_contains(lpl_t *lpl_target, lpl_t *lpl_leaf)
{
	int i;

	for (i = 0; i < lpl_target->lpl_nrset; i++) {
		if (lpl_target->lpl_rset[i] == lpl_leaf)
			return (1);
	}

	return (0);
}

/*
 * Called when we change cpu lpl membership.  This increments or decrements the
 * per-cpu counter in every lpl in which our leaf appears.
 */
void
lpl_cpu_adjcnt(lpl_act_t act, cpu_t *cp)
{
	cpupart_t	*cpupart;
	lgrp_t		*lgrp_leaf;
	lgrp_t		*lgrp_cur;
	lpl_t		*lpl_leaf;
	lpl_t		*lpl_cur;
	int		i;

	ASSERT(act == LPL_DECREMENT || act == LPL_INCREMENT);

	cpupart = cp->cpu_part;
	lpl_leaf = cp->cpu_lpl;
	lgrp_leaf = lgrp_table[lpl_leaf->lpl_lgrpid];

	for (i = 0; i <= lgrp_alloc_max; i++) {
		lgrp_cur = lgrp_table[i];

		/*
		 * Don't adjust if the lgrp isn't there, if we're the leaf lpl
		 * for the cpu in question, or if the current lgrp and leaf
		 * don't share the same resources.
		 */

		if (!LGRP_EXISTS(lgrp_cur) || (lgrp_cur == lgrp_leaf) ||
		    !klgrpset_intersects(lgrp_leaf->lgrp_set[LGRP_RSRC_CPU],
		    lgrp_cur->lgrp_set[LGRP_RSRC_CPU]))
			continue;


		lpl_cur = &cpupart->cp_lgrploads[lgrp_cur->lgrp_id];

		if (lpl_cur->lpl_nrset > 0) {
			if (act == LPL_INCREMENT) {
				lpl_cur->lpl_ncpu++;
			} else if (act == LPL_DECREMENT) {
				lpl_cur->lpl_ncpu--;
			}
		}
	}
}

/*
 * Initialize lpl with given resources and specified lgrp
 */
void
lpl_init(lpl_t *lpl, lpl_t *lpl_leaf, lgrp_t *lgrp)
{
	lpl->lpl_lgrpid = lgrp->lgrp_id;
	lpl->lpl_loadavg = 0;
	if (lpl == lpl_leaf)
		lpl->lpl_ncpu = 1;
	else
		lpl->lpl_ncpu = lpl_leaf->lpl_ncpu;
	lpl->lpl_nrset = 1;
	lpl->lpl_rset[0] = lpl_leaf;
	lpl->lpl_id2rset[lpl_leaf->lpl_lgrpid] = 0;
	lpl->lpl_lgrp = lgrp;
	lpl->lpl_parent = NULL; /* set by lpl_leaf_insert() */
	lpl->lpl_cpus = NULL; /* set by lgrp_part_add_cpu() */
}

/*
 * Clear an unused lpl
 */
void
lpl_clear(lpl_t *lpl)
{
	/*
	 * Clear out all fields in the lpl except:
	 *    lpl_lgrpid - to facilitate debugging
	 *    lpl_rset, lpl_rset_sz, lpl_id2rset - rset array references / size
	 *
	 * Note that the lpl's rset and id2rset mapping are cleared as well.
	 */
	lpl->lpl_loadavg = 0;
	lpl->lpl_ncpu = 0;
	lpl->lpl_lgrp = NULL;
	lpl->lpl_parent = NULL;
	lpl->lpl_cpus = NULL;
	lpl->lpl_nrset = 0;
	lpl->lpl_homed_time = 0;
	bzero(lpl->lpl_rset, sizeof (lpl->lpl_rset[0]) * lpl->lpl_rset_sz);
	bzero(lpl->lpl_id2rset,
	    sizeof (lpl->lpl_id2rset[0]) * lpl->lpl_rset_sz);
}

/*
 * Given a CPU-partition, verify that the lpl topology in the CPU-partition
 * is in sync with the lgroup toplogy in the system.  The lpl topology may not
 * make full use of all of the lgroup topology, but this checks to make sure
 * that for the parts that it does use, it has correctly understood the
 * relationships that exist. This function returns
 * 0 if the topology is correct, and a non-zero error code, for non-debug
 * kernels if incorrect.  Asserts are spread throughout the code to aid in
 * debugging on a DEBUG kernel.
 */
int
lpl_topo_verify(cpupart_t *cpupart)
{
	lgrp_t		*lgrp;
	lpl_t		*lpl;
	klgrpset_t	rset;
	klgrpset_t	cset;
	cpu_t		*cpu;
	cpu_t		*cp_start;
	int		i;
	int		j;
	int		sum;

	/* topology can't be incorrect if it doesn't exist */
	if (!lgrp_topo_initialized || !lgrp_initialized)
		return (LPL_TOPO_CORRECT);

	ASSERT(cpupart != NULL);

	for (i = 0; i <= lgrp_alloc_max; i++) {
		lgrp = lgrp_table[i];
		lpl = NULL;
		/* make sure lpls are allocated */
		ASSERT(cpupart->cp_lgrploads);
		if (!cpupart->cp_lgrploads)
			return (LPL_TOPO_PART_HAS_NO_LPL);

		lpl = &cpupart->cp_lgrploads[i];
		/* make sure our index is good */
		ASSERT(i < cpupart->cp_nlgrploads);

		/* if lgroup doesn't exist, make sure lpl is empty */
		if (!LGRP_EXISTS(lgrp)) {
			ASSERT(lpl->lpl_ncpu == 0);
			if (lpl->lpl_ncpu > 0) {
				return (LPL_TOPO_CPUS_NOT_EMPTY);
			} else {
				continue;
			}
		}

		/* verify that lgroup and lpl are identically numbered */
		ASSERT(lgrp->lgrp_id == lpl->lpl_lgrpid);

		/* if lgroup isn't in our partition, make sure lpl is empty */
		if (!klgrpset_intersects(lgrp->lgrp_leaves,
		    cpupart->cp_lgrpset)) {
			ASSERT(lpl->lpl_ncpu == 0);
			if (lpl->lpl_ncpu > 0) {
				return (LPL_TOPO_CPUS_NOT_EMPTY);
			}
			/*
			 * lpl is empty, and lgroup isn't in partition.  verify
			 * that lpl doesn't show up in anyone else's rsets (in
			 * this partition, anyway)
			 */
			for (j = 0; j < cpupart->cp_nlgrploads; j++) {
				lpl_t *i_lpl; /* lpl we're iterating over */

				i_lpl = &cpupart->cp_lgrploads[j];

				ASSERT(!lpl_rset_contains(i_lpl, lpl));
				if (lpl_rset_contains(i_lpl, lpl)) {
					return (LPL_TOPO_LPL_ORPHANED);
				}
			}
			/* lgroup is empty, and everything is ok. continue */
			continue;
		}


		/* lgroup is in this partition, now check it against lpl */

		/* do both have matching lgrps? */
		ASSERT(lgrp == lpl->lpl_lgrp);
		if (lgrp != lpl->lpl_lgrp) {
			return (LPL_TOPO_LGRP_MISMATCH);
		}

		/* do the parent lgroups exist and do they match? */
		if (lgrp->lgrp_parent) {
			ASSERT(lpl->lpl_parent);
			ASSERT(lgrp->lgrp_parent->lgrp_id ==
			    lpl->lpl_parent->lpl_lgrpid);

			if (!lpl->lpl_parent) {
				return (LPL_TOPO_MISSING_PARENT);
			} else if (lgrp->lgrp_parent->lgrp_id !=
			    lpl->lpl_parent->lpl_lgrpid) {
				return (LPL_TOPO_PARENT_MISMATCH);
			}
		}

		/* only leaf lgroups keep a cpucnt, only check leaves */
		if ((lpl->lpl_nrset == 1) && (lpl == lpl->lpl_rset[0])) {

			/* verify that lgrp is also a leaf */
			ASSERT((lgrp->lgrp_childcnt == 0) &&
			    (klgrpset_ismember(lgrp->lgrp_leaves,
			    lpl->lpl_lgrpid)));

			if ((lgrp->lgrp_childcnt > 0) ||
			    (!klgrpset_ismember(lgrp->lgrp_leaves,
			    lpl->lpl_lgrpid))) {
				return (LPL_TOPO_LGRP_NOT_LEAF);
			}

			ASSERT((lgrp->lgrp_cpucnt >= lpl->lpl_ncpu) &&
			    (lpl->lpl_ncpu > 0));
			if ((lgrp->lgrp_cpucnt < lpl->lpl_ncpu) ||
			    (lpl->lpl_ncpu <= 0)) {
				return (LPL_TOPO_BAD_CPUCNT);
			}

			/*
			 * Check that lpl_ncpu also matches the number of
			 * cpus in the lpl's linked list.  This only exists in
			 * leaves, but they should always match.
			 */
			j = 0;
			cpu = cp_start = lpl->lpl_cpus;
			while (cpu != NULL) {
				j++;

				/* check to make sure cpu's lpl is leaf lpl */
				ASSERT(cpu->cpu_lpl == lpl);
				if (cpu->cpu_lpl != lpl) {
					return (LPL_TOPO_CPU_HAS_BAD_LPL);
				}

				/* check next cpu */
				if ((cpu = cpu->cpu_next_lpl) != cp_start) {
					continue;
				} else {
					cpu = NULL;
				}
			}

			ASSERT(j == lpl->lpl_ncpu);
			if (j != lpl->lpl_ncpu) {
				return (LPL_TOPO_LPL_BAD_NCPU);
			}

			/*
			 * Also, check that leaf lpl is contained in all
			 * intermediate lpls that name the leaf as a descendant
			 */
			for (j = 0; j <= lgrp_alloc_max; j++) {
				klgrpset_t intersect;
				lgrp_t *lgrp_cand;
				lpl_t *lpl_cand;

				lgrp_cand = lgrp_table[j];
				intersect = klgrpset_intersects(
				    lgrp_cand->lgrp_set[LGRP_RSRC_CPU],
				    cpupart->cp_lgrpset);

				if (!LGRP_EXISTS(lgrp_cand) ||
				    !klgrpset_intersects(lgrp_cand->lgrp_leaves,
				    cpupart->cp_lgrpset) ||
				    (intersect == 0))
					continue;

				lpl_cand =
				    &cpupart->cp_lgrploads[lgrp_cand->lgrp_id];

				if (klgrpset_ismember(intersect,
				    lgrp->lgrp_id)) {
					ASSERT(lpl_rset_contains(lpl_cand,
					    lpl));

					if (!lpl_rset_contains(lpl_cand, lpl)) {
						return (LPL_TOPO_RSET_MSSNG_LF);
					}
				}
			}

		} else { /* non-leaf specific checks */

			/*
			 * Non-leaf lpls should have lpl_cpus == NULL
			 * verify that this is so
			 */
			ASSERT(lpl->lpl_cpus == NULL);
			if (lpl->lpl_cpus != NULL) {
				return (LPL_TOPO_NONLEAF_HAS_CPUS);
			}

			/*
			 * verify that the sum of the cpus in the leaf resources
			 * is equal to the total ncpu in the intermediate
			 */
			for (j = sum = 0; j < lpl->lpl_nrset; j++) {
				sum += lpl->lpl_rset[j]->lpl_ncpu;
			}

			ASSERT(sum == lpl->lpl_ncpu);
			if (sum != lpl->lpl_ncpu) {
				return (LPL_TOPO_LPL_BAD_NCPU);
			}
		}

		/*
		 * Check the rset of the lpl in question.  Make sure that each
		 * rset contains a subset of the resources in
		 * lgrp_set[LGRP_RSRC_CPU] and in cp_lgrpset.  This also makes
		 * sure that each rset doesn't include resources that are
		 * outside of that set.  (Which would be resources somehow not
		 * accounted for).
		 */
		klgrpset_clear(rset);
		for (j = 0; j < lpl->lpl_nrset; j++) {
			klgrpset_add(rset, lpl->lpl_rset[j]->lpl_lgrpid);
		}
		klgrpset_copy(cset, rset);
		/* make sure lpl rset matches lgrp rset */
		klgrpset_diff(rset, lgrp->lgrp_set[LGRP_RSRC_CPU]);
		/* make sure rset is contained with in partition, too */
		klgrpset_diff(cset, cpupart->cp_lgrpset);

		ASSERT(klgrpset_isempty(rset) && klgrpset_isempty(cset));
		if (!klgrpset_isempty(rset) || !klgrpset_isempty(cset)) {
			return (LPL_TOPO_RSET_MISMATCH);
		}

		/*
		 * check to make sure lpl_nrset matches the number of rsets
		 * contained in the lpl
		 */
		for (j = 0; j < lpl->lpl_nrset; j++) {
			if (lpl->lpl_rset[j] == NULL)
				break;
		}

		ASSERT(j == lpl->lpl_nrset);
		if (j != lpl->lpl_nrset) {
			return (LPL_TOPO_BAD_RSETCNT);
		}

	}
	return (LPL_TOPO_CORRECT);
}

/*
 * Flatten lpl topology to given number of levels.  This is presently only
 * implemented for a flatten to 2 levels, which will prune out the intermediates
 * and home the leaf lpls to the root lpl.
 */
int
lpl_topo_flatten(int levels)
{
	int		i;
	uint_t		sum;
	lgrp_t		*lgrp_cur;
	lpl_t		*lpl_cur;
	lpl_t		*lpl_root;
	cpupart_t	*cp;

	if (levels != 2)
		return (0);

	/* called w/ cpus paused - grab no locks! */
	ASSERT(MUTEX_HELD(&cpu_lock) || curthread->t_preempt > 0 ||
	    !lgrp_initialized);

	cp = cp_list_head;
	do {
		lpl_root = &cp->cp_lgrploads[lgrp_root->lgrp_id];
		ASSERT(LGRP_EXISTS(lgrp_root) && (lpl_root->lpl_ncpu > 0));

		for (i = 0; i <= lgrp_alloc_max; i++) {
			lgrp_cur = lgrp_table[i];
			lpl_cur = &cp->cp_lgrploads[i];

			if ((lgrp_cur == lgrp_root) ||
			    (!LGRP_EXISTS(lgrp_cur) &&
			    (lpl_cur->lpl_ncpu == 0)))
				continue;

			if (!LGRP_EXISTS(lgrp_cur) && (lpl_cur->lpl_ncpu > 0)) {
				/*
				 * this should be a deleted intermediate, so
				 * clear it
				 */
				lpl_clear(lpl_cur);
			} else if ((lpl_cur->lpl_nrset == 1) &&
			    (lpl_cur->lpl_rset[0] == lpl_cur) &&
			    ((lpl_cur->lpl_parent->lpl_ncpu == 0) ||
			    (!LGRP_EXISTS(lpl_cur->lpl_parent->lpl_lgrp)))) {
				/*
				 * this is a leaf whose parent was deleted, or
				 * whose parent had their lgrp deleted.  (And
				 * whose parent will soon be deleted).  Point
				 * this guy back to the root lpl.
				 */
				lpl_cur->lpl_parent = lpl_root;
				lpl_rset_add(lpl_root, lpl_cur);
			}

		}

		/*
		 * Now that we're done, make sure the count on the root lpl is
		 * correct, and update the hints of the children for the sake of
		 * thoroughness
		 */
		for (i = sum = 0; i < lpl_root->lpl_nrset; i++) {
			sum += lpl_root->lpl_rset[i]->lpl_ncpu;
		}
		lpl_root->lpl_ncpu = sum;
		lpl_child_update(lpl_root, cp);

		cp = cp->cp_next;
	} while (cp != cp_list_head);

	return (levels);
}

/*
 * Insert a lpl into the resource hierarchy and create any additional lpls that
 * are necessary to represent the varying states of locality for the cpu
 * resoruces newly added to the partition.
 *
 * This routine is clever enough that it can correctly add resources from the
 * new leaf into both direct and indirect resource sets in the hierarchy.  (Ie,
 * those for which the lpl is a leaf as opposed to simply a named equally local
 * resource).  The one special case that needs additional processing is when a
 * new intermediate lpl is introduced.  Since the main loop only traverses
 * looking to add the leaf resource where it does not yet exist, additional work
 * is necessary to add other leaf resources that may need to exist in the newly
 * created intermediate.  This is performed by the second inner loop, and is
 * only done when the check for more than one overlapping resource succeeds.
 */

void
lpl_leaf_insert(lpl_t *lpl_leaf, cpupart_t *cpupart)
{
	int		i;
	int		j;
	int		rset_num_intersect;
	lgrp_t		*lgrp_cur;
	lpl_t		*lpl_cur;
	lpl_t		*lpl_parent;
	lgrp_id_t	parent_id;
	klgrpset_t	rset_intersect; /* resources in cpupart and lgrp */

	for (i = 0; i <= lgrp_alloc_max; i++) {
		lgrp_cur = lgrp_table[i];

		/*
		 * Don't insert if the lgrp isn't there, if the leaf isn't
		 * contained within the current lgrp, or if the current lgrp has
		 * no leaves in this partition
		 */

		if (!LGRP_EXISTS(lgrp_cur) ||
		    !klgrpset_ismember(lgrp_cur->lgrp_set[LGRP_RSRC_CPU],
		    lpl_leaf->lpl_lgrpid) ||
		    !klgrpset_intersects(lgrp_cur->lgrp_leaves,
		    cpupart->cp_lgrpset))
			continue;

		lpl_cur = &cpupart->cp_lgrploads[lgrp_cur->lgrp_id];
		if (lgrp_cur->lgrp_parent != NULL) {
			/* if lgrp has a parent, assign it properly */
			parent_id = lgrp_cur->lgrp_parent->lgrp_id;
			lpl_parent = &cpupart->cp_lgrploads[parent_id];
		} else {
			/* if not, make sure parent ptr gets set to null */
			lpl_parent = NULL;
		}

		if (lpl_cur == lpl_leaf) {
			/*
			 * Almost all leaf state was initialized elsewhere.  The
			 * only thing left to do is to set the parent.
			 */
			lpl_cur->lpl_parent = lpl_parent;
			continue;
		}

		lpl_clear(lpl_cur);
		lpl_init(lpl_cur, lpl_leaf, lgrp_cur);

		lpl_cur->lpl_parent = lpl_parent;

		/* does new lpl need to be populated with other resources? */
		rset_intersect =
		    klgrpset_intersects(lgrp_cur->lgrp_set[LGRP_RSRC_CPU],
		    cpupart->cp_lgrpset);
		klgrpset_nlgrps(rset_intersect, rset_num_intersect);

		if (rset_num_intersect > 1) {
			/*
			 * If so, figure out what lpls have resources that
			 * intersect this one, and add them.
			 */
			for (j = 0; j <= lgrp_alloc_max; j++) {
				lgrp_t	*lgrp_cand;	/* candidate lgrp */
				lpl_t	*lpl_cand;	/* candidate lpl */

				lgrp_cand = lgrp_table[j];
				if (!LGRP_EXISTS(lgrp_cand) ||
				    !klgrpset_ismember(rset_intersect,
				    lgrp_cand->lgrp_id))
					continue;
				lpl_cand =
				    &cpupart->cp_lgrploads[lgrp_cand->lgrp_id];
				lpl_rset_add(lpl_cur, lpl_cand);
			}
		}
		/*
		 * This lpl's rset has changed. Update the hint in it's
		 * children.
		 */
		lpl_child_update(lpl_cur, cpupart);
	}
}

/*
 * remove a lpl from the hierarchy of resources, clearing its state when
 * finished.  If the lpls at the intermediate levels of the hierarchy have no
 * remaining resources, or no longer name a leaf resource in the cpu-partition,
 * delete them as well.
 */

void
lpl_leaf_remove(lpl_t *lpl_leaf, cpupart_t *cpupart)
{
	int		i;
	lgrp_t		*lgrp_cur;
	lpl_t		*lpl_cur;
	klgrpset_t	leaf_intersect;	/* intersection of leaves */

	for (i = 0; i <= lgrp_alloc_max; i++) {
		lgrp_cur = lgrp_table[i];

		/*
		 * Don't attempt to remove from lgrps that aren't there, that
		 * don't contain our leaf, or from the leaf itself. (We do that
		 * later)
		 */

		if (!LGRP_EXISTS(lgrp_cur))
			continue;

		lpl_cur = &cpupart->cp_lgrploads[lgrp_cur->lgrp_id];

		if (!klgrpset_ismember(lgrp_cur->lgrp_set[LGRP_RSRC_CPU],
		    lpl_leaf->lpl_lgrpid) ||
		    (lpl_cur == lpl_leaf)) {
			continue;
		}

		/*
		 * This is a slightly sleazy simplification in that we have
		 * already marked the cp_lgrpset as no longer containing the
		 * leaf we've deleted.  Any lpls that pass the above checks
		 * based upon lgrp membership but not necessarily cpu-part
		 * membership also get cleared by the checks below.  Currently
		 * this is harmless, as the lpls should be empty anyway.
		 *
		 * In particular, we want to preserve lpls that have additional
		 * leaf resources, even though we don't yet have a processor
		 * architecture that represents resources this way.
		 */

		leaf_intersect = klgrpset_intersects(lgrp_cur->lgrp_leaves,
		    cpupart->cp_lgrpset);

		lpl_rset_del(lpl_cur, lpl_leaf);
		if ((lpl_cur->lpl_nrset == 0) || (!leaf_intersect)) {
			lpl_clear(lpl_cur);
		} else {
			/*
			 * Update this lpl's children
			 */
			lpl_child_update(lpl_cur, cpupart);
		}
	}
	lpl_clear(lpl_leaf);
}

/*
 * add a cpu to a partition in terms of lgrp load avg bookeeping
 *
 * The lpl (cpu partition load average information) is now arranged in a
 * hierarchical fashion whereby resources that are closest, ie. most local, to
 * the cpu in question are considered to be leaves in a tree of resources.
 * There are two general cases for cpu additon:
 *
 * 1. A lpl structure that contains resources already in the hierarchy tree.
 * In this case, all of the associated lpl relationships have been defined, and
 * all that is necessary is that we link the new cpu into the per-lpl list of
 * cpus, and increment the ncpu count of all places where this cpu resource will
 * be accounted for.  lpl_cpu_adjcnt updates the cpu count, and the cpu pointer
 * pushing is accomplished by this routine.
 *
 * 2. The lpl to contain the resources in this cpu-partition for this lgrp does
 * not exist yet.  In this case, it is necessary to build the leaf lpl, and
 * construct the hierarchy of state necessary to name it's more distant
 * resources, if they should exist.  The leaf structure is initialized by this
 * routine, as is the cpu-partition state for the lgrp membership.  This routine
 * also calls lpl_leaf_insert() which inserts the named lpl into the hierarchy
 * and builds all of the "ancestoral" state necessary to identify resources at
 * differing levels of locality.
 */
void
lgrp_part_add_cpu(cpu_t *cp, lgrp_id_t lgrpid)
{
	cpupart_t	*cpupart;
	lgrp_t		*lgrp_leaf;
	lpl_t		*lpl_leaf;

	/* called sometimes w/ cpus paused - grab no locks */
	ASSERT(MUTEX_HELD(&cpu_lock) || !lgrp_initialized);

	cpupart = cp->cpu_part;
	lgrp_leaf = lgrp_table[lgrpid];

	/* don't add non-existent lgrp */
	ASSERT(LGRP_EXISTS(lgrp_leaf));
	lpl_leaf = &cpupart->cp_lgrploads[lgrpid];
	cp->cpu_lpl = lpl_leaf;

	/* only leaf lpls contain cpus */

	if (lpl_leaf->lpl_ncpu++ == 0) {
		lpl_init(lpl_leaf, lpl_leaf, lgrp_leaf);
		klgrpset_add(cpupart->cp_lgrpset, lgrpid);
		lpl_leaf_insert(lpl_leaf, cpupart);
	} else {
		/*
		 * the lpl should already exist in the parent, so just update
		 * the count of available CPUs
		 */
		lpl_cpu_adjcnt(LPL_INCREMENT, cp);
	}

	/* link cpu into list of cpus in lpl */

	if (lpl_leaf->lpl_cpus) {
		cp->cpu_next_lpl = lpl_leaf->lpl_cpus;
		cp->cpu_prev_lpl = lpl_leaf->lpl_cpus->cpu_prev_lpl;
		lpl_leaf->lpl_cpus->cpu_prev_lpl->cpu_next_lpl = cp;
		lpl_leaf->lpl_cpus->cpu_prev_lpl = cp;
	} else {
		/*
		 * We increment ncpu immediately after we create a new leaf
		 * lpl, so assert that ncpu == 1 for the case where we don't
		 * have any cpu pointers yet.
		 */
		ASSERT(lpl_leaf->lpl_ncpu == 1);
		lpl_leaf->lpl_cpus = cp->cpu_next_lpl = cp->cpu_prev_lpl = cp;
	}

}


/*
 * remove a cpu from a partition in terms of lgrp load avg bookeeping
 *
 * The lpl (cpu partition load average information) is now arranged in a
 * hierarchical fashion whereby resources that are closest, ie. most local, to
 * the cpu in question are considered to be leaves in a tree of resources.
 * There are two removal cases in question:
 *
 * 1. Removal of the resource in the leaf leaves other resources remaining in
 * that leaf.  (Another cpu still exists at this level of locality).  In this
 * case, the count of available cpus is decremented in all assocated lpls by
 * calling lpl_adj_cpucnt(), and the pointer to the removed cpu is pruned
 * from the per-cpu lpl list.
 *
 * 2. Removal of the resource results in the lpl containing no resources.  (It's
 * empty)  In this case, all of what has occurred for the first step must take
 * place; however, additionally we must remove the lpl structure itself, prune
 * out any stranded lpls that do not directly name a leaf resource, and mark the
 * cpu partition in question as no longer containing resources from the lgrp of
 * the lpl that has been delted.  Cpu-partition changes are handled by this
 * method, but the lpl_leaf_remove function deals with the details of pruning
 * out the empty lpl and any of its orphaned direct ancestors.
 */
void
lgrp_part_del_cpu(cpu_t *cp)
{
	lpl_t		*lpl;
	lpl_t		*leaf_lpl;
	lgrp_t		*lgrp_leaf;

	/* called sometimes w/ cpus paused - grab no locks */

	ASSERT(MUTEX_HELD(&cpu_lock) || !lgrp_initialized);

	lpl = leaf_lpl = cp->cpu_lpl;
	lgrp_leaf = leaf_lpl->lpl_lgrp;

	/* don't delete a leaf that isn't there */
	ASSERT(LGRP_EXISTS(lgrp_leaf));

	/* no double-deletes */
	ASSERT(lpl->lpl_ncpu);
	if (--lpl->lpl_ncpu == 0) {
		/*
		 * This was the last cpu in this lgroup for this partition,
		 * clear its bit in the partition's lgroup bitmask
		 */
		klgrpset_del(cp->cpu_part->cp_lgrpset, lpl->lpl_lgrpid);

		/* eliminate remaning lpl link pointers in cpu, lpl */
		lpl->lpl_cpus = cp->cpu_next_lpl = cp->cpu_prev_lpl = NULL;

		lpl_leaf_remove(leaf_lpl, cp->cpu_part);
	} else {

		/* unlink cpu from lists of cpus in lpl */
		cp->cpu_prev_lpl->cpu_next_lpl = cp->cpu_next_lpl;
		cp->cpu_next_lpl->cpu_prev_lpl = cp->cpu_prev_lpl;
		if (lpl->lpl_cpus == cp) {
			lpl->lpl_cpus = cp->cpu_next_lpl;
		}

		/*
		 * Update the cpu count in the lpls associated with parent
		 * lgroups.
		 */
		lpl_cpu_adjcnt(LPL_DECREMENT, cp);

	}
	/* clear cpu's lpl ptr when we're all done */
	cp->cpu_lpl = NULL;
}

/*
 * Recompute load average for the specified partition/lgrp fragment.
 *
 * We rely on the fact that this routine is called from the clock thread
 * at a point before the clock thread can block (i.e. before its first
 * lock request).  Since the clock thread can not be preempted (since it
 * runs at highest priority), we know that cpu partitions can not change
 * (since doing so would require either the repartition requester or the
 * cpu_pause thread to run on this cpu), so we can update the cpu's load
 * without grabbing cpu_lock.
 */
void
lgrp_loadavg(lpl_t *lpl, uint_t nrcpus, int ageflag)
{
	uint_t		ncpu;
	int64_t		old, new, f;

	/*
	 * 1 - exp(-1/(20 * ncpu)) << 13 = 400 for 1 cpu...
	 */
	static short expval[] = {
	    0, 3196, 1618, 1083,
	    814, 652, 543, 466,
	    408, 363, 326, 297,
	    272, 251, 233, 218,
	    204, 192, 181, 172,
	    163, 155, 148, 142,
	    136, 130, 125, 121,
	    116, 112, 109, 105
	};

	/* ASSERT (called from clock level) */

	if ((lpl == NULL) ||	/* we're booting - this is easiest for now */
	    ((ncpu = lpl->lpl_ncpu) == 0)) {
		return;
	}

	for (;;) {

		if (ncpu >= sizeof (expval) / sizeof (expval[0]))
			f = expval[1]/ncpu; /* good approx. for large ncpu */
		else
			f = expval[ncpu];

		/*
		 * Modify the load average atomically to avoid losing
		 * anticipatory load updates (see lgrp_move_thread()).
		 */
		if (ageflag) {
			/*
			 * We're supposed to both update and age the load.
			 * This happens 10 times/sec. per cpu.  We do a
			 * little hoop-jumping to avoid integer overflow.
			 */
			int64_t		q, r;

			do {
				old = new = lpl->lpl_loadavg;
				q = (old  >> 16) << 7;
				r = (old  & 0xffff) << 7;
				new += ((long long)(nrcpus - q) * f -
				    ((r * f) >> 16)) >> 7;

				/*
				 * Check for overflow
				 */
				if (new > LGRP_LOADAVG_MAX)
					new = LGRP_LOADAVG_MAX;
				else if (new < 0)
					new = 0;
			} while (atomic_cas_32((lgrp_load_t *)&lpl->lpl_loadavg,
			    old, new) != old);
		} else {
			/*
			 * We're supposed to update the load, but not age it.
			 * This option is used to update the load (which either
			 * has already been aged in this 1/10 sec. interval or
			 * soon will be) to account for a remotely executing
			 * thread.
			 */
			do {
				old = new = lpl->lpl_loadavg;
				new += f;
				/*
				 * Check for overflow
				 * Underflow not possible here
				 */
				if (new < old)
					new = LGRP_LOADAVG_MAX;
			} while (atomic_cas_32((lgrp_load_t *)&lpl->lpl_loadavg,
			    old, new) != old);
		}

		/*
		 * Do the same for this lpl's parent
		 */
		if ((lpl = lpl->lpl_parent) == NULL)
			break;
		ncpu = lpl->lpl_ncpu;
	}
}

/*
 * Initialize lpl topology in the target based on topology currently present in
 * lpl_bootstrap.
 *
 * lpl_topo_bootstrap is only called once from cpupart_initialize_default() to
 * initialize cp_default list of lpls. Up to this point all topology operations
 * were performed using lpl_bootstrap. Now cp_default has its own list of lpls
 * and all subsequent lpl operations should use it instead of lpl_bootstrap. The
 * `target' points to the list of lpls in cp_default and `size' is the size of
 * this list.
 *
 * This function walks the lpl topology in lpl_bootstrap and does for things:
 *
 * 1) Copies all fields from lpl_bootstrap to the target.
 *
 * 2) Sets CPU0 lpl pointer to the correct element of the target list.
 *
 * 3) Updates lpl_parent pointers to point to the lpls in the target list
 *    instead of lpl_bootstrap.
 *
 * 4) Updates pointers in the resource list of the target to point to the lpls
 *    in the target list instead of lpl_bootstrap.
 *
 * After lpl_topo_bootstrap() completes, target contains the same information
 * that would be present there if it were used during boot instead of
 * lpl_bootstrap. There is no need in information in lpl_bootstrap after this
 * and it is bzeroed.
 */
void
lpl_topo_bootstrap(lpl_t *target, int size)
{
	lpl_t	*lpl = lpl_bootstrap;
	lpl_t	*target_lpl = target;
	lpl_t	**rset;
	int	*id2rset;
	int	sz;
	int	howmany;
	int	id;
	int	i;

	/*
	 * The only target that should be passed here is cp_default lpl list.
	 */
	ASSERT(target == cp_default.cp_lgrploads);
	ASSERT(size == cp_default.cp_nlgrploads);
	ASSERT(!lgrp_topo_initialized);
	ASSERT(ncpus == 1);

	howmany = MIN(LPL_BOOTSTRAP_SIZE, size);
	for (i = 0; i < howmany; i++, lpl++, target_lpl++) {
		/*
		 * Copy all fields from lpl, except for the rset,
		 * lgrp id <=> rset mapping storage,
		 * and amount of storage
		 */
		rset = target_lpl->lpl_rset;
		id2rset = target_lpl->lpl_id2rset;
		sz = target_lpl->lpl_rset_sz;

		*target_lpl = *lpl;

		target_lpl->lpl_rset_sz = sz;
		target_lpl->lpl_rset = rset;
		target_lpl->lpl_id2rset = id2rset;

		/*
		 * Substitute CPU0 lpl pointer with one relative to target.
		 */
		if (lpl->lpl_cpus == CPU) {
			ASSERT(CPU->cpu_lpl == lpl);
			CPU->cpu_lpl = target_lpl;
		}

		/*
		 * Substitute parent information with parent relative to target.
		 */
		if (lpl->lpl_parent != NULL)
			target_lpl->lpl_parent = (lpl_t *)
			    (((uintptr_t)lpl->lpl_parent -
			    (uintptr_t)lpl_bootstrap) +
			    (uintptr_t)target);

		/*
		 * Walk over resource set substituting pointers relative to
		 * lpl_bootstrap's rset to pointers relative to target's
		 */
		ASSERT(lpl->lpl_nrset <= 1);

		for (id = 0; id < lpl->lpl_nrset; id++) {
			if (lpl->lpl_rset[id] != NULL) {
				target_lpl->lpl_rset[id] = (lpl_t *)
				    (((uintptr_t)lpl->lpl_rset[id] -
				    (uintptr_t)lpl_bootstrap) +
				    (uintptr_t)target);
			}
			target_lpl->lpl_id2rset[id] =
			    lpl->lpl_id2rset[id];
		}
	}

	/*
	 * Clean up the bootstrap lpls since we have switched over to the
	 * actual lpl array in the default cpu partition.
	 *
	 * We still need to keep one empty lpl around for newly starting
	 * slave CPUs to reference should they need to make it through the
	 * dispatcher prior to their lgrp/lpl initialization.
	 *
	 * The lpl related dispatcher code has been designed to work properly
	 * (and without extra checks) for this special case of a zero'ed
	 * bootstrap lpl. Such an lpl appears to the dispatcher as an lpl
	 * with lgrpid 0 and an empty resource set. Iteration over the rset
	 * array by the dispatcher is also NULL terminated for this reason.
	 *
	 * This provides the desired behaviour for an uninitialized CPU.
	 * It shouldn't see any other CPU to either dispatch to or steal
	 * from until it is properly initialized.
	 */
	bzero(lpl_bootstrap_list, sizeof (lpl_bootstrap_list));
	bzero(lpl_bootstrap_id2rset, sizeof (lpl_bootstrap_id2rset));
	bzero(lpl_bootstrap_rset, sizeof (lpl_bootstrap_rset));

	lpl_bootstrap_list[0].lpl_rset = lpl_bootstrap_rset;
	lpl_bootstrap_list[0].lpl_id2rset = lpl_bootstrap_id2rset;
}

/*
 * If the lowest load among the lgroups a process' threads are currently
 * spread across is greater than lgrp_expand_proc_thresh, we'll consider
 * expanding the process to a new lgroup.
 */
#define	LGRP_EXPAND_PROC_THRESH_DEFAULT 62250
lgrp_load_t	lgrp_expand_proc_thresh = LGRP_EXPAND_PROC_THRESH_DEFAULT;

#define	LGRP_EXPAND_PROC_THRESH(ncpu) \
	((lgrp_expand_proc_thresh) / (ncpu))

/*
 * A process will be expanded to a new lgroup only if the difference between
 * the lowest load on the lgroups the process' thread's are currently spread
 * across and the lowest load on the other lgroups in the process' partition
 * is greater than lgrp_expand_proc_diff.
 */
#define	LGRP_EXPAND_PROC_DIFF_DEFAULT 60000
lgrp_load_t	lgrp_expand_proc_diff = LGRP_EXPAND_PROC_DIFF_DEFAULT;

#define	LGRP_EXPAND_PROC_DIFF(ncpu) \
	((lgrp_expand_proc_diff) / (ncpu))

/*
 * The loadavg tolerance accounts for "noise" inherent in the load, which may
 * be present due to impreciseness of the load average decay algorithm.
 *
 * The default tolerance is lgrp_loadavg_max_effect. Note that the tunable
 * tolerance is scaled by the number of cpus in the lgroup just like
 * lgrp_loadavg_max_effect. For example, if lgrp_loadavg_tolerance = 0x10000,
 * and ncpu = 4, then lgrp_choose will consider differences in lgroup loads
 * of: 0x10000 / 4 => 0x4000 or greater to be significant.
 */
uint32_t	lgrp_loadavg_tolerance = LGRP_LOADAVG_THREAD_MAX;
#define	LGRP_LOADAVG_TOLERANCE(ncpu)	\
	((lgrp_loadavg_tolerance) / ncpu)

/*
 * lgrp_choose() will choose root lgroup as home when lowest lgroup load
 * average is above this threshold
 */
uint32_t	lgrp_load_thresh = UINT32_MAX;

/*
 * lgrp_choose() will try to skip any lgroups with less memory
 * than this free when choosing a home lgroup
 */
pgcnt_t	lgrp_mem_free_thresh = 0;

/*
 * When choosing between similarly loaded lgroups, lgrp_choose() will pick
 * one based on one of the following policies:
 * - Random selection
 * - Pseudo round robin placement
 * - Longest time since a thread was last placed
 */
#define	LGRP_CHOOSE_RANDOM	1
#define	LGRP_CHOOSE_RR		2
#define	LGRP_CHOOSE_TIME	3

int	lgrp_choose_policy = LGRP_CHOOSE_TIME;

/*
 * Choose a suitable leaf lgroup for a kthread.  The kthread is assumed not to
 * be bound to a CPU or processor set.
 *
 * Arguments:
 *	t		The thread
 *	cpupart		The partition the thread belongs to.
 *
 * NOTE: Should at least be called with the cpu_lock held, kernel preemption
 *	 disabled, or thread_lock held (at splhigh) to protect against the CPU
 *	 partitions changing out from under us and assumes that given thread is
 *	 protected.  Also, called sometimes w/ cpus paused or kernel preemption
 *	 disabled, so don't grab any locks because we should never block under
 *	 those conditions.
 */
lpl_t *
lgrp_choose(kthread_t *t, cpupart_t *cpupart)
{
	lgrp_load_t	bestload, bestrload;
	int		lgrpid_offset, lgrp_count;
	lgrp_id_t	lgrpid, lgrpid_start;
	lpl_t		*lpl, *bestlpl, *bestrlpl;
	klgrpset_t	lgrpset;
	proc_t		*p;

	ASSERT(t != NULL);
	ASSERT(MUTEX_HELD(&cpu_lock) || curthread->t_preempt > 0 ||
	    THREAD_LOCK_HELD(t));
	ASSERT(cpupart != NULL);

	p = t->t_procp;

	/* A process should always be in an active partition */
	ASSERT(!klgrpset_isempty(cpupart->cp_lgrpset));

	bestlpl = bestrlpl = NULL;
	bestload = bestrload = LGRP_LOADAVG_MAX;
	lgrpset = cpupart->cp_lgrpset;

	switch (lgrp_choose_policy) {
	case LGRP_CHOOSE_RR:
		lgrpid = cpupart->cp_lgrp_hint;
		do {
			if (++lgrpid > lgrp_alloc_max)
				lgrpid = 0;
		} while (!klgrpset_ismember(lgrpset, lgrpid));

		break;
	default:
	case LGRP_CHOOSE_TIME:
	case LGRP_CHOOSE_RANDOM:
		klgrpset_nlgrps(lgrpset, lgrp_count);
		lgrpid_offset =
		    (((ushort_t)(gethrtime() >> 4)) % lgrp_count) + 1;
		for (lgrpid = 0; ; lgrpid++) {
			if (klgrpset_ismember(lgrpset, lgrpid)) {
				if (--lgrpid_offset == 0)
					break;
			}
		}
		break;
	}

	lgrpid_start = lgrpid;

	DTRACE_PROBE2(lgrp_choose_start, lgrp_id_t, lgrpid_start,
	    lgrp_id_t, cpupart->cp_lgrp_hint);

	/*
	 * Use lgroup affinities (if any) to choose best lgroup
	 *
	 * NOTE: Assumes that thread is protected from going away and its
	 *	 lgroup affinities won't change (ie. p_lock, or
	 *	 thread_lock() being held and/or CPUs paused)
	 */
	if (t->t_lgrp_affinity) {
		lpl = lgrp_affinity_best(t, cpupart, lgrpid_start, B_FALSE);
		if (lpl != NULL)
			return (lpl);
	}

	ASSERT(klgrpset_ismember(lgrpset, lgrpid_start));

	do {
		pgcnt_t	npgs;

		/*
		 * Skip any lgroups outside of thread's pset
		 */
		if (!klgrpset_ismember(lgrpset, lgrpid)) {
			if (++lgrpid > lgrp_alloc_max)
				lgrpid = 0;	/* wrap the search */
			continue;
		}

		/*
		 * Skip any non-leaf lgroups
		 */
		if (lgrp_table[lgrpid]->lgrp_childcnt != 0)
			continue;

		/*
		 * Skip any lgroups without enough free memory
		 * (when threshold set to nonzero positive value)
		 */
		if (lgrp_mem_free_thresh > 0) {
			npgs = lgrp_mem_size(lgrpid, LGRP_MEM_SIZE_FREE);
			if (npgs < lgrp_mem_free_thresh) {
				if (++lgrpid > lgrp_alloc_max)
					lgrpid = 0;	/* wrap the search */
				continue;
			}
		}

		lpl = &cpupart->cp_lgrploads[lgrpid];
		if (klgrpset_isempty(p->p_lgrpset) ||
		    klgrpset_ismember(p->p_lgrpset, lgrpid)) {
			/*
			 * Either this is a new process or the process already
			 * has threads on this lgrp, so this is a preferred
			 * lgroup for the thread.
			 */
			if (bestlpl == NULL ||
			    lpl_pick(lpl, bestlpl)) {
				bestload = lpl->lpl_loadavg;
				bestlpl = lpl;
			}
		} else {
			/*
			 * The process doesn't have any threads on this lgrp,
			 * but we're willing to consider this lgrp if the load
			 * difference is big enough to justify splitting up
			 * the process' threads.
			 */
			if (bestrlpl == NULL ||
			    lpl_pick(lpl, bestrlpl)) {
				bestrload = lpl->lpl_loadavg;
				bestrlpl = lpl;
			}
		}
		if (++lgrpid > lgrp_alloc_max)
			lgrpid = 0;	/* wrap the search */
	} while (lgrpid != lgrpid_start);

	/*
	 * Return root lgroup if threshold isn't set to maximum value and
	 * lowest lgroup load average more than a certain threshold
	 */
	if (lgrp_load_thresh != UINT32_MAX &&
	    bestload >= lgrp_load_thresh && bestrload >= lgrp_load_thresh)
		return (&cpupart->cp_lgrploads[lgrp_root->lgrp_id]);

	/*
	 * If all the lgroups over which the thread's process is spread are
	 * heavily loaded, or otherwise undesirable, we'll consider placing
	 * the thread on one of the other leaf lgroups in the thread's
	 * partition.
	 */
	if ((bestlpl == NULL) ||
	    ((bestload > LGRP_EXPAND_PROC_THRESH(bestlpl->lpl_ncpu)) &&
	    (bestrload < bestload) &&	/* paranoid about wraparound */
	    (bestrload + LGRP_EXPAND_PROC_DIFF(bestrlpl->lpl_ncpu) <
	    bestload))) {
		bestlpl = bestrlpl;
	}

	if (bestlpl == NULL) {
		/*
		 * No lgroup looked particularly good, but we still
		 * have to pick something. Go with the randomly selected
		 * legal lgroup we started with above.
		 */
		bestlpl = &cpupart->cp_lgrploads[lgrpid_start];
	}

	cpupart->cp_lgrp_hint = bestlpl->lpl_lgrpid;
	bestlpl->lpl_homed_time = gethrtime_unscaled();

	ASSERT(bestlpl->lpl_ncpu > 0);
	return (bestlpl);
}

/*
 * Decide if lpl1 is a better candidate than lpl2 for lgrp homing.
 * Returns non-zero if lpl1 is a better candidate, and 0 otherwise.
 */
static int
lpl_pick(lpl_t *lpl1, lpl_t *lpl2)
{
	lgrp_load_t	l1, l2;
	lgrp_load_t	tolerance = LGRP_LOADAVG_TOLERANCE(lpl1->lpl_ncpu);

	l1 = lpl1->lpl_loadavg;
	l2 = lpl2->lpl_loadavg;

	if ((l1 + tolerance < l2) && (l1 < l2)) {
		/* lpl1 is significantly less loaded than lpl2 */
		return (1);
	}

	if (lgrp_choose_policy == LGRP_CHOOSE_TIME &&
	    l1 + tolerance >= l2 && l1 < l2 &&
	    lpl1->lpl_homed_time < lpl2->lpl_homed_time) {
		/*
		 * lpl1's load is within the tolerance of lpl2. We're
		 * willing to consider it be to better however if
		 * it has been longer since we last homed a thread there
		 */
		return (1);
	}

	return (0);
}

/*
 * lgrp_trthr_moves counts the number of times main thread (t_tid = 1) of a
 * process that uses text replication changed home lgrp. This info is used by
 * segvn asyncronous thread to detect if it needs to recheck what lgrps
 * should be used for text replication.
 */
static uint64_t lgrp_trthr_moves = 0;

uint64_t
lgrp_get_trthr_migrations(void)
{
	return (lgrp_trthr_moves);
}

void
lgrp_update_trthr_migrations(uint64_t incr)
{
	atomic_add_64(&lgrp_trthr_moves, incr);
}

/*
 * An LWP is expected to be assigned to an lgroup for at least this long
 * for its anticipatory load to be justified.  NOTE that this value should
 * not be set extremely huge (say, larger than 100 years), to avoid problems
 * with overflow in the calculation that uses it.
 */
#define	LGRP_MIN_NSEC	(NANOSEC / 10)		/* 1/10 of a second */
hrtime_t lgrp_min_nsec = LGRP_MIN_NSEC;

/*
 * Routine to change a thread's lgroup affiliation.  This routine updates
 * the thread's kthread_t struct and its process' proc_t struct to note the
 * thread's new lgroup affiliation, and its lgroup affinities.
 *
 * Note that this is the only routine that modifies a thread's t_lpl field,
 * and that adds in or removes anticipatory load.
 *
 * If the thread is exiting, newlpl is NULL.
 *
 * Locking:
 * The following lock must be held on entry:
 *	cpu_lock, kpreempt_disable(), or thread_lock -- to assure t's new lgrp
 *		doesn't get removed from t's partition
 *
 * This routine is not allowed to grab any locks, since it may be called
 * with cpus paused (such as from cpu_offline).
 */
void
lgrp_move_thread(kthread_t *t, lpl_t *newlpl, int do_lgrpset_delete)
{
	proc_t		*p;
	lpl_t		*lpl, *oldlpl;
	lgrp_id_t	oldid;
	kthread_t	*tp;
	uint_t		ncpu;
	lgrp_load_t	old, new;

	ASSERT(t);
	ASSERT(MUTEX_HELD(&cpu_lock) || curthread->t_preempt > 0 ||
	    THREAD_LOCK_HELD(t));

	/*
	 * If not changing lpls, just return
	 */
	if ((oldlpl = t->t_lpl) == newlpl)
		return;

	/*
	 * Make sure the thread's lwp hasn't exited (if so, this thread is now
	 * associated with process 0 rather than with its original process).
	 */
	if (t->t_proc_flag & TP_LWPEXIT) {
		if (newlpl != NULL) {
			t->t_lpl = newlpl;
		}
		return;
	}

	p = ttoproc(t);

	/*
	 * If the thread had a previous lgroup, update its process' p_lgrpset
	 * to account for it being moved from its old lgroup.
	 */
	if ((oldlpl != NULL) &&	/* thread had a previous lgroup */
	    (p->p_tlist != NULL)) {
		oldid = oldlpl->lpl_lgrpid;

		if (newlpl != NULL)
			lgrp_stat_add(oldid, LGRP_NUM_MIGR, 1);

		if ((do_lgrpset_delete) &&
		    (klgrpset_ismember(p->p_lgrpset, oldid))) {
			for (tp = p->p_tlist->t_forw; ; tp = tp->t_forw) {
				/*
				 * Check if a thread other than the thread
				 * that's moving is assigned to the same
				 * lgroup as the thread that's moving.  Note
				 * that we have to compare lgroup IDs, rather
				 * than simply comparing t_lpl's, since the
				 * threads may belong to different partitions
				 * but be assigned to the same lgroup.
				 */
				ASSERT(tp->t_lpl != NULL);

				if ((tp != t) &&
				    (tp->t_lpl->lpl_lgrpid == oldid)) {
					/*
					 * Another thread is assigned to the
					 * same lgroup as the thread that's
					 * moving, p_lgrpset doesn't change.
					 */
					break;
				} else if (tp == p->p_tlist) {
					/*
					 * No other thread is assigned to the
					 * same lgroup as the exiting thread,
					 * clear the lgroup's bit in p_lgrpset.
					 */
					klgrpset_del(p->p_lgrpset, oldid);
					break;
				}
			}
		}

		/*
		 * If this thread was assigned to its old lgroup for such a
		 * short amount of time that the anticipatory load that was
		 * added on its behalf has aged very little, remove that
		 * anticipatory load.
		 */
		if ((t->t_anttime + lgrp_min_nsec > gethrtime()) &&
		    ((ncpu = oldlpl->lpl_ncpu) > 0)) {
			lpl = oldlpl;
			for (;;) {
				do {
					old = new = lpl->lpl_loadavg;
					new -= LGRP_LOADAVG_MAX_EFFECT(ncpu);
					if (new > old) {
						/*
						 * this can happen if the load
						 * average was aged since we
						 * added in the anticipatory
						 * load
						 */
						new = 0;
					}
				} while (atomic_cas_32(
				    (lgrp_load_t *)&lpl->lpl_loadavg, old,
				    new) != old);

				lpl = lpl->lpl_parent;
				if (lpl == NULL)
					break;

				ncpu = lpl->lpl_ncpu;
				ASSERT(ncpu > 0);
			}
		}
	}
	/*
	 * If the thread has a new lgroup (i.e. it's not exiting), update its
	 * t_lpl and its process' p_lgrpset, and apply an anticipatory load
	 * to its new lgroup to account for its move to its new lgroup.
	 */
	if (newlpl != NULL) {
		/*
		 * This thread is moving to a new lgroup
		 */
		t->t_lpl = newlpl;
		if (t->t_tid == 1 && p->p_t1_lgrpid != newlpl->lpl_lgrpid) {
			p->p_t1_lgrpid = newlpl->lpl_lgrpid;
			membar_producer();
			if (p->p_tr_lgrpid != LGRP_NONE &&
			    p->p_tr_lgrpid != p->p_t1_lgrpid) {
				lgrp_update_trthr_migrations(1);
			}
		}

		/*
		 * Reflect move in load average of new lgroup
		 * unless it is root lgroup
		 */
		if (lgrp_table[newlpl->lpl_lgrpid] == lgrp_root)
			return;

		if (!klgrpset_ismember(p->p_lgrpset, newlpl->lpl_lgrpid)) {
			klgrpset_add(p->p_lgrpset, newlpl->lpl_lgrpid);
		}

		/*
		 * It'll take some time for the load on the new lgroup
		 * to reflect this thread's placement on it.  We'd
		 * like not, however, to have all threads between now
		 * and then also piling on to this lgroup.  To avoid
		 * this pileup, we anticipate the load this thread
		 * will generate on its new lgroup.  The goal is to
		 * make the lgroup's load appear as though the thread
		 * had been there all along.  We're very conservative
		 * in calculating this anticipatory load, we assume
		 * the worst case case (100% CPU-bound thread).  This
		 * may be modified in the future to be more accurate.
		 */
		lpl = newlpl;
		for (;;) {
			ncpu = lpl->lpl_ncpu;
			ASSERT(ncpu > 0);
			do {
				old = new = lpl->lpl_loadavg;
				new += LGRP_LOADAVG_MAX_EFFECT(ncpu);
				/*
				 * Check for overflow
				 * Underflow not possible here
				 */
				if (new < old)
					new = UINT32_MAX;
			} while (atomic_cas_32((lgrp_load_t *)&lpl->lpl_loadavg,
			    old, new) != old);

			lpl = lpl->lpl_parent;
			if (lpl == NULL)
				break;
		}
		t->t_anttime = gethrtime();
	}
}

/*
 * Return lgroup memory allocation policy given advice from madvise(3C)
 */
lgrp_mem_policy_t
lgrp_madv_to_policy(uchar_t advice, size_t size, int type)
{
	switch (advice) {
	case MADV_ACCESS_LWP:
		return (LGRP_MEM_POLICY_NEXT);
	case MADV_ACCESS_MANY:
		return (LGRP_MEM_POLICY_RANDOM);
	default:
		return (lgrp_mem_policy_default(size, type));
	}
}

/*
 * Figure out default policy
 */
lgrp_mem_policy_t
lgrp_mem_policy_default(size_t size, int type)
{
	cpupart_t		*cp;
	lgrp_mem_policy_t	policy;
	size_t			pset_mem_size;

	/*
	 * Randomly allocate memory across lgroups for shared memory
	 * beyond a certain threshold
	 */
	if ((type != MAP_SHARED && size > lgrp_privm_random_thresh) ||
	    (type == MAP_SHARED && size > lgrp_shm_random_thresh)) {
		/*
		 * Get total memory size of current thread's pset
		 */
		kpreempt_disable();
		cp = curthread->t_cpupart;
		klgrpset_totalsize(cp->cp_lgrpset, pset_mem_size);
		kpreempt_enable();

		/*
		 * Choose policy to randomly allocate memory across
		 * lgroups in pset if it will fit and is not default
		 * partition.  Otherwise, allocate memory randomly
		 * across machine.
		 */
		if (lgrp_mem_pset_aware && size < pset_mem_size)
			policy = LGRP_MEM_POLICY_RANDOM_PSET;
		else
			policy = LGRP_MEM_POLICY_RANDOM;
	} else
		/*
		 * Apply default policy for private memory and
		 * shared memory under the respective random
		 * threshold.
		 */
		policy = lgrp_mem_default_policy;

	return (policy);
}

/*
 * Get memory allocation policy for this segment
 */
lgrp_mem_policy_info_t *
lgrp_mem_policy_get(struct seg *seg, caddr_t vaddr)
{
	lgrp_mem_policy_info_t	*policy_info;
	extern struct seg_ops	segspt_ops;
	extern struct seg_ops	segspt_shmops;

	/*
	 * This is for binary compatibility to protect against third party
	 * segment drivers which haven't recompiled to allow for
	 * SEGOP_GETPOLICY()
	 */
	if (seg->s_ops != &segvn_ops && seg->s_ops != &segspt_ops &&
	    seg->s_ops != &segspt_shmops)
		return (NULL);

	policy_info = NULL;
	if (seg->s_ops->getpolicy != NULL)
		policy_info = SEGOP_GETPOLICY(seg, vaddr);

	return (policy_info);
}

/*
 * Set policy for allocating private memory given desired policy, policy info,
 * size in bytes of memory that policy is being applied.
 * Return 0 if policy wasn't set already and 1 if policy was set already
 */
int
lgrp_privm_policy_set(lgrp_mem_policy_t policy,
    lgrp_mem_policy_info_t *policy_info, size_t size)
{

	ASSERT(policy_info != NULL);

	if (policy == LGRP_MEM_POLICY_DEFAULT)
		policy = lgrp_mem_policy_default(size, MAP_PRIVATE);

	/*
	 * Policy set already?
	 */
	if (policy == policy_info->mem_policy)
		return (1);

	/*
	 * Set policy
	 */
	policy_info->mem_policy = policy;
	policy_info->mem_lgrpid = LGRP_NONE;

	return (0);
}


/*
 * Get shared memory allocation policy with given tree and offset
 */
lgrp_mem_policy_info_t *
lgrp_shm_policy_get(struct anon_map *amp, ulong_t anon_index, vnode_t *vp,
    u_offset_t vn_off)
{
	u_offset_t		off;
	lgrp_mem_policy_info_t	*policy_info;
	lgrp_shm_policy_seg_t	*policy_seg;
	lgrp_shm_locality_t	*shm_locality;
	avl_tree_t		*tree;
	avl_index_t		where;

	/*
	 * Get policy segment tree from anon_map or vnode and use specified
	 * anon index or vnode offset as offset
	 *
	 * Assume that no lock needs to be held on anon_map or vnode, since
	 * they should be protected by their reference count which must be
	 * nonzero for an existing segment
	 */
	if (amp) {
		ASSERT(amp->refcnt != 0);
		shm_locality = amp->locality;
		if (shm_locality == NULL)
			return (NULL);
		tree = shm_locality->loc_tree;
		off = ptob(anon_index);
	} else if (vp) {
		shm_locality = vp->v_locality;
		if (shm_locality == NULL)
			return (NULL);
		ASSERT(shm_locality->loc_count != 0);
		tree = shm_locality->loc_tree;
		off = vn_off;
	}

	if (tree == NULL)
		return (NULL);

	/*
	 * Lookup policy segment for offset into shared object and return
	 * policy info
	 */
	rw_enter(&shm_locality->loc_lock, RW_READER);
	policy_info = NULL;
	policy_seg = avl_find(tree, &off, &where);
	if (policy_seg)
		policy_info = &policy_seg->shm_policy;
	rw_exit(&shm_locality->loc_lock);

	return (policy_info);
}

/*
 * Default memory allocation policy for kernel segmap pages
 */
lgrp_mem_policy_t	lgrp_segmap_default_policy = LGRP_MEM_POLICY_RANDOM;

/*
 * Return lgroup to use for allocating memory
 * given the segment and address
 *
 * There isn't any mutual exclusion that exists between calls
 * to this routine and DR, so this routine and whomever calls it
 * should be mindful of the possibility that the lgrp returned
 * may be deleted. If this happens, dereferences of the lgrp
 * pointer will still be safe, but the resources in the lgrp will
 * be gone, and LGRP_EXISTS() will no longer be true.
 */
lgrp_t *
lgrp_mem_choose(struct seg *seg, caddr_t vaddr, size_t pgsz)
{
	int			i;
	lgrp_t			*lgrp;
	klgrpset_t		lgrpset;
	int			lgrps_spanned;
	unsigned long		off;
	lgrp_mem_policy_t	policy;
	lgrp_mem_policy_info_t	*policy_info;
	ushort_t		random;
	int			stat = 0;
	extern struct seg	*segkmap;

	/*
	 * Just return null if the lgrp framework hasn't finished
	 * initializing or if this is a UMA machine.
	 */
	if (nlgrps == 1 || !lgrp_initialized)
		return (lgrp_root);

	/*
	 * Get memory allocation policy for this segment
	 */
	policy = lgrp_mem_default_policy;
	if (seg != NULL) {
		if (seg->s_as == &kas) {
			if (seg == segkmap)
				policy = lgrp_segmap_default_policy;
			if (policy == LGRP_MEM_POLICY_RANDOM_PROC ||
			    policy == LGRP_MEM_POLICY_RANDOM_PSET)
				policy = LGRP_MEM_POLICY_RANDOM;
		} else {
			policy_info = lgrp_mem_policy_get(seg, vaddr);
			if (policy_info != NULL) {
				policy = policy_info->mem_policy;
				if (policy == LGRP_MEM_POLICY_NEXT_SEG) {
					lgrp_id_t id = policy_info->mem_lgrpid;
					ASSERT(id != LGRP_NONE);
					ASSERT(id < NLGRPS_MAX);
					lgrp = lgrp_table[id];
					if (!LGRP_EXISTS(lgrp)) {
						policy = LGRP_MEM_POLICY_NEXT;
					} else {
						lgrp_stat_add(id,
						    LGRP_NUM_NEXT_SEG, 1);
						return (lgrp);
					}
				}
			}
		}
	}
	lgrpset = 0;

	/*
	 * Initialize lgroup to home by default
	 */
	lgrp = lgrp_home_lgrp();

	/*
	 * When homing threads on root lgrp, override default memory
	 * allocation policies with root lgroup memory allocation policy
	 */
	if (lgrp == lgrp_root)
		policy = lgrp_mem_policy_root;

	/*
	 * Implement policy
	 */
	switch (policy) {
	case LGRP_MEM_POLICY_NEXT_CPU:

		/*
		 * Return lgroup of current CPU which faulted on memory
		 * If the CPU isn't currently in an lgrp, then opt to
		 * allocate from the root.
		 *
		 * Kernel preemption needs to be disabled here to prevent
		 * the current CPU from going away before lgrp is found.
		 */
		if (LGRP_CPU_HAS_NO_LGRP(CPU)) {
			lgrp = lgrp_root;
		} else {
			kpreempt_disable();
			lgrp = lgrp_cpu_to_lgrp(CPU);
			kpreempt_enable();
		}
		break;

	case LGRP_MEM_POLICY_NEXT:
	case LGRP_MEM_POLICY_DEFAULT:
	default:

		/*
		 * Just return current thread's home lgroup
		 * for default policy (next touch)
		 * If the thread is homed to the root,
		 * then the default policy is random across lgroups.
		 * Fallthrough to the random case.
		 */
		if (lgrp != lgrp_root) {
			if (policy == LGRP_MEM_POLICY_NEXT)
				lgrp_stat_add(lgrp->lgrp_id, LGRP_NUM_NEXT, 1);
			else
				lgrp_stat_add(lgrp->lgrp_id,
				    LGRP_NUM_DEFAULT, 1);
			break;
		}
		/* LINTED fallthrough on case statement */
	case LGRP_MEM_POLICY_RANDOM:

		/*
		 * Return a random leaf lgroup with memory
		 */
		lgrpset = lgrp_root->lgrp_set[LGRP_RSRC_MEM];
		/*
		 * Count how many lgroups are spanned
		 */
		klgrpset_nlgrps(lgrpset, lgrps_spanned);

		/*
		 * There may be no memnodes in the root lgroup during DR copy
		 * rename on a system with only two boards (memnodes)
		 * configured. In this case just return the root lgrp.
		 */
		if (lgrps_spanned == 0) {
			lgrp = lgrp_root;
			break;
		}

		/*
		 * Pick a random offset within lgroups spanned
		 * and return lgroup at that offset
		 */
		random = (ushort_t)gethrtime() >> 4;
		off = random % lgrps_spanned;
		ASSERT(off <= lgrp_alloc_max);

		for (i = 0; i <= lgrp_alloc_max; i++) {
			if (!klgrpset_ismember(lgrpset, i))
				continue;
			if (off)
				off--;
			else {
				lgrp = lgrp_table[i];
				lgrp_stat_add(lgrp->lgrp_id, LGRP_NUM_RANDOM,
				    1);
				break;
			}
		}
		break;

	case LGRP_MEM_POLICY_RANDOM_PROC:

		/*
		 * Grab copy of bitmask of lgroups spanned by
		 * this process
		 */
		klgrpset_copy(lgrpset, curproc->p_lgrpset);
		stat = LGRP_NUM_RANDOM_PROC;

		/* LINTED fallthrough on case statement */
	case LGRP_MEM_POLICY_RANDOM_PSET:

		if (!stat)
			stat = LGRP_NUM_RANDOM_PSET;

		if (klgrpset_isempty(lgrpset)) {
			/*
			 * Grab copy of bitmask of lgroups spanned by
			 * this processor set
			 */
			kpreempt_disable();
			klgrpset_copy(lgrpset,
			    curthread->t_cpupart->cp_lgrpset);
			kpreempt_enable();
		}

		/*
		 * Count how many lgroups are spanned
		 */
		klgrpset_nlgrps(lgrpset, lgrps_spanned);
		ASSERT(lgrps_spanned <= nlgrps);

		/*
		 * Probably lgrps_spanned should be always non-zero, but to be
		 * on the safe side we return lgrp_root if it is empty.
		 */
		if (lgrps_spanned == 0) {
			lgrp = lgrp_root;
			break;
		}

		/*
		 * Pick a random offset within lgroups spanned
		 * and return lgroup at that offset
		 */
		random = (ushort_t)gethrtime() >> 4;
		off = random % lgrps_spanned;
		ASSERT(off <= lgrp_alloc_max);

		for (i = 0; i <= lgrp_alloc_max; i++) {
			if (!klgrpset_ismember(lgrpset, i))
				continue;
			if (off)
				off--;
			else {
				lgrp = lgrp_table[i];
				lgrp_stat_add(lgrp->lgrp_id, LGRP_NUM_RANDOM,
				    1);
				break;
			}
		}
		break;

	case LGRP_MEM_POLICY_ROUNDROBIN:

		/*
		 * Use offset within segment to determine
		 * offset from home lgroup to choose for
		 * next lgroup to allocate memory from
		 */
		off = ((unsigned long)(vaddr - seg->s_base) / pgsz) %
		    (lgrp_alloc_max + 1);

		kpreempt_disable();
		lgrpset = lgrp_root->lgrp_set[LGRP_RSRC_MEM];
		i = lgrp->lgrp_id;
		kpreempt_enable();

		while (off > 0) {
			i = (i + 1) % (lgrp_alloc_max + 1);
			lgrp = lgrp_table[i];
			if (klgrpset_ismember(lgrpset, i))
				off--;
		}
		lgrp_stat_add(lgrp->lgrp_id, LGRP_NUM_ROUNDROBIN, 1);

		break;
	}

	ASSERT(lgrp != NULL);
	return (lgrp);
}

/*
 * Return the number of pages in an lgroup
 *
 * NOTE: NUMA test (numat) driver uses this, so changing arguments or semantics
 *	 could cause tests that rely on the numat driver to fail....
 */
pgcnt_t
lgrp_mem_size(lgrp_id_t lgrpid, lgrp_mem_query_t query)
{
	lgrp_t *lgrp;

	lgrp = lgrp_table[lgrpid];
	if (!LGRP_EXISTS(lgrp) ||
	    klgrpset_isempty(lgrp->lgrp_set[LGRP_RSRC_MEM]) ||
	    !klgrpset_ismember(lgrp->lgrp_set[LGRP_RSRC_MEM], lgrpid))
		return (0);

	return (lgrp_plat_mem_size(lgrp->lgrp_plathand, query));
}

/*
 * Initialize lgroup shared memory allocation policy support
 */
void
lgrp_shm_policy_init(struct anon_map *amp, vnode_t *vp)
{
	lgrp_shm_locality_t	*shm_locality;

	/*
	 * Initialize locality field in anon_map
	 * Don't need any locks because this is called when anon_map is
	 * allocated, but not used anywhere yet.
	 */
	if (amp) {
		ANON_LOCK_ENTER(&amp->a_rwlock, RW_WRITER);
		if (amp->locality == NULL) {
			/*
			 * Allocate and initialize shared memory locality info
			 * and set anon_map locality pointer to it
			 * Drop lock across kmem_alloc(KM_SLEEP)
			 */
			ANON_LOCK_EXIT(&amp->a_rwlock);
			shm_locality = kmem_alloc(sizeof (*shm_locality),
			    KM_SLEEP);
			rw_init(&shm_locality->loc_lock, NULL, RW_DEFAULT,
			    NULL);
			shm_locality->loc_count = 1;	/* not used for amp */
			shm_locality->loc_tree = NULL;

			/*
			 * Reacquire lock and check to see whether anyone beat
			 * us to initializing the locality info
			 */
			ANON_LOCK_ENTER(&amp->a_rwlock, RW_WRITER);
			if (amp->locality != NULL) {
				rw_destroy(&shm_locality->loc_lock);
				kmem_free(shm_locality,
				    sizeof (*shm_locality));
			} else
				amp->locality = shm_locality;
		}
		ANON_LOCK_EXIT(&amp->a_rwlock);
		return;
	}

	/*
	 * Allocate shared vnode policy info if vnode is not locality aware yet
	 */
	mutex_enter(&vp->v_lock);
	if ((vp->v_flag & V_LOCALITY) == 0) {
		/*
		 * Allocate and initialize shared memory locality info
		 */
		mutex_exit(&vp->v_lock);
		shm_locality = kmem_alloc(sizeof (*shm_locality), KM_SLEEP);
		rw_init(&shm_locality->loc_lock, NULL, RW_DEFAULT, NULL);
		shm_locality->loc_count = 1;
		shm_locality->loc_tree = NULL;

		/*
		 * Point vnode locality field at shared vnode policy info
		 * and set locality aware flag in vnode
		 */
		mutex_enter(&vp->v_lock);
		if ((vp->v_flag & V_LOCALITY) == 0) {
			vp->v_locality = shm_locality;
			vp->v_flag |= V_LOCALITY;
		} else {
			/*
			 * Lost race so free locality info and increment count.
			 */
			rw_destroy(&shm_locality->loc_lock);
			kmem_free(shm_locality, sizeof (*shm_locality));
			shm_locality = vp->v_locality;
			shm_locality->loc_count++;
		}
		mutex_exit(&vp->v_lock);

		return;
	}

	/*
	 * Increment reference count of number of segments mapping this vnode
	 * shared
	 */
	shm_locality = vp->v_locality;
	shm_locality->loc_count++;
	mutex_exit(&vp->v_lock);
}

/*
 * Destroy the given shared memory policy segment tree
 */
void
lgrp_shm_policy_tree_destroy(avl_tree_t *tree)
{
	lgrp_shm_policy_seg_t	*cur;
	lgrp_shm_policy_seg_t	*next;

	if (tree == NULL)
		return;

	cur = (lgrp_shm_policy_seg_t *)avl_first(tree);
	while (cur != NULL) {
		next = AVL_NEXT(tree, cur);
		avl_remove(tree, cur);
		kmem_free(cur, sizeof (*cur));
		cur = next;
	}
	kmem_free(tree, sizeof (avl_tree_t));
}

/*
 * Uninitialize lgroup shared memory allocation policy support
 */
void
lgrp_shm_policy_fini(struct anon_map *amp, vnode_t *vp)
{
	lgrp_shm_locality_t	*shm_locality;

	/*
	 * For anon_map, deallocate shared memory policy tree and
	 * zero locality field
	 * Don't need any locks because anon_map is being freed
	 */
	if (amp) {
		if (amp->locality == NULL)
			return;
		shm_locality = amp->locality;
		shm_locality->loc_count = 0;	/* not really used for amp */
		rw_destroy(&shm_locality->loc_lock);
		lgrp_shm_policy_tree_destroy(shm_locality->loc_tree);
		kmem_free(shm_locality, sizeof (*shm_locality));
		amp->locality = 0;
		return;
	}

	/*
	 * For vnode, decrement reference count of segments mapping this vnode
	 * shared and delete locality info if reference count drops to 0
	 */
	mutex_enter(&vp->v_lock);
	shm_locality = vp->v_locality;
	shm_locality->loc_count--;

	if (shm_locality->loc_count == 0) {
		rw_destroy(&shm_locality->loc_lock);
		lgrp_shm_policy_tree_destroy(shm_locality->loc_tree);
		kmem_free(shm_locality, sizeof (*shm_locality));
		vp->v_locality = 0;
		vp->v_flag &= ~V_LOCALITY;
	}
	mutex_exit(&vp->v_lock);
}

/*
 * Compare two shared memory policy segments
 * Used by AVL tree code for searching
 */
int
lgrp_shm_policy_compar(const void *x, const void *y)
{
	lgrp_shm_policy_seg_t *a = (lgrp_shm_policy_seg_t *)x;
	lgrp_shm_policy_seg_t *b = (lgrp_shm_policy_seg_t *)y;

	if (a->shm_off < b->shm_off)
		return (-1);
	if (a->shm_off >= b->shm_off + b->shm_size)
		return (1);
	return (0);
}

/*
 * Concatenate seg1 with seg2 and remove seg2
 */
static int
lgrp_shm_policy_concat(avl_tree_t *tree, lgrp_shm_policy_seg_t *seg1,
    lgrp_shm_policy_seg_t *seg2)
{
	if (!seg1 || !seg2 ||
	    seg1->shm_off + seg1->shm_size != seg2->shm_off ||
	    seg1->shm_policy.mem_policy != seg2->shm_policy.mem_policy)
		return (-1);

	seg1->shm_size += seg2->shm_size;
	avl_remove(tree, seg2);
	kmem_free(seg2, sizeof (*seg2));
	return (0);
}

/*
 * Split segment at given offset and return rightmost (uppermost) segment
 * Assumes that there are no overlapping segments
 */
static lgrp_shm_policy_seg_t *
lgrp_shm_policy_split(avl_tree_t *tree, lgrp_shm_policy_seg_t *seg,
    u_offset_t off)
{
	lgrp_shm_policy_seg_t	*newseg;
	avl_index_t		where;

	ASSERT(seg != NULL);
	ASSERT(off >= seg->shm_off && off <= seg->shm_off + seg->shm_size);

	if (!seg || off < seg->shm_off || off > seg->shm_off +
	    seg->shm_size)
		return (NULL);

	if (off == seg->shm_off || off == seg->shm_off + seg->shm_size)
		return (seg);

	/*
	 * Adjust size of left segment and allocate new (right) segment
	 */
	newseg = kmem_alloc(sizeof (lgrp_shm_policy_seg_t), KM_SLEEP);
	newseg->shm_policy = seg->shm_policy;
	newseg->shm_off = off;
	newseg->shm_size = seg->shm_size - (off - seg->shm_off);
	seg->shm_size = off - seg->shm_off;

	/*
	 * Find where to insert new segment in AVL tree and insert it
	 */
	(void) avl_find(tree, &off, &where);
	avl_insert(tree, newseg, where);

	return (newseg);
}

/*
 * Set shared memory allocation policy on specified shared object at given
 * offset and length
 *
 * Return 0 if policy wasn't set already, 1 if policy was set already, and
 * -1 if can't set policy.
 */
int
lgrp_shm_policy_set(lgrp_mem_policy_t policy, struct anon_map *amp,
    ulong_t anon_index, vnode_t *vp, u_offset_t vn_off, size_t len)
{
	u_offset_t		eoff;
	lgrp_shm_policy_seg_t	*next;
	lgrp_shm_policy_seg_t	*newseg;
	u_offset_t		off;
	u_offset_t		oldeoff;
	lgrp_shm_policy_seg_t	*prev;
	int			retval;
	lgrp_shm_policy_seg_t	*seg;
	lgrp_shm_locality_t	*shm_locality;
	avl_tree_t		*tree;
	avl_index_t		where;

	ASSERT(amp || vp);
	ASSERT((len & PAGEOFFSET) == 0);

	if (len == 0)
		return (-1);

	retval = 0;

	/*
	 * Get locality info and starting offset into shared object
	 * Try anon map first and then vnode
	 * Assume that no locks need to be held on anon_map or vnode, since
	 * it should be protected by its reference count which must be nonzero
	 * for an existing segment.
	 */
	if (amp) {
		/*
		 * Get policy info from anon_map
		 *
		 */
		ASSERT(amp->refcnt != 0);
		if (amp->locality == NULL)
			lgrp_shm_policy_init(amp, NULL);
		shm_locality = amp->locality;
		off = ptob(anon_index);
	} else if (vp) {
		/*
		 * Get policy info from vnode
		 */
		if ((vp->v_flag & V_LOCALITY) == 0 || vp->v_locality == NULL)
			lgrp_shm_policy_init(NULL, vp);
		shm_locality = vp->v_locality;
		ASSERT(shm_locality->loc_count != 0);
		off = vn_off;
	} else
		return (-1);

	ASSERT((off & PAGEOFFSET) == 0);

	/*
	 * Figure out default policy
	 */
	if (policy == LGRP_MEM_POLICY_DEFAULT)
		policy = lgrp_mem_policy_default(len, MAP_SHARED);

	/*
	 * Create AVL tree if there isn't one yet
	 * and set locality field to point at it
	 */
	rw_enter(&shm_locality->loc_lock, RW_WRITER);
	tree = shm_locality->loc_tree;
	if (!tree) {
		rw_exit(&shm_locality->loc_lock);

		tree = kmem_alloc(sizeof (avl_tree_t), KM_SLEEP);

		rw_enter(&shm_locality->loc_lock, RW_WRITER);
		if (shm_locality->loc_tree == NULL) {
			avl_create(tree, lgrp_shm_policy_compar,
			    sizeof (lgrp_shm_policy_seg_t),
			    offsetof(lgrp_shm_policy_seg_t, shm_tree));
			shm_locality->loc_tree = tree;
		} else {
			/*
			 * Another thread managed to set up the tree
			 * before we could. Free the tree we allocated
			 * and use the one that's already there.
			 */
			kmem_free(tree, sizeof (*tree));
			tree = shm_locality->loc_tree;
		}
	}

	/*
	 * Set policy
	 *
	 * Need to maintain hold on writer's lock to keep tree from
	 * changing out from under us
	 */
	while (len != 0) {
		/*
		 * Find policy segment for specified offset into shared object
		 */
		seg = avl_find(tree, &off, &where);

		/*
		 * Didn't find any existing segment that contains specified
		 * offset, so allocate new segment, insert it, and concatenate
		 * with adjacent segments if possible
		 */
		if (seg == NULL) {
			newseg = kmem_alloc(sizeof (lgrp_shm_policy_seg_t),
			    KM_SLEEP);
			newseg->shm_policy.mem_policy = policy;
			newseg->shm_policy.mem_lgrpid = LGRP_NONE;
			newseg->shm_off = off;
			avl_insert(tree, newseg, where);

			/*
			 * Check to see whether new segment overlaps with next
			 * one, set length of new segment accordingly, and
			 * calculate remaining length and next offset
			 */
			seg = AVL_NEXT(tree, newseg);
			if (seg == NULL || off + len <= seg->shm_off) {
				newseg->shm_size = len;
				len = 0;
			} else {
				newseg->shm_size = seg->shm_off - off;
				off = seg->shm_off;
				len -= newseg->shm_size;
			}

			/*
			 * Try to concatenate new segment with next and
			 * previous ones, since they might have the same policy
			 * now.  Grab previous and next segments first because
			 * they will change on concatenation.
			 */
			prev =  AVL_PREV(tree, newseg);
			next = AVL_NEXT(tree, newseg);
			(void) lgrp_shm_policy_concat(tree, newseg, next);
			(void) lgrp_shm_policy_concat(tree, prev, newseg);

			continue;
		}

		eoff = off + len;
		oldeoff = seg->shm_off + seg->shm_size;

		/*
		 * Policy set already?
		 */
		if (policy == seg->shm_policy.mem_policy) {
			/*
			 * Nothing left to do if offset and length
			 * fall within this segment
			 */
			if (eoff <= oldeoff) {
				retval = 1;
				break;
			} else {
				len = eoff - oldeoff;
				off = oldeoff;
				continue;
			}
		}

		/*
		 * Specified offset and length match existing segment exactly
		 */
		if (off == seg->shm_off && len == seg->shm_size) {
			/*
			 * Set policy and update current length
			 */
			seg->shm_policy.mem_policy = policy;
			seg->shm_policy.mem_lgrpid = LGRP_NONE;
			len = 0;

			/*
			 * Try concatenating new segment with previous and next
			 * segments, since they might have the same policy now.
			 * Grab previous and next segments first because they
			 * will change on concatenation.
			 */
			prev =  AVL_PREV(tree, seg);
			next = AVL_NEXT(tree, seg);
			(void) lgrp_shm_policy_concat(tree, seg, next);
			(void) lgrp_shm_policy_concat(tree, prev, seg);
		} else {
			/*
			 * Specified offset and length only apply to part of
			 * existing segment
			 */

			/*
			 * New segment starts in middle of old one, so split
			 * new one off near beginning of old one
			 */
			newseg = NULL;
			if (off > seg->shm_off) {
				newseg = lgrp_shm_policy_split(tree, seg, off);

				/*
				 * New segment ends where old one did, so try
				 * to concatenate with next segment
				 */
				if (eoff == oldeoff) {
					newseg->shm_policy.mem_policy = policy;
					newseg->shm_policy.mem_lgrpid =
					    LGRP_NONE;
					(void) lgrp_shm_policy_concat(tree,
					    newseg, AVL_NEXT(tree, newseg));
					break;
				}
			}

			/*
			 * New segment ends before old one, so split off end of
			 * old one
			 */
			if (eoff < oldeoff) {
				if (newseg) {
					(void) lgrp_shm_policy_split(tree,
					    newseg, eoff);
					newseg->shm_policy.mem_policy = policy;
					newseg->shm_policy.mem_lgrpid =
					    LGRP_NONE;
				} else {
					(void) lgrp_shm_policy_split(tree, seg,
					    eoff);
					seg->shm_policy.mem_policy = policy;
					seg->shm_policy.mem_lgrpid = LGRP_NONE;
				}

				if (off == seg->shm_off)
					(void) lgrp_shm_policy_concat(tree,
					    AVL_PREV(tree, seg), seg);
				break;
			}

			/*
			 * Calculate remaining length and next offset
			 */
			len = eoff - oldeoff;
			off = oldeoff;
		}
	}

	rw_exit(&shm_locality->loc_lock);
	return (retval);
}

/*
 * Return the best memnode from which to allocate memory given
 * an lgroup.
 *
 * "c" is for cookie, which is good enough for me.
 * It references a cookie struct that should be zero'ed to initialize.
 * The cookie should live on the caller's stack.
 *
 * The routine returns -1 when:
 *	- traverse is 0, and all the memnodes in "lgrp" have been returned.
 *	- traverse is 1, and all the memnodes in the system have been
 *	  returned.
 */
int
lgrp_memnode_choose(lgrp_mnode_cookie_t *c)
{
	lgrp_t		*lp = c->lmc_lgrp;
	mnodeset_t	nodes = c->lmc_nodes;
	int		cnt = c->lmc_cnt;
	int		offset, mnode;

	extern int	max_mem_nodes;

	/*
	 * If the set is empty, and the caller is willing, traverse
	 * up the hierarchy until we find a non-empty set.
	 */
	while (nodes == (mnodeset_t)0 || cnt <= 0) {
		if (c->lmc_scope == LGRP_SRCH_LOCAL ||
		    ((lp = lp->lgrp_parent) == NULL))
			return (-1);

		nodes = lp->lgrp_mnodes & ~(c->lmc_tried);
		cnt = lp->lgrp_nmnodes - c->lmc_ntried;
	}

	/*
	 * Select a memnode by picking one at a "random" offset.
	 * Because of DR, memnodes can come and go at any time.
	 * This code must be able to cope with the possibility
	 * that the nodes count "cnt" is inconsistent with respect
	 * to the number of elements actually in "nodes", and
	 * therefore that the offset chosen could be greater than
	 * the number of elements in the set (some memnodes may
	 * have dissapeared just before cnt was read).
	 * If this happens, the search simply wraps back to the
	 * beginning of the set.
	 */
	ASSERT(nodes != (mnodeset_t)0 && cnt > 0);
	offset = c->lmc_rand % cnt;
	do {
		for (mnode = 0; mnode < max_mem_nodes; mnode++)
			if (nodes & ((mnodeset_t)1 << mnode))
				if (!offset--)
					break;
	} while (mnode >= max_mem_nodes);

	/* Found a node. Store state before returning. */
	c->lmc_lgrp = lp;
	c->lmc_nodes = (nodes & ~((mnodeset_t)1 << mnode));
	c->lmc_cnt = cnt - 1;
	c->lmc_tried = (c->lmc_tried | ((mnodeset_t)1 << mnode));
	c->lmc_ntried++;

	return (mnode);
}

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

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/cpu.h>
#include <sys/cpuvar.h>
#include <sys/clock.h>
#include <sys/promif.h>
#include <sys/promimpl.h>
#include <sys/systm.h>
#include <sys/machsystm.h>
#include <sys/debug.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/cpu_module.h>
#include <sys/kobj.h>
#include <sys/cmp.h>
#include <sys/async.h>
#include <vm/page.h>
#include <vm/hat_sfmmu.h>
#include <sys/sysmacros.h>
#include <sys/mach_descrip.h>
#include <sys/mdesc.h>
#include <sys/archsystm.h>
#include <sys/error.h>
#include <sys/mmu.h>
#include <sys/bitmap.h>

int ncpunode;
struct cpu_node cpunodes[NCPU];

uint64_t cpu_q_entries;
uint64_t dev_q_entries;
uint64_t cpu_rq_entries;
uint64_t cpu_nrq_entries;

void fill_cpu(md_t *, mde_cookie_t);

static uint64_t get_mmu_ctx_bits(md_t *, mde_cookie_t);
static uint64_t get_cpu_pagesizes(md_t *, mde_cookie_t);
static char *construct_isalist(md_t *, mde_cookie_t, char **);
static void set_at_flags(char *, int, char **);
static void init_md_broken(md_t *);
static int get_l2_cache_info(md_t *, mde_cookie_t, uint64_t *, uint64_t *,
    uint64_t *);
static id_t get_exec_unit_mapping(md_t *, mde_cookie_t, mde_cookie_t *);
static int find_exec_unit_id(mde_cookie_t, mde_cookie_t *);
static void get_q_sizes(md_t *, mde_cookie_t);
static void get_va_bits(md_t *, mde_cookie_t);
static size_t get_ra_limit(md_t *);

uint64_t	system_clock_freq;
int		niobus = 0;
uint_t		niommu_tsbs = 0;

/* prevent compilation with VAC defined */
#ifdef VAC
#error "The sun4v architecture does not support VAC"
#endif

#define	S_VAC_SIZE	MMU_PAGESIZE
#define	S_VAC_SHIFT	MMU_PAGESHIFT

int		vac_size = S_VAC_SIZE;
uint_t		vac_mask = MMU_PAGEMASK & (S_VAC_SIZE - 1);
int		vac_shift = S_VAC_SHIFT;
uintptr_t	shm_alignment = S_VAC_SIZE;

void
map_wellknown_devices()
{
}

/*
 * For backward compatibility we need to verify that we can handle
 * running on platforms which shipped with missing MD properties.
 */
#define	ONTARIO_PLATNAME1	"SUNW,Sun-Fire-T200"
#define	ONTARIO_PLATNAME2	"SUNW,Sun-Fire-T2000"
#define	ONTARIO_PLATNAME3	"SUNW,SPARC-Enterprise-T2000"
#define	ERIE_PLATNAME1		"SUNW,Sun-Fire-T100"
#define	ERIE_PLATNAME2		"SUNW,Sun-Fire-T1000"
#define	ERIE_PLATNAME3		"SUNW,SPARC-Enterprise-T1000"

void
fill_cpu(md_t *mdp, mde_cookie_t cpuc)
{
	struct cpu_node *cpunode;
	uint64_t cpuid;
	uint64_t clk_freq;
	char *namebuf;
	char *namebufp;
	int namelen;
	uint64_t associativity = 0, linesize = 0, size = 0;
	int status;

	if (md_get_prop_val(mdp, cpuc, "id", &cpuid)) {
		return;
	}

	if (cpuid >= NCPU) {
		cmn_err(CE_CONT, "fill_cpu: out of range cpuid %ld - "
		    "cpu excluded from configuration", cpuid);

		mutex_enter(&cpu_lock);

		/*
		 * Since the CPU cannot be used, make sure it
		 * is in a safe place. If the firmware does not
		 * support CPU stop, this is known to be true.
		 * If it fails to stop for any other reason, the
		 * system is in an inconsistent state and cannot
		 * be allowed to continue.
		 */
		status = stopcpu_bycpuid(cpuid);

		if ((status != 0) && (status != ENOTSUP)) {
			cmn_err(CE_PANIC, "failed to stop cpu %lu (%d)",
			    cpuid, status);
		}

		mutex_exit(&cpu_lock);
		return;
	}

	cpunode = &cpunodes[cpuid];
	cpunode->cpuid = (int)cpuid;
	cpunode->device_id = cpuid;

	if (sizeof (cpunode->fru_fmri) > strlen(CPU_FRU_FMRI))
		(void) strcpy(cpunode->fru_fmri, CPU_FRU_FMRI);

	if (md_get_prop_data(mdp, cpuc,
	    "compatible", (uint8_t **)&namebuf, &namelen)) {
		cmn_err(CE_PANIC, "fill_cpu: Cannot read compatible "
		    "property");
	}
	namebufp = namebuf;
	if (strncmp(namebufp, "SUNW,", 5) == 0)
		namebufp += 5;
	if (strlen(namebufp) > sizeof (cpunode->name))
		cmn_err(CE_PANIC, "Compatible property too big to "
		    "fit into the cpunode name buffer");
	(void) strcpy(cpunode->name, namebufp);

	if (md_get_prop_val(mdp, cpuc,
	    "clock-frequency", &clk_freq)) {
			clk_freq = 0;
	}
	cpunode->clock_freq = clk_freq;

	ASSERT(cpunode->clock_freq != 0);
	/*
	 * Compute scaling factor based on rate of %tick. This is used
	 * to convert from ticks derived from %tick to nanoseconds. See
	 * comment in sun4u/sys/clock.h for details.
	 */
	cpunode->tick_nsec_scale = (uint_t)(((uint64_t)NANOSEC <<
	    (32 - TICK_NSEC_SHIFT)) / cpunode->clock_freq);

	/*
	 * The nodeid is not used in sun4v at all. Setting it
	 * to positive value to make starting of slave CPUs
	 * code happy.
	 */
	cpunode->nodeid = cpuid + 1;

	/*
	 * Obtain the L2 cache information from MD.
	 * If "Cache" node exists, then set L2 cache properties
	 * as read from MD.
	 * If node does not exists, then set the L2 cache properties
	 * in individual CPU module.
	 */
	if ((!get_l2_cache_info(mdp, cpuc,
	    &associativity, &size, &linesize)) ||
	    associativity == 0 || size == 0 || linesize == 0) {
		cpu_fiximp(cpunode);
	} else {
		/*
		 * Do not expect L2 cache properties to be bigger
		 * than 32-bit quantity.
		 */
		cpunode->ecache_associativity = (int)associativity;
		cpunode->ecache_size = (int)size;
		cpunode->ecache_linesize = (int)linesize;
	}

	cpunode->ecache_setsize =
	    cpunode->ecache_size / cpunode->ecache_associativity;

		/*
		 * Start off by assigning the cpu id as the default
		 * mapping index.
		 */

	cpunode->exec_unit_mapping = NO_EU_MAPPING_FOUND;

	if (ecache_setsize == 0)
		ecache_setsize = cpunode->ecache_setsize;
	if (ecache_alignsize == 0)
		ecache_alignsize = cpunode->ecache_linesize;

	ncpunode++;
}

void
empty_cpu(int cpuid)
{
	bzero(&cpunodes[cpuid], sizeof (struct cpu_node));
	ncpunode--;
}

void
setup_exec_unit_mappings(md_t *mdp)
{
	uint64_t num, num_eunits;
	mde_cookie_t cpus_node;
	mde_cookie_t *node, *eunit;
	int idx, i, j;
	processorid_t cpuid;
	char *eunit_name = broken_md_flag ? "exec_unit" : "exec-unit";

	/*
	 * Find the cpu integer exec units - and
	 * setup the mappings appropriately.
	 */
	num = md_alloc_scan_dag(mdp, md_root_node(mdp), "cpus", "fwd", &node);
	if (num < 1)
		cmn_err(CE_PANIC, "No cpus node in machine desccription");
	if (num > 1)
		cmn_err(CE_PANIC, "More than 1 cpus node in machine"
		    " description");

	cpus_node = node[0];
	md_free_scan_dag(mdp, &node);

	num_eunits = md_alloc_scan_dag(mdp, cpus_node, eunit_name,
	    "fwd", &eunit);
	if (num_eunits > 0) {
		char *match_type = broken_md_flag ? "int" : "integer";

		/* Spin through and find all the integer exec units */
		for (i = 0; i < num_eunits; i++) {
			char *p;
			char *val;
			int vallen;
			uint64_t lcpuid;

				/* ignore nodes with no type */
			if (md_get_prop_data(mdp, eunit[i], "type",
				(uint8_t **)&val, &vallen)) continue;

			for (p = val; *p != '\0'; p += strlen(p) + 1) {
				if (strcmp(p, match_type) == 0)
					goto found;
			}

			continue;
found:
			idx = NCPU + i;
			/*
			 * find the cpus attached to this EU and
			 * update their mapping indices
			 */
			num = md_alloc_scan_dag(mdp, eunit[i], "cpu",
			    "back", &node);

			if (num < 1)
				cmn_err(CE_PANIC, "exec-unit node in MD"
				    " not attached to a cpu node");

			for (j = 0; j < num; j++) {
				if (md_get_prop_val(mdp, node[j], "id",
				    &lcpuid))
					continue;
				if (lcpuid >= NCPU)
					continue;
				cpuid = (processorid_t)lcpuid;
				cpunodes[cpuid].exec_unit_mapping = idx;
			}
			md_free_scan_dag(mdp, &node);
		}


		md_free_scan_dag(mdp, &eunit);
	}
}

/*
 * All the common setup of sun4v CPU modules is done by this routine.
 */
void
cpu_setup_common(char **cpu_module_isa_set)
{
	extern int disable_delay_tlb_flush, delay_tlb_flush;
	extern int mmu_exported_pagesize_mask;
	int nocpus, i;
	size_t ra_limit;
	mde_cookie_t *cpulist;
	md_t *mdp;

	if ((mdp = md_get_handle()) == NULL)
		cmn_err(CE_PANIC, "Unable to initialize machine description");

	init_md_broken(mdp);

	nocpus = md_alloc_scan_dag(mdp,
	    md_root_node(mdp), "cpu", "fwd", &cpulist);
	if (nocpus < 1) {
		cmn_err(CE_PANIC, "cpu_common_setup: cpulist allocation "
		    "failed or incorrect number of CPUs in MD");
	}

	if (use_page_coloring) {
		do_pg_coloring = 1;
		if (use_virtual_coloring) {
			/*
			 * XXX Sun4v cpus don't have virtual caches
			 */
			do_virtual_coloring = 1;
		}
	}

	/*
	 * Get the valid mmu page sizes mask, Q sizes and isalist/r
	 * from the MD for the first available CPU in cpulist.
	 *
	 * Do not expect the MMU page sizes mask to be more than 32-bit.
	 */
	mmu_exported_pagesize_mask = (int)get_cpu_pagesizes(mdp, cpulist[0]);

	for (i = 0; i < nocpus; i++)
		fill_cpu(mdp, cpulist[i]);

	setup_exec_unit_mappings(mdp);

	/*
	 * If MD is broken then append the passed ISA set,
	 * otherwise trust the MD.
	 */

	if (broken_md_flag)
		isa_list = construct_isalist(mdp, cpulist[0],
		    cpu_module_isa_set);
	else
		isa_list = construct_isalist(mdp, cpulist[0], NULL);

	get_q_sizes(mdp, cpulist[0]);

	get_va_bits(mdp, cpulist[0]);

	/*
	 * ra_limit is the highest real address in the machine.
	 */
	ra_limit = get_ra_limit(mdp);

	md_free_scan_dag(mdp, &cpulist);

	(void) md_fini_handle(mdp);

	/*
	 * Block stores invalidate all pages of the d$ so pagecopy
	 * et. al. do not need virtual translations with virtual
	 * coloring taken into consideration.
	 */
	pp_consistent_coloring = 0;

	/*
	 * The kpm mapping window.
	 * kpm_size:
	 *	The size of a single kpm range.
	 *	The overall size will be: kpm_size * vac_colors.
	 * kpm_vbase:
	 *	The virtual start address of the kpm range within the kernel
	 *	virtual address space. kpm_vbase has to be kpm_size aligned.
	 */

	/*
	 * Make kpm_vbase, kpm_size aligned to kpm_size_shift.
	 * To do this find the nearest power of 2 size that the
	 * actual ra_limit fits within.
	 * If it is an even power of two use that, otherwise use the
	 * next power of two larger than ra_limit.
	 */

	ASSERT(ra_limit != 0);

	kpm_size_shift = (ra_limit & (ra_limit - 1)) != 0 ?
		highbit(ra_limit) : highbit(ra_limit) - 1;

	/*
	 * No virtual caches on sun4v so size matches size shift
	 */
	kpm_size = 1ul << kpm_size_shift;

	if (va_bits < VA_ADDRESS_SPACE_BITS) {
		/*
		 * In case of VA hole
		 * kpm_base = hole_end + 1TB
		 * Starting 1TB beyond where VA hole ends because on Niagara
		 * processor software must not use pages within 4GB of the
		 * VA hole as instruction pages to avoid problems with
		 * prefetching into the VA hole.
		 */
		kpm_vbase = (caddr_t)((0ull - (1ull << (va_bits - 1))) +
		    (1ull << 40));
	} else {		/* Number of VA bits 64 ... no VA hole */
		kpm_vbase = (caddr_t)0x8000000000000000ull;	/* 8 EB */
	}

	/*
	 * The traptrace code uses either %tick or %stick for
	 * timestamping.  The sun4v require use of %stick.
	 */
	traptrace_use_stick = 1;

	/*
	 * sun4v provides demap_all
	 */
	if (!disable_delay_tlb_flush)
		delay_tlb_flush = 1;
}

/*
 * Get the nctxs from MD. If absent panic.
 */
static uint64_t
get_mmu_ctx_bits(md_t *mdp, mde_cookie_t cpu_node_cookie)
{
	uint64_t ctx_bits;

	if (md_get_prop_val(mdp, cpu_node_cookie, "mmu-#context-bits",
	    &ctx_bits))
		ctx_bits = 0;

	if (ctx_bits < MIN_NCTXS_BITS || ctx_bits > MAX_NCTXS_BITS)
		cmn_err(CE_PANIC, "Incorrect %ld number of contexts bits "
		    "returned by MD", ctx_bits);

	return (ctx_bits);
}

/*
 * Initalize supported page sizes information.
 * Set to 0, if the page sizes mask information is absent in MD.
 */
static uint64_t
get_cpu_pagesizes(md_t *mdp, mde_cookie_t cpu_node_cookie)
{
	uint64_t mmu_page_size_list;

	if (md_get_prop_val(mdp, cpu_node_cookie, "mmu-page-size-list",
	    &mmu_page_size_list))
		mmu_page_size_list = 0;

	if (mmu_page_size_list == 0 || mmu_page_size_list > MAX_PAGESIZE_MASK)
		cmn_err(CE_PANIC, "Incorrect 0x%lx pagesize mask returned"
		    "by MD", mmu_page_size_list);

	return (mmu_page_size_list);
}

/*
 * This routine gets the isalist information from MD and appends
 * the CPU module ISA set if required.
 */
static char *
construct_isalist(md_t *mdp, mde_cookie_t cpu_node_cookie,
    char **cpu_module_isa_set)
{
	extern int at_flags;
	char *md_isalist;
	int md_isalen;
	char *isabuf;
	int isalen;
	char **isa_set;
	char *p, *q;
	int cpu_module_isalen = 0, found = 0;

	(void) md_get_prop_data(mdp, cpu_node_cookie,
	    "isalist", (uint8_t **)&isabuf, &isalen);

	/*
	 * We support binaries for all the cpus that have shipped so far.
	 * The kernel emulates instructions that are not supported by hardware.
	 */
	at_flags = EF_SPARC_SUN_US3 | EF_SPARC_32PLUS | EF_SPARC_SUN_US1;

	/*
	 * Construct the space separated isa_list.
	 */
	if (cpu_module_isa_set != NULL) {
		for (isa_set = cpu_module_isa_set; *isa_set != NULL;
		    isa_set++) {
			cpu_module_isalen += strlen(*isa_set);
			cpu_module_isalen++;	/* for space character */
		}
	}

	/*
	 * Allocate the buffer of MD isa buffer length + CPU module
	 * isa buffer length.
	 */
	md_isalen = isalen + cpu_module_isalen + 2;
	md_isalist = (char *)prom_alloc((caddr_t)0, md_isalen, 0);
	if (md_isalist == NULL)
		cmn_err(CE_PANIC, "construct_isalist: Allocation failed for "
		    "md_isalist");

	md_isalist[0] = '\0'; /* create an empty string to start */
	for (p = isabuf, q = p + isalen; p < q; p += strlen(p) + 1) {
		(void) strlcat(md_isalist, p, md_isalen);
		(void) strcat(md_isalist, " ");
	}

	/*
	 * Check if the isa_set is present in isalist returned by MD.
	 * If yes, then no need to append it, if no then append it to
	 * isalist returned by MD.
	 */
	if (cpu_module_isa_set != NULL) {
		for (isa_set = cpu_module_isa_set; *isa_set != NULL;
		    isa_set++) {
			found = 0;
			for (p = isabuf, q = p + isalen; p < q;
			    p += strlen(p) + 1) {
				if (strcmp(p, *isa_set) == 0) {
					found = 1;
					break;
				}
			}
			if (!found) {
				(void) strlcat(md_isalist, *isa_set, md_isalen);
				(void) strcat(md_isalist, " ");
			}
		}
	}

	/* Get rid of any trailing white spaces */
	md_isalist[strlen(md_isalist) - 1] = '\0';

	return (md_isalist);
}

uint64_t
get_ra_limit(md_t *mdp)
{
	mde_cookie_t *mem_list;
	mde_cookie_t *mblock_list;
	int i;
	int memnodes;
	int nmblock;
	uint64_t base;
	uint64_t size;
	uint64_t ra_limit = 0, new_limit = 0;

	memnodes = md_alloc_scan_dag(mdp,
	    md_root_node(mdp), "memory", "fwd", &mem_list);

	ASSERT(memnodes == 1);

	nmblock = md_alloc_scan_dag(mdp,
	    mem_list[0], "mblock", "fwd", &mblock_list);
	if (nmblock < 1)
		cmn_err(CE_PANIC, "cannot find mblock nodes in MD");

	for (i = 0; i < nmblock; i++) {
		if (md_get_prop_val(mdp, mblock_list[i], "base", &base))
			cmn_err(CE_PANIC, "base property missing from MD"
			    " mblock node");
		if (md_get_prop_val(mdp, mblock_list[i], "size", &size))
			cmn_err(CE_PANIC, "size property missing from MD"
			    " mblock node");

		ASSERT(size != 0);

		new_limit = base + size;

		if (base > new_limit)
			cmn_err(CE_PANIC, "mblock in MD wrapped around");

		if (new_limit > ra_limit)
		    ra_limit = new_limit;
	}

	ASSERT(ra_limit != 0);

	if (ra_limit > MAX_REAL_ADDRESS) {
		cmn_err(CE_WARN, "Highest real address in MD too large"
		    " clipping to %llx\n", MAX_REAL_ADDRESS);
		ra_limit = MAX_REAL_ADDRESS;
	}

	md_free_scan_dag(mdp, &mblock_list);

	md_free_scan_dag(mdp, &mem_list);

	return (ra_limit);
}

/*
 * This routine sets the globals for CPU and DEV mondo queue entries and
 * resumable and non-resumable error queue entries.
 */
static uint64_t
get_single_q_size(md_t *mdp, mde_cookie_t cpu_node_cookie,
    char *qnamep, uint64_t default_entries)
{
	uint64_t entries;

	if (md_get_prop_val(mdp, cpu_node_cookie, qnamep, &entries)) {
		if (!broken_md_flag)
			cmn_err(CE_PANIC, "Missing %s property in MD cpu node",
				qnamep);
		entries = default_entries;
	} else {
		entries = 1 << entries;
	}
	return (entries);
}


static void
get_q_sizes(md_t *mdp, mde_cookie_t cpu_node_cookie)
{
	cpu_q_entries = get_single_q_size(mdp, cpu_node_cookie,
	    "q-cpu-mondo-#bits", DEFAULT_CPU_Q_ENTRIES);

	dev_q_entries = get_single_q_size(mdp, cpu_node_cookie,
	    "q-dev-mondo-#bits", DEFAULT_DEV_Q_ENTRIES);

	cpu_rq_entries = get_single_q_size(mdp, cpu_node_cookie,
	    "q-resumable-#bits", CPU_RQ_ENTRIES);

	cpu_nrq_entries = get_single_q_size(mdp, cpu_node_cookie,
		"q-nonresumable-#bits", CPU_NRQ_ENTRIES);
}


static void
get_va_bits(md_t *mdp, mde_cookie_t cpu_node_cookie)
{
	uint64_t value = VA_ADDRESS_SPACE_BITS;

	if (md_get_prop_val(mdp, cpu_node_cookie, "mmu-#va-bits", &value))
		cmn_err(CE_PANIC, "mmu-#va-bits property  not found in MD");


	if (value == 0 || value > VA_ADDRESS_SPACE_BITS)
		cmn_err(CE_PANIC, "Incorrect number of va bits in MD");

	/* Do not expect number of VA bits to be more than 32-bit quantity */

	va_bits = (int)value;

	/*
	 * Correct the value for VA bits on UltraSPARC-T1 based systems
	 * in case of broken MD.
	 */
	if (broken_md_flag)
		va_bits = DEFAULT_VA_ADDRESS_SPACE_BITS;
}

/*
 * This routine returns the L2 cache information such as -- associativity,
 * size and linesize.
 */
static int
get_l2_cache_info(md_t *mdp, mde_cookie_t cpu_node_cookie,
	    uint64_t *associativity, uint64_t *size, uint64_t *linesize)
{
	mde_cookie_t *cachelist;
	int ncaches, i;
	uint64_t max_level;

	ncaches = md_alloc_scan_dag(mdp, cpu_node_cookie, "cache",
	    "fwd", &cachelist);
	/*
	 * The "cache" node is optional in MD, therefore ncaches can be 0.
	 */
	if (ncaches < 1) {
		return (0);
	}

	max_level = 0;
	for (i = 0; i < ncaches; i++) {
		uint64_t cache_level;
		uint64_t local_assoc;
		uint64_t local_size;
		uint64_t local_lsize;

		if (md_get_prop_val(mdp, cachelist[i], "level", &cache_level))
			continue;

		if (cache_level <= max_level) continue;

		/* If properties are missing from this cache ignore it */

		if ((md_get_prop_val(mdp, cachelist[i],
		    "associativity", &local_assoc))) {
			continue;
		}

		if ((md_get_prop_val(mdp, cachelist[i],
		    "size", &local_size))) {
			continue;
		}

		if ((md_get_prop_val(mdp, cachelist[i],
		    "line-size", &local_lsize))) {
			continue;
		}

		max_level = cache_level;
		*associativity = local_assoc;
		*size = local_size;
		*linesize = local_lsize;
	}

	md_free_scan_dag(mdp, &cachelist);

	return ((max_level > 0) ? 1 : 0);
}

/*
 * The broken_md_flag is set to 1, if the MD doesn't have
 * the domaining-enabled property in the platform node and the platforms
 * are Ontario and Erie. This flag is used to workaround some of the
 * incorrect MD properties.
 */
static void
init_md_broken(md_t *mdp)
{
	int nrnode;
	mde_cookie_t *platlist, rootnode;
	char *vbuf;
	uint64_t val = 0;

	rootnode = md_root_node(mdp);
	ASSERT(rootnode != MDE_INVAL_ELEM_COOKIE);

	nrnode = md_alloc_scan_dag(mdp, md_root_node(mdp), "platform", "fwd",
	    &platlist);

	ASSERT(nrnode == 1);

	if (md_get_prop_str(mdp, platlist[0], "name", &vbuf) != 0)
		panic("platform name not found in machine description");

	/*
	 * If domaining-enable prop doesn't exist and the platform name is
	 * Ontario or Erie the md is broken.
	 */

	if (md_get_prop_val(mdp, platlist[0], "domaining-enabled", &val) != 0 &&
	((strcmp(vbuf, ONTARIO_PLATNAME1) == 0) ||
	(strcmp(vbuf, ONTARIO_PLATNAME2) == 0) ||
	(strcmp(vbuf, ONTARIO_PLATNAME3) == 0) ||
	(strcmp(vbuf, ERIE_PLATNAME1) == 0) ||
	(strcmp(vbuf, ERIE_PLATNAME2) == 0) ||
	(strcmp(vbuf, ERIE_PLATNAME3) == 0)))
		broken_md_flag = 1;

	md_free_scan_dag(mdp, &platlist);
}

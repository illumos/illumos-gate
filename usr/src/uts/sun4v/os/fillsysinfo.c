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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

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
#include <sys/intreg.h>
#include <sys/instance.h>

struct cpu_node cpunodes[NCPU];

uint64_t cpu_q_entries;
uint64_t dev_q_entries;
uint64_t cpu_rq_entries;
uint64_t cpu_nrq_entries;
uint64_t ncpu_guest_max;

void fill_cpu(md_t *, mde_cookie_t);

static uint64_t get_mmu_ctx_bits(md_t *, mde_cookie_t);
static uint64_t get_mmu_tsbs(md_t *, mde_cookie_t);
static uint64_t	get_mmu_shcontexts(md_t *, mde_cookie_t);
static uint64_t get_cpu_pagesizes(md_t *, mde_cookie_t);
static char *construct_isalist(md_t *, mde_cookie_t, char **);
static void init_md_broken(md_t *, mde_cookie_t *);
static int get_l2_cache_info(md_t *, mde_cookie_t, uint64_t *, uint64_t *,
    uint64_t *);
static void get_hwcaps(md_t *, mde_cookie_t);
static void get_weakest_mem_model(md_t *, mde_cookie_t);
static void get_q_sizes(md_t *, mde_cookie_t);
static void get_va_bits(md_t *, mde_cookie_t);
static size_t get_ra_limit(md_t *, mde_cookie_t);
static int get_l2_cache_node_count(md_t *);
static unsigned long names2bits(char *tokens, size_t tokenslen,
    char *bit_formatter, char *warning);

uint64_t	system_clock_freq;
uint_t		niommu_tsbs = 0;

static int n_l2_caches = 0;

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

	if (md_get_prop_val(mdp, cpuc, "id", &cpuid)) {
		return;
	}

	/* All out-of-range cpus will be stopped later. */
	if (cpuid >= NCPU) {
		cmn_err(CE_CONT, "fill_cpu: out of range cpuid %ld - "
		    "cpu excluded from configuration\n", cpuid);

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
	 * Initialize the mapping for exec unit, chip and core.
	 */
	cpunode->exec_unit_mapping = NO_EU_MAPPING_FOUND;
	cpunode->l2_cache_mapping = NO_MAPPING_FOUND;
	cpunode->core_mapping = NO_CORE_MAPPING_FOUND;

	if (ecache_setsize == 0)
		ecache_setsize = cpunode->ecache_setsize;
	if (ecache_alignsize == 0)
		ecache_alignsize = cpunode->ecache_linesize;

}

void
empty_cpu(int cpuid)
{
	bzero(&cpunodes[cpuid], sizeof (struct cpu_node));
}

/*
 * Use L2 cache node to derive the chip mapping.
 */
void
setup_chip_mappings(md_t *mdp)
{
	int ncache, ncpu;
	mde_cookie_t *node, *cachelist;
	int i, j;
	processorid_t cpuid;
	int idx = 0;

	ncache = md_alloc_scan_dag(mdp, md_root_node(mdp), "cache",
	    "fwd", &cachelist);

	/*
	 * The "cache" node is optional in MD, therefore ncaches can be 0.
	 */
	if (ncache < 1) {
		return;
	}

	for (i = 0; i < ncache; i++) {
		uint64_t cache_level;
		uint64_t lcpuid;

		if (md_get_prop_val(mdp, cachelist[i], "level", &cache_level))
			continue;

		if (cache_level != 2)
			continue;

		/*
		 * Found a l2 cache node. Find out the cpu nodes it
		 * points to.
		 */
		ncpu = md_alloc_scan_dag(mdp, cachelist[i], "cpu",
		    "back", &node);

		if (ncpu < 1)
			continue;

		for (j = 0; j < ncpu; j++) {
			if (md_get_prop_val(mdp, node[j], "id", &lcpuid))
				continue;
			if (lcpuid >= NCPU)
				continue;
			cpuid = (processorid_t)lcpuid;
			cpunodes[cpuid].l2_cache_mapping = idx;
		}
		md_free_scan_dag(mdp, &node);

		idx++;
	}

	md_free_scan_dag(mdp, &cachelist);
}

void
setup_exec_unit_mappings(md_t *mdp)
{
	int num, num_eunits;
	mde_cookie_t cpus_node;
	mde_cookie_t *node, *eunit;
	int idx, i, j;
	processorid_t cpuid;
	char *eunit_name = broken_md_flag ? "exec_unit" : "exec-unit";
	enum eu_type { INTEGER, FPU } etype;

	/*
	 * Find the cpu integer exec units - and
	 * setup the mappings appropriately.
	 */
	num = md_alloc_scan_dag(mdp, md_root_node(mdp), "cpus", "fwd", &node);
	if (num < 1)
		cmn_err(CE_PANIC, "No cpus node in machine description");
	if (num > 1)
		cmn_err(CE_PANIC, "More than 1 cpus node in machine"
		    " description");

	cpus_node = node[0];
	md_free_scan_dag(mdp, &node);

	num_eunits = md_alloc_scan_dag(mdp, cpus_node, eunit_name,
	    "fwd", &eunit);
	if (num_eunits > 0) {
		char *int_str = broken_md_flag ? "int" : "integer";
		char *fpu_str = "fp";

		/* Spin through and find all the integer exec units */
		for (i = 0; i < num_eunits; i++) {
			char *p;
			char *val;
			int vallen;
			uint64_t lcpuid;

			/* ignore nodes with no type */
			if (md_get_prop_data(mdp, eunit[i], "type",
			    (uint8_t **)&val, &vallen))
				continue;

			for (p = val; *p != '\0'; p += strlen(p) + 1) {
				if (strcmp(p, int_str) == 0) {
					etype = INTEGER;
					goto found;
				}
				if (strcmp(p, fpu_str) == 0) {
					etype = FPU;
					goto found;
				}
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
				switch (etype) {
				case INTEGER:
					cpunodes[cpuid].exec_unit_mapping = idx;
					break;
				case FPU:
					cpunodes[cpuid].fpu_mapping = idx;
					break;
				}
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
	extern int mmu_exported_pagesize_mask;
	int nocpus, i;
	size_t ra_limit;
	mde_cookie_t *cpulist;
	md_t *mdp;

	if ((mdp = md_get_handle()) == NULL)
		cmn_err(CE_PANIC, "Unable to initialize machine description");

	boot_ncpus = nocpus = md_alloc_scan_dag(mdp,
	    md_root_node(mdp), "cpu", "fwd", &cpulist);
	if (nocpus < 1) {
		cmn_err(CE_PANIC, "cpu_common_setup: cpulist allocation "
		    "failed or incorrect number of CPUs in MD");
	}

	init_md_broken(mdp, cpulist);

	if (use_page_coloring) {
		do_pg_coloring = 1;
	}

	/*
	 * Get the valid mmu page sizes mask, Q sizes and isalist/r
	 * from the MD for the first available CPU in cpulist.
	 *
	 * Do not expect the MMU page sizes mask to be more than 32-bit.
	 */
	mmu_exported_pagesize_mask = (int)get_cpu_pagesizes(mdp, cpulist[0]);

	/*
	 * Get the number of contexts and tsbs supported.
	 */
	if (get_mmu_shcontexts(mdp, cpulist[0]) >= MIN_NSHCONTEXTS &&
	    get_mmu_tsbs(mdp, cpulist[0]) >= MIN_NTSBS) {
		shctx_on = 1;
	}

	for (i = 0; i < nocpus; i++)
		fill_cpu(mdp, cpulist[i]);

	/* setup l2 cache count. */
	n_l2_caches = get_l2_cache_node_count(mdp);

	setup_chip_mappings(mdp);
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

	get_hwcaps(mdp, cpulist[0]);
	get_weakest_mem_model(mdp, cpulist[0]);
	get_q_sizes(mdp, cpulist[0]);
	get_va_bits(mdp, cpulist[0]);

	/*
	 * ra_limit is the highest real address in the machine.
	 */
	ra_limit = get_ra_limit(mdp, cpulist[0]);

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

	kpm_size_shift = !ISP2(ra_limit) ?
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
 * Get the number of tsbs from MD. If absent the default value is 0.
 */
static uint64_t
get_mmu_tsbs(md_t *mdp, mde_cookie_t cpu_node_cookie)
{
	uint64_t number_tsbs;

	if (md_get_prop_val(mdp, cpu_node_cookie, "mmu-max-#tsbs",
	    &number_tsbs))
		number_tsbs = 0;

	return (number_tsbs);
}

/*
 * Get the number of shared contexts from MD. If absent the default value is 0.
 *
 */
static uint64_t
get_mmu_shcontexts(md_t *mdp, mde_cookie_t cpu_node_cookie)
{
	uint64_t number_contexts;

	if (md_get_prop_val(mdp, cpu_node_cookie, "mmu-#shared-contexts",
	    &number_contexts))
		number_contexts = 0;

	return (number_contexts);
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

static void
get_hwcaps(md_t *mdp, mde_cookie_t cpu_node_cookie)
{
	char *hwcapbuf;
	int hwcaplen;

	if (md_get_prop_data(mdp, cpu_node_cookie,
	    "hwcap-list", (uint8_t **)&hwcapbuf, &hwcaplen)) {
		/* Property not found */
		return;
	}

	cpu_hwcap_flags |= names2bits(hwcapbuf, hwcaplen, FMT_AV_SPARC,
	    "unrecognized token: %s");
}

static void
get_weakest_mem_model(md_t *mdp, mde_cookie_t cpu_node_cookie)
{
	char *mmbuf;
	int mmlen;
	uint_t wmm;
	char *p, *q;

	if (md_get_prop_data(mdp, cpu_node_cookie,
	    "memory-model-list", (uint8_t **)&mmbuf, &mmlen)) {
		/* Property not found */
		return;
	}

	wmm = TSTATE_MM_TSO;
	for (p = mmbuf, q = p + mmlen; p < q; p += strlen(p) + 1) {
		if (strcmp(p, "wc") == 0)
			wmm = TSTATE_MM_WC;
	}
	weakest_mem_model = wmm;
}

/*
 * Does the opposite of cmn_err(9f) "%b" conversion specification:
 * Given a list of strings, converts them to a bit-vector.
 *
 *  tokens - is a buffer of [NUL-terminated] strings.
 *  tokenslen - length of tokenbuf in bytes.
 *  bit_formatter - is a %b format string, such as FMT_AV_SPARC
 *    from /usr/include/sys/auxv_SPARC.h, of the form:
 *    <base-char>[<bit-char><token-string>]...
 *        <base-char> is ignored.
 *        <bit-char>  is [1-32], as per cmn_err(9f).
 *  warning - is a printf-style format string containing "%s",
 *    which is used to print a warning message when an unrecognized
 *    token is found.  If warning is NULL, no warning is printed.
 * Returns a bit-vector corresponding to the specified tokens.
 */

static unsigned long
names2bits(char *tokens, size_t tokenslen, char *bit_formatter, char *warning)
{
	char *cur;
	size_t  curlen;
	unsigned long ul = 0;
	char *hit;
	char *bs;

	bit_formatter++;	/* skip base; not needed for input */
	cur = tokens;
	while (tokenslen) {
		curlen = strlen(cur);
		bs = bit_formatter;
		/*
		 * We need a complicated while loop and the >=32 check,
		 * instead of a simple "if (strstr())" so that when the
		 * token is "vis", we don't match on "vis2" (for example).
		 */
		/* LINTED E_EQUALITY_NOT_ASSIGNMENT */
		while ((hit = strstr(bs, cur)) &&
		    *(hit + curlen) >= 32) {
			/*
			 * We're still in the middle of a word, i.e., not
			 * pointing at a <bit-char>.  So advance ptr
			 * to ensure forward progress.
			 */
			bs = hit + curlen + 1;
		}

		if (hit != NULL) {
			ul |= (1<<(*(hit-1) - 1));
		} else {
			/* The token wasn't found in bit_formatter */
			if (warning != NULL)
				cmn_err(CE_WARN, warning, cur);
		}
		tokenslen -= curlen + 1;
		cur += curlen + 1;
	}
	return (ul);
}

uint64_t
get_ra_limit(md_t *mdp, mde_cookie_t cpu_node_cookie)
{
	extern int ppvm_enable;
	extern int meta_alloc_enable;
	mde_cookie_t *mem_list;
	mde_cookie_t *mblock_list;
	int i;
	int memnodes;
	int nmblock;
	uint64_t r;
	uint64_t base;
	uint64_t size;
	uint64_t ra_limit = 0, new_limit = 0;

	if (md_get_prop_val(mdp, cpu_node_cookie, "mmu-#ra-bits", &r) == 0) {
		if (r == 0 || r > RA_ADDRESS_SPACE_BITS)
			cmn_err(CE_PANIC, "Incorrect number of ra bits in MD");
		else {
			/*
			 * Enable memory DR and metadata (page_t)
			 * allocation from existing memory.
			 */
			ppvm_enable = 1;
			meta_alloc_enable = 1;
			return (1ULL << r);
		}
	}

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
 *
 * First, look up the number of bits available to pass an entry number.
 * This can vary by platform and may result in allocating an unreasonably
 * (or impossibly) large amount of memory for the corresponding table,
 * so we clamp it by 'max_entries'.  Finally, since the q size is used when
 * calling contig_mem_alloc(), which expects a power of 2, clamp the q size
 * down to a power of 2.  If the prop is missing, use 'default_entries'.
 */
static uint64_t
get_single_q_size(md_t *mdp, mde_cookie_t cpu_node_cookie,
    char *qnamep, uint64_t default_entries, uint64_t max_entries)
{
	uint64_t entries;

	if (default_entries > max_entries)
		cmn_err(CE_CONT, "!get_single_q_size: dflt %ld > "
		    "max %ld for %s\n", default_entries, max_entries, qnamep);

	if (md_get_prop_val(mdp, cpu_node_cookie, qnamep, &entries)) {
		if (!broken_md_flag)
			cmn_err(CE_PANIC, "Missing %s property in MD cpu node",
			    qnamep);
		entries = default_entries;
	} else {
		entries = 1 << entries;
	}

	entries = MIN(entries, max_entries);
	/* If not a power of 2, truncate to a power of 2. */
	if (!ISP2(entries)) {
		entries = 1 << (highbit(entries) - 1);
	}

	return (entries);
}

/* Scaling constant used to compute size of cpu mondo queue */
#define	CPU_MONDO_Q_MULTIPLIER	8

static void
get_q_sizes(md_t *mdp, mde_cookie_t cpu_node_cookie)
{
	uint64_t max_qsize;
	mde_cookie_t *platlist;
	int nrnode;

	/*
	 * Compute the maximum number of entries for the cpu mondo queue.
	 * Use the appropriate property in the platform node, if it is
	 * available.  Else, base it on NCPU.
	 */
	nrnode = md_alloc_scan_dag(mdp,
	    md_root_node(mdp), "platform", "fwd", &platlist);

	ASSERT(nrnode == 1);

	ncpu_guest_max = NCPU;
	(void) md_get_prop_val(mdp, platlist[0], "max-cpus", &ncpu_guest_max);
	max_qsize = ncpu_guest_max * CPU_MONDO_Q_MULTIPLIER;

	md_free_scan_dag(mdp, &platlist);

	cpu_q_entries = get_single_q_size(mdp, cpu_node_cookie,
	    "q-cpu-mondo-#bits", DEFAULT_CPU_Q_ENTRIES, max_qsize);

	dev_q_entries = get_single_q_size(mdp, cpu_node_cookie,
	    "q-dev-mondo-#bits", DEFAULT_DEV_Q_ENTRIES, MAXIVNUM);

	cpu_rq_entries = get_single_q_size(mdp, cpu_node_cookie,
	    "q-resumable-#bits", CPU_RQ_ENTRIES, MAX_CPU_RQ_ENTRIES);

	cpu_nrq_entries = get_single_q_size(mdp, cpu_node_cookie,
	    "q-nonresumable-#bits", CPU_NRQ_ENTRIES, MAX_CPU_NRQ_ENTRIES);
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

int
l2_cache_node_count(void)
{
	return (n_l2_caches);
}

/*
 * count the number of l2 caches.
 */
int
get_l2_cache_node_count(md_t *mdp)
{
	int i;
	mde_cookie_t *cachenodes;
	uint64_t level;
	int n_cachenodes = md_alloc_scan_dag(mdp, md_root_node(mdp),
	    "cache", "fwd", &cachenodes);
	int l2_caches = 0;

	for (i = 0; i < n_cachenodes; i++) {
		if (md_get_prop_val(mdp, cachenodes[i], "level", &level) != 0) {
			level = 0;
		}
		if (level == 2) {
			l2_caches++;
		}
	}
	md_free_scan_dag(mdp, &cachenodes);
	return (l2_caches);
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
	uint64_t cache_level = 0;

	ncaches = md_alloc_scan_dag(mdp, cpu_node_cookie, "cache",
	    "fwd", &cachelist);
	/*
	 * The "cache" node is optional in MD, therefore ncaches can be 0.
	 */
	if (ncaches < 1) {
		return (0);
	}

	for (i = 0; i < ncaches; i++) {
		uint64_t local_assoc;
		uint64_t local_size;
		uint64_t local_lsize;

		if (md_get_prop_val(mdp, cachelist[i], "level", &cache_level))
			continue;

		if (cache_level != 2) continue;

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

		*associativity = local_assoc;
		*size = local_size;
		*linesize = local_lsize;
		break;
	}

	md_free_scan_dag(mdp, &cachelist);

	return ((cache_level == 2) ? 1 : 0);
}


/*
 * Set the broken_md_flag to 1 if the MD doesn't have
 * the domaining-enabled property in the platform node and the
 * platform uses the UltraSPARC-T1 cpu. This flag is used to
 * workaround some of the incorrect MD properties.
 */
static void
init_md_broken(md_t *mdp, mde_cookie_t *cpulist)
{
	int nrnode;
	mde_cookie_t *platlist, rootnode;
	uint64_t val = 0;
	char *namebuf;
	int namelen;

	rootnode = md_root_node(mdp);
	ASSERT(rootnode != MDE_INVAL_ELEM_COOKIE);
	ASSERT(cpulist);

	nrnode = md_alloc_scan_dag(mdp, rootnode, "platform", "fwd",
	    &platlist);

	if (nrnode < 1)
		cmn_err(CE_PANIC, "init_md_broken: platform node missing");

	if (md_get_prop_data(mdp, cpulist[0],
	    "compatible", (uint8_t **)&namebuf, &namelen)) {
		cmn_err(CE_PANIC, "init_md_broken: "
		    "Cannot read 'compatible' property of 'cpu' node");
	}

	if (md_get_prop_val(mdp, platlist[0],
	    "domaining-enabled", &val) == -1 &&
	    strcmp(namebuf, "SUNW,UltraSPARC-T1") == 0)
		broken_md_flag = 1;

	md_free_scan_dag(mdp, &platlist);
}

#define	PLAT_MAX_IOALIASES	8

static plat_alias_t *plat_ioaliases;
static uint64_t plat_num_ioaliases;

/*
 * split the aliases property into its
 * component strings for easy searching.
 */
static void
split_alias(plat_alias_t *pali, char *str)
{
	char *aliasv[PLAT_MAX_IOALIASES], *p;
	int i, duplen;
	char *dup;

	/* skip leading space */
	str = dup = strdup(str);
	duplen = strlen(dup) + 1;
	str += strspn(str, " ");
	for (i = 0; *str != '\0'; str = p) {

		p = strpbrk(str, " ");
		if (p != NULL) {
			*p++ = '\0';
		}

		VERIFY(i < PLAT_MAX_IOALIASES);
		aliasv[i++] = strdup(str);
		if (p == NULL)
			break;
		p += strspn(p, " ");
	}

	kmem_free(dup, duplen);

	if (i == 0) {
		pali->pali_naliases = 0;
		pali->pali_aliases = NULL;
		return;
	}

	pali->pali_naliases = i;
	pali->pali_aliases = kmem_alloc(i * sizeof (char *), KM_SLEEP);
	for (i = 0; i < pali->pali_naliases; i++) {
		pali->pali_aliases[i] = aliasv[i];
	}
}

/*
 * retrieve the ioalias info from the MD,
 * and init the ioalias struct.
 *
 * NOTE: Assumes that the ioalias info does not change at runtime
 * This routine is invoked only once at boot time.
 *
 * No lock needed as this is called at boot with a DDI lock held
 */
void
plat_ioaliases_init(void)
{
	md_t *mdp;
	mde_cookie_t *ionodes, alinode;
	plat_alias_t *pali;
	int nio;
	int i;
	int err;

	mdp = md_get_handle();
	if (mdp == NULL) {
		cmn_err(CE_PANIC, "no machine description (MD)");
		/*NOTREACHED*/
	}

	nio = md_alloc_scan_dag(mdp, md_root_node(mdp),
	    "ioaliases", "fwd", &ionodes);


	/* not all platforms support aliases */
	if (nio < 1) {
		(void) md_fini_handle(mdp);
		return;
	}
	if (nio > 1) {
		cmn_err(CE_PANIC, "multiple ioalias nodes in MD");
		/*NOTREACHED*/
	}

	alinode = ionodes[0];
	md_free_scan_dag(mdp, &ionodes);

	nio = md_alloc_scan_dag(mdp, alinode, "ioalias", "fwd", &ionodes);
	if (nio <= 0) {
		cmn_err(CE_PANIC, "MD alias node has no aliases");
		/*NOTREACHED*/
	}

	plat_num_ioaliases = nio;
	plat_ioaliases = pali = kmem_zalloc(nio * sizeof (plat_alias_t),
	    KM_SLEEP);

	/*
	 * Each ioalias map will have a composite property of
	 * aliases and the current valid path.
	 */
	for (i = 0; i < nio; i++) {
		char *str;

		err = md_get_prop_str(mdp, ionodes[i], "current", &str);
		if (err != 0) {
			cmn_err(CE_PANIC, "malformed ioalias node");
			/*NOTREACHED*/
		}
		pali->pali_current = strdup(str);

		err = md_get_prop_str(mdp, ionodes[i], "aliases", &str);
		if (err != 0) {
			cmn_err(CE_PANIC, "malformed aliases");
			/*NOTREACHED*/
		}
		DDI_MP_DBG((CE_NOTE, "path: %s aliases %s",
		    pali->pali_current, str));

		split_alias(pali, str);
		pali++;
	}

	md_free_scan_dag(mdp, &ionodes);

	/*
	 * Register the io-aliases array with the DDI framework
	 * The DDI framework assumes that this array and its contents
	 * will not change post-register. The DDI framework will
	 * cache this array and is free to access this array at
	 * any time without any locks.
	 */
	ddi_register_aliases(plat_ioaliases, plat_num_ioaliases);

	(void) md_fini_handle(mdp);
}

/*
 * Number of bits forming a valid context for use in a sun4v TTE and the MMU
 * context registers. Sun4v defines the minimum default value to be 13 if this
 * property is not specified in a cpu node in machine descriptor graph.
 */
#define	MMU_INFO_CTXBITS_MIN		13

/* Convert context bits to number of contexts */
#define	MMU_INFO_BNCTXS(nbits)		((uint_t)(1u<<(nbits)))

/*
 * Read machine descriptor and load TLB to CPU mappings.
 * Returned values: cpuid2pset[NCPU], nctxs[NCPU], md_gen
 * - cpuid2pset is initialized so it can convert cpuids to processor set of CPUs
 *   that are shared between TLBs.
 * - nctxs is initialized to number of contexts for each CPU
 * - md_gen is set to generation number of machine descriptor from which this
 *   data was.
 * Return: zero on success.
 */
static int
load_tlb_cpu_mappings(cpuset_t **cpuid2pset, uint_t *nctxs, uint64_t *md_gen)
{
	mde_str_cookie_t cpu_sc, bck_sc;
	int		tlbs_idx, cp_idx;
	mde_cookie_t	root;
	md_t		*mdp = NULL;
	mde_cookie_t	*tlbs = NULL;
	mde_cookie_t	*cp = NULL;
	uint64_t	*cpids = NULL;
	uint64_t	nbit;
	int		ntlbs;
	int		ncp;
	int		retval = 1;
	cpuset_t	*ppset;

	/* get MD handle, and string cookies for cpu and back nodes */
	if ((mdp = md_get_handle()) == NULL ||
	    (cpu_sc = md_find_name(mdp, "cpu")) == MDE_INVAL_STR_COOKIE ||
	    (bck_sc = md_find_name(mdp, "back")) == MDE_INVAL_STR_COOKIE)
		goto cleanup;

	/* set generation number of current MD handle */
	*md_gen = md_get_gen(mdp);

	/* Find root element, and search for all TLBs in MD */
	if ((root = md_root_node(mdp)) == MDE_INVAL_ELEM_COOKIE ||
	    (ntlbs = md_alloc_scan_dag(mdp, root, "tlb", "fwd", &tlbs)) <= 0)
		goto cleanup;

	cp = kmem_alloc(sizeof (mde_cookie_t) * NCPU, KM_SLEEP);
	cpids = kmem_alloc(sizeof (uint64_t) * NCPU, KM_SLEEP);

	/*
	 * Build processor sets, one per possible context domain.  For each tlb,
	 * search for connected CPUs.  If any CPU is already in a set, then add
	 * all the TLB's CPUs to that set.  Otherwise, create and populate a new
	 * pset.  Thus, a single pset is built to represent multiple TLBs if
	 * they have CPUs in common.
	 */
	for (tlbs_idx = 0; tlbs_idx < ntlbs; tlbs_idx++) {
		ncp = md_scan_dag(mdp, tlbs[tlbs_idx], cpu_sc, bck_sc, cp);
		if (ncp < 0)
			goto cleanup;
		else if (ncp == 0)
			continue;

		/* Get the id and number of contexts for each cpu */
		for (cp_idx = 0; cp_idx < ncp; cp_idx++) {
			mde_cookie_t c = cp[cp_idx];

			if (md_get_prop_val(mdp, c, "id", &cpids[cp_idx]))
				goto cleanup;
			if (md_get_prop_val(mdp, c, "mmu-#context-bits", &nbit))
				nbit = MMU_INFO_CTXBITS_MIN;
			nctxs[cpids[cp_idx]] = MMU_INFO_BNCTXS(nbit);
		}

		/*
		 * If a CPU is already in a set as shown by cpuid2pset[], then
		 * use that set.
		 */
		for (cp_idx = 0; cp_idx < ncp; cp_idx++) {
			ASSERT(cpids[cp_idx] < NCPU);
			ppset = cpuid2pset[cpids[cp_idx]];
			if (ppset != NULL)
				break;
		}

		/* No CPU has a set. Create a new one. */
		if (ppset == NULL) {
			ppset = kmem_alloc(sizeof (cpuset_t), KM_SLEEP);
			CPUSET_ZERO(*ppset);
		}

		/* Add every CPU to the set, and record the set assignment. */
		for (cp_idx = 0; cp_idx < ncp; cp_idx++) {
			cpuid2pset[cpids[cp_idx]] = ppset;
			CPUSET_ADD(*ppset, cpids[cp_idx]);
		}
	}

	retval = 0;

cleanup:
	if (tlbs != NULL)
		md_free_scan_dag(mdp, &tlbs);
	if (cp != NULL)
		kmem_free(cp, sizeof (mde_cookie_t) * NCPU);
	if (cpids != NULL)
		kmem_free(cpids, sizeof (uint64_t) * NCPU);
	if (mdp != NULL)
		(void) md_fini_handle(mdp);

	return (retval);
}

/*
 * Return MMU info based on cpuid.
 *
 * Algorithm:
 * Read machine descriptor and find all CPUs that share the same TLB with CPU
 * specified by cpuid. Go through found CPUs and see if any one of them already
 * has MMU index, if so, set index based on that value. If CPU does not share
 * TLB with any other CPU or if none of those CPUs has mmu_ctx pointer, find the
 * smallest available MMU index and give it to current CPU. If no available
 * domain, perform a round robin, and start assigning from the beginning.
 *
 * For optimization reasons, this function uses a cache to store all TLB to CPU
 * mappings, and updates them only when machine descriptor graph is changed.
 * Because of this, and because we search MMU table for smallest index id, this
 * function needs to be serialized which is protected by cpu_lock.
 */
void
plat_cpuid_to_mmu_ctx_info(processorid_t cpuid, mmu_ctx_info_t *info)
{
	static cpuset_t	**cpuid2pset = NULL;
	static uint_t	*nctxs;
	static uint_t	next_domain = 0;
	static uint64_t	md_gen = MDESC_INVAL_GEN;
	uint64_t	current_gen;
	int		idx;
	cpuset_t	cpuid_pset;
	processorid_t	id;
	cpu_t		*cp;

	ASSERT(MUTEX_HELD(&cpu_lock));

	current_gen = md_get_current_gen();

	/*
	 * Load TLB CPU mappings only if MD generation has changed, FW that do
	 * not provide generation number, always return MDESC_INVAL_GEN, and as
	 * result MD is read here only once on such machines: when cpuid2pset is
	 * NULL
	 */
	if (current_gen != md_gen || cpuid2pset == NULL) {
		if (cpuid2pset == NULL) {
			cpuid2pset = kmem_zalloc(sizeof (cpuset_t *) * NCPU,
			    KM_SLEEP);
			nctxs = kmem_alloc(sizeof (uint_t) * NCPU, KM_SLEEP);
		} else {
			/* clean cpuid2pset[NCPU], before loading new values */
			for (idx = 0; idx < NCPU; idx++) {
				cpuset_t *pset = cpuid2pset[idx];

				if (pset != NULL) {
					for (;;) {
						CPUSET_FIND(*pset, id);
						if (id == CPUSET_NOTINSET)
							break;
						CPUSET_DEL(*pset, id);
						ASSERT(id < NCPU);
						cpuid2pset[id] = NULL;
					}
					ASSERT(cpuid2pset[idx] == NULL);
					kmem_free(pset, sizeof (cpuset_t));
				}
			}
		}

		if (load_tlb_cpu_mappings(cpuid2pset, nctxs, &md_gen))
			goto error_panic;
	}

	info->mmu_nctxs = nctxs[cpuid];

	if (cpuid2pset[cpuid] == NULL)
		goto error_panic;

	cpuid_pset = *cpuid2pset[cpuid];
	CPUSET_DEL(cpuid_pset, cpuid);

	/* Search for a processor in the same TLB pset with MMU context */
	for (;;) {
		CPUSET_FIND(cpuid_pset, id);

		if (id == CPUSET_NOTINSET)
			break;

		ASSERT(id < NCPU);
		cp = cpu[id];
		if (cp != NULL && CPU_MMU_CTXP(cp) != NULL) {
			info->mmu_idx = CPU_MMU_IDX(cp);

			return;
		}
		CPUSET_DEL(cpuid_pset, id);
	}

	/*
	 * No CPU in the TLB pset has a context domain yet.
	 * Use next_domain if available, or search for an unused domain, or
	 * overload next_domain, in that order.  Overloading is necessary when
	 * the number of TLB psets is greater than max_mmu_ctxdoms.
	 */
	idx = next_domain;

	if (mmu_ctxs_tbl[idx] != NULL) {
		for (idx = 0; idx < max_mmu_ctxdoms; idx++)
			if (mmu_ctxs_tbl[idx] == NULL)
				break;
		if (idx == max_mmu_ctxdoms) {
			/* overload next_domain */
			idx = next_domain;

			if (info->mmu_nctxs < sfmmu_ctxdom_nctxs(idx))
				cmn_err(CE_PANIC, "max_mmu_ctxdoms is too small"
				    " to support CPUs with different nctxs");
		}
	}

	info->mmu_idx = idx;
	next_domain = (idx + 1) % max_mmu_ctxdoms;

	return;

error_panic:
	cmn_err(CE_PANIC, "!cpu%d: failed to get MMU CTX domain index", cpuid);
}

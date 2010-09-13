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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/mdb_modapi.h>
#include <sys/nsc_thread.h>

/* needed to maintain identical _sd_bitmap_t sizes */
#define	_SD_8K_BLKSIZE
#include <sys/nsctl/sd_bcache.h>

#include <ns/sdbc/sd_io.h>
#include <ns/sdbc/sd_ft.h>
#include <ns/sdbc/safestore.h>

/*
 * initialize cd filter options to this
 * to differentiate with kernel values in range [-1, sdbc_max_devs]
 */
#define	MDB_CD ((uintptr_t)~1)
#define	OPT_C_SELECTED (opt_c != MDB_CD)

/* initialize block filters to this */
#define	MDB_BLKNUM ((uintptr_t)~1)
#define	OPT_B_SELECTED (opt_b != MDB_BLKNUM)

enum vartype { UINTTYPE = 0, ADDRTYPE, LOCKTYPE, CVTYPE };

static void display_var(char *, enum vartype);
#ifdef SAFESTORE
static void print_wrq(_sd_writeq_t *, uint_t);
#endif

struct walk_info {
		uintptr_t w_start;
		uintptr_t w_end;
};


mdb_bitmask_t host_states[] = {
	{ "HOST_NONE", 0xff, _SD_HOST_NONE },
	{ "HOST_CONFIGURED", 0xff, _SD_HOST_CONFIGURED },
	{ "HOST_DECONFIGURED", 0xff, _SD_HOST_DECONFIGURED },
	{ "HOST_NOCACHE", 0xff, _SD_HOST_NOCACHE },
	{ NULL, 0, 0 }

};

mdb_bitmask_t cache_hints[] = {
	{ "WRTHRU", NSC_WRTHRU, NSC_WRTHRU },
	{ "FORCED_WRTHRU", NSC_FORCED_WRTHRU, NSC_FORCED_WRTHRU },
	{ "NOCACHE", NSC_NOCACHE, NSC_NOCACHE },
	{ "QUEUE", NSC_QUEUE, NSC_QUEUE },
	{ "RDAHEAD", NSC_RDAHEAD, NSC_RDAHEAD },
	{ "NO_FORCED_WRTHRU", NSC_NO_FORCED_WRTHRU, NSC_NO_FORCED_WRTHRU },
	{ "METADATA", NSC_METADATA, NSC_METADATA },
	{ "SEQ_IO", NSC_SEQ_IO, NSC_SEQ_IO },
	{ NULL, 0, 0 }

};


/*
 * some cache general dcmds that do not use walkers
 */
/*ARGSUSED*/
static int
sdbc_config(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	_sd_cache_param_t _sd_cache_config;
	_sd_net_t _sd_net_config;
	_sd_ft_info_t  _sd_ft_data;
	uint_t _sd_node_hint;
	char sdbc_version[17];

	if (mdb_readvar(sdbc_version, "sdbc_version") == -1) {
		mdb_warn("failed to read sdbc_version symbol");
	} else {
		sdbc_version[16] = '\0';  /* make sure string is terminated */
		mdb_printf("sdbc_version %s\n", sdbc_version);
	}

	if (mdb_readvar(&_sd_cache_config, "_sd_cache_config") == -1) {
		mdb_warn("failed to read _sd_cache_config symbol");
	} else {

		mdb_printf("SDBC Configuration:\n");
		mdb_inc_indent(4);
		mdb_printf("user magic: %X kernel magic: %X (should match)\n",
			    _SD_MAGIC, _sd_cache_config.magic);
		mdb_printf(
		    "mirror host: %2d Block size: %4d threads %4d "
		    "write cache: %4dM\n",
			    _sd_cache_config.mirror_host,
			    _sd_cache_config.blk_size,
			    _sd_cache_config.threads,
			    _sd_cache_config.write_cache);
		mdb_printf("num_handles %4-d cache_mem %4dM prot_lru %d\n",
			    _sd_cache_config.num_handles,
			    _sd_cache_config.cache_mem[0],
			    _sd_cache_config.prot_lru);
		mdb_printf("gen_pattern %d fill_pattern %?-p num_nodes %d\n",
			    _sd_cache_config.gen_pattern,
			    _sd_cache_config.fill_pattern,
			    _sd_cache_config.num_nodes);
		mdb_dec_indent(4);
	}

	if (mdb_readvar(&_sd_net_config, "_sd_net_config") == -1) {
		mdb_warn("failed to read _sd_net_config symbol");
	} else {
		mdb_inc_indent(4);
		mdb_printf(
	"psize %4-d configured %d csize %10-d wsize %10-d cpages %6d\n",
			_sd_net_config.sn_psize,
			_sd_net_config.sn_configured,
			_sd_net_config.sn_csize,
			_sd_net_config.sn_wsize,
			_sd_net_config.sn_cpages);

		mdb_dec_indent(4);
#ifdef SAFESTORE
		print_wrq(&(_sd_net_config.sn_wr_queue), FALSE);
#endif
	}


	if (mdb_readvar(&_sd_ft_data, "_sd_ft_data") == -1) {
		mdb_warn("failed to read _sd_ft_data symbol");

	} else {
		mdb_printf("FT data:\n");
		mdb_inc_indent(4);
		mdb_printf("crashed %d host_state <%b> numio %d\n",
			_sd_ft_data.fi_crashed,
			_sd_ft_data.fi_host_state, host_states,
			_sd_ft_data.fi_numio);
		mdb_printf("lock %?-p (owner) rem_sv %h-x sleep %?-p (owner)\n",
			_sd_ft_data.fi_lock._opaque[0],
			_sd_ft_data.fi_rem_sv._opaque,
			_sd_ft_data.fi_sleep._opaque[0]);
		mdb_dec_indent(4);
	}

	if (mdb_readvar(&_sd_node_hint, "_sd_node_hint") == -1) {
		mdb_warn("failed to read _sd_node_hint symbol");

	} else
		mdb_printf("Node Hints: %08x <%b>\n",
			_sd_node_hint, cache_hints);

	display_var("sdbc_wrthru_len", UINTTYPE);
	display_var("_sd_debug_level", UINTTYPE);
	display_var("_sdbc_attached", UINTTYPE);

	return (DCMD_OK);
}

static void
sdbc_hit_percent(uint_t hits, uint_t misses, char *type)
{
	uint64_t dhits, dmisses;
	uint64_t hit_rate = 0;

	mdb_printf("%s hits: %u\t %s misses: %u\n", type, hits, type, misses);

	/* a little crude. anything less than 1 percent will show as 0 */
	if (hits > 0 || misses > 0) {
		dhits = (uint64_t)hits;
		dmisses = (uint64_t)misses;
		hit_rate = (dhits * 100)/ (dhits + dmisses);
		mdb_printf("%s hit rate: %lld %%\n", type, hit_rate);
	}
	mdb_printf("\n");
}

/*ARGSUSED*/
static int
sdbc_stats(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int i;
	char *fn;
	_sd_stats_t *_sd_cache_stats; /* local memory */
	uintptr_t _sd_cache_statsp; /* kernel pointer */
	_sd_shared_t *sh;
	int statssize;
	GElf_Sym sym;
	int maxdevs;

	if (argc != 0)
		return (DCMD_USAGE);

	/* get the number of volumes */
	if (mdb_readvar(&maxdevs, "sdbc_max_devs") == -1) {
		mdb_warn("failed to read  sdbc_max_devs");
		return (DCMD_ERR);
	}

	statssize = sizeof (_sd_stats_t) + (maxdevs - 1) *
						sizeof (_sd_shared_t);

	_sd_cache_stats = mdb_zalloc(statssize, UM_SLEEP);

	if (mdb_lookup_by_obj("sdbc", "_sd_cache_stats", &sym) == -1) {
		mdb_warn("failed to lookup _sd_cache_stats symbol");
		return (DCMD_ERR);
	}

	if (mdb_vread(&_sd_cache_statsp, sizeof (uintptr_t),
						sym.st_value) == -1) {
		mdb_warn("failed to read _sd_stats_t pointer");
		return (DCMD_ERR);
	}

	if (mdb_vread(_sd_cache_stats, statssize, _sd_cache_statsp) == -1) {
		mdb_warn("failed to read _sd_stats_t structure");
		return (DCMD_ERR);
	}

	mdb_printf("Storage Device Block Cache Statistics\n");
	mdb_printf("-------------------------------------\n");

	i = _sd_cache_stats->st_blksize;
	mdb_printf("Blocksize: 0x%x (%d)\n", i, i);

	mdb_printf("\n");
	sdbc_hit_percent(_sd_cache_stats->st_rdhits, _sd_cache_stats->st_rdmiss,
				"Read");
	sdbc_hit_percent(_sd_cache_stats->st_wrhits, _sd_cache_stats->st_wrmiss,
				"Write");

	mdb_printf("%3s %10s %8s %8s %8s %8s %8s %7s %4s %4s %s\n",
		"Cd", "Dev", "Size",
		"CacheRd", "CacheWr", "DiskRd", "DiskWr",
		"DirtyBl", "#IO", "Fail", "F");
	for (i = 0; i < maxdevs; i++) {
		sh = &_sd_cache_stats->st_shared[i];
		if (!sh->sh_alloc)
			continue;
		fn = strrchr(sh->sh_filename, '/');
		fn = fn ? fn+1 : sh->sh_filename;
		mdb_printf("%3d %10s %7d %8d %8d %8d %8d %7d %4d %4d %d\n",
			sh->sh_cd, fn, sh->sh_filesize,
			sh->sh_cache_read, sh->sh_cache_write,
			sh->sh_disk_read, sh->sh_disk_write,
			sh->sh_numdirty, sh->sh_numio, sh->sh_numfail,
			sh->sh_failed);
	}

	mdb_free(_sd_cache_stats, statssize);
	return (DCMD_OK);
}

/*
 * display some variables and counters
 */
static void
display_var(char *name, enum vartype type)
{
	uint_t		uintval;
	uintptr_t	addrval;
	kmutex_t	lockval;
	kcondvar_t	cvval;

	switch (type) {
		case UINTTYPE:
			if (mdb_readvar(&uintval, name) == -1) {
				mdb_warn("failed to read %s variable", name);
			} else
				mdb_printf("%s =\t%8x %12u\n",
						    name, uintval, uintval);
			break;
		case ADDRTYPE:
			if (mdb_readvar(&addrval, name) == -1) {
				mdb_warn("failed to read %s variable", name);
			} else
				mdb_printf("%s =\t%?-p\n",
						    name, addrval);
			break;
		case LOCKTYPE:
			if (mdb_readvar(&lockval, name) == -1) {
				mdb_warn("failed to read %s lock variable",
								name);
			} else
				mdb_printf("%s =\t%-p (owner)\n",
						name, lockval._opaque[0]);
			break;
		case CVTYPE:
			if (mdb_readvar(&cvval, name) == -1) {
				mdb_warn("failed to read %s condvar variable",
								name);
			} else
				mdb_printf("%s = \t%h-x\n",
						name, cvval._opaque);
			break;
		default:
			mdb_warn("display_var: unknown type");
	}
}

mdb_bitmask_t dealloc_flag_vals[] = {
	{ "PROCESS_CACHE_DM", (u_longlong_t)~0, PROCESS_CACHE_DM },
	{ "CACHE_SHUTDOWN_DM", (u_longlong_t)~0, CACHE_SHUTDOWN_DM },
	{ "CACHE_THREAD_TERMINATED_DM",
	    (u_longlong_t)~0, CACHE_THREAD_TERMINATED_DM },
	{ "TIME_DELAY_LVL0", (u_longlong_t)~0, TIME_DELAY_LVL0 },
	{ "TIME_DELAY_LVL1", (u_longlong_t)~0, TIME_DELAY_LVL1 },
	{ "TIME_DELAY_LVL2", (u_longlong_t)~0, TIME_DELAY_LVL2 },
	{ NULL, 0, 0 }
};

mdb_bitmask_t mdp_bits[] = {
	{ "MONITOR_DYNMEM_PROCESS_DEFAULT",
	    (u_longlong_t)~0, MONITOR_DYNMEM_PROCESS_DEFAULT},
	{ "RPT_SHUTDOWN_PROCESS_DM",
	    RPT_SHUTDOWN_PROCESS_DM, RPT_SHUTDOWN_PROCESS_DM },
	{ "RPT_DEALLOC_STATS1_DM",
	    RPT_DEALLOC_STATS1_DM, RPT_DEALLOC_STATS1_DM },
	{ "RPT_DEALLOC_STATS2_DM",
	    RPT_DEALLOC_STATS2_DM, RPT_DEALLOC_STATS2_DM },
	{ NULL, 0, 0 }
};

mdb_bitmask_t process_directive_bits[] = {
	{ "PROCESS_DIRECTIVE_DEFAULT",
	    (u_longlong_t)~0, PROCESS_DIRECTIVE_DEFAULT },
	{ "WAKE_DEALLOC_THREAD_DM",
	    WAKE_DEALLOC_THREAD_DM, WAKE_DEALLOC_THREAD_DM },
	{ "MAX_OUT_ACCEL_HIST_FLAG_DM",
	    MAX_OUT_ACCEL_HIST_FLAG_DM, MAX_OUT_ACCEL_HIST_FLAG_DM},
	{ NULL, 0, 0 }
};

/*ARGSUSED*/
static int
sdbc_vars(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int sd_dealloc_flag_dm;
	_dm_process_vars_t dynmem_processing_dm;

	if (argc != 0)
		return (DCMD_USAGE);

	mdb_printf("counters and other variables:\n");
	mdb_inc_indent(4);

	display_var("xmem_inval_hit", UINTTYPE);
	display_var("xmem_inval_miss", UINTTYPE);
	display_var("xmem_inval_inuse", UINTTYPE);

	display_var("sdbc_allocb_pageio1", UINTTYPE);
	display_var("sdbc_allocb_pageio2", UINTTYPE);
	display_var("sdbc_allocb_inuse", UINTTYPE);
	display_var("sdbc_allocb_hit", UINTTYPE);
	display_var("sdbc_allocb_lost", UINTTYPE);
	display_var("sdbc_pageio_always", UINTTYPE);
	display_var("sdbc_do_page", UINTTYPE);
	display_var("sdbc_flush_pageio", UINTTYPE);

	display_var("sdbc_centry_hit", UINTTYPE);
	display_var("sdbc_centry_inuse", UINTTYPE);
	display_var("sdbc_centry_lost", UINTTYPE);
	display_var("sdbc_centry_deallocd", UINTTYPE);

	display_var("_sd_prefetch_opt", UINTTYPE);

	display_var("sdbc_ra_hash", UINTTYPE);
	display_var("sdbc_ra_none", UINTTYPE);

	display_var("sdbc_static_cache", UINTTYPE);
	display_var("sdbc_use_dmchain", UINTTYPE);

	/* in no particular order ... */
	display_var("sdbc_check_cot", UINTTYPE);
	display_var("_sd_cctl_groupsz", UINTTYPE);
	display_var("CBLOCKS", UINTTYPE);
	display_var("_SD_SELF_HOST", UINTTYPE);
	display_var("_SD_MIRROR_HOST", UINTTYPE);
	display_var("sdbc_bio_count", UINTTYPE);
	display_var("_sd_cblock_shift", UINTTYPE);
	display_var("_sd_nodes_configured", UINTTYPE);
	display_var("nv_alloc_factor", UINTTYPE);
	display_var("_sd_ft_exit", UINTTYPE);
	display_var("_sd_flush_exit", UINTTYPE);
	display_var("_sd_node_recovery", UINTTYPE);
	display_var("_sd_async_recovery", UINTTYPE);
	display_var("_sdbc_ft_hold_io", UINTTYPE);
	display_var("mirror_clean_shutdown", UINTTYPE);
	display_var("_sd_ft_warm_start", UINTTYPE);
	mdb_dec_indent(4);
	mdb_printf("\n");

	/* some addresses of various lists and tables */
	mdb_printf("Addresses:\n");
	mdb_inc_indent(4);
	display_var("_sd_htable", ADDRTYPE);
	display_var("_sdbc_gl_centry_info", ADDRTYPE);
	display_var("_sdbc_gl_centry_info_nvmem", ADDRTYPE);
	display_var("_sdbc_gl_centry_info_size", ADDRTYPE); /* size_t */
	display_var("_sdbc_gl_file_info", ADDRTYPE);
	display_var("_sdbc_gl_file_info_size", ADDRTYPE); /* size_t */
	mdb_dec_indent(4);
	mdb_printf("\n");

	/* dynamic memory variables */
	mdb_printf("Dynamic Memory variables and stats:\n");
	mdb_inc_indent(4);
	display_var("_sdbc_memtype_deconfigure_delayed", UINTTYPE);

	if (mdb_readvar(&sd_dealloc_flag_dm, "sd_dealloc_flag_dm") == -1) {
		mdb_warn("failed to read sd_dealloc_flag_dm symbol");
	} else
		mdb_printf("sd_dealloc_flag_dm %08x <%b>\n",
				sd_dealloc_flag_dm,
				sd_dealloc_flag_dm, dealloc_flag_vals);

	if (mdb_readvar(&dynmem_processing_dm, "dynmem_processing_dm") == -1) {
		mdb_warn("failed to read dynmem_processing_dm structure");
	} else {
		_dm_process_vars_t *dp;

		dp = &dynmem_processing_dm;

		mdb_printf(
		"thread_dm_cv %h-x thread_dm_lock %?-p (owner)\n",
			dp->thread_dm_cv._opaque,
			dp->thread_dm_lock._opaque[0]);

		mdb_printf("sd_dealloc_flagx %x %8Tmax_dyn_list %3-d\n",
			dp->sd_dealloc_flagx,
			dp->max_dyn_list);

		mdb_printf("monitor_dynmem_process <%b>\n",
			dp->monitor_dynmem_process, mdp_bits);

		mdb_printf(
	"cache_aging_ct1 %3-d  %8Tcache_aging_ct2 %3-d cache_aging_ct3 %3-d\n",
			dp->cache_aging_ct1,
			dp->cache_aging_ct2,
			dp->cache_aging_ct3);

		mdb_printf(
			"cache_aging_sec1 %3-d %8Tcache_aging_sec2 %3-d"
			" cache_aging_sec3 %3-d\n",
			dp->cache_aging_sec1,
			dp->cache_aging_sec2,
			dp->cache_aging_sec3);

		mdb_printf("cache_aging_pcnt1 %3-d %8Tcache_aging_pcnt2 %3-d\n",
			dp->cache_aging_pcnt1,
			dp->cache_aging_pcnt2);

		mdb_printf(
		    "max_holds_pcnt %3-d %8Talloc_ct %8-d dealloc_ct %8-d\n",
			dp->max_holds_pcnt,
			dp->alloc_ct,
			dp->dealloc_ct);

		mdb_printf(
		"history %4x %8Tnodatas %8-d notavail %8-d candidates %8-d\n",
			dp->history,
			dp->nodatas,
			dp->notavail,
			dp->candidates);

		mdb_printf(
			"deallocs %8-d %8Thosts %8-d pests %8-d metas %8-d\n",
			dp->deallocs,
			dp->hosts,
			dp->pests,
			dp->metas);

		mdb_printf("holds %8-d %8Tothers %8-d\n",
			dp->holds,
			dp->others);

		mdb_printf("process_directive <%b>\n",
			dp->process_directive, process_directive_bits);

		mdb_printf("read_hits %8-d %8Tread_misses %8-d\n",
			dp->read_hits,
			dp->read_misses);

		mdb_printf(
		    "write_thru %8-d %8Twrite_hits %8-d write_misses %8-d\n",
			dp->write_hits,
			dp->write_misses,
			dp->write_thru);

		mdb_printf("prefetch_hits %8-d prefetch_misses %8-d\n",
			dp->prefetch_hits,
			dp->prefetch_misses);
	}
	mdb_dec_indent(4);
	mdb_printf("\n");

	/* some locks and condition variables */
	mdb_printf("Locks:\n");
	mdb_inc_indent(4);
	display_var("mutex_and_condvar_flag", UINTTYPE);
	display_var("_sd_cache_lock", LOCKTYPE);
	display_var("_sd_block_lk", LOCKTYPE);
	display_var("_sdbc_config_lock", LOCKTYPE);
	display_var("_sdbc_ft_hold_io_lk", LOCKTYPE);
	display_var("_sd_flush_cv", CVTYPE);
	display_var("_sdbc_ft_hold_io_cv", CVTYPE);
	mdb_dec_indent(4);
	mdb_printf("\n");

	return (DCMD_OK);
}

const mdb_bitmask_t nsc_buf_bits[] = {
	{"HALLOCATED", NSC_HALLOCATED, NSC_HALLOCATED},
	{"HACTIVE", NSC_HACTIVE, NSC_HACTIVE},
	{"RDBUF", NSC_RDBUF, NSC_RDBUF},
	{"WRBUF", NSC_WRBUF, NSC_WRBUF},
	{"NOBLOCK", NSC_NOBLOCK, NSC_NOBLOCK},
	{"WRTHRU", NSC_WRTHRU, NSC_WRTHRU},
	{"NOCACHE", NSC_NOCACHE, NSC_NOCACHE},
	{"BCOPY", NSC_BCOPY, NSC_BCOPY},
	{"PAGEIO", NSC_PAGEIO, NSC_PAGEIO},
	{"PINNABLE", NSC_PINNABLE, NSC_PINNABLE},
	{"FORCED_WRTHRU", NSC_FORCED_WRTHRU, NSC_FORCED_WRTHRU},
	{"METADATA", NSC_METADATA, NSC_METADATA},
	{"MIXED", NSC_MIXED, NSC_MIXED},
	{NULL, 0, 0}
};


/*
 * HELP functions for cache ctl type dcmds
 */

static void
cctl_help_common(char *name)
{
	mdb_inc_indent(4);
	mdb_printf("-c cd displays cctls for cache descriptor 'cd'\n");
	mdb_dec_indent(4);
	mdb_printf("inclusive filters:\n");
	mdb_inc_indent(4);
	mdb_printf("-b blk displays cctls for cache block number 'blk'\n");
	mdb_printf("-d displays cctls with dirty bits\n");
	mdb_printf("-h displays cctls that are hashed\n");
	mdb_printf("-i displays cctls that are inuse\n");
	mdb_printf("-o displays cctls that have I/O in progress\n");
	mdb_printf("-p displays cctls that have pagio set\n");
	mdb_printf("-B displays cctls that are marked BAD\n");
	mdb_printf("-H displays cctls that are HOSTS\n");
	mdb_printf("-P displays cctls that are PARASITES\n");
	mdb_printf("-R displays cctls that are explicit (NSC_RDAHEAD) "
			"Prefetch bufs\n");
	mdb_printf("-r displays cctls that are implicit Prefetch bufs\n");
	mdb_printf("-V displays cctls that have valid bits set\n");
	mdb_printf("-v verbose\n");
	mdb_dec_indent(4);

	mdb_printf("Default: %s displays all cctls in the list\n", name);
	mdb_printf("\n");

	mdb_printf("Example:\n");
	mdb_inc_indent(4);

	mdb_printf("%s -io -c 5 displays all cctls for cd 5 that are\n"
			"in use or have I/O in progress\n", name);
	mdb_dec_indent(4);
}

#define	CCTL_OPTIONSTRING "[-vdhiopBHPV][-c cd][-b blknum]"
void
cctl_help()
{
	mdb_printf("sdbc_cctl displays cache ctl structures\n");
	mdb_printf("Usage: [address]::sdbc_cctl " CCTL_OPTIONSTRING "\n");
	cctl_help_common("sdbc_cctl");
}

void
cchain_help()
{
	mdb_printf("sdbc_cchain displays cache ctl structures in a"
			" (alloc) cc_chain\n");
	mdb_printf("Usage: address::sdbc_cchain " CCTL_OPTIONSTRING "\n");
	cctl_help_common("sdbc_cchain");
}

void
dchain_help()
{
	mdb_printf("sdbc_dchain displays cache ctl structures in a"
			" dirty chain\n");
	mdb_printf("Usage: address::sdbc_dchain " CCTL_OPTIONSTRING "\n");
	cctl_help_common("sdbc_dchain");
}

void
dmchain_help()
{
	mdb_printf("sdbc_dmchain displays cache ctl structures in a"
			" dynamic memory allocation chain\n");
	mdb_printf("order of display is:\n"
		    "the cctl represented by the given address,\n"
		    "the cc_head_dm cctl,\n"
		    "the chain starting at cc_next_dm of the head cctl\n");
	mdb_printf("Usage: address::sdbc_dmchain " CCTL_OPTIONSTRING "\n");
	cctl_help_common("sdbc_dmchain");
}

void
hashchain_help()
{
	mdb_printf("sdbc_hashchain displays cache ctl structures in a"
			" hash chain\n");
	mdb_printf("Usage: address::sdbc_hashchain " CCTL_OPTIONSTRING "\n");
	cctl_help_common("sdbc_hashchain");
}

void
hashtable_help()
{
	mdb_printf("sdbc_hashtable displays the hash table and its chains\n");
	mdb_printf("Usage: address::sdbc_hashtable " CCTL_OPTIONSTRING "\n");
	cctl_help_common("sdbc_hashtable");
}


void
lru_help()
{
	mdb_printf("sdbc_lru displays cache ctl structures in the LRU queue\n");
	mdb_printf("Usage: [address]::sdbc_lru " CCTL_OPTIONSTRING "\n");
	cctl_help_common("sdbc_lru");
}

/*
 * help functions for write ctl dcmds
 */
void
wctl_help_common(char *name)
{
	mdb_inc_indent(4);
	mdb_printf("-v verbose\n");
	mdb_printf("-c cd show ctl structs for cache descriptor 'cd'\n");
	mdb_printf("-d show ctl structs that have dirty bits set\n");
	mdb_dec_indent(4);
	mdb_printf("Default: %s displays all write ctl in the list\n", name);
}

void
wctl_help()
{
	mdb_printf(
	    "sdbc_wctl displays the allocated array of write ctl structures\n");
	mdb_printf("Usage: [address]::sdbc_wctl [-vd][-c cd]\n");
	wctl_help_common("sdbc_wctl");
}

void
wrq_help()
{
	mdb_printf("sdbc_wrq displays the write ctl queue (wctl free list)\n");
	mdb_printf("Usage: [address]::sdbc_wrq [-vd][-c cd]\n");
	wctl_help_common("sdbc_wrq");
}

/* help function for the sdbc_cdinfo dcmd */
void
cdinfo_help()
{
	mdb_printf(
	"sdbc_cdinfo displays cd information from the _sd_cache_files table\n");
	mdb_printf("Usage: [address]::sdbc_cdfinfo [-av][-c cd]\n");
	mdb_inc_indent(4);
	mdb_printf("-a displays info for all cd_info structures\n");
	mdb_printf("-c cd displays info for cache descriptor 'cd'\n");
	mdb_printf("-v verbose\n");
	mdb_dec_indent(4);
	mdb_printf("Default: display info for cd's that are allocated\n");
}

void
ftctl_help()
{
	mdb_printf(
	    "sdbc_ftctl displays the array of fault tolerant structures \n");
	mdb_printf("Usage: [address]::sdbc_ftctl [-vd][-c cd]\n");
	wctl_help_common("sdbc_ftctl");
}

/*
 * help function for the sdbc_handles dcmd
 */
void
handle_help()
{
	mdb_printf("sdbc_handles displays active or allocated"
			" cache buffer handles\n");
	mdb_printf("Usage: [address]::sdbc_handles [-avC][-c cd]\n");
	mdb_inc_indent(4);
	mdb_printf("-a displays all handles\n");
	mdb_printf("-c n displays handle for cd n\n");
	mdb_printf("-v displays detailed handle data\n");
	mdb_printf("-C displays the handle cc_chain\n");
	mdb_dec_indent(4);
	mdb_printf("Default: display only allocated or active handles\n");
}

/*
 * help functions for the "global" memory dcmds
 */
void
glcinfo_help()
{
	mdb_printf("sdbc_glcinfo displays the global cache entry info\n");
	mdb_printf("Usage: [address]::sdbc_glcinfo [-adC][-c cd][-b fbapos]\n");
	mdb_inc_indent(4);
	mdb_printf("-a displays all global info structs\n");
	mdb_printf("-b fbapos displays structs that match FBA block"
			"(not cache block) 'fbapos'\n");
	mdb_printf("-c cd displays structs that match cache descriptor 'cd'\n");
	mdb_printf("-d displays structs with dirty bits set\n");
	mdb_printf("-C does consistency check against nvram copy\n");
	mdb_dec_indent(4);
	mdb_printf("Default: display entries with a valid cd\n");
}

void
glfinfo_help()
{
	mdb_printf("sdbc_glfinfo displays the global file info\n");
	mdb_printf("Usage: [address]::sdbc_glfinfo [-aptC]\n");
	mdb_inc_indent(4);
	mdb_printf("-a displays all global info structs\n");
	mdb_printf("-p displays structs for pinned volumes\n");
	mdb_printf("-t displays structs for attached volumes\n");
	mdb_printf("-C does consistency check against nvram copy\n");
	mdb_dec_indent(4);
	mdb_printf("Default: display entries with non-null filename\n");
}


/*
 * WALKERS
 */

/*
 * walker for the cctl list using the cc_link_list_dm pointers
 */
static int
sdbc_cctl_winit(mdb_walk_state_t *wsp)
{
	_sd_cctl_t *_sd_cctl[_SD_CCTL_GROUPS]; /* for getting first entry */
	struct walk_info *winfo;

	winfo = mdb_zalloc(sizeof (struct walk_info), UM_SLEEP);

	if (wsp->walk_addr == NULL) {
		/*
		 * we get the "first" cctl from memory and then traverse
		 * the cc_link_list_dm pointers.
		 * this traversal could start from any cctl.  here we start with
		 * the first cctl in the _sd_cctl[] array.
		 */
		if (mdb_readvar(_sd_cctl, "_sd_cctl") == -1) {
			mdb_warn("failed to read _sd_cctl array");
			return (DCMD_ERR);
		}

		wsp->walk_addr = (uintptr_t)_sd_cctl[0];
	}

	winfo->w_start = 0;
	winfo->w_end = wsp->walk_addr;
	wsp->walk_data = winfo;

	return (WALK_NEXT);
}

static int
sdbc_cctl_wstep(mdb_walk_state_t *wsp)
{
	struct walk_info *winfo = wsp->walk_data;
	_sd_cctl_t centry;
	int status;

	if (wsp->walk_addr == NULL) /* should not happen */
		return (WALK_DONE);

	/*
	 * w_start is 0 on the first iteration so the test
	 * will fail, allowing the first centry to be processed
	 */
	if (wsp->walk_addr == winfo->w_start)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
		wsp->walk_cbdata);

	if (mdb_vread(&centry, sizeof (_sd_cctl_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read centry at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	wsp->walk_addr = (uintptr_t)(centry.cc_link_list_dm);
	/* set termination condition. only needs to be done once */
	winfo->w_start = winfo->w_end;

	return (status);
}

static void
sdbc_cctl_wfini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct walk_info));
}

/*
 * walk the cc_chain list of a _sd_cctl_t
 * no global walks -- must be called with an address
 */
static int
sdbc_cchain_winit(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL)
		return (WALK_ERR);

	wsp->walk_data = mdb_zalloc(sizeof (_sd_cctl_t), UM_SLEEP);

	return (WALK_NEXT);
}

static int
sdbc_cchain_wstep(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (_sd_cctl_t), wsp->walk_addr)
				== -1) {
		mdb_warn("sdbc_cchain_wstep failed to read centry at %p",
			wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
						wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)(((_sd_cctl_t *)
				(wsp->walk_data))->cc_chain);
	return (status);
}

static void
sdbc_cchain_wfini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (_sd_cctl_t));
}


/*
 * walk the dirty chain list of a _sd_cctl_t
 * no global walks -- must be called with an address
 */
static int
sdbc_dchain_winit(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL)
		return (WALK_ERR);

	wsp->walk_data = mdb_zalloc(sizeof (_sd_cctl_t), UM_SLEEP);

	/* walk data stores the first and subsequent cc_dirty_link */
	if (mdb_vread(wsp->walk_data, sizeof (_sd_cctl_t), wsp->walk_addr)
				== -1) {
		mdb_warn("sdbc_dchain_winit failed to read centry at %p",
			wsp->walk_addr);
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
sdbc_dchain_wstep(mdb_walk_state_t *wsp)
{
	_sd_cctl_t centry;
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
						wsp->walk_cbdata);


	if (mdb_vread(&centry, sizeof (_sd_cctl_t), wsp->walk_addr)
				== -1) {
		mdb_warn("sdbc_dchain_wstep failed to read centry at %p",
			wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr =
		(uintptr_t)(centry.cc_dirty_next);

	/* end of dirty_next chain?  start on subsequent dirty_link */
	if (wsp->walk_addr == NULL) {
		wsp->walk_addr =
		(uintptr_t)(((_sd_cctl_t *)(wsp->walk_data))->cc_dirty_link);

		/* update dirty link */
		/* walk data stores the first and subsequent cc_dirty_link */
		if (wsp->walk_addr) {
			if (mdb_vread(wsp->walk_data, sizeof (_sd_cctl_t),
					wsp->walk_addr) == -1) {

				mdb_warn(
				"sdbc_dchain_wstep failed to read centry at %p",
					wsp->walk_addr);

				return (WALK_ERR);
			}
		}
	}

	return (status);
}

static void
sdbc_dchain_wfini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (_sd_cctl_t));
}

/* for stepping thru the dynmem chain */
#define	GET_HEAD_DM 0x1
#define	GET_NEXT_DM 0x2

/*
 * walk the dm chain of a cctl
 * start with current address, then cc_head_dm, then the cc_next_dm chain
 */
static int
sdbc_dmchain_winit(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL)
		return (WALK_ERR);

	wsp->walk_data = (void *)GET_HEAD_DM;

	return (WALK_NEXT);
}

static int
sdbc_dmchain_wstep(mdb_walk_state_t *wsp)
{
	_sd_cctl_t centry;
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&centry, sizeof (_sd_cctl_t), wsp->walk_addr)
				== -1) {
		mdb_warn("sdbc_dmchain_wstep failed to read centry at %p",
			wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
						wsp->walk_cbdata);

	if (wsp->walk_data == (void *)GET_HEAD_DM) {
		wsp->walk_addr = (uintptr_t)centry.cc_head_dm;
		wsp->walk_data = (void *)GET_NEXT_DM;
	} else
		wsp->walk_addr = (uintptr_t)centry.cc_next_dm;

	return (status);
}

/*ARGSUSED*/
static void
sdbc_dmchain_wfini(mdb_walk_state_t *wsp)
{
}

/*
 * walk a hash chain
 * requires an address
 */
/*ARGSUSED*/
static int
sdbc_hashchain_winit(mdb_walk_state_t *wsp)
{

	if (wsp->walk_addr == NULL)
		return (WALK_ERR);


	return (WALK_NEXT);
}

static int
sdbc_hashchain_wstep(mdb_walk_state_t *wsp)
{
	int status;
	_sd_hash_hd_t hash_entry;


	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
						wsp->walk_cbdata);

	if (mdb_vread(&hash_entry, sizeof (_sd_hash_hd_t),
					wsp->walk_addr) == -1) {
		mdb_warn(
			"sdbc_hashchain_wstep failed to read hash_entry at %p",
			wsp->walk_addr);
		return (WALK_ERR); /* will upper layer continue ? */
	}

	wsp->walk_addr = (uintptr_t)hash_entry.hh_next;

	return (status);
}

/*ARGSUSED*/
static void
sdbc_hashchain_wfini(mdb_walk_state_t *wsp)
{
}

/*
 * walk the sdbc lru list
 */
static int
sdbc_lru_winit(mdb_walk_state_t *wsp)
{
	struct walk_info *winfo;
	GElf_Sym sym;

	winfo = mdb_zalloc(sizeof (struct walk_info), UM_SLEEP);

	/* if called without an address, start at the head of the queue */
	if (wsp->walk_addr == NULL) {

		if (mdb_lookup_by_obj("sdbc", "_sd_lru_q", &sym) == -1) {
			mdb_warn("failed to lookup _sd_lru_q symbol");
			return (WALK_ERR);
		}

		/* &(_sd_lru_q.sq_qhead) */
		wsp->walk_addr = (uintptr_t)(sym.st_value);
	}

	winfo->w_start = 0;
	winfo->w_end = wsp->walk_addr;
	wsp->walk_data = winfo;

	return (WALK_NEXT);
}

static int
sdbc_lru_wstep(mdb_walk_state_t *wsp)
{
	struct walk_info *winfo = wsp->walk_data;
	_sd_cctl_t centry;
	int status;

	if (wsp->walk_addr == NULL) /* should not happen */
		return (WALK_DONE);

	/*
	 * w_start is 0 on the first iteration so the test
	 * will fail, allowing the first centry to be processed
	 */
	if (wsp->walk_addr == winfo->w_start)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
						wsp->walk_cbdata);

	if (mdb_vread(&centry, sizeof (_sd_cctl_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read centry at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	wsp->walk_addr = (uintptr_t)(centry.cc_next);

	/* set termination condition. only needs to be done once */
	winfo->w_start = winfo->w_end;

	return (status);
}

static void
sdbc_lru_wfini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct walk_info));
}


#ifdef SAFESTORE
/*
 * walk the array of allocated write control structures
 */

static int
sdbc_wctl_winit(mdb_walk_state_t *wsp)
{
	_sd_net_t  _sd_net_config;
	_sd_writeq_t wrq;
	struct walk_info *winfo;
	int blk_shft;
	int count;


	winfo = mdb_zalloc(sizeof (struct walk_info), UM_SLEEP);

	/* need to calculate the end of the array */
	if (mdb_readvar(&_sd_net_config, "_sd_net_config") == -1) {
		mdb_warn("failed to read _sd_net_config structure");
		return (WALK_ERR);
	}

	if (wsp->walk_addr == NULL)
		wsp->walk_addr = (uintptr_t)(_sd_net_config.sn_wr_cctl);

	/*
	 * this module assumes 8k block size so this code can
	 * be commented out if necessary.
	 */
	if (mdb_readvar(&blk_shft, "_sd_cblock_shift") == -1) {
		mdb_warn("failed to read _sd_cblock_shift."
			"assuming 8k cache block size");
		blk_shft = 13;
	}

	count = (_sd_net_config.sn_wpages * _sd_net_config.sn_psize) /
						    (1 << blk_shft);

	winfo->w_end = (uintptr_t)(_sd_net_config.sn_wr_cctl + count);
	wsp->walk_data = winfo;

	return (WALK_NEXT);
}

static int
sdbc_wctl_wstep(mdb_walk_state_t *wsp)
{
	struct walk_info *winfo = wsp->walk_data;
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (wsp->walk_addr >= winfo->w_end)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
						wsp->walk_cbdata);

	wsp->walk_addr += sizeof (_sd_wr_cctl_t);

	return (status);

}

static void
sdbc_wctl_wfini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct walk_info));
}

/*
 * walk the queue (free list) of write control structures
 */

static int
sdbc_wrq_winit(mdb_walk_state_t *wsp)
{
	_sd_net_t  _sd_net_config;
	_sd_writeq_t wrq;

	/* if called without an address, start at the head of the queue */
	if (wsp->walk_addr == NULL) {

		if (mdb_readvar(&_sd_net_config, "_sd_net_config") == -1) {
			mdb_warn("failed to read _sd_net_config structure");
			return (WALK_ERR);
		}

		wsp->walk_addr = (uintptr_t)
					(_sd_net_config.sn_wr_queue.wq_qtop);
	}

	return (WALK_NEXT);
}

static int
sdbc_wrq_wstep(mdb_walk_state_t *wsp)
{
	_sd_wr_cctl_t wctl;
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
						wsp->walk_cbdata);

	if (mdb_vread(&wctl, sizeof (_sd_wr_cctl_t), wsp->walk_addr)
				== -1) {
		mdb_warn("sdbc_cchain_wstep failed to read wctl at %p",
			wsp->walk_addr);
		return (WALK_ERR);
	}

	/* special case -- mini-DSP fake wr_cctl */
	if (wsp->walk_addr == (uintptr_t)wctl.wc_next)
		return (WALK_DONE);

	wsp->walk_addr = (uintptr_t)(wctl.wc_next);

	return (WALK_NEXT);
}

static void
sdbc_wrq_wfini(mdb_walk_state_t *wsp)
{
}
#endif /* SAFESTORE */
/*
 * walk the _sd_cache_files array of cd_info structures
 */
static int
sdbc_cdinfo_winit(mdb_walk_state_t *wsp)
{
	struct walk_info *winfo;
	_sd_cd_info_t	*_sd_cache_files_addr;
	int maxdevs;

	winfo = mdb_zalloc(sizeof (struct walk_info), UM_SLEEP);


	/* get the address of the cdinfo table */
	if (mdb_readvar(&_sd_cache_files_addr, "_sd_cache_files") == -1) {
		mdb_warn("failed to read _sd_cache_files address\n");
		return (WALK_ERR);
	}

	/* if called without an address, start at the head of the queue */
	if (wsp->walk_addr == NULL) {
		/* address of first _sd_cd_info_t */
		wsp->walk_addr = (uintptr_t)(_sd_cache_files_addr);
	}

	/* get the number of volumes */
	if (mdb_readvar(&maxdevs, "sdbc_max_devs") == -1) {
		mdb_warn("failed to read  sdbc_max_devs");
		return (WALK_ERR);
	}

	winfo->w_end = (uintptr_t)(_sd_cache_files_addr + maxdevs);
	wsp->walk_data = winfo;

	return (WALK_NEXT);
}

static int
sdbc_cdinfo_wstep(mdb_walk_state_t *wsp)
{
	struct walk_info *winfo = wsp->walk_data;
	int status;

	if (wsp->walk_addr >= winfo->w_end)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
						wsp->walk_cbdata);

	wsp->walk_addr += sizeof (_sd_cd_info_t);

	return (status);
}

static void
sdbc_cdinfo_wfini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct walk_info));
}

#ifdef SAFESTORE
/*
 * walk the array of allocated fault tolerant control structures
 */
static int
sdbc_ftctl_winit(mdb_walk_state_t *wsp)
{
	_sd_net_t  _sd_net_config;
	struct walk_info *winfo;
	int blk_shft = 13; /* 8k default */
	int count;


	winfo = mdb_zalloc(sizeof (struct walk_info), UM_SLEEP);

	/* need to calculate the end of the array */
	if (mdb_readvar(&_sd_net_config, "_sd_net_config") == -1) {
		mdb_warn("failed to read _sd_net_config structure");
		return (WALK_ERR);
	}

	if (wsp->walk_addr == NULL)
		wsp->walk_addr = (uintptr_t)(_sd_net_config.sn_ft_cctl);

	/*
	 * this module assumes 8k block size so this code can
	 * be commented out if necessary.
	 */
	if (mdb_readvar(&blk_shft, "_sd_cblock_shift") == -1) {
		mdb_warn("failed to read _sd_cblock_shift."
			"assuming 8k cache block size");
		blk_shft = 13;
	}

	count = (_sd_net_config.sn_wpages * _sd_net_config.sn_psize) /
						    (1 << blk_shft);

	winfo->w_end = (uintptr_t)(_sd_net_config.sn_ft_cctl + count);
	wsp->walk_data = winfo;

	return (WALK_NEXT);
}

static int
sdbc_ftctl_wstep(mdb_walk_state_t *wsp)
{
	struct walk_info *winfo = wsp->walk_data;
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (wsp->walk_addr >= winfo->w_end)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
						wsp->walk_cbdata);

	wsp->walk_addr += sizeof (_sd_ft_cctl_t);

	return (status);
}

static void
sdbc_ftctl_wfini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct walk_info));
}
#endif /* SAFESTORE */

/*
 * walk the handle list
 */
static int
sdbc_handle_winit(mdb_walk_state_t *wsp)
{
	_sd_buf_hlist_t hl;
	struct walk_info *winfo;
	GElf_Sym sym;

	if (mdb_readvar(&hl, "_sd_handle_list") == -1) {
		mdb_warn("failed to read _sd_handle_list structure");
		return (WALK_ERR);
	}

	if (mdb_lookup_by_obj("sdbc", "_sd_handle_list", &sym) == -1) {
		mdb_warn("failed to lookup _sd_handle_list symbol");
		return (WALK_ERR);
	}

	/* if called without an address, start at first element in list */
	if (wsp->walk_addr == NULL)
		wsp->walk_addr = (uintptr_t)(hl.hl_top.bh_next);

	winfo = mdb_zalloc(sizeof (struct walk_info), UM_SLEEP);

	winfo->w_end = (uintptr_t)(sym.st_value); /* &_sd_handle_list.hl_top */
	wsp->walk_data = winfo;

	return (WALK_NEXT);
}

static int
sdbc_handle_wstep(mdb_walk_state_t *wsp)
{
	struct walk_info *winfo = wsp->walk_data;
	_sd_buf_handle_t handle;
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (wsp->walk_addr == winfo->w_end)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
						wsp->walk_cbdata);

	if (mdb_vread(&handle, sizeof (_sd_buf_handle_t), wsp->walk_addr)
								== -1) {
		mdb_warn("failed to read handle at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)(handle.bh_next);

	return (status);
}

static void
sdbc_handle_wfini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct walk_info));
}

/*
 * walk the global info array (dirty bits)
 */

static int
sdbc_glcinfo_winit(mdb_walk_state_t *wsp)
{
	ss_centry_info_t *gl_centry_info;
	size_t gl_centry_info_size;
	struct walk_info *winfo;


	winfo = mdb_zalloc(sizeof (struct walk_info), UM_SLEEP);

	/* get start of the cache entry metadata */
	if (mdb_readvar(&gl_centry_info, "_sdbc_gl_centry_info") == -1) {
		mdb_warn("failed to read  _sdbc_gl_centry_info");
		return (WALK_ERR);
	}

	/* need to calculate the end of the array */
	if (mdb_readvar(&gl_centry_info_size,
				"_sdbc_gl_centry_info_size") == -1) {
		mdb_warn("failed to read  _sdbc_gl_centry_info_size");
		return (WALK_ERR);
	}

	if (wsp->walk_addr == NULL)
		wsp->walk_addr = (uintptr_t)(gl_centry_info);



	winfo->w_end = ((uintptr_t)(gl_centry_info)) + gl_centry_info_size;
	wsp->walk_data = winfo;

	return (WALK_NEXT);
}

static int
sdbc_glcinfo_wstep(mdb_walk_state_t *wsp)
{
	struct walk_info *winfo = wsp->walk_data;
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (wsp->walk_addr >= winfo->w_end)
		return (WALK_DONE);
	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
						wsp->walk_cbdata);

	wsp->walk_addr += sizeof (ss_centry_info_t);

	return (status);
}

static void
sdbc_glcinfo_wfini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct walk_info));
}

/*
 * walk the global file info array
 */
static int
sdbc_glfinfo_winit(mdb_walk_state_t *wsp)
{
	ss_voldata_t *gl_file_info;
	struct walk_info *winfo;
	int maxdevs;


	winfo = mdb_zalloc(sizeof (struct walk_info), UM_SLEEP);

	/* get start of the cache entry metadata */
	if (mdb_readvar(&gl_file_info, "_sdbc_gl_file_info") == -1) {
		mdb_warn("failed to read  _sdbc_gl_file_info");
		return (WALK_ERR);
	}


	if (wsp->walk_addr == NULL)
		wsp->walk_addr = (uintptr_t)(gl_file_info);

	/* get the number of volumes */
	if (mdb_readvar(&maxdevs, "sdbc_max_devs") == -1) {
		mdb_warn("failed to read  sdbc_max_devs");
		return (WALK_ERR);
	}

	/* end of the array */
	winfo->w_end = (uintptr_t)((gl_file_info) + maxdevs);

	wsp->walk_data = winfo;

	return (WALK_NEXT);
}

static int
sdbc_glfinfo_wstep(mdb_walk_state_t *wsp)
{
	struct walk_info *winfo = wsp->walk_data;
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (wsp->walk_addr >= winfo->w_end)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
						wsp->walk_cbdata);

	wsp->walk_addr += sizeof (ss_voldata_t);

	return (status);

}

static void
sdbc_glfinfo_wfini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct walk_info));
}

/* end of WALKERS section */


const mdb_bitmask_t cc_flag_bits[] = {
	{"PEND_DIRTY", CC_PEND_DIRTY, CC_PEND_DIRTY},
	{"PINNED", CC_PINNED, CC_PINNED},
	{"PINNABLE", CC_PINNABLE, CC_PINNABLE},
	{"QHEAD", CC_QHEAD, CC_QHEAD},
	{NULL, 0, 0}
};

const mdb_bitmask_t io_status_bits[] = {
	{"IO_NONE", 0xff, _SD_IO_NONE},
	{"IO_INITIATE", 0xff, _SD_IO_INITIATE},
	{"IO_DONE", 0xff, _SD_IO_DONE},
	{"IO_FAILED", 0xff, _SD_IO_FAILED},
	{"IO_DISCARDED", 0xff, _SD_IO_DISCARDED},
	{NULL, 0, 0}
};

const mdb_bitmask_t cc_aging_bits[] = {
	{"FOUND_IN_HASH", FOUND_IN_HASH_DM, FOUND_IN_HASH_DM},
	{"FOUND_HOLD_OVER", FOUND_HOLD_OVER_DM, FOUND_HOLD_OVER_DM},
	{"HOST_ENTRY", HOST_ENTRY_DM, HOST_ENTRY_DM},
	{"PARASITIC_ENTRY", PARASITIC_ENTRY_DM, PARASITIC_ENTRY_DM},
	{"STICKY_METADATA", STICKY_METADATA_DM, STICKY_METADATA_DM},
	{"ELIGIBLE_ENTRY", ELIGIBLE_ENTRY_DM, ELIGIBLE_ENTRY_DM},
	{"HASH_ENTRY", HASH_ENTRY_DM, HASH_ENTRY_DM},
	{"HOLD_ENTRY", HOLD_ENTRY_DM, HOLD_ENTRY_DM},
	{"AVAIL_ENTRY", AVAIL_ENTRY_DM, AVAIL_ENTRY_DM},
	{"BAD_CHAIN", BAD_CHAIN_DM, BAD_CHAIN_DM},
	{"BAD_ENTRY", BAD_ENTRY_DM, BAD_ENTRY_DM},
	{"PREFETCH_I", PREFETCH_BUF_I, PREFETCH_BUF_I},
	{"PREFETCH_E", PREFETCH_BUF_E, PREFETCH_BUF_E},
	{NULL, 0, 0}
};


/* DCMDS that use walkers */

/*
 * dcmd to display cache entry control structures
 */
static int
sdbc_cctl(uintptr_t addr, uint_t flags, int argc,
					const mdb_arg_t *argv)
{
	uint_t opt_a = FALSE;
	uintptr_t opt_c = MDB_CD;    /* cd */
	uintptr_t opt_b = MDB_BLKNUM;    /* block num */
	uint_t opt_B = FALSE;    /* BAD CHAIN or ENTRY */
	uint_t opt_d = FALSE;    /* dirty */
	uint_t opt_H = FALSE;    /* HOST */
	uint_t opt_h = FALSE;    /* hashed */
	uint_t opt_i = FALSE;    /* inuse */
	uint_t opt_p = FALSE;    /* pageio */
	uint_t opt_P = FALSE;    /* PARASITE */
	uint_t opt_R = FALSE;    /* explicit read-ahead (prefetch) */
	uint_t opt_r = FALSE;    /* implicit read-ahead (prefetch) */
	uint_t opt_o = FALSE;    /* io in progress */
	uint_t opt_m = FALSE;	 /* has memory allocated */
	uint_t opt_V = FALSE;    /* valid bits */
	uint_t opt_v = FALSE;    /* verbose */
	uint_t nofilter = FALSE; /* true if b, d, h, i, o, p, V are all false */
	_sd_cctl_t centry;
	_sd_cctl_sync_t cc_sync;

	/*
	 * possible enhancements -- option to filter on flag bits
	 * option that toggles other options.
	 */
	if (mdb_getopts(argc, argv,
			'a', MDB_OPT_SETBITS, TRUE, &opt_a,
			'B', MDB_OPT_SETBITS, TRUE, &opt_B,
			'b', MDB_OPT_UINTPTR, &opt_b,
			'c', MDB_OPT_UINTPTR, &opt_c,
			'd', MDB_OPT_SETBITS, TRUE, &opt_d,
			'H', MDB_OPT_SETBITS, TRUE, &opt_H,
			'h', MDB_OPT_SETBITS, TRUE, &opt_h,
			'i', MDB_OPT_SETBITS, TRUE, &opt_i,
			'o', MDB_OPT_SETBITS, TRUE, &opt_o,
			'm', MDB_OPT_SETBITS, TRUE, &opt_m,
			'P', MDB_OPT_SETBITS, TRUE, &opt_P,
			'p', MDB_OPT_SETBITS, TRUE, &opt_p,
			'R', MDB_OPT_SETBITS, TRUE, &opt_R,
			'r', MDB_OPT_SETBITS, TRUE, &opt_r,
			'V', MDB_OPT_SETBITS, TRUE, &opt_V,
			'v', MDB_OPT_SETBITS, TRUE, &opt_v) != argc)
		return (DCMD_USAGE);


	nofilter = (!OPT_B_SELECTED && !opt_d && !opt_h && !opt_i &&
			!opt_o && !opt_m && !opt_p && !opt_V && !opt_B &&
			!opt_P && !opt_H && !opt_R && !opt_r); /* no options */

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("sdbc`sdbc_cctl", "sdbc`sdbc_cctl",
					argc, argv) == -1) {
			mdb_warn("failed to walk 'cctl' list");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("sdbc cache ctl structures:\n");
	}


	if (mdb_vread(&centry, sizeof (_sd_cctl_t), addr) == -1) {
		mdb_warn("dcmd failed to read centry at %p", addr);
		return (DCMD_ERR);
	}

	/* filter exclusively on a cd number if specified */
	if (OPT_C_SELECTED && (centry.cc_head.hh_cd != opt_c))
		return (DCMD_OK);

	/* all other filters are inclusive */
	if ((nofilter) ||
		(OPT_B_SELECTED && (centry.cc_head.hh_blk_num == opt_b)) ||
		(opt_B && (centry.cc_aging_dm &
			(BAD_ENTRY_DM | BAD_CHAIN_DM))) ||
		(opt_d && (centry.cc_dirty)) ||
		(opt_H && (centry.cc_aging_dm & HOST_ENTRY_DM)) ||
		(opt_h && (centry.cc_head.hh_hashed)) ||
		(opt_i && (centry.cc_inuse)) ||
		(opt_p && (centry.cc_pageio)) ||
		(opt_P && (centry.cc_aging_dm & PARASITIC_ENTRY_DM)) ||
		(opt_R && (centry.cc_aging_dm & PREFETCH_BUF_E)) ||
		(opt_r && (centry.cc_aging_dm & PREFETCH_BUF_I)) ||
		(opt_V && (centry.cc_valid)) ||
		(opt_m && (centry.cc_alloc_size_dm)) ||
		(opt_o && (centry.cc_iostatus != _SD_IO_NONE)))
		/*EMPTY*/;
	else
		return (DCMD_OK);

	mdb_inc_indent(4);
	mdb_printf(
	"%-?p cd %3-d blk_num %10-d valid %04hx dirty %04hx flag %02x\n",
			addr, centry.cc_head.hh_cd,
			centry.cc_head.hh_blk_num, centry.cc_valid,
			centry.cc_dirty, centry.cc_flag);
	mdb_dec_indent(4);

	if (!opt_v)
		return (DCMD_OK);

	/* verbose */
	mdb_inc_indent(4);
	mdb_printf(
	"hashed %d seq %4-d toflush %04hx %8Tawait_use %4-d await_page %4-d\n",
		centry.cc_head.hh_hashed, centry.cc_seq,
		centry.cc_toflush, centry.cc_await_use,
		centry.cc_await_page);

	mdb_printf("inuse %d pageio %d cc_flag <%b>\n",
		centry.cc_inuse, centry.cc_pageio,
		centry.cc_flag, cc_flag_bits);

	mdb_printf("iocount %2d iostatus <%b>\n",
		    centry.cc_iocount, centry.cc_iostatus, io_status_bits);

	if (mdb_vread(&cc_sync, sizeof (struct _sd_cctl_sync),
					(uintptr_t)centry.cc_sync)
		== -1)
		mdb_warn("failed to read cc_sync"); /* not catastophic */

	else
		mdb_printf("cc_sync blkcv: %h-x %8Tlock: 0x%p (owner)\n",
				cc_sync._cc_blkcv._opaque,
				cc_sync._cc_lock._opaque[0]);

	mdb_printf("dynamic memory allocation:\n");
	mdb_inc_indent(4);
	mdb_printf("aging_dm age %3d %4Tage flags: <%b> 0x%x\n",
			centry.cc_aging_dm & 0xff,
			centry.cc_aging_dm, cc_aging_bits, centry.cc_aging_dm);

	mdb_printf("alloc_size_dm %10-d head_dm %?-p\n",
		centry.cc_alloc_size_dm, centry.cc_head_dm);
	mdb_printf("next_dm %?-p link_list_dm %?-p\n",
		centry.cc_next_dm, centry.cc_link_list_dm);

	mdb_printf("alloc_ct_dm %10-d dealloc_ct_dm %10-d\n",
		centry.cc_alloc_ct_dm, centry.cc_dealloc_ct_dm);

	mdb_dec_indent(4);
	/* pointers */
	mdb_printf("cctl pointers:\n");
	mdb_inc_indent(4);

	mdb_printf("next %?-p prev %?-p chain %?-p\n",
		centry.cc_next, centry.cc_prev, centry.cc_chain);
	mdb_printf("dirty_next %?-p dirty_link %?-p\n",
		centry.cc_dirty_next, centry.cc_dirty_link);
	mdb_printf("data %?-p write ctl %?-p\n",
		centry.cc_data, centry.cc_write);

	mdb_dec_indent(4);

	/* dynmem chain */
	mdb_printf("cctl dmqueue index cc_blocks %4-d\n", centry.cc_cblocks);

	mdb_printf("anon_addr %?-p anon_len %8-d\n",
			centry.cc_anon_addr.sa_virt, centry.cc_anon_len);

	/* stats */
	mdb_printf("cctl stats:	");
	mdb_inc_indent(4);
	mdb_printf("hits %8-d creat time %?-p\n", centry.cc_hits,
			centry.cc_creat);
	mdb_dec_indent(4);

	mdb_printf("\n");

	mdb_dec_indent(4);

	return (DCMD_OK);
}


/*
 * convenience dcmd to display the _sd_cctl cc_chain list (alloc list)
 * Must be called with an address of a cache entry (_sd_cctl_t)
 * same options as sdbc_cctl().
 * alternatively the user can call the sdbc_cchain walker
 * and pipe the addresses to sdbc_cctl dcmd.
 */
static int
sdbc_cchain(uintptr_t addr, uint_t flags, int argc,
					const mdb_arg_t *argv)
{

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_pwalk_dcmd("sdbc`sdbc_cchain", "sdbc`sdbc_cctl",
						argc, argv, addr)
			== -1) {
		mdb_warn("failed to walk cc_chain at addr %p", addr);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}


/*
 * convenience dcmd to cdisplay the _sd_cctl dirty chain
 * (which is really a 2d chain).
 * Must be called with an address of a cache entry (_sd_cctl_t)
 * same options as sdbc_cctl().
 * alternatively the user can call the sdbc_dchain walker
 * and pipe the addresses to sdbc_cctl dcmd.
 */
static int
sdbc_dchain(uintptr_t addr, uint_t flags, int argc,
					const mdb_arg_t *argv)
{

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_pwalk_dcmd("sdbc`sdbc_dchain", "sdbc`sdbc_cctl",
						argc, argv, addr)
			== -1) {
		mdb_warn("failed to walk dirty chain at addr %p", addr);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*
 * convenience dcmd to display the _sd_cctl dm chain list
 * Must be called with an address of a cache entry (_sd_cctl_t)
 * same options as sdbc_cctl().
 * alternatively the user can call the sdbc_dmchain walker
 * and pipe the addresses to sdbc_cctl dcmd.
 */
static int
sdbc_dmchain(uintptr_t addr, uint_t flags, int argc,
					const mdb_arg_t *argv)
{

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_pwalk_dcmd("sdbc`sdbc_dmchain", "sdbc`sdbc_cctl",
						argc, argv, addr)
			== -1) {
		mdb_warn("failed to walk dm chain at addr %p", addr);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*
 * dcmd to walk a hash chain
 * requires an address. same options as sdbc_cctl dcmd
 */
static int
sdbc_hashchain(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_pwalk_dcmd("sdbc`sdbc_hashchain", "sdbc`sdbc_cctl",
					argc, argv, addr) == -1) {
		mdb_warn("failed to walk hashchain at %p", addr);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}


static void
display_hash_table(_sd_hash_table_t *addr, _sd_hash_table_t *ht)
{
	mdb_printf("hash table (%p):\n", addr);
	mdb_inc_indent(4);
	mdb_printf("size %7-d bits %2-d mask %8-x nmask %8-x buckets %p\n",
		ht->ht_size, ht->ht_bits, ht->ht_mask,
		ht->ht_nmask, ht->ht_buckets);
	mdb_dec_indent(4);
}

static void
display_hash_bucket(_sd_hash_bucket_t *addr, _sd_hash_bucket_t *hb)
{
	kmutex_t lock;
	int rc;

	if ((rc = mdb_vread(&lock, sizeof (kmutex_t),
				(uintptr_t)hb->hb_lock)) == -1)
		mdb_warn("failed to read bucket lock at %p", hb->hb_lock);

	mdb_printf("hash bucket (%p):\n", addr);
	mdb_inc_indent(4);
	mdb_printf("head %?-p tail %?-p lock %?-p %s\n",
		hb->hb_head, hb->hb_tail,
		(rc == -1) ? hb->hb_lock : lock._opaque[0],
		(rc == -1) ? "" : "(owner)");
	mdb_printf("inlist %d seq %d\n", hb->hb_inlist, hb->hb_seq);
	mdb_dec_indent(4);
}

/*
 * dcmd to walk the hash table
 * defaults to _sd_htable the cache hash table,
 * but wil accept an address which is probably only useful
 * in the event that other hash tables are implemented in
 * the cache.
 *
 * calls sdbc_hashchain dcmd.  same options as sdbc_cctl dcmd.
 */
static int
sdbc_hashtable(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	_sd_hash_table_t *sd_htable_addr;
	_sd_hash_table_t _sd_htable;
	_sd_hash_bucket_t hash_bucket;
	int i;



	if (!(flags & DCMD_ADDRSPEC)) {
		/* get the address of the standard cache hash table */
		if (mdb_readvar(&sd_htable_addr, "_sd_htable") == -1) {
			mdb_warn("failed to read _sd_htable address\n");
			return (DCMD_ERR);
		}
	} else
		sd_htable_addr = (_sd_hash_table_t *)addr;

	/* read in the hash table structure */
	if (mdb_vread(&_sd_htable, sizeof (_sd_hash_table_t),
		(uintptr_t)sd_htable_addr) == -1) {
		mdb_warn("failed to read _sd_htable structure at %p\n",
						    sd_htable_addr);
		return (DCMD_ERR);
	}

	display_hash_table(sd_htable_addr, &_sd_htable);

	/*
	 * read in the hash buckets
	 * and display chains if there are any
	 */
	for (i = 0; i < _sd_htable.ht_size; ++i) {
		if (mdb_vread(&hash_bucket, sizeof (_sd_hash_bucket_t),
			    (uintptr_t)(_sd_htable.ht_buckets + i)) == -1) {
			mdb_warn("failed to read ht_buckets at %p\n",
					    _sd_htable.ht_buckets + i);
			return (DCMD_ERR);
		}

		if (hash_bucket.hb_head != NULL) {
			display_hash_bucket(_sd_htable.ht_buckets + i,
							&hash_bucket);
			/*
			 * if this walk fails, continue trying
			 * to read hash buckets
			 */
			if (mdb_call_dcmd("sdbc`sdbc_hashchain",
					(uintptr_t)hash_bucket.hb_head,
					flags|DCMD_ADDRSPEC, argc, argv)
								    == -1)
				    mdb_warn(
					    "failed to walk hash chain at %p",
					hash_bucket.hb_head);
			    mdb_printf("\n");
		    }
	}

	return (DCMD_OK);
}
/*
 * dcmd to display the sdbc lru queue
 * same options as sdbc_cctl().
 * alternatively the user can call the sdbc_lru walker
 * and pipe the addresses to sdbc_cctl dcmd.
 */
static int
sdbc_lru(uintptr_t addr, uint_t flags, int argc,
					const mdb_arg_t *argv)
{
	_sd_queue_t _sd_lru_q;
	GElf_Sym sym;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_lookup_by_obj("sdbc", "_sd_lru_q", &sym) == -1) {
			mdb_warn("failed to lookup _sd_lru_q symbol");
			return (DCMD_ERR);
		}

		if (mdb_vread(&_sd_lru_q, sizeof (_sd_queue_t),
						sym.st_value) == -1) {
			mdb_warn("failed to read _sd_lru_q structure");
			return (DCMD_ERR);
		}

		mdb_printf("Cache LRU Queue\n");
		mdb_inc_indent(4);
		mdb_printf(
		"qlock: 0x%-p (owner) await %d seq %d inq %d req %d noreq %d\n",
			_sd_lru_q.sq_qlock._opaque[0],
			_sd_lru_q.sq_await,
			_sd_lru_q.sq_seq,
			_sd_lru_q.sq_inq,
			_sd_lru_q.sq_req_stat,
			_sd_lru_q.sq_noreq_stat);

		addr = (uintptr_t)(sym.st_value);
	}

	if (mdb_pwalk_dcmd("sdbc`sdbc_lru", "sdbc`sdbc_cctl",
					argc, argv, addr) == -1) {
		mdb_warn("failed to walk lru at addr %p", addr);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

#ifdef SAFESTORE
static void
print_wrq(_sd_writeq_t *wrq, uint_t verbose)
{
	int i;

	mdb_printf("Cache Write Ctl Queue:\n");
	mdb_inc_indent(4);
	mdb_printf("qtop %-p qlock: %-p (owner) inq %d\n",
		wrq->wq_qtop,
		wrq->wq_qlock._opaque[0],
		wrq->wq_inq);

	mdb_printf("slp_top %3-d slp_index %3-d slp_inq %3-d\n",
		wrq->wq_slp_top,
		wrq->wq_slp_index,
		wrq->wq_slp_inq);

	for (i = 0; verbose && i < SD_WR_SLP_Q_MAX; i += 2) {
		mdb_printf("%3d: cv %h-x wq_need %3-d wq_held %3-d%4T",
			i,
			wrq->wq_slp[i].slp_wqcv._opaque,
			wrq->wq_slp[i].slp_wqneed,
			wrq->wq_slp[i].slp_wqheld);
		if (SD_WR_SLP_Q_MAX > (i + 1)) {
			mdb_printf(
			"%3d: cv %h-x wq_need %3-d wq_held %3-d%\n",
			    i+1,
			    wrq->wq_slp[i+1].slp_wqcv._opaque,
			    wrq->wq_slp[i+1].slp_wqneed,
			    wrq->wq_slp[i+1].slp_wqheld);
		}
	}
	mdb_dec_indent(4);
}

/*
 * dcmd to display write control structures
 */

static int
sdbc_wctl(uintptr_t addr, uint_t flags, int argc,
					const mdb_arg_t *argv)
{
	_sd_wr_cctl_t wctl;
	ss_centry_info_t gl_info;
	ss_centry_info_t nv_gl_info;
	uintptr_t opt_c = MDB_CD;
	uint_t opt_d = FALSE;
	uint_t opt_v = FALSE;


	/* TODO option for fba pos */
	if (mdb_getopts(argc, argv,
			'd', MDB_OPT_SETBITS, TRUE, &opt_d,
			'c', MDB_OPT_UINTPTR, &opt_c,
			'v', MDB_OPT_SETBITS, TRUE, &opt_v) != argc)
		return (DCMD_USAGE);


	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("sdbc`sdbc_wctl", "sdbc`sdbc_wctl",
					argc, argv) == -1) {
			mdb_warn("failed to walk write ctl array");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("write control block structures:\n");
	}

	if (mdb_vread(&wctl, sizeof (_sd_wr_cctl_t), addr) == -1) {
		mdb_warn("failed to read wctl at 0x%p", addr);
		return (DCMD_ERR);
	}


	/*
	 * print "all" is the default.
	 * filter conditions can only be checked by reading in wc_gl_info
	 */
	if (opt_c || opt_d || opt_v)
	    if (mdb_vread(&gl_info, sizeof (ss_centry_info_t),
				(uintptr_t)wctl.wc_gl_info) == -1) {
		    mdb_warn("failed to read at wc_gl_info 0x%p", addr);
		return (DCMD_ERR);
	}


	if (OPT_C_SELECTED && (gl_info.gl_cd != opt_c))
		return (DCMD_OK);

	if (opt_d && !(gl_info.gl_dirty))
		return (DCMD_OK);

	mdb_inc_indent(4);
	mdb_printf("%-p data %-p gl_info %-p Ngl_info %-p flg %02x\n",
		addr,
		wctl.wc_data,
		wctl.wc_gl_info,
		wctl.wc_nvmem_gl_info,
		wctl.wc_flag);
	mdb_dec_indent(4);

	/* verbose */
	if (!opt_v)
		return (DCMD_OK);

	mdb_inc_indent(4);
	mdb_printf("next %?-p prev %?-p\n", wctl.wc_next, wctl.wc_prev);
	mdb_printf("      gl_info: ");
	mdb_printf("cd %3-d fpos %10-d dirty %04x flag <%b>\n",
		gl_info.gl_cd, gl_info.gl_fpos, gl_info.gl_dirty & 0xffff,
		gl_info.gl_flag, cc_flag_bits);

	if (wctl.wc_nvmem_gl_info) {
	    if (mdb_vread(&nv_gl_info, sizeof (ss_centry_info_t),
				(uintptr_t)wctl.wc_nvmem_gl_info) == -1) {
		    mdb_warn("failed to read at wc_nvmem_gl_info 0x%p",
		    wctl.wc_nvmem_gl_info);  /* not catastophic, continue */
	    } else {

		    /* consistency check */
			if (memcmp(&gl_info, &nv_gl_info,
					sizeof (ss_centry_info_t) != 0)) {
			mdb_warn("nvram and host memory are NOT identical!");
			mdb_printf("nvmem_gl_info: ");
			mdb_printf("cd %3-d fpos %10-d dirty %04x flag <%b>\n",
			nv_gl_info.gl_cd, nv_gl_info.gl_fpos,
			nv_gl_info.gl_dirty & 0xffff,
			nv_gl_info.gl_flag, cc_flag_bits);
		    }

	    }
	}

	mdb_dec_indent(4);
	mdb_printf("\n");
	return (DCMD_OK);
}

/*
 * dcmd to display write control structures in the free list
 * same options as sdbc_wctl
 */

static int
sdbc_wrq(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	_sd_net_t _sd_net_config;
	uintptr_t opt_c = MDB_CD;
	uint_t opt_d = FALSE;
	uint_t opt_v = FALSE;


	/* look for verbose option */
	if (mdb_getopts(argc, argv,
			'd', MDB_OPT_SETBITS, TRUE, &opt_d,
			'c', MDB_OPT_UINTPTR, &opt_c,
			'v', MDB_OPT_SETBITS, TRUE, &opt_v) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_readvar(&_sd_net_config, "_sd_net_config") == -1) {
			mdb_warn("failed to read _sd_net_config structure");
			return (DCMD_ERR);
		}

		print_wrq(&(_sd_net_config.sn_wr_queue), opt_v);

		addr = (uintptr_t)(_sd_net_config.sn_wr_queue.wq_qtop);
	}

	if (mdb_pwalk_dcmd("sdbc`sdbc_wrq", "sdbc`sdbc_wctl",
					argc, argv, addr) == -1) {
		mdb_warn("failed to walk write ctl queue at addr %p", addr);
		return (DCMD_ERR);
	}
	return (DCMD_OK);
}
#endif

/*
 * dcmd to display the dm queues
 * use sdbc_lru walker to walk each queue.
 */
/*ARGSUSED*/
static int
sdbc_dmqueues(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	_sd_queue_t *sdbc_dm_queues; /* kernel address of dm queues */
	int max_dm_queues;
	_sd_queue_t *queues = NULL; /* local copy */
	int i;


	if (argc != 0)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_readvar(&sdbc_dm_queues, "sdbc_dm_queues") == -1) {
			mdb_warn("failed to read sdbc_dm_queues address\n");
			return (DCMD_ERR);
		}

		if (mdb_readvar(&max_dm_queues, "max_dm_queues") == -1) {
			mdb_warn("failed to read max_dm_queues variable\n");
			return (DCMD_ERR);
		}

		queues = mdb_zalloc(max_dm_queues * sizeof (_sd_queue_t),
					UM_SLEEP);
mdb_printf("max_dm_queues %d sdbc_dm_queues %p queues %p\n",
		max_dm_queues, sdbc_dm_queues, queues);

		if (mdb_vread(queues, max_dm_queues * sizeof (_sd_queue_t),
					(uintptr_t)sdbc_dm_queues) == -1) {
			mdb_warn("failed to read sdbc_dm_queues");
			return (DCMD_ERR);
		}

		for (i = 0;  i < max_dm_queues; ++i) {
			mdb_printf("Cache DM Queue %d %p\n",
					queues[i].sq_dmchain_cblocks,
					sdbc_dm_queues +i);
			mdb_inc_indent(4);
			mdb_printf("qlock: 0x%-p (owner) await %d "
					"seq %d inq %d req %d noreq %d\n",
					queues[i].sq_qlock._opaque[0],
					queues[i].sq_await,
					queues[i].sq_seq,
					queues[i].sq_inq,
					queues[i].sq_req_stat,
					queues[i].sq_noreq_stat);

			mdb_dec_indent(4);
		}
	}

	return (DCMD_OK);
}


mdb_bitmask_t cd_writer_bits[] = {
	{ "NONE   ", (u_longlong_t)~0, _SD_WRITER_NONE },
	{ "CREATE ", (u_longlong_t)~0, _SD_WRITER_CREATE },
	{ "RUNNING", (u_longlong_t)~0, _SD_WRITER_RUNNING },
	{ NULL, 0, 0 }
};

mdb_bitmask_t sh_failed_status[] = {
	{ "STATUS OK", (u_longlong_t)~0, 0 },
	{ "I/O ERROR", (u_longlong_t)~0, 1 },
	{ "OPEN FAIL", (u_longlong_t)~0, 2 },
	{ NULL, 0, 0 }
};

mdb_bitmask_t sh_flag_bits[] = {
	{ "ATTACHED", CD_ATTACHED, CD_ATTACHED },
	{ NULL, 0, 0 }
};

mdb_bitmask_t sh_alloc_bits[] = {
	{ "ALLOC_IN_PROGRESS", CD_ALLOC_IN_PROGRESS, CD_ALLOC_IN_PROGRESS },
	{ "ALLOCATED", CD_ALLOCATED, CD_ALLOCATED },
	{ "CLOSE_IN_PROGRESS", CD_CLOSE_IN_PROGRESS, CD_CLOSE_IN_PROGRESS },
	{ NULL, 0, 0 }
};

/*
 * dcmd to display cd information
 */
static int
sdbc_cdinfo(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	_sd_shared_t sd_shared;
	_sd_cd_info_t cdi;
	ss_voldata_t gl_file;
	char *fn = "nopath"; /* filename if sd_shared info cannot be read */
	uchar_t sh_alloc = 0; /* assume not alloc'd if sd_shared info unavail */
	uintptr_t opt_c = MDB_CD;
	uint_t opt_a = FALSE;
	uint_t opt_v = FALSE;
	int dev_t_chars;

	dev_t_chars = sizeof (dev_t) * 2;	/* # chars to display dev_t */


	if (mdb_getopts(argc, argv,
			'a', MDB_OPT_SETBITS, TRUE, &opt_a,
			'c', MDB_OPT_UINTPTR, &opt_c,
			'v', MDB_OPT_SETBITS, TRUE, &opt_v) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("sdbc`sdbc_cdinfo", "sdbc`sdbc_cdinfo",
					argc, argv) == -1) {
			mdb_warn("failed to walk cd info array");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("cd info structures:\n");
	}

	if (mdb_vread(&cdi, sizeof (_sd_cd_info_t), addr) == -1) {
		mdb_warn("failed to read cd info at 0x%p", addr);
		return (DCMD_ERR);
	}

	/*
	 * need to do this read even for non-verbose option to
	 * get the filename and the sh_alloc field
	 */
	if (cdi.cd_info) {
	    if (mdb_vread(&sd_shared, sizeof (_sd_shared_t),
				    (uintptr_t)cdi.cd_info) == -1) {
		    mdb_warn("failed to read shared cd info at 0x%p",
						    cdi.cd_info);
		    /* not catastrophic, keep truckin' */
	    } else {
		    fn = sd_shared.sh_filename;
		    sh_alloc = sd_shared.sh_alloc;
	    }
	}

	if (!opt_a && (sh_alloc == 0))
		return (DCMD_OK);

	if (OPT_C_SELECTED && (opt_c != cdi.cd_desc))
		return (DCMD_OK);

	mdb_inc_indent(4);
	mdb_printf("%p cd %3-d filename %s\n",
		addr, cdi.cd_desc, fn);
	mdb_printf("alloc <%b> hint <%b>\n",
		sh_alloc, sh_alloc_bits,
		cdi.cd_hint, cache_hints);
	mdb_dec_indent(4);

	if (!opt_v)
		return (DCMD_OK);

	/* verbose */
	mdb_inc_indent(4);
	mdb_printf("rawfd %?-p crdev %0*lx iodev %?-p\n",
		cdi.cd_rawfd,
		dev_t_chars,
		cdi.cd_crdev,
		cdi.cd_iodev);
	mdb_printf("flag %x %8Tlock %?-p writer <%b>\n",
		cdi.cd_flag,
		cdi.cd_lock._opaque[0],
		cdi.cd_writer, cd_writer_bits);
	mdb_printf("global %?-p dirty_head %?-p\n",
		cdi.cd_global, cdi.cd_dirty_head);
	mdb_printf("last_ent %?-p lastchain_ptr %?-p lastchain %d\n",
		cdi.cd_last_ent, cdi.cd_lastchain_ptr,
		cdi.cd_lastchain);
	mdb_printf("io_head %?-p io_tail %?-p fail_head %?-p\n",
		cdi.cd_io_head, cdi.cd_io_tail, cdi.cd_fail_head);
	mdb_printf(
	    "cd_info %?-p failover %d recovering %d write_inprogress %d\n",
		cdi.cd_info, cdi.cd_failover,
		cdi.cd_recovering,
		cdi.cd_write_inprogress);

	if (cdi.cd_global != NULL) {
		if (mdb_vread(&gl_file, sizeof (ss_voldata_t),
					(uintptr_t)cdi.cd_global) == -1)
			mdb_warn("failed to read cd_global at %p",
						    cdi.cd_global);
		else {
			mdb_printf("cd_global: %s\n", gl_file.sv_volname);
			mdb_printf("pinned %2-d attached %2-d devidsz %3-d\n",
				gl_file.sv_pinned, gl_file.sv_attached,
				gl_file.sv_devidsz);
			mdb_printf("devid %s\n", gl_file.sv_devid);
			mdb_printf("vol %?p\n", gl_file.sv_vol);
		}
		/* TODO do a consistency check here against the nvram copy */
	}

	if (cdi.cd_info == NULL) {
		mdb_printf("no shared info\n");
	} else {
		mdb_printf("shared:\n");
		mdb_printf("failed <%b> cd %3-d",
		    sd_shared.sh_failed, sh_failed_status,
		    sd_shared.sh_cd);
		mdb_printf("cache_read %10-d cache_write %10-d\n",
		    sd_shared.sh_cache_read, sd_shared.sh_cache_write);
		mdb_printf("disk_read %10-d disk_write %10-d filesize %10-d\n",
		    sd_shared.sh_disk_read, sd_shared.sh_disk_write,
		    sd_shared.sh_filesize);
		mdb_printf("numdirty %8-d numio %8-d numfail %8-d\n",
		    sd_shared.sh_numdirty,
		    sd_shared.sh_numio,
		    sd_shared.sh_numfail);
		mdb_printf("flushloop %2-d sh_flag <%b>\n",
		    sd_shared.sh_flushloop, sd_shared.sh_flag, sh_flag_bits);

		/* this can be really verbose */
		if (cdi.cd_dirty_head) {
			mdb_printf("Dirty Chain (cd_dirty_head):");
			/* TODO reconstruct argv without opt_a */
			if (!opt_a)
				mdb_call_dcmd("sdbc_dchain",
					(uintptr_t)cdi.cd_dirty_head,
					flags, argc, argv);
			else /* print with no options */
				mdb_call_dcmd("sdbc_dchain",
					(uintptr_t)cdi.cd_dirty_head,
					flags, 0, NULL);
		}

		if (cdi.cd_io_head) {
			mdb_printf("I/O Pending Chain (cd_io_head):");
			/* TODO reconstruct argv without opt_a */
			if (!opt_a)
				mdb_call_dcmd("sdbc_dchain",
					(uintptr_t)cdi.cd_io_head,
					flags, argc, argv);
			else /* print with no options */
				mdb_call_dcmd("sdbc_dchain",
					(uintptr_t)cdi.cd_dirty_head,
					flags, 0, NULL);
		}

		if (cdi.cd_fail_head) {
			mdb_printf("Failed Chain (cd_fail_head):");
			/* TODO reconstruct argv without opt_a */
			if (!opt_a)
				mdb_call_dcmd("sdbc_dchain",
					(uintptr_t)cdi.cd_fail_head,
					flags, argc, argv);
			else /* print with no options */
				mdb_call_dcmd("sdbc_dchain",
					(uintptr_t)cdi.cd_dirty_head,
					flags, 0, NULL);
		}
	}

	mdb_dec_indent(4);

	mdb_printf("\n");

	return (DCMD_OK);
}

#ifdef SAFESTORE
/*
 * dcmd to display fault tolerant control structures
 */
static int
sdbc_ftctl(uintptr_t addr, uint_t flags, int argc,
					const mdb_arg_t *argv)
{
	_sd_ft_cctl_t ft_cent;
	ss_centry_info_t gl_info;
	ss_centry_info_t nv_gl_info;
	uintptr_t opt_c = MDB_CD;
	uint_t opt_d = FALSE;
	uint_t opt_v = FALSE;


	/* TODO option to select on fpos */
	if (mdb_getopts(argc, argv,
			'd', MDB_OPT_SETBITS, TRUE, &opt_d,
			'c', MDB_OPT_UINTPTR, &opt_c,
			'v', MDB_OPT_SETBITS, TRUE, &opt_v) != argc)
		return (DCMD_USAGE);


	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("sdbc`sdbc_ftctl", "sdbc`sdbc_ftctl",
					argc, argv) == -1) {
			mdb_warn("failed to walk write ctl array");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("Ft control block structures:\n");
	}

	if (mdb_vread(&ft_cent, sizeof (_sd_ft_cctl_t), addr) == -1) {
		mdb_warn("failed to read ft_cent at 0x%p", addr);
		return (DCMD_ERR);
	}


	/*
	 * print "all" is the default.
	 * filter conditions can only be checked by reading in wc_gl_info
	 */
	if (opt_c || opt_d || opt_v)
	    if (mdb_vread(&gl_info, sizeof (ss_centry_info_t),
				(uintptr_t)ft_cent.ft_gl_info) == -1) {
		mdb_warn("failed to read at wc_gl_info 0x%p", addr);
		return (DCMD_ERR);
	}


	if (OPT_C_SELECTED && (gl_info.gl_cd != opt_c))
		return (DCMD_OK);

	if (opt_d && !(gl_info.gl_dirty))
		return (DCMD_OK);

	mdb_inc_indent(4);
	mdb_printf("%-p data %?-p qnext %?-p\n",
		addr,
		ft_cent.ft_qnext,
		ft_cent.ft_data);
	mdb_printf("gl_info %?-p nvmem_gl_info %?-p\n",
		ft_cent.ft_gl_info,
		ft_cent.ft_nvmem_gl_info);
	mdb_dec_indent(4);

	/* verbose */
	if (!opt_v) {
		mdb_printf("\n");
		return (DCMD_OK);
	}

	mdb_inc_indent(4);
	mdb_printf("      gl_info: ");
	mdb_printf("cd %3-d fpos %10-d dirty %04x flag <%b>\n",
		gl_info.gl_cd, gl_info.gl_fpos, gl_info.gl_dirty & 0xffff,
		gl_info.gl_flag, cc_flag_bits);

	if (ft_cent.ft_nvmem_gl_info) {
	    if (mdb_vread(&nv_gl_info, sizeof (ss_centry_info_t),
				(uintptr_t)ft_cent.ft_nvmem_gl_info) == -1) {
		    mdb_warn("failed to read at ft_nvmem_gl_info 0x%p",
		    ft_cent.ft_nvmem_gl_info);  /* not catastophic, continue */
	    } else {
		    mdb_printf("nvmem_gl_info: ");
		    mdb_printf("cd %3-d fpos %10-d dirty %04x flag <%b>\n",
		    nv_gl_info.gl_cd, nv_gl_info.gl_fpos,
		    nv_gl_info.gl_dirty & 0xffff,
		    nv_gl_info.gl_flag, cc_flag_bits);

		    /* consistency check */
		    if (memcmp(&gl_info, &nv_gl_info, sizeof (ss_centry_info_t))
								!= 0) {
			mdb_warn("nvram and host memory are NOT identical!");
		    }

	    }
	}

	mdb_dec_indent(4);
	mdb_printf("\n");
	return (DCMD_OK);
}
#endif /* SAFESTORE */


/* dcmd to display buffer handles */
static int
sdbc_handles(uintptr_t addr, uint_t flags, int argc,
					const mdb_arg_t *argv)
{
	uint_t opt_a = FALSE;
	uintptr_t opt_c = MDB_CD;
	uint_t opt_v = FALSE;
	uint_t opt_C = FALSE;
	_sd_buf_hlist_t hl;
	_sd_buf_handle_t bh;


	if (mdb_getopts(argc, argv,
			'a', MDB_OPT_SETBITS, TRUE, &opt_a,
			'c', MDB_OPT_UINTPTR, &opt_c,
			'C', MDB_OPT_SETBITS, TRUE, &opt_C,
			'v', MDB_OPT_SETBITS, TRUE, &opt_v) != argc)
		return (DCMD_USAGE);


	if (mdb_readvar(&hl, "_sd_handle_list") == -1) {
		mdb_warn("failed to read _sd_handle_list structure");
		return (DCMD_ERR);
	}


	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("sdbc`sdbc_handles", "sdbc`sdbc_handles",
					argc, argv) == -1) {
			mdb_warn("failed to walk 'sdbc_handle_list'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("Handle List Info:\n");

		mdb_inc_indent(4);
		mdb_printf("hl_top.bh_next: 0x%p\n", hl.hl_top.bh_next);
		mdb_printf("hl_lock: 0x%p (owner)\n", hl.hl_lock._opaque[0]);
		mdb_printf("hl_count: %hd\n", hl.hl_count);
		mdb_dec_indent(4);
		mdb_printf("buf handles:\n");
	}

	if (mdb_vread(&bh, sizeof (bh), addr) == -1) {
		mdb_warn("failed to read buf handle at 0x%p", addr);
		return (DCMD_ERR);
	}

	if (!opt_a && !(bh.bh_flag & (NSC_HALLOCATED | NSC_HACTIVE)))
		return (DCMD_OK);

	/*
	 * may get false matches on cd option --
	 * a cleared bh_cd field will match if user specified cd 0
	 */
	if (OPT_C_SELECTED && (bh.bh_cd != opt_c))
		return (DCMD_OK);

	mdb_inc_indent(4);
	mdb_printf("%p %8T cd %3-d %4T<%b> %x\n", addr, bh.bh_cd,
					bh.bh_flag, nsc_buf_bits, bh.bh_flag);

	/* check for verbose, avoid printing twice */
	if (!opt_v && opt_C) {
		mdb_printf("cc_chain: ");
		if (bh.bh_centry)
			mdb_call_dcmd("sdbc`sdbc_cchain",
			    (uintptr_t)bh.bh_centry, DCMD_ADDRSPEC, 0, NULL);
	}

	mdb_dec_indent(4);

	if (!opt_v)
		return (DCMD_OK);

	/* verbose */
	mdb_inc_indent(4);

	mdb_printf("callbacks: %-20a%-20a%-20a\n",
	    bh.bh_disconnect_cb, bh.bh_read_cb, bh.bh_write_cb);

	mdb_printf("centry %?p %8T next %?p\n",
				bh.bh_centry, bh.bh_next);
	mdb_printf("buffer:\n");

	mdb_inc_indent(4);
	mdb_printf("fd 0x%p pos %10d len %6d flag 0x%x\n",
		    bh.bh_buf.sb_fd, bh.bh_fba_pos, bh.bh_fba_len, bh.bh_flag);

	mdb_printf("alloc_thread %p busy_thread %p\n", bh.bh_alloc_thread,
			bh.bh_busy_thread);

	mdb_printf("err %4d %8T bh_vec 0x%p\n", bh.bh_error, bh.bh_vec);
	mdb_dec_indent(4);

	mdb_printf("bufvec (scatter gather list): %-?s %8T%-s\n",
						"ADDR", "LEN");
	{
		_sd_bufvec_t *bv, *endvec;


		/* todo check for (bh_vec != bh_bufvec) => readahead? */

		bv = bh.bh_bufvec;
		endvec = bv + _SD_MAX_BLKS;
		mdb_inc_indent(30);
		while (bv->bufaddr) {
			mdb_printf("%p    %8T%d\n", bv->bufaddr, bv->buflen);
			++bv;
			if (bv > endvec) {
				mdb_warn("END of bh_bufvec ARRAY");
				break;
			}
		}
		mdb_dec_indent(30);
	}

	if (opt_C) {
		mdb_printf("cc_chain: ");
		if (bh.bh_centry)
			mdb_call_dcmd("sdbc`sdbc_cchain",
			    (uintptr_t)bh.bh_centry, DCMD_ADDRSPEC, 0, NULL);
	}

	mdb_dec_indent(4);
	mdb_printf("\n");

	return (DCMD_OK);
}
/*
 * dcmd to display ss_centry_info_t structures and
 * do optional consistency check with the nvram copy
 * if configured for nvram safe storage.
 */

static int
sdbc_glcinfo(uintptr_t addr, uint_t flags, int argc,
					const mdb_arg_t *argv)
{
	ss_centry_info_t gl_centry_info;
	/* for doing consistency check */

	ss_centry_info_t *gl_centry_info_start;
	ss_centry_info_t *nv_gl_centry_info_start;
	uintptr_t nv_addr;
	ss_centry_info_t nv_gl_centry_info;

	/* options */
	uint_t opt_a = FALSE;
	uintptr_t opt_b = MDB_BLKNUM;	/* fba pos match */
	uintptr_t opt_c = MDB_CD;
	uintptr_t opt_C = FALSE; /* consistency check */
	uint_t opt_d = FALSE;



	if (mdb_getopts(argc, argv,
			'a', MDB_OPT_SETBITS, TRUE, &opt_a,
			'b', MDB_OPT_UINTPTR, &opt_b,
			'c', MDB_OPT_UINTPTR, &opt_c,
			'C', MDB_OPT_SETBITS, TRUE, &opt_C,
			'd', MDB_OPT_SETBITS, TRUE, &opt_d) != argc)
		return (DCMD_USAGE);


	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("sdbc`sdbc_glcinfo", "sdbc`sdbc_glcinfo",
					argc, argv) == -1) {
			mdb_warn("failed to walk global centry info array");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("global cache entry info:\n");
	}

	if (mdb_vread(&gl_centry_info, sizeof (ss_centry_info_t), addr) == -1) {
		mdb_warn("failed to read gl_centry_info at 0x%p", addr);
		return (DCMD_ERR);
	}


	/*
	 * default is to print entries initialized with a cd.  return if
	 * no options are selected and cd is invalid.
	 */
	if (!opt_a && (!OPT_B_SELECTED) && (!OPT_C_SELECTED) && !opt_d &&
		(gl_centry_info.sc_cd == -1))
		return (DCMD_OK);


	/*
	 * opt_c is exclusive filter. if opt_c is selected and there
	 * is no match on the cd then return
	 */
	if (!opt_a &&
		(OPT_C_SELECTED && (gl_centry_info.sc_cd != opt_c)))
		return (DCMD_OK);

	/*
	 * opt_d and opt_b are inclusive. print if either one is chosen
	 * and the selection condition is true.
	 */
	if (opt_a ||
	    (!opt_d && (!OPT_B_SELECTED)) || /* no options chosen */
	    (opt_d && gl_centry_info.sc_dirty) ||
	    (OPT_B_SELECTED && (gl_centry_info.sc_fpos == opt_b)))
		/*EMPTY*/;
	else
		return (DCMD_OK);

	mdb_inc_indent(4);
	mdb_printf("%?-p cd %3-d fpos %10-d dirty %04x flag <%b>\n",
		addr,
		gl_centry_info.sc_cd,
		gl_centry_info.sc_fpos,
		gl_centry_info.sc_dirty & 0xffff,
		gl_centry_info.sc_flag, cc_flag_bits);

	if (opt_C) {
		/* get start of the cache entry metadata */
		if (mdb_readvar(&gl_centry_info_start,
				"_sdbc_gl_centry_info") == -1) {
			mdb_warn("failed to read  _sdbc_gl_centry_info");
			/* not catastrophic */
			goto end;
		}

		/* get start of the nvram copy cache entry metadata */
		if (mdb_readvar(&nv_gl_centry_info_start,
				"_sdbc_gl_centry_info_nvmem") == -1) {
			mdb_warn("failed to read  _sdbc_gl_centry_info_nvmem");
			/* not catastrophic */
			goto end;
		}

		nv_addr = (addr - (uintptr_t)gl_centry_info_start) +
				(uintptr_t)nv_gl_centry_info_start;

		if (mdb_vread(&nv_gl_centry_info, sizeof (ss_centry_info_t),
						    nv_addr) == -1) {
			mdb_warn("failed to read at nvmem_gl_info 0x%p",
					nv_addr);
		    /* not catastophic, continue */
	    } else {

			/* consistency check */
			mdb_inc_indent(4);
			if (memcmp(&gl_centry_info, &nv_gl_centry_info,
					sizeof (ss_centry_info_t) != 0)) {
				mdb_warn(
				"nvram and host memory are NOT identical!");
				mdb_printf("nvmem_gl_centry_info: ");
				mdb_printf(
			    "%?-p cd %3-d fpos %10-d dirty %04x flag <%b>\n",
				nv_addr,
				nv_gl_centry_info.sc_cd,
				nv_gl_centry_info.sc_fpos,
				nv_gl_centry_info.sc_dirty & 0xffff,
				nv_gl_centry_info.sc_flag, cc_flag_bits);
				mdb_printf("\n");
		    } else
				mdb_printf("NVRAM ok\n");

		    mdb_dec_indent(4);

	    }
	}

	end:
	mdb_dec_indent(4);
	return (DCMD_OK);
}

/*
 * dcmd to display ss_voldata_t structures and
 * do optional consistency check with the nvram copy
 * if configured for nvram safe storage.
 */

static int
sdbc_glfinfo(uintptr_t addr, uint_t flags, int argc,
					const mdb_arg_t *argv)
{
	ss_voldata_t gl_file_info;
	/* for doing consistency check */

	ss_voldata_t *gl_file_info_start;
	ss_voldata_t *nv_gl_file_info_start;
	uintptr_t nv_addr;
	ss_voldata_t nv_gl_file_info;

	/* options  default: valid filename */
	uint_t opt_a = FALSE; /* all */
	uint_t opt_p = FALSE; /* PINNED */
	uint_t opt_t = FALSE; /* attached */
	uint_t opt_C = FALSE; /* consistency check */



	/*
	 * possible enhancement -- match on filename,
	 * or filename part (e.g. controller number)
	 */
	if (mdb_getopts(argc, argv,
			'a', MDB_OPT_SETBITS, TRUE, &opt_a,
			'C', MDB_OPT_SETBITS, TRUE, &opt_C,
			'p', MDB_OPT_SETBITS, TRUE, &opt_p,
			't', MDB_OPT_SETBITS, TRUE, &opt_t) != argc)
		return (DCMD_USAGE);


	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("sdbc`sdbc_glfinfo", "sdbc`sdbc_glfinfo",
					argc, argv) == -1) {
			mdb_warn("failed to walk global file info array");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("global file entry info:\n");
	}

	if (mdb_vread(&gl_file_info, sizeof (ss_voldata_t), addr) == -1) {
		mdb_warn("failed to read gl_file_info at 0x%p", addr);
		return (DCMD_ERR);
	}


	/*
	 * default is to print entries initialized with non-null filename.
	 * return if no options are selected and filename is invalid.
	 */
	if (!opt_a && !opt_p && !opt_t &&
		(strlen(gl_file_info.sv_volname) == 0))
		return (DCMD_OK);


	if (opt_a ||
		(!opt_p && !opt_t) || /* no options chosen */
		(opt_p && (gl_file_info.sv_pinned != _SD_NO_HOST)) ||
		(opt_t && (gl_file_info.sv_attached != _SD_NO_HOST)))
		/*EMPTY*/;
	else
		return (DCMD_OK);

	mdb_inc_indent(4);
	mdb_printf("%?-p %s\n", addr, gl_file_info.sv_volname);
	mdb_printf("pinned %2-d attached %2-d devidsz %3-d\n",
		gl_file_info.sv_pinned,
		gl_file_info.sv_attached,
		gl_file_info.sv_devidsz);
	mdb_printf("devid %s\n", gl_file_info.sv_devid);

	if (opt_C) {
		/* get start of the cache entry metadata */
		if (mdb_readvar(&gl_file_info_start,
				"_sdbc_gl_file_info") == -1) {
			mdb_warn("failed to read  _sdbc_gl_file_info");
			/* not catastrophic */
			goto end;
		}

		/* get start of the nvram copy cache entry metadata */
		if (mdb_readvar(&nv_gl_file_info_start,
				"_sdbc_gl_file_info_nvmem") == -1) {
			mdb_warn("failed to read  _sdbc_gl_file_info_nvmem");
			/* not catastrophic */
			goto end;
		}

		nv_addr = (addr - (uintptr_t)gl_file_info_start) +
				(uintptr_t)nv_gl_file_info_start;

		if (mdb_vread(&nv_gl_file_info, sizeof (ss_voldata_t),
						    nv_addr) == -1) {
			mdb_warn("failed to read nvmem_gl_info at 0x%p",
					nv_addr);
		    /* not catastophic, continue */
	    } else {

		    /* consistency check */
		    mdb_inc_indent(4);
		    if (memcmp(&gl_file_info, &nv_gl_file_info,
				sizeof (ss_centry_info_t) != 0)) {
			mdb_warn("nvram and host memory are NOT identical!");
			mdb_printf("nvmem_gl_file_info: ");
			mdb_printf("%?-p %s\n", nv_addr,
					nv_gl_file_info.sv_volname);
			mdb_printf("pinned %2-d attached %2-d devidsz %3-d\n",
				nv_gl_file_info.sv_pinned,
				nv_gl_file_info.sv_attached,
				nv_gl_file_info.sv_devidsz);
			mdb_printf("devid %s\n", nv_gl_file_info.sv_devid);
		    } else
			mdb_printf("NVRAM ok\n");

		    mdb_dec_indent(4);

	    }
	}

	end:
	mdb_dec_indent(4);
	mdb_printf("\n");
	return (DCMD_OK);
}


/*
 * MDB module linkage information:
 *
 * We declare a list of structures describing our dcmds, and a function
 * named _mdb_init to return a pointer to our module information.
 */

static const mdb_dcmd_t dcmds[] = {
	/* general dcmds */
	{ "sdbc_config", NULL,
		"display sdbc configuration information",
		sdbc_config },
	{ "sdbc_stats", NULL,
		"display sdbc stats information",
		sdbc_stats },
	{ "sdbc_vars", NULL,
		"display some sdbc variables, counters and addresses",
		sdbc_vars },

	/* cctl dcmds */
	{"sdbc_cctl", "?[-vdhioV][-c cd][-b blknum]",
		"display sdbc cache ctl structures",
		sdbc_cctl, cctl_help },
	{"sdbc_cchain", ":[-vdhioV][-c cd][-b blknum]",
		"display cache ctl structure cc_chain",
		sdbc_cchain, cchain_help },
	{"sdbc_dchain", ":[-vdhioV][-c cd][-b blknum]",
		"display cache ctl structure dirty chain",
		sdbc_dchain, dchain_help },
	{"sdbc_dmchain", ":[-vdhioV][-c cd][-b blknum]",
		"display dynamic memory cache ctl chain",
		sdbc_dmchain, dmchain_help },
	{"sdbc_hashchain", ":[-vdhioV][-c cd][-b blknum]",
		"display a hash chain", sdbc_hashchain, hashchain_help },
	{"sdbc_hashtable", "?[-vdhioV][-c cd][-b blknum]",
		"display hash table", sdbc_hashtable, hashtable_help },
	{"sdbc_lru", "?[-vdhioV][-c cd][-b blknum]",
		"display the cache lru queue",
		sdbc_lru, lru_help },
#ifdef SAFESTORE
	/* wctl dcmds */
	{"sdbc_wctl", "?[-vd][-c cd]",
		"display the write control structures",
		sdbc_wctl, wctl_help },
	{"sdbc_wrq", "?[-vd][-c cd]",
		"display the write control queue",
		sdbc_wrq, wrq_help },
#endif /* SAFESTORE */

	/* others */
	{"sdbc_cdinfo", "?[-av][-c cd]",
		"display cache descriptor information",
		sdbc_cdinfo, cdinfo_help },
#ifdef SAFESTORE
	{"sdbc_ftctl", "?[-vd][-c cd]",
		"display the fault tolerant control structures",
		sdbc_ftctl, ftctl_help },
#endif /* SAFESTORE */
	{"sdbc_handles", "?[-avC][-c cd]",
		"display sdbc buffer handle information",
		sdbc_handles, handle_help },

	{ "sdbc_dmqueues", NULL,
		"display sdbc dynamic memory buffer queues information",
		sdbc_dmqueues },

	/* "global" metadata dcmds */
	{"sdbc_glcinfo", "?[-adC][-c cd][-b fbapos]",
		"display the global cache entry info structures",
		sdbc_glcinfo, glcinfo_help },
	{"sdbc_glfinfo", "?[-aptC]",
		"display the global file info structures",
		sdbc_glfinfo, glfinfo_help },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	/* walkers of cctl list and arrays */
	{ "sdbc_cchain", "walk the cc_chain (alloc chain) of a cache ctl",
		sdbc_cchain_winit, sdbc_cchain_wstep, sdbc_cchain_wfini },
	{ "sdbc_cctl", "walk the cache ctl structure list",
		sdbc_cctl_winit, sdbc_cctl_wstep, sdbc_cctl_wfini },
	{ "sdbc_dchain", "walk the dirty chain of a cache ctl",
		sdbc_dchain_winit, sdbc_dchain_wstep, sdbc_dchain_wfini },
	{ "sdbc_dmchain", "walk the dynamic memory chain of a cache cctl",
		sdbc_dmchain_winit, sdbc_dmchain_wstep, sdbc_dmchain_wfini },
	{ "sdbc_hashchain", "walk a hash chain",
		sdbc_hashchain_winit, sdbc_hashchain_wstep,
					sdbc_hashchain_wfini },
	{ "sdbc_lru", "walk the cache lru queue",
		sdbc_lru_winit, sdbc_lru_wstep, sdbc_lru_wfini },

#ifdef SAFESTORE
	/* walkers of wctl lists and arrays */
	{ "sdbc_wctl", "walk the allocated write ctl array",
		sdbc_wctl_winit, sdbc_wctl_wstep, sdbc_wctl_wfini },
	{ "sdbc_wrq", "walk the write ctl queue (free list)",
		sdbc_wrq_winit, sdbc_wrq_wstep, sdbc_wrq_wfini },
#endif /* SAFESTORE */
	/* others */
	{ "sdbc_cdinfo",
	    "walk the _sd_cache_files array of cache descriptor information",
		sdbc_cdinfo_winit, sdbc_cdinfo_wstep, sdbc_cdinfo_wfini },
#ifdef SAFESTORE
	{ "sdbc_ftctl",
	    "walk the allocated array of fault tolerant structures",
		sdbc_ftctl_winit, sdbc_ftctl_wstep, sdbc_ftctl_wfini },
#endif /* SAFESTORE */
	{ "sdbc_handles", "walk array of _sd_buf_handle_t structures",
		sdbc_handle_winit, sdbc_handle_wstep, sdbc_handle_wfini },

	/* walkers for metadata arrays */
	{ "sdbc_glcinfo", "walk the allocated global cache entry info array",
		sdbc_glcinfo_winit, sdbc_glcinfo_wstep, sdbc_glcinfo_wfini },
	{ "sdbc_glfinfo", "walk the allocated global file info array",
		sdbc_glfinfo_winit, sdbc_glfinfo_wstep, sdbc_glfinfo_wfini },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}

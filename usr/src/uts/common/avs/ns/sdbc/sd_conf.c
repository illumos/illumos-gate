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

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/ddi.h>

#include <sys/nsc_thread.h>
#include "sd_bcache.h"
#include "sd_ft.h"
#include "sd_misc.h"
#include "sd_pcu.h"
#include "sd_io.h"
#include "sd_bio.h"
#include "sd_trace.h"
#include "sd_tdaemon.h"
#include <sys/nsctl/nsctl.h>

#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_k.h>
#include <sys/unistat/spcs_errors.h>
#include <sys/nsctl/safestore.h>

extern int sdbc_use_dmchain;

int _sd_cblock_shift = 0;

int _SD_SELF_HOST = _SD_NO_HOST;
int _SD_MIRROR_HOST = _SD_NO_HOST;
int _SD_NUM_REM;
int _sd_nodes_configured;
int _sdbc_gateway_wblocks;

int _SD_NETS = 0;

/*
 * Normally we unregister memory at deconfig time. By setting this non-zero
 * it will be delayed until unload time.
 */
int _sdbc_memtype_deconfigure_delayed = 0;

nsc_mem_t *sdbc_iobuf_mem, *sdbc_hash_mem;
nsc_mem_t *sdbc_local_mem, *sdbc_stats_mem, *sdbc_cache_mem;
nsc_mem_t *sdbc_info_mem;

_sd_cache_param_t _sd_cache_config;

kmutex_t _sdbc_config_lock;
volatile int _sd_cache_dem_cnt;

#if !defined(m88k) || defined(lint)
volatile int _sd_cache_initialized;
#endif

static blind_t sdbc_power;

static
nsc_def_t _sdbc_power_def[] = {
	"Power_Lost",	(uintptr_t)_sdbc_power_lost,	0,
	"Power_OK",	(uintptr_t)_sdbc_power_ok,	0,
	"Power_Down",	(uintptr_t)_sdbc_power_down,	0,
	0,		0,		0
};

/*
 * Forward declare all statics that are used before defined to enforce
 * parameter checking
 * Some (if not all) of these could be removed if the code were reordered
 */

int _sd_fill_pattern(caddr_t addr, uint_t pat, uint_t size);
static void _sdbc_nodeid_deconfigure(void);
static void _sdbc_nodeid_configure(void);
static void _sdbc_thread_deconfigure(void);
static int _sdbc_thread_configure(void);
void sst_deinit();

ss_common_config_t safestore_config;
safestore_ops_t *sdbc_safestore;

/*
 * _sdbc_memtype_configure - register with the sd layer the types of memory
 * we want to use. If any of the critical memory types can't be registered
 * we return non-zero otherwise 0.
 */
static int
_sdbc_memtype_configure(void)
{

	if ((sdbc_info_mem = nsc_register_mem("sdbc:info",
	    NSC_MEM_GLOBAL, KM_NOSLEEP)) == NULL) {
		return (EINVAL);
	}

	sdbc_local_mem = nsc_register_mem("sdbc:local", NSC_MEM_LOCAL, 0);
	sdbc_stats_mem = nsc_register_mem("sdbc:stats", NSC_MEM_LOCAL, 0);
	sdbc_iobuf_mem = nsc_register_mem("sdbc:iobuf", NSC_MEM_LOCAL, 0);

	sdbc_cache_mem = nsc_register_mem("sdbc:cache", NSC_MEM_LOCAL, 0);

	sdbc_hash_mem = nsc_register_mem("sdbc:hash", NSC_MEM_LOCAL, 0);

	return (0);
}

/*
 * _sdbc_memtype_deconfigure - undo the effects of _sdbc_memtype_configure.
 */
void
_sdbc_memtype_deconfigure(void)
{

	if (sdbc_hash_mem)
		nsc_unregister_mem(sdbc_hash_mem);
	if (sdbc_iobuf_mem)
		nsc_unregister_mem(sdbc_iobuf_mem);
	if (sdbc_cache_mem)
		nsc_unregister_mem(sdbc_cache_mem);
	if (sdbc_stats_mem)
		nsc_unregister_mem(sdbc_stats_mem);
	if (sdbc_local_mem)
		nsc_unregister_mem(sdbc_local_mem);
	if (sdbc_info_mem)
		nsc_unregister_mem(sdbc_info_mem);

	sdbc_info_mem = NULL;
	sdbc_local_mem = sdbc_stats_mem = sdbc_cache_mem = NULL;
	sdbc_iobuf_mem = sdbc_hash_mem = NULL;

}


/*
 * figure out what kind of safe storage we need
 */
uint_t
sdbc_determine_safestore()
{
	return (SS_M_RAM | SS_T_NONE);
}

static void
sd_setup_ssconfig()
{
	safestore_config.ssc_client_psize = BLK_SIZE(1);

	if (_sd_cache_config.write_cache)
		safestore_config.ssc_wsize =
			_sd_cache_config.write_cache * MEGABYTE;
	else
		safestore_config.ssc_wsize =
			(_sd_cache_config.cache_mem[_SD_NO_NET] * MEGABYTE)/2;
	safestore_config.ssc_maxfiles = sdbc_max_devs;
	safestore_config.ssc_pattern = _sd_cache_config.fill_pattern;
	safestore_config.ssc_flag = _sd_cache_config.gen_pattern ?
	    SS_GENPATTERN : 0;
}

/*
 * _sdbc_configure - process the ioctl that describes the configuration
 * for the cache. This is the main driver routine for cache configuration
 * Return 0 on success, otherwise nonzero.
 *
 */
int
_sdbc_configure(_sd_cache_param_t *uptr,
	_sdbc_config_t *mgmt, spcs_s_info_t spcs_kstatus)
{
	int cache_bytes;
	nsc_io_t *io;
	char itmp[16];
	char itmp2[16];
	int i;
	uint_t ss_type;
	int rc;

	ASSERT(MUTEX_HELD(&_sdbc_config_lock));

	_sd_print(1, "sdbc(_sdbc_configure) _SD_MAGIC 0x%x\n", _SD_MAGIC);

	_sd_ioset = 0;
	if (_sd_cache_initialized) {
		spcs_s_add(spcs_kstatus, SDBC_EALREADY);
		rc = EALREADY;
		goto out;
	}

	ASSERT((uptr != NULL) || (mgmt != NULL));

	if (uptr) {
		if (copyin(uptr, &_sd_cache_config,
		    sizeof (_sd_cache_param_t))) {
			rc = EFAULT;
			goto out;
		}
	} else {
		bzero(&_sd_cache_config, sizeof (_sd_cache_config));

		/* copy in mgmt config info */

		_sd_cache_config.magic = mgmt->magic;
		_sd_cache_config.threads = mgmt->threads;

		for (i = 0; i < CACHE_MEM_PAD; i++) {
			_sd_cache_config.cache_mem[i] = mgmt->cache_mem[i];
		}

		/* fake the rest as a single node config */

		_sd_cache_config.nodes_conf[0] = nsc_node_id();
		_sd_cache_config.num_nodes = 1;
	}

	/*
	 * Check that the requested cache size doesn't break the code.
	 * This test can be refined once the cache size is stored in variables
	 * larger than an int.
	 */
	for (i = 0; i < MAX_CACHE_NET; i++) {
		if (_sd_cache_config.cache_mem[i] < 0) {
			cmn_err(CE_WARN, "_sdbc_configure: "
			    "negative cache size (%d) for net %d",
			    _sd_cache_config.cache_mem[i], i);
			spcs_s_add(spcs_kstatus, SDBC_ENONETMEM);
			rc = SDBC_ENONETMEM;
			goto out;
		}
		if (_sd_cache_config.cache_mem[i] > MAX_CACHE_SIZE) {
			_sd_cache_config.cache_mem[i] = MAX_CACHE_SIZE;
			cmn_err(CE_WARN, "_sdbc_configure: "
			    "cache size limited to %d megabytes for net %d",
			    MAX_CACHE_SIZE, i);
		}
	}

	if (_sd_cache_config.blk_size == 0)
		_sd_cache_config.blk_size = 8192;

	if (_sd_cache_config.procs == 0)
		_sd_cache_config.procs = 16;

#if !defined(_SD_8K_BLKSIZE)
	if (_sd_cache_config.blk_size != 4096) {
#else
	if (_sd_cache_config.blk_size != 8192) {
#endif
		(void) spcs_s_inttostring(_sd_cache_config.blk_size, itmp,
		    sizeof (itmp), 0);
		spcs_s_add(spcs_kstatus, SDBC_ESIZE, itmp);
		rc = SDBC_EENABLEFAIL;
		goto out;
	}
	if (((_sd_cblock_shift =
	    get_high_bit(_sd_cache_config.blk_size)) == -1) ||
	    (_sd_cache_config.blk_size != (1 << _sd_cblock_shift))) {
		(void) spcs_s_inttostring(_sd_cache_config.blk_size, itmp,
		    sizeof (itmp), 0);
		spcs_s_add(spcs_kstatus, SDBC_ESIZE, itmp);
		rc = SDBC_EENABLEFAIL;
		goto out;
	}

	if (_sd_cache_config.magic != _SD_MAGIC) {
		rc = SDBC_EMAGIC;
		goto out;
	}

	sdbc_use_dmchain = (_sd_cache_config.reserved1 & CFG_USE_DMCHAIN);
	sdbc_static_cache =  (_sd_cache_config.reserved1 & CFG_STATIC_CACHE);

	_sdbc_nodeid_configure();

	if (_SD_SELF_HOST > nsc_max_nodeid ||
	    _SD_MIRROR_HOST > nsc_max_nodeid) {
		(void) spcs_s_inttostring((_SD_SELF_HOST > nsc_max_nodeid ?
		    _SD_SELF_HOST : _SD_MIRROR_HOST), itmp, sizeof (itmp), 0);
		(void) spcs_s_inttostring(
		    nsc_max_nodeid, itmp2, sizeof (itmp2), 0);
		spcs_s_add(spcs_kstatus, SDBC_EINVHOSTID, itmp, itmp2);
		rc = SDBC_EENABLEFAIL;
		goto out;
	}


	if (_SD_SELF_HOST == _SD_MIRROR_HOST) {
		(void) spcs_s_inttostring(
		    _SD_SELF_HOST, itmp, sizeof (itmp), 0);
		(void) spcs_s_inttostring(
		    _SD_MIRROR_HOST, itmp2, sizeof (itmp2), 0);
		spcs_s_add(spcs_kstatus, SDBC_ENOTSAME, itmp, itmp2);
		rc = SDBC_EENABLEFAIL;
		goto out;
	}

	/* initialize the safestore modules */
	sst_init();

	/* figure out which kind of safestore we need to use */
	ss_type = sdbc_determine_safestore();

tryss:
	/* open and configure the safestore module */
	if ((sdbc_safestore = sst_open(ss_type, 0)) == NULL) {
		cmn_err(CE_WARN, "cannot open safestore module for type %x",
		    ss_type);
		rc = SDBC_EENABLEFAIL;
		goto out;
	} else {
		sd_setup_ssconfig();
		if (SSOP_CONFIGURE(sdbc_safestore, &safestore_config,
		    spcs_kstatus)) {
			cmn_err(CE_WARN,
			    "cannot configure safestore module for type %x",
			    ss_type);
			(void) sst_close(sdbc_safestore);

			/* try ram if possible, otherwise return */
			if ((ss_type & (SS_M_RAM | SS_T_NONE)) ==
			    (SS_M_RAM | SS_T_NONE)) {
				rc = SDBC_EENABLEFAIL;
				goto out;
			}

			ss_type = (SS_M_RAM | SS_T_NONE);
			goto tryss;
		}
	}

	if (SAFESTORE_LOCAL(sdbc_safestore))
		_SD_MIRROR_HOST = _SD_NO_HOST;

	ASSERT(safestore_config.ssc_ss_psize <= UINT16_MAX);	/* LINTED */
	_sd_net_config.sn_psize = safestore_config.ssc_ss_psize;


	_sd_net_config.sn_csize =
		_sd_cache_config.cache_mem[_SD_NO_NET] * MEGABYTE;
	_sd_net_config.sn_cpages =
		_sd_net_config.sn_csize / BLK_SIZE(1);

	_sd_net_config.sn_configured = 1;
	cache_bytes = _sd_net_config.sn_cpages * BLK_SIZE(1);

	if (_sdbc_memtype_configure()) {
		rc = EINVAL;
		goto out;
	}

	if ((rc = _sdbc_iobuf_configure(_sd_cache_config.iobuf))) {
		if (rc == -1) {
			rc = SDBC_ENOIOBMEM;
			goto out;
		}
		if (rc == -2) {
			rc = SDBC_ENOIOBCB;
			goto out;
		}

	}

	if (_sdbc_handles_configure()) {
		rc = SDBC_ENOHANDLEMEM;
		goto out;
	}

	_sd_cache_dem_cnt = 0;


	/*
	 * nvmem support:
	 * if the cache did not shutdown properly we mark it as dirty.
	 * this must be done before _sdbc_cache_configure() so it can
	 * refresh sd_info_mem and sd_file_mem from nvmem if necsssary,
	 * and before _sdbc_ft_configure() so the ft thread will do a recovery.
	 *
	 */
	if (SAFESTORE_RECOVERY(sdbc_safestore)) {
		_sdbc_set_warm_start();
		_sdbc_ft_hold_io = 1;
		cmn_err(CE_WARN,
		    "sdbc(_sdbc_configure) cache marked dirty after"
		    " incomplete shutdown");
	}

	if ((rc = _sdbc_cache_configure(cache_bytes / BLK_SIZE(1),
	    spcs_kstatus))) {
		goto out;
	}


	/* ST_ALERT trace buffer */
	if (_sdbc_tr_configure(-1 /* SDT_INV_CD */) != 0) {
		rc = EINVAL;
		goto out;
	}

	if (_sdbc_thread_configure()) {
		rc = SDBC_EFLUSHTHRD;
		goto out;
	}

	if (_sdbc_flush_configure()) {
		rc = EINVAL;
		goto out;
	}

	if (rc = _sdbc_dealloc_configure_dm()) {
		goto out;
	}

	if (_sd_cache_config.test_demons)
		if (_sdbc_tdaemon_configure(_sd_cache_config.test_demons)) {
			rc = EINVAL;
			goto out;
		}


	_sd_cache_initialized = 1;

	sdbc_power = nsc_register_power("sdbc", _sdbc_power_def);

	if (_sdbc_ft_configure() != 0) {
		rc = EINVAL;
		goto out;
	}

	/*
	 * try to control the race between the ft thread
	 * and threads that will open the devices that the ft thread
	 * may be recovering.  this synchronizing with the ft thread
	 * prevents sd_cadmin from returning until ft has opened
	 * the recovery devices, so if other apps wait for sd_cadmin
	 * to complete the race is prevented.
	 */
	mutex_enter(&_sdbc_ft_hold_io_lk);
	while (_sdbc_ft_hold_io) {
		cv_wait(&_sdbc_ft_hold_io_cv, &_sdbc_ft_hold_io_lk);
	}

	io = nsc_register_io("sdbc", NSC_SDBC_ID|NSC_FILTER,
	    _sd_sdbc_def);

	if (io) sdbc_io = io;

	mutex_exit(&_sdbc_ft_hold_io_lk);

#ifdef DEBUG
	cmn_err(CE_NOTE, "sd_config: Cache has been configured");
#endif

	rc = 0;

out:
	return (rc);
}

/*
 * _sdbc_deconfigure - Put the cache back to the unconfigured state. Release
 * any memory we allocated as part of the configuration process (but not the
 * load/init process).  Put globals back to unconfigured state and shut down
 * any processes/threads we have running.
 *
 * Since the cache has loaded we know that global lock/sv's are present and
 * we can use them to produce an orderly deconfiguration.
 *
 * NOTE: this routine and its callee should always be capable of reversing
 * the effects of _sdbc_configure no matter what partially configured
 * state might be present.
 *
 */
int
_sdbc_deconfigure(spcs_s_info_t spcs_kstatus)
{
	int i;
	_sd_cd_info_t *cdi;
	int rc;
	int pinneddata = 0;
	uint_t saved_hint;

	ASSERT(MUTEX_HELD(&_sdbc_config_lock));

#ifdef DEBUG
	cmn_err(CE_NOTE, "SD cache being deconfigured.");
#endif

	/* check if there is pinned data and our mirror is down */
	if (_sd_cache_files && _sd_is_mirror_down()) {
		for (i = 0; i < sdbc_max_devs; i++) {
			cdi = &(_sd_cache_files[i]);
			if (cdi->cd_info == NULL)
				continue;
			/*
			 * if (!(cdi->cd_info->sh_failed))
			 *	continue;
			 */
			if (!(_SD_CD_ALL_WRITES(i)))
				continue;
			spcs_s_add(spcs_kstatus, SDBC_EPINNED,
				cdi->cd_info->sh_filename);
			rc = SDBC_EDISABLEFAIL;
			goto out;
		}
	}

	/* remember hint setting for restoration in case shutdown fails */
	(void) _sd_get_node_hint(&saved_hint);

	(void) _sd_set_node_hint(NSC_FORCED_WRTHRU);


	/* TODO - there is a possible race between deconfig and power hits... */

	if (sdbc_power)
		(void) nsc_unregister_power(sdbc_power);


	if (sdbc_io) {
		rc = nsc_unregister_io(sdbc_io, NSC_PCATCH);
		if (rc == 0)
			sdbc_io = NULL;
		else {
			if (rc == EUSERS)
				spcs_s_add(spcs_kstatus, SDBC_EABUFS);

			spcs_s_add(spcs_kstatus, SDBC_EUNREG);

			/* Re-register-power if it was register before. */
			if (sdbc_power) {
				sdbc_power = nsc_register_power("sdbc",
					_sdbc_power_def);
			}

			/* Remove NSC_FORCED_WRTHRU if we set it */
			(void) _sd_clear_node_hint(
				(~saved_hint) & _SD_HINT_MASK);

			rc = SDBC_EDISABLEFAIL;
			goto out;
		}
	}

	sdbc_power = NULL;

#if defined(_SD_FAULT_RES)
	_sd_remote_disable(0);	/* notify mirror to forced_wrthru */
#endif
	/*
	 * close devices, deconfigure processes, wait for exits
	 */
	_sdbc_tdaemon_deconfigure();

	if (_sd_cache_files) {
		for (i = 0; i < sdbc_max_devs; i++) {
			if (FILE_OPENED(i) && ((rc = _sd_close(i)) > 0)) {
				cmn_err(CE_WARN, "sdbc(_sd_deconfigure)"
				    " %d not closed (%d)\n", i, rc);
			}
		}
	}

	/*
	 * look for pinned data
	 * TODO sort this out for multinode systems.
	 * cannot shutdown with pinned data on multinode.
	 * the state of pinned data should be determined in
	 * the close operation.
	 */
	if (_sd_cache_files) {
		for (i = 0; i < sdbc_max_devs; i++) {
			cdi = &(_sd_cache_files[i]);
			if (cdi->cd_info == NULL)
				continue;
			/*
			 * if (!(cdi->cd_info->sh_failed))
			 *	continue;
			 */
			if (!(_SD_CD_ALL_WRITES(i)))
				continue;
			cmn_err(CE_WARN,
			    "sdbc(_sd_deconfigure) Pinned Data on cd %d(%s)",
			    i, cdi->cd_info->sh_filename);
			pinneddata++;
		}
	}

	_sd_cache_initialized = 0;

	_sdbc_ft_deconfigure();

	_sdbc_flush_deconfigure();
	_sdbc_thread_deconfigure();

	mutex_enter(&_sd_cache_lock);

	while (_sd_cache_dem_cnt > 0) {
		mutex_exit(&_sd_cache_lock);
		(void) nsc_delay_sig(HZ/2);
		mutex_enter(&_sd_cache_lock);
	}
	mutex_exit(&_sd_cache_lock);

	/*
	 * remove all dynamically allocated cache data memory
	 * there should be no i/o at this point
	 */
	_sdbc_dealloc_deconfigure_dm();
	/*
	 * At this point no thread of control should be active in the cache
	 * but us (unless they are blocked on the config lock).
	 */


#if defined(_SD_FAULT_RES)
	_sd_remote_disable(1);	/* notify mirror I/O shutdown complete */
#endif

#define	KEEP_TRACES	0	/* set to 1 keep traces after deconfig */
#if !KEEP_TRACES
	/*
	 * This needs to happen before we unregister the memory.
	 */
	_sdbc_tr_deconfigure();
#endif


	/* delete/free hash table, cache blocks, etc */
	_sdbc_cache_deconfigure();

	_sdbc_handles_deconfigure();

	_sdbc_iobuf_deconfigure();

#if !KEEP_TRACES
	if (!_sdbc_memtype_deconfigure_delayed)
		_sdbc_memtype_deconfigure();
#else
	_sdbc_memtype_deconfigure_delayed = 1;
#endif

	/*
	 * Call ss deconfig(),
	 * check for valid pointer in case _sdbc_configure()
	 * failed before safestrore system was initialized.
	 */
	if (sdbc_safestore)
		SSOP_DECONFIGURE(sdbc_safestore, pinneddata);

	/* tear down safestore system */
	sst_deinit();

	_sdbc_nodeid_deconfigure();

	bzero(&_sd_cache_config, sizeof (_sd_cache_param_t));

	_SD_SELF_HOST = _SD_MIRROR_HOST = _SD_NO_HOST;
	_SD_NETS = 0;
	_sd_cblock_shift = 0;
	_sd_node_hint = 0;

#ifdef DEBUG
	cmn_err(CE_NOTE, "SD cache deconfigured.");
#endif

	rc = 0;

out:
	return (rc);
}



static int
find_low_bit(int mask, int start)
{
	for (; start < 32; start++)
		if ((mask & (1 << start)))
			break;

	return (start);
}

int
get_high_bit(int size)
{
	int lowbit;
	int newblk = size;
	int highbit = -1;
	int next_high = 0;

	while ((lowbit = find_low_bit(newblk, 0)) != 32) {
		if (highbit >= 0) next_high = 1;
		highbit = lowbit;
		newblk &= ~(1 << highbit);
	}

	if (highbit <= 0) {
		cmn_err(CE_WARN,
		    "sdbc(get_high_bit) invalid block size %x\n", size);
		return (-1);
	}

	if (next_high) highbit++;

	return (highbit);
}


int
_sd_fill_pattern(caddr_t addr, uint_t pat, uint_t size)
{
	caddr_t fmt_page;
	int i, page_size;

	page_size = (int)ptob(1);

	if ((fmt_page = (caddr_t)nsc_kmem_alloc(ptob(1),
	    KM_SLEEP, sdbc_local_mem)) == NULL) {
		cmn_err(CE_WARN, "sdbc(_sd_fill pattern) no more memory");
		return (-1);
	}
	for (i = 0; i < page_size; i += 4)
		*(int *)(void *)(fmt_page + i) = pat;

	while (size >= page_size) {
		bcopy(fmt_page, addr, ptob(1));
		addr += page_size;
		size -= page_size;
	}
	nsc_kmem_free(fmt_page, page_size);
	return (0);
}


/*
 * _sdbc_nodeid_deconfigure - merely a place holder until
 * such time as there is something to be undone w.r.t.
 * _sdbc_nodeid_configure.
 *
 */
static void
_sdbc_nodeid_deconfigure(void)
{
	/* My but we're quick */
}

/*
 * _sdbc_nodeid_configure - configure the nodeid's we need to connect
 * to any other nodes in the network.
 *
 */
void
_sdbc_nodeid_configure(void)
{

	if (_sd_cache_config.num_nodes == 0) {
		_sd_nodes_configured = 1;
	} else {
		_sd_nodes_configured = _sd_cache_config.num_nodes;
	}

	_SD_SELF_HOST   = nsc_node_id();
	_SD_MIRROR_HOST = _sd_cache_config.mirror_host;
}

#define	STACK_SIZE	(32*1024)
#define	num_spin 0
nstset_t *_sd_ioset;

/*
 * _sdbc_thread_deconfigure - cache is being deconfigure, stop any
 * thread activity.
 *
 */
static void
_sdbc_thread_deconfigure(void)
{
	ASSERT(MUTEX_HELD(&_sdbc_config_lock));
	nst_destroy(_sd_ioset);
	_sd_ioset = NULL;
}

/*
 * _sdbc_thread_configure - cache is being configured, initialize the
 * threads we need for flushing dirty cds.
 *
 */
static int
_sdbc_thread_configure(void)
{
	ASSERT(MUTEX_HELD(&_sdbc_config_lock));

	if (!_sd_ioset)
		_sd_ioset = nst_init("sd_thr", _sd_cache_config.threads);

	if (!_sd_ioset)
		return (EINVAL);

	return (0);
}

int
_sdbc_get_config(_sdbc_config_t *config_info)
{
	int i;

	config_info->enabled = _sd_cache_initialized;
	config_info->magic = _SD_MAGIC;
	for (i = 0; i < CACHE_MEM_PAD; i++) {
		config_info->cache_mem[i] = _sd_cache_config.cache_mem[i];
	}
	config_info->threads = _sd_cache_config.threads;

	return (0);
}

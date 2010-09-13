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

#ifndef _SD_CONF_H
#define	_SD_CONF_H

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_RCSID)
static char *rcs_sd_conf_h = "@(#)(SMI) sd_conf.h 1.1 07/06/21 16:17:54";
#endif

#define	MEGABYTE	(1024*1024)

#define	DEFAULT_HANDLES 1000
#define	MAX_SD_NODES    256   /* max configured nodes */
#define	SD_MCIII 0
#define	SD_MCIV  1

/* for initializing fields to an invalid host id */
#define	_SD_NO_HOST -1

/* netaddr filler for mc_*() compatibility */
#define	_SD_NO_NETADDR 0
/* dummy net for mc_*() compatibility */
#define	_SD_NO_NET 0

#define	_SD_VME_DEFAULT (1024*1024)	/* default 1mb contiguous memory */

#ifdef _KERNEL

extern _sd_cache_param_t _sd_cache_config;
extern int _SD_SELF_DSP, _SD_REM_DSP[], _SD_NUM_REM;
extern int _SD_SELF_HOST, _SD_MIRROR_HOST;
extern int _sd_nodes_configured, _SD_HOST_CONF[];
extern int _sd_parallel_resync_cnt;
extern int _sdbc_gateway_wblocks;
extern int _sdbc_memtype_deconfigure_delayed;
extern kmutex_t _sdbc_config_lock;
extern nsc_mem_t *sdbc_info_mem;
extern nsc_mem_t *sdbc_iobuf_mem, *sdbc_hash_mem;
extern nsc_mem_t *sdbc_local_mem, *sdbc_stats_mem, *sdbc_cache_mem;
#if defined(_SD_USE_THREADS)
extern nstset_t *_sd_ioset;
#endif  /* _SD_USE_THREADS */
extern ushort_t SD_AUTO_RESYNC;
extern volatile int _sd_cache_dem_cnt;
extern volatile int _sd_cache_initialized;

extern void _sdbc_memtype_deconfigure(void);
extern int _sdbc_configure(_sd_cache_param_t *,
	_sdbc_config_t *, spcs_s_info_t);
extern int _sdbc_deconfigure(spcs_s_info_t);
extern int _sdbc_get_config(_sdbc_config_t *);
extern int get_high_bit(int size);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SD_CONF_H */

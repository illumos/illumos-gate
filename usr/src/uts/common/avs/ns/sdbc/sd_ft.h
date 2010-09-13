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

#ifndef _SD_FT_H
#define	_SD_FT_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/ncall/ncall.h>

typedef struct _sd_ft_info {
	char 	fi_crashed;		/* mirror cache state */
	char 	fi_host_state;		/* mirror node state */
	kmutex_t	fi_lock;
	kcondvar_t	fi_rem_sv;
	volatile int 	fi_numio;
	kmutex_t fi_sleep;

} _sd_ft_info_t;


#define	_SD_MIRROR_CONFIGD	(_sd_ft_data.fi_host_state ==\
				_SD_HOST_CONFIGURED)
#define	_SD_MIRROR_DECONFIGD	(_sd_ft_data.fi_host_state == \
				_SD_HOST_DECONFIGURED)
#define	_SD_MIRROR_NOCACHE	(_sd_ft_data.fi_host_state == \
				_SD_HOST_NOCACHE)

#define	_SD_HOST_NONE		0x00	/* mirror node dead or state unknown */
#define	_SD_HOST_CONFIGURED	0x01	/* mirror cache configured */
#define	_SD_HOST_DECONFIGURED	0x02	/* mirror cache deconfigured */
#define	_SD_HOST_NOCACHE	0x03	/* mirror cache deconfigured and */
					/* waiting for node down or re-enable */

/*
 * mirror node has paniced with cache enabled,
 * or mirror cache has been deconfigured.
 */
#define	_sd_is_mirror_crashed()	((!_INFSD_NODE_UP(_SD_MIRROR_HOST) &&\
				_SD_MIRROR_CONFIGD) || _SD_MIRROR_DECONFIGD)

/*
 * mirror node has shutdown having previously
 * deconfigured its cache.
 */
#define	_sd_is_mirror_node_down()	\
				(!_INFSD_NODE_UP(_SD_MIRROR_HOST) &&\
				_SD_MIRROR_NOCACHE)

#define	_sd_is_mirror_down()	(_sd_ft_data.fi_crashed)
#define	_sd_mirror_cache_down()	(_sd_ft_data.fi_crashed = 1,\
				_sd_ft_data.fi_host_state = _SD_HOST_NOCACHE)
#define	_sd_mirror_down()	(_sd_ft_data.fi_crashed = 1,\
				_sd_ft_data.fi_host_state = _SD_HOST_NONE)
#define	_sd_mirror_up()		(_sd_ft_data.fi_crashed = 0)
#ifdef _KERNEL

extern _sd_ft_info_t _sd_ft_data;
extern int _sd_node_recovery;

extern void _sdbc_ft_unload(void);
extern int _sdbc_ft_load(void);
extern int _sdbc_ft_configure(void);
extern void _sdbc_ft_deconfigure(void);
extern int _sd_recovery_wait(void);
extern int _sd_recovery_wblk_wait(int cd);
extern void _sd_mirror_iodone(void);
extern int _sd_repin_cd(int);
extern void _sd_remote_disable(int);
extern void r_sd_ifs_cache_enable(ncall_t *, int *);
extern void r_sd_ifs_cache_disable(ncall_t *, int *);
extern void _sd_hash_invalidate_cd(int);
extern void r_cd_discard(ncall_t *, int *);
extern int _sd_uncommit(_sd_buf_handle_t *, nsc_off_t, nsc_size_t, int);
extern int _sd_uncommit_refresh(_sd_cctl_t *, int);
extern void r_sd_uncommit_refresh(ncall_t *, int *);
extern int _sd_wait_for_flush(int);
extern int _sdbc_warm_start(void);
extern void _sdbc_set_warm_start(void);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SD_FT_H */

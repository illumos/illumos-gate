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

#ifndef _SD_MISC_H
#define	_SD_MISC_H

#ifdef __cplusplus
extern "C" {
#endif

#define	_SD_FIFO_WAIT	1000
#define	_SD_FIFO_WSPIN	100
#ifdef _KERNEL

extern _dm_process_vars_t dynmem_processing_dm;

extern int sdbc_wrthru_len;
extern nsc_size_t sdbc_max_fbas;
extern int sdbc_max_devs;


extern int _init(void);
extern void _sd_data_log(int num, _sd_cctl_t *centry, nsc_off_t st,
    nsc_size_t len);
extern void _sd_data_log_chain(int num, _sd_cctl_t *centry, nsc_off_t fba_pos,
    nsc_size_t fba_len);
extern int _sd_reflect_ignore(ucaddr_t from, ucaddr_t to, int size);
extern int _sd_reflect(ucaddr_t from, ucaddr_t to, int size, int flag);
extern void _sd_timed_block(clock_t ticks, kcondvar_t *cvp);
extern void _sd_unblock(kcondvar_t *cvp);
extern void _sd_zap_stats(void);
extern int _sd_cache_sizes(int *asize, int *wsize);
extern void _sd_print(int level, char *fmt, ...);
extern int _sd_get_cd_blk(int cd, nsc_off_t blk, _sd_cctl_t **cc, caddr_t *data,
    char **filename);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SD_MISC_H */

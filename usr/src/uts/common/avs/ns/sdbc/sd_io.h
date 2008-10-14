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

#ifndef _SD_IO_H
#define	_SD_IO_H

#ifdef __cplusplus
extern "C" {
#endif

#define	SGIO_MAX 254

#define	_SD_IO_NONE	0
#define	_SD_IO_INITIATE 1
#define	_SD_IO_DONE	2
#define	_SD_IO_FAILED   3
#define	_SD_IO_DISCARDED   4

#define	_SD_WRITER_NONE    0
#define	_SD_WRITER_CREATE  1
#define	_SD_WRITER_RUNNING 2

#ifdef _KERNEL

extern kcondvar_t _sd_flush_cv;
/* secret flush toggle flag for testing */
extern int _sdbc_flush_flag;		/* 0 ==> noflushing, 1 ==> flush */


extern int _sdbc_flush_configure(void);
extern void _sdbc_flush_deconfigure(void);
extern void _sd_async_flclist(_sd_cctl_t *cclist, dev_t rdev);
extern void _sd_enqueue_io_pending(int cd, _sd_cctl_t *cclist);
extern void _sd_async_flcent(_sd_cctl_t *cc_ent, dev_t rdev);
extern int _sd_process_failure(_sd_cctl_t *cc_ent);
extern int cd_writer(int cd);
extern void _sd_ccent_rd(_sd_cctl_t *cc_ent, uint_t wanted, buf_t *bp);
extern int _sdbc_wait_pending(void);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SD_IO_H */
